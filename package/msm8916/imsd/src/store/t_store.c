/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Tests of the store model (store.c) on the inline file backend with the fake event loop: sequence numbers, cursors and the
 * X-IMSD-Ack-Seq rules, the delivery state machine, carbons, retention, failure and recovery. Plus a test with the real writer
 * thread (run alone under TSan with the argument "threads").
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "t_store.h"
#include "../util/log.h"

#define T0 1700000000

struct delivery {
	uint64_t seq;
	reg_id_t binding;
	uint8_t type;
	uint32_t features;
	char meta[48];
	bool body;
};

struct pend {
	void (*done)(void *arg, int nok);
	void *arg;
	reg_id_t binding;
};

static struct fx {
	char dir[96];
	struct store *s;
	int64_t wall;
	struct delivery log[512];
	unsigned nlog;
	struct pend pq[64];
	unsigned npq;
	unsigned inflight, maxinflight, aborted;
	int next_rc;			/* result of the next deliver(): 0 started, 1 skip, -errno */
	bool body_needed;
	bool inline_io;
	struct store_cfg cfg;
} F;

static int64_t wall_cb(void *ctx)
{
	(void)ctx;
	return F.wall;
}

static bool h_needs_body(void *ctx, uint8_t type, uint32_t features, bool has_body)
{
	(void)ctx;
	(void)type;
	(void)features;
	return F.body_needed && has_body;
}

static int h_deliver(void *ctx, const struct store_item *it, reg_id_t b, uint32_t features, void (*done)(void *, int), void *arg)
{
	struct delivery *d;

	(void)ctx;
	if (F.next_rc) {
		int rc = F.next_rc;

		F.next_rc = 0;
		return rc;
	}
	if (F.nlog < 512) {
		d = &F.log[F.nlog++];
		d->seq = it->seq;
		d->binding = b;
		d->type = it->type;
		d->features = features;
		d->body = it->body != NULL;
		snprintf(d->meta, sizeof(d->meta), "%.*s", it->meta_len > 47 ? 47 : (int)it->meta_len, (const char *)it->meta);
	}
	if (F.npq < 64) {
		F.pq[F.npq].done = done;
		F.pq[F.npq].arg = arg;
		F.pq[F.npq].binding = b;
		F.npq++;
	}
	F.inflight++;
	if (F.inflight > F.maxinflight)
		F.maxinflight = F.inflight;
	return 0;
}

static void h_abort(void *ctx, void *arg)
{
	unsigned i, j;

	(void)ctx;
	for (i = 0, j = 0; i < F.npq; i++) {
		if (F.pq[i].arg == arg) {
			F.inflight--;
			F.aborted++;
			continue;
		}
		F.pq[j++] = F.pq[i];
	}
	F.npq = j;
}

static const struct store_handler HANDLER = { .needs_body = h_needs_body, .deliver = h_deliver, .abort = h_abort };

static void settle(void)
{
	int i;

	for (i = 0; i < 12; i++) {
		if (F.s) {
			if (F.inline_io)
				store_sync(F.s);
			else
				evfake_poll_fds();
		}
		evfake_advance(0);
	}
}

/* the oldest pending delivery is answered: nok 1 = 2xx, 0 = failure */
static bool answer(int nok)
{
	struct pend p;
	unsigned i;

	if (!F.npq)
		return false;
	p = F.pq[0];
	for (i = 1; i < F.npq; i++)
		F.pq[i - 1] = F.pq[i];
	F.npq--;
	F.inflight--;
	p.done(p.arg, nok);
	settle();
	return true;
}

static void answer_all(void)
{
	int guard = 0;

	while (F.npq && guard++ < 600)
		answer(1);
}

static void fx_open(const char *tag, void (*tweak)(struct store_cfg *))
{
	struct store_ops ops;
	unsigned t;

	memset(&F, 0, sizeof(F));
	F.inline_io = true;
	F.wall = T0;
	t_tmpdir(tag, F.dir, sizeof(F.dir));
	evfake_reset();
	store_cfg_defaults(&F.cfg);
	snprintf(F.cfg.dir, sizeof(F.cfg.dir), "%s", F.dir);
	if (tweak)
		tweak(&F.cfg);
	memset(&ops, 0, sizeof(ops));
	ops.wall = wall_cb;
	ops.inline_io = true;
	F.s = store_new(&F.cfg, &ops);
	CHECK(F.s != NULL);
	for (t = 1; t < STORE_TYPE_MAX; t++)
		store_set_handler(F.s, (uint8_t)t, &HANDLER);
	settle();
}

static void fx_restart(void)
{
	struct store_ops ops;
	unsigned t;

	store_free(F.s);
	F.s = NULL;
	F.npq = F.inflight = 0;
	evfake_reset();
	memset(&ops, 0, sizeof(ops));
	ops.wall = wall_cb;
	ops.inline_io = F.inline_io;
	F.s = store_new(&F.cfg, &ops);
	CHECK(F.s != NULL);
	for (t = 1; t < STORE_TYPE_MAX; t++)
		store_set_handler(F.s, (uint8_t)t, &HANDLER);
	settle();
}

static void fx_close(void)
{
	store_free(F.s);
	F.s = NULL;
	evfake_reset();
	t_rmtree(F.dir);
}

/* ---- helpers ---- */

static struct reg_binding mkb(reg_id_t id, const char *instance, const char *user, uint32_t features, uint8_t ack_state, uint64_t ack)
{
	struct reg_binding b;

	memset(&b, 0, sizeof(b));
	b.id = id;
	snprintf(b.instance, sizeof(b.instance), "%s", instance ? instance : "");
	snprintf(b.aor, sizeof(b.aor), "sip:%s@192.168.68.1", user);
	b.features = features;
	b.ack_state = ack_state;
	b.ack_seq = ack;
	return b;
}

static void reg(reg_id_t id, const char *instance, const char *user, uint32_t features, uint8_t ack_state, uint64_t ack, bool refresh)
{
	struct reg_binding b = mkb(id, instance, user, features, ack_state, ack);

	store_on_binding(F.s, refresh ? REG_EV_REFRESHED : REG_EV_ADDED, &b, REG_RM_NONE);
	settle();
}

static void unreg(reg_id_t id)
{
	struct reg_binding b = mkb(id, "", "x", 0, 0, 0);

	store_on_binding(F.s, REG_EV_REMOVED, &b, REG_RM_UNREGISTERED);
	settle();
}

static uint64_t add_t(uint8_t type, const char *text, const uint64_t *excl, unsigned nexcl, const void *body, size_t bl, uint64_t dedup,
		      uint64_t lookup)
{
	struct store_add a;
	uint64_t seq = 0;
	int rc;

	memset(&a, 0, sizeof(a));
	a.type = type;
	a.peer = "+8210123";
	a.meta = text;
	a.meta_len = strlen(text);
	a.body = body;
	a.body_len = bl;
	a.dedup = dedup;
	a.lookup = lookup;
	a.excl = excl;
	a.nexcl = nexcl;
	rc = store_add(F.s, &a, NULL, NULL, &seq);
	CHECK_EQ(rc, 0);
	settle();
	return seq;
}

static uint64_t add_sms(const char *text)
{
	return add_t(STORE_SMS, text, NULL, 0, NULL, 0, 0, 0);
}

static struct store_status status(void)
{
	static struct store_status st;

	store_get_status(F.s, &st);
	return st;
}

static const struct store_dev_status *devst(const struct store_status *st, const char *id)
{
	unsigned i;

	for (i = 0; i < st->ndev; i++)
		if (!strncmp(st->dev[i].id, id, strlen(id)))
			return &st->dev[i];
	return NULL;
}

/* the deliveries of the log since index `from` as "seq,seq,..." */
static const char *seqs(unsigned from)
{
	static char b[512];
	unsigned i, n = 0;

	b[0] = 0;
	for (i = from; i < F.nlog; i++)
		n += (unsigned)snprintf(b + n, sizeof(b) - n, "%s%llu", i > from ? "," : "", (unsigned long long)F.log[i].seq);
	return b;
}

/* ------------------------------------------------------------------ */

void test_store_cursors(void)
{
	unsigned mark;
	const struct store_dev_status *d;
	struct store_status st;
	char ia[] = "<urn:uuid:aaaaaaaa-0000-4000-8000-000000000001>";
	char ib[] = "<urn:uuid:bbbbbbbb-0000-4000-8000-000000000002>";

	fx_open("cursors", NULL);
	CHECK(store_usable(F.s));
	/* 1. sequence numbers start at 1, strictly increasing */
	CHECK_EQ(add_sms("one"), 1);
	CHECK_EQ(add_sms("two"), 2);
	st = status();
	CHECK(st.items == 2 && st.first_seq == 1 && st.head_seq == 2);
	/* a device seen for the first time starts at the head: no history */
	reg(1, ia, "alice", 0, REG_ACK_NONE, 0, false);
	CHECK_EQ(F.nlog, 0);
	st = status();
	d = devst(&st, "aaaaaaaa");
	CHECK(d && d->registered && d->cursor == 2 && d->lag == 0 && !d->uses_ack);

	/* 2. a new item goes out at once, one at a time and in order; the next one waits for the 2xx */
	CHECK_EQ(add_sms("three"), 3);
	CHECK_EQ(F.nlog, 1);
	CHECK_EQ(F.log[0].seq, 3);
	CHECK_STR(F.log[0].meta, "three");
	CHECK_EQ(add_sms("four"), 4);
	CHECK_EQ(add_sms("five"), 5);
	CHECK_EQ(F.nlog, 1);
	CHECK_EQ(F.maxinflight, 1);
	CHECK(answer(1));
	CHECK_EQ(F.nlog, 2);
	CHECK_EQ(F.log[1].seq, 4);
	CHECK(answer(1));
	CHECK(answer(1));
	CHECK_STR(seqs(0), "3,4,5");
	CHECK_EQ(F.maxinflight, 1);
	st = status();
	d = devst(&st, "aaaaaaaa");
	CHECK(d && d->cursor == 5 && d->lag == 0 && d->delivered == 3);

	/* 3. gone while items arrive: they wait; the next REGISTER (a new binding) delivers the backlog in order */
	unreg(1);
	st = status();
	CHECK(devst(&st, "aaaaaaaa") && !devst(&st, "aaaaaaaa")->registered);
	add_sms("six");
	add_sms("seven");
	CHECK_EQ(F.nlog, 3);
	st = status();
	CHECK_EQ(devst(&st, "aaaaaaaa")->lag, 2);
	reg(2, ia, "alice", 0, REG_ACK_NONE, 0, false);
	CHECK_STR(seqs(3), "6");
	answer_all();
	CHECK_STR(seqs(3), "6,7");

	/* 4. failure: stops; a new item does not start again; one retry after 30 s, then only the next REGISTER */
	mark = F.nlog;
	add_sms("eight");
	CHECK_STR(seqs(mark), "8");
	CHECK(answer(0));
	add_sms("nine");
	CHECK_EQ(F.nlog, mark + 1);
	evfake_advance(29000);
	settle();
	CHECK_EQ(F.nlog, mark + 1);
	evfake_advance(2000);
	settle();
	CHECK_STR(seqs(mark), "8,8");			/* the timed retry */
	CHECK(answer(0));
	evfake_advance(120000);
	settle();
	CHECK_STR(seqs(mark), "8,8");			/* no second timed retry */
	st = status();
	CHECK(devst(&st, "aaaaaaaa")->failures == 2 && devst(&st, "aaaaaaaa")->lag == 2);
	reg(2, ia, "alice", 0, REG_ACK_NONE, 0, true);	/* refresh REGISTER: backlog again */
	CHECK_STR(seqs(mark), "8,8,8");
	answer_all();
	CHECK_STR(seqs(mark), "8,8,8,9");

	/* 5. X-IMSD-Ack-Seq: a first registration with the header is taken as it is (also history) */
	mark = F.nlog;
	reg(3, ib, "bob", 0, REG_ACK_OK, 7, false);	/* head is 9 */
	CHECK_STR(seqs(mark), "8");
	answer_all();
	CHECK_STR(seqs(mark), "8,9");
	st = status();
	d = devst(&st, "bbbbbbbb");
	CHECK(d && d->uses_ack && d->cursor == 7 && d->reported == 7 && d->pos == 9);
	/* a refresh without the header: what was answered stays answered (no resend within the registration) */
	mark = F.nlog;
	reg(3, ib, "bob", 0, REG_ACK_NONE, 0, true);
	CHECK_EQ(F.nlog, mark);
	/* a header BELOW the 2xx-based position: resend from there */
	reg(3, ib, "bob", 0, REG_ACK_OK, 5, true);
	CHECK_STR(seqs(mark), "6");
	answer_all();
	CHECK_STR(seqs(mark), "6,7,8,9");
	st = status();
	d = devst(&st, "bbbbbbbb");
	CHECK(d->cursor == 5 && d->pos == 9);		/* the gateway keeps the reported value, 2xx only moves the volatile position */
	/* above the head: clamped, nothing to send */
	mark = F.nlog;
	reg(3, ib, "bob", 0, REG_ACK_OK, 1000, true);
	CHECK_EQ(F.nlog, mark);
	st = status();
	d = devst(&st, "bbbbbbbb");
	CHECK(d->cursor == 9 && d->reported == 1000);
	/* malformed: ignored, nothing changes */
	reg(3, ib, "bob", 0, REG_ACK_BAD, 0, true);
	CHECK_EQ(F.nlog, mark);
	st = status();
	CHECK_EQ(devst(&st, "bbbbbbbb")->cursor, 9);
	/* a device that never reports: 2xx based, unchanged by header-less refreshes (alice is at 9) */
	st = status();
	CHECK(devst(&st, "aaaaaaaa")->cursor == 9 && !devst(&st, "aaaaaaaa")->uses_ack);

	/* two devices with different cursors, new items go to both */
	mark = F.nlog;
	add_sms("ten");
	CHECK_EQ(F.nlog, mark + 2);
	CHECK(F.log[mark].binding != F.log[mark + 1].binding);
	answer_all();
	st = status();
	CHECK_EQ(devst(&st, "aaaaaaaa")->cursor, 10);
	CHECK_EQ(devst(&st, "bbbbbbbb")->cursor, 9);	/* it reports its own */

	/* a restart keeps the items, the counter and the cursors; the device that reports starts from what it reported */
	fx_restart();
	st = status();
	CHECK(st.items == 10 && st.head_seq >= 10);
	{
		uint64_t n = add_sms("after restart");

		CHECK(n > 10);
		st = status();
		CHECK_EQ(devst(&st, "aaaaaaaa")->cursor, 10);	/* not registered: nothing delivered */
		CHECK_EQ(devst(&st, "aaaaaaaa")->lag, 1);
		mark = F.nlog;
		reg(5, ia, "alice", 0, REG_ACK_NONE, 0, false);
		CHECK_EQ(F.log[mark].seq, n);
		answer_all();
		reg(6, ib, "bob", 0, REG_ACK_NONE, 0, false);	/* no header after the restart: the last reported value */
		CHECK(F.nlog == mark + 2);
		answer_all();
	}
	fx_close();
}

static void check_ident(void)
{
	unsigned mark;
	struct store_status st;

	/* identity: +sip.instance wins; otherwise the user part of the AOR; same instance from another port is the same device */
	mark = F.nlog;
	reg(10, "<urn:uuid:11111111>", "shared", 0, REG_ACK_NONE, 0, false);
	reg(11, "<urn:uuid:22222222>", "shared", 0, REG_ACK_NONE, 0, false);
	st = status();
	CHECK(devst(&st, "11111111") && devst(&st, "22222222"));	/* two devices although the AOR is the same */
	reg(12, "<urn:uuid:11111111>", "other", 0, REG_ACK_NONE, 0, false);
	st = status();
	CHECK_EQ(st.ndev, 2);					/* the same instance under another AOR / binding id: the same device */
	reg(13, "", "carol", 0, REG_ACK_NONE, 0, false);
	reg(14, "", "dave", 0, REG_ACK_NONE, 0, false);
	st = status();
	CHECK_EQ(st.ndev, 4);					/* plain phones: distinct user names are distinct devices */
	CHECK(devst(&st, "u:carol") && devst(&st, "u:dave"));
	reg(15, "", "carol", 0, REG_ACK_NONE, 0, false);	/* carol again from another port: the same device */
	st = status();
	CHECK_EQ(st.ndev, 4);
	mark = F.nlog;
	add_sms("hello");
	/* carol's latest binding gets it, once */
	{
		unsigned i, nc = 0, n15 = 0, n13 = 0;

		for (i = mark; i < F.nlog; i++) {
			nc += 0;
			n15 += F.log[i].binding == 15;
			n13 += F.log[i].binding == 13;
		}
		CHECK_EQ(n15, 1);
		CHECK_EQ(n13, 0);
		CHECK_EQ(F.nlog - mark, 4);
		(void)nc;
	}
	answer_all();
}

void test_store_engine(void)
{
	unsigned mark;
	struct store_status st;
	uint64_t s1, s2, p0;

	fx_open("engine", NULL);
	check_ident();

	/* a registration that arrives while the log is still being read is replayed afterwards */
	fx_close();
	fx_open("engine2", NULL);
	add_sms("a");
	add_sms("b");
	reg(1, "<urn:uuid:aaaa0001>", "a", 0, REG_ACK_OK, 0, false);
	answer_all();
	CHECK_STR(seqs(0), "1,2");
	fx_restart();
	/* (fx_restart settles; do it by hand to register before the load completes) */
	{
		struct store_ops ops;

		store_free(F.s);
		evfake_reset();
		F.npq = F.inflight = 0;
		F.nlog = 0;
		memset(&ops, 0, sizeof(ops));
		ops.wall = wall_cb;
		ops.inline_io = true;
		F.s = store_new(&F.cfg, &ops);
		store_set_handler(F.s, STORE_SMS, &HANDLER);
		CHECK(!store_usable(F.s));
		{
			struct reg_binding b = mkb(1, "<urn:uuid:aaaa0001>", "a", 0, REG_ACK_OK, 1);

			store_on_binding(F.s, REG_EV_ADDED, &b, REG_RM_NONE);
		}
		settle();
		CHECK(store_usable(F.s));
		CHECK_STR(seqs(0), "2");			/* from its reported 1 */
		answer_all();
	}

	/* a skip answer (nothing to send to this device) counts as delivered */
	mark = F.nlog;
	F.next_rc = 1;
	s1 = add_sms("skipped");
	CHECK_EQ(F.nlog, mark);
	st = status();
	CHECK_EQ(devst(&st, "aaaa0001")->pos, s1);
	/* a start error stops the device like a failed answer */
	F.next_rc = -ENOENT;
	s2 = add_sms("failing");
	CHECK_EQ(F.nlog, mark);
	st = status();
	CHECK(devst(&st, "aaaa0001")->failures == 1 && devst(&st, "aaaa0001")->pos == s1);
	evfake_advance(31000);
	settle();
	CHECK_EQ(F.log[mark].seq, s2);
	/* the binding goes away while the MESSAGE is out: aborted, nothing is called back */
	{
		struct reg_binding b = mkb(1, "<urn:uuid:aaaa0001>", "a", 0, 0, 0);

		store_on_binding(F.s, REG_EV_REMOVED, &b, REG_RM_EXPIRED);
		settle();
		CHECK(F.aborted >= 1);
		CHECK_EQ(F.npq, 0);
	}
	/* LAN down: everything unregistered */
	reg(7, "<urn:uuid:aaaa0001>", "a", 0, REG_ACK_NONE, 0, false);
	CHECK_EQ(F.npq, 1);
	store_lan_down(F.s);
	CHECK_EQ(F.npq, 0);
	st = status();
	CHECK(!devst(&st, "aaaa0001")->registered);

	/* purge while a read is pending: the item is skipped, not an error */
	F.body_needed = false;
	mark = F.nlog;
	s1 = add_sms("will be purged");
	CHECK_EQ(store_purge(F.s, s1 + 1, false), 5);
	reg(8, "<urn:uuid:aaaa0001>", "a", 0, REG_ACK_NONE, 0, false);
	CHECK_EQ(F.nlog, mark);
	st = status();
	p0 = devst(&st, "aaaa0001")->pos;
	CHECK(st.items == 0 && devst(&st, "aaaa0001")->failures == 1);

	/* an item type without handler stalls the device (it is retried), it is not skipped */
	store_set_handler(F.s, STORE_MMS, NULL);
	mark = F.nlog;
	add_t(STORE_MMS, "mms", NULL, 0, "BODY", 4, 0, 0);
	CHECK_EQ(F.nlog, mark);
	st = status();
	CHECK_EQ(devst(&st, "aaaa0001")->pos, p0);
	store_set_handler(F.s, STORE_MMS, &HANDLER);
	F.body_needed = true;
	reg(8, "<urn:uuid:aaaa0001>", "a", 0, REG_ACK_NONE, 0, true);
	CHECK_EQ(F.nlog, mark + 1);
	CHECK(F.log[mark].body);			/* the body was loaded because the handler asked for it */
	answer_all();
	fx_close();
}

static void reg_carbon(reg_id_t id, const char *inst, const char *user, bool tag)
{
	reg(id, inst, user, tag ? REG_F_CARBONS : 0, REG_ACK_NONE, 0, false);
}

void test_store_carbons(void)
{
	unsigned mark;
	uint64_t ex[1], c1, c2;
	char sender[96], other[96];
	struct reg_binding bs, bo;
	struct store_status st;

	fx_open("carbons", NULL);
	bs = mkb(1, "<urn:uuid:5555>", "s", REG_F_CARBONS, 0, 0);
	bo = mkb(2, "", "r", REG_F_CARBONS, 0, 0);
	store_identity(&bs, sender, sizeof(sender));
	store_identity(&bo, other, sizeof(other));
	CHECK_STR(sender, "i:<urn:uuid:5555>");
	CHECK_STR(other, "u:r");
	ex[0] = store_hash(sender);
	reg_carbon(1, "<urn:uuid:5555>", "s", true);		/* the sender */
	reg_carbon(2, "", "r", true);				/* a receiver */
	reg_carbon(3, "", "plain", false);			/* a device without the tag */
	mark = F.nlog;
	c1 = add_t(STORE_CARBON_SMS, "sent text", ex, 1, NULL, 0, 0, 0);
	CHECK_STR(seqs(mark), "1");
	CHECK_EQ(F.log[mark].binding, 2);			/* only the receiver */
	answer_all();
	st = status();
	CHECK(devst(&st, "u:plain") && devst(&st, "u:plain")->pos == c1 && devst(&st, "u:plain")->lag == 0);	/* passed over, not owed */
	CHECK_EQ(devst(&st, "5555")->pos, c1);
	/* the sender comes back from another port (new binding id): still no copy of its own message */
	unreg(1);
	mark = F.nlog;
	reg(9, "<urn:uuid:5555>", "s", REG_F_CARBONS, REG_ACK_OK, 0, false);	/* it even reports 0: everything again */
	CHECK_STR(seqs(mark), "");				/* its own carbon is not owed, in the redelivery either */
	/* a receiver that was offline gets it at its next REGISTER (also for a sender excluded by identity only) */
	unreg(2);
	c2 = add_t(STORE_CARBON_MMS, "mmsmeta", ex, 1, "PDU", 3, 0, 77);
	CHECK(c2 > c1);
	mark = F.nlog;
	reg_carbon(12, "", "r", true);
	CHECK_STR(seqs(mark), "2");
	CHECK_EQ(F.log[mark].type, STORE_CARBON_MMS);
	answer_all();
	/* the untagged device registers later WITH the tag: the carbons that went by while it had no tag are not owed (its position passed them);
	 * a carbon created from now on is */
	mark = F.nlog;
	reg(13, "", "plain", REG_F_CARBONS, REG_ACK_NONE, 0, true);
	CHECK_EQ(F.nlog, mark);
	{
		uint64_t c3 = add_t(STORE_CARBON_SMS, "again", NULL, 0, NULL, 0, 0, 0);

		CHECK(F.nlog >= mark + 3);			/* all tagged devices, the sender too (no exclusion in this one) */
		(void)c3;
	}
	answer_all();
	/* an untagged device never gets a carbon: also a plain item gets to it */
	reg(14, "", "untagged", 0, REG_ACK_NONE, 0, false);
	mark = F.nlog;
	add_t(STORE_CARBON_SMS, "c", NULL, 0, NULL, 0, 0, 0);
	{
		unsigned i, n14 = 0;

		for (i = mark; i < F.nlog; i++)
			n14 += F.log[i].binding == 14;
		CHECK_EQ(n14, 0);
	}
	answer_all();
	add_sms("plain sms");
	{
		unsigned i, n14 = 0;

		for (i = mark; i < F.nlog; i++)
			n14 += F.log[i].binding == 14;
		CHECK_EQ(n14, 1);
	}
	answer_all();
	fx_close();
}

static void tw_small(struct store_cfg *c)
{
	c->keep_messages = 5;
}

static void tw_bytes(struct store_cfg *c)
{
	c->keep_bytes = 70000;
}

static void tw_age(struct store_cfg *c)
{
	c->keep_days = 2;
}

static void tw_age30(struct store_cfg *c)
{
	c->keep_days = 30;
}

static void tw_noage(struct store_cfg *c)
{
	c->keep_days = 0;
}

void test_store_limits(void)
{
	struct store_status st;
	struct store_info li[20];
	unsigned n, i;
	uint8_t big[30000];
	uint64_t found;

	memset(big, 'x', sizeof(big));
	/* count */
	fx_open("limit-count", tw_small);
	reg(1, "<urn:uuid:aaaa0001>", "a", 0, REG_ACK_NONE, 0, false);
	for (i = 1; i <= 3; i++)
		add_sms("m");
	answer_all();
	unreg(1);
	for (i = 4; i <= 9; i++)
		add_sms("m");
	st = status();
	CHECK(st.items == 5 && st.first_seq == 5 && st.head_seq == 9 && st.evicted == 4);
	/* the lagging device missed what went before: counted, skipped silently */
	st = status();
	CHECK_EQ(devst(&st, "aaaa0001")->missed, 1);	/* 4 was owed and is gone (1..3 were delivered before); 5..9 are still there */
	{
		unsigned mark = F.nlog;

		reg(2, "<urn:uuid:aaaa0001>", "a", 0, REG_ACK_NONE, 0, false);
		CHECK_STR(seqs(mark), "5");		/* the first one that is still there */
		answer_all();
		CHECK_STR(seqs(mark), "5,6,7,8,9");
	}
	/* the limits are honoured after a restart, and the log shrinks (compaction) */
	fx_restart();
	st = status();
	CHECK(st.items == 5 && st.first_seq == 5);
	n = store_list(F.s, 0, li, 20);
	CHECK_EQ(n, 5);
	CHECK(li[0].seq == 5 && li[4].seq == 9 && li[0].type == STORE_SMS && li[0].durable && li[0].size == 1);
	n = store_list(F.s, 8, li, 20);
	CHECK_EQ(n, 2);
	/* lookups */
	{
		uint64_t d1 = add_t(STORE_SMS, "dd", NULL, 0, NULL, 0, 0xfeed, 0);
		uint64_t l1 = add_t(STORE_MMS, "ll", NULL, 0, "B", 1, 0, 0xbeef);

		CHECK_EQ(store_find_dedup(F.s, STORE_SMS, 0xfeed, 600, &found), 0);
		CHECK_EQ(found, d1);
		CHECK_EQ(store_find_dedup(F.s, STORE_MMS, 0xfeed, 600, &found), -ENOENT);
		CHECK_EQ(store_find_lookup(F.s, STORE_MMS, 0xbeef, &found), 0);
		CHECK_EQ(found, l1);
		F.wall += 700;
		CHECK_EQ(store_find_dedup(F.s, STORE_SMS, 0xfeed, 600, &found), -ENOENT);	/* too old for a duplicate check */
		CHECK_EQ(store_find_dedup(F.s, STORE_SMS, 0xfeed, 0, &found), 0);
		fx_restart();
		CHECK_EQ(store_find_dedup(F.s, STORE_SMS, 0xfeed, 0, &found), 0);	/* the index survives the restart */
		CHECK_EQ(store_find_lookup(F.s, STORE_MMS, 0xbeef, &found), 0);
	}
	/* purge: before a number, then all; durable */
	st = status();
	n = store_purge(F.s, st.first_seq + 2, false);
	CHECK_EQ(n, 2);
	settle();
	fx_restart();
	st = status();
	CHECK_EQ(st.items, 3);				/* limit five: seven were added, two purged */
	CHECK(store_purge(F.s, 0, true) > 0);
	settle();
	fx_restart();
	st = status();
	CHECK_EQ(st.items, 0);
	{
		uint64_t keep = st.head_seq;

		CHECK_EQ(add_sms("n") > keep, 1);	/* numbers are never reused, not even after a purge of everything */
	}
	fx_close();

	/* bytes (meta and bodies count) */
	fx_open("limit-bytes", tw_bytes);
	for (i = 0; i < 4; i++)
		add_t(STORE_MMS, "x", NULL, 0, big, sizeof(big), 0, 0);
	st = status();
	CHECK(st.items == 2 && st.bytes <= 70000 && st.first_seq == 3);
	fx_restart();
	st = status();
	CHECK(st.items == 2 && st.first_seq == 3);
	fx_close();

	/* age: swept by the hourly timer; an item without a plausible time never ages */
	fx_open("limit-age", tw_age);
	add_sms("old");
	F.wall += 86400;
	add_sms("newer");
	F.wall += 86400 + 100;
	evfake_advance(3600 * 1000 + 10);
	settle();
	st = status();
	CHECK(st.items == 1 && st.first_seq == 2);
	F.wall += 86400 * 40;
	evfake_advance(3600 * 1000 + 10);
	settle();
	st = status();
	CHECK_EQ(st.items, 0);
	fx_close();

	/* no age limit (the default): a wall clock that jumps years ahead removes neither items nor device records */
	fx_open("noage", tw_noage);
	{
		add_sms("a");
		settle();
		reg(1, "<urn:uuid:0000aaaa>", "x", 0, REG_ACK_NONE, 0, false);
		unreg(1);
		F.wall += (int64_t)400 * 86400;
		evfake_advance(3600 * 1000 + 10);
		settle();
		st = status();
		CHECK_EQ(st.items, 1);
		CHECK_EQ(st.ndev, 1);
	}
	fx_close();

	/* devices: with an age limit set, 30 days unseen drops the record; more than 32 drops the least recently seen */
	fx_open("devices", tw_age30);
	{
		char inst[48];

		for (i = 0; i < 34; i++) {
			snprintf(inst, sizeof(inst), "<urn:uuid:%08x>", 0x100 + i);
			F.wall += 10;
			reg(100 + i, inst, "x", 0, REG_ACK_NONE, 0, false);
			unreg(100 + i);
		}
		st = status();
		CHECK_EQ(st.ndev, STORE_MAX_DEV);
		CHECK(!devst(&st, "00000100") && !devst(&st, "00000101"));
		CHECK(devst(&st, "00000121"));
		F.wall += 31 * 86400;
		evfake_advance(3600 * 1000 + 10);
		settle();
		st = status();
		CHECK_EQ(st.ndev, 0);
	}
	fx_close();
}

static struct {
	int n, status;
	char meta[16];
	bool has;
} cbr;

static void health_cb(void *arg, int status, uint64_t sq, const struct store_add *x)
{
	(void)arg;
	(void)sq;
	cbr.n++;
	cbr.status = status;
	cbr.has = x != NULL;
	if (x)
		snprintf(cbr.meta, sizeof(cbr.meta), "%.*s", (int)x->meta_len, (const char *)x->meta);
}

void test_store_health(void)
{
	struct store_status st;
	struct store_add a;
	uint64_t seq = 0;
	int rc;
	unsigned mark;
	fx_open("health", NULL);
	reg(1, "<urn:uuid:aaaa0001>", "a", 0, REG_ACK_NONE, 0, false);
	memset(&a, 0, sizeof(a));
	a.type = STORE_SMS;
	a.peer = "+82";
	a.meta = "keepme";
	a.meta_len = 6;

	/* a full file system: the item is refused through the callback with its payload (for the live fallback), the store says why,
	 * and later adds are refused at once */
	sio_fault.points = SIO_FP_LOGWRITE;
	sio_fault.err = ENOSPC;
	sio_fault.count = -1;
	rc = store_add(F.s, &a, health_cb, NULL, &seq);
	CHECK_EQ(rc, 0);
	CHECK_EQ(cbr.n, 0);				/* never synchronous */
	settle();
	CHECK(cbr.n == 1 && cbr.status == -ENOSPC && cbr.has);
	CHECK_STR(cbr.meta, "keepme");
	CHECK(!store_usable(F.s));
	CHECK_EQ(store_add(F.s, &a, NULL, NULL, &seq), -ENODEV);
	st = status();
	CHECK(!st.healthy && strstr(st.error, "no space") && st.items == 0 && st.add_failed == 1);
	/* still failing at the probe */
	sio_fault.points = SIO_FP_STATE;
	evfake_advance(31000);
	settle();
	CHECK(!store_usable(F.s));
	/* space is back: the probe recovers the store, new items go in, earlier numbers are not reused */
	sio_fault.points = 0;
	evfake_advance(31000);
	settle();
	CHECK(store_usable(F.s));
	st = status();
	CHECK(st.healthy && st.error[0] == 0);
	mark = F.nlog;
	seq = add_sms("fine again");
	CHECK(seq > 1);
	CHECK_EQ(F.nlog, mark + 1);
	answer_all();
	/* I/O error in reading: the device is stalled, the item stays */
	sio_fault.points = SIO_FP_READ;
	sio_fault.err = EIO;
	sio_fault.count = 1;
	mark = F.nlog;
	add_sms("unreadable once");
	CHECK_EQ(F.nlog, mark);
	st = status();
	CHECK(st.read_errors == 1 && devst(&st, "aaaa0001")->failures == 1);
	evfake_advance(31000);
	settle();
	CHECK_EQ(F.nlog, mark + 1);
	answer_all();

	/* abandoned: the caller gave up waiting; the item is dropped as soon as it is durable and nobody gets it */
	mark = F.nlog;
	rc = store_add(F.s, &a, NULL, NULL, &seq);
	CHECK_EQ(rc, 0);
	CHECK(store_abandon(F.s, seq));
	settle();
	CHECK_EQ(F.nlog, mark);
	st = status();
	CHECK(st.dropped == 1 && store_find_lookup(F.s, STORE_SMS, 1, NULL) != 0);
	{
		struct store_info li[8];
		unsigned n = store_list(F.s, seq, li, 8);

		CHECK_EQ(n, 0);
	}
	fx_restart();
	st = status();
	{
		struct store_info li[8];

		CHECK_EQ(store_list(F.s, seq, li, 8), 0);	/* the DROP record is durable: it does not come back */
	}
	fx_close();

	/* the store directory is not there at start: not usable, registrations are remembered, and the load is retried */
	{
		char parent[64], sub[96];
		struct store_ops ops;

		t_tmpdir("health-late", parent, sizeof(parent));
		memset(&F, 0, sizeof(F));
		F.inline_io = true;
		F.wall = T0;
		evfake_reset();
		store_cfg_defaults(&F.cfg);
		snprintf(sub, sizeof(sub), "%s/deeper/imsd", parent);
		snprintf(F.cfg.dir, sizeof(F.cfg.dir), "%s", sub);
		memset(&ops, 0, sizeof(ops));
		ops.wall = wall_cb;
		ops.inline_io = true;
		F.s = store_new(&F.cfg, &ops);
		CHECK(F.s != NULL);
		store_set_handler(F.s, STORE_SMS, &HANDLER);
		reg(1, "<urn:uuid:aaaa0001>", "a", 0, REG_ACK_OK, 0, false);
		CHECK(!store_usable(F.s));
		st = status();
		CHECK(!st.ready && st.error[0]);
		CHECK_EQ(store_add(F.s, &a, NULL, NULL, &seq), -ENODEV);
		{
			char d1[96];

			snprintf(d1, sizeof(d1), "%s/deeper", parent);
			CHECK(!mkdir(d1, 0700));
		}
		evfake_advance(31000);
		settle();
		CHECK(store_usable(F.s));
		add_sms("late");
		CHECK_EQ(F.nlog, 1);
		answer_all();
		store_free(F.s);
		F.s = NULL;
		evfake_reset();
		t_rmtree(parent);
	}
}

void test_store_threads(void)
{
	struct store_ops ops;
	struct store_status st;
	unsigned i, guard;
	uint64_t last = 0;
	bool ordered = true;

	memset(&F, 0, sizeof(F));
	F.wall = T0;
	F.inline_io = false;
	t_tmpdir("sthreads", F.dir, sizeof(F.dir));
	evfake_reset();
	store_cfg_defaults(&F.cfg);
	snprintf(F.cfg.dir, sizeof(F.cfg.dir), "%s", F.dir);
	memset(&ops, 0, sizeof(ops));
	ops.wall = wall_cb;
	F.s = store_new(&F.cfg, &ops);
	CHECK(F.s != NULL);
	for (i = 1; i < STORE_TYPE_MAX; i++)
		store_set_handler(F.s, (uint8_t)i, &HANDLER);
	F.body_needed = true;
	for (guard = 0; guard < 200 && !store_usable(F.s); guard++) {
		usleep(1000);
		settle();
	}
	CHECK(store_usable(F.s));
	reg(1, "<urn:uuid:aaaa0001>", "a", 0, REG_ACK_NONE, 0, false);
	for (i = 0; i < 40; i++) {
		struct store_add a;
		char t[16];

		memset(&a, 0, sizeof(a));
		snprintf(t, sizeof(t), "m%u", i);
		a.type = i % 2 ? STORE_MMS : STORE_SMS;
		a.peer = "+82";
		a.meta = t;
		a.meta_len = strlen(t);
		a.body = "BODYBODY";
		a.body_len = i % 2 ? 8 : 0;
		for (guard = 0; guard < 500 && store_add(F.s, &a, NULL, NULL, NULL); guard++) {
			usleep(500);
			settle();
		}
		/* answer what is out while the writer works */
		for (guard = 0; guard < 3; guard++) {
			usleep(200);
			settle();
			if (F.npq)
				answer(1);
		}
	}
	for (guard = 0; guard < 4000 && F.nlog < 40; guard++) {
		usleep(500);
		settle();
		if (F.npq)
			answer(1);
	}
	CHECK_EQ(F.nlog, 40);
	for (i = 0; i < F.nlog; i++) {
		if (F.log[i].seq <= last)
			ordered = false;
		last = F.log[i].seq;
		if ((F.log[i].type == STORE_MMS) != F.log[i].body)
			ordered = false;
	}
	CHECK(ordered);
	store_sync(F.s);
	st = status();
	CHECK(st.items == 40 && st.healthy);
	store_free(F.s);			/* the writer drains and stops; the cursor goes to disk */
	evfake_reset();
	memset(&ops, 0, sizeof(ops));
	ops.wall = wall_cb;
	F.s = store_new(&F.cfg, &ops);
	for (guard = 0; guard < 200 && !store_usable(F.s); guard++) {
		usleep(1000);
		settle();
	}
	CHECK(store_usable(F.s));
	st = status();
	CHECK(st.items == 40 && st.head_seq >= 40);
	CHECK(devst(&st, "aaaa0001") && devst(&st, "aaaa0001")->cursor >= 39);
	store_free(F.s);
	F.s = NULL;
	evfake_reset();
	t_rmtree(F.dir);
}
