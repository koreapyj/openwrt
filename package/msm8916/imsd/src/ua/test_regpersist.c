/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Persistence of the LAN registrar's bindings (regpersist.[ch]) on the inline file backend and a real temp directory. */
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include "test_ua.h"
#include "regpersist.h"
#include "../store/store.h"
#include "../util/evloop.h"

#define T0 1700000000LL
#define INST1 "<urn:uuid:11111111-2222-3333-4444-555555555555>"

static struct {
	struct uaw w;
	struct regpersist *p;
	struct store *st;
	struct lan_cfg lc;
	char dir[256];
	int64_t off, fixed;		/* wall clock: T0 + virtual time + off; `fixed` > 0 overrides it */
	bool no_persist;		/* lan_persist = 0 */
	const char *pre_item;		/* start(): added to the store before the LAN comes up */
	unsigned ndeliver;
	reg_id_t deliver_to[16];
	uint64_t deliver_seq[16];
} X;

static int64_t wall_cb(void *ctx)
{
	(void)ctx;
	return X.fixed ? X.fixed : T0 + X.off + (int64_t)(ev_now_ms() / 1000);
}

static int h_deliver(void *ctx, const struct store_item *it, reg_id_t b, uint32_t features, void (*done)(void *, int), void *arg)
{
	(void)ctx; (void)features; (void)done; (void)arg;
	if (X.ndeliver < 16) {
		X.deliver_to[X.ndeliver] = b;
		X.deliver_seq[X.ndeliver++] = it->seq;
	}
	return 0;
}
static void h_abort(void *ctx, void *arg) { (void)ctx; (void)arg; }
static bool h_body(void *ctx, uint8_t t, uint32_t f, bool hb) { (void)ctx; (void)t; (void)f; (void)hb; return false; }
static const struct store_handler HANDLER = { .needs_body = h_body, .deliver = h_deliver, .abort = h_abort };

static void on_binding(struct lan *l, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why, void *arg)
{
	(void)l; (void)arg;
	if (X.w.nbev < MAXLOG) {
		X.w.bev[X.w.nbev].ev = ev;
		X.w.bev[X.w.nbev].id = b->id;
		X.w.bev[X.w.nbev].why = why;
		X.w.nbev++;
	}
	regpersist_on_binding(X.p, ev, b, why);
	if (X.st)
		store_on_binding(X.st, ev, b, why);
}

static void tweak(struct lan_cfg *c)
{
	c->on_binding = on_binding;
	c->arg = &X;
	X.lc = *c;
}

static void rmtree(const char *d)
{
	char cmd[400];

	if (strlen(d) < 10 || strpbrk(d, "'\"\\;$`"))
		return;
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", d);
	if (system(cmd)) { /* nothing */ }
}

static struct regpersist_stats pst(void)
{
	struct regpersist_stats s;

	memset(&s, 0, sizeof(s));
	if (X.p)
		regpersist_stats(X.p, &s);
	return s;
}

static void start_store(void)
{
	struct store_cfg sc;
	struct store_ops so;

	store_cfg_defaults(&sc);
	snprintf(sc.dir, sizeof(sc.dir), "%.95s", X.dir);
	memset(&so, 0, sizeof(so));
	so.wall = wall_cb;
	so.inline_io = true;
	X.st = store_new(&sc, &so);
	CHECK(X.st != NULL);
	store_set_handler(X.st, STORE_SMS, &HANDLER);
	store_sync(X.st);
	evfake_advance(0);
}

/* bring the LAN side (and the persistence) up like the daemon does after a start */
static void start_lan(void)
{
	struct regpersist_cfg rc;

	if (X.pre_item) {
		struct store_add a;

		memset(&a, 0, sizeof(a));
		a.type = STORE_SMS;
		a.peer = "+8210123";
		a.meta = X.pre_item;
		a.meta_len = strlen(X.pre_item);
		CHECK_EQ(store_add(X.st, &a, NULL, NULL, NULL), 0);
		store_sync(X.st);
		evfake_advance(0);
		X.pre_item = NULL;
	}
	X.w.lan = lan_new(&X.lc);
	CHECK(X.w.lan != NULL);
	if (X.no_persist)
		return;
	memset(&rc, 0, sizeof(rc));
	rc.dir = X.dir;
	rc.inline_io = true;
	rc.wall = wall_cb;
	X.p = regpersist_new(&rc);
	CHECK(X.p != NULL);
	regpersist_attach(X.p, lan_registrar(X.w.lan), lan_endpoint(X.w.lan));
}

static void init(bool with_store)
{
	const char *base = getenv("IMSD_TEST_TMP");
	static int k;

	memset(&X.w, 0, sizeof(X.w));
	X.p = NULL;
	X.st = NULL;
	X.off = X.fixed = 0;
	X.no_persist = false;
	X.ndeliver = 0;
	snprintf(X.dir, sizeof(X.dir), "%s/regp-%d-%d", base ? base : "/tmp", (int)getpid(), ++k);
	rmtree(X.dir);
	CHECK_EQ(mkdir(X.dir, 0700), 0);
	uaw_init(&X.w, tweak, false);
	lan_free(X.w.lan);		/* the fixture builds its own lan (start_lan) so that "restarts" can repeat it */
	X.w.lan = NULL;
	if (with_store)
		start_store();
	start_lan();
}

/* the daemon goes down cleanly (final write) */
static void stop(void)
{
	regpersist_detach(X.p);
	regpersist_free(X.p);
	X.p = NULL;
	if (X.st) {
		store_lan_down(X.st);
		store_free(X.st);
		X.st = NULL;
	}
	lan_free(X.w.lan);
	X.w.lan = NULL;
	fakeep_clear(X.w.f);
}

static void start(int64_t down_s)
{
	X.off += down_s;
	X.w.nbev = 0;
	start_lan();
}

static void fini(void)
{
	if (X.p)
		stop();
	else if (X.st) {
		store_free(X.st);
		X.st = NULL;
		lan_free(X.w.lan);
		X.w.lan = NULL;
	} else if (X.w.lan) {
		lan_free(X.w.lan);
		X.w.lan = NULL;
	}
	uaw_fini(&X.w);
	rmtree(X.dir);
}

static void reg(int k, const char *contact_params, int cseq, const char *extra)
{
	char ct[400], cid[32], ex[600];

	snprintf(ct, sizeof(ct), "<sip:u%d@%s:5060>%s", k, dev_ip(k), contact_params);
	snprintf(cid, sizeof(cid), "dev%d-reg", k);
	snprintf(ex, sizeof(ex), "User-Agent: TestPhone\r\n%s", extra ? extra : "");
	fakeep_clear(X.w.f);
	uaw_rx(&X.w, dev_ip(k), 5060, mk_register(dev_ip(k), ct, cseq, cid, -1, ex));
}

static const struct reg_binding *first(void)
{
	return reg_next(lan_registrar(X.w.lan), REG_ID_NONE);
}

static const struct reg_binding *nth(int n)
{
	const struct reg_binding *b = first();

	while (b && n--)
		b = reg_next(lan_registrar(X.w.lan), b->id);
	return b;
}

static size_t file_read(unsigned char *buf, size_t cap)
{
	char p[300];
	FILE *f;
	size_t n;

	snprintf(p, sizeof(p), "%s/bindings", X.dir);
	f = fopen(p, "rb");
	if (!f)
		return 0;
	n = fread(buf, 1, cap, f);
	fclose(f);
	return n;
}

static void file_write(const unsigned char *buf, size_t n)
{
	char p[300];
	FILE *f;

	snprintf(p, sizeof(p), "%s/bindings", X.dir);
	f = fopen(p, "wb");
	CHECK(f != NULL);
	if (f) {
		if (n && fwrite(buf, 1, n, f) != n) { /* short write */ }
		fclose(f);
	}
}

static long remain_s(const struct reg_binding *b)
{
	return (long)((int64_t)b->expires_at_ms - (int64_t)ev_now_ms()) / 1000;
}

static const char *FEAT = ";expires=600;q=0.5;+sip.instance=\"" INST1 "\";+g.imsd.mms;+g.imsd.carbons";
static const char *EXTRA = "Accept: text/plain, application/vnd.wap.mms-message\r\nSupported: path, gruu\r\nAllow: INVITE, ACK, MESSAGE\r\n";

/* ---- round trip of every field ---- */
static void t_roundtrip(void)
{
	struct reg_binding s1, s2;
	const struct reg_binding *b;
	struct regpersist_stats st;
	long left;

	init(false);
	reg(1, FEAT, 1, EXTRA);
	/* a Contact host that is not the source (NAT): the source wins, target_from_src */
	{
		char ct[200];

		snprintf(ct, sizeof(ct), "<sip:u2@10.9.9.9:5060>;expires=900");
		fakeep_clear(X.w.f);
		uaw_rx(&X.w, dev_ip(2), 5060, mk_register(dev_ip(2), ct, 7, "dev2-reg", -1, "User-Agent: Natted\r\n"));
	}
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 2);
	s1 = *nth(0);
	s2 = *nth(1);
	CHECK(!s1.target_from_src && s2.target_from_src);
	evfake_advance(1500);
	CHECK_EQ(pst().writes, 1);		/* both changes within the second: one write */
	CHECK_EQ(pst().write_errors, 0);
	stop();
	start(30);
	st = pst();
	CHECK(st.loaded && !st.file_bad);
	CHECK_EQ(st.restored, 2); CHECK_EQ(st.expired, 0);
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 2);
	b = nth(0);
	CHECK(b != NULL);
	if (b) {
		CHECK(b->restored);
		CHECK_STR(b->aor, s1.aor); CHECK_STR(b->contact, s1.contact); CHECK_STR(b->key, s1.key);
		CHECK_STR(b->instance, INST1); CHECK_STR(b->ua, "TestPhone");
		CHECK_STR(b->accept, s1.accept); CHECK_STR(b->supported, s1.supported); CHECK(strstr(b->accept, "mms-message") != NULL);
		CHECK(addr_equal(&b->src, &s1.src)); CHECK(addr_equal(&b->target, &s1.target));
		CHECK_EQ(b->target_from_src, s1.target_from_src);
		CHECK_EQ(b->expires_s, s1.expires_s); CHECK_EQ(b->q, 500);
		CHECK_STR(b->call_id, s1.call_id); CHECK_EQ(b->cseq, s1.cseq);
		CHECK_EQ(b->allow, s1.allow); CHECK(b->allow_known);
		CHECK_EQ(b->features, REG_F_MMS | REG_F_CARBONS);
		CHECK_EQ(b->ack_state, REG_ACK_NONE);
		CHECK(b->reachable);
		left = (long)((int64_t)s1.expires_at_ms - (int64_t)ev_now_ms()) / 1000 - 30;
		CHECK(remain_s(b) >= left - 1 && remain_s(b) <= left + 1);	/* the ORIGINAL absolute expiry, minus the downtime */
	}
	b = nth(1);
	CHECK(b != NULL);
	if (b) {
		CHECK(b->restored && b->target_from_src);
		CHECK_STR(b->contact, s2.contact); CHECK(addr_equal(&b->target, &s2.target)); CHECK_EQ(b->cseq, 7);
		CHECK_EQ(b->features, 0);
	}
	CHECK_EQ(X.w.nbev, 2); CHECK_EQ(X.w.bev[0].ev, REG_EV_ADDED);	/* the normal add path: the hook fires */
	CHECK_EQ(pst().writes, 0);		/* a restore does not write the file again */
	evfake_advance(5000);
	CHECK_EQ(pst().writes, 0);
	/* the same state a second restart later (nothing lost by restoring) */
	stop();
	start(0);
	CHECK_EQ(pst().restored, 2);
	fini();
}

/* ---- expired entries are dropped; an unusable clock keeps them with the minimum lifetime ---- */
static void t_expiry(void)
{
	const struct reg_binding *b;

	init(false);
	reg(1, ";expires=120", 1, NULL);
	reg(2, ";expires=600", 1, NULL);
	evfake_advance(1500);
	stop();
	start(300);
	CHECK_EQ(pst().restored, 1); CHECK_EQ(pst().expired, 1);
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 1);
	b = first();
	CHECK(b && strstr(b->contact, "u2@") != NULL);
	if (b)
		CHECK(remain_s(b) >= 297 - 5 && remain_s(b) <= 300);
	/* it really expires at that time */
	evfake_advance(290000);
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 1);
	evfake_advance(15000);
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 0);
	/* the removal by expiry is written */
	evfake_advance(2000);
	stop();
	start(0);
	CHECK_EQ(pst().restored, 0);

	/* the clock is not set after the restart (before 2020): everything is kept, with the registrar's minimum lifetime */
	reg(1, ";expires=600", 1, NULL);
	reg(2, ";expires=600", 1, NULL);
	evfake_advance(1500);
	stop();
	X.fixed = 1000;
	start(0);
	CHECK_EQ(pst().restored, 2);
	b = first();
	CHECK(b && remain_s(b) >= 59 && remain_s(b) <= 60);
	/* a file written under an unset clock is no better: its times mean nothing */
	evfake_advance(1500);
	stop();
	X.fixed = 0;
	start(0);
	CHECK_EQ(pst().restored, 2);
	b = first();
	CHECK(b && remain_s(b) >= 59 && remain_s(b) <= 61);
	fini();
}

/* ---- a restored binding is a live one: forks, replacement by the next REGISTER ---- */
static void t_live(void)
{
	struct lan_req q;
	struct fork_rec fr = {0};
	struct lan_fork *f;
	const struct reg_binding *b;
	reg_id_t id;
	int n;

	init(false);
	reg(1, FEAT, 1, EXTRA);
	evfake_advance(1500);
	stop();
	start(5);
	b = first();
	CHECK(b != NULL);
	id = b ? b->id : 0;

	mk_invite_req(&q, "v=0\r\no=- 1 1 IN IP4 192.168.68.1\r\ns=-\r\nc=IN IP4 192.168.68.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 8\r\n");
	f = lan_fork_request(X.w.lan, &q, NULL, fork_cb, &fr, NULL);
	CHECK(f != NULL);
	CHECK_EQ(count_sent(X.w.f, "INVITE"), 1);
	CHECK(find_sent(X.w.f, dev_ip(1), 5060, "INVITE", 0) >= 0);
	if (f)
		lan_fork_cancel(f);
	fakeep_clear(X.w.f);
	q.method = "MESSAGE";
	q.content_type = "text/plain; charset=utf-8";
	q.body = (const uint8_t *)"hi";
	q.body_len = 2;
	f = lan_fork_request(X.w.lan, &q, NULL, fork_cb, &fr, NULL);
	CHECK(f != NULL);
	CHECK(find_sent(X.w.f, dev_ip(1), 5060, "MESSAGE", 0) >= 0);
	CHECK(dev_reply(&X.w, 1, "MESSAGE", 200, NULL));
	CHECK_EQ(fr_find(&fr, LAN_FORK_COMPLETE, 0) >= 0, 1);
	fr_release(&fr);
	evfake_advance(40000);

	/* the next REGISTER of the instance (here from another port, new Contact) replaces it: same id, not a second binding */
	n = X.w.nbev;
	fakeep_clear(X.w.f);
	uaw_rx(&X.w, dev_ip(1), 5070, mk_register(dev_ip(1), "<sip:u1@192.168.68.11:5070>;expires=600;+sip.instance=\"" INST1 "\"", 2,
						  "dev1-reg", -1, "User-Agent: TestPhone\r\n"));
	CHECK_EQ(sent_status(X.w.f, last_resp(X.w.f)), 200);
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 1);
	b = first();
	CHECK(b && b->id == id && !b->restored && strstr(b->contact, ":5070") != NULL);
	CHECK_EQ(X.w.bev[n].ev, REG_EV_REFRESHED);
	/* ... and the same Contact refreshes it as well (restored binding of a device without instance) */
	evfake_advance(1500);
	stop();
	start(0);
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 1);
	reg(1, ";expires=600;+sip.instance=\"" INST1 "\"", 3, NULL);
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 1);
	CHECK(!first()->restored);
	/* Call-ID / CSeq ordering is kept across the restart: an older CSeq of the same Call-ID is refused */
	stop();
	start(0);
	reg(1, ";expires=600;+sip.instance=\"" INST1 "\"", 1, NULL);
	CHECK_EQ(sent_status(X.w.f, last_resp(X.w.f)), 500);
	CHECK(first()->restored);
	fini();
}

/* ---- unregister reaches the file ---- */
static void t_unregister(void)
{
	init(false);
	reg(1, ";expires=600", 1, NULL);
	reg(2, ";expires=600", 1, NULL);
	evfake_advance(1500);
	reg(1, ";expires=0", 2, NULL);
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 1);
	evfake_advance(1500);
	CHECK_EQ(pst().writes, 2);
	stop();
	start(0);
	CHECK_EQ(pst().restored, 1);
	CHECK(first() && strstr(first()->contact, "u2@") != NULL);
	/* Contact: * with Expires: 0 */
	fakeep_clear(X.w.f);
	uaw_rx(&X.w, dev_ip(2), 5060, mk_register(dev_ip(2), "*", 2, "dev2-reg", 0, NULL));
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 0);
	evfake_advance(1500);
	stop();
	start(0);
	CHECK_EQ(pst().restored, 0); CHECK(!pst().file_bad);
	fini();
}

/* ---- a file that does not verify is ignored (and replaced by the next write) ---- */
static void t_corrupt(void)
{
	static unsigned char buf[8192], bad[8192];
	size_t n, i;
	int mode;

	init(false);
	reg(1, FEAT, 1, EXTRA);
	reg(2, ";expires=600", 1, NULL);
	evfake_advance(1500);
	stop();
	n = file_read(buf, sizeof(buf));
	CHECK(n > 100);
	CHECK(memcmp(buf, "IMSDREG1", 8) == 0);
	for (mode = 0; mode < 6; mode++) {
		memcpy(bad, buf, n);
		i = n;
		if (mode == 0) i = n / 2;			/* truncated */
		else if (mode == 1) i = n - 1;			/* one byte short */
		else if (mode == 2) bad[n / 2] ^= 0x40;		/* bit rot in the middle */
		else if (mode == 3) bad[0] = 'X';		/* wrong magic */
		else if (mode == 4) i = 0;			/* empty */
		else { bad[8] = 9; }				/* other version (CRC now wrong as well) */
		file_write(bad, i);
		start(0);
		CHECK(pst().file_bad);
		CHECK(pst().loaded);
		CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 0);
		stop();
	}
	/* a new REGISTER writes a good file again */
	file_write(buf, n / 2);
	start(0);
	CHECK(pst().file_bad);
	reg(1, ";expires=600", 1, NULL);
	evfake_advance(1500);
	stop();
	start(0);
	CHECK(!pst().file_bad); CHECK_EQ(pst().restored, 1);
	/* a missing file is the normal first start */
	stop();
	{
		char p[300];

		snprintf(p, sizeof(p), "%s/bindings", X.dir);
		unlink(p);
	}
	start(0);
	CHECK(!pst().file_bad); CHECK_EQ(pst().restored, 0);
	/* a directory that is not usable: the registrar works, nothing is written, nothing breaks */
	stop();
	rmtree(X.dir);
	start(0);
	reg(1, ";expires=600", 1, NULL);
	evfake_advance(1500);
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 1);
	CHECK(pst().write_errors >= 1);
	CHECK_EQ(mkdir(X.dir, 0700), 0);
	fini();
}

/* ---- lan_persist = 0: no regpersist object at all, nothing written, nothing read ---- */
static void t_off(void)
{
	static unsigned char before[8192], after[8192];
	size_t n0, n1;

	init(false);
	reg(1, ";expires=600", 1, NULL);
	evfake_advance(1500);
	stop();
	n0 = file_read(before, sizeof(before));
	CHECK(n0 > 0);
	X.no_persist = true;
	start(0);
	CHECK(X.p == NULL);
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 0);		/* the file that is there is not read */
	reg(2, ";expires=600", 1, NULL);
	evfake_advance(70000);
	CHECK_EQ(reg_count(lan_registrar(X.w.lan)), 1);
	regpersist_on_binding(NULL, REG_EV_ADDED, first(), REG_RM_NONE);	/* the module hook with no object is harmless */
	regpersist_detach(NULL);
	regpersist_free(NULL);
	n1 = file_read(after, sizeof(after));
	CHECK(n1 == n0 && !memcmp(before, after, n0));		/* ... and not written */
	fini();

	/* with no file at all: none is created */
	init(false);
	stop();
	{
		char p[300];

		snprintf(p, sizeof(p), "%s/bindings", X.dir);
		unlink(p);
		X.no_persist = true;
		start(0);
		reg(1, ";expires=600", 1, NULL);
		evfake_advance(70000);
		CHECK(access(p, F_OK) != 0);
	}
	fini();
}

/* ---- write coalescing ---- */
static void t_coalesce(void)
{
	uint64_t last = 0;
	unsigned long w, prev;
	int i;

	init(false);
	/* five changes in one second: one write, one second after the first */
	reg(1, ";expires=600", 1, NULL);
	reg(2, ";expires=600", 1, NULL);
	reg(3, ";expires=600", 1, NULL);
	reg(2, ";expires=0", 2, NULL);
	reg(4, ";expires=600", 1, NULL);
	evfake_advance(900);
	CHECK_EQ(pst().writes, 0);
	evfake_advance(200);
	CHECK_EQ(pst().writes, 1);
	/* an immediate follow-up change is held back to one write per second */
	last = ev_now_ms();
	reg(5, ";expires=600", 1, NULL);
	evfake_advance(500);
	CHECK_EQ(pst().writes, 1);
	evfake_advance(600);
	CHECK_EQ(pst().writes, 2);
	/* pure refreshes: every 5 s for 10 minutes -> one write per 60 s at most */
	prev = pst().writes;
	last = ev_now_ms();
	for (i = 2; i < 122; i++) {
		evfake_advance(5000);
		reg(1, ";expires=600", i, NULL);
		w = pst().writes;
		if (w != prev) {
			CHECK(ev_now_ms() - last >= 59000);
			last = ev_now_ms();
			prev = w;
		}
	}
	CHECK(pst().writes >= 2 + 9 && pst().writes <= 2 + 11);
	/* the refreshed expiry reaches the file at those writes: after a restart the binding is no more than ~60 s stale */
	stop();
	start(0);
	CHECK_EQ(pst().restored, 1);		/* the others (not refreshed) have expired by now */
	CHECK(first() && remain_s(first()) >= 600 - 65);
	fini();
}

/* ---- the store redelivers its backlog to a restored device ---- */
static void t_store(void)
{
	reg_id_t rid;

	init(true);
	reg(1, FEAT, 1, EXTRA);
	CHECK_EQ(X.ndeliver, 0);
	evfake_advance(1500);
	stop();
	/* the daemon starts: the store is up first, a message arrives while the LAN side is not there yet */
	start_store();
	X.pre_item = "while down";
	X.off += 20;
	X.w.nbev = 0;
	start_lan();
	store_sync(X.st);
	evfake_advance(0);
	CHECK_EQ(pst().restored, 1);
	rid = first() ? first()->id : 0;
	CHECK_EQ(X.ndeliver, 1);
	CHECK(X.ndeliver && X.deliver_to[0] == rid && X.deliver_seq[0] >= 1);	/* the item that arrived while the LAN side was down */
	fini();
}

void test_regpersist(void)
{
	t_roundtrip();
	t_expiry();
	t_live();
	t_unregister();
	t_corrupt();
	t_off();
	t_coalesce();
	t_store();
}
