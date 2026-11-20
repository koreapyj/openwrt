/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdlib.h>
#include "tcommon.h"

struct rx {
	enum cssms_kind kind;
	char from[48], ts[32], text[2048], dts[32];
	bool alnum, backlog, multipart, wsp, mms, trunc;
	uint8_t data[64];
	size_t dlen;
	int cls;
	unsigned parts, msgref, dstate;
};

static struct rx RX[200];
static int NRX;
static struct cssms *SM;
static struct cssms_cfg CFG;
static unsigned RXID;
static int RXRC;		/* what the callback answers */

static int on_msg(void *arg, const struct cssms_in *m)
{
	struct rx *r;

	(void)arg;
	if (NRX >= 200)
		return 0;
	r = &RX[NRX++];
	memset(r, 0, sizeof(*r));
	r->kind = m->kind;
	snprintf(r->from, sizeof(r->from), "%s", m->from);
	snprintf(r->ts, sizeof(r->ts), "%s", m->ts);
	if (m->text)
		snprintf(r->text, sizeof(r->text), "%s", m->text);
	if (m->data && m->data_len <= sizeof(r->data))
		memcpy(r->data, m->data, m->data_len);
	r->dlen = m->data_len;
	r->alnum = m->from_alnum;
	r->backlog = m->backlog;
	r->multipart = m->multipart;
	r->parts = m->parts;
	r->wsp = m->wsp_push;
	r->mms = m->mms_hint;
	r->cls = m->sms_class;
	r->msgref = m->message_reference;
	r->dstate = m->delivery_state;
	r->trunc = m->truncated;
	snprintf(r->dts, sizeof(r->dts), "%s", m->discharge_ts);
	RXID = m->id;
	return RXRC;
}

static void setup(bool start_sms)
{
	env_line(NULL);
	env_up();
	cssms_cfg_defaults(&CFG);
	CFG.on_message = on_msg;
	NRX = 0;
	SM = NULL;
	if (start_sms)
		SM = cssms_new(LINE, &CFG);
	adv(100);
}

static void teardown(void)
{
	cssms_free(SM);
	SM = NULL;
	env_down();
}

static int live_sms(void)
{
	int i, n = 0;

	for (i = 0; i < FK_SMS; i++)
		n += FK.sms[i].used;
	return n;
}

/* ------------------------------------------------------------------ incoming */

static void t_rx_basic(void)
{
	struct cssms_status st;
	struct fk_sms *s;

	setup(true);
	cssms_get_status(SM, &st);
	CHECK(st.drained && FK.n[CSU_SMS_LIST] == 1);		/* an empty storage: drained at once */
	/* a text */
	fk_net_sms("+821051226862", "hello \xEC\x95\x88\xEB\x85\x95", true);
	CHECK_EQ(NRX, 0);					/* not from inside the notification */
	adv(10);
	CHECK_EQ(NRX, 1);
	CHECK(RX[0].kind == CSSMS_TEXT && !RX[0].backlog && !RX[0].alnum && !RX[0].multipart && RX[0].parts == 1 && RX[0].cls == -1);
	CHECK_STR(RX[0].from, "+821051226862");
	CHECK_STR(RX[0].text, "hello \xEC\x95\x88\xEB\x85\x95");
	CHECK_STR(RX[0].ts, "2026-11-20T09:00:00+09:00");
	CHECK_STR(FK.order, "lgd");
	CHECK_EQ(live_sms(), 0);				/* read once, then deleted */
	cssms_get_status(SM, &st);
	CHECK(st.rx_text == 1 && st.rx_deleted == 1 && st.work_len == 0);

	/* duplicates of the same notification, a late list: once */
	FK.order[0] = 0;
	s = fk_net_sms("01011112222", "dup", false);
	fk_notify("messaging.added", s->path, NULL, NULL, NULL, true);
	fk_notify("messaging.added", s->path, NULL, NULL, NULL, true);
	fk_notify("messaging.state_changed", s->path, "receiving", "received", NULL, false);
	adv(10);
	CHECK_EQ(NRX, 2);
	CHECK_STR(RX[1].text, "dup");
	fk_notify("messaging.added", s->path, NULL, NULL, NULL, true);	/* after it is gone */
	adv(10);
	CHECK_EQ(NRX, 2);
	cssms_get_status(SM, &st);
	CHECK(st.rx_text == 2 && st.rx_deleted == 2);

	/* class 0, alphanumeric sender */
	s = fk_net_sms("KT-Info", "flash", false);
	s->cls = 0;
	fk_notify("messaging.added", s->path, NULL, NULL, NULL, true);
	adv(10);
	CHECK(NRX == 3 && RX[2].cls == 0 && RX[2].alnum && !strcmp(RX[2].from, "KT-Info"));

	/* a message we sent ourselves (created by someone else's ubus call): not ours to deliver, not deleted */
	{
		struct csu_notify n;
		struct fk_sms *m;

		(void)n;
		m = fk_net_sms("01099990000", "mine", false);
		snprintf(m->state, sizeof(m->state), "sent");
		snprintf(m->pdu, sizeof(m->pdu), "submit");
		fk_notify("messaging.added", m->path, NULL, NULL, NULL, false);	/* received = false: ignored */
		adv(10);
		CHECK_EQ(NRX, 3);
		CHECK_EQ(live_sms(), 1);
		fk_notify("messaging.added", m->path, NULL, NULL, NULL, true);	/* ... and even when read: state "sent" */
		adv(10);
		CHECK_EQ(NRX, 3);
		CHECK_EQ(live_sms(), 1);
		m->used = false;
	}

	/* a status report */
	s = fk_net_sms("+8210123", "", false);
	snprintf(s->pdu, sizeof(s->pdu), "status-report");
	s->has_text = false;
	s->msgref = 42;
	s->dstate = 0;
	snprintf(s->dts, sizeof(s->dts), "2026-11-20T09:00:05+09:00");
	fk_notify("messaging.added", s->path, NULL, NULL, NULL, true);
	adv(10);
	CHECK(NRX == 4 && RX[3].kind == CSSMS_REPORT && RX[3].msgref == 42 && RX[3].dstate == 0 && !strcmp(RX[3].dts, "2026-11-20T09:00:05+09:00"));
	CHECK_EQ(live_sms(), 0);

	/* binary: a WAP push carrying an MMS notification (the UDH with the port 2948 is not visible) and other data */
	s = fk_net_sms("+821051226862", "", false);
	s->has_text = false;
	s->has_data = true;
	{
		static const uint8_t push[] = { 0x01, 0x06, 0x24, 0xBE, 0x81, 0x8D, 0xDF, 0x8C, 0x82 };
		static const uint8_t other[] = { 0x02, 0x70, 0x00, 0x01 };

		memcpy(s->data, push, sizeof(push));
		s->dlen = sizeof(push);
		fk_notify("messaging.added", s->path, NULL, NULL, NULL, true);
		adv(10);
		CHECK(NRX == 5 && RX[4].kind == CSSMS_DATA && RX[4].dlen == sizeof(push) && RX[4].wsp && RX[4].mms && !memcmp(RX[4].data, push, sizeof(push)));
		s = fk_net_sms("+821051226862", "", false);
		s->has_text = false;
		s->has_data = true;
		memcpy(s->data, other, sizeof(other));
		s->dlen = sizeof(other);
		fk_notify("messaging.added", s->path, NULL, NULL, NULL, true);
		adv(10);
		CHECK(NRX == 6 && RX[5].kind == CSSMS_DATA && !RX[5].wsp && !RX[5].mms);
		s = fk_net_sms("+821051226862", "", false);
		s->has_text = false;
		s->has_data = true;
		{
			static const uint8_t textual[] = { 0x03, 0x06, 0x30, 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'v', 'n', 'd', '.', 'w', 'a', 'p', '.',
							   'm', 'm', 's', '-', 'm', 'e', 's', 's', 'a', 'g', 'e', 0 };

			memcpy(s->data, textual, sizeof(textual));
			s->dlen = sizeof(textual);
		}
		fk_notify("messaging.added", s->path, NULL, NULL, NULL, true);
		adv(10);
		CHECK(NRX == 7 && RX[6].wsp && RX[6].mms);
	}
	teardown();
}

static void t_rx_multipart(void)
{
	struct fk_sms *s, *t;
	struct cssms_status st;

	setup(true);
	/* three parts: announced with the first one (receiving), delivered when complete */
	s = fk_net_sms_part("+821051226862", 3, 1);
	adv(10);
	CHECK_EQ(NRX, 0);
	cssms_get_status(SM, &st);
	CHECK(st.incomplete == 1);
	CHECK_EQ(live_sms(), 1);		/* the object stays: its parts are in the modem storage */
	s->parts = 2;			/* a part arrives: uqmid sends no notification for it */
	adv(1000);
	CHECK_EQ(NRX, 0);
	fk_net_sms_complete(s, "part one part two part three");
	adv(10);
	CHECK_EQ(NRX, 1);
	CHECK(RX[0].kind == CSSMS_TEXT && RX[0].multipart && RX[0].parts == 3 && !strcmp(RX[0].text, "part one part two part three"));
	CHECK_EQ(live_sms(), 0);
	cssms_get_status(SM, &st);
	CHECK(st.incomplete == 0 && st.rx_text == 1);

	/* a concatenated message that never completes is deleted after 10 minutes */
	t = fk_net_sms_part("+821051226862", 5, 2);
	adv(10);
	CHECK(t->used && NRX == 1);
	adv(9 * 60000);
	CHECK(t->used);
	adv(2 * 60000);
	CHECK_EQ(live_sms(), 0);
	cssms_get_status(SM, &st);
	CHECK(st.rx_dropped_incomplete == 1 && st.incomplete == 0);
	CHECK_EQ(NRX, 1);

	/* two partial messages at once, completed in the other order */
	s = fk_net_sms_part("+8210111", 2, 1);
	t = fk_net_sms_part("+8210222", 2, 1);
	adv(10);
	fk_net_sms_complete(t, "second");
	adv(10);
	fk_net_sms_complete(s, "first");
	adv(10);
	CHECK(NRX == 3 && !strcmp(RX[1].text, "second") && !strcmp(RX[2].text, "first"));
	CHECK_EQ(live_sms(), 0);
	teardown();
}

/* the object is deleted only after the taker confirmed it */
static void t_rx_pending(void)
{
	struct cssms_status st;

	setup(true);
	RXRC = CSSMS_PENDING;
	fk_net_sms("+8210111", "one", true);
	fk_net_sms("+8210222", "two", true);
	adv(100);
	CHECK_EQ(NRX, 1);			/* the queue waits for the confirmation */
	CHECK_EQ(live_sms(), 2);
	cssms_in_done(SM, RXID + 1, true);	/* a stale id is ignored */
	adv(100);
	CHECK(NRX == 1 && live_sms() == 2);
	cssms_in_done(SM, RXID, true);
	adv(100);
	CHECK(NRX == 2 && live_sms() == 1);	/* "one" deleted, "two" waits */
	CHECK_STR(RX[1].text, "two");
	/* given back: it stays and is offered again by a later list */
	cssms_in_done(SM, RXID, false);
	adv(100);
	CHECK_EQ(live_sms(), 1);
	RXRC = CSSMS_TAKEN;
	adv(6000);
	CHECK_EQ(NRX, 3);
	CHECK_STR(RX[2].text, "two");
	CHECK_EQ(live_sms(), 0);
	/* a negative answer: the same */
	RXRC = -ENOMEM;
	fk_net_sms("+8210333", "three", true);
	adv(100);
	CHECK(NRX == 4 && live_sms() == 1);
	RXRC = CSSMS_TAKEN;
	adv(6000);
	CHECK(NRX == 5 && live_sms() == 0);
	cssms_get_status(SM, &st);
	CHECK_EQ(st.work_len, 0);
	teardown();
	RXRC = 0;
}

static void t_rx_drain(void)
{
	struct cssms_status st;
	struct fk_sms *s;
	int i;

	/* what is already in the modem when we start: delivered once, flagged, deleted */
	setup(false);
	fk_net_sms("+8210111", "old one", false);
	fk_net_sms("+8210222", "old two", false);
	s = fk_net_sms("+8210333", "", false);
	snprintf(s->pdu, sizeof(s->pdu), "status-report");
	s->has_text = false;
	s = fk_net_sms_part("+8210444", 2, 1);	/* announced before we listen, still incomplete */
	(void)s;
	/* ... and one of them is announced again by a notification while the drain runs */
	SM = cssms_new(LINE, &CFG);
	fk_notify("messaging.added", FK.sms[0].path, NULL, NULL, NULL, true);
	adv(200);
	CHECK_EQ(NRX, 3);
	CHECK(RX[0].backlog && RX[1].backlog && RX[2].backlog);
	CHECK(!strcmp(RX[0].text, "old one") && !strcmp(RX[1].text, "old two") && RX[2].kind == CSSMS_REPORT);
	cssms_get_status(SM, &st);
	CHECK(st.drained && st.rx_backlog == 3 && st.incomplete == 1);
	CHECK_EQ(live_sms(), 1);	/* the incomplete one stays for its parts */
	/* from now on new messages are not backlog */
	fk_net_sms("+8210555", "new", true);
	adv(10);
	CHECK(NRX == 4 && !RX[3].backlog && !strcmp(RX[3].text, "new"));
	teardown();

	/* more objects than one list holds (32): several passes, every message once, in order */
	setup(false);
	for (i = 0; i < 75; i++) {
		char t[16];

		snprintf(t, sizeof(t), "m%02d", i);
		fk_net_sms("+8210111", t, false);
	}
	SM = cssms_new(LINE, &CFG);
	adv(30000);
	CHECK_EQ(NRX, 75);
	{
		int ok = 1, bl = 1;

		for (i = 0; i < 75 && i < NRX; i++) {
			char t[16];

			snprintf(t, sizeof(t), "m%02d", i);
			if (strcmp(RX[i].text, t))
				ok = 0;
			if (!RX[i].backlog)
				bl = 0;
		}
		CHECK(ok && bl);
	}
	CHECK_EQ(live_sms(), 0);
	cssms_get_status(SM, &st);
	CHECK(st.drained && st.rx_deleted == 75 && st.work_len == 0);
	teardown();

	/* the drain waits for the modem to be enabled: nothing is asked of a disabled modem */
	env_line(NULL);
	strcpy(FK.mstate, "disabled");
	csline_ev_uqmid_up(LINE, true);
	adv(100);
	fk_net_sms("+8210111", "stored", false);
	cssms_cfg_defaults(&CFG);
	CFG.on_message = on_msg;
	NRX = 0;
	SM = cssms_new(LINE, &CFG);
	adv(100);
	CHECK(FK.n[CSU_SMS_LIST] == 0 && NRX == 0);
	fk_modem_state("enabled", NULL, NULL, true);
	adv(500);
	CHECK(NRX == 1 && RX[0].backlog);
	teardown();

	/* a new modem object (SIM swap): the drain runs again for it */
	setup(true);
	fk_net_sms("+8210111", "after", true);
	adv(10);
	CHECK_EQ(NRX, 1);
	FK.modem_listed = false;
	fk_modem_remove();
	adv(10);
	memset(FK.sms, 0, sizeof(FK.sms));
	strcpy(FK.modem, "uqmid.modem.3");
	fk_net_sms("+8210111", "on the new modem", false);
	FK.modem_listed = true;
	fk_modem_add();
	adv(3500);
	CHECK(NRX == 2 && RX[1].backlog && !strcmp(RX[1].text, "on the new modem"));
	teardown();
}

static void t_rx_faults(void)
{
	struct cssms_status st;

	/* a delete that fails is retried, the message is not delivered twice */
	setup(true);
	fk_net_sms("+8210111", "x", false);
	fk_notify("messaging.added", FK.sms[0].path, NULL, NULL, NULL, true);
	fk_fail_next(CSU_SMS_DELETE, 2, CSU_E_FAILED, "failed", "Couldn't delete");
	adv(10);
	CHECK_EQ(NRX, 1);
	CHECK_EQ(live_sms(), 1);
	adv(5100);
	adv(5100);
	CHECK_EQ(live_sms(), 0);
	CHECK_EQ(NRX, 1);
	cssms_get_status(SM, &st);
	CHECK(st.rx_deleted == 1 && st.rx_delete_failed == 0);
	/* ... until it gives up */
	fk_net_sms("+8210111", "y", false);
	fk_notify("messaging.added", FK.sms[0].path, NULL, NULL, NULL, true);
	fk_fail_next(CSU_SMS_DELETE, 9, CSU_E_FAILED, "failed", "Couldn't delete");
	adv(20000);
	CHECK_EQ(NRX, 2);
	cssms_get_status(SM, &st);
	CHECK(st.rx_delete_failed == 1 && st.work_len == 0 && strstr(st.last_error, "delete"));
	/* an unreadable object (gone meanwhile) is skipped */
	{
		struct fk_sms *s = fk_net_sms("+8210111", "z", false);
		char p[64];

		snprintf(p, sizeof(p), "%s", s->path);
		FK.fail[CSU_SMS_GET].count = 0;
		fk_fail_next(CSU_SMS_GET, 1, CSU_E_GONE, "not-found", "gone");
		fk_notify("messaging.added", p, NULL, NULL, NULL, true);
		adv(10);
		CHECK_EQ(NRX, 2);
	}
	/* a message while the modem object is replaced: nothing is delivered from the stale object */
	teardown();

	/* the callback may be slow to be installed or absent: messages are still deleted */
	env_line(NULL);
	env_up();
	cssms_cfg_defaults(&CFG);
	CFG.on_message = NULL;
	SM = cssms_new(LINE, &CFG);
	fk_net_sms("+8210111", "nobody listens", true);
	adv(100);
	CHECK_EQ(live_sms(), 0);
	teardown();
}

/* ------------------------------------------------------------------ outgoing */

static struct { int n; struct cssms_result r[16]; } DONE;

static void on_done(void *arg, const struct cssms_result *r)
{
	(void)arg;
	if (DONE.n < 16)
		DONE.r[DONE.n] = *r;
	DONE.n++;
}

static int submit(const char *dest, const char *text)
{
	struct cssms_submit q = { .dest = dest, .text = text };

	return cssms_submit(SM, &q, on_done, NULL);
}

static void t_tx(void)
{
	char big[3000];
	int i;

	setup(true);
	memset(&DONE, 0, sizeof(DONE));
	CHECK_EQ(submit("+821051226862", "hi there"), 0);
	CHECK_EQ(DONE.n, 0);
	adv(10);
	CHECK_EQ(DONE.n, 1);
	CHECK(DONE.r[0].status == 200 && DONE.r[0].parts == 1);
	CHECK_STR(FK.last_dest, "+821051226862");
	CHECK_STR(FK.last_text, "hi there");
	CHECK_STR(FK.order, "lcsd");		/* (the start-up list), create, send, delete */
	CHECK_EQ(live_sms(), 0);

	/* in order, one at a time */
	memset(&DONE, 0, sizeof(DONE));
	FK.order[0] = 0;
	FK.hold[CSU_SMS_SEND] = true;
	CHECK_EQ(submit("0101", "one"), 0);
	CHECK_EQ(submit("0102", "two"), 0);
	CHECK_EQ(submit("0103", "three"), 0);
	adv(100);
	CHECK_EQ(FK.n[CSU_SMS_CREATE], 2);	/* cumulative: only the first of these three has started */
	fk_release(CSU_SMS_SEND);
	adv(100);
	CHECK_EQ(DONE.n, 3);
	CHECK_STR(FK.order, "csdcsdcsd");
	CHECK_STR(FK.last_dest, "0103");

	/* long text: counted like the relay does */
	memset(&DONE, 0, sizeof(DONE));
	memset(big, 'a', 400);
	big[400] = 0;
	CHECK_EQ(submit("0101", big), 0);
	adv(10);
	CHECK(DONE.n == 1 && DONE.r[0].status == 200 && DONE.r[0].parts == 3);
	for (i = 0; i < 1700; i++)
		big[i] = 'a';
	big[1700] = 0;			/* 12 parts of 153 */
	CHECK_EQ(submit("0101", big), -E2BIG);
	CHECK_EQ(cssms_status_of_errno(-E2BIG), 413);
	CHECK_EQ(submit("0101", ""), -EINVAL);
	CHECK_EQ(submit("0101", "\xFF\xFE"), -EINVAL);
	CHECK_EQ(submit("01a1", "x"), -EDESTADDRREQ);
	CHECK_EQ(submit("", "x"), -EDESTADDRREQ);
	CHECK_EQ(submit("123456789012345678901", "x"), -EDESTADDRREQ);
	CHECK_EQ(submit("+8210", NULL), -EINVAL);
	adv(10);
	CHECK_EQ(DONE.n, 1);			/* none of the refused ones calls back */

	/* failures and their codes */
	{
		static const struct { int err; const char *name, *msg; int status; } F[] = {
			{ CSU_E_TIMEOUT, "timeout", "Timed out", 504 },
			{ CSU_E_STATE, "wrong-state", "Modem is not enabled", 480 },
			{ CSU_E_FAILED, "failed", "Couldn't send SMS part: QMI operation failed: WMS message delivery failure", 502 },
			{ CSU_E_FAILED, "failed", "Couldn't send SMS part: QMI operation failed: WMS cause code", 502 },
			{ CSU_E_FAILED, "failed", "Couldn't send SMS part: QMI operation failed: Network not ready", 503 },
			{ CSU_E_FAILED, "failed", "Couldn't send SMS part: QMI operation failed: No radio", 503 },
			{ CSU_E_FAILED, "failed", "Couldn't send SMS part: QMI operation failed: timed out", 504 },
			{ CSU_E_ARGS, "invalid-args", "Cannot create SMS: invalid number", 484 },
			{ CSU_E_GONE, "aborted", "Modem went away", 503 },
			{ CSU_E_CONN, "", "no ubus connection", 503 },
			{ CSU_E_BUSY, "in-progress", "Another operation on this SMS is running", 503 },
		};

		for (i = 0; i < (int)(sizeof(F) / sizeof(F[0])); i++) {
			memset(&DONE, 0, sizeof(DONE));
			fk_fail_next(CSU_SMS_SEND, 1, F[i].err, F[i].name, F[i].msg);
			CHECK_EQ(submit("0101", "x"), 0);
			adv(10);
			CHECK(DONE.n == 1 && DONE.r[0].status == F[i].status);
			if (DONE.r[0].status != F[i].status)
				printf("  case %d: %d != %d\n", i, DONE.r[0].status, F[i].status);
			CHECK_EQ(live_sms(), 0);	/* the object of a failed send is deleted too */
		}
		memset(&DONE, 0, sizeof(DONE));
		fk_fail_next(CSU_SMS_CREATE, 1, CSU_E_STATE, "wrong-state", "Modem is not enabled");
		submit("0101", "x");
		adv(10);
		CHECK(DONE.n == 1 && DONE.r[0].status == 480 && strstr(DONE.r[0].text, "wrong-state"));
		memset(&DONE, 0, sizeof(DONE));
		fk_fail_next(CSU_SMS_CREATE, 1, CSU_E_FAILED, "failed", "Cannot create SMS: too many messages, delete some");
		submit("0101", "x");
		adv(10);
		CHECK(DONE.n == 1 && DONE.r[0].status == 502);	/* (not a reason to retry blindly: the text says what it is) */
	}

	/* the modem is stuck: 504 after the timeout, the late answer does not confuse the next message */
	memset(&DONE, 0, sizeof(DONE));
	FK.hold[CSU_SMS_SEND] = true;
	submit("0101", "stuck");
	submit("0102", "next");
	adv(119000);
	CHECK_EQ(DONE.n, 0);
	adv(2000);
	CHECK(DONE.n >= 1 && DONE.r[0].status == 504);
	fk_release(CSU_SMS_SEND);
	adv(100);
	CHECK_EQ(DONE.n, 2);
	CHECK(DONE.r[1].status == 200);
	CHECK_EQ(live_sms(), 0);

	/* the modem goes away while one is on its way */
	memset(&DONE, 0, sizeof(DONE));
	FK.hold[CSU_SMS_SEND] = true;
	submit("0101", "gone");
	submit("0102", "queued");
	adv(10);
	FK.modem_listed = false;
	fk_modem_remove();
	adv(10);
	CHECK_EQ(DONE.n, 2);
	CHECK(DONE.r[0].status == 503 && DONE.r[1].status == 503);
	fk_release(CSU_SMS_SEND);
	adv(100);
	CHECK_EQ(DONE.n, 2);			/* exactly one result each */
	CHECK_EQ(submit("0101", "x"), -ENOTCONN);	/* no line */
	teardown();

	/* queue limit; a line that cannot send */
	setup(true);
	memset(&DONE, 0, sizeof(DONE));
	FK.hold[CSU_SMS_CREATE] = true;
	for (i = 0; i < 8; i++)
		CHECK_EQ(submit("0101", "q"), 0);
	CHECK_EQ(submit("0101", "q"), -ENOBUFS);
	CHECK_EQ(cssms_status_of_errno(-ENOBUFS), 503);
	{
		struct cssms_status st;

		cssms_get_status(SM, &st);
		CHECK_EQ(st.mo_queue, 8);
	}
	/* freed with messages queued: every one is answered 503 once */
	cssms_free(SM);
	SM = NULL;
	CHECK_EQ(DONE.n, 8);
	CHECK(DONE.r[0].status == 503 && DONE.r[7].status == 503);
	fk_release(CSU_SMS_CREATE);
	adv(100);
	CHECK_EQ(DONE.n, 8);
	env_down();

	setup(true);
	fk_modem_state("registered", "searching", NULL, true);
	adv(500);
	CHECK_EQ(submit("0101", "x"), -ENOTCONN);
	fk_modem_state("registered", "home-sms-only", NULL, true);	/* SMS works without voice */
	adv(500);
	memset(&DONE, 0, sizeof(DONE));
	CHECK_EQ(submit("0101", "x"), 0);
	adv(10);
	CHECK(DONE.n == 1 && DONE.r[0].status == 200);
	teardown();

	/* the text reaches uqmid as it is (UTF-8, Hangul) */
	setup(true);
	memset(&DONE, 0, sizeof(DONE));
	CHECK_EQ(submit("+821051226862", "\xEC\x95\x88\xEB\x85\x95 \xF0\x9F\x98\x80"), 0);
	adv(10);
	CHECK_STR(FK.last_text, "\xEC\x95\x88\xEB\x85\x95 \xF0\x9F\x98\x80");
	CHECK(DONE.n == 1 && DONE.r[0].parts == 1);
	teardown();
}

/* a message nobody takes: 20 quick passes, then one per slow_retry_ms; the object is never deleted, a kick starts quick passes again */
static void t_rx_kept_bound(void)
{
	struct cssms_status st;
	int n;

	setup(false);
	CFG.slow_retry_ms = 60000;
	SM = cssms_new(LINE, &CFG);
	adv(100);
	RXRC = -EAGAIN;
	fk_net_sms("+8210111", "kept", true);
	adv(100);
	CHECK(NRX == 1 && live_sms() == 1);
	adv(5100L * 25);			/* well beyond 20 passes */
	n = NRX;
	CHECK(n >= 15 && n <= 25);		/* bounded: the quick passes stopped */
	CHECK_EQ(live_sms(), 1);		/* ... and the object is still in the modem */
	adv(30000);
	CHECK_EQ(NRX, n);			/* between the slow passes nothing happens */
	adv(40000);
	CHECK_EQ(NRX, n + 1);			/* the slow pass */
	CHECK_EQ(live_sms(), 1);
	cssms_get_status(SM, &st);
	CHECK_EQ(st.rx_kept, 1);
	/* a kick: offered at once, taken now, deleted */
	RXRC = CSSMS_TAKEN;
	cssms_kick(SM);
	adv(500);
	CHECK_EQ(NRX, n + 2);
	CHECK_EQ(live_sms(), 0);
	/* the retry bound again after a kick: kept messages still stay */
	RXRC = -EAGAIN;
	fk_net_sms("+8210222", "kept2", true);
	adv(100);
	adv(5100L * 30);
	CHECK_EQ(live_sms(), 1);
	cssms_kick(SM);
	adv(500);
	n = NRX;
	adv(5100);
	CHECK(NRX > n);				/* quick passes again after the kick */
	RXRC = CSSMS_TAKEN;
	cssms_kick(SM);
	adv(500);
	CHECK_EQ(live_sms(), 0);
	teardown();
	RXRC = 0;
}

void test_sms(void)
{
	t_rx_basic();
	t_rx_multipart();
	t_rx_pending();
	t_rx_drain();
	t_rx_kept_bound();
	t_rx_faults();
	t_tx();
}
