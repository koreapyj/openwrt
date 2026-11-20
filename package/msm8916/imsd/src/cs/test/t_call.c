/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include "tcommon.h"

#define OPS (&cscall_carrier_ops)

struct got {
	enum cc_event_type type;
	int status, cause;
	bool by_remote;
	enum cc_media_kind mk;
	char reason[128];
};

static struct got EV[64];
static int NEV;
static struct carrier_call *CALL;
static struct cscall_mgr *CM;
static struct cscall_cfg CFG;
static int n_incoming, incoming_rc;
static struct cc_incoming IN;
static struct carrier_call *IN_CALL;
static bool install_handler = true;

static void on_ev(struct carrier_call *c, const struct cc_event *e, void *arg)
{
	(void)c;
	(void)arg;
	if (NEV < 64) {
		EV[NEV].type = e->type;
		EV[NEV].status = e->status;
		EV[NEV].cause = e->cause;
		EV[NEV].by_remote = e->by_remote;
		EV[NEV].mk = e->media_kind;
		snprintf(EV[NEV].reason, sizeof(EV[NEV].reason), "%s", e->reason);
		NEV++;
	}
}

static int on_incoming(struct carrier_call *c, const struct cc_incoming *in, void *arg)
{
	(void)arg;
	n_incoming++;
	IN = *in;
	IN_CALL = c;
	if (incoming_rc)
		return incoming_rc;
	if (install_handler)
		OPS->set_handler(c, on_ev, NULL);
	return 0;
}

static int count(enum cc_event_type t)
{
	int i, n = 0;

	for (i = 0; i < NEV; i++)
		n += EV[i].type == t;
	return n;
}

static int terminals(void)
{
	return count(CC_EV_FAILED) + count(CC_EV_CANCELLED) + count(CC_EV_TERMINATED);
}

static const struct got *last(void)
{
	return NEV ? &EV[NEV - 1] : NULL;
}

static void setup(void)
{
	env_line(NULL);
	env_up();
	cscall_cfg_defaults(&CFG);
	CFG.on_incoming = on_incoming;
	CM = cscall_mgr_new(LINE, &CFG);
	NEV = 0;
	CALL = NULL;
	IN_CALL = NULL;
	n_incoming = 0;
	incoming_rc = 0;
	install_handler = true;
	adv(1100);			/* the start-up rescan */
}

static void teardown(void)
{
	cscall_mgr_free(CM);
	CM = NULL;
	env_down();
}

static int dial(const char *num)
{
	struct cc_dial d = { .target = num };

	NEV = 0;
	return OPS->dial(CM, &d, on_ev, NULL, &CALL);
}

static const char *P(int i)
{
	return FK.call[i].path;
}

/* the live call object of the fake with the given direction */
static struct fk_call *fcall(void)
{
	int i;

	for (i = 0; i < FK_CALLS; i++)
		if (FK.call[i].used)
			return &FK.call[i];
	return NULL;
}

static void to_active_mo(void)
{
	CHECK(dial("01099998888") == 0);
	adv(10);
	fk_net_state(fcall()->path, "ringing-out", "unknown");
	fk_net_state(fcall()->path, "active", "unknown");
}

/* ------------------------------------------------------------------ MO */

static void t_mo_happy(void)
{
	const struct got *g;
	struct cscall_status st;
	struct cc_info info[2];
	char path[64];

	setup();
	CHECK_EQ(dial("010-1234-5678"), 0);
	CHECK(CALL != NULL && NEV == 0);	/* never a callback from inside dial() */
	CHECK(OPS->state(CALL) == CC_ST_DIALING && OPS->direction(CALL) == CC_MO);
	adv(10);
	CHECK_STR(FK.order, "CS");
	CHECK_STR(FK.last_create_num, "01012345678");
	CHECK_STR(fcall()->state, "dialing");
	CHECK(NEV == 0 && OPS->state(CALL) == CC_ST_DIALING);
	CHECK_EQ(OPS->count(CM), 1);
	CHECK_EQ(OPS->list(CM, info, 2), 1);
	CHECK(info[0].dir == CC_MO && info[0].media_kind == CC_MEDIA_PCM);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	/* alerting: ringback and the early media path */
	fk_net_state(path, "ringing-out", "unknown");
	CHECK_EQ(NEV, 4);
	CHECK(EV[0].type == CC_EV_RINGING && EV[0].status == 180);
	CHECK(EV[1].type == CC_EV_PROGRESS && EV[1].status == 180);
	CHECK(EV[2].type == CC_EV_PROGRESS && EV[2].status == 183);
	CHECK(EV[3].type == CC_EV_EARLY_MEDIA && EV[3].mk == CC_MEDIA_PCM);
	CHECK(OPS->state(CALL) == CC_ST_EARLY);
	fk_net_state(path, "ringing-out", "unknown");	/* duplicate */
	CHECK_EQ(NEV, 4);
	fk_net_state(path, "active", "unknown");
	CHECK_EQ(NEV, 5);
	CHECK(EV[4].type == CC_EV_ANSWERED && EV[4].status == 200);
	CHECK(OPS->state(CALL) == CC_ST_CONNECTED);
	fk_net_state(path, "active", "unknown");
	CHECK_EQ(NEV, 5);
	/* DTMF: one digit at a time, in order, uqmid being busy once */
	FK.dtmf_busy_once = true;
	CHECK_EQ(OPS->send_dtmf(CALL, '1'), 0);
	CHECK_EQ(OPS->send_dtmf(CALL, '2'), 0);
	CHECK_EQ(OPS->send_dtmf(CALL, '#'), 0);
	CHECK_EQ(OPS->send_dtmf(CALL, 'x'), -EINVAL);
	CHECK_EQ(OPS->send_dtmf(CALL, 'b'), 0);	/* lower case accepted */
	CHECK_EQ(FK.n[CSU_CALL_DTMF], 0);		/* nothing synchronous */
	adv(1000);
	CHECK_STR(FK.dig, "12#B");
	CHECK_EQ(FK.n[CSU_CALL_DTMF], 5);		/* four digits + the busy retry */
	cscall_mgr_status(CM, &st);
	CHECK(st.dtmf_sent == 4 && st.dtmf_dropped == 0 && st.mo == 1 && st.answered == 1);
	/* hold: the call stays up, no request */
	{
		int reqs = FK.n[CSU_CALL_HANGUP] + FK.n[CSU_CALL_GET];

		CHECK_EQ(OPS->set_hold(CALL, true), 0);
		CHECK_EQ(OPS->set_hold(CALL, false), 0);
		CHECK_EQ(FK.n[CSU_CALL_HANGUP] + FK.n[CSU_CALL_GET], reqs);
	}
	CHECK(OPS->get_media(CALL, NULL) == false);
	/* the LAN side hangs up */
	CHECK_EQ(OPS->hangup(CALL), 0);
	CHECK_EQ(NEV, 5);			/* the terminal event comes from the loop */
	adv(10);
	CHECK_EQ(terminals(), 1);
	g = last();
	CHECK(g->type == CC_EV_TERMINATED && !g->by_remote);
	CHECK_EQ(fk_live_calls(), 0);		/* the object was deleted */
	CHECK(strstr(FK.order, "HD") != NULL);
	CHECK_EQ(OPS->count(CM), 0);
	adv(10);
	teardown();
}

static void t_mo_variants(void)
{
	const struct got *g;
	char path[64];

	/* early media only at the answer */
	setup();
	CFG.early_media = false;
	cscall_mgr_set_cfg(CM, &CFG);
	dial("114");
	adv(10);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	fk_net_state(path, "ringing-out", "unknown");
	CHECK_EQ(NEV, 2);
	CHECK(EV[0].type == CC_EV_RINGING && EV[1].type == CC_EV_PROGRESS && EV[1].status == 180);
	fk_net_state(path, "active", "unknown");
	CHECK_EQ(NEV, 4);
	CHECK(EV[2].type == CC_EV_EARLY_MEDIA && EV[3].type == CC_EV_ANSWERED);
	teardown();

	/* active before any ringing-out (a network that connects at once): early media, then answered; the late ringing-out is ignored */
	setup();
	dial("114");
	adv(10);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	fk_net_state(path, "active", "unknown");
	CHECK_EQ(NEV, 2);
	CHECK(EV[0].type == CC_EV_EARLY_MEDIA && EV[1].type == CC_EV_ANSWERED);
	fk_net_state(path, "ringing-out", "unknown");
	fk_net_state(path, "dialing", "unknown");
	CHECK_EQ(NEV, 2);
	CHECK(OPS->state(CALL) == CC_ST_CONNECTED);
	/* the network ends it */
	fk_net_state(path, "terminated", "unknown");
	CHECK_EQ(terminals(), 1);
	g = last();
	CHECK(g->type == CC_EV_TERMINATED && g->by_remote && g->status == 0);
	fk_net_state(path, "terminated", "unknown");	/* a duplicate */
	fk_net_state(path, "active", "unknown");	/* ... and a straggler */
	CHECK_EQ(terminals(), 1);
	adv(10);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* refused before alerting (busy, unallocated ... : the modem does not say which) */
	setup();
	dial("01000000000");
	adv(10);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	fk_net_state(path, "terminated", "unknown");
	CHECK_EQ(NEV, 1);
	g = last();
	CHECK(g->type == CC_EV_FAILED && g->status == 503 && g->by_remote && strstr(g->reason, "no cause"));
	adv(10);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* declined while alerting (fast) = 603; unanswered (slow) = 480 */
	setup();
	dial("01000000000");
	adv(10);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	fk_net_state(path, "ringing-out", "unknown");
	adv(1500);
	fk_net_state(path, "terminated", "unknown");
	g = last();
	CHECK(g->type == CC_EV_FAILED && g->status == 603);
	teardown();
	setup();
	dial("01000000000");
	adv(10);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	fk_net_state(path, "ringing-out", "unknown");
	adv(4500);
	fk_net_state(path, "terminated", "unknown");
	g = last();
	CHECK(g->type == CC_EV_FAILED && g->status == 480);
	teardown();

	/* a lost notification: the periodic read finds the end, with a cause if uqmid ever reports one */
	setup();
	dial("01000000000");
	adv(10);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	fk_net_state(path, "ringing-out", "unknown");
	fcall()->end_cause = 17;
	fk_net_state_quiet(path, "terminated");
	CHECK_EQ(terminals(), 0);
	adv(5100);
	CHECK_EQ(terminals(), 1);
	g = last();
	CHECK(g->type == CC_EV_FAILED && g->status == 486 && g->cause == 17 && strstr(g->reason, "user busy"));
	teardown();

	/* end cause sources, in order: cc_cause, else the QMI end reason, else the timing heuristic */
	{
		static const struct { int cause, er; const char *name; bool alert; int status; } t[] = {
			{ 17, 141, "unassigned-number", true, 486 },	/* cc_cause wins over a different end reason */
			{ 0, 146, "user-busy", false, 486 },
			{ 0, 141, "unassigned-number", false, 404 },
			{ 0, 115, "call-barred", false, 403 },
			{ 0, 144, "operator-determined-barring", true, 403 },
			{ 0, 135, "rejected-by-network", true, 603 },	/* a slow decline is still a rejection when the modem says so */
			{ 0, 148, "user-alerting-no-answer", true, 480 },
			{ 0, 145, "normal-call-clearing", false, 480 },	/* never connected: no answer */
			{ 0, 104, "network-end", true, 480 },
			{ 0, 29, "client-end", true, 480 },
			{ 0, 0, "", true, 480 },			/* neither: the timing says 480 after a long alerting */
			{ 0, 0, "", false, 503 },			/* neither, before alerting */
		};
		unsigned i;

		for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
			setup();
			dial("01000000000");
			adv(10);
			snprintf(path, sizeof(path), "%s", fcall()->path);
			if (t[i].alert) {
				fk_net_state(path, "ringing-out", "unknown");
				adv(5000);
			}
			fk_set_end(path, t[i].cause, t[i].er, t[i].name);
			fk_net_state(path, "terminated", "unknown");
			CHECK_EQ(terminals(), 1);
			g = last();
			CHECK(g->type == CC_EV_FAILED && g->status == t[i].status && g->cause == t[i].cause);
			if (t[i].er)
				CHECK(strstr(g->reason, t[i].name) != NULL);
			{
				struct cscall_status cst;

				cscall_mgr_status(CM, &cst);
				CHECK(strstr(cst.last_end, g->reason) != NULL);	/* shown in the status */
			}
			teardown();
		}
	}

	/* the same through a lost notification (call get): the end reason alone, and after the answer a normal end has no status */
	setup();
	dial("01000000000");
	adv(10);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	fk_net_state(path, "ringing-out", "unknown");
	fk_set_end(path, 0, 146, "user-busy");
	fk_net_state_quiet(path, "terminated");
	adv(5100);
	g = last();
	CHECK(g->type == CC_EV_FAILED && g->status == 486 && g->cause == 0 && strstr(g->reason, "user-busy"));
	teardown();
	setup();
	dial("01000000000");
	adv(10);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	fk_net_state(path, "ringing-out", "unknown");
	fk_net_state(path, "active", "unknown");
	fk_set_end(path, 0, 145, "normal-call-clearing");
	fk_net_state(path, "terminated", "unknown");
	g = last();
	CHECK(g->type == CC_EV_TERMINATED && g->by_remote && g->status == 0 && strstr(g->reason, "normal call clearing"));
	teardown();

	/* the call object vanishes (deleted elsewhere) */
	setup();
	dial("01000000000");
	adv(10);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	fk_net_state(path, "ringing-out", "unknown");
	fcall()->used = false;
	adv(5100);
	CHECK_EQ(terminals(), 1);
	CHECK(last()->type == CC_EV_FAILED);
	teardown();

	/* no answer: our own timeout cancels the call (like the INVITE timeout of gm) */
	setup();
	CFG.ring_timeout_s = 30;
	cscall_mgr_set_cfg(CM, &CFG);
	dial("01000000000");
	adv(10);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	fk_net_state(path, "ringing-out", "unknown");
	adv(29000);
	CHECK_EQ(terminals(), 0);
	adv(2000);
	CHECK_EQ(terminals(), 1);
	g = last();
	CHECK(g->type == CC_EV_CANCELLED && !g->by_remote && g->status == 480);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* cancel while ringing (the LAN device hung up) */
	setup();
	dial("01000000000");
	adv(10);
	snprintf(path, sizeof(path), "%s", fcall()->path);
	fk_net_state(path, "ringing-out", "unknown");
	NEV = 0;
	CHECK_EQ(OPS->hangup(CALL), 0);
	CHECK_EQ(OPS->state(CALL), CC_ST_CANCELLING);
	adv(10);
	CHECK_EQ(NEV, 1);
	CHECK(EV[0].type == CC_EV_CANCELLED && !EV[0].by_remote);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();
}

static void t_mo_errors(void)
{
	const struct got *g;

	/* validation and refusals: -errno, no event */
	setup();
	{
		struct cc_dial d = { .target = "abc" };
		struct carrier_call *c = NULL;

		CHECK_EQ(OPS->dial(CM, &d, on_ev, NULL, &c), -EINVAL);
		d.target = "";
		CHECK_EQ(OPS->dial(CM, &d, on_ev, NULL, &c), -EINVAL);
		d.target = "sip:114@x";
		CHECK_EQ(OPS->dial(CM, &d, on_ev, NULL, &c), -EINVAL);
		CHECK(c == NULL && FK.n[CSU_CALL_CREATE] == 0);
		fk_modem_state("enabled", "searching", NULL, true);
		adv(500);
		d.target = "114";
		CHECK_EQ(OPS->dial(CM, &d, on_ev, NULL, &c), -ENOTCONN);
		fk_modem_state("registered", "home", NULL, true);
		adv(500);
	}
	/* a call is active: the second attempt is refused (the LAN device gets 486) */
	{
		struct cc_dial d = { .target = "114" };
		struct carrier_call *c2 = NULL;
		struct cscall_status st;

		CHECK_EQ(dial("01011112222"), 0);
		CHECK_EQ(OPS->dial(CM, &d, on_ev, NULL, &c2), -EBUSY);
		adv(10);
		CHECK_EQ(OPS->dial(CM, &d, on_ev, NULL, &c2), -EBUSY);
		cscall_mgr_status(CM, &st);
		CHECK(st.busy_refused == 2 && st.live == 1);
		OPS->hangup(CALL);
		adv(10);
		CHECK_EQ(fk_live_calls(), 0);
		adv(10);
		CHECK_EQ(OPS->dial(CM, &d, on_ev, NULL, &c2), 0);	/* free again */
		adv(10);
		OPS->release(c2);
		adv(10);
		CHECK_EQ(fk_live_calls(), 0);
	}
	teardown();

	/* uqmid refuses to create / start */
	setup();
	fk_fail_next(CSU_CALL_CREATE, 1, CSU_E_STATE, "wrong-state", "Modem is not enabled");
	dial("114");
	CHECK_EQ(NEV, 0);
	adv(10);
	g = last();
	CHECK(NEV == 1 && g->type == CC_EV_FAILED && g->status == 503);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();
	setup();
	fk_fail_next(CSU_CALL_CREATE, 1, CSU_E_TIMEOUT, "timeout", "Timed out");
	dial("114");
	adv(10);
	CHECK(NEV == 1 && last()->type == CC_EV_FAILED && last()->status == 408);
	teardown();
	setup();
	FK.emerg = true;		/* uqmid: registered no more, only emergency numbers */
	dial("114");
	adv(10);
	g = last();
	CHECK(NEV == 1 && g->type == CC_EV_FAILED && g->status == 403);
	adv(10);
	CHECK_EQ(fk_live_calls(), 0);	/* the object of the refused call is deleted too */
	teardown();
	setup();
	fk_fail_next(CSU_CALL_START, 1, CSU_E_FAILED, "failed", "Couldn't create call");
	dial("114");
	adv(10);
	g = last();
	CHECK(NEV == 1 && g->type == CC_EV_FAILED && g->status == 503);
	adv(10);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* the modem does not answer the dial in time */
	setup();
	FK.hold[CSU_CALL_CREATE] = true;
	dial("114");
	adv(19000);
	CHECK_EQ(NEV, 0);
	adv(2000);
	CHECK(NEV == 1 && last()->type == CC_EV_FAILED && last()->status == 408);
	fk_release(CSU_CALL_CREATE);	/* the late create is turned into a delete */
	adv(100);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* hangup while the create is still in flight */
	setup();
	FK.hold[CSU_CALL_CREATE] = true;
	dial("114");
	adv(10);
	CHECK_EQ(OPS->hangup(CALL), 0);
	adv(10);
	CHECK(NEV == 1 && last()->type == CC_EV_CANCELLED);
	CHECK_EQ(FK.n[CSU_CALL_START], 0);
	fk_release(CSU_CALL_CREATE);
	adv(100);
	CHECK_EQ(FK.n[CSU_CALL_START], 0);	/* never dialled */
	CHECK_EQ(fk_live_calls(), 0);
	teardown();
}

/* ------------------------------------------------------------------ MT */

static void t_mt(void)
{
	struct fk_call *fc;
	char path[64];
	const struct got *g;

	/* answered, then the caller hangs up */
	setup();
	fc = fk_net_ring("+82 10-5122-6862");
	snprintf(path, sizeof(path), "%s", fc->path);
	adv(10);
	CHECK_EQ(n_incoming, 1);
	CHECK_STR(IN.caller.number, "+821051226862");
	CHECK_STR(IN.caller.uri, "tel:+821051226862");
	CHECK(!IN.caller.anonymous && IN.media_kind == CC_MEDIA_PCM && IN.backend_cs);
	CHECK_STR(IN.called, "+821012345678");
	CALL = IN_CALL;
	CHECK(OPS->state(CALL) == CC_ST_INCOMING && OPS->direction(CALL) == CC_MT);
	CHECK_STR(OPS->remote(CALL)->number, "+821051226862");
	CHECK_EQ(OPS->ring(CALL), 0);
	CHECK_EQ(FK.n[CSU_CALL_ACCEPT], 0);
	CHECK_EQ(OPS->answer(CALL, NULL), 0);
	CHECK_EQ(OPS->answer(CALL, NULL), -EINVAL);	/* once */
	CHECK(OPS->state(CALL) == CC_ST_ANSWERING);
	adv(10);
	CHECK_STR(fk_find_call(path)->state, "active");
	CHECK(OPS->state(CALL) == CC_ST_CONNECTED);
	CHECK_EQ(count(CC_EV_ANSWERED), 1);
	CHECK_EQ(NEV, 1);			/* one ANSWERED, although uqmid also notified "active" */
	CHECK_EQ(OPS->send_dtmf(CALL, '5'), 0);
	adv(10);
	CHECK_STR(FK.dig, "5");
	fk_net_state(path, "terminated", "unknown");
	CHECK_EQ(terminals(), 1);
	g = last();
	CHECK(g->type == CC_EV_TERMINATED && g->by_remote);
	adv(10);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* the caller gives up while it rings */
	setup();
	fc = fk_net_ring("01051226862");
	snprintf(path, sizeof(path), "%s", fc->path);
	adv(10);
	CALL = IN_CALL;
	fk_net_state(path, "terminated", "unknown");
	CHECK_EQ(NEV, 1);
	g = last();
	CHECK(g->type == CC_EV_CANCELLED && g->by_remote && g->status == 487);
	CHECK_EQ(OPS->answer(CALL, NULL), -ESTALE);	/* glare: the LAN side answers a call that is gone */
	CHECK_EQ(FK.n[CSU_CALL_ACCEPT], 0);
	adv(10);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* glare 2: answer() is on its way when the caller hangs up: one terminal event, no second one when the accept fails */
	setup();
	fc = fk_net_ring("01051226862");
	snprintf(path, sizeof(path), "%s", fc->path);
	adv(10);
	CALL = IN_CALL;
	FK.hold[CSU_CALL_ACCEPT] = true;
	CHECK_EQ(OPS->answer(CALL, NULL), 0);
	adv(10);
	fk_net_state(path, "terminated", "unknown");
	CHECK_EQ(terminals(), 1);
	CHECK(last()->type == CC_EV_TERMINATED && last()->by_remote);
	fk_release(CSU_CALL_ACCEPT);
	adv(100);
	CHECK_EQ(terminals(), 1);
	CHECK_EQ(count(CC_EV_ANSWERED), 0);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* the accept fails */
	setup();
	fc = fk_net_ring("01051226862");
	adv(10);
	CALL = IN_CALL;
	fk_fail_next(CSU_CALL_ACCEPT, 1, CSU_E_FAILED, "failed", "Couldn't accept call");
	OPS->answer(CALL, NULL);
	adv(10);
	CHECK_EQ(terminals(), 1);
	CHECK(last()->type == CC_EV_TERMINATED && last()->status == 503 && !last()->by_remote);
	adv(10);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* the LAN side rejects */
	setup();
	fk_net_ring("01051226862");
	adv(10);
	CALL = IN_CALL;
	CHECK_EQ(OPS->reject(CALL, 486), 0);
	CHECK_EQ(NEV, 0);
	adv(10);
	CHECK_EQ(NEV, 1);
	CHECK(EV[0].type == CC_EV_CANCELLED && !EV[0].by_remote && EV[0].status == 486);
	CHECK(!strncmp(FK.order, "GH", 2));	/* read, then hung up (= rejected at the network) ... */
	adv(10);
	CHECK_EQ(fk_live_calls(), 0);		/* ... and deleted */
	teardown();

	/* nobody on the LAN side takes it: the incoming callback refuses */
	setup();
	incoming_rc = -1;
	fk_net_ring("01051226862");
	adv(10);
	CHECK_EQ(n_incoming, 1);
	CHECK_EQ(NEV, 0);
	adv(10);
	CHECK_EQ(FK.n[CSU_CALL_ACCEPT], 0);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* the LAN side never answers: rejected after the ring timeout */
	setup();
	CFG.ring_timeout_s = 20;
	cscall_mgr_set_cfg(CM, &CFG);
	fk_net_ring("01051226862");
	adv(10);
	adv(21000);
	CHECK_EQ(NEV, 1);
	CHECK(EV[0].type == CC_EV_CANCELLED && !EV[0].by_remote && EV[0].status == 480);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* withheld number */
	setup();
	fk_net_ring("");
	adv(10);
	CHECK(n_incoming == 1 && IN.caller.anonymous && !IN.caller.number[0] && !strcmp(IN.caller.uri, "sip:anonymous@anonymous.invalid"));
	teardown();

	/* a hangup of a ringing call by the user of the leg (release) */
	setup();
	fk_net_ring("01051226862");
	adv(10);
	OPS->release(IN_CALL);
	adv(10);
	CHECK_EQ(NEV, 0);			/* detached: no event */
	CHECK_EQ(fk_live_calls(), 0);
	teardown();
}

/* ------------------------------------------------------------------ one call at a time */

static void t_waiting(void)
{
	struct cscall_status st;
	struct fk_call *w;
	char wpath[64], path[64];

	setup();
	to_active_mo();
	snprintf(path, sizeof(path), "%s", P(0));
	CHECK(count(CC_EV_ANSWERED) == 1);
	/* a second call rings at the network: left alone, reported */
	w = fk_net_ring("01077776666");
	snprintf(wpath, sizeof(wpath), "%s", w->path);
	snprintf(w->state, sizeof(w->state), "waiting");
	adv(10);
	CHECK_EQ(n_incoming, 0);
	cscall_mgr_status(CM, &st);
	CHECK(st.waiting == 1 && st.waiting_total == 1 && !strcmp(st.waiting_number, "01077776666") && st.live == 1);
	CHECK_EQ(FK.n[CSU_CALL_ACCEPT], 0);
	CHECK_EQ(FK.n[CSU_CALL_HANGUP], 0);
	CHECK_STR(fk_find_call(wpath)->state, "waiting");
	{
		struct cc_dial d = { .target = "114" };
		struct carrier_call *c2;

		CHECK_EQ(OPS->dial(CM, &d, on_ev, NULL, &c2), -EBUSY);
	}
	/* more notifications about it change nothing */
	fk_net_state(wpath, "ringing-in", "unknown");
	adv(10);
	CHECK_EQ(n_incoming, 0);
	cscall_mgr_status(CM, &st);
	CHECK(st.waiting == 1 && st.waiting_total == 1);
	/* the first call ends: the waiting one is offered as a normal incoming call */
	NEV = 0;
	OPS->hangup(CALL);
	adv(10);
	CHECK(terminals() == 1);
	adv(1000);
	CHECK_EQ(n_incoming, 1);
	CHECK_STR(IN.caller.number, "01077776666");
	CALL = IN_CALL;
	CHECK_EQ(OPS->answer(CALL, NULL), 0);
	adv(10);
	CHECK_STR(fk_find_call(wpath)->state, "active");
	cscall_mgr_status(CM, &st);
	CHECK(st.waiting == 0 && st.live == 1);
	OPS->hangup(CALL);
	adv(10);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* a waiting call that ends before the active one: deleted, never offered */
	setup();
	to_active_mo();
	w = fk_net_ring("01077776666");
	snprintf(wpath, sizeof(wpath), "%s", w->path);
	adv(10);
	fk_net_state(wpath, "terminated", "unknown");
	adv(10);
	cscall_mgr_status(CM, &st);
	CHECK(st.waiting == 0 && n_incoming == 0);
	CHECK(fk_find_call(wpath) == NULL);
	OPS->release(CALL);
	adv(10);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* objects that exist before we start (daemon restart): a ringing call is offered, a terminated one deleted */
	env_line(NULL);
	env_up();
	fk_net_ring("01055554444");
	{
		struct fk_call *t = fk_net_ring("01011110000");

		snprintf(t->state, sizeof(t->state), "terminated");
	}
	cscall_cfg_defaults(&CFG);
	CFG.on_incoming = on_incoming;
	n_incoming = 0;
	NEV = 0;
	CM = cscall_mgr_new(LINE, &CFG);
	adv(2000);
	CHECK_EQ(n_incoming, 1);
	CHECK_STR(IN.caller.number, "01055554444");
	CHECK_EQ(fk_live_calls(), 1);
	teardown();

	/* an active call we did not place (another ubus user): blocks dialling, is not touched */
	env_line(NULL);
	env_up();
	{
		struct fk_call *a = fk_net_ring("01055554444");

		snprintf(a->state, sizeof(a->state), "active");
		snprintf(a->dir, sizeof(a->dir), "outgoing");
	}
	cscall_cfg_defaults(&CFG);
	CM = cscall_mgr_new(LINE, &CFG);
	adv(2000);
	cscall_mgr_status(CM, &st);
	CHECK(st.foreign == 1 && st.live == 0);
	{
		struct cc_dial d = { .target = "114" };
		struct carrier_call *c2;

		CHECK_EQ(OPS->dial(CM, &d, on_ev, NULL, &c2), -EBUSY);
	}
	CHECK_EQ(FK.n[CSU_CALL_HANGUP], 0);
	fk_net_state(P(0), "terminated", "unknown");
	adv(10);
	cscall_mgr_status(CM, &st);
	CHECK(st.foreign == 0 && fk_live_calls() == 0);
	teardown();
}

/* ------------------------------------------------------------------ restarts and failures */

static void t_restart(void)
{
	/* uqmid goes away in the middle of an established call */
	setup();
	to_active_mo();
	NEV = 0;
	csline_ev_uqmid_up(LINE, false);
	CHECK_EQ(NEV, 0);			/* from the loop, not from inside the event */
	adv(10);
	CHECK_EQ(terminals(), 1);
	CHECK(last()->type == CC_EV_TERMINATED && last()->status == 503 && !last()->by_remote && strstr(last()->reason, "modem lost"));
	CHECK_EQ(OPS->count(CM), 0);
	/* it comes back: the old object is still there (uqmid kept it) and is hung up / deleted by a fresh start? it is
	 * not ours any more: it is found as a foreign active call and blocks dialling until it ends */
	FK.call[0].used = false;		/* a restarted uqmid has no objects */
	csline_ev_uqmid_up(LINE, true);
	adv(2000);
	{
		struct cc_dial d = { .target = "114" };
		struct carrier_call *c2 = NULL;

		CHECK_EQ(OPS->dial(CM, &d, on_ev, NULL, &c2), 0);
		adv(10);
		OPS->release(c2);
		adv(10);
	}
	teardown();

	/* the modem object disappears while dialling: FAILED 503; the replies of the old object are ignored */
	setup();
	FK.hold[CSU_CALL_START] = true;
	dial("114");
	adv(10);
	CHECK_EQ(FK.n[CSU_CALL_CREATE], 1);
	FK.modem_listed = false;
	fk_modem_remove();
	adv(10);
	CHECK(NEV == 1 && last()->type == CC_EV_FAILED && last()->status == 503);
	fk_release(CSU_CALL_START);
	adv(100);
	CHECK_EQ(NEV, 1);			/* the stale answer did nothing */
	teardown();

	/* modem removed while an incoming call rings and answering is in flight */
	setup();
	fk_net_ring("01051226862");
	adv(10);
	CALL = IN_CALL;
	FK.hold[CSU_CALL_ACCEPT] = true;
	OPS->answer(CALL, NULL);
	adv(10);
	FK.modem_listed = false;
	fk_modem_remove();
	adv(10);
	CHECK_EQ(terminals(), 1);
	CHECK(last()->type == CC_EV_TERMINATED && last()->status == 503);
	fk_release(CSU_CALL_ACCEPT);
	adv(100);
	CHECK_EQ(terminals(), 1);
	teardown();

	/* uqmid restarts with the call object under a new modem number: calls of the old object end, new calls work */
	setup();
	to_active_mo();
	FK.modem_listed = false;
	fk_modem_remove();
	adv(10);
	CHECK_EQ(terminals(), 1);
	memset(FK.call, 0, sizeof(FK.call));
	strcpy(FK.modem, "uqmid.modem.5");
	FK.modem_listed = true;
	fk_modem_add();
	adv(2000);
	{
		struct cscall_status st;

		cscall_mgr_status(CM, &st);
		CHECK(st.lost_modem == 1);
	}
	CHECK_EQ(dial("114"), 0);
	adv(10);
	CHECK(strstr(fcall()->path, "uqmid.modem.5.call.") != NULL);
	teardown();

	/* the PCM device could not be opened (EBUSY: the other voice device is open) / vanished */
	setup();
	CHECK_EQ(dial("114"), 0);
	adv(10);
	fk_net_state(fcall()->path, "ringing-out", "unknown");
	NEV = 0;
	OPS->media_failed(CALL, EBUSY);
	adv(10);
	CHECK(NEV == 1 && last()->type == CC_EV_FAILED && last()->status == 503 && strstr(last()->reason, "Device or resource busy"));
	CHECK(strstr(FK.order, "H") != NULL);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();
	setup();
	to_active_mo();
	NEV = 0;
	OPS->media_failed(CALL, ENODEV);
	adv(10);
	CHECK(NEV == 1 && last()->type == CC_EV_TERMINATED && last()->status == 503);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* hangup racing with the network: one event, either way */
	setup();
	to_active_mo();
	NEV = 0;
	FK.hold[CSU_CALL_HANGUP] = true;
	OPS->hangup(CALL);
	adv(10);
	fk_net_state(P(0), "terminated", "unknown");
	CHECK_EQ(terminals(), 1);
	CHECK(last()->type == CC_EV_TERMINATED && !last()->by_remote);	/* it was our hangup */
	fk_release(CSU_CALL_HANGUP);
	adv(100);
	CHECK_EQ(terminals(), 1);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* hangup request not answered by uqmid: the end is reported after the wait anyway */
	setup();
	to_active_mo();
	NEV = 0;
	FK.hold[CSU_CALL_HANGUP] = true;
	OPS->hangup(CALL);
	adv(2000);
	CHECK_EQ(terminals(), 0);
	adv(1500);
	CHECK_EQ(terminals(), 1);
	fk_release(CSU_CALL_HANGUP);
	adv(100);
	CHECK_EQ(terminals(), 1);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* release() of an established call: hung up, deleted, no event */
	setup();
	to_active_mo();
	NEV = 0;
	OPS->release(CALL);
	adv(10);
	CHECK_EQ(NEV, 0);
	CHECK_EQ(fk_live_calls(), 0);
	CHECK(strstr(FK.order, "H") && strstr(FK.order, "D"));
	teardown();

	/* DTMF queue limits and states */
	setup();
	CHECK_EQ(dial("114"), 0);
	adv(10);
	CHECK_EQ(OPS->send_dtmf(CALL, '1'), -ENOTCONN);	/* not connected yet */
	fk_net_state(fcall()->path, "active", "unknown");
	FK.hold[CSU_CALL_DTMF] = true;
	{
		int i, ok = 0, full = 0;

		for (i = 0; i < 40; i++) {
			int rc = OPS->send_dtmf(CALL, (char)('0' + i % 10));

			if (rc == 0)
				ok++;
			else if (rc == -ENOBUFS)
				full++;
		}
		CHECK(ok == 32 && full == 8);
	}
	fk_release(CSU_CALL_DTMF);
	adv(2000);
	CHECK_EQ(FK.ndig, 32);
	{
		int i, in_order = 1;

		for (i = 0; i < 32; i++)
			if (FK.dig[i] != (char)('0' + i % 10))
				in_order = 0;
		CHECK(in_order);
	}
	/* a failing digit is dropped, the next ones go on */
	FK.ndig = 0;
	fk_fail_next(CSU_CALL_DTMF, 1, CSU_E_FAILED, "failed", "Couldn't send DTMF character");
	OPS->send_dtmf(CALL, '1');
	OPS->send_dtmf(CALL, '2');
	adv(1000);
	CHECK_STR(FK.dig, "2");
	OPS->hangup(CALL);
	adv(10);
	CHECK_EQ(fk_live_calls(), 0);
	teardown();

	/* the manager is destroyed with a call up: silent */
	setup();
	to_active_mo();
	NEV = 0;
	cscall_mgr_free(CM);
	CM = NULL;
	adv(100);
	CHECK_EQ(NEV, 0);
	env_down();
}

void test_call(void)
{
	t_mo_happy();
	t_mo_variants();
	t_mo_errors();
	t_mt();
	t_waiting();
	t_restart();
}
