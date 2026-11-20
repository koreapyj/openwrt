/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Circuit switched call leg over uqmid, see cscall.h. Facts about uqmid this relies on (sources: uqmid/voice.c):
 *  - voice_create_call only makes the object (state unknown); start dials (state dialing, notification
 *    voice.call_state_changed {path, old, new, reason} on the modem object); QMI call states map 1:1: origination ->
 *    dialing, alerting -> ringing-out, incoming / setup -> ringing-in, conversation -> active, hold -> held, waiting ->
 *    waiting, disconnecting / end -> terminated (voice.c:717).
 *  - a call the network ended is reported only as the state "terminated" with state_reason "unknown": there is no end cause
 *    (the QMI All Call Status indication is decoded without one, common/voice-parse.c). A call we hung up shows
 *    reason "terminated". So the status is inferred (cs_infer_status) unless an "end_cause" field shows up in call get.
 *  - an ended call object stays until voice_delete_call; hangup of an ended call is an error (voice.c:1024).
 *  - send_dtmf takes a string but sends 500 ms per digit and refuses a second one while busy (voice.c:1144).
 *  - a second incoming call while one is active is created as state "waiting" / "ringing-in" (voice.c:698).
 */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cscall.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define DTMF_Q 32
#define MAX_FO 8
#define MAX_REQS 24

enum cu { CU_UNKNOWN, CU_DIALING, CU_RINGING_OUT, CU_RINGING_IN, CU_ACTIVE, CU_HELD, CU_WAITING, CU_TERMINATED };

static enum cu cu_parse(const char *s)
{
	static const char *const n[] = { "unknown", "dialing", "ringing-out", "ringing-in", "active", "held", "waiting", "terminated" };
	unsigned i;

	for (i = 0; i < sizeof(n) / sizeof(n[0]); i++)
		if (!strcmp(s, n[i]))
			return (enum cu)i;
	return CU_UNKNOWN;
}

enum mk { MK_CREATE, MK_START, MK_ACCEPT, MK_HANGUP, MK_GET, MK_DTMF, MK_DELETE, MK_LIST, MK_NEWGET };

struct mreq {
	struct mreq *next;
	struct cscall_mgr *m;
	struct cscall *c;	/* NULL: not bound to a call */
	enum mk kind;
	unsigned gen;
	void *h;
	char path[CSU_PATH];
	bool orphan;		/* MK_CREATE of a call that ended meanwhile: delete what comes back */
	bool fired;
};

struct cscall {
	struct cscall_mgr *m;
	struct cscall *next;
	unsigned id;
	enum cc_dir dir;
	enum cc_state st;
	unsigned gen;
	char path[CSU_PATH];
	struct cc_identity remote;
	char called[48];
	cc_event_cb cb;
	void *arg;
	bool detached, dead;
	enum cu uq;
	bool seen_alert, seen_active, early_sent, answered_sent, answer_asked;
	bool ending, kill_on_path, hold;
	uint64_t t_create, t_alert, t_active;
	/* a terminal event decided but not delivered yet */
	bool pend;
	enum cc_event_type pend_type;
	int pend_status, pend_cause;
	bool pend_remote;
	char pend_reason[128];
	struct ev_timer *t_kick, *t_ring, *t_hup, *t_rec, *t_dtmf;
	char dq[DTMF_Q];
	unsigned dq_n;
	bool dtmf_busy;
};

struct fo {
	char path[CSU_PATH];
	char number[48];
	enum cu st;
	bool incoming;
};

struct cscall_mgr {
	struct csline *line;
	struct cscall_cfg cfg;
	struct cscall *calls, *dead;
	struct mreq *reqs;
	unsigned n_reqs;
	struct ev_timer *t_reap, *t_rescan;
	unsigned next_id;
	struct fo fo[MAX_FO];
	unsigned n_fo;
	struct cscall_status st;
	bool dying;
	bool rescanning;
};

/* ------------------------------------------------------------------ cause table */

/*
 * Q.850 / TS 24.008 annex H cause -> SIP status, after RFC 3398 table 3 (ISUP cause value to SIP response). Values the RFC
 * has no row for are mapped by class (local policy, marked *).
 */
static const struct { int q850; int sip; const char *text; } CAUSES[] = {
	{ 1, 404, "unallocated number" }, { 2, 404, "no route to the specified transit network" }, { 3, 404, "no route to destination" },
	{ 16, 480, "normal call clearing" }, { 17, 486, "user busy" }, { 18, 408, "no user responding" },
	{ 19, 480, "no answer from user" }, { 20, 480, "subscriber absent" }, { 21, 603, "call rejected" },
	{ 22, 410, "number changed" }, { 25, 483, "exchange routing error" }, { 27, 502, "destination out of order" },
	{ 28, 484, "invalid number format" }, { 29, 501, "facility rejected" }, { 31, 480, "normal, unspecified" },
	{ 34, 503, "no circuit / channel available" }, { 38, 503, "network out of order" }, { 41, 503, "temporary failure" },
	{ 42, 503, "switching equipment congestion" }, { 44, 503, "requested circuit / channel not available" },
	{ 47, 503, "resource unavailable, unspecified" }, { 55, 403, "incoming calls barred within the CUG" },
	{ 57, 403, "bearer capability not authorized" }, { 58, 503, "bearer capability not presently available" },
	{ 65, 488, "bearer capability not implemented" }, { 69, 501, "requested facility not implemented" },
	{ 79, 501, "service or option not implemented, unspecified" }, { 87, 403, "user not a member of the CUG" },
	{ 88, 503, "incompatible destination" }, { 102, 504, "recovery on timer expiry" }, { 111, 500, "protocol error, unspecified" },
	{ 127, 500, "interworking, unspecified" },
};

int cs_cause_to_sip(int q850, const char **text)
{
	unsigned i;

	for (i = 0; i < sizeof(CAUSES) / sizeof(CAUSES[0]); i++) {
		if (CAUSES[i].q850 == q850) {
			if (text)
				*text = CAUSES[i].text;
			return CAUSES[i].sip;
		}
	}
	if (text)
		*text = "cause not in the table";
	if (q850 <= 0 || q850 > 127)
		return 500;
	if (q850 < 32)		/* * normal event class: the call went nowhere, nothing more known */
		return 480;
	if (q850 < 64)		/* * resource unavailable */
		return 503;
	if (q850 < 96)		/* * service or option not available / implemented */
		return 501;
	return 500;		/* * invalid message / protocol error / interworking */
}

static const struct { int value; const char *name; int sip; const char *text; bool normal; } END_REASONS[] = {
	{ 146, "user-busy", 486, "user busy", false }, { 141, "unassigned-number", 404, "unassigned number", false },
	{ 115, "call-barred", 403, "call barred", false }, { 144, "operator-determined-barring", 403, "operator determined barring", false },
	{ 135, "rejected-by-network", 603, "rejected by the network", false }, { 148, "user-alerting-no-answer", 480, "no answer", false },
	{ 145, "normal-call-clearing", 480, "normal call clearing", true }, { 104, "network-end", 480, "ended by the network", true },
	{ 29, "client-end", 480, "ended locally", true },
};

int cs_end_reason_to_sip(int value, const char *name, const char **text, bool *normal)
{
	unsigned i;

	for (i = 0; i < sizeof(END_REASONS) / sizeof(END_REASONS[0]); i++) {
		if ((value > 0 && END_REASONS[i].value == value) || (value <= 0 && name && !strcmp(END_REASONS[i].name, name))) {
			if (text)
				*text = END_REASONS[i].text;
			if (normal)
				*normal = END_REASONS[i].normal;
			return END_REASONS[i].sip;
		}
	}
	return 0;
}

int cs_infer_status(enum cc_dir dir, bool alerting, bool active, unsigned alert_ms, unsigned short_ring_ms, const char *uq_reason)
{
	if (dir == CC_MT)
		return 487;			/* the caller hung up before we answered: Request Terminated */
	if (uq_reason && (!strcmp(uq_reason, "error") || !strcmp(uq_reason, "audio-setup-failed")))
		return 503;
	if (active)
		return 0;			/* an established call: no status, the B2BUA sends BYE */
	if (!alerting)
		return 503;			/* refused before alerting: busy / unallocated / barred cannot be told apart without the cause */
	return alert_ms < short_ring_ms ? 603 : 480;	/* declined at once vs no answer */
}

/* ------------------------------------------------------------------ strings */

int cs_number_normalize(const char *in, char *out, size_t n)
{
	size_t o = 0;
	const char *p = in;
	bool uri = false;

	if (!in || !n)
		return -1;
	while (*p == ' ' || *p == '<')
		p++;
	if (!strncasecmp(p, "sip:", 4) || !strncasecmp(p, "sips:", 5) || !strncasecmp(p, "tel:", 4)) {
		p = strchr(p, ':') + 1;
		uri = true;
	}
	for (; *p; p++) {
		if (uri && (*p == '@' || *p == ';' || *p == '>'))
			break;
		if (*p == '+' && !o) {
			if (o + 1 >= n)
				return -1;
			out[o++] = '+';
		} else if (*p == '%' && !strncmp(p, "%2B", 3) && !o) {
			out[o++] = '+';
			p += 2;
		} else if ((*p >= '0' && *p <= '9') || *p == '*' || *p == '#') {
			if (o + 1 >= n)
				return -1;
			out[o++] = *p;
		}
	}
	out[o] = 0;
	if (!o || (o == 1 && out[0] == '+'))
		return -1;
	return 0;
}

int cs_dial_string(const char *in, char *out, size_t n)
{
	size_t o = 0;
	const char *p;

	if (!in || !n)
		return -1;
	for (p = in; *p; p++) {
		if (*p == ' ' || *p == '-' || *p == '.' || *p == '(' || *p == ')')
			continue;
		if (*p == '+' && o == 0) {
			out[o++] = '+';
		} else if ((*p >= '0' && *p <= '9') || *p == '*' || *p == '#') {
			if (o + 1 >= n || o >= 32)
				return -1;
			out[o++] = *p;
		} else {
			return -1;
		}
	}
	out[o] = 0;
	return o && !(o == 1 && out[0] == '+') ? 0 : -1;
}

static void set_identity(struct cc_identity *id, const char *raw)
{
	memset(id, 0, sizeof(*id));
	if (raw && !cs_number_normalize(raw, id->number, sizeof(id->number))) {
		snprintf(id->uri, sizeof(id->uri), "tel:%s", id->number);
		return;
	}
	id->anonymous = true;
	snprintf(id->uri, sizeof(id->uri), "sip:anonymous@anonymous.invalid");
}

void cscall_cfg_defaults(struct cscall_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->early_media = true;
	c->ring_timeout_s = 120;
	c->dial_timeout_ms = 20000;
	c->hangup_wait_ms = 3000;
	c->reconcile_ms = 5000;
	c->short_ring_ms = 4000;
	c->max_calls = 4;
}

/* ------------------------------------------------------------------ requests */

static void mreq_done(void *arg, const struct csu_res *r);

static struct mreq *mreq_start(struct cscall_mgr *m, struct cscall *c, enum mk kind, const struct csu_req *rq, const char *path)
{
	struct mreq *q;

	if (m->n_reqs >= MAX_REQS) {
		LOGW("cs: too many requests in flight");
		return NULL;
	}
	q = calloc(1, sizeof(*q));
	if (!q)
		return NULL;
	q->m = m;
	q->c = c;
	q->kind = kind;
	q->gen = csline_status(m->line)->gen;
	if (path)
		str_copy(q->path, path, sizeof(q->path));
	q->next = m->reqs;
	m->reqs = q;
	m->n_reqs++;
	q->h = csline_call(m->line, rq, mreq_done, q);
	if (!q->h && !q->fired) {		/* OOM in the backend: no callback will come */
		struct mreq **pp;

		for (pp = &m->reqs; *pp; pp = &(*pp)->next)
			if (*pp == q) {
				*pp = q->next;
				break;
			}
		m->n_reqs--;
		free(q);
		return NULL;
	}
	return q;
}

static void mreq_unlink(struct mreq *q)
{
	struct mreq **pp;

	for (pp = &q->m->reqs; *pp; pp = &(*pp)->next) {
		if (*pp == q) {
			*pp = q->next;
			break;
		}
	}
	q->m->n_reqs--;
}

/* forget every request bound to c (the answers are not wanted any more; a pending create is turned into a delete) */
static void mreq_detach_call(struct cscall_mgr *m, struct cscall *c)
{
	struct mreq *q;

	for (q = m->reqs; q; q = q->next) {
		if (q->c != c)
			continue;
		q->c = NULL;
		if (q->kind == MK_CREATE)
			q->orphan = true;
		else if (q->kind != MK_DELETE) {
			q->kind = MK_DELETE;	/* the completion just frees it */
			q->orphan = false;
			q->path[0] = 0;
		}
	}
}

static void req_simple(struct cscall_mgr *m, struct cscall *c, enum mk kind, enum csu_op op, const char *obj, const char *str, const char *path)
{
	struct csu_req rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = op;
	rq.sms_class = -1;
	str_copy(rq.obj, obj, sizeof(rq.obj));
	if (str)
		str_copy(rq.str, str, sizeof(rq.str));
	mreq_start(m, c, kind, &rq, path);
}

static void do_delete(struct cscall_mgr *m, const char *path)
{
	if (!path[0] || !csline_modem(m->line)[0])
		return;
	req_simple(m, NULL, MK_DELETE, CSU_CALL_DELETE, csline_modem(m->line), path, path);
}

/* ------------------------------------------------------------------ call objects */

static unsigned live_count(const struct cscall_mgr *m)
{
	const struct cscall *c;
	unsigned n = 0;

	for (c = m->calls; c; c = c->next)
		if (c->st != CC_ST_ENDED)
			n++;
	return n;
}

static struct cscall *live_call(const struct cscall_mgr *m)
{
	struct cscall *c;

	for (c = m->calls; c; c = c->next)
		if (c->st != CC_ST_ENDED)
			return c;
	return NULL;
}

static struct cscall *find_path(const struct cscall_mgr *m, const char *path)
{
	struct cscall *c;

	if (!path[0])
		return NULL;
	for (c = m->calls; c; c = c->next)
		if (c->st != CC_ST_ENDED && !strcmp(c->path, path))
			return c;
	return NULL;
}

static void kick_cb(void *arg);
static void ring_cb(void *arg);
static void hup_cb(void *arg);
static void rec_cb(void *arg);
static void dtmf_cb(void *arg);

static struct cscall *call_new(struct cscall_mgr *m, enum cc_dir dir)
{
	struct cscall *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	c->m = m;
	c->id = ++m->next_id;
	c->dir = dir;
	c->st = dir == CC_MO ? CC_ST_DIALING : CC_ST_INCOMING;
	c->gen = csline_status(m->line)->gen;
	c->t_create = ev_now_ms();
	c->t_kick = ev_timer_new(kick_cb, c);
	c->t_ring = ev_timer_new(ring_cb, c);
	c->t_hup = ev_timer_new(hup_cb, c);
	c->t_rec = ev_timer_new(rec_cb, c);
	c->t_dtmf = ev_timer_new(dtmf_cb, c);
	if (!c->t_kick || !c->t_ring || !c->t_hup || !c->t_rec || !c->t_dtmf) {
		ev_timer_free(c->t_kick);
		ev_timer_free(c->t_ring);
		ev_timer_free(c->t_hup);
		ev_timer_free(c->t_rec);
		ev_timer_free(c->t_dtmf);
		free(c);
		return NULL;
	}
	c->next = m->calls;
	m->calls = c;
	return c;
}

static void call_free(struct cscall *c)
{
	ev_timer_free(c->t_kick);
	ev_timer_free(c->t_ring);
	ev_timer_free(c->t_hup);
	ev_timer_free(c->t_rec);
	ev_timer_free(c->t_dtmf);
	free(c);
}

static void reap_cb(void *arg)
{
	struct cscall_mgr *m = arg;
	struct cscall *c;

	while ((c = m->dead)) {
		m->dead = c->next;
		call_free(c);
	}
}

static void emit(struct cscall *c, enum cc_event_type type, int status, bool by_remote, const char *reason, int cause)
{
	struct cc_event ev;

	if (c->detached || !c->cb)
		return;
	memset(&ev, 0, sizeof(ev));
	ev.type = type;
	ev.status = status;
	ev.by_remote = by_remote;
	ev.media_kind = (type == CC_EV_EARLY_MEDIA) ? CC_MEDIA_PCM : CC_MEDIA_NONE;
	ev.cause = cause;
	if (reason)
		str_copy(ev.reason, reason, sizeof(ev.reason));
	c->cb((struct carrier_call *)c, &ev, c->arg);
}

static void call_timers_stop(struct cscall *c)
{
	ev_timer_cancel(c->t_ring);
	ev_timer_cancel(c->t_hup);
	ev_timer_cancel(c->t_rec);
	ev_timer_cancel(c->t_dtmf);
}

/* the one terminal event */
static void finish(struct cscall *c, enum cc_event_type type, int status, bool by_remote, const char *reason, int cause)
{
	struct cscall_mgr *m = c->m;
	char last[128];

	if (c->st == CC_ST_ENDED)
		return;
	c->st = CC_ST_ENDED;
	c->pend = false;
	ev_timer_cancel(c->t_kick);
	call_timers_stop(c);
	mreq_detach_call(m, c);
	if (c->path[0])
		do_delete(m, c->path);	/* uqmid hangs up a call that is not terminated yet, then removes the object */
	if (type == CC_EV_FAILED)
		m->st.failed++;
	snprintf(last, sizeof(last), "%s %s %d: %s", c->dir == CC_MO ? "mo" : "mt",
		 type == CC_EV_FAILED ? "failed" : type == CC_EV_CANCELLED ? "cancelled" : "ended", status, reason ? reason : "");
	str_copy(m->st.last_end, last, sizeof(m->st.last_end));
	LOGI("cs: call %u (%s) %s", c->id, c->path[0] ? c->path : "-", last);
	emit(c, type, status, by_remote, reason, cause);
	c->detached = true;
	c->dead = true;
	{
		struct cscall **pp;

		for (pp = &m->calls; *pp; pp = &(*pp)->next)
			if (*pp == c) {
				*pp = c->next;
				break;
			}
		c->next = m->dead;
		m->dead = c;
		ev_timer_set(m->t_reap, 0);
	}
	if (m->n_fo)
		ev_timer_set(m->t_rescan, 500);	/* a call that was left waiting may be ringing for real now */
}

/* decide the terminal event now, deliver it from the loop (the API never calls back synchronously) */
static void finish_later(struct cscall *c, enum cc_event_type type, int status, bool by_remote, const char *reason, int cause)
{
	if (c->st == CC_ST_ENDED || c->pend)
		return;
	c->pend = true;
	c->pend_type = type;
	c->pend_status = status;
	c->pend_remote = by_remote;
	c->pend_cause = cause;
	str_copy(c->pend_reason, reason ? reason : "", sizeof(c->pend_reason));
	ev_timer_set(c->t_kick, 0);
}

static void kick_cb(void *arg)
{
	struct cscall *c = arg;

	if (c->pend && c->st != CC_ST_ENDED)
		finish(c, c->pend_type, c->pend_status, c->pend_remote, c->pend_reason, c->pend_cause);
}

struct cs_end {			/* what uqmid reported about the end of a call (all optional) */
	int cause;			/* cc_cause */
	int er;				/* end_reason.value */
	char er_name[32];
};

static const struct cs_end NO_END;

/* the network ended the call (or the call object vanished) */
static void net_end(struct cscall *c, const char *reason, const struct cs_end *e, const char *uq_reason)
{
	int cause = e->cause;
	unsigned alert_ms = c->seen_alert ? (unsigned)(ev_now_ms() - c->t_alert) : 0;
	char text[128];
	int status, tstatus = 0;
	bool normal = false, er_known = false;
	const char *t = "";

	if (c->st == CC_ST_ENDED)
		return;
	if (c->ending && c->pend) {		/* we hung up: the pending event stands */
		finish(c, c->pend_type, c->pend_status, c->pend_remote, c->pend_reason, c->pend_cause);
		return;
	}
	LOGI("cs: call %u: ended by the network: cc_cause %d, end_reason %s (%d), uqmid reason '%s'", c->id, cause,
	     e->er_name[0] ? e->er_name : "-", e->er, uq_reason ? uq_reason : "");
	if (cause > 0) {			/* 1. the network's own cause */
		status = cs_cause_to_sip(cause, &t);
		tstatus = status;
		snprintf(text, sizeof(text), "%s (cause %d%s%s)", t, cause, e->er_name[0] ? ", end reason " : "", e->er_name);
	} else if ((status = cs_end_reason_to_sip(e->er, e->er_name, &t, &normal)) > 0) {	/* 2. the QMI end reason */
		er_known = true;
		snprintf(text, sizeof(text), "%s (end reason %s %d)", t, e->er_name[0] ? e->er_name : "-", e->er);
		if (c->dir == CC_MT)
			status = 487;		/* the caller ended it before we answered */
		tstatus = normal ? 0 : status;	/* an established call that ends normally has no status */
	} else {				/* 3. nothing reported: infer from the direction and the timing */
		status = cs_infer_status(c->dir, c->seen_alert, c->seen_active, alert_ms, c->m->cfg.short_ring_ms, uq_reason);
		snprintf(text, sizeof(text), "%s (no cause reported by the modem)", reason);
	}
	if (c->seen_active || (c->dir == CC_MT && c->answer_asked)) {
		finish(c, CC_EV_TERMINATED, (cause > 0 || er_known) ? tstatus : 0, true, text, cause);
	} else if (c->dir == CC_MT) {
		finish(c, CC_EV_CANCELLED, status, true, text, cause);
	} else {
		finish(c, CC_EV_FAILED, status, true, text, cause);
	}
}

/* we lost the modem / uqmid: nothing on the air can be asked for any more */
static void modem_lost(struct cscall *c)
{
	c->m->st.lost_modem++;
	if (c->st == CC_ST_ENDED)
		return;
	if (c->ending && c->pend) {
		finish(c, c->pend_type, c->pend_status, c->pend_remote, c->pend_reason, c->pend_cause);
		return;
	}
	if (c->seen_active || (c->dir == CC_MT && c->answer_asked))
		finish_later(c, CC_EV_TERMINATED, 503, false, "modem lost", 0);
	else if (c->dir == CC_MT)
		finish_later(c, CC_EV_CANCELLED, 503, false, "modem lost", 0);
	else
		finish_later(c, CC_EV_FAILED, 503, false, "modem lost", 0);
}

/* ------------------------------------------------------------------ uqmid state of a call */

static void arm_reconcile(struct cscall *c)
{
	if (c->m->cfg.reconcile_ms && c->st != CC_ST_ENDED)
		ev_timer_set(c->t_rec, c->m->cfg.reconcile_ms);
}

static void uq_state(struct cscall *c, const char *name, const char *reason, const struct cs_end *e)
{
	enum cu s = cu_parse(name);

	if (c->st == CC_ST_ENDED || s == c->uq || s == CU_UNKNOWN)
		return;			/* duplicates and the initial "unknown" */
	if (c->uq == CU_TERMINATED)
		return;
	if (s == CU_TERMINATED) {
		c->uq = s;
		net_end(c, "the network ended the call", e, reason);
		return;
	}
	if (c->uq == CU_ACTIVE && (s == CU_RINGING_OUT || s == CU_DIALING || s == CU_RINGING_IN)) {
		LOGD("cs: call %u: late %s after active ignored", c->id, name);
		return;			/* out of order */
	}
	c->uq = s;
	switch (s) {
	case CU_RINGING_OUT:
		if (c->dir != CC_MO || c->seen_alert)
			break;
		c->seen_alert = true;
		c->t_alert = ev_now_ms();
		if (c->st == CC_ST_DIALING)
			c->st = CC_ST_EARLY;
		emit(c, CC_EV_RINGING, 180, false, "alerting", 0);
		if (c->st == CC_ST_ENDED)
			return;
		emit(c, CC_EV_PROGRESS, 180, false, "alerting", 0);
		if (c->m->cfg.early_media && !c->early_sent && c->st != CC_ST_ENDED) {
			c->early_sent = true;
			emit(c, CC_EV_PROGRESS, 183, false, "carrier audio", 0);
			if (c->st != CC_ST_ENDED)
				emit(c, CC_EV_EARLY_MEDIA, 183, false, "carrier audio", 0);
		}
		break;
	case CU_ACTIVE:
		if (c->seen_active)
			break;
		c->seen_active = true;
		c->t_active = ev_now_ms();
		if (c->dir == CC_MO) {
			c->seen_alert = true;
			if (c->st == CC_ST_CANCELLING)
				break;		/* we are hanging up: the end follows */
			if (!c->early_sent) {
				c->early_sent = true;
				emit(c, CC_EV_EARLY_MEDIA, 183, false, "carrier audio", 0);
				if (c->st == CC_ST_ENDED)
					return;
			}
			c->st = CC_ST_CONNECTED;
			c->m->st.answered++;
			c->answered_sent = true;
			emit(c, CC_EV_ANSWERED, 200, false, "answered", 0);
		} else if (c->st == CC_ST_ANSWERING || c->st == CC_ST_INCOMING) {
			/* accepted: the accept answer normally gets here first (ANSWERED is sent once) */
			c->st = CC_ST_CONNECTED;
			if (!c->answered_sent) {
				c->answered_sent = true;
				c->m->st.answered++;
				emit(c, CC_EV_ANSWERED, 200, false, "answered", 0);
			}
		}
		break;
	case CU_HELD:
	case CU_WAITING:
	default:
		break;
	}
}

static void get_apply(struct cscall *c, const struct csu_res *r)
{
	if (!c->remote.number[0] && r->call_number[0] && c->dir == CC_MT)
		set_identity(&c->remote, r->call_number);
	{
		struct cs_end e = { r->end_cause, r->end_reason, "" };

		str_copy(e.er_name, r->end_reason_name, sizeof(e.er_name));
		uq_state(c, r->call_state, r->call_reason, &e);
	}
}

/* ------------------------------------------------------------------ foreign / waiting calls */

static struct fo *fo_find(struct cscall_mgr *m, const char *path)
{
	unsigned i;

	for (i = 0; i < m->n_fo; i++)
		if (!strcmp(m->fo[i].path, path))
			return &m->fo[i];
	return NULL;
}

static void fo_recount(struct cscall_mgr *m)
{
	unsigned i;

	m->st.waiting = m->st.foreign = 0;
	m->st.waiting_number[0] = 0;
	for (i = 0; i < m->n_fo; i++) {
		if (m->fo[i].incoming) {
			if (!m->st.waiting++)
				str_copy(m->st.waiting_number, m->fo[i].number, sizeof(m->st.waiting_number));
		} else {
			m->st.foreign++;
		}
	}
}

static void fo_remove(struct cscall_mgr *m, const char *path)
{
	struct fo *f = fo_find(m, path);

	if (!f)
		return;
	*f = m->fo[--m->n_fo];
	fo_recount(m);
}

static void fo_set(struct cscall_mgr *m, const char *path, const char *number, enum cu st, bool incoming)
{
	struct fo *f = fo_find(m, path);

	if (!f) {
		if (m->n_fo >= MAX_FO)
			return;
		f = &m->fo[m->n_fo++];
		memset(f, 0, sizeof(*f));
		str_copy(f->path, path, sizeof(f->path));
		if (incoming) {
			m->st.waiting_total++;
			LOGI("cs: incoming call %s from '%s' while a call is active: left untouched at the network", path, number);
		}
	}
	str_copy(f->number, number, sizeof(f->number));
	f->st = st;
	f->incoming = incoming;
	fo_recount(m);
}

static void incoming_new(struct cscall_mgr *m, const char *path, const char *number)
{
	struct cscall *c;
	struct cc_incoming in;
	int rc;

	if (live_count(m) >= m->cfg.max_calls) {
		fo_set(m, path, number, CU_RINGING_IN, true);
		return;
	}
	c = call_new(m, CC_MT);
	if (!c)
		return;
	str_copy(c->path, path, sizeof(c->path));
	c->uq = CU_RINGING_IN;
	set_identity(&c->remote, number);
	str_copy(c->called, csline_status(m->line)->own_number, sizeof(c->called));
	m->st.mt++;
	fo_remove(m, path);
	LOGI("cs: incoming call %u from '%s'", c->id, c->remote.number);
	memset(&in, 0, sizeof(in));
	in.caller = c->remote;
	str_copy(in.called, c->called, sizeof(in.called));
	in.media_kind = CC_MEDIA_PCM;
	in.backend_cs = true;
	rc = m->cfg.on_incoming ? m->cfg.on_incoming((struct carrier_call *)c, &in, m->cfg.incoming_arg) : -1;
	if (rc) {
		/* refused (or nobody listens): hang up what rings; the object is deleted by finish() */
		c->detached = true;
		if (c->st != CC_ST_ENDED)
			finish(c, CC_EV_CANCELLED, 480, false, "refused by the LAN side", 0);
		return;
	}
	if (c->ending || c->st == CC_ST_ENDED)
		return;
	if (m->cfg.ring_timeout_s)
		ev_timer_set(c->t_ring, (uint64_t)m->cfg.ring_timeout_s * 1000);
	arm_reconcile(c);
}

/* an object we do not own: classify it (reply of CALL_GET) */
static void classify(struct cscall_mgr *m, const char *path, const struct csu_res *r)
{
	enum cu st = cu_parse(r->call_state);
	bool incoming = !strcmp(r->call_dir, "incoming");
	struct cscall *c = find_path(m, path);

	if (c) {
		get_apply(c, r);
		return;
	}
	if (st == CU_TERMINATED) {
		fo_remove(m, path);
		do_delete(m, path);
		return;
	}
	if (incoming && st == CU_RINGING_IN && !live_call(m) && !m->st.foreign && csline_status(m->line)->voice_ok) {
		incoming_new(m, path, r->call_number);
		return;
	}
	if (incoming && (st == CU_RINGING_IN || st == CU_WAITING)) {
		fo_set(m, path, r->call_number, st, true);
		return;
	}
	if (st == CU_DIALING || st == CU_RINGING_OUT || st == CU_ACTIVE || st == CU_HELD)
		fo_set(m, path, r->call_number, st, false);
}

static void rescan(struct cscall_mgr *m)
{
	if (m->rescanning || !csline_modem(m->line)[0])
		return;
	m->rescanning = true;
	req_simple(m, NULL, MK_LIST, CSU_CALL_LIST, csline_modem(m->line), NULL, NULL);
	if (!m->reqs || m->reqs->kind != MK_LIST)
		m->rescanning = false;
}

static void rescan_cb(void *arg)
{
	rescan(arg);
}

/* ------------------------------------------------------------------ dtmf */

static void dtmf_pump(struct cscall *c)
{
	struct cscall_mgr *m = c->m;
	char d[2];

	if (c->dtmf_busy || !c->dq_n || c->st != CC_ST_CONNECTED || !c->path[0])
		return;
	d[0] = c->dq[0];
	d[1] = 0;
	c->dtmf_busy = true;
	{
		struct csu_req rq;
		struct mreq *q;

		memset(&rq, 0, sizeof(rq));
		rq.op = CSU_CALL_DTMF;
		rq.sms_class = -1;
		str_copy(rq.obj, c->path, sizeof(rq.obj));
		str_copy(rq.str, d, sizeof(rq.str));
		q = mreq_start(m, c, MK_DTMF, &rq, NULL);
		if (!q) {
			c->dtmf_busy = false;
			memmove(c->dq, c->dq + 1, --c->dq_n);
			m->st.dtmf_dropped++;
		}
	}
}

static void dtmf_cb(void *arg)
{
	dtmf_pump(arg);
}

/* ------------------------------------------------------------------ completions */

static unsigned long fail_status(const struct csu_res *r)
{
	switch (r->err) {
	case CSU_E_STATE:
		return !strcmp(r->errname, "unauthorized") ? 403 : 503;	/* not registered: only emergency calls */
	case CSU_E_TIMEOUT:
		return 408;
	case CSU_E_ARGS:
		return 484;
	default:
		return 503;
	}
}

static void mreq_done(void *arg, const struct csu_res *r)
{
	struct mreq *q = arg;
	struct cscall_mgr *m = q->m;
	struct cscall *c = q->c;
	bool stale = q->gen != csline_status(m->line)->gen;
	enum mk kind = q->kind;
	bool orphan = q->orphan;
	char path[CSU_PATH];
	char reason[128];

	q->fired = true;
	str_copy(path, q->path, sizeof(path));
	mreq_unlink(q);
	free(q);
	if (m->dying)
		return;
	if (stale)
		return;			/* an answer of the previous modem object: the calls ended with it (l_modem) */
	switch (kind) {
	case MK_CREATE:
		if (orphan || !c || c->st == CC_ST_ENDED) {
			if (!r->err && r->path[0])
				do_delete(m, r->path);
			return;
		}
		if (r->err || !r->path[0]) {
			snprintf(reason, sizeof(reason), "cannot create the call: %.80s", r->errmsg[0] ? r->errmsg : "no path");
			finish(c, CC_EV_FAILED, (int)fail_status(r), false, reason, 0);
			return;
		}
		str_copy(c->path, r->path, sizeof(c->path));
		if (c->kill_on_path) {		/* hung up while the object was being created */
			do_delete(m, c->path);
			c->path[0] = 0;
			return;
		}
		req_simple(m, c, MK_START, CSU_CALL_START, c->path, NULL, NULL);
		break;
	case MK_START:
		if (!c || c->st == CC_ST_ENDED)
			return;
		if (r->err) {
			snprintf(reason, sizeof(reason), "cannot dial: %.100s", r->errmsg[0] ? r->errmsg : r->errname);
			if (c->ending)
				finish(c, c->pend_type, c->pend_status, c->pend_remote, c->pend_reason, c->pend_cause);
			else
				finish(c, CC_EV_FAILED, (int)fail_status(r), false, reason, 0);
			return;
		}
		ev_timer_cancel(c->t_hup);	/* the dial timeout covers create + start */
		if (m->cfg.ring_timeout_s)
			ev_timer_set(c->t_ring, (uint64_t)m->cfg.ring_timeout_s * 1000);
		arm_reconcile(c);
		break;
	case MK_ACCEPT:
		if (!c || c->st == CC_ST_ENDED)
			return;		/* glare: the network ended the call first */
		if (r->err) {
			snprintf(reason, sizeof(reason), "cannot answer: %.100s", r->errmsg[0] ? r->errmsg : r->errname);
			if (c->ending)
				finish(c, c->pend_type, c->pend_status, c->pend_remote, c->pend_reason, c->pend_cause);
			else
				finish(c, CC_EV_TERMINATED, 503, false, reason, 0);
			return;
		}
		if (c->ending)
			return;
		if (c->st == CC_ST_ANSWERING) {
			c->st = CC_ST_CONNECTED;
			c->t_active = ev_now_ms();
			c->seen_active = true;
			c->uq = CU_ACTIVE;
			if (!c->answered_sent) {
				c->answered_sent = true;
				m->st.answered++;
				emit(c, CC_EV_ANSWERED, 200, false, "answered", 0);
			}
			dtmf_pump(c);
		}
		break;
	case MK_HANGUP:
		if (!c || c->st == CC_ST_ENDED)
			return;
		/* answer or error ("not active": it ended already): the call is over either way */
		if (c->pend)
			finish(c, c->pend_type, c->pend_status, c->pend_remote, c->pend_reason, c->pend_cause);
		break;
	case MK_GET:
		if (!c || c->st == CC_ST_ENDED)
			return;
		if (r->err == CSU_E_GONE) {
			net_end(c, "the call object vanished", &NO_END, "unknown");
			return;
		}
		if (!r->err)
			get_apply(c, r);
		if (c->st != CC_ST_ENDED)
			arm_reconcile(c);
		break;
	case MK_DTMF:
		if (!c || c->st == CC_ST_ENDED)
			return;
		c->dtmf_busy = false;
		if (r->err == CSU_E_BUSY) {	/* uqmid is still playing the previous digit */
			ev_timer_set(c->t_dtmf, 200);
			return;
		}
		if (c->dq_n) {
			memmove(c->dq, c->dq + 1, --c->dq_n);
			if (r->err)
				m->st.dtmf_dropped++;
			else
				m->st.dtmf_sent++;
		}
		dtmf_pump(c);
		break;
	case MK_DELETE:
		if (r->err && r->err != CSU_E_GONE)
			LOGD("cs: delete %s: %s", path, r->errmsg);
		break;
	case MK_NEWGET:
		if (r->err) {
			LOGD("cs: cannot read %s: %s", path, r->errmsg);
			return;
		}
		classify(m, path, r);
		break;
	case MK_LIST: {
		int i;
		unsigned k;

		m->rescanning = false;
		if (r->err)
			return;
		/* forget foreign entries that are not listed any more */
		for (k = 0; k < m->n_fo;) {
			bool listed = false;

			for (i = 0; i < r->n_paths; i++)
				if (!strcmp(r->paths[i], m->fo[k].path))
					listed = true;
			if (listed)
				k++;
			else
				fo_remove(m, m->fo[k].path);
		}
		for (i = 0; i < r->n_paths; i++) {
			if (find_path(m, r->paths[i]))
				continue;
			req_simple(m, NULL, MK_NEWGET, CSU_CALL_GET, r->paths[i], NULL, r->paths[i]);
		}
		break;
	}
	}
}

/* ------------------------------------------------------------------ timers */

static void start_hangup(struct cscall *c, enum cc_event_type type, int status, const char *reason);

static void ring_cb(void *arg)
{
	struct cscall *c = arg;

	if (c->st == CC_ST_ENDED || c->seen_active || c->ending)
		return;
	LOGI("cs: call %u: not answered after %u s", c->id, c->m->cfg.ring_timeout_s);
	/* gm: the INVITE is cancelled and the caller gets 480; same here */
	start_hangup(c, CC_EV_CANCELLED, 480, c->dir == CC_MO ? "no answer within the ring timeout" : "not answered by the LAN side");
}

static void hup_cb(void *arg)
{
	struct cscall *c = arg;

	if (c->st == CC_ST_ENDED)
		return;
	if (c->pend)
		finish(c, c->pend_type, c->pend_status, c->pend_remote, c->pend_reason, c->pend_cause);
	else if (c->dir == CC_MO && c->st == CC_ST_DIALING && !c->seen_alert)
		finish(c, CC_EV_FAILED, 408, false, "the modem did not start the call in time", 0);
	else
		net_end(c, "hangup not confirmed", &NO_END, "terminated");
}

static void rec_cb(void *arg)
{
	struct cscall *c = arg;

	if (c->st == CC_ST_ENDED || !c->path[0])
		return;
	req_simple(c->m, c, MK_GET, CSU_CALL_GET, c->path, NULL, NULL);
}

/* ------------------------------------------------------------------ line events */

static void l_modem(void *arg, bool present, const char *path, unsigned gen)
{
	struct cscall_mgr *m = arg;
	struct cscall *c, *nx;

	(void)path;
	(void)gen;
	/* every request in flight belongs to the old modem object: their answers are void (gen check); the calls end */
	for (c = m->calls; c; c = nx) {
		nx = c->next;
		if (c->st != CC_ST_ENDED && c->gen != gen)
			modem_lost(c);
	}
	m->n_fo = 0;
	fo_recount(m);
	m->rescanning = false;
	if (present)
		ev_timer_set(m->t_rescan, 1000);	/* calls that were already there (daemon restart) */
}

static void l_status(void *arg, const struct csline_status *s)
{
	struct cscall_mgr *m = arg;

	if (s->voice_ok && s->modem[0] && !live_call(m))
		ev_timer_set(m->t_rescan, 300);
}

static void l_notify(void *arg, const struct csu_notify *n)
{
	struct cscall_mgr *m = arg;
	struct cscall *c;

	if (!strcmp(n->method, "voice.call_added")) {
		bool creating = false;

		if (find_path(m, n->path) || fo_find(m, n->path))
			return;
		for (c = m->calls; c; c = c->next)
			if (c->st != CC_ST_ENDED && c->dir == CC_MO && !c->path[0])
				creating = true;	/* our own create: the reply carries the path */
		if (creating)
			return;
		req_simple(m, NULL, MK_NEWGET, CSU_CALL_GET, n->path, NULL, n->path);
	} else if (!strcmp(n->method, "voice.call_state_changed")) {
		c = find_path(m, n->path);
		if (c) {
			struct cs_end e = { n->cc_cause, n->end_reason, "" };

			str_copy(e.er_name, n->end_reason_name, sizeof(e.er_name));
			uq_state(c, n->new_state, n->reason, &e);
			return;
		}
		{
			struct fo *f = fo_find(m, n->path);
			enum cu s = cu_parse(n->new_state);

			if (s == CU_TERMINATED) {
				fo_remove(m, n->path);
				do_delete(m, n->path);
			} else if (f || s == CU_RINGING_IN) {
				/* a waiting call may start to ring for real, or an unknown call changes: read it */
				req_simple(m, NULL, MK_NEWGET, CSU_CALL_GET, n->path, NULL, n->path);
			}
		}
	} else if (!strcmp(n->method, "voice.call_deleted")) {
		fo_remove(m, n->path);
	}
}

/* ------------------------------------------------------------------ manager */

struct cscall_mgr *cscall_mgr_new(struct csline *line, const struct cscall_cfg *cfg)
{
	struct cscall_mgr *m = calloc(1, sizeof(*m));
	struct csline_listener l = { 0 };

	if (!m)
		return NULL;
	m->line = line;
	m->cfg = *cfg;
	if (m->cfg.max_calls < 1)
		m->cfg.max_calls = 1;
	if (m->cfg.max_calls > 4)
		m->cfg.max_calls = 4;
	m->t_reap = ev_timer_new(reap_cb, m);
	m->t_rescan = ev_timer_new(rescan_cb, m);
	l.on_modem = l_modem;
	l.on_notify = l_notify;
	l.on_status = l_status;
	l.arg = m;
	if (!m->t_reap || !m->t_rescan || csline_add_listener(line, &l)) {
		ev_timer_free(m->t_reap);
		ev_timer_free(m->t_rescan);
		free(m);
		return NULL;
	}
	if (csline_modem(line)[0])
		ev_timer_set(m->t_rescan, 500);
	return m;
}

void cscall_mgr_free(struct cscall_mgr *m)
{
	struct cscall *c;

	if (!m)
		return;
	m->dying = true;
	csline_remove_listener(m->line, m);
	while (m->reqs) {
		struct mreq *q = m->reqs;

		m->reqs = q->next;
		csline_cancel(m->line, q->h);
		free(q);
	}
	while ((c = m->calls)) {
		m->calls = c->next;
		call_free(c);
	}
	while ((c = m->dead)) {
		m->dead = c->next;
		call_free(c);
	}
	ev_timer_free(m->t_reap);
	ev_timer_free(m->t_rescan);
	free(m);
}

void cscall_mgr_set_cfg(struct cscall_mgr *m, const struct cscall_cfg *cfg)
{
	m->cfg = *cfg;
	if (m->cfg.max_calls < 1)
		m->cfg.max_calls = 1;
	if (m->cfg.max_calls > 4)
		m->cfg.max_calls = 4;
}

void cscall_mgr_status(const struct cscall_mgr *m, struct cscall_status *s)
{
	struct cscall *c = live_call(m);

	*s = m->st;
	s->live = live_count(m);
	s->active_id = c ? c->id : 0;
}

/* ------------------------------------------------------------------ operations */

int cscall_dial(struct cscall_mgr *m, const struct cc_dial *d, cc_event_cb cb, void *arg, struct carrier_call **out)
{
	char num[40];
	struct cscall *c;
	struct csu_req rq;
	struct mreq *q;

	if (!d || !d->target || cs_dial_string(d->target, num, sizeof(num)) < 0)
		return -EINVAL;
	if (!csline_status(m->line)->voice_ok)
		return -ENOTCONN;
	if (live_call(m) || m->st.foreign) {
		m->st.busy_refused++;
		return -EBUSY;
	}
	c = call_new(m, CC_MO);
	if (!c)
		return -ENOMEM;
	c->cb = cb;
	c->arg = arg;
	set_identity(&c->remote, num);
	str_copy(c->called, num, sizeof(c->called));
	memset(&rq, 0, sizeof(rq));
	rq.op = CSU_CALL_CREATE;
	rq.sms_class = -1;
	str_copy(rq.obj, csline_modem(m->line), sizeof(rq.obj));
	str_copy(rq.str, num, sizeof(rq.str));
	q = mreq_start(m, c, MK_CREATE, &rq, NULL);
	if (!q) {
		struct cscall **pp;

		for (pp = &m->calls; *pp; pp = &(*pp)->next)
			if (*pp == c) {
				*pp = c->next;
				break;
			}
		call_free(c);
		return -ENOBUFS;
	}
	m->st.mo++;
	LOGI("cs: call %u: dialing '%s'", c->id, num);
	if (m->cfg.dial_timeout_ms)
		ev_timer_set(c->t_hup, m->cfg.dial_timeout_ms);	/* hup_cb: net_end() = FAILED if nothing came of it */
	*out = (struct carrier_call *)c;
	return 0;
}

static int op_dial(void *be, const struct cc_dial *d, cc_event_cb cb, void *arg, struct carrier_call **out)
{
	return cscall_dial(be, d, cb, arg, out);
}

static void op_set_incoming(void *be, cc_incoming_cb cb, void *arg)
{
	struct cscall_mgr *m = be;

	m->cfg.on_incoming = cb;
	m->cfg.incoming_arg = arg;
}

static unsigned op_count(const void *be)
{
	return live_count(be);
}

static int op_list(const void *be, struct cc_info *out, int max)
{
	const struct cscall_mgr *m = be;
	const struct cscall *c;
	int n = 0;

	for (c = m->calls; c; c = c->next) {
		if (c->st == CC_ST_ENDED)
			continue;
		if (n < max) {
			memset(&out[n], 0, sizeof(out[n]));
			out[n].id = c->id;
			out[n].dir = c->dir;
			out[n].state_name = cc_state_name(c->st);
			out[n].remote = c->remote;
			out[n].age_ms = ev_now_ms() - c->t_create;
			out[n].talk_ms = c->t_active ? ev_now_ms() - c->t_active : 0;
			out[n].media_kind = CC_MEDIA_PCM;
			out[n].hold = c->hold;
		}
		n++;
	}
	return n;
}

static void op_set_handler(struct carrier_call *cc, cc_event_cb cb, void *arg)
{
	struct cscall *c = (struct cscall *)cc;

	c->cb = cb;
	c->arg = arg;
}

static int op_ring(struct carrier_call *cc)
{
	struct cscall *c = (struct cscall *)cc;

	return c->st == CC_ST_INCOMING ? 0 : -EINVAL;	/* the network rings the caller by itself */
}

static int op_answer(struct carrier_call *cc, const struct addr *rtp)
{
	struct cscall *c = (struct cscall *)cc;

	(void)rtp;
	if (c->st == CC_ST_ENDED)
		return -ESTALE;
	if (c->dir != CC_MT || c->st != CC_ST_INCOMING || c->ending) {
		if (c->dir == CC_MT && c->st == CC_ST_ANSWERING)
			c->m->st.glare++;
		return -EINVAL;
	}
	c->st = CC_ST_ANSWERING;
	c->answer_asked = true;
	ev_timer_cancel(c->t_ring);
	req_simple(c->m, c, MK_ACCEPT, CSU_CALL_ACCEPT, c->path, NULL, NULL);
	return 0;
}

static void start_hangup(struct cscall *c, enum cc_event_type type, int status, const char *reason)
{
	c->ending = true;
	finish_later(c, type, status, false, reason, 0);
	ev_timer_cancel(c->t_ring);
	if (c->path[0] && c->uq != CU_TERMINATED) {
		if (c->st != CC_ST_CONNECTED)
			c->st = CC_ST_CANCELLING;
		req_simple(c->m, c, MK_HANGUP, CSU_CALL_HANGUP, c->path, NULL, NULL);
		ev_timer_set(c->t_hup, c->m->cfg.hangup_wait_ms);
		ev_timer_cancel(c->t_kick);		/* the end follows the hangup answer, bounded by hangup_wait_ms */
	} else if (!c->path[0]) {
		c->kill_on_path = true;			/* the create is still running: its answer is deleted */
	}
}

static int op_hangup(struct carrier_call *cc)
{
	struct cscall *c = (struct cscall *)cc;

	if (c->st == CC_ST_ENDED)
		return -ESTALE;
	if (c->ending)
		return 0;
	if (c->st == CC_ST_CONNECTED || c->st == CC_ST_ANSWERING)
		start_hangup(c, CC_EV_TERMINATED, 0, "hung up");
	else
		start_hangup(c, CC_EV_CANCELLED, c->dir == CC_MT ? 480 : 0, c->dir == CC_MT ? "not answered" : "cancelled");
	return 0;
}

static int op_reject(struct carrier_call *cc, int status)
{
	struct cscall *c = (struct cscall *)cc;

	if (c->st == CC_ST_ENDED)
		return -ESTALE;
	if (c->dir != CC_MT || c->st != CC_ST_INCOMING)
		return -EINVAL;
	if (c->ending)
		return 0;
	/* a hangup of a ringing call is the network's "rejected / busy"; the SIP status only goes to the log */
	start_hangup(c, CC_EV_CANCELLED, status, "rejected");
	return 0;
}

static void op_release(struct carrier_call *cc)
{
	struct cscall *c = (struct cscall *)cc;

	if (c->st == CC_ST_ENDED) {
		c->detached = true;
		return;
	}
	c->detached = true;
	if (!c->ending)
		op_hangup(cc);
}

static int op_set_hold(struct carrier_call *cc, bool hold)
{
	struct cscall *c = (struct cscall *)cc;

	if (c->st == CC_ST_ENDED)
		return -ESTALE;
	c->hold = hold;			/* the call stays up; the B2BUA feeds silence by the bridge direction */
	return 0;
}

static int op_send_dtmf(struct carrier_call *cc, char digit)
{
	struct cscall *c = (struct cscall *)cc;

	if (digit >= 'a' && digit <= 'd')
		digit = (char)(digit - 32);
	if (!((digit >= '0' && digit <= '9') || digit == '*' || digit == '#' || (digit >= 'A' && digit <= 'D')))
		return -EINVAL;
	if (c->st != CC_ST_CONNECTED || c->ending)
		return -ENOTCONN;
	if (c->dq_n >= DTMF_Q) {
		c->m->st.dtmf_dropped++;
		return -ENOBUFS;
	}
	c->dq[c->dq_n++] = digit;
	dtmf_pump(c);
	return 0;
}

static void op_media_failed(struct carrier_call *cc, int err)
{
	struct cscall *c = (struct cscall *)cc;
	char t[96];

	if (c->st == CC_ST_ENDED || c->ending)
		return;
	snprintf(t, sizeof(t), "PCM audio device failed: %s", strerror(err < 0 ? -err : err));
	LOGW("cs: call %u: %s", c->id, t);
	c->ending = true;
	if (c->seen_active || c->answer_asked)
		finish_later(c, CC_EV_TERMINATED, 503, false, t, 0);
	else if (c->dir == CC_MT)
		finish_later(c, CC_EV_CANCELLED, 503, false, t, 0);
	else
		finish_later(c, CC_EV_FAILED, 503, false, t, 0);
	if (c->path[0])
		req_simple(c->m, c, MK_HANGUP, CSU_CALL_HANGUP, c->path, NULL, NULL);
	ev_timer_set(c->t_hup, c->m->cfg.hangup_wait_ms);
}

static bool op_get_media(const struct carrier_call *c, struct sdpn_media *out)
{
	(void)c;
	(void)out;
	return false;
}

static enum cc_state op_state(const struct carrier_call *c)
{
	return ((const struct cscall *)c)->st;
}

static enum cc_dir op_direction(const struct carrier_call *c)
{
	return ((const struct cscall *)c)->dir;
}

static const struct cc_identity *op_remote(const struct carrier_call *c)
{
	return &((const struct cscall *)c)->remote;
}

static unsigned op_id(const struct carrier_call *c)
{
	return ((const struct cscall *)c)->id;
}

static uint64_t op_talk_ms(const struct carrier_call *c)
{
	const struct cscall *k = (const struct cscall *)c;

	return k->t_active ? ev_now_ms() - k->t_active : 0;
}

const struct carrier_call_ops cscall_carrier_ops = {
	.name = "cs",
	.media_kind = CC_MEDIA_PCM,
	.set_incoming = op_set_incoming,
	.dial = op_dial,
	.count = op_count,
	.list = op_list,
	.set_handler = op_set_handler,
	.ring = op_ring,
	.answer = op_answer,
	.reject = op_reject,
	.hangup = op_hangup,
	.release = op_release,
	.set_hold = op_set_hold,
	.send_dtmf = op_send_dtmf,
	.media_failed = op_media_failed,
	.get_media = op_get_media,
	.state = op_state,
	.direction = op_direction,
	.remote = op_remote,
	.id = op_id,
	.talk_ms = op_talk_ms,
};

void cscall_carrier_backend(struct cscall_mgr *m, struct carrier_backend *out)
{
	out->ops = &cscall_carrier_ops;
	out->be = m;
}
