/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cssms.h"
#include "../smscodec/gsm7.h"
#include "../smscodec/utf8.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define WORK_MAX 64
#define HANDLED_MAX 64
#define INC_MAX 16
#define MAX_REQS 8
#define DEL_TRIES 3
#define DRAIN_PASSES 20

enum wk { WK_READ, WK_DELETE };

struct work {
	char path[CSU_PATH];
	enum wk kind;
	bool backlog;
	unsigned tries;
	uint64_t not_before;		/* a delete retry waits for retry_ms */
};

struct inc {
	char path[CSU_PATH];
	uint64_t since;
};

struct mo {
	struct mo *next;
	char dest[32];
	char *text;
	bool dra;
	unsigned vp;
	unsigned parts;
	cssms_done_cb cb;
	void *arg;
	char path[CSU_PATH];
	unsigned serial;
};

enum sk { SK_LIST, SK_READ, SK_DELETE, SK_CREATE, SK_SEND, SK_MODELETE };

struct sreq {
	struct sreq *next;
	struct cssms *s;
	enum sk kind;
	unsigned gen;
	void *h;
	bool fired;
	unsigned serial;	/* SK_CREATE / SK_SEND: the MO message it belongs to */
};

struct cssms {
	struct csline *line;
	struct cssms_cfg cfg;
	struct sreq *reqs;
	unsigned n_reqs;
	bool dying;
	/* incoming */
	struct work work[WORK_MAX];
	unsigned w_head, w_n;
	bool w_busy;			/* a read / delete of the head is in flight */
	char handled[HANDLED_MAX][CSU_PATH];
	unsigned h_next, h_n;
	struct inc inc[INC_MAX];
	unsigned n_inc;
	unsigned gen;			/* the modem object the state belongs to */
	bool drain_started, drained, relist, listing;
	unsigned mo_serial, cur_serial;
	bool w_pending;			/* the head was handed over and the taker has not confirmed it yet (CSSMS_PENDING) */
	unsigned in_serial, pend_id;
	unsigned passes, pass_kept;
	bool kicked;
	uint64_t slow_at;
	struct ev_timer *t_work, *t_gc, *t_mo;
	/* outgoing */
	struct mo *mo_head, *mo_tail;
	unsigned mo_n;
	bool mo_busy;
	struct cssms_status st;
};

/* ------------------------------------------------------------------ helpers */

void cssms_cfg_defaults(struct cssms_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->max_segments = 10;
	c->queue_max = 8;
	c->send_timeout_ms = 120000;
	c->incomplete_ms = 600000;
	c->retry_ms = 5000;
	c->slow_retry_ms = 300000;
}

static void clamp(struct cssms_cfg *c)
{
	if (!c->max_segments || c->max_segments > 32)
		c->max_segments = c->max_segments ? 32 : 10;
	if (!c->queue_max || c->queue_max > 32)
		c->queue_max = c->queue_max ? 32 : 8;
}

int cssms_count_parts(const char *s)
{
	size_t n = strlen(s), i = 0, sept = 0, ucs = 0;
	bool gsm = true;

	while (i < n) {
		uint32_t cp;
		uint8_t o[2];
		int k = utf8_decode(s + i, n - i, &cp), g;

		if (k < 0)
			return -1;
		i += (size_t)k;
		g = gsm7_from_cp(cp, o);
		if (g == 0)
			gsm = false;
		sept += (size_t)(g ? g : 1);
		ucs += cp > 0xFFFF ? 2 : 1;
	}
	if (!sept)
		return 0;
	if (gsm)
		return sept <= 160 ? 1 : (int)((sept + 152) / 153);
	return ucs <= 70 ? 1 : (int)((ucs + 66) / 67);
}

static void seterr(struct cssms *s, const char *fmt, const char *a)
{
	snprintf(s->st.last_error, sizeof(s->st.last_error), fmt, a);
}

/* ------------------------------------------------------------------ requests */

static void sreq_done(void *arg, const struct csu_res *r);
static void work_next(struct cssms *s);
static void mo_next(struct cssms *s);

static bool sreq_start(struct cssms *s, enum sk kind, const struct csu_req *rq)
{
	struct sreq *q;

	if (s->n_reqs >= MAX_REQS)
		return false;
	q = calloc(1, sizeof(*q));
	if (!q)
		return false;
	q->s = s;
	q->kind = kind;
	q->gen = csline_status(s->line)->gen;
	q->serial = s->cur_serial;
	q->next = s->reqs;
	s->reqs = q;
	s->n_reqs++;
	q->h = csline_call(s->line, rq, sreq_done, q);
	if (!q->h && !q->fired) {
		struct sreq **pp;

		for (pp = &s->reqs; *pp; pp = &(*pp)->next)
			if (*pp == q) {
				*pp = q->next;
				break;
			}
		s->n_reqs--;
		free(q);
		return false;
	}
	return true;
}

static void req_init(struct csu_req *rq, enum csu_op op, const char *obj, const char *str)
{
	memset(rq, 0, sizeof(*rq));
	rq->op = op;
	rq->sms_class = -1;
	str_copy(rq->obj, obj, sizeof(rq->obj));
	if (str)
		str_copy(rq->str, str, sizeof(rq->str));
}

/* ------------------------------------------------------------------ incoming */

static bool was_handled(const struct cssms *s, const char *path)
{
	unsigned i;

	for (i = 0; i < s->h_n; i++)
		if (!strcmp(s->handled[i], path))
			return true;
	return false;
}

static void mark_handled(struct cssms *s, const char *path)
{
	str_copy(s->handled[s->h_next], path, CSU_PATH);
	s->h_next = (s->h_next + 1) % HANDLED_MAX;
	if (s->h_n < HANDLED_MAX)
		s->h_n++;
}

static bool queued(const struct cssms *s, const char *path)
{
	unsigned i;

	for (i = 0; i < s->w_n; i++)
		if (!strcmp(s->work[(s->w_head + i) % WORK_MAX].path, path))
			return true;
	return false;
}

static bool enqueue(struct cssms *s, const char *path, enum wk kind, bool backlog, unsigned tries)
{
	struct work *w;

	if (kind == WK_READ && (was_handled(s, path) || queued(s, path)))
		return true;
	if (s->w_n >= WORK_MAX) {
		s->st.rx_overflow++;
		s->relist = true;		/* the object stays in uqmid: a later list finds it again */
		return false;
	}
	w = &s->work[(s->w_head + s->w_n) % WORK_MAX];
	str_copy(w->path, path, sizeof(w->path));
	w->kind = kind;
	w->backlog = backlog;
	w->tries = tries;
	w->not_before = tries ? ev_now_ms() + s->cfg.retry_ms : 0;
	s->w_n++;
	ev_timer_set(s->t_work, tries ? s->cfg.retry_ms : 0);
	return true;
}

static void work_pop(struct cssms *s)
{
	s->w_head = (s->w_head + 1) % WORK_MAX;
	s->w_n--;
	s->w_busy = false;
}

static void inc_remove(struct cssms *s, const char *path)
{
	unsigned i;

	for (i = 0; i < s->n_inc; i++) {
		if (!strcmp(s->inc[i].path, path)) {
			s->inc[i] = s->inc[--s->n_inc];
			return;
		}
	}
}

static void inc_add(struct cssms *s, const char *path)
{
	unsigned i;

	for (i = 0; i < s->n_inc; i++)
		if (!strcmp(s->inc[i].path, path))
			return;
	if (s->n_inc >= INC_MAX) {
		/* the oldest goes: its parts are deleted at once */
		enqueue(s, s->inc[0].path, WK_DELETE, false, 0);
		s->st.rx_dropped_incomplete++;
		s->inc[0] = s->inc[--s->n_inc];
	}
	str_copy(s->inc[s->n_inc].path, path, CSU_PATH);
	s->inc[s->n_inc].since = ev_now_ms();
	s->n_inc++;
	ev_timer_set(s->t_gc, 60000);
}

static bool looks_numeric(const char *n)
{
	const char *p = n;

	if (*p == '+')
		p++;
	if (!*p)
		return false;
	for (; *p; p++)
		if (!isdigit((unsigned char)*p) && *p != '*' && *p != '#')
			return false;
	return true;
}

/* WSP Push (WAP-230): <TID> 06|07 <headers len> <content type ...>; the MMS notification has application/vnd.wap.mms-message
 * (well known content type 0x3E = octet 0xBE, or the text) */
static void wsp_sniff(const uint8_t *d, size_t n, bool *push, bool *mms)
{
	*push = *mms = false;
	if (n < 4 || (d[1] != 0x06 && d[1] != 0x07))
		return;
	*push = true;
	if (d[3] == 0xBE || memmem(d, n, "application/vnd.wap.mms-message", 30))
		*mms = true;
}

static int deliver(struct cssms *s, const struct csu_res *r, bool backlog)
{
	int rc = 0;
	struct cssms_in in;
	bool report = !strcmp(r->sms_pdu, "status-report");

	memset(&in, 0, sizeof(in));
	str_copy(in.from, r->sms_number, sizeof(in.from));
	in.from_alnum = !looks_numeric(in.from);
	str_copy(in.ts, r->sms_timestamp, sizeof(in.ts));
	in.sms_class = r->sms_class;
	in.multipart = r->sms_multipart;
	in.parts = r->sms_multipart && r->sms_max_parts > 0 ? (unsigned)r->sms_max_parts : 1;
	in.backlog = backlog;
	in.truncated = r->sms_text_cut;
	in.id = ++s->in_serial;
	if (report) {
		in.kind = CSSMS_REPORT;
		in.message_reference = r->sms_msgref;
		in.delivery_state = r->sms_delivery_state;
		str_copy(in.discharge_ts, r->sms_discharge, sizeof(in.discharge_ts));
		s->st.rx_reports++;
	} else if (r->sms_has_data && !r->sms_has_text) {
		in.kind = CSSMS_DATA;
		in.data = r->sms_data;
		in.data_len = r->sms_data_len;
		wsp_sniff(in.data, in.data_len, &in.wsp_push, &in.mms_hint);
		s->st.rx_data++;
	} else {
		in.kind = CSSMS_TEXT;
		in.text = r->sms_text;
		s->st.rx_text++;
	}
	if (backlog)
		s->st.rx_backlog++;
	LOGI("cs: sms from %s: %s%s%s", in.from[0] ? in.from : "?", in.kind == CSSMS_TEXT ? "text" : in.kind == CSSMS_DATA ? "binary" : "status report",
	     in.multipart ? " (concatenated)" : "", backlog ? " (backlog)" : "");
	if (s->cfg.on_message)
		rc = s->cfg.on_message(s->cfg.arg, &in);
	if (rc > 0)
		s->pend_id = in.id;
	return rc;
}

static void unmark_handled(struct cssms *s, const char *path)
{
	unsigned i;

	for (i = 0; i < s->h_n; i++)
		if (!strcmp(s->handled[i], path))
			s->handled[i][0] = 0;
}

/* the taker did not take the head: it stays in the modem and a later list offers it again */
static void not_taken(struct cssms *s)
{
	struct work *w = &s->work[s->w_head];

	LOGW("cs: sms %s was not taken, it stays in the modem and is offered again", w->path);
	s->st.rx_kept = ++s->pass_kept;
	if (s->pass_kept == 21)
		LOGW("cs: sms: more than 20 messages are kept in the modem (nobody can take them now); the network holds back further ones when its storage is full");
	unmark_handled(s, w->path);
	work_pop(s);
	s->relist = true;
	ev_timer_set(s->t_gc, s->cfg.retry_ms);
	work_next(s);
}

static void work_next(struct cssms *s)
{
	struct work *w;
	struct csu_req rq;
	const char *modem = csline_modem(s->line);

	if (s->dying || s->w_busy || !s->w_n)
		return;
	if (!modem[0])
		return;			/* nothing to ask; the work stays until a modem is there (or l_modem clears it) */
	w = &s->work[s->w_head];
	if (w->not_before > ev_now_ms()) {	/* head of line: a failed delete is retried before anything else is read */
		ev_timer_set(s->t_work, w->not_before - ev_now_ms());
		return;
	}
	if (w->kind == WK_READ)
		req_init(&rq, CSU_SMS_GET, w->path, NULL);
	else
		req_init(&rq, CSU_SMS_DELETE, modem, w->path);
	s->w_busy = true;
	if (!sreq_start(s, w->kind == WK_READ ? SK_READ : SK_DELETE, &rq)) {
		s->w_busy = false;
		ev_timer_set(s->t_work, s->cfg.retry_ms);
	}
}

static void start_list(struct cssms *s)
{
	struct csu_req rq;

	if (!csline_modem(s->line)[0])
		return;
	req_init(&rq, CSU_SMS_LIST, csline_modem(s->line), NULL);
	s->listing = true;
	if (!sreq_start(s, SK_LIST, &rq)) {
		s->listing = false;
		s->relist = true;
		ev_timer_set(s->t_gc, s->cfg.retry_ms);
	}
}

/* the drain is complete when the queue is empty and a list found nothing new */
static void drain_check(struct cssms *s)
{
	if (s->drained || !s->drain_started)
		return;
	if (s->w_n || s->w_busy || s->relist || s->listing)
		return;
	s->drained = true;
	LOGI("cs: sms: start-up drain done (%lu backlog message(s) delivered)", s->st.rx_backlog);
}

static void gc_cb(void *arg)
{
	struct cssms *s = arg;
	uint64_t now = ev_now_ms();
	unsigned i;

	if (s->dying)
		return;
	for (i = 0; i < s->n_inc;) {
		if (now - s->inc[i].since >= s->cfg.incomplete_ms) {
			LOGW("cs: sms %s is still incomplete after %u s: deleted", s->inc[i].path, s->cfg.incomplete_ms / 1000);
			s->st.rx_dropped_incomplete++;
			enqueue(s, s->inc[i].path, WK_DELETE, false, 0);
			s->inc[i] = s->inc[--s->n_inc];
		} else {
			i++;
		}
	}
	if (s->n_inc)
		ev_timer_set(s->t_gc, 60000);
	/* a list that failed, a queue overflow or kept (not taken) objects: look again; quick passes first, then one per slow_retry_ms.
	 * Running out of passes never deletes anything. */
	if (s->relist && s->drain_started && (s->w_n || s->w_busy)) {
		ev_timer_set(s->t_gc, s->kicked ? 200 : s->cfg.retry_ms);
	} else if (s->relist && s->drain_started) {
		if (s->passes >= DRAIN_PASSES) {
			if (!s->slow_at)
				s->slow_at = now + s->cfg.slow_retry_ms;
			if (now < s->slow_at) {
				ev_timer_set(s->t_gc, (unsigned)(s->slow_at - now));
				return;
			}
			s->slow_at = 0;		/* one slow pass; the bound stays reached */
		} else {
			s->passes++;
		}
		s->relist = s->kicked = false;
		s->pass_kept = 0;
		start_list(s);
	}
}

void cssms_kick(struct cssms *s)
{
	if (!s || s->dying || !s->drain_started)
		return;
	s->passes = 0;
	s->slow_at = 0;
	s->kicked = true;
	s->relist = true;
	ev_timer_set(s->t_gc, 0);
}

static void on_read(struct cssms *s, const struct csu_res *r)
{
	struct work *w = &s->work[s->w_head];
	int rc;

	if (r->err) {
		if (r->err != CSU_E_GONE)
			seterr(s, "cannot read an sms object: %.100s", r->errmsg);
		work_pop(s);			/* gone (deleted elsewhere): nothing to do */
		work_next(s);
		drain_check(s);
		return;
	}
	if (!strcmp(r->sms_state, "receiving")) {
		inc_add(s, w->path);		/* parts missing: waits for state_changed -> received */
		work_pop(s);
		work_next(s);
		drain_check(s);
		return;
	}
	if (strcmp(r->sms_state, "received") || (strcmp(r->sms_pdu, "deliver") && strcmp(r->sms_pdu, "status-report"))) {
		work_pop(s);			/* ours (sent / stored) or unknown: not an incoming message */
		work_next(s);
		drain_check(s);
		return;
	}
	inc_remove(s, w->path);
	mark_handled(s, w->path);
	rc = deliver(s, r, w->backlog);
	if (rc < 0) {
		not_taken(s);
		return;
	}
	/* the same work item becomes the delete: at once (taken), or when the taker confirms it (pending: the queue waits) */
	w->kind = WK_DELETE;
	if (rc > 0) {
		s->w_pending = true;
		return;
	}
	s->w_busy = false;
	work_next(s);
}

void cssms_in_done(struct cssms *s, unsigned id, bool taken)
{
	if (s->dying || !s->w_pending || id != s->pend_id)
		return;
	s->w_pending = false;
	if (!taken) {
		not_taken(s);
		return;
	}
	s->w_busy = false;
	work_next(s);
}

static void on_delete(struct cssms *s, const struct csu_res *r)
{
	struct work w = s->work[s->w_head];

	work_pop(s);
	if (!r->err || r->err == CSU_E_GONE) {
		s->st.rx_deleted++;
	} else if (w.tries + 1 < DEL_TRIES) {
		enqueue(s, w.path, WK_DELETE, false, w.tries + 1);
	} else {
		s->st.rx_delete_failed++;
		seterr(s, "cannot delete an sms object: %.100s", r->errmsg);
		LOGW("cs: sms: giving up deleting %s: %s", w.path, r->errmsg);
	}
	work_next(s);
	drain_check(s);
}

static void on_list(struct cssms *s, const struct csu_res *r)
{
	int i;
	bool more = false;

	s->listing = false;
	if (r->err) {
		s->relist = true;
		ev_timer_set(s->t_gc, s->cfg.retry_ms);
		return;
	}
	for (i = 0; i < r->n_paths; i++) {
		if (was_handled(s, r->paths[i]))
			continue;
		if (!enqueue(s, r->paths[i], WK_READ, !s->drained, 0))
			more = true;
	}
	if (r->n_paths >= CSU_MAX_PATHS)	/* the list is cut: more may follow once these are deleted */
		more = true;
	if (more) {
		s->relist = true;
		ev_timer_set(s->t_gc, 500);
	}
	drain_check(s);
}

/* ------------------------------------------------------------------ outgoing */

static void mo_free(struct mo *m)
{
	free(m->text);
	free(m);
}

static void mo_finish(struct cssms *s, struct mo *m, int status, const char *text)
{
	struct cssms_result r;

	memset(&r, 0, sizeof(r));
	r.status = status;
	str_copy(r.text, text, sizeof(r.text));
	r.parts = m->parts;
	if (m->path[0] && csline_modem(s->line)[0]) {	/* timed out after the object was created: do not leave it behind */
		struct csu_req rq;

		req_init(&rq, CSU_SMS_DELETE, csline_modem(s->line), m->path);
		sreq_start(s, SK_MODELETE, &rq);
	}
	s->mo_head = m->next;
	if (!s->mo_head)
		s->mo_tail = NULL;
	s->mo_n--;
	s->mo_busy = false;
	ev_timer_cancel(s->t_mo);
	if (status == 200)
		s->st.mo_ok++;
	else {
		s->st.mo_failed++;
		snprintf(s->st.last_error, sizeof(s->st.last_error), "MO to %s failed: %s", m->dest, text);
	}
	if (m->cb)
		m->cb(m->arg, &r);
	mo_free(m);
	mo_next(s);
}

static int map_send_error(const struct csu_res *r, char *text, size_t n)
{
	char low[160];
	size_t i;
	int status;

	for (i = 0; i < sizeof(low) - 1 && r->errmsg[i]; i++)
		low[i] = (char)tolower((unsigned char)r->errmsg[i]);
	low[i] = 0;
	switch (r->err) {
	case CSU_E_TIMEOUT:
		status = 504;
		break;
	case CSU_E_STATE:
		status = 480;			/* wrong-state: the modem is not enabled / registered */
		break;
	case CSU_E_ARGS:
		status = 484;
		break;
	case CSU_E_GONE:
	case CSU_E_CONN:
	case CSU_E_BUSY:
		status = 503;
		break;
	default:
		if (strstr(low, "timed out"))
			status = 504;
		else if (strstr(low, "network not ready") || strstr(low, "no network") || strstr(low, "no radio") || strstr(low, "out of call") ||
			 strstr(low, "no memory") || strstr(low, "memory"))
			status = 503;		/* temporary */
		else
			status = 502;		/* the network (RP-ERROR / delivery failure) refused it */
		break;
	}
	snprintf(text, n, "uqmid: %.24s%s%.90s", r->errname[0] ? r->errname : "failed", r->errmsg[0] ? ": " : "", r->errmsg);
	return status;
}

static void mo_timeout(void *arg)
{
	struct cssms *s = arg;

	if (s->mo_head && s->mo_busy) {
		/* the answer of the stuck request is void now: its callback is ignored (kind check) */
		s->mo_busy = false;
		mo_finish(s, s->mo_head, 504, "the modem did not answer in time");
	}
}

static void mo_next(struct cssms *s)
{
	struct mo *m = s->mo_head;
	struct csu_req rq;

	if (s->dying || !m || s->mo_busy)
		return;
	if (!csline_status(s->line)->sms_ok) {
		mo_finish(s, m, csline_status(s->line)->modem[0] ? 480 : 503, csline_status(s->line)->reason);
		return;
	}
	req_init(&rq, CSU_SMS_CREATE, csline_modem(s->line), m->dest);
	rq.text = m->text;
	rq.dra = m->dra;
	rq.validity_min = m->vp;
	m->path[0] = 0;
	m->serial = ++s->mo_serial;
	s->cur_serial = m->serial;
	s->mo_busy = true;
	if (!sreq_start(s, SK_CREATE, &rq)) {
		s->mo_busy = false;
		mo_finish(s, m, 503, "cannot start the request");
		return;
	}
	ev_timer_set(s->t_mo, s->cfg.send_timeout_ms);
}

static void on_mo_reply(struct cssms *s, enum sk kind, unsigned serial, const struct csu_res *r)
{
	struct mo *m = s->mo_head;
	struct csu_req rq;
	char text[128];
	int status;

	if (!m || !s->mo_busy || m->serial != serial) {
		if (kind == SK_CREATE && !r->err && r->path[0]) {	/* a late answer after the timeout: do not leave the object */
			req_init(&rq, CSU_SMS_DELETE, csline_modem(s->line), r->path);
			sreq_start(s, SK_MODELETE, &rq);
		}
		return;
	}
	if (kind == SK_CREATE) {
		if (r->err) {
			status = map_send_error(r, text, sizeof(text));
			mo_finish(s, m, status, text);
			return;
		}
		str_copy(m->path, r->path, sizeof(m->path));
		req_init(&rq, CSU_SMS_SEND, m->path, NULL);
		s->cur_serial = m->serial;
		if (!sreq_start(s, SK_SEND, &rq))
			mo_finish(s, m, 503, "cannot start the request");
		return;
	}
	/* SK_SEND done: the object goes either way */
	if (m->path[0]) {
		req_init(&rq, CSU_SMS_DELETE, csline_modem(s->line), m->path);
		sreq_start(s, SK_MODELETE, &rq);
		m->path[0] = 0;
	}
	if (r->err) {
		status = map_send_error(r, text, sizeof(text));
		mo_finish(s, m, status, text);
	} else {
		mo_finish(s, m, 200, "sent");
	}
}

int cssms_submit(struct cssms *s, const struct cssms_submit *q, cssms_done_cb cb, void *arg)
{
	struct mo *m;
	int parts;
	size_t i;

	if (!q || !q->dest || !q->text || !*q->text)
		return -EINVAL;
	parts = cssms_count_parts(q->text);
	if (parts < 0)
		return -EINVAL;
	{
		const char *d = q->dest;
		size_t nd = 0;

		if (*d == '+')
			d++;
		for (i = 0; d[i]; i++) {
			if (!isdigit((unsigned char)d[i]) && d[i] != '*' && d[i] != '#')
				return -EDESTADDRREQ;
			nd++;
		}
		if (!nd || nd > 20)
			return -EDESTADDRREQ;
	}
	if ((unsigned)parts > s->cfg.max_segments)
		return -E2BIG;
	if (!csline_status(s->line)->sms_ok)
		return -ENOTCONN;
	if (s->mo_n >= s->cfg.queue_max)
		return -ENOBUFS;
	m = calloc(1, sizeof(*m));
	if (!m)
		return -ENOMEM;
	m->text = strdup(q->text);
	if (!m->text) {
		free(m);
		return -ENOMEM;
	}
	str_copy(m->dest, q->dest, sizeof(m->dest));
	m->dra = q->delivery_report;
	m->vp = q->vp_minutes;
	m->parts = (unsigned)parts;
	m->cb = cb;
	m->arg = arg;
	if (s->mo_tail)
		s->mo_tail->next = m;
	else
		s->mo_head = m;
	s->mo_tail = m;
	s->mo_n++;
	ev_timer_set(s->t_work, 0);		/* mo_next from the loop, never from inside submit */
	return 0;
}

/* ------------------------------------------------------------------ completion + line events */

static void sreq_done(void *arg, const struct csu_res *r)
{
	struct sreq *q = arg;
	struct cssms *s = q->s;
	enum sk kind = q->kind;
	unsigned serial = q->serial;
	bool stale = q->gen != csline_status(s->line)->gen;
	struct sreq **pp;

	q->fired = true;
	for (pp = &s->reqs; *pp; pp = &(*pp)->next)
		if (*pp == q) {
			*pp = q->next;
			break;
		}
	s->n_reqs--;
	free(q);
	if (s->dying || stale)
		return;			/* the modem object changed: l_modem reset everything */
	switch (kind) {
	case SK_LIST:
		on_list(s, r);
		break;
	case SK_READ:
		on_read(s, r);
		break;
	case SK_DELETE:
		on_delete(s, r);
		break;
	case SK_CREATE:
	case SK_SEND:
		on_mo_reply(s, kind, serial, r);
		break;
	case SK_MODELETE:
		break;
	}
}

static void mo_fail_all(struct cssms *s, int status, const char *text)
{
	while (s->mo_head) {
		s->mo_busy = false;
		mo_finish(s, s->mo_head, status, text);
	}
}

static void l_modem(void *arg, bool present, const char *path, unsigned gen)
{
	struct cssms *s = arg;

	(void)path;
	s->gen = gen;
	s->w_head = s->w_n = 0;
	s->w_busy = false;
	s->w_pending = false;
	s->n_inc = 0;
	s->h_n = s->h_next = 0;
	s->drain_started = s->drained = s->relist = false;
	s->passes = s->pass_kept = 0;
	s->slow_at = 0;
	s->kicked = false;
	if (!present && s->mo_head)
		mo_fail_all(s, 503, "the modem went away");
}

static void maybe_start_drain(struct cssms *s, const struct csline_status *st)
{
	if (s->drain_started || !st->modem[0] || !st->enabled)
		return;
	s->drain_started = true;
	s->passes = 1;
	start_list(s);
}

static void l_status(void *arg, const struct csline_status *st)
{
	struct cssms *s = arg;

	maybe_start_drain(s, st);
	if (s->mo_head && !s->mo_busy)
		mo_next(s);
}

static void l_notify(void *arg, const struct csu_notify *n)
{
	struct cssms *s = arg;

	if (!strcmp(n->method, "messaging.added")) {
		if (n->received) {
			enqueue(s, n->path, WK_READ, !s->drained, 0);
			if (s->relist)
				cssms_kick(s);
		}
	} else if (!strcmp(n->method, "messaging.state_changed")) {
		if (!strcmp(n->new_state, "received"))
			enqueue(s, n->path, WK_READ, !s->drained, 0);
	} else if (!strcmp(n->method, "messaging.deleted")) {
		inc_remove(s, n->path);
	}
}

static void t_work_cb(void *arg)
{
	struct cssms *s = arg;

	work_next(s);
	mo_next(s);
}

struct cssms *cssms_new(struct csline *line, const struct cssms_cfg *cfg)
{
	struct cssms *s = calloc(1, sizeof(*s));
	struct csline_listener l = { 0 };

	if (!s)
		return NULL;
	s->line = line;
	s->cfg = *cfg;
	clamp(&s->cfg);
	s->gen = csline_status(line)->gen;
	s->t_work = ev_timer_new(t_work_cb, s);
	s->t_gc = ev_timer_new(gc_cb, s);
	s->t_mo = ev_timer_new(mo_timeout, s);
	l.on_modem = l_modem;
	l.on_notify = l_notify;
	l.on_status = l_status;
	l.arg = s;
	if (!s->t_work || !s->t_gc || !s->t_mo || csline_add_listener(line, &l)) {
		ev_timer_free(s->t_work);
		ev_timer_free(s->t_gc);
		ev_timer_free(s->t_mo);
		free(s);
		return NULL;
	}
	maybe_start_drain(s, csline_status(line));
	return s;
}

void cssms_free(struct cssms *s)
{
	if (!s)
		return;
	s->dying = true;
	csline_remove_listener(s->line, s);
	while (s->reqs) {
		struct sreq *q = s->reqs;

		s->reqs = q->next;
		csline_cancel(s->line, q->h);
		free(q);
	}
	while (s->mo_head) {
		struct mo *m = s->mo_head;
		struct cssms_result r = { .status = 503 };

		s->mo_head = m->next;
		str_copy(r.text, "shutting down", sizeof(r.text));
		if (m->cb)
			m->cb(m->arg, &r);
		mo_free(m);
	}
	ev_timer_free(s->t_work);
	ev_timer_free(s->t_gc);
	ev_timer_free(s->t_mo);
	free(s);
}

void cssms_set_cfg(struct cssms *s, const struct cssms_cfg *cfg)
{
	s->cfg = *cfg;
	clamp(&s->cfg);
}

void cssms_get_status(const struct cssms *s, struct cssms_status *st)
{
	*st = s->st;
	st->drained = s->drained;
	st->work_len = s->w_n;
	st->incomplete = s->n_inc;
	st->mo_queue = s->mo_n;
}
