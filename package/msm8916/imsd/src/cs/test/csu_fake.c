/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "csu_fake.h"
#include "../../util/evloop.h"
#include "../../util/sys.h"

struct fk FK;

struct fh {
	struct fh *next;
	struct csu_req rq;
	char text[2048];
	uint8_t data[300];
	csu_cb cb;
	void *arg;
	struct ev_timer *t;
	bool parked;
};

static struct fh *HEAD;

static void order(char c)
{
	size_t n = strlen(FK.order);

	if (n + 1 < sizeof(FK.order)) {
		FK.order[n] = c;
		FK.order[n + 1] = 0;
	}
}

void fk_reset(struct csline *line)
{
	struct fh *h;

	while ((h = HEAD)) {
		HEAD = h->next;
		ev_timer_free(h->t);
		free(h);
	}
	memset(&FK, 0, sizeof(FK));
	FK.line = line;
	strcpy(FK.modem, "uqmid.modem.0");
	strcpy(FK.device, "/dev/wwan0qmi0");
	strcpy(FK.mstate, "registered");
	strcpy(FK.reg, "home");
	strcpy(FK.act, "umts hspa");
	strcpy(FK.opcode, "45005");
	strcpy(FK.opname, "SKTelecom");
	strcpy(FK.own, "+821012345678");
	FK.modem_listed = true;
	FK.notify_before_reply = true;
}

void fk_notify(const char *method, const char *path, const char *old, const char *nw, const char *reason, bool received)
{
	struct csu_notify n;

	memset(&n, 0, sizeof(n));
	snprintf(n.method, sizeof(n.method), "%s", method);
	snprintf(n.path, sizeof(n.path), "%s", path ? path : "");
	snprintf(n.old_state, sizeof(n.old_state), "%s", old ? old : "");
	snprintf(n.new_state, sizeof(n.new_state), "%s", nw ? nw : "");
	snprintf(n.reason, sizeof(n.reason), "%s", reason ? reason : "");
	n.received = received;
	if (!strcmp(method, "registration_state_changed")) {
		snprintf(n.operator_code, sizeof(n.operator_code), "%s", FK.opcode);
		snprintf(n.operator_name, sizeof(n.operator_name), "%s", FK.opname);
	}
	csline_ev_notify(FK.line, &n);
}

struct fk_call *fk_find_call(const char *path)
{
	int i;

	for (i = 0; i < FK_CALLS; i++)
		if (FK.call[i].used && !strcmp(FK.call[i].path, path))
			return &FK.call[i];
	return NULL;
}

struct fk_sms *fk_find_sms(const char *path)
{
	int i;

	for (i = 0; i < FK_SMS; i++)
		if (FK.sms[i].used && !strcmp(FK.sms[i].path, path))
			return &FK.sms[i];
	return NULL;
}

int fk_live_calls(void)
{
	int i, n = 0;

	for (i = 0; i < FK_CALLS; i++)
		n += FK.call[i].used;
	return n;
}

static struct fk_call *call_alloc(const char *dir, const char *number, const char *state)
{
	int i;

	for (i = 0; i < FK_CALLS; i++) {
		struct fk_call *c = &FK.call[i];

		if (c->used)
			continue;
		memset(c, 0, sizeof(*c));
		c->used = true;
		snprintf(c->path, sizeof(c->path), "%s.call.%u", FK.modem, FK.next_call++);
		snprintf(c->dir, sizeof(c->dir), "%s", dir);
		snprintf(c->number, sizeof(c->number), "%s", number);
		snprintf(c->state, sizeof(c->state), "%s", state);
		snprintf(c->reason, sizeof(c->reason), "unknown");
		c->qid = (int)FK.next_call;
		return c;
	}
	return NULL;
}

struct fk_call *fk_net_ring(const char *number)
{
	struct fk_call *c = call_alloc("incoming", number, "ringing-in");

	if (!c)
		return NULL;
	snprintf(c->reason, sizeof(c->reason), "incoming-new");
	fk_notify("voice.call_added", c->path, NULL, NULL, NULL, false);
	return c;
}

void fk_net_state_quiet(const char *path, const char *state)
{
	struct fk_call *c = fk_find_call(path);

	if (c) {
		snprintf(c->state, sizeof(c->state), "%s", state);
		if (!strcmp(state, "terminated"))
			c->qid = 0;
	}
}

void fk_net_state(const char *path, const char *state, const char *reason)
{
	struct fk_call *c = fk_find_call(path);
	char old[16];

	if (!c)
		return;
	snprintf(old, sizeof(old), "%s", c->state);
	fk_net_state_quiet(path, state);
	snprintf(c->reason, sizeof(c->reason), "%s", reason ? reason : "unknown");
	if (!strcmp(state, "terminated") && (c->end_cause || c->er_value)) {
		struct csu_notify n;

		memset(&n, 0, sizeof(n));
		snprintf(n.method, sizeof(n.method), "voice.call_state_changed");
		snprintf(n.path, sizeof(n.path), "%s", path);
		snprintf(n.old_state, sizeof(n.old_state), "%s", old);
		snprintf(n.new_state, sizeof(n.new_state), "%s", state);
		snprintf(n.reason, sizeof(n.reason), "%s", c->reason);
		n.cc_cause = c->end_cause;
		n.end_reason = c->er_value;
		snprintf(n.end_reason_name, sizeof(n.end_reason_name), "%s", c->er_name);
		csline_ev_notify(FK.line, &n);
		return;
	}
	fk_notify("voice.call_state_changed", path, old, state, c->reason, false);
}

void fk_set_end(const char *path, int cc_cause, int er_value, const char *er_name)
{
	struct fk_call *c = fk_find_call(path);

	if (!c)
		return;
	c->end_cause = cc_cause;
	c->er_value = er_value;
	snprintf(c->er_name, sizeof(c->er_name), "%s", er_name ? er_name : "");
}

static struct fk_sms *sms_alloc(const char *state, const char *pdu, const char *number)
{
	int i;

	for (i = 0; i < FK_SMS; i++) {
		struct fk_sms *s = &FK.sms[i];

		if (s->used)
			continue;
		memset(s, 0, sizeof(*s));
		s->used = true;
		s->cls = -1;
		snprintf(s->path, sizeof(s->path), "%s.sms.%u", FK.modem, FK.next_sms++);
		snprintf(s->state, sizeof(s->state), "%s", state);
		snprintf(s->pdu, sizeof(s->pdu), "%s", pdu);
		snprintf(s->number, sizeof(s->number), "%s", number);
		snprintf(s->ts, sizeof(s->ts), "2026-11-20T09:00:00+09:00");
		return s;
	}
	return NULL;
}

struct fk_sms *fk_net_sms(const char *number, const char *text, bool notify)
{
	struct fk_sms *s = sms_alloc("received", "deliver", number);

	if (!s)
		return NULL;
	s->has_text = true;
	snprintf(s->text, sizeof(s->text), "%s", text);
	if (notify)
		fk_notify("messaging.added", s->path, NULL, NULL, NULL, true);
	return s;
}

struct fk_sms *fk_net_sms_part(const char *number, int max_parts, int got)
{
	struct fk_sms *s = sms_alloc("receiving", "deliver", number);

	if (!s)
		return NULL;
	s->multipart = true;
	s->maxp = max_parts;
	s->parts = got;
	fk_notify("messaging.added", s->path, NULL, NULL, NULL, true);
	return s;
}

void fk_net_sms_complete(struct fk_sms *s, const char *text)
{
	s->parts = s->maxp;
	s->has_text = true;
	snprintf(s->text, sizeof(s->text), "%s", text);
	snprintf(s->state, sizeof(s->state), "received");
	fk_notify("messaging.state_changed", s->path, "receiving", "received", NULL, false);
}

void fk_modem_state(const char *state, const char *reg, const char *act, bool notify)
{
	char old[16];

	snprintf(old, sizeof(old), "%s", FK.mstate);
	if (state)
		snprintf(FK.mstate, sizeof(FK.mstate), "%s", state);
	if (reg)
		snprintf(FK.reg, sizeof(FK.reg), "%s", reg);
	if (act)
		snprintf(FK.act, sizeof(FK.act), "%s", act);
	if (notify) {
		if (state)
			fk_notify("state_changed", FK.modem, old, FK.mstate, "unknown", false);
		if (reg)
			fk_notify("registration_state_changed", FK.modem, "x", FK.reg, NULL, false);
	}
}

void fk_modem_add(void)
{
	csline_ev_modem_added(FK.line, FK.modem, FK.device);
}

void fk_modem_remove(void)
{
	csline_ev_modem_removed(FK.line, FK.modem);
}

void fk_fail_next(int op, int count, int err, const char *name, const char *msg)
{
	FK.fail[op].count = count;
	FK.fail[op].err = err;
	snprintf(FK.fail[op].name, sizeof(FK.fail[op].name), "%s", name ? name : "");
	snprintf(FK.fail[op].msg, sizeof(FK.fail[op].msg), "%s", msg ? msg : "");
}

/* ------------------------------------------------------------------ the requests */

static void errset(struct csu_res *r, int err, const char *name, const char *msg)
{
	r->err = err;
	snprintf(r->errname, sizeof(r->errname), "%s", name);
	snprintf(r->errmsg, sizeof(r->errmsg), "%s", msg);
}

static void exec(struct fh *h, struct csu_res *r)
{
	const struct csu_req *q = &h->rq;
	struct fk_call *c;
	struct fk_sms *s;
	int i;

	r->end_cause = 0;
	r->end_reason = 0;
	r->end_reason_name[0] = 0;
	r->sms_class = -1;
	if (FK.fail[q->op].count > 0) {
		FK.fail[q->op].count--;
		errset(r, FK.fail[q->op].err, FK.fail[q->op].name, FK.fail[q->op].msg);
		return;
	}
	switch (q->op) {
	case CSU_LIST:
		if (FK.modem_listed) {
			snprintf(r->modems[0].path, CSU_PATH, "%s", FK.modem);
			snprintf(r->modems[0].device, sizeof(r->modems[0].device), "%s", FK.device);
			snprintf(r->modems[0].state, sizeof(r->modems[0].state), "%s", FK.mstate);
			r->n_modems = 1;
			if (FK.list_two) {
				snprintf(r->modems[1].path, CSU_PATH, "uqmid.modem.1");
				snprintf(r->modems[1].device, sizeof(r->modems[1].device), "/dev/wwan1qmi0");
				r->n_modems = 2;
			}
		}
		break;
	case CSU_ENABLE:
		if (strcmp(q->obj, FK.modem)) {
			errset(r, CSU_E_GONE, "not-found", "no modem");
			break;
		}
		order('E');
		if (q->flag) {
			char old[16];

			snprintf(old, sizeof(old), "%s", FK.mstate);
			snprintf(FK.mstate, sizeof(FK.mstate), "enabled");
			fk_notify("state_changed", FK.modem, old, "enabled", "user-requested", false);
		}
		break;
	case CSU_MODEM_GET:
		if (strcmp(q->obj, FK.modem)) {
			errset(r, CSU_E_GONE, "not-found", "no such modem");
			break;
		}
		snprintf(r->state, sizeof(r->state), "%s", FK.mstate);
		snprintf(r->reg_state, sizeof(r->reg_state), "%s", FK.reg);
		snprintf(r->act, sizeof(r->act), "%s", FK.act);
		snprintf(r->operator_code, sizeof(r->operator_code), "%s", FK.opcode);
		snprintf(r->operator_name, sizeof(r->operator_name), "%s", FK.opname);
		snprintf(r->own_number, sizeof(r->own_number), "%s", FK.own);
		r->emergency_only = FK.emerg;
		break;
	case CSU_CALL_CREATE:
		if (strcmp(q->obj, FK.modem) || !strcmp(FK.mstate, "disabled")) {
			errset(r, CSU_E_STATE, "wrong-state", "Modem is not enabled");
			break;
		}
		c = call_alloc("outgoing", q->str, "unknown");
		if (!c) {
			errset(r, CSU_E_FAILED, "failed", "too many calls");
			break;
		}
		order('C');
		snprintf(FK.last_create_num, sizeof(FK.last_create_num), "%s", q->str);
		fk_notify("voice.call_added", c->path, NULL, NULL, NULL, false);
		snprintf(r->path, sizeof(r->path), "%s", c->path);
		break;
	case CSU_CALL_START:
		c = fk_find_call(q->obj);
		if (!c) {
			errset(r, CSU_E_GONE, "not-found", "no such call");
			break;
		}
		order('S');
		if (strcmp(c->state, "unknown")) {
			errset(r, CSU_E_FAILED, "failed", "This call was not in unknown state, cannot start it");
			break;
		}
		if (FK.emerg) {
			snprintf(c->state, sizeof(c->state), "terminated");
			errset(r, CSU_E_STATE, "unauthorized", "only emergency calls allowed");
			break;
		}
		snprintf(c->state, sizeof(c->state), "dialing");
		snprintf(c->reason, sizeof(c->reason), "outgoing-started");
		fk_notify("voice.call_state_changed", c->path, "unknown", "dialing", "outgoing-started", false);
		break;
	case CSU_CALL_ACCEPT:
		c = fk_find_call(q->obj);
		if (!c) {
			errset(r, CSU_E_GONE, "not-found", "no such call");
			break;
		}
		order('A');
		if (strcmp(c->state, "ringing-in")) {
			errset(r, CSU_E_FAILED, "failed", "This call was not ringing, cannot accept");
			break;
		}
		snprintf(c->state, sizeof(c->state), "active");
		snprintf(c->reason, sizeof(c->reason), "accepted");
		fk_notify("voice.call_state_changed", c->path, "ringing-in", "active", "accepted", false);
		break;
	case CSU_CALL_HANGUP:
		c = fk_find_call(q->obj);
		if (!c) {
			errset(r, CSU_E_GONE, "not-found", "no such call");
			break;
		}
		order('H');
		if (!strcmp(c->state, "terminated") || !strcmp(c->state, "unknown")) {
			errset(r, CSU_E_FAILED, "failed", "This call was not active, cannot hangup");
			break;
		} else {
			char old[16];

			snprintf(old, sizeof(old), "%s", c->state);
			c->qid = 0;
			snprintf(c->state, sizeof(c->state), "terminated");
			snprintf(c->reason, sizeof(c->reason), "terminated");
			fk_notify("voice.call_state_changed", c->path, old, "terminated", "terminated", false);
		}
		break;
	case CSU_CALL_DTMF:
		c = fk_find_call(q->obj);
		if (!c) {
			errset(r, CSU_E_GONE, "not-found", "no such call");
			break;
		}
		order('T');
		if (strcmp(c->state, "active")) {
			errset(r, CSU_E_FAILED, "failed", "This call was not active, cannot send dtmf");
			break;
		}
		if (FK.dtmf_busy_once) {
			FK.dtmf_busy_once = false;
			errset(r, CSU_E_BUSY, "in-progress", "Already sending DTMF");
			break;
		}
		for (i = 0; q->str[i] && FK.ndig < FK_DIG - 1; i++)
			FK.dig[FK.ndig++] = q->str[i];
		FK.dig[FK.ndig] = 0;
		break;
	case CSU_CALL_DELETE:
		c = fk_find_call(q->str);
		order('D');
		if (!c) {
			errset(r, CSU_E_GONE, "not-found", "No call found with that path");
			break;
		}
		c->used = false;
		fk_notify("voice.call_deleted", q->str, NULL, NULL, NULL, false);
		break;
	case CSU_CALL_GET:
		c = fk_find_call(q->obj);
		if (!c) {
			errset(r, CSU_E_GONE, "not-found", "no such call");
			break;
		}
		order('G');
		snprintf(r->call_state, sizeof(r->call_state), "%s", c->state);
		snprintf(r->call_reason, sizeof(r->call_reason), "%s", c->reason);
		snprintf(r->call_dir, sizeof(r->call_dir), "%s", c->dir);
		snprintf(r->call_number, sizeof(r->call_number), "%s", c->number);
		r->call_qmi_id = c->qid;
		r->end_cause = c->end_cause;
		r->end_reason = c->er_value;
		snprintf(r->end_reason_name, sizeof(r->end_reason_name), "%s", c->er_name);
		break;
	case CSU_CALL_LIST:
		for (i = 0; i < FK_CALLS && r->n_paths < CSU_MAX_PATHS; i++)
			if (FK.call[i].used)
				snprintf(r->paths[r->n_paths++], CSU_PATH, "%s", FK.call[i].path);
		break;
	case CSU_SMS_CREATE:
		if (strcmp(q->obj, FK.modem) || !strcmp(FK.mstate, "disabled")) {
			errset(r, CSU_E_STATE, "wrong-state", "Modem is not enabled");
			break;
		}
		s = sms_alloc("unknown", "submit", q->str);
		if (!s) {
			errset(r, CSU_E_FAILED, "failed", "Cannot create SMS: too many messages, delete some");
			break;
		}
		order('c');
		if (q->text) {
			s->has_text = true;
			snprintf(s->text, sizeof(s->text), "%s", q->text);
			snprintf(FK.last_text, sizeof(FK.last_text), "%s", q->text);
		}
		snprintf(FK.last_dest, sizeof(FK.last_dest), "%s", q->str);
		fk_notify("messaging.added", s->path, NULL, NULL, NULL, false);
		snprintf(r->path, sizeof(r->path), "%s", s->path);
		break;
	case CSU_SMS_SEND:
		s = fk_find_sms(q->obj);
		if (!s) {
			errset(r, CSU_E_GONE, "not-found", "no such sms");
			break;
		}
		order('s');
		if (s->send_err) {
			errset(r, s->send_err, s->send_name, s->send_msg);
			break;
		}
		snprintf(s->state, sizeof(s->state), "sent");
		fk_notify("messaging.state_changed", s->path, "unknown", "sent", NULL, false);
		break;
	case CSU_SMS_GET:
		s = fk_find_sms(q->obj);
		if (!s) {
			errset(r, CSU_E_GONE, "not-found", "no such sms");
			break;
		}
		order('g');
		snprintf(r->sms_state, sizeof(r->sms_state), "%s", s->state);
		snprintf(r->sms_pdu, sizeof(r->sms_pdu), "%s", s->pdu);
		snprintf(r->sms_number, sizeof(r->sms_number), "%s", s->number);
		snprintf(r->sms_timestamp, sizeof(r->sms_timestamp), "%s", s->ts);
		snprintf(r->sms_discharge, sizeof(r->sms_discharge), "%s", s->dts);
		if (s->has_text) {
			r->sms_has_text = true;
			snprintf(r->sms_text, sizeof(r->sms_text), "%s", s->text);
		}
		if (s->has_data) {
			r->sms_has_data = true;
			memcpy(r->sms_data, s->data, s->dlen);
			r->sms_data_len = s->dlen;
		}
		r->sms_class = s->cls;
		r->sms_multipart = s->multipart;
		r->sms_max_parts = s->maxp;
		r->sms_parts = s->parts;
		r->sms_msgref = s->msgref;
		r->sms_delivery_state = s->dstate;
		break;
	case CSU_SMS_DELETE:
		s = fk_find_sms(q->str);
		order('d');
		if (!s) {
			errset(r, CSU_E_GONE, "not-found", "No SMS found with that path");
			break;
		}
		s->used = false;
		fk_notify("messaging.deleted", q->str, NULL, NULL, NULL, false);
		break;
	case CSU_SMS_LIST:
		order('l');
		for (i = 0; i < FK_SMS && r->n_paths < CSU_MAX_PATHS; i++)
			if (FK.sms[i].used)
				snprintf(r->paths[r->n_paths++], CSU_PATH, "%s", FK.sms[i].path);
		break;
	}
}

static void h_fire(void *arg)
{
	struct fh *h = arg;
	struct csu_res *r;
	struct fh **pp;
	csu_cb cb;
	void *cbarg;

	if (FK.hold[h->rq.op] && !h->parked) {
		h->parked = true;
		return;
	}
	for (pp = &HEAD; *pp; pp = &(*pp)->next)
		if (*pp == h) {
			*pp = h->next;
			break;
		}
	r = calloc(1, sizeof(*r));
	FK.n[h->rq.op]++;
	exec(h, r);
	cb = h->cb;
	cbarg = h->arg;
	ev_timer_free(h->t);
	free(h);
	cb(cbarg, r);
	free(r);
}

static void *fk_call(void *ctx, const struct csu_req *rq, csu_cb cb, void *arg)
{
	struct fh *h = calloc(1, sizeof(*h));

	(void)ctx;
	h->rq = *rq;
	if (rq->text) {
		snprintf(h->text, sizeof(h->text), "%s", rq->text);
		h->rq.text = h->text;
	}
	if (rq->data && rq->data_len <= sizeof(h->data)) {
		memcpy(h->data, rq->data, rq->data_len);
		h->rq.data = h->data;
	}
	h->cb = cb;
	h->arg = arg;
	h->t = ev_timer_new(h_fire, h);
	h->next = HEAD;
	HEAD = h;
	ev_timer_set(h->t, FK.delay_ms[rq->op]);
	return h;
}

static void fk_cancel(void *ctx, void *handle)
{
	struct fh *h = handle, **pp;

	(void)ctx;
	for (pp = &HEAD; *pp; pp = &(*pp)->next)
		if (*pp == h) {
			*pp = h->next;
			break;
		}
	FK.cancelled++;
	ev_timer_free(h->t);
	free(h);
}

static void fk_watch(void *ctx, const char *path)
{
	(void)ctx;
	FK.watch = path && path[0];
	snprintf(FK.watched, sizeof(FK.watched), "%s", path ? path : "");
}

void fk_release(int op)
{
	struct fh *h;

	FK.hold[op] = false;
	for (h = HEAD; h; h = h->next)
		if (h->rq.op == (enum csu_op)op && h->parked) {
			h->parked = false;
			ev_timer_set(h->t, 0);
		}
}

static const struct csu_ops ops = { .call = fk_call, .cancel = fk_cancel, .watch_modem = fk_watch };

const struct csu_ops *fk_ops(void)
{
	return &ops;
}
