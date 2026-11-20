/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "csline.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define MAX_LISTENERS 4

enum job { J_NONE, J_LIST, J_GET, J_ENABLE };

struct csline {
	struct csline_cfg cfg;
	struct csu_ops ops;
	struct csline_status st, pub;
	bool have_pub;
	char device[96];
	bool got_get;
	bool enable_tried;
	enum job job;
	void *job_h;
	unsigned job_gen;
	struct ev_timer *retry, *refresh;
	bool in_step, again, backing;	/* backing: a retry timer is armed, nothing is started before it fires */
	struct csline_listener lst[MAX_LISTENERS];
	int n_lst;
	bool dying;
	unsigned next_gen;
};

void csline_cfg_defaults(struct csline_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->allow_roaming = true;
	c->call_timeout_ms = 15000;
	c->enable_timeout_ms = 60000;
	c->retry_ms = 3000;
	c->refresh_ms = 300;
}

const char *csline_rat_name(enum csline_rat r)
{
	switch (r) {
	case CSRAT_GSM: return "gsm";
	case CSRAT_UMTS: return "umts";
	case CSRAT_LTE: return "lte";
	default: return "none";
	}
}

enum csline_rat csline_rat_parse(const char *act)
{
	enum csline_rat best = CSRAT_NONE;
	char buf[64], *tok, *save = NULL;

	if (!act)
		return CSRAT_NONE;
	str_copy(buf, act, sizeof(buf));
	for (tok = strtok_r(buf, " ,", &save); tok; tok = strtok_r(NULL, " ,", &save)) {
		enum csline_rat r = CSRAT_NONE;

		if (!strncmp(tok, "lte", 3) || !strcmp(tok, "5gnr"))
			r = CSRAT_LTE;
		else if (!strcmp(tok, "umts") || !strncmp(tok, "hs", 2) || !strcmp(tok, "hspa-plus"))
			r = CSRAT_UMTS;
		else if (!strcmp(tok, "gsm") || !strcmp(tok, "gprs") || !strcmp(tok, "edge") || !strcmp(tok, "gsm-compact"))
			r = CSRAT_GSM;
		if (r > best)
			best = r;
	}
	return best;
}

/* ------------------------------------------------------------------ status */

static bool state_registered(const char *s)
{
	return !strcmp(s, "registered") || !strcmp(s, "connecting") || !strcmp(s, "connected") || !strcmp(s, "disconnecting");
}

static bool state_enabled(const char *s)
{
	return state_registered(s) || !strcmp(s, "enabled") || !strcmp(s, "searching");
}

/* voice: CS (or CSFB) registration; "*-sms-only" has no voice. Roaming per cfg. */
static void compute(struct csline *l)
{
	struct csline_status *s = &l->st;
	const char *r = s->reg_state;
	bool reg_voice, reg_sms;

	s->roaming = strstr(r, "roaming") != NULL;
	s->enabled = s->modem[0] && state_enabled(s->modem_state);
	reg_voice = !strcmp(r, "home") || !strcmp(r, "roaming") || !strcmp(r, "home-csfb-not-preferred") ||
		    !strcmp(r, "roaming-csfb-not-preferred");
	reg_sms = reg_voice || !strcmp(r, "home-sms-only") || !strcmp(r, "roaming-sms-only");
	s->voice_ok = s->sms_ok = false;
	if (!s->uqmid) {
		str_copy(s->reason, "waiting-for-uqmid", sizeof(s->reason));
	} else if (!s->modem[0]) {
		str_copy(s->reason, "no-modem", sizeof(s->reason));
	} else if (!strcmp(s->modem_state, "failed")) {
		str_copy(s->reason, "modem-failed", sizeof(s->reason));
	} else if (!strcmp(s->modem_state, "locked")) {
		str_copy(s->reason, "sim-locked", sizeof(s->reason));
	} else if (!strcmp(s->modem_state, "disabled")) {
		str_copy(s->reason, "modem-disabled", sizeof(s->reason));
	} else if (!state_enabled(s->modem_state)) {
		snprintf(s->reason, sizeof(s->reason), "modem-%s", s->modem_state[0] ? s->modem_state : "unknown");
	} else if (!strcmp(s->modem_state, "searching") || !strcmp(r, "searching")) {
		str_copy(s->reason, "searching", sizeof(s->reason));
	} else if (!strcmp(r, "denied")) {
		str_copy(s->reason, "denied", sizeof(s->reason));
	} else if (!state_registered(s->modem_state) || !reg_sms) {
		str_copy(s->reason, !strcmp(r, "emergency-only") ? "emergency-only" : "not-registered", sizeof(s->reason));
	} else if (s->roaming && !l->cfg.allow_roaming) {
		str_copy(s->reason, "roaming-not-allowed", sizeof(s->reason));
	} else if (!reg_voice) {
		str_copy(s->reason, "sms-only", sizeof(s->reason));
		s->sms_ok = true;
	} else {
		str_copy(s->reason, "ok", sizeof(s->reason));
		s->voice_ok = s->sms_ok = true;
	}
}

static void publish(struct csline *l)
{
	int i;

	compute(l);
	if (l->have_pub && !memcmp(&l->pub, &l->st, offsetof(struct csline_status, seq)))
		return;
	l->st.seq++;
	l->pub = l->st;
	l->have_pub = true;
	LOGI("cs: line %s state=%s reg=%s act=%s op=%s voice=%d sms=%d reason=%s", l->st.modem[0] ? l->st.modem : "-",
	     l->st.modem_state, l->st.reg_state, l->st.act, l->st.operator_code, l->st.voice_ok, l->st.sms_ok, l->st.reason);
	for (i = 0; i < l->n_lst; i++)
		if (l->lst[i].on_status)
			l->lst[i].on_status(l->lst[i].arg, &l->st);
}

/* ------------------------------------------------------------------ steps */

static void step(struct csline *l);

static void job_cancel(struct csline *l)
{
	if (l->job_h)
		l->ops.cancel(l->ops.ctx, l->job_h);
	l->job_h = NULL;
	l->job = J_NONE;
}

static void backoff(struct csline *l)
{
	l->backing = true;
	ev_timer_set(l->retry, l->cfg.retry_ms);
}

static bool pin_matches(const struct csline *l, const char *path, const char *device)
{
	return !l->cfg.modem_pin[0] || !strcmp(l->cfg.modem_pin, device) || !strcmp(l->cfg.modem_pin, path);
}

static void notify_modem(struct csline *l, bool present)
{
	int i;

	for (i = 0; i < l->n_lst; i++)
		if (l->lst[i].on_modem)
			l->lst[i].on_modem(l->lst[i].arg, present, l->st.modem, l->st.gen);
}

static void adopt(struct csline *l, const char *path, const char *device)
{
	l->st.gen = ++l->next_gen;
	str_copy(l->st.modem, path, sizeof(l->st.modem));
	str_copy(l->device, device, sizeof(l->device));
	l->got_get = false;
	l->enable_tried = false;
	l->st.modem_state[0] = l->st.reg_state[0] = l->st.act[0] = 0;
	l->st.operator_code[0] = l->st.operator_name[0] = l->st.own_number[0] = 0;
	l->st.rat = CSRAT_NONE;
	LOGI("cs: using modem %s (%s)", path, device);
	if (l->ops.watch_modem)
		l->ops.watch_modem(l->ops.ctx, path);
	notify_modem(l, true);
}

static void drop_modem(struct csline *l)
{
	if (!l->st.modem[0])
		return;
	job_cancel(l);
	ev_timer_cancel(l->refresh);
	LOGW("cs: modem %s is gone", l->st.modem);
	l->st.modem[0] = 0;
	l->st.gen = ++l->next_gen;
	l->got_get = false;
	l->st.modem_state[0] = l->st.reg_state[0] = l->st.act[0] = 0;
	l->st.operator_code[0] = l->st.operator_name[0] = 0;
	l->st.rat = CSRAT_NONE;
	if (l->ops.watch_modem)
		l->ops.watch_modem(l->ops.ctx, NULL);
	notify_modem(l, false);
}

struct jctx {
	struct csline *l;
	unsigned gen;
	enum job job;
};

static void job_done(void *arg, const struct csu_res *r);

static void job_start(struct csline *l, enum job j, const struct csu_req *rq)
{
	struct jctx *c = calloc(1, sizeof(*c));

	if (!c) {
		backoff(l);
		return;
	}
	c->l = l;
	c->gen = l->st.gen;
	c->job = j;
	l->job = j;
	l->job_gen = l->st.gen;
	l->job_h = l->ops.call(l->ops.ctx, rq, job_done, c);
	if (!l->job_h) {
		free(c);
		l->job = J_NONE;
		backoff(l);
	}
}

static void apply_get(struct csline *l, const struct csu_res *r)
{
	str_copy(l->st.modem_state, r->state, sizeof(l->st.modem_state));
	str_copy(l->st.reg_state, r->reg_state, sizeof(l->st.reg_state));
	str_copy(l->st.act, r->act, sizeof(l->st.act));
	l->st.rat = csline_rat_parse(r->act);
	str_copy(l->st.operator_code, r->operator_code, sizeof(l->st.operator_code));
	str_copy(l->st.operator_name, r->operator_name, sizeof(l->st.operator_name));
	str_copy(l->st.own_number, r->own_number, sizeof(l->st.own_number));
}

static void job_done(void *arg, const struct csu_res *r)
{
	struct jctx *c = arg;
	struct csline *l = c->l;
	enum job j = c->job;
	bool stale = c->gen != l->st.gen || l->dying;

	free(c);
	if (stale)
		return;			/* the modem changed meanwhile: step() restarts from the current one */
	l->job_h = NULL;
	l->job = J_NONE;
	switch (j) {
	case J_LIST: {
		int i, pick = -1;

		if (r->err) {
			LOGD("cs: uqmid list failed: %s", r->errmsg);
			backoff(l);
			break;
		}
		for (i = 0; i < r->n_modems; i++) {
			if (pin_matches(l, r->modems[i].path, r->modems[i].device)) {
				if (pick >= 0 && !l->cfg.modem_pin[0]) {
					LOGW("cs: several modems and no modem_pin: not using any");
					pick = -2;
					break;
				}
				pick = i;
			}
		}
		if (pick >= 0)
			adopt(l, r->modems[pick].path, r->modems[pick].device);
		else
			backoff(l);
		break;
	}
	case J_GET:
		if (r->err) {
			if (r->err == CSU_E_GONE)
				drop_modem(l);
			backoff(l);
			break;
		}
		apply_get(l, r);
		l->got_get = true;
		break;
	case J_ENABLE:
		if (r->err)
			LOGW("cs: enabling the modem failed: %s", r->errmsg);
		l->got_get = false;	/* read the state again */
		break;
	default:
		break;
	}
	step(l);
}

static void step(struct csline *l)
{
	struct csu_req rq;

	if (l->dying)
		return;
	if (l->in_step) {
		l->again = true;
		return;
	}
	l->in_step = true;
	do {
		l->again = false;
		if (!l->st.uqmid) {
			publish(l);
			break;
		}
		if (l->job || l->backing)
			break;
		if (!l->st.modem[0]) {
			publish(l);
			memset(&rq, 0, sizeof(rq));
			rq.op = CSU_LIST;
			snprintf(rq.obj, sizeof(rq.obj), "uqmid");
			job_start(l, J_LIST, &rq);
			break;
		}
		if (!l->got_get) {
			memset(&rq, 0, sizeof(rq));
			rq.op = CSU_MODEM_GET;
			str_copy(rq.obj, l->st.modem, sizeof(rq.obj));
			job_start(l, J_GET, &rq);
			break;
		}
		if (!strcmp(l->st.modem_state, "disabled") && l->cfg.manage_modem && !l->enable_tried) {
			l->enable_tried = true;
			memset(&rq, 0, sizeof(rq));
			rq.op = CSU_ENABLE;
			rq.flag = true;
			str_copy(rq.obj, l->st.modem, sizeof(rq.obj));
			job_start(l, J_ENABLE, &rq);
			publish(l);
			break;
		}
		publish(l);
	} while (l->again);
	l->in_step = false;
}

static void retry_cb(void *arg)
{
	struct csline *l = arg;

	l->backing = false;
	step(l);
}

static void refresh_cb(void *arg)
{
	struct csline *l = arg;

	if (!l->st.modem[0] || !l->st.uqmid)
		return;
	if (l->job) {			/* a read is running: it is at least as fresh as this one needs to be */
		ev_timer_set(l->refresh, l->cfg.refresh_ms);
		return;
	}
	l->got_get = false;
	l->backing = false;
	step(l);
}

/* ------------------------------------------------------------------ API */

struct csline *csline_new(const struct csline_cfg *cfg, const struct csu_ops *ops)
{
	struct csline *l = calloc(1, sizeof(*l));

	if (!l)
		return NULL;
	l->cfg = *cfg;
	l->ops = *ops;
	l->retry = ev_timer_new(retry_cb, l);
	l->refresh = ev_timer_new(refresh_cb, l);
	if (!l->retry || !l->refresh) {
		ev_timer_free(l->retry);
		ev_timer_free(l->refresh);
		free(l);
		return NULL;
	}
	compute(l);
	return l;
}

void csline_free(struct csline *l)
{
	if (!l)
		return;
	l->dying = true;
	job_cancel(l);
	ev_timer_free(l->retry);
	ev_timer_free(l->refresh);
	if (l->st.modem[0] && l->ops.watch_modem)
		l->ops.watch_modem(l->ops.ctx, NULL);
	free(l);
}

bool csline_set_cfg(struct csline *l, const struct csline_cfg *cfg)
{
	bool pin = strcmp(l->cfg.modem_pin, cfg->modem_pin) != 0;

	l->cfg = *cfg;
	if (pin && l->st.modem[0] && !pin_matches(l, l->st.modem, l->device)) {
		drop_modem(l);
		l->backing = false;
		step(l);
		return true;
	}
	if (pin && !l->st.modem[0] && l->st.uqmid) {	/* a pin may select the modem that was refused before */
		l->backing = false;
		step(l);
	}
	publish(l);
	return false;
}

int csline_add_listener(struct csline *l, const struct csline_listener *lst)
{
	if (l->n_lst >= MAX_LISTENERS)
		return -ENOBUFS;
	l->lst[l->n_lst++] = *lst;
	return 0;
}

void csline_remove_listener(struct csline *l, void *arg)
{
	int i;

	for (i = 0; i < l->n_lst; i++) {
		if (l->lst[i].arg == arg) {
			memmove(&l->lst[i], &l->lst[i + 1], (size_t)(l->n_lst - i - 1) * sizeof(l->lst[0]));
			l->n_lst--;
			return;
		}
	}
}

void csline_ev_uqmid_up(struct csline *l, bool up)
{
	if (l->st.uqmid == up)
		return;
	l->st.uqmid = up;
	l->backing = false;
	if (!up) {
		job_cancel(l);
		ev_timer_cancel(l->retry);
		ev_timer_cancel(l->refresh);
		drop_modem(l);		/* the objects of a dead uqmid are gone with it */
		publish(l);
		return;
	}
	step(l);
}

void csline_ev_modem_added(struct csline *l, const char *path, const char *device)
{
	if (!l->st.uqmid || l->st.modem[0] || !pin_matches(l, path, device))
		return;
	job_cancel(l);
	l->backing = false;
	ev_timer_cancel(l->retry);
	adopt(l, path, device);
	step(l);
}

void csline_ev_modem_removed(struct csline *l, const char *path)
{
	if (strcmp(l->st.modem, path))
		return;
	drop_modem(l);
	publish(l);
	l->backing = false;
	step(l);			/* look for a replacement (uqmid renumbers the modem after a SIM swap / reset) */
}

void csline_ev_notify(struct csline *l, const struct csu_notify *n)
{
	int i;

	if (!l->st.modem[0])
		return;
	if (!strcmp(n->method, "state_changed") && n->new_state[0]) {
		str_copy(l->st.modem_state, n->new_state, sizeof(l->st.modem_state));
		publish(l);
		ev_timer_set(l->refresh, l->cfg.refresh_ms);	/* operator, access technology and own number follow */
	} else if (!strcmp(n->method, "registration_state_changed")) {
		if (n->new_state[0])
			str_copy(l->st.reg_state, n->new_state, sizeof(l->st.reg_state));
		str_copy(l->st.operator_code, n->operator_code, sizeof(l->st.operator_code));
		str_copy(l->st.operator_name, n->operator_name, sizeof(l->st.operator_name));
		publish(l);
		ev_timer_set(l->refresh, l->cfg.refresh_ms);
	}
	for (i = 0; i < l->n_lst; i++)
		if (l->lst[i].on_notify)
			l->lst[i].on_notify(l->lst[i].arg, n);
}

void *csline_call(struct csline *l, const struct csu_req *rq, csu_cb cb, void *arg)
{
	return l->ops.call(l->ops.ctx, rq, cb, arg);
}

void csline_cancel(struct csline *l, void *handle)
{
	if (handle)
		l->ops.cancel(l->ops.ctx, handle);
}

const struct csline_status *csline_status(const struct csline *l)
{
	return &l->st;
}

const char *csline_modem(const struct csline *l)
{
	return l->st.modem;
}

void csline_refresh(struct csline *l)
{
	if (l->st.modem[0])
		ev_timer_set(l->refresh, 0);
}
