/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The call module: lifecycle, registration with the core, carrier event routing, listing. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "b2b_int.h"
#include "../util/rtpsock.h"

struct b2b B;
static struct carrier_backend CS_BE;			/* ops NULL: no circuit switched backend */
static enum b2b_backend SEL = B2B_BE_GM;

static void mod_reg_hook(void *arg, enum reg_event ev, const char *reason)
{
	(void)arg;
	if (B.gm)
		gmcall_reg_hook(B.gm, ev, reason);
}

/* ---- Gm side: carrier requests for gmcall ---- */
static bool gmh_request(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
			const struct sip_msg *req, void *arg)
{
	(void)r; (void)arg;
	return B.gm && gmcall_on_request(B.gm, st, ep, src, req);
}

static const struct reg_handlers gm_handlers = {
	.on_invite = gmh_request,
	.on_in_dialog = gmh_request,
	.on_ack = gmh_request,
};

static const struct lan_hooks lan_hooks = {
	.on_invite = b2b_lan_on_invite,
	.on_in_dialog = b2b_lan_on_in_dialog,
	.on_ack = b2b_lan_on_ack,
};

static void mod_stray(struct core *c, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *resp, void *arg)
{
	(void)c; (void)arg;
	if (B.gm)
		gmcall_on_stray_response(B.gm, ep, src, resp);
}

/* ------------------------------------------------------------------ */

const struct imsd_config *b2b_cfg(void)
{
	return core_cfg(B.core);
}

const char *b2b_user_agent(void)
{
	return b2b_cfg()->user_agent;
}

void b2b_set_ops(const struct b2b_ops *ops)
{
	if (ops)
		B.ops = *ops;
	else
		memset(&B.ops, 0, sizeof(B.ops));
}

void b2b_set_notify(b2b_notify_cb cb, void *arg)
{
	B.notify = cb;
	B.notify_arg = arg;
}

bool b2b_running(void)
{
	return B.running;
}

int b2b_rtp_lan(struct addr *bound)
{
	if (B.ops.rtp_lan)
		return B.ops.rtp_lan(B.ops.ctx, bound);
	return core_rtp_open_lan(B.core, bound);
}

int b2b_rtp_carrier(struct addr *bound)
{
	const struct reg_ctx *x = reg_context(core_reg(B.core));
	const char *nd = core_param_ims_netdev(B.core);

	if (!x || !x->ep)
		return -ENOTCONN;
	if (B.ops.rtp_carrier)
		return B.ops.rtp_carrier(B.ops.ctx, &x->ep->advertised, nd[0] ? nd : NULL, bound);
	return core_rtp_open_carrier(B.core, &x->ep->advertised, nd[0] ? nd : NULL, bound);
}

void b2b_new_origin(struct sdp_origin *o)
{
	memset(o, 0, sizeof(*o));
	snprintf(o->user, sizeof(o->user), "imsd");
	o->sess_id = ((uint64_t)rnd32() << 16 | (rnd32() & 0xffff)) & 0x7fffffffffffULL;
	o->version = 1;
}

static enum sdpn_codec codec_to_sdpn(enum codec_id id)
{
	switch (id) {
	case CODEC_OPUS: return SDPN_C_OPUS;
	case CODEC_G722: return SDPN_C_G722;
	case CODEC_PCMA: return SDPN_C_PCMA;
	default: return SDPN_C_NONE;
	}
}

void b2b_lan_cfg(bool wideband, struct sdpn_lan_cfg *lc)
{
	const struct imsd_config *cfg = b2b_cfg();
	int i, n = 0;

	sdpn_lan_cfg_default(lc);
	lc->carrier_wideband = wideband;
	for (i = 0; i < cfg->n_lan_codec_pref && n < 4; i++) {
		enum sdpn_codec c = codec_to_sdpn(cfg->lan_codec_pref[i]);

		if (c != SDPN_C_NONE)
			lc->pref[n++] = c;
	}
	lc->npref = n;
}

/* ---- calls ---- */

struct b2b_call *b2b_call_new(bool out)
{
	struct b2b_call *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	c->id = B.next_id++;
	c->out = out;
	c->lfd = c->cfd = -1;
	c->t_start = ev_now_ms();
	c->l_rdir = SDP_DIR_SENDRECV;
	c->t_ring = NULL;
	c->next = B.calls;
	B.calls = c;
	return c;
}

struct b2b_call *b2b_find(unsigned id)
{
	struct b2b_call *c;

	for (c = B.calls; c; c = c->next)
		if (c->id == id && c->st != CS_ENDED)
			return c;
	return NULL;
}

const char *b2b_state_name(const struct b2b_call *c)
{
	switch (c->st) {
	case CS_SETUP:
		return c->out ? (c->sent_180 ? "ringing" : "dialing") : "ringing";
	case CS_EARLY:
		return "early-media";
	case CS_ANSWERING:
		return "answering";
	case CS_UP:
		return c->hold_c || c->hold_l ? "hold" : "up";
	default:
		return "ended";
	}
}

void b2b_notify(struct b2b_call *c, const char *event, int status, const char *reason)
{
	struct b2b_notice n;

	if (!B.notify)
		return;
	memset(&n, 0, sizeof(n));
	n.id = c->id;
	n.event = event;
	n.dir = c->out ? "out" : "in";
	n.number = c->number;
	n.status = status;
	n.reason = reason ? reason : "";
	B.notify(B.notify_arg, &n);
}

void b2b_try_free(struct b2b_call *c)
{
	(void)c;
	if (B.t_reap)
		ev_timer_set(B.t_reap, 0);
}

static void call_free(struct b2b_call *c)
{
	ev_timer_free(c->t_ring);
	free(c->offer);
	free(c->ans);
	free(c);
}

static void reap_fire(void *arg)
{
	struct b2b_call **pp = &B.calls;

	(void)arg;
	while (*pp) {
		struct b2b_call *c = *pp;

		if (c->st == CS_ENDED && !c->fork) {
			*pp = c->next;
			call_free(c);
		} else {
			pp = &c->next;
		}
	}
}

void b2b_cc_reject_release(struct b2b_call *c, int status)
{
	if (!c->cc)
		return;
	c->ops->reject(c->cc, status);
	c->ops->release(c->cc);
	c->cc = NULL;
}

bool b2b_is_gm(const struct b2b_call *c)
{
	return c->ops == &carrier_gm_ops;
}

const struct carrier_backend *b2b_cur_backend(void)
{
	if (SEL == B2B_BE_GM)
		return B.gm_be.ops ? &B.gm_be : NULL;
	if (SEL == B2B_BE_CS)
		return CS_BE.ops ? &CS_BE : NULL;
	return NULL;
}

int b2b_dial_status(int rc, bool pcm)
{
	switch (rc) {
	case -ENOTCONN: return 503;
	case -EINVAL: return pcm ? 484 : 404;
	case -EBUSY: return 486;	/* the PCM path is single: a call is up */
	case -ENOBUFS: return 486;
	default: return 500;
	}
}

void b2b_set_cs_backend(const struct carrier_backend *be)
{
	struct b2b_call *c;

	if (!be || !be->ops) {
		if (!CS_BE.ops)
			return;
		for (c = B.calls; c; c = c->next)
			if (c->st != CS_ENDED && c->ops == CS_BE.ops)
				b2b_teardown(c, "the circuit switched backend stopped", true);
		CS_BE.ops->set_incoming(CS_BE.be, NULL, NULL);
		memset(&CS_BE, 0, sizeof(CS_BE));
		return;
	}
	CS_BE = *be;
	CS_BE.ops->set_incoming(CS_BE.be, b2b_in_incoming, (void *)CS_BE.ops);
}

void b2b_select_backend(enum b2b_backend b)
{
	SEL = b;
}

enum b2b_backend b2b_selected_backend(void)
{
	return SEL;
}

unsigned b2b_active_calls(void)
{
	struct b2b_call *c;
	unsigned n = 0;

	for (c = B.calls; c; c = c->next)
		if (c->st != CS_ENDED)
			n++;
	return n;
}

void b2b_teardown(struct b2b_call *c, const char *why, bool bye_lan)
{
	enum b2b_st prev = c->st;

	if (prev == CS_ENDED)
		return;
	c->st = CS_ENDED;
	LOGI("call#%u (%s %s): ended: %s", c->id, c->out ? "out" : "in", c->number, why ? why : "");
	snprintf(c->end_reason, sizeof(c->end_reason), "%s", why ? why : "");
	b2b_timer_cancel(c->t_ring);
	if (c->rtx) {
		sip_rtx_stop(c->rtx);
		c->rtx = NULL;
	}
	if (c->cc) {
		c->ops->release(c->cc);
		c->cc = NULL;
	}
	if (c->ist) {
		struct txn_server *st = c->ist;

		c->ist = NULL;
		txn_server_set_cb(st, NULL, NULL);
		if (txn_server_last_status(st) < 200)
			b2b_lan_reply(st, c->end_status ? c->end_status : (c->client_cancelled ? 487 : 503), NULL);
	}
	if (bye_lan && c->ldlg_ok && (prev == CS_ANSWERING || prev == CS_UP))
		b2b_lan_send_bye(c);
	b2b_in_end(c);
	b2b_lan_dlg_drop(c);
	b2b_bridge_destroy(c);
	b2b_close_socks(c);
	b2b_notify(c, "ended", c->end_status, c->end_reason);
	b2b_try_free(c);
}

/* carrier leg events */
void b2b_cc_event(struct carrier_call *cc, const struct cc_event *ev, void *arg)
{
	struct b2b_call *c = arg;

	(void)cc;
	if (ev->type == CC_EV_FAILED || ev->type == CC_EV_CANCELLED || ev->type == CC_EV_TERMINATED)
		c->cc = NULL;	/* the pointer is dead once this callback returns */
	if (c->st == CS_ENDED)
		return;
	if (c->out)
		b2b_out_cc_event(c, ev);
	else
		b2b_in_cc_event(c, ev);
}

void b2b_end_all(const char *reason)
{
	struct b2b_call *c;

	for (c = B.calls; c; c = c->next)
		if (c->st != CS_ENDED)
			b2b_teardown(c, reason, true);
}

/* ---- listing ---- */

void b2b_get_counters(struct b2b_counters *o)
{
	struct b2b_call *c;

	*o = B.cnt;
	o->active = 0;
	for (c = B.calls; c; c = c->next)
		if (c->st != CS_ENDED)
			o->active++;
}

int b2b_list(struct b2b_info *out, int max)
{
	struct b2b_call *c;
	int n = 0;

	for (c = B.calls; c; c = c->next) {
		if (c->st == CS_ENDED)
			continue;
		if (n < max)
			b2b_fill_info(c, &out[n]);
		n++;
	}
	return n;
}

/* ---- module ---- */

static int mod_start(struct core *c, void *arg)
{
	struct gmcall_cfg gc;
	const struct imsd_config *cfg = core_cfg(c);
	char ua[128];
	struct b2b_ops ops = B.ops;
	b2b_notify_cb nf = B.notify;
	void *na = B.notify_arg;

	(void)arg;
	memset(&B, 0, sizeof(B));
	B.ops = ops;
	B.notify = nf;
	B.notify_arg = na;
	B.core = c;
	B.reg = core_reg(c);
	B.next_id = 1;
	gmcall_cfg_defaults(&gc);
	config_ims_user_agent(cfg, ua, sizeof(ua));
	gc.tl = core_txn(c);
	gc.reg = &gmcall_reg_adapter;
	gc.reg_arg = B.reg;
	gc.phone_context = cfg->phone_context[0] ? cfg->phone_context : core_param_domain(c);
	gc.contact_params = cfg->contact_params[0] ? cfg->contact_params : NULL;
	gc.user_agent = ua;
	gc.session_expires = cfg->session_expires;
	gc.max_calls = 1024;		/* no call-count policy: the network and the devices decide */
	B.gm = gmcall_mgr_new(&gc);
	B.t_reap = ev_timer_new(reap_fire, NULL);
	if (!B.gm || !B.t_reap) {
		gmcall_mgr_free(B.gm);
		ev_timer_free(B.t_reap);
		memset(&B, 0, sizeof(B));
		return -ENOMEM;
	}
	carrier_gm_backend(B.gm, &B.gm_be);
	B.gm_be.ops->set_incoming(B.gm, b2b_in_incoming, (void *)B.gm_be.ops);
	if (reg_add_hook(B.reg, mod_reg_hook, NULL)) {
		gmcall_mgr_free(B.gm);
		ev_timer_free(B.t_reap);
		memset(&B, 0, sizeof(B));
		return -ENOMEM;
	}
	B.running = true;
	return 0;
}

static void drop_forks(void)
{
	struct b2b_call *c;

	for (c = B.calls; c; c = c->next) {
		if (c->fork) {
			lan_fork_cancel(c->fork);
			lan_fork_detach(c->fork);
			c->fork = NULL;
		}
	}
}

static void mod_lan_state(struct core *c, struct lan *l, void *arg)
{
	(void)c; (void)arg;
	if (l || !B.running)
		return;
	/* the LAN side goes away: calls end (the BYEs still go out through the old endpoint), forks are dropped */
	b2b_end_all("LAN side restarted");
	drop_forks();
	reap_fire(NULL);
}

static void mod_stop(struct core *c, void *arg)
{
	struct b2b_call *k;

	(void)arg;
	if (!B.running)
		return;
	b2b_end_all("daemon stopping");
	drop_forks();
	if (CS_BE.ops) {		/* the daemon frees its manager itself; no callback may come after this */
		CS_BE.ops->set_incoming(CS_BE.be, NULL, NULL);
		memset(&CS_BE, 0, sizeof(CS_BE));
	}
	reg_remove_hook(core_reg(c), mod_reg_hook, NULL);
	gmcall_mgr_free(B.gm);		/* before the transaction layer goes */
	B.gm = NULL;
	reap_fire(NULL);
	while ((k = B.calls)) {		/* nothing is left that could call back */
		B.calls = k->next;
		call_free(k);
	}
	ev_timer_free(B.t_reap);
	B.t_reap = NULL;
	B.running = false;
}

const struct core_module b2b_module = {
	.name = "call",
	.start = mod_start,
	.stop = mod_stop,
	.lan_state = mod_lan_state,
	.lan_hooks = &lan_hooks,
	.gm_handlers = &gm_handlers,
	.on_stray = mod_stray,
	.bridge_event = b2b_bridge_event,
};
