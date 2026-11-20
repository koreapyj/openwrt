/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Carrier call leg: manager, call object lifecycle, event delivery, request
 * dispatch, registration events. MO / MT / in-dialog logic is in
 * gmcall_mo.c, gmcall_mt.c and gmcall_dlg.c.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "gmcall_int.h"

/* ------------------------------------------------------------------ */
/* configuration / manager                                             */

/* the User-Agent of every request and response we originate (one manager per daemon) */
static char g_ua[96];

void gmcall_cfg_defaults(struct gmcall_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->phone_context = "lguplus.co.kr";
	c->contact_params = GMCALL_DEF_CONTACT_PARAMS;
	c->session_expires = 1800;
	c->min_se = 90;
	c->ring_timeout_s = 180;
	c->max_calls = 8;
	c->auto_ring = true;
	sdpn_carrier_cfg_default(&c->sdp);
}

static void reap_fire(void *arg)
{
	struct gmcall_mgr *m = arg;

	while (m->dead) {
		struct gmcall *c = m->dead;

		m->dead = c->next;
		gm_creq_detach_call(c);
		gm_dlg_cleanup(c);
		ev_timer_free(c->t_sess);
		ev_timer_free(c->t_misc);
		ev_timer_free(c->t_defer);
		if (c->inv_st)
			txn_server_set_cb(c->inv_st, NULL, NULL);
		if (c->ds) {
			dlgset_release(c->ds);
			free(c->ds);
		}
		if (c->udlg_used)
			dlg_release(&c->udlg);
		free(c->offer);
		free(c->late_offer);
		free(c);
	}
}

struct gmcall_mgr *gmcall_mgr_new(const struct gmcall_cfg *cfg)
{
	struct gmcall_mgr *m;

	if (!cfg || !cfg->tl || !cfg->reg || !cfg->reg->context || !cfg->reg->contact_uri)
		return NULL;
	m = calloc(1, sizeof(*m));
	if (!m)
		return NULL;
	m->cfg = *cfg;
	snprintf(m->phone_context, sizeof(m->phone_context), "%s", cfg->phone_context ? cfg->phone_context : "");
	snprintf(m->contact_params, sizeof(m->contact_params), "%s",
		 cfg->contact_params ? cfg->contact_params : GMCALL_DEF_CONTACT_PARAMS);
	snprintf(m->user_agent, sizeof(m->user_agent), "%s", cfg->user_agent ? cfg->user_agent : "");
	m->cfg.phone_context = m->phone_context;
	m->cfg.contact_params = m->contact_params;
	m->cfg.user_agent = m->user_agent;
	snprintf(g_ua, sizeof(g_ua), "%s", m->user_agent);
	if (!m->cfg.session_expires)
		m->cfg.session_expires = 1800;
	if (m->cfg.session_expires < 90)
		m->cfg.session_expires = 90;
	if (!m->cfg.min_se)
		m->cfg.min_se = 90;
	if (!m->cfg.max_calls)
		m->cfg.max_calls = 8;
	m->t_reap = ev_timer_new(reap_fire, m);
	if (!m->t_reap) {
		free(m);
		return NULL;
	}
	m->next_id = 1;
	return m;
}

const char *gm_user_agent(void)
{
	return g_ua;
}

int gm_reply(struct txn_server *st, const struct sip_resp_parts *p)
{
	struct sip_resp_parts q = *p;
	char ex[1400];

	if (g_ua[0] && (!p->extra || strlen(p->extra) < sizeof(ex) - sizeof(g_ua) - 20)) {
		snprintf(ex, sizeof(ex), "User-Agent: %s\r\n%s", g_ua, p->extra ? p->extra : "");
		q.extra = ex;
	}
	return txn_server_reply(st, &q);
}

void gmcall_mgr_set_strings(struct gmcall_mgr *m, const char *phone_context, const char *contact_params, const char *user_agent)
{
	if (phone_context)
		snprintf(m->phone_context, sizeof(m->phone_context), "%s", phone_context);
	if (contact_params)
		snprintf(m->contact_params, sizeof(m->contact_params), "%s", contact_params[0] ? contact_params : GMCALL_DEF_CONTACT_PARAMS);
	if (user_agent) {
		snprintf(m->user_agent, sizeof(m->user_agent), "%s", user_agent);
		snprintf(g_ua, sizeof(g_ua), "%s", user_agent);
	}
}

void gmcall_mgr_set_session_expires(struct gmcall_mgr *m, unsigned secs)
{
	m->cfg.session_expires = secs < 90 ? 90 : secs;
}

void gmcall_mgr_free(struct gmcall_mgr *m)
{
	struct creq *r;

	if (!m)
		return;
	while ((r = m->reqs)) {	/* the transactions keep running in the layer, silently */
		if (r->c)
			txn_client_detach(r->c);
		gm_creq_free(r);
	}
	for (;;) {
		struct gmcall *c = m->calls ? m->calls : m->dead;

		if (!c)
			break;
		if (m->calls)
			m->calls = c->next;
		else
			m->dead = c->next;
		c->next = m->dead;	/* reuse the reaper's free path */
		m->dead = c;
		reap_fire(m);
	}
	ev_timer_free(m->t_reap);
	free(m);
}

void gmcall_set_incoming(struct gmcall_mgr *m, gmcall_incoming_cb cb, void *arg)
{
	m->cfg.on_incoming = cb;
	m->cfg.incoming_arg = arg;
}

unsigned gmcall_count(const struct gmcall_mgr *m)
{
	return m->ncalls;
}

const struct reg_ctx *gm_ctx(const struct gmcall_mgr *m)
{
	return m->cfg.reg->context(m->cfg.reg_arg);
}

void gm_snapshot(struct gmcall *c, const struct reg_ctx *x)
{
	if (!x || !x->security_verify)
		return;
	snprintf(c->snap.sv, sizeof(c->snap.sv), "%s", x->security_verify);
	snprintf(c->snap.pani, sizeof(c->snap.pani), "%s", x->pani ? x->pani : "");
	c->snap.pcscf = x->pcscf_ps;
	c->snap.valid = true;
}

/* ------------------------------------------------------------------ */
/* call objects                                                        */

static void defer_fire(void *arg)
{
	struct gmcall *c = arg;

	gm_finish(c, &c->defer_ev);
}

static void sess_cb(void *arg)
{
	gm_sess_fire(arg);
}

struct gmcall *gm_call_new(struct gmcall_mgr *m, enum gmcall_dir dir)
{
	struct gmcall *c;

	if (m->ncalls >= m->cfg.max_calls)
		return NULL;
	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;
	c->t_defer = ev_timer_new(defer_fire, c);
	c->t_sess = ev_timer_new(sess_cb, c);
	if (!c->t_defer || !c->t_sess) {
		ev_timer_free(c->t_defer);
		ev_timer_free(c->t_sess);
		free(c);
		return NULL;
	}
	c->mgr = m;
	c->id = m->next_id++;
	c->dir = dir;
	c->t_start = ev_now_ms();
	c->want_dir = SDP_DIR_SENDRECV;
	m->ncalls++;
	c->next = m->calls;
	m->calls = c;
	return c;
}

bool gm_live(const struct gmcall *c)
{
	return c && c->state != GMCALL_ST_ENDED;
}

struct sip_dialog *gm_main_dlg(struct gmcall *c)
{
	if (c->ds)
		return c->ds->answered >= 0 ? &c->ds->d[c->ds->answered] : NULL;
	return c->udlg_used ? &c->udlg : NULL;
}

void gm_ev_text(struct gmcall_event *ev, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(ev->reason, sizeof(ev->reason), fmt, ap);
	va_end(ap);
}

void gm_emit(struct gmcall *c, const struct gmcall_event *ev)
{
	if (c->state == GMCALL_ST_ENDED || !c->cb)
		return;
	c->cb(c, ev, c->cb_arg);
}

static void quiesce(struct gmcall *c)
{
	c->state = GMCALL_ST_ENDED;
	gm_misc_cancel(c);
	gm_sess_stop(c);
	gm_dlg_cleanup(c);
	if (c->rtx200) {
		sip_rtx_stop(c->rtx200);
		c->rtx200 = NULL;
	}
}

static void unlink_call(struct gmcall *c)
{
	struct gmcall_mgr *m = c->mgr;
	struct gmcall **pp;

	for (pp = &m->calls; *pp; pp = &(*pp)->next) {
		if (*pp == c) {
			*pp = c->next;
			break;
		}
	}
	c->next = m->dead;
	m->dead = c;
	if (m->ncalls)
		m->ncalls--;
	ev_timer_set(m->t_reap, 0);
}

void gm_finish(struct gmcall *c, const struct gmcall_event *ev)
{
	struct gmcall_event e;

	if (c->finished)
		return;
	if (c->state != GMCALL_ST_ENDED)
		quiesce(c);
	c->finished = true;
	e = *ev;
	LOGI("gmcall#%u: %s call ended: %s (%d) %s", c->id, c->dir == GMCALL_MO ? "MO" : "MT",
	     e.type == GMCALL_EV_FAILED ? "FAILED" : e.type == GMCALL_EV_CANCELLED ? "CANCELLED" : "TERMINATED",
	     e.status, e.reason);
	if (c->cb) {
		gmcall_event_cb cb = c->cb;

		cb(c, &e, c->cb_arg);
	}
	unlink_call(c);
}

void gm_finish_deferred(struct gmcall *c, const struct gmcall_event *ev)
{
	if (c->state == GMCALL_ST_ENDED)
		return;
	quiesce(c);
	c->defer_ev = *ev;
	ev_timer_set(c->t_defer, 0);
}

/* ---- misc timer (ring timeout, cancel guard, glare retry) ---- */
static void misc_fire(void *arg)
{
	struct gmcall *c = arg;
	enum misc_kind k = c->misc;

	c->misc = MISC_NONE;
	if (!gm_live(c))
		return;
	switch (k) {
	case MISC_RING:
		if (c->dir == GMCALL_MO)
			gm_mo_ring_timeout(c);
		else
			gm_mt_ring_timeout(c);
		break;
	case MISC_CANCEL_GUARD:
		gm_mo_cancel_guard(c);
		break;
	case MISC_GLARE:
	case MISC_REFRESH_RETRY:
		gm_misc_fire_dlg(c);
		break;
	case MISC_NONE:
		break;
	}
}

void gm_misc_arm(struct gmcall *c, enum misc_kind k, uint64_t ms)
{
	if (!c->t_misc)
		c->t_misc = ev_timer_new(misc_fire, c);
	if (!c->t_misc)
		return;
	c->misc = k;
	ev_timer_set(c->t_misc, ms);
}

void gm_misc_cancel(struct gmcall *c)
{
	c->misc = MISC_NONE;
	if (c->t_misc)
		ev_timer_cancel(c->t_misc);
}

/* ------------------------------------------------------------------ */
/* media reporting                                                     */

void gm_origin_new(struct sdp_origin *o)
{
	memset(o, 0, sizeof(*o));
	snprintf(o->user, sizeof(o->user), "root");
	o->sess_id = (uint64_t)(rnd32() & 0x7fffffffu) + 1;
	o->version = o->sess_id;
}

bool gm_media_equal(const struct sdpn_media *a, const struct sdpn_media *b)
{
	return a->valid == b->valid && addr_equal(&a->remote, &b->remote) && a->codec == b->codec &&
	       a->pt_send == b->pt_send && a->pt_recv == b->pt_recv && a->octet_align == b->octet_align &&
	       a->mode_set == b->mode_set && a->dir == b->dir && a->legacy_hold == b->legacy_hold &&
	       a->dtmf_pt == b->dtmf_pt && a->dtmf_pt_recv == b->dtmf_pt_recv && a->ptime == b->ptime;
}

void gm_report_media(struct gmcall *c, const struct sdpn_media *neg, bool early, bool force)
{
	struct gmcall_event ev;

	if (!force && c->has_media && gm_media_equal(&c->media, neg))
		return;
	c->media = *neg;
	c->has_media = true;
	memset(&ev, 0, sizeof(ev));
	ev.type = GMCALL_EV_MEDIA;
	ev.media = &c->media;
	ev.early = early;
	gm_emit(c, &ev);
}

bool gm_has_sdp(const struct sip_msg *m)
{
	const char *ct = sip_hdr(m, "Content-Type", 0);

	return m->body_len > 0 && ct && strcasestr(ct, "application/sdp");
}

/* ------------------------------------------------------------------ */
/* client transaction contexts                                         */

struct creq *gm_creq_new(struct gmcall_mgr *m, struct gmcall *c, enum creq_kind k)
{
	struct creq *r = calloc(1, sizeof(*r));

	if (!r)
		return NULL;
	r->mgr = m;
	r->call = c;
	r->kind = k;
	r->dlg = -1;
	r->next = m->reqs;
	m->reqs = r;
	return r;
}

void gm_creq_free(struct creq *r)
{
	struct creq **pp;

	for (pp = &r->mgr->reqs; *pp; pp = &(*pp)->next) {
		if (*pp == r) {
			*pp = r->next;
			break;
		}
	}
	free(r->offer);
	free(r);
}

void gm_creq_detach_call(struct gmcall *c)
{
	struct creq *r;

	for (r = c->mgr->reqs; r; r = r->next)
		if (r->call == c)
			r->call = NULL;
	c->inv = NULL;
	c->reinv = NULL;
}

static void creq_cb(struct txn_client *tc, enum txn_cli_event ev, const struct sip_msg *resp, struct sip_endpoint *rx_ep,
		    const struct addr *src, void *arg)
{
	struct creq *r = arg;
	struct gmcall *c = gm_live(r->call) ? r->call : NULL;

	(void)tc; (void)rx_ep; (void)src;
	switch (ev) {
	case TXN_CLI_RESPONSE:
		if (r->kind == CK_INVITE) {
			if (c)
				gm_mo_response(c, r, resp);
		} else {
			gm_client_response(r, c, resp);
		}
		break;
	case TXN_CLI_TIMEOUT:
	case TXN_CLI_TRANSPORT_ERROR: {
		int st = ev == TXN_CLI_TIMEOUT ? 408 : 503;

		if (r->kind == CK_INVITE) {
			if (c)
				gm_mo_txn_failed(c, r, st, ev == TXN_CLI_TIMEOUT ? "no response from the network (timeout)"
									: "transport error sending the INVITE");
		} else {
			gm_client_failure(r, c, st);
		}
		break;
	}
	case TXN_CLI_TERMINATED:
		if (r->call) {
			if (r->call->inv == r)
				r->call->inv = NULL;
			if (r->call->reinv == r)
				r->call->reinv = NULL;
		}
		r->c = NULL;
		gm_creq_free(r);
		break;
	}
}

int gm_creq_start(struct gmcall *c, struct creq *r, struct sip_endpoint *ep, const struct addr *dst,
		  const uint8_t *data, size_t len)
{
	struct txn_client_req cr;

	(void)c;
	memset(&cr, 0, sizeof(cr));
	cr.ep = ep;
	cr.dst = *dst;
	cr.data = data;
	cr.len = len;
	cr.cb = creq_cb;
	cr.arg = r;
	r->c = txn_client_start(r->mgr->cfg.tl, &cr);
	if (!r->c) {
		gm_creq_free(r);
		return -ENOBUFS;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* request dispatch                                                    */

static struct gmcall *find_by_request(struct gmcall_mgr *m, const struct sip_msg *req, struct sip_dialog **dp)
{
	struct gmcall *c;
	int i;

	for (c = m->calls; c; c = c->next) {
		if (!gm_live(c))
			continue;
		if (c->ds) {
			for (i = 0; i < DLG_MAX_DIALOGS; i++) {
				if (c->ds->d[i].used && dlg_match_request(&c->ds->d[i], req)) {
					*dp = &c->ds->d[i];
					return c;
				}
			}
		} else if (c->udlg_used && dlg_match_request(&c->udlg, req)) {
			*dp = &c->udlg;
			return c;
		}
	}
	return NULL;
}

bool gmcall_on_request(struct gmcall_mgr *m, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
		       const struct sip_msg *req)
{
	struct sip_dialog *d = NULL;
	struct gmcall *c;
	const char *to;
	char tag[160];

	(void)src;
	if (req->is_resp)
		return false;
	if (!st) {		/* ACK without a transaction */
		if (strcmp(req->method, "ACK"))
			return false;
		c = find_by_request(m, req, &d);
		if (!c)
			return false;
		gm_ack_received(c, req);
		return true;
	}
	to = sip_hdr(req, "To", 0);
	if (!to || sip_tag(to, tag, sizeof(tag)))
		return false;
	if (!tag[0]) {
		if (strcmp(req->method, "INVITE"))
			return false;
		return gm_mt_new(m, st, ep, req);
	}
	c = find_by_request(m, req, &d);
	if (!c)
		return false;
	gm_in_dialog_request(c, d, st, req);
	return true;
}

bool gmcall_on_stray_response(struct gmcall_mgr *m, struct sip_endpoint *ep, const struct addr *src,
			      const struct sip_msg *resp)
{
	struct gmcall *c;
	const char *cid = sip_hdr(resp, "Call-ID", 0);
	uint32_t cs;
	char meth[16];

	(void)src;
	if (!resp->is_resp || resp->status < 200 || resp->status >= 300 || !cid || sip_cseq(resp, &cs, meth, sizeof(meth)) ||
	    strcasecmp(meth, "INVITE"))
		return false;
	for (c = m->calls; c; c = c->next)
		if (c->dir == GMCALL_MO && gm_live(c) && !strcmp(c->call_id, cid))
			return gm_mo_stray_2xx(c, ep, resp);
	return false;
}

/* ------------------------------------------------------------------ */
/* registration events                                                 */

void gmcall_reg_hook(void *arg, enum reg_event ev, const char *reason)
{
	struct gmcall_mgr *m = arg;
	struct gmcall *c, *n;
	const struct reg_ctx *x;

	switch (ev) {
	case REG_EV_UP:
		return;
	case REG_EV_REPLACED:
		/* requests are built from the current context at send time, so they already use the new
		 * endpoint and Security-Verify; the snapshot is only the fallback */
		x = gm_ctx(m);
		for (c = m->calls; c; c = c->next)
			if (gm_live(c))
				gm_snapshot(c, x);
		return;
	case REG_EV_DOWN:
		LOGW("gmcall: registration lost (%s): ending %u call(s)", reason ? reason : "?", m->ncalls);
		for (c = m->calls; c; c = n) {
			n = c->next;
			if (!gm_live(c))
				continue;
			if (c->dir == GMCALL_MO)
				gm_mo_down(c);
			else
				gm_mt_down(c);
		}
		return;
	}
}

/* ------------------------------------------------------------------ */
/* user API                                                            */

void gmcall_set_handler(struct gmcall *c, gmcall_event_cb cb, void *arg)
{
	c->cb = cb;
	c->cb_arg = arg;
}

int gmcall_dial(struct gmcall_mgr *m, const struct gmcall_dial *d, gmcall_event_cb cb, void *arg, struct gmcall **out)
{
	return gm_mo_dial(m, d, cb, arg, out);
}

int gmcall_hangup(struct gmcall *c)
{
	if (!gm_live(c))
		return -ESTALE;
	if (c->dir == GMCALL_MO)
		return gm_mo_hangup(c);
	return gm_mt_hangup(c);
}

void gmcall_release(struct gmcall *c)
{
	c->cb = NULL;
	c->cb_arg = NULL;
	if (gm_live(c))
		gmcall_hangup(c);
}

int gmcall_set_media(struct gmcall *c, const struct addr *rtp, enum sdp_dir dir)
{
	if (!gm_live(c))
		return -ESTALE;
	if (c->state != GMCALL_ST_CONNECTED && c->state != GMCALL_ST_ANSWERING)
		return -EINVAL;
	if (dir == SDP_DIR_NONE)
		dir = SDP_DIR_SENDRECV;
	if (rtp && !addr_port(rtp))
		return -EINVAL;
	if (!gm_ctx(c->mgr))
		return -ENOTCONN;
	c->want_dir = dir;
	if (rtp) {
		c->want_rtp = *rtp;
		c->has_want_rtp = true;
	}
	c->reoffer_wanted = true;
	gm_maybe_reoffer(c);
	return 0;
}

/* ---- getters ---- */
const char *gmcall_state_name(enum gmcall_state s)
{
	static const char *const n[] = { "dialing", "early", "cancelling", "incoming", "answering", "connected", "ended" };

	return (unsigned)s < sizeof(n) / sizeof(n[0]) ? n[s] : "?";
}

enum gmcall_dir gmcall_direction(const struct gmcall *c) { return c->dir; }
enum gmcall_state gmcall_get_state(const struct gmcall *c) { return c->state; }
unsigned gmcall_id(const struct gmcall *c) { return c->id; }
const char *gmcall_call_id(const struct gmcall *c) { return c->call_id; }
const struct gmcall_identity *gmcall_remote(const struct gmcall *c) { return &c->remote; }

bool gmcall_get_media(const struct gmcall *c, struct sdpn_media *out)
{
	if (!c->has_media)
		return false;
	*out = c->media;
	return true;
}

enum sdp_dir gmcall_local_dir(const struct gmcall *c)
{
	if (c->has_local && c->local.nmedia > 0)
		return sdp_media_dir(&c->local, &c->local.media[0]);
	return SDP_DIR_SENDRECV;
}

uint64_t gmcall_age_ms(const struct gmcall *c) { return ev_now_ms() - c->t_start; }
uint64_t gmcall_talk_ms(const struct gmcall *c) { return c->t_connect ? ev_now_ms() - c->t_connect : 0; }

int gmcall_list(const struct gmcall_mgr *m, struct gmcall_info *out, int max)
{
	const struct gmcall *c;
	int n = 0;

	for (c = m->calls; c; c = c->next) {
		struct gmcall_info *i;

		if (n++ >= max)
			continue;
		i = &out[n - 1];
		memset(i, 0, sizeof(*i));
		i->id = c->id;
		i->dir = c->dir;
		i->state_name = gmcall_state_name(c->state);
		snprintf(i->call_id, sizeof(i->call_id), "%s", c->call_id);
		i->remote = c->remote;
		i->age_ms = gmcall_age_ms(c);
		i->talk_ms = gmcall_talk_ms(c);
		i->media_valid = c->has_media;
		if (c->has_media) {
			addr_str(&c->media.remote, i->remote_media, sizeof(i->remote_media));
			snprintf(i->codec, sizeof(i->codec), "%s", sdpn_codec_name(c->media.codec));
		}
		i->local_dir = gmcall_local_dir(c);
		i->session_interval = c->se_interval;
		i->session_refresher_local = c->se_local_refresher;
		i->session_next_ms = c->se_interval && c->sess_at > ev_now_ms() ? (int)(c->sess_at - ev_now_ms()) : -1;
	}
	return n;
}
