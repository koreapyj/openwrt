/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * In-dialog machinery of a carrier call: requests we send (ACK, BYE, UPDATE,
 * re-INVITE, PRACK are built here), requests we receive (BYE, UPDATE,
 * re-INVITE, INFO, OPTIONS ...), RFC 4028 session timers, hold / resume.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "gmcall_int.h"

static void reply(struct txn_server *st, int status, const char *extra)
{
	struct sip_resp_parts p;

	memset(&p, 0, sizeof(p));
	p.status = status;
	p.extra = extra;
	gm_reply(st, &p);
}

/* ------------------------------------------------------------------ */
/* request construction                                                */

int gm_route_get(struct gmcall *c, struct sip_dialog *d, struct gm_route *rt)
{
	const struct reg_ctx *x = gm_ctx(c->mgr);

	if (x && x->ep && x->security_verify) {
		gm_snapshot(c, x);
		rt->ep = x->ep;
		rt->dst = x->pcscf_ps;
	} else if (c->snap.valid && d && d->ep && !d->ep->retired) {
		/* registration gone: best effort through the endpoint the dialog started on */
		rt->ep = d->ep;
		rt->dst = c->snap.pcscf;
	} else {
		return -ENOTCONN;
	}
	rt->sv = c->snap.sv;
	rt->pani = c->snap.pani;
	return 0;
}

int gm_contact(struct gmcall *c, char *out, size_t n)
{
	char uri[200];
	int r;

	if (c->mgr->cfg.reg->contact_uri(c->mgr->cfg.reg_arg, uri, sizeof(uri)))
		return -1;
	r = snprintf(out, n, "<%s>%s", uri, c->mgr->contact_params);
	return r < 0 || (size_t)r >= n ? -1 : 0;
}

static bool uri_is_pcscf(const char *uri, const struct addr *pcscf)
{
	struct sip_uri u;
	struct addr a;

	if (sip_uri_parse(uri, &u) || !u.host[0])
		return false;
	if (addr_set(&a, u.host, u.port ? u.port : 5060))
		return false;
	return addr_equal(&a, pcscf);
}

static bool first_route_is_pcscf(const struct sip_dialog *d, const struct addr *pcscf)
{
	struct sip_nameaddr na;

	return d->nroute > 0 && !sip_nameaddr_parse(d->route[0], &na) && uri_is_pcscf(na.uri, pcscf);
}

static uint32_t next_cseq(struct gmcall *c, struct sip_dialog *d)
{
	if (c->ds) {
		d->local_cseq = ++c->cseq;
		return c->cseq;
	}
	return dlg_next_cseq(d);
}

int gm_build_in_dialog(struct gmcall *c, struct sip_dialog *d, const struct gm_req *q, struct gm_route *rt,
		       struct buf *out, uint32_t *cseq_used)
{
	char ruri[256], via[200], branch[SIP_BRANCH_LEN], from[340], to[520], contact[512], pc[96];
	struct buf rh, route, ex;
	struct sip_req_parts p;
	int rc = -1;

	if (!d->remote_target[0])
		snprintf(d->remote_target, sizeof(d->remote_target), "%s", d->remote_uri);
	buf_init(&rh, 4096);
	buf_init(&route, 4096);
	buf_init(&ex, 4096);
	if (dlg_route(d, ruri, sizeof(ruri), &rh))
		goto out;
	/* every request leaves through the P-CSCF: put its Route first unless the target / first route is it */
	if (!uri_is_pcscf(ruri, &rt->dst) && !first_route_is_pcscf(d, &rt->dst)) {
		if (addr_str(&rt->dst, pc, sizeof(pc)))
			goto out;
		buf_printf(&route, "Route: <sip:%s;lr>\r\n", pc);
	}
	buf_add(&route, rh.p, rh.len);
	sip_new_branch(branch);
	if (sip_via_make(via, sizeof(via), rt->ep->kind == SIP_TP_TCP ? "TCP" : "UDP", &rt->ep->advertised, branch, false))
		goto out;
	snprintf(from, sizeof(from), "<%s>;tag=%s", d->local_uri, d->local_tag);
	if (d->remote_tag[0])
		snprintf(to, sizeof(to), "<%s>;tag=%s", d->remote_uri, d->remote_tag);
	else
		snprintf(to, sizeof(to), "<%s>", d->remote_uri);
	if (rt->pani[0])
		buf_printf(&ex, "P-Access-Network-Info: %s\r\n", rt->pani);
	buf_printf(&ex, "Security-Verify: %s\r\n", rt->sv);
	if (gm_user_agent()[0])
		buf_printf(&ex, "User-Agent: %s\r\n", gm_user_agent());
	if (q->extra)
		buf_puts(&ex, q->extra);
	buf_puts(&ex, "Require: sec-agree\r\nProxy-Require: sec-agree\r\n");
	if (q->contact && gm_contact(c, contact, sizeof(contact)))
		goto out;
	memset(&p, 0, sizeof(p));
	p.method = q->method;
	p.ruri = ruri;
	p.via = via;
	p.from = from;
	p.to = to;
	p.call_id = d->call_id;
	p.cseq = q->cseq ? q->cseq : next_cseq(c, d);
	p.route = route.len ? buf_cstr(&route) : NULL;
	p.contact = q->contact ? contact : NULL;
	p.extra = buf_cstr(&ex);
	p.content_type = q->ctype;
	p.body = q->body;
	p.body_len = q->blen;
	if (cseq_used)
		*cseq_used = p.cseq;
	if (buf_ok(&route) && buf_ok(&ex))
		rc = sip_build_request(out, &p);
out:
	buf_free(&rh);
	buf_free(&route);
	buf_free(&ex);
	return rc;
}

void gm_send_ack(struct gmcall *c, struct sip_dialog *d, uint32_t invite_cseq)
{
	struct gm_route rt;
	struct gm_req q;
	struct buf b;

	if (gm_route_get(c, d, &rt)) {
		LOGW("gmcall#%u: cannot ACK, no registration", c->id);
		return;
	}
	memset(&q, 0, sizeof(q));
	q.method = "ACK";
	q.cseq = invite_cseq;
	buf_init(&b, SIP_MAX_MSG);
	if (!gm_build_in_dialog(c, d, &q, &rt, &b, NULL))
		sip_ep_send(rt.ep, &rt.dst, b.p, b.len);
	else
		LOGW("gmcall#%u: ACK could not be built", c->id);
	buf_free(&b);
}

/* start a client transaction for a built request */
static int start_req(struct gmcall *c, struct creq *r, struct gm_route *rt, const struct buf *b)
{
	return gm_creq_start(c, r, rt->ep, &rt->dst, b->p, b->len);
}

void gm_send_bye(struct gmcall *c, struct sip_dialog *d)
{
	struct gm_route rt;
	struct gm_req q;
	struct creq *r;
	struct buf b;

	if (gm_route_get(c, d, &rt)) {
		LOGW("gmcall#%u: no BYE sent (no endpoint)", c->id);
		return;
	}
	memset(&q, 0, sizeof(q));
	q.method = "BYE";
	buf_init(&b, SIP_MAX_MSG);
	r = gm_creq_new(c->mgr, NULL, CK_BYE);	/* orphan: nobody waits for the answer */
	if (r && !gm_build_in_dialog(c, d, &q, &rt, &b, &r->cseq)) {
		if (start_req(c, r, &rt, &b))
			LOGW("gmcall#%u: BYE could not be sent", c->id);
	} else {
		LOGW("gmcall#%u: BYE could not be built", c->id);
		if (r)
			gm_creq_free(r);
	}
	buf_free(&b);
}

void gm_terminate_local(struct gmcall *c, bool send_bye, const char *reason)
{
	struct gmcall_event ev;
	struct sip_dialog *d = gm_main_dlg(c);

	if (!gm_live(c))
		return;
	if (send_bye && d)
		gm_send_bye(c, d);
	memset(&ev, 0, sizeof(ev));
	ev.type = GMCALL_EV_TERMINATED;
	ev.by_remote = false;
	gm_ev_text(&ev, "%s", reason);
	gm_finish_deferred(c, &ev);
}

void gm_note_allow(struct gmcall *c, const struct sip_msg *m)
{
	const char *a = sip_hdr(m, "Allow", 0);

	if (a)
		c->peer_update = gmcall_has_token(a, "UPDATE");
}

/* ------------------------------------------------------------------ */
/* session timers (RFC 4028)                                           */

static void sess_arm(struct gmcall *c)
{
	uint64_t ms;
	unsigned margin;

	if (!c->se_interval) {
		ev_timer_cancel(c->t_sess);
		return;
	}
	if (c->se_local_refresher) {
		ms = (uint64_t)c->se_interval * 500;
	} else {
		margin = c->se_interval / 3 < 32 ? c->se_interval / 3 : 32;
		ms = (uint64_t)(c->se_interval - margin) * 1000;
	}
	c->sess_at = ev_now_ms() + ms;
	ev_timer_set(c->t_sess, ms);
}

void gm_sess_start(struct gmcall *c, unsigned interval, bool local_refresher)
{
	c->se_interval = interval;
	c->se_local_refresher = local_refresher;
	c->refresh_fails = 0;
	LOGI("gmcall#%u: session timer %us, %s refreshes", c->id, interval, local_refresher ? "we" : "the network");
	sess_arm(c);
}

void gm_sess_stop(struct gmcall *c)
{
	if (c->t_sess)
		ev_timer_cancel(c->t_sess);
}

void gm_sess_from_2xx(struct gmcall *c, const struct sip_msg *resp)
{
	const char *se = sip_hdr(resp, "Session-Expires", 0);
	unsigned iv;
	int ref;

	c->se_interval = 0;
	if (!se || gmcall_parse_session_expires(se, &iv, &ref)) {
		if (se)
			LOGW("gmcall#%u: malformed Session-Expires '%s' in the 2xx: no session timer", c->id, se);
		return;
	}
	/* the interval of the 2xx wins (the network answered 600 to our 3600); refresher absent: the UAC */
	gm_sess_start(c, iv, ref != GMCALL_REFRESHER_UAS);
}

static void se_extra(struct gmcall *c, struct buf *b)
{
	if (c->se_interval)
		buf_printf(b, "Session-Expires: %u;refresher=%s\r\n", c->se_interval, c->se_local_refresher ? "uac" : "uas");
	buf_puts(b, "Supported: timer\r\n");
}

static int send_refresh(struct gmcall *c, bool retried);

void gm_sess_fire(struct gmcall *c)
{
	if (!gm_live(c) || !c->se_interval)
		return;
	if (c->state != GMCALL_ST_CONNECTED) {
		if (c->state == GMCALL_ST_ANSWERING || c->state == GMCALL_ST_EARLY)
			ev_timer_set(c->t_sess, 1000);	/* wait for the ACK */
		return;
	}
	if (!c->se_local_refresher) {
		LOGW("gmcall#%u: session expired (no refresh within %us): BYE", c->id, c->se_interval);
		gm_terminate_local(c, true, "session timer expired");
		return;
	}
	if (c->reinv || c->rtx_reinv || c->late_offer) {	/* an offer/answer exchange is in flight: refresh shortly */
		ev_timer_set(c->t_sess, 2000);
		return;
	}
	send_refresh(c, false);
}

static int send_refresh(struct gmcall *c, bool retried)
{
	struct sip_dialog *d = gm_main_dlg(c);
	struct gm_route rt;
	struct gm_req q;
	struct creq *r;
	struct buf b, ex, sb;
	int rc = -1;

	c->refresh_due = false;
	if (!d || gm_route_get(c, d, &rt)) {
		gm_terminate_local(c, false, "session refresh impossible: no registration");
		return -ENOTCONN;
	}
	buf_init(&b, SIP_MAX_MSG);
	buf_init(&ex, 512);
	buf_init(&sb, 0);
	se_extra(c, &ex);
	memset(&q, 0, sizeof(q));
	q.contact = true;
	q.extra = buf_cstr(&ex);
	if (c->peer_update) {
		q.method = "UPDATE";
	} else {	/* the peer does not list UPDATE: re-INVITE with the unchanged SDP */
		q.method = "INVITE";
		if (sdp_write(&c->local, &sb))
			goto out;
		q.ctype = "application/sdp";
		q.body = sb.p;
		q.blen = sb.len;
	}
	r = gm_creq_new(c->mgr, c, CK_REFRESH);
	if (!r)
		goto out;
	if (gm_build_in_dialog(c, d, &q, &rt, &b, &r->cseq)) {
		gm_creq_free(r);
		goto out;
	}
	r->via_invite = !c->peer_update;
	r->retried = retried;
	c->reinv = r;
	rc = start_req(c, r, &rt, &b);
	if (rc)
		c->reinv = NULL;
out:
	buf_free(&b);
	buf_free(&ex);
	buf_free(&sb);
	if (rc) {
		LOGW("gmcall#%u: session refresh could not be sent", c->id);
		gm_misc_arm(c, MISC_REFRESH_RETRY, 5000);
		c->refresh_due = true;
	} else {
		LOGI("gmcall#%u: session refresh (%s) sent", c->id, c->peer_update ? "UPDATE" : "re-INVITE");
	}
	return rc;
}

/* ------------------------------------------------------------------ */
/* hold / resume / media change: our re-INVITE                          */

static int send_reinvite(struct gmcall *c)
{
	struct sip_dialog *d = gm_main_dlg(c);
	struct gm_route rt;
	struct gm_req q;
	struct creq *r;
	struct buf b, ex, sb;
	struct sdp *o;
	bool addr_change = c->has_want_rtp && !addr_equal(&c->want_rtp, &c->local_rtp);
	int idx = c->audio_idx, rc = -1;

	if (!d || gm_route_get(c, d, &rt))
		return -ENOTCONN;
	if (idx < 0 || idx >= c->local.nmedia)
		return -EINVAL;
	o = malloc(sizeof(*o));
	if (!o)
		return -ENOMEM;
	*o = c->local;
	if (addr_change) {
		sdp_set_conn(&o->conn, &c->want_rtp);
		if (o->media[idx].conn.present)
			sdp_set_conn(&o->media[idx].conn, &c->want_rtp);
		o->media[idx].port = addr_port(&c->want_rtp);
		o->o_addr = c->want_rtp;
		addr_set_port(&o->o_addr, 0);
		o->o_addr_ok = true;
	}
	sdpn_apply_dir(o, &o->media[idx], c->want_dir, false);
	if (sdp_origin_succeed(o, &c->local)) {
		free(o);
		return -EMSGSIZE;
	}
	buf_init(&b, SIP_MAX_MSG);
	buf_init(&ex, 512);
	buf_init(&sb, 0);
	if (sdp_write(o, &sb))
		goto out;
	se_extra(c, &ex);
	buf_puts(&ex, "Allow: " GMCALL_ALLOW "\r\n");
	memset(&q, 0, sizeof(q));
	q.method = "INVITE";
	q.contact = true;
	q.extra = buf_cstr(&ex);
	q.ctype = "application/sdp";
	q.body = sb.p;
	q.blen = sb.len;
	r = gm_creq_new(c->mgr, c, CK_REINVITE);
	if (!r)
		goto out;
	if (gm_build_in_dialog(c, d, &q, &rt, &b, &r->cseq)) {
		gm_creq_free(r);
		goto out;
	}
	r->offer = o;
	o = NULL;
	c->reinv = r;
	rc = start_req(c, r, &rt, &b);
	if (rc)
		c->reinv = NULL;
	else
		LOGI("gmcall#%u: re-INVITE sent (direction %s)", c->id, sdp_dir_name(c->want_dir));
out:
	buf_free(&b);
	buf_free(&ex);
	buf_free(&sb);
	free(o);
	return rc;
}

void gm_maybe_reoffer(struct gmcall *c)
{
	enum sdp_dir cur;
	bool addr_change;

	if (!c->reoffer_wanted || c->state != GMCALL_ST_CONNECTED)
		return;
	if (c->reinv || c->rtx_reinv || c->late_offer || c->misc == MISC_GLARE)
		return;
	cur = gmcall_local_dir(c);
	addr_change = c->has_want_rtp && !addr_equal(&c->want_rtp, &c->local_rtp);
	if (c->want_dir == cur && !addr_change) {
		c->reoffer_wanted = false;
		c->has_want_rtp = false;
		return;
	}
	if (send_reinvite(c)) {
		struct gmcall_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.type = GMCALL_EV_REOFFER_FAILED;
		ev.status = 0;
		gm_ev_text(&ev, "re-INVITE could not be sent");
		c->reoffer_wanted = false;
		c->want_dir = cur;
		c->has_want_rtp = false;
		gm_emit(c, &ev);
	}
}

void gm_misc_fire_dlg(struct gmcall *c)
{
	if (c->refresh_due && c->state == GMCALL_ST_CONNECTED && c->se_interval) {
		if (c->reinv || c->rtx_reinv || c->late_offer)
			gm_misc_arm(c, MISC_REFRESH_RETRY, 2000);
		else
			send_refresh(c, false);
		return;
	}
	gm_maybe_reoffer(c);
}

static void glare_wait(struct gmcall *c)
{
	uint32_t ms = c->dir == GMCALL_MO ? rnd_range(2100, 4000) : rnd_range(0, 2000);	/* RFC 3261 14.1 */

	gm_misc_arm(c, MISC_GLARE, ms);
}

static void reoffer_fail(struct gmcall *c, int status, const char *why)
{
	struct gmcall_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = GMCALL_EV_REOFFER_FAILED;
	ev.status = status;
	gm_ev_text(&ev, "%s", why);
	c->reoffer_wanted = false;
	c->want_dir = gmcall_local_dir(c);
	c->has_want_rtp = false;
	gm_emit(c, &ev);
}

/* a final response to our UPDATE / re-INVITE refresh or hold */
static void on_reinvite_final(struct creq *r, struct gmcall *c, const struct sip_msg *resp)
{
	struct sip_dialog *d = gm_main_dlg(c);
	int st = resp->status;
	bool is_refresh = r->kind == CK_REFRESH;
	unsigned minse;

	if (c->reinv != r) {	/* a retransmitted or late answer: a 2xx to an INVITE is ACKed every time (RFC 3261 13.2.2.4) */
		if (st >= 200 && st < 300 && d && (r->via_invite || r->kind == CK_REINVITE))
			gm_send_ack(c, d, r->cseq);
		return;
	}
	if (st >= 200 && st < 300) {
		const char *se = sip_hdr(resp, "Session-Expires", 0);
		unsigned iv;
		int ref;

		if (d) {
			dlg_refresh_target(d, resp);
			if (r->via_invite || r->kind == CK_REINVITE)
				gm_send_ack(c, d, r->cseq);
		}
		gm_note_allow(c, resp);
		if (is_refresh) {
			c->refresh_fails = 0;
			if (se && !gmcall_parse_session_expires(se, &iv, &ref))
				gm_sess_start(c, iv, ref == GMCALL_REFRESHER_UAC ? true :
					      ref == GMCALL_REFRESHER_UAS ? false : c->se_local_refresher);
			else
				gm_sess_start(c, c->se_interval, c->se_local_refresher);
			c->reinv = NULL;
			return;
		}
		/* hold / resume / media change: the answer is in the 2xx */
		{
			struct sdp *ans = NULL;
			struct sdpn_media neg;
			int rc = -1;

			if (gm_has_sdp(resp) && (ans = malloc(sizeof(*ans))))
				rc = sdp_parse(ans, (const char *)resp->body, resp->body_len);
			if (rc == 0 && !sdpn_from_answer(r->offer, ans, &neg)) {
				c->local = *r->offer;
				if (c->has_want_rtp) {
					c->local_rtp = c->want_rtp;
					c->has_want_rtp = false;
				}
				gm_report_media(c, &neg, false, false);
			} else {
				reoffer_fail(c, 488, "unusable answer to our re-INVITE");
			}
			free(ans);
		}
		c->reinv = NULL;
		gm_maybe_reoffer(c);
		return;
	}
	if (st == 491) {
		LOGI("gmcall#%u: 491 Request Pending, retrying after the glare timer", c->id);
		c->reinv = NULL;
		if (is_refresh)
			c->refresh_due = true;
		glare_wait(c);
		return;
	}
	if (st == 422 && !r->retried) {
		const char *mh = sip_hdr(resp, "Min-SE", 0);

		if (mh && !gmcall_parse_min_se(mh, &minse) && minse > c->se_interval && is_refresh) {
			c->se_interval = minse;
			c->reinv = NULL;
			send_refresh(c, true);
			return;
		}
	}
	if (st == 408 || st == 481) {
		LOGW("gmcall#%u: %s answered %d: the dialog is gone, BYE", c->id, is_refresh ? "session refresh" : "re-INVITE", st);
		c->reinv = NULL;
		gm_terminate_local(c, true, st == 408 ? "request timeout during a refresh / re-INVITE" : "481 during a refresh / re-INVITE");
		return;
	}
	c->reinv = NULL;
	if (is_refresh) {
		c->refresh_fails++;
		LOGW("gmcall#%u: session refresh answered %d (failure %u)", c->id, st, c->refresh_fails);
		if (c->refresh_fails >= 3) {
			gm_terminate_local(c, true, "session refresh failed");
			return;
		}
		c->refresh_due = true;
		gm_misc_arm(c, MISC_REFRESH_RETRY, c->se_interval * 250u < 5000 ? 5000 : c->se_interval * 250u);
		return;
	}
	{
		char txt[96];

		snprintf(txt, sizeof(txt), "re-INVITE rejected: %d %s", st, resp->reason);
		reoffer_fail(c, st, txt);
	}
}

void gm_client_response(struct creq *r, struct gmcall *c, const struct sip_msg *resp)
{
	int st = resp->status;

	if (st < 200)
		return;
	switch (r->kind) {
	case CK_BYE:
		LOGD("gmcall: BYE answered %d", st);
		break;
	case CK_CANCEL:
		LOGD("gmcall: CANCEL answered %d", st);
		break;
	case CK_PRACK:
		if (st >= 300)
			LOGW("gmcall: PRACK answered %d", st);
		break;
	case CK_REFRESH:
	case CK_REINVITE:
		if (c)
			on_reinvite_final(r, c, resp);
		break;
	default:
		break;
	}
}

void gm_client_failure(struct creq *r, struct gmcall *c, int status)
{
	if (!c) {
		LOGD("gmcall: orphan request kind %d failed (%d)", r->kind, status);
		return;
	}
	switch (r->kind) {
	case CK_REFRESH:
	case CK_REINVITE:
		if (c->reinv == r) {
			c->reinv = NULL;
			gm_terminate_local(c, true, "no answer to a refresh / re-INVITE");
		}
		break;
	default:
		LOGD("gmcall#%u: request kind %d failed (%d)", c->id, r->kind, status);
		break;
	}
}

/* ------------------------------------------------------------------ */
/* requests from the network                                           */

/* session timer fields of a remote request: updates c, returns the headers to echo in the 2xx; -1: 422 needed (min filled) */
static int remote_session(struct gmcall *c, const struct sip_msg *req, char *echo, size_t n, unsigned *minse)
{
	const char *se = sip_hdr(req, "Session-Expires", 0);
	unsigned iv;
	int ref;
	bool local_ref;

	echo[0] = 0;
	if (!se || gmcall_parse_session_expires(se, &iv, &ref)) {
		if (c->se_interval)
			sess_arm(c);	/* a refresh without the header still refreshes */
		return 0;
	}
	if (iv < c->mgr->cfg.min_se) {
		*minse = c->mgr->cfg.min_se;
		return -1;
	}
	if (ref == GMCALL_REFRESHER_NONE)
		ref = c->se_interval && c->se_local_refresher ? GMCALL_REFRESHER_UAS : GMCALL_REFRESHER_UAC;
	local_ref = ref == GMCALL_REFRESHER_UAS;	/* the request's UAS (us) refreshes */
	gm_sess_start(c, iv, local_ref);
	snprintf(echo, n, "%sSession-Expires: %u;refresher=%s\r\n", local_ref ? "" : "Require: timer\r\n", iv,
		 local_ref ? "uas" : "uac");
	return 0;
}

static void reinv_giveup(struct sip_rtx *r, void *arg)
{
	struct gmcall *c = arg;

	(void)r;
	c->rtx_reinv = NULL;	/* freed by the helper right after this callback */
	LOGW("gmcall#%u: no ACK for the 200 of a re-INVITE", c->id);
	gm_terminate_local(c, true, "no ACK for the 200 OK of a re-INVITE");
}

static void remote_offer(struct gmcall *c, struct sip_dialog *d, struct txn_server *st, const struct sip_msg *req,
			 bool is_invite)
{
	bool has_sdp = gm_has_sdp(req);
	struct sdp *offer = NULL, *ans = NULL;
	struct sdpn_media neg;
	struct buf body, ex;
	struct sip_resp_parts p;
	char contact[512], echo[160], ra[48];
	unsigned minse = 0;
	int rc;
	bool reinv_out = c->reinv && (c->reinv->kind == CK_REINVITE || c->reinv->via_invite);

	(void)d;
	buf_init(&body, 0);
	buf_init(&ex, 1024);
	/* RFC 3261 14.2 / RFC 3311: offers cannot cross */
	if ((is_invite || has_sdp) && (reinv_out || c->state == GMCALL_ST_INCOMING ||
	    (c->dir == GMCALL_MO && c->state != GMCALL_ST_CONNECTED && !c->has_media))) {
		reply(st, 491, NULL);
		goto out;
	}
	if (is_invite && (c->rtx_reinv || c->state == GMCALL_ST_ANSWERING || c->late_offer)) {
		snprintf(ra, sizeof(ra), "Retry-After: %u\r\n", rnd_range(0, 10));
		reply(st, 500, ra);
		goto out;
	}
	if (!c->has_local && (has_sdp || is_invite)) {
		reply(st, 500, NULL);
		goto out;
	}
	if (remote_session(c, req, echo, sizeof(echo), &minse)) {
		snprintf(ra, sizeof(ra), "Min-SE: %u\r\n", minse);
		reply(st, 422, ra);
		goto out;
	}
	if (has_sdp) {
		struct sdp_origin org = c->local.o;
		enum sdp_dir od, ours;
		bool legacy;

		offer = malloc(sizeof(*offer));
		ans = malloc(sizeof(*ans));
		if (!offer || !ans) {
			reply(st, 500, NULL);
			goto out;
		}
		if (sdp_parse(offer, (const char *)req->body, req->body_len)) {
			reply(st, 488, NULL);
			goto out;
		}
		rc = sdpn_carrier_answer(&c->mgr->cfg.sdp, offer, &org, &c->local_rtp, ans, &neg);
		if (rc < 0) {
			LOGW("gmcall#%u: cannot answer the re-offer: %s", c->id, sdpn_strerror(rc));
			reply(st, sdpn_sip_status(rc), NULL);
			goto out;
		}
		od = sdpn_remote_dir(offer, &offer->media[neg.media_index], &legacy);
		ours = sdpn_answer_dir(od, c->want_dir);
		sdpn_apply_dir(ans, &ans->media[neg.media_index], ours, false);
		neg.dir = ours;
		if (sdp_origin_succeed(ans, &c->local) || sdp_write(ans, &body)) {
			reply(st, 500, NULL);
			goto out;
		}
	} else if (is_invite) {	/* late offer: our offer goes into the 2xx, the answer comes with the ACK */
		ans = malloc(sizeof(*ans));
		if (!ans) {
			reply(st, 500, NULL);
			goto out;
		}
		*ans = c->local;
		sdpn_apply_dir(ans, &ans->media[c->audio_idx], c->want_dir, false);
		if (sdp_origin_succeed(ans, &c->local) || sdp_write(ans, &body)) {
			reply(st, 500, NULL);
			goto out;
		}
	}
	if (gm_contact(c, contact, sizeof(contact))) {
		reply(st, 500, NULL);
		goto out;
	}
	buf_puts(&ex, "Allow: " GMCALL_ALLOW "\r\nSupported: timer\r\n");
	buf_puts(&ex, echo);
	memset(&p, 0, sizeof(p));
	p.status = 200;
	p.contact = contact;
	p.extra = buf_cstr(&ex);
	if (body.len) {
		p.content_type = "application/sdp";
		p.body = body.p;
		p.body_len = body.len;
	}
	rc = gm_reply(st, &p);
	if (rc && rc != -EAGAIN) {
		reply(st, 500, NULL);
		goto out;
	}
	if (is_invite) {
		uint32_t cs = 0;

		sip_cseq(req, &cs, NULL, 0);
		c->reinv_cseq = cs;
		c->rtx_reinv = txn_server_start_2xx_rtx(st, 0, 0, reinv_giveup, c);
		if (!has_sdp) {	/* late offer */
			c->late_offer = ans;
			ans = NULL;
		}
	}
	if (has_sdp) {
		c->local = *ans;
		c->audio_idx = neg.media_index;
		gm_report_media(c, &neg, c->state != GMCALL_ST_CONNECTED && c->state != GMCALL_ST_ANSWERING, false);
	}
out:
	buf_free(&body);
	buf_free(&ex);
	free(offer);
	free(ans);
}

static void remote_bye(struct gmcall *c, struct sip_dialog *d, struct txn_server *st, const struct sip_msg *req)
{
	struct gmcall_event ev;
	char txt[96];

	reply(st, 200, NULL);
	memset(&ev, 0, sizeof(ev));
	gmcall_reason_text(sip_hdr(req, "Reason", 0), txt, sizeof(txt));
	if (c->dir == GMCALL_MO && d != gm_main_dlg(c)) {
		LOGI("gmcall#%u: BYE on a dialog that is not the answered one: ignored", c->id);
		return;
	}
	if (c->state == GMCALL_ST_INCOMING) {	/* the caller gave up with BYE before we answered */
		struct sip_resp_parts p = { .status = 487 };

		if (c->inv_st)
			gm_reply(c->inv_st, &p);
		ev.type = GMCALL_EV_CANCELLED;
		ev.by_remote = true;
		gm_ev_text(&ev, "%s", txt[0] ? txt : "BYE before answer");
		gm_finish(c, &ev);
		return;
	}
	if (c->state != GMCALL_ST_CONNECTED && c->state != GMCALL_ST_ANSWERING) {
		LOGI("gmcall#%u: BYE in state %s ignored", c->id, gmcall_state_name(c->state));
		return;
	}
	ev.type = GMCALL_EV_TERMINATED;
	ev.by_remote = true;
	gm_ev_text(&ev, "%s", txt[0] ? txt : "BYE from the network");
	gm_finish(c, &ev);
}

void gm_in_dialog_request(struct gmcall *c, struct sip_dialog *d, struct txn_server *st, const struct sip_msg *req)
{
	const char *m = req->method;

	if (c->ds && c->ds->answered >= 0 && d != gm_main_dlg(c) && strcmp(m, "BYE")) {
		reply(st, 481, NULL);	/* another (forked, early) dialog of the INVITE: only the answered one lives */
		return;
	}
	if (dlg_check_remote_cseq(d, req)) {
		LOGW("gmcall#%u: %s with a CSeq that is not higher than the last one", c->id, m);
		reply(st, 500, NULL);
		return;
	}
	if (!strcmp(m, "BYE")) {
		remote_bye(c, d, st, req);
	} else if (!strcmp(m, "INFO")) {
		reply(st, 200, NULL);
	} else if (!strcmp(m, "OPTIONS")) {
		reply(st, 200, "Allow: " GMCALL_ALLOW "\r\nAccept: application/sdp\r\n");
	} else if (!strcmp(m, "UPDATE") || !strcmp(m, "INVITE")) {
		dlg_refresh_target(d, req);
		gm_note_allow(c, req);
		remote_offer(c, d, st, req, m[0] == 'I');
	} else if (!strcmp(m, "PRACK")) {
		reply(st, 481, NULL);	/* we never send reliable provisional responses */
	} else if (!strcmp(m, "REFER") || !strcmp(m, "NOTIFY")) {
		LOGW("gmcall#%u: in-dialog %s is not supported (501)", c->id, m);
		reply(st, 501, NULL);
	} else {
		LOGW("gmcall#%u: in-dialog %s is not supported (405)", c->id, m);
		reply(st, 405, "Allow: " GMCALL_ALLOW "\r\n");
	}
}

void gm_ack_received(struct gmcall *c, const struct sip_msg *req)
{
	uint32_t cs = 0;

	sip_cseq(req, &cs, NULL, 0);
	if (c->rtx_reinv && cs == c->reinv_cseq) {
		sip_rtx_stop(c->rtx_reinv);
		c->rtx_reinv = NULL;
		if (c->late_offer) {
			struct sdp *ans = malloc(sizeof(*ans));
			struct sdpn_media neg;

			if (ans && gm_has_sdp(req) && !sdp_parse(ans, (const char *)req->body, req->body_len) &&
			    !sdpn_from_answer(c->late_offer, ans, &neg)) {
				c->local = *c->late_offer;
				gm_report_media(c, &neg, false, false);
			} else {
				LOGW("gmcall#%u: no usable SDP answer in the ACK of our late-offer 200", c->id);
			}
			free(ans);
			free(c->late_offer);
			c->late_offer = NULL;
		}
		gm_maybe_reoffer(c);
		return;
	}
	if (c->dir == GMCALL_MT && c->state == GMCALL_ST_ANSWERING) {
		struct gmcall_event ev;

		if (c->rtx200) {
			sip_rtx_stop(c->rtx200);
			c->rtx200 = NULL;
		}
		c->state = GMCALL_ST_CONNECTED;
		memset(&ev, 0, sizeof(ev));
		ev.type = GMCALL_EV_ANSWERED;
		gm_emit(c, &ev);
		gm_maybe_reoffer(c);
	}
}

void gm_dlg_cleanup(struct gmcall *c)
{
	if (c->rtx_reinv) {
		sip_rtx_stop(c->rtx_reinv);
		c->rtx_reinv = NULL;
	}
	if (c->rtx200) {
		sip_rtx_stop(c->rtx200);
		c->rtx200 = NULL;
	}
	free(c->late_offer);
	c->late_offer = NULL;
}
