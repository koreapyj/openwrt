/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Outgoing (MO) carrier call: INVITE construction, forking-aware response
 * handling (early dialogs, PRACK, 2xx on a different dialog, extra 2xx),
 * CANCEL, 422 retry.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "gmcall_int.h"

static int send_invite(struct gmcall *c, bool first)
{
	struct gmcall_mgr *m = c->mgr;
	const struct reg_ctx *x = gm_ctx(m);
	char via[200], branch[SIP_BRANCH_LEN], from[300], to[300], contact[512], pc[96], tag[64], pai[300];
	struct buf route, ex, out, sb;
	struct sip_req_parts p;
	struct creq *r;
	int i, rc = -ENOMEM;

	if (!x || !x->ep || !x->impu || !x->security_verify)
		return -ENOTCONN;
	gm_snapshot(c, x);
	if (first) {
		rnd_token(tag, 16);
	} else {
		snprintf(tag, sizeof(tag), "%s", c->ds->local_tag);
		dlgset_release(c->ds);
	}
	c->cseq++;
	if (dlgset_init(c->ds, x->ep, c->call_id, tag, x->impu, c->target, c->cseq))
		return -EMSGSIZE;
	if (addr_str(&x->pcscf_ps, pc, sizeof(pc)) || gm_contact(c, contact, sizeof(contact)))
		return -EMSGSIZE;
	sip_new_branch(branch);
	if (sip_via_make(via, sizeof(via), x->ep->kind == SIP_TP_TCP ? "TCP" : "UDP", &x->ep->advertised, branch, false))
		return -EMSGSIZE;
	snprintf(from, sizeof(from), "<%s>;tag=%s", x->impu, tag);
	snprintf(to, sizeof(to), "<%s>", c->target);
	snprintf(pai, sizeof(pai), "<%s>", x->impu);

	buf_init(&route, 2048);
	buf_init(&ex, 4096);
	buf_init(&out, SIP_MAX_MSG);
	buf_init(&sb, 0);
	buf_printf(&route, "Route: <sip:%s;lr>\r\n", pc);
	for (i = 0; i < x->n_service_route; i++)
		buf_printf(&route, "Route: %s\r\n", x->service_route[i]);
	if (x->pani && x->pani[0])
		buf_printf(&ex, "P-Access-Network-Info: %s\r\n", x->pani);
	buf_printf(&ex, "Security-Verify: %s\r\n", x->security_verify);
	buf_puts(&ex, "Proxy-Require: sec-agree\r\nRequire: sec-agree\r\n");
	buf_printf(&ex, "P-Preferred-Identity: %s\r\n", pai);
	if (m->user_agent[0])
		buf_printf(&ex, "User-Agent: %s\r\n", m->user_agent);
	buf_puts(&ex, "Allow: " GMCALL_ALLOW "\r\n");
	buf_puts(&ex, "Accept: application/sdp\r\n");
	buf_puts(&ex, "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel\r\n");
	buf_puts(&ex, "Accept-Contact: *;+g.3gpp.icsi-ref=\"" GMCALL_ICSI "\"\r\n");
	buf_puts(&ex, "Supported: 100rel,timer\r\n");	/* not "replaces": not implemented */
	buf_puts(&ex, "P-Early-Media: supported\r\n");
	buf_printf(&ex, "Session-Expires: %u;refresher=uac\r\n", c->se_req);
	if (c->min_se_hdr)
		buf_printf(&ex, "Min-SE: %u\r\n", c->min_se_hdr);
	buf_puts(&ex, c->extra_hdrs);

	if (sdp_write(&c->local, &sb) || !buf_ok(&route) || !buf_ok(&ex))
		goto out;
	memset(&p, 0, sizeof(p));
	p.method = "INVITE";
	p.ruri = c->target;
	p.via = via;
	p.from = from;
	p.to = to;
	p.call_id = c->call_id;
	p.cseq = c->cseq;
	p.route = buf_cstr(&route);
	p.contact = contact;
	p.extra = buf_cstr(&ex);
	p.content_type = "application/sdp";
	p.body = sb.p;
	p.body_len = sb.len;
	if (sip_build_request(&out, &p)) {
		rc = -EMSGSIZE;
		goto out;
	}
	r = gm_creq_new(m, c, CK_INVITE);
	if (!r)
		goto out;
	r->cseq = c->cseq;
	c->inv = r;
	rc = gm_creq_start(c, r, x->ep, &x->pcscf_ps, out.p, out.len);
	if (rc)
		c->inv = NULL;
	else
		LOGI("gmcall#%u: INVITE %s sent (%zu bytes)", c->id, c->target, out.len);
out:
	buf_free(&route);
	buf_free(&ex);
	buf_free(&out);
	buf_free(&sb);
	return rc;
}

int gm_mo_dial(struct gmcall_mgr *m, const struct gmcall_dial *d, gmcall_event_cb cb, void *arg, struct gmcall **out)
{
	const struct reg_ctx *x = gm_ctx(m);
	struct gmcall *c;
	struct sdp_origin org;
	char host[64];
	int rc;

	if (!d || !d->target || !out)
		return -EINVAL;
	if (!x)
		return -ENOTCONN;
	if (!addr_port(&d->local_rtp))
		return -EINVAL;
	if (d->extra_headers && strlen(d->extra_headers) >= sizeof(((struct gmcall *)0)->extra_hdrs))
		return -EMSGSIZE;
	if (m->ncalls >= m->cfg.max_calls) {
		LOGW("gmcall: call limit (%u) reached, not dialling", m->cfg.max_calls);
		return -ENOBUFS;
	}
	c = gm_call_new(m, GMCALL_MO);
	if (!c)
		return -ENOMEM;
	rc = gmcall_make_target(d->target, m->phone_context, c->target, sizeof(c->target));
	if (rc)
		goto fail;
	if (d->extra_headers)
		snprintf(c->extra_hdrs, sizeof(c->extra_hdrs), "%s", d->extra_headers);
	rc = -ENOMEM;
	c->ds = calloc(1, sizeof(*c->ds));
	if (!c->ds)
		goto fail;
	c->cb = cb;
	c->cb_arg = arg;
	c->state = GMCALL_ST_DIALING;
	c->se_req = m->cfg.session_expires;
	c->local_rtp = d->local_rtp;
	snprintf(c->remote.uri, sizeof(c->remote.uri), "%s", c->target);
	if (gmcall_number_normalize(c->target, c->remote.number, sizeof(c->remote.number)))
		c->remote.number[0] = 0;
	if (addr_host(&x->ep->advertised, host, sizeof(host)))
		snprintf(host, sizeof(host), "imsd");
	snprintf(c->call_id, sizeof(c->call_id), "%08x%08x@%s", rnd32(), rnd32(), host);
	gm_origin_new(&org);
	if (sdpn_carrier_offer(&m->cfg.sdp, &org, &d->local_rtp, &c->local) < 0) {
		rc = -EINVAL;
		goto fail;
	}
	c->has_local = true;
	c->audio_idx = 0;
	rc = send_invite(c, true);
	if (rc)
		goto fail;
	if (m->cfg.ring_timeout_s)
		gm_misc_arm(c, MISC_RING, (uint64_t)m->cfg.ring_timeout_s * 1000);
	*out = c;
	return 0;
fail:
	/* nothing was announced to the user: silent removal (reaped on the next loop iteration) */
	c->cb = NULL;
	{
		struct gmcall_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.type = GMCALL_EV_FAILED;
		c->state = GMCALL_ST_DIALING;
		gm_finish(c, &ev);
	}
	return rc;
}

/* ------------------------------------------------------------------ */

static void finish_cancelled(struct gmcall *c)
{
	struct gmcall_event ev;

	memset(&ev, 0, sizeof(ev));
	if (c->timeout_cancel) {
		ev.type = GMCALL_EV_FAILED;
		ev.status = 408;
		gm_ev_text(&ev, "no answer (ring timeout)");
	} else {
		ev.type = GMCALL_EV_CANCELLED;
		ev.by_remote = false;
		gm_ev_text(&ev, "cancelled");
	}
	gm_finish(c, &ev);
}

static int do_cancel(struct gmcall *c)
{
	if (!c->inv || !c->inv->c || txn_client_cancel(c->inv->c, NULL, NULL))
		return -EINVAL;
	c->state = GMCALL_ST_CANCELLING;
	gm_misc_arm(c, MISC_CANCEL_GUARD, GMCALL_CANCEL_GUARD_MS);
	return 0;
}

int gm_mo_hangup(struct gmcall *c)
{
	switch (c->state) {
	case GMCALL_ST_DIALING:
	case GMCALL_ST_EARLY:
		return do_cancel(c);
	case GMCALL_ST_CANCELLING:
		return 0;
	case GMCALL_ST_CONNECTED:
		gm_terminate_local(c, true, "local hangup");
		return 0;
	default:
		return -EINVAL;
	}
}

void gm_mo_ring_timeout(struct gmcall *c)
{
	if (c->state != GMCALL_ST_DIALING && c->state != GMCALL_ST_EARLY)
		return;
	LOGW("gmcall#%u: no final response within the ring timeout: CANCEL", c->id);
	c->timeout_cancel = true;
	if (do_cancel(c))
		finish_cancelled(c);
}

void gm_mo_cancel_guard(struct gmcall *c)
{
	if (c->state != GMCALL_ST_CANCELLING)
		return;
	LOGW("gmcall#%u: no final response to the CANCELled INVITE", c->id);
	finish_cancelled(c);
}

void gm_mo_down(struct gmcall *c)
{
	struct gmcall_event ev;

	memset(&ev, 0, sizeof(ev));
	switch (c->state) {
	case GMCALL_ST_CONNECTED: {
		struct sip_dialog *d = gm_main_dlg(c);

		if (d)
			gm_send_bye(c, d);	/* only goes out if the endpoint still exists */
		ev.type = GMCALL_EV_TERMINATED;
		gm_ev_text(&ev, "registration lost");
		break;
	}
	case GMCALL_ST_CANCELLING:
		ev.type = GMCALL_EV_CANCELLED;
		gm_ev_text(&ev, "registration lost");
		break;
	default:
		ev.type = GMCALL_EV_FAILED;
		ev.status = 0;
		gm_ev_text(&ev, "registration lost");
		break;
	}
	gm_finish(c, &ev);
}

/* ------------------------------------------------------------------ */

/* interpret the SDP of a response as the answer to our offer and report it */
static int handle_answer(struct gmcall *c, const struct sip_msg *resp, bool early)
{
	struct sdp *ans = malloc(sizeof(*ans));
	struct sdpn_media neg;
	int rc;

	if (!ans)
		return -1;
	rc = sdp_parse(ans, (const char *)resp->body, resp->body_len);
	if (rc) {
		LOGW("gmcall#%u: unparsable SDP in a %d (%s)", c->id, resp->status, sdp_strerror(rc));
		free(ans);
		return -1;
	}
	rc = sdpn_from_answer(&c->local, ans, &neg);
	free(ans);
	if (rc) {
		LOGW("gmcall#%u: SDP answer in a %d is unusable: %s", c->id, resp->status, sdpn_strerror(rc));
		return -1;
	}
	gm_report_media(c, &neg, early, !early);
	return 0;
}

static void send_prack(struct gmcall *c, int di, uint32_t rseq)
{
	struct sip_dialog *d = &c->ds->d[di];
	struct gm_route rt;
	struct gm_req q;
	struct creq *r;
	struct buf b;
	char ra[64];

	if (gm_route_get(c, d, &rt))
		return;
	snprintf(ra, sizeof(ra), "RAck: %u %u INVITE\r\n", rseq, c->ds->invite_cseq);
	memset(&q, 0, sizeof(q));
	q.method = "PRACK";
	q.extra = ra;
	buf_init(&b, SIP_MAX_MSG);
	r = gm_creq_new(c->mgr, NULL, CK_PRACK);
	if (r && !gm_build_in_dialog(c, d, &q, &rt, &b, &r->cseq)) {
		if (gm_creq_start(c, r, rt.ep, &rt.dst, b.p, b.len))
			LOGW("gmcall#%u: PRACK could not be sent", c->id);
	} else if (r) {
		gm_creq_free(r);
	}
	buf_free(&b);
}

static void provisional(struct gmcall *c, const struct sip_msg *resp, const struct dlg_ev *ev, int n, int di)
{
	struct gmcall_event e;
	bool has_sdp = gm_has_sdp(resp), fresh;
	char tag[64] = "";
	const char *to = sip_hdr(resp, "To", 0), *em = sip_hdr(resp, "P-Early-Media", 0);
	int i;

	if (c->state == GMCALL_ST_DIALING)
		c->state = GMCALL_ST_EARLY;
	if (c->state == GMCALL_ST_CANCELLING) {
		for (i = 0; i < n; i++)	/* keep the early dialog healthy, nothing is reported any more */
			if (ev[i].type == DLG_EV_PRACK)
				send_prack(c, ev[i].dlg, ev[i].rseq);
		return;
	}
	for (i = 0; i < n; i++)
		if (ev[i].type == DLG_EV_PRACK)
			send_prack(c, ev[i].dlg, ev[i].rseq);
	if (to)
		sip_tag(to, tag, sizeof(tag));
	fresh = resp->status != c->last_prog_status || strcmp(tag, c->last_prog_tag) || has_sdp != c->last_prog_sdp;
	c->last_prog_status = resp->status;
	c->last_prog_sdp = has_sdp;
	snprintf(c->last_prog_tag, sizeof(c->last_prog_tag), "%s", tag);
	if (fresh) {
		memset(&e, 0, sizeof(e));
		e.type = GMCALL_EV_PROGRESS;
		e.status = resp->status;
		e.has_sdp = has_sdp;
		if (em)
			snprintf(e.early_media, sizeof(e.early_media), "%s", em);
		gm_emit(c, &e);
	}
	if (has_sdp && di >= 0 && gm_live(c))
		handle_answer(c, resp, true);
	if (fresh && gm_live(c) && resp->status == 180 && !has_sdp) {
		memset(&e, 0, sizeof(e));
		e.type = GMCALL_EV_RINGING;
		gm_emit(c, &e);
	}
}

static void failed_final(struct gmcall *c, const struct sip_msg *resp)
{
	struct gmcall_event e;
	char txt[96] = "";

	memset(&e, 0, sizeof(e));
	e.type = GMCALL_EV_FAILED;
	e.status = resp->status;
	gmcall_warning_text(sip_hdr(resp, "Warning", 0), e.warning, sizeof(e.warning));
	gmcall_reason_text(sip_hdr(resp, "Reason", 0), txt, sizeof(txt));
	if (txt[0])
		gm_ev_text(&e, "%s", txt);
	else if (e.warning[0])
		gm_ev_text(&e, "%s", e.warning);
	else
		gm_ev_text(&e, "%s", resp->reason[0] ? resp->reason : sip_reason_phrase(resp->status));
	if (resp->status == 401 || resp->status == 407)	/* re-authentication is the registration module's job */
		LOGW("gmcall#%u: INVITE challenged with %d: reported as a failure", c->id, resp->status);
	gm_finish(c, &e);
}

static void final_failure(struct gmcall *c, const struct sip_msg *resp)
{
	int st = resp->status;

	if (st == 422 && !c->retried_422 && c->state != GMCALL_ST_CANCELLING) {
		unsigned minse;

		if (!gmcall_parse_min_se(sip_hdr(resp, "Min-SE", 0), &minse)) {
			c->retried_422 = true;
			c->min_se_hdr = minse;
			if (c->se_req < minse)
				c->se_req = minse;
			LOGI("gmcall#%u: 422, retrying the INVITE with Session-Expires %u", c->id, c->se_req);
			if (!send_invite(c, false))
				return;
		}
	}
	if (c->state == GMCALL_ST_CANCELLING) {
		finish_cancelled(c);
		return;
	}
	failed_final(c, resp);
}

static void final_2xx(struct gmcall *c, const struct sip_msg *resp, const struct dlg_ev *ev, int n)
{
	struct dlgset *ds = c->ds;
	struct gmcall_event e;
	int i;

	for (i = 0; i < n; i++) {
		struct sip_dialog *d = &ds->d[ev[i].dlg];

		if (ev[i].type == DLG_EV_DUP_2XX) {
			gm_send_ack(c, d, ds->invite_cseq);
			continue;
		}
		if (ev[i].type != DLG_EV_ACK)
			continue;
		if (c->state == GMCALL_ST_CANCELLING || ds->answered != ev[i].dlg) {
			/* a 2xx we do not want: the user cancelled, or another fork answered as well */
			gm_send_ack(c, d, ds->invite_cseq);
			gm_send_bye(c, d);
			if (c->state == GMCALL_ST_CANCELLING)
				finish_cancelled(c);
			else
				LOGI("gmcall#%u: extra 2xx from a forked dialog (tag %s): ACK + BYE", c->id, d->remote_tag);
			continue;
		}
		gm_send_ack(c, d, ds->invite_cseq);
		gm_note_allow(c, resp);
		if (gm_has_sdp(resp)) {
			if (handle_answer(c, resp, false)) {
				gm_send_bye(c, d);
				memset(&e, 0, sizeof(e));
				e.type = GMCALL_EV_FAILED;
				e.status = 488;
				gm_ev_text(&e, "unusable SDP answer in the 200 OK");
				gm_finish(c, &e);
				return;
			}
		} else if (!c->has_media) {
			LOGW("gmcall#%u: 200 OK without SDP and no early media: no media description", c->id);
		}
		c->state = GMCALL_ST_CONNECTED;
		c->t_connect = ev_now_ms();
		gm_misc_cancel(c);
		gm_sess_from_2xx(c, resp);
		memset(&e, 0, sizeof(e));
		e.type = GMCALL_EV_ANSWERED;
		gm_emit(c, &e);
		if (!gm_live(c))
			return;
	}
}

void gm_mo_response(struct gmcall *c, struct creq *r, const struct sip_msg *resp)
{
	struct dlg_ev ev[4];
	char tag[160] = "";
	const char *to;
	int n, di = -1;

	if (r && r != c->inv)
		return;		/* answer to the INVITE that a 422 retry replaced */
	if (resp->status == 100 || !c->ds)
		return;
	if (resp->status >= 300) {
		if (r)
			final_failure(c, resp);
		return;
	}
	n = dlgset_on_response(c->ds, resp, ev, 4);
	to = sip_hdr(resp, "To", 0);
	if (to && !sip_tag(to, tag, sizeof(tag)) && tag[0])
		di = dlgset_find(c->ds, tag);
	if (resp->status < 200)
		provisional(c, resp, ev, n, di);
	else
		final_2xx(c, resp, ev, n);
}

void gm_mo_txn_failed(struct gmcall *c, struct creq *r, int status, const char *why)
{
	struct gmcall_event e;

	if (r != c->inv)
		return;
	if (c->state == GMCALL_ST_CANCELLING) {
		finish_cancelled(c);
		return;
	}
	memset(&e, 0, sizeof(e));
	e.type = GMCALL_EV_FAILED;
	e.status = status;
	gm_ev_text(&e, "%s", why);
	gm_finish(c, &e);
}

bool gm_mo_stray_2xx(struct gmcall *c, struct sip_endpoint *ep, const struct sip_msg *resp)
{
	(void)ep;
	LOGD("gmcall#%u: 2xx outside the INVITE transaction", c->id);
	gm_mo_response(c, NULL, resp);
	return true;
}
