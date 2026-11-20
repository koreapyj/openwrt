/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Incoming (MT) carrier call: validation, 100 / 180 / 200, reject, CANCEL,
 * 200 retransmission until the ACK.
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

static bool is_ours(const struct reg_ctx *x, const struct sip_endpoint *ep, const char *ruri)
{
	struct sip_uri u, iu;
	struct addr a;

	if (sip_uri_parse(ruri, &u))
		return false;
	if (!strcmp(u.scheme, "tel"))
		return true;
	if (!u.host[0])
		return false;
	if (!addr_set(&a, u.host, 0) && addr_equal_ip(&a, &ep->advertised))
		return true;
	if (x->impu && !sip_uri_parse(x->impu, &iu)) {
		if (u.user[0] && !strcasecmp(u.user, iu.user))
			return true;
		if (!u.user[0] && !strcasecmp(u.host, iu.host))
			return true;
	}
	return false;
}

/* join every line of a (possibly repeated) header into out, comma separated */
static void join_hdr(const struct sip_msg *req, const char *name, char *out, size_t n)
{
	int i, cnt = sip_hdr_count(req, name);
	size_t o = 0;

	out[0] = 0;
	for (i = 0; i < cnt; i++) {
		const char *v = sip_hdr(req, name, i);
		int w = snprintf(out + o, n - o, "%s%s", o ? "," : "", v);

		if (w < 0 || (size_t)w >= n - o)
			break;
		o += (size_t)w;
	}
}

static void send_final_in_state(struct gmcall *c, int status)
{
	if (c->inv_st)
		reply(c->inv_st, status, NULL);
}

static void mt_ev_end(struct gmcall *c, enum gmcall_event_type t, bool by_remote, const char *why, bool deferred)
{
	struct gmcall_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = t;
	ev.by_remote = by_remote;
	gm_ev_text(&ev, "%s", why);
	if (deferred)
		gm_finish_deferred(c, &ev);
	else
		gm_finish(c, &ev);
}

static void srv_cb(struct txn_server *st, enum txn_srv_event ev, void *arg)
{
	struct gmcall *c = arg;

	switch (ev) {
	case TXN_SRV_CANCELLED:
		if (c->state == GMCALL_ST_INCOMING) {
			char txt[96] = "";

			gmcall_reason_text(txn_server_cancel_reason(st), txt, sizeof(txt));
			reply(st, 487, NULL);
			mt_ev_end(c, GMCALL_EV_CANCELLED, true, txt[0] ? txt : "cancelled by the caller", false);
		}
		break;
	case TXN_SRV_TIMEOUT:
		LOGD("gmcall#%u: no ACK for the final response of the INVITE", c->id);
		break;
	case TXN_SRV_TERMINATED:
		c->inv_st = NULL;
		break;
	}
}

static int ring_reply(struct gmcall *c)
{
	struct sip_resp_parts p;
	struct buf ex;
	char contact[512];
	int rc;

	if (!c->inv_st || gm_contact(c, contact, sizeof(contact)))
		return -EINVAL;
	buf_init(&ex, 512);
	if (c->snap.pani[0])
		buf_printf(&ex, "P-Access-Network-Info: %s\r\n", c->snap.pani);
	buf_puts(&ex, "Allow: " GMCALL_ALLOW "\r\n");
	memset(&p, 0, sizeof(p));
	p.status = 180;
	p.contact = contact;
	p.extra = buf_cstr(&ex);
	rc = gm_reply(c->inv_st, &p);
	buf_free(&ex);
	return rc == -EINVAL ? -EINVAL : 0;
}

int gmcall_ring(struct gmcall *c)
{
	if (!gm_live(c))
		return -ESTALE;
	if (c->dir != GMCALL_MT || c->state != GMCALL_ST_INCOMING)
		return -EINVAL;
	if (c->ringing_sent)
		return 0;
	c->ringing_sent = true;
	return ring_reply(c);
}

static void rtx200_giveup(struct sip_rtx *r, void *arg)
{
	struct gmcall *c = arg;

	(void)r;
	c->rtx200 = NULL;	/* freed by the helper after this callback */
	LOGW("gmcall#%u: no ACK for the 200 OK within 64*T1: BYE", c->id);
	gm_terminate_local(c, true, "no ACK for the 200 OK");
}

int gmcall_answer(struct gmcall *c, const struct addr *rtp)
{
	struct sdp_origin org;
	struct sdpn_media neg;
	struct sip_resp_parts p;
	struct buf ex, body;
	char contact[512], se[160] = "";
	int rc;

	if (!gm_live(c))
		return -ESTALE;
	if (c->dir != GMCALL_MT || c->state != GMCALL_ST_INCOMING || !c->offer || !c->inv_st)
		return -EINVAL;
	if (!rtp || !addr_port(rtp))
		return -EINVAL;
	gm_origin_new(&org);
	rc = sdpn_carrier_answer(&c->mgr->cfg.sdp, c->offer, &org, rtp, &c->local, &neg);
	if (rc < 0) {
		LOGW("gmcall#%u: cannot build the SDP answer: %s", c->id, sdpn_strerror(rc));
		return -EPROTO;
	}
	if (gm_contact(c, contact, sizeof(contact)))
		return -EINVAL;
	buf_init(&body, 0);
	buf_init(&ex, 1024);
	if (sdp_write(&c->local, &body)) {
		buf_free(&body);
		buf_free(&ex);
		return -EMSGSIZE;
	}
	if (c->snap.pani[0])
		buf_printf(&ex, "P-Access-Network-Info: %s\r\n", c->snap.pani);
	buf_puts(&ex, "Allow: " GMCALL_ALLOW "\r\nSupported: timer\r\n");
	if (c->se_req) {
		if (!c->se_local_refresher)
			buf_puts(&ex, "Require: timer\r\n");	/* RFC 4028 section 9: refresher=uac */
		snprintf(se, sizeof(se), "Session-Expires: %u;refresher=%s\r\n", c->se_req,
			 c->se_local_refresher ? "uas" : "uac");
		buf_puts(&ex, se);
	}
	memset(&p, 0, sizeof(p));
	p.status = 200;
	p.contact = contact;
	p.extra = buf_cstr(&ex);
	p.content_type = "application/sdp";
	p.body = body.p;
	p.body_len = body.len;
	rc = gm_reply(c->inv_st, &p);
	buf_free(&ex);
	buf_free(&body);
	if (rc == -EINVAL)
		return -EINVAL;
	c->has_local = true;
	c->local_rtp = *rtp;
	c->audio_idx = neg.media_index;
	c->media = neg;
	c->has_media = true;
	c->rtx200 = txn_server_start_2xx_rtx(c->inv_st, 0, 0, rtx200_giveup, c);
	if (!c->rtx200)
		LOGW("gmcall#%u: cannot retransmit the 200 OK (out of memory)", c->id);
	c->state = GMCALL_ST_ANSWERING;
	c->t_connect = ev_now_ms();
	gm_misc_cancel(c);
	free(c->offer);
	c->offer = NULL;
	if (c->se_req)
		gm_sess_start(c, c->se_req, c->se_local_refresher);
	return 0;
}

int gmcall_reject(struct gmcall *c, int status)
{
	char why[64];

	if (!gm_live(c))
		return -ESTALE;
	if (c->dir != GMCALL_MT || c->state != GMCALL_ST_INCOMING || !c->inv_st)
		return -EINVAL;
	if (status < 300 || status > 699)
		return -EINVAL;
	send_final_in_state(c, status);
	snprintf(why, sizeof(why), "rejected with %d %s", status, sip_reason_phrase(status));
	mt_ev_end(c, GMCALL_EV_CANCELLED, false, why, true);
	return 0;
}

int gm_mt_hangup(struct gmcall *c)
{
	switch (c->state) {
	case GMCALL_ST_INCOMING:
		return gmcall_reject(c, 480);
	case GMCALL_ST_ANSWERING:
	case GMCALL_ST_CONNECTED:
		gm_terminate_local(c, true, "local hangup");
		return 0;
	default:
		return -EINVAL;
	}
}

void gm_mt_ring_timeout(struct gmcall *c)
{
	if (c->state != GMCALL_ST_INCOMING)
		return;
	send_final_in_state(c, 480);
	mt_ev_end(c, GMCALL_EV_CANCELLED, false, "not answered (ring timeout)", false);
}

void gm_mt_down(struct gmcall *c)
{
	if (c->state == GMCALL_ST_INCOMING) {
		send_final_in_state(c, 480);
		mt_ev_end(c, GMCALL_EV_CANCELLED, false, "registration lost", false);
		return;
	}
	if (c->state == GMCALL_ST_ANSWERING || c->state == GMCALL_ST_CONNECTED) {
		gm_send_bye(c, &c->udlg);
		mt_ev_end(c, GMCALL_EV_TERMINATED, false, "registration lost", false);
	}
}

/* ------------------------------------------------------------------ */

bool gm_mt_new(struct gmcall_mgr *m, struct txn_server *st, struct sip_endpoint *ep, const struct sip_msg *req)
{
	const struct reg_ctx *x = gm_ctx(m);
	struct gmcall *c = NULL;
	struct sdp *offer = NULL, *dry = NULL;
	struct sdp_origin org;
	struct sdpn_media neg;
	struct addr dummy;
	char unsup[96], reqs[160], supp[160], called[48] = "", tmp[256];
	const char *se, *pcp;
	unsigned se_iv = 0;
	int se_ref = GMCALL_REFRESHER_NONE, rc;
	bool timer_ok;

	if (!x) {
		reply(st, 480, NULL);
		return true;
	}
	if (!is_ours(x, ep, req->ruri)) {
		LOGW("gmcall: INVITE for %s is not for us (404)", req->ruri);
		reply(st, 404, NULL);
		return true;
	}
	/* never implemented: 100rel (we would have to send reliable provisionals), preconditions */
	join_hdr(req, "Require", reqs, sizeof(reqs));
	if (gmcall_unsupported_options(reqs, unsup, sizeof(unsup))) {
		char h[128];

		LOGE("gmcall: INVITE requires '%s' which is not supported: 420 (Require: %s)", unsup, reqs);
		snprintf(h, sizeof(h), "Unsupported: %s\r\n", unsup);
		reply(st, 420, h);
		return true;
	}
	if (!m->cfg.on_incoming) {
		LOGI("gmcall: no handler for incoming calls: 480");
		reply(st, 480, NULL);
		return true;
	}
	if (m->ncalls >= m->cfg.max_calls) {
		LOGW("gmcall: call limit reached, incoming INVITE answered 486");
		reply(st, 486, NULL);
		return true;
	}
	if (!gm_has_sdp(req)) {
		LOGW("gmcall: INVITE without an SDP offer is not supported: 488");
		reply(st, 488, NULL);
		return true;
	}
	offer = malloc(sizeof(*offer));
	dry = malloc(sizeof(*dry));
	if (!offer || !dry) {
		reply(st, 500, NULL);
		goto out;
	}
	rc = sdp_parse(offer, (const char *)req->body, req->body_len);
	if (rc) {
		LOGW("gmcall: unparsable SDP offer: %s", sdp_strerror(rc));
		reply(st, 488, NULL);
		goto out;
	}
	/* dry run: reject unusable offers before the phone rings */
	gm_origin_new(&org);
	addr_set(&dummy, "::1", 9);
	rc = sdpn_carrier_answer(&m->cfg.sdp, offer, &org, &dummy, dry, &neg);
	if (rc < 0) {
		LOGW("gmcall: SDP offer cannot be answered: %s", sdpn_strerror(rc));
		reply(st, sdpn_sip_status(rc), NULL);
		goto out;
	}
	join_hdr(req, "Supported", supp, sizeof(supp));
	timer_ok = gmcall_has_token(supp, "timer") || gmcall_has_token(reqs, "timer");
	se = sip_hdr(req, "Session-Expires", 0);
	if (se && !gmcall_parse_session_expires(se, &se_iv, &se_ref)) {
		if (se_iv < m->cfg.min_se) {
			snprintf(tmp, sizeof(tmp), "Min-SE: %u\r\n", m->cfg.min_se);
			reply(st, 422, tmp);
			goto out;
		}
	} else {
		se_iv = 0;
	}
	c = gm_call_new(m, GMCALL_MT);
	if (!c) {
		reply(st, 500, NULL);
		goto out;
	}
	if (dlg_init_uas(&c->udlg, ep, req, txn_server_to_tag(st))) {
		LOGW("gmcall: INVITE with unusable dialog headers: 400");
		reply(st, 400, NULL);
		c->state = GMCALL_ST_INCOMING;
		gm_finish_deferred(c, &(struct gmcall_event){ .type = GMCALL_EV_CANCELLED });
		goto out;
	}
	c->udlg_used = true;
	c->state = GMCALL_ST_INCOMING;
	c->inv_st = st;
	txn_server_set_cb(st, srv_cb, c);
	snprintf(c->call_id, sizeof(c->call_id), "%s", c->udlg.call_id);
	gmcall_identity_from_request(req, &c->remote);
	pcp = sip_hdr(req, "P-Called-Party-ID", 0);
	if (gmcall_number_normalize(pcp ? pcp : req->ruri, called, sizeof(called)))
		called[0] = 0;
	snprintf(c->called, sizeof(c->called), "%s", called);
	gm_snapshot(c, x);
	gm_note_allow(c, req);
	c->offer = offer;
	offer = NULL;
	c->media = neg;
	c->has_media = true;
	if (se_iv) {
		if (se_ref == GMCALL_REFRESHER_NONE)
			se_ref = timer_ok ? GMCALL_REFRESHER_UAC : GMCALL_REFRESHER_UAS;
		c->se_req = se_iv;
		c->se_local_refresher = se_ref == GMCALL_REFRESHER_UAS;
	}
	if (txn_server_last_status(st) < 100) {
		reply(st, 100, NULL);
	}
	LOGI("gmcall#%u: incoming call from %s (%s) to %s, offer %s %s", c->id, c->remote.number, c->remote.uri, c->called,
	     sdpn_codec_name(neg.codec), c->remote.anonymous ? "[anonymous]" : "");
	{
		struct gmcall_incoming in;

		memset(&in, 0, sizeof(in));
		in.caller = c->remote;
		snprintf(in.called, sizeof(in.called), "%s", c->called);
		in.offered = &c->media;
		in.session_timer = se_iv != 0;
		rc = m->cfg.on_incoming(c, &in, m->cfg.incoming_arg);
	}
	if (!gm_live(c))
		goto out;
	if (rc) {
		if (c->state == GMCALL_ST_INCOMING)
			gmcall_reject(c, 480);
		goto out;
	}
	if (!c->cb)
		LOGW("gmcall#%u: the incoming handler did not install an event handler", c->id);
	if (m->cfg.auto_ring && !c->ringing_sent && c->state == GMCALL_ST_INCOMING)
		gmcall_ring(c);
	if (c->state == GMCALL_ST_INCOMING && m->cfg.ring_timeout_s)
		gm_misc_arm(c, MISC_RING, (uint64_t)m->cfg.ring_timeout_s * 1000);
out:
	free(offer);
	free(dry);
	return true;
}
