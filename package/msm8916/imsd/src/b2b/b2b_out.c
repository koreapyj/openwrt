/* SPDX-License-Identifier: GPL-2.0-or-later */
/* LAN -> network: the client's INVITE becomes a carrier call; carrier events become responses to the client. */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "b2b_int.h"

#define ALLOW "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, UPDATE, INFO\r\n"

static int hexv(int c)
{
	return isdigit(c) ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
}

/* the dialled number: the user part of the Request-URI, percent-decoded ("*21%23" -> "*21#") */
static int ruri_number(const char *ruri, char *out, size_t n)
{
	struct sip_uri u;
	size_t o = 0;
	const char *s;

	if (!ruri || sip_uri_parse(ruri, &u) || !u.user[0])
		return -1;
	for (s = u.user; *s && o + 1 < n; s++) {
		if (*s == '%' && hexv(s[1]) >= 0 && hexv(s[2]) >= 0) {
			out[o++] = (char)(hexv(s[1]) * 16 + hexv(s[2]));
			s += 2;
		} else {
			out[o++] = *s;
		}
	}
	out[o] = 0;
	return o ? 0 : -1;
}

/* the carrier's final status as the client should see it */
static int map_status(int st)
{
	switch (st) {
	case 400: case 403: case 404: case 406: case 410: case 480: case 484: case 486: case 488:
	case 500: case 501: case 502: case 503: case 504: case 513:
	case 600: case 603: case 604: case 606:
		return st;
	case 485:
		return 404;
	case 0:
		return 503;
	case 408:
		return 480;
	default:
		if (st >= 600)
			return st;
		if (st >= 500)
			return 503;
		return 480;	/* 3xx, auth / timer problems (401 407 422 423) and the rest of the 4xx */
	}
}

static void clean_text(const char *in, char *out, size_t n)
{
	size_t o = 0;

	for (; *in && o + 1 < n; in++)
		out[o++] = (*in == '"' || *in == '\\' || (unsigned char)*in < 0x20) ? ' ' : *in;
	out[o] = 0;
}

static void send_prov(struct b2b_call *c, int status, bool with_sdp)
{
	struct sip_resp_parts p;
	struct buf body, ex;
	char contact[128], h[80];
	struct lan *l = core_lan(B.core);

	if (!c->ist || !l)
		return;
	addr_uri_host(&lan_endpoint(l)->advertised, h, sizeof(h));
	snprintf(contact, sizeof(contact), "<sip:imsd@%s:%u>", h, addr_port(&lan_endpoint(l)->advertised));
	memset(&p, 0, sizeof(p));
	buf_init(&body, 0);
	buf_init(&ex, 256);
	buf_printf(&ex, "Server: %s\r\n" ALLOW, b2b_user_agent());
	p.status = status;
	p.contact = contact;
	p.extra = buf_cstr(&ex);
	if (with_sdp && c->ans && !sdp_write(c->ans, &body)) {
		p.content_type = "application/sdp";
		p.body = body.p;
		p.body_len = body.len;
	}
	txn_server_reply(c->ist, &p);
	buf_free(&body);
	buf_free(&ex);
}

static void srv_cb(struct txn_server *st, enum txn_srv_event ev, void *arg)
{
	struct b2b_call *c = arg;

	switch (ev) {
	case TXN_SRV_CANCELLED:
		LOGI("call#%u: CANCEL from the client %s", c->id, txn_server_cancel_reason(st));
		c->client_cancelled = true;
		if (c->st == CS_SETUP || c->st == CS_EARLY) {
			b2b_lan_reply(st, 487, NULL);
			c->end_status = 487;
			b2b_teardown(c, "cancelled by the client", false);
		}
		break;
	case TXN_SRV_TERMINATED:
		if (c->ist == st)
			c->ist = NULL;
		break;
	default:
		break;
	}
}

void b2b_out_invite(const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req)
{
	const struct imsd_config *cfg = b2b_cfg();
	const char *ct = sip_hdr(req, "Content-Type", 0), *rq = sip_hdr(req, "Require", 0);
	struct b2b_call *c = NULL;
	struct sdp *offer = NULL;
	struct sdpn_lan_cfg lc;
	struct sdp_origin org;
	struct cc_dial d;
	const struct carrier_backend *be = b2b_cur_backend();
	bool pcm = be && be->ops->media_kind == CC_MEDIA_PCM;
	char num[48], phone_ctx[96], ua[128], hdr[200];
	const char *why = "";
	int rc, status = 0;
	bool legacy = false;

	(void)p;
	if (!B.running || !core_lan(B.core)) {
		b2b_lan_reply(st, 503, NULL);
		return;
	}
	if (rq) {
		snprintf(hdr, sizeof(hdr), "Unsupported: %.150s\r\n", rq);
		b2b_lan_reply(st, 420, hdr);
		return;
	}
	if (!req->body_len || !ct || strncasecmp(ct, "application/sdp", 15)) {
		b2b_lan_reply(st, 488, "Warning: 399 imsd \"an SDP offer is required\"\r\n");
		return;
	}
	if (ruri_number(req->ruri, num, sizeof(num)) < 0) {
		b2b_lan_reply(st, 404, "Warning: 399 imsd \"no number in the Request-URI\"\r\n");
		return;
	}
	if (!be) {
		b2b_lan_reply(st, 503, "Warning: 399 imsd \"no call backend is available (the line is not ready)\"\r\n");
		return;
	}
	if (!pcm && !reg_is_registered(core_reg(B.core))) {
		b2b_lan_reply(st, 503, "Warning: 399 imsd \"not registered to the network\"\r\n");
		return;
	}
	offer = malloc(sizeof(*offer));
	c = b2b_call_new(true);
	if (!offer || !c) {
		free(offer);
		b2b_lan_reply(st, 500, NULL);
		if (c)
			b2b_teardown(c, "out of memory", false);
		return;
	}
	c->ans = malloc(sizeof(*c->ans));
	c->ops = be->ops;
	c->pcm = pcm;
	snprintf(c->number, sizeof(c->number), "%s", num);
	B.cnt.out_total++;
	LOGI("call#%u: INVITE from the LAN client for %s", c->id, num);
	if (!c->ans) {
		status = 500;
		why = "out of memory";
		goto fail;
	}
	if (sdp_parse(offer, (const char *)req->body, req->body_len)) {
		status = 400;
		why = "bad SDP";
		goto fail;
	}
	c->lfd = b2b_rtp_lan(&c->lbound);
	if (c->lfd < 0) {
		status = 503;
		why = "no RTP port on the LAN side";
		c->lfd = -1;
		goto fail;
	}
	b2b_lan_cfg(!pcm, &lc);	/* the modem's PCM path is narrowband */
	b2b_new_origin(&org);
	rc = sdpn_lan_answer(&lc, offer, &org, &c->lbound, c->ans, &c->lm);
	if (rc < 0) {
		status = sdpn_sip_status(rc);
		why = sdpn_strerror(rc);
		goto fail;
	}
	c->lm_ok = true;
	c->l_rdir = sdpn_remote_dir(offer, &offer->media[c->lm.media_index], &legacy);
	memset(&d, 0, sizeof(d));
	d.target = num;
	if (!pcm) {
		c->cfd = b2b_rtp_carrier(&c->cbound);
		if (c->cfd < 0) {
			status = 503;
			why = "no RTP port on the IMS side";
			c->cfd = -1;
			goto fail;
		}
		snprintf(phone_ctx, sizeof(phone_ctx), "%s", cfg->phone_context[0] ? cfg->phone_context : core_param_domain(B.core));
		config_ims_user_agent(cfg, ua, sizeof(ua));
		gmcall_mgr_set_strings(B.gm, phone_ctx, cfg->contact_params, ua);
		gmcall_mgr_set_session_expires(B.gm, cfg->session_expires);
		core_pani_refresh(B.core);
		d.local_rtp = c->cbound;
	}
	rc = be->ops->dial(be->be, &d, b2b_cc_event, c, &c->cc);
	if (rc) {
		status = b2b_dial_status(rc, pcm);
		why = strerror(-rc);
		goto fail;
	}
	if (dlg_init_uas(&c->ldlg, txn_server_endpoint(st), req, txn_server_to_tag(st))) {
		c->ops->release(c->cc);
		c->cc = NULL;
		status = 500;
		why = "dialog";
		goto fail;
	}
	c->ldlg_ok = true;
	c->ldst = *txn_server_src(st);
	c->ist = st;
	txn_server_set_cb(st, srv_cb, c);
	b2b_lan_reply(st, 100, NULL);
	free(offer);
	b2b_notify(c, "new", 0, "");
	return;
fail:
	free(offer);
	LOGW("call#%u: INVITE refused with %d (%s)", c->id, status, why);
	snprintf(hdr, sizeof(hdr), "Warning: 399 imsd \"%.100s\"\r\n", why);
	b2b_lan_reply(st, status, hdr);
	c->end_status = status;
	b2b_teardown(c, why, false);
}

/* ---- carrier events ---- */

void b2b_out_send_200(struct b2b_call *c)
{
	if (!c->ist) {
		b2b_teardown(c, "the client's INVITE is gone", true);
		return;
	}
	c->st = CS_ANSWERING;
	send_prov(c, 200, true);
	if (txn_server_last_status(c->ist) == 200) {
		uint32_t cs = 0;

		sip_cseq(txn_server_request(c->ist), &cs, NULL, 0);
		c->rtx_cseq = cs;
		c->rtx_initial = true;
		c->rtx = txn_server_start_2xx_rtx(c->ist, 0, 0, b2b_out_rtx_giveup, c);
	}
}

void b2b_out_rtx_giveup(struct sip_rtx *r, void *arg)
{
	struct b2b_call *c = arg;

	(void)r;
	c->rtx = NULL;
	LOGW("call#%u: no ACK from the client for our 200 OK", c->id);
	b2b_teardown(c, "no ACK from the client", true);
}

void b2b_out_client_ack(struct b2b_call *c)
{
	if (c->st != CS_ANSWERING)
		return;
	c->st = CS_UP;
	c->t_up = ev_now_ms();
	B.cnt.answered++;
	b2b_notify(c, "answered", 0, "");
}

void b2b_reoffer_failed(struct b2b_call *c, const struct cc_event *ev)
{
	LOGW("call#%u: the network refused our hold/resume/media change (%d %s): the call goes on unchanged", c->id,
	     ev->status, ev->reason);
	/* the carrier leg keeps what the network last agreed to */
	if (c->cc)
		c->cdir = b2b_br_dir(c->cm_ok ? c->cm.dir : SDP_DIR_SENDRECV);
	if (c->br)
		bridge_set_dir(c->br, BR_CARRIER, c->cdir);
}

/* early media: the client gets our answer now (the 200 will carry the same one) */
static void out_early(struct b2b_call *c)
{
	if (!c->bench && c->st == CS_SETUP && !c->ans_sent && c->ist) {
		send_prov(c, 183, true);
		c->ans_sent = true;
		c->st = CS_EARLY;
		b2b_notify(c, "early-media", 0, "");
	}
}

static void out_no_bridge(struct b2b_call *c)
{
	LOGW("call#%u: the media bridge could not be started", c->id);
	c->end_status = 500;
	if (c->ist && txn_server_last_status(c->ist) < 200)
		b2b_lan_reply(c->ist, 500, "Warning: 399 imsd \"media bridge\"\r\n");
	b2b_teardown(c, "media bridge failed", true);
}

static void out_media(struct b2b_call *c, const struct cc_event *ev)
{
	if (!c->br && !ev->media->valid)
		return;
	b2b_carrier_media(c, ev->media);
	if (!c->br) {
		out_no_bridge(c);
		return;
	}
	if (ev->early)
		out_early(c);
}

/* PCM carrier: the call audio is available (alerting with early media, or the answer): open the PCM bridge */
static void out_pcm_media(struct b2b_call *c, bool early)
{
	if (!c->br && b2b_bridge_up(c)) {
		out_no_bridge(c);
		return;
	}
	if (early)
		out_early(c);
}

void b2b_out_cc_event(struct b2b_call *c, const struct cc_event *ev)
{
	char extra[320], t[100];
	int status;

	switch (ev->type) {
	case CC_EV_PROGRESS:
		break;
	case CC_EV_RINGING:
		if (!c->bench && c->st == CS_SETUP && !c->sent_180) {
			send_prov(c, 180, false);
			c->sent_180 = true;
		}
		b2b_notify(c, "ringing", 0, "");
		break;
	case CC_EV_EARLY_MEDIA:
	case CC_EV_MEDIA:
		if (ev->media_kind == CC_MEDIA_PCM)
			out_pcm_media(c, true);
		else
			out_media(c, ev);
		break;
	case CC_EV_ANSWERED:
		if (c->pcm && !c->br && b2b_bridge_up(c)) {	/* no early media: the PCM path opens with the answer */
			out_no_bridge(c);
			break;
		}
		if (c->bench) {
			c->st = CS_UP;
			c->t_up = ev_now_ms();
			B.cnt.answered++;
			if (c->br && !c->bench_play_started) {
				c->bench_play_started = true;
				c->ldir = BR_SENDRECV;
				bridge_set_dir(c->br, BR_CLIENT, BR_SENDRECV);	/* the play file starts with the answer */
			}
			b2b_notify(c, "answered", 0, "");
		} else if (!c->br) {
			c->end_status = 500;
			b2b_teardown(c, "answered without media", true);
		} else {
			b2b_out_send_200(c);
		}
		break;
	case CC_EV_REOFFER_FAILED:
		b2b_reoffer_failed(c, ev);
		break;
	case CC_EV_FAILED:
		status = map_status(ev->status);
		B.cnt.failed++;
		c->end_status = status;
		clean_text(ev->reason, t, sizeof(t));
		snprintf(extra, sizeof(extra), "Reason: SIP;cause=%d;text=\"%s\"\r\nWarning: 399 imsd \"%s\"\r\n", ev->status, t, t);
		LOGI("call#%u: the network answered %d (%s) -> %d to the client", c->id, ev->status, t, status);
		if (c->ist && txn_server_last_status(c->ist) < 200)
			b2b_lan_reply(c->ist, status, extra);
		b2b_teardown(c, t[0] ? t : "failed", false);
		break;
	case CC_EV_CANCELLED:
		c->end_status = c->end_status ? c->end_status : (c->client_cancelled ? 487 : 503);
		b2b_teardown(c, ev->reason[0] ? ev->reason : "cancelled", false);
		break;
	case CC_EV_TERMINATED:
		b2b_teardown(c, ev->reason[0] ? ev->reason : (ev->by_remote ? "hangup by the network" : "call ended"), true);
		break;
	}
}
