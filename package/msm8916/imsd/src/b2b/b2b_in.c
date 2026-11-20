/* SPDX-License-Identifier: GPL-2.0-or-later */
/* network -> LAN: an incoming carrier call is forked to every registered LAN device; the first to answer wins. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "b2b_int.h"

#define ALLOW "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, UPDATE, INFO\r\n"

void b2b_in_end(struct b2b_call *c)
{
	if (c->fork)
		lan_fork_cancel(c->fork);	/* later 2xx arrive as EXTRA_2XX (ACK + BYE); DONE ends the wait */
}

static void ring_fire(void *arg)
{
	struct b2b_call *c = arg;

	if (c->st != CS_SETUP || !c->cc)
		return;
	LOGI("call#%u: nobody answered within %u s", c->id, b2b_cfg()->ring_timeout_s);
	B.cnt.missed++;
	c->end_status = 480;
	b2b_cc_reject_release(c, 480);
	b2b_teardown(c, "ring timeout", false);
}

static void in_winner(struct b2b_call *c, struct lan_fork_event *ev)
{
	struct sdp *ans = NULL;
	const char *ct = ev->resp ? sip_hdr(ev->resp, "Content-Type", 0) : NULL;
	int rc, status = 480;
	const char *why = "";

	if (c->st == CS_ENDED || !c->cc || !c->offer) {
		b2b_lan_ack_bye(ev->dlg, ev->src, ev->invite_cseq);
		return;
	}
	ans = malloc(sizeof(*ans));
	if (!ans) {
		why = "out of memory";
		goto fail;
	}
	if (!ct || strncasecmp(ct, "application/sdp", 15) || !ev->resp->body_len ||
	    sdp_parse(ans, (const char *)ev->resp->body, ev->resp->body_len)) {
		why = "the device answered without a usable SDP";
		goto fail;
	}
	rc = sdpn_from_answer(c->offer, ans, &c->lm);
	if (rc < 0) {
		why = sdpn_strerror(rc);
		goto fail;
	}
	c->lm_ok = true;
	c->l_rdir = sdpn_remote_dir(ans, &ans->media[c->lm.media_index], NULL);
	if (c->pcm) {
		rc = c->ops->answer(c->cc, NULL);	/* the PCM bridge is started below */
		if (rc) {
			why = strerror(-rc);
			goto fail;
		}
	} else {
		c->cfd = b2b_rtp_carrier(&c->cbound);
		if (c->cfd < 0) {
			c->cfd = -1;
			status = 503;
			why = "no RTP port on the IMS side";
			goto fail;
		}
		rc = c->ops->answer(c->cc, &c->cbound);
		if (rc) {
			why = strerror(-rc);
			goto fail;
		}
		if (!c->ops->get_media(c->cc, &c->cm)) {
			why = "no carrier media";
			goto fail;
		}
		c->cm_ok = true;
	}
	/* the dialog is ours from here on */
	c->ldlg = *ev->dlg;
	c->ldlg_ok = true;
	ev->take_dlg = true;
	c->ldst = *ev->src;
	b2b_lan_send_ack(c, ev->invite_cseq);
	c->ans = c->offer;		/* what we last sent to the device */
	c->offer = NULL;
	c->st = CS_UP;
	c->t_up = ev_now_ms();
	b2b_timer_cancel(c->t_ring);
	B.cnt.answered++;
	free(ans);
	if (b2b_bridge_up(c)) {
		c->end_status = 500;
		b2b_teardown(c, "media bridge failed", true);
		return;
	}
	LOGI("call#%u: answered by the LAN device (binding %u)", c->id, ev->id);
	b2b_notify(c, "answered", 0, "");
	return;
fail:
	free(ans);
	LOGW("call#%u: the winning device cannot be used: %s", c->id, why);
	b2b_lan_ack_bye(ev->dlg, ev->src, ev->invite_cseq);
	c->end_status = status;
	b2b_cc_reject_release(c, status);
	b2b_teardown(c, why, false);
}

static void in_all_failed(struct b2b_call *c, const struct lan_fork_event *ev)
{
	int i, st = 480;
	bool all_busy = ev->nresults > 0;

	if (c->st == CS_ENDED)
		return;
	for (i = 0; i < ev->nresults; i++)
		if (ev->results[i].status != 486)
			all_busy = false;
	if (all_busy)
		st = 486;
	LOGI("call#%u: no LAN device took the call (%d)", c->id, st);
	B.cnt.failed++;
	c->end_status = st;
	b2b_cc_reject_release(c, st);
	b2b_teardown(c, st == 486 ? "all devices busy" : "no device answered", false);
}

static void fork_cb(struct lan_fork *f, struct lan_fork_event *ev, void *arg)
{
	struct b2b_call *c = arg;

	(void)f;
	switch (ev->type) {
	case LAN_FORK_PROVISIONAL:
		LOGD("call#%u: device %u: %d", c->id, ev->id, ev->status);
		break;
	case LAN_FORK_BRANCH_FINAL:
		c->n_branch_final++;
		if (ev->status == 486)
			c->n_branch_busy++;
		break;
	case LAN_FORK_WINNER:
		in_winner(c, ev);
		break;
	case LAN_FORK_EXTRA_2XX:
		LOGI("call#%u: a second device answered (binding %u): ACK + BYE", c->id, ev->id);
		b2b_lan_ack_bye(ev->dlg, ev->src, ev->invite_cseq);
		break;
	case LAN_FORK_2XX_RETRANS:
		if (ev->is_winner && c->ldlg_ok)
			b2b_lan_send_ack(c, ev->invite_cseq);
		break;
	case LAN_FORK_COMPLETE:
		if (ev->status != 200)
			in_all_failed(c, ev);
		break;
	case LAN_FORK_DONE:
		c->fork = NULL;
		b2b_try_free(c);
		break;
	}
}

int b2b_in_incoming(struct carrier_call *cc, const struct cc_incoming *in, void *arg)
{
	const struct carrier_call_ops *ops = arg;
	const struct imsd_config *cfg = b2b_cfg();
	struct lan *l = core_lan(B.core);
	unsigned nb = l ? reg_count(lan_registrar(l)) : 0;
	struct b2b_call *c;
	struct sdpn_lan_cfg lc;
	struct sdp_origin org;
	struct lan_req rq;
	struct buf body;
	const char *num, *why = "";
	int status = 480;

	if (!B.running)
		return -1;
	if (nb == 0 && !cfg->bench_incoming) {
		LOGI("incoming call from %s: no LAN device is registered, 480", in->caller.number);
		B.cnt.no_device++;
		return -1;
	}
	c = b2b_call_new(false);
	if (!c)
		return -1;
	c->ops = ops;
	c->pcm = ops->media_kind == CC_MEDIA_PCM;
	snprintf(c->number, sizeof(c->number), "%s", in->caller.anonymous ? "anonymous" : in->caller.number);
	c->wideband = !c->pcm && in->offered && in->offered->codec == SDPN_C_AMRWB;
	B.cnt.in_total++;
	LOGI("call#%u: incoming call from %s", c->id, c->number[0] ? c->number : "unknown");
	if (nb == 0) {
		c->bench = true;	/* answered over ubus (bench_incoming) */
		c->cc = cc;
		ops->set_handler(cc, b2b_cc_event, c);
		b2b_notify(c, "new", 0, "");
		return 0;
	}
	c->lfd = b2b_rtp_lan(&c->lbound);
	if (c->lfd < 0) {
		c->lfd = -1;
		why = "no RTP port on the LAN side";
		status = 503;
		goto fail;
	}
	c->offer = malloc(sizeof(*c->offer));
	if (!c->offer) {
		why = "out of memory";
		goto fail;
	}
	b2b_lan_cfg(c->wideband, &lc);
	b2b_new_origin(&org);
	if (sdpn_lan_offer(&lc, &org, &c->lbound, c->offer) < 0) {
		why = "cannot build the offer";
		goto fail;
	}
	buf_init(&body, 0);
	if (sdp_write(c->offer, &body)) {
		buf_free(&body);
		why = "cannot write the offer";
		goto fail;
	}
	memset(&rq, 0, sizeof(rq));
	rq.method = "INVITE";
	num = c->number[0] && !in->caller.anonymous ? c->number : "unknown";
	rq.from_user = num;
	if (in->caller.anonymous) {
		rq.from_display = "Anonymous";
		rq.from_uri = "sip:anonymous@anonymous.invalid";
	} else {
		rq.from_display = in->caller.display[0] ? in->caller.display : NULL;
	}
	rq.extra = ALLOW;
	rq.content_type = "application/sdp";
	rq.body = body.p;
	rq.body_len = body.len;
	c->fork = lan_fork_request(l, &rq, NULL, fork_cb, c, NULL);
	buf_free(&body);
	if (!c->fork) {
		why = errno == ENOENT ? "no LAN device can be called" : "cannot start the fork";
		if (errno == ENOENT)
			B.cnt.no_device++;
		else
			status = 503;
		goto fail;
	}
	if (cfg->ring_timeout_s) {
		c->t_ring = ev_timer_new(ring_fire, c);
		if (c->t_ring)
			ev_timer_set(c->t_ring, (uint64_t)cfg->ring_timeout_s * 1000);
	}
	c->cc = cc;
	ops->set_handler(cc, b2b_cc_event, c);
	b2b_notify(c, "new", 0, "");
	return 0;
fail:
	LOGW("call#%u: incoming call refused: %s", c->id, why);
	ops->reject(cc, status);
	c->end_status = status;
	b2b_teardown(c, why, false);
	return -1;
}

void b2b_in_cc_event(struct b2b_call *c, const struct cc_event *ev)
{
	switch (ev->type) {
	case CC_EV_MEDIA:
	case CC_EV_EARLY_MEDIA:
		if (c->cm_ok && !c->pcm && ev->media_kind == CC_MEDIA_RTP)
			b2b_carrier_media(c, ev->media);
		break;
	case CC_EV_REOFFER_FAILED:
		b2b_reoffer_failed(c, ev);
		break;
	case CC_EV_CANCELLED:
		if (ev->by_remote) {
			B.cnt.missed++;
			LOGI("call#%u: the caller hung up before an answer", c->id);
		}
		b2b_teardown(c, ev->reason[0] ? ev->reason : "cancelled", false);
		break;
	case CC_EV_TERMINATED:
		b2b_teardown(c, ev->reason[0] ? ev->reason : (ev->by_remote ? "hangup by the network" : "call ended"), true);
		break;
	default:
		break;
	}
}
