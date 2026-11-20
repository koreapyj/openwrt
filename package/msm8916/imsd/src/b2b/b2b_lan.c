/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The LAN dialog of a call: ACK / BYE generation (we own both for every dialog), the in-dialog requests of the
 * client (BYE, re-INVITE / UPDATE for hold, resume, refresh and media changes, INFO DTMF) and the ACK hook.
 */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "b2b_int.h"

#define ALLOW "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, UPDATE, INFO\r\n"

void b2b_lan_reply(struct txn_server *st, int status, const char *extra)
{
	struct sip_resp_parts p;
	char hdr[512];

	memset(&p, 0, sizeof(p));
	p.status = status;
	snprintf(hdr, sizeof(hdr), "Server: %s\r\n%s", b2b_user_agent(), extra ? extra : "");
	p.extra = hdr;
	txn_server_reply(st, &p);
}

static void lan_contact(char *out, size_t n)
{
	struct lan *l = core_lan(B.core);
	char h[80];

	out[0] = 0;
	if (!l)
		return;
	addr_uri_host(&lan_endpoint(l)->advertised, h, sizeof(h));
	snprintf(out, n, "<sip:imsd@%s:%u>", h, addr_port(&lan_endpoint(l)->advertised));
}

/* ---- requests we send inside a LAN dialog ---- */

static void bye_cb(struct txn_client *t, enum txn_cli_event ev, const struct sip_msg *resp, struct sip_endpoint *rx,
		   const struct addr *src, void *arg)
{
	(void)t; (void)ev; (void)resp; (void)rx; (void)src; (void)arg;	/* nothing to do: the call is gone either way */
}

static int build(struct sip_dialog *d, const char *method, uint32_t cseq, struct buf *out, char *branch)
{
	char via[160], extra[160];
	struct dlg_req_opts o;

	if (!d->ep)
		return -1;
	sip_new_branch(branch);
	sip_via_make(via, sizeof(via), "UDP", &d->ep->advertised, branch, false);
	snprintf(extra, sizeof(extra), "User-Agent: %s\r\n", b2b_user_agent());
	memset(&o, 0, sizeof(o));
	o.method = method;
	o.cseq = cseq;
	o.via = via;
	o.extra = extra;
	buf_init(out, SIP_MAX_MSG);
	return dlg_build_request(d, out, &o, NULL);
}

static void send_ack(struct sip_dialog *d, const struct addr *dst, uint32_t invite_cseq)
{
	struct buf b;
	char br[SIP_BRANCH_LEN];

	if (!build(d, "ACK", invite_cseq, &b, br))
		sip_ep_send(d->ep, dst, b.p, b.len);
	buf_free(&b);
}

static void send_bye(struct sip_dialog *d, const struct addr *dst)
{
	struct buf b;
	char br[SIP_BRANCH_LEN];
	struct txn_client_req r;

	if (!core_txn(B.core) || build(d, "BYE", 0, &b, br)) {
		buf_free(&b);
		return;
	}
	memset(&r, 0, sizeof(r));
	r.ep = d->ep;
	r.dst = *dst;
	r.data = b.p;
	r.len = b.len;
	r.cb = bye_cb;
	if (!txn_client_start(core_txn(B.core), &r))
		LOGW("lan: BYE could not be started");
	buf_free(&b);
}

void b2b_lan_send_ack(struct b2b_call *c, uint32_t invite_cseq)
{
	if (c->ldlg_ok)
		send_ack(&c->ldlg, &c->ldst, invite_cseq);
}

void b2b_lan_send_bye(struct b2b_call *c)
{
	if (c->ldlg_ok)
		send_bye(&c->ldlg, &c->ldst);
}

void b2b_lan_ack_bye(struct sip_dialog *d, const struct addr *dst, uint32_t invite_cseq)
{
	send_ack(d, dst, invite_cseq);
	send_bye(d, dst);
}

void b2b_lan_dlg_drop(struct b2b_call *c)
{
	if (c->ldlg_ok) {
		dlg_release(&c->ldlg);
		c->ldlg_ok = false;
	}
}

/* ---- the in-dialog requests of the client ---- */

static struct b2b_call *find_by_dialog(const struct sip_msg *req)
{
	struct b2b_call *c;

	for (c = B.calls; c; c = c->next)
		if (c->st != CS_ENDED && c->ldlg_ok && dlg_match_request(&c->ldlg, req))
			return c;
	return NULL;
}

void b2b_lan_on_ack(struct lan *l, const struct lan_peer *p, const struct sip_msg *req, void *arg)
{
	struct b2b_call *c = find_by_dialog(req);
	uint32_t cs = 0;

	(void)l; (void)p; (void)arg;
	if (!c) {
		LOGD("lan: ACK of no call");
		return;
	}
	sip_cseq(req, &cs, NULL, 0);
	if (c->rtx && cs == c->rtx_cseq) {
		bool initial = c->rtx_initial;

		sip_rtx_stop(c->rtx);
		c->rtx = NULL;
		if (initial)
			b2b_out_client_ack(c);
	}
}

/* "Signal=5\r\nDuration=160" (application/dtmf-relay) or a bare digit (application/dtmf) */
static bool info_dtmf(const struct sip_msg *req, char *digit, unsigned *ms)
{
	const char *ct = sip_hdr(req, "Content-Type", 0);
	const char *b = (const char *)req->body, *s;

	*ms = 160;
	if (!ct || !req->body_len || !b)
		return false;
	if (!strncasecmp(ct, "application/dtmf-relay", 22)) {
		s = strcasestr(b, "Signal");
		if (!s || !(s = strchr(s, '=')))
			return false;
		while (*++s == ' ')
			;
		*digit = *s;
		if ((s = strcasestr(b, "Duration")) && (s = strchr(s, '=')))
			*ms = (unsigned)atoi(s + 1);
	} else if (!strncasecmp(ct, "application/dtmf", 16)) {
		while (*b == ' ' || *b == '\r' || *b == '\n')
			b++;
		*digit = *b;
	} else {
		return false;
	}
	if (*digit == 'a' || *digit == 'b' || *digit == 'c' || *digit == 'd')
		*digit = (char)toupper((unsigned char)*digit);
	return (*digit >= '0' && *digit <= '9') || *digit == '*' || *digit == '#' || (*digit >= 'A' && *digit <= 'D');
}

static void lan_info(struct b2b_call *c, struct txn_server *st, const struct sip_msg *req)
{
	char d = 0;
	unsigned ms;

	if (!info_dtmf(req, &d, &ms)) {
		LOGD("call#%u: INFO ignored (only application/dtmf-relay and application/dtmf with a digit are used)", c->id);
	} else if (c->pcm && c->cc) {
		int rc = c->ops->send_dtmf(c->cc, d);	/* circuit switched: digits go with the call control */

		if (rc)
			LOGW("call#%u: DTMF %c (SIP INFO) not sent: %s", c->id, d, strerror(-rc));
		else
			LOGD("call#%u: DTMF %c (SIP INFO) sent with the call control", c->id, d);
	} else if (c->br) {
		if (bridge_send_dtmf(c->br, BR_CARRIER, d, ms))
			LOGW("call#%u: DTMF %c could not be queued", c->id, d);
		else
			LOGD("call#%u: DTMF %c (SIP INFO) sent as RFC 4733 events", c->id, d);
	} else {
		LOGD("call#%u: INFO ignored (only application/dtmf-relay and application/dtmf with a digit are used)", c->id);
	}
	b2b_lan_reply(st, 200, NULL);
}

static void lan_reinvite(struct b2b_call *c, struct txn_server *st, const struct sip_msg *req)
{
	bool is_inv = sip_is_method(req, "INVITE");
	const char *ct = sip_hdr(req, "Content-Type", 0);
	bool has_sdp = req->body_len && ct && !strncasecmp(ct, "application/sdp", 15);
	struct sdp *offer = NULL, *ans = NULL;
	struct sdpn_media lm;
	struct sdpn_lan_cfg lc;
	struct sdp_origin org;
	struct sip_resp_parts p;
	struct buf body, ex;
	char contact[128], hdr[256];
	uint32_t cs = 0;
	int rc;

	if (c->st != CS_UP || !c->ans) {
		b2b_lan_reply(st, 491, NULL);
		return;
	}
	if (is_inv && c->rtx) {
		b2b_lan_reply(st, 491, NULL);
		return;
	}
	if (dlg_check_remote_cseq(&c->ldlg, req)) {
		b2b_lan_reply(st, 500, NULL);
		return;
	}
	dlg_refresh_target(&c->ldlg, req);
	c->ldst = *txn_server_src(st);
	if (req->body_len && !has_sdp) {
		b2b_lan_reply(st, 415, "Accept: application/sdp\r\n");
		return;
	}
	if (has_sdp) {
		offer = malloc(sizeof(*offer));
		ans = malloc(sizeof(*ans));
		if (!offer || !ans) {
			free(offer);
			free(ans);
			b2b_lan_reply(st, 500, NULL);
			return;
		}
		rc = sdp_parse(offer, (const char *)req->body, req->body_len);
		if (rc) {
			b2b_lan_reply(st, 400, "Warning: 399 imsd \"bad SDP\"\r\n");
			goto out;
		}
		b2b_lan_cfg(c->pcm ? false : c->cm_ok ? c->cm.codec == SDPN_C_AMRWB : true, &lc);
		org = c->ans->o;
		rc = sdpn_lan_answer(&lc, offer, &org, &c->lbound, ans, &lm);
		if (rc < 0) {
			snprintf(hdr, sizeof(hdr), "Warning: 399 imsd \"%s\"\r\n", sdpn_strerror(rc));
			b2b_lan_reply(st, sdpn_sip_status(rc), hdr);
			goto out;
		}
		sdp_origin_succeed(ans, c->ans);
		{
			bool legacy = false;
			enum sdp_dir rd = sdpn_remote_dir(offer, &offer->media[lm.media_index], &legacy);

			b2b_client_media(c, &lm);
			if (rd != c->l_rdir) {
				c->l_rdir = rd;
				if (c->cc && c->pcm && !c->bench) {
					/* circuit switched: no hold towards the network; the LAN leg goes inactive and the modem gets silence */
					bool hold = rd == SDP_DIR_SENDONLY || rd == SDP_DIR_INACTIVE;

					c->ops->set_hold(c->cc, hold);
					c->cdir = hold ? BR_RECVONLY : BR_SENDRECV;
					if (c->br) {
						bridge_set_dir(c->br, BR_CARRIER, c->cdir);
						if (hold)
							bridge_set_dir(c->br, BR_CLIENT, BR_INACTIVE);
					}
				} else if (c->cc && b2b_is_gm(c) && !c->bench) {
					enum sdp_dir fd = sdpn_forward_dir(rd);

					/* hold / resume of the client is mirrored to the network */
					if (gmcall_set_direction(carrier_gm_call(c->cc), fd))
						LOGW("call#%u: the network could not be told about the direction change", c->id);
					c->cdir = b2b_br_dir(fd);
					if (c->br)
						bridge_set_dir(c->br, BR_CARRIER, c->cdir);
				}
			}
		}
		*c->ans = *ans;
	}
	memset(&p, 0, sizeof(p));
	lan_contact(contact, sizeof(contact));
	buf_init(&body, 0);
	buf_init(&ex, 256);
	buf_printf(&ex, "Server: %s\r\n" ALLOW, b2b_user_agent());
	p.status = 200;
	p.contact = contact[0] ? contact : NULL;
	p.extra = buf_cstr(&ex);
	if (has_sdp || is_inv) {	/* a re-INVITE without a body is a session refresh: our SDP goes in the 200 */
		sdp_write(c->ans, &body);
		p.content_type = "application/sdp";
		p.body = body.p;
		p.body_len = body.len;
	}
	rc = txn_server_reply(st, &p);
	if (!rc && is_inv) {
		sip_cseq(req, &cs, NULL, 0);
		c->rtx_cseq = cs;
		c->rtx_initial = false;
		c->rtx = txn_server_start_2xx_rtx(st, 0, 0, b2b_out_rtx_giveup, c);
	}
	buf_free(&body);
	buf_free(&ex);
out:
	free(offer);
	free(ans);
}

void b2b_lan_on_in_dialog(struct lan *l, const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req, void *arg)
{
	struct b2b_call *c = find_by_dialog(req);

	(void)l; (void)p; (void)arg;
	if (!c) {
		if (st)
			b2b_lan_reply(st, 481, NULL);
		return;
	}
	if (!st)
		return;
	if (sip_is_method(req, "BYE")) {
		b2b_lan_reply(st, 200, NULL);
		b2b_teardown(c, "hangup by the client", false);
	} else if (sip_is_method(req, "INVITE") || sip_is_method(req, "UPDATE")) {
		lan_reinvite(c, st, req);
	} else if (sip_is_method(req, "INFO")) {
		lan_info(c, st, req);
	} else if (sip_is_method(req, "OPTIONS")) {
		b2b_lan_reply(st, 200, ALLOW);
	} else if (sip_is_method(req, "NOTIFY") || sip_is_method(req, "PRACK") || sip_is_method(req, "MESSAGE")) {
		b2b_lan_reply(st, 200, NULL);
	} else if (sip_is_method(req, "REFER")) {
		LOGI("call#%u: REFER (transfer) is not supported", c->id);
		b2b_lan_reply(st, 501, "Warning: 399 imsd \"transfer is not supported\"\r\n");
	} else {
		b2b_lan_reply(st, 501, NULL);
	}
}

void b2b_lan_on_invite(struct lan *l, const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req, void *arg)
{
	(void)l; (void)arg;
	b2b_out_invite(p, st, req);
}
