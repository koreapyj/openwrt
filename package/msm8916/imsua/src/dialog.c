/* SPDX-License-Identifier: GPL-2.0-only */
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include "dialog.h"
#include "util.h"

void call_init(struct call *c, uint32_t invite_cseq)
{
	memset(c, 0, sizeof(*c));
	c->answered = -1;
	c->invite_cseq = invite_cseq;
}

static int dlg_find(struct call *c, const char *tag)
{
	int i;

	for (i = 0; i < MAX_DLG; i++)
		if (c->d[i].used && !strcmp(c->d[i].tag, tag)) return i;
	for (i = 0; i < MAX_DLG; i++)
		if (!c->d[i].used) {
			memset(&c->d[i], 0, sizeof(c->d[i]));
			c->d[i].used = 1;
			strlcpy_(c->d[i].tag, tag, sizeof(c->d[i].tag));
			return i;
		}
	return -1;
}

static void dlg_fill(struct dlg *d, const struct sip_msg *m)
{
	const char *ct = sip_hdr(m, "Contact", 0);
	char l[8][256];
	int n = 0, i, k;

	if (ct) sip_uri_of(ct, d->contact, sizeof(d->contact));
	d->nrr = 0;
	for (i = 0; sip_hdr(m, "Record-Route", i); i++) {
		int j, nn = sip_split_list(sip_hdr(m, "Record-Route", i), l + n, 8 - n);
		for (j = 0; j < nn; j++) n++;
		if (n >= 8) break;
	}
	/* UAC route set = Record-Route in reverse order */
	for (k = n - 1; k >= 0 && d->nrr < MAX_RR; k--)
		strlcpy_(d->rr[d->nrr++], l[k], 256);
}

int call_on_response(struct call *c, const struct sip_msg *m, struct call_ev *ev, int maxev)
{
	int n = 0, di;
	char tag[160], meth[16];
	uint32_t cs;
	int has_sdp;

	if (!m->is_resp || sip_cseq(m, &cs, meth, sizeof(meth)) || strcasecmp(meth, "INVITE") || cs != c->invite_cseq)
		return 0;
	has_sdp = m->body_len > 0 && sip_hdr(m, "Content-Type", 0) && strcasestr(sip_hdr(m, "Content-Type", 0), "sdp");
	sip_tag(sip_hdr(m, "To", 0) ? sip_hdr(m, "To", 0) : "", tag, sizeof(tag));

	if (m->status == 100) return 0;
	if (m->status >= 300) {
		c->final_nonok = m->status;
		/* non-2xx final: ACK belongs to the transaction, not to any dialog */
		if (n < maxev) { ev[n].type = EV_ACK_NON2XX; ev[n].dlg = -1; ev[n].rseq = 0; n++; }
		return n;
	}
	if (!tag[0]) return 0;	/* a dialog needs a To tag */
	di = dlg_find(c, tag);
	if (di < 0) return 0;

	if (m->status < 200) {
		struct dlg *d = &c->d[di];
		const char *req = sip_hdr(m, "Require", 0), *rs = sip_hdr(m, "RSeq", 0);
		dlg_fill(d, m);
		if (has_sdp) d->sdp_seen = 1;
		if (req && strcasestr(req, "100rel") && rs) {
			uint32_t r = strtoul(rs, NULL, 10);
			if (r != d->last_rseq && n < maxev) {	/* retransmitted 1xx: do not PRACK twice */
				d->last_rseq = r;
				ev[n].type = EV_PRACK; ev[n].dlg = di; ev[n].rseq = r; n++;
			}
		}
	} else {
		struct dlg *d = &c->d[di];
		int dup = d->confirmed;
		dlg_fill(d, m);
		d->confirmed = 1;
		if (c->answered < 0) c->answered = di;
		if (n < maxev) { ev[n].type = dup ? EV_DUP_2XX : EV_ACK; ev[n].dlg = di; ev[n].rseq = 0; n++; }
		if (has_sdp) d->sdp_seen = 1;
	}
	/* media starts with the first SDP answer, 18x or 2xx */
	if (has_sdp && !c->rtp_started && n < maxev) {
		c->rtp_started = 1;
		ev[n].type = EV_START_RTP; ev[n].dlg = di; ev[n].rseq = 0; n++;
	}
	return n;
}

int call_bye_target(const struct call *c)
{
	return c->answered;	/* only a dialog that got the 2xx; never an early one */
}

/* ---- cap ---- */
void cap_init(struct cap *c, uint32_t user_cap_ms)
{
	memset(c, 0, sizeof(*c));
	c->cap_ms = IMSUA_CALL_HARD_CAP_MS;
	if (user_cap_ms && user_cap_ms < c->cap_ms) c->cap_ms = user_cap_ms;	/* may only be lowered */
}

enum cap_act cap_poll(struct cap *c, uint32_t t, int confirmed)
{
	int want = confirmed ? CAP_SEND_BYE : CAP_SEND_CANCEL;

	if (t >= IMSUA_CALL_ABORT_MS && !c->done)
		return CAP_FATAL;
	if (c->done) return CAP_NONE;
	if (!c->started) {
		if (t < c->cap_ms && !c->force) return CAP_NONE;
		c->started = 1; c->kind = want;
		c->interval = IMSUA_CAP_RTX_FIRST_MS;
		c->next_rtx = t + c->interval;
		return want;
	}
	if (want != c->kind) {		/* CANCEL sent, then a 2xx raced in: switch to BYE */
		c->kind = want;
		c->interval = IMSUA_CAP_RTX_FIRST_MS;
		c->next_rtx = t + c->interval;
		return want;
	}
	if (t >= c->next_rtx) {
		c->interval = c->interval * 2 > 4000 ? 4000 : c->interval * 2;
		c->next_rtx = t + c->interval;
		return CAP_RESEND;
	}
	return CAP_NONE;
}

void cap_final_seen(struct cap *c) { c->done = 1; }
