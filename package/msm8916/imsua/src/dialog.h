/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IMSUA_DIALOG_H
#define IMSUA_DIALOG_H
#include <stdint.h>
#include "sip.h"

/*
 * HARD CALL LIMIT. Compile-time only; options can only lower it.
 * A call is never allowed to reach 20 s: BYE/CANCEL goes out at 18 s after
 * the INVITE, and if that is still unanswered at 19 s the process exits.
 */
#define IMSUA_CALL_HARD_CAP_MS	18000u
#define IMSUA_CALL_ABORT_MS	19000u
#define IMSUA_CAP_RTX_FIRST_MS	500u	/* RFC 3261 T1 */

#define MAX_DLG 4
#define MAX_RR 6

struct dlg {
	int used;
	int confirmed;		/* got a 2xx on this dialog */
	char tag[160];		/* remote (To) tag */
	char contact[256];	/* remote target URI */
	char rr[MAX_RR][256];	/* route set, in the order to be used in requests */
	int nrr;
	uint32_t last_rseq;
	int sdp_seen;
};

struct call {
	struct dlg d[MAX_DLG];
	int answered;		/* index of the confirmed dialog, -1 */
	int rtp_started;
	int final_nonok;	/* final non-2xx status received (0 if none) */
	uint32_t invite_cseq;
};

enum ev_type { EV_NONE, EV_PRACK, EV_ACK, EV_START_RTP, EV_ACK_NON2XX, EV_DUP_2XX };
struct call_ev {
	enum ev_type type;
	int dlg;		/* dialog index (PRACK/ACK), -1 otherwise */
	uint32_t rseq;
};

void call_init(struct call *c, uint32_t invite_cseq);
/* Feed a response to the INVITE; events (requests to send / media to start) are returned.
 * Requests are generated ONLY for: PRACK on a dialog whose 1xx has Require: 100rel,
 * ACK on a dialog that got a 2xx. Nothing is ever generated for an early dialog without 100rel. */
int call_on_response(struct call *c, const struct sip_msg *m, struct call_ev *ev, int maxev);
/* Dialog that BYE may be sent on (the 2xx dialog); -1 if none (use CANCEL instead). */
int call_bye_target(const struct call *c);

/* ---- hard cap state machine ---- */
enum cap_act { CAP_NONE, CAP_SEND_BYE, CAP_SEND_CANCEL, CAP_RESEND, CAP_FATAL };
struct cap {
	uint32_t cap_ms;	/* effective cap, <= IMSUA_CALL_HARD_CAP_MS */
	int started;		/* BYE/CANCEL first sent */
	int kind;		/* CAP_SEND_BYE / CAP_SEND_CANCEL */
	uint32_t next_rtx;	/* relative ms */
	uint32_t interval;
	int done;		/* final response to BYE/CANCEL seen */
	int force;		/* shutdown requested: act immediately */
};
void cap_init(struct cap *c, uint32_t user_cap_ms);	/* 0 = use the hard cap */
/* t = ms since INVITE was sent. Returns the action to take now. confirmed = a 2xx dialog exists */
enum cap_act cap_poll(struct cap *c, uint32_t t, int confirmed);
void cap_final_seen(struct cap *c);
#endif
