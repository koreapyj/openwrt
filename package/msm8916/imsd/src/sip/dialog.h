/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SIP_DIALOG_H
#define IMSD_SIP_DIALOG_H
#include <stdbool.h>
#include <stdint.h>
#include "msg.h"
#include "transport.h"

/*
 * Minimal dialog bookkeeping (RFC 3261 section 12). No session/SDP logic and
 * no timers. A dialog is pinned to the endpoint it started on (it holds a
 * reference on it until dlg_release).
 *
 * UAC side: a struct dlgset tracks all dialogs an INVITE creates (forking:
 * a 183 and the 200 may carry different To tags; requests go only to the
 * dialog they belong to) and tells the caller what to send in reaction to
 * each response (PRACK for 100rel, ACK for a 2xx). Nothing is ever generated
 * for an early dialog without 100rel, and BYE only goes to the dialog that
 * got the 2xx (dlgset_bye_target). The ACK for a non-2xx final response is
 * the transaction layer's job (txn.c).
 * UAS side: dlg_init_uas() builds one dialog from an incoming INVITE.
 */

#define DLG_MAX_ROUTES	8
#define DLG_MAX_DIALOGS	8	/* per dlgset */

enum dlg_state { DLG_EARLY, DLG_CONFIRMED, DLG_TERMINATED };

struct sip_dialog {
	bool used;
	bool is_uac;
	enum dlg_state state;
	char call_id[128];
	char local_tag[64];
	char remote_tag[160];
	char local_uri[256];	/* From URI (UAC) / To URI (UAS) */
	char remote_uri[256];
	char remote_target[256];	/* from Contact */
	char route[DLG_MAX_ROUTES][256];	/* route set in the order requests use it (each "<uri;lr>" as received) */
	int nroute;
	uint32_t local_cseq;	/* last CSeq we used */
	uint32_t remote_cseq;
	bool has_remote_cseq;
	uint32_t last_rseq;	/* UAC: last RSeq we PRACKed (0 = none) */
	bool sdp_seen;
	struct sip_endpoint *ep;	/* referenced */
};

/* ---- UAC: all dialogs of one INVITE ---- */
struct dlgset {
	struct sip_dialog d[DLG_MAX_DIALOGS];
	int answered;		/* index of the dialog that got a 2xx, -1 */
	int final_status;	/* final non-2xx status of the INVITE, 0 if none */
	uint32_t invite_cseq;
	char call_id[128];
	char local_tag[64];
	char local_uri[256];
	char remote_uri[256];
	struct sip_endpoint *ep;	/* referenced by the set */
};

enum dlg_ev_type {
	DLG_EV_PRACK,		/* send PRACK on dlg with RAck rseq / invite cseq */
	DLG_EV_ACK,		/* first 2xx on dlg: send ACK (CSeq = invite cseq) */
	DLG_EV_DUP_2XX,		/* retransmitted 2xx on dlg: send the ACK again */
	DLG_EV_SDP,		/* this response carried an SDP body (dlg says on which dialog) */
};
struct dlg_ev {
	enum dlg_ev_type type;
	int dlg;
	uint32_t rseq;
};

/* Prepare for an INVITE with the given identifiers (strings copied, ep referenced). 0 / -1. */
int dlgset_init(struct dlgset *s, struct sip_endpoint *ep, const char *call_id, const char *local_tag,
		const char *local_uri, const char *remote_uri, uint32_t invite_cseq);
/* drop all endpoint references; the set is unusable afterwards */
void dlgset_release(struct dlgset *s);
/*
 * Feed a response to the INVITE (provisional or final, also repeated ones).
 * Fills up to max events, returns their count (0 for responses of other
 * transactions or without a To tag).
 */
int dlgset_on_response(struct dlgset *s, const struct sip_msg *resp, struct dlg_ev *ev, int max);
/* the dialog BYE may go to (the one with the 2xx); NULL means use CANCEL / nothing */
struct sip_dialog *dlgset_bye_target(struct dlgset *s);
/* dialog index matching a To tag, -1 */
int dlgset_find(const struct dlgset *s, const char *remote_tag);

/* ---- UAS ---- */
/* Create a dialog from an incoming dialog-creating request (INVITE). local_tag is the To tag we answer with. Takes an endpoint reference. 0 / -1. */
int dlg_init_uas(struct sip_dialog *d, struct sip_endpoint *ep, const struct sip_msg *req, const char *local_tag);
void dlg_release(struct sip_dialog *d);
void dlg_confirm(struct sip_dialog *d);

/* ---- common ---- */
/* next local CSeq (increments) */
uint32_t dlg_next_cseq(struct sip_dialog *d);
/* does an incoming in-dialog request belong to d? (Call-ID, From tag == remote tag, To tag == local tag) */
bool dlg_match_request(const struct sip_dialog *d, const struct sip_msg *req);
/* does a response to one of our in-dialog requests belong to d? */
bool dlg_match_response(const struct sip_dialog *d, const struct sip_msg *resp);
/* Accept the CSeq of an incoming in-dialog request: 0 and remembered, -1 if it is not higher than the last one (reply 500). ACK and CANCEL are never checked. */
int dlg_check_remote_cseq(struct sip_dialog *d, const struct sip_msg *req);
/* refresh the remote target from the Contact of a request or 2xx (target refresh). 0 / -1 */
int dlg_refresh_target(struct sip_dialog *d, const struct sip_msg *m);
/* Request-URI and Route header lines for a request in this dialog (RFC 3261 12.2.1.1: loose routing, or strict routing when the first route has no ;lr). route_hdrs gets "Route: <..>\r\n" lines (possibly none). 0 / -1 */
int dlg_route(const struct sip_dialog *d, char *ruri, size_t ruri_sz, struct buf *route_hdrs);

struct dlg_req_opts {
	const char *method;
	uint32_t cseq;		/* 0: allocate the next one; ACK/CANCEL pass the INVITE's CSeq */
	const char *via;	/* complete Via value for this request (see sip_via_make) */
	const char *contact;	/* optional */
	const char *extra;	/* optional extra header lines (CRLF terminated each) */
	const char *content_type;
	const uint8_t *body;
	size_t body_len;
};
/* Compose an in-dialog request into out (From/To/Call-ID/CSeq/Route from the dialog). The CSeq used is stored in *cseq_used if given. 0 / -1 */
int dlg_build_request(struct sip_dialog *d, struct buf *out, const struct dlg_req_opts *o, uint32_t *cseq_used);
#endif
