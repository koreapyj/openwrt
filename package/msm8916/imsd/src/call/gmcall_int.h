/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CALL_GMCALL_INT_H
#define IMSD_CALL_GMCALL_INT_H
/* internals shared by gmcall*.c; not part of the API */
#include "gmcall.h"
#include "../sip/dialog.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define GMCALL_ALLOW "INVITE,BYE,CANCEL,ACK,NOTIFY,UPDATE,PRACK,INFO,MESSAGE,OPTIONS"
#define GMCALL_ICSI "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
#define GMCALL_DEF_CONTACT_PARAMS ";+g.3gpp.icsi-ref=\"" GMCALL_ICSI "\""
#define GMCALL_SV_MAX 384
#define GMCALL_CANCEL_GUARD_MS 32000u	/* 64 * T1: no final response to a CANCELled INVITE */

enum creq_kind { CK_INVITE, CK_CANCEL, CK_PRACK, CK_BYE, CK_REFRESH, CK_REINVITE };

/* one client transaction of the TU; may outlive its call (call == NULL then) */
struct creq {
	struct creq *next;
	struct gmcall_mgr *mgr;
	struct gmcall *call;
	struct txn_client *c;
	enum creq_kind kind;
	uint32_t cseq;
	struct sdp *offer;	/* CK_REINVITE: what we sent */
	bool via_invite;	/* CK_REFRESH sent as re-INVITE (peer lacks UPDATE) */
	bool retried;		/* 422 retry already done for this exchange */
	int dlg;		/* CK_PRACK: early dialog */
};

enum misc_kind { MISC_NONE, MISC_RING, MISC_CANCEL_GUARD, MISC_GLARE, MISC_REFRESH_RETRY };

/* last known registration data (used when the registration is gone) */
struct gm_snap {
	bool valid;
	char sv[GMCALL_SV_MAX];
	char pani[160];
	struct addr pcscf;
};

struct gmcall {
	struct gmcall_mgr *mgr;
	struct gmcall *next;
	unsigned id;
	enum gmcall_dir dir;
	enum gmcall_state state;
	gmcall_event_cb cb;
	void *cb_arg;
	bool finished;		/* terminal event delivered / scheduled */
	struct gmcall_event defer_ev;	/* terminal event waiting for the deferred timer */
	struct ev_timer *t_defer;

	struct gmcall_identity remote;
	char called[48];
	char call_id[128];
	uint64_t t_start, t_connect;

	/* dialogs */
	struct dlgset *ds;	/* MO: all dialogs of the INVITE */
	struct sip_dialog udlg;	/* MT: the UAS dialog */
	bool udlg_used;
	uint32_t cseq;		/* MO: call wide CSeq counter (last used) */
	struct creq *inv;	/* MO: the INVITE client transaction */
	struct txn_server *inv_st;	/* MT: the INVITE server transaction (NULL once terminated) */
	struct sip_rtx *rtx200;	/* MT: retransmission of the initial 200 */
	bool ringing_sent;
	bool timeout_cancel;	/* MO: our ring timeout fired, CANCEL sent for that reason */
	bool retried_422;
	unsigned se_req;	/* MO: Session-Expires asked for (raised after a 422) */
	unsigned min_se_hdr;	/* MO: Min-SE to send (0 = none) */
	char target[256];	/* MO: dialled Request-URI */
	char extra_hdrs[512];	/* MO: caller supplied headers kept for a 422 retry */

	/* SDP */
	struct sdp local;	/* the last SDP we sent (offer for MO, answer for MT) */
	bool has_local;
	struct sdp *offer;	/* MT: the network's offer until answered */
	struct addr local_rtp;
	struct sdpn_media media;	/* last remote media reported */
	bool has_media;
	enum sdp_dir want_dir;
	struct addr want_rtp;
	bool has_want_rtp;
	bool reoffer_wanted;
	char last_prog_tag[64];
	int last_prog_status;
	bool last_prog_sdp;
	bool ringback_given;

	/* registration snapshot */
	struct gm_snap snap;

	/* session timer (RFC 4028) */
	unsigned se_interval;	/* 0: none */
	bool se_local_refresher;
	struct ev_timer *t_sess;
	uint64_t sess_at;	/* when t_sess fires */
	bool peer_update;	/* peer's Allow lists UPDATE */
	unsigned refresh_fails;
	struct ev_timer *t_misc;
	enum misc_kind misc;

	/* in-dialog exchanges */
	struct creq *reinv;		/* our re-INVITE / refresh in flight */
	struct sip_rtx *rtx_reinv;	/* 200 of a remote re-INVITE until its ACK */
	uint32_t reinv_cseq;
	struct sdp *late_offer;		/* our offer in the 200 of a late-offer re-INVITE: awaiting the answer in the ACK */
	unsigned glare_tries;
	bool refresh_due;		/* a session refresh is waiting for the glare timer */
	int audio_idx;			/* index of the audio section in our SDP */
};

struct gmcall_mgr {
	struct gmcall_cfg cfg;
	char phone_context[64];
	char contact_params[256];
	char user_agent[96];
	struct gmcall *calls;
	struct gmcall *dead;	/* ended, memory reclaimed by the reaper */
	struct creq *reqs;
	struct ev_timer *t_reap;
	unsigned next_id;
	unsigned ncalls;
};

/* ---- gmcall.c ---- */
const char *gm_user_agent(void);
/* txn_server_reply with our User-Agent added */
int gm_reply(struct txn_server *st, const struct sip_resp_parts *p);
struct gmcall *gm_call_new(struct gmcall_mgr *m, enum gmcall_dir dir);
const struct reg_ctx *gm_ctx(const struct gmcall_mgr *m);
void gm_snapshot(struct gmcall *c, const struct reg_ctx *x);
/* non-terminal event */
void gm_emit(struct gmcall *c, const struct gmcall_event *ev);
/* terminal event now / on the next loop iteration */
void gm_finish(struct gmcall *c, const struct gmcall_event *ev);
void gm_finish_deferred(struct gmcall *c, const struct gmcall_event *ev);
void gm_ev_text(struct gmcall_event *ev, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
bool gm_live(const struct gmcall *c);
struct sip_dialog *gm_main_dlg(struct gmcall *c);
void gm_misc_arm(struct gmcall *c, enum misc_kind k, uint64_t ms);
void gm_misc_cancel(struct gmcall *c);
bool gm_media_equal(const struct sdpn_media *a, const struct sdpn_media *b);
void gm_report_media(struct gmcall *c, const struct sdpn_media *neg, bool early, bool force);
bool gm_has_sdp(const struct sip_msg *m);
void gm_origin_new(struct sdp_origin *o);

/* creq plumbing */
struct creq *gm_creq_new(struct gmcall_mgr *m, struct gmcall *c, enum creq_kind k);
void gm_creq_free(struct creq *r);
/* attach the transaction; the callback is gm_creq_cb below */
int gm_creq_start(struct gmcall *c, struct creq *r, struct sip_endpoint *ep, const struct addr *dst,
		  const uint8_t *data, size_t len);
void gm_creq_detach_call(struct gmcall *c);

/* ---- gmcall_dlg.c: requests inside a dialog, session timer, re-offers ---- */
struct gm_route {
	struct sip_endpoint *ep;
	struct addr dst;
	const char *sv;
	const char *pani;
};
struct gm_req {
	const char *method;
	uint32_t cseq;		/* 0: next */
	const char *extra;	/* method specific header lines */
	bool contact;		/* add our Contact (target refresh) */
	const char *ctype;
	const uint8_t *body;
	size_t blen;
};
int gm_route_get(struct gmcall *c, struct sip_dialog *d, struct gm_route *rt);
int gm_build_in_dialog(struct gmcall *c, struct sip_dialog *d, const struct gm_req *q, struct gm_route *rt,
		       struct buf *out, uint32_t *cseq_used);
int gm_contact(struct gmcall *c, char *out, size_t n);
/* ACK for the 2xx of dialog d (CSeq of the INVITE), sent immediately */
void gm_send_ack(struct gmcall *c, struct sip_dialog *d, uint32_t invite_cseq);
/* BYE on d as an orphan transaction (nobody waits for the answer) */
void gm_send_bye(struct gmcall *c, struct sip_dialog *d);
/* send a BYE if the call has an answered dialog, then the terminal event */
void gm_terminate_local(struct gmcall *c, bool send_bye, const char *reason);
/* a request arrived inside dialog d of call c; always consumed */
void gm_in_dialog_request(struct gmcall *c, struct sip_dialog *d, struct txn_server *st, const struct sip_msg *req);
/* ACK of a 2xx (st == NULL) matched to call c */
void gm_ack_received(struct gmcall *c, const struct sip_msg *req);
/* MO: take the session timer from the 2xx (Session-Expires; refresher absent means uac) */
void gm_sess_from_2xx(struct gmcall *c, const struct sip_msg *resp);
/* start / restart the session timer */
void gm_sess_start(struct gmcall *c, unsigned interval, bool local_refresher);
void gm_sess_stop(struct gmcall *c);
void gm_note_allow(struct gmcall *c, const struct sip_msg *m);
void gm_maybe_reoffer(struct gmcall *c);
void gm_dlg_cleanup(struct gmcall *c);	/* stop rtx / timers of the in-dialog machinery */
void gm_client_response(struct creq *r, struct gmcall *c, const struct sip_msg *resp);	/* responses of BYE/UPDATE/re-INVITE/PRACK */
void gm_client_failure(struct creq *r, struct gmcall *c, int status);	/* timeout / transport error */
void gm_misc_fire_dlg(struct gmcall *c);	/* MISC_GLARE / MISC_REFRESH_RETRY */
void gm_sess_fire(struct gmcall *c);

/* ---- gmcall_mo.c ---- */
int gm_mo_dial(struct gmcall_mgr *m, const struct gmcall_dial *d, gmcall_event_cb cb, void *arg, struct gmcall **out);
void gm_mo_response(struct gmcall *c, struct creq *r, const struct sip_msg *resp);
void gm_mo_txn_failed(struct gmcall *c, struct creq *r, int status, const char *why);
int gm_mo_hangup(struct gmcall *c);
void gm_mo_ring_timeout(struct gmcall *c);
void gm_mo_cancel_guard(struct gmcall *c);
bool gm_mo_stray_2xx(struct gmcall *c, struct sip_endpoint *ep, const struct sip_msg *resp);
void gm_mo_down(struct gmcall *c);

/* ---- gmcall_mt.c ---- */
bool gm_mt_new(struct gmcall_mgr *m, struct txn_server *st, struct sip_endpoint *ep, const struct sip_msg *req);
void gm_mt_ring_timeout(struct gmcall *c);
void gm_mt_down(struct gmcall *c);
int gm_mt_hangup(struct gmcall *c);

#endif
