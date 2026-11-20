/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_B2B_B2B_INT_H
#define IMSD_B2B_B2B_INT_H
/* internals shared by b2b*.c; not part of the API */
#include "b2b.h"
#include "../call/gmcall.h"
#include "../cs/carrier_gm.h"
#include "../cs/csmedia.h"
#include "../sdp/sdp.h"
#include "../sdp/sdp_neg.h"
#include "../sip/dialog.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

enum b2b_st {
	CS_SETUP,	/* OUT: carrier dialing / ringing; IN: LAN devices ringing */
	CS_EARLY,	/* OUT: 183 with our answer sent */
	CS_ANSWERING,	/* OUT: 200 sent, waiting for the ACK */
	CS_UP,
	CS_ENDED,
};

struct b2b_call {
	struct b2b_call *next;
	unsigned id;
	bool out;			/* LAN -> network */
	bool bench;			/* the LAN leg is a PCM file leg */
	enum b2b_st st;
	struct carrier_call *cc;	/* carrier leg, NULL after its terminal event / release */
	const struct carrier_call_ops *ops;	/* the backend of cc: carrier_gm_ops or cscall_carrier_ops */
	bool pcm;			/* the carrier media is the modem's PCM device (no carrier RTP / SDP) */
	char number[48];		/* remote party (dialled number / caller) */
	uint64_t t_start, t_up;
	bool sent_180, ans_sent, bench_play_started;
	bool client_cancelled;
	bool hold_c, hold_l;		/* the carrier / the client put the call on hold */
	/* LAN leg */
	struct txn_server *ist;		/* OUT: the INVITE server transaction until it ends */
	struct sip_dialog ldlg;
	bool ldlg_ok;
	struct addr ldst;		/* where requests of the LAN dialog go */
	struct sip_rtx *rtx;		/* 200 retransmission: the initial one or a re-INVITE's */
	uint32_t rtx_cseq;
	bool rtx_initial;
	struct lan_fork *fork;		/* IN: until LAN_FORK_DONE */
	struct sdp *offer;		/* IN: our offer to the devices */
	struct sdp *ans;		/* OUT: our current answer to the client */
	struct sdpn_media lm, cm;	/* negotiated legs */
	bool lm_ok, cm_ok;
	enum sdp_dir l_rdir;		/* direction the client last asked for (its view) */
	bool wideband;			/* IN: the carrier offered AMR-WB */
	/* media */
	int lfd, cfd;			/* RTP sockets until handed to the bridge, else -1 */
	struct addr lbound, cbound;
	bool cfd_br, lfd_br;		/* the socket was handed to the bridge (it closes it) */
	enum br_dir cdir, ldir;		/* effective direction of the bridge legs (what we may do on them) */
	struct bridge *br;
	bool br_started;
	struct ev_timer *t_ring;
	char play[200], rec[200];
	unsigned rate;
	/* IN: what the devices said */
	unsigned n_branch_final, n_branch_busy;
	char end_reason[96];
	int end_status;
};

struct b2b {
	struct core *core;
	struct gmcall_mgr *gm;
	struct carrier_backend gm_be;		/* the IMS backend (B.gm) */
	struct b2b_call *calls;
	struct b2b_call *dead;
	struct ev_timer *t_reap;
	unsigned next_id;
	bool running;
	struct b2b_counters cnt;
	struct b2b_ops ops;
	b2b_notify_cb notify;
	void *notify_arg;
	struct reg *reg;
};
extern struct b2b B;

static inline void b2b_timer_cancel(struct ev_timer *t)
{
	if (t)
		ev_timer_cancel(t);
}

/* ---- b2b.c ---- */
const struct imsd_config *b2b_cfg(void);
struct b2b_call *b2b_find(unsigned id);
struct b2b_call *b2b_call_new(bool out);
void b2b_notify(struct b2b_call *c, const char *event, int status, const char *reason);
/* finish a call: carrier leg released, bridge destroyed, LAN dialog ended with a BYE when bye_lan, timers stopped, freed later */
void b2b_teardown(struct b2b_call *c, const char *why, bool bye_lan);
const char *b2b_state_name(const struct b2b_call *c);
int b2b_rtp_lan(struct addr *bound);
int b2b_rtp_carrier(struct addr *bound);
void b2b_new_origin(struct sdp_origin *o);
void b2b_cc_event(struct carrier_call *cc, const struct cc_event *ev, void *arg);
/* release the carrier leg after rejecting (MT) with status */
void b2b_cc_reject_release(struct b2b_call *c, int status);
/* status given to the LAN client for a failed carrier dial() */
int b2b_dial_status(int rc, bool pcm);
bool b2b_is_gm(const struct b2b_call *c);
const struct carrier_backend *b2b_cur_backend(void);	/* the backend of new outgoing calls, NULL: none */
void b2b_try_free(struct b2b_call *c);
void b2b_lan_cfg(bool wideband, struct sdpn_lan_cfg *lc);
const char *b2b_user_agent(void);

/* ---- b2b_media.c ---- */
enum br_dir b2b_br_dir(enum sdp_dir d);
bool b2b_media_same(const struct sdpn_media *a, const struct sdpn_media *b);
int b2b_bridge_up(struct b2b_call *c);	/* create + start the bridge from c->cm / c->lm (or the PCM leg) */
void b2b_bridge_destroy(struct b2b_call *c);
void b2b_close_socks(struct b2b_call *c);
/* the carrier media changed (early, final or a re-offer): update the bridge */
void b2b_carrier_media(struct b2b_call *c, const struct sdpn_media *m);
/* the client's media changed: update the bridge (codec -> restart, address, direction) */
void b2b_client_media(struct b2b_call *c, const struct sdpn_media *m);
void b2b_bridge_event(void *arg, const struct br_event *ev);
void b2b_fill_info(const struct b2b_call *c, struct b2b_info *i);

/* ---- b2b_lan.c: the LAN dialog ---- */
void b2b_lan_on_invite(struct lan *l, const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req, void *arg);
void b2b_lan_on_in_dialog(struct lan *l, const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req, void *arg);
void b2b_lan_on_ack(struct lan *l, const struct lan_peer *p, const struct sip_msg *req, void *arg);
void b2b_lan_reply(struct txn_server *st, int status, const char *extra);
/* requests of the LAN dialog of c; ACK uses the INVITE cseq; BYE etc. run as client transactions */
void b2b_lan_send_ack(struct b2b_call *c, uint32_t invite_cseq);
void b2b_lan_send_bye(struct b2b_call *c);
/* ACK + BYE of a dialog that is not (or no longer) a call's: extra 2xx, a winner nobody wants */
void b2b_lan_ack_bye(struct sip_dialog *d, const struct addr *dst, uint32_t invite_cseq);
void b2b_lan_dlg_drop(struct b2b_call *c);

/* ---- b2b_out.c: LAN -> network ---- */
void b2b_out_invite(const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req);
void b2b_out_cc_event(struct b2b_call *c, const struct cc_event *ev);
void b2b_out_client_ack(struct b2b_call *c);
void b2b_out_send_200(struct b2b_call *c);
void b2b_out_rtx_giveup(struct sip_rtx *r, void *arg);
void b2b_reoffer_failed(struct b2b_call *c, const struct cc_event *ev);

/* ---- b2b_in.c: network -> LAN ---- */
int b2b_in_incoming(struct carrier_call *cc, const struct cc_incoming *in, void *arg);	/* arg: the backend's struct carrier_call_ops */
void b2b_in_cc_event(struct b2b_call *c, const struct cc_event *ev);
void b2b_in_end(struct b2b_call *c);	/* cancel the fork when still running */
/* ---- b2b_bench.c ---- */
int b2b_bench_pcm_cfg(struct b2b_call *c, struct br_leg_cfg *cfg);
#endif
