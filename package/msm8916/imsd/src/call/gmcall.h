/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CALL_GMCALL_H
#define IMSD_CALL_GMCALL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "gmcall_util.h"
#include "../gm/reg.h"
#include "../sdp/sdp_neg.h"
#include "../sip/txn.h"

/*
 * Carrier ("Gm") call leg: one struct gmcall is one SIP call towards the LG U+
 * IMS core, outgoing (MO) or incoming (MT), with its own dialog(s), session
 * timer, hold state and SDP offer/answer state. It carries no media: it
 * reports what the remote negotiated (struct sdpn_media) and is told which
 * local RTP address to advertise. A later layer (the B2BUA) joins it with a
 * LAN leg and the media bridge.
 *
 * ---- threading, re-entrancy, lifetime (the contract) -------------------------
 *  - Single threaded; nothing here blocks. Everything runs from the event loop.
 *  - Events (gmcall_event_cb, gmcall_incoming_cb) are delivered ONLY from the
 *    event loop (network receive, timers, registration hook), never from
 *    inside a gmcall_*() call made by the user. A gmcall_*() function returns
 *    its result and the consequence arrives later as an event. Consequently
 *    a user callback may freely call any gmcall_*() function on any call.
 *  - Every call ends with EXACTLY ONE terminal event: FAILED, CANCELLED or
 *    TERMINATED (also when the user ended it). It is the last callback. The
 *    struct gmcall pointer is valid until that callback returns (memory is
 *    reclaimed afterwards, at the latest on the next loop iteration);
 *    gmcall_*() calls on an ended call return -ESTALE as long as the memory
 *    is still around, but a user must not rely on that and must drop the
 *    pointer when it sees the terminal event.
 *  - gmcall_release() detaches the user (no more callbacks, not even the
 *    terminal one) and ends the call by itself; the pointer is invalid right
 *    after it returns.
 *  - Callbacks may be invoked while the call is in the middle of being torn
 *    down by gmcall_on_reg_event(REG_EV_DOWN): the terminal events of all
 *    calls are delivered one after the other inside that hook; a callback
 *    for call A can therefore call gmcall_hangup(B) (B is then already
 *    ended or about to be: -ESTALE or fine) but must not assume B survives.
 *  - gmcall_mgr_free() destroys all calls silently (no callbacks).
 *
 * ---- events -------------------------------------------------------------------
 *  PROGRESS    MO: a provisional response (101..199) arrived. status, has_sdp
 *              (an SDP answer was in it), early_media (value of P-Early-Media,
 *              "" if absent: informational; this module passes early media
 *              through by itself, it never gates it). Deduplicated: the same
 *              (status, dialog, has_sdp) is reported once.
 *  RINGING     MO: a 180 without SDP: the caller should generate ringback
 *              (a 180/183 WITH SDP means the network sends audio itself).
 *              Once per early dialog.
 *  MEDIA       the remote media description is established or changed
 *              (early answer, final answer, 2xx on a different dialog than
 *              the early media came from, remote re-INVITE/UPDATE changing
 *              the address / codec / direction, a hold/resume by the remote,
 *              the answer to our own re-INVITE). media points to a struct
 *              valid only during the callback; early = true for answers that
 *              came before the 2xx. After MEDIA(early=false) of an MO call
 *              the codec is final. For MT calls the offered media is NOT
 *              reported by an event: it is in struct gmcall_incoming and
 *              gmcall_get_media(); events only report later changes.
 *  ANSWERED    MO: the 2xx arrived and was ACKed (MEDIA(early=false) came just
 *              before it if the 2xx carried SDP). MT: the ACK for our 200 arrived.
 *              The call is CONNECTED from now on (MT: from the moment we sent
 *              the 200; ANSWERED only confirms the ACK).
 *  REOFFER_FAILED  our own re-INVITE (hold/resume, media change) was rejected
 *              (status) or its answer unusable; the call goes on unchanged.
 *  FAILED      MO only, terminal: the INVITE failed. status is the final SIP
 *              status (408 timeout, 503 transport error, 0 local failure
 *              without a SIP response, e.g. registration lost: map to 503),
 *              reason the best human text (Reason header text, else Warning
 *              text, else the reason phrase), warning the Warning text.
 *              401/407 are reported as plain failures: re-authentication is
 *              the registration module's business.
 *  CANCELLED   terminal: ended before it was answered without a network
 *              failure. by_remote = true: the caller hung up (MT, CANCEL;
 *              reason = Reason header text, e.g. "Call completed elsewhere").
 *              by_remote = false: we cancelled (MO, gmcall_hangup) or rejected
 *              (MT, gmcall_reject), or registration was lost.
 *  TERMINATED  terminal: an established call (or an MT call we had already
 *              answered) ended. by_remote = true: the network sent BYE (reason
 *              from its Reason header); false: gmcall_hangup, session timer
 *              expiry, failed session refresh (408/481), missing ACK,
 *              registration lost (reason says which).
 *  DTMF is not here (RTP level, media module).
 *
 * ---- MO outline / MT outline ----------------------------------------------------
 *  MO: gmcall_dial() -> [PROGRESS, RINGING, MEDIA(early)]* -> (MEDIA, ANSWERED
 *      | FAILED | CANCELLED), then TERMINATED when it ends.
 *  MT: gmcall_on_request(INVITE) -> incoming callback (the user accepts by
 *      returning 0 and installing its event handler with gmcall_set_handler();
 *      180 is sent automatically after the callback returns unless the user
 *      already called gmcall_ring()/answer()/reject() inside it or auto_ring
 *      is off) -> gmcall_answer(local rtp) / gmcall_reject(status)
 *      -> ANSWERED (ACK) -> ... TERMINATED; or CANCELLED.
 */

struct gmcall;
struct gmcall_mgr;

enum gmcall_dir { GMCALL_MO, GMCALL_MT };

enum gmcall_state {
	GMCALL_ST_DIALING,	/* MO: INVITE sent, no provisional response yet */
	GMCALL_ST_EARLY,	/* MO: provisional response(s) seen */
	GMCALL_ST_CANCELLING,	/* MO: CANCEL requested, waiting for the final response */
	GMCALL_ST_INCOMING,	/* MT: INVITE received, not answered */
	GMCALL_ST_ANSWERING,	/* MT: 200 sent, waiting for the ACK */
	GMCALL_ST_CONNECTED,	/* established; also on hold */
	GMCALL_ST_ENDED,	/* terminal event pending / delivered */
};
const char *gmcall_state_name(enum gmcall_state s);

enum gmcall_event_type {
	GMCALL_EV_PROGRESS,
	GMCALL_EV_RINGING,
	GMCALL_EV_MEDIA,
	GMCALL_EV_ANSWERED,
	GMCALL_EV_REOFFER_FAILED,
	GMCALL_EV_FAILED,	/* terminal */
	GMCALL_EV_CANCELLED,	/* terminal */
	GMCALL_EV_TERMINATED,	/* terminal */
};

struct gmcall_event {
	enum gmcall_event_type type;
	int status;			/* PROGRESS, FAILED, REOFFER_FAILED */
	bool has_sdp;			/* PROGRESS */
	char early_media[24];		/* PROGRESS: P-Early-Media value or "" */
	const struct sdpn_media *media;	/* MEDIA (valid during the callback only) */
	bool early;			/* MEDIA */
	bool by_remote;			/* CANCELLED, TERMINATED */
	char reason[128];		/* FAILED, CANCELLED, TERMINATED, REOFFER_FAILED: best text */
	char warning[96];		/* FAILED: Warning header text */
};
typedef void (*gmcall_event_cb)(struct gmcall *call, const struct gmcall_event *ev, void *arg);

/* what the user is told about an incoming call */
struct gmcall_incoming {
	struct gmcall_identity caller;	/* P-Asserted-Identity, else From */
	char called[48];		/* number the call was addressed to (P-Called-Party-ID, else Request-URI) */
	const struct sdpn_media *offered;	/* remote media of the offer (codec, address, direction); valid during the callback; also gmcall_get_media() */
	bool session_timer;		/* the network asked for a session timer */
};
/*
 * A new MT call. Return 0 to accept: the user MUST install its event handler
 * from inside the callback (gmcall_set_handler) before returning. Non-zero
 * refuses: 480 Temporarily Unavailable (or the status passed to
 * gmcall_reject inside the callback). The call may be answered later.
 */
typedef int (*gmcall_incoming_cb)(struct gmcall *call, const struct gmcall_incoming *in, void *arg);

/* ---- registered context provider ---------------------------------------------- */
struct gmcall_reg_ops {
	/* NULL while not registered. The pointer is only used immediately. */
	const struct reg_ctx *(*context)(void *arg);
	/* "sip:user@[addr]:port-s" of the current registration; 0 / -1 */
	int (*contact_uri)(void *arg, char *out, size_t n);
};
/* adapter over a struct reg (gmcall_reg.c); pass the struct reg * as reg_arg */
extern const struct gmcall_reg_ops gmcall_reg_adapter;

struct gmcall_cfg {
	struct txn_layer *tl;			/* the transaction layer the Gm endpoint is attached to (required) */
	const struct gmcall_reg_ops *reg;	/* required */
	void *reg_arg;
	const char *phone_context;		/* "lguplus.co.kr": for dialled national numbers. (MT requests show lte-lguplus.co.kr; the PoC's MO value was proven) */
	const char *contact_params;		/* Contact feature tags of our INVITE / 2xx, with leading ';'. Default: ;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel" */
	const char *user_agent;			/* optional User-Agent header value, default none */
	unsigned session_expires;		/* seconds asked for in our INVITE (refresher=uac); the network may lower it. default 1800 */
	unsigned min_se;			/* our floor, advertised in 422; default 90 */
	unsigned ring_timeout_s;		/* MO: no final response after this: CANCEL and FAILED(408); MT: not answered after this: 480. 0 = off. default 180 */
	unsigned max_calls;			/* concurrent calls (MO + MT); MT over the limit gets 486, dial returns -ENOBUFS. default 8 */
	bool auto_ring;				/* MT: send 180 right after the incoming callback accepted. default true */
	struct sdpn_carrier_cfg sdp;		/* codec / SDP offer configuration (sdpn_carrier_cfg_default) */
	gmcall_incoming_cb on_incoming;		/* MT calls; NULL: they are answered 480 */
	void *incoming_arg;
};
void gmcall_cfg_defaults(struct gmcall_cfg *c);

/* The strings in cfg are copied. NULL on OOM / missing tl or reg. */
struct gmcall_mgr *gmcall_mgr_new(const struct gmcall_cfg *cfg);
/* Destroy every call silently (no callbacks, nothing is sent) and free. Call before txn_layer_free(). */
void gmcall_mgr_free(struct gmcall_mgr *m);
/* Change the strings of later calls (a NULL argument keeps the value; empty contact_params = the default tag) and the Session-Expires we ask for. */
void gmcall_mgr_set_strings(struct gmcall_mgr *m, const char *phone_context, const char *contact_params, const char *user_agent);
void gmcall_mgr_set_session_expires(struct gmcall_mgr *m, unsigned secs);
void gmcall_set_incoming(struct gmcall_mgr *m, gmcall_incoming_cb cb, void *arg);
unsigned gmcall_count(const struct gmcall_mgr *m);

/*
 * ---- plug-in points for gm/reg.c -------------------------------------------------
 *
 * gmcall_on_request: call it for every request received on the protected
 * endpoint that reg.c does not handle itself (INVITE, BYE, UPDATE, PRACK,
 * INFO, OPTIONS, ... and ACK, for which st is NULL). Returns true if the
 * request was consumed (a response was sent through st, or it was an ACK);
 * false means "not ours" (unknown dialog, no registration ...): the caller
 * then runs its default handling (480 for INVITE, 481 in-dialog).
 * CANCEL never gets here (the transaction layer handles it).
 */
bool gmcall_on_request(struct gmcall_mgr *m, struct txn_server *st, struct sip_endpoint *ep,
		       const struct addr *src, const struct sip_msg *req);
/*
 * gmcall_on_stray_response: for the transaction layer's on_stray_response
 * (a 2xx to an INVITE that no client transaction matches any more:
 * retransmitted or forked 2xx). It re-ACKs a 2xx of a known dialog, or ACKs
 * and BYEs an unknown extra dialog of a call we own. Returns true if used.
 */
bool gmcall_on_stray_response(struct gmcall_mgr *m, struct sip_endpoint *ep, const struct addr *src,
			      const struct sip_msg *resp);
/* reg_hook_cb compatible: reg_add_hook(reg, gmcall_reg_hook, mgr) (REG_EV_REPLACED / DOWN, see gmcall.c) */
void gmcall_reg_hook(void *mgr, enum reg_event ev, const char *reason);

/* ---- outgoing ----------------------------------------------------------------------- */
struct gmcall_dial {
	const char *target;		/* "01012345678", "+821012345678", "114", "*23#", or a full "sip:..."/"tel:..." URI (passed unchanged) */
	struct addr local_rtp;		/* local RTP address AND port advertised in the SDP offer */
	const char *extra_headers;	/* optional extra header lines, each CRLF terminated (e.g. "Privacy: id\r\n") */
};
/*
 * Start an MO call. 0 and *out set (events follow), or -errno without any
 * event: -EINVAL (bad target / bad rtp), -ENOTCONN (not registered),
 * -ENOBUFS (call limit or transaction limit), -EMSGSIZE, -ENOMEM.
 * cb/arg receive the events (cb may be NULL).
 */
int gmcall_dial(struct gmcall_mgr *m, const struct gmcall_dial *d, gmcall_event_cb cb, void *arg, struct gmcall **out);

/* ---- incoming ----------------------------------------------------------------------- */
/* install / replace the event handler (mandatory inside the incoming callback) */
void gmcall_set_handler(struct gmcall *c, gmcall_event_cb cb, void *arg);
/* MT: send 180 Ringing (once; later calls are no-ops). 0 / -errno (-EINVAL wrong state) */
int gmcall_ring(struct gmcall *c);
/*
 * MT: answer with 200 and our SDP answer built for local_rtp (address and
 * port to advertise). 0, or -errno: -EINVAL (not an unanswered MT call),
 * -EPROTO (the offer cannot be answered any more). The ACK is awaited and the
 * 200 retransmitted until it arrives; ANSWERED follows.
 */
int gmcall_answer(struct gmcall *c, const struct addr *local_rtp);
/* MT: final response (status 400..699, 486 Busy, 480, 603 Decline ...) -> CANCELLED(by_remote=false) event */
int gmcall_reject(struct gmcall *c, int status);

/* ---- both ----------------------------------------------------------------------------- */
/*
 * End the call whatever its state: MO dialing/early: CANCEL (CANCELLED follows
 * the 487; if a 2xx wins the race it is ACKed and BYEd and CANCELLED is
 * reported); MT unanswered: 480 Temporarily Unavailable (use gmcall_reject for
 * a specific status); established: BYE (sent best effort, TERMINATED(by_remote=
 * false) is reported without waiting for its answer). 0 / -errno. Never calls
 * back synchronously.
 */
int gmcall_hangup(struct gmcall *c);
/* hangup + detach the user: no callback of any kind afterwards, pointer invalid on return */
void gmcall_release(struct gmcall *c);
/*
 * Hold / resume / media change: send a re-INVITE with our SDP (origin
 * version incremented, direction attribute as asked) as soon as no offer is
 * pending (requests made meanwhile are coalesced: the latest one wins).
 * dir: SDP_DIR_SENDRECV resumes, SENDONLY / INACTIVE hold (RFC 3264). rtp may
 * be NULL (keep) or a new local RTP address+port. The result is the
 * MEDIA event of the answer (or REOFFER_FAILED). 0 / -errno (-EINVAL: not
 * established, -ENOTCONN: not registered).
 */
int gmcall_set_media(struct gmcall *c, const struct addr *rtp, enum sdp_dir dir);
static inline int gmcall_set_direction(struct gmcall *c, enum sdp_dir dir)
{
	return gmcall_set_media(c, NULL, dir);
}

/* ---- getters (valid while the pointer is valid) ------------------------------------ */
enum gmcall_dir gmcall_direction(const struct gmcall *c);
enum gmcall_state gmcall_get_state(const struct gmcall *c);
unsigned gmcall_id(const struct gmcall *c);			/* manager-unique, for logs / ubus */
const char *gmcall_call_id(const struct gmcall *c);		/* SIP Call-ID */
const struct gmcall_identity *gmcall_remote(const struct gmcall *c);
/* last remote media reported (or the offer of an MT call); false if none yet */
bool gmcall_get_media(const struct gmcall *c, struct sdpn_media *out);
/* our current local direction (what we last offered / answered) */
enum sdp_dir gmcall_local_dir(const struct gmcall *c);
uint64_t gmcall_age_ms(const struct gmcall *c);		/* since creation */
uint64_t gmcall_talk_ms(const struct gmcall *c);		/* since connected, 0 before */

/* status dump (for ubus): one row per call */
struct gmcall_info {
	unsigned id;
	enum gmcall_dir dir;
	const char *state_name;		/* static string */
	char call_id[128];
	struct gmcall_identity remote;
	uint64_t age_ms, talk_ms;
	bool media_valid;
	char remote_media[64];		/* "[2001:..]:48814" */
	char codec[24];			/* "AMR-WB" ... */
	enum sdp_dir local_dir;
	unsigned session_interval;	/* 0 = no session timer */
	bool session_refresher_local;
	int session_next_ms;		/* until the next refresh (we refresh) / expiry guard (peer refreshes); -1 none */
};
/* fills up to max rows, returns the number of calls (may exceed max) */
int gmcall_list(const struct gmcall_mgr *m, struct gmcall_info *out, int max);
#endif
