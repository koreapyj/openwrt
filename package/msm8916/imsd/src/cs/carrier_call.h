/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_CARRIER_CALL_H
#define IMSD_CS_CARRIER_CALL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../sdp/sdp_neg.h"
#include "../util/addr.h"

/*
 * One interface for the carrier side of a call, so that the B2BUA can drive either backend:
 *   "gm" - struct gmcall (IMS: SIP towards the LG U+ core, RTP / AMR media), wrapped by cs/carrier_gm.c
 *   "cs" - struct cscall (circuit switched call control through uqmid, 8 kHz PCM through the modem's sound card)
 * It has the shape of call/gmcall.h (same lifetime rules: events only from the event loop, never from inside a
 * call; exactly one terminal event per call; the call pointer is valid until the terminal callback returns;
 * release() detaches the user and ends the call), plus two things the CS backend needs:
 *   - the media of the carrier side is a kind: RTP (the SDP of the remote, as with gmcall) or PCM (the local sound card;
 *     no SDP, no addresses: the B2BUA creates the bridge with a BR_LEG_PCMDEV carrier leg, cs/csmedia.h);
 *   - digits towards the carrier are sent with the call control (send_dtmf), not as RFC 4733 packets.
 *
 * ---- events -------------------------------------------------------------------------------------------
 *  PROGRESS    MO: the network is working on it. status = 183 once the carrier audio is available, 180 for ringing
 *              (a gm 18x with / without SDP); informational, the B2BUA relays a 180 / 183 to the LAN device.
 *  RINGING     MO: the far end is alerting. gm: a 180 without SDP (generate ringback yourself); cs: the alerting state
 *              of the network; whether in-band ringback arrives is up to the network (EARLY_MEDIA follows).
 *  EARLY_MEDIA MO: the carrier audio is available before the answer: gm = a provisional answer with SDP (media points to
 *              it), cs = the call reached the alerting state: open the bridge now (PCM) and send 183 with SDP to the LAN
 *              device so the caller hears real ringback / announcements. At most once, before ANSWERED.
 *  MEDIA       gm only: the remote media description changed (see gmcall.h). cs never sends it.
 *  ANSWERED    MO: the call is connected. MT: the call is connected (the network confirmed our answer).
 *  FAILED      MO only, terminal: the call could not be set up (status = SIP status, reason = text).
 *  CANCELLED   terminal: ended before it was answered. by_remote: the far end gave up (MT) / false: we cancelled or rejected.
 *  TERMINATED  terminal: an established call ended. by_remote true: the far end / the network ended it.
 *  status on the terminal events is the SIP status the B2BUA should relay to the other leg (FAILED: the response; CANCELLED
 *  and TERMINATED: informational, 0 = none).
 */
struct carrier_call;			/* a struct gmcall or a struct cscall (opaque to the user) */

enum cc_dir { CC_MO, CC_MT };
enum cc_state { CC_ST_DIALING, CC_ST_EARLY, CC_ST_CANCELLING, CC_ST_INCOMING, CC_ST_ANSWERING, CC_ST_CONNECTED, CC_ST_ENDED };
const char *cc_state_name(enum cc_state s);

enum cc_media_kind { CC_MEDIA_NONE = 0, CC_MEDIA_RTP, CC_MEDIA_PCM };

enum cc_event_type {
	CC_EV_PROGRESS,
	CC_EV_RINGING,
	CC_EV_EARLY_MEDIA,
	CC_EV_MEDIA,
	CC_EV_ANSWERED,
	CC_EV_FAILED,		/* terminal */
	CC_EV_CANCELLED,	/* terminal */
	CC_EV_TERMINATED,	/* terminal */
	CC_EV_REOFFER_FAILED,	/* gm only: the network refused a hold / resume / media change; the call goes on (status, reason) */
};

struct cc_event {
	enum cc_event_type type;
	int status;			/* SIP status: PROGRESS, FAILED; terminal events: what to relay (0 none) */
	enum cc_media_kind media_kind;	/* EARLY_MEDIA, MEDIA */
	const struct sdpn_media *media;	/* RTP media, valid during the callback only (NULL for PCM) */
	bool early;			/* MEDIA: before the final answer */
	bool by_remote;			/* CANCELLED, TERMINATED */
	char reason[128];		/* human text of the cause */
	int cause;			/* cs: Q.850 cause when the network reported one, 0 otherwise (status inferred) */
};
typedef void (*cc_event_cb)(struct carrier_call *c, const struct cc_event *ev, void *arg);

struct cc_identity {
	char uri[256];			/* tel:/sip: URI of the other party */
	char number[48];		/* normalised: "+821012345678" / "01051226862", "" when unknown */
	char display[64];
	bool anonymous;			/* no number was presented */
};

struct cc_incoming {
	struct cc_identity caller;
	char called[48];		/* number the call was addressed to, "" if unknown (cs: the line's own number when known) */
	enum cc_media_kind media_kind;
	const struct sdpn_media *offered;	/* RTP offer, valid during the callback only (NULL for PCM) */
	bool backend_cs;
};
/* Return 0 to accept (install the event handler with ops->set_handler inside the callback), non-zero to refuse (480, or
 * the status given to ops->reject inside the callback). */
typedef int (*cc_incoming_cb)(struct carrier_call *c, const struct cc_incoming *in, void *arg);

struct cc_dial {
	const char *target;		/* "01012345678", "+821012345678", "114", "*23#" or (gm only) a sip:/tel: URI */
	struct addr local_rtp;		/* gm: local RTP address and port for the SDP offer; cs: ignored */
	const char *extra_headers;	/* gm only */
};

struct cc_info {
	unsigned id;
	enum cc_dir dir;
	const char *state_name;
	struct cc_identity remote;
	uint64_t age_ms, talk_ms;
	enum cc_media_kind media_kind;
	bool hold;
};

struct carrier_call_ops {
	const char *name;		/* "gm" | "cs" */
	enum cc_media_kind media_kind;	/* what the carrier side of a call is */
	/* ---- manager ---- */
	void (*set_incoming)(void *be, cc_incoming_cb cb, void *arg);
	/* Start an MO call: 0 and *out, or -errno without any event: -EINVAL (bad target), -ENOTCONN (line not usable), -EBUSY (cs: a
	 * call is active, the PCM path is single: answer the LAN device 486), -ENOBUFS, -ENOMEM. */
	int (*dial)(void *be, const struct cc_dial *d, cc_event_cb cb, void *arg, struct carrier_call **out);
	unsigned (*count)(const void *be);
	int (*list)(const void *be, struct cc_info *out, int max);
	/* ---- per call ---- */
	void (*set_handler)(struct carrier_call *c, cc_event_cb cb, void *arg);
	int (*ring)(struct carrier_call *c);			/* MT: tell the network the call is alerting (gm: 180; cs: nothing to do) */
	int (*answer)(struct carrier_call *c, const struct addr *local_rtp);	/* MT; cs ignores local_rtp (NULL) */
	int (*reject)(struct carrier_call *c, int status);	/* MT, before answering */
	int (*hangup)(struct carrier_call *c);			/* any state; the terminal event follows from the loop */
	void (*release)(struct carrier_call *c);		/* hangup + detach: no event of any kind afterwards */
	/* hold / resume the carrier leg. gm: re-INVITE with sendonly / sendrecv. cs: there is no usable hold (the network's
	 * supplementary service is not driven): the call stays up and the B2BUA feeds silence (bridge direction); returns 0. */
	int (*set_hold)(struct carrier_call *c, bool hold);
	/* one DTMF digit '0'-'9' '*' '#' 'A'-'D' towards the carrier, in order. gm: -ENOTSUP (media sends RFC 4733). cs: queued, sent
	 * one at a time with uqmid send_dtmf. 0 or -errno (-ENOTCONN: not connected, -ENOBUFS: queue full) */
	int (*send_dtmf)(struct carrier_call *c, char digit);
	/* the media layer reports a problem with the carrier media of this call (cs: the PCM device could not be opened /
	 * vanished): the call is ended with 503. gm: no-op. err = errno of the failure. */
	void (*media_failed)(struct carrier_call *c, int err);
	bool (*get_media)(const struct carrier_call *c, struct sdpn_media *out);	/* gm: last remote media; cs: false */
	enum cc_state (*state)(const struct carrier_call *c);
	enum cc_dir (*direction)(const struct carrier_call *c);
	const struct cc_identity *(*remote)(const struct carrier_call *c);
	unsigned (*id)(const struct carrier_call *c);
	uint64_t (*talk_ms)(const struct carrier_call *c);
};

/* a backend instance: the ops table and its manager */
struct carrier_backend {
	const struct carrier_call_ops *ops;
	void *be;
};

/* the SIP status a cs / gm cause is relayed as: see cs/cscall.h cs_cause_to_sip() */
#endif
