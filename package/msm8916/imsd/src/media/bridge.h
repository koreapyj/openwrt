/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MEDIA_BRIDGE_H
#define IMSD_MEDIA_BRIDGE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../util/addr.h"
#include "codec.h"
#include "pcmdev.h"

/*
 * Media bridge: two RTP legs joined by a packet-driven transcoder.
 *
 * THREADING MODEL
 *   One dedicated media thread (started by bridge_engine_start) serves ALL
 *   bridges with a single epoll set (leg sockets + a command eventfd).  The
 *   main thread (the SIP event loop) never touches bridge internals: every
 *   function below except bridge_get_stats() just appends a command to a
 *   mutex-protected ring and kicks an eventfd.  The mutex is held for a
 *   struct copy only (uncontended in practice), so no call ever waits for
 *   media work.  A full ring makes a call fail with -1 (errno EAGAIN)
 *   instead of blocking.  Commands are applied in order.  Results that the
 *   main thread cares about come back as events (below) through bridge_event_fd().
 *   bridge_get_stats() takes a different short mutex that the media thread
 *   only holds while copying a snapshot (taken after each batch of packets).
 *
 *   A struct bridge * belongs to the main thread from bridge_create() until
 *   bridge_destroy(); after destroy it must not be used.  Sockets: the fd of
 *   a UDP leg is created, bound (AF_INET6 dual-stack, matching util/addr.h,
 *   non-blocking) by the caller.  With own_fd = true the media thread closes
 *   it when the bridge is destroyed; with own_fd = false the caller closes it
 *   itself but must first wait for BR_EV_STOPPED (after bridge_stop) or
 *   BR_EV_DESTROYED, because the media thread may still be using the fd until
 *   then.  Stop/start keeps the sockets open.
 *
 * PACKET PATH (no allocation after bridge start)
 *   leg A packet -> RTP parse -> telephone-event? decode, queue on leg B's generator (dtmf.c)
 *                -> else depacketise (AMR RFC 4867) -> decode -> resample
 *                (8k<->16k) -> 20 ms frames -> encode -> packetise -> leg B.
 *   Frame synchronous: N frames in -> N packets out, immediately, no jitter
 *   buffer.  See bridge.c header comment for the loss / DTX / marker rules.
 *
 * DIRECTION is per leg and means what WE do on that leg (SDP a= attribute of
 * the answer, seen from us): SENDRECV; SENDONLY = we only send to it (what
 * it sends is dropped); RECVONLY = we only receive from it (nothing is sent
 * to it); INACTIVE = neither.  Audio and DTMF flow A -> B only if A may be
 * received from and B may be sent to.
 */

enum br_leg_id { BR_CARRIER = 0, BR_CLIENT = 1 };	/* role labels; the code is symmetric */

enum br_dir { BR_SENDRECV = 0, BR_SENDONLY, BR_RECVONLY, BR_INACTIVE };

enum br_leg_kind {
	BR_LEG_NONE = 0,
	BR_LEG_UDP,	/* RTP over a caller supplied UDP socket */
	BR_LEG_PCM,	/* local PCM: file / callback (bench mode and tests) */
	BR_LEG_PCMDEV,	/* local PCM device of the modem (circuit switched call audio, pcmdev.h): 8 kHz, paced by its capture stream */
};

struct br_leg_cfg {
	enum br_leg_kind kind;
	enum br_dir dir;

	/* ---- UDP leg ---- */
	int fd;			/* bound non-blocking AF_INET6 UDP socket */
	bool own_fd;		/* media thread closes fd when the bridge is destroyed */
	struct addr remote;	/* where to send; may be set later (bridge_set_remote) */
	bool has_remote;
	/* Learn the peer from received packets (intended for the LAN leg only): with no
	 * remote set the first valid packet defines it; with one set, packets from the same
	 * IP are accepted from any port and the port is followed.  Without learn, packets
	 * from any address other than remote are dropped. */
	bool learn;
	enum codec_id codec;
	struct codec_params cp;	/* AMR: mode / modeset / dtx; Opus: bitrate etc. */
	bool amr_oa;		/* octet-align=1 as answered (AMR only) */
	int amr_cmr_tx;		/* CMR we put in outgoing AMR packets; default 15 (no request) */
	uint8_t pt;		/* payload type of the codec */
	int te_pt;		/* telephone-event payload type, -1: none */
	uint32_t te_clock;	/* telephone-event clock rate (8000 / 16000 / 48000); 0: codec clock */
	/* Digits sent TOWARD this leg (relayed from the peer leg or from bridge_send_dtmf) are regenerated, not copied:
	 * each plays for max(announced duration, dtmf_min_ms), at most dtmf_max_ms (a key still held is extended while its
	 * packets keep arriving), followed by dtmf_pause_ms before the next queued digit starts.  Defaults 100 / 60 / 2000;
	 * dtmf_max_ms 0 means 2000.  A te clock of 48000 limits events to 1365 ms (16 bit duration field). */
	uint32_t dtmf_min_ms, dtmf_pause_ms, dtmf_max_ms;
	uint32_t rx_timeout_ms;	/* BR_EV_RX_TIMEOUT after this much silence while we may receive (SENDRECV / RECVONLY); the timer restarts
				 * on every direction change, so a hold toggle never raises a spurious timeout; 0: off */
	/* Keep-alive (AMR / AMR-WB UDP leg only; default off).  Keeps NAT / conntrack open and shows the network
	 * a live RTP stream even when the other leg is silent or still ringing: AMR NO_DATA frames (FT 15) from
	 * this leg's own RTP state, every 20 ms for the first 2 s after start / resume / the last real packet
	 * (real packets: 200 ms grace), then every 160 ms.  Flows only while we may send to the leg (SENDRECV or
	 * SENDONLY) and a remote is known; RECVONLY / INACTIVE legs get nothing.  Counted in bridge_leg_stats.ka_pkts. */
	bool keepalive;

	/* ---- PCM leg ---- */
	int pcm_rate;		/* 8000 or 16000 */
	char play_path[200];	/* source: WAV (16-bit mono) or raw s16le at pcm_rate, paced in real time; "" none */
	bool play_loop;
	char rec_path[200];	/* sink: raw s16le at pcm_rate, or WAV when the name ends in .wav; "" none */
	/* callbacks run on the media thread; src returns the number of samples written (0: silence / nothing) */
	size_t (*pcm_src)(void *arg, int16_t *pcm, size_t n);
	void (*pcm_sink)(void *arg, const int16_t *pcm, size_t n);
	void *pcm_arg;

	/* ---- PCM device leg (BR_LEG_PCMDEV) ----
	 * pdev_ops: the device implementation (pcmdev_alsa_ops, or a fake in tests); pdev_spec: "" / "auto" / "<card>,<dev>"
	 * (pcmdev.h); pcm_rate 8000 (or 16000). The capture stream is the clock: every downlink period read from the device
	 * goes to the peer leg, and exactly one uplink period is written back, taken from a small queue of the peer's frames
	 * (target depth 2 frames; above 5 the oldest is dropped, an empty queue is filled with silence; both are counted:
	 * clock drift against the LAN RTP stream). dir works as for any leg: no sending toward the device = silence uplink.
	 * Digits for the device are not played (the main loop sends them with the call control, see BR_EV_DTMF). */
	const struct br_pcmdev_ops *pdev_ops;
	char pdev_spec[48];
};

/* defaults: UDP kind none, sendrecv, fd -1, te_pt -1, cmr 15, pcm_rate 16000, codec params default */
void br_leg_cfg_default(struct br_leg_cfg *c);

struct bridge;

/* ---- engine ---- */

/* Start the media thread (idempotent).  0 or -1. */
int bridge_engine_start(void);
/* Stop and join the thread, destroying every bridge still known to it. Shutdown path only (may wait). */
void bridge_engine_stop(void);

/* ---- events media thread -> main thread ---- */

enum br_event_type {
	BR_EV_FIRST_RX,		/* first valid RTP packet seen on leg (since start) */
	BR_EV_RX_TIMEOUT,	/* no packet for rx_timeout_ms (once per silence) */
	BR_EV_DTMF,		/* telephone event started / ended on leg */
	BR_EV_ERROR,		/* fatal for the bridge (bad config, codec failure); bridge is stopped */
	BR_EV_STOPPED,		/* bridge_stop / error finished: sockets released */
	BR_EV_DESTROYED,	/* bridge_destroy finished; br is a stale identity only */
	BR_EV_PLAY_DONE,	/* PCM leg play file reached its end */
	BR_EV_PCM_LOST,		/* PCM device leg: the device went away (modem crash / removal) or failed repeatedly; err = -errno. The bridge keeps running, the leg is dead until stop / start. */
};

struct br_event {
	enum br_event_type type;
	struct bridge *br;
	void *user;		/* pointer given to bridge_create */
	int leg;
	/* BR_EV_DTMF */
	char digit;		/* '0'-'9' '*' '#' 'A'-'D' 'F' */
	bool end;		/* false: key down, true: key up */
	uint32_t duration_ms;	/* only meaningful when end */
	/* BR_EV_ERROR, BR_EV_PCM_LOST */
	char msg[64];
	int err;		/* errno of a failed PCM device open (BR_EV_ERROR, e.g. EBUSY / ENODEV), -errno for BR_EV_PCM_LOST; 0 otherwise */
};

typedef void (*br_event_cb)(void *arg, const struct br_event *ev);
/* readable (poll/uloop fd) when events are queued; owned by the engine */
int bridge_event_fd(void);
/* Clear the fd and deliver every queued event to cb. Returns the count. Call from the main loop's fd callback. */
int bridge_events_dispatch(br_event_cb cb, void *arg);

/* ---- control (all asynchronous; 0 or -1 with errno) ---- */

/* Allocates a bridge in the "created" state (call from the main thread). NULL on OOM / engine not running. */
struct bridge *bridge_create(void *user);
/* Configure a leg.  Only while stopped (before the first start, or between stop and start; a
 * running bridge rejects it with a BR_EV_ERROR-free log message).  Use stop/set_leg/start for a re-INVITE
 * that changes codec parameters (codec state restarts; RTP ssrc/seq/timestamp continue). */
int bridge_set_leg(struct bridge *b, int leg, const struct br_leg_cfg *cfg);
/* change the destination of a leg at any time */
int bridge_set_remote(struct bridge *b, int leg, const struct addr *remote);
/* change direction at any time (hold / resume). */
int bridge_set_dir(struct bridge *b, int leg, enum br_dir dir);
/* Send a DTMF digit ('0'-'9' '*' '#' 'A'-'D') toward a leg as RFC 4733 telephone-event packets: a start packet
 * (marker), an update every 20 ms, three end packets (0: 160 ms; clamped to 40..5000, then the leg's dtmf_min_ms /
 * dtmf_max_ms apply).  The digit goes through the same per-leg queue as digits relayed from the peer leg, so it is played
 * in order after the ones queued before it, never overlapping them.  Needs a running bridge, a UDP leg with te_pt >= 0,
 * a remote and a direction we may send in; otherwise nothing is sent (logged, counted in dtmf_dropped).  Timestamps /
 * sequence numbers continue the leg's audio stream; transcoded audio toward that leg is suppressed while the event
 * plays.  0 or -1 (EINVAL). */
int bridge_send_dtmf(struct bridge *b, int to_leg, char digit, unsigned duration_ms);
/* validate, create codecs, register sockets: afterwards packets flow.  Emits BR_EV_ERROR on failure. */
int bridge_start(struct bridge *b);
/* unregister sockets, free codecs; emits BR_EV_STOPPED.  The bridge can be configured and started again. */
int bridge_stop(struct bridge *b);
/* stop if needed, close own_fd sockets, free; emits BR_EV_DESTROYED (also for a bridge that never started). */
int bridge_destroy(struct bridge *b);

/* bridges created and not yet destroyed (main thread's view; 0 after bridge_engine_stop) and whether the engine runs */
int bridge_count(void);
bool bridge_engine_running(void);

struct bridge_leg_stats {
	uint64_t rx_pkts, rx_bytes;	/* accepted RTP packets (any payload type) */
	uint64_t tx_pkts, tx_bytes;
	uint32_t rx_lost;		/* estimate from sequence gaps */
	uint32_t rx_jitter;		/* RFC 3550 jitter in RTP clock units */
	uint32_t rx_bad;		/* malformed RTP / payload */
	uint32_t rx_dropped;		/* wrong source, unknown PT, direction, no remote, duplicates/late */
	uint32_t tx_err;		/* send failures / frames not sent */
	uint32_t frames_out;		/* media frames encoded toward this leg */
	uint32_t plc_frames;		/* concealment / comfort-noise frames run on this leg's decoder */
	uint32_t dtmf_events;		/* events received on this leg */
	uint32_t dtmf_dropped;		/* digits meant for this leg that were not played: queue overflow, direction, no te pt / remote */
	uint32_t ka_pkts;		/* keep-alive NO_DATA frames sent (also counted in tx_pkts) */
	uint64_t last_rx_ms;		/* mono_ms() of the last accepted packet, 0 = never */
	int amr_mode;			/* current AMR encoder mode, -1 if not AMR */
	bool running;
	/* PCM device leg (rx_pkts / last_rx_ms count capture periods, tx_pkts the uplink periods written, frames_out the peer frames queued) */
	uint32_t pcm_xrun_rx;		/* capture overruns (recovered) */
	uint32_t pcm_xrun_tx;		/* playback underruns (recovered) */
	uint32_t pcm_ul_drop;		/* peer frames dropped: queue over its high mark (peer clock faster than the modem's) */
	uint32_t pcm_ul_fill;		/* silence frames inserted although the peer was talking: queue ran dry (peer slower / jitter) */
	uint32_t pcm_ul_idle;		/* silence frames written while the peer sent nothing (hold, silence suppression, no media yet) */
	uint32_t pcm_ul_full;		/* uplink periods the device did not take (buffer full) */
	uint32_t pcm_err;		/* other device errors */
	uint32_t pcm_ul_depth;		/* current queue depth in frames */
	bool pcm_lost;			/* BR_EV_PCM_LOST was raised */
};

struct bridge_stats {
	struct bridge_leg_stats leg[2];
};

/* Copy of the latest snapshot (taken by the media thread after every batch of packets). 0, or -1 for a NULL bridge. */
int bridge_get_stats(struct bridge *b, struct bridge_stats *out);
#endif
