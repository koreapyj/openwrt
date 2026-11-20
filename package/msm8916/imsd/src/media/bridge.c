/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Media bridge, see bridge.h for the API and the threading model.
 *
 * BEHAVIOUR (all decisions are per input packet, nothing is buffered):
 *
 *  Loss.  A sequence gap on the input is passed on as loss, not repaired: the
 *    decoder of the source leg runs its concealment once per lost frame (up to
 *    MAX_PLC, output discarded; keeps the AMR/Opus predictor state sane), and
 *    the destination's RTP sequence number and timestamp are advanced by the
 *    number of lost frames without sending anything, so the far end sees the
 *    same gap and applies its own PLC.  The lost-frame count comes from the
 *    timestamp jump (ts delta minus the duration of the previous packet),
 *    falling back to the sequence gap.  Re-encoding concealed audio would
 *    cost CPU and make the far end's PLC see "good" frames full of artefacts.
 *    (If the destination is a PCM sink the concealed frames ARE delivered so a
 *    recording keeps its timeline.)
 *
 *  Silence gaps.  A timestamp jump with contiguous sequence numbers means the
 *    sender stopped (DTX / silence suppression).  If the last frame we
 *    received was an AMR SID/NO_DATA frame the gap is up to DTX_FILL_MAX
 *    frames long, the decoder is fed "no data" for each missing frame: it
 *    produces comfort noise from the last SID, which is encoded and sent, so
 *    the far end keeps getting a continuous 20 ms stream (simplest robust
 *    choice; AMR DTX produces a SID every 160 ms and clients without DTX
 *    handling would otherwise hear gating).  Any other gap (client phone with
 *    silence suppression, longer DTX pause) is not filled: nothing is sent,
 *    the destination timestamp advances by the gap and the next packet gets
 *    the RTP marker bit.  SID and NO_DATA frames themselves are decoded like
 *    any frame (comfort noise) and the PCM is re-encoded toward the peer.
 *    An AMR encoder with DTX enabled that answers NO_DATA produces no packet
 *    (timestamp advances, marker is set on the next one); SID frames go out.
 *
 *  Marker bit.  Set on the first media packet after (re)start, after a gap
 *    that was not filled, after hold, after an SSRC change of the source; never
 *    on loss gaps.  Telephone-event packets carry the marker on the first
 *    packet of an event only.
 *
 *  Timestamps.  Each leg owns its SSRC, sequence number and timestamp.  The
 *    timestamp advances by the codec's ts-per-frame (AMR-NB 160, AMR-WB 320,
 *    PCMA 160, G.722 160 (RTP clock 8000 although audio is 16 kHz), Opus 960
 *    (RTP clock 48000 regardless of the internal PCM rate)) for each frame sent.
 *    Telephone events use the leg's timeline scaled to the te clock rate.
 *
 *  Hold.  While forwarding toward a leg is not allowed, input is still parsed
 *    and tracked, but not decoded or sent; the destination timeline moves on
 *    by the input duration and the marker is set when sending resumes.
 *
 *  Opus packets of other durations than 20 ms (2.5..120 ms) are accepted:
 *    decoded PCM goes through a per-leg accumulator and is encoded in 20 ms
 *    frames.
 *
 *  DTMF.  Telephone events are NOT relayed packet by packet.  The events arriving on a leg are decoded
 *    into key down / key up (dtmf_dec) and queued as digits on the other leg's generator (dtmf_gen),
 *    which plays each digit as a fresh handset-like event driven by the media thread's own 20 ms timing:
 *    marker on the first packet, an update every 20 ms with a growing duration, three end packets,
 *    then an inter-digit pause (see dtmf.h for the exact timing and the cfg dtmf_* knobs).  A source that
 *    announces a whole event in one burst, or presses keys faster than a mobile network's media gateway
 *    accepts, therefore still produces well formed, non-overlapping events.  bridge_send_dtmf feeds the
 *    same generator.  While an event is on the wire the leg's audio is not sent (RFC 4733 sec. 2.3: the
 *    event replaces the audio for its duration; sequence numbers stay continuous, the audio timeline keeps
 *    running, the first audio packet afterwards carries the marker bit like after any other gap) and
 *    keep-alives are held back.  Digits that cannot be sent (direction, no te payload type, no remote) are
 *    dropped and counted (bridge_leg_stats.dtmf_dropped).
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include "amr.h"
#include "bridge.h"
#include "dtmf.h"
#include "resample.h"
#include "rtp.h"
#include "../util/log.h"
#include "../util/sys.h"

#define RX_BUF 2048
#define PCM_MAX 3072		/* decode scratch (samples) */
#define ACC_MAX 4096		/* per-leg pending PCM (samples) */
#define MAX_PLC 8
#define DTX_FILL_MAX 16
#define MAX_READS 16		/* packets served per fd per wakeup */
#define MAX_CMDS 32		/* commands applied per wakeup */
#define DTMF_IDLE_MS 400
#define TICK_MS 100
#define CMD_RING 256
#define EV_RING 256
#define FAST_TICK_MS 10		/* epoll timeout while a keep-alive or DTMF generator is active */
#define KA_GRACE_MS 200		/* after real media was sent: wait this long before keep-alive starts */
#define KA_FAST_MS 2000		/* keep-alive pace is 20 ms for this long after start / after the last real packet ... */
#define KA_SLOW_MS 160		/* ... and this afterwards */
#define DTMF_TX_MIN_MS 40
#define DTMF_TX_MAX_MS 5000
#define PD_RING 8		/* PCM device leg: uplink frame queue (frames of up to PCMDEV_MAX_FRAMES samples) */
#define PD_HIGH 5		/* above this many queued frames the oldest is dropped (100 ms of latency at most) */
#define PD_PRIME 2		/* after the queue ran dry: wait for this many frames before playing again (jitter margin) */
#define PD_PER_WAKE 4		/* capture periods served per wakeup */
#define PD_MAX_ERRS 5		/* consecutive non-fatal device errors before the device counts as lost */

struct leg {
	struct bridge *br;
	int idx;
	struct br_leg_cfg cfg;
	struct codec *codec;	/* NULL for a PCM leg */
	bool is_amr;
	enum amr_type amr_t;
	uint16_t modeset;
	int pcm_rate, frame_samples, clock, ts_inc;
	uint32_t te_clock;
	struct addr remote;
	bool remote_valid;
	bool registered;	/* in epoll */

	/* transmit */
	struct rtp_tx tx;
	bool tx_init;
	bool marker_pending;
	/* pipeline INTO this leg: peer PCM -> resample -> accumulate -> encode */
	struct resamp rs;
	int rs_mode;		/* 0 none, 1 up2, 2 down2 */
	int16_t acc[ACC_MAX];
	size_t acc_n;
	/* receive */
	struct rtp_stats rx;
	bool in_have, in_last_dtx;
	uint32_t in_ssrc, in_ts;
	uint16_t in_seq;
	int64_t in_dur;		/* duration of the previous packet in source ticks */
	uint64_t start_ms, last_rx_ms;
	bool first_rx_sent, timeout_fired;
	struct dtmf_dec dec;	/* decoder of the events arriving on this leg */
	struct bridge_leg_stats st;
	/* keep-alive (UDP AMR leg with cfg.keepalive): see ka_tick */
	uint64_t ka_next;	/* when the next NO_DATA frame is due */
	uint64_t ka_ref;	/* last real packet sent toward this leg (or start / resume) */
	uint64_t ka_tl;		/* wall time that tx.ts corresponds to */
	bool ka_real;		/* a real packet was sent since ka_ref was reset */
	uint32_t ka_credit;	/* frames of timeline already consumed by keep-alive frames */
	/* DTMF generated toward this leg (events from the peer leg and bridge_send_dtmf) */
	struct dtmf_gen gen;
	uint32_t ev_ts0;	/* audio timeline (codec clock) at the start of the event being played */
	/* PCM leg */
	FILE *play, *rec;
	bool rec_wav, play_done;
	uint32_t rec_bytes;
	uint64_t next_due;
	long play_off;		/* start of the sample data in the play file */
	uint32_t play_total, play_left;	/* WAV data bytes (0 total: until EOF) */
	/* PCM device leg */
	void *pd;		/* open device, NULL when closed / lost */
	int pd_fd;		/* capture fd in the epoll set */
	int16_t pd_ring[PD_RING][PCMDEV_MAX_FRAMES];
	unsigned pd_head, pd_n, pd_errs;
	bool pd_primed;
	uint64_t pd_last_push;
};

enum bstate { BS_CREATED, BS_RUNNING, BS_STOPPED };

struct bridge {
	void *user;
	enum bstate state;
	struct leg leg[2];
	struct bridge *next;
	bool dirty, dead;
	pthread_mutex_t stat_mu;
	struct bridge_stats snap;
};

enum cmd_type { CMD_ADD, CMD_SET_LEG, CMD_SET_REMOTE, CMD_SET_DIR, CMD_DTMF, CMD_START, CMD_STOP, CMD_DESTROY, CMD_QUIT };

struct cmd {
	enum cmd_type t;
	struct bridge *br;
	int leg;
	union {
		struct br_leg_cfg cfg;
		struct addr addr;
		int dir;
		struct { uint8_t event; uint32_t ms; } dtmf;
	} u;
};

static struct {
	bool running;
	pthread_t th;
	int ep, cmd_fd, ev_fd;
	pthread_mutex_t cmd_mu, ev_mu;
	struct cmd *cmds;
	unsigned c_head, c_cnt;
	struct br_event *evs;
	unsigned e_head, e_cnt;
	struct bridge *all, *dead;
	unsigned tmo;		/* epoll timeout (ms): shortened to the next keep-alive / DTMF deadline */
	/* scratch for the per-packet path: only the media thread uses these */
	uint8_t rxbuf[RX_BUF], txbuf[RX_BUF], enc[1400];
	int16_t dec[PCM_MAX], rs_buf[2 * RS_MAX_IN + 8], fr[PCM_MAX];
} E = { .tmo = TICK_MS / 2, .cmd_mu = PTHREAD_MUTEX_INITIALIZER, .ev_mu = PTHREAD_MUTEX_INITIALIZER, .ep = -1, .cmd_fd = -1, .ev_fd = -1 };

static int n_alive;		/* bridges created and not yet destroyed by the main thread (bridge_count) */
static const int ep_cmd_tag;	/* address used as epoll data for the command eventfd */

/* ------------------------------------------------------------------ helpers */

static bool leg_can_rx(const struct leg *l)
{
	return l->cfg.dir == BR_SENDRECV || l->cfg.dir == BR_RECVONLY;
}

static bool leg_can_tx(const struct leg *l)
{
	return l->cfg.dir == BR_SENDRECV || l->cfg.dir == BR_SENDONLY;
}

static bool leg_is_pcm(const struct leg *l)
{
	return l->cfg.kind == BR_LEG_PCM || l->cfg.kind == BR_LEG_PCMDEV;
}

/*
 * KEEP-ALIVE (cfg.keepalive on a UDP AMR / AMR-WB leg).  Only a leg that may be sent to (SENDRECV or
 * SENDONLY), has a remote and runs is served; RECVONLY / INACTIVE legs get nothing, as always.  When
 * nothing real went out toward the leg, an AMR NO_DATA frame (FT 15, no marker, in the negotiated
 * octet-aligned / bandwidth-efficient layout) is sent from the leg's own RTP state: every 20 ms from
 * the start (or from a resume / remote change) for KA_FAST_MS, every KA_SLOW_MS afterwards.  After real
 * media (transcoded audio, DTMF) the generator waits KA_GRACE_MS, then restarts the 20 ms pace for
 * another KA_FAST_MS.  Timestamps follow the wall clock (ka_tl is the time tx.ts stands for), so a slow
 * frame carries a timestamp that has advanced by the silent time; sequence numbers stay contiguous.
 * Frames of timeline that keep-alives already consumed (ka_credit) are subtracted when the audio
 * pipeline accounts a gap, so real audio resumes without a doubled timestamp jump.
 */
static bool ka_eligible(const struct leg *l)
{
	return l->cfg.keepalive && l->cfg.kind == BR_LEG_UDP && l->is_amr && l->remote_valid && l->registered &&
	       leg_can_tx(l) && !dtmf_gen_busy(&l->gen);
}

static void ka_reset(struct leg *l, uint64_t now)
{
	l->ka_ref = l->ka_tl = l->ka_next = now;
	l->ka_real = false;
	l->ka_credit = 0;
}

/* a real packet (audio, DTMF) went out toward l */
static void leg_real_tx(struct leg *l)
{
	uint64_t now;

	if (!l->cfg.keepalive)
		return;
	now = mono_ms();
	l->ka_ref = now;
	l->ka_real = true;
	l->ka_next = now + KA_GRACE_MS;
	l->ka_tl = now + 20;
	l->ka_credit = 0;
}

/* timeline of l was advanced by one frame without sending (encoder DTX) */
static void ka_tl_touch(struct leg *l)
{
	if (l->cfg.keepalive)
		l->ka_tl = mono_ms() + 20;
}

/* timeline frames already covered by keep-alives that a gap of n frames may use up; returns the rest */
static unsigned ka_absorb(struct leg *l, unsigned n)
{
	unsigned c = l->ka_credit < n ? l->ka_credit : n;

	l->ka_credit -= c;
	return n - c;
}

void br_leg_cfg_default(struct br_leg_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->kind = BR_LEG_NONE;
	c->dir = BR_SENDRECV;
	c->fd = -1;
	c->amr_cmr_tx = AMR_CMR_NONE;
	c->te_pt = -1;
	c->dtmf_min_ms = 100;
	c->dtmf_pause_ms = 60;
	c->dtmf_max_ms = 2000;
	c->pcm_rate = 16000;
	codec_params_default(&c->cp);
}

static void push_event(const struct br_event *ev)
{
	pthread_mutex_lock(&E.ev_mu);
	if (E.e_cnt < EV_RING) {
		E.evs[(E.e_head + E.e_cnt) % EV_RING] = *ev;
		E.e_cnt++;
	}
	pthread_mutex_unlock(&E.ev_mu);
	if (E.ev_fd >= 0) {
		uint64_t one = 1;

		if (write(E.ev_fd, &one, sizeof(one)) < 0) { /* counter full: reader will wake anyway */ }
	}
}

static void ev_err(struct bridge *br, enum br_event_type t, int leg, const char *msg, int err)
{
	struct br_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = t;
	ev.br = br;
	ev.user = br->user;
	ev.leg = leg;
	ev.err = err;
	if (msg)
		str_copy(ev.msg, msg, sizeof(ev.msg));
	push_event(&ev);
}

static void ev_simple(struct bridge *br, enum br_event_type t, int leg, const char *msg)
{
	ev_err(br, t, leg, msg, 0);
}

static int leg_native_rate(const struct br_leg_cfg *c)
{
	switch (c->kind) {
	case BR_LEG_PCM:
	case BR_LEG_PCMDEV:
		return c->pcm_rate;
	case BR_LEG_UDP:
		switch (c->codec) {
		case CODEC_AMRNB:
		case CODEC_PCMA:
			return 8000;
		case CODEC_AMRWB:
		case CODEC_G722:
			return 16000;
		default:
			return c->cp.pcm_rate;	/* opus; 0 = decide from the peer */
		}
	default:
		return 0;
	}
}

/* ------------------------------------------------------------------ PCM helpers */

static uint32_t get_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/*
 * Open the play file.  A file starting with "RIFF....WAVE" must be 16-bit mono PCM at the leg's
 * pcm_rate (the fmt chunk is checked, the data chunk size bounds what is played, other chunks are
 * skipped); anything else is read as raw s16le mono at pcm_rate.  Returns NULL or an error text.
 */
static const char *wav_open_play(struct leg *l, const char *path)
{
	uint8_t h[12], ck[8], fmt[16];
	bool have_fmt = false;
	FILE *f = fopen(path, "rb");

	if (!f)
		return "cannot open play file";
	l->play_total = l->play_left = 0;
	if (fread(h, 1, 12, f) == 12 && !memcmp(h, "RIFF", 4)) {
		if (memcmp(h + 8, "WAVE", 4)) {
			fclose(f);
			return "play file: RIFF but not WAVE";
		}
		for (;;) {
			uint32_t sz;

			if (fread(ck, 1, 8, f) != 8) {
				fclose(f);
				return have_fmt ? "play wav: no data chunk" : "play wav: no fmt chunk";
			}
			sz = get_le32(ck + 4);
			if (!memcmp(ck, "fmt ", 4)) {
				unsigned tag, ch, bits;
				uint32_t rate;
				const char *err = NULL;

				if (sz < 16 || fread(fmt, 1, 16, f) != 16) {
					fclose(f);
					return "play wav: bad fmt chunk";
				}
				tag = (unsigned)(fmt[0] | fmt[1] << 8);
				ch = (unsigned)(fmt[2] | fmt[3] << 8);
				rate = get_le32(fmt + 4);
				bits = (unsigned)(fmt[14] | fmt[15] << 8);
				if (tag != 1 && tag != 0xfffe)
					err = "play wav: not PCM";
				else if (ch != 1)
					err = "play wav: not mono";
				else if (bits != 16)
					err = "play wav: not 16-bit";
				else if (rate != (uint32_t)l->cfg.pcm_rate)
					err = "play wav: rate != pcm_rate";
				if (err) {
					fclose(f);
					return err;
				}
				have_fmt = true;
				if (fseek(f, (long)(((sz - 16) + 1) & ~1u), SEEK_CUR) < 0) {
					fclose(f);
					return "play wav: truncated";
				}
				continue;
			}
			if (!memcmp(ck, "data", 4)) {
				if (!have_fmt) {
					fclose(f);
					return "play wav: data before fmt";
				}
				if (sz != 0xffffffffu)
					l->play_total = l->play_left = sz;	/* 0: streamed file, play to EOF */
				break;
			}
			if (fseek(f, (long)((sz + 1) & ~1u), SEEK_CUR) < 0) {
				fclose(f);
				return "play wav: truncated";
			}
		}
		l->play_off = ftell(f);
	} else {
		rewind(f);	/* raw s16le */
		l->play_off = 0;
	}
	l->play = f;
	return NULL;
}

static void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void wav_header(uint8_t h[44], int rate, uint32_t bytes)
{
	memcpy(h, "RIFF", 4);
	put_le32(h + 4, 36 + bytes);
	memcpy(h + 8, "WAVEfmt ", 8);
	put_le32(h + 16, 16);
	h[20] = 1; h[21] = 0; h[22] = 1; h[23] = 0;
	put_le32(h + 24, (uint32_t)rate);
	put_le32(h + 28, (uint32_t)rate * 2);
	h[32] = 2; h[33] = 0; h[34] = 16; h[35] = 0;
	memcpy(h + 36, "data", 4);
	put_le32(h + 40, bytes);
}

static void pd_close(struct leg *l)
{
	if (l->pd && l->cfg.pdev_ops)
		l->cfg.pdev_ops->close(l->pd);
	l->pd = NULL;
	l->pd_fd = -1;
	l->pd_n = l->pd_head = 0;
}

static void pcm_close(struct leg *l)
{
	if (l->play)
		fclose(l->play);
	l->play = NULL;
	if (l->rec) {
		if (l->rec_wav) {
			uint8_t h[44];

			wav_header(h, l->pcm_rate, l->rec_bytes);
			if (fseek(l->rec, 0, SEEK_SET) == 0 && fwrite(h, 1, 44, l->rec) != 44)
				LOGW("media: wav header write failed");
		}
		fclose(l->rec);
	}
	l->rec = NULL;
}

/* ------------------------------------------------------------------ send side */

static void leg_send(struct leg *l, const uint8_t *pkt, size_t n)
{
	ssize_t r = sendto(l->cfg.fd, pkt, n, MSG_DONTWAIT, (const struct sockaddr *)&l->remote.sa, sizeof(l->remote.sa));

	if (r < 0) {
		l->st.tx_err++;
	} else {
		l->st.tx_pkts++;
		l->st.tx_bytes += (uint64_t)r;
	}
}

/* a peer frame for the PCM device: queued, played one per capture period (pcmdev_rx) */
static void pd_push(struct leg *l, const int16_t *pcm)
{
	if (!l->pd)
		return;
	if (l->pd_n >= PD_HIGH) {		/* peer clock ahead of the modem: drop the oldest frame */
		l->pd_head = (l->pd_head + 1) % PD_RING;
		l->pd_n--;
		l->st.pcm_ul_drop++;
	}
	memcpy(l->pd_ring[(l->pd_head + l->pd_n) % PD_RING], pcm, (size_t)l->frame_samples * sizeof(int16_t));
	l->pd_n++;
	l->pd_last_push = mono_ms();
	if (!l->pd_primed && l->pd_n >= PD_PRIME)
		l->pd_primed = true;
}

/* one 20 ms frame of PCM at this leg's rate goes out */
static void leg_emit_frame(struct leg *l, const int16_t *pcm)
{
	int n;
	const uint8_t *pl;
	size_t plen;
	struct amr_frame fr;
	int len;

	l->st.frames_out++;
	if (dtmf_gen_active(&l->gen) && l->cfg.kind == BR_LEG_UDP) {	/* a DTMF event owns the stream: no audio meanwhile */
		l->tx.ts += (uint32_t)l->ts_inc;
		l->marker_pending = true;
		return;
	}
	if (l->cfg.kind == BR_LEG_PCMDEV) {
		pd_push(l, pcm);
		return;
	}
	if (l->cfg.kind == BR_LEG_PCM) {
		if (l->cfg.pcm_sink)
			l->cfg.pcm_sink(l->cfg.pcm_arg, pcm, (size_t)l->frame_samples);
		if (l->rec) {
			if (fwrite(pcm, 2, (size_t)l->frame_samples, l->rec) == (size_t)l->frame_samples)
				l->rec_bytes += (uint32_t)l->frame_samples * 2;
		}
		return;
	}
	if (!l->remote_valid) {
		l->st.tx_err++;
		return;
	}
	n = codec_encode(l->codec, pcm, E.enc, sizeof(E.enc));
	if (n < 0) {
		l->st.tx_err++;
		return;
	}
	if (n == 0) {
		l->tx.ts += (uint32_t)l->ts_inc;
		l->marker_pending = true;
		ka_tl_touch(l);
		return;
	}
	if (l->is_amr) {
		if (amr_frame_from_storage(l->amr_t, &fr, E.enc, (size_t)n) < 0) {
			l->st.tx_err++;
			return;
		}
		if (fr.ft == AMR_FT_NO_DATA) {	/* DTX: nothing to send */
			l->tx.ts += (uint32_t)l->ts_inc;
			l->marker_pending = true;
			ka_tl_touch(l);
			return;
		}
		len = amr_build(l->amr_t, l->cfg.amr_oa, (unsigned)l->cfg.amr_cmr_tx, &fr, 1, E.txbuf + RTP_HDR_MIN,
				sizeof(E.txbuf) - RTP_HDR_MIN);
		if (len < 0) {
			l->st.tx_err++;
			return;
		}
		pl = E.txbuf + RTP_HDR_MIN;
		plen = (size_t)len;
	} else {
		pl = E.enc;
		plen = (size_t)n;
	}
	{
		uint16_t seq = rtp_tx_next(&l->tx, l->tx.ts, plen);
		int tl = rtp_build(E.txbuf, sizeof(E.txbuf), l->marker_pending, l->cfg.pt, seq, l->tx.ts, l->tx.ssrc,
				   pl, plen);	/* memmove-safe: pl may point at txbuf+12 == destination of the copy */

		l->marker_pending = false;
		l->tx.ts += (uint32_t)l->ts_inc;
		if (tl > 0) {
			leg_send(l, E.txbuf, (size_t)tl);
			leg_real_tx(l);
		}
	}
}

/* PCM from the peer (at src_rate) -> this leg's rate -> frames -> out */
static void leg_push_pcm(struct leg *l, const int16_t *pcm, size_t n, int src_rate)
{
	while (n) {
		size_t chunk = n > RS_MAX_IN ? RS_MAX_IN : n;
		const int16_t *p = pcm;
		int m;

		if (l->rs_mode == 1 && src_rate < l->pcm_rate) {
			m = resamp_up2(&l->rs, pcm, chunk, E.rs_buf);
			p = E.rs_buf;
		} else if (l->rs_mode == 2 && src_rate > l->pcm_rate) {
			chunk &= ~(size_t)1;
			if (!chunk)
				return;
			m = resamp_down2(&l->rs, pcm, chunk, E.rs_buf);
			p = E.rs_buf;
		} else {
			m = (int)chunk;
		}
		if (m < 0 || l->acc_n + (size_t)m > ACC_MAX) {
			l->st.tx_err++;
			return;
		}
		memcpy(l->acc + l->acc_n, p, (size_t)m * sizeof(int16_t));
		l->acc_n += (size_t)m;
		pcm += chunk;
		n -= chunk;
	}
	while (l->acc_n >= (size_t)l->frame_samples) {
		size_t fs = (size_t)l->frame_samples;

		memcpy(E.fr, l->acc, fs * sizeof(int16_t));
		l->acc_n -= fs;
		memmove(l->acc, l->acc + fs, l->acc_n * sizeof(int16_t));
		leg_emit_frame(l, E.fr);
	}
}

static void send_events(struct leg *dst, const struct dtmf_pkt *o, int n)
{
	uint8_t pl[4];
	int i, tl;

	for (i = 0; i < n; i++) {
		uint16_t seq;

		dtmf_build(pl, &o[i].ev);
		seq = rtp_tx_next(&dst->tx, o[i].ts, 4);
		tl = rtp_build(E.txbuf, sizeof(E.txbuf), o[i].marker, (uint8_t)dst->cfg.te_pt, seq, o[i].ts, dst->tx.ssrc, pl, 4);
		if (tl > 0) {
			leg_send(dst, E.txbuf, (size_t)tl);
			leg_real_tx(dst);
		}
	}
}

static void dtmf_notify(struct leg *src, uint8_t event, bool end, uint32_t duration_ms)
{
	struct br_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = BR_EV_DTMF;
	ev.br = src->br;
	ev.user = src->br->user;
	ev.leg = src->idx;
	ev.digit = dtmf_event_char(event);
	ev.end = end;
	ev.duration_ms = duration_ms;
	push_event(&ev);
}

/* ------------------------------------------------------------------ audio forwarding */

/* may digits be played toward l? */
static bool leg_dtmf_ok(const struct leg *l)
{
	return l->cfg.kind == BR_LEG_UDP && l->cfg.te_pt >= 0 && l->remote_valid && leg_can_tx(l) &&
	       l->br->state == BS_RUNNING;
}

/* a decoded event of src (DTMF_F_* flags): tell the main thread, queue / update / release the digit on dst */
static void dtmf_apply(struct leg *src, struct leg *dst, unsigned flags, const struct dtmf_in *in, uint64_t now)
{
	if (flags & DTMF_F_START) {
		src->st.dtmf_events++;
		dtmf_notify(src, in->event, false, 0);
	}
	if (flags & DTMF_F_END)
		dtmf_notify(src, in->event, true, in->dur_ms);
	if (!leg_dtmf_ok(dst)) {
		if ((flags & DTMF_F_START) && dst->cfg.kind != BR_LEG_PCMDEV)	/* toward a PCM device the digit is the main loop's (BR_EV_DTMF) */
			dst->st.dtmf_dropped++;
		return;
	}
	if (flags & DTMF_F_START)
		dtmf_gen_down(&dst->gen, DTMF_SRC_PEER, in->event, in->volume, in->dur_ms, now);
	else if (!(flags & DTMF_F_END))
		dtmf_gen_hold(&dst->gen, DTMF_SRC_PEER, in->event, in->dur_ms, now);
	if (flags & DTMF_F_END)
		dtmf_gen_up(&dst->gen, DTMF_SRC_PEER, in->event, in->dur_ms, now);
}

static void forward_dtmf(struct leg *src, struct leg *dst, const struct rtp_pkt *p, uint64_t now)
{
	struct dtmf_event ev;
	struct dtmf_in in;
	unsigned flags;

	if (dtmf_parse(p->payload, p->plen, &ev) < 0) {
		src->st.rx_bad++;
		return;
	}
	flags = dtmf_dec_feed(&src->dec, p->h.ts, &ev, now, &in);
	if (flags)
		dtmf_apply(src, dst, flags, &in, now);
}

static void plc_one(struct leg *src, struct leg *dst, bool push)
{
	int n = codec_decode(src->codec, NULL, 0, E.dec, PCM_MAX);

	src->st.plc_frames++;
	if (n > 0 && push)
		leg_push_pcm(dst, E.dec, (size_t)n, src->pcm_rate);
}

/*
 * Track sequence / timestamp continuity of the source.  Returns -1 to drop the
 * packet (duplicate / late), else 0 with *fill = number of comfort-noise frames
 * to synthesise before the real frames.
 */
static int gap_account(struct leg *src, struct leg *dst, const struct rtp_pkt *p, bool fwd, unsigned *fill)
{
	int sd, inc = src->ts_inc;
	int32_t delta;
	int64_t extra;
	unsigned ef = 0, lost, i;

	*fill = 0;
	if (!src->in_have || p->h.ssrc != src->in_ssrc) {
		if (src->in_have)
			dst->marker_pending = true;
		src->in_have = true;
		src->in_ssrc = p->h.ssrc;
		src->in_last_dtx = false;
		return 0;
	}
	sd = rtp_seq_diff(p->h.seq, src->in_seq);
	if (sd <= 0) {
		src->st.rx_dropped++;
		return -1;
	}
	delta = rtp_ts_diff(p->h.ts, src->in_ts);
	extra = (int64_t)delta - src->in_dur;
	if (delta <= 0 || extra >= 1000 * (int64_t)inc) {
		dst->marker_pending = true;	/* timestamps restarted: resync, no advance */
		return 0;
	}
	if (extra > 0)
		ef = (unsigned)((extra + inc / 2) / inc);
	if (sd > 1) {
		lost = ef ? ef : (unsigned)(sd - 1);
		if (lost > 1000)
			lost = 1000;
		if (fwd) {
				for (i = 0; i < lost && i < MAX_PLC; i++)
					plc_one(src, dst, leg_is_pcm(dst));
			if (dst->cfg.kind == BR_LEG_UDP) {
				unsigned rem = ka_absorb(dst, lost);

				dst->tx.seq = (uint16_t)(dst->tx.seq + rem);
				dst->tx.ts += rem * (uint32_t)dst->ts_inc;
			}
		}
	} else if (ef) {
		if (fwd && src->in_last_dtx && ef <= DTX_FILL_MAX) {
			*fill = ka_absorb(dst, ef);
		} else if (fwd) {
			dst->tx.ts += ka_absorb(dst, ef) * (uint32_t)dst->ts_inc;
			dst->marker_pending = true;
		}
	}
	return 0;
}

static void forward_audio(struct leg *src, struct leg *dst, const struct rtp_pkt *p)
{
	struct amr_pdu pdu;
	unsigned nfr = 1, fill, i;
	bool fwd = leg_can_tx(dst);
	int64_t dur = 0;

	if (src->is_amr) {
		if (amr_parse(src->amr_t, src->cfg.amr_oa, p->payload, p->plen, &pdu) < 0) {
			src->st.rx_bad++;
			return;
		}
		nfr = pdu.n;
		if (pdu.cmr != AMR_CMR_NONE)	/* CMR from the carrier steers OUR encoder toward the carrier */
			codec_set_mode(src->codec, amr_apply_cmr(src->amr_t, src->modeset, codec_get_mode(src->codec), pdu.cmr));
	} else if (p->plen == 0) {
		src->st.rx_bad++;
		return;
	}
	if (gap_account(src, dst, p, fwd, &fill) < 0)
		return;
	if (!fwd) {
		/* hold toward dst: keep its timeline running, send nothing */
		dst->tx.ts += nfr * (uint32_t)dst->ts_inc;
		dst->marker_pending = true;
		dur = (int64_t)nfr * src->ts_inc;
	} else {
		for (i = 0; i < fill; i++)
			plc_one(src, dst, true);
		if (src->is_amr) {
			for (i = 0; i < nfr; i++) {
				int n = codec_decode(src->codec, pdu.f[i].data, 1u + pdu.f[i].nbytes, E.dec, PCM_MAX);

				if (n <= 0) {
					src->st.rx_bad++;
					continue;
				}
				dur += src->ts_inc;
				leg_push_pcm(dst, E.dec, (size_t)n, src->pcm_rate);
			}
			src->in_last_dtx = amr_ft_is_dtx(src->amr_t, pdu.f[nfr - 1].ft);
		} else {
			int n = codec_decode(src->codec, p->payload, p->plen, E.dec, PCM_MAX);

			if (n <= 0) {
				src->st.rx_bad++;
			} else {
				dur = (int64_t)n * src->clock / src->pcm_rate;
				leg_push_pcm(dst, E.dec, (size_t)n, src->pcm_rate);
			}
		}
	}
	src->in_seq = p->h.seq;
	src->in_ts = p->h.ts;
	src->in_dur = dur ? dur : src->ts_inc;
}

/* ------------------------------------------------------------------ receive */

static void leg_rx(struct leg *l)
{
	struct bridge *br = l->br;
	struct leg *o = &br->leg[1 - l->idx];
	int i;

	for (i = 0; i < MAX_READS; i++) {
		struct sockaddr_in6 sa;
		socklen_t sl = sizeof(sa);
		struct rtp_pkt p;
		struct addr from;
		ssize_t r = recvfrom(l->cfg.fd, E.rxbuf, sizeof(E.rxbuf), MSG_DONTWAIT, (struct sockaddr *)&sa, &sl);
		uint64_t now;
		bool is_te, is_media;

		if (r < 0)
			break;
		br->dirty = true;
		if (sl < sizeof(sa) || sa.sin6_family != AF_INET6) {
			l->st.rx_dropped++;
			continue;
		}
		addr_from_sa6(&from, &sa);
		if (rtp_parse(E.rxbuf, (size_t)r, &p) < 0) {
			l->st.rx_bad++;
			continue;
		}
		is_te = l->cfg.te_pt >= 0 && p.h.pt == (uint8_t)l->cfg.te_pt;
		is_media = p.h.pt == l->cfg.pt;
		if (!is_te && !is_media) {
			l->st.rx_dropped++;
			continue;
		}
		if (!l->remote_valid) {
			if (!l->cfg.learn) {
				l->st.rx_dropped++;
				continue;
			}
			l->remote = from;
			l->remote_valid = true;
		} else if (!addr_equal(&from, &l->remote)) {
			if (!l->cfg.learn || !addr_equal_ip(&from, &l->remote)) {
				l->st.rx_dropped++;
				continue;
			}
			l->remote = from;
		}
		now = mono_ms();
		rtp_stats_rx(&l->rx, p.h.seq, p.h.ts, p.h.ssrc, (size_t)r, now, is_media ? (uint32_t)l->clock : 0);
		l->st.rx_pkts++;
		l->st.rx_bytes += (uint64_t)r;
		l->st.last_rx_ms = l->last_rx_ms = now;
		l->timeout_fired = false;
		if (!l->first_rx_sent) {
			l->first_rx_sent = true;
			ev_simple(br, BR_EV_FIRST_RX, l->idx, NULL);
		}
		if (!leg_can_rx(l)) {
			l->st.rx_dropped++;
			continue;
		}
		if (is_te) {
			/* the events share the source's sequence space with its audio: they are not lost audio frames */
			if (l->in_have && p.h.ssrc == l->in_ssrc && rtp_seq_diff(p.h.seq, l->in_seq) == 1)
				l->in_seq = p.h.seq;
			forward_dtmf(l, o, &p, now);
		} else if (o->cfg.kind != BR_LEG_NONE) {
			forward_audio(l, o, &p);
		}
	}
}

/* ------------------------------------------------------------------ PCM leg source */

/* up to fs samples of the play file into E.fr, honouring the WAV data size */
static size_t play_read(struct leg *l, size_t fs)
{
	size_t want = fs, n;

	if (l->play_total) {
		size_t avail = l->play_left / 2;

		if (want > avail)
			want = avail;
	}
	n = want ? fread(E.fr, 2, want, l->play) : 0;
	if (l->play_total)
		l->play_left -= (uint32_t)(n * 2);
	return n;
}

static void pcm_tick(struct leg *l, uint64_t now)
{
	struct leg *o = &l->br->leg[1 - l->idx];
	int k;

	for (k = 0; k < 3 && now >= l->next_due; k++) {
		size_t n = 0, fs = (size_t)l->frame_samples;

		l->next_due += 20;
		if (!leg_can_rx(l) || l->play_done)
			continue;
		if (!leg_can_tx(o))
			continue;
		if (l->cfg.pcm_src) {
			n = l->cfg.pcm_src(l->cfg.pcm_arg, E.fr, fs);
		} else if (l->play) {
			n = play_read(l, fs);
			if (n == 0 && l->cfg.play_loop) {
				if (fseek(l->play, l->play_off, SEEK_SET) == 0)
					l->play_left = l->play_total;
				n = play_read(l, fs);
			}
			if (n == 0) {
				l->play_done = true;
				ev_simple(l->br, BR_EV_PLAY_DONE, l->idx, NULL);
				continue;
			}
			if (n < fs)
				memset(E.fr + n, 0, (fs - n) * 2);
			n = fs;
		}
		if (n == 0) {
			if (o->cfg.kind == BR_LEG_UDP && !ka_eligible(o)) {	/* a keep-alive leg keeps its own timeline */
				o->tx.ts += (uint32_t)o->ts_inc;
				o->marker_pending = true;
			}
			continue;
		}
		l->br->dirty = true;
		l->st.rx_pkts++;
		leg_push_pcm(o, E.fr, n, l->pcm_rate);
	}
	if (now > l->next_due + 200)
		l->next_due = now;
}

/* ------------------------------------------------------------------ PCM device leg */

static void pd_lost(struct leg *l, int err)
{
	if (l->registered && l->pd_fd >= 0)
		epoll_ctl(E.ep, EPOLL_CTL_DEL, l->pd_fd, NULL);
	l->registered = false;
	pd_close(l);
	l->st.pcm_lost = true;
	l->br->dirty = true;
	LOGW("media: PCM device lost on leg %d (%s)", l->idx, strerror(err < 0 ? -err : err));
	ev_err(l->br, BR_EV_PCM_LOST, l->idx, "pcm device lost", err);
}

static bool pd_fatal(int r)
{
	return r == -ENODEV || r == -ENOENT || r == -EBADF || r == -ENXIO;
}

/* one uplink period per downlink period; false when the device was lost */
static bool pd_uplink(struct leg *l)
{
	const struct br_pcmdev_ops *op = l->cfg.pdev_ops;
	unsigned fs = (unsigned)l->frame_samples;
	int16_t f[PCMDEV_MAX_FRAMES];
	int r, tries;

	if (l->pd_n && l->pd_primed) {
		memcpy(f, l->pd_ring[l->pd_head], fs * sizeof(int16_t));
		l->pd_head = (l->pd_head + 1) % PD_RING;
		l->pd_n--;
	} else {
		memset(f, 0, fs * sizeof(int16_t));
		if (l->pd_primed) {		/* the queue ran dry: wait for a little margin before playing again */
			l->pd_primed = false;
			if (mono_ms() - l->pd_last_push < 100)
				l->st.pcm_ul_fill++;
			else
				l->st.pcm_ul_idle++;
		} else if (l->pd_n == 0 && mono_ms() - l->pd_last_push < 100) {
			l->st.pcm_ul_fill++;	/* still refilling after an underrun */
		} else {
			l->st.pcm_ul_idle++;
		}
	}
	for (tries = 0; tries < 2; tries++) {
		r = op->write(l->pd, f, fs);
		if (r == -EPIPE) {
			l->st.pcm_xrun_tx++;
			continue;
		}
		break;
	}
	if (r >= 0) {
		l->st.tx_pkts++;
		l->st.tx_bytes += (uint64_t)r * 2;
		if ((unsigned)r < fs)
			l->st.pcm_ul_full++;
	} else if (r == -EAGAIN) {
		l->st.pcm_ul_full++;
	} else if (r == -EPIPE) {
		l->st.tx_err++;
	} else if (pd_fatal(r)) {
		pd_lost(l, r);
		return false;
	} else {
		l->st.pcm_err++;
		l->st.tx_err++;
	}
	return true;
}

/* the capture stream has data: serve up to PD_PER_WAKE periods (media thread, from epoll) */
static void pcmdev_rx(struct leg *l)
{
	struct bridge *br = l->br;
	struct leg *o = &br->leg[1 - l->idx];
	const struct br_pcmdev_ops *op = l->cfg.pdev_ops;
	unsigned fs = (unsigned)l->frame_samples;
	int k;

	for (k = 0; k < PD_PER_WAKE && l->pd; k++) {
		int r = op->read(l->pd, E.fr, fs);
		uint64_t now;

		if (r == 0)
			break;
		br->dirty = true;
		if (r == -EPIPE) {
			l->st.pcm_xrun_rx++;
			continue;
		}
		if (r < 0) {
			if (pd_fatal(r) || ++l->pd_errs >= PD_MAX_ERRS) {
				pd_lost(l, pd_fatal(r) ? r : -EIO);
				return;
			}
			l->st.pcm_err++;
			break;
		}
		l->pd_errs = 0;
		now = mono_ms();
		l->st.rx_pkts++;
		l->st.rx_bytes += (uint64_t)r * 2;
		l->st.last_rx_ms = l->last_rx_ms = now;
		l->timeout_fired = false;
		if (!l->first_rx_sent) {
			l->first_rx_sent = true;
			ev_simple(br, BR_EV_FIRST_RX, l->idx, NULL);
		}
		if (leg_can_rx(l) && leg_can_tx(o))
			leg_push_pcm(o, E.fr, fs, l->pcm_rate);
		if (!pd_uplink(l))
			return;
	}
	l->st.pcm_ul_depth = l->pd_n;
}

/* ------------------------------------------------------------------ bridge lifecycle (media thread) */

static void snapshot(struct bridge *br)
{
	int i;
	struct bridge_stats s;

	for (i = 0; i < 2; i++) {
		struct leg *l = &br->leg[i];

		s.leg[i] = l->st;
		s.leg[i].dtmf_dropped += l->gen.dropped;
		s.leg[i].rx_lost = rtp_stats_lost(&l->rx);
		s.leg[i].rx_jitter = l->rx.jitter >> 4;
		s.leg[i].amr_mode = l->codec ? codec_get_mode(l->codec) : -1;
		s.leg[i].running = br->state == BS_RUNNING;
		s.leg[i].pcm_ul_depth = l->pd_n;
	}
	pthread_mutex_lock(&br->stat_mu);
	br->snap = s;
	pthread_mutex_unlock(&br->stat_mu);
	br->dirty = false;
}

static void bridge_halt(struct bridge *br, bool notify, bool close_fds)
{
	int i;

	/* idempotent: also used to unwind a failed start; own_fd sockets are closed only when the bridge is destroyed */
	br->state = BS_STOPPED;
	for (i = 0; i < 2; i++) {
		struct leg *l = &br->leg[i];

		if (l->registered)
			epoll_ctl(E.ep, EPOLL_CTL_DEL, l->cfg.kind == BR_LEG_PCMDEV ? l->pd_fd : l->cfg.fd, NULL);
		l->registered = false;
		pd_close(l);
		if (close_fds && l->cfg.kind == BR_LEG_UDP && l->cfg.own_fd && l->cfg.fd >= 0) {
			close(l->cfg.fd);
			l->cfg.fd = -1;
		}
		pcm_close(l);
		codec_destroy(l->codec);
		l->codec = NULL;
	}
	snapshot(br);
	if (notify)
		ev_simple(br, BR_EV_STOPPED, 0, NULL);
}

static void bridge_fail_e(struct bridge *br, const char *msg, int err)
{
	LOGE("media: bridge start failed: %s%s%s", msg, err ? ": " : "", err ? strerror(err) : "");
	bridge_halt(br, false, false);
	ev_err(br, BR_EV_ERROR, 0, msg, err);
}

static void bridge_fail(struct bridge *br, const char *msg)
{
	bridge_fail_e(br, msg, 0);
}

static void bridge_begin(struct bridge *br)
{
	int rate[2], i;
	uint64_t now = mono_ms();

	if (br->state == BS_RUNNING)
		return;
	for (i = 0; i < 2; i++) {
		struct br_leg_cfg *c = &br->leg[i].cfg;

		if (c->kind == BR_LEG_NONE)
			return bridge_fail(br, "leg not configured");
		if (c->kind == BR_LEG_UDP && c->fd < 0)
			return bridge_fail(br, "leg has no socket");
		if (c->kind == BR_LEG_UDP && !codec_available(c->codec))
			return bridge_fail(br, "codec not available");
		if ((c->kind == BR_LEG_PCM || c->kind == BR_LEG_PCMDEV) && c->pcm_rate != 8000 && c->pcm_rate != 16000)
			return bridge_fail(br, "bad pcm rate");
		if (c->kind == BR_LEG_PCMDEV && !c->pdev_ops)
			return bridge_fail(br, "pcm device leg has no ops");
		rate[i] = leg_native_rate(c);
	}
	for (i = 0; i < 2; i++) {
		if (rate[i] == 0)
			rate[i] = rate[1 - i] ? rate[1 - i] : 16000;	/* opus follows its peer */
		if (rate[i] != 8000 && rate[i] != 16000 && rate[i] != 12000 && rate[i] != 24000 && rate[i] != 48000)
			return bridge_fail(br, "bad pcm rate");
	}
	if (rate[0] != rate[1] && rate[0] != 2 * rate[1] && rate[1] != 2 * rate[0])
		return bridge_fail(br, "unsupported sample rate conversion");
	for (i = 0; i < 2; i++) {
		struct leg *l = &br->leg[i];
		struct codec_params cp = l->cfg.cp;

		l->br = br;
		l->idx = i;
		l->pcm_rate = rate[i];
		l->frame_samples = rate[i] / 50;
		/* resampler INTO this leg: peer rate -> this rate */
		l->rs_mode = 0;
		if (rate[1 - i] < rate[i])
			l->rs_mode = 1;
		else if (rate[1 - i] > rate[i])
			l->rs_mode = 2;
		resamp_init(&l->rs);
		l->acc_n = 0;
		l->codec = NULL;
		l->is_amr = false;
		if (l->cfg.kind == BR_LEG_UDP) {
			cp.pcm_rate = rate[i];
			l->codec = codec_create(l->cfg.codec, &cp);
			if (!l->codec)
				return bridge_fail(br, "codec create failed");
			l->clock = codec_rtp_clock(l->codec);
			l->ts_inc = codec_ts_per_frame(l->codec);
			l->frame_samples = codec_frame_samples(l->codec);
			l->is_amr = l->cfg.codec == CODEC_AMRNB || l->cfg.codec == CODEC_AMRWB;
			l->amr_t = l->cfg.codec == CODEC_AMRWB ? AMR_WB : AMR_NB;
			l->modeset = cp.modeset ? cp.modeset : (l->is_amr ? amr_modeset_all(l->amr_t) : 0);
			if (l->is_amr && (l->cfg.amr_cmr_tx < 0 || l->cfg.amr_cmr_tx > 15))
				l->cfg.amr_cmr_tx = AMR_CMR_NONE;
			l->te_clock = l->cfg.te_clock ? l->cfg.te_clock : (uint32_t)l->clock;
			l->remote = l->cfg.remote;
			l->remote_valid = l->cfg.has_remote;
		} else {
			l->clock = rate[i];
			l->ts_inc = l->frame_samples;
			l->te_clock = (uint32_t)l->clock;
		}
		if (!l->tx_init) {
			rtp_tx_init(&l->tx);
			l->tx_init = true;
		}
		l->marker_pending = true;
		rtp_stats_init(&l->rx);
		memset(&l->st, 0, sizeof(l->st));
		l->in_have = false;
		l->in_dur = 0;
		l->in_last_dtx = false;
		l->first_rx_sent = l->timeout_fired = false;
		l->start_ms = l->last_rx_ms = now;
		ka_reset(l, now);
		l->play_done = false;
		l->rec_bytes = 0;
		l->next_due = now + 20;
		l->pd = NULL;
		l->pd_fd = -1;
		l->pd_head = l->pd_n = l->pd_errs = 0;
		l->pd_primed = false;
		l->pd_last_push = 0;
	}
	for (i = 0; i < 2; i++) {
		struct leg *l = &br->leg[i];

		dtmf_dec_init(&l->dec, l->te_clock);
		dtmf_gen_init(&l->gen, l->te_clock, l->cfg.dtmf_min_ms, l->cfg.dtmf_pause_ms, l->cfg.dtmf_max_ms);
		if (l->cfg.kind == BR_LEG_PCM) {
			if (l->cfg.play_path[0]) {
				const char *err = wav_open_play(l, l->cfg.play_path);

				if (err)
					return bridge_fail(br, err);
			}
			if (l->cfg.rec_path[0]) {
				size_t n = strlen(l->cfg.rec_path);

				l->rec = fopen(l->cfg.rec_path, "wb");
				if (!l->rec)
					return bridge_fail(br, "cannot open record file");
				l->rec_wav = n > 4 && !strcasecmp(l->cfg.rec_path + n - 4, ".wav");
				if (l->rec_wav) {
					uint8_t h[44];

					wav_header(h, l->pcm_rate, 0);
					if (fwrite(h, 1, 44, l->rec) != 44)
						return bridge_fail(br, "record file write failed");
				}
			}
		} else if (l->cfg.kind == BR_LEG_PCMDEV) {
			struct epoll_event ee = { .events = EPOLLIN, .data.ptr = l };

			errno = 0;
			l->pd = l->cfg.pdev_ops->open(l->cfg.pdev_spec, (unsigned)l->pcm_rate, (unsigned)l->frame_samples);
			if (!l->pd)
				return bridge_fail_e(br, "pcm device open failed", errno ? errno : EIO);
			l->pd_fd = l->cfg.pdev_ops->poll_fd(l->pd);
			if (l->pd_fd < 0 || epoll_ctl(E.ep, EPOLL_CTL_ADD, l->pd_fd, &ee) < 0)
				return bridge_fail_e(br, "pcm device epoll failed", errno ? errno : EIO);
			l->registered = true;
		} else {
			struct epoll_event ee = { .events = EPOLLIN, .data.ptr = l };

			if (epoll_ctl(E.ep, EPOLL_CTL_ADD, l->cfg.fd, &ee) < 0)
				return bridge_fail(br, "epoll_ctl failed");
			l->registered = true;
		}
	}
	br->state = BS_RUNNING;
	br->dirty = true;
}

/* ------------------------------------------------------------------ periodic work */

static void wake_by(uint64_t due, uint64_t now)
{
	unsigned ms = due > now ? (unsigned)(due - now) : 1;

	if (ms < 1)
		ms = 1;
	if (ms < E.tmo)
		E.tmo = ms;
}

static void ka_tick(struct leg *l, uint64_t now)
{
	struct amr_frame fr;
	int len, tl;
	int64_t elapsed;
	unsigned k;
	uint16_t seq;
	bool fast;

	if (!ka_eligible(l))
		return;
	if (now < l->ka_next) {
		wake_by(l->ka_next, now);
		return;
	}
	memset(&fr, 0, sizeof(fr));
	fr.ft = AMR_FT_NO_DATA;
	amr_frame_finish(&fr);
	len = amr_build(l->amr_t, l->cfg.amr_oa, (unsigned)l->cfg.amr_cmr_tx, &fr, 1, E.txbuf + RTP_HDR_MIN,
			sizeof(E.txbuf) - RTP_HDR_MIN);
	if (len < 0)
		return;
	elapsed = (int64_t)(now - l->ka_tl);
	k = elapsed > 0 ? (unsigned)(elapsed / 20) : 0;
	if (k > 1000)
		k = 1000;
	l->tx.ts += k * (uint32_t)l->ts_inc;
	seq = rtp_tx_next(&l->tx, l->tx.ts, (size_t)len);
	tl = rtp_build(E.txbuf, sizeof(E.txbuf), false, l->cfg.pt, seq, l->tx.ts, l->tx.ssrc,
		       E.txbuf + RTP_HDR_MIN, (size_t)len);
	l->tx.ts += (uint32_t)l->ts_inc;
	l->ka_tl += (uint64_t)(k + 1) * 20;
	l->ka_credit += k + 1;
	if (tl > 0) {
		leg_send(l, E.txbuf, (size_t)tl);
		l->st.ka_pkts++;
	}
	l->br->dirty = true;
	fast = now - l->ka_ref < (uint64_t)KA_FAST_MS + (l->ka_real ? KA_GRACE_MS : 0);
	l->ka_next = fast ? l->ka_tl : now + KA_SLOW_MS;
	wake_by(l->ka_next, now);
}

/*
 * Play out the digits queued toward l: packets are due on the generator's own 20 ms schedule.  The event
 * start timestamp is the leg's audio timeline at that moment; when the first end packet goes out the
 * timeline is moved past the end of the event if the (suppressed) audio has not got there yet, and audio
 * resumes with the marker bit once the last end packet is out.
 */
static void gen_service(struct leg *l, uint64_t now)
{
	uint64_t due;
	int i;

	if (!dtmf_gen_busy(&l->gen))
		return;
	if (!leg_dtmf_ok(l)) {
		if (dtmf_gen_flush(&l->gen))
			l->marker_pending = true;
		l->br->dirty = true;
		return;
	}
	for (i = 0; i < 4; i++) {
		struct dtmf_pkt pkt;
		unsigned fl;
		uint32_t ts_now = l->clock ? (uint32_t)((uint64_t)l->tx.ts * l->te_clock / (uint32_t)l->clock) : l->tx.ts;

		if (!dtmf_gen_tick(&l->gen, now, ts_now, &pkt, &fl))
			break;
		if (fl & DTMF_G_START)
			l->ev_ts0 = l->tx.ts;
		send_events(l, &pkt, 1);
		if (fl & DTMF_G_END1) {
			uint32_t end_ts = l->ev_ts0 + (uint32_t)((uint64_t)pkt.ev.duration * (uint32_t)l->clock / l->te_clock);

			if (rtp_ts_diff(end_ts, l->tx.ts) > 0)
				l->tx.ts = end_ts;
		}
		if (fl & DTMF_G_DONE)
			l->marker_pending = true;
		l->br->dirty = true;
	}
	due = dtmf_gen_due(&l->gen);
	if (due)
		wake_by(due, now);
}

static void bridge_tick(struct bridge *br, uint64_t now)
{
	int i;

	for (i = 0; i < 2; i++) {	/* events whose end packets never came: close them before the generators run */
		struct leg *l = &br->leg[i];
		struct dtmf_in in;

		if (l->cfg.kind == BR_LEG_UDP && dtmf_dec_idle(&l->dec, now, DTMF_IDLE_MS, &in)) {
			dtmf_apply(l, &br->leg[1 - i], DTMF_F_END, &in, now);
			br->dirty = true;
		}
	}
	for (i = 0; i < 2; i++) {
		struct leg *l = &br->leg[i];

		if (l->cfg.kind == BR_LEG_PCM) {
			pcm_tick(l, now);
			continue;
		}
		if (l->cfg.kind == BR_LEG_PCMDEV) {	/* stalled capture stream: the rx timeout below reports it */
			if (l->cfg.rx_timeout_ms && !l->timeout_fired && l->pd && now - l->last_rx_ms >= l->cfg.rx_timeout_ms) {
				l->timeout_fired = true;
				ev_simple(br, BR_EV_RX_TIMEOUT, i, NULL);
			}
			continue;
		}
		gen_service(l, now);
		ka_tick(l, now);
		if (l->cfg.rx_timeout_ms && !l->timeout_fired && leg_can_rx(l) &&
		    now - l->last_rx_ms >= l->cfg.rx_timeout_ms) {
			l->timeout_fired = true;
			ev_simple(br, BR_EV_RX_TIMEOUT, i, NULL);
		}
	}
	if (br->dirty)
		snapshot(br);
}

/* ------------------------------------------------------------------ commands */

static void bridge_free(struct bridge *br)
{
	pthread_mutex_destroy(&br->stat_mu);
	free(br);
}

static void list_remove(struct bridge **head, struct bridge *br)
{
	for (; *head; head = &(*head)->next) {
		if (*head == br) {
			*head = br->next;
			br->next = NULL;
			return;
		}
	}
}

static void apply_cmd(const struct cmd *c)
{
	struct bridge *br = c->br;

	switch (c->t) {
	case CMD_ADD:
		br->next = E.all;
		E.all = br;
		break;
	case CMD_SET_LEG:
		if (br->state == BS_RUNNING) {
			LOGW("media: set_leg on a running bridge ignored");
			break;
		}
		br->leg[c->leg].cfg = c->u.cfg;
		br->leg[c->leg].br = br;
		br->leg[c->leg].idx = c->leg;
		break;
	case CMD_SET_REMOTE:
		br->leg[c->leg].remote = c->u.addr;
		br->leg[c->leg].remote_valid = true;
		br->leg[c->leg].cfg.remote = c->u.addr;
		br->leg[c->leg].cfg.has_remote = true;
		ka_reset(&br->leg[c->leg], mono_ms());
		break;
	case CMD_DTMF:
		if (br->state == BS_RUNNING) {
			struct leg *l = &br->leg[c->leg];
			uint64_t now = mono_ms();

			if (leg_dtmf_ok(l)) {
				dtmf_gen_down(&l->gen, DTMF_SRC_API, c->u.dtmf.event, DTMF_VOLUME, c->u.dtmf.ms, now);
				dtmf_gen_up(&l->gen, DTMF_SRC_API, c->u.dtmf.event, c->u.dtmf.ms, now);
			} else {
				l->st.dtmf_dropped++;
				LOGW("media: dtmf not sent: leg %d cannot send telephone-event", l->idx);
			}
		}
		break;
	case CMD_SET_DIR: {
		struct leg *l = &br->leg[c->leg];
		enum br_dir d = (enum br_dir)c->u.dir;

		if (l->cfg.dir != d) {
			uint64_t now = mono_ms();

			l->cfg.dir = d;
			/* a hold toggle restarts the receive timer (no spurious BR_EV_RX_TIMEOUT after a long hold) */
			l->last_rx_ms = now;
			l->timeout_fired = false;
			ka_reset(l, now);
			if (!leg_can_tx(l) && dtmf_gen_flush(&l->gen))	/* queued digits are dropped (counted) */
				br->dirty = true;
			/* both pipelines touching this leg resync: new talkspurt, fresh gap tracking */
			l->in_have = false;
			l->marker_pending = true;
			br->leg[1 - c->leg].in_have = false;
			br->leg[1 - c->leg].marker_pending = true;
		}
		break;
	}
	case CMD_START:
		bridge_begin(br);
		break;
	case CMD_STOP:
		if (br->state == BS_RUNNING)
			bridge_halt(br, true, false);
		break;
	case CMD_DESTROY:
		bridge_halt(br, false, true);
		list_remove(&E.all, br);
		br->dead = true;
		br->next = E.dead;
		E.dead = br;
		ev_simple(br, BR_EV_DESTROYED, 0, NULL);
		break;
	case CMD_QUIT:
		break;
	}
}

static bool drain_commands(void)
{
	uint64_t cnt;
	int done = 0;
	bool quit = false;

	if (read(E.cmd_fd, &cnt, sizeof(cnt)) < 0) { /* EAGAIN: nothing pending */ }
	for (;;) {
		struct cmd *c;
		struct cmd local;

		if (done++ >= MAX_CMDS) {
			uint64_t one = 1;	/* more left: wake again after serving sockets */

			if (write(E.cmd_fd, &one, sizeof(one)) < 0) { /* nothing */ }
			break;
		}
		pthread_mutex_lock(&E.cmd_mu);
		if (!E.c_cnt) {
			pthread_mutex_unlock(&E.cmd_mu);
			break;
		}
		c = &E.cmds[E.c_head];
		memcpy(&local, c, sizeof(local));
		E.c_head = (E.c_head + 1) % CMD_RING;
		E.c_cnt--;
		pthread_mutex_unlock(&E.cmd_mu);
		if (local.t == CMD_QUIT)
			quit = true;
		else
			apply_cmd(&local);
	}
	return quit;
}

static int cmd_push(const struct cmd *c)
{
	uint64_t one = 1;

	if (!E.running) {
		errno = ENODEV;
		return -1;
	}
	pthread_mutex_lock(&E.cmd_mu);
	if (E.c_cnt >= CMD_RING) {
		pthread_mutex_unlock(&E.cmd_mu);
		errno = EAGAIN;
		return -1;
	}
	E.cmds[(E.c_head + E.c_cnt) % CMD_RING] = *c;
	E.c_cnt++;
	pthread_mutex_unlock(&E.cmd_mu);
	if (write(E.cmd_fd, &one, sizeof(one)) < 0) { /* counter saturated: thread is awake anyway */ }
	return 0;
}

/* ------------------------------------------------------------------ the thread */

static void *media_thread(void *arg)
{
	struct epoll_event evs[16];
	bool quit = false;
	struct sched_param sp = { .sched_priority = 5 };
	int rc;

	(void)arg;
	pthread_setname_np(pthread_self(), "imsd-media");
	rc = pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
	if (rc)
		LOGD("media: SCHED_FIFO not permitted (%d), normal priority", rc);
	while (!quit) {
		struct bridge *br, *nx;
		int n, i;
		uint64_t now;

		n = epoll_wait(E.ep, evs, 16, (int)E.tmo);
		if (n < 0 && errno != EINTR)
			n = 0;
		for (i = 0; i < n; i++) {
			if (evs[i].data.ptr == &ep_cmd_tag) {
				if (drain_commands())
					quit = true;
			} else {
				struct leg *l = evs[i].data.ptr;

				if (l->br->state == BS_RUNNING && l->registered) {
					if (l->cfg.kind == BR_LEG_PCMDEV)
						pcmdev_rx(l);
					else
						leg_rx(l);
				}
			}
		}
		now = mono_ms();
		E.tmo = TICK_MS / 2;
		for (br = E.all; br; br = br->next)
			if (br->state == BS_RUNNING)
				bridge_tick(br, now);
		for (br = E.dead; br; br = nx) {
			nx = br->next;
			bridge_free(br);
		}
		E.dead = NULL;
	}
	/* shutdown: apply what is left, then release everything */
	drain_commands();
	while (E.all) {
		struct bridge *br = E.all;

		bridge_halt(br, false, true);
		E.all = br->next;
		bridge_free(br);
	}
	while (E.dead) {
		struct bridge *br = E.dead;

		E.dead = br->next;
		bridge_free(br);
	}
	return NULL;
}

int bridge_engine_start(void)
{
	sigset_t all, old;
	struct epoll_event ee = { .events = EPOLLIN, .data.ptr = (void *)&ep_cmd_tag };

	if (E.running)
		return 0;
	E.cmds = calloc(CMD_RING, sizeof(*E.cmds));
	E.evs = calloc(EV_RING, sizeof(*E.evs));
	E.ep = epoll_create1(EPOLL_CLOEXEC);
	E.cmd_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	E.ev_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (!E.cmds || !E.evs || E.ep < 0 || E.cmd_fd < 0 || E.ev_fd < 0 ||
	    epoll_ctl(E.ep, EPOLL_CTL_ADD, E.cmd_fd, &ee) < 0)
		goto fail;
	E.c_head = E.c_cnt = E.e_head = E.e_cnt = 0;
	/* the media thread must not receive the daemon's signals */
	sigfillset(&all);
	pthread_sigmask(SIG_BLOCK, &all, &old);
	E.running = true;
	if (pthread_create(&E.th, NULL, media_thread, NULL)) {
		E.running = false;
		pthread_sigmask(SIG_SETMASK, &old, NULL);
		goto fail;
	}
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	return 0;
fail:
	free(E.cmds);
	free(E.evs);
	E.cmds = NULL;
	E.evs = NULL;
	if (E.ep >= 0)
		close(E.ep);
	if (E.cmd_fd >= 0)
		close(E.cmd_fd);
	if (E.ev_fd >= 0)
		close(E.ev_fd);
	E.ep = E.cmd_fd = E.ev_fd = -1;
	return -1;
}

void bridge_engine_stop(void)
{
	struct cmd c = { .t = CMD_QUIT };

	if (!E.running)
		return;
	while (cmd_push(&c) < 0)
		usleep(1000);
	pthread_join(E.th, NULL);
	E.running = false;
	__atomic_store_n(&n_alive, 0, __ATOMIC_RELAXED);
	close(E.ep);
	close(E.cmd_fd);
	close(E.ev_fd);
	E.ep = E.cmd_fd = E.ev_fd = -1;
	free(E.cmds);
	free(E.evs);
	E.cmds = NULL;
	E.evs = NULL;
}

bool bridge_engine_running(void)
{
	return E.running;
}

int bridge_event_fd(void)
{
	return E.ev_fd;
}

int bridge_events_dispatch(br_event_cb cb, void *arg)
{
	uint64_t cnt;
	int n = 0;

	if (!E.running)
		return 0;
	if (read(E.ev_fd, &cnt, sizeof(cnt)) < 0) { /* EAGAIN */ }
	for (;;) {
		struct br_event ev;

		pthread_mutex_lock(&E.ev_mu);
		if (!E.e_cnt) {
			pthread_mutex_unlock(&E.ev_mu);
			break;
		}
		ev = E.evs[E.e_head];
		E.e_head = (E.e_head + 1) % EV_RING;
		E.e_cnt--;
		pthread_mutex_unlock(&E.ev_mu);
		cb(arg, &ev);
		n++;
	}
	return n;
}

/* ------------------------------------------------------------------ main-thread API */

struct bridge *bridge_create(void *user)
{
	struct bridge *br;
	struct cmd c = { .t = CMD_ADD };
	int i;

	if (!E.running) {
		errno = ENODEV;
		return NULL;
	}
	br = calloc(1, sizeof(*br));
	if (!br)
		return NULL;
	pthread_mutex_init(&br->stat_mu, NULL);
	br->user = user;
	br->state = BS_CREATED;
	for (i = 0; i < 2; i++) {
		br_leg_cfg_default(&br->leg[i].cfg);
		br->leg[i].br = br;
		br->leg[i].idx = i;
		br->snap.leg[i].amr_mode = -1;
	}
	c.br = br;
	if (cmd_push(&c) < 0) {
		pthread_mutex_destroy(&br->stat_mu);
		free(br);
		return NULL;
	}
	__atomic_add_fetch(&n_alive, 1, __ATOMIC_RELAXED);
	return br;
}

int bridge_set_leg(struct bridge *b, int leg, const struct br_leg_cfg *cfg)
{
	struct cmd c = { .t = CMD_SET_LEG, .br = b, .leg = leg };

	if (!b || leg < 0 || leg > 1 || !cfg) {
		errno = EINVAL;
		return -1;
	}
	c.u.cfg = *cfg;
	return cmd_push(&c);
}

int bridge_set_remote(struct bridge *b, int leg, const struct addr *remote)
{
	struct cmd c = { .t = CMD_SET_REMOTE, .br = b, .leg = leg };

	if (!b || leg < 0 || leg > 1 || !remote) {
		errno = EINVAL;
		return -1;
	}
	c.u.addr = *remote;
	return cmd_push(&c);
}

int bridge_set_dir(struct bridge *b, int leg, enum br_dir dir)
{
	struct cmd c = { .t = CMD_SET_DIR, .br = b, .leg = leg };

	if (!b || leg < 0 || leg > 1 || (unsigned)dir > BR_INACTIVE) {
		errno = EINVAL;
		return -1;
	}
	c.u.dir = (int)dir;
	return cmd_push(&c);
}

static int simple_cmd(struct bridge *b, enum cmd_type t)
{
	struct cmd c = { .t = t, .br = b };

	if (!b) {
		errno = EINVAL;
		return -1;
	}
	return cmd_push(&c);
}

int bridge_send_dtmf(struct bridge *b, int to_leg, char digit, unsigned duration_ms)
{
	struct cmd c = { .t = CMD_DTMF, .br = b, .leg = to_leg };
	int ev;

	if (!b || to_leg < 0 || to_leg > 1) {
		errno = EINVAL;
		return -1;
	}
	if (digit >= '0' && digit <= '9')
		ev = digit - '0';
	else if (digit == '*')
		ev = 10;
	else if (digit == '#')
		ev = 11;
	else if (digit >= 'A' && digit <= 'D')
		ev = 12 + digit - 'A';
	else if (digit >= 'a' && digit <= 'd')
		ev = 12 + digit - 'a';
	else {
		errno = EINVAL;
		return -1;
	}
	if (!duration_ms)
		duration_ms = 160;
	if (duration_ms < DTMF_TX_MIN_MS)
		duration_ms = DTMF_TX_MIN_MS;
	if (duration_ms > DTMF_TX_MAX_MS)
		duration_ms = DTMF_TX_MAX_MS;
	c.u.dtmf.event = (uint8_t)ev;
	c.u.dtmf.ms = duration_ms;
	return cmd_push(&c);
}

int bridge_start(struct bridge *b) { return simple_cmd(b, CMD_START); }
int bridge_stop(struct bridge *b) { return simple_cmd(b, CMD_STOP); }
int bridge_destroy(struct bridge *b)
{
	int rc = simple_cmd(b, CMD_DESTROY);

	if (!rc)
		__atomic_sub_fetch(&n_alive, 1, __ATOMIC_RELAXED);
	return rc;
}

int bridge_count(void)
{
	return __atomic_load_n(&n_alive, __ATOMIC_RELAXED);
}

int bridge_get_stats(struct bridge *b, struct bridge_stats *out)
{
	if (!b || !out)
		return -1;
	pthread_mutex_lock(&b->stat_mu);
	*out = b->snap;
	pthread_mutex_unlock(&b->stat_mu);
	return 0;
}
