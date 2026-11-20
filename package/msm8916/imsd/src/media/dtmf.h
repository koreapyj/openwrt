/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MEDIA_DTMF_H
#define IMSD_MEDIA_DTMF_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * RFC 4733 telephone-event payload, a decoder that turns a received packet
 * stream into key down / key up and a generator that plays queued digits out
 * as a fresh, handset-like packet stream on the other leg (possibly with a
 * different telephone-event clock).  The two are deliberately decoupled: the
 * generator is driven by the caller's own 20 ms timing, never by the arrival
 * of input packets, so a source that announces a whole event in one burst
 * (or two events 200 ms apart) still produces events a mobile network's media
 * gateway accepts.  No in-band tone generation or detection.  No allocation,
 * no I/O: the caller passes the clock in (virtual time in the unit tests).
 */

struct dtmf_event {
	uint8_t event;		/* 0-9 digits, 10 '*', 11 '#', 12-15 A-D, 16 flash */
	bool end;		/* E bit */
	uint8_t volume;		/* 0..63 (dBm0, positive magnitude) */
	uint16_t duration;	/* in RTP clock units of the stream the event came from / goes to */
};

/* 4 bytes payload (extra bytes, e.g. several events, are ignored). 0 or -1 if len < 4. */
int dtmf_parse(const uint8_t *p, size_t len, struct dtmf_event *ev);
/* writes 4 bytes */
void dtmf_build(uint8_t out[4], const struct dtmf_event *ev);
/* '0'..'9','*','#','A'..'D', 'F' for flash, '?' otherwise */
char dtmf_event_char(uint8_t event);

/* One output packet of the generator. */
struct dtmf_pkt {
	struct dtmf_event ev;	/* duration in the destination te clock */
	uint32_t ts;		/* event start timestamp (destination timeline, destination te clock) */
	bool marker;		/* set on the first packet of an event */
};

#define DTMF_END_REPEAT 3	/* RFC 4733 sec. 2.5.1.4: the final packet is sent three times */
#define DTMF_STEP_MS 20		/* packet interval of the generator */
#define DTMF_VOLUME 10		/* volume of events we originate (-10 dBm0) */

/* ------------------------------------------------------------------ decoder */

#define DTMF_F_START 1u		/* first packet of a new event: key down */
#define DTMF_F_UPDATE 2u	/* the packet carries a (new) duration for the event */
#define DTMF_F_END 4u		/* the event ended with this packet: key up */

struct dtmf_in {
	uint8_t event;
	uint8_t volume;
	uint32_t dur_ms;	/* announced duration so far, in ms (source clock converted) */
};

/*
 * Decoder state for the events arriving on ONE leg.  An event is identified by
 * (event code, source start timestamp): the same RTP timestamp is the same
 * event, a new one starts a new event (a still-active previous event whose end
 * was lost is simply replaced).  A start packet that is lost is tolerated (the
 * first packet seen is the start).  The source's own end retransmissions of an
 * event already closed are swallowed.
 */
struct dtmf_dec {
	uint32_t clock;
	bool active;		/* an event is in progress (no end seen yet) */
	bool ended;		/* last event finished; its end retransmissions are being swallowed */
	uint8_t event, volume;
	uint32_t src_ts;
	uint32_t last_ms_dur;	/* announced duration of the last packet, ms */
	uint64_t last_ms;	/* time of the last packet of the active event */
};

void dtmf_dec_init(struct dtmf_dec *d, uint32_t clock);
/* Feed one parsed packet.  Returns DTMF_F_* (0: swallowed duplicate) and fills *in. */
unsigned dtmf_dec_feed(struct dtmf_dec *d, uint32_t src_ts, const struct dtmf_event *ev, uint64_t now_ms, struct dtmf_in *in);
/* If an event has been active with no packet for idle_ms, close it: returns DTMF_F_END and fills *in, else 0. */
unsigned dtmf_dec_idle(struct dtmf_dec *d, uint64_t now_ms, uint64_t idle_ms, struct dtmf_in *in);

/* ------------------------------------------------------------------ generator */

#define DTMF_Q_MAX 32		/* queued digits per destination leg */
#define DTMF_HOLD_STALE_MS 100	/* a held key whose packets stopped this long ago is released */

#define DTMF_G_START 1u		/* the packet returned opens an event (its ts is the event start) */
#define DTMF_G_END1 2u		/* first end packet of the event */
#define DTMF_G_DONE 4u		/* last end packet of the event: the event is complete */

#define DTMF_SRC_PEER 0		/* digit decoded from the other leg's packets */
#define DTMF_SRC_API 1		/* digit from bridge_send_dtmf */

struct dtmf_q {
	uint8_t event, volume, src;
	bool closed;		/* key up seen */
	uint32_t ann_ms;	/* announced / requested duration so far */
	uint64_t last_ms;	/* last time the source said anything about the key */
};

/*
 * Generator for ONE destination leg: a FIFO of digits and the state of the
 * event being played (always queue entry 0).
 *
 * Playing a digit: packet k (k = 0, 1, ...) goes out at start + 20 ms * k, the
 * first with the marker bit, the duration field being (k+1) * clock/50 (RFC
 * 4733 sec. 2.5.1.2: duration is cumulative, timestamp fixed at the event
 * start, one packet per packetisation interval).  The event ends at the first
 * k whose elapsed time 20 ms * k has reached the target, with the last
 * duration sent (so the announced duration equals the wall-clock length).
 * Target = max(announced, min_ms), at most max_ms (also at most what the 16 bit
 * duration field holds).  A key still held (no key up) is extended beyond the
 * target while its packets keep arriving (DTMF_HOLD_STALE_MS), up to max_ms.
 * End: three identical end packets 20 ms apart, the same interval as the
 * updates (RFC 2833 sec. 3.6 / RFC 4733 sec. 2.5.1.4); the first one is sent at
 * the nominal end of the event.  The next digit starts at the nominal end +
 * pause_ms, but never before the last end packet + 20 ms (events never
 * overlap on the wire).
 */
struct dtmf_gen {
	uint32_t clock, step;	/* te clock; duration units per 20 ms */
	uint32_t min_ms, pause_ms, max_ms;	/* policy (max_ms already limited to the 16 bit field) */
	struct dtmf_q q[DTMF_Q_MAX];
	unsigned head, cnt;
	int state;		/* 0 idle, 1 sending updates, 2 sending end packets */
	uint32_t ts, k, dur;
	unsigned end_sent;
	uint64_t next_ms, nominal_end, gate;
	uint32_t dropped;	/* digits discarded: queue overflow or flush */
	uint32_t played;	/* events completed */
};

/* min_ms is raised to 20, max_ms 0 means 2000 */
void dtmf_gen_init(struct dtmf_gen *g, uint32_t clock, uint32_t min_ms, uint32_t pause_ms, uint32_t max_ms);
/*
 * Key down: queue a digit (an unclosed digit of the same src is closed first).  When the queue is full the oldest digit
 * that has not started is dropped and counted.
 */
void dtmf_gen_down(struct dtmf_gen *g, int src, uint8_t event, uint8_t volume, uint32_t dur_ms, uint64_t now_ms);
/* the key is still down, announced duration dur_ms (ignored when no such digit is queued) */
void dtmf_gen_hold(struct dtmf_gen *g, int src, uint8_t event, uint32_t dur_ms, uint64_t now_ms);
/* key up with the announced duration */
void dtmf_gen_up(struct dtmf_gen *g, int src, uint8_t event, uint32_t dur_ms, uint64_t now_ms);
/* discard everything including the running event (counted as dropped); returns the number of digits */
unsigned dtmf_gen_flush(struct dtmf_gen *g);
/*
 * Advance the generator.  ts_now is the destination audio timeline in the te clock (used when an event starts).
 * Returns 1 and fills *out when a packet is due now (call again until 0: a late tick catches up), else 0.
 * *flags gets DTMF_G_*.
 */
int dtmf_gen_tick(struct dtmf_gen *g, uint64_t now_ms, uint32_t ts_now, struct dtmf_pkt *out, unsigned *flags);
/* an event is on the wire (updates or end packets): the audio of the leg is replaced meanwhile */
bool dtmf_gen_active(const struct dtmf_gen *g);
/* active or digits waiting */
bool dtmf_gen_busy(const struct dtmf_gen *g);
/* absolute time of the next packet, 0 when idle with an empty queue */
uint64_t dtmf_gen_due(const struct dtmf_gen *g);
#endif
