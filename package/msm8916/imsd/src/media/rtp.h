/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MEDIA_RTP_H
#define IMSD_MEDIA_RTP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * RTP (RFC 3550) header parsing / building and a tiny statistics block.
 *
 * RTCP is NOT implemented in this phase.  The carrier advertises b=RS/RR, so
 * it may expect SR/RR eventually.  The intended attachment point: a leg's
 * UDP socket pair (RTP port N, RTCP port N+1) gets a second fd handled by
 * the media thread; struct rtp_stats already carries everything an RTCP
 * receiver report needs (extended highest seq, cumulative lost, interarrival
 * jitter, last-rx time) and struct rtp_tx carries what a sender report needs
 * (ssrc, packet and octet counts, last rtp timestamp).
 *
 * All functions are reentrant; none allocates.
 */

#define RTP_HDR_MIN 12
#define RTP_VERSION 2

struct rtp_hdr {
	uint8_t version;	/* always 2 for a parsed packet */
	bool padding;
	bool extension;
	bool marker;
	uint8_t cc;		/* CSRC count */
	uint8_t pt;		/* 0..127 */
	uint16_t seq;
	uint32_t ts;
	uint32_t ssrc;
};

struct rtp_pkt {
	struct rtp_hdr h;
	const uint8_t *payload;	/* points into the caller's buffer; padding and header extension already removed */
	size_t plen;
};

/*
 * Parse a datagram.  Checks version 2, CSRC list, header extension and
 * padding bounds; the payload is what remains after those.  Returns 0 or -1
 * (too short, wrong version, lengths run past the packet, padding count 0 or
 * larger than the payload).  An empty payload is valid (plen == 0).
 */
int rtp_parse(const uint8_t *buf, size_t len, struct rtp_pkt *out);

/*
 * Build a plain header (no padding/extension/CSRC) followed by payload.
 * Returns the datagram length or -1 if outsz is too small / pt > 127.
 */
int rtp_build(uint8_t *out, size_t outsz, bool marker, uint8_t pt, uint16_t seq,
	      uint32_t ts, uint32_t ssrc, const void *payload, size_t plen);

/* signed distance a - b for 16-bit sequence numbers (RFC 3550 wraparound) */
static inline int rtp_seq_diff(uint16_t a, uint16_t b)
{
	return (int16_t)(uint16_t)(a - b);
}

/* signed distance a - b for 32-bit timestamps */
static inline int32_t rtp_ts_diff(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b);
}

/*
 * Outgoing stream state: one SSRC, continuous seq / timestamp.  The first
 * packet after rtp_tx_init() carries the marker bit by convention of the
 * caller (see rtp_tx_next).
 */
struct rtp_tx {
	uint32_t ssrc;
	uint16_t seq;		/* seq of the NEXT packet */
	uint32_t ts;		/* timestamp of the NEXT media packet */
	uint32_t last_ts;	/* timestamp used by the last packet (sender report) */
	uint64_t packets, octets;
};

/* random ssrc, seq and ts (RFC 3550 sec. 5.1) */
void rtp_tx_init(struct rtp_tx *t);
/* seq of the packet about to be sent; consumes it and updates the counters */
uint16_t rtp_tx_next(struct rtp_tx *t, uint32_t ts, size_t payload_octets);

/* Receive statistics (RFC 3550 appendix A.1 / A.8, simplified, no probation). */
struct rtp_stats {
	bool seen;
	uint16_t base_seq, max_seq;
	uint32_t cycles;		/* upper 16 bits of the extended seq */
	uint32_t received;		/* packets accepted */
	uint64_t rx_octets;		/* payload + header bytes */
	uint64_t last_rx_ms;		/* caller supplied clock of the last packet */
	uint32_t jitter;		/* RFC 3550 interarrival jitter, in RTP clock units << 4 */
	uint32_t ssrc;			/* last seen ssrc */
	uint32_t dups_or_late;		/* packets older than max_seq (not counted in jitter) */
	int64_t transit;
	bool have_transit;
};

void rtp_stats_init(struct rtp_stats *s);
/*
 * Account one received packet.  clock_hz is the RTP clock rate of the stream
 * (jitter units).  Returns the number of packets missing between this packet
 * and the previous highest one (0 for in-order / late / duplicate packets).
 */
uint32_t rtp_stats_rx(struct rtp_stats *s, uint16_t seq, uint32_t ts, uint32_t ssrc,
		      size_t octets, uint64_t now_ms, uint32_t clock_hz);
/* extended highest sequence number received */
uint32_t rtp_stats_ext_max(const struct rtp_stats *s);
/* cumulative packets lost (expected - received, never negative) */
uint32_t rtp_stats_lost(const struct rtp_stats *s);
#endif
