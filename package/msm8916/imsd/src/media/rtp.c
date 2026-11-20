/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "rtp.h"
#include "../util/sys.h"

int rtp_parse(const uint8_t *b, size_t len, struct rtp_pkt *o)
{
	size_t off = RTP_HDR_MIN, end = len;

	if (len < RTP_HDR_MIN || (b[0] >> 6) != RTP_VERSION)
		return -1;
	o->h.version = RTP_VERSION;
	o->h.padding = b[0] & 0x20;
	o->h.extension = b[0] & 0x10;
	o->h.cc = b[0] & 0x0f;
	o->h.marker = b[1] & 0x80;
	o->h.pt = b[1] & 0x7f;
	o->h.seq = (uint16_t)(b[2] << 8 | b[3]);
	o->h.ts = (uint32_t)b[4] << 24 | (uint32_t)b[5] << 16 | (uint32_t)b[6] << 8 | b[7];
	o->h.ssrc = (uint32_t)b[8] << 24 | (uint32_t)b[9] << 16 | (uint32_t)b[10] << 8 | b[11];
	off += (size_t)o->h.cc * 4;
	if (off > len)
		return -1;
	if (o->h.extension) {
		size_t xl;

		if (off + 4 > len)
			return -1;
		xl = ((size_t)b[off + 2] << 8 | b[off + 3]) * 4;
		off += 4 + xl;
		if (off > len)
			return -1;
	}
	if (o->h.padding) {
		size_t pad = b[len - 1];

		if (pad == 0 || off + pad > len)
			return -1;
		end = len - pad;
	}
	o->payload = b + off;
	o->plen = end - off;
	return 0;
}

int rtp_build(uint8_t *out, size_t outsz, bool marker, uint8_t pt, uint16_t seq,
	      uint32_t ts, uint32_t ssrc, const void *payload, size_t plen)
{
	if (pt > 127 || plen > outsz || outsz - plen < RTP_HDR_MIN)
		return -1;
	out[0] = RTP_VERSION << 6;
	out[1] = (uint8_t)((marker ? 0x80 : 0) | pt);
	out[2] = (uint8_t)(seq >> 8);
	out[3] = (uint8_t)seq;
	out[4] = (uint8_t)(ts >> 24);
	out[5] = (uint8_t)(ts >> 16);
	out[6] = (uint8_t)(ts >> 8);
	out[7] = (uint8_t)ts;
	out[8] = (uint8_t)(ssrc >> 24);
	out[9] = (uint8_t)(ssrc >> 16);
	out[10] = (uint8_t)(ssrc >> 8);
	out[11] = (uint8_t)ssrc;
	if (plen)
		memcpy(out + RTP_HDR_MIN, payload, plen);
	return (int)(RTP_HDR_MIN + plen);
}

void rtp_tx_init(struct rtp_tx *t)
{
	memset(t, 0, sizeof(*t));
	t->ssrc = rnd32();
	t->seq = (uint16_t)rnd32();
	t->ts = rnd32();
	t->last_ts = t->ts;
}

uint16_t rtp_tx_next(struct rtp_tx *t, uint32_t ts, size_t octets)
{
	t->last_ts = ts;
	t->packets++;
	t->octets += octets;
	return t->seq++;
}

void rtp_stats_init(struct rtp_stats *s)
{
	memset(s, 0, sizeof(*s));
}

uint32_t rtp_stats_rx(struct rtp_stats *s, uint16_t seq, uint32_t ts, uint32_t ssrc,
		      size_t octets, uint64_t now_ms, uint32_t clock_hz)
{
	uint32_t missing = 0;

	s->received++;
	s->rx_octets += octets;
	s->last_rx_ms = now_ms;
	if (!s->seen || ssrc != s->ssrc) {
		/* first packet, or the far end restarted its stream: new base */
		s->seen = true;
		s->ssrc = ssrc;
		s->base_seq = s->max_seq = seq;
		s->cycles = 0;
		s->have_transit = false;
		s->received = 1;
		s->dups_or_late = 0;
		return 0;
	}
	{
		int d = rtp_seq_diff(seq, s->max_seq);

		if (d > 0) {
			if (seq < s->max_seq)
				s->cycles += 0x10000;
			missing = (uint32_t)(d - 1);
			s->max_seq = seq;
		} else {
			s->dups_or_late++;
			return 0;
		}
	}
	if (clock_hz) {
		int64_t arr = (int64_t)(now_ms * clock_hz / 1000);
		int64_t tr = arr - (int64_t)ts, dd;

		if (s->have_transit) {
			dd = tr - s->transit;
			if (dd < 0)
				dd = -dd;
			/* J += (|D| - J) / 16 with J kept << 4 */
			s->jitter += (uint32_t)(dd - (int64_t)((s->jitter + 8) >> 4));
		}
		s->transit = tr;
		s->have_transit = true;
	}
	return missing;
}

uint32_t rtp_stats_ext_max(const struct rtp_stats *s)
{
	return s->cycles + s->max_seq;
}

uint32_t rtp_stats_lost(const struct rtp_stats *s)
{
	uint32_t expected;

	if (!s->seen)
		return 0;
	expected = rtp_stats_ext_max(s) - s->base_seq + 1;
	return expected > s->received - s->dups_or_late ? expected - (s->received - s->dups_or_late) : 0;
}
