/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "../rtp.h"
#include "test.h"

void test_rtp(void)
{
	uint8_t b[64], pl[5] = { 1, 2, 3, 4, 5 };
	struct rtp_pkt p;
	int n;

	/* round trip */
	n = rtp_build(b, sizeof(b), true, 96, 65535, 0xfffffff0u, 0xdeadbeef, pl, sizeof(pl));
	CHECK(n == 17);
	CHECK(rtp_parse(b, (size_t)n, &p) == 0);
	CHECK(p.h.version == 2 && p.h.marker && p.h.pt == 96 && p.h.seq == 65535);
	CHECK(p.h.ts == 0xfffffff0u && p.h.ssrc == 0xdeadbeef && p.plen == 5 && !memcmp(p.payload, pl, 5));
	CHECK(!p.h.padding && !p.h.extension && p.h.cc == 0);
	CHECK(b[0] == 0x80 && b[1] == (0x80 | 96));
	/* empty payload */
	n = rtp_build(b, sizeof(b), false, 0, 1, 2, 3, NULL, 0);
	CHECK(n == 12 && rtp_parse(b, 12, &p) == 0 && p.plen == 0 && !p.h.marker);
	/* build limits */
	CHECK(rtp_build(b, 16, false, 0, 0, 0, 0, pl, 5) < 0);
	CHECK(rtp_build(b, 17, false, 0, 0, 0, 0, pl, 5) == 17);
	CHECK(rtp_build(b, 64, false, 128, 0, 0, 0, pl, 5) < 0);

	/* CSRC + extension + padding */
	{
		uint8_t x[64];

		memset(x, 0, sizeof(x));
		x[0] = 0x80 | 0x20 | 0x10 | 2;	/* P X cc=2 */
		x[1] = 8;
		/* 12 hdr + 8 csrc, extension header 4 + 2 words, payload 3, padding 4 */
		x[20] = 0xbe; x[21] = 0xde; x[22] = 0; x[23] = 2;
		x[32] = 7; x[33] = 8; x[34] = 9;
		x[35] = 0; x[36] = 0; x[37] = 0; x[38] = 4;
		CHECK(rtp_parse(x, 39, &p) == 0);
		CHECK(p.plen == 3 && p.payload == x + 32 && p.h.cc == 2 && p.h.extension && p.h.padding);
		/* padding count larger than the packet */
		x[38] = 40;
		CHECK(rtp_parse(x, 39, &p) < 0);
		/* padding count zero is invalid */
		x[38] = 0;
		CHECK(rtp_parse(x, 39, &p) < 0);
		x[38] = 4;
		/* padding eating into header */
		x[38] = 8;
		CHECK(rtp_parse(x, 39, &p) < 0);
		x[38] = 4;
		/* CSRC list overruns */
		CHECK(rtp_parse(x, 19, &p) < 0);
		/* extension header truncated */
		CHECK(rtp_parse(x, 22, &p) < 0);
		/* extension length overruns */
		x[23] = 200;
		CHECK(rtp_parse(x, 39, &p) < 0);
	}
	/* malformed */
	CHECK(rtp_parse(b, 0, &p) < 0);
	CHECK(rtp_parse(b, 11, &p) < 0);
	b[0] = 0x40;
	CHECK(rtp_parse(b, 12, &p) < 0);	/* version 1 */
	b[0] = 0x00;
	CHECK(rtp_parse(b, 12, &p) < 0);	/* version 0 */

	/* sequence / timestamp arithmetic */
	CHECK(rtp_seq_diff(1, 65535) == 2 && rtp_seq_diff(65535, 1) == -2 && rtp_seq_diff(5, 5) == 0);
	CHECK(rtp_ts_diff(10, 0xfffffff6u) == 20);

	/* tx context */
	{
		struct rtp_tx t;
		uint16_t s0, s1;

		rtp_tx_init(&t);
		t.seq = 65535;
		s0 = rtp_tx_next(&t, 100, 33);
		s1 = rtp_tx_next(&t, 260, 33);
		CHECK(s0 == 65535 && s1 == 0 && t.packets == 2 && t.octets == 66 && t.last_ts == 260);
	}
	/* rx stats: in order, gap, duplicate, wrap */
	{
		struct rtp_stats s;
		uint32_t m;

		rtp_stats_init(&s);
		CHECK(rtp_stats_rx(&s, 65534, 0, 1, 100, 1000, 8000) == 0);
		CHECK(rtp_stats_rx(&s, 65535, 160, 1, 100, 1020, 8000) == 0);
		CHECK(rtp_stats_rx(&s, 2, 640, 1, 100, 1080, 8000) == 2);	/* 0 and 1 missing, across the wrap */
		CHECK(rtp_stats_rx(&s, 2, 640, 1, 100, 1081, 8000) == 0);	/* duplicate */
		m = rtp_stats_lost(&s);
		CHECK(m == 2);
		CHECK(rtp_stats_ext_max(&s) == 0x10000u + 2);
		CHECK(s.rx_octets == 400);
		/* new ssrc restarts accounting */
		CHECK(rtp_stats_rx(&s, 500, 0, 2, 100, 2000, 8000) == 0 && rtp_stats_lost(&s) == 0);
	}
}
