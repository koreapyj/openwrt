/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "../amr.h"
#include "../codec.h"
#include "test.h"

static void hexcmp(const char *what, const uint8_t *p, size_t n, const char *hex)
{
	char buf[256];
	size_t i;

	for (i = 0; i < n && i < 100; i++)
		sprintf(buf + 2 * i, "%02x", p[i]);
	buf[2 * i] = 0;
	CHECKF(!strcmp(buf, hex), "%s: got %s want %s", what, buf, hex);
}

static void unhex(const char *h, uint8_t *o, size_t *n)
{
	size_t i;

	for (i = 0; h[2 * i]; i++) {
		unsigned v;

		sscanf(h + 2 * i, "%2x", &v);
		o[i] = (uint8_t)v;
	}
	*n = i;
}

static void tables(void)
{
	CHECK(amr_frame_bits(AMR_NB, 7) == 244 && amr_frame_bytes(AMR_NB, 7) == 31);
	CHECK(amr_frame_bits(AMR_NB, 0) == 95 && amr_frame_bytes(AMR_NB, 0) == 12);
	CHECK(amr_frame_bits(AMR_NB, 8) == 39 && amr_frame_bytes(AMR_NB, 8) == 5);
	CHECK(amr_frame_bits(AMR_NB, 15) == 0);
	CHECK(amr_frame_bits(AMR_NB, 9) < 0 && amr_frame_bits(AMR_NB, 14) < 0 && amr_frame_bits(AMR_NB, 16) < 0);
	CHECK(amr_frame_bits(AMR_WB, 8) == 477 && amr_frame_bytes(AMR_WB, 8) == 60);
	CHECK(amr_frame_bits(AMR_WB, 0) == 132 && amr_frame_bytes(AMR_WB, 0) == 17);
	CHECK(amr_frame_bits(AMR_WB, 9) == 40 && amr_frame_bits(AMR_WB, 14) == 0 && amr_frame_bits(AMR_WB, 15) == 0);
	CHECK(amr_frame_bits(AMR_WB, 10) < 0 && amr_frame_bits(AMR_WB, 13) < 0);
	CHECK(amr_ft_is_speech(AMR_NB, 7) && !amr_ft_is_speech(AMR_NB, 8) && amr_ft_is_speech(AMR_WB, 8));
	CHECK(amr_ft_is_dtx(AMR_NB, 8) && amr_ft_is_dtx(AMR_NB, 15) && !amr_ft_is_dtx(AMR_NB, 7));
	CHECK(amr_ft_is_dtx(AMR_WB, 9) && amr_ft_is_dtx(AMR_WB, 14) && !amr_ft_is_dtx(AMR_WB, 8));
	CHECK(amr_mode_bps(AMR_WB, 8) == 23850 && amr_mode_bps(AMR_NB, 7) == 12200 && amr_mode_bps(AMR_NB, 8) == 0);
}

static void vectors(void)
{
	/* hand computed with an independent bit-by-bit script (see test comments in report) */
	static const uint8_t sid[5] = { 0xa5, 0x5a, 0xff, 0x00, 0xfe };
	static const uint8_t wsid[5] = { 0x12, 0x34, 0x56, 0x78, 0x9a };
	struct amr_pdu pdu;
	struct amr_frame f[2];
	uint8_t out[128], raw[128];
	size_t n;
	int len;

	/* NB SID, CMR 15, Q=1 */
	memset(f, 0, sizeof(f));
	f[0].ft = 8; f[0].q = 1; f[0].nbytes = 5;
	memcpy(f[0].data + 1, sid, 5);
	len = amr_build(AMR_NB, false, 15, f, 1, out, sizeof(out));
	CHECK(len == 7);
	hexcmp("nb sid be", out, (size_t)len, "f46956bfc03f80");
	unhex("f46956bfc03f80", raw, &n);
	CHECK(amr_parse(AMR_NB, false, raw, n, &pdu) == 0 && pdu.n == 1 && pdu.cmr == 15 && pdu.f[0].ft == 8 && pdu.f[0].q == 1);
	CHECK(pdu.f[0].nbytes == 5 && !memcmp(pdu.f[0].data + 1, sid, 5) && pdu.f[0].data[0] == 0x44);
	len = amr_build(AMR_NB, true, 15, f, 1, out, sizeof(out));
	hexcmp("nb sid oa", out, (size_t)len, "f044a55aff00fe");
	unhex("f044a55aff00fe", raw, &n);
	CHECK(amr_parse(AMR_NB, true, raw, n, &pdu) == 0 && pdu.n == 1 && pdu.f[0].ft == 8 && !memcmp(pdu.f[0].data + 1, sid, 5));

	/* WB: SID + NO_DATA, CMR 3 */
	memset(f, 0, sizeof(f));
	f[0].ft = 9; f[0].q = 1; f[0].nbytes = 5;
	memcpy(f[0].data + 1, wsid, 5);
	f[1].ft = 15; f[1].q = 0;
	len = amr_build(AMR_WB, false, 3, f, 2, out, sizeof(out));
	hexcmp("wb 2fr be", out, (size_t)len, "3cde123456789a");
	unhex("3cde123456789a", raw, &n);
	CHECK(amr_parse(AMR_WB, false, raw, n, &pdu) == 0 && pdu.n == 2 && pdu.cmr == 3);
	CHECK(pdu.f[0].ft == 9 && pdu.f[1].ft == 15 && pdu.f[1].nbytes == 0 && pdu.f[1].data[0] == 0x78);
	len = amr_build(AMR_WB, true, 3, f, 2, out, sizeof(out));
	hexcmp("wb 2fr oa", out, (size_t)len, "30cc78123456789a");
	unhex("30cc78123456789a", raw, &n);
	CHECK(amr_parse(AMR_WB, true, raw, n, &pdu) == 0 && pdu.n == 2 && pdu.f[0].ft == 9 && pdu.f[1].ft == 15);

	/* WB mode 0, 132 bits (4 pad bits in the last byte) */
	{
		uint8_t d0[17];
		int i;

		for (i = 0; i < 17; i++)
			d0[i] = (uint8_t)(0x11 + i);
		d0[16] &= 0xf0;
		memset(f, 0, sizeof(f));
		f[0].ft = 0; f[0].q = 1; f[0].nbytes = 17;
		memcpy(f[0].data + 1, d0, 17);
		len = amr_build(AMR_WB, false, 7, f, 1, out, sizeof(out));
		hexcmp("wb0 be", out, (size_t)len, "70444484c5054585c6064686c7074787c808");
		len = amr_build(AMR_WB, true, 7, f, 1, out, sizeof(out));
		hexcmp("wb0 oa", out, (size_t)len, "70041112131415161718191a1b1c1d1e1f2020");
	}
}

static void malformed(void)
{
	struct amr_pdu pdu;
	uint8_t b[80];
	struct amr_frame f;
	size_t i;

	memset(b, 0, sizeof(b));
	CHECK(amr_parse(AMR_WB, true, b, 0, &pdu) < 0);
	CHECK(amr_parse(AMR_WB, true, b, 1, &pdu) < 0);
	CHECK(amr_parse(AMR_WB, false, b, 1, &pdu) < 0);
	/* OA: ToC says WB mode 8 (60 bytes) but only 10 bytes follow */
	memset(b, 0, sizeof(b));
	b[0] = 0xf0; b[1] = (8 << 3) | 4;
	CHECK(amr_parse(AMR_WB, true, b, 12, &pdu) < 0);
	CHECK(amr_parse(AMR_WB, true, b, 61, &pdu) < 0);
	CHECK(amr_parse(AMR_WB, true, b, 62, &pdu) == 0);
	CHECK(amr_parse(AMR_WB, true, b, 64, &pdu) == 0);	/* trailing bytes tolerated */
	/* ToC without terminator */
	memset(b, 0x80 | (0 << 3), sizeof(b));
	b[0] = 0xf0;
	CHECK(amr_parse(AMR_NB, true, b, 40, &pdu) < 0);
	/* reserved FT */
	b[0] = 0xf0; b[1] = (10 << 3);
	CHECK(amr_parse(AMR_WB, true, b, 20, &pdu) < 0);
	b[1] = (10 << 3);
	CHECK(amr_parse(AMR_NB, true, b, 20, &pdu) < 0);
	/* BE: FT 7 needs 244 bits, give 20 bytes */
	memset(b, 0, sizeof(b));
	b[0] = 0xf0 | 0x0; b[1] = (7 << 3 | 4) << 0;
	/* BE layout: CMR(4) F(1) FT(4) Q(1) = bits; FT 7 -> 0 0111 1 => 0000 0111 1.. just construct via build */
	memset(&f, 0, sizeof(f));
	f.ft = 7; f.nbytes = 31;
	CHECK(amr_build(AMR_NB, false, 15, &f, 1, b, sizeof(b)) == 32);
	for (i = 1; i < 32; i++)
		CHECK(amr_parse(AMR_NB, false, b, i, &pdu) < 0);
	CHECK(amr_parse(AMR_NB, false, b, 32, &pdu) == 0);
	/* too many frames */
	{
		struct amr_frame many[AMR_MAX_FRAMES + 1];
		uint8_t big[400];

		memset(many, 0, sizeof(many));
		for (i = 0; i < AMR_MAX_FRAMES + 1; i++)
			many[i].ft = 15;
		CHECK(amr_build(AMR_NB, true, 15, many, AMR_MAX_FRAMES + 1, big, sizeof(big)) < 0);
		CHECK(amr_build(AMR_NB, true, 15, many, AMR_MAX_FRAMES, big, sizeof(big)) == 1 + AMR_MAX_FRAMES);
		CHECK(amr_parse(AMR_NB, true, big, 1 + AMR_MAX_FRAMES, &pdu) == 0 && pdu.n == AMR_MAX_FRAMES);
		/* one more ToC entry than we accept */
		memset(big, 0x80 | (15 << 3), sizeof(big));
		big[0] = 0xf0;
		big[1 + AMR_MAX_FRAMES] = 15 << 3;
		CHECK(amr_parse(AMR_NB, true, big, 1 + AMR_MAX_FRAMES + 1, &pdu) < 0);
	}
	/* build errors */
	f.ft = 8;
	CHECK(amr_build(AMR_NB, true, 16, &f, 1, b, sizeof(b)) < 0);
	CHECK(amr_build(AMR_NB, true, 15, &f, 0, b, sizeof(b)) < 0);
	CHECK(amr_build(AMR_NB, true, 15, &f, 1, b, 6) < 0);
	CHECK(amr_build(AMR_NB, false, 15, &f, 1, b, 6) < 0);
	f.ft = 9;
	CHECK(amr_build(AMR_NB, true, 15, &f, 1, b, sizeof(b)) < 0);
}

static void modeset(void)
{
	CHECK(amr_modeset_parse(AMR_NB, "0,2,7") == (1 | 4 | 128));
	CHECK(amr_modeset_parse(AMR_WB, "8") == 256);
	CHECK(amr_modeset_parse(AMR_NB, "7") == 128);
	CHECK(amr_modeset_parse(AMR_NB, " 1 , 3 ") == (2 | 8));
	CHECK(amr_modeset_parse(AMR_NB, "") == 0xff && amr_modeset_parse(AMR_NB, NULL) == 0xff);
	CHECK(amr_modeset_parse(AMR_WB, "") == 0x1ff);
	CHECK(amr_modeset_parse(AMR_NB, "8") == 0);	/* no such NB mode */
	CHECK(amr_modeset_parse(AMR_WB, "9") == 0);
	CHECK(amr_modeset_parse(AMR_WB, "1,,2") == 0 && amr_modeset_parse(AMR_WB, "a") == 0 && amr_modeset_parse(AMR_WB, "1;2") == 0);
	CHECK(amr_modeset_parse(AMR_WB, "-1") == 0);
	{
		uint16_t m = amr_modeset_parse(AMR_WB, "0,2,3,8");

		CHECK(amr_mode_clamp(AMR_WB, m, 8) == 8);
		CHECK(amr_mode_clamp(AMR_WB, m, 4) == 3);
		CHECK(amr_mode_clamp(AMR_WB, m, 1) == 0);
		CHECK(amr_mode_clamp(AMR_WB, m, 7) == 3);
		CHECK(amr_mode_clamp(AMR_WB, m, 99) == 8);
		CHECK(amr_mode_clamp(AMR_WB, 4 | 256, 1) == 2);	/* nothing at or below: lowest allowed */
		CHECK(amr_mode_clamp(AMR_WB, 0, 5) == 5);
		CHECK(amr_apply_cmr(AMR_WB, m, 8, 15) == 8);	/* no request */
		CHECK(amr_apply_cmr(AMR_WB, m, 8, 4) == 3);
		CHECK(amr_apply_cmr(AMR_WB, m, 3, 9) == 3);	/* CMR 9..14 invalid for WB */
		CHECK(amr_apply_cmr(AMR_NB, 0xff, 7, 3) == 3);
		CHECK(amr_apply_cmr(AMR_NB, 0xff, 7, 8) == 7);
	}
	CHECK(amr_mode_clamp(AMR_NB, 128, 3) == 7);
}

struct pass {
	size_t pkts, single, ident, frames, dtx, nodata, bad_energy, decfail;
	double rms_sum;
	size_t rms_n, loud;
};

static void capture(const char *rel, enum amr_type t, bool oa, int pt, size_t expect_n)
{
	struct cap c;
	struct pass ps;
	struct codec *dec;
	size_t i, k;
	int16_t pcm[960];
	uint16_t prev_seq = 0;
	size_t gaps = 0;

	if (cap_load(&c, rel) < 0)
		return;
	memset(&ps, 0, sizeof(ps));
	CHECKF(c.n == expect_n, "%s: %zu packets, expected %zu", rel, c.n, expect_n);
	dec = codec_create(t == AMR_WB ? CODEC_AMRWB : CODEC_AMRNB, NULL);
	CHECK(dec != NULL);
	for (i = 0; i < c.n; i++) {
		struct amr_pdu pdu;
		uint8_t re[256];
		int len;

		if (c.r[i].pt != pt)
			CHECKF(0, "%s: pkt %zu pt %u", rel, i, c.r[i].pt);
		if (i && (uint16_t)(c.r[i].seq - prev_seq) != 1)
			gaps++;
		prev_seq = c.r[i].seq;
		ps.pkts++;
		if (amr_parse(t, oa, c.r[i].p, c.r[i].len, &pdu) < 0) {
			CHECKF(0, "%s: pkt %zu (seq %u len %u) fails to parse", rel, i, c.r[i].seq, c.r[i].len);
			continue;
		}
		if (pdu.n == 1) {
			ps.single++;
			len = amr_build(t, oa, pdu.cmr, pdu.f, pdu.n, re, sizeof(re));
			if (len == (int)c.r[i].len && !memcmp(re, c.r[i].p, (size_t)len))
				ps.ident++;
			else
				CHECKF(0, "%s: pkt %zu repack differs", rel, i);
		}
		for (k = 0; k < pdu.n; k++) {
			int n = codec_decode(dec, pdu.f[k].data, 1u + pdu.f[k].nbytes, pcm, 960);

			ps.frames++;
			if (amr_ft_is_dtx(t, pdu.f[k].ft))
				ps.dtx++;
			if (n != codec_frame_samples(dec)) {
				ps.decfail++;
				continue;
			}
			{
				double r = rms16(pcm, (size_t)n);

				ps.rms_sum += r;
				ps.rms_n++;
				if (r > 100)
					ps.loud++;
			}
		}
	}
	printf("  %-16s %zu pkts, %zu frames (%zu single, %zu byte-identical repack, %zu dtx), seq gaps %zu, mean rms %.0f, loud frames %zu\n",
	       rel, ps.pkts, ps.frames, ps.single, ps.ident, ps.dtx, gaps, ps.rms_n ? ps.rms_sum / (double)ps.rms_n : 0, ps.loud);
	CHECK(ps.decfail == 0);
	CHECK(ps.single == ps.ident);
	CHECK(ps.rms_n > 0 && ps.rms_sum / (double)ps.rms_n > 200.0);
	CHECK(ps.loud > ps.frames / 4);
	codec_destroy(dec);
	cap_free(&c);
}

void test_amr(void)
{
	tables();
	vectors();
	malformed();
	modeset();
	capture("l1/mt/rtp_rx.bin", AMR_WB, true, 100, 613);
	capture("n1/rtp_rx.bin", AMR_WB, true, 104, 592);
	capture("c1/rtp_rx.bin", AMR_WB, false, 104, 232);
	capture("run1/rtp_rx.bin", AMR_NB, false, 102, 616);
}
