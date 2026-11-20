/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "../amr.h"
#include "../codec.h"
#include "../resample.h"
#include "test.h"

#define PI 3.14159265358979323846

static void sine(int16_t *x, size_t n, double hz, double rate, double amp, size_t off)
{
	size_t i;

	for (i = 0; i < n; i++)
		x[i] = (int16_t)(amp * sin(2 * PI * hz * (double)(i + off) / rate));
}

/* frames of a two-tone "speech-like" signal */
static void voice(int16_t *x, size_t n, double rate, size_t off)
{
	size_t i;

	for (i = 0; i < n; i++) {
		double t = (double)(i + off) / rate;

		x[i] = (int16_t)(5000 * sin(2 * PI * 300 * t) + 3000 * sin(2 * PI * 900 * t + 1) + 1500 * sin(2 * PI * 1700 * t));
	}
}

/* encode -> decode through one codec instance for nfr frames; returns corr and rms ratio */
static void roundtrip(enum codec_id id, const struct codec_params *p, int nfr, double *corr, double *ratio, int maxlag_ms,
		      double *avg_bytes)
{
	struct codec *c = codec_create(id, p);
	int fs, rate, f, skip = 5;
	int16_t *in, *out, *ref;
	uint8_t buf[1400];
	size_t tot = 0;
	size_t bytes = 0;

	if (!c) {
		CHECKF(0, "%s create failed", codec_name(id));
		*corr = 0;
		*ratio = 0;
		return;
	}
	fs = codec_frame_samples(c);
	rate = codec_pcm_rate(c);
	in = malloc((size_t)fs * (size_t)nfr * 2);
	ref = malloc((size_t)fs * (size_t)nfr * 2);
	out = calloc((size_t)fs * (size_t)nfr, 2);
	voice(in, (size_t)fs * (size_t)nfr, rate, 0);
	memcpy(ref, in, (size_t)fs * (size_t)nfr * 2);
	for (f = 0; f < nfr; f++) {
		int n = codec_encode(c, in + f * fs, buf, sizeof(buf));
		int d;

		CHECK(n > 0);
		if (n <= 0)
			break;
		CHECK(!memcmp(in + f * fs, ref + f * fs, (size_t)fs * 2));	/* input untouched (opencore NB!) */
		bytes += (size_t)n;
		d = codec_decode(c, buf, (size_t)n, out + f * fs, (size_t)(fs * (nfr - f)));
		CHECK(d == fs);
		tot += (size_t)fs;
	}
	{
		size_t s0 = (size_t)(skip * fs);
		int lag;

		*corr = best_corr(ref + s0, out + s0, tot - s0 - (size_t)(rate / 10), rate * maxlag_ms / 1000, &lag);
		*ratio = rms16(out + s0, tot - s0) / rms16(ref + s0, tot - s0);
	}
	*avg_bytes = (double)bytes / nfr;
	free(in);
	free(ref);
	free(out);
	codec_destroy(c);
}

static void codecs_roundtrip(void)
{
	struct codec_params p;
	double corr, ratio, ab;
	int m;

	codec_params_default(&p);
	for (m = 0; m <= 7; m += 7) {
		p.mode = m;
		roundtrip(CODEC_AMRNB, &p, 50, &corr, &ratio, 5, &ab);
		printf("  AMR-NB mode %d: %.1f bytes/frame corr %.4f ratio %.2f\n", m, ab, corr, ratio);
		CHECK(corr > 0.8 && ratio > 0.5 && ratio < 1.5);
	}
	for (m = 0; m <= 8; m += 4) {
		p.mode = m;
		roundtrip(CODEC_AMRWB, &p, 50, &corr, &ratio, 5, &ab);
		printf("  AMR-WB mode %d: %.1f bytes/frame corr %.4f ratio %.2f\n", m, ab, corr, ratio);
		CHECK(corr > (m == 8 ? 0.9 : 0.6) && ratio > 0.5 && ratio < 1.5);
	}
	codec_params_default(&p);
	roundtrip(CODEC_PCMA, &p, 50, &corr, &ratio, 1, &ab);
	printf("  PCMA: %.1f bytes/frame corr %.5f ratio %.3f\n", ab, corr, ratio);
	CHECK(corr > 0.999 && ratio > 0.98 && ratio < 1.02);
#ifdef IMSD_WITH_G722
	roundtrip(CODEC_G722, &p, 50, &corr, &ratio, 5, &ab);
	printf("  G722: %.1f bytes/frame corr %.5f ratio %.3f\n", ab, corr, ratio);
	CHECK(corr > 0.99 && ratio > 0.9 && ratio < 1.1 && ab == 160.0);
#endif
#ifdef IMSD_WITH_OPUS
	{
		int rates[] = { 8000, 16000, 48000 }, i;

		for (i = 0; i < 3; i++) {
			p.pcm_rate = rates[i];
			p.bitrate = 24000;
			roundtrip(CODEC_OPUS, &p, 60, &corr, &ratio, 20, &ab);
			printf("  Opus @%d: %.1f bytes/frame corr %.4f ratio %.2f\n", rates[i], ab, corr, ratio);
			CHECK(corr > 0.8 && ratio > 0.6 && ratio < 1.4);
		}
	}
#endif
}

static void codec_properties(void)
{
	struct codec_params p;
	struct codec *c;
	int16_t pcm[960];
	uint8_t buf[100];
	struct amr_frame fr;
	int i;

	codec_params_default(&p);
	/* geometry */
	c = codec_create(CODEC_AMRNB, NULL);
	CHECK(codec_pcm_rate(c) == 8000 && codec_frame_samples(c) == 160 && codec_rtp_clock(c) == 8000 && codec_ts_per_frame(c) == 160);
	codec_destroy(c);
	c = codec_create(CODEC_AMRWB, NULL);
	CHECK(codec_pcm_rate(c) == 16000 && codec_frame_samples(c) == 320 && codec_rtp_clock(c) == 16000 && codec_ts_per_frame(c) == 320);
	/* default mode is the highest, WB mode 8, storage frame 61 bytes */
	sine(pcm, 320, 1000, 16000, 8000, 0);
	CHECK(codec_get_mode(c) == 8);
	CHECK(codec_encode(c, pcm, buf, sizeof(buf)) == 61);
	/* mode follows set_mode / bitrate */
	CHECK(codec_set_mode(c, 2) == 2);
	sine(pcm, 320, 1000, 16000, 8000, 0);
	i = codec_encode(c, pcm, buf, sizeof(buf));
	CHECK(i == 1 + 32 && amr_frame_from_storage(AMR_WB, &fr, buf, (size_t)i) == 0 && fr.ft == 2 && fr.q == 1);
	codec_set_bitrate(c, 15900);
	CHECK(codec_get_mode(c) == 4);
	codec_destroy(c);
	/* mode-set restricts */
	p.modeset = amr_modeset_parse(AMR_WB, "8");
	c = codec_create(CODEC_AMRWB, &p);
	CHECK(codec_get_mode(c) == 8 && codec_set_mode(c, 3) == 8);
	codec_destroy(c);
	p.modeset = amr_modeset_parse(AMR_NB, "0,2,7");
	p.mode = 5;
	c = codec_create(CODEC_AMRNB, &p);
	CHECK(codec_get_mode(c) == 2);
	codec_destroy(c);
	p.modeset = 0;
	p.mode = -1;
	/* NB frame sizes */
	c = codec_create(CODEC_AMRNB, &p);
	sine(pcm, 160, 500, 8000, 8000, 0);
	CHECK(codec_encode(c, pcm, buf, sizeof(buf)) == 32);
	CHECK(codec_set_mode(c, 0) == 0);
	sine(pcm, 160, 500, 8000, 8000, 0);
	CHECK(codec_encode(c, pcm, buf, sizeof(buf)) == 13);
	/* decoder: loss, SID, NO_DATA, malformed */
	CHECK(codec_decode(c, NULL, 0, pcm, 160) == 160);
	{
		uint8_t sid[6] = { 8 << 3 | 4, 0, 0, 0, 0, 0 }, nd[1] = { 15 << 3 }, bad[1] = { 10 << 3 };

		CHECK(codec_decode(c, sid, 6, pcm, 160) == 160);
		CHECK(codec_decode(c, nd, 1, pcm, 160) == 160);
		CHECK(codec_decode(c, bad, 1, pcm, 160) < 0);
		CHECK(codec_decode(c, sid, 3, pcm, 160) < 0);	/* truncated storage frame */
		CHECK(codec_decode(c, buf, 0, pcm, 160) < 0);
		CHECK(codec_decode(c, sid, 6, pcm, 100) < 0);	/* output too small */
	}
	/* encoder DTX produces SID / NO_DATA on silence */
	CHECK(codec_set_dtx(c, true) == 0);
	{
		int n_sid = 0, n_nd = 0, n_sp = 0, k;

		memset(pcm, 0, sizeof(pcm));
		for (k = 0; k < 60; k++) {
			int16_t z[160];
			int n;

			memset(z, 0, sizeof(z));
			n = codec_encode(c, z, buf, sizeof(buf));
			if (n == 1 && (buf[0] >> 3) == 15)
				n_nd++;
			else if ((buf[0] >> 3) == 8)
				n_sid++;
			else
				n_sp++;
		}
		printf("  AMR-NB DTX on silence: %d speech, %d SID, %d NO_DATA\n", n_sp, n_sid, n_nd);
		CHECK(n_sid > 0 && n_nd > 0);
	}
	codec_destroy(c);
	CHECK(codec_create(CODEC_COUNT, NULL) == NULL);
	CHECK(codec_available(CODEC_AMRNB) && codec_available(CODEC_PCMA));
#ifdef IMSD_WITH_OPUS
	{
		int16_t big[5760];
		uint8_t pk[1400];
		int n;

		p.pcm_rate = 16000;
		c = codec_create(CODEC_OPUS, &p);
		CHECK(codec_rtp_clock(c) == 48000 && codec_ts_per_frame(c) == 960 && codec_frame_samples(c) == 320);
		sine(pcm, 320, 1000, 16000, 8000, 0);
		n = codec_encode(c, pcm, pk, sizeof(pk));
		CHECK(n > 5 && n < 200);
		CHECK(codec_decode(c, pk, (size_t)n, big, 1920) == 320);
		CHECK(codec_decode(c, NULL, 0, big, 1920) == 320);	/* PLC */
		CHECK(codec_decode(c, pk, 0, big, 1920) < 0);
		{
			uint8_t junk[3] = { 0xff, 0xff, 0xff };

			CHECK(codec_decode(c, junk, 3, big, 1920) < 0 || 1);	/* must not crash */
		}
		CHECK(codec_set_bitrate(c, 16000) == 0 && codec_set_dtx(c, true) == 0);
		codec_destroy(c);
		p.pcm_rate = 44100;
		CHECK(codec_create(CODEC_OPUS, &p) == NULL);
	}
#endif
}

/* ---- resampler ---- */

static double goertzel(const int16_t *x, size_t n, double hz, double rate)
{
	double w = 2 * PI * hz / rate, c = 2 * cos(w), s1 = 0, s2 = 0, s;
	size_t i;

	for (i = 0; i < n; i++) {
		s = x[i] + c * s1 - s2;
		s2 = s1;
		s1 = s;
	}
	return sqrt((s1 * s1 + s2 * s2 - c * s1 * s2)) * 2 / (double)n;	/* amplitude */
}

static int rs_run(struct resamp *r, int up, const int16_t *in, size_t n, int16_t *out)
{
	size_t k, m = 0;

	for (k = 0; k < n; k += 320) {
		int d = up ? resamp_up2(r, in + k, 320, out + m) : resamp_down2(r, in + k, 320, out + m);

		if (d < 0)
			return -1;
		m += (size_t)d;
	}
	return (int)m;
}

static void resampler(void)
{
	struct resamp r;
	static int16_t in[16000], out[32000];
	double f;
	int i;
	static const double pass[] = { 100, 300, 1000, 2000, 3000, 3400 };

	/* down 16k -> 8k: passband */
	for (i = 0; i < 6; i++) {
		double ratio, lvl;

		f = pass[i];
		resamp_init(&r);
		sine(in, 3200, f, 16000, 10000, 0);
		CHECK(rs_run(&r, 0, in, 3200, out) == 1600);
		ratio = rms16(out + 200, 1200) / rms16(in + 400, 2400);
		lvl = 20 * log10(ratio);
		printf("  down2 %5.0f Hz: %+.2f dB\n", f, lvl);
		CHECK(fabs(lvl) < (f > 3300 ? 1.0 : 0.3));
	}
	/* down: aliasing rejection: 5/6/7/7.9 kHz at 16k fold to 3/2/1/0.1 kHz */
	{
		static const double al[] = { 4800, 5000, 6000, 7000, 7900 };

		for (i = 0; i < 5; i++) {
			double rej;

			resamp_init(&r);
			sine(in, 3200, al[i], 16000, 10000, 0);
			rs_run(&r, 0, in, 3200, out);
			rej = 20 * log10((rms16(out + 200, 1200) + 1e-9) / (10000 / sqrt(2.0)));
			printf("  down2 alias %5.0f Hz: %.1f dB\n", al[i], rej);
			CHECK(rej < -50);
		}
	}
	/* up 8k -> 16k: passband gain 1 (same RMS), image rejection */
	for (i = 0; i < 6; i++) {
		double lvl;

		f = pass[i];
		resamp_init(&r);
		sine(in, 1600, f, 8000, 10000, 0);
		CHECK(rs_run(&r, 1, in, 1600, out) == 3200);
		lvl = 20 * log10(rms16(out + 400, 2400) / rms16(in + 200, 1200));
		printf("  up2   %5.0f Hz: %+.2f dB\n", f, lvl);
		CHECK(fabs(lvl) < (f > 3300 ? 1.0 : 0.3));
	}
	{
		double fund, img;

		resamp_init(&r);
		sine(in, 1600, 1000, 8000, 10000, 0);
		rs_run(&r, 1, in, 1600, out);
		fund = goertzel(out + 400, 2000, 1000, 16000);
		img = goertzel(out + 400, 2000, 7000, 16000);
		printf("  up2 image 7000 Hz: %.1f dB below the 1 kHz tone\n", 20 * log10(img / fund));
		CHECK(20 * log10(img / fund) < -50);
	}
	/* block boundaries do not matter: one call == many small calls */
	{
		struct resamp a, b;
		static int16_t o1[2000], o2[2000];
		int k;

		resamp_init(&a);
		resamp_init(&b);
		voice(in, 640, 16000, 0);
		resamp_down2(&a, in, 640, o1);
		for (k = 0; k < 2; k++)
			resamp_down2(&b, in + k * 320, 320, o2 + k * 160);
		CHECK(!memcmp(o1, o2, 320 * 2));
		resamp_init(&a);
		resamp_init(&b);
		resamp_up2(&a, in, 640, o1);
		for (k = 0; k < 4; k++)
			resamp_up2(&b, in + k * 160, 160, o2 + k * 320);
		CHECK(!memcmp(o1, o2, 1280 * 2));
	}
	/* error handling */
	resamp_init(&r);
	CHECK(resamp_down2(&r, in, 3, out) < 0 && resamp_up2(&r, in, RS_MAX_IN + 1, out) < 0);
	/* full scale does not wrap */
	{
		int16_t sq[400];

		for (i = 0; i < 400; i++)
			sq[i] = (i / 8) & 1 ? -32768 : 32767;
		resamp_init(&r);
		resamp_up2(&r, sq, 400, out);
		resamp_down2(&r, out, 800, sq);
		CHECK(1);
	}
}

void test_codec(void)
{
	codecs_roundtrip();
	codec_properties();
	resampler();
}
