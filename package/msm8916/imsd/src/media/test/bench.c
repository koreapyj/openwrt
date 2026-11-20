/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Host CPU cost of the bridge's per-frame work, one frame = 20 ms of audio:
 * RTP parse -> depacketise -> decode -> resample -> encode -> packetise -> RTP build
 * (no sockets).  This is an x86_64 host number, NOT a Cortex-A53 number.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../amr.h"
#include "../codec.h"
#include "../resample.h"
#include "../rtp.h"

#define NF 400
#define ROUNDS 10

/* minimal reader of the capture format (see test.h); payload pointers into buf */
struct crec {
	uint16_t len;
	const uint8_t *p;
};

static int cap_read(const char *path, uint8_t **buf, struct crec *r, size_t max, size_t *n)
{
	FILE *f = fopen(path, "rb");
	long sz;
	size_t i;

	*n = 0;
	if (!f)
		return -1;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	*buf = malloc((size_t)sz);
	if (!*buf || fread(*buf, 1, (size_t)sz, f) != (size_t)sz) {
		fclose(f);
		return -1;
	}
	fclose(f);
	for (i = 0; i + 13 <= (size_t)sz && *n < max;) {
		const uint8_t *b = *buf + i;

		r[*n].len = (uint16_t)(b[11] | b[12] << 8);
		r[*n].p = b + 13;
		i += 13 + r[*n].len;
		(*n)++;
	}
	return 0;
}

static double now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

struct side {
	enum codec_id id;
	struct codec *c;
	int rate;
	bool amr;
	enum amr_type t;
	struct resamp rs;
	uint16_t seq;
	uint32_t ts;
};

static void side_init(struct side *s, enum codec_id id, int pcm_rate)
{
	struct codec_params p;

	memset(s, 0, sizeof(*s));
	codec_params_default(&p);
	p.pcm_rate = pcm_rate;
	s->id = id;
	s->c = codec_create(id, &p);
	if (!s->c) {
		fprintf(stderr, "cannot create %s\n", codec_name(id));
		exit(1);
	}
	s->rate = codec_pcm_rate(s->c);
	s->amr = id == CODEC_AMRNB || id == CODEC_AMRWB;
	s->t = id == CODEC_AMRWB ? AMR_WB : AMR_NB;
	resamp_init(&s->rs);
}

/* PCM at the side's rate -> RTP packet */
static int side_encode(struct side *s, const int16_t *pcm, uint8_t *pkt, size_t pktsz)
{
	uint8_t enc[1400], pl[1400];
	int n = codec_encode(s->c, pcm, enc, sizeof(enc));
	struct amr_frame fr;

	if (n <= 0)
		return -1;
	if (s->amr) {
		if (amr_frame_from_storage(s->t, &fr, enc, (size_t)n) < 0)
			return -1;
		n = amr_build(s->t, true, 15, &fr, 1, pl, sizeof(pl));
	} else {
		memcpy(pl, enc, (size_t)n);
	}
	n = rtp_build(pkt, pktsz, false, 96, s->seq++, s->ts, 1, pl, (size_t)n);
	s->ts += (uint32_t)codec_ts_per_frame(s->c);
	return n;
}

/* what the bridge does for one packet: parse, decode (src), resample, encode (dst), build */
static int bridge_work(struct side *src, struct side *dst, const uint8_t *pkt, size_t len, uint8_t *out, size_t outsz)
{
	struct rtp_pkt p;
	int16_t dec[1920], rs[1920];
	const int16_t *pcm = dec;
	int n;
	uint8_t enc[1400], pl[1400];
	struct amr_pdu pdu;
	struct amr_frame fr;

	if (rtp_parse(pkt, len, &p) < 0)
		return -1;
	if (src->amr) {
		if (amr_parse(src->t, true, p.payload, p.plen, &pdu) < 0)
			return -1;
		n = codec_decode(src->c, pdu.f[0].data, 1u + pdu.f[0].nbytes, dec, 1920);
	} else {
		n = codec_decode(src->c, p.payload, p.plen, dec, 1920);
	}
	if (n <= 0)
		return -1;
	if (src->rate == 8000 && dst->rate == 16000) {
		n = resamp_up2(&dst->rs, dec, (size_t)n, rs);
		pcm = rs;
	} else if (src->rate == 16000 && dst->rate == 8000) {
		n = resamp_down2(&dst->rs, dec, (size_t)n, rs);
		pcm = rs;
	}
	if (n != codec_frame_samples(dst->c))
		return -1;
	n = codec_encode(dst->c, pcm, enc, sizeof(enc));
	if (n <= 0)
		return -1;
	if (dst->amr) {
		if (amr_frame_from_storage(dst->t, &fr, enc, (size_t)n) < 0)
			return -1;
		n = amr_build(dst->t, true, 15, &fr, 1, pl, sizeof(pl));
	} else {
		memcpy(pl, enc, (size_t)n);
	}
	n = rtp_build(out, outsz, false, 97, dst->seq++, dst->ts, 2, pl, (size_t)n);
	dst->ts += (uint32_t)codec_ts_per_frame(dst->c);
	return n;
}

static void run_pair(const char *title, enum codec_id ia, enum codec_id ib, const int16_t *speech16)
{
	static uint8_t pa[NF][200], pb[NF][1400];
	static int la[NF], lb[NF];
	struct side a, b, ga, gb;	/* a,b: bridge instances; ga,gb: stimulus generators */
	int16_t pcm[960];
	uint8_t out[1500];
	double t0, t_ab, t_ba;
	int f, r, bad = 0;
	int ra, rb;

	side_init(&ga, ia, 0);
	side_init(&gb, ib, 16000);
	ra = ga.rate;
	rb = gb.rate;
	for (f = 0; f < NF; f++) {
		struct resamp d;

		resamp_init(&d);
		if (ra == 16000)
			memcpy(pcm, speech16 + f * 320, 640);
		else
			resamp_down2(&d, speech16 + f * 320, 320, pcm);
		la[f] = side_encode(&ga, pcm, pa[f], sizeof(pa[f]));
		if (rb == 16000)
			memcpy(pcm, speech16 + f * 320, 640);
		else
			resamp_down2(&d, speech16 + f * 320, 320, pcm);
		lb[f] = side_encode(&gb, pcm, pb[f], sizeof(pb[f]));
	}
	side_init(&a, ia, 0);
	side_init(&b, ib, 16000);
	for (f = 0; f < 20; f++)
		bridge_work(&a, &b, pa[f], (size_t)la[f], out, sizeof(out));	/* warm up */
	t0 = now_us();
	for (r = 0; r < ROUNDS; r++)
		for (f = 0; f < NF; f++)
			if (bridge_work(&a, &b, pa[f], (size_t)la[f], out, sizeof(out)) < 0)
				bad++;
	t_ab = (now_us() - t0) / (ROUNDS * NF);
	for (f = 0; f < 20; f++)
		bridge_work(&b, &a, pb[f], (size_t)lb[f], out, sizeof(out));
	t0 = now_us();
	for (r = 0; r < ROUNDS; r++)
		for (f = 0; f < NF; f++)
			if (bridge_work(&b, &a, pb[f], (size_t)lb[f], out, sizeof(out)) < 0)
				bad++;
	t_ba = (now_us() - t0) / (ROUNDS * NF);
	printf("%-44s A->B %6.1f us  B->A %6.1f us  pair %6.1f us per 20 ms frame (%.2f%% of one core)%s\n", title, t_ab, t_ba,
	       t_ab + t_ba, (t_ab + t_ba) / 20000.0 * 100.0, bad ? "  [ERRORS]" : "");
	codec_destroy(a.c);
	codec_destroy(b.c);
	codec_destroy(ga.c);
	codec_destroy(gb.c);
}

int main(void)
{
	static struct crec rec[4096];
	static int16_t speech[NF * 320];
	uint8_t *buf = NULL;
	struct codec *dec = codec_create(CODEC_AMRWB, NULL);
	size_t i, n = 0, nr;

	const char *dir = getenv("IMSD_TEST_CAPDIR");
	char path[512];

	if (!dir || !*dir) {
		printf("SKIP bench: needs a recorded AMR-WB RTP capture, set IMSD_TEST_CAPDIR (n1/rtp_rx.bin below it)\n");
		return 0;
	}
	snprintf(path, sizeof(path), "%s/n1/rtp_rx.bin", dir);
	if (cap_read(path, &buf, rec, 4096, &nr) < 0) {
		fprintf(stderr, "capture %s not found\n", path);
		return 1;
	}
	for (i = 0; i < nr && n < NF; i++) {
		struct amr_pdu p;

		if (amr_parse(AMR_WB, true, rec[i].p, rec[i].len, &p) == 0 && p.n == 1 && p.f[0].ft <= 8 && p.f[0].nbytes > 20 &&
		    codec_decode(dec, p.f[0].data, 1u + p.f[0].nbytes, speech + n * 320, 320) == 320)
			n++;
	}
	codec_destroy(dec);
	free(buf);
	if (n < NF) {
		fprintf(stderr, "only %zu speech frames\n", n);
		return 1;
	}
	printf("HOST (x86_64) cost per 20 ms frame, packet in -> packet out, -O2, real speech; NOT a Cortex-A53 figure\n");
	run_pair("AMR-WB 23.85k <-> Opus 16k (24 kbit/s, cx 5)", CODEC_AMRWB, CODEC_OPUS, speech);
	run_pair("AMR-WB 23.85k <-> G.722", CODEC_AMRWB, CODEC_G722, speech);
	run_pair("AMR-WB 23.85k <-> PCMA (8k, resample)", CODEC_AMRWB, CODEC_PCMA, speech);
	run_pair("AMR-NB 12.2k  <-> G.722 (resample)", CODEC_AMRNB, CODEC_G722, speech);
	run_pair("AMR-NB 12.2k  <-> Opus 16k (resample)", CODEC_AMRNB, CODEC_OPUS, speech);
	return 0;
}
