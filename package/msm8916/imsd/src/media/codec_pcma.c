/* SPDX-License-Identifier: GPL-2.0-or-later */
/* G.711 A-law, arithmetic (ITU-T G.711 reference algorithm, own implementation). */
#include <stdlib.h>
#include "codec_priv.h"

static uint8_t lin2alaw(int16_t pcm)
{
	static const int seg_end[8] = { 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff, 0xfff };
	int v = pcm >> 3, mask, seg;
	uint8_t a;

	if (v >= 0) {
		mask = 0xd5;
	} else {
		mask = 0x55;
		v = -v - 1;
	}
	for (seg = 0; seg < 8; seg++)
		if (v <= seg_end[seg])
			break;
	if (seg >= 8)
		return (uint8_t)(0x7f ^ mask);
	a = (uint8_t)(seg << 4);
	a |= (uint8_t)((seg < 2 ? v >> 1 : v >> seg) & 0x0f);
	return (uint8_t)(a ^ mask);
}

static int16_t alaw2lin(uint8_t a)
{
	int t, seg;

	a ^= 0x55;
	t = (a & 0x0f) << 4;
	seg = (a & 0x70) >> 4;
	switch (seg) {
	case 0:
		t += 8;
		break;
	case 1:
		t += 0x108;
		break;
	default:
		t += 0x108;
		t <<= seg - 1;
	}
	return (int16_t)((a & 0x80) ? t : -t);
}

static int pcma_encode(struct codec *c, const int16_t *pcm, uint8_t *out, size_t outsz)
{
	int i;

	(void)outsz;
	for (i = 0; i < c->frame_samples; i++)
		out[i] = lin2alaw(pcm[i]);
	return c->frame_samples;
}

static int pcma_decode(struct codec *c, const uint8_t *d, size_t len, int16_t *pcm, size_t max)
{
	size_t i;

	if (!d) {
		/* no concealment worth the name in G.711 without Appendix I: silence */
		for (i = 0; i < (size_t)c->frame_samples; i++)
			pcm[i] = 0;
		return c->frame_samples;
	}
	if (len > max)
		len = max;	/* longer packets (e.g. 30 ms) are decoded up to the caller's capacity */
	for (i = 0; i < len; i++)
		pcm[i] = alaw2lin(d[i]);
	return (int)len;
}

static void pcma_destroy(struct codec *c)
{
	free(c);
}

static const struct codec_ops ops = { .destroy = pcma_destroy, .encode = pcma_encode, .decode = pcma_decode };

struct codec *codec_pcma_create(const struct codec_params *p)
{
	struct codec *c = calloc(1, sizeof(*c));

	(void)p;
	if (!c)
		return NULL;
	c->ops = &ops;
	c->id = CODEC_PCMA;
	c->pcm_rate = 8000;
	c->frame_samples = 160;
	c->rtp_clock = 8000;
	c->ts_per_frame = 160;
	c->max_payload = 160;
	c->max_decode = 960;	/* up to 120 ms */
	return c;
}
