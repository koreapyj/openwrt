/* SPDX-License-Identifier: GPL-2.0-or-later */
/* G.722 64 kbit/s wrapper around the vendored implementation in g722/ (IMSD_WITH_G722). */
#include <stdlib.h>
#include "codec_priv.h"
#include "g722/g722_enc_dec.h"

struct g722c {
	struct codec c;
	G722EncoderState *enc;
	G722DecoderState *dec;
	int16_t last[320];	/* last decoded frame, repeated (faded) as a crude concealment */
	int plc_run;
};

static int g722_encode(struct codec *c, const int16_t *pcm, uint8_t *out, size_t outsz)
{
	struct g722c *g = (struct g722c *)c;

	(void)outsz;
	return (int)WebRtc_g722_encode(g->enc, out, pcm, 320);
}

static int g722_decode(struct codec *c, const uint8_t *d, size_t len, int16_t *pcm, size_t max)
{
	struct g722c *g = (struct g722c *)c;
	int i, n;

	if (!d) {
		/* repeat the last frame with a 3 dB-ish fade per lost frame, silence after 4 */
		int fade = g->plc_run < 4 ? 4 - g->plc_run : 0;

		for (i = 0; i < 320; i++)
			pcm[i] = (int16_t)(g->last[i] * fade / 5);
		g->plc_run++;
		return 320;
	}
	if (len > max / 2)
		len = max / 2;
	n = (int)WebRtc_g722_decode(g->dec, pcm, d, len);
	if (n == 320) {
		for (i = 0; i < 320; i++)
			g->last[i] = pcm[i];
	}
	g->plc_run = 0;
	return n;
}

static void g722_destroy(struct codec *c)
{
	struct g722c *g = (struct g722c *)c;

	if (g->enc)
		WebRtc_g722_encode_release(g->enc);
	if (g->dec)
		WebRtc_g722_decode_release(g->dec);
	free(g);
}

static const struct codec_ops ops = { .destroy = g722_destroy, .encode = g722_encode, .decode = g722_decode };

struct codec *codec_g722_create(const struct codec_params *p)
{
	struct g722c *g = calloc(1, sizeof(*g));

	(void)p;
	if (!g)
		return NULL;
	g->c.ops = &ops;
	g->c.id = CODEC_G722;
	g->c.pcm_rate = 16000;
	g->c.frame_samples = 320;
	g->c.rtp_clock = 8000;
	g->c.ts_per_frame = 160;
	g->c.max_payload = 160;
	g->c.max_decode = 1920;
	g->enc = WebRtc_g722_encode_init(NULL, 64000, 0);
	g->dec = WebRtc_g722_decode_init(NULL, 64000, 0);
	if (!g->enc || !g->dec) {
		g722_destroy(&g->c);
		return NULL;
	}
	return &g->c;
}
