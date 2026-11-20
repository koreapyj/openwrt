/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * AMR-NB (opencore-amrnb encoder + decoder) and AMR-WB (vo-amrwbenc encoder,
 * opencore-amrwb decoder) wrappers.
 *
 * opencore-amrnb's Encoder_Interface_Encode() overwrites its input PCM, so
 * the wrapper encodes from a private copy.  The decoders read a fixed number
 * of bytes derived from the FT in the header, therefore the wrapper checks
 * the length first.  Loss (data == NULL) is signalled with the library's own
 * "bad frame" input (NO_DATA), which makes both decoders run concealment.
 */
#include <stdlib.h>
#include <string.h>
#include <opencore-amrnb/interf_dec.h>
#include <opencore-amrnb/interf_enc.h>
#include <opencore-amrwb/dec_if.h>
#include <vo-amrwbenc/enc_if.h>
#include "amr.h"
#include "codec_priv.h"

struct amrc {
	struct codec c;
	void *enc, *dec;
	bool dtx;
	enum amr_type type;
};

static int amr_set_mode(struct codec *c, int mode)
{
	enum amr_type t = c->id == CODEC_AMRWB ? AMR_WB : AMR_NB;

	c->mode = amr_mode_clamp(t, c->modeset, mode);
	return c->mode;
}

static int amr_set_bitrate(struct codec *c, int bps)
{
	enum amr_type t = c->id == CODEC_AMRWB ? AMR_WB : AMR_NB;
	int m, best = 0;

	for (m = 0; m <= amr_max_mode(t); m++)
		if (amr_mode_bps(t, m) <= bps)
			best = m;
	amr_set_mode(c, best);
	return 0;
}

static int amr_decode(struct codec *c, const uint8_t *data, size_t len, int16_t *pcm, size_t max)
{
	struct amrc *a = (struct amrc *)c;
	uint8_t tmp[1 + AMR_MAX_SPEECH_BYTES + 1];
	int bfi = 0;

	(void)max;	/* checked by codec_decode: >= frame_samples, and AMR yields exactly one frame */
	if (!data) {
		memset(tmp, 0, sizeof(tmp));
		tmp[0] = AMR_FT_NO_DATA << 3;
		bfi = 1;
	} else {
		int nb;

		if (len < 1)
			return -1;
		nb = amr_frame_bytes(a->type, (data[0] >> 3) & 0x0f);
		if (nb < 0 || len < (size_t)nb + 1)
			return -1;
		memset(tmp, 0, sizeof(tmp));
		memcpy(tmp, data, (size_t)nb + 1);
	}
	if (a->type == AMR_WB)
		D_IF_decode(a->dec, tmp, pcm, bfi);
	else
		Decoder_Interface_Decode(a->dec, tmp, pcm, bfi);
	return c->frame_samples;
}

static int amrnb_encode(struct codec *c, const int16_t *pcm, uint8_t *out, size_t outsz)
{
	struct amrc *a = (struct amrc *)c;
	short work[160];
	uint8_t tmp[64];
	int n;

	(void)outsz;
	memcpy(work, pcm, sizeof(work));	/* the library scribbles over its input */
	n = Encoder_Interface_Encode(a->enc, (enum Mode)c->mode, work, tmp, 0);
	if (n < 1 || n > (int)c->max_payload)
		return -1;
	memcpy(out, tmp, (size_t)n);
	return n;
}

static int amrwb_encode(struct codec *c, const int16_t *pcm, uint8_t *out, size_t outsz)
{
	struct amrc *a = (struct amrc *)c;
	uint8_t tmp[80];
	int n;

	(void)outsz;
	n = E_IF_encode(a->enc, c->mode, pcm, tmp, a->dtx ? 1 : 0);
	if (n < 1 || n > (int)c->max_payload)
		return -1;
	memcpy(out, tmp, (size_t)n);
	return n;
}

static int amrnb_set_dtx(struct codec *c, bool dtx)
{
	struct amrc *a = (struct amrc *)c;
	void *e;

	if (dtx == a->dtx)
		return 0;
	e = Encoder_Interface_init(dtx ? 1 : 0);
	if (!e)
		return -1;
	Encoder_Interface_exit(a->enc);
	a->enc = e;
	a->dtx = dtx;
	return 0;
}

static int amrwb_set_dtx(struct codec *c, bool dtx)
{
	((struct amrc *)c)->dtx = dtx;
	return 0;
}

static void amrnb_destroy(struct codec *c)
{
	struct amrc *a = (struct amrc *)c;

	if (a->enc)
		Encoder_Interface_exit(a->enc);
	if (a->dec)
		Decoder_Interface_exit(a->dec);
	free(a);
}

static void amrwb_destroy(struct codec *c)
{
	struct amrc *a = (struct amrc *)c;

	if (a->enc)
		E_IF_exit(a->enc);
	if (a->dec)
		D_IF_exit(a->dec);
	free(a);
}

static const struct codec_ops nb_ops = {
	.destroy = amrnb_destroy, .encode = amrnb_encode, .decode = amr_decode,
	.set_mode = amr_set_mode, .set_bitrate = amr_set_bitrate, .set_dtx = amrnb_set_dtx,
};

static const struct codec_ops wb_ops = {
	.destroy = amrwb_destroy, .encode = amrwb_encode, .decode = amr_decode,
	.set_mode = amr_set_mode, .set_bitrate = amr_set_bitrate, .set_dtx = amrwb_set_dtx,
};

static struct amrc *amr_alloc(const struct codec_params *p, enum amr_type t)
{
	struct amrc *a = calloc(1, sizeof(*a));

	if (!a)
		return NULL;
	a->type = t;
	a->dtx = p->dtx;
	a->c.id = t == AMR_WB ? CODEC_AMRWB : CODEC_AMRNB;
	a->c.pcm_rate = t == AMR_WB ? 16000 : 8000;
	a->c.frame_samples = a->c.pcm_rate / 50;
	a->c.rtp_clock = a->c.pcm_rate;
	a->c.ts_per_frame = a->c.frame_samples;
	a->c.max_payload = 1 + AMR_MAX_SPEECH_BYTES;
	a->c.max_decode = (size_t)a->c.frame_samples;
	a->c.modeset = p->modeset ? (uint16_t)(p->modeset & amr_modeset_all(t)) : amr_modeset_all(t);
	if (!a->c.modeset) {
		free(a);
		return NULL;
	}
	a->c.mode = amr_mode_clamp(t, a->c.modeset, p->mode < 0 ? amr_max_mode(t) : p->mode);
	return a;
}

struct codec *codec_amrnb_create(const struct codec_params *p)
{
	struct amrc *a = amr_alloc(p, AMR_NB);

	if (!a)
		return NULL;
	a->c.ops = &nb_ops;
	a->enc = Encoder_Interface_init(a->dtx ? 1 : 0);
	a->dec = Decoder_Interface_init();
	if (!a->enc || !a->dec) {
		amrnb_destroy(&a->c);
		return NULL;
	}
	return &a->c;
}

struct codec *codec_amrwb_create(const struct codec_params *p)
{
	struct amrc *a = amr_alloc(p, AMR_WB);

	if (!a)
		return NULL;
	a->c.ops = &wb_ops;
	a->enc = E_IF_init();
	a->dec = D_IF_init();
	if (!a->enc || !a->dec) {
		amrwb_destroy(&a->c);
		return NULL;
	}
	return &a->c;
}
