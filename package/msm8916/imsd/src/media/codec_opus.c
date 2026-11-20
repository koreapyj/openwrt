/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Opus wrapper (mono, 20 ms, VOIP application).  The RTP clock is always
 * 48000 (RFC 7587) while the codec runs at the configured internal rate
 * (default 16 kHz), so one 20 ms frame is 960 RTP ticks but 320 samples.
 * Defaults: 24 kbit/s VBR, complexity 5, in-band FEC off, DTX off.
 */
#include <stdlib.h>
#include <opus/opus.h>
#include "codec_priv.h"

struct opusc {
	struct codec c;
	OpusEncoder *enc;
	OpusDecoder *dec;
};

static int opus_enc(struct codec *c, const int16_t *pcm, uint8_t *out, size_t outsz)
{
	struct opusc *o = (struct opusc *)c;
	int n = opus_encode(o->enc, pcm, c->frame_samples, out, (opus_int32)outsz);

	return n > 0 ? n : -1;
}

static int opus_dec(struct codec *c, const uint8_t *d, size_t len, int16_t *pcm, size_t max)
{
	struct opusc *o = (struct opusc *)c;
	int n;

	if (!d)
		return opus_decode(o->dec, NULL, 0, pcm, c->frame_samples, 0) > 0 ? c->frame_samples : -1;
	if (len == 0)
		return -1;
	n = opus_decode(o->dec, d, (opus_int32)len, pcm, (int)(max > 5760 ? 5760 : max), 0);
	return n > 0 ? n : -1;
}

static int opus_setbr(struct codec *c, int bps)
{
	return opus_encoder_ctl(((struct opusc *)c)->enc, OPUS_SET_BITRATE(bps)) == OPUS_OK ? 0 : -1;
}

static int opus_setdtx(struct codec *c, bool dtx)
{
	return opus_encoder_ctl(((struct opusc *)c)->enc, OPUS_SET_DTX(dtx ? 1 : 0)) == OPUS_OK ? 0 : -1;
}

static void opus_destroy(struct codec *c)
{
	struct opusc *o = (struct opusc *)c;

	if (o->enc)
		opus_encoder_destroy(o->enc);
	if (o->dec)
		opus_decoder_destroy(o->dec);
	free(o);
}

static const struct codec_ops ops = {
	.destroy = opus_destroy, .encode = opus_enc, .decode = opus_dec,
	.set_bitrate = opus_setbr, .set_dtx = opus_setdtx,
};

struct codec *codec_opus_create(const struct codec_params *p)
{
	struct opusc *o;
	int rate = p->pcm_rate ? p->pcm_rate : 16000, err = 0;

	if (rate != 8000 && rate != 12000 && rate != 16000 && rate != 24000 && rate != 48000)
		return NULL;
	o = calloc(1, sizeof(*o));
	if (!o)
		return NULL;
	o->c.ops = &ops;
	o->c.id = CODEC_OPUS;
	o->c.pcm_rate = rate;
	o->c.frame_samples = rate / 50;
	o->c.rtp_clock = 48000;
	o->c.ts_per_frame = 960;
	o->c.max_payload = 1276;
	o->c.max_decode = (size_t)rate * 120 / 1000;
	o->enc = opus_encoder_create(rate, 1, OPUS_APPLICATION_VOIP, &err);
	if (!o->enc)
		goto fail;
	o->dec = opus_decoder_create(rate, 1, &err);
	if (!o->dec)
		goto fail;
	opus_encoder_ctl(o->enc, OPUS_SET_BITRATE(p->bitrate > 0 ? p->bitrate : 24000));
	opus_encoder_ctl(o->enc, OPUS_SET_VBR(1));
	opus_encoder_ctl(o->enc, OPUS_SET_COMPLEXITY(p->complexity >= 0 && p->complexity <= 10 ? p->complexity : 5));
	opus_encoder_ctl(o->enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
	opus_encoder_ctl(o->enc, OPUS_SET_INBAND_FEC(p->fec ? 1 : 0));
	opus_encoder_ctl(o->enc, OPUS_SET_PACKET_LOSS_PERC(p->fec ? 10 : 0));
	opus_encoder_ctl(o->enc, OPUS_SET_DTX(p->dtx ? 1 : 0));
	return &o->c;
fail:
	opus_destroy(&o->c);
	return NULL;
}
