/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdlib.h>
#include "codec_priv.h"

void codec_params_default(struct codec_params *p)
{
	p->mode = -1;
	p->modeset = 0;
	p->dtx = false;
	p->bitrate = 0;
	p->complexity = -1;
	p->fec = false;
	p->pcm_rate = 0;
}

const char *codec_name(enum codec_id id)
{
	static const char *const n[CODEC_COUNT] = { "AMR", "AMR-WB", "opus", "PCMA", "G722" };

	return (unsigned)id < CODEC_COUNT ? n[id] : "?";
}

bool codec_available(enum codec_id id)
{
	switch (id) {
	case CODEC_AMRNB:
	case CODEC_AMRWB:
	case CODEC_PCMA:
		return true;
	case CODEC_OPUS:
#ifdef IMSD_WITH_OPUS
		return true;
#else
		return false;
#endif
	case CODEC_G722:
#ifdef IMSD_WITH_G722
		return true;
#else
		return false;
#endif
	default:
		return false;
	}
}

struct codec *codec_create(enum codec_id id, const struct codec_params *p)
{
	struct codec_params def;

	if (!p) {
		codec_params_default(&def);
		p = &def;
	}
	switch (id) {
	case CODEC_AMRNB:
		return codec_amrnb_create(p);
	case CODEC_AMRWB:
		return codec_amrwb_create(p);
	case CODEC_PCMA:
		return codec_pcma_create(p);
#ifdef IMSD_WITH_OPUS
	case CODEC_OPUS:
		return codec_opus_create(p);
#endif
#ifdef IMSD_WITH_G722
	case CODEC_G722:
		return codec_g722_create(p);
#endif
	default:
		return NULL;
	}
}

void codec_destroy(struct codec *c)
{
	if (c)
		c->ops->destroy(c);
}

enum codec_id codec_get_id(const struct codec *c) { return c->id; }
int codec_pcm_rate(const struct codec *c) { return c->pcm_rate; }
int codec_frame_samples(const struct codec *c) { return c->frame_samples; }
int codec_rtp_clock(const struct codec *c) { return c->rtp_clock; }
int codec_ts_per_frame(const struct codec *c) { return c->ts_per_frame; }
size_t codec_max_payload(const struct codec *c) { return c->max_payload; }
size_t codec_max_decode_samples(const struct codec *c) { return c->max_decode; }

int codec_encode(struct codec *c, const int16_t *pcm, uint8_t *out, size_t outsz)
{
	if (outsz < c->max_payload)
		return -1;
	return c->ops->encode(c, pcm, out, outsz);
}

int codec_decode(struct codec *c, const uint8_t *data, size_t len, int16_t *pcm, size_t max)
{
	if (max < (size_t)c->frame_samples)
		return -1;
	return c->ops->decode(c, data, len, pcm, max);
}

int codec_set_mode(struct codec *c, int mode)
{
	return c->ops->set_mode ? c->ops->set_mode(c, mode) : -1;
}

int codec_get_mode(const struct codec *c)
{
	return (c->id == CODEC_AMRNB || c->id == CODEC_AMRWB) ? c->mode : -1;
}

int codec_set_bitrate(struct codec *c, int bps)
{
	return c->ops->set_bitrate ? c->ops->set_bitrate(c, bps) : 0;
}

int codec_set_dtx(struct codec *c, bool dtx)
{
	return c->ops->set_dtx ? c->ops->set_dtx(c, dtx) : 0;
}
