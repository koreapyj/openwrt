/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MEDIA_CODEC_PRIV_H
#define IMSD_MEDIA_CODEC_PRIV_H
#include "codec.h"

/* internal: codec implementations plug in through this table */
struct codec_ops {
	void (*destroy)(struct codec *c);
	int (*encode)(struct codec *c, const int16_t *pcm, uint8_t *out, size_t outsz);
	int (*decode)(struct codec *c, const uint8_t *data, size_t len, int16_t *pcm, size_t max);
	int (*set_mode)(struct codec *c, int mode);
	int (*set_bitrate)(struct codec *c, int bps);
	int (*set_dtx)(struct codec *c, bool dtx);
};

struct codec {
	const struct codec_ops *ops;
	enum codec_id id;
	int pcm_rate, frame_samples, rtp_clock, ts_per_frame;
	size_t max_payload, max_decode;
	int mode;		/* AMR */
	uint16_t modeset;
};

struct codec *codec_amrnb_create(const struct codec_params *p);
struct codec *codec_amrwb_create(const struct codec_params *p);
struct codec *codec_pcma_create(const struct codec_params *p);
struct codec *codec_opus_create(const struct codec_params *p);	/* IMSD_WITH_OPUS */
struct codec *codec_g722_create(const struct codec_params *p);	/* IMSD_WITH_G722 */
#endif
