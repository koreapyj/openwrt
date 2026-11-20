/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MEDIA_CODEC_H
#define IMSD_MEDIA_CODEC_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Uniform speech codec interface.  One struct codec is one encoder plus one
 * decoder (independent states) for a single leg.  Everything works on
 * 20 ms frames of mono 16-bit PCM.  No function allocates after creation;
 * a codec instance must only be used by one thread at a time.
 *
 * Payload byte conventions of encode()/decode():
 *   AMRNB, AMRWB : one frame in codec-library storage format (1 header byte
 *                  (FT << 3) | (Q << 2) followed by the octet-padded speech
 *                  bits), exactly what amr_frame_from_storage()/amr.h use.
 *                  Pack/unpack to RTP with amr_build()/amr_parse().
 *   OPUS         : the Opus packet as it goes into the RTP payload.
 *   PCMA, G722   : 160 octets per 20 ms.
 */

enum codec_id {
	CODEC_AMRNB = 0,	/* 8 kHz, RTP clock 8000 */
	CODEC_AMRWB,		/* 16 kHz, RTP clock 16000 */
	CODEC_OPUS,		/* RTP clock always 48000 (RFC 7587); PCM rate configurable */
	CODEC_PCMA,		/* G.711 A-law, 8 kHz, clock 8000 */
	CODEC_G722,		/* 16 kHz audio, RTP clock 8000 (RFC 3551) */
	CODEC_COUNT
};

struct codec_params {
	/* AMR */
	int mode;		/* initial encoder mode; -1: highest allowed by modeset */
	uint16_t modeset;	/* allowed encoder modes, bit i = mode i; 0: all */
	/* AMR (encoder DTX: SID / NO_DATA frames come out of encode()) and Opus (DTX) */
	bool dtx;
	/* Opus */
	int bitrate;		/* bit/s; 0: 24000 */
	int complexity;		/* 0..10; -1: 5 (suits a Cortex-A53) */
	bool fec;		/* in-band FEC, default off */
	int pcm_rate;		/* internal PCM rate 8000/12000/16000/24000/48000; 0: 16000 */
};

/* fill p with the defaults described above */
void codec_params_default(struct codec_params *p);

struct codec;

const char *codec_name(enum codec_id id);
/* false if that codec was compiled out (IMSD_WITH_OPUS / IMSD_WITH_G722 not defined) */
bool codec_available(enum codec_id id);
/* p may be NULL (defaults).  NULL on failure / unavailable codec / bad parameter. */
struct codec *codec_create(enum codec_id id, const struct codec_params *p);
void codec_destroy(struct codec *c);	/* NULL ok */

enum codec_id codec_get_id(const struct codec *c);
/* PCM sample rate in Hz of the audio handed to encode() / returned by decode() */
int codec_pcm_rate(const struct codec *c);
/* samples in one 20 ms frame at the PCM rate */
int codec_frame_samples(const struct codec *c);
/* RTP clock rate in Hz */
int codec_rtp_clock(const struct codec *c);
/* RTP timestamp increment of one 20 ms frame (160 / 320 / 960 / 160 / 160) */
int codec_ts_per_frame(const struct codec *c);
/* upper bound for one encoded payload (storage frame for AMR) */
size_t codec_max_payload(const struct codec *c);
/* largest sample count decode() can return for one call */
size_t codec_max_decode_samples(const struct codec *c);

/*
 * Encode one frame of codec_frame_samples() samples.  pcm is not modified.
 * Returns the number of bytes written (> 0), 0 if nothing is to be sent
 * (reserved for codecs that drop frames), -1 on error.
 */
int codec_encode(struct codec *c, const int16_t *pcm, uint8_t *out, size_t outsz);

/*
 * Decode one payload to PCM (at most max samples are written; max must be at
 * least codec_max_decode_samples() for a hostile Opus packet, otherwise the
 * packet is rejected).  data == NULL means "frame lost": the codec runs its
 * packet-loss concealment and returns one frame.  Returns the sample count
 * or -1.  Opus packets may hold 2.5..120 ms, so the count can differ from
 * codec_frame_samples().
 */
int codec_decode(struct codec *c, const uint8_t *data, size_t len, int16_t *pcm, size_t max);

/* AMR: set the encoder mode (clamped to the mode-set); returns the mode in use or -1 for other codecs */
int codec_set_mode(struct codec *c, int mode);
int codec_get_mode(const struct codec *c);
/* Opus: bit rate; AMR: selects the nearest allowed mode not above bps; PCMA/G722: no-op. 0 / -1 */
int codec_set_bitrate(struct codec *c, int bps);
/* AMR-NB re-creates the encoder (state restart), AMR-WB and Opus switch at once, others no-op */
int codec_set_dtx(struct codec *c, bool dtx);
#endif
