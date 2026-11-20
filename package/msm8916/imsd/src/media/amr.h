/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MEDIA_AMR_H
#define IMSD_MEDIA_AMR_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * AMR / AMR-WB RTP payload format (RFC 4867), bandwidth-efficient and
 * octet-aligned, single channel.  Not supported (rejected or ignored): CRC,
 * robust sorting, interleaving (the daemon never negotiates them).
 *
 * A parsed frame is kept in the "storage format" that the opencore decoders
 * and the encoders' output use: byte 0 is (FT << 3) | (Q << 2), followed by
 * the speech bits packed MSB first and padded with zero bits to a whole
 * byte.  The same bit order is used on the wire, so for octet-aligned
 * packets the frame bytes are a plain copy and for bandwidth-efficient
 * packets they are just shifted.
 */

enum amr_type { AMR_NB = 0, AMR_WB = 1 };

#define AMR_NB_FT_SID 8
#define AMR_WB_FT_SID 9
#define AMR_WB_FT_LOST 14	/* "speech lost" (WB only) */
#define AMR_FT_NO_DATA 15
#define AMR_CMR_NONE 15		/* "no mode request" */
#define AMR_MAX_FRAMES 16	/* frames accepted per packet */
#define AMR_MAX_SPEECH_BYTES 61	/* AMR-WB 23.85k: 477 bits */

struct amr_frame {
	uint8_t ft;			/* frame type 0..15 */
	uint8_t q;			/* quality indicator bit */
	uint8_t nbytes;			/* speech bytes in data[1..] */
	uint8_t data[1 + AMR_MAX_SPEECH_BYTES];	/* storage format frame, 1 + nbytes valid */
};

struct amr_pdu {
	uint8_t cmr;			/* codec mode request, 0..15 (15 = none) */
	unsigned n;			/* number of frames */
	struct amr_frame f[AMR_MAX_FRAMES];
};

/* Number of speech bits of a frame type (SID and NO_DATA included), -1 if the FT is reserved / invalid for the codec. */
int amr_frame_bits(enum amr_type t, unsigned ft);
/* speech bytes of a frame type (ceil(bits/8)), -1 if invalid */
int amr_frame_bytes(enum amr_type t, unsigned ft);
/* true for speech frame types (NB 0..7, WB 0..8) */
bool amr_ft_is_speech(enum amr_type t, unsigned ft);
/* true for SID and NO_DATA / speech-lost frames (the DTX family) */
bool amr_ft_is_dtx(enum amr_type t, unsigned ft);
/* highest speech mode number (NB 7, WB 8) */
int amr_max_mode(enum amr_type t);
/* bit rate of a speech mode in bit/s (0 if invalid) */
int amr_mode_bps(enum amr_type t, int mode);

/*
 * Parse an RTP payload.  oa selects octet-aligned (true) or
 * bandwidth-efficient layout.  Returns 0 on success, -1 on malformed input
 * (empty payload, no ToC terminator, reserved frame type, truncated frame
 * data, more than AMR_MAX_FRAMES frames).  Bytes after the last frame are
 * ignored.  Never reads outside [p, p+len).
 */
int amr_parse(enum amr_type t, bool oa, const uint8_t *p, size_t len, struct amr_pdu *out);

/*
 * Build a payload from cmr and n frames (f[i].ft, .q and .data[1..] are
 * used, data[0] is ignored).  Returns the payload length or -1 (n == 0,
 * n > AMR_MAX_FRAMES, bad FT, cmr > 15, outsz too small).
 */
int amr_build(enum amr_type t, bool oa, unsigned cmr, const struct amr_frame *f, unsigned n,
	      uint8_t *out, size_t outsz);

/* Set fr->data[0] from ft / q (call after filling ft/q). */
void amr_frame_finish(struct amr_frame *fr);
/*
 * Make a frame out of a codec-library storage frame (as produced by the
 * encoders); returns 0, or -1 if len does not match the FT.
 */
int amr_frame_from_storage(enum amr_type t, struct amr_frame *fr, const uint8_t *st, size_t len);
/* storage frame length of fr (1 + nbytes) */
static inline size_t amr_frame_storage_len(const struct amr_frame *fr)
{
	return 1u + fr->nbytes;
}

/* ---- mode-set (RFC 4867 sec. 8.1) and CMR helpers ---- */

/* mask with every mode of the codec allowed (bit i = mode i) */
uint16_t amr_modeset_all(enum amr_type t);
/*
 * Parse an fmtp mode-set value such as "0,2,7".  An empty / NULL string
 * means "all modes".  Returns the mask, or 0 if the list is malformed or
 * names a mode the codec does not have.
 */
uint16_t amr_modeset_parse(enum amr_type t, const char *list);
/*
 * Highest mode in mask that is <= requested; if none is that low, the
 * lowest allowed mode.  A mask without any valid bit falls back to
 * requested clamped to the codec range.
 */
int amr_mode_clamp(enum amr_type t, uint16_t mask, int requested);
/*
 * Apply a received CMR to the current encoder mode: CMR 15 or an invalid
 * CMR keeps cur; otherwise amr_mode_clamp(mask, cmr).
 */
int amr_apply_cmr(enum amr_type t, uint16_t mask, int cur, unsigned cmr);
#endif
