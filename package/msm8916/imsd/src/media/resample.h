/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MEDIA_RESAMPLE_H
#define IMSD_MEDIA_RESAMPLE_H
#include <stddef.h>
#include <stdint.h>

/*
 * Fixed-ratio 2:1 / 1:2 resampler (8 kHz <-> 16 kHz) built on one linear
 * phase half-band style low-pass FIR (RS_TAPS taps, Kaiser window, cut-off
 * at a quarter of the high rate, > 55 dB stop band from 4.6 kHz at 16 kHz).
 * Group delay is (RS_TAPS-1)/2 samples at the high rate (24 samples = 1.5 ms).
 * An instance holds the filter history of ONE stream and ONE direction;
 * use separate instances per direction.  No allocation.
 */
#define RS_TAPS 49
#define RS_MAX_IN 1024		/* maximum input samples per call */

struct resamp {
	int16_t coef[RS_TAPS];	/* Q15, DC gain 1.0 */
	int16_t hist[RS_TAPS];	/* previous input samples (oldest first) */
};

void resamp_init(struct resamp *r);
/* in: n samples at the low rate -> out: 2n samples. Returns 2n, or -1 if n > RS_MAX_IN. */
int resamp_up2(struct resamp *r, const int16_t *in, size_t n, int16_t *out);
/* in: n samples (n even) at the high rate -> out: n/2 samples. Returns n/2, or -1 if n odd / > RS_MAX_IN. */
int resamp_down2(struct resamp *r, const int16_t *in, size_t n, int16_t *out);
#endif
