/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MEDIA_TEST_H
#define IMSD_MEDIA_TEST_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern int g_checks, g_fail;

#define CHECK(c) do { \
	g_checks++; \
	if (!(c)) { \
		g_fail++; \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
	} \
} while (0)

#define CHECKF(c, ...) do { \
	g_checks++; \
	if (!(c)) { \
		g_fail++; \
		fprintf(stderr, "FAIL %s:%d: %s: ", __FILE__, __LINE__, #c); \
		fprintf(stderr, __VA_ARGS__); \
		fputc('\n', stderr); \
	} \
} while (0)

/* Recordings of a live line (RTP payload captures) are NOT part of the tree: the directory comes from the environment
 * variable IMSD_TEST_CAPDIR; without it the capture based checks are skipped (counted in g_skipped, "SKIP" lines). */
extern int g_skipped;

/* real RTP payload capture: u32 arrival_ms, u16 seq, u32 rtp_ts, u8 pt, u16 len, payload (little endian, packed) */
struct cap_rec {
	uint32_t ms;
	uint16_t seq;
	uint32_t ts;
	uint8_t pt;
	uint16_t len;
	const uint8_t *p;
};
struct cap {
	uint8_t *buf;
	struct cap_rec *r;
	size_t n;
};
/* rel is relative to $IMSD_TEST_CAPDIR; 0, or -1 when the directory is not set / the file is missing (counted as skipped) */
int cap_load(struct cap *c, const char *rel);
void cap_free(struct cap *c);

double rms16(const int16_t *x, size_t n);
/* best normalised cross correlation of a[i] with b[i+lag], lag 0..maxlag */
double best_corr(const int16_t *a, const int16_t *b, size_t n, int maxlag, int *lag);
/* scratch directory for files written by tests */
const char *test_tmp(void);

void test_rtp(void);
void test_amr(void);
void test_codec(void);
void test_dtmf(void);
void test_bridge(void);
void test_stress(void);
void test_pcmdev(void);
#endif
