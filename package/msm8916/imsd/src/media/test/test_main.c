/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"

int g_checks, g_fail, g_skipped;

int cap_load(struct cap *c, const char *rel)
{
	const char *dir = getenv("IMSD_TEST_CAPDIR");
	char path[512];
	FILE *f = NULL;
	long sz;
	size_t i = 0, n = 0, cnt = 0;

	memset(c, 0, sizeof(*c));
	if (dir && *dir && snprintf(path, sizeof(path), "%s/%s", dir, rel) < (int)sizeof(path))
		f = fopen(path, "rb");
	if (!f) {
		g_skipped++;
		printf("SKIP capture %s (IMSD_TEST_CAPDIR %s)\n", rel, dir && *dir ? "has no such file" : "not set");
		return -1;
	}
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	c->buf = malloc((size_t)sz + 1);
	if (!c->buf || fread(c->buf, 1, (size_t)sz, f) != (size_t)sz) {
		fclose(f);
		free(c->buf);
		c->buf = NULL;
		return -1;
	}
	fclose(f);
	for (i = 0; i + 13 <= (size_t)sz; cnt++) {
		uint16_t len = (uint16_t)(c->buf[i + 11] | c->buf[i + 12] << 8);

		i += 13 + len;
	}
	c->r = calloc(cnt + 1, sizeof(*c->r));
	for (i = 0; i + 13 <= (size_t)sz && n < cnt;) {
		const uint8_t *b = c->buf + i;
		struct cap_rec *r = &c->r[n++];

		r->ms = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
		r->seq = (uint16_t)(b[4] | b[5] << 8);
		r->ts = (uint32_t)b[6] | (uint32_t)b[7] << 8 | (uint32_t)b[8] << 16 | (uint32_t)b[9] << 24;
		r->pt = b[10];
		r->len = (uint16_t)(b[11] | b[12] << 8);
		r->p = b + 13;
		i += 13 + r->len;
		if (i > (size_t)sz) {
			n--;
			break;
		}
	}
	c->n = n;
	return 0;
}

void cap_free(struct cap *c)
{
	free(c->buf);
	free(c->r);
	memset(c, 0, sizeof(*c));
}

double rms16(const int16_t *x, size_t n)
{
	double s = 0;
	size_t i;

	for (i = 0; i < n; i++)
		s += (double)x[i] * x[i];
	return n ? sqrt(s / (double)n) : 0;
}

double best_corr(const int16_t *a, const int16_t *b, size_t n, int maxlag, int *lagp)
{
	double best = -2;
	int lag, bl = 0;
	size_t i;

	for (lag = 0; lag <= maxlag; lag++) {
		double c = 0, e = 0, f = 0;

		for (i = 0; i + (size_t)lag < n; i++) {
			c += (double)a[i] * b[i + (size_t)lag];
			e += (double)a[i] * a[i];
			f += (double)b[i + (size_t)lag] * b[i + (size_t)lag];
		}
		c /= sqrt(e * f) + 1e-9;
		if (c > best) {
			best = c;
			bl = lag;
		}
	}
	if (lagp)
		*lagp = bl;
	return best;
}

const char *test_tmp(void)
{
	const char *t = getenv("IMSD_TEST_TMP");

	return t && *t ? t : "/tmp";
}

int main(int argc, char **argv)
{
	static const struct { const char *name; void (*fn)(void); } T[] = {
		{ "rtp", test_rtp }, { "amr", test_amr }, { "codec", test_codec }, { "dtmf", test_dtmf },
		{ "bridge", test_bridge }, { "stress", test_stress }, { "pcmdev", test_pcmdev },
	};
	size_t i;
	int a;

	for (i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
		bool run = argc == 1;

		for (a = 1; a < argc; a++)
			if (!strcmp(argv[a], T[i].name) || (!strcmp(argv[a], "threads") && i >= 4))
				run = true;
		if (!run)
			continue;
		int before = g_fail, bc = g_checks;

		T[i].fn();
		printf("%-7s %4d checks, %d failed\n", T[i].name, g_checks - bc, g_fail - before);
		fflush(stdout);
	}
	if (g_skipped)
		printf("%d capture based tests skipped (IMSD_TEST_CAPDIR)\n", g_skipped);
	printf("TOTAL %d checks, %d failed\n", g_checks, g_fail);
	return g_fail ? 1 : 0;
}
