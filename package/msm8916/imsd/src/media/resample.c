/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <math.h>
#include <string.h>
#include "resample.h"

static double bessel_i0(double x)
{
	double s = 1, t = 1;
	int k;

	for (k = 1; k < 30; k++) {
		t *= (x / (2 * k)) * (x / (2 * k));
		s += t;
	}
	return s;
}

void resamp_init(struct resamp *r)
{
	double h[RS_TAPS], sum = 0;
	const double beta = 7.0, pi = 3.14159265358979323846;
	int i, c = RS_TAPS / 2;

	memset(r->hist, 0, sizeof(r->hist));
	for (i = 0; i < RS_TAPS; i++) {
		double n = i - c, x = n / c;
		double s = n == 0 ? 0.5 : sin(pi * n / 2) / (pi * n);	/* fc = fs/4 */

		h[i] = s * bessel_i0(beta * sqrt(1 - x * x)) / bessel_i0(beta);
		sum += h[i];
	}
	for (i = 0; i < RS_TAPS; i++)
		r->coef[i] = (int16_t)lrint(h[i] / sum * 32768.0 > 32767 ? 32767 : h[i] / sum * 32768.0);
}

static inline int16_t sat16(int32_t v)
{
	return v > 32767 ? 32767 : v < -32768 ? -32768 : (int16_t)v;
}

int resamp_up2(struct resamp *r, const int16_t *in, size_t n, int16_t *out)
{
	int16_t w[RS_TAPS + RS_MAX_IN];
	size_t k;
	int j;

	if (n > RS_MAX_IN)
		return -1;
	/* history holds the last RS_TAPS/2+1 input samples that can still matter */
	memcpy(w, r->hist, sizeof(int16_t) * (RS_TAPS - 1));
	memcpy(w + RS_TAPS - 1, in, n * sizeof(int16_t));
	/* zero stuffed signal x'[2k] = x[k]; y[m] = sum_j h[j] x'[m-j] (gain 2) */
	for (k = 0; k < n; k++) {
		int32_t a0 = 0, a1 = 0;
		const int16_t *x = w + RS_TAPS - 1 + k;	/* x[k] */

		/* even output 2k: taps j even, x[k - j/2]; odd output 2k+1: taps j odd, x[k - (j-1)/2] */
		for (j = 0; j < RS_TAPS; j += 2)
			a0 += r->coef[j] * x[-(j / 2)];
		for (j = 1; j < RS_TAPS; j += 2)
			a1 += r->coef[j] * x[-(j / 2)];
		out[2 * k] = sat16((a0 + (1 << 13)) >> 14);
		out[2 * k + 1] = sat16((a1 + (1 << 13)) >> 14);
	}
	memcpy(r->hist, w + n, sizeof(int16_t) * (RS_TAPS - 1));
	return (int)(2 * n);
}

int resamp_down2(struct resamp *r, const int16_t *in, size_t n, int16_t *out)
{
	int16_t w[RS_TAPS + RS_MAX_IN];
	size_t k;
	int j;

	if (n > RS_MAX_IN || (n & 1))
		return -1;
	memcpy(w, r->hist, sizeof(int16_t) * (RS_TAPS - 1));
	memcpy(w + RS_TAPS - 1, in, n * sizeof(int16_t));
	for (k = 0; k < n; k += 2) {
		int32_t a = 0;
		const int16_t *x = w + RS_TAPS - 1 + k;

		for (j = 0; j < RS_TAPS; j++)
			a += r->coef[j] * x[-j];
		out[k / 2] = sat16((a + (1 << 14)) >> 15);
	}
	memcpy(r->hist, w + n, sizeof(int16_t) * (RS_TAPS - 1));
	return (int)(n / 2);
}
