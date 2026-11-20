/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "codec.h"

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_encode(const uint8_t *s, size_t n, char *out, size_t outsz)
{
	size_t i, o = 0;

	if (outsz < (n + 2) / 3 * 4 + 1)
		return -1;
	for (i = 0; i < n; i += 3) {
		uint32_t v = (uint32_t)s[i] << 16 | (i + 1 < n ? s[i + 1] << 8 : 0) |
			     (i + 2 < n ? s[i + 2] : 0);
		out[o++] = B64[v >> 18 & 63];
		out[o++] = B64[v >> 12 & 63];
		out[o++] = i + 1 < n ? B64[v >> 6 & 63] : '=';
		out[o++] = i + 2 < n ? B64[v & 63] : '=';
	}
	out[o] = 0;
	return o;
}

int b64_decode(const char *s, uint8_t *out, size_t outsz)
{
	uint32_t acc = 0;
	int bits = 0;
	size_t o = 0;

	for (; *s && *s != '='; s++) {
		const char *p;

		if (*s == ' ' || *s == '\r' || *s == '\n')
			continue;
		p = strchr(B64, *s);
		if (!p)
			return -1;
		acc = acc << 6 | (uint32_t)(p - B64);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (o >= outsz)
				return -1;
			out[o++] = acc >> bits & 0xff;
		}
	}
	return o;
}

static int hv(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int hex_decode(const char *s, uint8_t *out, size_t max)
{
	size_t n = 0;

	while (*s) {
		int a, b;

		if (*s == ' ') {
			s++;
			continue;
		}
		a = hv(s[0]);
		b = a < 0 ? -1 : hv(s[1]);
		if (a < 0 || b < 0 || n >= max)
			return -1;
		out[n++] = a << 4 | b;
		s += 2;
	}
	return n;
}

void hex_encode(const uint8_t *in, size_t n, char *out)
{
	static const char H[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		out[2 * i] = H[in[i] >> 4];
		out[2 * i + 1] = H[in[i] & 15];
	}
	out[2 * n] = 0;
}
