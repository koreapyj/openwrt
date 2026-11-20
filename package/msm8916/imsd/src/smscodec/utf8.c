/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "utf8.h"

int utf8_decode(const char *s, size_t n, uint32_t *cp)
{
	const uint8_t *p = (const uint8_t *)s;
	uint32_t c;
	size_t len, i;

	if (n == 0)
		return -1;
	c = p[0];
	if (c < 0x80) {
		*cp = c;
		return 1;
	}
	if (c >= 0xC2 && c <= 0xDF) {
		len = 2;
		c &= 0x1F;
	} else if (c >= 0xE0 && c <= 0xEF) {
		len = 3;
		c &= 0x0F;
	} else if (c >= 0xF0 && c <= 0xF4) {
		len = 4;
		c &= 0x07;
	} else {
		return -1;
	}
	if (n < len)
		return -1;
	for (i = 1; i < len; i++) {
		if ((p[i] & 0xC0) != 0x80)
			return -1;
		c = (c << 6) | (p[i] & 0x3F);
	}
	if ((len == 3 && c < 0x800) || (len == 4 && c < 0x10000))
		return -1;	/* overlong */
	if (c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF))
		return -1;
	*cp = c;
	return (int)len;
}

int utf8_encode(uint32_t cp, char out[4])
{
	if (cp < 0x80) {
		out[0] = (char)cp;
		return 1;
	}
	if (cp < 0x800) {
		out[0] = (char)(0xC0 | (cp >> 6));
		out[1] = (char)(0x80 | (cp & 0x3F));
		return 2;
	}
	if (cp >= 0xD800 && cp <= 0xDFFF)
		return 0;
	if (cp < 0x10000) {
		out[0] = (char)(0xE0 | (cp >> 12));
		out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
		out[2] = (char)(0x80 | (cp & 0x3F));
		return 3;
	}
	if (cp <= 0x10FFFF) {
		out[0] = (char)(0xF0 | (cp >> 18));
		out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
		out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
		out[3] = (char)(0x80 | (cp & 0x3F));
		return 4;
	}
	return 0;
}
