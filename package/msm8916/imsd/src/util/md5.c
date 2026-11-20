/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "md5.h"
#include "codec.h"

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
static const uint32_t K[64] = {
	0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
	0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
	0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
	0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
	0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
	0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
	0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
	0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
static const uint8_t R[64] = {
	7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22, 5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
	4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23, 6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };

static void md5_block(uint32_t s[4], const uint8_t *p)
{
	uint32_t w[16], a = s[0], b = s[1], c = s[2], d = s[3], f, t;
	int i, g;

	for (i = 0; i < 16; i++)
		w[i] = p[i * 4] | p[i * 4 + 1] << 8 | p[i * 4 + 2] << 16 | (uint32_t)p[i * 4 + 3] << 24;
	for (i = 0; i < 64; i++) {
		if (i < 16)      { f = (b & c) | (~b & d); g = i; }
		else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
		else if (i < 48) { f = b ^ c ^ d;          g = (3 * i + 5) & 15; }
		else             { f = c ^ (b | ~d);       g = (7 * i) & 15; }
		t = d; d = c; c = b;
		b = b + ROL(a + f + K[i] + w[g], R[i]);
		a = t;
	}
	s[0] += a; s[1] += b; s[2] += c; s[3] += d;
}

void md5_init(struct md5_ctx *c)
{
	c->s[0] = 0x67452301; c->s[1] = 0xefcdab89; c->s[2] = 0x98badcfe; c->s[3] = 0x10325476;
	c->bytes = 0;
}

void md5_update(struct md5_ctx *c, const void *data, size_t len)
{
	const uint8_t *p = data;
	size_t fill = c->bytes & 63;

	c->bytes += len;
	if (fill) {
		size_t n = 64 - fill < len ? 64 - fill : len;

		memcpy(c->buf + fill, p, n);
		p += n; len -= n;
		if (fill + n < 64)
			return;
		md5_block(c->s, c->buf);
	}
	while (len >= 64) {
		md5_block(c->s, p);
		p += 64; len -= 64;
	}
	memcpy(c->buf, p, len);
}

void md5_final(struct md5_ctx *c, uint8_t out[16])
{
	uint64_t bits = c->bytes * 8;
	uint8_t pad[72] = { 0x80 };
	size_t fill = c->bytes & 63, padlen = (fill < 56 ? 56 : 120) - fill;
	int i;

	md5_update(c, pad, padlen);
	for (i = 0; i < 8; i++)
		pad[i] = bits >> (8 * i);
	md5_update(c, pad, 8);
	for (i = 0; i < 16; i++)
		out[i] = c->s[i / 4] >> (8 * (i % 4));
}

void md5_buf(const void *data, size_t len, uint8_t out[16])
{
	struct md5_ctx c;

	md5_init(&c);
	md5_update(&c, data, len);
	md5_final(&c, out);
}

void md5_hex(const void *data, size_t len, char out[33])
{
	uint8_t d[16];

	md5_buf(data, len, d);
	hex_encode(d, 16, out);
}
