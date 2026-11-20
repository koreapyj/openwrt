/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include "util.h"

/* ---- MD5 (RFC 1321) ---- */
struct md5c { uint32_t s[4]; uint64_t bits; uint8_t buf[64]; };

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
		w[i] = p[i*4] | p[i*4+1] << 8 | p[i*4+2] << 16 | (uint32_t)p[i*4+3] << 24;
	for (i = 0; i < 64; i++) {
		if (i < 16)      { f = (b & c) | (~b & d); g = i; }
		else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) & 15; }
		else if (i < 48) { f = b ^ c ^ d;          g = (3*i + 5) & 15; }
		else             { f = c ^ (b | ~d);       g = (7*i) & 15; }
		t = d; d = c; c = b;
		b = b + ROL(a + f + K[i] + w[g], R[i]);
		a = t;
	}
	s[0] += a; s[1] += b; s[2] += c; s[3] += d;
}

void md5_buf(const void *data, size_t len, uint8_t out[16])
{
	struct md5c c = { { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 }, 0, {0} };
	const uint8_t *p = data;
	size_t n = len, r;
	uint8_t tail[128];
	int i;

	while (n >= 64) { md5_block(c.s, p); p += 64; n -= 64; }
	r = n;
	memcpy(tail, p, r);
	tail[r++] = 0x80;
	while ((r & 63) != 56) tail[r++] = 0;
	c.bits = (uint64_t)len * 8;
	for (i = 0; i < 8; i++) tail[r++] = c.bits >> (8 * i);
	md5_block(c.s, tail);
	if (r > 64) md5_block(c.s, tail + 64);
	for (i = 0; i < 16; i++) out[i] = c.s[i / 4] >> (8 * (i % 4));
}

void md5_hex(const void *data, size_t len, char out[33])
{
	uint8_t d[16];

	md5_buf(data, len, d);
	bin2hex(d, 16, out);
}

/* ---- base64 ---- */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64enc(const uint8_t *s, size_t n, char *out, size_t outsz)
{
	size_t i, o = 0;

	if (outsz < (n + 2) / 3 * 4 + 1) return -1;
	for (i = 0; i < n; i += 3) {
		uint32_t v = s[i] << 16 | (i + 1 < n ? s[i+1] << 8 : 0) | (i + 2 < n ? s[i+2] : 0);
		out[o++] = B64[v >> 18 & 63];
		out[o++] = B64[v >> 12 & 63];
		out[o++] = i + 1 < n ? B64[v >> 6 & 63] : '=';
		out[o++] = i + 2 < n ? B64[v & 63] : '=';
	}
	out[o] = 0;
	return o;
}

int b64dec(const char *s, uint8_t *out, size_t outsz)
{
	uint32_t acc = 0;
	int bits = 0;
	size_t o = 0;

	for (; *s && *s != '='; s++) {
		const char *p;
		if (*s == ' ' || *s == '\r' || *s == '\n') continue;
		p = strchr(B64, *s);
		if (!p) return -1;
		acc = acc << 6 | (p - B64);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (o >= outsz) return -1;
			out[o++] = acc >> bits & 0xff;
		}
	}
	return o;
}

/* ---- hex ---- */
static int hv(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int hex2bin(const char *s, uint8_t *out, size_t max)
{
	size_t n = 0;

	while (*s) {
		int a, b;
		if (*s == ' ') { s++; continue; }
		a = hv(s[0]); b = a < 0 ? -1 : hv(s[1]);
		if (a < 0 || b < 0 || n >= max) return -1;
		out[n++] = a << 4 | b;
		s += 2;
	}
	return n;
}

void bin2hex(const uint8_t *in, size_t n, char *out)
{
	static const char H[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) { out[2*i] = H[in[i] >> 4]; out[2*i+1] = H[in[i] & 15]; }
	out[2*n] = 0;
}

/* ---- time / random ---- */
uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

uint32_t rnd32(void)
{
	uint32_t v = 0;
	int fd = open("/dev/urandom", O_RDONLY);

	if (fd >= 0) {
		if (read(fd, &v, sizeof(v)) != sizeof(v)) v = 0;
		close(fd);
	}
	if (!v) v = (uint32_t)now_ms() * 2654435761u + getpid();
	return v;
}

uint32_t rnd_range(uint32_t lo, uint32_t hi)
{
	return lo + rnd32() % (hi - lo + 1);
}

size_t strlcpy_(char *dst, const char *src, size_t n)
{
	size_t l = strlen(src);

	if (n) {
		size_t c = l >= n ? n - 1 : l;
		memcpy(dst, src, c);
		dst[c] = 0;
	}
	return l;
}

/* ---- logging ---- */
static FILE *logf;

int log_open(const char *path)
{
	logf = fopen(path, "a");
	return logf ? 0 : -1;
}

void log_close(void)
{
	if (logf) fclose(logf);
	logf = NULL;
}

static void stamp(char *b, size_t n)
{
	struct timeval tv;
	struct tm tm;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	snprintf(b, n, "%02d:%02d:%02d.%03d", tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(tv.tv_usec / 1000));
}

void ilog(const char *fmt, ...)
{
	char ts[24], msg[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	stamp(ts, sizeof(ts));
	fprintf(stderr, "%s %s\n", ts, msg);
	if (logf) { fprintf(logf, "%s %s\n", ts, msg); fflush(logf); }
}

void ilog_msg(const char *dir, const char *peer, const char *buf, size_t len)
{
	char ts[24];

	stamp(ts, sizeof(ts));
	fprintf(stderr, "%s ---- %s %s (%zu bytes)\n%.*s\n", ts, dir, peer, len, (int)len, buf);
	if (logf) {
		fprintf(logf, "%s ---- %s %s (%zu bytes)\n%.*s\n", ts, dir, peer, len, (int)len, buf);
		fflush(logf);
	}
}
