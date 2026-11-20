/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
#include "sys.h"

uint64_t mono_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void rnd_bytes(void *buf, size_t n)
{
	uint8_t *p = buf;
	size_t got = 0;
	ssize_t r;

	while (got < n && (r = getrandom(p + got, n - got, GRND_NONBLOCK)) > 0)
		got += r;
	if (got < n) {
		int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

		if (fd >= 0) {
			while (got < n && (r = read(fd, p + got, n - got)) > 0)
				got += r;
			close(fd);
		}
	}
	if (got < n) {	/* last resort, not cryptographic */
		static uint64_t x;

		if (!x)
			x = mono_ms() * 0x9e3779b97f4a7c15ull ^ getpid();
		while (got < n) {
			x ^= x << 13; x ^= x >> 7; x ^= x << 17;
			p[got++] = x >> 24;
		}
	}
}

uint32_t rnd32(void)
{
	uint32_t v;

	rnd_bytes(&v, sizeof(v));
	return v;
}

uint32_t rnd_range(uint32_t lo, uint32_t hi)
{
	return lo + rnd32() % (hi - lo + 1);
}

void rnd_token(char *out, size_t n)
{
	static const char H[] = "0123456789abcdef";
	uint8_t r[64];
	size_t i;

	if (n > sizeof(r))
		n = sizeof(r);
	rnd_bytes(r, n);
	for (i = 0; i < n; i++)
		out[i] = H[r[i] & 15];
	out[n] = 0;
}

size_t str_copy(char *dst, const char *src, size_t n)
{
	size_t l = strlen(src);

	if (n) {
		size_t c = l >= n ? n - 1 : l;

		memcpy(dst, src, c);
		dst[c] = 0;
	}
	return l;
}
