/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UTIL_SYS_H
#define IMSD_UTIL_SYS_H
#include <stddef.h>
#include <stdint.h>

/* CLOCK_MONOTONIC in milliseconds. */
uint64_t mono_ms(void);
/* Fill buf with random bytes (getrandom / urandom, never blocks; weak fallback if neither works). */
void rnd_bytes(void *buf, size_t n);
uint32_t rnd32(void);
/* uniform-ish value in [lo, hi] inclusive */
uint32_t rnd_range(uint32_t lo, uint32_t hi);
/* NUL terminated token of n lower-case hex chars (out needs n+1 bytes), for tags / Call-IDs / branches */
void rnd_token(char *out, size_t n);
/* copy with truncation and NUL; returns strlen(src) so callers can detect truncation (>= n) */
size_t str_copy(char *dst, const char *src, size_t n);
#endif
