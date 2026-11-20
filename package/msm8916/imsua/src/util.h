/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IMSUA_UTIL_H
#define IMSUA_UTIL_H
#include <stddef.h>
#include <stdint.h>

void md5_buf(const void *data, size_t len, uint8_t out[16]);
void md5_hex(const void *data, size_t len, char out[33]);

/* returns encoded length (without NUL) or -1 */
int b64enc(const uint8_t *src, size_t n, char *out, size_t outsz);
/* returns decoded length or -1; stops at the end of the string */
int b64dec(const char *s, uint8_t *out, size_t outsz);

int hex2bin(const char *s, uint8_t *out, size_t max); /* length or -1 */
void bin2hex(const uint8_t *in, size_t n, char *out);   /* NUL terminated */

uint64_t now_ms(void);                  /* CLOCK_MONOTONIC */
uint32_t rnd32(void);
uint32_t rnd_range(uint32_t lo, uint32_t hi); /* inclusive */

/* logging: stderr + optional file, timestamped */
int log_open(const char *path);
void log_close(void);
void ilog(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ilog_msg(const char *dir, const char *peer, const char *buf, size_t len);

size_t strlcpy_(char *dst, const char *src, size_t n);
#endif
