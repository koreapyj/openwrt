/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UTIL_MD5_H
#define IMSD_UTIL_MD5_H
#include <stddef.h>
#include <stdint.h>

/* RFC 1321 MD5, self-contained (no libubox dependency). */
struct md5_ctx {
	uint32_t s[4];
	uint64_t bytes;
	uint8_t buf[64];
};

void md5_init(struct md5_ctx *c);
void md5_update(struct md5_ctx *c, const void *data, size_t len);
void md5_final(struct md5_ctx *c, uint8_t out[16]);
/* one-shot digest */
void md5_buf(const void *data, size_t len, uint8_t out[16]);
/* one-shot digest as 32 lower-case hex chars + NUL */
void md5_hex(const void *data, size_t len, char out[33]);
#endif
