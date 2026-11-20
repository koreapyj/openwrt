/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UTIL_CODEC_H
#define IMSD_UTIL_CODEC_H
#include <stddef.h>
#include <stdint.h>

/* Base64 encode n bytes into out (NUL terminated). Returns the encoded length, or -1 if outsz is too small. */
int b64_encode(const uint8_t *src, size_t n, char *out, size_t outsz);
/* Decode base64 (padding and whitespace tolerated, stops at the first '=' or NUL). Returns bytes or -1 on bad input / overflow. */
int b64_decode(const char *s, uint8_t *out, size_t outsz);

/* Lower-case hex of n bytes into out (needs 2n+1 bytes), NUL terminated. */
void hex_encode(const uint8_t *in, size_t n, char *out);
/* Decode hex (spaces allowed between bytes). Returns the byte count or -1 on bad input / overflow. */
int hex_decode(const char *s, uint8_t *out, size_t max);
#endif
