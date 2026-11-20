/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SMSCODEC_UTF8_H
#define IMSD_SMSCODEC_UTF8_H
#include <stddef.h>
#include <stdint.h>

#define UTF8_REPLACEMENT 0xFFFDu

/*
 * Strict UTF-8 (RFC 3629): overlong forms, surrogates (U+D800..DFFF) and
 * code points above U+10FFFF are invalid.
 *
 * Decode one code point from s[0..n). Returns the number of bytes consumed
 * (1..4) and stores the code point in *cp, or -1 if the sequence is invalid
 * or truncated (n == 0 also gives -1).
 */
int utf8_decode(const char *s, size_t n, uint32_t *cp);
/* Encode cp (must be a valid scalar value) into out; returns 1..4, or 0 if cp is not encodable. */
int utf8_encode(uint32_t cp, char out[4]);
#endif
