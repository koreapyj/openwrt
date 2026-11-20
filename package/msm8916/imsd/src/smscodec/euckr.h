/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SMSCODEC_EUCKR_H
#define IMSD_SMSCODEC_EUCKR_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../util/buf.h"

/*
 * EUC-KR (KS X 1001, the two-byte part with lead and trail bytes
 * 0xA1..0xFE, plus ASCII) to UTF-8, using a built-in table (about 17 KiB
 * of flash). The CP949 extension (lead 0x81..0xA0 / 0xC7..0xC9 and trail
 * bytes below 0xA1) is not covered: such a byte pair becomes U+FFFD and
 * *lossy is set (never cleared). A truncated trailing lead byte also
 * becomes U+FFFD. Returns 0, or -1 if out overflowed.
 */
int euckr_to_utf8(const uint8_t *in, size_t n, struct buf *out, bool *lossy);
#endif
