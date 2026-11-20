/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SMSCODEC_GSM7_H
#define IMSD_SMSCODEC_GSM7_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../util/buf.h"

/*
 * GSM 7-bit default alphabet and its extension table (3GPP TS 23.038
 * section 6.2.1 / 6.2.1.1) plus septet packing (TS 23.038 section 6.1.2.1).
 * National language shift tables are not implemented.
 *
 * "Septet arrays" hold one 7-bit value per byte (0..127). Extension
 * characters occupy two septets: 0x1B followed by the extension code.
 */
#define GSM7_ESC 0x1B

/* Octets needed for nsept septets starting at bit offset fill_bits (0..6). */
size_t gsm7_packed_len(size_t nsept, unsigned fill_bits);

/*
 * Pack nsept septets, the first one starting at bit offset fill_bits
 * (0..6, the padding after a UDH). Returns the number of octets written,
 * or -1 if out_max is too small or an argument is bad. Padding bits are 0.
 */
int gsm7_pack(const uint8_t *sept, size_t nsept, unsigned fill_bits, uint8_t *out, size_t out_max);

/*
 * Unpack nsept septets starting at bit offset fill_bits from n packed
 * octets into sept[] (nsept bytes). Returns 0, or -1 if the data is too
 * short.
 */
int gsm7_unpack(const uint8_t *packed, size_t n, unsigned fill_bits, size_t nsept, uint8_t *sept);

/*
 * Convert septets to UTF-8 appended to out. An undefined extension code
 * is shown as the default-alphabet character with that code (TS 23.038);
 * a trailing lone ESC is dropped and reported through *lossy (set to true,
 * never cleared). Returns 0, or -1 if out overflowed.
 */
int gsm7_to_utf8(const uint8_t *sept, size_t n, struct buf *out, bool *lossy);

/*
 * Map one Unicode code point to 1 or 2 septets (out[0], out[1]).
 * Returns the septet count, or 0 if the character is not in the default
 * alphabet or the extension table.
 */
int gsm7_from_cp(uint32_t cp, uint8_t out[2]);

/* Unicode code point of a default-alphabet septet (0x1B maps to U+0020) */
uint32_t gsm7_default_cp(uint8_t sept);
#endif
