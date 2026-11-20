/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SMSRELAY_SMSFMT_H
#define IMSD_SMSRELAY_SMSFMT_H
#include <stddef.h>
#include <stdint.h>
#include "../smscodec/tpdu.h"

/* Text helpers of the SMS relay: sender rendering, time formats, destination numbers. Pure functions. */

#define SMSFMT_USER_MAX	96	/* SIP user part buffer */
#define SMSFMT_DISP_MAX	80	/* display name buffer */

/*
 * Render an originating / recipient address for a SIP From.
 *  - numbers (digits, leading '+' kept, '*'): user = the number, display = "" (a '#' becomes %23)
 *  - alphanumeric senders (TOA 5, "KT-Info"): user = "alnum." + the text reduced to [A-Za-z0-9._-]
 *    (anything else -> '-'), so every alphanumeric sender is a distinct, harmless, non-dialable
 *    URI user; display = the original text with control characters, quotes, backslash and
 *    angle brackets replaced by '?' (the UA quotes it).
 * Returns 1 if alphanumeric, 0 if a number.
 */
int smsfmt_sender(const struct tp_addr *a, char *user, size_t un, char *display, size_t dn);

/* "2026-11-19T15:30:12+09:00" from the SCTS local time and offset. 0, or -1 if !t->valid or n < 26 */
int smsfmt_iso(const struct tp_scts *t, char *out, size_t n);
/* RFC 3261 / 5322 "Thu, 19 Nov 2026 06:30:12 GMT" from a UTC epoch. 0 / -1 */
int smsfmt_date(int64_t epoch, char *out, size_t n);

enum {
	SMSFMT_E_NOTNUM = -1,	/* not a phone number at all */
	SMSFMT_E_LENGTH = -2,	/* numeric but empty or longer than 20 digits */
};
/*
 * Destination number of an MO SMS from a Request-URI (sip:, sips:, tel:). Percent escapes are
 * decoded, visual separators " -.()" removed; what remains must be [+]digits/'*'/'#'.
 * out receives it (needs 24 bytes). 0, or SMSFMT_E_*.
 */
int smsfmt_dest(const char *ruri, char *out, size_t n);

/* text safe inside a quoted header string: control characters, '"' and '\\' -> '?' ; truncated with "..." if longer than n-1 */
void smsfmt_quote_safe(const char *s, char *out, size_t n);
#endif
