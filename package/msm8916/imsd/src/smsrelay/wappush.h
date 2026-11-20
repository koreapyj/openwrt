/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SMSRELAY_WAPPUSH_H
#define IMSD_SMSRELAY_WAPPUSH_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Reassembly of WAP Push carried in concatenated binary SMS (WDP over SMS, WAP-259-WDP: application port addressing and
 * concatenation information elements in the user data header). This is the one exception to "no reassembly" of the SMS
 * relay: text messages are still forwarded per segment, port addressed binary messages are put together here.
 *
 * Bounded: WAPPUSH_MAX_MSG messages in assembly, WAPPUSH_MAX_SEG segments of at most WAPPUSH_SEG_MAX bytes each; an
 * incomplete message is dropped (and logged) after WAPPUSH_TIMEOUT_MS; when the table is full the oldest goes.
 * Keyed by (originator, reference, total).
 */
#define WAPPUSH_MAX_MSG		8
#define WAPPUSH_MAX_SEG		16
#define WAPPUSH_SEG_MAX		140
#define WAPPUSH_TIMEOUT_MS	(5u * 60 * 1000)

/* a complete message: from = originator, port = WDP destination port, data = the WDP payload (not valid after the call) */
typedef void (*wappush_cb)(void *arg, const char *from, unsigned port, const uint8_t *data, size_t len);

struct wappush;
struct wappush *wappush_new(wappush_cb cb, void *arg);
void wappush_free(struct wappush *w);

/*
 * One segment. total 0 / 1: not concatenated, delivered at once. port: WDP destination port (0 when this segment has no
 * port addressing: the port of the first segment of the message is used). Returns 0, or -1 when the segment was refused
 * (too many segments, no space) and logged.
 */
int wappush_segment(struct wappush *w, const char *from, unsigned port, uint16_t ref, unsigned total, unsigned seq,
		    const uint8_t *data, size_t len);
/* is a message of this key being assembled (a later segment without port addressing belongs to it) */
bool wappush_pending(const struct wappush *w, const char *from, uint16_t ref, unsigned total);
unsigned wappush_count(const struct wappush *w);
#endif
