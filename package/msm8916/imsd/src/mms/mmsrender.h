/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_MMSRENDER_H
#define IMSD_MMS_MMSRENDER_H
#include <stdbool.h>
#include <stddef.h>
#include "mmspdu.h"
#include "../util/buf.h"

/* Text side of a received MMS: what becomes of its parts in the text sent to the LAN devices. Pure functions. */

#define MMSR_PART_TEXT_MAX	(32 * 1024)	/* UTF-8 bytes taken from one text part */
#define MMSR_MAX_CHUNKS		16	/* = LAN_PIECES_MAX */

bool mmsr_is_smil(const struct mms_part *p);
bool mmsr_is_text(const struct mms_part *p);	/* text/plain or text/html: shown in the message body */
/* The text of a text/plain or text/html part as UTF-8 (HTML reduced to text), appended to out. The part's charset
 * is honoured (no charset: UTF-8 with invalid bytes replaced). */
void mmsr_part_text(const struct mms_part *p, struct buf *out);
/* Presentation order of the parts: the sources named by the SMIL part in document order (matched by Content-Location
 * or Content-ID, "cid:" prefix allowed), then the rest in the order of the message. The SMIL part itself is left out.
 * Fills order[] (room for n entries) and returns the count. */
unsigned mmsr_order(const struct mms_part *parts, unsigned n, unsigned *order);
/* crude HTML to text: tags dropped (br, p, div, li, tr, h1..h6 end a line), script / style / comments removed, the common
 * entities and numeric references decoded, runs of white space collapsed */
void mmsr_html_to_text(const char *html, struct buf *out);
/* a single header line value: control characters become blanks, cut at n-1 on a UTF-8 character boundary */
void mmsr_oneline(const char *in, char *out, size_t n);
/* "1.4 MB", "37 KB", "512 B" */
void mmsr_human_size(size_t n, char *out, size_t cap);
/* Lossless split of a rendered text into pieces of at most limit bytes: see lan_text_split() (ua/lan_text.h), which this calls */
unsigned mmsr_split(const char *s, size_t len, size_t limit, size_t *off, size_t *plen, unsigned max, bool *truncated);
#endif
