/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_WSP_H
#define IMSD_MMS_WSP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * WSP (WAP-230-WSP, section 8.4 "Binary header encoding") primitives and the WSP Push PDU, as far as the MMS
 * encapsulation (OMA-TS-MMS_ENC) needs them. Pure functions on a bounds-checked cursor: every read checks the
 * remaining length, nothing is allocated, a malformed input yields -1 and never reads outside the buffer.
 */

struct wsp_rd {
	const uint8_t *p;
	size_t len;
	size_t pos;
};

void wsp_rd_init(struct wsp_rd *r, const uint8_t *p, size_t len);
size_t wsp_left(const struct wsp_rd *r);
/* sub-reader over the next n bytes (and advance r past them). 0, or -1 when fewer than n bytes are left */
int wsp_sub(struct wsp_rd *r, size_t n, struct wsp_rd *sub);

int wsp_u8(struct wsp_rd *r, uint8_t *v);
/* variable length unsigned integer, at most 5 octets, must fit 32 bits */
int wsp_uintvar(struct wsp_rd *r, uint32_t *v);
/* Value-length: Short-length (0..30) or Length-quote (31) + uintvar; the length must not exceed what is left */
int wsp_value_length(struct wsp_rd *r, size_t *len);
/* Integer-value: Short-integer (0x80..0xFF) or Long-integer (length octet 1..8, then big endian) */
int wsp_integer(struct wsp_rd *r, uint64_t *v);
/*
 * Text-string / Quoted-string / Token-text: an optional Quote octet (0x7F or '"'), then the characters up to NUL. At most n-1 bytes are
 * stored (cut silently, *trunc set), but the whole string is consumed. -1 when no NUL terminator follows.
 */
int wsp_text(struct wsp_rd *r, char *out, size_t n, bool *trunc);
/* skip one Field-value by the WSP rule (WAP-230 8.4.2.1): 0..30 length + data, 31 uintvar length + data, 32..127 text, 128.. one octet */
int wsp_skip_value(struct wsp_rd *r);

/* well-known charset (IANA MIBenum) names; NULL when unknown */
const char *wsp_charset_name(unsigned mib);
/* well-known content type (WAP-230 table 40); unknown codes give "application/x-wap-<hex>" in buf */
const char *wsp_media_name(unsigned code, char *buf, size_t n);

/*
 * Convert text in the given MIBenum charset to UTF-8 into out (NUL terminated, cut at n-1 on a character boundary).
 * 0/absent, 106 UTF-8 (invalid sequences become U+FFFD), 3 US-ASCII, 4 ISO-8859-1, 36 KS_C_5601-1987 and 38 EUC-KR (smscodec/euckr),
 * 1000 UCS-2 / 1013 UTF-16BE / 1014 UTF-16LE / 1015 UTF-16 (BOM, default big endian). An unknown MIBenum is treated as UTF-8.
 * Returns the number of bytes produced.
 */
size_t wsp_to_utf8(unsigned mib, const uint8_t *in, size_t n, char *out, size_t cap);
/*
 * Encoded-string-value (MMS ENC 7.2.9): Text-string, or Value-length + Char-set + Text-string. Result in UTF-8.
 * 0, or -1.
 */
int wsp_encoded_string(struct wsp_rd *r, char *out, size_t n);

/* ---- Content-type-value ---- */
#define WSP_NAME_MAX 128
struct wsp_ctype {
	char type[96];			/* "text/plain", "application/vnd.wap.multipart.related" ... */
	int charset;			/* MIBenum, 0 when absent */
	char name[WSP_NAME_MAX];	/* name parameter */
	char filename[WSP_NAME_MAX];	/* filename parameter */
	char start[WSP_NAME_MAX];	/* start parameter (the root part of multipart/related) */
	char type_param[64];		/* type parameter (content type of the root part) */
};
/* Content-type-value (Constrained-media | Content-general-form with parameters). Consumes exactly the value. 0, or -1 */
int wsp_content_type(struct wsp_rd *r, struct wsp_ctype *ct);

/* Parameters (typed and untyped) until r is exhausted, filling ct; an unknown typed parameter ends the list. Used for Content-Disposition too. */
void wsp_parse_params(struct wsp_rd *r, struct wsp_ctype *ct);

/* One header name: well-known field (high bit set, *code = value & 0x7F) or Token-text application header (name filled). 0, or -1 */
int wsp_header_name(struct wsp_rd *r, bool *wellknown, unsigned *code, char *name, size_t n);

/* ---- WSP Push PDU (connectionless push over WDP port 2948) ---- */
struct wsp_push {
	uint8_t tid;
	uint8_t pdu_type;		/* 6 Push, 7 ConfirmedPush */
	struct wsp_ctype ct;
	bool has_app_id;
	char app_id[64];		/* X-Wap-Application-Id: the text, or the well-known name ("x-wap-application:mms.ua") */
	const uint8_t *body;		/* points into the input */
	size_t body_len;
};
/* 0, or -1 (truncated, not a push PDU, bad header length) */
int wsp_parse_push(const uint8_t *d, size_t n, struct wsp_push *out);

#define WSP_PUSH_PORT 2948
#define WSP_PUSH_PORT_SECURE 2949
#endif
