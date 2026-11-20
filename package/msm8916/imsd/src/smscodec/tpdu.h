/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SMSCODEC_TPDU_H
#define IMSD_SMSCODEC_TPDU_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * SMS transfer layer (TP) codec, 3GPP TS 23.040, with the alphabets of
 * TS 23.038. This is NOT the RP layer (TS 24.011, see sms/rp.h): callers
 * hand in / get back the bare TPDU (the RP-User-Data contents).
 *
 * All functions are pure, allocate nothing and never write beyond the
 * structures passed in. Errors are negative TP_E_* codes; nothing is
 * truncated silently (soft problems are reported in tp_sms.flags).
 */

#define TP_MAX_UD	140	/* user data octets in one TPDU */
#define TP_MAX_TEXT	400	/* UTF-8 bytes of one decoded segment, plus NUL */
#define TP_ADDR_MAX	48	/* printable address, plus NUL */
#define TP_MAX_TPDU	176	/* largest TPDU produced by tp_encode_submit */
#define TP_MAX_SEGMENTS	255	/* concatenation total is one octet */

enum tp_err {
	TP_E_ARG = -1,
	TP_E_TRUNC = -2,	/* TPDU shorter than its fields claim */
	TP_E_MTI = -3,		/* not the expected message type */
	TP_E_ADDR = -4,		/* bad address field / destination number */
	TP_E_COMPRESSED = -5,	/* DCS says the user data is compressed (unsupported) */
	TP_E_UDL = -6,		/* user data length out of range */
	TP_E_UDH = -7,		/* malformed user data header */
	TP_E_UTF8 = -8,		/* input text is not valid UTF-8 (or contains NUL) */
	TP_E_TOOLONG = -9,	/* text needs more than max_out / 255 segments */
	TP_E_VP = -10,		/* validity period not representable */
	TP_E_OVERFLOW = -11,	/* internal output buffer too small (bug guard) */
};

const char *tp_strerror(int err);

/* How the user data is coded (from the DCS) */
enum tp_charset {
	TP_CS_GSM7 = 0,		/* GSM 7-bit default alphabet */
	TP_CS_8BIT,		/* 8-bit data: raw bytes, no text */
	TP_CS_UCS2,		/* UTF-16BE (UCS2 incl. surrogate pairs) */
	TP_CS_KSC5601,		/* DCS 0x84: EUC-KR (Korean operator convention) */
	TP_CS_UNKNOWN,		/* reserved coding group: raw bytes, no text */
};

/* tp_sms.flags */
#define TP_F_LOSSY_TEXT		0x0001	/* some input was replaced by U+FFFD or dropped */
#define TP_F_RESERVED_ALPHABET	0x0002	/* DCS alphabet bits 11: treated as GSM 7-bit */
#define TP_F_NLS		0x0004	/* national language shift IE present, default tables used */
#define TP_F_BAD_CONCAT		0x0008	/* concatenation IE with impossible numbers, ignored */
#define TP_F_BAD_SCTS		0x0010	/* SCTS not a valid date (tp_sms.scts.valid false) */
#define TP_F_UNKNOWN_CHARSET	0x0020	/* DCS coding not understood, only raw bytes given */

struct tp_addr {
	uint8_t ton;		/* type of number (0 unknown, 1 international, 5 alphanumeric ...) */
	uint8_t npi;
	bool alnum;		/* ton == 5: GSM 7-bit alphanumeric sender */
	char str[TP_ADDR_MAX];	/* printable UTF-8; international numbers get a leading '+' */
};

struct tp_scts {
	bool valid;		/* all fields plausible; epoch only meaningful if true */
	int year, mon, day, hour, min, sec;	/* local time at the sender, year 2000+ */
	int tz_quarters;	/* offset from UTC in 15 minute units (sign handled) */
	int64_t epoch;		/* seconds since 1970-01-01 UTC */
};

struct tp_concat {
	bool present;
	bool ref16;		/* IEI 0x08 (16-bit reference) instead of 0x00 */
	uint16_t ref;
	uint8_t total;		/* 1..255 */
	uint8_t seq;		/* 1..total */
};

/* application port addressing (UDH IEI 0x05 with 16 bit ports, IEI 0x04 with 8 bit ports; TS 23.040 9.2.3.24.3 / .4) */
struct tp_ports {
	bool present;
	uint16_t dst, src;
};

/* A decoded SMS-DELIVER (mti 0) or SMS-SUBMIT (mti 1) */
struct tp_sms {
	int mti;
	bool more_messages;	/* DELIVER: the SC has more messages for us */
	bool sri;		/* DELIVER: status report indication */
	bool srr;		/* SUBMIT: status report requested */
	bool rd;		/* SUBMIT: reject duplicates */
	bool rp;		/* reply path */
	bool udhi;
	struct tp_addr addr;	/* DELIVER: originating, SUBMIT: destination */
	uint8_t mr;		/* SUBMIT: message reference */
	uint8_t pid;
	uint8_t dcs;
	enum tp_charset charset;
	int msg_class;		/* 0..3, -1 when the DCS has no class */
	bool mwi;		/* DCS message waiting indication group */
	bool mwi_active;
	uint8_t mwi_type;	/* 0 voicemail, 1 fax, 2 email, 3 other */
	struct tp_scts scts;	/* DELIVER */
	bool vp_relative;	/* SUBMIT with a relative validity period */
	uint32_t vp_minutes;
	struct tp_concat concat;
	struct tp_ports ports;	/* first port addressing IE, if any */
	uint8_t nls_single;	/* national language shift IE values, 0 = absent (not applied) */
	uint8_t nls_locking;
	uint32_t flags;		/* TP_F_* */
	uint8_t udh[TP_MAX_UD];	/* raw information elements (without the UDHL octet) */
	uint8_t udh_len;
	bool has_text;		/* text[] is valid (GSM7, UCS2, KSC5601) */
	char text[TP_MAX_TEXT];	/* UTF-8, NUL terminated, UDH excluded */
	size_t text_len;
	uint8_t data[TP_MAX_UD];/* raw octets after the UDH, for 8BIT / KSC5601 / UNKNOWN */
	size_t data_len;
};

/*
 * Decode an SMS-DELIVER TPDU (network to MS). Returns 0 or TP_E_*.
 * UDHI user data headers are parsed (concatenation IEs 0x00/0x08 into
 * s->concat, national language shift IEs noted, all other IEs skipped),
 * 7-bit text honours the septet alignment after the header, extension
 * table included. A compressed DCS fails with TP_E_COMPRESSED. DCS 0x84
 * is decoded as EUC-KR with a built-in table (CP949 extension characters
 * become U+FFFD with TP_F_LOSSY_TEXT) and the raw bytes are kept in data[].
 */
int tp_decode_deliver(const uint8_t *tpdu, size_t n, struct tp_sms *s);

/* Decode an SMS-SUBMIT TPDU (MS to network); same rules as tp_decode_deliver. */
int tp_decode_submit(const uint8_t *tpdu, size_t n, struct tp_sms *s);

struct tp_status_report {
	bool more_messages, lp, srq, udhi;
	uint8_t mr;		/* of the SMS-SUBMIT this report refers to */
	struct tp_addr ra;	/* recipient */
	struct tp_scts scts;	/* when the SC received the message */
	struct tp_scts dt;	/* discharge time */
	uint8_t st;		/* TP-Status, raw */
};

/* Minimal SMS-STATUS-REPORT decode (optional trailing fields ignored). */
int tp_decode_status_report(const uint8_t *tpdu, size_t n, struct tp_status_report *r);
/* success: 0x00..0x02 (received / forwarded / replaced); final: success, 0x03..0x1F (SC specific) or
 * 0x40..0x7F (permanent error, or temporary error the SC gave up on); 0x20..0x3F means still trying */
bool tp_status_is_success(uint8_t st);
bool tp_status_is_final(uint8_t st);

struct tp_submit_report {
	bool udhi;
	bool is_error;		/* decoded as the TPDU of an RP-ERROR */
	uint8_t fcs;		/* failure cause, only when is_error */
	uint8_t pi;		/* parameter indicator (first octet) */
	struct tp_scts scts;	/* service centre timestamp */
	bool has_pid, has_dcs;
	uint8_t pid, dcs;
};

/*
 * SMS-SUBMIT-REPORT decode, the TPDU inside an RP-ACK (is_error false) or
 * RP-ERROR (is_error true, an FCS octet follows the first octet). The
 * captured RP-ACK carries 01 00 <SCTS>. Optional user data is ignored.
 */
int tp_decode_submit_report(const uint8_t *tpdu, size_t n, bool is_error, struct tp_submit_report *r);

/*
 * Given the bytes after the RP header of an RP-ACK / RP-ERROR (an RP-User-Data
 * IE: IEI 0x41, length, TPDU), return the TPDU. 0, or TP_E_TRUNC / TP_E_MTI
 * (IEI is not 0x41).
 */
int tp_rp_user_data(const uint8_t *ie, size_t n, const uint8_t **tpdu, size_t *tpdu_len);

/* Decode the 7 octet SCTS/DT field. Always fills *t; t->valid tells whether the date is plausible. */
void tp_scts_decode(const uint8_t p[7], struct tp_scts *t);

struct tp_submit_req {
	const char *dest;	/* NUL terminated: digits, '*' '#', optional leading '+' (<= 20 digits) */
	const char *text;	/* UTF-8, validated; need not be NUL terminated */
	size_t text_len;
	uint8_t mr;		/* TP-MR of the first segment; segment i gets (mr + i) mod 256 */
	uint8_t concat_ref;	/* 8-bit reference for concatenated messages */
	bool status_report;	/* TP-SRR */
	uint32_t vp_minutes;	/* 0: no validity period (TP-VPF 0, as the network accepted);
				 * else relative VP, rounded UP to the next representable value
				 * (5 min steps to 12 h, 30 min to 24 h, days to 30 d, weeks to 63 w) */
	bool force_ucs2;	/* use UCS2 even if the text fits GSM 7-bit */
};

struct tp_pdu {
	uint8_t data[TP_MAX_TPDU];
	size_t len;
	bool ucs2;		/* coding chosen for the whole message */
	uint8_t seq, total;	/* 1/1 for a single message */
};

/*
 * Encode text as one or more SMS-SUBMIT TPDUs.
 *   - dest: '+' prefix gives TOA 0x91, otherwise 0x81 (as the accepted
 *     captures for 010xxxxxxxx); PID 0.
 *   - DCS 0x00 if every character is in the GSM 7-bit default or extension
 *     alphabet (extension characters cost 2 septets), else 0x08 UCS2
 *     (UTF-16BE, surrogate pairs for U+10000 and up).
 *   - a message that fits 160 septets / 70 UTF-16 units goes in one TPDU,
 *     otherwise it is split into 153 / 67 unit segments with a concatenation
 *     UDH (IEI 0x00, 8-bit reference); an extension escape pair or a
 *     surrogate pair is never split across segments.
 * Returns the number of segments written to out[] (>= 1; empty text gives one
 * empty segment), or a negative TP_E_*: TP_E_UTF8 (invalid UTF-8 or NUL),
 * TP_E_ADDR, TP_E_VP, TP_E_TOOLONG (more than max_out or 255 segments).
 */
int tp_encode_submit(const struct tp_submit_req *req, struct tp_pdu *out, size_t max_out);

/*
 * Relative validity period octet for vp_minutes (rounded up), TS 23.040
 * section 9.2.3.12.1. Returns 0..255 or TP_E_VP (0 minutes, or over 63 weeks).
 */
int tp_vp_encode(uint32_t minutes);
/* Minutes denoted by a relative VP octet */
uint32_t tp_vp_decode(uint8_t vp);
#endif
