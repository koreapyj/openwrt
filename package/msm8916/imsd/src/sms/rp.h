/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SMS_RP_H
#define IMSD_SMS_RP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Minimal RP layer codec (TS 24.011 section 7.3) for SMS over IMS
 * (MESSAGE with application/vnd.3gpp.sms). Only the header octets are
 * interpreted; the RP-User-Data / TPDU is not decoded here.
 *   octet 1: message type (low 3 bits)   octet 2: message reference
 */
enum rp_mti {
	RP_DATA_MS_N = 0,	/* RP-DATA ms -> network */
	RP_DATA_N_MS = 1,	/* RP-DATA network -> ms (an incoming SMS) */
	RP_ACK_MS_N = 2,
	RP_ACK_N_MS = 3,	/* the network acknowledges our MO SMS */
	RP_ERROR_MS_N = 4,
	RP_ERROR_N_MS = 5,	/* the network rejects our MO SMS */
	RP_SMMA = 6,
};

struct rp_info {
	int mti;		/* 0..7 */
	uint8_t mr;
	int cause;		/* RP-ERROR: the RP-Cause value, else -1 */
};

/* 0, or -1 if shorter than two octets */
int rp_parse(const uint8_t *d, size_t n, struct rp_info *r);
const char *rp_mti_name(int mti);
/* RP-ACK ms -> network for a received RP-DATA: 02 MR */
void rp_build_ack(uint8_t mr, uint8_t out[2]);

/*
 * RP-DATA in both directions with RP addresses, RP-ERROR building, the RP user data of RP-ACK / RP-ERROR and the
 * RP-Cause text table (used by the SMS relay). Pure functions, no allocation.
 */

#define RP_ADDR_MAX	11	/* RP address contents: TOA + up to 10 BCD octets */

/* An RP-OA / RP-DA address element without its length octet. len 0 = absent (zero length element). */
struct rp_addr {
	uint8_t len;		/* 0, or 2..RP_ADDR_MAX */
	uint8_t b[RP_ADDR_MAX];/* b[0] = type of address octet, then semi-octet BCD digits */
};

/* "+821020921821" / "0105..." -> RP address (TOA 0x91 with '+', else 0x81). 0, or -1 if empty / not digits / over 20 digits */
int rp_addr_from_str(const char *s, struct rp_addr *a);
/* RP address -> printable number ('+' for international, digits, '*' '#'). 0, or -1 (absent, bad or out too small) */
int rp_addr_to_str(const struct rp_addr *a, char *out, size_t n);

/* a parsed RP-DATA (either direction); ud points into the input */
struct rp_data {
	uint8_t mti;		/* 0 (ms->n) or 1 (n->ms) */
	uint8_t mr;
	struct rp_addr oa;	/* originator (len 0 in ms->n) */
	struct rp_addr da;	/* destination (len 0 in n->ms) */
	const uint8_t *ud;	/* RP-User-Data contents: the TPDU */
	size_t ud_len;
};
/* Parse an RP-DATA. 0, or -1 (wrong type, truncated, bad lengths: nothing is guessed) */
int rp_parse_data(const uint8_t *d, size_t n, struct rp_data *r);

/*
 * Build RP-DATA ms -> network: 00 MR 00 <len,DA> <len,TPDU>. Returns the length, or -1 if
 * the TPDU is longer than 233 octets or cap is too small.
 */
int rp_build_data_ms_n(uint8_t mr, const struct rp_addr *da, const uint8_t *tpdu, size_t n, uint8_t *out, size_t cap);

/* RP-ERROR ms -> network: 04 MR 01 <cause> (4 octets, no user data) */
void rp_build_error(uint8_t mr, uint8_t cause, uint8_t out[4]);

/*
 * RP-ACK (n->ms: 03 MR [41 len TPDU]) / RP-ERROR (05 MR len cause... [41 len TPDU]) trailing user data.
 * Sets *tpdu / *len to the TPDU (len 0 and tpdu NULL when the message has none). 0, or -1 if malformed.
 */
int rp_report_tpdu(const uint8_t *d, size_t n, const uint8_t **tpdu, size_t *len);

/* text for an RP-Cause value (TS 24.011 table 8.4); "unspecified cause" for the rest */
const char *rp_cause_text(int cause);
/* true for causes where retrying later makes sense (network out of order, temporary failure, congestion, ...) */
int rp_cause_temporary(int cause);

/* RP-Cause values used here */
#define RP_CAUSE_MEMORY_EXCEEDED	22
#define RP_CAUSE_TEMP_FAILURE		41
#define RP_CAUSE_CONGESTION		42
#define RP_CAUSE_INVALID_MANDATORY	96
#define RP_CAUSE_PROTOCOL_ERROR	111
#endif
