/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CALL_GMCALL_UTIL_H
#define IMSD_CALL_GMCALL_UTIL_H
#include <stdbool.h>
#include <stddef.h>
#include "../sip/msg.h"

/*
 * Pure helpers of the carrier call leg: dial strings, number normalisation,
 * caller identity, Session-Expires / Reason / Warning / Require parsing.
 * No state, no I/O; every function reports overflow instead of truncating.
 */

/* who a call is with */
struct gmcall_identity {
	char uri[256];		/* sip:/tel: URI of the party (PAI, else From; for MO the dialled URI) */
	char number[48];	/* normalised number: "+821012345678" / "01051226862" ("" when unusable) */
	char display[64];	/* display name or "" */
	bool anonymous;		/* Privacy: id / header (or an anonymous From) asked to hide the identity */
};

/*
 * Reduce "sip:+8210...@host;user=phone", "tel:010-1234-5678;phone-context=x",
 * "<sip:0105...@d>" or a bare number to its digits (a leading '+' is kept,
 * visual separators - . ( ) and blanks are dropped, %2B is decoded).
 * Returns 0, or -1 when no number results (host-only URI, "anonymous", empty)
 * or out is too small.
 */
int gmcall_number_normalize(const char *in, char *out, size_t n);

/*
 * Turn a dial string into the Request-URI / To URI of an outgoing INVITE.
 *  - "sip:", "sips:" and "tel:" URIs pass through unchanged;
 *  - "+<digits>" becomes the global number "tel:+<digits>" (no phone-context);
 *  - "<digits>" (digits, '*', '#' after dropping blanks - . ( )) becomes
 *    "tel:<digits>;phone-context=<phone_context>" ('#' is written %23).
 * Returns 0, -EINVAL (garbage: empty, letters, '+' inside, more than 32
 * digits ...) or -EMSGSIZE (does not fit).
 */
int gmcall_make_target(const char *in, const char *phone_context, char *out, size_t n);

enum { GMCALL_REFRESHER_NONE = 0, GMCALL_REFRESHER_UAC, GMCALL_REFRESHER_UAS };
/* "600;refresher=uac" -> *interval = 600, *refresher = UAC. 0, or -1 if malformed / zero. */
int gmcall_parse_session_expires(const char *v, unsigned *interval, int *refresher);
/* Min-SE value; 0 ok, -1 malformed */
int gmcall_parse_min_se(const char *v, unsigned *secs);

/* Reason header ("SIP ;cause=200 ;text=\"Call completed elsewhere\"") -> text, else "cause N". "" if neither. 0, or -1 if out is too small. */
int gmcall_reason_text(const char *reason_hdr, char *out, size_t n);
/* Warning header ("399 host \"text\"") -> text. "" if none. 0 / -1 */
int gmcall_warning_text(const char *warning_hdr, char *out, size_t n);

/* is the (comma separated, case-insensitive) option-tag list hdr containing tok */
bool gmcall_has_token(const char *hdr, const char *tok);
/*
 * Option tags of a Require header that we cannot honour (everything but
 * "timer" and "sec-agree"), comma separated into out. Returns how many.
 */
int gmcall_unsupported_options(const char *require_hdr, char *out, size_t n);

/* caller identity of an incoming request: P-Asserted-Identity (first), else From; Privacy handling */
void gmcall_identity_from_request(const struct sip_msg *req, struct gmcall_identity *id);

/* Reason-Phrase style short text for a SIP status used when only a number is known */
const char *gmcall_status_text(int status);
#endif
