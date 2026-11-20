/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_GM_SECAGREE_H
#define IMSD_GM_SECAGREE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../sip/msg.h"

/*
 * Security mechanism agreement (RFC 3329, TS 33.203 ipsec-3gpp) and the
 * AKAv1-MD5 digest (RFC 3310 / 2617 without qop) as used on Gm.
 * None of these functions log key material.
 */

/* ---- Security-Server / Security-Client ---- */
struct sec_ent {
	char prot[16];
	char alg[24];
	char ealg[16];
	char mod[16];		/* e.g. "trans" (kept, unknown params are tolerated) */
	bool has_q;
	double q;
	uint32_t spi_c, spi_s;
	int port_c, port_s;
	bool ok;		/* ipsec-3gpp, alg hmac-md5-96 / hmac-sha-1-96, ealg null/absent, spis and ports present */
	bool sha1;		/* alg is hmac-sha-1-96 */
};
#define SEC_MAX_ENT 8
/* Parse a Security-Server value (comma separated mechanisms). Returns the number of entries stored (<= max). Unknown parameters are ignored. */
int sec_parse(const char *hdrval, struct sec_ent *out, int max);
/* Index of the supported entry with the highest q (first wins ties); -1 if none is supported. */
int sec_select(const struct sec_ent *e, int n);
/* All Security-Server header lines of m joined with ", " into out. 0, -1 if absent or too long. */
int sec_server_value(const struct sip_msg *m, char *out, size_t n);

struct sec_client {
	uint32_t spi_c, spi_s;	/* our SPIs (uc / us) */
	uint16_t port_c, port_s;	/* our ports */
};
/* Security-Client value offering hmac-md5-96 and hmac-sha-1-96, ealg=null. 0 / -1 if out too small. */
int sec_build_client(char *out, size_t n, const struct sec_client *c);
/* Security-Verify value: the server's Security-Server value echoed unchanged. 0 / -1 */
int sec_build_verify(char *out, size_t n, const char *server_value);

/* ---- digest AKAv1-MD5 ---- */
struct digest_challenge {
	char realm[128];
	char nonce[256];	/* base64 text exactly as received (used verbatim in the response) */
	char algorithm[24];
	bool aka;		/* algorithm is AKAv1-MD5 (or AKAv2) and the nonce decodes to >= 32 bytes */
	uint8_t rand[16];
	uint8_t autn[16];
};
/* Parse a WWW-Authenticate / Proxy-Authenticate value. 0 / -1 (no realm or nonce). */
int digest_parse_challenge(const char *hdrval, struct digest_challenge *c);

/* response = MD5(MD5(user:realm:RES_raw) : nonce : MD5(method:uri)); res is the raw RES bytes. out: 32 hex + NUL */
void digest_response(const char *user, const char *realm, const uint8_t *res, size_t reslen,
		     const char *nonce, const char *method, const char *uri, char out[33]);

struct digest_auth {
	const char *user;	/* IMPI */
	const char *realm;
	const char *nonce;	/* "" for the initial unauthenticated REGISTER */
	const char *uri;	/* digest-uri, e.g. "sip:lte-lguplus.co.kr" */
	const char *method;
	const uint8_t *res;	/* raw RES (normal answer) ... */
	size_t res_len;
	const uint8_t *auts;	/* ... or AUTS (14 bytes) for a resynchronisation: response="" auts="<b64>" */
	size_t auts_len;
};
/* Authorization header value. Initial form (nonce empty): response="" nonce=""; with auts: resync form; else the digest response. 0 / -1 */
int digest_build_authorization(char *out, size_t n, const struct digest_auth *a);
#endif
