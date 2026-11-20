/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_GM_REGMSG_H
#define IMSD_GM_REGMSG_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "secagree.h"
#include "../sip/msg.h"

/*
 * Builders for the Gm REGISTER and for requests inside the registration,
 * with the header set the LG U+ network accepted in the proof of concept
 * (imsua build_register / build_message).
 */
#define REG_ALLOW "INVITE,BYE,CANCEL,ACK,NOTIFY,UPDATE,PRACK,INFO,MESSAGE,OPTIONS"
#define REG_ICSI_MMTEL "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"

struct regmsg_params {
	const char *domain;		/* "lte-lguplus.co.kr": Request-URI sip:<domain> */
	const char *impu;		/* From / To */
	const char *user;		/* user part of the Contact URI */
	const char *imei;		/* 8-6-1 formatted, "" / NULL: no +sip.instance */
	const struct addr *adv;		/* Via sent-by and Contact (the endpoint's advertised address) */
	const struct addr *pcscf;	/* Route target (address and port) */
	const char *call_id;
	uint32_t cseq;
	int expires;
	const char *pani;		/* P-Access-Network-Info value, "" / NULL: none */
	const char *user_agent;		/* User-Agent value, "" / NULL: none */
	bool is_protected;
	const char *security_verify;	/* protected requests */
	const char *authorization;	/* complete Authorization value */
	const struct sec_client *sc;	/* Security-Client offer */
	const char *tag;		/* From tag, NULL: random */
	const char *branch;		/* NULL: generate */
};

/* Compose a REGISTER. The branch used is copied to branch_out (may be NULL). 0, -1 on overflow / missing input. */
int regmsg_build_register(struct buf *out, const struct regmsg_params *p, char branch_out[SIP_BRANCH_LEN]);

/* Authorization header value, the PoC layout. nonce "" gives the initial form; auts_b64 != NULL the resync form (response=""); else response_hex. opaque may be "" */
int regmsg_authorization(char *out, size_t n, const char *impi, const char *realm, const char *domain,
			 const char *nonce, const char *opaque, const char *response_hex, const char *auts_b64);

/* "sip:user@host:port" for the advertised address */
int regmsg_contact_uri(char *out, size_t n, const char *user, const struct addr *adv);
/* "Route: <sip:host:port;lr>\r\n" */
int regmsg_route(char *out, size_t n, const struct addr *pcscf);
#endif
