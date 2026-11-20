/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <string.h>
#include "regmsg.h"
#include "../util/sys.h"

int regmsg_contact_uri(char *out, size_t n, const char *user, const struct addr *adv)
{
	char hp[96];
	int r;

	if (addr_str(adv, hp, sizeof(hp)))
		return -1;
	r = user && user[0] ? snprintf(out, n, "sip:%s@%s", user, hp) : snprintf(out, n, "sip:%s", hp);
	return r < 0 || (size_t)r >= n ? -1 : 0;
}

int regmsg_route(char *out, size_t n, const struct addr *pcscf)
{
	char hp[96];
	int r;

	if (addr_str(pcscf, hp, sizeof(hp)))
		return -1;
	r = snprintf(out, n, "Route: <sip:%s;lr>\r\n", hp);
	return r < 0 || (size_t)r >= n ? -1 : 0;
}

int regmsg_authorization(char *out, size_t n, const char *impi, const char *realm, const char *domain,
			 const char *nonce, const char *opaque, const char *response_hex, const char *auts_b64)
{
	char opq[160] = "";
	int r;

	if (!nonce || !nonce[0])
		r = snprintf(out, n, "Digest uri=\"sip:%s\",username=\"%s\",response=\"\",realm=\"%s\",nonce=\"\"", domain, impi, realm);
	else {
		if (opaque && opaque[0])
			snprintf(opq, sizeof(opq), "opaque=\"%s\",", opaque);
		if (auts_b64)
			r = snprintf(out, n, "Digest username=\"%s\",realm=\"%s\",uri=\"sip:%s\",nonce=\"%s\",algorithm=AKAv1-MD5,%sauts=\"%s\",response=\"\"",
				     impi, realm, domain, nonce, opq, auts_b64);
		else
			r = snprintf(out, n, "Digest username=\"%s\",realm=\"%s\",uri=\"sip:%s\",nonce=\"%s\",algorithm=AKAv1-MD5,%sresponse=\"%s\"",
				     impi, realm, domain, nonce, opq, response_hex ? response_hex : "");
	}
	return r < 0 || (size_t)r >= n ? -1 : 0;
}

int regmsg_build_register(struct buf *out, const struct regmsg_params *p, char branch_out[SIP_BRANCH_LEN])
{
	char branch[SIP_BRANCH_LEN], via[200], from[260], to[200], ruri[140], contact[512], route[160], tags[300];
	char sc[400], tag[16], uri[200];
	struct buf ex;
	struct sip_req_parts q;
	int ok;

	if (!p->domain || !p->impu || !p->adv || !p->pcscf || !p->call_id || !p->authorization)
		return -1;
	if (p->branch)
		snprintf(branch, sizeof(branch), "%s", p->branch);
	else
		sip_new_branch(branch);
	if (branch_out)
		memcpy(branch_out, branch, sizeof(branch));
	if (p->tag)
		snprintf(tag, sizeof(tag), "%s", p->tag);
	else
		snprintf(tag, sizeof(tag), "%u", rnd32());
	snprintf(ruri, sizeof(ruri), "sip:%s", p->domain);
	snprintf(from, sizeof(from), "<%s>;tag=%s", p->impu, tag);
	snprintf(to, sizeof(to), "<%s>", p->impu);
	if (sip_via_make(via, sizeof(via), "UDP", p->adv, branch, false) ||
	    regmsg_route(route, sizeof(route), p->pcscf) ||
	    regmsg_contact_uri(uri, sizeof(uri), p->user, p->adv))
		return -1;
	if (p->imei && p->imei[0])
		snprintf(tags, sizeof(tags), ";+sip.instance=\"<urn:gsma:imei:%s>\";+g.3gpp.icsi-ref=\"%s\";+g.3gpp.smsip", p->imei, REG_ICSI_MMTEL);
	else
		snprintf(tags, sizeof(tags), ";+g.3gpp.icsi-ref=\"%s\";+g.3gpp.smsip", REG_ICSI_MMTEL);
	snprintf(contact, sizeof(contact), "<%s>%s", uri, tags);

	buf_init(&ex, 4096);
	if (p->pani && p->pani[0])
		buf_printf(&ex, "P-Access-Network-Info: %s\r\n", p->pani);
	if (p->user_agent && p->user_agent[0])
		buf_printf(&ex, "User-Agent: %s\r\n", p->user_agent);
	if (p->is_protected && p->security_verify)
		buf_printf(&ex, "Security-Verify: %s\r\n", p->security_verify);
	buf_printf(&ex, "Authorization: %s\r\n", p->authorization);
	buf_printf(&ex, "Expires: %d\r\n", p->expires);
	buf_puts(&ex, "Require: sec-agree\r\nProxy-Require: sec-agree\r\nSupported: path,sec-agree\r\n");
	buf_puts(&ex, "Allow: " REG_ALLOW "\r\n");
	if (p->sc) {
		if (sec_build_client(sc, sizeof(sc), p->sc)) {
			buf_free(&ex);
			return -1;
		}
		buf_printf(&ex, "Security-Client: %s\r\n", sc);
	}
	memset(&q, 0, sizeof(q));
	q.method = "REGISTER";
	q.ruri = ruri;
	q.via = via;
	q.from = from;
	q.to = to;
	q.call_id = p->call_id;
	q.cseq = p->cseq;
	q.route = route;
	q.contact = contact;
	q.extra = buf_cstr(&ex);
	ok = buf_ok(&ex) ? sip_build_request(out, &q) : -1;
	buf_free(&ex);
	return ok;
}
