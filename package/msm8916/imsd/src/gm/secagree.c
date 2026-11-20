/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "secagree.h"
#include "../util/codec.h"
#include "../util/md5.h"
#include "../util/sys.h"

static bool num(const char *s, unsigned long long max, unsigned long long *v)
{
	char *e;

	*v = strtoull(s, &e, 10);
	return e != s && !*e && *v <= max;
}

int sec_parse(const char *v, struct sec_ent *out, int max)
{
	char el[320];
	const char *cur = v;
	int k = 0;

	while (k < max && sip_split_next(&cur, el, sizeof(el)) == 1) {
		struct sec_ent *e = &out[k];
		char tmp[64], *semi, *t;
		unsigned long long x;
		bool nums_ok = true;

		memset(e, 0, sizeof(*e));
		semi = strchr(el, ';');
		if (semi)
			*semi = 0;
		t = el;
		while (*t == ' ' || *t == '\t')
			t++;
		str_copy(e->prot, t, sizeof(e->prot));
		for (t = e->prot + strlen(e->prot); t > e->prot && (t[-1] == ' ' || t[-1] == '\t'); )
			*--t = 0;
		if (semi)
			*semi = ';';
		/* the params follow the first ';' */
		sip_params_get(semi ? semi : "", "alg", e->alg, sizeof(e->alg));
		sip_params_get(semi ? semi : "", "ealg", e->ealg, sizeof(e->ealg));
		sip_params_get(semi ? semi : "", "mod", e->mod, sizeof(e->mod));
		if (sip_params_get(semi ? semi : "", "q", tmp, sizeof(tmp)) > 0) {
			e->has_q = true;
			e->q = atof(tmp);
		}
		if (sip_params_get(semi ? semi : "", "spi-c", tmp, sizeof(tmp)) > 0 && num(tmp, 0xffffffffull, &x))
			e->spi_c = x;
		else
			nums_ok = false;
		if (sip_params_get(semi ? semi : "", "spi-s", tmp, sizeof(tmp)) > 0 && num(tmp, 0xffffffffull, &x))
			e->spi_s = x;
		else
			nums_ok = false;
		if (sip_params_get(semi ? semi : "", "port-c", tmp, sizeof(tmp)) > 0 && num(tmp, 65535, &x))
			e->port_c = x;
		else
			nums_ok = false;
		if (sip_params_get(semi ? semi : "", "port-s", tmp, sizeof(tmp)) > 0 && num(tmp, 65535, &x))
			e->port_s = x;
		else
			nums_ok = false;
		e->sha1 = !strcasecmp(e->alg, "hmac-sha-1-96");
		e->ok = nums_ok && !strcasecmp(e->prot, "ipsec-3gpp") &&
			(e->sha1 || !strcasecmp(e->alg, "hmac-md5-96")) &&
			(!e->ealg[0] || !strcasecmp(e->ealg, "null")) &&
			e->spi_c && e->spi_s && e->port_c && e->port_s;
		k++;
	}
	return k;
}

int sec_select(const struct sec_ent *e, int n)
{
	int i, best = -1;

	for (i = 0; i < n; i++) {
		if (!e[i].ok)
			continue;
		if (best < 0 || (e[i].has_q ? e[i].q : 0.0) > (e[best].has_q ? e[best].q : 0.0))
			best = i;
	}
	return best;
}

int sec_server_value(const struct sip_msg *m, char *out, size_t n)
{
	int i, c = sip_hdr_count(m, "Security-Server");
	size_t l = 0;

	if (!c)
		return -1;
	for (i = 0; i < c; i++) {
		const char *v = sip_hdr(m, "Security-Server", i);
		size_t vl = strlen(v), need = vl + (i ? 2 : 0);

		if (l + need >= n)
			return -1;
		if (i) {
			memcpy(out + l, ", ", 2);
			l += 2;
		}
		memcpy(out + l, v, vl);
		l += vl;
	}
	out[l] = 0;
	return 0;
}

int sec_build_client(char *out, size_t n, const struct sec_client *c)
{
	int r = snprintf(out, n,
		"ipsec-3gpp; alg=hmac-md5-96; ealg=null; spi-c=%u; spi-s=%u; port-c=%u; port-s=%u,"
		"ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=%u; spi-s=%u; port-c=%u; port-s=%u",
		c->spi_c, c->spi_s, c->port_c, c->port_s, c->spi_c, c->spi_s, c->port_c, c->port_s);

	return r < 0 || (size_t)r >= n ? -1 : 0;
}

int sec_build_verify(char *out, size_t n, const char *server_value)
{
	return str_copy(out, server_value, n) >= n ? -1 : 0;
}

/* ---- digest ---- */

int digest_parse_challenge(const char *v, struct digest_challenge *c)
{
	uint8_t raw[64];
	int n;

	memset(c, 0, sizeof(*c));
	if (sip_kv_get(v, "realm", c->realm, sizeof(c->realm)) != 1 ||
	    sip_kv_get(v, "nonce", c->nonce, sizeof(c->nonce)) != 1)
		return -1;
	sip_kv_get(v, "algorithm", c->algorithm, sizeof(c->algorithm));
	if (!strncasecmp(c->algorithm, "AKAv", 4)) {
		n = b64_decode(c->nonce, raw, sizeof(raw));
		if (n >= 32) {
			memcpy(c->rand, raw, 16);
			memcpy(c->autn, raw + 16, 16);
			c->aka = true;
		}
	}
	return 0;
}

void digest_response(const char *user, const char *realm, const uint8_t *res, size_t reslen,
		     const char *nonce, const char *method, const char *uri, char out[33])
{
	struct md5_ctx c;
	uint8_t h1[16];
	char h1hex[33], h2hex[33], tmp[512];

	md5_init(&c);
	md5_update(&c, user, strlen(user));
	md5_update(&c, ":", 1);
	md5_update(&c, realm, strlen(realm));
	md5_update(&c, ":", 1);
	md5_update(&c, res, reslen);
	md5_final(&c, h1);
	hex_encode(h1, 16, h1hex);
	snprintf(tmp, sizeof(tmp), "%s:%s", method, uri);
	md5_hex(tmp, strlen(tmp), h2hex);
	md5_init(&c);
	md5_update(&c, h1hex, 32);
	md5_update(&c, ":", 1);
	md5_update(&c, nonce, strlen(nonce));
	md5_update(&c, ":", 1);
	md5_update(&c, h2hex, 32);
	md5_final(&c, h1);
	hex_encode(h1, 16, out);
}

int digest_build_authorization(char *out, size_t n, const struct digest_auth *a)
{
	int r;

	if (!a->nonce[0]) {
		r = snprintf(out, n, "Digest uri=\"%s\",username=\"%s\",response=\"\",realm=\"%s\",nonce=\"\"",
			     a->uri, a->user, a->realm);
	} else if (a->auts && a->auts_len) {
		char b64[40];

		if (b64_encode(a->auts, a->auts_len, b64, sizeof(b64)) < 0)
			return -1;
		r = snprintf(out, n, "Digest username=\"%s\",realm=\"%s\",uri=\"%s\",nonce=\"%s\","
			     "algorithm=AKAv1-MD5,response=\"\",auts=\"%s\"",
			     a->user, a->realm, a->uri, a->nonce, b64);
	} else {
		char resp[33];

		digest_response(a->user, a->realm, a->res, a->res_len, a->nonce, a->method, a->uri, resp);
		r = snprintf(out, n, "Digest username=\"%s\",realm=\"%s\",uri=\"%s\",nonce=\"%s\","
			     "algorithm=AKAv1-MD5,response=\"%s\"",
			     a->user, a->realm, a->uri, a->nonce, resp);
	}
	return r < 0 || (size_t)r >= n ? -1 : 0;
}
