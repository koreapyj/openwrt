/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "gmcall_util.h"

#define MAX_DIGITS 32

static bool is_sep(char c)
{
	return c == ' ' || c == '-' || c == '.' || c == '(' || c == ')' || c == '\t';
}

/* decode %XX in place into out (only what number URIs contain) */
static int unescape(const char *in, char *out, size_t n)
{
	size_t o = 0;

	for (; *in; in++) {
		char c = *in;

		if (c == '%' && isxdigit((unsigned char)in[1]) && isxdigit((unsigned char)in[2])) {
			char h[3] = { in[1], in[2], 0 };

			c = (char)strtol(h, NULL, 16);
			in += 2;
		}
		if (o + 1 >= n)
			return -1;
		out[o++] = c;
	}
	out[o] = 0;
	return 0;
}

int gmcall_number_normalize(const char *in, char *out, size_t n)
{
	char buf[256], raw[256], dec[256];
	struct sip_uri u;
	const char *src;
	size_t o = 0, i;

	if (!in || !n)
		return -1;
	out[0] = 0;
	if (strchr(in, '<')) {
		if (sip_uri_of(in, buf, sizeof(buf)))
			return -1;
	} else if (strlen(in) >= sizeof(buf)) {
		return -1;
	} else {
		snprintf(buf, sizeof(buf), "%s", in);
	}
	if (!strncasecmp(buf, "sip:", 4) || !strncasecmp(buf, "sips:", 5) || !strncasecmp(buf, "tel:", 4)) {
		if (sip_uri_parse(buf, &u))
			return -1;
		if (strcmp(u.scheme, "tel") && !u.host[0])
			return -1;
		if (strcmp(u.scheme, "tel") && !strstr(buf, "@"))
			return -1;	/* sip:host without a user part: no number */
		snprintf(raw, sizeof(raw), "%s", u.user);
	} else {
		char *semi;

		snprintf(raw, sizeof(raw), "%s", buf);
		semi = strchr(raw, ';');
		if (semi)
			*semi = 0;
	}
	if (unescape(raw, dec, sizeof(dec)))
		return -1;
	src = dec;
	for (i = 0; src[i]; i++) {
		char c = src[i];

		if (is_sep(c))
			continue;
		if (isdigit((unsigned char)c) || c == '*' || c == '#' || (c == '+' && o == 0)) {
			if (o + 1 >= n)
				return -1;
			out[o++] = c;
		} else {
			out[0] = 0;	/* letters ("anonymous", host names): not a number */
			return -1;
		}
	}
	out[o] = 0;
	return o ? 0 : -1;
}

int gmcall_make_target(const char *in, const char *phone_context, char *out, size_t n)
{
	char num[MAX_DIGITS + 4];
	size_t o = 0, i, ndig = 0;
	bool plus = false;
	int r;

	if (!in || !out || !n)
		return -EINVAL;
	while (*in == ' ' || *in == '\t')
		in++;
	if (!strncasecmp(in, "sip:", 4) || !strncasecmp(in, "sips:", 5) || !strncasecmp(in, "tel:", 4)) {
		struct sip_uri u;

		if (sip_uri_parse(in, &u))
			return -EINVAL;
		r = snprintf(out, n, "%s", in);
		/* strip trailing blanks only */
		while (r > 0 && ((size_t)r < n) && (out[r - 1] == ' ' || out[r - 1] == '\t'))
			out[--r] = 0;
		return r < 0 || (size_t)r >= n ? -EMSGSIZE : 0;
	}
	for (i = 0; in[i]; i++) {
		char c = in[i];

		if (is_sep(c))
			continue;
		if (c == '+' && o == 0) {
			plus = true;
		} else if (isdigit((unsigned char)c) || c == '*' || c == '#') {
			if (isdigit((unsigned char)c))
				ndig++;
		} else {
			return -EINVAL;
		}
		if (o + 1 >= sizeof(num))
			return -EINVAL;
		num[o++] = c;
	}
	num[o] = 0;
	if (!ndig || ndig > MAX_DIGITS)
		return -EINVAL;
	if (plus) {
		for (i = 1; num[i]; i++)
			if (!isdigit((unsigned char)num[i]))
				return -EINVAL;	/* '*' / '#' do not belong into a global number */
		r = snprintf(out, n, "tel:%s", num);
	} else {
		char enc[3 * MAX_DIGITS + 4];
		size_t e = 0;

		for (i = 0; num[i]; i++) {
			if (num[i] == '#') {
				memcpy(enc + e, "%23", 3);
				e += 3;
			} else {
				enc[e++] = num[i];
			}
		}
		enc[e] = 0;
		if (!phone_context || !phone_context[0])
			r = snprintf(out, n, "tel:%s", enc);
		else
			r = snprintf(out, n, "tel:%s;phone-context=%s", enc, phone_context);
	}
	return r < 0 || (size_t)r >= n ? -EMSGSIZE : 0;
}

int gmcall_parse_session_expires(const char *v, unsigned *interval, int *refresher)
{
	char *end;
	unsigned long iv;
	const char *p, *semi;
	char val[16];

	if (!v)
		return -1;
	while (*v == ' ')
		v++;
	iv = strtoul(v, &end, 10);
	if (end == v || iv == 0 || iv > 86400 * 7)
		return -1;
	while (*end == ' ')
		end++;
	if (*end && *end != ';')
		return -1;
	*interval = (unsigned)iv;
	if (refresher) {
		*refresher = GMCALL_REFRESHER_NONE;
		semi = strchr(v, ';');
		p = semi ? semi : "";
		if (sip_params_get(p, "refresher", val, sizeof(val)) == 1) {
			if (!strcasecmp(val, "uac"))
				*refresher = GMCALL_REFRESHER_UAC;
			else if (!strcasecmp(val, "uas"))
				*refresher = GMCALL_REFRESHER_UAS;
		}
	}
	return 0;
}

int gmcall_parse_min_se(const char *v, unsigned *secs)
{
	char *end;
	unsigned long x;

	if (!v)
		return -1;
	x = strtoul(v, &end, 10);
	if (end == v || x == 0 || x > 86400)
		return -1;
	*secs = (unsigned)x;
	return 0;
}

int gmcall_reason_text(const char *h, char *out, size_t n)
{
	const char *semi;
	char val[96];
	int r;

	if (!n)
		return -1;
	out[0] = 0;
	if (!h)
		return 0;
	semi = strchr(h, ';');
	if (!semi)
		return 0;
	r = sip_params_get(semi, "text", val, sizeof(val));
	if (r < 0)
		return -1;
	if (r == 1 && val[0])
		return snprintf(out, n, "%s", val) >= (int)n ? -1 : 0;
	r = sip_params_get(semi, "cause", val, sizeof(val));
	if (r == 1 && val[0])
		return snprintf(out, n, "cause %s", val) >= (int)n ? -1 : 0;
	return 0;
}

int gmcall_warning_text(const char *h, char *out, size_t n)
{
	const char *q1, *q2;
	size_t l;

	if (!n)
		return -1;
	out[0] = 0;
	if (!h || !(q1 = strchr(h, '"')))
		return 0;
	q2 = strchr(q1 + 1, '"');
	if (!q2)
		return 0;
	l = (size_t)(q2 - q1 - 1);
	if (l >= n)
		return -1;
	memcpy(out, q1 + 1, l);
	out[l] = 0;
	return 0;
}

static bool tok_eq(const char *s, size_t l, const char *tok)
{
	return strlen(tok) == l && !strncasecmp(s, tok, l);
}

/* iterate list elements; returns false at the end */
static bool list_next(const char **p, const char **s, size_t *l)
{
	const char *q = *p, *e;

	while (*q == ' ' || *q == ',' || *q == '\t')
		q++;
	if (!*q)
		return false;
	e = q;
	while (*e && *e != ',' && *e != ';')
		e++;
	*s = q;
	*l = (size_t)(e - q);
	while (*l && (q[*l - 1] == ' ' || q[*l - 1] == '\t'))
		(*l)--;
	while (*e && *e != ',')
		e++;	/* skip parameters */
	*p = e;
	return true;
}

bool gmcall_has_token(const char *hdr, const char *tok)
{
	const char *p = hdr, *s;
	size_t l;

	if (!hdr)
		return false;
	while (list_next(&p, &s, &l))
		if (tok_eq(s, l, tok))
			return true;
	return false;
}

int gmcall_unsupported_options(const char *req, char *out, size_t n)
{
	const char *p = req, *s;
	size_t l, o = 0;
	int cnt = 0;

	if (n)
		out[0] = 0;
	if (!req)
		return 0;
	while (list_next(&p, &s, &l)) {
		if (tok_eq(s, l, "timer") || tok_eq(s, l, "sec-agree"))
			continue;
		if (o + l + 2 >= n)
			break;
		if (o)
			out[o++] = ',';
		memcpy(out + o, s, l);
		o += l;
		out[o] = 0;
		cnt++;
	}
	return cnt;
}

static void id_from_value(const char *v, struct gmcall_identity *id)
{
	struct sip_nameaddr na;
	char first[320];
	const char *cur = v;

	if (!v || sip_split_next(&cur, first, sizeof(first)) <= 0)
		return;
	if (sip_nameaddr_parse(first, &na))
		return;
	snprintf(id->uri, sizeof(id->uri), "%s", na.uri);
	snprintf(id->display, sizeof(id->display), "%s", na.display);
	if (gmcall_number_normalize(na.uri, id->number, sizeof(id->number)))
		id->number[0] = 0;
}

void gmcall_identity_from_request(const struct sip_msg *req, struct gmcall_identity *id)
{
	const char *pai = sip_hdr(req, "P-Asserted-Identity", 0), *from = sip_hdr(req, "From", 0);
	const char *priv = sip_hdr(req, "Privacy", 0);
	struct gmcall_identity f;
	int i;

	memset(id, 0, sizeof(*id));
	memset(&f, 0, sizeof(f));
	id_from_value(from, &f);
	if (pai)
		id_from_value(pai, id);
	if (!id->uri[0])
		*id = f;
	else if (!id->display[0])
		snprintf(id->display, sizeof(id->display), "%s", f.display);
	/* with several P-Asserted-Identity lines prefer a sip: one that yields a number */
	for (i = 1; !id->number[0] && sip_hdr(req, "P-Asserted-Identity", i); i++)
		id_from_value(sip_hdr(req, "P-Asserted-Identity", i), id);
	if (priv) {
		char pv[96], *c;

		snprintf(pv, sizeof(pv), "%s", priv);
		for (c = pv; *c; c++)	/* priv-values are ';' separated */
			if (*c == ';')
				*c = ',';
		if (gmcall_has_token(pv, "id") || gmcall_has_token(pv, "header"))
			id->anonymous = true;
	}
	if (!id->anonymous && from && strcasestr(from, "anonymous@anonymous.invalid"))
		id->anonymous = true;
}

const char *gmcall_status_text(int s)
{
	return sip_reason_phrase(s);
}
