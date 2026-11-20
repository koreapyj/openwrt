/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "msg.h"
#include "../util/sys.h"

/* ------------------------------------------------------------------ */
/* header names                                                        */

static const struct { char c; const char *full; } compact[] = {
	{ 'i', "Call-ID" }, { 'm', "Contact" }, { 'e', "Content-Encoding" },
	{ 'l', "Content-Length" }, { 'c', "Content-Type" }, { 'f', "From" },
	{ 's', "Subject" }, { 'k', "Supported" }, { 't', "To" }, { 'v', "Via" },
};

static const char *canon(const char *n)
{
	size_t i;

	if (n[0] && !n[1])
		for (i = 0; i < sizeof(compact) / sizeof(compact[0]); i++)
			if (tolower((unsigned char)n[0]) == compact[i].c)
				return compact[i].full;
	return n;
}

static bool name_eq(const char *a, const char *b)
{
	return !strcasecmp(canon(a), canon(b));
}

const char *sip_hdr(const struct sip_msg *m, const char *name, int idx)
{
	int i;

	for (i = 0; i < m->nh; i++)
		if (name_eq(m->hdr[i].name, name) && idx-- == 0)
			return m->hdr[i].val;
	return NULL;
}

int sip_hdr_count(const struct sip_msg *m, const char *name)
{
	int i, n = 0;

	for (i = 0; i < m->nh; i++)
		if (name_eq(m->hdr[i].name, name))
			n++;
	return n;
}

bool sip_is_method(const struct sip_msg *m, const char *method)
{
	return !m->is_resp && !strcmp(m->method, method);
}

const char *sip_reason_phrase(int s)
{
	switch (s) {
	case 100: return "Trying";
	case 180: return "Ringing";
	case 181: return "Call Is Being Forwarded";
	case 183: return "Session Progress";
	case 200: return "OK";
	case 202: return "Accepted";
	case 300: return "Multiple Choices";
	case 302: return "Moved Temporarily";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 406: return "Not Acceptable";
	case 407: return "Proxy Authentication Required";
	case 408: return "Request Timeout";
	case 410: return "Gone";
	case 413: return "Request Entity Too Large";
	case 415: return "Unsupported Media Type";
	case 420: return "Bad Extension";
	case 421: return "Extension Required";
	case 422: return "Session Interval Too Small";
	case 423: return "Interval Too Brief";
	case 480: return "Temporarily Unavailable";
	case 481: return "Call/Transaction Does Not Exist";
	case 482: return "Loop Detected";
	case 483: return "Too Many Hops";
	case 484: return "Address Incomplete";
	case 486: return "Busy Here";
	case 487: return "Request Terminated";
	case 488: return "Not Acceptable Here";
	case 489: return "Bad Event";
	case 491: return "Request Pending";
	case 500: return "Server Internal Error";
	case 501: return "Not Implemented";
	case 502: return "Bad Gateway";
	case 503: return "Service Unavailable";
	case 504: return "Server Time-out";
	case 513: return "Message Too Large";
	case 603: return "Decline";
	case 604: return "Does Not Exist Anywhere";
	case 606: return "Not Acceptable";
	default: return "Unknown";
	}
}

/* ------------------------------------------------------------------ */
/* parser                                                              */

static char *trim_ws(char *s)
{
	char *e;

	while (*s == ' ' || *s == '\t')
		s++;
	e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t'))
		*--e = 0;
	return s;
}

/* index of the end of the header text and of the start of the body */
static void find_hdr_end(const uint8_t *d, size_t len, size_t *he, size_t *bs)
{
	size_t i;

	*he = *bs = len;
	for (i = 0; i < len; i++) {
		if (d[i] != '\n')
			continue;
		if (i + 1 < len && d[i + 1] == '\n') {
			*he = i; *bs = i + 2; return;
		}
		if (i + 2 < len && d[i + 1] == '\r' && d[i + 2] == '\n') {
			*he = i; *bs = i + 3; return;
		}
	}
}

static int parse_start_line(struct sip_msg *m, char *line)
{
	char *sp1, *sp2;
	size_t i;

	if (!strncasecmp(line, "SIP/2.0", 7) && line[7] == ' ') {
		char *p = line + 8;

		for (i = 0; i < 3; i++)
			if (!isdigit((unsigned char)p[i]))
				return SIP_E_BAD;
		if (p[3] && p[3] != ' ')
			return SIP_E_BAD;
		m->is_resp = true;
		m->status = (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
		if (m->status < 100)
			return SIP_E_BAD;
		m->reason = p[3] ? p + 4 : p + 3;
		return 0;
	}
	sp1 = strchr(line, ' ');
	if (!sp1 || sp1 == line)
		return SIP_E_BAD;
	*sp1++ = 0;
	sp2 = strrchr(sp1, ' ');
	if (!sp2 || sp2 == sp1 || strcasecmp(sp2 + 1, "SIP/2.0"))
		return SIP_E_BAD;
	*sp2 = 0;
	if (strlen(line) >= sizeof(m->method))
		return SIP_E_TOOBIG;
	for (i = 0; line[i]; i++)
		if (!isalnum((unsigned char)line[i]) && line[i] != '-' && line[i] != '.')
			return SIP_E_BAD;
	memcpy(m->method, line, strlen(line) + 1);
	m->ruri = sp1;
	return 0;
}

int sip_parse(const uint8_t *data, size_t len, struct sip_msg *m)
{
	size_t he, bs, r = 0, w = 0;
	bool first = true;
	char *b;
	int rc;

	memset(m, 0, sizeof(*m));
	if (len > SIP_MAX_MSG)
		return SIP_E_TOOBIG;
	if (!len)
		return SIP_E_BAD;
	b = malloc(len + 1);
	if (!b)
		return SIP_E_NOMEM;
	memcpy(b, data, len);
	b[len] = 0;
	m->buf = b;
	find_hdr_end(data, len, &he, &bs);

	while (r < he) {
		const char *nl = memchr(b + r, '\n', he - r);
		size_t le = nl ? (size_t)(nl - b) : he, tl = le - r;
		char *o = b + w;

		if (tl && b[r + tl - 1] == '\r')
			tl--;
		if (first) {
			memmove(o, b + r, tl);
			o[tl] = 0;
			rc = parse_start_line(m, o);
			if (rc)
				goto fail;
			w += tl + 1;
			first = false;
		} else if (tl && (b[r] == ' ' || b[r] == '\t')) {
			char *t;

			if (!m->nh) {
				r = le + 1;
				continue;
			}
			memmove(o, b + r, tl);
			o[tl] = 0;
			t = trim_ws(o);
			if (*t) {	/* join onto the previous header value */
				size_t n = strlen(t);

				b[w - 1] = ' ';
				memmove(b + w, t, n + 1);
				w += n + 1;
			}
		} else if (tl) {
			char *colon;

			memmove(o, b + r, tl);
			o[tl] = 0;
			colon = strchr(o, ':');
			if (colon && colon != o) {
				if (m->nh >= SIP_MAX_HDRS) {
					rc = SIP_E_HDRS;
					goto fail;
				}
				*colon = 0;
				m->hdr[m->nh].name = trim_ws(o);
				m->hdr[m->nh].val = trim_ws(colon + 1);
				m->nh++;
				w += tl + 1;
			}	/* lines without a colon are ignored */
		}
		r = le + 1;
	}
	if (first) {
		rc = SIP_E_BAD;
		goto fail;
	}
	{
		size_t avail = bs <= len ? len - bs : 0;
		const char *cl = sip_hdr(m, "Content-Length", 0);

		m->body_len = avail;
		if (cl) {
			char *e;
			unsigned long v;

			v = strtoul(cl, &e, 10);
			if (e == cl || *e) {
				rc = SIP_E_BAD;
				goto fail;
			}
			if (v > avail) {
				rc = SIP_E_TRUNC;
				goto fail;
			}
			m->body_len = v;
		}
		m->body = (const uint8_t *)b + (bs <= len ? bs : len);
		b[(bs <= len ? bs : len) + m->body_len] = 0;
	}
	return 0;
fail:
	sip_msg_free(m);
	return rc;
}

void sip_msg_free(struct sip_msg *m)
{
	free(m->buf);
	memset(m, 0, sizeof(*m));
}

long sip_frame_len(const uint8_t *d, size_t len)
{
	size_t he, bs, i;
	unsigned long cl = 0;

	find_hdr_end(d, len, &he, &bs);
	if (he == len) {	/* no blank line yet */
		return len > SIP_MAX_MSG ? -1 : 0;
	}
	/* scan header lines for Content-Length / l */
	i = 0;
	while (i < he) {
		const uint8_t *nl = memchr(d + i, '\n', he - i);
		size_t le = nl ? (size_t)(nl - d) : he;
		const uint8_t *ln = d + i;
		size_t ll = le - i, k = 0;

		if (ll && (ln[0] == 'l' || ln[0] == 'L' || ln[0] == 'C' || ln[0] == 'c')) {
			size_t nlen;
			char name[16];

			while (k < ll && ln[k] != ':' && ln[k] != ' ' && ln[k] != '\t')
				k++;
			nlen = k;
			if (nlen < sizeof(name)) {
				memcpy(name, ln, nlen);
				name[nlen] = 0;
				if (!strcasecmp(name, "Content-Length") || !strcasecmp(name, "l")) {
					char num[24];
					size_t q = k, n = 0;

					while (q < ll && (ln[q] == ' ' || ln[q] == '\t' || ln[q] == ':'))
						q++;
					while (q < ll && isdigit(ln[q]) && n < sizeof(num) - 1)
						num[n++] = ln[q++];
					num[n] = 0;
					if (!n)
						return -1;
					cl = strtoul(num, NULL, 10);
				}
			}
		}
		i = le + 1;
	}
	if (cl > SIP_MAX_MSG || bs + cl > SIP_MAX_MSG)
		return -1;
	if (len < bs + cl)
		return 0;
	return (long)(bs + cl);
}

/* ------------------------------------------------------------------ */
/* lists and parameters                                                */

int sip_split_next(const char **cursor, char *out, size_t outsz)
{
	const char *p = *cursor;

	for (;;) {
		const char *start, *end;
		int depth = 0, q = 0;
		size_t l;

		while (*p == ' ' || *p == '\t' || *p == ',')
			p++;
		if (!*p) {
			*cursor = p;
			return 0;
		}
		start = p;
		for (; *p; p++) {
			if (*p == '"' && (p == start || p[-1] != '\\'))
				q = !q;
			else if (!q) {
				if (*p == '<')
					depth++;
				else if (*p == '>' && depth)
					depth--;
				else if (*p == ',' && !depth)
					break;
			}
		}
		end = p;
		while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
			end--;
		*cursor = p;
		l = end - start;
		if (!l)
			continue;
		if (l >= outsz)
			return -1;
		memcpy(out, start, l);
		out[l] = 0;
		return 1;
	}
}

void sip_list_init(struct sip_list *it, const struct sip_msg *m, const char *name)
{
	it->m = m;
	it->name = name;
	it->hidx = 0;
	it->cur = NULL;
}

int sip_list_next(struct sip_list *it, char *out, size_t outsz)
{
	for (;;) {
		int r;

		if (!it->cur) {
			it->cur = sip_hdr(it->m, it->name, it->hidx++);
			if (!it->cur)
				return 0;
		}
		r = sip_split_next(&it->cur, out, outsz);
		if (r > 0)
			return 1;
		if (r < 0) {
			it->cur = "";
			it->hidx = 1 << 20;
			return -1;
		}
		it->cur = NULL;
	}
}

/* iterate segments separated by any char of seps outside quotes/<> */
static const char *seg_next(const char *p, const char *seps, const char **s, const char **e)
{
	int depth = 0, q = 0;

	if (!*p)
		return NULL;
	*s = p;
	for (; *p; p++) {
		if (*p == '"' && (p == *s || p[-1] != '\\'))
			q = !q;
		else if (!q) {
			if (*p == '<')
				depth++;
			else if (*p == '>' && depth)
				depth--;
			else if (!depth && strchr(seps, *p))
				break;
		}
	}
	*e = p;
	return *p ? p + 1 : p;
}

static int seg_match(const char *s, const char *e, const char *name, bool keytok, char *out, size_t n)
{
	const char *eq = memchr(s, '=', e - s), *ke = eq ? eq : e, *ks = s, *v, *ve;
	size_t nl = strlen(name), l;

	while (ks < ke && (*ks == ' ' || *ks == '\t'))
		ks++;
	while (ke > ks && (ke[-1] == ' ' || ke[-1] == '\t'))
		ke--;
	if (keytok) {	/* "Digest realm" -> "realm" */
		const char *t = ke;

		while (t > ks && t[-1] != ' ' && t[-1] != '\t')
			t--;
		ks = t;
	}
	if ((size_t)(ke - ks) != nl || strncasecmp(ks, name, nl))
		return 0;
	if (!eq) {
		if (n)
			out[0] = 0;
		return 1;
	}
	v = eq + 1;
	ve = e;
	while (v < ve && (*v == ' ' || *v == '\t'))
		v++;
	while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t'))
		ve--;
	if (ve - v >= 2 && *v == '"' && ve[-1] == '"') {
		v++;
		ve--;
	}
	l = ve - v;
	if (l >= n)
		return -1;
	memcpy(out, v, l);
	out[l] = 0;
	return 1;
}

int sip_params_get(const char *params, const char *name, char *out, size_t n)
{
	const char *p = params, *s, *e;

	while ((p = seg_next(p, ";", &s, &e))) {
		int r = seg_match(s, e, name, false, out, n);

		if (r)
			return r;
	}
	return 0;
}

int sip_kv_get(const char *v, const char *name, char *out, size_t n)
{
	const char *p = v, *s, *e;

	while ((p = seg_next(p, ";,", &s, &e))) {
		int r = seg_match(s, e, name, true, out, n);

		if (r)
			return r;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* URIs                                                                */

static int copy_to(char *dst, size_t n, const char *s, size_t l)
{
	if (l >= n)
		return -1;
	memcpy(dst, s, l);
	dst[l] = 0;
	return 0;
}

int sip_uri_parse(const char *s, struct sip_uri *u)
{
	const char *colon = strchr(s, ':'), *rest, *at, *hp, *q;
	size_t i, l;

	memset(u, 0, sizeof(*u));
	if (!colon || (size_t)(colon - s) >= sizeof(u->scheme))
		return -1;
	for (i = 0; s + i < colon; i++)
		u->scheme[i] = tolower((unsigned char)s[i]);
	rest = colon + 1;
	q = strchr(rest, '?');
	if (!strcmp(u->scheme, "tel")) {
		const char *semi = strchr(rest, ';');
		const char *end = q ? q : rest + strlen(rest);

		if (semi && semi > end)
			semi = NULL;
		l = (semi ? semi : end) - rest;
		if (!l || copy_to(u->user, sizeof(u->user), rest, l))
			return -1;
		if (semi && copy_to(u->params, sizeof(u->params), semi, end - semi))
			return -1;
		return 0;
	}
	if (strcmp(u->scheme, "sip") && strcmp(u->scheme, "sips"))
		return -1;
	at = strchr(rest, '@');
	if (at && q && at > q)
		at = NULL;
	if (at) {
		const char *pw = memchr(rest, ':', at - rest);

		l = (pw ? pw : at) - rest;
		if (copy_to(u->user, sizeof(u->user), rest, l))
			return -1;
		hp = at + 1;
	} else {
		hp = rest;
	}
	{
		const char *end = q ? q : hp + strlen(hp), *he = hp, *semi;

		if (*hp == '[') {
			const char *rb = memchr(hp, ']', end - hp);

			if (!rb)
				return -1;
			if (copy_to(u->host, sizeof(u->host), hp + 1, rb - hp - 1))
				return -1;
			he = rb + 1;
		} else {
			while (he < end && *he != ':' && *he != ';')
				he++;
			if (he == hp || copy_to(u->host, sizeof(u->host), hp, he - hp))
				return -1;
		}
		if (he < end && *he == ':') {
			char *e;
			unsigned long v = strtoul(he + 1, &e, 10);

			if (e == he + 1 || v > 65535)
				return -1;
			u->port = v;
			he = e;
		}
		semi = he;
		if (semi < end && *semi == ';' && copy_to(u->params, sizeof(u->params), semi, end - semi))
			return -1;
		else if (semi < end && *semi != ';')
			return -1;
	}
	if (!u->host[0])
		return -1;
	return 0;
}

int sip_uri_format(const struct sip_uri *u, char *out, size_t n)
{
	int r;

	if (!strcmp(u->scheme, "tel"))
		r = snprintf(out, n, "tel:%s%s", u->user, u->params);
	else {
		char port[8] = "";

		if (u->port)
			snprintf(port, sizeof(port), ":%u", u->port);
		r = snprintf(out, n, host_is_v6(u->host) ? "%s:%s%s[%s]%s%s" : "%s:%s%s%s%s%s",
			     u->scheme, u->user, u->user[0] ? "@" : "", u->host, port, u->params);
	}
	return r < 0 || (size_t)r >= n ? -1 : 0;
}

int sip_uri_param(const struct sip_uri *u, const char *name, char *out, size_t n)
{
	return sip_params_get(u->params, name, out, n);
}

int sip_nameaddr_parse(const char *v, struct sip_nameaddr *n)
{
	const char *p = v, *lt = NULL, *gt, *q;
	int inq = 0;

	memset(n, 0, sizeof(*n));
	while (*p == ' ' || *p == '\t')
		p++;
	for (q = p; *q; q++) {
		if (*q == '"' && (q == p || q[-1] != '\\'))
			inq = !inq;
		else if (*q == '<' && !inq) {
			lt = q;
			break;
		}
	}
	if (lt) {
		const char *ds = p, *de = lt;

		gt = strchr(lt, '>');
		if (!gt)
			return -1;
		while (de > ds && (de[-1] == ' ' || de[-1] == '\t'))
			de--;
		if (de - ds >= 2 && *ds == '"' && de[-1] == '"') {
			ds++;
			de--;
		}
		if (copy_to(n->display, sizeof(n->display), ds, de - ds))
			return -1;
		if (copy_to(n->uri, sizeof(n->uri), lt + 1, gt - lt - 1))
			return -1;
		p = gt + 1;
		while (*p == ' ' || *p == '\t')
			p++;
		return copy_to(n->params, sizeof(n->params), p, strlen(p));
	}
	/* addr-spec: parameters belong to the header */
	for (q = p; *q && *q != ';' && *q != ',' && *q != ' ' && *q != '\t'; q++)
		;
	if (copy_to(n->uri, sizeof(n->uri), p, q - p))
		return -1;
	while (*q == ' ' || *q == '\t')
		q++;
	return copy_to(n->params, sizeof(n->params), q, strlen(q));
}

int sip_tag(const char *v, char *out, size_t n)
{
	struct sip_nameaddr na;
	int r;

	if (sip_nameaddr_parse(v, &na))
		return -1;
	r = sip_params_get(na.params, "tag", out, n);
	if (r < 0)
		return -1;
	if (!r && n)
		out[0] = 0;
	return 0;
}

int sip_uri_of(const char *v, char *out, size_t n)
{
	struct sip_nameaddr na;

	if (sip_nameaddr_parse(v, &na) || strlen(na.uri) >= n)
		return -1;
	memcpy(out, na.uri, strlen(na.uri) + 1);
	return 0;
}

int sip_cseq(const struct sip_msg *m, uint32_t *num, char *method, size_t msz)
{
	const char *v = sip_hdr(m, "CSeq", 0);
	char *e;
	unsigned long long x;

	if (!v)
		return -1;
	x = strtoull(v, &e, 10);
	if (e == v || x > 0xffffffffull)
		return -1;
	*num = x;
	while (*e == ' ' || *e == '\t')
		e++;
	if (!*e)
		return -1;
	if (method && msz && str_copy(method, e, msz) >= msz)
		return -1;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Via                                                                 */

int sip_via_parse(const char *v, struct sip_via *o)
{
	const char *p = v, *t, *te, *sb, *sbe, *semi;
	char tmp[16];
	size_t i;
	int r;

	memset(o, 0, sizeof(*o));
	o->rport = -1;
	/* SIP / 2.0 / UDP with optional blanks around the slashes */
	for (i = 0; i < 2; i++) {
		while (*p == ' ' || *p == '\t')
			p++;
		while (*p && *p != '/')
			p++;
		if (*p != '/')
			return -1;
		p++;
	}
	while (*p == ' ' || *p == '\t')
		p++;
	t = p;
	while (*p && *p != ' ' && *p != '\t' && *p != ';')
		p++;
	te = p;
	if (te == t || (size_t)(te - t) >= sizeof(o->transport))
		return -1;
	for (i = 0; t + i < te; i++)
		o->transport[i] = toupper((unsigned char)t[i]);
	while (*p == ' ' || *p == '\t')
		p++;
	sb = p;
	while (*p && *p != ';' && *p != ' ' && *p != '\t')
		p++;
	sbe = p;
	if (sbe == sb)
		return -1;
	if (*sb == '[') {
		const char *rb = memchr(sb, ']', sbe - sb);

		if (!rb || copy_to(o->host, sizeof(o->host), sb + 1, rb - sb - 1))
			return -1;
		if (rb + 1 < sbe && rb[1] == ':')
			o->port = atoi(rb + 2);
	} else {
		const char *c = memchr(sb, ':', sbe - sb);

		if (copy_to(o->host, sizeof(o->host), sb, (c ? c : sbe) - sb))
			return -1;
		if (c)
			o->port = atoi(c + 1);
	}
	while (*p == ' ' || *p == '\t')
		p++;
	semi = p;
	if (*semi == ';' && copy_to(o->params, sizeof(o->params), semi, strlen(semi)))
		return -1;
	if (sip_params_get(o->params, "branch", o->branch, sizeof(o->branch)) < 0 ||
	    sip_params_get(o->params, "received", o->received, sizeof(o->received)) < 0)
		return -1;
	r = sip_params_get(o->params, "rport", tmp, sizeof(tmp));
	if (r > 0)
		o->rport = tmp[0] ? atoi(tmp) : 0;
	return 0;
}

int sip_top_via(const struct sip_msg *m, struct sip_via *out)
{
	struct sip_list it;
	char el[320];

	sip_list_init(&it, m, "Via");
	if (sip_list_next(&it, el, sizeof(el)) != 1)
		return -1;
	return sip_via_parse(el, out);
}

int sip_via_make(char *out, size_t n, const char *transport, const struct addr *sb, const char *branch, bool rport)
{
	char hp[INET6_ADDRSTRLEN + 8], tr[8];
	size_t i;
	int r;

	if (addr_str(sb, hp, sizeof(hp)) || strlen(transport) >= sizeof(tr))
		return -1;
	for (i = 0; transport[i]; i++)
		tr[i] = toupper((unsigned char)transport[i]);
	tr[i] = 0;
	r = snprintf(out, n, "SIP/2.0/%s %s;branch=%s%s", tr, hp, branch, rport ? ";rport" : "");
	return r < 0 || (size_t)r >= n ? -1 : 0;
}

void sip_new_branch(char out[SIP_BRANCH_LEN])
{
	memcpy(out, SIP_MAGIC_COOKIE, 7);
	rnd_token(out + 7, 16);
}

/* ------------------------------------------------------------------ */
/* builder                                                             */

static bool has_crlf(const char *s)
{
	return s && strpbrk(s, "\r\n");
}

static void put_hdr(struct buf *b, const char *name, const char *val)
{
	buf_puts(b, name);
	buf_puts(b, ": ");
	buf_puts(b, val);
	buf_puts(b, "\r\n");
}

static void put_tail(struct buf *b, const char *ctype, const uint8_t *body, size_t blen, const char *extra)
{
	if (extra)
		buf_puts(b, extra);
	if (blen && ctype)
		put_hdr(b, "Content-Type", ctype);
	buf_printf(b, "Content-Length: %zu\r\n\r\n", blen);
	if (blen)
		buf_add(b, body, blen);
}

int sip_build_request(struct buf *out, const struct sip_req_parts *p)
{
	if (!p->method || !p->ruri || !p->via || !p->from || !p->to || !p->call_id ||
	    has_crlf(p->method) || has_crlf(p->ruri) || has_crlf(p->via) || has_crlf(p->from) ||
	    has_crlf(p->to) || has_crlf(p->call_id) || has_crlf(p->contact) || has_crlf(p->content_type)) {
		out->ovf = true;
		return -1;
	}
	buf_printf(out, "%s %s SIP/2.0\r\n", p->method, p->ruri);
	put_hdr(out, "Via", p->via);
	buf_printf(out, "Max-Forwards: %d\r\n", p->max_forwards ? p->max_forwards : 70);
	put_hdr(out, "From", p->from);
	put_hdr(out, "To", p->to);
	put_hdr(out, "Call-ID", p->call_id);
	buf_printf(out, "CSeq: %u %s\r\n", p->cseq, p->method);
	if (p->route)
		buf_puts(out, p->route);
	if (p->contact)
		put_hdr(out, "Contact", p->contact);
	put_tail(out, p->content_type, p->body, p->body_len, p->extra);
	return buf_ok(out) ? 0 : -1;
}

/* emit the first Via element with received=/rport= filled in */
static void put_via_patched(struct buf *b, const char *line, const struct addr *src)
{
	char first[320], hostbuf[INET6_ADDRSTRLEN];
	const char *cur = line, *rest;
	struct sip_via v;
	const char *semi, *s, *e, *p;
	bool need_recv;

	if (sip_split_next(&cur, first, sizeof(first)) != 1 || sip_via_parse(first, &v) ||
	    !src || addr_host(src, hostbuf, sizeof(hostbuf))) {
		put_hdr(b, "Via", line);
		return;
	}
	need_recv = v.rport >= 0 || strcmp(v.host, hostbuf);
	if (!need_recv && v.rport < 0) {
		put_hdr(b, "Via", line);
		return;
	}
	rest = cur;
	buf_puts(b, "Via: ");
	semi = strchr(first, ';');
	buf_add(b, first, semi ? (size_t)(semi - first) : strlen(first));
	p = v.params;
	while ((p = seg_next(p, ";", &s, &e))) {
		char key[16];
		size_t kl = 0;

		while (s + kl < e && s[kl] != '=' && s[kl] != ' ' && kl < sizeof(key) - 1) {
			key[kl] = s[kl];
			kl++;
		}
		key[kl] = 0;
		if (!strcasecmp(key, "rport") || !strcasecmp(key, "received") || e == s)
			continue;
		buf_putc(b, ';');
		buf_add(b, s, e - s);
	}
	buf_printf(b, ";received=%s", hostbuf);
	if (v.rport >= 0)
		buf_printf(b, ";rport=%u", addr_port(src));
	while (*rest == ' ' || *rest == '\t' || *rest == ',')
		rest++;
	if (*rest) {
		buf_puts(b, ", ");
		buf_puts(b, rest);
	}
	buf_puts(b, "\r\n");
}

int sip_build_response(struct buf *out, const struct sip_msg *req, const struct sip_resp_parts *p)
{
	const char *to = sip_hdr(req, "To", 0), *from = sip_hdr(req, "From", 0);
	const char *cid = sip_hdr(req, "Call-ID", 0), *cs = sip_hdr(req, "CSeq", 0);
	int i, nvia = 0;
	bool add_tag;

	if (!to || !from || !cid || !cs || !sip_hdr(req, "Via", 0) || has_crlf(p->reason) ||
	    has_crlf(p->to_tag) || has_crlf(p->contact) || has_crlf(p->content_type)) {
		out->ovf = true;
		return -1;
	}
	{
		struct sip_nameaddr na;
		char t[8];

		/* the To header already has a tag if the lookup finds one (r != 0: found or too long for t) */
		add_tag = p->to_tag && p->status != 100 && !sip_nameaddr_parse(to, &na) &&
			  !sip_params_get(na.params, "tag", t, sizeof(t));
	}
	buf_printf(out, "SIP/2.0 %d %s\r\n", p->status, p->reason ? p->reason : sip_reason_phrase(p->status));
	for (i = 0; i < req->nh; i++) {
		if (!name_eq(req->hdr[i].name, "Via"))
			continue;
		if (nvia++ == 0)
			put_via_patched(out, req->hdr[i].val, p->src);
		else
			put_hdr(out, "Via", req->hdr[i].val);
	}
	if (p->status < 300)
		for (i = 0; i < req->nh; i++)
			if (name_eq(req->hdr[i].name, "Record-Route"))
				put_hdr(out, "Record-Route", req->hdr[i].val);
	put_hdr(out, "From", from);
	buf_puts(out, "To: ");
	buf_puts(out, to);
	if (add_tag)
		buf_printf(out, ";tag=%s", p->to_tag);
	buf_puts(out, "\r\n");
	put_hdr(out, "Call-ID", cid);
	put_hdr(out, "CSeq", cs);
	if (p->contact)
		put_hdr(out, "Contact", p->contact);
	put_tail(out, p->content_type, p->body, p->body_len, p->extra);
	return buf_ok(out) ? 0 : -1;
}
