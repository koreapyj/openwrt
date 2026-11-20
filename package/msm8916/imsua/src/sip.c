/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdarg.h>
#include "sip.h"
#include "util.h"

void sb_init(struct sbuf *b, char *p, size_t cap) { b->p = p; b->n = 0; b->cap = cap; b->ovf = 0; if (cap) p[0] = 0; }

void sb_add(struct sbuf *b, const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = vsnprintf(b->p + b->n, b->cap - b->n, fmt, ap);
	va_end(ap);
	if (r < 0 || (size_t)r >= b->cap - b->n) { b->ovf = 1; b->n = b->cap - 1; }
	else b->n += r;
}

/* ---- parsing ---- */
static char *trim(char *s)
{
	char *e;

	while (*s == ' ' || *s == '\t') s++;
	e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
	return s;
}

int sip_parse(const char *data, size_t len, struct sip_msg *m)
{
	char *p, *line, *end, *hdr_end;
	size_t i;

	memset(m, 0, sizeof(*m));
	m->buf = malloc(len + 1);
	if (!m->buf) return -1;
	memcpy(m->buf, data, len);
	m->buf[len] = 0;

	/* find end of header block */
	hdr_end = NULL;
	for (i = 0; i + 1 < len; i++) {
		if (m->buf[i] == '\n' && (m->buf[i+1] == '\n' || (m->buf[i+1] == '\r' && i + 2 < len && m->buf[i+2] == '\n'))) {
			hdr_end = m->buf + i;
			m->body = m->buf + i + (m->buf[i+1] == '\n' ? 2 : 3);
			break;
		}
	}
	if (!hdr_end) { hdr_end = m->buf + len; m->body = m->buf + len; }
	m->body_len = m->buf + len - m->body;
	*hdr_end = 0;

	p = m->buf;
	end = hdr_end;
	/* start line */
	line = p;
	p = strchr(line, '\n'); if (!p) p = end; else *p++ = 0;
	if ((i = strlen(line)) && line[i-1] == '\r') line[i-1] = 0;
	if (!strncmp(line, "SIP/2.0 ", 8)) {
		m->is_resp = 1;
		m->status = atoi(line + 8);
		if (strlen(line) > 12) strlcpy_(m->reason, line + 12, sizeof(m->reason));
	} else {
		char *sp1 = strchr(line, ' '), *sp2;
		if (!sp1) goto bad;
		*sp1++ = 0;
		sp2 = strrchr(sp1, ' ');
		if (!sp2) goto bad;
		*sp2 = 0;
		strlcpy_(m->method, line, sizeof(m->method));
		strlcpy_(m->ruri, sp1, sizeof(m->ruri));
	}
	/* headers, with folding */
	while (p < end && *p) {
		char *colon;
		line = p;
		p = strchr(line, '\n'); if (!p) p = end; else *p++ = 0;
		if ((i = strlen(line)) && line[i-1] == '\r') line[i-1] = 0;
		if ((*line == ' ' || *line == '\t') && m->nh) {
			/* continuation: append in place is not possible; ignore (rare) */
			continue;
		}
		colon = strchr(line, ':');
		if (!colon || m->nh >= SIP_MAXH) continue;
		*colon = 0;
		m->name[m->nh] = trim(line);
		m->val[m->nh] = trim(colon + 1);
		m->nh++;
	}
	return 0;
bad:
	sip_free(m);
	return -1;
}

void sip_free(struct sip_msg *m)
{
	free(m->buf);
	memset(m, 0, sizeof(*m));
}

const char *sip_hdr(const struct sip_msg *m, const char *name, int idx)
{
	int i;

	for (i = 0; i < m->nh; i++)
		if (!strcasecmp(m->name[i], name) && idx-- == 0)
			return m->val[i];
	return NULL;
}

int sip_cseq(const struct sip_msg *m, uint32_t *num, char *method, size_t msz)
{
	const char *v = sip_hdr(m, "CSeq", 0);
	char *e;

	if (!v) return -1;
	*num = strtoul(v, &e, 10);
	while (*e == ' ') e++;
	if (method) strlcpy_(method, e, msz);
	return 0;
}

int sip_param(const char *v, const char *name, char *out, size_t n)
{
	size_t nl = strlen(name);
	const char *p = v;

	while ((p = strcasestr(p, name))) {
		const char *q = p + nl;
		int prev_ok = (p == v) || p[-1] == ';' || p[-1] == ',' || p[-1] == ' ';
		if (prev_ok && *q == '=') {
			size_t l = 0;
			q++;
			if (*q == '"') {
				q++;
				while (*q && *q != '"' && l + 1 < n) out[l++] = *q++;
			} else {
				while (*q && *q != ';' && *q != ',' && *q != ' ' && *q != '>' && l + 1 < n) out[l++] = *q++;
			}
			out[l] = 0;
			return 1;
		}
		p = q;
	}
	return 0;
}

void sip_tag(const char *v, char *out, size_t n)
{
	const char *gt = strrchr(v, '>');	/* tag param lives after the URI */

	if (!sip_param(gt ? gt : v, "tag", out, n)) out[0] = 0;
}

int sip_uri_of(const char *v, char *out, size_t n)
{
	const char *a = strchr(v, '<'), *b;

	if (a) {
		b = strchr(a, '>');
		if (!b) return -1;
		a++;
	} else {
		a = v; while (*a == ' ') a++;
		b = a; while (*b && *b != ';' && *b != ' ' && *b != ',') b++;
	}
	if ((size_t)(b - a) >= n) return -1;
	memcpy(out, a, b - a);
	out[b - a] = 0;
	return 0;
}

int sip_split_list(const char *v, char out[][256], int max)
{
	int n = 0, depth = 0, q = 0;
	size_t l = 0;
	const char *p;

	for (p = v; ; p++) {
		if ((*p == ',' && !depth && !q) || !*p) {
			out[n][l] = 0;
			if (l) n++;
			l = 0;
			if (!*p || n >= max) break;
			continue;
		}
		if (*p == '<') depth++;
		if (*p == '>' && depth) depth--;
		if (*p == '"') q = !q;
		if (l == 0 && *p == ' ') continue;
		if (l < 255) out[n][l++] = *p;
	}
	return n;
}

/* ---- security headers ---- */
int sec_parse(const char *v, struct sec_ent *out, int max)
{
	char ents[8][256];
	int n = sip_split_list(v, ents, 8), i, k = 0;

	for (i = 0; i < n && k < max; i++) {
		struct sec_ent *e = &out[k];
		char tmp[64], *s = ents[i], *semi;

		memset(e, 0, sizeof(*e));
		semi = strchr(s, ';');
		if (semi) { size_t l = semi - s; if (l >= sizeof(e->prot)) l = sizeof(e->prot) - 1; memcpy(e->prot, s, l); e->prot[l] = 0; }
		else strlcpy_(e->prot, s, sizeof(e->prot));
		{ char *t = e->prot; while (*t == ' ') memmove(t, t + 1, strlen(t)); for (t = e->prot + strlen(e->prot); t > e->prot && t[-1] == ' '; ) *--t = 0; }
		sip_param(s, "alg", e->alg, sizeof(e->alg));
		sip_param(s, "ealg", e->ealg, sizeof(e->ealg));
		sip_param(s, "mod", e->mod, sizeof(e->mod));
		if (sip_param(s, "q", tmp, sizeof(tmp))) { e->has_q = 1; e->q = atof(tmp); }
		if (sip_param(s, "spi-c", tmp, sizeof(tmp))) e->spi_c = strtoul(tmp, NULL, 10);
		if (sip_param(s, "spi-s", tmp, sizeof(tmp))) e->spi_s = strtoul(tmp, NULL, 10);
		if (sip_param(s, "port-c", tmp, sizeof(tmp))) e->port_c = atoi(tmp);
		if (sip_param(s, "port-s", tmp, sizeof(tmp))) e->port_s = atoi(tmp);
		e->sha1 = !strcasecmp(e->alg, "hmac-sha-1-96");
		e->ok = !strcasecmp(e->prot, "ipsec-3gpp") &&
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
		if (!e[i].ok) continue;
		if (best < 0 || (e[i].has_q ? e[i].q : 0.0) > (e[best].has_q ? e[best].q : 0.0))
			best = i;
	}
	return best;
}

/* ---- digest ---- */
void digest_response(const char *user, const char *realm, const uint8_t *res, size_t reslen,
		     const char *nonce, const char *method, const char *uri, char out[33])
{
	uint8_t a1in[256], h1[16];
	char h1hex[33], h2hex[33], tmp[512];
	size_t l = 0;

	l = snprintf((char *)a1in, sizeof(a1in) - reslen, "%s:%s:", user, realm);
	memcpy(a1in + l, res, reslen);
	md5_buf(a1in, l + reslen, h1);
	bin2hex(h1, 16, h1hex);
	snprintf(tmp, sizeof(tmp), "%s:%s", method, uri);
	md5_hex(tmp, strlen(tmp), h2hex);
	snprintf(tmp, sizeof(tmp), "%s:%s:%s", h1hex, nonce, h2hex);
	md5_hex(tmp, strlen(tmp), out);
}

/* ---- SDP ---- */
int sdp_parse(const char *body, size_t len, struct sdp_media *o)
{
	char *b = malloc(len + 1), *line, *sv = NULL;
	int mpts[16], nm = 0, i, in_audio = 0;
	struct { int pt; char enc[24]; int wb; int oa; } pt[16];
	int npt = 0;

	if (!b) return -1;
	memcpy(b, body, len); b[len] = 0;
	memset(o, 0, sizeof(*o));
	o->pt = -1; o->dtmf_pt = -1;
	for (line = strtok_r(b, "\n", &sv); line; line = strtok_r(NULL, "\n", &sv)) {
		size_t l = strlen(line);
		if (l && line[l-1] == '\r') line[--l] = 0;
		if (!strncmp(line, "c=IN IP", 7) && (in_audio || !o->ip[0])) {
			const char *a = strchr(line + 7, ' ');
			if (a) { char *s; strlcpy_(o->ip, a + 1, sizeof(o->ip)); s = strchr(o->ip, '/'); if (s) *s = 0; }
		} else if (!strncmp(line, "m=audio ", 8)) {
			char *e, *tok, *sv2 = NULL;
			in_audio = 1;
			o->port = strtol(line + 8, &e, 10);
			tok = strtok_r(e, " ", &sv2);	/* proto */
			while ((tok = strtok_r(NULL, " ", &sv2)) && nm < 16) mpts[nm++] = atoi(tok);
		} else if (!strncmp(line, "m=", 2)) {
			in_audio = 0;
		} else if (in_audio && !strncmp(line, "a=rtpmap:", 9) && npt < 16) {
			char enc[24] = "";
			int p = atoi(line + 9);
			const char *s = strchr(line, ' ');
			if (s) {
				size_t k = 0; s++;
				while (*s && *s != '/' && k < sizeof(enc) - 1) enc[k++] = *s++;
				enc[k] = 0;
				pt[npt].pt = p; strlcpy_(pt[npt].enc, enc, sizeof(pt[npt].enc));
				pt[npt].wb = !strcasecmp(enc, "AMR-WB"); pt[npt].oa = 0;
				npt++;
			}
		} else if (in_audio && !strncmp(line, "a=fmtp:", 7)) {
			int p = atoi(line + 7);
			for (i = 0; i < npt; i++)
				if (pt[i].pt == p && strstr(line, "octet-align=1")) pt[i].oa = 1;
		}
	}
	for (i = 0; i < npt; i++) {
		if (!strcasecmp(pt[i].enc, "telephone-event") && o->dtmf_pt < 0) o->dtmf_pt = pt[i].pt;
	}
	/* first payload in the m= line order that is AMR / AMR-WB */
	for (i = 0; i < nm && o->pt < 0; i++) {
		int j;
		for (j = 0; j < npt; j++)
			if (pt[j].pt == mpts[i] && (!strcasecmp(pt[j].enc, "AMR") || pt[j].wb)) {
				o->pt = pt[j].pt; o->wb = pt[j].wb; o->octet_align = pt[j].oa;
				strlcpy_(o->enc, pt[j].enc, sizeof(o->enc));
				break;
			}
	}
	free(b);
	return o->ip[0] && o->port ? 0 : -1;
}
