/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "sdp.h"

const char *sdp_strerror(int err)
{
	switch (err) {
	case SDP_OK: return "ok";
	case SDP_E_ARG: return "bad argument";
	case SDP_E_SYNTAX: return "syntax error";
	case SDP_E_RANGE: return "number out of range";
	case SDP_E_LIMIT: return "size limit exceeded";
	case SDP_E_ADDR: return "bad connection address";
	case SDP_E_OVERFLOW: return "output overflow";
	}
	return "unknown error";
}

/* ------------------------------------------------------------------ */
/* string pool                                                        */
/* ------------------------------------------------------------------ */

static int intern(struct sdp *s, const char *p, size_t n, sdp_str *out)
{
	if (n == 0) {
		*out = 0;
		return 0;
	}
	if ((size_t)s->pool_len + n + 1 > SDP_POOL_SIZE)
		return SDP_E_LIMIT;
	memcpy(s->pool + s->pool_len, p, n);
	s->pool[s->pool_len + n] = 0;
	*out = s->pool_len;
	s->pool_len = (uint16_t)(s->pool_len + n + 1);
	return 0;
}

static int intern_str(struct sdp *s, const char *p, sdp_str *out)
{
	return intern(s, p, p ? strlen(p) : 0, out);
}

const char *sdp_get(const struct sdp *s, sdp_str ref)
{
	return ref < SDP_POOL_SIZE ? s->pool + ref : "";
}

const char *sdp_media_type(const struct sdp *s, const struct sdp_media *m)
{
	return sdp_get(s, m->type);
}

const char *sdp_media_proto(const struct sdp *s, const struct sdp_media *m)
{
	return sdp_get(s, m->proto);
}

const char *sdp_fmt_enc(const struct sdp *s, const struct sdp_fmt *f)
{
	return sdp_get(s, f->enc);
}

const char *sdp_fmt_fmtp(const struct sdp *s, const struct sdp_fmt *f)
{
	return sdp_get(s, f->fmtp);
}

void sdp_init(struct sdp *s)
{
	memset(s, 0, sizeof(*s));
	s->pool_len = 1;	/* pool[0] == 0 is the empty string */
	strcpy(s->o.user, "-");
	s->bw.as = s->bw.rs = s->bw.rr = -1;
}

/* ------------------------------------------------------------------ */
/* small text helpers                                                 */
/* ------------------------------------------------------------------ */

static char *next_tok(char **sp)
{
	char *p = *sp, *t;

	while (*p == ' ' || *p == '\t')
		p++;
	if (!*p) {
		*sp = p;
		return NULL;
	}
	t = p;
	while (*p && *p != ' ' && *p != '\t')
		p++;
	if (*p)
		*p++ = 0;
	*sp = p;
	return t;
}

static char *trim(char *p)
{
	size_t n;

	while (*p == ' ' || *p == '\t' || *p == '\r')
		p++;
	n = strlen(p);
	while (n && (p[n - 1] == ' ' || p[n - 1] == '\t' || p[n - 1] == '\r'))
		p[--n] = 0;
	return p;
}

/* decimal, digits only, at most max. -1 on error, -2 if above max */
static long long parse_dec(const char *s, long long max)
{
	long long v = 0;

	if (!*s)
		return -1;
	for (; *s; s++) {
		if (*s < '0' || *s > '9')
			return -1;
		v = v * 10 + (*s - '0');
		if (v > max)
			return -2;
	}
	return v;
}

static int parse_u64(const char *s, uint64_t *out)
{
	uint64_t v = 0;

	if (!*s)
		return SDP_E_SYNTAX;
	for (; *s; s++) {
		unsigned d;

		if (*s < '0' || *s > '9')
			return SDP_E_SYNTAX;
		d = (unsigned)(*s - '0');
		if (v > (UINT64_MAX - d) / 10)
			return SDP_E_RANGE;
		v = v * 10 + d;
	}
	*out = v;
	return 0;
}

/* ------------------------------------------------------------------ */
/* parser                                                             */
/* ------------------------------------------------------------------ */

static int parse_addr_lit(const char *nettype, const char *addrtype, char *host, struct addr *a)
{
	char *sl = strchr(host, '/');
	bool v6;

	if (sl)
		*sl = 0;
	if (strcmp(nettype, "IN"))
		return SDP_E_ADDR;
	if (!strcmp(addrtype, "IP4"))
		v6 = false;
	else if (!strcmp(addrtype, "IP6"))
		v6 = true;
	else
		return SDP_E_ADDR;
	if (v6 != (strchr(host, ':') != NULL))
		return SDP_E_ADDR;
	if (host[0] == '[' || addr_set(a, host, 0) < 0)
		return SDP_E_ADDR;
	return 0;
}

static int parse_conn(char *rest, struct sdp_conn *c)
{
	char *nt = next_tok(&rest), *at = next_tok(&rest), *host = next_tok(&rest);
	int r;

	if (!nt || !at || !host)
		return SDP_E_SYNTAX;
	r = parse_addr_lit(nt, at, host, &c->addr);
	if (r < 0)
		return r;
	c->present = true;
	return 0;
}

static int parse_bw(char *rest, struct sdp_bw *bw)
{
	char *colon = strchr(rest, ':');
	long long v;

	if (!colon)
		return SDP_E_SYNTAX;
	*colon++ = 0;
	v = parse_dec(trim(colon), INT32_MAX);
	if (v == -1)
		return SDP_E_SYNTAX;
	if (v < 0)
		return SDP_E_RANGE;
	if (!strcmp(rest, "AS"))
		bw->as = (int32_t)v;
	else if (!strcmp(rest, "RS"))
		bw->rs = (int32_t)v;
	else if (!strcmp(rest, "RR"))
		bw->rr = (int32_t)v;
	/* other bandwidth types (CT, TIAS ...) are ignored */
	return 0;
}

static struct sdp_fmt *find_fmt(struct sdp_media *m, int pt)
{
	int i;

	for (i = 0; i < m->nfmt; i++)
		if (m->fmt[i].pt == pt)
			return &m->fmt[i];
	return NULL;
}

const struct sdp_fmt *sdp_media_find_fmt(const struct sdp_media *m, int pt)
{
	int i;

	for (i = 0; i < m->nfmt; i++)
		if (m->fmt[i].pt == pt)
			return &m->fmt[i];
	return NULL;
}

static int add_attr(struct sdp *s, struct sdp_attr *list, int *n, const char *name, const char *value)
{
	struct sdp_attr *a;
	int r;

	if (*n >= SDP_MAX_ATTR)
		return SDP_E_LIMIT;
	a = &list[*n];
	memset(a, 0, sizeof(*a));
	r = intern_str(s, name, &a->name);
	if (r < 0)
		return r;
	if (value) {
		a->has_value = true;
		r = intern_str(s, value, &a->value);
		if (r < 0)
			return r;
	}
	(*n)++;
	return 0;
}

/* a=rtpmap:<pt> <enc>/<clock>[/<channels>]; false in *used if the pt is not in the m= line */
static int parse_rtpmap(struct sdp *s, struct sdp_media *m, char *val, bool *used)
{
	char *p = val, *pts = next_tok(&p), *map = next_tok(&p), *clk, *ch;
	long long pt, clock, chans = 0;
	struct sdp_fmt *f;
	int r;

	*used = false;
	if (!pts || !map)
		return SDP_E_SYNTAX;
	pt = parse_dec(pts, 255);
	if (pt < 0)
		return pt == -1 ? SDP_E_SYNTAX : SDP_E_RANGE;
	clk = strchr(map, '/');
	if (!clk || clk == map)
		return SDP_E_SYNTAX;
	*clk++ = 0;
	ch = strchr(clk, '/');
	if (ch) {
		*ch++ = 0;
		chans = parse_dec(ch, 16);
		if (chans < 1)
			return chans == -1 ? SDP_E_SYNTAX : SDP_E_RANGE;
	}
	clock = parse_dec(clk, 1000000);
	if (clock < 1)
		return clock == -1 ? SDP_E_SYNTAX : SDP_E_RANGE;
	f = find_fmt(m, (int)pt);
	if (!f)
		return 0;
	r = intern_str(s, map, &f->enc);
	if (r < 0)
		return r;
	f->clock = (uint32_t)clock;
	f->channels = (uint8_t)chans;
	f->has_rtpmap = true;
	*used = true;
	return 0;
}

static int parse_fmtp(struct sdp *s, struct sdp_media *m, char *val, bool *used)
{
	char *p = val, *pts = next_tok(&p), *par;
	long long pt;
	struct sdp_fmt *f;

	*used = false;
	if (!pts)
		return SDP_E_SYNTAX;
	pt = parse_dec(pts, 255);
	if (pt < 0)
		return pt == -1 ? SDP_E_SYNTAX : SDP_E_RANGE;
	par = trim(p);
	if (!*par)
		return SDP_E_SYNTAX;
	f = find_fmt(m, (int)pt);
	if (!f)
		return 0;
	*used = true;
	return intern_str(s, par, &f->fmtp);
}

static int parse_rtcp(struct sdp_media *m, char *val)
{
	char *p = val, *port = next_tok(&p);
	long long v;

	if (!port)
		return SDP_E_SYNTAX;
	v = parse_dec(port, 65535);
	if (v == -1)
		return SDP_E_SYNTAX;
	if (v < 1)
		return SDP_E_RANGE;
	m->rtcp_port = (int)v;
	if (*trim(p)) {
		char *nt = next_tok(&p), *at = next_tok(&p), *host = next_tok(&p);

		if (!nt || !at || !host)
			return SDP_E_SYNTAX;
		if (parse_addr_lit(nt, at, host, &m->rtcp_addr) < 0)
			return SDP_E_ADDR;
		m->has_rtcp_addr = true;
	}
	return 0;
}

static int parse_ptime(char *v, int *out)
{
	long long n = parse_dec(trim(v), 10000);

	if (n == -1)
		return SDP_E_SYNTAX;
	if (n < 1)
		return SDP_E_RANGE;
	*out = (int)n;
	return 0;
}

static int parse_m(struct sdp *s, char *rest)
{
	char *type = next_tok(&rest), *port = next_tok(&rest), *proto = next_tok(&rest), *fm;
	struct sdp_media *m;
	long long pv, np = 0;
	char *sl;
	int r;

	if (!type || !port || !proto)
		return SDP_E_SYNTAX;
	if (s->nmedia >= SDP_MAX_MEDIA)
		return SDP_E_LIMIT;
	sl = strchr(port, '/');
	if (sl) {
		*sl++ = 0;
		np = parse_dec(sl, 65535);
		if (np < 0)
			return np == -1 ? SDP_E_SYNTAX : SDP_E_RANGE;
	}
	pv = parse_dec(port, 65535);
	if (pv < 0)
		return pv == -1 ? SDP_E_SYNTAX : SDP_E_RANGE;
	m = &s->media[s->nmedia];
	memset(m, 0, sizeof(*m));
	m->bw.as = m->bw.rs = m->bw.rr = -1;
	m->port = (uint16_t)pv;
	m->nports = (uint16_t)np;
	if ((r = intern_str(s, type, &m->type)) < 0 || (r = intern_str(s, proto, &m->proto)) < 0)
		return r;
	m->rtp = !strncmp(proto, "RTP/", 4);
	fm = trim(rest);
	if (!*fm)
		return SDP_E_SYNTAX;
	if (!m->rtp) {
		r = intern_str(s, fm, &m->raw_fmts);
		if (r < 0)
			return r;
	} else {
		char *t;

		while ((t = next_tok(&fm)) != NULL) {
			long long pt = parse_dec(t, 127);

			if (pt == -1)
				return SDP_E_SYNTAX;
			if (pt < 0)
				return SDP_E_RANGE;
			if (m->nfmt >= SDP_MAX_FMT)
				return SDP_E_LIMIT;
			memset(&m->fmt[m->nfmt], 0, sizeof(m->fmt[0]));
			m->fmt[m->nfmt++].pt = (int)pt;
		}
	}
	s->nmedia++;
	return 0;
}

static const struct {
	uint8_t pt;
	const char *enc;
	uint32_t clock;
	uint8_t ch;
} static_pt[] = {
	{ 0, "PCMU", 8000, 1 }, { 3, "GSM", 8000, 1 }, { 4, "G723", 8000, 1 }, { 5, "DVI4", 8000, 1 },
	{ 6, "DVI4", 16000, 1 }, { 7, "LPC", 8000, 1 }, { 8, "PCMA", 8000, 1 }, { 9, "G722", 8000, 1 },
	{ 10, "L16", 44100, 2 }, { 11, "L16", 44100, 1 }, { 12, "QCELP", 8000, 1 }, { 13, "CN", 8000, 1 },
	{ 14, "MPA", 90000, 0 }, { 15, "G728", 8000, 1 }, { 16, "DVI4", 11025, 1 }, { 17, "DVI4", 22050, 1 },
	{ 18, "G729", 8000, 1 },
};

static int fill_static(struct sdp *s, struct sdp_media *m)
{
	int i;
	size_t k;

	if (strcmp(sdp_get(s, m->type), "audio"))
		return 0;
	for (i = 0; i < m->nfmt; i++) {
		struct sdp_fmt *f = &m->fmt[i];

		if (f->has_rtpmap || f->pt > 18)
			continue;
		for (k = 0; k < sizeof(static_pt) / sizeof(static_pt[0]); k++) {
			if (static_pt[k].pt == f->pt) {
				int r = intern_str(s, static_pt[k].enc, &f->enc);

				if (r < 0)
					return r;
				f->clock = static_pt[k].clock;
				f->channels = static_pt[k].ch;
			}
		}
	}
	return 0;
}

static int parse_line(struct sdp *s, char *ln, int *saw_v, int *sptime, int *smaxptime)
{
	char type = ln[0], *rest = ln + 2;
	struct sdp_media *m = s->nmedia ? &s->media[s->nmedia - 1] : NULL;
	int r;

	if (!*saw_v && type != 'v')
		return SDP_E_SYNTAX;
	switch (type) {
	case 'v':
		if (*saw_v || strcmp(trim(rest), "0"))
			return SDP_E_SYNTAX;
		*saw_v = 1;
		return 0;
	case 'o': {
		char *user = next_tok(&rest), *sid = next_tok(&rest), *ver = next_tok(&rest);
		char *nt = next_tok(&rest), *at = next_tok(&rest), *host = next_tok(&rest);

		if (!user || !sid || !ver || !nt || !at || !host)
			return SDP_E_SYNTAX;
		if (strlen(user) >= sizeof(s->o.user))
			return SDP_E_LIMIT;
		strcpy(s->o.user, user);
		if ((r = parse_u64(sid, &s->o.sess_id)) < 0 || (r = parse_u64(ver, &s->o.version)) < 0)
			return r;
		s->o_addr_ok = parse_addr_lit(nt, at, host, &s->o_addr) == 0;
		return 0;
	}
	case 's':
		return intern_str(s, trim(rest), &s->name);
	case 'c':
		return parse_conn(rest, m ? &m->conn : &s->conn);
	case 'b':
		return parse_bw(trim(rest), m ? &m->bw : &s->bw);
	case 'm':
		return parse_m(s, rest);
	case 'a': {
		char *name = trim(rest), *val = NULL, *colon = strchr(name, ':');
		bool used = false;

		if (colon) {
			*colon = 0;
			val = trim(colon + 1);
		}
		name = trim(name);
		if (!*name)
			return SDP_E_SYNTAX;
		if (!strcmp(name, "sendrecv") || !strcmp(name, "sendonly") || !strcmp(name, "recvonly") ||
		    !strcmp(name, "inactive")) {
			enum sdp_dir d = name[0] == 's' ? (name[4] == 'r' ? SDP_DIR_SENDRECV : SDP_DIR_SENDONLY) :
				 name[0] == 'r' ? SDP_DIR_RECVONLY : SDP_DIR_INACTIVE;

			if (m)
				m->dir = d;
			else
				s->dir = d;
			return 0;
		}
		if (val && !strcmp(name, "ptime"))
			return parse_ptime(val, m ? &m->ptime : sptime);
		if (val && !strcmp(name, "maxptime"))
			return parse_ptime(val, m ? &m->maxptime : smaxptime);
		if (m && val && !strcmp(name, "rtpmap")) {
			char tmp[SDP_MAX_LINE + 1];

			strcpy(tmp, val);
			r = parse_rtpmap(s, m, tmp, &used);
			if (r < 0)
				return r;
			if (used)
				return 0;
		} else if (m && val && !strcmp(name, "fmtp")) {
			char tmp[SDP_MAX_LINE + 1];

			strcpy(tmp, val);
			r = parse_fmtp(s, m, tmp, &used);
			if (r < 0)
				return r;
			if (used)
				return 0;
		} else if (m && val && !strcmp(name, "rtcp")) {
			return parse_rtcp(m, val);
		}
		return m ? add_attr(s, m->attr, &m->nattr, name, val) : add_attr(s, s->attr, &s->nattr, name, val);
	}
	default:
		break;		/* i= u= e= p= t= r= z= k= and anything else: ignored */
	}
	return 0;
}

int sdp_parse(struct sdp *s, const char *body, size_t len)
{
	const char *p = body, *end = body + len;
	int lineno = 0, saw_v = 0, sptime = 0, smax = 0, r, i;

	if (!s || (!body && len))
		return SDP_E_ARG;
	sdp_init(s);
	while (p < end) {
		const char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t n = nl ? (size_t)(nl - p) : (size_t)(end - p);
		char ln[SDP_MAX_LINE + 1];

		lineno++;
		s->err_line = lineno;
		if (n > SDP_MAX_LINE)
			return SDP_E_LIMIT;
		memcpy(ln, p, n);
		ln[n] = 0;
		p = nl ? nl + 1 : end;
		if (strlen(ln) != n)
			return SDP_E_SYNTAX;	/* embedded NUL */
		{
			char *t = trim(ln);

			if (!*t)
				continue;
			if (t != ln)
				memmove(ln, t, strlen(t) + 1);
		}
		if (!isalpha((unsigned char)ln[0]) || ln[1] != '=')
			return SDP_E_SYNTAX;
		r = parse_line(s, ln, &saw_v, &sptime, &smax);
		if (r < 0)
			return r;
	}
	if (!saw_v) {
		s->err_line = lineno ? lineno : 1;
		return SDP_E_SYNTAX;
	}
	for (i = 0; i < s->nmedia; i++) {
		struct sdp_media *m = &s->media[i];

		r = fill_static(s, m);
		if (r < 0)
			return r;
		if (!m->ptime)
			m->ptime = sptime;
		if (!m->maxptime)
			m->maxptime = smax;
	}
	s->err_line = 0;
	return 0;
}

/* ------------------------------------------------------------------ */
/* accessors                                                          */
/* ------------------------------------------------------------------ */

static const struct sdp_attr *find_in(const struct sdp *s, const struct sdp_attr *list, int n, const char *name)
{
	int i;

	for (i = 0; i < n; i++)
		if (!strcmp(sdp_get(s, list[i].name), name))
			return &list[i];
	return NULL;
}

const struct sdp_attr *sdp_media_find_attr(const struct sdp *s, const struct sdp_media *m, const char *name)
{
	return find_in(s, m->attr, m->nattr, name);
}

const struct sdp_attr *sdp_find_attr(const struct sdp *s, const char *name)
{
	return find_in(s, s->attr, s->nattr, name);
}

enum sdp_dir sdp_media_dir(const struct sdp *s, const struct sdp_media *m)
{
	if (m->dir != SDP_DIR_NONE)
		return m->dir;
	if (s->dir != SDP_DIR_NONE)
		return s->dir;
	return SDP_DIR_SENDRECV;
}

const struct sdp_conn *sdp_media_conn(const struct sdp *s, const struct sdp_media *m)
{
	if (m->conn.present)
		return &m->conn;
	if (s->conn.present)
		return &s->conn;
	return NULL;
}

bool sdp_conn_is_any(const struct sdp_conn *c)
{
	uint8_t raw[16];
	int n, i;

	if (!c || !c->present)
		return false;
	n = addr_raw(&c->addr, raw);
	for (i = 0; i < n; i++)
		if (raw[i])
			return false;
	return n > 0;
}

const char *sdp_dir_name(enum sdp_dir d)
{
	switch (d) {
	case SDP_DIR_SENDONLY: return "sendonly";
	case SDP_DIR_RECVONLY: return "recvonly";
	case SDP_DIR_INACTIVE: return "inactive";
	case SDP_DIR_SENDRECV: return "sendrecv";
	default: return "";
	}
}

bool sdp_dir_sends(enum sdp_dir d)
{
	return d == SDP_DIR_NONE || d == SDP_DIR_SENDRECV || d == SDP_DIR_SENDONLY;
}

bool sdp_dir_recvs(enum sdp_dir d)
{
	return d == SDP_DIR_NONE || d == SDP_DIR_SENDRECV || d == SDP_DIR_RECVONLY;
}

enum sdp_dir sdp_dir_make(bool sends, bool recvs)
{
	if (sends)
		return recvs ? SDP_DIR_SENDRECV : SDP_DIR_SENDONLY;
	return recvs ? SDP_DIR_RECVONLY : SDP_DIR_INACTIVE;
}

enum sdp_dir sdp_dir_flip(enum sdp_dir d)
{
	if (d == SDP_DIR_SENDONLY)
		return SDP_DIR_RECVONLY;
	if (d == SDP_DIR_RECVONLY)
		return SDP_DIR_SENDONLY;
	return d;
}

/* ------------------------------------------------------------------ */
/* fmtp                                                               */
/* ------------------------------------------------------------------ */

/* iterate ';' separated items; returns false at the end */
static bool fmtp_next(const char **pp, const char **k, size_t *kl, const char **v, size_t *vl)
{
	const char *p = *pp, *e, *eq, *ke, *vs;

	while (*p == ';' || *p == ' ' || *p == '\t')
		p++;
	if (!*p)
		return false;
	e = strchr(p, ';');
	if (!e)
		e = p + strlen(p);
	*pp = *e ? e + 1 : e;
	eq = memchr(p, '=', (size_t)(e - p));
	ke = eq ? eq : e;
	while (ke > p && (ke[-1] == ' ' || ke[-1] == '\t'))
		ke--;
	*k = p;
	*kl = (size_t)(ke - p);
	if (eq) {
		vs = eq + 1;
		while (vs < e && (*vs == ' ' || *vs == '\t'))
			vs++;
		while (e > vs && (e[-1] == ' ' || e[-1] == '\t'))
			e--;
		*v = vs;
		*vl = (size_t)(e - vs);
	} else {
		*v = e;
		*vl = 0;
	}
	return true;
}

int sdp_fmtp_get(const char *fmtp, const char *key, char *out, size_t outsz)
{
	const char *p = fmtp, *k, *v;
	size_t kl, vl, want = strlen(key);

	if (!fmtp)
		return -1;
	while (fmtp_next(&p, &k, &kl, &v, &vl)) {
		if (kl == want && !strncasecmp(k, key, kl)) {
			if (vl + 1 > outsz)
				return -2;
			memcpy(out, v, vl);
			out[vl] = 0;
			return 0;
		}
	}
	return -1;
}

int sdp_fmtp_get_int(const char *fmtp, const char *key, long *val)
{
	char t[24];
	int r = sdp_fmtp_get(fmtp, key, t, sizeof(t));
	long long v;

	if (r == -1)
		return -1;
	if (r == -2)
		return -2;
	v = parse_dec(t, 1000000000LL);
	if (v < 0)
		return -2;
	*val = (long)v;
	return 0;
}

bool sdp_fmtp_is_bare(const char *fmtp)
{
	return fmtp && *fmtp && !strchr(fmtp, '=');
}

/* ------------------------------------------------------------------ */
/* builder                                                            */
/* ------------------------------------------------------------------ */

int sdp_set_origin(struct sdp *s, const char *user, uint64_t sess_id, uint64_t version, const struct addr *addr)
{
	size_t n = user ? strlen(user) : 0;

	if (n >= sizeof(s->o.user))
		return SDP_E_LIMIT;
	if (n)
		memcpy(s->o.user, user, n + 1);
	else
		strcpy(s->o.user, "-");
	s->o.sess_id = sess_id;
	s->o.version = version;
	if (addr) {
		s->o_addr = *addr;
		addr_set_port(&s->o_addr, 0);
		s->o_addr_ok = true;
	}
	return 0;
}

int sdp_set_name(struct sdp *s, const char *name)
{
	return intern_str(s, name, &s->name);
}

void sdp_set_conn(struct sdp_conn *c, const struct addr *addr)
{
	c->present = true;
	c->addr = *addr;
	addr_set_port(&c->addr, 0);
}

void sdp_set_conn_any(struct sdp_conn *c, bool v6)
{
	struct addr a;

	addr_set(&a, v6 ? "::" : "0.0.0.0", 0);
	sdp_set_conn(c, &a);
}

struct sdp_media *sdp_add_media(struct sdp *s, const char *type, uint16_t port, const char *proto)
{
	struct sdp_media *m;

	if (s->nmedia >= SDP_MAX_MEDIA)
		return NULL;
	m = &s->media[s->nmedia];
	memset(m, 0, sizeof(*m));
	m->bw.as = m->bw.rs = m->bw.rr = -1;
	m->port = port;
	m->rtp = !strncmp(proto, "RTP/", 4);
	if (intern_str(s, type, &m->type) < 0 || intern_str(s, proto, &m->proto) < 0)
		return NULL;
	s->nmedia++;
	return m;
}

int sdp_add_fmt(struct sdp *s, struct sdp_media *m, int pt, const char *enc, uint32_t clock, int channels,
		const char *fmtp)
{
	struct sdp_fmt *f;
	int r;

	if (pt < 0 || pt > 127 || channels < 0 || channels > 16)
		return SDP_E_RANGE;
	if (m->nfmt >= SDP_MAX_FMT)
		return SDP_E_LIMIT;
	f = &m->fmt[m->nfmt];
	memset(f, 0, sizeof(*f));
	f->pt = pt;
	f->clock = clock;
	f->channels = (uint8_t)channels;
	if (enc && *enc) {
		r = intern_str(s, enc, &f->enc);
		if (r < 0)
			return r;
		f->has_rtpmap = clock != 0;
	}
	if (fmtp && *fmtp) {
		r = intern_str(s, fmtp, &f->fmtp);
		if (r < 0)
			return r;
	}
	m->nfmt++;
	return 0;
}

int sdp_fmt_set_fmtp(struct sdp *s, struct sdp_fmt *f, const char *fmtp)
{
	return intern_str(s, fmtp && *fmtp ? fmtp : NULL, &f->fmtp);
}

int sdp_media_set_raw_fmts(struct sdp *s, struct sdp_media *m, const char *fmts)
{
	return intern_str(s, fmts, &m->raw_fmts);
}

int sdp_media_add_attr(struct sdp *s, struct sdp_media *m, const char *name, const char *value)
{
	return add_attr(s, m->attr, &m->nattr, name, value);
}

int sdp_add_attr(struct sdp *s, const char *name, const char *value)
{
	return add_attr(s, s->attr, &s->nattr, name, value);
}

void sdp_media_set_dir(struct sdp_media *m, enum sdp_dir d)
{
	m->dir = d;
}

static void put_bw(struct buf *b, const struct sdp_bw *bw)
{
	if (bw->as >= 0)
		buf_printf(b, "b=AS:%" PRId32 "\r\n", bw->as);
	if (bw->rs >= 0)
		buf_printf(b, "b=RS:%" PRId32 "\r\n", bw->rs);
	if (bw->rr >= 0)
		buf_printf(b, "b=RR:%" PRId32 "\r\n", bw->rr);
}

static void put_conn(struct buf *b, const struct sdp_conn *c)
{
	char t[64];

	if (!c->present)
		return;
	if (addr_sdp(&c->addr, t, sizeof(t)) < 0) {
		b->ovf = true;
		return;
	}
	buf_printf(b, "c=IN %s\r\n", t);
}

static void put_attrs(struct buf *b, const struct sdp *s, const struct sdp_attr *a, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (a[i].has_value)
			buf_printf(b, "a=%s:%s\r\n", sdp_get(s, a[i].name), sdp_get(s, a[i].value));
		else
			buf_printf(b, "a=%s\r\n", sdp_get(s, a[i].name));
	}
}

static int write_body(const struct sdp *s, struct buf *b, bool with_origin)
{
	int i, j;

	buf_puts(b, "v=0\r\n");
	if (with_origin) {
		char t[64] = "IP4 0.0.0.0";

		if (s->o_addr_ok && addr_sdp(&s->o_addr, t, sizeof(t)) < 0)
			return SDP_E_OVERFLOW;
		buf_printf(b, "o=%s %" PRIu64 " %" PRIu64 " IN %s\r\n", s->o.user[0] ? s->o.user : "-", s->o.sess_id,
			   s->o.version, t);
	}
	buf_printf(b, "s=%s\r\n", s->name ? sdp_get(s, s->name) : "-");
	put_conn(b, &s->conn);
	put_bw(b, &s->bw);
	buf_puts(b, "t=0 0\r\n");
	if (s->dir != SDP_DIR_NONE)
		buf_printf(b, "a=%s\r\n", sdp_dir_name(s->dir));
	put_attrs(b, s, s->attr, s->nattr);
	for (i = 0; i < s->nmedia; i++) {
		const struct sdp_media *m = &s->media[i];

		buf_printf(b, "m=%s %u", sdp_get(s, m->type), (unsigned)m->port);
		if (m->nports)
			buf_printf(b, "/%u", (unsigned)m->nports);
		buf_printf(b, " %s", sdp_get(s, m->proto));
		if (m->rtp) {
			if (m->nfmt == 0)
				return SDP_E_ARG;
			for (j = 0; j < m->nfmt; j++)
				buf_printf(b, " %d", m->fmt[j].pt);
		} else {
			buf_printf(b, " %s", m->raw_fmts ? sdp_get(s, m->raw_fmts) : "*");
		}
		buf_puts(b, "\r\n");
		put_conn(b, &m->conn);
		put_bw(b, &m->bw);
		for (j = 0; j < m->nfmt; j++) {
			const struct sdp_fmt *f = &m->fmt[j];

			if (f->enc && f->clock) {
				buf_printf(b, "a=rtpmap:%d %s/%u", f->pt, sdp_get(s, f->enc), (unsigned)f->clock);
				if (f->channels)
					buf_printf(b, "/%u", (unsigned)f->channels);
				buf_puts(b, "\r\n");
			}
			if (f->fmtp)
				buf_printf(b, "a=fmtp:%d %s\r\n", f->pt, sdp_get(s, f->fmtp));
		}
		if (m->ptime)
			buf_printf(b, "a=ptime:%d\r\n", m->ptime);
		if (m->maxptime)
			buf_printf(b, "a=maxptime:%d\r\n", m->maxptime);
		if (m->rtcp_port) {
			buf_printf(b, "a=rtcp:%d", m->rtcp_port);
			if (m->has_rtcp_addr) {
				char t[64];

				if (addr_sdp(&m->rtcp_addr, t, sizeof(t)) < 0)
					return SDP_E_OVERFLOW;
				buf_printf(b, " IN %s", t);
			}
			buf_puts(b, "\r\n");
		}
		if (m->dir != SDP_DIR_NONE)
			buf_printf(b, "a=%s\r\n", sdp_dir_name(m->dir));
		put_attrs(b, s, m->attr, m->nattr);
	}
	return buf_ok(b) ? 0 : SDP_E_OVERFLOW;
}

int sdp_write(const struct sdp *s, struct buf *out)
{
	return write_body(s, out, true);
}

int sdp_origin_succeed(struct sdp *next, const struct sdp *prev)
{
	struct buf a, b;
	bool same;
	int r;

	buf_init(&a, 32768);
	buf_init(&b, 32768);
	r = write_body(next, &a, false);
	if (r == 0)
		r = write_body(prev, &b, false);
	same = r == 0 && a.len == b.len && !memcmp(a.p, b.p, a.len);
	buf_free(&a);
	buf_free(&b);
	if (r < 0)
		return r;
	memcpy(next->o.user, prev->o.user, sizeof(next->o.user));
	next->o.sess_id = prev->o.sess_id;
	next->o.version = prev->o.version + (same ? 0 : 1);
	return 0;
}
