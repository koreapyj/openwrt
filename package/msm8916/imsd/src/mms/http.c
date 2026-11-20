/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Asynchronous HTTP/1.1 client, see http.h. */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "http.h"
#include "../util/buf.h"
#include "../util/evloop.h"
#include "../util/log.h"

#define HEAD_MAX	8192
#define RX_CHUNK	4096
#define DEF_MAX_BODY	(1024 * 1024)
#define DEF_TIMEOUT	60000u
#define DEF_IDLE	20000u

#define TGT_HOST(r) ((r)->proxy_host[0] ? (r)->proxy_host : (r)->url.host)
#define TGT_PORT(r) ((r)->proxy_host[0] ? (r)->proxy_port : (r)->url.port)

enum state { S_DNS, S_GATE, S_CONNECT, S_SEND, S_HEAD, S_BODY_CL, S_BODY_CHUNK, S_BODY_CLOSE };
enum cstate { C_SIZE, C_EXT, C_DATA, C_DATA_CR, C_DATA_LF, C_TRAILER_LINE, C_TRAILER_END };

struct http {
	const struct net_ops *ops;
	struct dns *dns;
	struct http_req *reqs;
};

struct http_req {
	struct http_req *next;
	struct http *h;
	struct dns_bind b;
	char method[8];
	char *headers;
	uint8_t *body_in;
	size_t body_in_len;
	size_t max_body;
	unsigned idle_ms;
	uint64_t deadline;
	int redirects;
	struct http_url url;
	char proxy_host[256];		/* "" = direct */
	uint16_t proxy_port;
	bool gate_wait;
	char url_text[HTTP_MAX_URL];
	enum state st;
	int fd;
	struct ev_fd *w;
	struct ev_timer *t;
	struct dns_query *dq;
	struct addr addr[DNS_MAX_ADDR];
	int naddr, aidx;
	uint8_t *out;
	size_t out_len, out_sent;
	uint8_t head[HEAD_MAX];
	size_t head_len;
	int status;
	bool chunked, have_clen;
	uint64_t clen;
	char ctype[128];
	char location[HTTP_MAX_URL];
	uint8_t *body;
	size_t blen, bcap;
	uint64_t got;		/* body bytes counted against Content-Length */
	enum cstate cs;
	uint64_t csize;
	int csize_digits;
	int sub_err;
	http_cb cb;
	void *arg;
	bool deliver_now;	/* the timer reports `pending_err` */
	bool start_pending;	/* the timer starts the request (never synchronously from http_request) */
	int pending_err;
};

const char *http_strerror(int e)
{
	switch (e) {
	case HTTP_OK: return "ok";
	case HTTP_E_URL: return "malformed URL";
	case HTTP_E_UNSUPPORTED: return "unsupported scheme (https)";
	case HTTP_E_DNS: return "name resolution failed";
	case HTTP_E_CONNECT: return "connect failed";
	case HTTP_E_TIMEOUT: return "timeout";
	case HTTP_E_IO: return "connection lost";
	case HTTP_E_PROTO: return "protocol error";
	case HTTP_E_TOOBIG: return "response too large";
	case HTTP_E_REDIRECT: return "redirect not followed";
	case HTTP_E_NOMEM: return "out of memory";
	default: return "bad argument";
	}
}

/* ------------------------------------------------------------------ */
/* URL                                                                 */

int http_parse_url(const char *url, struct http_url *u)
{
	const char *p, *auth, *end, *q;
	size_t l;

	memset(u, 0, sizeof(*u));
	if (!strncasecmp(url, "http://", 7)) {
		p = url + 7;
		u->port = 80;
	} else if (!strncasecmp(url, "https://", 8)) {
		u->https = true;
		p = url + 8;
		u->port = 443;
	} else {
		return strstr(url, "://") ? HTTP_E_UNSUPPORTED : HTTP_E_URL;
	}
	auth = p;
	end = auth + strcspn(auth, "/?#");
	if (memchr(auth, '@', (size_t)(end - auth)))
		return HTTP_E_URL;
	if (*auth == '[') {
		q = memchr(auth, ']', (size_t)(end - auth));
		if (!q)
			return HTTP_E_URL;
		l = (size_t)(q - auth - 1);
		if (!l || l >= sizeof(u->host))
			return HTTP_E_URL;
		memcpy(u->host, auth + 1, l);
		u->host[l] = 0;
		q++;
		if (q < end && *q != ':')
			return HTTP_E_URL;
	} else {
		q = memchr(auth, ':', (size_t)(end - auth));
		l = q ? (size_t)(q - auth) : (size_t)(end - auth);
		if (!l || l >= sizeof(u->host))
			return HTTP_E_URL;
		memcpy(u->host, auth, l);
		u->host[l] = 0;
	}
	if (q && q < end && *q == ':') {
		unsigned long port = 0;

		q++;
		if (q == end)
			return HTTP_E_URL;
		for (; q < end; q++) {
			if (!isdigit((unsigned char)*q) || (port = port * 10 + (unsigned long)(*q - '0')) > 65535)
				return HTTP_E_URL;
		}
		if (!port)
			return HTTP_E_URL;
		u->port = (uint16_t)port;
	}
	for (l = 0; u->host[l]; l++)
		if ((unsigned char)u->host[l] <= ' ')
			return HTTP_E_URL;
	if (*end == '/' || *end == '?') {
		size_t pl = strcspn(end, "#");

		if (*end == '?') {
			if (pl + 2 > sizeof(u->path))
				return HTTP_E_URL;
			u->path[0] = '/';
			memcpy(u->path + 1, end, pl);
			u->path[pl + 1] = 0;
		} else {
			if (pl + 1 > sizeof(u->path))
				return HTTP_E_URL;
			memcpy(u->path, end, pl);
			u->path[pl] = 0;
		}
	} else {
		snprintf(u->path, sizeof(u->path), "/");
	}
	for (l = 0; u->path[l]; l++)
		if ((unsigned char)u->path[l] <= ' ' || u->path[l] == 0x7f)
			return HTTP_E_URL;
	return u->https ? HTTP_E_UNSUPPORTED : 0;
}

/* ------------------------------------------------------------------ */
/* request life cycle                                                  */

struct http *http_new(const struct net_ops *ops, struct dns *dns)
{
	struct http *h = calloc(1, sizeof(*h));

	if (h) {
		h->ops = ops;
		h->dns = dns;
	}
	return h;
}

static void conn_close(struct http_req *r)
{
	ev_fd_del(r->w);
	r->w = NULL;
	if (r->fd >= 0)
		r->h->ops->close(r->h->ops->ctx, r->fd);
	r->fd = -1;
}

static void req_unlink(struct http_req *r)
{
	struct http_req **pp;

	for (pp = &r->h->reqs; *pp; pp = &(*pp)->next)
		if (*pp == r) {
			*pp = r->next;
			break;
		}
}

static void gate_drop(struct http_req *r)
{
	if (r->gate_wait && r->b.gate_cancel)
		r->b.gate_cancel(r->b.gate_ctx, r);
	r->gate_wait = false;
}

static void req_release(struct http_req *r)
{
	gate_drop(r);
	req_unlink(r);
	conn_close(r);
	ev_timer_free(r->t);
	dns_cancel(r->dq);
	free(r->headers);
	free(r->out);
	free(r->body);
	free(r->body_in);
	free(r);
}

void http_cancel(struct http_req *r)
{
	if (r)
		req_release(r);
}

void http_free(struct http *h)
{
	if (!h)
		return;
	while (h->reqs)
		req_release(h->reqs);
	free(h);
}

static void req_done(struct http_req *r, int err)
{
	struct http_resp resp;
	http_cb cb = r->cb;
	void *arg = r->arg;

	memset(&resp, 0, sizeof(resp));
	resp.status = r->status;
	resp.content_type = r->ctype;
	resp.body = err ? NULL : r->body;
	resp.len = err ? 0 : r->blen;
	resp.sub_err = r->sub_err;
	resp.final_url = r->url_text;
	if (!resp.body && !err)
		resp.body = (const uint8_t *)"";
	/* the response lives in r: call back first, free after */
	gate_drop(r);
	req_unlink(r);
	conn_close(r);
	ev_timer_cancel(r->t);
	cb(arg, err, &resp);
	ev_timer_free(r->t);
	dns_cancel(r->dq);
	free(r->headers);
	free(r->out);
	free(r->body);
	free(r->body_in);
	free(r);
}

static void arm(struct http_req *r)
{
	uint64_t now = ev_now_ms(), left = r->deadline > now ? r->deadline - now : 0;

	ev_timer_set(r->t, left < r->idle_ms ? left : r->idle_ms);
}

static void begin(struct http_req *r);

static void on_timer(void *arg)
{
	struct http_req *r = arg;

	if (r->start_pending) {
		r->start_pending = false;
		begin(r);
		return;
	}
	if (r->deliver_now) {
		req_done(r, r->pending_err);
		return;
	}
	LOGI("mms: http: timeout talking to %s:%u (%s)", TGT_HOST(r), TGT_PORT(r),
	     ev_now_ms() >= r->deadline ? "overall" : "idle");
	req_done(r, HTTP_E_TIMEOUT);
}

static void fail_later(struct http_req *r, int err)
{
	r->deliver_now = true;
	r->pending_err = err;
	ev_timer_set(r->t, 0);
}

static void reset_parse(struct http_req *r)
{
	r->head_len = 0;
	r->status = 0;
	r->chunked = r->have_clen = false;
	r->clen = r->got = 0;
	r->ctype[0] = 0;
	r->location[0] = 0;
	r->blen = 0;
	r->cs = C_SIZE;
	r->csize = 0;
	r->csize_digits = 0;
	free(r->out);
	r->out = NULL;
	r->out_len = r->out_sent = 0;
}

static void on_io(void *arg, int fd);
static void do_connect(struct http_req *r);
static void begin(struct http_req *r);

static void host_port(const struct http_req *r, char *out, size_t n)
{
	bool v6 = strchr(r->url.host, ':') != NULL;

	if (r->url.port == 80)
		snprintf(out, n, v6 ? "[%s]" : "%s", r->url.host);
	else
		snprintf(out, n, v6 ? "[%s]:%u" : "%s:%u", r->url.host, r->url.port);
}

static int build_request(struct http_req *r)
{
	struct buf b;
	char hp[300];
	uint8_t *p;
	size_t n;

	buf_init(&b, HTTP_MAX_URL + 4096 + r->body_in_len);
	host_port(r, hp, sizeof(hp));
	if (r->proxy_host[0])		/* absolute-URI form to a proxy (RFC 7230 5.3.2) */
		buf_printf(&b, "%s http://%s%s HTTP/1.1\r\nHost: %s\r\n", r->method, hp, r->url.path, hp);
	else
		buf_printf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", r->method, r->url.path, hp);
	if (r->headers)
		buf_puts(&b, r->headers);
	if (r->body_in_len || !strcmp(r->method, "POST"))
		buf_printf(&b, "Content-Length: %zu\r\n", r->body_in_len);
	buf_puts(&b, "Connection: close\r\n\r\n");
	if (r->body_in_len)
		buf_add(&b, r->body_in, r->body_in_len);
	if (!buf_ok(&b)) {
		buf_free(&b);
		return -1;
	}
	p = buf_steal(&b, &n);
	if (!p)
		return -1;
	r->out = p;
	r->out_len = n;
	r->out_sent = 0;
	free(r->body_in);		/* the request is built; a redirect only follows a GET */
	r->body_in = NULL;
	r->body_in_len = 0;
	return 0;
}

/* the connection failed / the address is unusable: the next address, else give up */
static void next_addr(struct http_req *r, int err)
{
	conn_close(r);
	if (r->aidx + 1 < r->naddr) {
		r->aidx++;
		do_connect(r);
		return;
	}
	r->sub_err = err;
	LOGI("mms: http: cannot reach %s:%u (%s)", TGT_HOST(r), TGT_PORT(r), strerror(-err));
	req_done(r, HTTP_E_CONNECT);
}

static void connect_now(struct http_req *r)
{
	struct addr dst = r->addr[r->aidx];
	struct http *h = r->h;

	addr_set_port(&dst, r->proxy_host[0] ? r->proxy_port : r->url.port);
	r->st = S_CONNECT;
	r->fd = h->ops->tcp_connect(h->ops->ctx, &r->b.local, r->b.netdev, &dst);
	if (r->fd < 0) {
		int e = r->fd;

		r->fd = -1;
		next_addr(r, e);
		return;
	}
	r->w = ev_fd_add_ev(r->fd, EV_WRITE, on_io, r);
	if (!r->w) {
		req_done(r, HTTP_E_NOMEM);
		return;
	}
	arm(r);
}

static void gate_done(void *arg, int err)
{
	struct http_req *r = arg;

	r->gate_wait = false;
	if (err) {
		next_addr(r, err);
		return;
	}
	connect_now(r);
}

static void do_connect(struct http_req *r)
{
	reset_parse(r);
	if (r->b.gate) {
		struct addr dst = r->addr[r->aidx];
		int rc;

		addr_set_port(&dst, r->proxy_host[0] ? r->proxy_port : r->url.port);
		r->st = S_GATE;
		rc = r->b.gate(r->b.gate_ctx, &dst, gate_done, r);
		if (rc > 0) {
			r->gate_wait = true;
			arm(r);
			return;
		}
		if (rc < 0) {
			next_addr(r, rc);
			return;
		}
	}
	connect_now(r);
}

static void dns_done(void *arg, int err, const struct addr *a, int n)
{
	struct http_req *r = arg;

	r->dq = NULL;
	if (err || n < 1) {
		r->sub_err = err;
		LOGI("mms: http: cannot resolve %s: %s", TGT_HOST(r), strerror(err < 0 ? -err : EIO));
		req_done(r, HTTP_E_DNS);
		return;
	}
	memcpy(r->addr, a, sizeof(*a) * (size_t)n);
	r->naddr = n;
	r->aidx = 0;
	do_connect(r);
}

/* start (or restart after a redirect) with r->url */
static void begin(struct http_req *r)
{
	struct addr a;
	const char *name = r->proxy_host[0] ? r->proxy_host : r->url.host;

	reset_parse(r);
	r->naddr = r->aidx = 0;
	if (!addr_set(&a, name, 0)) {
		r->addr[0] = a;
		r->naddr = 1;
		do_connect(r);
		return;
	}
	r->st = S_DNS;
	r->dq = dns_resolve(r->h->dns, &r->b, name, addr_family(&r->b.local), dns_done, r);
	if (!r->dq) {
		req_done(r, HTTP_E_NOMEM);
		return;
	}
	arm(r);
}

struct http_req *http_request(struct http *h, const struct dns_bind *bind, const struct http_opts *o, http_cb cb, void *arg)
{
	struct http_req *r;
	int rc;

	if (!o || !o->url || !o->method || !cb || (strcmp(o->method, "GET") && strcmp(o->method, "POST")) ||
	    o->body_len > HTTP_MAX_REQ_BODY || (o->body_len && !o->body)) {
		errno = EINVAL;
		return NULL;
	}
	r = calloc(1, sizeof(*r));
	if (!r)
		return NULL;
	r->h = h;
	r->b = *bind;
	r->fd = -1;
	r->cb = cb;
	r->arg = arg;
	snprintf(r->method, sizeof(r->method), "%s", o->method);
	if (o->headers && o->headers[0]) {
		r->headers = strdup(o->headers);
		if (!r->headers) {
			free(r);
			return NULL;
		}
	}
	if (o->body_len) {
		r->body_in = malloc(o->body_len);
		if (!r->body_in) {
			free(r->headers);
			free(r);
			return NULL;
		}
		memcpy(r->body_in, o->body, o->body_len);
	}
	r->body_in_len = o->body_len;
	r->max_body = o->max_body ? o->max_body : DEF_MAX_BODY;
	r->idle_ms = o->idle_ms ? o->idle_ms : DEF_IDLE;
	r->deadline = ev_now_ms() + (o->timeout_ms ? o->timeout_ms : DEF_TIMEOUT);
	snprintf(r->url_text, sizeof(r->url_text), "%s", o->url);
	if (o->proxy_host && o->proxy_host[0]) {
		if (strlen(o->proxy_host) >= sizeof(r->proxy_host)) {
			free(r->headers);
			free(r->body_in);
			free(r);
			errno = EINVAL;
			return NULL;
		}
		snprintf(r->proxy_host, sizeof(r->proxy_host), "%s", o->proxy_host);
		r->proxy_port = o->proxy_port ? (uint16_t)o->proxy_port : 80;
	}
	r->t = ev_timer_new(on_timer, r);
	if (!r->t) {
		free(r->headers);
		free(r->body_in);
		free(r);
		return NULL;
	}
	r->next = h->reqs;
	h->reqs = r;
	rc = strlen(o->url) < sizeof(r->url_text) ? http_parse_url(o->url, &r->url) : HTTP_E_URL;
	if (rc) {
		if (rc == HTTP_E_UNSUPPORTED)
			LOGI("mms: http: %s is not supported (only plain http)", r->url.https ? "https" : "this URL scheme");
		fail_later(r, rc);
		return r;
	}
	r->start_pending = true;
	ev_timer_set(r->t, 0);
	return r;
}

/* ------------------------------------------------------------------ */
/* response parsing                                                    */

static bool is_redirect(int s)
{
	return s == 301 || s == 302 || s == 303 || s == 307 || s == 308;
}

static int follow_redirect(struct http_req *r)
{
	char nu[HTTP_MAX_URL];
	char hp[300];
	struct http_url u;
	int rc;

	if (r->redirects >= HTTP_MAX_REDIRECTS)
		return HTTP_E_REDIRECT;
	if (!strncasecmp(r->location, "http://", 7) || !strncasecmp(r->location, "https://", 8)) {
		snprintf(nu, sizeof(nu), "%s", r->location);
	} else if (r->location[0] == '/' && r->location[1] != '/') {
		bool v6 = strchr(r->url.host, ':') != NULL;
		size_t a, b;

		snprintf(hp, sizeof(hp), v6 ? "[%s]:%u" : "%s:%u", r->url.host, r->url.port);
		a = strlen(hp);
		b = strlen(r->location);
		if (7 + a + b + 1 > sizeof(nu))
			return HTTP_E_REDIRECT;
		memcpy(nu, "http://", 7);
		memcpy(nu + 7, hp, a);
		memcpy(nu + 7 + a, r->location, b + 1);
	} else {
		return HTTP_E_REDIRECT;
	}
	rc = http_parse_url(nu, &u);
	if (rc == HTTP_E_UNSUPPORTED)
		LOGI("mms: http: redirect to https is not supported");
	if (rc)
		return rc == HTTP_E_UNSUPPORTED ? rc : HTTP_E_REDIRECT;
	r->redirects++;
	r->url = u;
	snprintf(r->url_text, sizeof(r->url_text), "%s", nu);
	return 0;
}

static int body_append(struct http_req *r, const uint8_t *d, size_t n)
{
	if (n > r->max_body - r->blen)
		return HTTP_E_TOOBIG;
	if (r->blen + n + 1 > r->bcap) {
		size_t nc = r->bcap ? r->bcap : RX_CHUNK;
		uint8_t *nb;

		while (nc < r->blen + n + 1)
			nc *= 2;
		if (nc > r->max_body + 1)
			nc = r->max_body + 1;
		nb = realloc(r->body, nc);
		if (!nb)
			return HTTP_E_NOMEM;
		r->body = nb;
		r->bcap = nc;
	}
	memcpy(r->body + r->blen, d, n);
	r->blen += n;
	r->body[r->blen] = 0;
	return 0;
}

/* feed body bytes; returns 0 (more), 1 (complete), or a negative HTTP_E_* */
static int body_feed(struct http_req *r, const uint8_t *d, size_t n)
{
	size_t i = 0;
	int rc;

	if (r->st == S_BODY_CL) {
		size_t take = n;

		if (r->clen - r->got < take)
			take = (size_t)(r->clen - r->got);
		rc = body_append(r, d, take);
		if (rc)
			return rc;
		r->got += take;
		return r->got == r->clen ? 1 : 0;
	}
	if (r->st == S_BODY_CLOSE)
		return body_append(r, d, n);
	while (i < n) {
		uint8_t c = d[i];

		switch (r->cs) {
		case C_SIZE:
			if (isxdigit(c)) {
				if (++r->csize_digits > 12)
					return HTTP_E_PROTO;
				r->csize = r->csize * 16 + (uint64_t)(isdigit(c) ? c - '0' : (tolower(c) - 'a' + 10));
				i++;
			} else if (c == ';' || c == '\r' || c == ' ' || c == '\t') {
				if (!r->csize_digits)
					return HTTP_E_PROTO;
				r->cs = C_EXT;
			} else if (c == '\n') {
				if (!r->csize_digits)
					return HTTP_E_PROTO;
				i++;
				r->cs = r->csize ? C_DATA : C_TRAILER_LINE;
				if (!r->csize)
					r->csize_digits = 0;
			} else {
				return HTTP_E_PROTO;
			}
			break;
		case C_EXT:
			i++;
			if (c == '\n') {
				r->cs = r->csize ? C_DATA : C_TRAILER_LINE;
				if (!r->csize)
					r->csize_digits = 0;
			}
			break;
		case C_DATA: {
			size_t take = n - i;

			if (r->csize < take)
				take = (size_t)r->csize;
			rc = body_append(r, d + i, take);
			if (rc)
				return rc;
			i += take;
			r->csize -= take;
			if (!r->csize)
				r->cs = C_DATA_CR;
			break;
		}
		case C_DATA_CR:
			if (c == '\r') {
				i++;
				r->cs = C_DATA_LF;
			} else if (c == '\n') {
				i++;
				r->cs = C_SIZE;
				r->csize = 0;
				r->csize_digits = 0;
			} else {
				return HTTP_E_PROTO;
			}
			break;
		case C_DATA_LF:
			if (c != '\n')
				return HTTP_E_PROTO;
			i++;
			r->cs = C_SIZE;
			r->csize = 0;
			r->csize_digits = 0;
			break;
		case C_TRAILER_LINE:		/* the line start after the last chunk: empty line ends the message */
			if (c == '\r') {
				i++;
				r->cs = C_TRAILER_END;
			} else if (c == '\n') {
				return 1;
			} else {
				r->csize_digits = 1;	/* a trailer header: skip to its end of line */
				i++;
				r->cs = C_EXT;
				r->csize = 0;
			}
			break;
		case C_TRAILER_END:
			if (c != '\n')
				return HTTP_E_PROTO;
			return 1;
		}
	}
	return 0;
}

/* trailer header lines: C_EXT with csize == 0 returns to C_TRAILER_LINE at the next LF, which is what the code above does */

static const char *hdr_value(const char *line, const char *name)
{
	size_t l = strlen(name);

	if (strncasecmp(line, name, l) || line[l] != ':')
		return NULL;
	line += l + 1;
	while (*line == ' ' || *line == '\t')
		line++;
	return line;
}

/* parse the status line and headers in r->head[0..hl). 1 = a final response, 0 = a 1xx to skip, negative = error */
static int parse_head(struct http_req *r, size_t hl)
{
	char *s = (char *)r->head, *line, *save = NULL;
	int first = 1;

	s[hl] = 0;
	r->chunked = r->have_clen = false;
	r->clen = 0;
	r->ctype[0] = 0;
	r->location[0] = 0;
	for (line = strtok_r(s, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		size_t l = strlen(line);
		const char *v;

		if (l && line[l - 1] == '\r')
			line[--l] = 0;
		if (first) {
			first = 0;
			if (strncmp(line, "HTTP/1.", 7) || !isdigit((unsigned char)line[7]) || line[8] != ' ' ||
			    !isdigit((unsigned char)line[9]) || !isdigit((unsigned char)line[10]) ||
			    !isdigit((unsigned char)line[11]))
				return HTTP_E_PROTO;
			r->status = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0');
			continue;
		}
		if ((v = hdr_value(line, "Content-Length"))) {
			char *e;
			unsigned long long x;

			if (!isdigit((unsigned char)*v))
				return HTTP_E_PROTO;
			x = strtoull(v, &e, 10);
			while (*e == ' ' || *e == '\t')
				e++;
			if (*e)
				return HTTP_E_PROTO;
			r->have_clen = true;
			r->clen = x;
		} else if ((v = hdr_value(line, "Transfer-Encoding"))) {
			if (strcasestr(v, "chunked"))
				r->chunked = true;
		} else if ((v = hdr_value(line, "Content-Type"))) {
			snprintf(r->ctype, sizeof(r->ctype), "%s", v);
		} else if ((v = hdr_value(line, "Location"))) {
			snprintf(r->location, sizeof(r->location), "%s", v);
		}
	}
	if (first)
		return HTTP_E_PROTO;
	return r->status >= 200 || r->status == 101 ? 1 : 0;
}

/* feed received bytes in the head / body states; returns 0 (continue) or finishes the request (returns 1: r is gone) */
static int feed(struct http_req *r, const uint8_t *d, size_t n)
{
	int rc;

	while (n) {
		if (r->st == S_HEAD) {
			size_t take = n, old = r->head_len, i, end = 0;
			bool found = false;

			if (old + take > HEAD_MAX - 1)
				take = HEAD_MAX - 1 - old;
			memcpy(r->head + old, d, take);
			r->head_len += take;
			/* find the blank line, looking back 3 bytes into the old data */
			for (i = old > 3 ? old - 3 : 0; i + 3 < r->head_len + 0 && !found; i++)
				if (r->head[i] == '\r' && r->head[i + 1] == '\n' && r->head[i + 2] == '\r' && r->head[i + 3] == '\n') {
					found = true;
					end = i + 4;
				}
			if (!found) {
				for (i = old > 1 ? old - 1 : 0; i + 1 < r->head_len && !found; i++)
					if (r->head[i] == '\n' && r->head[i + 1] == '\n') {
						found = true;
						end = i + 2;
					}
			}
			if (!found) {
				if (r->head_len >= HEAD_MAX - 1) {
					req_done(r, HTTP_E_PROTO);
					return 1;
				}
				return 0;
			}
			/* bytes of d that belong to the body */
			{
				size_t used = end - old;

				d += used;
				n -= used;
			}
			rc = parse_head(r, end);
			if (rc < 0) {
				req_done(r, rc);
				return 1;
			}
			r->head_len = 0;
			if (rc == 0)
				continue;		/* 1xx: skip, the next head follows */
			LOGD("mms: http: %s -> %d", r->method, r->status);
			if (is_redirect(r->status) && r->location[0] && !strcmp(r->method, "GET")) {
				int e = follow_redirect(r);

				if (e) {
					req_done(r, e);
					return 1;
				}
				conn_close(r);
				begin(r);
				return 1;		/* r lives on (new connection) but this feed is over */
			}
			if (r->status == 204 || r->status == 304 || (r->status >= 100 && r->status < 200)) {
				req_done(r, 0);
				return 1;
			}
			if (r->chunked) {
				r->st = S_BODY_CHUNK;
			} else if (r->have_clen) {
				if (r->clen > r->max_body) {
					LOGI("mms: http: response of %llu bytes exceeds the limit of %zu", (unsigned long long)r->clen,
					     r->max_body);
					req_done(r, HTTP_E_TOOBIG);
					return 1;
				}
				if (!r->clen) {
					req_done(r, 0);
					return 1;
				}
				r->st = S_BODY_CL;
			} else {
				r->st = S_BODY_CLOSE;
			}
			continue;
		}
		rc = body_feed(r, d, n);
		n = 0;
		if (rc == 1) {
			req_done(r, 0);
			return 1;
		}
		if (rc < 0) {
			req_done(r, rc);
			return 1;
		}
	}
	return 0;
}

static void on_io(void *arg, int fd)
{
	struct http_req *r = arg;
	struct http *h = r->h;
	int i;

	(void)fd;
	if (r->st == S_CONNECT) {
		int s = h->ops->tcp_status(h->ops->ctx, r->fd);

		if (s == -EINPROGRESS)
			return;
		if (s < 0) {
			next_addr(r, s);
			return;
		}
		if (build_request(r)) {
			req_done(r, HTTP_E_NOMEM);
			return;
		}
		r->st = S_SEND;
	}
	if (r->st == S_SEND) {
		while (r->out_sent < r->out_len) {
			ssize_t n = h->ops->tcp_send(h->ops->ctx, r->fd, r->out + r->out_sent, r->out_len - r->out_sent);

			if (n == -EAGAIN)
				return;
			if (n < 0) {
				r->sub_err = (int)n;
				req_done(r, HTTP_E_IO);
				return;
			}
			r->out_sent += (size_t)n;
			arm(r);
		}
		r->st = S_HEAD;
		free(r->out);
		r->out = NULL;
		ev_fd_set_events(r->w, EV_READ);
		arm(r);
		return;
	}
	for (i = 0; i < 16; i++) {
		uint8_t buf[RX_CHUNK];
		ssize_t n = h->ops->tcp_recv(h->ops->ctx, r->fd, buf, sizeof(buf));

		if (n == -EAGAIN)
			return;
		if (n < 0) {
			r->sub_err = (int)n;
			req_done(r, HTTP_E_IO);
			return;
		}
		if (n == 0) {		/* end of stream */
			if (r->st == S_BODY_CLOSE)
				req_done(r, 0);
			else
				req_done(r, HTTP_E_IO);
			return;
		}
		arm(r);
		if (feed(r, buf, (size_t)n))
			return;
	}
}
