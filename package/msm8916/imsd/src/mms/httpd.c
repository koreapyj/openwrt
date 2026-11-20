/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Non-blocking HTTP/1.1 server, see httpd.h. */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include "httpd.h"
#include "../util/evloop.h"
#include "../util/log.h"

#define LINGER_MS	2000u
#define LINGER_MAX	(256u * 1024)	/* bytes of an unwanted request body read and thrown away after the answer */
#define BACKLOG		8

enum cstate { CS_HEAD, CS_BODY, CS_WAIT, CS_TX, CS_LINGER };

struct httpd_conn {
	struct httpd_conn *next;
	struct httpd *h;
	int fd;
	struct ev_fd *w;
	struct ev_timer *t;
	enum cstate st;
	struct addr peer;
	uint64_t start, last;		/* monotonic: when the phase began / the last progress */
	uint8_t *in;			/* head buffer */
	size_t in_len;
	char *head;			/* parsed head (copy, NUL terminated) */
	struct httpd_req rq;
	uint8_t *body;
	size_t body_len, body_got;
	bool sent_continue;
	char ctype[128];		/* Content-Type value of the request */
	bool eof;			/* the client closed its side */
	uint8_t *tx_head, *tx_body;
	size_t tx_hlen, tx_blen, tx_off;
	size_t lingered;
};

struct httpd {
	struct httpd_cfg cfg;
	struct httpd_ops ops;
	void *ctx;
	int lfd;
	struct ev_fd *lw;
	struct addr bound;
	struct httpd_conn *conns;
	unsigned nconn;
};

void httpd_cfg_defaults(struct httpd_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->max_conns = 8;
	c->max_header = 8192;
	c->max_body = 1024 * 1024;
	c->idle_ms = 10000;
	c->rx_ms = 30000;
	c->tx_ms = 30000;
}

static const char *reason(int s)
{
	switch (s) {
	case 100: return "Continue";
	case 200: return "OK";
	case 204: return "No Content";
	case 400: return "Bad Request";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 408: return "Request Timeout";
	case 409: return "Conflict";
	case 411: return "Length Required";
	case 413: return "Payload Too Large";
	case 415: return "Unsupported Media Type";
	case 417: return "Expectation Failed";
	case 431: return "Request Header Fields Too Large";
	case 500: return "Internal Server Error";
	case 501: return "Not Implemented";
	case 502: return "Bad Gateway";
	case 503: return "Service Unavailable";
	case 504: return "Gateway Timeout";
	case 505: return "HTTP Version Not Supported";
	default: return "Status";
	}
}

const char *httpd_header(const struct httpd_req *rq, const char *name, char *out, size_t n)
{
	size_t nl = strlen(name);
	const char *p = rq->headers;

	while (p && *p) {
		const char *e = strstr(p, "\r\n");
		size_t ll = e ? (size_t)(e - p) : strlen(p);

		if (ll > nl && p[nl] == ':' && !strncasecmp(p, name, nl)) {
			const char *v = p + nl + 1, *ve = p + ll;

			while (v < ve && (*v == ' ' || *v == '\t'))
				v++;
			while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t'))
				ve--;
			if ((size_t)(ve - v) >= n)
				return NULL;
			memcpy(out, v, (size_t)(ve - v));
			out[ve - v] = 0;
			return out;
		}
		p = e ? e + 2 : NULL;
	}
	return NULL;
}

/* ------------------------------------------------------------------ */

static void conn_free(struct httpd_conn *c)
{
	struct httpd_conn **pp;

	for (pp = &c->h->conns; *pp; pp = &(*pp)->next)
		if (*pp == c) {
			*pp = c->next;
			break;
		}
	c->h->nconn--;
	ev_fd_del(c->w);
	ev_timer_free(c->t);
	if (c->fd >= 0)
		close(c->fd);
	free(c->in);
	free(c->head);
	free(c->body);
	free(c->tx_head);
	free(c->tx_body);
	free(c);
}

/* the connection ends now; a request that waits for its answer is reported */
static void conn_kill(struct httpd_conn *c)
{
	if (c->st == CS_WAIT && c->h->ops.on_gone)
		c->h->ops.on_gone(c->h->ctx, c);
	conn_free(c);
}

static void conn_arm(struct httpd_conn *c)
{
	uint64_t now = ev_now_ms(), idle, total, ms;
	unsigned rxms = c->h->cfg.rx_ms, txms = c->h->cfg.tx_ms;

	switch (c->st) {
	case CS_HEAD:
	case CS_BODY:
		idle = c->last + c->h->cfg.idle_ms;
		total = c->start + rxms;
		break;
	case CS_TX:
		idle = c->last + c->h->cfg.idle_ms;
		total = c->start + txms;
		break;
	case CS_LINGER:
		idle = total = c->start + LINGER_MS;
		break;
	default:
		ev_timer_cancel(c->t);
		return;
	}
	if (total < idle)
		idle = total;
	ms = idle > now ? idle - now : 0;
	ev_timer_set(c->t, ms);
}

static void conn_timer(void *arg)
{
	struct httpd_conn *c = arg;

	if (c->st == CS_HEAD || c->st == CS_BODY) {
		const char *msg = "request timeout\n";
		char b[256];
		int n = snprintf(b, sizeof(b), "HTTP/1.1 408 Request Timeout\r\nConnection: close\r\nContent-Type: text/plain\r\n"
				 "Content-Length: %zu\r\n\r\n%s", strlen(msg), msg);

		if (n > 0)
			(void)send(c->fd, b, (size_t)n, MSG_NOSIGNAL | MSG_DONTWAIT);
	}
	conn_kill(c);
}

static void conn_io(void *arg, int fd);

static void conn_events(struct httpd_conn *c, unsigned ev)
{
	if (!ev) {
		ev_fd_del(c->w);
		c->w = NULL;
	} else if (!c->w) {
		c->w = ev_fd_add_ev(c->fd, ev, conn_io, c);
	} else {
		ev_fd_set_events(c->w, ev);
	}
}

/* start sending the answer (head + body); the connection ends after it */
static void tx_begin(struct httpd_conn *c, uint8_t *head, size_t hlen, uint8_t *body, size_t blen)
{
	c->st = CS_TX;
	c->tx_head = head;
	c->tx_hlen = hlen;
	c->tx_body = body;
	c->tx_blen = blen;
	c->tx_off = 0;
	c->start = c->last = ev_now_ms();
	conn_events(c, EV_WRITE);
	conn_arm(c);
}

static int tx_step(struct httpd_conn *c)	/* 1 done, 0 more later, -1 error */
{
	while (c->tx_off < c->tx_hlen + c->tx_blen) {
		const uint8_t *p;
		size_t n;
		ssize_t r;

		if (c->tx_off < c->tx_hlen) {
			p = c->tx_head + c->tx_off;
			n = c->tx_hlen - c->tx_off;
		} else {
			p = c->tx_body + (c->tx_off - c->tx_hlen);
			n = c->tx_hlen + c->tx_blen - c->tx_off;
		}
		r = send(c->fd, p, n, MSG_NOSIGNAL);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
		c->tx_off += (size_t)r;
		c->last = ev_now_ms();
	}
	return 1;
}

static void tx_finished(struct httpd_conn *c)
{
	free(c->tx_head);
	free(c->tx_body);
	c->tx_head = c->tx_body = NULL;
	shutdown(c->fd, SHUT_WR);		/* the answer is complete: FIN, then read what is left so that no RST eats it */
	c->st = CS_LINGER;
	c->start = c->last = ev_now_ms();
	conn_events(c, EV_READ);
	conn_arm(c);
}

static void respond(struct httpd_conn *c, int status, const char *ctype, const char *extra, const void *body, size_t len, bool take)
{
	char head[1024];
	uint8_t *hb, *bb = NULL;
	int n;

	n = snprintf(head, sizeof(head), "HTTP/1.1 %d %s\r\n%s%s%s%s%sContent-Length: %zu\r\nConnection: close\r\n\r\n", status,
		     reason(status), ctype ? "Content-Type: " : "", ctype ? ctype : "", ctype ? "\r\n" : "", c->h->cfg.extra_headers,
		     extra ? extra : "", len);
	if (n < 0 || (size_t)n >= sizeof(head)) {
		if (take)
			free((void *)body);
		n = snprintf(head, sizeof(head), "HTTP/1.1 500 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", reason(500));
		len = 0;
		body = NULL;
		take = false;
	}
	hb = malloc((size_t)n);
	if (!hb) {
		if (take)
			free((void *)body);
		conn_kill(c);
		return;
	}
	memcpy(hb, head, (size_t)n);
	if (len) {
		if (take) {
			bb = (uint8_t *)body;
		} else {
			bb = malloc(len);
			if (!bb) {
				free(hb);
				conn_kill(c);
				return;
			}
			memcpy(bb, body, len);
		}
	} else if (take) {
		free((void *)body);
	}
	tx_begin(c, hb, (size_t)n, bb, len);
	switch (tx_step(c)) {
	case 1:
		tx_finished(c);
		break;
	case -1:
		/* the peer is gone: end it from the timer, not from inside the caller's call chain */
		conn_events(c, 0);
		ev_timer_set(c->t, 0);
		c->st = CS_LINGER;
		break;
	default:
		break;
	}
}

void httpd_respond(struct httpd_conn *c, int status, const char *ctype, const char *extra, const void *body, size_t len, bool take)
{
	if (c->st != CS_WAIT) {
		if (take)
			free((void *)body);
		return;
	}
	respond(c, status, ctype, extra, body, len, take);
}

const struct addr *httpd_peer(const struct httpd_conn *c)
{
	return &c->peer;
}

/* an answer decided by the server itself */
static void reject(struct httpd_conn *c, int status, const char *extra)
{
	char msg[96];

	snprintf(msg, sizeof(msg), "%d %s\n", status, reason(status));
	c->st = CS_WAIT;
	respond(c, status, "text/plain", extra, msg, strlen(msg), false);
}

/* ------------------------------------------------------------------ */
/* request parsing                                                     */

static bool parse_ulong(const char *s, size_t *out)
{
	size_t v = 0;

	if (!*s)
		return false;
	for (; *s; s++) {
		if (!isdigit((unsigned char)*s) || v > ((size_t)-1) / 10 - 1)
			return false;
		v = v * 10 + (size_t)(*s - '0');
	}
	*out = v;
	return true;
}

static bool header_ok(const char *line, size_t n)
{
	size_t i;
	const char *colon = memchr(line, ':', n);

	if (!colon || colon == line)
		return false;
	for (i = 0; i < (size_t)(colon - line); i++)
		if (line[i] <= ' ' || line[i] >= 0x7f)
			return false;
	for (i = 0; i < n; i++)
		if ((unsigned char)line[i] < 0x20 && line[i] != '\t')
			return false;
	return true;
}

/* the head is in c->in[0 .. hl): parse it. Returns 0 to go on or the status to answer */
static int parse_head(struct httpd_conn *c, size_t hl)
{
	char *h = malloc(2 * hl + 2), *sp1, *sp2, *line_end, *q;
	char tmp[64];
	size_t cl = 0;

	if (!h)
		return 500;
	memcpy(h, c->in, hl);
	h[hl] = 0;
	free(c->head);
	c->head = h;
	line_end = strstr(h, "\r\n");
	if (!line_end)
		return 400;
	*line_end = 0;
	sp1 = strchr(h, ' ');
	sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
	if (!sp1 || !sp2 || sp1 == h || sp2 == sp1 + 1)
		return 400;
	*sp1 = 0;
	*sp2 = 0;
	if (strncmp(sp2 + 1, "HTTP/", 5))
		return 400;
	if (strcmp(sp2 + 1, "HTTP/1.1") && strcmp(sp2 + 1, "HTTP/1.0"))
		return 505;
	if (strspn(h, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != strlen(h))
		return 400;
	c->rq.method = h;
	c->rq.target = sp1 + 1;
	if (!strcmp(h, "CONNECT"))	/* a tunnel is not what this proxy does */
		return 501;
	if (c->rq.target[0] != '/' && !strstr(c->rq.target, "://"))	/* origin form, or absolute-form for the forward proxy (the handler judges the scheme) */
		return 400;
	q = strchr((char *)c->rq.target, '?');
	c->rq.path = c->rq.target;
	c->rq.query = "";
	if (q) {
		size_t pl = (size_t)(q - c->rq.target);
		char *pp = h + hl + 1;		/* the second half of the allocation */

		memcpy(pp, c->rq.target, pl);
		pp[pl] = 0;
		c->rq.query = q + 1;
		c->rq.path = pp;
	}
	{
		const char *p = line_end + 2;

		c->rq.headers = p;
		while (*p) {
			const char *e = strstr(p, "\r\n");
			size_t ll = e ? (size_t)(e - p) : strlen(p);

			if (!ll)
				break;
			if (!header_ok(p, ll))
				return 400;
			p = e ? e + 2 : p + ll;
		}
	}
	if (httpd_header(&c->rq, "Transfer-Encoding", tmp, sizeof(tmp)))
		return 411;
	if (httpd_header(&c->rq, "Content-Length", tmp, sizeof(tmp))) {
		if (!parse_ulong(tmp, &cl))
			return 400;
	} else if (!strcmp(c->rq.method, "POST")) {
		return 411;
	}
	c->rq.content_length = cl;
	return 0;
}

/* ------------------------------------------------------------------ */
/* connection I/O                                                      */

/* the head is complete and fine: what next */
static void head_done(struct httpd_conn *c, size_t hl)
{
	struct httpd *h = c->h;
	size_t got = c->in_len - hl, cl;
	char tmp[64];
	int rc = parse_head(c, hl);

	if (rc) {
		reject(c, rc, NULL);
		return;
	}
	if (strcmp(c->rq.method, "GET") && strcmp(c->rq.method, "POST")) {
		if (!strcmp(c->rq.method, "OPTIONS")) {
			c->st = CS_WAIT;
			respond(c, 204, NULL, "Allow: GET, POST, OPTIONS\r\n", NULL, 0, false);
		} else {
			reject(c, 405, "Allow: GET, POST, OPTIONS\r\n");
		}
		return;
	}
	cl = c->rq.content_length;
	if (cl > h->cfg.max_body) {		/* before a byte of the body is read, "Expect: 100-continue" or not */
		reject(c, 413, NULL);
		return;
	}
	c->ctype[0] = 0;
	httpd_header(&c->rq, "Content-Type", c->ctype, sizeof(c->ctype));
	c->rq.content_type = c->ctype;
	if (httpd_header(&c->rq, "Expect", tmp, sizeof(tmp))) {
		if (strcasecmp(tmp, "100-continue")) {
			reject(c, 417, NULL);
			return;
		}
	}
	if (h->ops.on_head) {
		rc = h->ops.on_head(h->ctx, &c->rq);
		if (rc) {
			reject(c, rc, NULL);
			return;
		}
	}
	c->body = malloc(cl + 1);
	if (!c->body) {
		reject(c, 503, NULL);
		return;
	}
	c->body_len = cl;
	c->body_got = got > cl ? cl : got;
	if (c->body_got)
		memcpy(c->body, c->in + hl, c->body_got);
	free(c->in);
	c->in = NULL;
	c->in_len = 0;
	if (c->body_got < cl) {
		if (httpd_header(&c->rq, "Expect", tmp, sizeof(tmp)) && !c->sent_continue) {
			static const char CONT[] = "HTTP/1.1 100 Continue\r\n\r\n";

			c->sent_continue = true;
			(void)send(c->fd, CONT, sizeof(CONT) - 1, MSG_NOSIGNAL | MSG_DONTWAIT);
		}
		c->st = CS_BODY;
		conn_arm(c);
		return;
	}
	c->body[cl] = 0;
	c->rq.body = cl ? c->body : NULL;
	c->rq.body_len = cl;
	c->st = CS_WAIT;
	conn_arm(c);
	h->ops.on_request(h->ctx, c, &c->rq);
}

static void conn_io(void *arg, int fd)
{
	struct httpd_conn *c = arg;

	(void)fd;
	switch (c->st) {
	case CS_HEAD:
	case CS_BODY: {
		for (;;) {
			ssize_t r;
			uint8_t *dst;
			size_t room;

			if (c->st == CS_HEAD) {
				if (!c->in) {
					c->in = malloc(c->h->cfg.max_header + 1);
					if (!c->in) {
						conn_kill(c);
						return;
					}
				}
				dst = c->in + c->in_len;
				room = c->h->cfg.max_header - c->in_len;
				if (!room) {
					reject(c, 431, NULL);
					return;
				}
			} else {
				dst = c->body + c->body_got;
				room = c->body_len - c->body_got;
			}
			r = recv(c->fd, dst, room, 0);
			if (r < 0 && errno == EINTR)
				continue;
			if (r < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return;
				conn_kill(c);
				return;
			}
			if (r == 0) {			/* closed before the request was complete */
				conn_kill(c);
				return;
			}
			c->last = ev_now_ms();
			if (c->st == CS_HEAD) {
				size_t from = c->in_len > 3 ? c->in_len - 3 : 0, i;

				c->in_len += (size_t)r;
				c->in[c->in_len] = 0;
				for (i = from; i + 3 < c->in_len; i++)
					if (!memcmp(c->in + i, "\r\n\r\n", 4)) {
						head_done(c, i + 4);
						return;
					}
				if (c->in_len >= c->h->cfg.max_header) {
					reject(c, 431, NULL);
					return;
				}
				conn_arm(c);
			} else {
				c->body_got += (size_t)r;
				if (c->body_got >= c->body_len) {
					c->body[c->body_len] = 0;
					c->rq.body = c->body_len ? c->body : NULL;
					c->rq.body_len = c->body_len;
					c->st = CS_WAIT;
					conn_arm(c);
					c->h->ops.on_request(c->h->ctx, c, &c->rq);
					return;
				}
				conn_arm(c);
			}
		}
	}
	case CS_WAIT: {
		uint8_t b[512];
		ssize_t r = recv(c->fd, b, sizeof(b), 0);

		if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
			if (r < 0) {
				conn_kill(c);	/* reset: the client is gone */
				return;
			}
			c->eof = true;		/* it may have only closed its sending side: the answer is still sent */
			conn_events(c, 0);
		}
		return;
	}
	case CS_TX: {
		int r = tx_step(c);

		if (r < 0)
			conn_kill(c);
		else if (r > 0)
			tx_finished(c);
		else
			conn_arm(c);
		return;
	}
	case CS_LINGER: {
		uint8_t b[2048];

		for (;;) {
			ssize_t r = recv(c->fd, b, sizeof(b), 0);

			if (r < 0 && errno == EINTR)
				continue;
			if (r <= 0 && !(r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
				conn_free(c);
				return;
			}
			if (r < 0)
				return;
			c->lingered += (size_t)r;
			if (c->lingered > LINGER_MAX) {
				conn_free(c);
				return;
			}
		}
	}
	}
}

/* ------------------------------------------------------------------ */
/* listener                                                            */

static void on_accept(void *arg, int fd)
{
	struct httpd *h = arg;
	int i;

	for (i = 0; i < 16; i++) {
		struct sockaddr_in6 sa;
		socklen_t sl = sizeof(sa);
		int cfd = accept4(fd, (struct sockaddr *)&sa, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
		struct httpd_conn *c;

		if (cfd < 0)
			return;
		if (h->nconn >= h->cfg.max_conns) {
			static const char BUSY[] = "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nConnection: close\r\n"
						   "Content-Length: 0\r\n\r\n";

			(void)send(cfd, BUSY, sizeof(BUSY) - 1, MSG_NOSIGNAL | MSG_DONTWAIT);
			close(cfd);
			continue;
		}
		c = calloc(1, sizeof(*c));
		if (!c) {
			close(cfd);
			continue;
		}
		c->h = h;
		c->fd = cfd;
		c->st = CS_HEAD;
		addr_from_sa6(&c->peer, &sa);
		c->rq.peer = c->peer;
		c->start = c->last = ev_now_ms();
		c->t = ev_timer_new(conn_timer, c);
		c->w = ev_fd_add_ev(cfd, EV_READ, conn_io, c);
		if (!c->t || !c->w) {
			ev_timer_free(c->t);
			ev_fd_del(c->w);
			close(cfd);
			free(c);
			continue;
		}
		c->next = h->conns;
		h->conns = c;
		h->nconn++;
		conn_arm(c);
	}
}

struct httpd *httpd_new(const struct httpd_cfg *cfg, const struct httpd_ops *ops, void *ctx)
{
	struct httpd *h = calloc(1, sizeof(*h));

	if (!h)
		return NULL;
	h->cfg = *cfg;
	h->ops = *ops;
	h->ctx = ctx;
	h->lfd = -1;
	return h;
}

void httpd_unlisten(struct httpd *h)
{
	ev_fd_del(h->lw);
	h->lw = NULL;
	if (h->lfd >= 0)
		close(h->lfd);
	h->lfd = -1;
}

void httpd_free(struct httpd *h)
{
	if (!h)
		return;
	httpd_unlisten(h);
	while (h->conns)
		conn_kill(h->conns);
	free(h);
}

void httpd_set_cfg(struct httpd *h, const struct httpd_cfg *cfg)
{
	h->cfg = *cfg;
}

int httpd_listen(struct httpd *h, const struct addr *a, const char *ifname)
{
	struct sockaddr_in6 sa = a->sa;
	socklen_t sl = sizeof(sa);
	int fd, off = 0, on = 1, e;

	httpd_unlisten(h);
	fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (ifname && ifname[0] && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname) + 1)) {
		e = errno;
		close(fd);
		return -e;
	}
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) || listen(fd, BACKLOG)) {
		e = errno;
		close(fd);
		return -e;
	}
	if (!getsockname(fd, (struct sockaddr *)&sa, &sl))
		addr_from_sa6(&h->bound, &sa);
	h->lfd = fd;
	h->lw = ev_fd_add(fd, on_accept, h);
	if (!h->lw) {
		httpd_unlisten(h);
		return -ENOMEM;
	}
	return 0;
}

bool httpd_listening(const struct httpd *h)
{
	return h->lfd >= 0;
}

unsigned httpd_port(const struct httpd *h)
{
	return h->lfd >= 0 ? addr_port(&h->bound) : 0;
}

unsigned httpd_conns(const struct httpd *h)
{
	return h->nconn;
}
