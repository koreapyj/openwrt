/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_HTTPD_H
#define IMSD_MMS_HTTPD_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../util/addr.h"

/*
 * A small non-blocking HTTP/1.1 server on the event loop (util/evloop.h) for the LAN side of the MMS proxy.
 *
 * One request per connection: every response carries "Connection: close" and the connection is closed after it (a
 * keep-alive client is tolerated, it just has to reconnect). No TLS, no authentication, no compression, no chunked
 * request bodies (a request body needs Content-Length: 411 otherwise), no pipelining (bytes after the body are discarded).
 *
 * Limits: at most max_conns connections (the next one is answered 503 and closed), the header block (request line included)
 * at most max_header bytes (431), a body of at most max_body bytes (413 from the Content-Length alone, before the body is
 * read; "Expect: 100-continue" is answered "100 Continue" only when the request is acceptable). A client that sends nothing for
 * idle_ms, or does not finish its request within rx_ms, or does not take the response within tx_ms, is dropped. A request
 * handed to the handler waits for httpd_respond() for as long as the handler wants (it has its own timeouts).
 *
 * Methods: GET and POST reach the handler, OPTIONS is answered here ("Allow: GET, POST, OPTIONS"), everything else is 405.
 * The request-target is the origin form ("/path?query") or the absolute form ("http://host/path?query", as sent to a forward proxy;
 * path then holds the whole target up to '?', the handler judges scheme and host). CONNECT is 501.
 * Garbage (no request line, bad version, bad header) is 400; HTTP versions other than 1.0 / 1.1 are 505.
 *
 * The listening socket is dual-stack AF_INET6 (the address is v4-mapped for IPv4) and bound to the interface when one is given.
 * Sockets are real; a test drives them over loopback with the fake event loop.
 */
struct httpd;
struct httpd_conn;

struct httpd_cfg {
	unsigned max_conns;		/* default 8 */
	size_t max_header;		/* default 8192 */
	size_t max_body;		/* default 1 MiB */
	unsigned idle_ms;		/* default 10000 */
	unsigned rx_ms;			/* default 30000 */
	unsigned tx_ms;			/* default 30000 */
	char extra_headers[160];	/* header lines (CRLF each) added to every response, e.g. "X-MMS-Max-Size: 1048576\r\n" */
};
void httpd_cfg_defaults(struct httpd_cfg *c);

struct httpd_req {
	const char *method;		/* "GET" / "POST" */
	const char *target;		/* request-target as received */
	const char *path;		/* target up to '?' (not decoded) */
	const char *query;		/* after the '?', "" if none (not decoded) */
	const char *headers;		/* the header lines as received (CRLF separated), for httpd_header() */
	const char *content_type;	/* "" if absent */
	size_t content_length;		/* 0 if absent */
	const uint8_t *body;		/* NUL terminated after body_len; NULL when there is no body */
	size_t body_len;
	struct addr peer;		/* the client's address */
};
/* value of a request header (case-insensitive name) into out; NULL when absent */
const char *httpd_header(const struct httpd_req *rq, const char *name, char *out, size_t n);

struct httpd_ops {
	/* The head is complete: 0 to go on (read the body, call on_request), or an HTTP status to answer at once. May be NULL. */
	int (*on_head)(void *ctx, const struct httpd_req *rq);
	/* The whole request. The handler answers with httpd_respond() now or later. rq is valid during the call only. */
	void (*on_request)(void *ctx, struct httpd_conn *c, const struct httpd_req *rq);
	/* The connection ended (client gone, timeout, server stopped) before httpd_respond(): c is invalid after the call. May be NULL. */
	void (*on_gone)(void *ctx, struct httpd_conn *c);
};

struct httpd *httpd_new(const struct httpd_cfg *cfg, const struct httpd_ops *ops, void *ctx);
/* closes everything; on_gone is called for the requests that wait for an answer */
void httpd_free(struct httpd *h);
void httpd_set_cfg(struct httpd *h, const struct httpd_cfg *cfg);
/* start listening on addr (with its port; 0 = any, see httpd_port()), SO_BINDTODEVICE ifname when not NULL / empty. 0 / -errno. */
int httpd_listen(struct httpd *h, const struct addr *a, const char *ifname);
/* stop listening (running connections finish) */
void httpd_unlisten(struct httpd *h);
bool httpd_listening(const struct httpd *h);
unsigned httpd_port(const struct httpd *h);
unsigned httpd_conns(const struct httpd *h);

/* Answer a request: status line, Content-Type (NULL: none), the extra headers of the configuration, extra (header lines, CRLF each, or
 * NULL), Content-Length, Connection: close, then the body. body is copied, or taken (and freed with free()) when take. Once per request. */
void httpd_respond(struct httpd_conn *c, int status, const char *ctype, const char *extra, const void *body, size_t len, bool take);
/* the client's address of a connection */
const struct addr *httpd_peer(const struct httpd_conn *c);
#endif
