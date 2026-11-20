/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_HTTP_H
#define IMSD_MMS_HTTP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dns.h"
#include "netio.h"

/*
 * Minimal asynchronous HTTP/1.1 client for plain http:// URLs on the event loop (util/evloop.h): the name is
 * resolved by the stub resolver (dns.h) through the IMS bearer's DNS servers (or is an IP literal), the TCP
 * connection is made from a socket bound to the IMS address and netdev, the request goes out with
 * `Connection: close` (one request per connection) and the response is read whole into memory.
 *
 * Supported: GET and POST with caller supplied headers / body; Content-Length, Transfer-Encoding: chunked and
 * connection close delimited bodies; 1xx responses are skipped; GET follows 301/302/303/307/308 with a Location
 * of http://... or an absolute path (at most HTTP_MAX_REDIRECTS, every hop resolved and bound the same way).
 * HTTP proxy (http_opts.proxy_host): like a handset's MMS proxy setting, the TCP connection goes to the proxy (its name resolved by the
 * same resolver, the addresses tried in turn), the request line carries the absolute URI ("POST http://omms.nate.com:9082/oma_mms
 * HTTP/1.1") and Host is the origin's; no CONNECT (plain http only); redirects go through the proxy as well.
 * Not supported: https (HTTP_E_UNSUPPORTED), keep-alive, compression, authentication.
 * The body cap is enforced early (Content-Length) and while reading (HTTP_E_TOOBIG). The response body of a callback
 * is valid during the call only. The callback is never called from inside http_request().
 */
#define HTTP_MAX_REDIRECTS	3
#define HTTP_MAX_URL		768
#define HTTP_MAX_REQ_BODY	(16u * 1024 * 1024)

enum http_err {
	HTTP_OK = 0,
	HTTP_E_URL = -1,		/* malformed URL */
	HTTP_E_UNSUPPORTED = -2,	/* https:// or another scheme */
	HTTP_E_DNS = -3,		/* the name did not resolve (see http_resp.sub_err) */
	HTTP_E_CONNECT = -4,
	HTTP_E_TIMEOUT = -5,		/* overall or idle timeout */
	HTTP_E_IO = -6,			/* connection lost / reset */
	HTTP_E_PROTO = -7,		/* not an HTTP response, bad header, bad chunk */
	HTTP_E_TOOBIG = -8,		/* body larger than max_body */
	HTTP_E_REDIRECT = -9,		/* too many redirects, or a redirect that cannot be followed */
	HTTP_E_NOMEM = -10,
	HTTP_E_ARG = -11,
};
const char *http_strerror(int err);

struct http_opts {
	const char *method;		/* "GET" or "POST" */
	const char *url;
	const char *headers;		/* extra header lines, CRLF terminated; Host, Content-Length and Connection are added */
	const uint8_t *body;		/* request body (POST), at most HTTP_MAX_REQ_BODY, copied (and released once the request is built) */
	size_t body_len;
	size_t max_body;		/* response body cap (default 1 MiB) */
	const char *proxy_host;		/* "" / NULL = direct. Name or IP literal of the HTTP proxy */
	unsigned proxy_port;		/* default 80 */
	unsigned timeout_ms;		/* whole request, default 60000 */
	unsigned idle_ms;		/* no progress, default 20000 */
};

struct http_resp {
	int status;			/* HTTP status of the last response seen (0 if none) */
	const char *content_type;	/* "" if absent */
	const uint8_t *body;
	size_t len;
	int sub_err;			/* HTTP_E_DNS: the resolver's -errno; HTTP_E_CONNECT / IO: -errno */
	const char *final_url;		/* after redirects */
};
/* err: 0 (any HTTP status, see resp->status) or an HTTP_E_*; resp is never NULL */
typedef void (*http_cb)(void *arg, int err, const struct http_resp *resp);

struct http;
struct http_req;
struct http *http_new(const struct net_ops *ops, struct dns *dns);
/* drops every request without calling back */
void http_free(struct http *h);
/* NULL (errno) on out of memory / bad arguments (HTTP_E_URL and HTTP_E_UNSUPPORTED are reported through the callback) */
struct http_req *http_request(struct http *h, const struct dns_bind *bind, const struct http_opts *o, http_cb cb, void *arg);
/* no callback any more, connection closed */
void http_cancel(struct http_req *r);

/* ---- URL helper, exposed for the manager and the tests ---- */
struct http_url {
	char host[256];		/* without brackets */
	uint16_t port;
	char path[HTTP_MAX_URL];	/* with the query, starts with '/' */
	bool https;
};
/* 0, HTTP_E_URL, HTTP_E_UNSUPPORTED (https:// is parsed too, with ->https set) */
int http_parse_url(const char *url, struct http_url *u);
#endif
