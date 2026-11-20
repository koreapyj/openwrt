/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_DNS_H
#define IMSD_MMS_DNS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "netio.h"

/*
 * Minimal asynchronous stub resolver on the event loop (util/evloop.h): A and AAAA over UDP, sent from a socket bound
 * to the IMS bearer's address and netdev to the bearer's DNS servers in turn. The names the MMSC uses resolve only
 * there. No search domains, no /etc/resolv.conf, no TCP fallback (a truncated answer that carries no address is a
 * failure of that server), no negative cache. A small positive cache honours the TTL (at most DNS_TTL_CAP seconds).
 *
 * dns_resolve asks the address family of the bearer first (prefer) and the other family only when the first answer has
 * no address (NODATA). Per server: DNS_TIMEOUT_MS; the servers are tried round robin, DNS_ROUNDS rounds in total.
 * The callback is never called from inside dns_resolve().
 */
#define DNS_MAX_SERVERS	4
#define DNS_MAX_ADDR	4
#define DNS_TTL_CAP	300
#define DNS_TIMEOUT_MS	2000
#define DNS_ROUNDS	2
#define DNS_NAME_MAX	254

struct dns_bind {
	struct addr local;		/* the IMS address (port ignored) */
	char netdev[16];		/* the IMS netdev, "" = no SO_BINDTODEVICE */
	struct addr server[DNS_MAX_SERVERS];	/* port 53 is set by the resolver when 0 */
	int n_server;
	/* Optional gate for the TCP connections of the HTTP client (the MMS bearer's traffic guard, mmsguard.h): asked with the destination
	 * before every connect. 0: go ahead; > 0: wait, done(arg, err) follows once from the event loop (err 0 = allowed, else -errno);
	 * < 0: refused. gate_cancel(ctx, arg) when the request goes away while waiting. NULL: no gate. DNS queries are not gated (the
	 * servers are the bearer's own and are in the guard's DNS set from the moment the bearer is armed). */
	int (*gate)(void *ctx, const struct addr *dst, void (*done)(void *arg, int err), void *arg);
	void (*gate_cancel)(void *ctx, void *arg);
	void *gate_ctx;
};

/* err: 0, or -ENOENT (NXDOMAIN), -ENODATA (no address of either family), -ETIMEDOUT, -EIO (every server failed),
 * -EINVAL (bad name / no server), -ENETDOWN (cannot open the socket), -ECANCELED never delivered */
typedef void (*dns_cb)(void *arg, int err, const struct addr *a, int n);

struct dns;
struct dns_query;
struct dns *dns_new(const struct net_ops *ops);
/* drops every query without calling back */
void dns_free(struct dns *d);
/* forget the cache (the link changed) */
void dns_flush(struct dns *d);
/* prefer: AF_INET6 or AF_INET. NULL (errno) when out of memory. */
struct dns_query *dns_resolve(struct dns *d, const struct dns_bind *b, const char *name, int prefer, dns_cb cb, void *arg);
/* no callback any more */
void dns_cancel(struct dns_query *q);

/* ---- wire format, exposed for the tests ---- */
bool dns_name_ok(const char *name);
/* query packet (id, RD set, one question, class IN); length or 0 */
size_t dns_build_query(const char *name, uint16_t type, uint16_t id, uint8_t *out, size_t cap);
struct dns_answer {
	int rcode;
	bool tc;
	struct addr addr[DNS_MAX_ADDR];
	int n;
	uint32_t ttl;			/* smallest TTL of the addresses */
};
/* Validate a response to (id, name, type) and extract the addresses (following CNAMEs inside the answer, with name
 * compression). 0, or -1 when it is not a valid answer to that question. */
int dns_parse_answer(const uint8_t *p, size_t n, uint16_t id, const char *name, uint16_t type, struct dns_answer *out);
#endif
