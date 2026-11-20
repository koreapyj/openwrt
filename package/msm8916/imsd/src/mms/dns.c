/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Asynchronous stub resolver, see dns.h. */
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "dns.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define T_A	1
#define T_CNAME	5
#define T_AAAA	28
#define MAX_PKT	1232
#define CACHE_N	16
#define MAX_RR	64
#define MAX_CHAIN 8

/* ------------------------------------------------------------------ */
/* wire format                                                         */

bool dns_name_ok(const char *s)
{
	size_t i, l = strlen(s), lab = 0;

	if (!l || l > DNS_NAME_MAX - 1)
		return false;
	if (s[l - 1] == '.')
		l--;
	if (!l)
		return false;
	for (i = 0; i < l; i++) {
		unsigned char c = (unsigned char)s[i];

		if (c == '.') {
			if (!lab)
				return false;
			lab = 0;
			continue;
		}
		if (!(isalnum(c) || c == '-' || c == '_') || ++lab > 63)
			return false;
	}
	return lab > 0;
}

size_t dns_build_query(const char *name, uint16_t type, uint16_t id, uint8_t *out, size_t cap)
{
	size_t k = 12, l;
	const char *p = name;

	if (!dns_name_ok(name) || cap < 12 + strlen(name) + 2 + 4)
		return 0;
	memset(out, 0, 12);
	out[0] = id >> 8;
	out[1] = id & 0xff;
	out[2] = 0x01;		/* RD */
	out[5] = 1;		/* QDCOUNT */
	while (*p) {
		const char *e = strchr(p, '.');

		l = e ? (size_t)(e - p) : strlen(p);
		out[k++] = (uint8_t)l;
		memcpy(out + k, p, l);
		k += l;
		if (!e)
			break;
		p = e + 1;
	}
	out[k++] = 0;
	out[k++] = type >> 8;
	out[k++] = type & 0xff;
	out[k++] = 0;
	out[k++] = 1;		/* IN */
	return k;
}

/* name at *off (compression followed), lower case, without the trailing dot; *off moves past the name in place */
static int read_name(const uint8_t *p, size_t n, size_t *off, char *out, size_t cap)
{
	size_t pos = *off, o = 0, end = 0;
	int hops = 0;
	bool jumped = false;

	for (;;) {
		uint8_t l;

		if (pos >= n)
			return -1;
		l = p[pos];
		if (!l) {
			if (!jumped)
				end = pos + 1;
			break;
		}
		if ((l & 0xc0) == 0xc0) {
			size_t ptr;

			if (pos + 1 >= n)
				return -1;
			ptr = (size_t)((l & 0x3f) << 8) | p[pos + 1];
			if (!jumped)
				end = pos + 2;
			jumped = true;
			if (++hops > 16 || ptr >= n)
				return -1;
			pos = ptr;
			continue;
		}
		if (l & 0xc0)
			return -1;
		if (pos + 1 + l > n || o + l + 2 > cap)
			return -1;
		if (o)
			out[o++] = '.';
		for (size_t i = 0; i < l; i++)
			out[o++] = (char)tolower(p[pos + 1 + i]);
		pos += 1 + (size_t)l;
	}
	out[o] = 0;
	*off = end;
	return 0;
}

struct rr {
	char owner[DNS_NAME_MAX + 1];
	uint16_t type, cls;
	uint32_t ttl;
	size_t rd, rdlen;
};

static int next_rr(const uint8_t *p, size_t n, size_t *off, struct rr *r)
{
	size_t o = *off;

	if (read_name(p, n, &o, r->owner, sizeof(r->owner)) || o + 10 > n)
		return -1;
	r->type = (uint16_t)((p[o] << 8) | p[o + 1]);
	r->cls = (uint16_t)((p[o + 2] << 8) | p[o + 3]);
	r->ttl = ((uint32_t)p[o + 4] << 24) | ((uint32_t)p[o + 5] << 16) | ((uint32_t)p[o + 6] << 8) | p[o + 7];
	r->rdlen = (size_t)((p[o + 8] << 8) | p[o + 9]);
	r->rd = o + 10;
	if (r->rd + r->rdlen > n)
		return -1;
	*off = r->rd + r->rdlen;
	return 0;
}

int dns_parse_answer(const uint8_t *p, size_t n, uint16_t id, const char *name, uint16_t type, struct dns_answer *out)
{
	char q[DNS_NAME_MAX + 1], want[DNS_NAME_MAX + 1], chain[MAX_CHAIN + 1][DNS_NAME_MAX + 1];
	size_t off = 12, start, l = strlen(name);
	unsigned an, qd, flags, i;
	int nchain = 1, grow;

	memset(out, 0, sizeof(*out));
	if (n < 12 || (unsigned)((p[0] << 8) | p[1]) != id)
		return -1;
	flags = (unsigned)((p[2] << 8) | p[3]);
	qd = (unsigned)((p[4] << 8) | p[5]);
	an = (unsigned)((p[6] << 8) | p[7]);
	if (!(flags & 0x8000) || ((flags >> 11) & 0xf) != 0 || qd != 1)
		return -1;
	if (read_name(p, n, &off, q, sizeof(q)) || off + 4 > n)
		return -1;
	if (l && name[l - 1] == '.')
		l--;
	if (l >= sizeof(want))
		return -1;
	for (i = 0; i < l; i++)
		want[i] = (char)tolower((unsigned char)name[i]);
	want[l] = 0;
	if (strcmp(q, want) || (unsigned)((p[off] << 8) | p[off + 1]) != type || p[off + 2] != 0 || p[off + 3] != 1)
		return -1;
	off += 4;
	out->rcode = flags & 0xf;
	out->tc = flags & 0x200;
	if (out->rcode)
		return 0;
	if (an > MAX_RR)
		an = MAX_RR;
	start = off;
	/* follow CNAMEs: chain[0] is the question, each CNAME owned by the last name adds its target */
	snprintf(chain[0], sizeof(chain[0]), "%s", want);
	do {
		grow = 0;
		off = start;
		for (i = 0; i < an && nchain <= MAX_CHAIN; i++) {
			struct rr r;
			size_t ro;

			if (next_rr(p, n, &off, &r))
				return -1;
			if (r.type == T_CNAME && r.cls == 1 && !strcmp(r.owner, chain[nchain - 1])) {
				ro = r.rd;
				if (read_name(p, n, &ro, chain[nchain], sizeof(chain[0])) || ro > r.rd + r.rdlen)
					continue;
				nchain++;
				grow = 1;
				break;
			}
		}
	} while (grow && nchain <= MAX_CHAIN);
	if (nchain > MAX_CHAIN)
		nchain = MAX_CHAIN;
	off = start;
	for (i = 0; i < an; i++) {
		struct rr r;
		int k;

		if (next_rr(p, n, &off, &r))
			return -1;
		if (r.cls != 1 || r.type != type || out->n >= DNS_MAX_ADDR)
			continue;
		for (k = 0; k < nchain; k++)
			if (!strcmp(r.owner, chain[k]))
				break;
		if (k == nchain)
			continue;
		if (type == T_A && r.rdlen == 4) {
			uint32_t be;

			memcpy(&be, p + r.rd, 4);
			addr_set_v4(&out->addr[out->n], be, 0);
		} else if (type == T_AAAA && r.rdlen == 16) {
			addr_set_v6(&out->addr[out->n], p + r.rd, 0);
		} else {
			continue;
		}
		if (!out->n || r.ttl < out->ttl)
			out->ttl = r.ttl;
		out->n++;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* resolver                                                            */

struct cache_ent {
	bool used;
	char name[DNS_NAME_MAX + 1];
	int fam;
	struct addr a[DNS_MAX_ADDR];
	int n;
	uint64_t expires;
};

struct dns {
	const struct net_ops *ops;
	struct dns_query *q;
	struct cache_ent cache[CACHE_N];
	unsigned cnext;
};

struct dns_query {
	struct dns_query *next;
	struct dns *d;
	struct dns_bind b;
	char name[DNS_NAME_MAX + 1];
	int fam[2];
	int nfam, stage;
	int fd;
	struct ev_fd *w;
	struct ev_timer *t;
	uint16_t id;
	int attempt;		/* sends in this stage */
	int err;		/* result delivered by the timer (cache hit / immediate failure) */
	bool failed_once;	/* a server answered with an error (not just silence) */
	struct addr res[DNS_MAX_ADDR];
	int nres;
	bool deliver_now;
	dns_cb cb;
	void *arg;
};

struct dns *dns_new(const struct net_ops *ops)
{
	struct dns *d = calloc(1, sizeof(*d));

	if (d)
		d->ops = ops;
	return d;
}

static void q_close(struct dns_query *q)
{
	ev_fd_del(q->w);
	q->w = NULL;
	if (q->fd >= 0)
		q->d->ops->close(q->d->ops->ctx, q->fd);
	q->fd = -1;
	ev_timer_free(q->t);
	q->t = NULL;
}

static void q_unlink(struct dns_query *q)
{
	struct dns_query **pp;

	for (pp = &q->d->q; *pp; pp = &(*pp)->next)
		if (*pp == q) {
			*pp = q->next;
			break;
		}
}

void dns_cancel(struct dns_query *q)
{
	if (!q)
		return;
	q_unlink(q);
	q_close(q);
	free(q);
}

void dns_free(struct dns *d)
{
	if (!d)
		return;
	while (d->q)
		dns_cancel(d->q);
	free(d);
}

void dns_flush(struct dns *d)
{
	memset(d->cache, 0, sizeof(d->cache));
}

static void finish(struct dns_query *q, int err)
{
	dns_cb cb = q->cb;
	void *arg = q->arg;
	struct addr res[DNS_MAX_ADDR];
	int n = q->nres;

	memcpy(res, q->res, sizeof(res));
	q_unlink(q);
	q_close(q);
	free(q);
	cb(arg, err, res, err ? 0 : n);
}

static void cache_put(struct dns *d, const char *name, int fam, const struct addr *a, int n, uint32_t ttl)
{
	struct cache_ent *c;

	if (!ttl || !n)
		return;
	if (ttl > DNS_TTL_CAP)
		ttl = DNS_TTL_CAP;
	c = &d->cache[d->cnext++ % CACHE_N];
	memset(c, 0, sizeof(*c));
	c->used = true;
	snprintf(c->name, sizeof(c->name), "%s", name);
	c->fam = fam;
	memcpy(c->a, a, sizeof(*a) * (size_t)n);
	c->n = n;
	c->expires = ev_now_ms() + (uint64_t)ttl * 1000;
}

static const struct cache_ent *cache_get(struct dns *d, const char *name, int fam)
{
	int i;
	uint64_t now = ev_now_ms();

	for (i = 0; i < CACHE_N; i++) {
		struct cache_ent *c = &d->cache[i];

		if (c->used && c->fam == fam && !strcasecmp(c->name, name)) {
			if (c->expires > now)
				return c;
			c->used = false;
		}
	}
	return NULL;
}

static void send_next(struct dns_query *q);

static void on_timeout(void *arg)
{
	struct dns_query *q = arg;

	if (q->deliver_now) {
		finish(q, q->err);
		return;
	}
	send_next(q);
}

static void on_readable(void *arg, int fd);

static void start_stage(struct dns_query *q)
{
	q->id = (uint16_t)rnd32();
	q->attempt = 0;
	send_next(q);
}

/* send the current stage's query to the next server, or give up */
static void send_next(struct dns_query *q)
{
	uint8_t pkt[MAX_PKT];
	size_t l;
	struct addr dst;
	uint16_t type = q->fam[q->stage] == AF_INET6 ? T_AAAA : T_A;

	if (q->attempt >= q->b.n_server * DNS_ROUNDS) {
		LOGI("mms: dns: no usable answer for %s from %d server(s)", q->name, q->b.n_server);
		finish(q, q->failed_once ? -EIO : -ETIMEDOUT);
		return;
	}
	dst = q->b.server[q->attempt % q->b.n_server];
	if (!addr_port(&dst))
		addr_set_port(&dst, 53);
	q->attempt++;
	l = dns_build_query(q->name, type, q->id, pkt, sizeof(pkt));
	if (!l) {
		finish(q, -EINVAL);
		return;
	}
	if (q->d->ops->udp_send(q->d->ops->ctx, q->fd, pkt, l, &dst) < 0)
		LOGD("mms: dns: send to server %d failed", (q->attempt - 1) % q->b.n_server);
	ev_timer_set(q->t, DNS_TIMEOUT_MS);
}

static void on_readable(void *arg, int fd)
{
	struct dns_query *q = arg;
	struct dns *d = q->d;
	int i;

	(void)fd;
	for (i = 0; i < 8; i++) {
		uint8_t pkt[MAX_PKT];
		struct addr src;
		struct dns_answer ans;
		ssize_t n = d->ops->udp_recv(d->ops->ctx, q->fd, pkt, sizeof(pkt), &src);
		int k, ok = 0;
		uint16_t type = q->fam[q->stage] == AF_INET6 ? T_AAAA : T_A;

		if (n < 0)
			return;
		for (k = 0; k < q->b.n_server; k++) {
			struct addr s = q->b.server[k];

			if (!addr_port(&s))
				addr_set_port(&s, 53);
			if (addr_equal(&s, &src))
				ok = 1;
		}
		if (!ok || dns_parse_answer(pkt, (size_t)n, q->id, q->name, type, &ans))
			continue;		/* not from a server we asked / not the answer to our question */
		if (ans.rcode == 3) {
			finish(q, -ENOENT);
			return;
		}
		if (ans.rcode) {		/* SERVFAIL, REFUSED ...: the next server */
			q->failed_once = true;
			ev_timer_set(q->t, 0);
			return;
		}
		if (ans.n) {
			cache_put(d, q->name, q->fam[q->stage], ans.addr, ans.n, ans.ttl);
			memcpy(q->res, ans.addr, sizeof(q->res));
			q->nres = ans.n;
			finish(q, 0);
			return;
		}
		if (ans.tc) {			/* truncated and no address: this server cannot help */
			q->failed_once = true;
			ev_timer_set(q->t, 0);
			return;
		}
		if (q->stage + 1 < q->nfam) {	/* NODATA: the other family (from the cache when it is there) */
			const struct cache_ent *c = cache_get(d, q->name, q->fam[q->stage + 1]);

			if (c) {
				memcpy(q->res, c->a, sizeof(q->res));
				q->nres = c->n;
				finish(q, 0);
				return;
			}
			q->stage++;
			start_stage(q);
			return;
		}
		finish(q, -ENODATA);
		return;
	}
}

struct dns_query *dns_resolve(struct dns *d, const struct dns_bind *b, const char *name, int prefer, dns_cb cb, void *arg)
{
	struct dns_query *q = calloc(1, sizeof(*q));
	const struct cache_ent *c;

	if (!q)
		return NULL;
	q->d = d;
	q->b = *b;
	q->cb = cb;
	q->arg = arg;
	q->fd = -1;
	snprintf(q->name, sizeof(q->name), "%s", name);
	q->fam[0] = prefer == AF_INET ? AF_INET : AF_INET6;
	q->fam[1] = q->fam[0] == AF_INET ? AF_INET6 : AF_INET;
	q->nfam = 2;
	q->t = ev_timer_new(on_timeout, q);
	q->next = d->q;
	d->q = q;
	if (!q->t) {
		dns_cancel(q);
		errno = ENOMEM;
		return NULL;
	}
	if (!dns_name_ok(name) || b->n_server < 1) {
		q->deliver_now = true;
		q->err = -EINVAL;
		ev_timer_set(q->t, 0);
		return q;
	}
	if (b->n_server > DNS_MAX_SERVERS)
		q->b.n_server = DNS_MAX_SERVERS;
	c = cache_get(d, q->name, q->fam[0]);
	if (c) {
		memcpy(q->res, c->a, sizeof(q->res));
		q->nres = c->n;
		q->deliver_now = true;
		q->err = 0;
		ev_timer_set(q->t, 0);
		return q;
	}
	q->fd = d->ops->udp_open(d->ops->ctx, &q->b.local, q->b.netdev);
	if (q->fd < 0) {
		LOGI("mms: dns: cannot open the socket on %s: %s", q->b.netdev, strerror(-q->fd));
		q->fd = -1;
		q->deliver_now = true;
		q->err = -ENETDOWN;
		ev_timer_set(q->t, 0);
		return q;
	}
	q->w = ev_fd_add(q->fd, on_readable, q);
	if (!q->w) {
		dns_cancel(q);
		errno = ENOMEM;
		return NULL;
	}
	start_stage(q);
	return q;
}
