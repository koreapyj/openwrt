/* SPDX-License-Identifier: GPL-2.0-or-later */
/* DNS and HTTP clients: wire format, mock sockets, and loopback integration with real sockets. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include "t_common.h"

static struct addr A(const char *s)
{
	struct addr a;

	addr_set(&a, s, 0);
	return a;
}

/* ------------------------------------------------------------------ */
/* DNS wire format                                                     */

static void t_dns_wire(void)
{
	uint8_t q[300], r[600];
	size_t ql, rl, i;
	struct dns_answer a;
	static const uint8_t V4[4] = { 192, 168, 230, 14 };
	uint8_t v6[16];
	struct dns_rr_spec rr[3];

	CHECK(dns_name_ok("omammsc.uplus.co.kr")); CHECK(dns_name_ok("a.b.")); CHECK(dns_name_ok("x_y-1.example"));
	CHECK(!dns_name_ok("")); CHECK(!dns_name_ok(".")); CHECK(!dns_name_ok("a..b")); CHECK(!dns_name_ok(".a"));
	CHECK(!dns_name_ok("a b")); CHECK(!dns_name_ok("[::1]"));
	{
		char l[80];

		memset(l, 'a', 64); l[64] = 0;
		CHECK(!dns_name_ok(l));
		l[63] = 0;
		CHECK(dns_name_ok(l));
	}
	ql = dns_build_query("Mmsc.Test", 28, 0x1234, q, sizeof(q));
	CHECK_EQ(ql, 12 + 1 + 4 + 1 + 4 + 1 + 4);
	CHECK_EQ(q[0], 0x12); CHECK_EQ(q[1], 0x34); CHECK_EQ(q[2], 1); CHECK_EQ(q[5], 1);
	CHECK(!memcmp(q + 12, "\x04Mmsc\x04Test\x00\x00\x1c\x00\x01", 15));	/* 15 bytes: the query ends there (the 16th was read from beyond it) */
	CHECK_EQ(dns_build_query("bad name", 1, 1, q, sizeof(q)), 0);
	CHECK_EQ(dns_build_query("a.b", 1, 1, q, 10), 0);

	/* A record, then every truncation of the answer: never a crash, never "valid" with a wrong length */
	ql = dns_build_query("mmsc.test", 1, 0x4242, q, sizeof(q));
	memset(rr, 0, sizeof(rr));
	rr[0].type = 1; rr[0].ttl = 60; rr[0].rdata = V4; rr[0].rdlen = 4; rr[0].owner_ref = -1;
	rl = dns_response(q, ql, 0, false, rr, 1, r, sizeof(r));
	CHECK(rl > ql);
	CHECK_EQ(dns_parse_answer(r, rl, 0x4242, "mmsc.test", 1, &a), 0);
	CHECK_EQ(a.rcode, 0); CHECK_EQ(a.n, 1); CHECK_EQ(a.ttl, 60);
	CHECK(addr_is_v4(&a.addr[0])); { char h[40]; addr_host(&a.addr[0], h, sizeof(h)); CHECK_STR(h, "192.168.230.14"); }
	for (i = 0; i < rl; i++)
		(void)dns_parse_answer(r, i, 0x4242, "mmsc.test", 1, &a);
	CHECK_EQ(dns_parse_answer(r, rl, 0x4243, "mmsc.test", 1, &a), -1);	/* wrong id */
	CHECK_EQ(dns_parse_answer(r, rl, 0x4242, "other.test", 1, &a), -1);	/* wrong question */
	CHECK_EQ(dns_parse_answer(r, rl, 0x4242, "mmsc.test", 28, &a), -1);	/* wrong type */
	CHECK_EQ(dns_parse_answer(r, rl, 0x4242, "MMSC.test.", 1, &a), 0);	/* case and the trailing dot do not matter */
	r[2] &= 0x7f;								/* not a response */
	CHECK_EQ(dns_parse_answer(r, rl, 0x4242, "mmsc.test", 1, &a), -1);
	r[2] |= 0x80;
	/* rcodes, truncation flag */
	rl = dns_response(q, ql, 3, false, NULL, 0, r, sizeof(r));
	CHECK_EQ(dns_parse_answer(r, rl, 0x4242, "mmsc.test", 1, &a), 0); CHECK_EQ(a.rcode, 3); CHECK_EQ(a.n, 0);
	rl = dns_response(q, ql, 0, true, NULL, 0, r, sizeof(r));
	CHECK_EQ(dns_parse_answer(r, rl, 0x4242, "mmsc.test", 1, &a), 0); CHECK(a.tc);
	/* AAAA, a record of the wrong length is ignored, the TTL is the smallest */
	memset(v6, 0, 16); v6[0] = 0x20; v6[1] = 0x01; v6[15] = 1;
	ql = dns_build_query("mmsc.test", 28, 7, q, sizeof(q));
	memset(rr, 0, sizeof(rr));
	rr[0].type = 28; rr[0].ttl = 300; rr[0].rdata = v6; rr[0].rdlen = 16; rr[0].owner_ref = -1;
	rr[1].type = 28; rr[1].ttl = 30; rr[1].rdata = V4; rr[1].rdlen = 4; rr[1].owner_ref = -1;
	rr[2].type = 28; rr[2].ttl = 20; rr[2].rdata = v6; rr[2].rdlen = 16; rr[2].owner_ref = -1;
	rl = dns_response(q, ql, 0, false, rr, 3, r, sizeof(r));
	CHECK_EQ(dns_parse_answer(r, rl, 7, "mmsc.test", 28, &a), 0); CHECK_EQ(a.n, 2); CHECK_EQ(a.ttl, 20);
	/* CNAME chain: mmsc.test -> a.cdn.test (target written in full) -> addresses owned by the target (pointer into the rdata) */
	memset(rr, 0, sizeof(rr));
	rr[0].type = 5; rr[0].ttl = 60; rr[0].cname_target = "a.cdn.test"; rr[0].owner_ref = -1;
	rr[1].type = 28; rr[1].ttl = 50; rr[1].rdata = v6; rr[1].rdlen = 16; rr[1].owner_ref = 0;
	rl = dns_response(q, ql, 0, false, rr, 2, r, sizeof(r));
	CHECK_EQ(dns_parse_answer(r, rl, 7, "mmsc.test", 28, &a), 0); CHECK_EQ(a.n, 1); CHECK_EQ(a.ttl, 50);
	for (i = 0; i < rl; i++)
		(void)dns_parse_answer(r, i, 7, "mmsc.test", 28, &a);
	/* a compression pointer loop in the question or an owner name ends cleanly */
	rl = dns_response(q, ql, 0, false, rr, 1, r, sizeof(r));
	{
		uint8_t m[600];

		memcpy(m, r, rl);
		m[12] = 0xc0; m[13] = 12;		/* the question name points at itself */
		CHECK_EQ(dns_parse_answer(m, rl, 7, "mmsc.test", 28, &a), -1);
		memcpy(m, r, rl);
		m[ql] = 0xc0; m[ql + 1] = (uint8_t)ql;	/* an owner name that points at itself */
		CHECK_EQ(dns_parse_answer(m, rl, 7, "mmsc.test", 28, &a), -1);
	}
}

/* ------------------------------------------------------------------ */
/* resolver on mock sockets                                            */

struct dres {
	int calls, err, n;
	struct addr a[DNS_MAX_ADDR];
};

static void dns_cb_rec(void *arg, int err, const struct addr *a, int n)
{
	struct dres *d = arg;

	d->calls++;
	d->err = err;
	d->n = n;
	if (n)
		memcpy(d->a, a, sizeof(*a) * (size_t)n);
}

static struct dns_bind mkbind(void)
{
	struct dns_bind b;

	memset(&b, 0, sizeof(b));
	addr_set(&b.local, "2001:4430:141:990a::cb69", 0);
	snprintf(b.netdev, sizeof(b.netdev), "wwan0");
	addr_set(&b.server[0], "2001:4430:8000:20:0:1:0:1", 0);
	addr_set(&b.server[1], "2001:4430:8000:20:0:1:0:2", 0);
	b.n_server = 2;
	return b;
}

static void t_dns_mock(void)
{
	struct mocknet mn;
	struct dns *d;
	struct dres r;
	struct dns_bind b = mkbind();
	struct dns_query *q;
	struct mock_dns_rule rule;
	char h[64];

	evfake_reset();
	mock_init(&mn);
	d = dns_new(&mn.ops);
	memset(&rule, 0, sizeof(rule));
	rule.name = "omammsc.uplus.co.kr"; rule.type = 28; rule.ttl = 60; rule.n = 1;
	rule.addr[0] = A("2001:4430:8000:20:0:1:0:1");
	mock_dns_add(&mn, &rule);

	/* AAAA first (the bearer is IPv6), sent from the IMS address and netdev to the first server, port 53; the callback is not synchronous */
	memset(&r, 0, sizeof(r));
	q = dns_resolve(d, &b, "omammsc.uplus.co.kr", AF_INET6, dns_cb_rec, &r);
	CHECK(q != NULL); CHECK_EQ(r.calls, 0);
	spin(10);
	CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, 0); CHECK_EQ(r.n, 1);
	addr_host(&r.a[0], h, sizeof(h)); CHECK_STR(h, "2001:4430:8000:20:0:1:0:1");
	CHECK_EQ(mn.n_usent, 1); CHECK_EQ(addr_port(&mn.usent[0].dst), 53);
	addr_host(&mn.usent[0].dst, h, sizeof(h)); CHECK_STR(h, "2001:4430:8000:20:0:1:0:1");
	CHECK_STR(mn.udp_netdev, "wwan0");
	addr_host(&mn.udp_local, h, sizeof(h)); CHECK_STR(h, "2001:4430:141:990a::cb69");
	CHECK_EQ(mn.n_closed, 1);

	/* cache: the second lookup sends nothing (and still answers asynchronously); after the TTL it asks again */
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "OMAMMSC.uplus.co.kr", AF_INET6, dns_cb_rec, &r);
	CHECK_EQ(r.calls, 0);
	spin(5);
	CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, 0); CHECK_EQ(mn.n_usent, 1);
	advance(61000);
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "omammsc.uplus.co.kr", AF_INET6, dns_cb_rec, &r);
	spin(10);
	CHECK_EQ(r.calls, 1); CHECK_EQ(mn.n_usent, 2);
	dns_flush(d);
	dns_resolve(d, &b, "omammsc.uplus.co.kr", AF_INET6, dns_cb_rec, &r);
	spin(10);
	CHECK_EQ(mn.n_usent, 3);

	/* a TTL above the cap (5 minutes) is cut */
	mn.n_usent = 0;
	mn.dns[0].ttl = 100000;
	dns_flush(d);
	dns_resolve(d, &b, "omammsc.uplus.co.kr", AF_INET6, dns_cb_rec, &r);
	spin(10);
	CHECK_EQ(mn.n_usent, 1);
	advance(290000);
	dns_resolve(d, &b, "omammsc.uplus.co.kr", AF_INET6, dns_cb_rec, &r);
	spin(10);
	CHECK_EQ(mn.n_usent, 1);
	advance(20000);
	dns_resolve(d, &b, "omammsc.uplus.co.kr", AF_INET6, dns_cb_rec, &r);
	spin(10);
	CHECK_EQ(mn.n_usent, 2);
	dns_free(d);
	mock_free(&mn);

	/* NODATA for AAAA: the A query follows; the address is IPv4 */
	evfake_reset();
	mock_init(&mn);
	d = dns_new(&mn.ops);
	memset(&rule, 0, sizeof(rule));
	rule.name = "v4only.test"; rule.type = 28; rule.ttl = 60;
	mock_dns_add(&mn, &rule);
	memset(&rule, 0, sizeof(rule));
	rule.name = "v4only.test"; rule.type = 1; rule.ttl = 30; rule.n = 1; rule.addr[0] = A("192.168.230.14");
	mock_dns_add(&mn, &rule);
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "v4only.test", AF_INET6, dns_cb_rec, &r);
	spin(20);
	CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, 0); CHECK_EQ(r.n, 1); CHECK(addr_is_v4(&r.a[0]));
	CHECK_EQ(mn.n_usent, 2);
	/* the bearer is IPv4: A first, and AAAA is not asked when A has an answer */
	mn.n_usent = 0;
	dns_flush(d);
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "v4only.test", AF_INET, dns_cb_rec, &r);
	spin(20);
	CHECK_EQ(r.err, 0); CHECK_EQ(mn.n_usent, 1);

	/* NXDOMAIN, no retry of the other family */
	memset(&rule, 0, sizeof(rule));
	rule.name = "nx.test"; rule.type = 28; rule.rcode = 3;
	mock_dns_add(&mn, &rule);
	mn.n_usent = 0;
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "nx.test", AF_INET6, dns_cb_rec, &r);
	spin(20);
	CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, -ENOENT); CHECK_EQ(mn.n_usent, 1);

	/* neither family has an address */
	memset(&rule, 0, sizeof(rule));
	rule.name = "none.test"; rule.type = 28;
	mock_dns_add(&mn, &rule);
	rule.type = 1;
	mock_dns_add(&mn, &rule);
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "none.test", AF_INET6, dns_cb_rec, &r);
	spin(20);
	CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, -ENODATA);

	/* SERVFAIL from the first server: the second one is asked at once; a silent first server: after the timeout */
	memset(&rule, 0, sizeof(rule));
	rule.name = "sf.test"; rule.type = 28; rule.rcode = 2; rule.ignore = 0; rule.n = 0;
	mock_dns_add(&mn, &rule);
	mn.n_usent = 0;
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "sf.test", AF_INET6, dns_cb_rec, &r);
	spin(30);
	CHECK_EQ(r.calls, 1); CHECK_EQ(mn.n_usent, 4);	/* every server twice, at once: DNS_ROUNDS = 2 */
	CHECK_EQ(r.err, -EIO);

	memset(&rule, 0, sizeof(rule));
	rule.name = "slow.test"; rule.type = 28; rule.ttl = 60; rule.n = 1; rule.addr[0] = A("2001:db8::9"); rule.ignore = 1;
	mock_dns_add(&mn, &rule);
	mn.n_usent = 0;
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "slow.test", AF_INET6, dns_cb_rec, &r);
	spin(10);
	CHECK_EQ(r.calls, 0); CHECK_EQ(mn.n_usent, 1);
	advance(1900); CHECK_EQ(r.calls, 0); CHECK_EQ(mn.n_usent, 1);
	advance(200);
	CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, 0); CHECK_EQ(mn.n_usent, 2);
	addr_host(&mn.usent[1].dst, h, sizeof(h)); CHECK_STR(h, "2001:4430:8000:20:0:1:0:2");	/* the next server */

	/* nobody answers: DNS_ROUNDS rounds over the servers, then -ETIMEDOUT */
	memset(&rule, 0, sizeof(rule));
	rule.name = "dead.test"; rule.type = 28; rule.ignore = 100;
	mock_dns_add(&mn, &rule);
	mn.n_usent = 0;
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "dead.test", AF_INET6, dns_cb_rec, &r);
	advance(7900); CHECK_EQ(r.calls, 0);
	advance(300);
	CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, -ETIMEDOUT); CHECK_EQ(mn.n_usent, 4);

	/* answers from a stranger / with a wrong id / for another question are ignored */
	memset(&rule, 0, sizeof(rule));
	rule.name = "late.test"; rule.type = 28; rule.ignore = 1;
	mock_dns_add(&mn, &rule);
	mn.n_usent = 0;
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "late.test", AF_INET6, dns_cb_rec, &r);
	spin(10);
	{
		uint8_t pkt[600], v6a[16] = { 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 };
		struct dns_rr_spec rr[1] = { { .type = 28, .ttl = 60, .rdata = v6a, .rdlen = 16, .owner_ref = -1 } };
		size_t pl = dns_response(mn.usent[0].d, mn.usent[0].n, 0, false, rr, 1, pkt, sizeof(pkt));
		struct addr stranger = A("2001:db8::bad");

		addr_set_port(&stranger, 53);
		{	/* queue it by hand as if it came from another host: use the udp_in queue through a rule-free path */
			int i;

			for (i = 0; i < MN_MAX_UDP; i++)
				if (!mn.uin[i].n) {
					mn.uin[i].src = stranger;
					memcpy(mn.uin[i].d, pkt, pl);
					mn.uin[i].n = pl;
					mn.uin[i].fd = mn.fa[mn.n_fd - 1];
					if (write(mn.fb[mn.n_fd - 1], "x", 1) < 0)
						break;
					break;
				}
		}
		spin(10);
		CHECK_EQ(r.calls, 0);
		pkt[0] ^= 0xff;		/* wrong id from the right server */
		{
			int i;

			for (i = 0; i < MN_MAX_UDP; i++)
				if (!mn.uin[i].n) {
					mn.uin[i].src = mn.usent[0].dst;
					memcpy(mn.uin[i].d, pkt, pl);
					mn.uin[i].n = pl;
					mn.uin[i].fd = mn.fa[mn.n_fd - 1];
					if (write(mn.fb[mn.n_fd - 1], "x", 1) < 0)
						break;
					break;
				}
		}
		spin(10);
		CHECK_EQ(r.calls, 0);
		pkt[0] ^= 0xff;
		{
			int i;

			for (i = 0; i < MN_MAX_UDP; i++)
				if (!mn.uin[i].n) {
					mn.uin[i].src = mn.usent[0].dst;
					memcpy(mn.uin[i].d, pkt, pl);
					mn.uin[i].n = pl;
					mn.uin[i].fd = mn.fa[mn.n_fd - 1];
					if (write(mn.fb[mn.n_fd - 1], "x", 1) < 0)
						break;
					break;
				}
		}
		spin(10);
		CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, 0);
	}

	/* CNAME in the answer (through the mock rule) */
	memset(&rule, 0, sizeof(rule));
	rule.name = "alias.test"; rule.type = 28; rule.ttl = 60; rule.n = 1; rule.addr[0] = A("2001:db8::77"); rule.cname = "real.cdn.test";
	mock_dns_add(&mn, &rule);
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "alias.test", AF_INET6, dns_cb_rec, &r);
	spin(10);
	CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, 0); CHECK_EQ(r.n, 1);

	/* bad names and no servers: an asynchronous -EINVAL; no socket opened */
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "bad name", AF_INET6, dns_cb_rec, &r);
	CHECK_EQ(r.calls, 0);
	spin(5);
	CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, -EINVAL);
	{
		struct dns_bind nb = b;

		nb.n_server = 0;
		memset(&r, 0, sizeof(r));
		dns_resolve(d, &nb, "x.test", AF_INET6, dns_cb_rec, &r);
		spin(5);
		CHECK_EQ(r.err, -EINVAL);
	}
	/* the socket cannot be opened (the link vanished) */
	mn.udp_open_rc = -ENODEV;
	memset(&r, 0, sizeof(r));
	dns_resolve(d, &b, "open.test", AF_INET6, dns_cb_rec, &r);
	spin(5);
	CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, -ENETDOWN);
	mn.udp_open_rc = 0;
	/* cancel: no callback, the socket is closed */
	{
		int closed = mn.n_closed;

		memset(&rule, 0, sizeof(rule));
		rule.name = "cancel.test"; rule.type = 28; rule.ignore = 100;
		mock_dns_add(&mn, &rule);
		memset(&r, 0, sizeof(r));
		q = dns_resolve(d, &b, "cancel.test", AF_INET6, dns_cb_rec, &r);
		spin(5);
		dns_cancel(q);
		advance(20000);
		CHECK_EQ(r.calls, 0); CHECK_EQ(mn.n_closed, closed + 1);
		/* and dns_free with a query in flight */
		q = dns_resolve(d, &b, "cancel.test", AF_INET6, dns_cb_rec, &r);
		spin(5);
		(void)q;
	}
	dns_free(d);
	CHECK_EQ(evfake_armed_timers(), 0);
	CHECK_EQ(evfake_fd_watches(), 0);
	mock_free(&mn);
}

/* ------------------------------------------------------------------ */
/* HTTP on mock sockets                                                */

struct hres {
	int calls, err, status, sub_err;
	char ctype[96], url[HTTP_MAX_URL];
	uint8_t *body;
	size_t len;
};

static void hres_clear(struct hres *r)
{
	free(r->body);
	memset(r, 0, sizeof(*r));
}

static void http_cb_rec(void *arg, int err, const struct http_resp *resp)
{
	struct hres *r = arg;

	r->calls++;
	r->err = err;
	r->status = resp->status;
	r->sub_err = resp->sub_err;
	snprintf(r->ctype, sizeof(r->ctype), "%s", resp->content_type ? resp->content_type : "");
	snprintf(r->url, sizeof(r->url), "%s", resp->final_url ? resp->final_url : "");
	free(r->body);
	r->body = NULL;
	r->len = 0;
	if (resp->body && resp->len) {
		r->body = malloc(resp->len);
		memcpy(r->body, resp->body, resp->len);
		r->len = resp->len;
	}
}

struct hfix {
	struct mocknet mn;
	struct dns *dns;
	struct http *h;
	struct dns_bind b;
	struct hres r;
	uint8_t resp[4096];
};

static void hfix_init(struct hfix *f)
{
	memset(f, 0, sizeof(*f));
	evfake_reset();
	mock_init(&f->mn);
	f->dns = dns_new(&f->mn.ops);
	f->h = http_new(&f->mn.ops, f->dns);
	f->b = mkbind();
}

static void hfix_fini(struct hfix *f)
{
	http_free(f->h);
	dns_free(f->dns);
	hres_clear(&f->r);
	CHECK_EQ(evfake_armed_timers(), 0);
	CHECK_EQ(evfake_fd_watches(), 0);
	mock_free(&f->mn);
}

static struct http_req *hget(struct hfix *f, const char *url, const char *hdr)
{
	struct http_opts o;

	memset(&o, 0, sizeof(o));
	o.method = "GET";
	o.url = url;
	o.headers = hdr;
	hres_clear(&f->r);
	return http_request(f->h, &f->b, &o, http_cb_rec, &f->r);
}

#define ACCEPT_UA "Accept: */*, application/vnd.wap.mms-message, application/vnd.wap.sic\r\nUser-Agent: TTA-VoLTE/3.0 imsd/0.1 Device_Type/Android_Phone OMD\r\n"

static void t_http_basic(void)
{
	struct hfix f;
	struct mock_resp m;
	static const uint8_t BODY[] = "MMSBODY\x00\xff\x01";
	char url[200];
	size_t i;

	hfix_init(&f);
	/* 1: IPv6 literal, the request the live network accepted, bound to the IMS address and netdev */
	memset(&m, 0, sizeof(m));
	m.d = f.resp;
	m.n = http_ok(f.resp, sizeof(f.resp), 200, "application/vnd.wap.mms-message", BODY, sizeof(BODY) - 1);
	mock_respond(&f.mn, &m);
	CHECK(hget(&f, "http://[2001:4430:8000:20:0:1:0:1]:9095/?AvBt6f7q", ACCEPT_UA) != NULL);
	CHECK_EQ(f.r.calls, 0);					/* not from inside http_request */
	spin(30);
	CHECK_EQ(f.r.calls, 1); CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.status, 200);
	CHECK_STR(f.r.ctype, "application/vnd.wap.mms-message"); CHECK_EQ(f.r.len, sizeof(BODY) - 1); CHECK(!memcmp(f.r.body, BODY, f.r.len));
	CHECK_STR(mock_req(&f.mn, 0),
		  "GET /?AvBt6f7q HTTP/1.1\r\nHost: [2001:4430:8000:20:0:1:0:1]:9095\r\n" ACCEPT_UA "Connection: close\r\n\r\n");
	CHECK_STR(f.mn.conn[0].netdev, "wwan0");
	{
		char h[64];

		addr_host(&f.mn.conn[0].local, h, sizeof(h)); CHECK_STR(h, "2001:4430:141:990a::cb69");
		addr_host(&f.mn.conn[0].dst, h, sizeof(h)); CHECK_STR(h, "2001:4430:8000:20:0:1:0:1");
		CHECK_EQ(addr_port(&f.mn.conn[0].dst), 9095);
	}
	CHECK(f.mn.conn[0].closed);

	/* 2: a name, port 80 (no port in Host), resolved through the bearer's DNS */
	{
		struct mock_dns_rule rule;

		memset(&rule, 0, sizeof(rule));
		rule.name = "omammsc.uplus.co.kr"; rule.type = 28; rule.ttl = 60; rule.n = 1; rule.addr[0] = A("2001:4430:8000:20:0:1:0:1");
		mock_dns_add(&f.mn, &rule);
	}
	mock_respond(&f.mn, &m);
	hget(&f, "http://omammsc.uplus.co.kr/path/x?y=1#frag", "");
	spin(40);
	CHECK_EQ(f.r.calls, 1); CHECK_EQ(f.r.err, 0);
	CHECK_STR(mock_req(&f.mn, 1), "GET /path/x?y=1 HTTP/1.1\r\nHost: omammsc.uplus.co.kr\r\nConnection: close\r\n\r\n");
	CHECK_EQ(addr_port(&f.mn.conn[1].dst), 80);
	CHECK_EQ(f.mn.n_usent, 1);

	/* 3: the response in pieces of one byte, whatever the boundaries */
	for (i = 1; i <= 3; i++) {
		struct hfix g;

		hfix_init(&g);
		m.step = i == 3 ? 7 : 1;
		m.d = g.resp;
		m.n = http_ok(g.resp, sizeof(g.resp), 200, "x/y", BODY, sizeof(BODY) - 1);
		mock_respond(&g.mn, &m);
		hget(&g, "http://[2001:db8::1]/", "");
		spin(i == 3 ? 60 : 400);
		CHECK_EQ(g.r.calls, 1); CHECK_EQ(g.r.err, 0); CHECK_EQ(g.r.len, sizeof(BODY) - 1);
		hfix_fini(&g);
	}
	m.step = 0;

	/* 4: 404 is a normal answer; 204 and an empty Content-Length need no body; a 100 Continue is skipped */
	{
		static const char R404[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope";
		static const char R204[] = "HTTP/1.1 204 No Content\r\n\r\n";
		static const char R100[] = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
		static const char RLF[] = "HTTP/1.0 200 OK\nContent-Length: 2\n\nok";

		memset(&m, 0, sizeof(m));
		m.d = (const uint8_t *)R404; m.n = strlen(R404); mock_respond(&f.mn, &m);
		m.d = (const uint8_t *)R204; m.n = strlen(R204); mock_respond(&f.mn, &m);
		m.d = (const uint8_t *)R100; m.n = strlen(R100); mock_respond(&f.mn, &m);
		m.d = (const uint8_t *)RLF; m.n = strlen(RLF); mock_respond(&f.mn, &m);
		f.mn.n_responses = 0;
		/* responses are matched by connection number: connections 0 and 1 are used; rebuild the list from index 2 */
		memset(f.mn.responses, 0, sizeof(f.mn.responses));
		memset(&m, 0, sizeof(m));
		f.mn.n_responses = 2;
		m.d = (const uint8_t *)R404; m.n = strlen(R404); f.mn.responses[2] = m; f.mn.n_responses = 3;
		m.d = (const uint8_t *)R204; m.n = strlen(R204); f.mn.responses[3] = m; f.mn.n_responses = 4;
		m.d = (const uint8_t *)R100; m.n = strlen(R100); f.mn.responses[4] = m; f.mn.n_responses = 5;
		m.d = (const uint8_t *)RLF; m.n = strlen(RLF); f.mn.responses[5] = m; f.mn.n_responses = 6;
		hget(&f, "http://[2001:db8::1]/a", ""); spin(40);
		CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.status, 404); CHECK_EQ(f.r.len, 4);
		hget(&f, "http://[2001:db8::1]/a", ""); spin(40);
		CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.status, 204); CHECK_EQ(f.r.len, 0);
		hget(&f, "http://[2001:db8::1]/a", ""); spin(40);
		CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.status, 200); CHECK_EQ(f.r.len, 2); CHECK(!memcmp(f.r.body, "ok", 2));
		hget(&f, "http://[2001:db8::1]/a", ""); spin(40);
		CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.status, 200); CHECK_EQ(f.r.len, 2);
	}
	hfix_fini(&f);
	(void)url;
}

static void t_http_bodies(void)
{
	struct hfix f;
	struct mock_resp m;
	size_t i;
	static const char CHUNKED[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: a/b\r\n\r\n"
				      "5;ext=1\r\nhello\r\n1\r\n \r\nA\r\n0123456789\r\n0\r\nX-Trailer: 1\r\nY: 2\r\n\r\n";
	static const char CLOSED[] = "HTTP/1.0 200 OK\r\nContent-Type: a/b\r\n\r\nuntil the end";
	static const char SHORT[] = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
	static const char BADCH[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n";
	static const char BADCH2[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX";
	static const char BADLINE[] = "garbage\r\n\r\n";
	static const char BADCL[] = "HTTP/1.1 200 OK\r\nContent-Length: 12x\r\n\r\n";
	static const char BIGCL[] = "HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\nxxx";
	static const char NOTHTTP[] = "SSH-2.0-x\r\n\r\n";
	char big[9000];
	struct http_opts o;

	for (i = 0; i < 4; i++) {
		hfix_init(&f);
		memset(&m, 0, sizeof(m));
		m.step = i == 1 ? 1 : i == 2 ? 3 : 0;
		m.eof = true;
		m.d = (const uint8_t *)CHUNKED; m.n = strlen(CHUNKED);
		mock_respond(&f.mn, &m);
		hget(&f, "http://[2001:db8::1]/c", "");
		spin(i == 1 ? 600 : 100);
		CHECK_EQ(f.r.calls, 1); CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.len, 16); CHECK(!memcmp(f.r.body, "hello 0123456789", 16));
		CHECK_STR(f.r.ctype, "a/b");
		hfix_fini(&f);
	}
	/* close delimited, and chunked without a closing connection (the end is in the data) */
	hfix_init(&f);
	memset(&m, 0, sizeof(m));
	m.eof = true; m.d = (const uint8_t *)CLOSED; m.n = strlen(CLOSED);
	mock_respond(&f.mn, &m);
	hget(&f, "http://[2001:db8::1]/c", ""); spin(50);
	CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.len, 13); CHECK(!memcmp(f.r.body, "until the end", 13));
	memset(&m, 0, sizeof(m));
	m.d = (const uint8_t *)CHUNKED; m.n = strlen(CHUNKED);		/* no eof: still complete */
	mock_respond(&f.mn, &m);
	hget(&f, "http://[2001:db8::1]/c", ""); spin(50);
	CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.len, 16);
	hfix_fini(&f);

	/* errors in the stream */
	{
		const struct { const char *d; bool eof; int err; } T[] = {
			{ SHORT, true, HTTP_E_IO },			/* closed before Content-Length bytes */
			{ BADCH, false, HTTP_E_PROTO },
			{ BADCH2, false, HTTP_E_PROTO },
			{ BADLINE, true, HTTP_E_PROTO },
			{ BADCL, false, HTTP_E_PROTO },
			{ NOTHTTP, true, HTTP_E_PROTO },
			{ BIGCL, false, HTTP_E_TOOBIG },
			{ "", true, HTTP_E_IO },			/* closed without a response */
			{ "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n", true, HTTP_E_IO },	/* closed inside the headers */
		};
		size_t k;

		for (k = 0; k < sizeof(T) / sizeof(T[0]); k++) {
			hfix_init(&f);
			memset(&m, 0, sizeof(m));
			m.d = (const uint8_t *)T[k].d; m.n = strlen(T[k].d); m.eof = T[k].eof;
			mock_respond(&f.mn, &m);
			memset(&o, 0, sizeof(o));
			o.method = "GET"; o.url = "http://[2001:db8::1]/e"; o.max_body = 1000;
			http_request(f.h, &f.b, &o, http_cb_rec, &f.r);
			spin(60);
			CHECK_EQ(f.r.calls, 1);
			CHECK_EQ(f.r.err, T[k].err);
			CHECK_EQ(f.r.len, 0);
			hfix_fini(&f);
		}
	}
	/* an oversized body: Content-Length rejects early (before the body is read), chunked and close delimited while reading */
	hfix_init(&f);
	memset(big, 'x', sizeof(big));
	memset(&m, 0, sizeof(m));
	{
		static uint8_t r1[9300], r2[9400], r3[9400];
		int h1 = snprintf((char *)r1, sizeof(r1), "HTTP/1.1 200 OK\r\nContent-Length: 9000\r\n\r\n");
		int h2 = snprintf((char *)r2, sizeof(r2), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2328\r\n");
		int h3 = snprintf((char *)r3, sizeof(r3), "HTTP/1.1 200 OK\r\n\r\n");

		memcpy(r1 + h1, big, 9000);
		memcpy(r2 + h2, big, 9000);
		memcpy(r3 + h3, big, 9000);
		m.d = r1; m.n = (size_t)h1 + 10; mock_respond(&f.mn, &m);	/* only the head and a few bytes: refused on the header */
		m.d = r2; m.n = (size_t)h2 + 9000; mock_respond(&f.mn, &m);
		m.d = r3; m.n = (size_t)h3 + 9000; mock_respond(&f.mn, &m);
		memset(&o, 0, sizeof(o));
		o.method = "GET"; o.url = "http://[2001:db8::1]/b"; o.max_body = 8192;
		http_request(f.h, &f.b, &o, http_cb_rec, &f.r); spin(80);
		CHECK_EQ(f.r.err, HTTP_E_TOOBIG); CHECK_EQ(f.r.status, 200);
		http_request(f.h, &f.b, &o, http_cb_rec, &f.r); spin(80);
		CHECK_EQ(f.r.err, HTTP_E_TOOBIG);
		http_request(f.h, &f.b, &o, http_cb_rec, &f.r); spin(80);
		CHECK_EQ(f.r.err, HTTP_E_TOOBIG);
		/* exactly at the limit is fine */
		o.max_body = 9000;
		f.mn.n_responses = 0;
		m.d = r1; m.n = (size_t)h1 + 9000; f.mn.responses[3] = m; f.mn.n_responses = 4;
		http_request(f.h, &f.b, &o, http_cb_rec, &f.r); spin(80);
		CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.len, 9000);
	}
	hfix_fini(&f);
}

static void t_http_redirect_post(void)
{
	struct hfix f;
	struct mock_resp m;
	static const char R302[] = "HTTP/1.1 302 Found\r\nLocation: /moved?x=1\r\nContent-Length: 0\r\n\r\n";
	static const char R301[] = "HTTP/1.1 301 Moved\r\nLocation: http://[2001:db8::2]:8080/final\r\nContent-Length: 0\r\n\r\n";
	static const char R200[] = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nend";
	static const char RHTTPS[] = "HTTP/1.1 302 Found\r\nLocation: https://x.example/\r\n\r\n";
	static const char RREL[] = "HTTP/1.1 302 Found\r\nLocation: relative/path\r\n\r\n";
	struct http_opts o;
	int k;

	hfix_init(&f);
	memset(&m, 0, sizeof(m));
	m.d = (const uint8_t *)R302; m.n = strlen(R302); mock_respond(&f.mn, &m);
	m.d = (const uint8_t *)R301; m.n = strlen(R301); mock_respond(&f.mn, &m);
	m.d = (const uint8_t *)R200; m.n = strlen(R200); mock_respond(&f.mn, &m);
	hget(&f, "http://[2001:db8::1]:9095/start", "X-Test: 1\r\n");
	spin(100);
	CHECK_EQ(f.r.calls, 1); CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.status, 200); CHECK_EQ(f.r.len, 3);
	CHECK_EQ(f.mn.n_conn, 3);
	CHECK(strstr(mock_req(&f.mn, 1), "GET /moved?x=1 HTTP/1.1\r\nHost: [2001:db8::1]:9095\r\nX-Test: 1\r\n") != NULL);
	CHECK(strstr(mock_req(&f.mn, 2), "GET /final HTTP/1.1\r\nHost: [2001:db8::2]:8080\r\n") != NULL);
	CHECK_EQ(addr_port(&f.mn.conn[2].dst), 8080);
	CHECK_STR(f.mn.conn[2].netdev, "wwan0");		/* every hop is bound the same way */
	CHECK_STR(f.r.url, "http://[2001:db8::2]:8080/final");
	hfix_fini(&f);

	/* a loop: three redirects are followed, the fourth is an error */
	hfix_init(&f);
	memset(&m, 0, sizeof(m));
	m.d = (const uint8_t *)R302; m.n = strlen(R302);
	for (k = 0; k < 6; k++)
		mock_respond(&f.mn, &m);
	hget(&f, "http://[2001:db8::1]/start", ""); spin(200);
	CHECK_EQ(f.r.err, HTTP_E_REDIRECT); CHECK_EQ(f.mn.n_conn, 4);
	hfix_fini(&f);

	/* a redirect to https and a relative path without a slash are not followed */
	hfix_init(&f);
	memset(&m, 0, sizeof(m));
	m.d = (const uint8_t *)RHTTPS; m.n = strlen(RHTTPS); mock_respond(&f.mn, &m);
	m.d = (const uint8_t *)RREL; m.n = strlen(RREL); mock_respond(&f.mn, &m);
	hget(&f, "http://[2001:db8::1]/a", ""); spin(60);
	CHECK_EQ(f.r.err, HTTP_E_UNSUPPORTED);
	hget(&f, "http://[2001:db8::1]/a", ""); spin(60);
	CHECK_EQ(f.r.err, HTTP_E_REDIRECT);
	hfix_fini(&f);

	/* POST: headers, Content-Length, body bytes; a 302 to a POST is returned as it is */
	hfix_init(&f);
	memset(&m, 0, sizeof(m));
	m.d = (const uint8_t *)R302; m.n = strlen(R302); mock_respond(&f.mn, &m);
	m.d = (const uint8_t *)R200; m.n = strlen(R200); mock_respond(&f.mn, &m);
	memset(&o, 0, sizeof(o));
	o.method = "POST"; o.url = "http://[2001:db8::1]:9084/"; o.headers = "Content-Type: application/vnd.wap.mms-message\r\n";
	o.body = (const uint8_t *)"\x8c\x83\x00\xff"; o.body_len = 4;
	http_request(f.h, &f.b, &o, http_cb_rec, &f.r); spin(60);
	CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.status, 302);
	CHECK(!strncmp(mock_req(&f.mn, 0), "POST / HTTP/1.1\r\nHost: [2001:db8::1]:9084\r\nContent-Type: application/vnd.wap.mms-message\r\nContent-Length: 4\r\nConnection: close\r\n\r\n", 140 - 140 + 130));
	{
		size_t bn;
		const uint8_t *bd = mock_req_body(&f.mn, 0, &bn);

		CHECK_EQ(bn, 4); CHECK(bd && !memcmp(bd, "\x8c\x83\x00\xff", 4));
	}
	CHECK_EQ(f.mn.n_conn, 1);
	/* body sizes and methods are checked */
	o.body_len = HTTP_MAX_REQ_BODY + 1;
	CHECK(http_request(f.h, &f.b, &o, http_cb_rec, &f.r) == NULL);
	o.body_len = 4; o.method = "PUT";
	CHECK(http_request(f.h, &f.b, &o, http_cb_rec, &f.r) == NULL);
	hfix_fini(&f);
}

static void t_http_failures(void)
{
	struct hfix f;
	struct mock_resp m;
	struct http_opts o;
	struct http_url u;
	struct http_req *r;
	static const char R200[] = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nend";

	/* URLs */
	CHECK_EQ(http_parse_url("http://a.b:81/p?q#f", &u), 0); CHECK_STR(u.host, "a.b"); CHECK_EQ(u.port, 81); CHECK_STR(u.path, "/p?q");
	CHECK_EQ(http_parse_url("HTTP://[::1]/", &u), 0); CHECK_STR(u.host, "::1"); CHECK_EQ(u.port, 80);
	CHECK_EQ(http_parse_url("http://h?x=1", &u), 0); CHECK_STR(u.path, "/?x=1");
	CHECK_EQ(http_parse_url("http://h", &u), 0); CHECK_STR(u.path, "/");
	CHECK_EQ(http_parse_url("https://h/", &u), HTTP_E_UNSUPPORTED); CHECK(u.https); CHECK_EQ(u.port, 443);
	CHECK_EQ(http_parse_url("ftp://h/", &u), HTTP_E_UNSUPPORTED);
	CHECK_EQ(http_parse_url("h/", &u), HTTP_E_URL);
	CHECK_EQ(http_parse_url("http://", &u), HTTP_E_URL);
	CHECK_EQ(http_parse_url("http://:80/", &u), HTTP_E_URL);
	CHECK_EQ(http_parse_url("http://h:/", &u), HTTP_E_URL);
	CHECK_EQ(http_parse_url("http://h:0/", &u), HTTP_E_URL);
	CHECK_EQ(http_parse_url("http://h:70000/", &u), HTTP_E_URL);
	CHECK_EQ(http_parse_url("http://h:8x/", &u), HTTP_E_URL);
	CHECK_EQ(http_parse_url("http://u:p@h/", &u), HTTP_E_URL);
	CHECK_EQ(http_parse_url("http://[::1/", &u), HTTP_E_URL);
	CHECK_EQ(http_parse_url("http://[::1]x/", &u), HTTP_E_URL);
	CHECK_EQ(http_parse_url("http://h/a b", &u), HTTP_E_URL);
	CHECK_EQ(http_parse_url("http://h /", &u), HTTP_E_URL);

	/* https and a bad URL are reported through the callback, asynchronously */
	hfix_init(&f);
	r = hget(&f, "https://secure.example/m", "");
	CHECK(r != NULL); CHECK_EQ(f.r.calls, 0);
	spin(5);
	CHECK_EQ(f.r.err, HTTP_E_UNSUPPORTED); CHECK_EQ(f.mn.n_conn, 0); CHECK_EQ(f.mn.n_usent, 0);
	hget(&f, "http://", ""); spin(5);
	CHECK_EQ(f.r.err, HTTP_E_URL);
	{
		char longu[HTTP_MAX_URL + 50];

		memset(longu, 'a', sizeof(longu)); memcpy(longu, "http://h/", 9); longu[sizeof(longu) - 1] = 0;
		hget(&f, longu, ""); spin(5);
		CHECK_EQ(f.r.err, HTTP_E_URL);
	}
	hfix_fini(&f);

	/* name resolution failures: NXDOMAIN, a link that is gone */
	hfix_init(&f);
	{
		struct mock_dns_rule rule;

		memset(&rule, 0, sizeof(rule));
		rule.name = "gone.test"; rule.type = 28; rule.rcode = 3;
		mock_dns_add(&f.mn, &rule);
	}
	hget(&f, "http://gone.test/", ""); spin(40);
	CHECK_EQ(f.r.err, HTTP_E_DNS); CHECK_EQ(f.r.sub_err, -ENOENT); CHECK_EQ(f.mn.n_conn, 0);
	hfix_fini(&f);

	/* connect: refused on the first address, the second one works; all refused; timeout while pending; send nothing */
	hfix_init(&f);
	{
		struct mock_dns_rule rule;

		memset(&rule, 0, sizeof(rule));
		rule.name = "two.test"; rule.type = 28; rule.ttl = 30; rule.n = 2;
		rule.addr[0] = A("2001:db8::1"); rule.addr[1] = A("2001:db8::2");
		mock_dns_add(&f.mn, &rule);
	}
	memset(&m, 0, sizeof(m));
	m.connect_rc = -ECONNREFUSED; m.d = (const uint8_t *)R200; m.n = strlen(R200); mock_respond(&f.mn, &m);
	m.connect_rc = 0; mock_respond(&f.mn, &m);
	hget(&f, "http://two.test/x", ""); spin(60);
	CHECK_EQ(f.r.err, 0); CHECK_EQ(f.r.status, 200); CHECK_EQ(f.mn.n_conn, 2);
	mock_reset_conns(&f.mn);
	m.connect_rc = -ECONNREFUSED; mock_respond(&f.mn, &m); mock_respond(&f.mn, &m);
	hget(&f, "http://two.test/x", ""); spin(60);
	CHECK_EQ(f.r.err, HTTP_E_CONNECT); CHECK_EQ(f.r.sub_err, -ECONNREFUSED);
	/* tcp_connect itself fails (no route) */
	mock_reset_conns(&f.mn); f.mn.tcp_open_fail_n = 5; f.mn.tcp_open_rc = -ENETUNREACH;
	hget(&f, "http://two.test/x", ""); spin(60);
	CHECK_EQ(f.r.err, HTTP_E_CONNECT); CHECK_EQ(f.r.sub_err, -ENETUNREACH);
	f.mn.tcp_open_fail_n = 0;
	hfix_fini(&f);

	/* timeouts: connect never completes (idle), no answer to the request (idle), overall limit with trickling data */
	hfix_init(&f);
	memset(&m, 0, sizeof(m));
	m.connect_rc = -EINPROGRESS;
	mock_respond(&f.mn, &m);
	hget(&f, "http://[2001:db8::1]/x", "");
	advance(19000); CHECK_EQ(f.r.calls, 0);
	advance(2000); CHECK_EQ(f.r.calls, 1); CHECK_EQ(f.r.err, HTTP_E_TIMEOUT);
	memset(&m, 0, sizeof(m));
	m.silent = true;
	mock_respond(&f.mn, &m);	/* conn index 1 */
	memset(&o, 0, sizeof(o));
	o.method = "GET"; o.url = "http://[2001:db8::1]/x"; o.idle_ms = 3000;
	http_request(f.h, &f.b, &o, http_cb_rec, &f.r);
	advance(2500); CHECK_EQ(f.r.calls, 1);
	advance(1000); CHECK_EQ(f.r.calls, 2); CHECK_EQ(f.r.err, HTTP_E_TIMEOUT);
	/* overall: a server that dribbles one byte per second never finishes within 5 s */
	{
		static const char SLOW[] = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
		static uint8_t slow[1100];
		int i;

		memcpy(slow, SLOW, strlen(SLOW));
		memset(slow + strlen(SLOW), 'x', 1000);
		memset(&m, 0, sizeof(m));
		m.d = slow; m.n = strlen(SLOW) + 1000; m.step = 1;
		mock_respond(&f.mn, &m);	/* conn 2: delivers, but we stop spinning the fds and only advance time */
		memset(&o, 0, sizeof(o));
		o.method = "GET"; o.url = "http://[2001:db8::1]/x"; o.timeout_ms = 5000; o.idle_ms = 3000;
		hres_clear(&f.r);
		http_request(f.h, &f.b, &o, http_cb_rec, &f.r);
		for (i = 0; i < 8 && !f.r.calls; i++) {
			evfake_advance(1000);
			evfake_poll_fds();	/* one callback per second: 16 reads of 1 byte at most, never complete */
		}
		CHECK_EQ(f.r.calls, 1); CHECK_EQ(f.r.err, HTTP_E_TIMEOUT);
	}
	hfix_fini(&f);

	/* cancel: no callback, the connection is closed; http_free with requests in flight */
	hfix_init(&f);
	memset(&m, 0, sizeof(m));
	m.silent = true;
	mock_respond(&f.mn, &m);
	r = hget(&f, "http://[2001:db8::1]/x", ""); spin(10);
	CHECK_EQ(f.mn.n_conn, 1);
	http_cancel(r);
	advance(30000);
	CHECK_EQ(f.r.calls, 0); CHECK(f.mn.conn[0].closed);
	mock_respond(&f.mn, &m);
	hget(&f, "http://[2001:db8::1]/x", ""); spin(5);
	hget(&f, "http://[2001:db8::1]/x", "");	/* never started */
	hfix_fini(&f);
}

/* mutated responses: whatever arrives, the request ends exactly once (an answer or an error), nothing is left behind */
static void t_http_fuzz(void)
{
	static const char CL[] = "HTTP/1.1 200 OK\r\nServer: x\r\nContent-Type: application/vnd.wap.mms-message\r\nContent-Length: 20\r\n\r\n01234567890123456789";
	static const char CH[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=1\r\nhello\r\n0a\r\n0123456789\r\n0\r\nT: 1\r\n\r\n";
	static const char RD[] = "HTTP/1.1 302 Found\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n";
	const char *base[3] = { CL, CH, RD };
	uint64_t x = 88172645463325252ull;
	int it;

	for (it = 0; it < 600; it++) {
		struct hfix f;
		struct mock_resp m;
		uint8_t buf[300];
		const char *b = base[it % 3];
		size_t n = strlen(b), k, nm;

		x ^= x << 13; x ^= x >> 7; x ^= x << 17;
		memcpy(buf, b, n);
		nm = 1 + (x % 3);
		for (k = 0; k < nm; k++) {
			x ^= x << 13; x ^= x >> 7; x ^= x << 17;
			buf[x % n] = (uint8_t)(x >> 20);
		}
		hfix_init(&f);
		memset(&m, 0, sizeof(m));
		m.d = buf; m.n = n;
		m.step = 1 + (x >> 8) % 40;
		m.eof = (x >> 16) & 1;
		mock_respond(&f.mn, &m);
		mock_respond(&f.mn, &m);	/* a redirect target */
		hget(&f, "http://[2001:db8::1]/f", "");
		advance(25000);
		CHECK_EQ(f.r.calls, 1);
		hfix_fini(&f);
	}
}

/* ------------------------------------------------------------------ */
/* loopback: real sockets, a DNS responder and an HTTP server in the test */

struct lsrv {
	int dfd;			/* UDP DNS responder */
	struct addr daddr;
	int lfd, cfd;			/* TCP listener, accepted connection */
	struct addr laddr;
	char in[8192];
	size_t n;
	int dns_queries, conns;
	size_t out_pos;
	const uint8_t *out;
	size_t out_len;
	size_t piece;			/* bytes written per step */
	char last_req[2048];
	bool redirect_a;
	uint8_t resp[3000];
	int mode;
};

static int lsrv_open(struct lsrv *s, bool v6)
{
	struct sockaddr_in6 a6;
	struct sockaddr_in a4;
	socklen_t l;
	int one = 1;

	memset(s, 0, sizeof(*s));
	s->dfd = s->cfd = -1;
	if (v6) {
		memset(&a6, 0, sizeof(a6));
		a6.sin6_family = AF_INET6;
		a6.sin6_addr = in6addr_loopback;
		s->dfd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		s->lfd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
		if (s->dfd < 0 || s->lfd < 0 || bind(s->dfd, (struct sockaddr *)&a6, sizeof(a6)) ||
		    (setsockopt(s->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)), bind(s->lfd, (struct sockaddr *)&a6, sizeof(a6))) ||
		    listen(s->lfd, 4))
			return -1;
		l = sizeof(a6);
		getsockname(s->dfd, (struct sockaddr *)&a6, &l);
		addr_from_sa6(&s->daddr, &a6);
		l = sizeof(a6);
		getsockname(s->lfd, (struct sockaddr *)&a6, &l);
		addr_from_sa6(&s->laddr, &a6);
	} else {
		memset(&a4, 0, sizeof(a4));
		a4.sin_family = AF_INET;
		a4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		s->dfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		s->lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
		if (s->dfd < 0 || s->lfd < 0 || bind(s->dfd, (struct sockaddr *)&a4, sizeof(a4)) || bind(s->lfd, (struct sockaddr *)&a4, sizeof(a4)) ||
		    listen(s->lfd, 4))
			return -1;
		l = sizeof(a4);
		getsockname(s->dfd, (struct sockaddr *)&a4, &l);
		addr_set_v4(&s->daddr, a4.sin_addr.s_addr, ntohs(a4.sin_port));
		l = sizeof(a4);
		getsockname(s->lfd, (struct sockaddr *)&a4, &l);
		addr_set_v4(&s->laddr, a4.sin_addr.s_addr, ntohs(a4.sin_port));
	}
	return 0;
}

static void lsrv_close(struct lsrv *s)
{
	if (s->dfd >= 0)
		close(s->dfd);
	if (s->lfd >= 0)
		close(s->lfd);
	if (s->cfd >= 0)
		close(s->cfd);
}

/* serve the DNS name "mmsc.test" -> the listener's address, and HTTP by mode */
static void lsrv_step(struct lsrv *s, bool v6)
{
	uint8_t q[600], r[700];
	struct sockaddr_storage from;
	socklen_t fl = sizeof(from);
	ssize_t n = recvfrom(s->dfd, q, sizeof(q), MSG_DONTWAIT, (struct sockaddr *)&from, &fl);

	if (n > 0) {
		char name[100];
		int type;
		unsigned id;

		s->dns_queries++;
		if (!dns_qinfo(q, (size_t)n, name, sizeof(name), &type, &id) && !strcmp(name, "mmsc.test")) {
			struct dns_rr_spec rr[1];
			uint8_t raw[16];
			size_t rl;
			int want = v6 ? 28 : 1;

			memset(rr, 0, sizeof(rr));
			if (type == want) {
				if (v6)
					memcpy(raw, in6addr_loopback.s6_addr, 16);
				else
					memcpy(raw, "\x7f\x00\x00\x01", 4);
				rr[0].type = type; rr[0].ttl = 30; rr[0].rdata = raw; rr[0].rdlen = v6 ? 16 : 4; rr[0].owner_ref = -1;
				rl = dns_response(q, (size_t)n, 0, false, rr, 1, r, sizeof(r));
			} else {
				rl = dns_response(q, (size_t)n, 0, false, NULL, 0, r, sizeof(r));	/* NODATA */
			}
			sendto(s->dfd, r, rl, 0, (struct sockaddr *)&from, fl);
		}
	}
	if (s->cfd < 0) {
		s->cfd = accept4(s->lfd, NULL, NULL, SOCK_NONBLOCK);
		if (s->cfd >= 0) {
			s->conns++;
			s->n = 0;
			s->in[0] = 0;
			s->out = NULL;
			s->out_pos = 0;
		}
	}
	if (s->cfd >= 0) {
		if (!s->out) {
			n = read(s->cfd, s->in + s->n, sizeof(s->in) - 1 - s->n);
			if (n > 0) {
				s->n += (size_t)n;
				s->in[s->n] = 0;
			}
			if (strstr(s->in, "\r\n\r\n")) {
				const char *cl = strcasestr(s->in, "Content-Length:");
				const char *body = strstr(s->in, "\r\n\r\n") + 4;

				if (!cl || s->in + s->n - body >= atoi(cl + 15)) {
					snprintf(s->last_req, sizeof(s->last_req), "%.2000s", s->in);
					if (s->mode == 1 && !strncmp(s->in, "GET /a ", 7)) {
						static const char R[] = "HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n";

						memcpy(s->resp, R, sizeof(R) - 1);
						s->out_len = sizeof(R) - 1;
					} else if (s->mode == 2) {
						static const char R[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";

						memcpy(s->resp, R, sizeof(R) - 1);
						s->out_len = sizeof(R) - 1;
					} else {
						int h = snprintf((char *)s->resp, sizeof(s->resp), "HTTP/1.1 200 OK\r\nContent-Length: 2000\r\n\r\n");
						size_t i;

						for (i = 0; i < 2000; i++)
							s->resp[h + i] = (uint8_t)('a' + i % 26);
						s->out_len = (size_t)h + 2000;
					}
					s->out = s->resp;
					s->out_pos = 0;
				}
			}
		}
		if (s->out) {
			size_t c = s->out_len - s->out_pos;

			if (s->piece && c > s->piece)
				c = s->piece;
			if (c) {
				ssize_t w = write(s->cfd, s->out + s->out_pos, c);

				if (w > 0)
					s->out_pos += (size_t)w;
			}
			if (s->out_pos >= s->out_len) {
				close(s->cfd);
				s->cfd = -1;
				s->out = NULL;
			}
		}
	}
}

static void loop_until(struct lsrv *s, bool v6, struct hres *r, int calls)
{
	int i;

	for (i = 0; i < 4000 && r->calls < calls; i++) {
		lsrv_step(s, v6);
		evfake_poll_fds();
		evfake_advance(0);
		if (i % 8 == 7)
			usleep(200);
	}
}

static void t_loopback(void)
{
	bool v6;

	for (v6 = true;; v6 = false) {
		struct lsrv s;
		struct dns *d;
		struct http *h;
		struct dns_bind b;
		struct hres r;
		struct http_opts o;
		char url[200], lh[64];

		if (lsrv_open(&s, v6)) {
			printf("(loopback %s unavailable, skipped)\n", v6 ? "IPv6" : "IPv4");
			lsrv_close(&s);
			if (!v6)
				break;
			continue;
		}
		evfake_reset();
		memset(&r, 0, sizeof(r));
		d = dns_new(net_real_ops());
		h = http_new(net_real_ops(), d);
		memset(&b, 0, sizeof(b));
		addr_set(&b.local, v6 ? "::1" : "127.0.0.1", 0);
		b.server[0] = s.daddr;
		b.n_server = 1;
		addr_host(&s.laddr, lh, sizeof(lh));

		/* a literal address with a Content-Length body delivered in small pieces */
		s.piece = 97;
		snprintf(url, sizeof(url), v6 ? "http://[%s]:%u/lit?x=1" : "http://%s:%u/lit?x=1", lh, addr_port(&s.laddr));
		memset(&o, 0, sizeof(o));
		o.method = "GET"; o.url = url; o.headers = ACCEPT_UA;
		http_request(h, &b, &o, http_cb_rec, &r);
		loop_until(&s, v6, &r, 1);
		CHECK_EQ(r.calls, 1); CHECK_EQ(r.err, 0); CHECK_EQ(r.status, 200); CHECK_EQ(r.len, 2000);
		CHECK(r.len == 2000 && r.body[0] == 'a' && r.body[1999] == (uint8_t)('a' + 1999 % 26));
		CHECK(!strncmp(s.last_req, "GET /lit?x=1 HTTP/1.1\r\nHost: ", 28));
		CHECK(strstr(s.last_req, "\r\nUser-Agent: TTA-VoLTE/3.0") != NULL); CHECK(strstr(s.last_req, "\r\nConnection: close\r\n\r\n") != NULL);
		CHECK_EQ(s.dns_queries, 0);

		/* a name: the resolver asks the responder (AAAA, then A for an IPv4 bearer), then the connection follows */
		snprintf(url, sizeof(url), "http://mmsc.test:%u/byname", addr_port(&s.laddr));
		o.url = url;
		http_request(h, &b, &o, http_cb_rec, &r);
		loop_until(&s, v6, &r, 2);
		CHECK_EQ(r.calls, 2); CHECK_EQ(r.err, 0); CHECK_EQ(r.status, 200); CHECK_EQ(r.len, 2000);
		CHECK_EQ(s.dns_queries, 1);
		CHECK(!strncmp(s.last_req, "GET /byname HTTP/1.1\r\n", 22));

		/* redirect handled by the server, chunked response */
		s.mode = 1;
		snprintf(url, sizeof(url), "http://mmsc.test:%u/a", addr_port(&s.laddr));
		o.url = url;
		s.mode = 2;
		http_request(h, &b, &o, http_cb_rec, &r);
		loop_until(&s, v6, &r, 3);
		CHECK_EQ(r.calls, 3); CHECK_EQ(r.err, 0); CHECK_EQ(r.len, 9); CHECK(!memcmp(r.body, "Wikipedia", 9));
		s.mode = 1;
		{	/* /a -> 302 /b -> (mode 1 answers /b with the 2000 byte body) */
			snprintf(url, sizeof(url), "http://mmsc.test:%u/a", addr_port(&s.laddr));
			http_request(h, &b, &o, http_cb_rec, &r);
			loop_until(&s, v6, &r, 4);
			CHECK_EQ(r.calls, 4); CHECK_EQ(r.err, 0); CHECK_EQ(r.len, 2000); CHECK(!strncmp(s.last_req, "GET /b ", 7));
		}
		/* POST with a body */
		s.mode = 0;
		memset(&o, 0, sizeof(o));
		snprintf(url, sizeof(url), "http://mmsc.test:%u/", addr_port(&s.laddr));
		o.method = "POST"; o.url = url; o.headers = "Content-Type: application/vnd.wap.mms-message\r\n";
		o.body = (const uint8_t *)"\x8c\x83\x98ID\x00"; o.body_len = 6;
		http_request(h, &b, &o, http_cb_rec, &r);
		loop_until(&s, v6, &r, 5);
		CHECK_EQ(r.calls, 5); CHECK_EQ(r.err, 0);
		CHECK(!strncmp(s.last_req, "POST / HTTP/1.1\r\nHost: mmsc.test:", 33));
		CHECK(strstr(s.last_req, "Content-Type: application/vnd.wap.mms-message\r\nContent-Length: 6\r\nConnection: close\r\n\r\n\x8c\x83") != NULL);
		/* nothing listening any more: connection refused */
		lsrv_close(&s);
		s.lfd = s.dfd = s.cfd = -1;
		snprintf(url, sizeof(url), v6 ? "http://[%s]:%u/gone" : "http://%s:%u/gone", lh, addr_port(&s.laddr));
		memset(&o, 0, sizeof(o));
		o.method = "GET"; o.url = url;
		http_request(h, &b, &o, http_cb_rec, &r);
		{
			int i;

			for (i = 0; i < 400 && r.calls < 6; i++) {
				evfake_poll_fds();
				evfake_advance(0);
				usleep(200);
			}
		}
		CHECK_EQ(r.calls, 6); CHECK_EQ(r.err, HTTP_E_CONNECT);
		http_free(h);
		dns_free(d);
		hres_clear(&r);
		if (!v6)
			break;
	}
}

void test_mms_net(void)
{
	t_dns_wire();
	t_dns_mock();
	t_http_basic();
	t_http_bodies();
	t_http_redirect_post();
	t_http_failures();
	t_http_fuzz();
	t_loopback();
}
