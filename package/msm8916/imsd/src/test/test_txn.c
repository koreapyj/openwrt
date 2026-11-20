/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdlib.h>
#include <errno.h>
#include "test.h"
#include "fakeep.h"
#include "evloop_fake.h"
#include "../sip/txn.h"

/* ---------------- helpers ---------------- */

struct rec {
	int ev[32], nev;
	int status[32], nresp;
	struct sip_endpoint *rx_ep[32];
	struct txn_client *c;
	/* server side */
	struct txn_server *st;
	int nreq, nack;		/* requests with / without a transaction */
	int cancelled, timeout, terminated;
	int stray;
	int giveups;
	char reason[200];	/* txn_server_cancel_reason seen inside TXN_SRV_CANCELLED */
};

static void cli_cb(struct txn_client *c, enum txn_cli_event ev, const struct sip_msg *resp, struct sip_endpoint *rx_ep,
		   const struct addr *src, void *arg)
{
	struct rec *r = arg;

	(void)c; (void)src;
	if (r->nev < 32)
		r->ev[r->nev++] = ev;
	if (ev == TXN_CLI_RESPONSE && r->nresp < 32) {
		r->status[r->nresp] = resp->status;
		r->rx_ep[r->nresp++] = rx_ep;
	}
}

static void srv_cb(struct txn_server *st, enum txn_srv_event ev, void *arg)
{
	struct rec *r = arg;

	if (ev == TXN_SRV_CANCELLED) {
		r->cancelled++;
		snprintf(r->reason, sizeof(r->reason), "%s", txn_server_cancel_reason(st));
	}
	if (ev == TXN_SRV_TIMEOUT) r->timeout++;
	if (ev == TXN_SRV_TERMINATED) r->terminated++;
}

static void req_cb(struct txn_layer *tl, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
		   const struct sip_msg *req, void *arg)
{
	struct rec *r = arg;

	(void)tl; (void)ep; (void)src; (void)req;
	if (!st) {
		r->nack++;
		return;
	}
	r->nreq++;
	r->st = st;
	txn_server_set_cb(st, srv_cb, r);
}

static void stray_cb(struct txn_layer *tl, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *resp, void *arg)
{
	struct rec *r = arg;

	(void)tl; (void)ep; (void)src; (void)resp;
	r->stray++;
}

static void giveup_cb(struct sip_rtx *x, void *arg)
{
	struct rec *r = arg;

	(void)x;
	r->giveups++;
}

static struct txn_layer *mk_layer(struct rec *r, bool auto100, unsigned max)
{
	struct txn_cfg c;

	memset(&c, 0, sizeof(c));
	c.auto_100 = auto100;
	c.max_txns = max;
	c.on_request = req_cb;
	c.on_stray_response = stray_cb;
	c.arg = r;
	return txn_layer_new(&c);
}

static struct addr A(const char *ip, int port)
{
	struct addr a;

	addr_set(&a, ip, port);
	return a;
}

static char *mkreq(const char *method, const char *branch, int cseq, const char *via_host, const char *extra)
{
	static char bufs[8][1500];
	static int k;
	char *b = bufs[k++ & 7];

	snprintf(b, 1500, "%s sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP %s;branch=%s\r\n"
		 "From: <sip:alice@example.com>;tag=ft\r\nTo: <sip:bob@example.com>\r\nCall-ID: cid-%s\r\nCSeq: %d %s\r\n"
		 "Max-Forwards: 70\r\n%sContent-Length: 0\r\n\r\n", method, via_host, branch, branch, cseq, method, extra ? extra : "");
	return b;
}

static struct txn_client *start(struct txn_layer *tl, struct fakeep *f, const char *req, struct rec *r)
{
	struct txn_client_req q;

	memset(&q, 0, sizeof(q));
	q.ep = f->ep;
	q.dst = A("2001:db8::2", 5060);
	q.data = (const uint8_t *)req;
	q.len = strlen(req);
	q.cb = cli_cb;
	q.arg = r;
	r->c = txn_client_start(tl, &q);
	return r->c;
}

/* response to sent[i] of tx, delivered on rx */
static void reply(struct fakeep *rx, const struct fakeep *tx, int i, int status, const char *to_tag)
{
	struct sip_msg m;
	struct sip_resp_parts p;
	struct buf b;
	struct addr src = A("2001:db8::2", 7000);

	CHECK(!fakeep_parse(tx, i, &m));
	memset(&p, 0, sizeof(p));
	p.status = status;
	p.to_tag = to_tag;
	buf_init(&b, 0);
	CHECK(!sip_build_response(&b, &m, &p));
	fakeep_rx_n(rx, &src, b.p, b.len);
	buf_free(&b);
	sip_msg_free(&m);
}

static const char *method_of(const struct fakeep *f, int i, char *out)
{
	struct sip_msg m;

	if (fakeep_parse(f, i, &m))
		return "?";
	strcpy(out, m.is_resp ? "resp" : m.method);
	sip_msg_free(&m);
	return out;
}

static int status_of(const struct fakeep *f, int i)
{
	struct sip_msg m;
	int s = 0;

	if (!fakeep_parse(f, i, &m)) {
		s = m.is_resp ? m.status : -1;
		sip_msg_free(&m);
	}
	return s;
}

/* ---------------- client, non-INVITE ---------------- */

static void t_client_noninvite(void)
{
	struct rec r = {0}, r2 = {0};
	struct txn_layer *tl;
	struct fakeep *f = fakeep_new("tx", false, NULL), *f2 = fakeep_new("rx", false, NULL);
	static const uint64_t sched[] = { 500, 1500, 3500, 7500, 11500, 15500, 19500, 23500, 27500, 31500 };
	uint64_t t = 0;
	size_t i;

	/* retransmission schedule: T1 doubling, capped at T2 (4 s); Timer F (64*T1 = 32 s) -> timeout */
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep); txn_layer_attach(tl, f2->ep);
	CHECK(start(tl, f, mkreq("OPTIONS", "z9hG4bKn1", 1, "[2001:db8::1]:5060", NULL), &r) != NULL);
	CHECK_EQ(f->nsent, 1);
	for (i = 0; i < sizeof(sched) / sizeof(sched[0]); i++) {
		evfake_advance(sched[i] - t - 1); t = sched[i] - 1;
		CHECK_EQ(f->nsent, (int)i + 1);
		evfake_advance(1); t++;
		CHECK_EQ(f->nsent, (int)i + 2);
	}
	CHECK_EQ(r.nev, 0);
	evfake_advance(32000 - t - 1);
	CHECK_EQ(r.nev, 0);
	evfake_advance(1);
	CHECK_EQ(r.nev, 2); CHECK_EQ(r.ev[0], TXN_CLI_TIMEOUT); CHECK_EQ(r.ev[1], TXN_CLI_TERMINATED);
	CHECK_EQ(f->nsent, 11);
	CHECK_EQ(txn_layer_count(tl), 0); CHECK_EQ(evfake_armed_timers(), 0);
	CHECK_EQ(f->ep->refs, 1);	/* the transaction released its endpoint reference */
	txn_layer_free(tl);
	fakeep_clear(f);

	/* a response arriving on ANOTHER endpoint's socket matches on branch + CSeq method; Timer K absorbs retransmissions */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep); txn_layer_attach(tl, f2->ep);
	start(tl, f, mkreq("OPTIONS", "z9hG4bKn2", 1, "[2001:db8::1]:5060", NULL), &r);
	evfake_advance(600);
	CHECK_EQ(f->nsent, 2);
	reply(f2, f, 0, 200, NULL);
	CHECK_EQ(r.nresp, 1); CHECK_EQ(r.status[0], 200); CHECK(r.rx_ep[0] == f2->ep);
	reply(f2, f, 0, 200, NULL);	/* retransmitted final: absorbed */
	CHECK_EQ(r.nresp, 1);
	evfake_advance(10000);
	CHECK_EQ(f->nsent, 2);		/* retransmissions stopped */
	CHECK_EQ(txn_layer_count(tl), 0);	/* Timer K (T4) ended it */
	txn_layer_free(tl);
	fakeep_clear(f);

	/* Timer K = T4 */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("OPTIONS", "z9hG4bKn3", 1, "[2001:db8::1]:5060", NULL), &r);
	reply(f, f, 0, 200, NULL);
	CHECK_EQ(txn_layer_count(tl), 1);
	evfake_advance(4999); CHECK_EQ(txn_layer_count(tl), 1);
	evfake_advance(1); CHECK_EQ(txn_layer_count(tl), 0); CHECK_EQ(r.ev[r.nev - 1], TXN_CLI_TERMINATED);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* provisional: retransmit every T2 from now on, then the final */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("OPTIONS", "z9hG4bKn4", 1, "[2001:db8::1]:5060", NULL), &r);
	evfake_advance(500);			/* 2nd transmission */
	reply(f, f, 0, 100, NULL);
	CHECK_EQ(r.nresp, 1); CHECK_EQ(r.status[0], 100);
	fakeep_clear(f);
	evfake_advance(3999); CHECK_EQ(f->nsent, 0);	/* E restarts at T2 from the provisional */
	evfake_advance(1); CHECK_EQ(f->nsent, 1);
	evfake_advance(4000); CHECK_EQ(f->nsent, 2);
	reply(f, f, 0, 200, NULL);
	CHECK_EQ(r.nresp, 2);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* reliable endpoint: no retransmissions, Timer F still runs, K = 0 */
	{
		struct fakeep *fr = fakeep_new("tcp", true, NULL);

		memset(&r, 0, sizeof(r));
		evfake_reset();
		tl = mk_layer(&r, false, 0);
		txn_layer_attach(tl, fr->ep);
		start(tl, fr, mkreq("OPTIONS", "z9hG4bKn5", 1, "[2001:db8::1]:5060", NULL), &r);
		evfake_advance(31999);
		CHECK_EQ(fr->nsent, 1); CHECK_EQ(r.nev, 0);
		evfake_advance(1); CHECK_EQ(r.ev[0], TXN_CLI_TIMEOUT);
		memset(&r, 0, sizeof(r));
		start(tl, fr, mkreq("OPTIONS", "z9hG4bKn6", 1, "[2001:db8::1]:5060", NULL), &r);
		reply(fr, fr, 1, 200, NULL);
		CHECK_EQ(r.nresp, 1); CHECK_EQ(txn_layer_count(tl), 1);
		evfake_advance(0); CHECK_EQ(txn_layer_count(tl), 0);	/* terminated on the next loop iteration */
		txn_layer_free(tl);
		fakeep_free(fr);
	}

	/* transport errors: hard error is reported asynchronously, EAGAIN just drops and retransmission recovers */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_clear(f);
	f->fail_errno = ENETUNREACH;
	CHECK(start(tl, f, mkreq("OPTIONS", "z9hG4bKn7", 1, "[2001:db8::1]:5060", NULL), &r) != NULL);
	CHECK_EQ(r.nev, 0);			/* never from inside txn_client_start */
	evfake_advance(0);
	CHECK_EQ(r.nev, 2); CHECK_EQ(r.ev[0], TXN_CLI_TRANSPORT_ERROR); CHECK_EQ(r.ev[1], TXN_CLI_TERMINATED);
	memset(&r, 0, sizeof(r));
	f->fail_errno = EAGAIN;
	start(tl, f, mkreq("OPTIONS", "z9hG4bKn8", 1, "[2001:db8::1]:5060", NULL), &r);
	evfake_advance(100); CHECK_EQ(r.nev, 0); CHECK_EQ(f->nsent, 0);
	f->fail_errno = 0;
	evfake_advance(400);
	CHECK_EQ(f->nsent, 1); CHECK_EQ(txn_client_retransmits(r.c), 1);
	reply(f, f, 0, 200, NULL); CHECK_EQ(r.nresp, 1);
	txn_layer_free(tl);

	/* limit, malformed requests */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 1);
	txn_layer_attach(tl, f->ep);
	CHECK(start(tl, f, mkreq("OPTIONS", "z9hG4bKn9", 1, "[2001:db8::1]:5060", NULL), &r) != NULL);
	CHECK(start(tl, f, mkreq("OPTIONS", "z9hG4bKn10", 1, "[2001:db8::1]:5060", NULL), &r2) == NULL);
	txn_layer_free(tl);
	tl = mk_layer(&r, false, 0);
	CHECK(start(tl, f, "SIP/2.0 200 OK\r\n\r\n", &r2) == NULL);
	CHECK(start(tl, f, "OPTIONS sip:a SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n", &r2) == NULL);	/* no Via/branch */
	txn_layer_free(tl);
	fakeep_free(f); fakeep_free(f2);
}

/* ---------------- client INVITE ---------------- */

static void t_client_invite(void)
{
	struct rec r = {0}, rc = {0};
	struct txn_layer *tl;
	struct fakeep *f = fakeep_new("tx", false, NULL);
	char mb[16];
	struct sip_msg m;
	static const char *routes = "Route: <sip:pcscf1.example.com;lr>\r\nRoute: <sip:[2001:db8::2]:5060;lr>\r\n";
	uint64_t t = 0;
	size_t i;
	static const uint64_t sched[] = { 500, 1500, 3500, 7500, 15500, 31500 };	/* Timer A doubles without a cap */

	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("INVITE", "z9hG4bKi1", 1, "[2001:db8::1]:5060", routes), &r);
	for (i = 0; i < sizeof(sched) / sizeof(sched[0]); i++) {
		evfake_advance(sched[i] - t); t = sched[i];
		CHECK_EQ(f->nsent, (int)i + 2);
	}
	evfake_advance(32000 - t);	/* Timer B */
	CHECK_EQ(f->nsent, 7);
	CHECK_EQ(r.nev, 2); CHECK_EQ(r.ev[0], TXN_CLI_TIMEOUT);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* 100 stops retransmission and Timer B; final 486 -> ACK by the transaction layer; retransmitted 486 -> ACK again; Timer D */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("INVITE", "z9hG4bKi2", 1, "[2001:db8::1]:5060", routes), &r);
	reply(f, f, 0, 100, NULL);
	evfake_advance(100000);
	CHECK_EQ(f->nsent, 1); CHECK_EQ(r.nev, 1);	/* silent: no Timer B in Proceeding */
	reply(f, f, 0, 180, "tt1");
	reply(f, f, 0, 486, "tt1");
	CHECK_EQ(r.nresp, 3); CHECK_EQ(r.status[2], 486);
	CHECK_EQ(f->nsent, 2);
	CHECK_STR(method_of(f, 1, mb), "ACK");
	CHECK(!fakeep_parse(f, 1, &m));
	CHECK_STR(m.ruri, "sip:bob@example.com");
	CHECK_STR(sip_hdr(&m, "CSeq", 0), "1 ACK");
	CHECK_STR(sip_hdr(&m, "To", 0), "<sip:bob@example.com>;tag=tt1");		/* To of the response */
	CHECK_STR(sip_hdr(&m, "Via", 0), "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKi2");	/* same branch as the INVITE */
	CHECK_EQ(sip_hdr_count(&m, "Route"), 2); CHECK_STR(sip_hdr(&m, "Route", 0), "<sip:pcscf1.example.com;lr>");
	CHECK_STR(sip_hdr(&m, "Call-ID", 0), "cid-z9hG4bKi2"); CHECK_STR(sip_hdr(&m, "Max-Forwards", 0), "70");
	sip_msg_free(&m);
	CHECK(f->sent[1].dst.sa.sin6_port == htons(5060));
	reply(f, f, 0, 486, "tt1");		/* retransmitted final: ACK again, TU not bothered */
	CHECK_EQ(f->nsent, 3); CHECK_EQ(r.nresp, 3);
	evfake_advance(31999); CHECK_EQ(txn_layer_count(tl), 1);
	evfake_advance(1); CHECK_EQ(txn_layer_count(tl), 0); CHECK_EQ(r.ev[r.nev - 1], TXN_CLI_TERMINATED);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* 2xx: Accepted: no ACK from the transaction layer, repeated and forked 2xx go to the TU, stray after the end */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("INVITE", "z9hG4bKi3", 1, "[2001:db8::1]:5060", NULL), &r);
	reply(f, f, 0, 183, "e1");
	reply(f, f, 0, 200, "d1");
	CHECK_EQ(f->nsent, 1);
	CHECK_EQ(r.nresp, 2);
	reply(f, f, 0, 200, "d1");	/* retransmission */
	reply(f, f, 0, 200, "d2");	/* fork */
	CHECK_EQ(r.nresp, 4); CHECK_EQ(r.status[3], 200);
	reply(f, f, 0, 180, "d2");	/* provisionals after the 2xx are dropped */
	CHECK_EQ(r.nresp, 4);
	evfake_advance(31999); CHECK_EQ(txn_layer_count(tl), 1);
	evfake_advance(1); CHECK_EQ(txn_layer_count(tl), 0);
	reply(f, f, 0, 200, "d1");
	CHECK_EQ(r.stray, 1); CHECK_EQ(r.nresp, 4);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* CANCEL before any response: pending, sent on the first 1xx, own transaction with the INVITE's branch */
	memset(&r, 0, sizeof(r)); memset(&rc, 0, sizeof(rc));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("INVITE", "z9hG4bKi4", 7, "[2001:db8::1]:5060", routes), &r);
	CHECK_EQ(txn_client_cancel(r.c, cli_cb, &rc), 0);
	CHECK(txn_client_cancel_pending(r.c));
	CHECK_EQ(txn_client_cancel(r.c, cli_cb, &rc), -1);	/* only once */
	evfake_advance(500);
	CHECK_EQ(f->nsent, 2); CHECK_STR(method_of(f, 1, mb), "INVITE");	/* INVITE retransmit, no CANCEL yet */
	reply(f, f, 0, 180, "c1");
	CHECK(!txn_client_cancel_pending(r.c));
	CHECK_EQ(f->nsent, 3); CHECK_STR(method_of(f, 2, mb), "CANCEL");
	CHECK(!fakeep_parse(f, 2, &m));
	CHECK_STR(m.ruri, "sip:bob@example.com"); CHECK_STR(sip_hdr(&m, "CSeq", 0), "7 CANCEL");
	CHECK_STR(sip_hdr(&m, "Via", 0), "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKi4");
	CHECK_STR(sip_hdr(&m, "To", 0), "<sip:bob@example.com>");	/* no To tag on CANCEL */
	CHECK_STR(sip_hdr(&m, "From", 0), "<sip:alice@example.com>;tag=ft");
	CHECK_EQ(sip_hdr_count(&m, "Route"), 2);
	sip_msg_free(&m);
	/* 200 for CANCEL goes to the CANCEL transaction (same branch, different method), 487 to the INVITE */
	reply(f, f, 2, 200, "c1");
	CHECK_EQ(rc.nresp, 1); CHECK_EQ(rc.status[0], 200); CHECK_EQ(r.nresp, 1);
	reply(f, f, 0, 487, "c1");
	CHECK_EQ(r.nresp, 2); CHECK_EQ(r.status[1], 487); CHECK_STR(method_of(f, 3, mb), "ACK");
	txn_layer_free(tl);
	fakeep_clear(f);

	/* CANCEL pending but a final response comes first: nothing is sent */
	memset(&r, 0, sizeof(r)); memset(&rc, 0, sizeof(rc));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("INVITE", "z9hG4bKi5", 1, "[2001:db8::1]:5060", NULL), &r);
	CHECK_EQ(txn_client_cancel(r.c, cli_cb, &rc), 0);
	reply(f, f, 0, 200, "w1");
	evfake_advance(60000);
	for (i = 0; i < (size_t)f->nsent; i++) CHECK(strcmp(method_of(f, i, mb), "CANCEL"));
	CHECK_EQ(rc.nev, 0);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* CANCEL after a provisional goes out immediately; after a final it is refused */
	memset(&r, 0, sizeof(r)); memset(&rc, 0, sizeof(rc));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("INVITE", "z9hG4bKi6", 1, "[2001:db8::1]:5060", NULL), &r);
	reply(f, f, 0, 180, "x1");
	CHECK_EQ(txn_client_cancel(r.c, cli_cb, &rc), 0);
	CHECK_EQ(f->nsent, 2); CHECK_STR(method_of(f, 1, mb), "CANCEL");
	reply(f, f, 0, 200, "x1");
	CHECK_EQ(txn_client_cancel(r.c, cli_cb, &rc), -1);
	txn_layer_free(tl);
	/* non-INVITE cannot be cancelled */
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("OPTIONS", "z9hG4bKi7", 1, "[2001:db8::1]:5060", NULL), &r);
	CHECK_EQ(txn_client_cancel(r.c, cli_cb, &rc), -1);
	txn_layer_free(tl);

	/* CANCEL with extra headers, sent at once (Proceeding); nobody ever answers the CANCEL or the INVITE:
	 * the INVITE transaction times out 64*T1 after the CANCEL went out (RFC 3261 9.1) and frees its slot */
	memset(&r, 0, sizeof(r)); memset(&rc, 0, sizeof(rc));
	evfake_reset();
	fakeep_clear(f);
	tl = mk_layer(&r, false, 4);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("INVITE", "z9hG4bKi8", 3, "[2001:db8::1]:5060", NULL), &r);
	reply(f, f, 0, 180, "k1");
	evfake_advance(10000);	/* ringing for a while: no timer runs in Proceeding */
	CHECK_EQ(txn_layer_count(tl), 1);
	CHECK_EQ(txn_client_cancel_ex(r.c, "Reason: SIP;cause=200;text=\"Call completed elsewhere\"\r\n", cli_cb, &rc), 0);
	CHECK_EQ(f->nsent, 2); CHECK_STR(method_of(f, 1, mb), "CANCEL");
	CHECK(!fakeep_parse(f, 1, &m));
	CHECK_STR(sip_hdr(&m, "Reason", 0), "SIP;cause=200;text=\"Call completed elsewhere\"");
	CHECK_STR(sip_hdr(&m, "CSeq", 0), "3 CANCEL");
	sip_msg_free(&m);
	CHECK_EQ(txn_layer_count(tl), 2);	/* INVITE + CANCEL */
	reply(f, f, 0, 181, "k1");	/* another provisional must not disarm the guard */
	evfake_advance(31999);
	CHECK_EQ(r.nev, 2);	/* two provisionals, no timeout yet */
	evfake_advance(1);
	CHECK_EQ(r.nev, 4); CHECK_EQ(r.ev[2], TXN_CLI_TIMEOUT); CHECK_EQ(r.ev[3], TXN_CLI_TERMINATED);
	CHECK_EQ(txn_layer_count(tl), 0);
	txn_layer_free(tl);

	/* pending CANCEL (no provisional yet) is bounded by Timer B; after the 1xx the CANCEL carries the extra
	 * headers and the 64*T1 guard restarts */
	memset(&r, 0, sizeof(r)); memset(&rc, 0, sizeof(rc));
	evfake_reset();
	fakeep_clear(f);
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("INVITE", "z9hG4bKi9", 1, "[2001:db8::1]:5060", NULL), &r);
	CHECK_EQ(txn_client_cancel(r.c, cli_cb, &rc), 0);
	evfake_advance(32000);
	CHECK_EQ(r.nev, 2); CHECK_EQ(r.ev[0], TXN_CLI_TIMEOUT); CHECK_EQ(txn_layer_count(tl), 0);
	txn_layer_free(tl);
	memset(&r, 0, sizeof(r)); memset(&rc, 0, sizeof(rc));
	evfake_reset();
	fakeep_clear(f);
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	start(tl, f, mkreq("INVITE", "z9hG4bKi10", 1, "[2001:db8::1]:5060", NULL), &r);
	CHECK_EQ(txn_client_cancel_ex(r.c, "X-Why: test\r\n", cli_cb, &rc), 0);
	CHECK(txn_client_cancel_pending(r.c));
	evfake_advance(20000);
	reply(f, f, 0, 180, "m1");
	CHECK(!fakeep_parse(f, f->nsent - 1, &m));
	CHECK_STR(m.method, "CANCEL"); CHECK_STR(sip_hdr(&m, "X-Why", 0), "test");
	sip_msg_free(&m);
	evfake_advance(31999); CHECK_EQ(txn_layer_count(tl), 2);	/* guard restarted at the CANCEL, not at the INVITE */
	evfake_advance(1); CHECK_EQ(txn_layer_count(tl), 0);
	txn_layer_free(tl);
	fakeep_free(f);
}

/* ---------------- server, non-INVITE ---------------- */

static void t_server_noninvite(void)
{
	struct rec r = {0};
	struct txn_layer *tl;
	struct fakeep *f = fakeep_new("lan", false, NULL);
	struct addr src = A("10.0.0.77", 49152);
	struct sip_resp_parts p;
	struct sip_msg m;
	struct sip_via v;

	/* response goes to the Via sent-by when there is no rport; retransmitted request -> same response, TU sees it once */
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("OPTIONS", "z9hG4bKs1", 1, "10.0.0.9:5070", NULL));
	CHECK_EQ(r.nreq, 1); CHECK_EQ(txn_layer_count(tl), 1);
	fakeep_rx(f, &src, mkreq("OPTIONS", "z9hG4bKs1", 1, "10.0.0.9:5070", NULL));	/* retransmission while Trying: dropped */
	CHECK_EQ(r.nreq, 1); CHECK_EQ(f->nsent, 0);
	memset(&p, 0, sizeof(p)); p.status = 200;
	CHECK_EQ(txn_server_reply(r.st, &p), 0);
	CHECK_EQ(f->nsent, 1);
	CHECK(addr_equal(&f->sent[0].dst, &(struct addr){ .sa = A("10.0.0.9", 5070).sa }));
	fakeep_rx(f, &src, mkreq("OPTIONS", "z9hG4bKs1", 1, "10.0.0.9:5070", NULL));
	CHECK_EQ(f->nsent, 2); CHECK_EQ(r.nreq, 1);
	CHECK(!memcmp(f->sent[0].data, f->sent[1].data, f->sent[0].len));	/* identical retransmission */
	CHECK_EQ(txn_server_reply(r.st, &p), -EINVAL);	/* a second final is refused */
	evfake_advance(31999); CHECK_EQ(txn_layer_count(tl), 1);	/* Timer J = 64*T1 */
	evfake_advance(1); CHECK_EQ(txn_layer_count(tl), 0); CHECK_EQ(r.terminated, 1);
	/* the same request after termination is a new transaction (that is what J is for) */
	fakeep_rx(f, &src, mkreq("OPTIONS", "z9hG4bKs1", 1, "10.0.0.9:5070", NULL));
	CHECK_EQ(r.nreq, 2);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* rport: back to the source, received + rport filled in */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	{
		char req[1200];

		snprintf(req, sizeof(req), "OPTIONS sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.9;branch=z9hG4bKs2b;rport\r\n"
			 "From: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\n\r\n");
		memset(&r, 0, sizeof(r));
		fakeep_rx(f, &src, req);
	}
	memset(&p, 0, sizeof(p)); p.status = 200;
	CHECK_EQ(txn_server_reply(r.st, &p), 0);
	CHECK(addr_equal(&f->sent[0].dst, &src));
	CHECK(!fakeep_parse(f, 0, &m)); CHECK(!sip_top_via(&m, &v));
	CHECK_EQ(v.rport, 49152); CHECK_STR(v.received, "10.0.0.77"); CHECK_STR(v.branch, "z9hG4bKs2b");
	CHECK(strstr(sip_hdr(&m, "To", 0), ";tag="));	/* a tag was generated */
	sip_msg_free(&m);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* response destination override (protected Gm endpoint): always the P-CSCF port-s, whatever the Via says */
	{
		struct addr ov = A("2001:db8::2", 5071), pc = A("2001:db8::2", 5073);
		struct fakeep *g = fakeep_new("gm", false, &ov);

		memset(&r, 0, sizeof(r));
		evfake_reset();
		tl = mk_layer(&r, false, 0);
		txn_layer_attach(tl, g->ep);
		fakeep_rx(g, &pc, mkreq("MESSAGE", "z9hG4bKg1", 5, "[2001:db8::2]:9999", NULL));
		memset(&p, 0, sizeof(p)); p.status = 200;
		CHECK_EQ(txn_server_reply(r.st, &p), 0);
		CHECK(addr_equal(&g->sent[0].dst, &ov));
		CHECK(addr_equal(txn_server_dest(r.st), &ov));
		fakeep_rx(g, &pc, mkreq("MESSAGE", "z9hG4bKg1", 5, "[2001:db8::2]:9999", NULL));	/* retransmission: also to the override */
		CHECK_EQ(g->nsent, 2); CHECK(addr_equal(&g->sent[1].dst, &ov));
		txn_layer_free(tl);
		fakeep_free(g);
	}

	/* provisional then final; 1xx is repeated for a retransmitted request */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("SUBSCRIBE", "z9hG4bKs3", 1, "10.0.0.9:5070", NULL));
	memset(&p, 0, sizeof(p)); p.status = 100;
	CHECK_EQ(txn_server_reply(r.st, &p), 0);
	fakeep_rx(f, &src, mkreq("SUBSCRIBE", "z9hG4bKs3", 1, "10.0.0.9:5070", NULL));
	CHECK_EQ(f->nsent, 2); CHECK_EQ(status_of(f, 1), 100);
	p.status = 489;
	CHECK_EQ(txn_server_reply(r.st, &p), 0);
	CHECK_EQ(status_of(f, 2), 489);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* reliable endpoint: Timer J is 0 */
	{
		struct fakeep *g = fakeep_new("tcp", true, NULL);

		memset(&r, 0, sizeof(r));
		evfake_reset();
		tl = mk_layer(&r, false, 0);
		txn_layer_attach(tl, g->ep);
		fakeep_rx(g, &src, mkreq("OPTIONS", "z9hG4bKs4", 1, "10.0.0.9:5070", NULL));
		memset(&p, 0, sizeof(p)); p.status = 200;
		txn_server_reply(r.st, &p);
		CHECK_EQ(txn_layer_count(tl), 1);
		evfake_advance(0); CHECK_EQ(txn_layer_count(tl), 0);
		CHECK(addr_equal(&g->sent[0].dst, &src));	/* reliable: back over the connection it came from */
		txn_layer_free(tl);
		fakeep_free(g);
	}

	/* transaction limit: stateless 503, ACK-less */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 2);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("OPTIONS", "z9hG4bKl1", 1, "10.0.0.9:5070", NULL));
	fakeep_rx(f, &src, mkreq("OPTIONS", "z9hG4bKl2", 1, "10.0.0.9:5070", NULL));
	CHECK_EQ(f->nsent, 0);
	fakeep_rx(f, &src, mkreq("OPTIONS", "z9hG4bKl3", 1, "10.0.0.9:5070", NULL));
	CHECK_EQ(r.nreq, 2); CHECK_EQ(f->nsent, 1); CHECK_EQ(status_of(f, 0), 503);
	/* garbage is dropped silently */
	fakeep_rx(f, &src, "\x01\x02 not sip");
	fakeep_rx(f, &src, "OPTIONS sip:a SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n");	/* no Via */
	CHECK_EQ(f->nsent, 1);
	txn_layer_free(tl);
	fakeep_free(f);
}

/* ---------------- server INVITE ---------------- */

static void t_server_invite(void)
{
	struct rec r = {0};
	struct txn_layer *tl;
	struct fakeep *f = fakeep_new("gm", false, NULL);
	struct addr src = A("2001:db8::2", 5073);
	struct sip_resp_parts p;
	char mb[16];
	static const uint64_t g_at[] = { 500, 1500, 3500, 7500, 11500, 15500, 19500, 23500, 27500, 31500 };
	size_t i;
	uint64_t t = 0;
	const char *inv_extra = "Contact: <sip:[2001:db8::2]:5071>\r\n";

	/* auto 100; 486 retransmitted by Timer G until the ACK; Timer I after the ACK */
	evfake_reset();
	tl = mk_layer(&r, true, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKv1", 1, "[2001:db8::2]:5071", inv_extra));
	CHECK_EQ(r.nreq, 1); CHECK_EQ(f->nsent, 1); CHECK_EQ(status_of(f, 0), 100);
	fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKv1", 1, "[2001:db8::2]:5071", inv_extra));	/* retransmitted INVITE: 100 again */
	CHECK_EQ(f->nsent, 2); CHECK_EQ(r.nreq, 1);
	memset(&p, 0, sizeof(p)); p.status = 180;
	CHECK_EQ(txn_server_reply(r.st, &p), 0);
	p.status = 486;
	CHECK_EQ(txn_server_reply(r.st, &p), 0);
	CHECK_EQ(f->nsent, 4);
	CHECK(addr_equal(&f->sent[3].dst, &(struct addr){ .sa = A("2001:db8::2", 5071).sa }));	/* to the Via sent-by (port-s) */
	for (i = 0; i < 3; i++) {
		evfake_advance(g_at[i] - t - 1); t = g_at[i] - 1;
		CHECK_EQ(f->nsent, 4 + (int)i);
		evfake_advance(1); t++;
		CHECK_EQ(f->nsent, 5 + (int)i);
		CHECK_EQ(status_of(f, f->nsent - 1), 486);
	}
	/* ACK for the 486 (same branch, method ACK) is absorbed by the transaction */
	fakeep_rx(f, &src, mkreq("ACK", "z9hG4bKv1", 1, "[2001:db8::2]:5071", NULL));
	CHECK_EQ(r.nack, 0);
	{
		int n = f->nsent;

		evfake_advance(20000);
		CHECK_EQ(f->nsent, n);	/* G stopped */
	}
	CHECK_EQ(txn_layer_count(tl), 0);	/* I (5 s) is over */
	CHECK_EQ(r.terminated, 1); CHECK_EQ(r.timeout, 0);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* no ACK: G retransmits (T1 doubling, T2 cap) until Timer H = 64*T1, then TIMEOUT */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKv2", 1, "[2001:db8::2]:5071", NULL));
	CHECK_EQ(f->nsent, 0);		/* no auto 100 */
	memset(&p, 0, sizeof(p)); p.status = 603;
	txn_server_reply(r.st, &p);
	evfake_advance(31999);
	CHECK_EQ(f->nsent, 1 + 10);	/* initial + retransmissions at 0.5 1.5 3.5 7.5 11.5 15.5 19.5 23.5 27.5 31.5 s */
	CHECK_EQ(r.timeout, 0);
	evfake_advance(1);
	CHECK_EQ(r.timeout, 1); CHECK_EQ(r.terminated, 1); CHECK_EQ(txn_layer_count(tl), 0);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* 2xx: transaction goes to Accepted; the TU retransmits the 2xx with the helper until the ACK (new branch, reaches the TU) */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKv3", 1, "[2001:db8::2]:5071", inv_extra));
	memset(&p, 0, sizeof(p)); p.status = 200; p.contact = "<sip:me@[2001:db8::1]:5060>";
	CHECK_EQ(txn_server_reply(r.st, &p), 0);
	{
		struct sip_rtx *x = txn_server_start_2xx_rtx(r.st, 0, 0, giveup_cb, &r);

		CHECK(x != NULL);
		CHECK_EQ(f->nsent, 1);
		evfake_advance(499); CHECK_EQ(f->nsent, 1);
		evfake_advance(1); CHECK_EQ(f->nsent, 2); CHECK_EQ(sip_rtx_count(x), 1);
		evfake_advance(1000); CHECK_EQ(f->nsent, 3);
		evfake_advance(2000); CHECK_EQ(f->nsent, 4);
		evfake_advance(4000); CHECK_EQ(f->nsent, 5);	/* capped at T2 */
		CHECK_EQ(status_of(f, 4), 200);
		fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKv3", 1, "[2001:db8::2]:5071", inv_extra));	/* retransmitted INVITE absorbed, 2xx repeated */
		CHECK_EQ(r.nreq, 1); CHECK_EQ(f->nsent, 6);
		fakeep_rx(f, &src, mkreq("ACK", "z9hG4bKv3ack", 1, "[2001:db8::2]:5071", NULL));	/* ACK for a 2xx: new branch, TU */
		CHECK_EQ(r.nack, 1);
		sip_rtx_stop(x);
		evfake_advance(60000);
		CHECK_EQ(f->nsent, 6); CHECK_EQ(r.giveups, 0);
	}
	CHECK_EQ(txn_layer_count(tl), 0);	/* Accepted ended after 64*T1 */
	txn_layer_free(tl);
	fakeep_clear(f);

	/* 2xx never ACKed: give up at 64*T1 */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKv4", 1, "[2001:db8::2]:5071", NULL));
	memset(&p, 0, sizeof(p)); p.status = 200;
	txn_server_reply(r.st, &p);
	txn_server_start_2xx_rtx(r.st, 0, 0, giveup_cb, &r);
	evfake_advance(31999); CHECK_EQ(r.giveups, 0); CHECK_EQ(f->nsent, 1 + 10);
	evfake_advance(1); CHECK_EQ(r.giveups, 1);
	CHECK_EQ(evfake_armed_timers(), 0);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* the helper on a reliable endpoint does not retransmit but still gives up */
	{
		struct fakeep *g = fakeep_new("tcp", true, NULL);
		struct sip_rtx *x;
		uint8_t msg[] = "SIP/2.0 200 OK\r\n\r\n";
		struct addr d = A("2001:db8::2", 5071);

		memset(&r, 0, sizeof(r));
		evfake_reset();
		x = sip_rtx_start(g->ep, &d, msg, sizeof(msg) - 1, 0, 0, giveup_cb, &r);
		evfake_advance(31999); CHECK_EQ(g->nsent, 0); CHECK_EQ(r.giveups, 0);
		evfake_advance(1); CHECK_EQ(r.giveups, 1);
		(void)x;
		fakeep_free(g);
	}

	/* CANCEL: 200 for the CANCEL by the layer, CANCELLED for the INVITE, TU answers 487 */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, true, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKv5", 3, "[2001:db8::2]:5071", NULL));
	CHECK_EQ(r.nreq, 1);
	{
		struct txn_server *inv = r.st;

		memset(&p, 0, sizeof(p)); p.status = 180;
		txn_server_reply(inv, &p);
		fakeep_clear(f);
		fakeep_rx(f, &src, mkreq("CANCEL", "z9hG4bKv5", 3, "[2001:db8::2]:5071", NULL));
		CHECK_EQ(r.nreq, 1);		/* the TU does not see the CANCEL request itself */
		CHECK_EQ(r.cancelled, 1);
		CHECK_EQ(f->nsent, 1); CHECK_EQ(status_of(f, 0), 200); CHECK_STR(method_of(f, 0, mb), "resp");
		{
			struct sip_msg m;

			fakeep_parse(f, 0, &m);
			CHECK_STR(sip_hdr(&m, "CSeq", 0), "3 CANCEL");
			sip_msg_free(&m);
		}
		p.status = 487;
		CHECK_EQ(txn_server_reply(inv, &p), 0);
		CHECK_EQ(status_of(f, 1), 487);
		{
			struct sip_msg m;

			fakeep_parse(f, 1, &m);
			CHECK_STR(sip_hdr(&m, "CSeq", 0), "3 INVITE");
			sip_msg_free(&m);
		}
		fakeep_rx(f, &src, mkreq("CANCEL", "z9hG4bKv5", 3, "[2001:db8::2]:5071", NULL));	/* retransmitted CANCEL: 200 again, no second notification */
		CHECK_EQ(r.cancelled, 1); CHECK_EQ(f->nsent, 3); CHECK_EQ(status_of(f, 2), 200);
	}
	txn_layer_free(tl);
	fakeep_clear(f);

	/* CANCEL for an unknown INVITE: 481; CANCEL after the final response: 200 but no notification */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("CANCEL", "z9hG4bKnone", 1, "[2001:db8::2]:5071", NULL));
	CHECK_EQ(f->nsent, 1); CHECK_EQ(status_of(f, 0), 481); CHECK_EQ(r.nreq, 0);
	fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKv6", 1, "[2001:db8::2]:5071", NULL));
	memset(&p, 0, sizeof(p)); p.status = 200;
	txn_server_reply(r.st, &p);
	fakeep_rx(f, &src, mkreq("CANCEL", "z9hG4bKv6", 1, "[2001:db8::2]:5071", NULL));
	CHECK_EQ(r.cancelled, 0); CHECK_EQ(status_of(f, f->nsent - 1), 200);
	txn_layer_free(tl);
	fakeep_free(f);
}

/* ---------------- matching rules ---------------- */

static void t_matching(void)
{
	struct rec r = {0}, r1 = {0}, r2 = {0};
	struct txn_layer *tl;
	struct fakeep *f = fakeep_new("tx", false, NULL), *g = fakeep_new("other", false, NULL);

	/* two client transactions, replies for the second arrive first, on a different endpoint; unknown branch -> stray */
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep); txn_layer_attach(tl, g->ep);
	start(tl, f, mkreq("OPTIONS", "z9hG4bKm1", 1, "[2001:db8::1]:5060", NULL), &r1);
	start(tl, f, mkreq("OPTIONS", "z9hG4bKm2", 1, "[2001:db8::1]:5060", NULL), &r2);
	reply(g, f, 1, 200, NULL);
	CHECK_EQ(r1.nresp, 0); CHECK_EQ(r2.nresp, 1); CHECK(r2.rx_ep[0] == g->ep);
	{
		/* the same branch but a CSeq method that has no transaction */
		struct sip_msg m;
		struct sip_resp_parts p = { .status = 200 };
		struct buf b;
		struct addr src = A("2001:db8::2", 5060);

		fakeep_parse(f, 0, &m);
		buf_init(&b, 0);
		sip_build_response(&b, &m, &p);
		/* turn "CSeq: 1 OPTIONS" into "CSeq: 1 BYE" */
		{
			char *s = strstr((char *)b.p, "1 OPTIONS");

			memcpy(s, "1 BYE    ", 9);
		}
		fakeep_rx_n(g, &src, b.p, b.len);
		CHECK_EQ(r1.nresp, 0); CHECK_EQ(r.stray, 1);
		buf_free(&b); sip_msg_free(&m);
	}
	reply(g, f, 0, 200, NULL);
	CHECK_EQ(r1.nresp, 1);
	txn_layer_free(tl);
	fakeep_free(f); fakeep_free(g);
}

/* ---------------- CANCEL Reason, ACK / stray delivery ---------------- */

static void t_cancel_reason_ack(void)
{
	struct rec r = {0};
	struct txn_layer *tl;
	struct fakeep *f = fakeep_new("gm", false, NULL);
	struct addr src = A("2001:db8::2", 5073);
	struct sip_resp_parts p;
	const char *rs = "SIP;cause=200;text=\"Call completed elsewhere\"";
	char longrs[400];

	CHECK_STR(txn_server_cancel_reason(NULL), "");
	/* with a Reason: visible inside the callback and afterwards; a retransmitted CANCEL does not clobber it */
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKr1", 1, "[2001:db8::2]:5071", NULL));
	CHECK_STR(txn_server_cancel_reason(r.st), "");
	memset(&p, 0, sizeof(p)); p.status = 180;
	txn_server_reply(r.st, &p);
	fakeep_rx(f, &src, mkreq("CANCEL", "z9hG4bKr1", 1, "[2001:db8::2]:5071", "Reason: SIP;cause=200;text=\"Call completed elsewhere\"\r\n"));
	CHECK_EQ(r.cancelled, 1); CHECK_STR(r.reason, rs);
	CHECK_STR(txn_server_cancel_reason(r.st), rs);
	fakeep_rx(f, &src, mkreq("CANCEL", "z9hG4bKr1", 1, "[2001:db8::2]:5071", "Reason: SIP;cause=486\r\n"));
	CHECK_EQ(r.cancelled, 1); CHECK_STR(txn_server_cancel_reason(r.st), rs);
	txn_layer_free(tl);
	fakeep_clear(f);

	/* without a Reason header, and an over-long one is truncated */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKr2", 1, "[2001:db8::2]:5071", NULL));
	fakeep_rx(f, &src, mkreq("CANCEL", "z9hG4bKr2", 1, "[2001:db8::2]:5071", NULL));
	CHECK_EQ(r.cancelled, 1); CHECK_STR(r.reason, ""); CHECK_STR(txn_server_cancel_reason(r.st), "");
	fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKr3", 1, "[2001:db8::2]:5071", NULL));
	memset(longrs, 'x', sizeof(longrs));
	memcpy(longrs, "Reason: SIP;text=\"", 18);
	strcpy(longrs + 350, "\"\r\n");
	fakeep_rx(f, &src, mkreq("CANCEL", "z9hG4bKr3", 1, "[2001:db8::2]:5071", longrs));
	CHECK_EQ(r.cancelled, 2); CHECK_EQ((int)strlen(r.reason), 159);
	CHECK(!strncmp(r.reason, "SIP;text=\"xxx", 13));
	txn_layer_free(tl);
	fakeep_clear(f);

	/* ACK that matches no server transaction (ACK for a 2xx, or plain stray) reaches on_request with st == NULL */
	memset(&r, 0, sizeof(r));
	evfake_reset();
	tl = mk_layer(&r, false, 0);
	txn_layer_attach(tl, f->ep);
	fakeep_rx(f, &src, mkreq("ACK", "z9hG4bKnoinv", 1, "[2001:db8::2]:5071", NULL));
	CHECK_EQ(r.nack, 1); CHECK_EQ(r.nreq, 0); CHECK_EQ(f->nsent, 0); CHECK_EQ(txn_layer_count(tl), 0);
	fakeep_rx(f, &src, mkreq("INVITE", "z9hG4bKr4", 1, "[2001:db8::2]:5071", NULL));
	memset(&p, 0, sizeof(p)); p.status = 200;
	txn_server_reply(r.st, &p);
	evfake_advance(40000);	/* Accepted state is over, the transaction is gone */
	CHECK_EQ(txn_layer_count(tl), 0);
	fakeep_rx(f, &src, mkreq("ACK", "z9hG4bKr4", 1, "[2001:db8::2]:5071", NULL));	/* same branch, late ACK */
	CHECK_EQ(r.nack, 2);
	/* a 2xx response that matches no client transaction goes to on_stray_response */
	{
		struct fakeep *g = fakeep_new("tx", false, NULL);
		struct rec r2 = {0};

		start(tl, g, mkreq("INVITE", "z9hG4bKr5", 1, "[2001:db8::1]:5060", NULL), &r2);
		{
			struct sip_msg m;
			struct sip_resp_parts rp = { .status = 200, .to_tag = "t" };
			struct buf b;

			fakeep_parse(g, 0, &m);
			buf_init(&b, 0);
			sip_build_response(&b, &m, &rp);
			*strstr((char *)b.p, "z9hG4bKr5") = 'Y';	/* branch no client knows */
			fakeep_rx_n(f, &src, b.p, b.len);
			buf_free(&b); sip_msg_free(&m);
		}
		CHECK_EQ(r.stray, 1); CHECK_EQ(r2.nresp, 0);
		fakeep_free(g);
	}
	txn_layer_free(tl);
	fakeep_free(f);
}

void test_txn(void)
{
	t_client_noninvite();
	t_client_invite();
	t_server_noninvite();
	t_server_invite();
	t_matching();
	t_cancel_reason_ack();
}
