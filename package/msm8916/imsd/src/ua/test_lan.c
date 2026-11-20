/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <strings.h>
#include "test_ua.h"

#define ALLOW "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER, MESSAGE, UPDATE, INFO, NOTIFY"

static const char *mk(const char *method, const char *ip, const char *extra, const char *to_tag, const char *contact)
{
	static char bufs[8][1500];
	static int k, uniq;
	char *b = bufs[k++ & 7];
	char ct[300] = "", tag[64] = "";
	int u = ++uniq;

	if (contact)
		snprintf(ct, sizeof(ct), "Contact: <%s>\r\n", contact);
	if (to_tag)
		snprintf(tag, sizeof(tag), ";tag=%s", to_tag);
	snprintf(b, 1500, "%s sip:alice@192.168.68.1 SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bKq%d\r\n"
		 "From: <sip:u@%s>;tag=ft%d\r\nTo: <sip:alice@192.168.68.1>%s\r\nCall-ID: q%d@%s\r\nCSeq: 1 %s\r\n"
		 "Max-Forwards: 70\r\n%s%sContent-Length: 0\r\n\r\n", method, ip, u, ip, u, tag, u, ip, method,
		 ct, extra ? extra : "");
	return b;
}

static int last_st(struct uaw *w)
{
	int i = last_resp(w->f);

	return i < 0 ? 0 : sent_status(w->f, i);
}

static const char *last_h(struct uaw *w, const char *name, char *out)
{
	return sent_hdr(w->f, last_resp(w->f), name, out, 300);
}

static void t_simple_methods(void)
{
	struct uaw w;
	char v[300];

	uaw_init(&w, NULL, false);
	dev_register(&w, 1);
	fakeep_clear(w.f);

	/* OPTIONS: honest Allow, no Supported (no 100rel / timer / replaces / path), Server header */
	uaw_rx(&w, dev_ip(1), 5060, mk("OPTIONS", dev_ip(1), NULL, NULL, NULL));
	CHECK_EQ(last_st(&w), 200);
	CHECK_STR(last_h(&w, "Allow", v), ALLOW);
	CHECK_STR(last_h(&w, "Accept", v), "application/sdp, text/plain");
	CHECK_STR(last_h(&w, "Supported", v), "");
	CHECK_STR(last_h(&w, "Server", v), "imsd");
	CHECK_STR(last_h(&w, "Allow-Events", v), "");
	/* an unregistered source is answered too */
	fakeep_clear(w.f);
	uaw_rx(&w, "192.168.68.77", 5060, mk("OPTIONS", "192.168.68.77", NULL, NULL, NULL));
	CHECK_EQ(last_st(&w), 200);

	/* SUBSCRIBE (MWI, reg event): 489, well-formed, no Allow-Events */
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("SUBSCRIBE", dev_ip(1), "Event: message-summary\r\nAccept: application/simple-message-summary\r\nExpires: 3600\r\n", NULL, "sip:u1@192.168.68.11:5060"));
	CHECK_EQ(last_st(&w), 489);
	CHECK_STR(last_h(&w, "Allow-Events", v), "");
	CHECK(strstr(last_h(&w, "To", v), "tag=") != NULL);
	CHECK(strstr(last_h(&w, "CSeq", v), "SUBSCRIBE") != NULL);
	{
		struct sip_msg m;

		CHECK(!fakeep_parse(w.f, last_resp(w.f), &m));
		CHECK_STR(m.reason, "Bad Event");
		CHECK_EQ(m.body_len, 0);
		sip_msg_free(&m);
	}
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("SUBSCRIBE", dev_ip(1), "Event: reg\r\n", NULL, NULL));
	CHECK_EQ(last_st(&w), 489);

	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("PUBLISH", dev_ip(1), "Event: presence\r\n", NULL, NULL));
	CHECK_EQ(last_st(&w), 405);
	CHECK_STR(last_h(&w, "Allow", v), ALLOW);
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("REFER", dev_ip(1), "Refer-To: <sip:x@y>\r\n", "abc", NULL));
	CHECK_EQ(last_st(&w), 501);
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("NOTIFY", dev_ip(1), "Event: refer\r\n", NULL, NULL));
	CHECK_EQ(last_st(&w), 481);
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("NOTIFY", dev_ip(1), "Event: keep-alive\r\n", NULL, NULL));
	CHECK_EQ(last_st(&w), 200);
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("INFO", dev_ip(1), "Content-Type: application/dtmf-relay\r\n", "xyz", NULL));
	CHECK_EQ(last_st(&w), 200);
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("FOO", dev_ip(1), NULL, NULL, NULL));
	CHECK_EQ(last_st(&w), 501);

	/* no hooks installed */
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("INVITE", dev_ip(1), NULL, NULL, "sip:u1@192.168.68.11:5060"));
	CHECK_EQ(find_sent(w.f, dev_ip(1), 5060, "INVITE", 0), -1);
	CHECK_EQ(sent_status(w.f, last_resp(w.f)), 480);
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("MESSAGE", dev_ip(1), "Content-Type: text/plain\r\n", NULL, NULL));
	CHECK_EQ(last_st(&w), 503);
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("BYE", dev_ip(1), NULL, "tt", NULL));
	CHECK_EQ(last_st(&w), 481);
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("INVITE", dev_ip(1), NULL, "tt", NULL));	/* re-INVITE */
	CHECK_EQ(last_st(&w), 481);
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("BYE", dev_ip(1), NULL, NULL, NULL));	/* no tag at all */
	CHECK_EQ(last_st(&w), 481);
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk("ACK", dev_ip(1), NULL, "tt", NULL));	/* stray ACK: dropped silently */
	CHECK_EQ(w.f->nsent, 0);
	uaw_fini(&w);
}

static void t_hooks(void)
{
	struct uaw w;
	reg_id_t id1, id2;
	struct lan_stats st;

	uaw_init(&w, NULL, true);
	id1 = dev_register(&w, 1);
	id2 = dev_register(&w, 2);
	CHECK(id1 != REG_ID_NONE && id2 != id1);
	w.hk.autoreply = true;

	uaw_rx(&w, dev_ip(1), 5060, mk("INVITE", dev_ip(1), NULL, NULL, "sip:u1@192.168.68.11:5060"));
	CHECK_EQ(w.hk.invite, 1);
	CHECK(w.hk.last_registered); CHECK_EQ(w.hk.last_id, id1);
	CHECK_EQ(sent_status(w.f, last_resp(w.f)), 200);
	uaw_rx(&w, dev_ip(2), 5060, mk("MESSAGE", dev_ip(2), "Content-Type: text/plain\r\n", NULL, NULL));
	CHECK_EQ(w.hk.message, 1); CHECK_EQ(w.hk.last_id, id2);
	/* in-dialog: BYE / UPDATE / re-INVITE / INFO / PRACK with a To tag */
	uaw_rx(&w, dev_ip(1), 5060, mk("BYE", dev_ip(1), NULL, "tt", NULL));
	uaw_rx(&w, dev_ip(1), 5060, mk("UPDATE", dev_ip(1), NULL, "tt", NULL));
	uaw_rx(&w, dev_ip(1), 5060, mk("INVITE", dev_ip(1), NULL, "tt", NULL));
	uaw_rx(&w, dev_ip(1), 5060, mk("INFO", dev_ip(1), NULL, "tt", NULL));
	uaw_rx(&w, dev_ip(1), 5060, mk("NOTIFY", dev_ip(1), "Event: refer\r\n", "tt", NULL));
	CHECK_EQ(w.hk.in_dialog, 5);
	CHECK_EQ(w.hk.invite, 1);		/* the re-INVITE did not count as a new call */
	CHECK_STR(w.hk.last_method, "NOTIFY");
	/* ACK has no transaction */
	uaw_rx(&w, dev_ip(2), 5060, mk("ACK", dev_ip(2), NULL, "tt", NULL));
	CHECK_EQ(w.hk.ack, 1); CHECK_EQ(w.hk.last_id, id2);
	CHECK(w.hk.st == NULL);

	/* identification: unregistered source is flagged but served */
	uaw_rx(&w, "192.168.68.99", 5060, mk("INVITE", "192.168.68.99", NULL, NULL, "sip:z@192.168.68.99:5060"));
	CHECK_EQ(w.hk.invite, 2);
	CHECK(!w.hk.last_registered); CHECK_EQ(w.hk.last_id, REG_ID_NONE);
	/* same device, other source port: found through its Contact */
	uaw_rx(&w, dev_ip(1), 5099, mk("INVITE", dev_ip(1), NULL, NULL, "sip:u1@192.168.68.11:5060"));
	CHECK(w.hk.last_registered); CHECK_EQ(w.hk.last_id, id1);
	/* ... or, without a Contact, through its (unique) IP */
	uaw_rx(&w, dev_ip(1), 5098, mk("MESSAGE", dev_ip(1), "Content-Type: text/plain\r\n", NULL, NULL));
	CHECK(w.hk.last_registered); CHECK_EQ(w.hk.last_id, id1);
	/* ambiguous IP (two bindings on one host, unknown port, no Contact): unregistered */
	{
		struct uaw *wp = &w;

		uaw_rx(wp, dev_ip(1), 5060, mk_register(dev_ip(1), "<sip:second@192.168.68.11:5070>;expires=300", 1, "second", -1, NULL));
		uaw_rx(wp, dev_ip(1), 5097, mk("MESSAGE", dev_ip(1), "Content-Type: text/plain\r\n", NULL, NULL));
		CHECK(!w.hk.last_registered);
		/* but the second one is identified by its own source/target port */
		uaw_rx(wp, dev_ip(1), 5070, mk("MESSAGE", dev_ip(1), "Content-Type: text/plain\r\n", NULL, NULL));
		CHECK(w.hk.last_registered); CHECK(w.hk.last_id != id1);
	}
	lan_status(w.lan, &st, NULL, NULL);
	CHECK_EQ(st.rx_unregistered, 2);
	CHECK_EQ(st.rx_invite, 4);
	CHECK_EQ(st.rx_ack, 1);
	CHECK_EQ(st.rx_register, 3);

	/* hooks can be swapped later (call module installing itself) */
	{
		struct lan_hooks h;

		memset(&h, 0, sizeof(h));
		lan_set_hooks(w.lan, &h);
		fakeep_clear(w.f);
		uaw_rx(&w, dev_ip(1), 5060, mk("MESSAGE", dev_ip(1), "Content-Type: text/plain\r\n", NULL, NULL));
		CHECK_EQ(last_st(&w), 503);
	}
	uaw_fini(&w);
}

struct xrec {
	int ev[8], n, status;
	struct lan_xact *x;
};

static void xcb(struct lan_xact *x, enum txn_cli_event ev, const struct sip_msg *resp, const struct addr *src, void *arg)
{
	struct xrec *r = arg;

	(void)x; (void)src;
	if (r->n < 8)
		r->ev[r->n++] = ev;
	if (resp)
		r->status = resp->status;
}

static void t_send_request(void)
{
	struct uaw w;
	reg_id_t id;
	struct lan_req q;
	struct lan_sent sent;
	struct xrec r = {0};
	char v[300];
	int i;
	const struct reg_binding *b;
	struct sip_msg m;

	uaw_init(&w, NULL, false);
	id = dev_register(&w, 1);
	memset(&q, 0, sizeof(q));
	q.method = "MESSAGE";
	q.from_user = "+821012345678";
	q.from_display = "Alice \"A\"";
	q.content_type = "text/plain; charset=utf-8";
	q.body = (const uint8_t *)"hello";
	q.body_len = 5;
	fakeep_clear(w.f);
	CHECK(lan_send_request(w.lan, 999, &q, xcb, &r, NULL) == NULL);
	CHECK(lan_send_request(w.lan, id, &q, xcb, &r, &sent) != NULL);
	CHECK_EQ(w.f->nsent, 1);
	{
		struct addr da = ua_addr(dev_ip(1), 5060);

		CHECK(addr_equal(&w.f->sent[0].dst, &da));
	}
	CHECK(!fakeep_parse(w.f, 0, &m));
	CHECK_STR(m.method, "MESSAGE");
	CHECK_STR(m.ruri, "sip:u1@192.168.68.11:5060");
	CHECK_STR(sip_hdr(&m, "To", 0), "<sip:alice@192.168.68.1>");
	CHECK(strstr(sip_hdr(&m, "From", 0), "\"Alice \\\"A\\\"\" <sip:+821012345678@[2001:db8::1]>;tag=") == sip_hdr(&m, "From", 0));
	CHECK(strstr(sip_hdr(&m, "Via", 0), "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK") != NULL);
	CHECK_STR(sip_hdr(&m, "Max-Forwards", 0), "70");
	CHECK_STR(sip_hdr(&m, "Contact", 0), "<sip:imsd@[2001:db8::1]:5060>");
	CHECK_STR(sip_hdr(&m, "User-Agent", 0), "imsd");
	CHECK_STR(sip_hdr(&m, "Content-Type", 0), "text/plain; charset=utf-8");
	CHECK_EQ(m.body_len, 5);
	CHECK_STR(sip_hdr(&m, "CSeq", 0), "1 MESSAGE");
	CHECK_STR(sip_hdr(&m, "Call-ID", 0), sent.call_id);
	CHECK(strstr(sip_hdr(&m, "From", 0), sent.from_tag) != NULL);
	CHECK_STR(sent.to_uri, "sip:alice@192.168.68.1");
	CHECK_STR(sent.from_uri, "sip:+821012345678@[2001:db8::1]");
	sip_msg_free(&m);
	/* the device answers: bookkeeping */
	b = reg_find(lan_registrar(w.lan), id);
	CHECK(!b->answered); CHECK(!b->allow_known); CHECK_EQ(b->n_tx, 1);
	dev_reply_idx(&w, 0, 1, 200, NULL, "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS\r\n");
	CHECK_EQ(r.status, 200);
	CHECK_EQ(r.ev[0], TXN_CLI_RESPONSE);
	b = reg_find(lan_registrar(w.lan), id);
	CHECK(b->answered); CHECK(b->allow_known); CHECK(!reg_allows(b, "MESSAGE")); CHECK_EQ(b->n_answered, 1);
	evfake_advance(10000);
	CHECK_EQ(r.ev[r.n - 1], TXN_CLI_TERMINATED);

	/* from_uri override, explicit identifiers */
	memset(&q, 0, sizeof(q));
	q.method = "INFO";
	q.from_uri = "sip:line@example.net";
	q.call_id = "fixed-call-id";
	q.from_tag = "ftag";
	q.cseq = 7;
	fakeep_clear(w.f);
	CHECK(lan_send_request(w.lan, id, &q, NULL, NULL, &sent) != NULL);
	sent_hdr(w.f, 0, "From", v, sizeof(v));
	CHECK_STR(v, "<sip:line@example.net>;tag=ftag");
	sent_hdr(w.f, 0, "CSeq", v, sizeof(v));
	CHECK_STR(v, "7 INFO");
	CHECK_EQ(sent.cseq, 7);
	CHECK_EQ(count_sent(w.f, "INFO"), 1);
	/* bad request */
	q.from_uri = NULL;
	CHECK(lan_send_request(w.lan, id, &q, NULL, NULL, NULL) == NULL);

	/* timeout: unreachable, still bound */
	memset(&q, 0, sizeof(q));
	q.method = "OPTIONS";
	q.from_user = "imsd";
	r = (struct xrec){0};
	CHECK(lan_send_request(w.lan, id, &q, xcb, &r, NULL) != NULL);
	evfake_advance(33000);
	CHECK_EQ(r.ev[0], TXN_CLI_TIMEOUT);
	b = reg_find(lan_registrar(w.lan), id);
	CHECK(b != NULL && !b->reachable && b->n_timeouts >= 1);
	CHECK_EQ(w.bev[w.nbev - 1].ev, REG_EV_UNREACHABLE);
	/* any request from the device is a sign of life */
	uaw_rx(&w, dev_ip(1), 5060, mk("OPTIONS", dev_ip(1), NULL, NULL, NULL));
	CHECK(reg_find(lan_registrar(w.lan), id)->reachable);
	CHECK_EQ(w.bev[w.nbev - 1].ev, REG_EV_REACHABLE);
	/* detach: callback silenced */
	r = (struct xrec){0};
	{
		struct lan_xact *x = lan_send_request(w.lan, id, &q, xcb, &r, NULL);

		CHECK(x != NULL);
		lan_xact_detach(x);
	}
	evfake_advance(40000);
	CHECK_EQ(r.n, 0);
	for (i = 0; i < w.f->nsent; i++)
		(void)i;
	uaw_fini(&w);
}

static void tweak_ka(struct lan_cfg *c)
{
	c->reg.keepalive_s = 30;
}

static void on_status(const struct lan_binding_status *s, void *arg)
{
	int *n = arg;

	(*n)++;
	CHECK(s->id != REG_ID_NONE);
	CHECK(s->expires_in > 0 && s->expires_in <= 600);
	CHECK(strstr(s->source, ":5060") != NULL);
	CHECK(strstr(s->contact, "sip:u") == s->contact);
	CHECK_STR(s->user_agent, "TestPhone");
}

static void t_keepalive_status(struct uaw *wp)
{
	struct uaw w;
	reg_id_t id1, id2;
	int n = 0;
	struct lan_stats st;
	const struct reg_binding *b1, *b2;

	(void)wp;
	/* default: off */
	uaw_init(&w, NULL, false);
	dev_register(&w, 1);
	fakeep_clear(w.f);
	evfake_advance(300000);
	CHECK_EQ(count_sent(w.f, "OPTIONS"), 0);
	uaw_fini(&w);

	uaw_init(&w, tweak_ka, false);
	id1 = dev_register(&w, 1);
	id2 = dev_register(&w, 2);
	fakeep_clear(w.f);
	evfake_advance(30000);
	CHECK_EQ(count_sent(w.f, "OPTIONS"), 2);
	CHECK(dev_reply(&w, 1, "OPTIONS", 200, NULL));
	b1 = reg_find(lan_registrar(w.lan), id1);
	CHECK(b1->answered && b1->reachable);
	evfake_advance(31000);		/* t = 61 s: dev 2 has not answered yet (Timer F fires at 62 s) */
	CHECK(reg_find(lan_registrar(w.lan), id2)->reachable);
	evfake_advance(1000);
	b2 = reg_find(lan_registrar(w.lan), id2);
	CHECK(b2 != NULL && !b2->reachable);	/* flagged, not removed */
	CHECK_EQ(reg_count(lan_registrar(w.lan)), 2);
	CHECK_EQ(w.bev[w.nbev - 1].ev, REG_EV_UNREACHABLE); CHECK_EQ(w.bev[w.nbev - 1].id, id2);
	/* the second ping (t = 60 s) is answered late: reachable again */
	{
		int idx = -1, k;
		struct addr d2 = ua_addr(dev_ip(2), 5060);
		char mm[16];

		/* the latest ping (retransmissions of the first one belong to its own, finished, transaction) */
		for (k = w.f->nsent - 1; k >= 0 && idx < 0; k--)
			if (addr_equal(&w.f->sent[k].dst, &d2) && !strcmp(sent_method(w.f, k, mm), "OPTIONS"))
				idx = k;
		CHECK(idx >= 0);
		dev_reply_idx(&w, idx, 2, 200, NULL, NULL);
	}
	CHECK(reg_find(lan_registrar(w.lan), id2)->reachable);
	CHECK_EQ(w.bev[w.nbev - 1].ev, REG_EV_REACHABLE);

	lan_status(w.lan, &st, on_status, &n);
	CHECK_EQ(n, 2);
	CHECK_EQ(st.bindings, 2);
	CHECK_EQ(st.reg.added, 2);
	uaw_fini(&w);
}

void test_lan(void)
{
	t_simple_methods();
	t_hooks();
	t_send_request();
	t_keepalive_status(NULL);
}
