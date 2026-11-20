/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <strings.h>
#include "test_ua.h"

/* status of the last response sent on the LAN endpoint */
static int last_status(struct uaw *w)
{
	int i = last_resp(w->f);

	return i < 0 ? 0 : sent_status(w->f, i);
}

/* Contact header lines of the last response: count, and the nth value into out */
static int resp_contacts(struct uaw *w, int n, char *out, size_t sz)
{
	struct sip_msg m;
	int i = last_resp(w->f), c = 0;

	if (out)
		out[0] = 0;
	if (i < 0 || fakeep_parse(w->f, i, &m))
		return -1;
	c = sip_hdr_count(&m, "Contact");
	if (out && n < c)
		snprintf(out, sz, "%s", sip_hdr(&m, "Contact", n));
	sip_msg_free(&m);
	return c;
}

static const struct reg_binding *only_binding(struct uaw *w)
{
	return reg_next(lan_registrar(w->lan), REG_ID_NONE);
}

static void reg_it(struct uaw *w, int k, const char *contact, int cseq, const char *cid, int exp_hdr, const char *extra)
{
	fakeep_clear(w->f);
	uaw_rx(w, dev_ip(k), 5060, mk_register(dev_ip(k), contact, cseq, cid, exp_hdr, extra));
}

static void t_basic(void)
{
	struct uaw w;
	struct registrar *r;
	const struct reg_binding *b;
	char v[300];
	reg_id_t id;
	int refs0;

	uaw_init(&w, NULL, false);
	r = lan_registrar(w.lan);
	refs0 = w.f->ep->refs;

	/* add */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=300", 1, "c1", -1, "User-Agent: Phone/1\r\n");
	CHECK_EQ(last_status(&w), 200);
	CHECK_EQ(reg_count(r), 1);
	CHECK_EQ(resp_contacts(&w, 0, v, sizeof(v)), 1);
	CHECK_STR(v, "<sip:u1@192.168.68.11:5060>;expires=300");
	CHECK_EQ(w.nbev, 1); CHECK_EQ(w.bev[0].ev, REG_EV_ADDED);
	sent_hdr(w.f, last_resp(w.f), "Date", v, sizeof(v));
	CHECK(strstr(v, " GMT") != NULL);
	b = only_binding(&w);
	CHECK(b != NULL);
	id = b->id;
	CHECK_STR(b->ua, "Phone/1");
	CHECK_STR(b->aor, "sip:alice@192.168.68.1");
	CHECK_EQ(b->expires_s, 300);
	CHECK(b->reachable); CHECK(!b->answered); CHECK(!b->target_from_src);

	/* refresh, same id; time passes: expires= shows the remaining time? no: the granted interval of the REGISTER */
	evfake_advance(10000);
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=300", 2, "c1", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	CHECK_EQ(w.nbev, 2); CHECK_EQ(w.bev[1].ev, REG_EV_REFRESHED);
	CHECK_EQ(only_binding(&w)->id, id);
	CHECK_EQ(reg_count(r), 1);

	/* query: no Contact lists the current bindings, with the remaining time */
	evfake_advance(20000);
	reg_it(&w, 1, NULL, 3, "c1", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	CHECK_EQ(resp_contacts(&w, 0, v, sizeof(v)), 1);
	CHECK_STR(v, "<sip:u1@192.168.68.11:5060>;expires=280");
	CHECK_EQ(reg_count(r), 1);
	CHECK_EQ(w.nbev, 2);	/* a query is not a refresh */

	/* clamping: too brief -> 423 with Min-Expires, nothing changed */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=10", 4, "c1", -1, NULL);
	CHECK_EQ(last_status(&w), 423);
	sent_hdr(w.f, last_resp(w.f), "Min-Expires", v, sizeof(v));
	CHECK_STR(v, "60");
	CHECK_EQ(only_binding(&w)->expires_s, 300);
	/* Expires header form of the same */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>", 5, "c1", 30, NULL);
	CHECK_EQ(last_status(&w), 423);
	/* too long -> clamped to max */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=99999", 6, "c1", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	resp_contacts(&w, 0, v, sizeof(v));
	CHECK_STR(v, "<sip:u1@192.168.68.11:5060>;expires=3600");
	/* Expires header gives the interval, Contact param wins over it */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>", 7, "c1", 120, NULL);
	resp_contacts(&w, 0, v, sizeof(v));
	CHECK_STR(v, "<sip:u1@192.168.68.11:5060>;expires=120");
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=200", 8, "c1", 120, NULL);
	resp_contacts(&w, 0, v, sizeof(v));
	CHECK_STR(v, "<sip:u1@192.168.68.11:5060>;expires=200");
	/* neither: the default */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>", 9, "c1", -1, NULL);
	resp_contacts(&w, 0, v, sizeof(v));
	CHECK_STR(v, "<sip:u1@192.168.68.11:5060>;expires=3600");

	/* unregister */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=0", 10, "c1", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	CHECK_EQ(resp_contacts(&w, 0, NULL, 0), 0);
	CHECK_EQ(reg_count(r), 0);
	CHECK_EQ(w.bev[w.nbev - 1].ev, REG_EV_REMOVED); CHECK_EQ(w.bev[w.nbev - 1].why, REG_RM_UNREGISTERED);
	CHECK(reg_find(r, id) == NULL);
	evfake_advance(60000);			/* let the server transactions end */
	CHECK_EQ(w.f->ep->refs, refs0);		/* the binding gave its endpoint reference back */
	CHECK_EQ(evfake_armed_timers(), 0);	/* no binding -> no expiry timer */
	uaw_fini(&w);
}

static void t_wildcard_expiry(void)
{
	struct uaw w;
	struct registrar *r;
	int n0;

	uaw_init(&w, NULL, false);
	r = lan_registrar(w.lan);
	dev_register(&w, 1);
	dev_register(&w, 2);
	CHECK_EQ(reg_count(r), 2);
	/* Contact: * needs Expires: 0 */
	reg_it(&w, 1, "*", 5, "dev1-reg", -1, NULL);
	CHECK_EQ(last_status(&w), 400);
	reg_it(&w, 1, "*", 6, "dev1-reg", 3600, NULL);
	CHECK_EQ(last_status(&w), 400);
	reg_it(&w, 1, "*", 7, "dev1-reg", 0, "Contact: <sip:x@192.168.68.99>\r\n");
	CHECK_EQ(last_status(&w), 400);
	CHECK_EQ(reg_count(r), 2);
	n0 = w.nbev;
	reg_it(&w, 1, "*", 8, "dev1-reg", 0, NULL);
	CHECK_EQ(last_status(&w), 200);
	CHECK_EQ(reg_count(r), 0);			/* all bindings of the AOR, also the other device's */
	CHECK_EQ(w.nbev, n0 + 2);
	CHECK_EQ(w.bev[n0].ev, REG_EV_REMOVED); CHECK_EQ(w.bev[n0 + 1].ev, REG_EV_REMOVED);

	/* expiry timer */
	w.nbev = 0;
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=100", 1, "e1", -1, NULL);
	reg_it(&w, 2, "<sip:u2@192.168.68.12:5060>;expires=200", 1, "e2", -1, NULL);
	CHECK_EQ(reg_count(r), 2);
	evfake_advance(99999);
	CHECK_EQ(reg_count(r), 2);
	evfake_advance(1);
	CHECK_EQ(reg_count(r), 1);
	CHECK_EQ(w.bev[w.nbev - 1].ev, REG_EV_REMOVED); CHECK_EQ(w.bev[w.nbev - 1].why, REG_RM_EXPIRED);
	CHECK(evfake_armed_timers() >= 1);
	/* a refresh moves the deadline */
	reg_it(&w, 2, "<sip:u2@192.168.68.12:5060>;expires=200", 2, "e2", -1, NULL);
	evfake_advance(199999);
	CHECK_EQ(reg_count(r), 1);
	evfake_advance(1);
	CHECK_EQ(reg_count(r), 0);
	CHECK_EQ(reg_get_stats(r)->expired, 2);
	uaw_fini(&w);
}

static void t_ordering_instance(void)
{
	struct uaw w;
	struct registrar *r;
	reg_id_t id;
	char v[300];

	uaw_init(&w, NULL, false);
	r = lan_registrar(w.lan);
	/* RFC 3261 10.3: same Call-ID, lower CSeq -> 500; another Call-ID is always fresh */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=300", 5, "ord", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=300", 4, "ord", -1, NULL);
	CHECK_EQ(last_status(&w), 500);
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=0", 3, "ord", -1, NULL);	/* an old un-REGISTER must not win */
	CHECK_EQ(last_status(&w), 500);
	CHECK_EQ(reg_count(r), 1);
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=300", 5, "ord", -1, NULL);	/* equal: tolerated (late retransmission) */
	CHECK_EQ(last_status(&w), 200);
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=300", 1, "after-reboot", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	CHECK_EQ(only_binding(&w)->cseq, 1);
	CHECK_EQ(reg_count(r), 1);
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=0", 2, "after-reboot", -1, NULL);
	CHECK_EQ(reg_count(r), 0);

	/* rinstance= and other URI parameters do not make a new binding */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060;rinstance=aaaa>;expires=300", 1, "ri1", -1, NULL);
	id = only_binding(&w)->id;
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060;rinstance=bbbb;transport=udp>;expires=300", 1, "ri2", -1, NULL);
	CHECK_EQ(reg_count(r), 1);
	CHECK_EQ(only_binding(&w)->id, id);
	CHECK_STR(only_binding(&w)->contact, "sip:u1@192.168.68.11:5060;rinstance=bbbb;transport=udp");	/* requests use the latest Contact as registered */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060;rinstance=bbbb;transport=udp>;expires=0", 2, "ri2", -1, NULL);
	CHECK_EQ(reg_count(r), 0);

	/* +sip.instance: a device coming back from another port replaces its old binding (same id) */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5060>;expires=300;+sip.instance=\"<urn:uuid:1111-2222>\"", 1, "in1", -1, NULL);
	CHECK_EQ(reg_count(r), 1);
	id = only_binding(&w)->id;
	CHECK_STR(only_binding(&w)->instance, "<urn:uuid:1111-2222>");
	w.nbev = 0;
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5070>;expires=300;+sip.instance=\"<urn:uuid:1111-2222>\"", 1, "in2", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	CHECK_EQ(reg_count(r), 1);
	CHECK_EQ(only_binding(&w)->id, id);
	CHECK_STR(only_binding(&w)->contact, "sip:u1@192.168.68.11:5070");
	CHECK_EQ(addr_port(&only_binding(&w)->target), 5070);
	CHECK_EQ(w.nbev, 1); CHECK_EQ(w.bev[0].ev, REG_EV_REFRESHED);
	CHECK_EQ(resp_contacts(&w, 0, v, sizeof(v)), 1);
	CHECK_STR(v, "<sip:u1@192.168.68.11:5070>;expires=300;+sip.instance=\"<urn:uuid:1111-2222>\"");
	/* another instance on the same host is another device */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5080>;expires=300;+sip.instance=\"<urn:uuid:9999>\"", 1, "in3", -1, NULL);
	CHECK_EQ(reg_count(r), 2);
	/* q-value is stored and echoed */
	reg_it(&w, 1, "<sip:u1@192.168.68.11:5080>;expires=300;q=0.5;+sip.instance=\"<urn:uuid:9999>\"", 2, "in3", -1, NULL);
	CHECK_EQ(reg_next(r, id)->q, 500);
	uaw_fini(&w);
}

static void tweak_max3(struct lan_cfg *c)
{
	c->reg.max_bindings = 3;
}

static void t_full(void)
{
	struct uaw w;
	struct registrar *r;
	char ct[160];
	int k;

	uaw_init(&w, tweak_max3, false);
	r = lan_registrar(w.lan);
	for (k = 1; k <= 3; k++)
		dev_register(&w, k);
	CHECK_EQ(reg_count(r), 3);
	w.nbev = 0;
	reg_it(&w, 4, "<sip:u4@192.168.68.14:5060>;expires=300", 1, "d4", -1, NULL);
	CHECK_EQ(last_status(&w), 503);
	CHECK_EQ(reg_count(r), 3);		/* no silent eviction */
	CHECK_EQ(w.nbev, 0);
	CHECK_EQ(reg_get_stats(r)->rejected_503, 1);
	sent_hdr(w.f, last_resp(w.f), "Retry-After", ct, sizeof(ct));
	CHECK_STR(ct, "300");
	/* refreshing an existing one is fine while full */
	reg_it(&w, 2, "<sip:u2@192.168.68.12:5060>;expires=300", 2, "dev2-reg", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	/* swapping within one request: remove one, add one */
	snprintf(ct, sizeof(ct), "<sip:u1@192.168.68.11:5060>;expires=0, <sip:u4@192.168.68.14:5060>;expires=300");
	reg_it(&w, 1, ct, 2, "dev1-reg", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	CHECK_EQ(reg_count(r), 3);
	/* a REGISTER that adds two contacts with one free slot is rejected as a whole */
	reg_it(&w, 5, "<sip:a@192.168.68.15:5060>;expires=300, <sip:b@192.168.68.15:5062>;expires=300", 1, "d5", -1, NULL);
	CHECK_EQ(last_status(&w), 503);
	CHECK_EQ(reg_count(r), 3);
	/* after one is gone there is room again */
	reg_it(&w, 2, "<sip:u2@192.168.68.12:5060>;expires=0", 3, "dev2-reg", -1, NULL);
	reg_it(&w, 5, "<sip:a@192.168.68.15:5060>;expires=300", 1, "d5", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	uaw_fini(&w);
}

static void t_target_and_errors(void)
{
	struct uaw w;
	struct registrar *r;
	const struct reg_binding *b;
	struct addr src;

	uaw_init(&w, NULL, false);
	r = lan_registrar(w.lan);
	/* Contact host differs from the source: the source address wins */
	reg_it(&w, 1, "<sip:u1@10.9.9.9:5060>;expires=300", 1, "t1", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	b = only_binding(&w);
	src = ua_addr(dev_ip(1), 5060);
	CHECK(b->target_from_src);
	CHECK(addr_equal(&b->target, &src));
	CHECK_STR(b->contact, "sip:u1@10.9.9.9:5060");	/* stored as registered */
	/* a host name is never resolved: source again */
	reg_it(&w, 2, "<sip:u2@phone.lan:5060>;expires=300", 1, "t2", -1, NULL);
	CHECK(reg_next(r, b->id)->target_from_src);
	/* same IP, other port: the Contact port is where the phone listens */
	reg_it(&w, 3, "<sip:u3@192.168.68.13:5099>;expires=300", 1, "t3", -1, NULL);
	b = reg_next(r, reg_next(r, REG_ID_NONE)->id);
	b = reg_next(r, b->id);
	CHECK(!b->target_from_src);
	CHECK_EQ(addr_port(&b->target), 5099);
	CHECK_EQ(addr_port(&b->src), 5060);

	/* garbage */
	reg_it(&w, 4, "<sip:u4@192.168.68.14", 1, "bad1", -1, NULL);
	CHECK_EQ(last_status(&w), 400);
	reg_it(&w, 4, "<sip:u4@192.168.68.14:5060>;expires=abc", 1, "bad2", -1, NULL);
	CHECK_EQ(last_status(&w), 400);
	reg_it(&w, 4, "<sip:u4@192.168.68.14:5060>", 1, "bad3", -1, "Require: 100rel\r\n");
	CHECK_EQ(last_status(&w), 420);
	reg_it(&w, 4, "<sip:u4@192.168.68.14:5060>;expires=300", 1, "ok4", -1, "Require: outbound\r\n");
	CHECK_EQ(last_status(&w), 200);
	CHECK_EQ(reg_count(r), 4);
	/* remove of an unknown contact is a harmless 200 */
	reg_it(&w, 5, "<sip:nobody@192.168.68.15:5060>;expires=0", 1, "unk", -1, NULL);
	CHECK_EQ(last_status(&w), 200);
	CHECK_EQ(reg_count(r), 4);
	/* flush */
	reg_flush(r);
	CHECK_EQ(reg_count(r), 0);
	uaw_fini(&w);
}

struct rw {
	const char *name, *ip;
	int port;
	const char *msg;
	const char *contact;	/* expected stored Contact URI */
	unsigned expires;
	const char *ua;
	int allow_msg;		/* 1 declared with MESSAGE, 0 declared without, -1 no Allow header */
	int tport;
};

static const struct rw rw_cases[] = {
	{ "linphone", "192.168.68.20", 5060,
	  "REGISTER sip:192.168.68.1 SIP/2.0\r\n"
	  "Via: SIP/2.0/UDP 192.168.68.20:5060;branch=z9hG4bK.PAwQe8Zv1;rport\r\n"
	  "From: <sip:alice@192.168.68.1>;tag=nR8Zg4tVz\r\n"
	  "To: <sip:alice@192.168.68.1>\r\n"
	  "CSeq: 20 REGISTER\r\n"
	  "Call-ID: kX5c1Ng2d9\r\n"
	  "Max-Forwards: 70\r\n"
	  "Supported: replaces, outbound, gruu\r\n"
	  "Accept: application/sdp, text/plain, application/vnd.gsma.rcs-ft-http+xml\r\n"
	  "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK, UPDATE\r\n"
	  "Contact: <sip:alice@192.168.68.20:5060;transport=udp>;+sip.instance=\"<urn:uuid:7a9f11fe-4c4b-4a1e-9e0f-0c5b6b1a2f33>\";expires=3600\r\n"
	  "User-Agent: Linphone-Desktop/5.0.12 (belle-sip/5.2.62)\r\n"
	  "Content-Length: 0\r\n\r\n",
	  "sip:alice@192.168.68.20:5060;transport=udp", 3600, "Linphone-Desktop/5.0.12 (belle-sip/5.2.62)", 1, 5060 },
	{ "baresip-compact", "192.168.68.21", 5060,
	  "REGISTER sip:192.168.68.1 SIP/2.0\r\n"
	  "v: SIP/2.0/UDP 192.168.68.21:5060;branch=z9hG4bK2f5b3d6e0c1a7b8e;rport\r\n"
	  "Max-Forwards: 70\r\n"
	  "f: <sip:alice@192.168.68.1>;tag=9c1d3e7a55f0b2c1\r\n"
	  "t: <sip:alice@192.168.68.1>\r\n"
	  "i: 3bd5d9f4b1a0c5@192.168.68.21\r\n"
	  "CSeq: 31245 REGISTER\r\n"
	  "m: <sip:alice@192.168.68.21:5060;transport=udp>;expires=900\r\n"
	  "Allow: INVITE,ACK,BYE,CANCEL,OPTIONS,REFER,NOTIFY,SUBSCRIBE,INFO,MESSAGE\r\n"
	  "User-Agent: baresip v2.12.0 (x86_64/linux)\r\n"
	  "l: 0\r\n\r\n",
	  "sip:alice@192.168.68.21:5060;transport=udp", 900, "baresip v2.12.0 (x86_64/linux)", 1, 5060 },
	{ "yealink", "192.168.68.22", 5060,
	  "REGISTER sip:192.168.68.1:5060 SIP/2.0\r\n"
	  "Via: SIP/2.0/UDP 192.168.68.22:5060;branch=z9hG4bK1741386021\r\n"
	  "From: \"Desk\" <sip:alice@192.168.68.1:5060>;tag=1853278844\r\n"
	  "To: \"Desk\" <sip:alice@192.168.68.1:5060>\r\n"
	  "Call-ID: 0_3071253586@192.168.68.22\r\n"
	  "CSeq: 1 REGISTER\r\n"
	  "Contact: <sip:alice@192.168.68.22:5060>\r\n"
	  "Allow: INVITE, INFO, PRACK, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REGISTER, SUBSCRIBE, REFER, PUBLISH, UPDATE, MESSAGE\r\n"
	  "Max-Forwards: 70\r\n"
	  "User-Agent: Yealink SIP-T46S 66.85.0.5\r\n"
	  "Expires: 3600\r\n"
	  "Allow-Events: talk,hold,conference,refer,check-sync\r\n"
	  "Content-Length: 0\r\n\r\n",
	  "sip:alice@192.168.68.22:5060", 3600, "Yealink SIP-T46S 66.85.0.5", 1, 5060 },
	{ "grandstream", "192.168.68.23", 5062,
	  "REGISTER sip:192.168.68.1 SIP/2.0\r\n"
	  "Via: SIP/2.0/UDP 192.168.68.23:5062;branch=z9hG4bK4c6a1de2;rport\r\n"
	  "Route: <sip:192.168.68.1;lr>\r\n"
	  "From: <sip:alice@192.168.68.1>;tag=8f2e0b0b4c\r\n"
	  "To: <sip:alice@192.168.68.1>\r\n"
	  "Call-ID: 1b9d6f3a-0d1c-4e0f@192.168.68.23\r\n"
	  "CSeq: 2000 REGISTER\r\n"
	  "Contact: <sip:alice@192.168.68.23:5062;ob>;+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-C074AD1234AB>\"\r\n"
	  "Expires: 60\r\n"
	  "Max-Forwards: 70\r\n"
	  "User-Agent: Grandstream GXP1630 1.0.11.8\r\n"
	  "Supported: path\r\n"
	  "Accept: application/sdp\r\n"
	  "Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, SUBSCRIBE, NOTIFY, INFO, REFER, UPDATE\r\n"
	  "Content-Length: 0\r\n\r\n",
	  "sip:alice@192.168.68.23:5062;ob", 60, "Grandstream GXP1630 1.0.11.8", 0, 5062 },
	{ "asterisk-pjsip", "192.168.68.50", 5060,
	  "REGISTER sip:192.168.68.1:5060 SIP/2.0\r\n"
	  "Via: SIP/2.0/UDP 192.168.68.50:5060;rport;branch=z9hG4bKPj4ad6f0f1-9d54-4a47-9b0d-3b3c0c7d1e5a\r\n"
	  "From: <sip:imsd@192.168.68.1>;tag=0dc2f7a7-c5d0-4d2a-8a0b-b5a1e0d2b1f7\r\n"
	  "To: <sip:imsd@192.168.68.1>\r\n"
	  "Call-ID: 7a1e5b6f-1d6f-4fa4-ae5d-3d79e5a2a1b4\r\n"
	  "CSeq: 31822 REGISTER\r\n"
	  "Contact: <sip:imsd@192.168.68.50:5060>\r\n"
	  "Expires: 120\r\n"
	  "Allow: OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, INFO, MESSAGE, REFER\r\n"
	  "Max-Forwards: 70\r\n"
	  "User-Agent: Asterisk PBX 20.5.0\r\n"
	  "Content-Length:  0\r\n\r\n",
	  "sip:imsd@192.168.68.50:5060", 120, "Asterisk PBX 20.5.0", 1, 5060 },
	{ "ipv6-softphone", "fd00::22", 5060,
	  "REGISTER sip:[fd00::1] SIP/2.0\r\n"
	  "Via: SIP/2.0/UDP [fd00::22]:5060;branch=z9hG4bK77aa11;rport\r\n"
	  "From: <sip:bob@[fd00::1]>;tag=abcdef\r\n"
	  "To: <sip:bob@[fd00::1]>\r\n"
	  "Call-ID: v6call1\r\n"
	  "CSeq: 7 REGISTER\r\n"
	  "Max-Forwards: 70\r\n"
	  "Contact: <sip:bob@[fd00::22]:5060;transport=udp>;expires=1800\r\n"
	  "User-Agent: PhoneV6/0.1\r\n"
	  "Content-Length: 0\r\n\r\n",
	  "sip:bob@[fd00::22]:5060;transport=udp", 1800, "PhoneV6/0.1", -1, 5060 },
	{ "folded-nobrackets", "192.168.68.24", 5060,	/* name-addr without <>, folded header, tabs, LF-less spacing */
	  "REGISTER sip:192.168.68.1 SIP/2.0\r\n"
	  "Via: SIP/2.0/UDP 192.168.68.24:5060;branch=z9hG4bKold3261\r\n"
	  "From: sip:alice@192.168.68.1;tag=ff00\r\n"
	  "To: sip:alice@192.168.68.1\r\n"
	  "Call-ID: oldphone-1\r\n"
	  "CSeq: 1 REGISTER\r\n"
	  "Contact: sip:alice@192.168.68.24:5060;expires=600\r\n"
	  "User-Agent: Cisco/SPA504G-7.6.2\r\n"
	  "Allow: ACK, BYE, CANCEL, INFO, INVITE,\r\n\tNOTIFY, OPTIONS, REFER\r\n"
	  "Content-Length: 0\r\n\r\n",
	  "sip:alice@192.168.68.24:5060", 600, "Cisco/SPA504G-7.6.2", 0, 5060 },
};

static void t_realworld(void)
{
	struct uaw w;
	struct registrar *r;
	size_t i;
	char v[400];
	unsigned n = 0;

	uaw_init(&w, NULL, false);
	r = lan_registrar(w.lan);
	for (i = 0; i < sizeof(rw_cases) / sizeof(rw_cases[0]); i++) {
		const struct rw *c = &rw_cases[i];
		const struct reg_binding *b;
		struct addr src = ua_addr(c->ip, c->port);
		reg_id_t id;
		char want[64];

		fakeep_clear(w.f);
		uaw_rx(&w, c->ip, c->port, c->msg);
		if (last_status(&w) != 200)
			printf("  case %s answered %d\n", c->name, last_status(&w));
		CHECK_EQ(last_status(&w), 200);
		CHECK_EQ(reg_count(r), ++n);
		id = reg_identify(r, &src, NULL);
		b = reg_find(r, id);
		CHECK(b != NULL);
		if (!b)
			continue;
		CHECK_STR(b->contact, c->contact);
		CHECK_EQ(b->expires_s, c->expires);
		CHECK_STR(b->ua, c->ua);
		CHECK_EQ(addr_port(&b->target), c->tport);
		CHECK(!b->target_from_src);
		CHECK(addr_equal_ip(&b->src, &src));
		CHECK_EQ(b->allow_known, c->allow_msg >= 0);
		if (c->allow_msg >= 0)
			CHECK_EQ(reg_allows(b, "MESSAGE"), c->allow_msg);
		CHECK(reg_allows(b, "INVITE"));
		/* the answer: exactly the one Contact of this AOR's... well, of all bindings of the AOR */
		snprintf(want, sizeof(want), ";expires=%u", c->expires);
		{
			struct sip_msg m;
			int j, found = 0, bad = 0;

			CHECK(!fakeep_parse(w.f, last_resp(w.f), &m));
			for (j = 0; j < sip_hdr_count(&m, "Contact"); j++) {
				const char *h = sip_hdr(&m, "Contact", j);

				if (strstr(h, c->contact) && strstr(h, want))
					found++;
			}
			CHECK_EQ(found, 1);
			(void)bad;
			sip_hdr(&m, "To", 0);
			CHECK(sip_hdr(&m, "To", 0) != NULL);
			sent_hdr(w.f, last_resp(w.f), "To", v, sizeof(v));
			CHECK(strstr(v, "tag=") != NULL);	/* the registrar's To tag */
			sip_msg_free(&m);
		}
	}
	/* Linphone accepts text/plain, Grandstream only sdp */
	{
		struct addr a = ua_addr("192.168.68.20", 5060), g = ua_addr("192.168.68.23", 5062);
		const struct reg_binding *lb = reg_find(r, reg_identify(r, &a, NULL)), *gb = reg_find(r, reg_identify(r, &g, NULL));

		CHECK(reg_accepts(lb, "text/plain"));
		CHECK(reg_accepts(gb, "application/sdp"));
		CHECK(!reg_accepts(gb, "text/plain"));
		CHECK(!reg_allows(gb, "MESSAGE"));
		CHECK_STR(gb->instance, "<urn:uuid:00000000-0000-1000-8000-C074AD1234AB>");
	}
	/* Two AORs (alice@..., bob@[fd00::1], imsd@...): a re-REGISTER lists only its own AOR's contacts */
	{
		struct sip_msg m;

		fakeep_clear(w.f);
		uaw_rx(&w, "192.168.68.21", 5060, "REGISTER sip:192.168.68.1 SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.68.21:5060;branch=z9hG4bKagain\r\n"
		       "From: <sip:alice@192.168.68.1>;tag=9c1d3e7a55f0b2c1\r\nTo: <sip:alice@192.168.68.1>\r\nCall-ID: 3bd5d9f4b1a0c5@192.168.68.21\r\n"
		       "CSeq: 31246 REGISTER\r\nContact: <sip:alice@192.168.68.21:5060;transport=udp>;expires=900\r\nContent-Length: 0\r\n\r\n");
		CHECK_EQ(last_status(&w), 200);
		CHECK(!fakeep_parse(w.f, last_resp(w.f), &m));
		CHECK_EQ(sip_hdr_count(&m, "Contact"), 5);	/* alice@: linphone, baresip, yealink, grandstream, cisco */
		sip_msg_free(&m);
	}
	uaw_fini(&w);
}

struct feat_seen {
	int n, with_mms;
	uint32_t or_all;
};

static void feat_row(const struct lan_binding_status *s, void *arg)
{
	struct feat_seen *f = arg;

	f->n++;
	f->or_all |= s->features;
	f->with_mms += (s->features & REG_F_MMS) != 0;
}

static unsigned feat_of(struct uaw *w, int k, const char *contact_params)
{
	char ct[400], cid[24];
	const struct reg_binding *b;
	struct addr a = ua_addr(dev_ip(k), 5060);

	snprintf(ct, sizeof(ct), "<sip:u%d@%s:5060>%s", k, dev_ip(k), contact_params);
	snprintf(cid, sizeof(cid), "ft%d", k);
	reg_it(w, k, ct, 1, cid, -1, NULL);
	CHECK_EQ(last_status(w), 200);
	b = reg_find(lan_registrar(w->lan), reg_identify(lan_registrar(w->lan), &a, NULL));
	return b ? b->features : 0xffff;
}

static void t_features(void)
{
	struct uaw w;
	char v[400];
	const struct reg_binding *b;
	struct lan_stats st;
	struct feat_seen fs;

	uaw_init(&w, NULL, false);
	/* with and without a value, any case, among other parameters; the value 0 / false switches a tag off */
	CHECK_EQ(feat_of(&w, 1, ";expires=300"), 0);
	CHECK_EQ(feat_of(&w, 2, ";+g.imsd.mms;expires=300"), REG_F_MMS);
	CHECK_EQ(feat_of(&w, 3, ";+g.imsd.mms=\"1\";+g.imsd.carbons=\"1\""), REG_F_MMS | REG_F_CARBONS);
	CHECK_EQ(feat_of(&w, 4, ";+G.IMSD.Carbons;expires=300"), REG_F_CARBONS);
	CHECK_EQ(feat_of(&w, 5, ";+g.imsd.mms=\"0\";+g.imsd.carbons=false"), 0);
	CHECK_EQ(feat_of(&w, 6, ";+g.imsd.mmsx;+g.imsd.carbon"), 0);		/* other names are not these tags */
	CHECK_EQ(feat_of(&w, 7, ";q=0.5;+g.imsd.mms=yes;expires=300"), REG_F_MMS);
	/* the refresh of a binding replaces the set */
	CHECK_EQ(feat_of(&w, 2, ";expires=300"), 0);
	CHECK_EQ(feat_of(&w, 2, ";+g.imsd.carbons"), REG_F_CARBONS);
	/* the 200 echoes the tags */
	{
		int i, n = resp_contacts(&w, 0, v, sizeof(v)), found = 0;

		for (i = 0; i < n; i++) {
			resp_contacts(&w, i, v, sizeof(v));
			if (strstr(v, "u2@"))
				found = strstr(v, ";+g.imsd.carbons") != NULL && strstr(v, ";+g.imsd.mms") == NULL;
		}
		CHECK(found);
	}
	/* lan_status carries them per binding */
	memset(&fs, 0, sizeof(fs));
	lan_status(w.lan, &st, feat_row, &fs);
	CHECK_EQ(st.bindings, 7);
	CHECK_EQ(fs.n, 7);
	CHECK_EQ(fs.or_all, REG_F_MMS | REG_F_CARBONS);
	CHECK_EQ(fs.with_mms, 2);			/* bindings 3 and 7 (2 became carbons-only) */
	uaw_fini(&w);

	/* the Contact of the Android client as captured: tags without values after other parameters, three Accept lines
	 * that do not list the MMS type, an instance with angle brackets */
	uaw_init(&w, NULL, false);
	fakeep_clear(w.f);
	uaw_rx(&w, dev_ip(1), 5060, mk_register(dev_ip(1),
		"<sip:+821051226862@192.168.68.11:55527;transport=udp>;+g.imsd.mms;+g.imsd.carbons;+sip.instance=\"<urn:uuid:7484f55e-3c82-477a-9446-7bf9ca0b9bb3>\";+org.linphone.specs=\"lime\"",
		1, "cap1", 3600, "Supported: replaces, outbound, gruu, path\r\nAccept: application/sdp\r\nAccept: text/plain\r\n"
		"Accept: application/vnd.gsma.rcs-ft-http+xml\r\nUser-Agent: Softphone/0.1.0 (Linphone)\r\n"));
	CHECK_EQ(last_status(&w), 200);
	b = only_binding(&w);
	CHECK(b != NULL);
	if (b) {
		CHECK_EQ(b->features, REG_F_MMS | REG_F_CARBONS);
		CHECK_STR(b->instance, "<urn:uuid:7484f55e-3c82-477a-9446-7bf9ca0b9bb3>");
		CHECK(reg_accepts(b, "text/plain"));
		CHECK(!reg_accepts(b, "application/vnd.wap.mms-message"));	/* declared Accept lists do not decide about delivery */
	}
	CHECK(resp_contacts(&w, 0, v, sizeof(v)) == 1);
	CHECK(strstr(v, ";+g.imsd.mms;+g.imsd.carbons") != NULL);
	uaw_fini(&w);
}

/* X-IMSD-Ack-Seq of the last REGISTER (store/store.h): a plain decimal number, anything else is reported as malformed */
static void t_ack_seq(void)
{
	struct uaw w;
	struct addr a = ua_addr(dev_ip(1), 5060);
	char ct[200], ex[100];
	static const struct { const char *v; int state; unsigned long long n; } T[] = {
		{ "0", REG_ACK_OK, 0 }, { "17", REG_ACK_OK, 17 }, { "  42 ", REG_ACK_OK, 42 }, { "18446744073709551615", REG_ACK_OK, 18446744073709551615ull },
		{ "18446744073709551616", REG_ACK_BAD, 0 }, { "123456789012345678901", REG_ACK_BAD, 0 }, { "", REG_ACK_BAD, 0 },
		{ "-1", REG_ACK_BAD, 0 }, { "12abc", REG_ACK_BAD, 0 }, { "0x10", REG_ACK_BAD, 0 }, { "1 2", REG_ACK_BAD, 0 }, { "+5", REG_ACK_BAD, 0 },
	};
	unsigned i;
	const struct reg_binding *b;

	uaw_init(&w, NULL, false);
	snprintf(ct, sizeof(ct), "<sip:u1@%s:5060>", dev_ip(1));
	reg_it(&w, 1, ct, 1, "ack0", -1, NULL);
	b = reg_find(lan_registrar(w.lan), reg_identify(lan_registrar(w.lan), &a, NULL));
	CHECK(b && b->ack_state == REG_ACK_NONE && b->ack_seq == 0);
	for (i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
		snprintf(ex, sizeof(ex), "X-IMSD-Ack-Seq: %s\r\n", T[i].v);
		reg_it(&w, 1, ct, (int)i + 2, "ack0", -1, ex);
		CHECK_EQ(last_status(&w), 200);
		b = reg_find(lan_registrar(w.lan), reg_identify(lan_registrar(w.lan), &a, NULL));
		CHECK(b != NULL);
		if (b) {
			CHECK_EQ(b->ack_state, T[i].state);
			CHECK(b->ack_seq == T[i].n);
		}
	}
	/* the next REGISTER without the header: absent again (it is per REGISTER) */
	reg_it(&w, 1, ct, 50, "ack0", -1, NULL);
	b = reg_find(lan_registrar(w.lan), reg_identify(lan_registrar(w.lan), &a, NULL));
	CHECK(b && b->ack_state == REG_ACK_NONE);
	uaw_fini(&w);
}

void test_registrar(void)
{
	t_ack_seq();
	t_features();
	t_basic();
	t_wildcard_expiry();
	t_ordering_instance();
	t_full();
	t_target_and_errors();
	t_realworld();
}
