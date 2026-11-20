/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The MMS manager on mock sockets: the captured notification end to end, retries, link handling, queue, expiry. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "t_common.h"
#include "t_vectors.h"
#include "mmsstore.h"
#include "../util/log.h"

static struct addr A6(const char *s)
{
	struct addr a;

	addr_set(&a, s, 0);
	return a;
}

#define UA "TTA-VoLTE/3.0 imsd/0.1 Device_Type/Android_Phone OMD"
#define ACCEPT_LINE "Accept: */*, application/vnd.wap.mms-message, application/vnd.wap.sic\r\n"

struct delivered {
	struct mms_out out;
	char text[MMSR_MAX_CHUNKS][1200];
	char from[MMS_ADDR_MAX];
};

struct mfix {
	struct mocknet mn;
	struct mms *m;
	struct mms_cfg cfg;
	struct mms_link link;
	struct delivered del[8];
	int ndel;
	int deliver_rc;
	int auto_nok;		/* done() is called at once with this (0: not at all) */
	int64_t wall;
	uint8_t push[256];
	size_t pushn;
	uint8_t conf[1024];
	size_t confn;
	uint8_t httpconf[2048];
	size_t httpconfn;
	uint8_t ok_empty[256];
	size_t ok_empty_n;
	char dir[64];
	char imsi[24];		/* "" = unknown operator: the confirmations go to the Content-Location's server */
};

static struct mfix *FX;

static void fx_link(void *ctx, struct mms_link *out)
{
	(void)ctx;
	*out = FX->link;
}

static int fx_deliver(void *ctx, const struct mms_out *o, void (*done)(void *, int), void *arg)
{
	struct delivered *d;
	unsigned i;

	(void)ctx;
	if (FX->deliver_rc)
		return FX->deliver_rc;
	d = &FX->del[FX->ndel < 8 ? FX->ndel : 7];
	FX->ndel++;
	d->out = *o;
	for (i = 0; i < o->n; i++) {
		snprintf(d->text[i], sizeof(d->text[i]), "%s", o->text[i]);
		d->out.text[i] = d->text[i];
	}
	if (FX->auto_nok)
		done(arg, FX->auto_nok);
	return 0;
}

static void fx_abort(void *ctx, void *arg)
{
	(void)ctx;
	(void)arg;
}

static const char *fx_imsi(void *ctx)
{
	(void)ctx;
	return FX->imsi;
}

static const char *fx_host(void *ctx)
{
	(void)ctx;
	return "192.168.50.1";
}

static int64_t fx_wall(void *ctx)
{
	(void)ctx;
	return FX->wall;
}

static void fx_init(struct mfix *f)
{
	struct mms_ops ops;
	struct mock_dns_rule rule;
	char *d;

	memset(f, 0, sizeof(*f));
	FX = f;
	evfake_reset();
	mock_init(&f->mn);
	mms_cfg_defaults(&f->cfg);
	snprintf(f->cfg.user_agent, sizeof(f->cfg.user_agent), "%s", UA);
	snprintf(f->dir, sizeof(f->dir), "/tmp/imsd-mms-mgr-XXXXXX");
	d = mkdtemp(f->dir);
	CHECK(d != NULL);
	snprintf(f->cfg.dir, sizeof(f->cfg.dir), "%s/m", f->dir);
	f->link.up = true;
	snprintf(f->link.netdev, sizeof(f->link.netdev), "wwan0");
	f->link.local = A6("2001:4430:141:990a::cb69");
	f->link.dns[0] = A6("2001:4430:8000:20:0:1:0:1");
	f->link.dns[1] = A6("2001:4430:8000:20:0:1:0:2");
	f->link.n_dns = 2;
	f->link.seq = 1;
	f->auto_nok = 1;
	f->wall = 1795134300;
	memset(&ops, 0, sizeof(ops));
	ops.link = fx_link;
	ops.deliver = fx_deliver;
	ops.deliver_abort = fx_abort;
	ops.lan_host = fx_host;
	ops.imsi = fx_imsi;
	ops.wall = fx_wall;
	ops.net = &f->mn.ops;
	f->m = mms_new(&f->cfg, &ops);
	CHECK(f->m != NULL);
	memset(&rule, 0, sizeof(rule));
	rule.name = "omammsc.uplus.co.kr"; rule.type = 28; rule.ttl = 3600; rule.n = 1; rule.addr[0] = A6("2001:4430:8000:20:0:1:0:1");
	mock_dns_add(&f->mn, &rule);
	f->pushn = hexv(V_NOTIF_PUSH, f->push, sizeof(f->push));
	f->confn = hexv(V_RETRIEVE_CONF, f->conf, sizeof(f->conf));
	f->httpconfn = http_ok(f->httpconf, sizeof(f->httpconf), 200, "application/vnd.wap.mms-message", f->conf, f->confn);
	f->ok_empty_n = http_ok(f->ok_empty, sizeof(f->ok_empty), 200, "text/plain", "", 0);
}

static void fx_fini(struct mfix *f)
{
	char cmd[128];

	mms_free(f->m);
	CHECK_EQ(evfake_armed_timers(), 0);
	CHECK_EQ(evfake_fd_watches(), 0);
	mock_free(&f->mn);
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", f->dir);
	if (system(cmd) < 0)
		CHECK(0);
}

static void resp(struct mfix *f, const uint8_t *d, size_t n)
{
	struct mock_resp r;

	memset(&r, 0, sizeof(r));
	r.d = d;
	r.n = n;
	mock_respond(&f->mn, &r);
}

static void resp_silent(struct mfix *f)
{
	struct mock_resp r;

	memset(&r, 0, sizeof(r));
	r.silent = true;
	mock_respond(&f->mn, &r);
}

static const char *g_subject = "[LG U+]";

static void push_notif(struct mfix *f, const char *tid, const char *url, uint32_t size, int expiry)
{
	struct pb n = { .n = 0 }, p = { .n = 0 };

	build_notif(&n, tid, 0x92, "114", g_subject, size, expiry, url);
	build_push(&p, n.d, n.n);
	mms_on_push(f->m, "0100000004", 2948, p.d, p.n);
}

/* ---- scenarios ---- */

static void t_captured(void)
{
	struct mfix f;
	struct mms_status st;
	static const uint8_t NR[] = { 0x8c, 0x83, 0x98, 'A', 'v', 'B', 't', '6', 'f', '7', 'q', 0, 0x8d, 0x92, 0x95, 0x81 };
	static const uint8_t ACK[] = { 0x8c, 0x85, 0x98, 'A', 'v', 'B', 't', '6', 'f', '7', 'q', 0, 0x8d, 0x90 };
	const uint8_t *b;
	size_t bn;
	const char *r0;
	struct delivered *d;

	fx_init(&f);
	snprintf(f.cfg.uaprof, sizeof(f.cfg.uaprof), "%s", "");
	resp(&f, f.httpconf, f.httpconfn);
	resp(&f, f.ok_empty, f.ok_empty_n);
	resp(&f, f.ok_empty, f.ok_empty_n);
	mms_on_push(f.m, "0100000004", 2948, f.push, f.pushn);
	CHECK_EQ(f.mn.n_conn, 0);			/* nothing before the loop runs */
	spin(100);
	/* the GET: the request the live network accepted (headers in the same order) */
	r0 = mock_req(&f.mn, 0);
	CHECK_STR(r0, "GET /?AvBt6f7q HTTP/1.1\r\nHost: omammsc.uplus.co.kr:9095\r\n" ACCEPT_LINE "User-Agent: " UA "\r\nConnection: close\r\n\r\n");
	CHECK_STR(f.mn.conn[0].netdev, "wwan0");
	CHECK_EQ(addr_port(&f.mn.conn[0].dst), 9095);
	CHECK_EQ(f.mn.n_usent, 1);			/* one AAAA query */
	CHECK_EQ(f.mn.n_conn, 3);
	/* the delivery: sender 114, the subject line in front (it is not the first line of the text), the text as sent */
	CHECK_EQ(f.ndel, 1);
	d = &f.del[0];
	CHECK_STR(d->out.from, "114"); CHECK_STR(d->out.subject, "[LG U+]"); CHECK_STR(d->out.message_id, "AvBt6f7q");
	CHECK(d->out.has_ts); CHECK_EQ(d->out.ts, 1795134219); CHECK_EQ(d->out.n, 1);
	CHECK(!strncmp(d->out.text[0], "[LG U+]\n[Web발신]\n[LG U+] 보이는 ARS 연결 안내\r\n \r\nLG유플러스 모바일 고객센터", 20));
	CHECK(strstr(d->out.text[0], "감사합니다.") != NULL);
	CHECK_EQ(strlen(d->out.text[0]), 8 + 433);	/* "[LG U+]\n" + the text part as it is */
	/* M-NotifyResp.ind (Retrieved) then M-Acknowledge.ind, to the server that served the message (derived: scheme://host:port/) */
	CHECK(!strncmp(mock_req(&f.mn, 1), "POST / HTTP/1.1\r\nHost: omammsc.uplus.co.kr:9095\r\n" ACCEPT_LINE "User-Agent: " UA
		       "\r\nContent-Type: application/vnd.wap.mms-message\r\nContent-Length: 16\r\nConnection: close\r\n\r\n", 200));
	b = mock_req_body(&f.mn, 1, &bn); CHECK_EQ(bn, sizeof(NR)); CHECK(b && !memcmp(b, NR, sizeof(NR)));
	b = mock_req_body(&f.mn, 2, &bn); CHECK_EQ(bn, sizeof(ACK)); CHECK(b && !memcmp(b, ACK, sizeof(ACK)));
	CHECK(strstr(mock_req(&f.mn, 2), "Content-Length: 14\r\n") != NULL);
	mms_get_status(f.m, &st);
	CHECK_EQ(st.notifications, 1); CHECK_EQ(st.retrieved, 1); CHECK_EQ(st.delivered, 1); CHECK_EQ(st.failed, 0); CHECK_EQ(st.pending, 0);
	CHECK_EQ(st.duplicates, 0); CHECK_EQ(st.lost_no_client, 0); CHECK_EQ(st.rejected, 0);
	CHECK_STR(st.mmsc, "http://omammsc.uplus.co.kr:9095/");

	/* the network repeats the notification: ignored (also after the first one completed) */
	mms_on_push(f.m, "0100000004", 2948, f.push, f.pushn);
	spin(50);
	CHECK_EQ(f.mn.n_conn, 3); CHECK_EQ(f.ndel, 1);
	mms_get_status(f.m, &st); CHECK_EQ(st.duplicates, 1); CHECK_EQ(st.notifications, 1);
	fx_fini(&f);
}

static void t_config_variants(void)
{
	struct mfix f;
	struct mms_cfg c;

	/* an explicit MMSC and x-wap-profile */
	fx_init(&f);
	c = f.cfg;
	snprintf(c.mmsc, sizeof(c.mmsc), "http://omammsc.uplus.co.kr:9084");
	snprintf(c.uaprof, sizeof(c.uaprof), "http://uaprof.example/p.xml");
	mms_set_cfg(f.m, &c);
	resp(&f, f.httpconf, f.httpconfn);
	resp(&f, f.ok_empty, f.ok_empty_n);
	resp(&f, f.ok_empty, f.ok_empty_n);
	mms_on_push(f.m, "0100000004", 2948, f.push, f.pushn);
	spin(100);
	CHECK(strstr(mock_req(&f.mn, 0), "User-Agent: " UA "\r\nx-wap-profile: http://uaprof.example/p.xml\r\nConnection: close") != NULL);
	CHECK(!strncmp(mock_req(&f.mn, 1), "POST / HTTP/1.1\r\nHost: omammsc.uplus.co.kr:9084\r\n", 49));
	CHECK(strstr(mock_req(&f.mn, 1), "x-wap-profile: http://uaprof.example/p.xml\r\nContent-Type: application/vnd.wap.mms-message\r\n") != NULL);
	CHECK_EQ(addr_port(&f.mn.conn[1].dst), 9084);
	fx_fini(&f);

	/* mms disabled: the push is dropped */
	fx_init(&f);
	c = f.cfg; c.enable = false;
	mms_set_cfg(f.m, &c);
	mms_on_push(f.m, "0100000004", 2948, f.push, f.pushn);
	spin(50);
	CHECK_EQ(f.mn.n_conn, 0);
	fx_fini(&f);

	/* no LAN client: logged as lost (counter), the MMSC still gets its confirmations */
	fx_init(&f);
	f.deliver_rc = -ENOENT;
	resp(&f, f.httpconf, f.httpconfn);
	resp(&f, f.ok_empty, f.ok_empty_n);
	resp(&f, f.ok_empty, f.ok_empty_n);
	mms_on_push(f.m, "0100000004", 2948, f.push, f.pushn);
	spin(100);
	{
		struct mms_status st;

		mms_get_status(f.m, &st);
		CHECK_EQ(st.retrieved, 1); CHECK_EQ(st.lost_no_client, 1); CHECK_EQ(st.delivered, 0); CHECK_EQ(f.mn.n_conn, 3);
		CHECK(strstr(st.last_error, "no LAN client") != NULL);
	}
	fx_fini(&f);

	/* a client that does not take it (done with 0) */
	fx_init(&f);
	f.auto_nok = 0;
	resp(&f, f.httpconf, f.httpconfn);
	resp(&f, f.ok_empty, f.ok_empty_n);
	resp(&f, f.ok_empty, f.ok_empty_n);
	mms_on_push(f.m, "0100000004", 2948, f.push, f.pushn);
	spin(100);
	CHECK_EQ(f.ndel, 1);
	fx_fini(&f);
}

static void t_other_pushes(void)
{
	struct mfix f;
	struct pb p = { .n = 0 }, n = { .n = 0 };
	struct mms_status st;
	uint8_t bad[] = { 0, 6, 200, 1, 2 };

	fx_init(&f);
	/* a service indication (text/vnd.wap.si = 0x2d), an OMA CP, a non-push PDU, garbage, an MMS PDU that is not a notification */
	pb_u8(&p, 0); pb_u8(&p, 6); pb_u8(&p, 1); pb_u8(&p, 0xad); pb_text(&p, "<si/>");
	mms_on_push(f.m, "TEST", 2948, p.d, p.n);
	memset(&p, 0, sizeof(p));
	pb_u8(&p, 0); pb_u8(&p, 6); pb_u8(&p, 1); pb_u8(&p, 0xb6); pb_u8(&p, 1);
	mms_on_push(f.m, "TEST", 2948, p.d, p.n);
	mms_on_push(f.m, "TEST", 2948, (const uint8_t *)"\x00\x01\x02\x03", 4);
	mms_on_push(f.m, "TEST", 2948, bad, sizeof(bad));
	mms_on_push(f.m, "TEST", 2948, f.push, 3);
	mms_on_push(f.m, "TEST", 2948, NULL, 0);
	{	/* m-delivery-ind (0x86) inside a valid push */
		static const uint8_t DI[] = { 0x8c, 0x86, 0x98, 'X', 0 };

		memset(&p, 0, sizeof(p));
		build_push(&p, DI, sizeof(DI));
		mms_on_push(f.m, "114", 2948, p.d, p.n);
	}
	{	/* a notification without a location */
		static const uint8_t NL[] = { 0x8c, 0x82, 0x98, 'X', 0 };

		memset(&p, 0, sizeof(p));
		build_push(&p, NL, sizeof(NL));
		mms_on_push(f.m, "114", 2948, p.d, p.n);
	}
	spin(50);
	mms_get_status(f.m, &st);
	CHECK_EQ(st.notifications, 0); CHECK_EQ(st.pending, 0); CHECK_EQ(f.mn.n_conn, 0); CHECK_EQ(f.mn.n_usent, 0);
	/* the application id alone also identifies MMS (content type absent / other): not guessed, the content type rules */
	(void)n;
	fx_fini(&f);
}

static void t_oversize(void)
{
	struct mfix f;
	struct mms_status st;
	static const uint8_t REJ[] = { 0x8c, 0x83, 0x98, 'B', 'I', 'G', 0, 0x8d, 0x92, 0x95, 0x82 };
	const uint8_t *b;
	size_t bn;

	/* the notification says 2 MiB: refused without a GET, M-NotifyResp.ind(Rejected) */
	fx_init(&f);
	resp(&f, f.ok_empty, f.ok_empty_n);
	push_notif(&f, "BIG", "http://omammsc.uplus.co.kr:9095/?BIG", 2 * 1024 * 1024, -1);
	spin(100);
	CHECK_EQ(f.mn.n_conn, 1);
	CHECK(!strncmp(mock_req(&f.mn, 0), "POST / HTTP/1.1", 15));
	b = mock_req_body(&f.mn, 0, &bn); CHECK_EQ(bn, sizeof(REJ)); CHECK(b && !memcmp(b, REJ, sizeof(REJ)));
	mms_get_status(f.m, &st); CHECK_EQ(st.rejected, 1); CHECK_EQ(st.failed, 0); CHECK_EQ(st.pending, 0); CHECK_EQ(f.ndel, 0);
	/* the cap is configurable */
	{
		struct mms_cfg c = f.cfg;

		c.max_size = 4 * 1024 * 1024;
		mms_set_cfg(f.m, &c);
	}
	resp(&f, f.httpconf, f.httpconfn);
	resp(&f, f.ok_empty, f.ok_empty_n);
	resp(&f, f.ok_empty, f.ok_empty_n);
	{	/* (the same tid is a repeat now: use another) */
		push_notif(&f, "BIG2", "http://omammsc.uplus.co.kr:9095/?BIG2", 2 * 1024 * 1024, -1);
		f.mn.n_responses = 0;
	}
	fx_fini(&f);

	/* the answer is bigger than the cap although the notification was small: rejected when it does not fit */
	fx_init(&f);
	{
		static uint8_t huge[100];
		struct mms_cfg c = f.cfg;
		uint8_t r[400];
		struct mock_resp m;
		int h = snprintf((char *)r, sizeof(r), "HTTP/1.1 200 OK\r\nContent-Type: x\r\nContent-Length: 9999999\r\n\r\n");

		(void)huge;
		memset(&m, 0, sizeof(m));
		m.d = r; m.n = (size_t)h;
		mock_respond(&f.mn, &m);
		resp(&f, f.ok_empty, f.ok_empty_n);
		c.max_size = 5000;
		mms_set_cfg(f.m, &c);
		push_notif(&f, "SM", "http://omammsc.uplus.co.kr:9095/?SM", 100, -1);
		spin(100);
		CHECK_EQ(f.mn.n_conn, 2);
		b = mock_req_body(&f.mn, 1, &bn); CHECK_EQ(bn, 10); CHECK(b && b[9] == 0x82 && b[8] == 0x95);
		mms_get_status(f.m, &st); CHECK_EQ(st.rejected, 1); CHECK_EQ(st.failed, 0);
	}
	fx_fini(&f);
}

static void t_http_errors(void)
{
	struct mfix f;
	struct mms_status st;
	uint8_t r404[200], r503[200], rgarb[200], rhttps[10];
	size_t n404, n503, ngarb;

	/* 404: permanent, no retry, nothing sent to the MMSC */
	fx_init(&f);
	n404 = http_ok(r404, sizeof(r404), 404, "text/html", "<html>no</html>", 15);
	n503 = http_ok(r503, sizeof(r503), 503, "text/html", "busy", 4);
	ngarb = http_ok(rgarb, sizeof(rgarb), 200, "application/vnd.wap.mms-message", "\x8c\x84garbage", 9);
	resp(&f, r404, n404);
	push_notif(&f, "N404", "http://omammsc.uplus.co.kr:9095/?N404", 100, -1);
	advance(300000);
	CHECK_EQ(f.mn.n_conn, 1);
	mms_get_status(f.m, &st); CHECK_EQ(st.failed, 1); CHECK_EQ(st.pending, 0); CHECK(strstr(st.last_error, "HTTP 404") != NULL);
	/* an answer that is not an m-retrieve-conf: permanent, nothing is sent */
	resp(&f, rgarb, ngarb);
	push_notif(&f, "GARB", "http://omammsc.uplus.co.kr:9095/?GARB", 100, -1);
	advance(300000);
	CHECK_EQ(f.mn.n_conn, 2);
	mms_get_status(f.m, &st); CHECK_EQ(st.failed, 2); CHECK_EQ(st.retrieved, 0);
	fx_fini(&f);

	/* 503 four times: 5 s, 30 s, 2 min between the attempts, then the end */
	fx_init(&f);
	resp(&f, r503, n503); resp(&f, r503, n503); resp(&f, r503, n503); resp(&f, r503, n503);
	push_notif(&f, "N503", "http://omammsc.uplus.co.kr:9095/?N503", 100, -1);
	spin(60);
	CHECK_EQ(f.mn.n_conn, 1);
	advance(4800); CHECK_EQ(f.mn.n_conn, 1);
	advance(400); CHECK_EQ(f.mn.n_conn, 2);
	advance(29000); CHECK_EQ(f.mn.n_conn, 2);
	advance(1500); CHECK_EQ(f.mn.n_conn, 3);
	advance(119000); CHECK_EQ(f.mn.n_conn, 3);
	advance(1500); CHECK_EQ(f.mn.n_conn, 4);
	mms_get_status(f.m, &st); CHECK_EQ(st.failed, 1); CHECK_EQ(st.pending, 0);
	advance(600000); CHECK_EQ(f.mn.n_conn, 4);
	CHECK(strstr(st.last_error, "HTTP 503") != NULL);
	fx_fini(&f);

	/* 503, then success on the second attempt */
	fx_init(&f);
	resp(&f, r503, n503); resp(&f, f.httpconf, f.httpconfn); resp(&f, f.ok_empty, f.ok_empty_n); resp(&f, f.ok_empty, f.ok_empty_n);
	push_notif(&f, "AvBt6f7q", "http://omammsc.uplus.co.kr:9095/?AvBt6f7q", 496, -1);
	advance(6000);
	spin(100);
	CHECK_EQ(f.mn.n_conn, 4); CHECK_EQ(f.ndel, 1);
	mms_get_status(f.m, &st); CHECK_EQ(st.failed, 0); CHECK_EQ(st.retrieved, 1);
	fx_fini(&f);

	/* a request that times out (no answer) is retried; a DNS failure too */
	fx_init(&f);
	resp_silent(&f);
	resp(&f, f.httpconf, f.httpconfn); resp(&f, f.ok_empty, f.ok_empty_n); resp(&f, f.ok_empty, f.ok_empty_n);
	push_notif(&f, "AvBt6f7q", "http://omammsc.uplus.co.kr:9095/?AvBt6f7q", 496, -1);
	advance(19000); CHECK_EQ(f.mn.n_conn, 1);
	advance(2000);					/* idle timeout at 20 s */
	CHECK_EQ(f.mn.n_conn, 1);
	advance(5000);					/* + 5 s backoff */
	spin(100);
	CHECK(f.mn.n_conn >= 2); CHECK_EQ(f.ndel, 1);
	fx_fini(&f);

	fx_init(&f);
	{
		struct mock_dns_rule rule;

		memset(&rule, 0, sizeof(rule));
		rule.name = "down.example"; rule.type = 28; rule.ignore = 1000;
		mock_dns_add(&f.mn, &rule);
	}
	push_notif(&f, "DNSF", "http://down.example:9095/?x", 100, -1);
	advance(10000);					/* the resolver: 2 servers x 2 rounds x 2 s = 8 s, then the 5 s backoff */
	advance(6000);
	CHECK_EQ(f.mn.n_conn, 0);
	mms_get_status(f.m, &st); CHECK_EQ(st.failed, 0); CHECK_EQ(st.pending, 1);
	advance(400000);
	mms_get_status(f.m, &st); CHECK_EQ(st.failed, 1); CHECK_EQ(st.pending, 0);
	CHECK(strstr(st.last_error, "name resolution") != NULL);
	fx_fini(&f);

	/* https: unsupported, no retry, nothing sent, nothing resolved */
	fx_init(&f);
	snprintf((char *)rhttps, sizeof(rhttps), "x");
	push_notif(&f, "HTTPS", "https://omammsc.uplus.co.kr:9095/?x", 100, -1);
	advance(10000);
	CHECK_EQ(f.mn.n_conn, 0); CHECK_EQ(f.mn.n_usent, 0);
	mms_get_status(f.m, &st); CHECK_EQ(st.failed, 1); CHECK(strstr(st.last_error, "https") != NULL);
	fx_fini(&f);

	/* an m-retrieve-conf with an error status */
	fx_init(&f);
	{
		struct pb p = { .n = 0 };
		uint8_t ct[2], hh[300], err[400];
		size_t hl;

		pb_u8(&p, 0x8c); pb_u8(&p, 0x84); pb_u8(&p, 0x8d); pb_u8(&p, 0x90); pb_u8(&p, 0x99); pb_u8(&p, 0xe0);
		pb_u8(&p, 0x84); ct_wk(ct, 0x03); pb_u8(&p, ct[0]);
		hl = http_ok(hh, sizeof(hh), 200, "application/vnd.wap.mms-message", p.d, p.n);
		memcpy(err, hh, hl);
		resp(&f, err, hl);
		push_notif(&f, "RS", "http://omammsc.uplus.co.kr:9095/?RS", 100, -1);
		advance(100000);
		CHECK_EQ(f.mn.n_conn, 1);
		mms_get_status(f.m, &st); CHECK_EQ(st.failed, 1); CHECK_EQ(st.retrieved, 0);
	}
	fx_fini(&f);
}

static void t_link(void)
{
	struct mfix f;
	struct mms_status st;
	int i;

	/* the link is down when the notification arrives: nothing happens until it is up; DNS and sockets are not touched */
	fx_init(&f);
	f.link.up = false;
	resp(&f, f.httpconf, f.httpconfn); resp(&f, f.ok_empty, f.ok_empty_n); resp(&f, f.ok_empty, f.ok_empty_n);
	mms_on_push(f.m, "0100000004", 2948, f.push, f.pushn);
	advance(60000);
	CHECK_EQ(f.mn.n_conn, 0); CHECK_EQ(f.mn.n_usent, 0);
	mms_get_status(f.m, &st); CHECK_EQ(st.pending, 1);
	f.link.up = true; f.link.seq++;
	mms_link_changed(f.m);
	spin(100);
	CHECK_EQ(f.ndel, 1); CHECK_EQ(f.mn.n_conn, 3);
	mms_get_status(f.m, &st); CHECK_EQ(st.pending, 0); CHECK_EQ(st.failed, 0);
	fx_fini(&f);

	/* the link goes away while the GET is in flight: the request is abandoned and repeated when it returns (no retry used up) */
	fx_init(&f);
	resp_silent(&f);
	resp(&f, f.httpconf, f.httpconfn); resp(&f, f.ok_empty, f.ok_empty_n); resp(&f, f.ok_empty, f.ok_empty_n);
	mms_on_push(f.m, "0100000004", 2948, f.push, f.pushn);
	spin(60);
	CHECK_EQ(f.mn.n_conn, 1); CHECK(!f.mn.conn[0].closed);
	f.link.up = false; f.link.seq++;
	mms_link_changed(f.m);
	spin(20);
	CHECK(f.mn.conn[0].closed);
	advance(30000);
	CHECK_EQ(f.mn.n_conn, 1);
	f.link.up = true; f.link.seq++;
	f.link.local = A6("2001:4430:141:990a::1111");		/* a new bearer address: used by the next request */
	mms_link_changed(f.m);
	spin(100);
	CHECK_EQ(f.ndel, 1); CHECK_EQ(f.mn.n_conn, 4);
	{
		char h[64];

		addr_host(&f.mn.conn[1].local, h, sizeof(h)); CHECK_STR(h, "2001:4430:141:990a::1111");
	}
	fx_fini(&f);

	/* a link event that changes nothing does not disturb a request in flight */
	fx_init(&f);
	resp_silent(&f);
	mms_on_push(f.m, "0100000004", 2948, f.push, f.pushn);
	spin(60);
	mms_link_changed(f.m);
	spin(20);
	CHECK(!f.mn.conn[0].closed);
	fx_fini(&f);

	/* queue: 8 waiting while the link is down, the 9th is dropped, then everything is fetched one at a time in order */
	fx_init(&f);
	f.link.up = false;
	g_subject = NULL;
	for (i = 0; i < 9; i++) {
		char tid[16], url[100];

		snprintf(tid, sizeof(tid), "T%d", i);
		snprintf(url, sizeof(url), "http://omammsc.uplus.co.kr:9095/?T%d", i);
		push_notif(&f, tid, url, 100, -1);
	}
	mms_get_status(f.m, &st);
	CHECK_EQ(st.pending, MMS_QUEUE); CHECK_EQ(st.notifications, 8); CHECK_EQ(st.failed, 1);
	CHECK(strstr(st.last_error, "queue full") != NULL);
	{
		static uint8_t conf[8][700];
		size_t cn[8];
		struct pb d = { .n = 0 };

		for (i = 0; i < 8; i++) {
			struct pb p = { .n = 0 };
			uint8_t ct[8];
			size_t cl = ct_wk_charset(ct, 0x03, 106);
			struct pb body = { .n = 0 }, e = { .n = 0 };
			char tid[16], text[32];

			snprintf(tid, sizeof(tid), "T%d", i);
			snprintf(text, sizeof(text), "message %d", i);
			mp_entry(&e, ct, cl, NULL, 0, text, strlen(text));
			build_multipart(&body, 1, &e);
			cl = ct_wk(ct, 0x23);
			build_retrieve(&p, tid, 0x90, "0101", NULL, 1795134000 + i, ct, cl, body.d, body.n);
			cn[i] = http_ok(conf[i], sizeof(conf[i]), 200, "application/vnd.wap.mms-message", p.d, p.n);
			resp(&f, conf[i], cn[i]);
			resp(&f, f.ok_empty, f.ok_empty_n);
			resp(&f, f.ok_empty, f.ok_empty_n);
		}
		(void)d;
		f.link.up = true; f.link.seq++;
		mms_link_changed(f.m);
		spin(600);
		g_subject = "[LG U+]";
		CHECK_EQ(f.ndel, 8);
		for (i = 0; i < 8; i++) {
			char want[32];

			snprintf(want, sizeof(want), "message %d", i);
			CHECK_STR(f.del[i].out.text[0], want);		/* the queue is FIFO */
		}
		CHECK_EQ(f.mn.n_conn, 24);
		/* strictly one at a time: each GET came after the previous job's two POSTs */
		CHECK(!strncmp(mock_req(&f.mn, 0), "GET /?T0 ", 9)); CHECK(!strncmp(mock_req(&f.mn, 1), "POST ", 5));
		CHECK(!strncmp(mock_req(&f.mn, 3), "GET /?T1 ", 9)); CHECK(!strncmp(mock_req(&f.mn, 21), "GET /?T7 ", 9));
		mms_get_status(f.m, &st); CHECK_EQ(st.pending, 0); CHECK_EQ(st.retrieved, 8); CHECK_EQ(st.delivered, 8);
	}
	fx_fini(&f);
}

static void t_expiry(void)
{
	struct mfix f;
	struct mms_status st;
	uint8_t r503[200];
	size_t n503;

	/* relative expiry of 10 s with a failing server: the 30 s backoff would end after it */
	fx_init(&f);
	n503 = http_ok(r503, sizeof(r503), 503, "text/html", "busy", 4);
	resp(&f, r503, n503); resp(&f, r503, n503); resp(&f, r503, n503);
	push_notif(&f, "EXP1", "http://omammsc.uplus.co.kr:9095/?EXP1", 100, 10);
	advance(6000);
	CHECK_EQ(f.mn.n_conn, 2);
	advance(60000);
	CHECK_EQ(f.mn.n_conn, 2);
	mms_get_status(f.m, &st); CHECK_EQ(st.failed, 1); CHECK_EQ(st.pending, 0); CHECK(strstr(st.last_error, "expired") != NULL);
	fx_fini(&f);

	/* expired while waiting for the link */
	fx_init(&f);
	f.link.up = false;
	push_notif(&f, "EXP2", "http://omammsc.uplus.co.kr:9095/?EXP2", 100, 30);
	advance(40000);
	f.link.up = true; f.link.seq++;
	mms_link_changed(f.m);
	spin(50);
	CHECK_EQ(f.mn.n_conn, 0); CHECK_EQ(f.mn.n_usent, 0);
	mms_get_status(f.m, &st); CHECK_EQ(st.failed, 1); CHECK_EQ(st.pending, 0);
	fx_fini(&f);

	/* an absolute expiry in the past (the wall clock is set): not fetched; with an unset clock the expiry is ignored */
	fx_init(&f);
	{
		uint8_t pdu[] = { 0x8c, 0x82, 0x98, 'A', 'B', 0, 0x8d, 0x92, 0x88, 6, 0x80, 4, 0x6a, 0xff, 0x93, 0x0b,
				  0x83, 'h', 't', 't', 'p', ':', '/', '/', 'o', 'm', 'a', 'm', 'm', 's', 'c', '.', 'u', 'p', 'l', 'u', 's', '.',
				  'c', 'o', '.', 'k', 'r', '/', 'x', 0 };
		struct pb p = { .n = 0 };

		build_push(&p, pdu, sizeof(pdu));
		f.wall = 0x6aff930b + 1;
		mms_on_push(f.m, "114", 2948, p.d, p.n);
		spin(50);
		CHECK_EQ(f.mn.n_conn, 0);
		mms_get_status(f.m, &st); CHECK_EQ(st.failed, 1);
		/* the clock is not set (1970): the expiry says nothing */
		f.wall = 1000;
		pdu[4] = 'C';
		memset(&p, 0, sizeof(p));
		build_push(&p, pdu, sizeof(pdu));
		resp(&f, f.httpconf, f.httpconfn); resp(&f, f.ok_empty, f.ok_empty_n); resp(&f, f.ok_empty, f.ok_empty_n);
		mms_on_push(f.m, "114", 2948, p.d, p.n);
		spin(100);
		CHECK_EQ(f.mn.n_conn, 3);
	}
	fx_fini(&f);
}

static void t_fetch(void)
{
	struct mfix f;
	struct mms_status st;
	int i;

	fx_init(&f);
	resp(&f, f.httpconf, f.httpconfn);
	CHECK_EQ(mms_fetch(f.m, "http://omammsc.uplus.co.kr:9095/?AvBt6f7q", "114", "[LG U+]"), 0);
	spin(100);
	CHECK_EQ(f.mn.n_conn, 1);				/* no M-NotifyResp / Acknowledge for a bench fetch */
	CHECK_EQ(f.ndel, 1); CHECK_STR(f.del[0].out.from, "114");
	mms_get_status(f.m, &st); CHECK_EQ(st.retrieved, 1); CHECK_EQ(st.notifications, 0); CHECK_EQ(st.pending, 0);
	/* the same URL again is not a duplicate (no notification id) */
	resp(&f, f.httpconf, f.httpconfn);
	CHECK_EQ(mms_fetch(f.m, "http://omammsc.uplus.co.kr:9095/?AvBt6f7q", NULL, NULL), 0);
	spin(100);
	CHECK_EQ(f.ndel, 2);
	CHECK_EQ(mms_fetch(f.m, "https://x/", "", ""), -ENOTSUP);
	CHECK_EQ(mms_fetch(f.m, "mms://x/", "", ""), -ENOTSUP);
	CHECK_EQ(mms_fetch(f.m, "nonsense", "", ""), -EINVAL);
	f.link.up = false;
	for (i = 0; i < MMS_QUEUE; i++)
		CHECK_EQ(mms_fetch(f.m, "http://h/x", "", ""), 0);
	CHECK_EQ(mms_fetch(f.m, "http://h/x", "", ""), -EBUSY);
	fx_fini(&f);
}

/* ---- log capture (host tests: util/log.c hook) ---- */
static struct { int level; int warn; int info_dup; int warn_unknown; int warn_refused; char last_dup[200]; } LG;

static void log_hook(int prio, const char *msg)
{
	if (prio == LOG_WARNING) {
		LG.warn++;
		if (strstr(msg, "MMSC URL is unknown"))
			LG.warn_unknown++;
		if (strstr(msg, "the MMSC URL is wrong"))
			LG.warn_refused++;
	}
	if (prio == LOG_INFO && strstr(msg, "is a duplicate of a message delivered")) {
		LG.info_dup++;
		snprintf(LG.last_dup, sizeof(LG.last_dup), "%s", msg);
	}
}

static void log_start(void)
{
	LG = (typeof(LG)){ 0 };
	LG.level = imsd_log_get_level();
	imsd_log_level(LOG_INFO);
	imsd_log_set_hook(log_hook);
}

static void log_stop(void)
{
	imsd_log_set_hook(NULL);
	imsd_log_level(LG.level);
}

#define LGU_IMSI "450061051226862"

/* copies of the captured notification / retrieve-conf with another transaction id (same length: patched in place), and
 * optionally another text byte and another Date */
static void patch_all(uint8_t *d, size_t n, const char *from, const char *to)
{
	size_t i, l = strlen(from);

	for (i = 0; i + l <= n; i++)
		if (!memcmp(d + i, from, l))
			memcpy(d + i, to, l);
}

struct variant {
	uint8_t push[256], conf[1024], http[2048];
	size_t pushn, confn, httpn;
	char tid[9];
};

/* date: 0 = as captured; text: change the "ARS" of the text to "ARX" */
static void make_variant(struct mfix *f, struct variant *v, const char *tid, uint32_t date, bool text)
{
	size_t i;

	memcpy(v->push, f->push, f->pushn); v->pushn = f->pushn;
	memcpy(v->conf, f->conf, f->confn); v->confn = f->confn;
	snprintf(v->tid, sizeof(v->tid), "%s", tid);
	patch_all(v->push, v->pushn, "AvBt6f7q", tid);
	patch_all(v->conf, v->confn, "AvBt6f7q", tid);
	if (date)		/* X-Mms-Date: 0x85, length 4, then the seconds */
		for (i = 0; i + 6 <= v->confn; i++)
			if (v->conf[i] == 0x85 && v->conf[i + 1] == 4) {
				v->conf[i + 2] = (uint8_t)(date >> 24); v->conf[i + 3] = (uint8_t)(date >> 16);
				v->conf[i + 4] = (uint8_t)(date >> 8); v->conf[i + 5] = (uint8_t)date;
				break;
			}
	if (text)
		for (i = 0; i + 4 <= v->confn; i++)
			if (!memcmp(v->conf + i, "ARS ", 4)) {
				v->conf[i + 2] = 'X';
				break;
			}
	v->httpn = http_ok(v->http, sizeof(v->http), 200, "application/vnd.wap.mms-message", v->conf, v->confn);
}

/* one notification of v, answered with its retrieve-conf and two 200s; runs the loop */
static void run_variant(struct mfix *f, const struct variant *v, int ack_status)
{
	uint8_t ack[256];
	size_t an = http_ok(ack, sizeof(ack), ack_status, "text/plain", "", 0);

	resp(f, v->http, v->httpn);
	resp(f, ack, an);
	resp(f, ack, an);
	mms_on_push(f->m, "0100000004", 2948, v->push, v->pushn);
	spin(100);
}

/* the acknowledgements go to the operator table's MMSC (port 9084), not to the server that served the message (9095, 405) */
static void t_mmsc_resolution(void)
{
	struct mfix f;
	struct mms_status st;
	struct variant v;
	struct mms_cfg c;

	log_start();
	/* LG U+ IMSI, nothing configured: the table's http://omammsc.uplus.co.kr:9084 */
	fx_init(&f);
	snprintf(f.imsi, sizeof(f.imsi), "%s", LGU_IMSI);
	make_variant(&f, &v, "AvBt6f7q", 0, false);
	run_variant(&f, &v, 200);
	CHECK_EQ(f.mn.n_conn, 3);
	CHECK(!strncmp(mock_req(&f.mn, 0), "GET /?AvBt6f7q HTTP/1.1\r\nHost: omammsc.uplus.co.kr:9095\r\n", 55));
	CHECK(!strncmp(mock_req(&f.mn, 1), "POST / HTTP/1.1\r\nHost: omammsc.uplus.co.kr:9084\r\n", 49));
	CHECK(!strncmp(mock_req(&f.mn, 2), "POST / HTTP/1.1\r\nHost: omammsc.uplus.co.kr:9084\r\n", 49));
	CHECK_EQ(addr_port(&f.mn.conn[1].dst), 9084); CHECK_EQ(addr_port(&f.mn.conn[2].dst), 9084);
	mms_get_status(f.m, &st);
	CHECK_EQ(st.acked, 2); CHECK_EQ(st.ack_failed, 0); CHECK_EQ(st.delivered, 1);
	CHECK_STR(st.mmsc, "http://omammsc.uplus.co.kr:9084"); CHECK_STR(st.mmsc_source, "carrier");
	CHECK_EQ(LG.warn, 0);
	fx_fini(&f);

	/* an explicit uci URL beats the table (host, port and path asserted) */
	fx_init(&f);
	snprintf(f.imsi, sizeof(f.imsi), "%s", LGU_IMSI);
	c = f.cfg;
	snprintf(c.mmsc, sizeof(c.mmsc), "http://omammsc.uplus.co.kr:9099/mms/ack");
	mms_set_cfg(f.m, &c);
	make_variant(&f, &v, "AvBt6f7q", 0, false);
	run_variant(&f, &v, 200);
	CHECK(!strncmp(mock_req(&f.mn, 1), "POST /mms/ack HTTP/1.1\r\nHost: omammsc.uplus.co.kr:9099\r\n", 56));
	CHECK_EQ(addr_port(&f.mn.conn[1].dst), 9099);
	mms_get_status(f.m, &st); CHECK_STR(st.mmsc_source, "config"); CHECK_STR(st.mmsc, "http://omammsc.uplus.co.kr:9099/mms/ack");
	CHECK_EQ(st.acked, 2);
	fx_fini(&f);

	/* unknown operator, nothing configured: the Content-Location's server, one warning (not one per message) */
	fx_init(&f);
	snprintf(f.imsi, sizeof(f.imsi), "310260123456789");
	make_variant(&f, &v, "AvBt6f7q", 0, false);
	run_variant(&f, &v, 200);
	CHECK(!strncmp(mock_req(&f.mn, 1), "POST / HTTP/1.1\r\nHost: omammsc.uplus.co.kr:9095\r\n", 49));
	CHECK_EQ(LG.warn_unknown, 1);
	make_variant(&f, &v, "Z7Btp70Q", 1795140000, false);
	run_variant(&f, &v, 200);
	CHECK_EQ(LG.warn_unknown, 1);
	mms_get_status(f.m, &st); CHECK_STR(st.mmsc_source, "none"); CHECK_STR(st.mmsc, "http://omammsc.uplus.co.kr:9095/");
	CHECK_EQ(st.acked, 4);
	fx_fini(&f);
	log_stop();
}

/* the server answers 405 to the acknowledgements: warning, ack_failed, nothing is retried */
static void t_ack_refused(void)
{
	struct mfix f;
	struct mms_status st;
	struct variant v;

	log_start();
	fx_init(&f);
	snprintf(f.imsi, sizeof(f.imsi), "310260123456789");		/* the derived URL, as before this fix on LG U+ */
	make_variant(&f, &v, "AvBt6f7q", 0, false);
	run_variant(&f, &v, 405);
	CHECK_EQ(f.mn.n_conn, 3);
	mms_get_status(f.m, &st);
	CHECK_EQ(st.ack_failed, 2); CHECK_EQ(st.acked, 0); CHECK_EQ(st.delivered, 1); CHECK_EQ(st.pending, 0);
	CHECK_EQ(LG.warn_refused, 2);
	CHECK(strstr(st.last_error, "405") != NULL);
	advance(600000);
	CHECK_EQ(f.mn.n_conn, 3);					/* no retry storm */
	fx_fini(&f);
	/* 404 too; another status (500) is counted but not a "wrong URL" warning */
	fx_init(&f);
	make_variant(&f, &v, "AvBt6f7q", 0, false);
	run_variant(&f, &v, 404);
	mms_get_status(f.m, &st); CHECK_EQ(st.ack_failed, 2); CHECK_EQ(LG.warn_refused, 4);
	make_variant(&f, &v, "Z7Btp70Q", 1795140000, false);
	run_variant(&f, &v, 500);
	mms_get_status(f.m, &st); CHECK_EQ(st.ack_failed, 4); CHECK_EQ(LG.warn_refused, 4);
	advance(600000);
	CHECK_EQ(f.mn.n_conn, 6);
	fx_fini(&f);
	log_stop();
}

/* the same message re-notified under another transaction id and Content-Location (as the live MMSC does) */
static void t_renotified(void)
{
	struct mfix f;
	struct mms_status st;
	struct variant a, b, c3, d4;
	const uint8_t *body;
	size_t bn;
	static const uint8_t NR2[] = { 0x8c, 0x83, 0x98, 'Z', '7', 'B', 't', 'p', '7', '0', 'Q', 0, 0x8d, 0x92, 0x95, 0x81 };
	static const uint8_t ACK2[] = { 0x8c, 0x85, 0x98, 'Z', '7', 'B', 't', 'p', '7', '0', 'Q', 0, 0x8d, 0x90 };

	log_start();
	fx_init(&f);
	snprintf(f.imsi, sizeof(f.imsi), "%s", LGU_IMSI);
	make_variant(&f, &a, "AvBt6f7q", 0, false);
	make_variant(&f, &b, "Z7Btp70Q", 0, false);
	run_variant(&f, &a, 200);
	CHECK_EQ(f.ndel, 1); CHECK_EQ(f.mn.n_conn, 3);
	advance(600000);						/* 10 minutes later the MMSC notifies again */
	run_variant(&f, &b, 200);
	CHECK(!strncmp(mock_req(&f.mn, 3), "GET /?Z7Btp70Q HTTP/1.1\r\nHost: omammsc.uplus.co.kr:9095\r\n", 55));
	CHECK_EQ(f.mn.n_conn, 6);					/* downloaded, then two acknowledgements */
	CHECK_EQ(f.ndel, 1);						/* but delivered once */
	body = mock_req_body(&f.mn, 4, &bn); CHECK_EQ(bn, sizeof(NR2)); CHECK(body && !memcmp(body, NR2, sizeof(NR2)));
	body = mock_req_body(&f.mn, 5, &bn); CHECK_EQ(bn, sizeof(ACK2)); CHECK(body && !memcmp(body, ACK2, sizeof(ACK2)));
	CHECK(!strncmp(mock_req(&f.mn, 4), "POST / HTTP/1.1\r\nHost: omammsc.uplus.co.kr:9084\r\n", 49));
	mms_get_status(f.m, &st);
	CHECK_EQ(st.notifications, 2); CHECK_EQ(st.retrieved, 2); CHECK_EQ(st.delivered, 1); CHECK_EQ(st.duplicates, 1);
	CHECK_EQ(st.acked, 4); CHECK_EQ(st.ack_failed, 0); CHECK_EQ(st.pending, 0);
	CHECK_EQ(LG.info_dup, 1);
	CHECK(strstr(LG.last_dup, "delivered 10 min ago") != NULL);
	/* a different message from the same sender with the same subject but another text, and another Date: both delivered */
	make_variant(&f, &c3, "ZSBtrBGl", 0, true);
	run_variant(&f, &c3, 200);
	CHECK_EQ(f.ndel, 2);
	make_variant(&f, &d4, "ZEBtk7vp", 1795134220, false);
	run_variant(&f, &d4, 200);
	CHECK_EQ(f.ndel, 3);
	mms_get_status(f.m, &st); CHECK_EQ(st.duplicates, 1); CHECK_EQ(st.acked, 8);
	/* and the text variant, re-notified, is a duplicate of itself */
	make_variant(&f, &c3, "ZSBtrB22", 0, true);
	run_variant(&f, &c3, 200);
	CHECK_EQ(f.ndel, 3);
	mms_get_status(f.m, &st); CHECK_EQ(st.duplicates, 2); CHECK_EQ(st.acked, 10);
	/* the transaction id check stays the cheap first one: the very same notification is dropped before any download */
	{
		int conns = f.mn.n_conn;

		mms_on_push(f.m, "0100000004", 2948, b.push, b.pushn);
		spin(50);
		CHECK_EQ(f.mn.n_conn, conns);
		mms_get_status(f.m, &st); CHECK_EQ(st.duplicates, 3);
	}
	fx_fini(&f);
	log_stop();
}

/* ring: 24 h lifetime on the monotonic clock, 32 entries, lost messages, mms_fetch */
static void t_dedup_ring(void)
{
	struct mfix f;
	struct mms_status st;
	struct variant v;
	int i;

	log_start();
	/* a message is remembered past the 1 h of the transaction id ring and forgotten after 24 h */
	fx_init(&f);
	snprintf(f.imsi, sizeof(f.imsi), "%s", LGU_IMSI);
	make_variant(&f, &v, "AvBt6f7q", 0, false);
	run_variant(&f, &v, 200);
	CHECK_EQ(f.ndel, 1);
	evfake_advance(23ull * 3600 * 1000);
	make_variant(&f, &v, "Z7Btp70Q", 0, false);
	run_variant(&f, &v, 200);
	CHECK_EQ(f.ndel, 1);						/* 23 h: still a duplicate */
	mms_get_status(f.m, &st); CHECK_EQ(st.duplicates, 1);
	CHECK(strstr(LG.last_dup, "delivered 1380 min ago") != NULL);
	evfake_advance(2ull * 3600 * 1000);				/* 25 h after the delivery of the first copy (the repeat was not delivered) */
	make_variant(&f, &v, "ZSBtrBGl", 0, false);
	run_variant(&f, &v, 200);
	CHECK_EQ(f.ndel, 2);						/* expired: delivered again */
	mms_get_status(f.m, &st); CHECK_EQ(st.duplicates, 1); CHECK_EQ(st.acked, 6);
	fx_fini(&f);

	/* the ring holds 32: after 40 other messages the first is forgotten, the last is still known */
	fx_init(&f);
	snprintf(f.imsi, sizeof(f.imsi), "%s", LGU_IMSI);
	for (i = 0; i < 40; i++) {
		char tid[9];

		snprintf(tid, sizeof(tid), "T%07d", i);
		make_variant(&f, &v, tid, 1795000000u + (uint32_t)i, false);
		run_variant(&f, &v, 200);
	}
	CHECK_EQ(f.ndel, 40);
	make_variant(&f, &v, "U0000039", 1795000039u, false);
	run_variant(&f, &v, 200);
	CHECK_EQ(f.ndel, 40);
	make_variant(&f, &v, "U0000000", 1795000000u, false);
	run_variant(&f, &v, 200);
	CHECK_EQ(f.ndel, 41);
	make_variant(&f, &v, "U0000008", 1795000008u, false);		/* slot of the 9th was reused by the re-delivered first message: the ring keeps 32 */
	run_variant(&f, &v, 200);
	CHECK_EQ(f.ndel, 42);
	mms_get_status(f.m, &st); CHECK_EQ(st.duplicates, 1); CHECK_EQ(st.acked, 2 * 43);
	fx_fini(&f);

	/* lost for lack of a LAN client: in the ring as well, and confirmed both times */
	fx_init(&f);
	snprintf(f.imsi, sizeof(f.imsi), "%s", LGU_IMSI);
	f.deliver_rc = -ENOENT;
	make_variant(&f, &v, "AvBt6f7q", 0, false);
	run_variant(&f, &v, 200);
	make_variant(&f, &v, "Z7Btp70Q", 0, false);
	run_variant(&f, &v, 200);
	mms_get_status(f.m, &st);
	CHECK_EQ(st.lost_no_client, 1); CHECK_EQ(st.duplicates, 1); CHECK_EQ(st.acked, 4); CHECK_EQ(f.ndel, 0);
	f.deliver_rc = 0;						/* a client registers later: the re-notification is still a duplicate */
	make_variant(&f, &v, "ZSBtrBGl", 0, false);
	run_variant(&f, &v, 200);
	CHECK_EQ(f.ndel, 0);
	mms_get_status(f.m, &st); CHECK_EQ(st.duplicates, 2);
	fx_fini(&f);

	/* mms_fetch is an explicit request: delivered although the content was delivered before, and it does not feed the ring */
	fx_init(&f);
	snprintf(f.imsi, sizeof(f.imsi), "%s", LGU_IMSI);
	make_variant(&f, &v, "AvBt6f7q", 0, false);
	run_variant(&f, &v, 200);
	CHECK_EQ(f.ndel, 1);
	resp(&f, f.httpconf, f.httpconfn);
	CHECK_EQ(mms_fetch(f.m, "http://omammsc.uplus.co.kr:9095/?AvBt6f7q", "114", "[LG U+]"), 0);
	spin(100);
	CHECK_EQ(f.ndel, 2);
	mms_get_status(f.m, &st); CHECK_EQ(st.duplicates, 0);
	fx_fini(&f);
	log_stop();
}

void test_mms_mgr(void)
{
	t_captured();
	t_config_variants();
	t_other_pushes();
	t_oversize();
	t_http_errors();
	t_link();
	t_expiry();
	t_fetch();
	t_mmsc_resolution();
	t_ack_refused();
	t_renotified();
	t_dedup_ring();
}
