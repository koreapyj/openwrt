/* SPDX-License-Identifier: GPL-2.0-or-later */
/* core: request dispatch by endpoint, module / hook registration, LAN lifecycle, RTP socket helpers */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "test.h"
#include "fakeep.h"
#include "evloop_fake.h"
#include "../core.h"
#include "../util/ifaddr.h"
#include "../util/rtpsock.h"
#include "../ua/regpersist_mod.h"
#include <sys/stat.h>
#include <time.h>

/* ---------------- fixture ---------------- */

#define MAXEP 8
static struct {
	struct fakeep *eps[MAXEP];
	int n_open;
	int open_fail;		/* next open_ep fails with this errno */
	char lan_ip[32];	/* what the resolver returns, "" = no address */
	int n_lookup;
	struct { int added, removed, other; char contact[256], ua[96]; } bind;
} T;

static struct sip_endpoint *t_open_ep(void *ctx, const struct sip_ep_cfg *cfg)
{
	(void)ctx;
	if (T.open_fail) {
		errno = T.open_fail;
		T.open_fail = 0;
		return NULL;
	}
	T.eps[T.n_open] = fakeep_open(cfg);
	return T.eps[T.n_open++]->ep;
}

static int t_lan_addr(void *ctx, const char *ifname, const struct addr *prefer, struct addr *out)
{
	(void)ctx; (void)ifname; (void)prefer;
	T.n_lookup++;
	if (!T.lan_ip[0])
		return -1;
	return addr_set(out, T.lan_ip, 0);
}

static void t_binding(void *ctx, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why)
{
	(void)ctx; (void)why;
	if (ev == REG_EV_ADDED) {
		T.bind.added++;
		snprintf(T.bind.contact, sizeof(T.bind.contact), "%s", b->contact);
		snprintf(T.bind.ua, sizeof(T.bind.ua), "%s", b->ua);
	} else if (ev == REG_EV_REMOVED) {
		T.bind.removed++;
	} else {
		T.bind.other++;
	}
}

static struct addr A(const char *ip, int port)
{
	struct addr a;

	addr_set(&a, ip, port);
	return a;
}

static int status_of(const struct fakeep *f, int i)
{
	struct sip_msg m;
	int s = -1;

	if (i >= 0 && !fakeep_parse(f, i, &m)) {
		s = m.is_resp ? m.status : 0;
		sip_msg_free(&m);
	}
	return s;
}

static char HDRBUF[300];
static const char *hdr_of(const struct fakeep *f, int i, const char *name)
{
	struct sip_msg m;
	const char *v;

	HDRBUF[0] = 0;
	if (!fakeep_parse(f, i, &m)) {
		v = sip_hdr(&m, name, 0);
		if (v)
			snprintf(HDRBUF, sizeof(HDRBUF), "%s", v);
		sip_msg_free(&m);
	}
	return HDRBUF;
}

static int req_seq;
/* send a request from ip:port into endpoint f; extra: complete header lines */
static void send_req(struct fakeep *f, const char *ip, int port, const char *method, const char *ruri, const char *extra)
{
	char m[1200];
	struct addr src = A(ip, port);

	snprintf(m, sizeof(m), "%s %s SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bKcore%d;rport\r\nFrom: <sip:1000@192.168.68.1>;tag=a%d\r\n"
		 "To: <%s>\r\nCall-ID: core-%d@test\r\nCSeq: 1 %s\r\nMax-Forwards: 70\r\n%sContent-Length: 0\r\n\r\n",
		 method, ruri, ip, port, req_seq, req_seq, ruri, req_seq, method, extra ? extra : "");
	req_seq++;
	fakeep_rx(f, &src, m);
}

static struct imsd_config CFG;
static struct core *C;
static struct fakeep *GM;	/* a "Gm" endpoint attached to the shared layer */

static void setup(const char *lan_ip)
{
	struct core_ops ops = { .open_ep = t_open_ep, .lan_addr = t_lan_addr, .on_binding = t_binding };

	memset(&T, 0, sizeof(T));
	snprintf(T.lan_ip, sizeof(T.lan_ip), "%s", lan_ip);
	evfake_reset();
	config_defaults(&CFG);
	C = core_new(&CFG, &ops);
	CHECK(C != NULL);
	/* modules are added by the tests before core_start() */
}

static int start(void)
{
	struct reg_ops ro;
	struct sip_ep_cfg gc;
	int rc;

	memset(&ro, 0, sizeof(ro));
	rc = core_start(C, &ro);
	if (rc)
		return rc;
	memset(&gc, 0, sizeof(gc));
	gc.name = "gm#test";
	addr_set(&gc.rx_bind, "2001:db8::1", 5071);
	GM = fakeep_open(&gc);
	txn_layer_attach(core_txn(C), GM->ep);
	return 0;
}

static void teardown(void)
{
	int i;

	core_stop(C);
	sip_ep_retire(GM->ep);
	core_free(C);
	for (i = 0; i < T.n_open; i++)
		fakeep_destroy(T.eps[i]);
	fakeep_destroy(GM);
	C = NULL;
}

#define REGISTER_HDRS "Contact: <sip:1000@192.168.68.10:5062>;expires=600\r\nUser-Agent: TestPhone/1.0\r\n"

/* ---------------- modules for the extension tests ---------------- */

static struct {
	int start, stop, lan_up, lan_down, stray, bridge, lan_invite, lan_ack, gm_invite_a, gm_invite_b, gm_msg, gm_ack, gm_dlg;
	int last_arg;
	bool lan_present_at_start;
	bool take_a, take_b;
} M;

static void reply_status(struct txn_server *st, int status)
{
	struct sip_resp_parts p;

	memset(&p, 0, sizeof(p));
	p.status = status;
	txn_server_reply(st, &p);
}

static int m_start(struct core *c, void *arg)
{
	(void)arg;
	M.start++;
	M.lan_present_at_start = core_lan(c) != NULL;
	CHECK(core_reg(c) != NULL && core_txn(c) != NULL && core_cfg(c) == &CFG);
	return 0;
}
static void m_stop(struct core *c, void *arg)
{
	(void)arg;
	M.stop++;
	CHECK(core_reg(c) != NULL);	/* still alive while modules stop */
}
static void m_lan_state(struct core *c, struct lan *l, void *arg)
{
	(void)arg;
	if (l) {
		M.lan_up++;
		CHECK(core_lan(c) == l);
	} else {
		M.lan_down++;
		CHECK(core_lan(c) != NULL);	/* the old object is still valid during the callback */
	}
}
static void m_stray(struct core *c, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *resp, void *arg)
{
	(void)c; (void)ep; (void)src; (void)resp; (void)arg;
	M.stray++;
}
static void m_bridge(void *arg, const struct br_event *ev)
{
	M.last_arg = (int)(long)arg;
	M.bridge += ev->leg + 1;
}
static void h_lan_invite(struct lan *l, const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req, void *arg)
{
	(void)l; (void)p; (void)req;
	M.last_arg = (int)(long)arg;
	M.lan_invite++;
	reply_status(st, 486);
}
static void h_lan_ack(struct lan *l, const struct lan_peer *p, const struct sip_msg *req, void *arg)
{
	(void)l; (void)p; (void)req; (void)arg;
	M.lan_ack++;
}
static bool g_invite_a(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, void *arg)
{
	(void)r; (void)ep; (void)src; (void)req; (void)arg;
	M.gm_invite_a++;
	if (!M.take_a)
		return false;
	reply_status(st, 603);
	return true;
}
static bool g_invite_b(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, void *arg)
{
	(void)r; (void)ep; (void)src; (void)req; (void)arg;
	M.gm_invite_b++;
	if (!M.take_b)
		return false;
	reply_status(st, 600);
	return true;
}
static bool g_msg(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, void *arg)
{
	(void)r; (void)ep; (void)src; (void)req; (void)arg;
	M.gm_msg++;
	reply_status(st, 202);
	return true;
}
static bool g_ack(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, void *arg)
{
	(void)r; (void)st; (void)ep; (void)src; (void)req; (void)arg;
	M.gm_ack++;
	return true;
}

static const struct lan_hooks LH = { .on_invite = h_lan_invite, .on_ack = h_lan_ack, .arg = (void *)7 };
static const struct reg_handlers GA = { .on_invite = g_invite_a, .on_message = g_msg, .on_ack = g_ack };
static const struct reg_handlers GB = { .on_invite = g_invite_b };

static int m_start_fail(struct core *c, void *arg) { (void)c; (void)arg; return -ENOMEM; }

/* ---------------- tests ---------------- */

static void t_dispatch(void)
{
	struct fakeep *lan;
	struct core_lan_info li;
	struct lan_stats st;
	char s[64];
	int n;

	setup("192.168.68.1");
	CHECK_EQ(start(), 0);
	CHECK(core_running(C));
	CHECK_EQ(T.n_open, 1);
	lan = T.eps[0];
	core_lan_info(C, &li);
	CHECK(li.up); CHECK_STR(li.state, "up"); CHECK_STR(li.ifname, "br-lan");
	addr_str(&li.addr, s, sizeof(s)); CHECK_STR(s, "192.168.68.1:5060");
	addr_str(&lan->ep->advertised, s, sizeof(s)); CHECK_STR(s, "192.168.68.1:5060");
	addr_str(&lan->ep->local_rx, s, sizeof(s)); CHECK_STR(s, "192.168.68.1:5060");
	CHECK_STR(lan->ep->name, "lan");

	/* REGISTER on the LAN endpoint reaches the registrar */
	send_req(lan, "192.168.68.10", 5062, "REGISTER", "sip:192.168.68.1", REGISTER_HDRS);
	CHECK_EQ(lan->nsent, 1);
	CHECK_EQ(status_of(lan, 0), 200);
	CHECK_EQ(reg_count(lan_registrar(core_lan(C))), 1);
	CHECK_EQ(T.bind.added, 1); CHECK_STR(T.bind.contact, "sip:1000@192.168.68.10:5062"); CHECK_STR(T.bind.ua, "TestPhone/1.0");
	lan_status(core_lan(C), &st, NULL, NULL);
	CHECK_EQ(st.bindings, 1); CHECK_EQ(st.rx_register, 1);
	/* OPTIONS on the LAN endpoint: the LAN answer (Server: imsd, LAN Allow list) */
	send_req(lan, "192.168.68.10", 5062, "OPTIONS", "sip:192.168.68.1", NULL);
	CHECK_EQ(status_of(lan, 1), 200);
	CHECK_STR(hdr_of(lan, 1, "Server"), "imsd");
	CHECK(strstr(hdr_of(lan, 1, "Allow"), "REGISTER") != NULL);

	/* OPTIONS on a Gm endpoint still gets the Gm answer; REGISTER there is refused and never reaches the registrar */
	send_req(GM, "2001:db8::43", 5071, "OPTIONS", "sip:01051226862@lte-lguplus.co.kr", NULL);
	CHECK_EQ(GM->nsent, 1); CHECK_EQ(status_of(GM, 0), 200);
	CHECK_STR(hdr_of(GM, 0, "Accept"), "application/sdp");
	CHECK(strstr(hdr_of(GM, 0, "Allow"), "MESSAGE") != NULL);
	send_req(GM, "2001:db8::43", 5071, "REGISTER", "sip:lte-lguplus.co.kr", REGISTER_HDRS);
	CHECK_EQ(status_of(GM, 1), 405);
	CHECK_EQ(reg_count(lan_registrar(core_lan(C))), 1);
	/* nothing leaked across: the Gm answers never went out of the LAN endpoint and vice versa */
	CHECK_EQ(lan->nsent, 2); CHECK_EQ(GM->nsent, 2);

	/* defaults without modules: LAN INVITE 480 / MESSAGE 503, Gm INVITE 480 */
	send_req(lan, "192.168.68.10", 5062, "INVITE", "sip:0101234567@192.168.68.1", NULL);
	CHECK_EQ(status_of(lan, 2), 480);
	send_req(lan, "192.168.68.10", 5062, "MESSAGE", "sip:0101234567@192.168.68.1", NULL);
	CHECK_EQ(status_of(lan, 3), 503);
	send_req(GM, "2001:db8::43", 5071, "INVITE", "sip:01051226862@lte-lguplus.co.kr", NULL);
	CHECK_EQ(status_of(GM, 2), 480);

	/* unregister: the binding goes, the notification fires */
	send_req(lan, "192.168.68.10", 5062, "REGISTER", "sip:192.168.68.1",
		 "Contact: <sip:1000@192.168.68.10:5062>;expires=0\r\n");
	CHECK_EQ(status_of(lan, 4), 200);
	CHECK_EQ(reg_count(lan_registrar(core_lan(C))), 0); CHECK_EQ(T.bind.removed, 1);
	n = T.bind.added + T.bind.removed + T.bind.other; CHECK_EQ(n, 2 + T.bind.other);
	teardown();
}

static void t_modules(void)
{
	static const struct core_module MA = { .name = "a", .start = m_start, .stop = m_stop, .lan_state = m_lan_state, .on_stray = m_stray,
		.lan_hooks = &LH, .gm_handlers = &GA, .bridge_event = m_bridge, .arg = (void *)3 };
	static const struct core_module MB = { .name = "b", .gm_handlers = &GB };
	static const struct core_module BAD_LAN = { .name = "dup-lan", .lan_hooks = &LH };
	static const struct core_module BAD_BR = { .name = "dup-br", .bridge_event = m_bridge };
	static const struct core_module BAD_START = { .name = "bad", .start = m_start_fail, .stop = m_stop, .gm_handlers = &GA };
	struct fakeep *lan;
	struct br_event ev;
	int i;

	memset(&M, 0, sizeof(M));
	setup("192.168.68.1");
	CHECK_EQ(core_add_module(C, &MA), 0);
	CHECK_EQ(core_add_module(C, &MB), 0);
	CHECK_EQ(core_add_module(C, &BAD_LAN), -EBUSY);	/* a LAN hook slot has one owner */
	CHECK_EQ(core_add_module(C, &BAD_BR), -EBUSY);	/* so does the media event handler */
	CHECK_EQ(core_add_module(C, NULL), -EINVAL);
	CHECK_EQ(core_add_module(C, &BAD_START), 0);
	CHECK_EQ(start(), 0);
	CHECK_EQ(M.start, 1); CHECK(!M.lan_present_at_start);	/* modules start before the LAN side opens */
	CHECK_EQ(M.lan_up, 1);
	CHECK_EQ(core_add_module(C, &MB), -EINVAL);		/* running */
	lan = T.eps[0];

	/* LAN hooks installed from the module's table; slots it left NULL keep the router's behaviour */
	send_req(lan, "192.168.68.10", 5062, "INVITE", "sip:0101234567@192.168.68.1", NULL);
	CHECK_EQ(M.lan_invite, 1); CHECK_EQ(M.last_arg, 7); CHECK_EQ(status_of(lan, 0), 486);
	send_req(lan, "192.168.68.10", 5062, "MESSAGE", "sip:0101234567@192.168.68.1", NULL);
	CHECK_EQ(status_of(lan, 1), 503);
	{
		const char *ack = "ACK sip:x@192.168.68.1 SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.68.10:5062;branch=z9hG4bKack1\r\n"
				  "From: <sip:1000@192.168.68.1>;tag=1\r\nTo: <sip:2000@192.168.68.1>;tag=2\r\nCall-ID: ack1\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n";
		struct addr s = A("192.168.68.10", 5062);

		fakeep_rx(lan, &s, ack);
		CHECK_EQ(M.lan_ack, 1);
	}

	/* Gm table: a asked first (declines), then b, then built-in 480; a takes -> 603 and b is not asked */
	M.take_a = false; M.take_b = false;
	send_req(GM, "2001:db8::43", 5071, "INVITE", "sip:01051226862@lte-lguplus.co.kr", NULL);
	CHECK_EQ(M.gm_invite_a, 1); CHECK_EQ(M.gm_invite_b, 1); CHECK_EQ(status_of(GM, 0), 480);
	M.take_b = true;
	send_req(GM, "2001:db8::43", 5071, "INVITE", "sip:01051226862@lte-lguplus.co.kr", NULL);
	CHECK_EQ(M.gm_invite_a, 2); CHECK_EQ(M.gm_invite_b, 2); CHECK_EQ(status_of(GM, 1), 600);
	M.take_a = true;
	send_req(GM, "2001:db8::43", 5071, "INVITE", "sip:01051226862@lte-lguplus.co.kr", NULL);
	CHECK_EQ(M.gm_invite_a, 3); CHECK_EQ(M.gm_invite_b, 2); CHECK_EQ(status_of(GM, 2), 603);
	/* MESSAGE: module a owns it (any content type); BYE has no module handler: built-in 481 */
	send_req(GM, "2001:db8::43", 5071, "MESSAGE", "sip:01051226862@lte-lguplus.co.kr", "Content-Type: application/vnd.3gpp.sms\r\n");
	CHECK_EQ(M.gm_msg, 1); CHECK_EQ(status_of(GM, 3), 202);
	send_req(GM, "2001:db8::43", 5071, "BYE", "sip:01051226862@lte-lguplus.co.kr", NULL);
	CHECK_EQ(status_of(GM, 4), 481);
	{
		const char *ack = "ACK sip:x@y SIP/2.0\r\nVia: SIP/2.0/UDP [2001:db8::43]:5071;branch=z9hG4bKack2\r\n"
				  "From: <sip:a@b>;tag=1\r\nTo: <sip:c@d>;tag=2\r\nCall-ID: ack2\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n";
		struct addr s = A("2001:db8::43", 5071);

		fakeep_rx(GM, &s, ack);
		CHECK_EQ(M.gm_ack, 1); CHECK_EQ(M.lan_ack, 1);
	}

	/* media events go to the module that registered for them */
	memset(&ev, 0, sizeof(ev)); ev.leg = 1;
	core_bridge_event(C, &ev);
	CHECK_EQ(M.bridge, 2); CHECK_EQ(M.last_arg, 3);

	/* a LAN restart is a down + up for the modules and re-installs the hooks */
	CFG.lan_sip_port = 5080;
	core_reload(C);
	CHECK_EQ(M.lan_down, 1); CHECK_EQ(M.lan_up, 2); CHECK_EQ(T.n_open, 2);
	send_req(T.eps[1], "192.168.68.10", 5062, "INVITE", "sip:0101234567@192.168.68.1", NULL);
	CHECK_EQ(M.lan_invite, 2); CHECK_EQ(status_of(T.eps[1], 0), 486);

	core_stop(C);
	CHECK_EQ(M.stop, 1);		/* the module whose start failed is not stopped */
	CHECK_EQ(M.lan_down, 2);
	CHECK(!core_running(C)); CHECK(core_lan(C) == NULL); CHECK(core_txn(C) == NULL);
	core_bridge_event(C, &ev);	/* no longer delivered */
	CHECK_EQ(M.bridge, 2);
	sip_ep_retire(GM->ep);
	core_free(C);
	for (i = 0; i < T.n_open; i++)
		fakeep_destroy(T.eps[i]);
	fakeep_destroy(GM);
}

static void t_lan_lifecycle(void)
{
	struct core_lan_info li;
	char s[64];

	/* no address yet: pending, retried on a timer, reported */
	setup("");
	CHECK_EQ(start(), 0);
	CHECK_EQ(T.n_open, 0); CHECK(core_lan(C) == NULL);
	core_lan_info(C, &li); CHECK(!li.up); CHECK_STR(li.state, "waiting for address"); CHECK(strstr(li.reason, "br-lan") != NULL);
	evfake_advance(4999); CHECK_EQ(T.n_lookup, 1);
	evfake_advance(1); CHECK_EQ(T.n_lookup, 2); CHECK_EQ(T.n_open, 0);
	snprintf(T.lan_ip, sizeof(T.lan_ip), "192.168.68.1");
	evfake_advance(5000);
	CHECK_EQ(T.n_open, 1); CHECK(core_lan(C) != NULL);
	core_lan_info(C, &li); CHECK(li.up); CHECK_STR(li.state, "up");
	/* Gm requests work in the meantime / afterwards, the LAN endpoint is the one that was opened */
	send_req(T.eps[0], "192.168.68.10", 5062, "REGISTER", "sip:192.168.68.1", REGISTER_HDRS);
	CHECK_EQ(status_of(T.eps[0], 0), 200);

	/* the derived address is re-checked; unchanged: nothing happens, changed: the LAN side restarts on the new one */
	evfake_advance(30000); CHECK_EQ(T.n_open, 1);
	snprintf(T.lan_ip, sizeof(T.lan_ip), "192.168.68.2");
	evfake_advance(30000);
	CHECK_EQ(T.n_open, 2); CHECK(T.eps[0]->closed);	/* old endpoint released (nothing was holding it) */
	core_lan_info(C, &li); addr_str(&li.addr, s, sizeof(s)); CHECK_STR(s, "192.168.68.2:5060");
	CHECK_EQ(reg_count(lan_registrar(core_lan(C))), 0);	/* bindings do not survive a restart */
	/* the old endpoint no longer feeds the layer */
	CHECK(T.eps[0]->closed);

	/* the address vanishes: waiting again */
	T.lan_ip[0] = 0;
	evfake_advance(30000);
	core_lan_info(C, &li); CHECK(!li.up); CHECK_STR(li.state, "waiting for address"); CHECK(core_lan(C) == NULL);

	/* bind failure: error state with the reason, retried */
	snprintf(T.lan_ip, sizeof(T.lan_ip), "192.168.68.1");
	T.open_fail = EADDRNOTAVAIL;
	evfake_advance(5000);
	core_lan_info(C, &li); CHECK_STR(li.state, "error"); CHECK(strstr(li.reason, "192.168.68.1:5060") != NULL);
	evfake_advance(5000);
	core_lan_info(C, &li); CHECK(li.up);

	/* reload: nothing relevant changed -> no restart; a LAN option / explicit address -> restart */
	{
		int n = T.n_open;

		CFG.opus_bitrate = 32000;
		core_reload(C);
		CHECK_EQ(T.n_open, n);
		snprintf(CFG.lan_addr, sizeof(CFG.lan_addr), "192.168.68.9");
		core_reload(C);
		CHECK_EQ(T.n_open, n + 1);
		core_lan_info(C, &li); addr_str(&li.addr, s, sizeof(s)); CHECK_STR(s, "192.168.68.9:5060");
		/* an explicit address is not re-checked (no lookups) */
		T.n_lookup = 0;
		evfake_advance(120000);
		CHECK_EQ(T.n_lookup, 0); CHECK_EQ(T.n_open, n + 1);
		CFG.user_agent[0] = 'X';
		core_reload(C);
		CHECK_EQ(T.n_open, n + 2);
	}
	teardown();

	/* disabled core: reload and info are harmless */
	setup("192.168.68.1");
	core_reload(C);
	core_lan_info(C, &li); CHECK_STR(li.state, "stopped");
	CHECK_EQ(core_rtp_open_lan(C, &(struct addr){ 0 }), -ENOTCONN);
	core_free(C);
}

static void t_rtpsock(void)
{
	struct addr lo = A("127.0.0.1", 0), b, peer, from;
	int fd[8], i, n = 0, v;
	socklen_t vl = sizeof(v), fl = sizeof(from.sa);
	char buf[16];

	/* range handling */
	CHECK_EQ(rtpsock_open(&lo, NULL, 40000, 39999, &b), -EINVAL);
	CHECK_EQ(rtpsock_open(&lo, NULL, 100, 200, &b), -EINVAL);
	CHECK_EQ(rtpsock_open(&lo, NULL, 40001, 40001, &b), -EINVAL);	/* no even port inside */
	CHECK_EQ(rtpsock_open(&lo, NULL, 40000, 70000, &b), -EINVAL);

	/* 40000..40009 holds the even ports 40000, 40002, ..., 40008: five sockets, then the range is exhausted */
	for (i = 0; i < 5; i++) {
		fd[i] = rtpsock_open(&lo, NULL, 40000, 40009, &b);
		CHECK(fd[i] >= 0);
		if (fd[i] < 0)
			continue;
		n++;
		CHECK(addr_port(&b) >= 40000 && addr_port(&b) <= 40008 && addr_port(&b) % 2 == 0);
		CHECK(addr_is_v4(&b)); CHECK_STR((addr_host(&b, buf, sizeof(buf)), buf), "127.0.0.1");
	}
	CHECK_EQ(rtpsock_open(&lo, NULL, 40000, 40009, &b), -EADDRINUSE);
	if (n == 5) {
		for (i = 0; i < 5; i++)	/* all different */
			for (v = i + 1; v < 5; v++) {
				struct sockaddr_in6 x, y;
				socklen_t l1 = sizeof(x), l2 = sizeof(y);

				getsockname(fd[i], (struct sockaddr *)&x, &l1);
				getsockname(fd[v], (struct sockaddr *)&y, &l2);
				CHECK(x.sin6_port != y.sin6_port);
			}
		/* properties of the sockets: non-blocking, close-on-exec, dual-stack, usable */
		CHECK(fcntl(fd[0], F_GETFL) & O_NONBLOCK);
		CHECK(fcntl(fd[0], F_GETFD) & FD_CLOEXEC);
		v = 1; getsockopt(fd[0], IPPROTO_IPV6, IPV6_V6ONLY, &v, &vl); CHECK_EQ(v, 0);
		CHECK_EQ(recvfrom(fd[0], buf, sizeof(buf), 0, NULL, NULL), -1); CHECK(errno == EAGAIN);
		{
			struct sockaddr_in6 x;
			socklen_t l1 = sizeof(x);
			int s = socket(AF_INET6, SOCK_DGRAM, 0);

			getsockname(fd[0], (struct sockaddr *)&x, &l1);
			CHECK_EQ(sendto(s, "rtp", 3, 0, (struct sockaddr *)&x, sizeof(x)), 3);
			peer = A("127.0.0.1", 0);
			CHECK_EQ(recvfrom(fd[0], buf, sizeof(buf), 0, (struct sockaddr *)&from.sa, &fl), 3);
			CHECK(!memcmp(buf, "rtp", 3));
			close(s);
		}
		/* a released port is found again */
		close(fd[2]);
		fd[2] = rtpsock_open(&lo, NULL, 40000, 40009, &b);
		CHECK(fd[2] >= 0);
	}
	for (i = 0; i < 5; i++)
		if (fd[i] >= 0)
			close(fd[i]);
	(void)peer;

	/* errors of the system calls come back as -errno: not a local address; unknown device */
	{
		struct addr nl = A("192.0.2.123", 0);

		CHECK_EQ(rtpsock_open(&nl, NULL, 40000, 40009, &b), -EADDRNOTAVAIL);
		CHECK(rtpsock_open(&lo, "nonexistent0", 40000, 40009, &b) < 0);	/* ENODEV, or EPERM without CAP_NET_RAW */
	}
	/* netdev "lo": allowed for unprivileged processes on recent kernels, EPERM elsewhere: only check consistency */
	v = rtpsock_open(&lo, "lo", 40010, 40019, &b);
	CHECK(v >= 0 || v == -EPERM);
	if (v >= 0)
		close(v);

	/* core helpers use the configured ranges: LAN leg on the LAN address (here 127.0.0.1 via "lo"), carrier on the given local address */
	setup("127.0.0.1");
	snprintf(CFG.lan_ifname, sizeof(CFG.lan_ifname), "lo");
	CFG.rtp_port_min = 41000; CFG.rtp_port_max = 41009;
	CFG.carrier_rtp_port_min = 42000; CFG.carrier_rtp_port_max = 42009;
	CHECK_EQ(start(), 0);
	v = core_rtp_open_lan(C, &b);
	CHECK(v >= 0 || v == -EPERM);
	if (v >= 0) {
		CHECK(addr_port(&b) >= 41000 && addr_port(&b) <= 41008); CHECK(addr_is_v4(&b));
		close(v);
	}
	v = core_rtp_open_carrier(C, &lo, NULL, &b);
	CHECK(v >= 0);
	if (v >= 0) {
		CHECK(addr_port(&b) >= 42000 && addr_port(&b) <= 42008);
		close(v);
	}
	teardown();
}

static void t_ifaddr(void)
{
	struct addr a, p, out;
	char s[64];

	CHECK_EQ(ifaddr_first_v4("lo", NULL, &a), 0);
	addr_host(&a, s, sizeof(s)); CHECK_STR(s, "127.0.0.1"); CHECK(addr_is_v4(&a)); CHECK_EQ(addr_port(&a), 0);
	p = A("127.0.0.1", 0);
	CHECK_EQ(ifaddr_first_v4("lo", &p, &out), 0); CHECK(addr_equal_ip(&out, &p));
	p = A("10.99.99.99", 0);	/* preferred address not present: the first one */
	CHECK_EQ(ifaddr_first_v4("lo", &p, &out), 0);
	addr_host(&out, s, sizeof(s)); CHECK_STR(s, "127.0.0.1");
	CHECK_EQ(ifaddr_first_v4("nonexistent0", NULL, &out), -1);
	CHECK_EQ(ifaddr_first_v4("", NULL, &out), -1);
	CHECK_EQ(ifaddr_first_v4(NULL, NULL, &out), -1);
}

static void t_own_number(void)
{
	char o[40];

	core_uri_number("sip:+821051226862@ims.mnc006.mcc450.3gppnetwork.org", o, sizeof(o)); CHECK_STR(o, "+821051226862");
	core_uri_number("sips:+821051226862@x;user=phone", o, sizeof(o)); CHECK_STR(o, "+821051226862");
	core_uri_number("tel:+821051226862", o, sizeof(o)); CHECK_STR(o, "+821051226862");
	core_uri_number("tel:+821051226862;phone-context=x", o, sizeof(o)); CHECK_STR(o, "+821051226862");
	core_uri_number("SIP:01051226862@x", o, sizeof(o)); CHECK_STR(o, "01051226862");
	core_uri_number("", o, sizeof(o)); CHECK_STR(o, "");
	core_uri_number(NULL, o, sizeof(o)); CHECK_STR(o, "");
	core_uri_number("sip:+821051226862@x", o, 5); CHECK_STR(o, "+821");
	core_own_number(NULL, o, sizeof(o)); CHECK_STR(o, "");		/* not registered */
}

/* the registrar persistence module (ua/regpersist_mod.c) with the real writer thread: saves, restores at the next start, off with lan_persist=0 */
static bool wait_file(const char *path, bool want)
{
	int i;

	for (i = 0; i < 200; i++) {
		struct timespec ts = { 0, 10 * 1000 * 1000 };

		evfake_poll_fds();
		evfake_advance(100);	/* the virtual clock runs the write timer once the load has completed */
		if ((access(path, F_OK) == 0) == want)
			return true;
		nanosleep(&ts, NULL);
	}
	return false;
}

static void t_regpersist(void)
{
	char dir[120], path[160];
	const char *base = getenv("IMSD_TEST_TMP");
	int i;

	snprintf(dir, sizeof(dir), "%s/core-regp-%d", base ? base : "/tmp", (int)getpid());
	snprintf(path, sizeof(path), "%s/bindings", dir);
	if (mkdir(dir, 0700)) { /* exists from an earlier run */ }
	unlink(path);

	/* lan_persist = 0: nothing is written, not even at stop */
	setup("192.168.68.1");
	snprintf(CFG.store_dir, sizeof(CFG.store_dir), "%s", dir);
	CFG.lan_persist = false;
	CHECK_EQ(core_add_module(C, &regpersist_module), 0);
	CHECK_EQ(start(), 0);
	send_req(T.eps[0], "192.168.68.10", 5062, "REGISTER", "sip:192.168.68.1", REGISTER_HDRS);
	CHECK_EQ(status_of(T.eps[0], 0), 200);
	evfake_advance(70000);
	teardown();
	CHECK(!wait_file(path, true));

	/* on: written promptly, and at the clean stop; restored by the next start */
	setup("192.168.68.1");
	snprintf(CFG.store_dir, sizeof(CFG.store_dir), "%s", dir);
	CHECK_EQ(core_add_module(C, &regpersist_module), 0);
	CHECK_EQ(start(), 0);
	send_req(T.eps[0], "192.168.68.10", 5062, "REGISTER", "sip:192.168.68.1", REGISTER_HDRS);
	CHECK_EQ(status_of(T.eps[0], 0), 200);
	evfake_advance(1500);
	CHECK(wait_file(path, true));
	teardown();
	setup("192.168.68.1");
	snprintf(CFG.store_dir, sizeof(CFG.store_dir), "%s", dir);
	CHECK_EQ(core_add_module(C, &regpersist_module), 0);
	CHECK_EQ(start(), 0);
	for (i = 0; i < 200 && !reg_count(lan_registrar(core_lan(C))); i++) {
		struct timespec ts = { 0, 10 * 1000 * 1000 };

		evfake_poll_fds();
		nanosleep(&ts, NULL);
	}
	CHECK_EQ(reg_count(lan_registrar(core_lan(C))), 1);
	CHECK(reg_next(lan_registrar(core_lan(C)), 0)->restored);
	CHECK_STR(reg_next(lan_registrar(core_lan(C)), 0)->contact, "sip:1000@192.168.68.10:5062");
	CHECK_EQ(T.bind.added, 1);		/* the hooks of every module (and core's own callback) saw it as an add */
	teardown();
	unlink(path);
	{
		char cmd[200];

		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
		if (strlen(dir) > 10 && system(cmd)) { /* nothing */ }
	}
}

void test_core(void)
{
	t_own_number();
	t_dispatch();
	t_modules();
	t_lan_lifecycle();
	t_rtpsock();
	t_ifaddr();
	t_regpersist();
}
