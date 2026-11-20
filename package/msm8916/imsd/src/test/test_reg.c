/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Registration state machine, driven with mock endpoints, a mock xfrm, a
 * scripted AKA and the fake clock. The "network" is the test: it parses the
 * REGISTERs the machine sent and injects the responses.
 */
#include <errno.h>
#include <stdlib.h>
#include "test.h"
#include "fakeep.h"
#include "evloop_fake.h"
#include "mockworld.h"
#include "../gm/reg.h"
#include "../gm/regmsg.h"
#include "../util/codec.h"
#include "../util/evloop.h"

#define MAXEP 64
#define NET_SPI_C 3417264u
#define NET_SPI_S 3417263u
#define NET_PORT_C 5073
#define NET_PORT_S 5071

struct env {
	struct reg *r;
	struct fakeep *eps[MAXEP];
	struct sip_ep_cfg cfg[MAXEP];
	uint64_t opened_at[MAXEP];
	int neps;
	struct xfrm_sa_params sas[MAXEP];
	struct xfrm_sa_params removed[MAXEP];
	int n_install, n_remove;
	bool install_fail;
	bool open_fail;
	/* aka */
	int aka_script[8];	/* statuses to return in order (enum aka_status), then OK; 100 = never answer */
	int n_aka_script;
	int n_aka;
	bool aka_pending;
	imsmodem_aka_cb aka_cb;
	void *aka_arg;
	struct ev_timer *aka_t;
	uint8_t last_rand[16], last_autn[16];
	/* hooks */
	int n_up, n_down, n_replaced;
	char down_reason[64];
	int sms_resp;
	int n_resp;
	const char *live_pani;	/* what reg_ops.pani returns */
};
static struct env E;

static struct addr A(const char *ip, int port)
{
	struct addr a;

	addr_set(&a, ip, port);
	return a;
}

/* ---- mock ops ---- */
static void aka_fire(void *arg)
{
	struct aka_result r;
	imsmodem_aka_cb cb = E.aka_cb;
	void *a = E.aka_arg;
	int st = E.n_aka_script ? E.aka_script[0] : AKA_OK, i;

	(void)arg;
	if (E.n_aka_script) {
		memmove(E.aka_script, E.aka_script + 1, sizeof(E.aka_script[0]) * (--E.n_aka_script));
	}
	E.aka_pending = false;
	memset(&r, 0, sizeof(r));
	r.status = st;
	r.sw = 0x9000;
	if (st == AKA_OK) {
		r.res_len = 8;
		for (i = 0; i < 8; i++) r.res[i] = E.last_rand[i] ^ 0x5A;
		for (i = 0; i < 16; i++) { r.ck[i] = 0x20 + i; r.ik[i] = 0x40 + i; }
	} else if (st == AKA_SYNC_FAIL) {
		r.auts_len = 14;
		for (i = 0; i < 14; i++) r.auts[i] = 0xA0 + i;
	} else {
		r.sw = 0x9862;
	}
	cb(a, &r);
}

static int op_aka(void *ctx, const uint8_t rand[16], const uint8_t autn[16], imsmodem_aka_cb cb, void *arg)
{
	(void)ctx;
	E.n_aka++;
	memcpy(E.last_rand, rand, 16);
	memcpy(E.last_autn, autn, 16);
	E.aka_cb = cb;
	E.aka_arg = arg;
	E.aka_pending = true;
	if (!E.aka_t)
		E.aka_t = ev_timer_new(aka_fire, NULL);
	if (!(E.n_aka_script && E.aka_script[0] == 100))
		ev_timer_set(E.aka_t, 0);
	return 0;
}

static void op_aka_cancel(void *ctx, void *arg)
{
	(void)ctx;
	if (E.aka_pending && E.aka_arg == arg) {
		E.aka_pending = false;
		ev_timer_cancel(E.aka_t);
	}
}

static int op_install(void *ctx, const struct xfrm_sa_params *p)
{
	(void)ctx;
	if (E.install_fail)
		return -EEXIST;
	E.sas[E.n_install++] = *p;
	return 0;
}

static void op_remove(void *ctx, const struct xfrm_sa_params *p)
{
	(void)ctx;
	if (E.n_remove < MAXEP)
		E.removed[E.n_remove] = *p;
	E.n_remove++;
}

static struct sip_endpoint *op_open(void *ctx, const struct sip_ep_cfg *cfg)
{
	(void)ctx;
	if (E.open_fail || E.neps >= MAXEP) {
		errno = EADDRINUSE;
		return NULL;
	}
	E.cfg[E.neps] = *cfg;
	E.opened_at[E.neps] = ev_now_ms();
	E.eps[E.neps] = fakeep_open(cfg);
	return E.eps[E.neps++]->ep;
}

static void hook(void *arg, enum reg_event ev, const char *reason)
{
	(void)arg;
	if (ev == REG_EV_UP) E.n_up++;
	else if (ev == REG_EV_DOWN) { E.n_down++; snprintf(E.down_reason, sizeof(E.down_reason), "%s", reason); }
	else E.n_replaced++;
}

static const char *op_pani(void *ctx)
{
	(void)ctx;
	return E.live_pani;
}

static struct ims_link mklink(int npc)
{
	struct ims_link l;

	memset(&l, 0, sizeof(l));
	l.ready = true;
	snprintf(l.id.impi, sizeof(l.id.impi), "450061051226862@lte-lguplus.co.kr");
	snprintf(l.id.impu, sizeof(l.id.impu), "sip:01051226862@lte-lguplus.co.kr");
	snprintf(l.id.domain, sizeof(l.id.domain), "lte-lguplus.co.kr");
	snprintf(l.id.user, sizeof(l.id.user), "01051226862");
	snprintf(l.id.imei, sizeof(l.id.imei), "86883708-366218-5");
	snprintf(l.br.ifname, sizeof(l.br.ifname), "wwan0");
	addr_set(&l.br.local, "2001:4430:141:990a:25b5:899e:232:cb69", 0);
	l.br.prefix = 64; l.br.mtu = 1400;
	l.n_pcscf = npc;
	snprintf(l.pcscf[0], sizeof(l.pcscf[0]), "2001:4430:5:405::43");
	snprintf(l.pcscf[1], sizeof(l.pcscf[1]), "2001:4430:4:405::43");
	l.pcscf_src = PCSCF_NETWORK;
	l.seq = 1;
	return l;
}

static struct ims_link LINK;

static void setup(int npc)
{
	struct reg_cfg c;
	struct reg_ops o;

	evfake_reset();
	memset(&E, 0, sizeof(E));
	reg_cfg_defaults(&c);
	memset(&o, 0, sizeof(o));
	o.aka = op_aka; o.aka_cancel = op_aka_cancel; o.xfrm_install = op_install; o.xfrm_remove = op_remove; o.open_ep = op_open;
	o.pani = op_pani;
	E.r = reg_new(&c, &o);
	reg_add_hook(E.r, hook, NULL);
	LINK = mklink(npc);
}

static void teardown(void)
{
	int i;

	reg_free(E.r);
	for (i = 0; i < E.neps; i++)
		fakeep_destroy(E.eps[i]);
	ev_timer_free(E.aka_t);
}

static void pump(unsigned ms)
{
	evfake_advance(ms);
}

/* ---- network side helpers ---- */
static struct fakeep *last_ep(bool prot)
{
	int i;

	for (i = E.neps - 1; i >= 0; i--)
		if (E.cfg[i].split_tx == prot && !E.eps[i]->closed)
			return E.eps[i];
	return NULL;
}

static int ep_index(const struct fakeep *f)
{
	int i;

	for (i = 0; i < E.neps; i++)
		if (E.eps[i] == f)
			return i;
	return -1;
}

static int last_msg(struct fakeep *f, struct sip_msg *m)
{
	return f && f->nsent ? fakeep_parse(f, f->nsent - 1, m) : -1;
}

static void send_resp(struct fakeep *f, const struct sip_msg *req, int status, const char *reason, const char *extra, const struct addr *src)
{
	char b[4096];

	snprintf(b, sizeof(b), "SIP/2.0 %d %s\r\nVia: %s\r\nFrom: %s\r\nTo: %s;tag=net%d\r\nCall-ID: %s\r\nCSeq: %s\r\n%sContent-Length: 0\r\n\r\n",
		 status, reason, sip_hdr(req, "Via", 0), sip_hdr(req, "From", 0), sip_hdr(req, "To", 0), status,
		 sip_hdr(req, "Call-ID", 0), sip_hdr(req, "CSeq", 0), extra ? extra : "");
	fakeep_rx(f, src, b);
}

static void make_401(char *out, size_t n, int seed, bool with_sec)
{
	uint8_t raw[32];
	char nonce[64];
	int i;

	for (i = 0; i < 32; i++) raw[i] = seed + i;
	b64_encode(raw, 32, nonce, sizeof(nonce));
	snprintf(out, n, "WWW-Authenticate: Digest realm=\"lte-lguplus.co.kr\",nonce=\"%s\",algorithm=AKAv1-MD5\r\n%s", nonce,
		 with_sec ? "Security-Server: ipsec-3gpp; mod=trans; alg=hmac-md5-96; ealg=null; spi-c=3417264; spi-s=3417263; port-c=5073; port-s=5071\r\n" : "");
}

static void reply_401(struct fakeep *u, int seed)
{
	struct sip_msg m;
	char x[800];
	struct addr pc = A("2001:4430:5:405::43", 5060);

	CHECK(!last_msg(u, &m));
	make_401(x, sizeof(x), seed, true);
	send_resp(u, &m, 401, "UNAUTHORIZED", x, &pc);
	sip_msg_free(&m);
}

static void reply_200(struct fakeep *p, int expires, const char *pcscf)
{
	struct sip_msg m;
	char x[900];
	struct addr src = A(pcscf, NET_PORT_C);

	CHECK(!last_msg(p, &m));
	snprintf(x, sizeof(x), "Contact: %s;expires=%d\r\nExpires: %d\r\nP-Associated-URI: <sip:01051226862@lte-lguplus.co.kr>\r\n",
		 sip_hdr(&m, "Contact", 0), expires, expires);
	send_resp(p, &m, 200, "OK", x, &src);
	sip_msg_free(&m);
}

/* the unprotected REGISTER is out: 401, AKA, SA, protected REGISTER, 200 */
static void finish_registration(int expires, const char *pcscf)
{
	struct fakeep *u = last_ep(false), *p;

	reply_401(u, 1);
	pump(10);
	p = last_ep(true);
	CHECK(p != NULL);
	if (p)
		reply_200(p, expires, pcscf);
}

static const char *PC0 = "2001:4430:5:405::43";
static const char *PC1 = "2001:4430:4:405::43";

/* all resources released and every endpoint closed once the transactions drained */
static void check_clean_at(int line)
{
	int i, open = 0;

	pump(60000);
	CHECK_EQ(E.n_install, E.n_remove);
	for (i = 0; i < E.neps; i++)
		if (!E.eps[i]->closed)
			open++;
	t_checks++;
	if (open) {
		t_fails++;
		printf("FAIL %s:%d: %d endpoint(s) still open\n", __FILE__, line, open);
	}
}
#define check_clean() check_clean_at(__LINE__)

static int hdr_int(const struct sip_msg *m, const char *name)
{
	const char *v = sip_hdr(m, name, 0);

	return v ? atoi(v) : -1;
}

static void get_sc(const struct sip_msg *m, struct sec_ent *e)
{
	struct sec_ent all[4];

	CHECK(sec_parse(sip_hdr(m, "Security-Client", 0), all, 4) >= 1);
	*e = all[0];
}

/* a registered machine on P-CSCF 0 */
static void go_registered(int npc)
{
	setup(npc);
	reg_set_link(E.r, &LINK);
	finish_registration(600, PC0);
}


static struct ims_link not_ready(const char *reason)
{
	struct ims_link l;

	memset(&l, 0, sizeof(l));
	snprintf(l.reason, sizeof(l.reason), "%s", reason);
	l.seq = 99;
	return l;
}

static int sent_to(const struct fakeep *f, int i, const char *ip, int port)
{
	struct addr a = A(ip, port);

	return i < f->nsent && addr_equal(&f->sent[i].dst, &a);
}

static void inject_req(struct fakeep *f, const char *method, const char *ruri, const char *extra, const uint8_t *body, size_t blen)
{
	char h[1500];
	uint8_t all[2000];
	struct addr src = A(PC0, NET_PORT_C);
	int n;

	n = snprintf(h, sizeof(h), "%s %s SIP/2.0\r\nVia: SIP/2.0/UDP [2001:4430:5:405::43]:5071;branch=z9hG4bK-%s%d\r\nFrom: <sip:ipsmgw.lte-lguplus.co.kr>;tag=t1\r\n"
		     "To: <sip:01051226862@lte-lguplus.co.kr>\r\nCall-ID: in-%s-%d\r\nCSeq: 7 %s\r\nMax-Forwards: 66\r\n%sContent-Length: %zu\r\n\r\n",
		     method, ruri, method, f->nsent, method, f->nsent, method, extra ? extra : "", blen);
	memcpy(all, h, n);
	if (blen)
		memcpy(all + n, body, blen);
	fakeep_rx_n(f, &src, all, n + blen);
}

static int last_status(struct fakeep *f)
{
	struct sip_msg m;
	int st = -1;

	if (!last_msg(f, &m)) {
		st = m.is_resp ? m.status : 0;
		sip_msg_free(&m);
	}
	return st;
}


/* ---- extension handler table (core modules taking over INVITE / MESSAGE / in-dialog requests) ---- */
static struct { int invite, message, in_dialog, ack; bool take; int status; } HX;

static bool hx_reply(struct txn_server *st)
{
	struct sip_resp_parts p;

	if (!HX.take)
		return false;
	memset(&p, 0, sizeof(p));
	p.status = HX.status;
	txn_server_reply(st, &p);
	return true;
}
static bool hx_invite(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, void *arg)
{
	(void)r; (void)ep; (void)src; (void)req; (void)arg;
	HX.invite++;
	return hx_reply(st);
}
static bool hx_message(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, void *arg)
{
	(void)r; (void)ep; (void)src; (void)req; (void)arg;
	HX.message++;
	return hx_reply(st);
}
static bool hx_in_dialog(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, void *arg)
{
	(void)r; (void)ep; (void)src; (void)req; (void)arg;
	HX.in_dialog++;
	return hx_reply(st);
}
static bool hx_ack(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, void *arg)
{
	(void)r; (void)ep; (void)src; (void)req; (void)arg;
	CHECK(st == NULL);
	HX.ack++;
	return true;
}

static int shut_n;
static void shut_cb(void *a)
{
	(void)a;
	shut_n++;
}

#define AUTH_RESP_OK(m, expect) do { const char *_a = sip_hdr((m), "Authorization", 0); CHECK(_a && strstr(_a, (expect))); } while (0)

/* ===== registration on top of the real imsmodem (mock uqmid, ISIM, netdev): the AKA service contract ===== */
static struct imsmodem *IM;
static int ig_reg_done, ig_modem_done;

static int ig_aka(void *ctx, const uint8_t rand[16], const uint8_t autn[16], imsmodem_aka_cb cb, void *arg)
{
	(void)ctx;
	return imsmodem_aka(IM, rand, autn, cb, arg);
}

static void ig_aka_cancel(void *ctx, void *arg)
{
	(void)ctx;
	imsmodem_aka_cancel(IM, arg);
}

static void ig_link(void *arg, const struct ims_link *l)
{
	(void)arg;
	reg_set_link(E.r, l);
}

static void ig_modem_done_cb(void *arg)
{
	(void)arg;
	ig_modem_done++;
}

static void ig_reg_done_cb(void *arg)
{
	(void)arg;
	ig_reg_done++;
	imsmodem_shutdown(IM, ig_modem_done_cb, NULL, 2000);
}

static void integration(void)
{
	struct reg_cfg c;
	struct reg_ops o;
	struct imsmodem_ops mo;
	struct imsmodem_cfg mc;
	struct reg_status st;
	struct sip_msg m;
	struct fakeep *u, *p;
	char bp[64], expect[200], resp[33];
	uint8_t res[8];
	int i;

	evfake_reset();
	memset(&E, 0, sizeof(E));
	world_reset();
	reg_cfg_defaults(&c);
	memset(&o, 0, sizeof(o));
	o.aka = ig_aka; o.aka_cancel = ig_aka_cancel; o.xfrm_install = op_install; o.xfrm_remove = op_remove; o.open_ep = op_open;
	E.r = reg_new(&c, &o);
	reg_add_hook(E.r, hook, NULL);
	imsmodem_cfg_defaults(&mc);
	mo = world_ops();
	mo.on_link = ig_link;
	IM = imsmodem_new(&mc, &mo);
	imsmodem_uqmid_up(IM, true);
	pump(300);
	CHECK(imsmodem_link(IM)->ready);
	CHECK_EQ(E.neps, 1);
	u = E.eps[0];
	CHECK(sent_to(u, 0, PC0, 5060));
	CHECK(addr_equal_ip(&E.cfg[0].rx_bind, &imsmodem_link(IM)->br.local));
	CHECK_STR(E.cfg[0].netdev, "wwan0");
	reply_401(u, 1);
	pump(300);	/* AKA: channel, AUTHENTICATE, GET RESPONSE through the mocked card */
	CHECK_EQ(E.n_install, 1);
	CHECK(W.n_apdu >= 2);
	p = last_ep(true);
	CHECK(p != NULL);
	if (p) {
		/* the digest response was computed from the card's RES (first 8 bytes of RAND xor 5A in the mock) */
		CHECK(!last_msg(p, &m));
		for (i = 0; i < 8; i++) res[i] = (i + 1) ^ 0x5A;
		digest_response("450061051226862@lte-lguplus.co.kr", "lte-lguplus.co.kr", res, 8, "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "REGISTER", "sip:lte-lguplus.co.kr", resp);
		snprintf(expect, sizeof(expect), "response=\"%s\"", resp);
		AUTH_RESP_OK(&m, expect);
		sip_msg_free(&m);
		reply_200(p, 600, PC0);
	}
	reg_get_status(E.r, &st);
	CHECK(st.registered); CHECK_EQ(E.n_up, 1);
	CHECK(E.sas[0].ik[0] == 0x40 && E.sas[0].ik[15] == 0x4f);

	/* the IMS bearer is lost: the registration releases everything, the bearer comes back, we register again */
	snprintf(bp, sizeof(bp), "%s", imsmodem_link(IM)->br.path);
	imsmodem_ev_bearer(IM, W.mpath, bp, false);
	reg_get_status(E.r, &st);
	CHECK(!st.registered); CHECK_EQ(E.n_down, 1); CHECK_EQ(E.n_remove, 1); CHECK_EQ(W.net_remove, 1);
	CHECK_STR(st.reason, "bearer-lost");
	pump(5500);
	CHECK(imsmodem_link(IM)->ready);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_UNPROT);
	reply_401(last_ep(false), 3);
	pump(300);
	CHECK_EQ(E.n_install, 2);
	reply_200(last_ep(true), 600, PC0);
	reg_get_status(E.r, &st);
	CHECK(st.registered); CHECK_EQ(E.n_up, 2);

	/* shutdown: de-register, then the modem side releases the bearer and the netdev */
	reg_shutdown(E.r, ig_reg_done_cb, NULL);
	CHECK(!last_msg(last_ep(true), &m)); CHECK_STR(sip_hdr(&m, "Expires", 0), "0"); sip_msg_free(&m);
	{
		struct addr src = A(PC0, NET_PORT_C);

		CHECK(!last_msg(last_ep(true), &m));
		send_resp(last_ep(true), &m, 200, "OK", "Expires: 0\r\n", &src);
		sip_msg_free(&m);
	}
	pump(500);
	CHECK_EQ(ig_reg_done, 1); CHECK_EQ(ig_modem_done, 1);
	CHECK_EQ(world_bearers(), 0); CHECK_EQ(W.net_apply, W.net_remove);
	CHECK_EQ(E.n_install, E.n_remove);
	pump(60000);
	for (i = 0; i < E.neps; i++)
		CHECK(E.eps[i]->closed);
	reg_free(E.r);
	imsmodem_free(IM);
	for (i = 0; i < E.neps; i++)
		fakeep_destroy(E.eps[i]);
}

void test_reg(void)
{
	struct sip_msg m, m2;
	struct reg_status st;
	struct fakeep *u, *p, *p2;
	struct sec_ent sc1, sc2;
	char x[900], resp[33], expect[200];
	const struct reg_ctx *ctx;
	uint32_t cseq1;
	uint8_t res[8];
	uint64_t t0;
	int i, n_before;

	/* ===== happy path: unprotected -> 401 -> AKA -> SA -> protected -> 200 -> refresh at half time ===== */
	setup(2);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_WAIT_LINK);
	reg_set_link(E.r, &LINK);
	CHECK_EQ(E.neps, 1);
	CHECK(!E.cfg[0].split_tx); CHECK_STR(E.cfg[0].netdev, "wwan0");
	CHECK(addr_equal_ip(&E.cfg[0].rx_bind, &LINK.br.local));
	u = E.eps[0];
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_UNPROT); CHECK_STR(st.pcscf, PC0);
	CHECK(sent_to(u, 0, PC0, 5060));
	CHECK(!last_msg(u, &m));
	CHECK_STR(m.method, "REGISTER");
	AUTH_RESP_OK(&m, "nonce=\"\"");
	get_sc(&m, &sc1);
	CHECK(sc1.port_c >= 8000 && sc1.port_c <= 8999 && sc1.port_s >= 8000 && sc1.port_s <= 8999 && sc1.port_c != sc1.port_s);
	CHECK(sc1.spi_c >= 256 && sc1.spi_s >= 256 && sc1.spi_c != sc1.spi_s);
	{
		struct sip_via v;

		CHECK(!sip_top_via(&m, &v));
		CHECK_EQ(v.port, addr_port(&E.cfg[0].rx_bind));
	}
	cseq1 = (uint32_t)atoi(sip_hdr(&m, "CSeq", 0));
	snprintf(x, sizeof(x), "%s", sip_hdr(&m, "Call-ID", 0));
	sip_msg_free(&m);
	t0 = ev_now_ms();

	reply_401(u, 1);
	CHECK_EQ(E.n_aka, 1);
	CHECK(E.last_rand[0] == 1 && E.last_rand[15] == 16 && E.last_autn[0] == 17 && E.last_autn[15] == 32);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_AKA);
	CHECK_EQ(E.n_install, 0);
	pump(10);
	CHECK_EQ(E.n_install, 1);
	{
		const struct xfrm_sa_params *sa = &E.sas[0];

		CHECK(sa->spi_uc == sc1.spi_c && sa->spi_us == sc1.spi_s && sa->spi_pc == NET_SPI_C && sa->spi_ps == NET_SPI_S);
		CHECK(sa->port_uc == sc1.port_c && sa->port_us == sc1.port_s && sa->port_pc == NET_PORT_C && sa->port_ps == NET_PORT_S);
		CHECK(addr_equal_ip(&sa->ue, &LINK.br.local));
		{
			struct addr pc = A(PC0, 0);

			CHECK(addr_equal_ip(&sa->pcscf, &pc));
		}
		CHECK(!sa->sha1); CHECK(sa->ik[0] == 0x40 && sa->ik[15] == 0x4f);
		CHECK_EQ(sa->proto, IPPROTO_UDP); CHECK(sa->reqid >= 1000 && (sa->reqid & 3) == 0);
	}
	CHECK_EQ(E.neps, 2);
	CHECK(E.cfg[1].split_tx && E.cfg[1].has_adv && E.cfg[1].has_resp_override);
	CHECK_EQ(addr_port(&E.cfg[1].rx_bind), sc1.port_s); CHECK_EQ(addr_port(&E.cfg[1].tx_bind), sc1.port_c);
	CHECK_EQ(addr_port(&E.cfg[1].adv), sc1.port_s);
	{
		struct addr ro = A(PC0, NET_PORT_S);

		CHECK(addr_equal(&E.cfg[1].resp_override, &ro));
	}
	CHECK_STR(E.cfg[1].netdev, "wwan0");
	p = E.eps[1];
	CHECK(sent_to(p, 0, PC0, NET_PORT_S));
	CHECK(!last_msg(p, &m));
	CHECK_STR(sip_hdr(&m, "Call-ID", 0), x);
	CHECK_EQ(atoi(sip_hdr(&m, "CSeq", 0)), (int)cseq1 + 1);
	CHECK_STR(sip_hdr(&m, "Security-Verify", 0), "ipsec-3gpp; mod=trans; alg=hmac-md5-96; ealg=null; spi-c=3417264; spi-s=3417263; port-c=5073; port-s=5071");
	{
		struct sip_via v;
		int j;

		CHECK(!sip_top_via(&m, &v));
		CHECK_EQ(v.port, sc1.port_s);
		for (j = 0; j < 8; j++) res[j] = E.last_rand[j] ^ 0x5A;
		digest_response("450061051226862@lte-lguplus.co.kr", "lte-lguplus.co.kr", res, 8, "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "REGISTER", "sip:lte-lguplus.co.kr", resp);
		snprintf(expect, sizeof(expect), "response=\"%s\"", resp);
		AUTH_RESP_OK(&m, expect);
		AUTH_RESP_OK(&m, "nonce=\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\"");
	}
	{
		const char *au = sip_hdr(&m, "Authorization", 0);

		snprintf(x, sizeof(x), "%s", au);	/* remembered for the refresh */
	}
	CHECK_STR(sip_hdr(&m, "Expires", 0), "8000");
	sip_msg_free(&m);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_PROT);

	reply_200(p, 600, PC0);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_REGISTERED); CHECK(st.registered); CHECK_EQ(E.n_up, 1);
	CHECK_STR(st.assoc_uri, "sip:01051226862@lte-lguplus.co.kr");
	CHECK(st.expires_in_s >= 598 && st.expires_in_s <= 600);
	CHECK_EQ(st.port_c, sc1.port_c); CHECK_EQ(st.port_s, sc1.port_s); CHECK_EQ(st.pcscf_port_s, NET_PORT_S);
	CHECK_EQ(st.successes, 1); CHECK_EQ(st.attempts, 1); CHECK_EQ(st.auth_failures, 0);
	CHECK_STR(st.impu, "sip:01051226862@lte-lguplus.co.kr"); CHECK_EQ(st.pcscf_source, PCSCF_NETWORK);
	ctx = reg_context(E.r);
	CHECK(ctx != NULL);
	if (ctx) {
		struct addr ro = A(PC0, NET_PORT_S);

		CHECK(ctx->ep == p->ep); CHECK(addr_equal(&ctx->pcscf_ps, &ro));
		CHECK_STR(ctx->security_verify, "ipsec-3gpp; mod=trans; alg=hmac-md5-96; ealg=null; spi-c=3417264; spi-s=3417263; port-c=5073; port-s=5071");
		CHECK_STR(ctx->impu, "sip:01051226862@lte-lguplus.co.kr"); CHECK_STR(ctx->assoc_uri, "sip:01051226862@lte-lguplus.co.kr");
		CHECK_EQ(ctx->n_service_route, 0);
	}
	{
		char cu[200], ec[200];

		CHECK(!reg_contact_uri(E.r, cu, sizeof(cu)));
		snprintf(ec, sizeof(ec), "sip:01051226862@[2001:4430:141:990a:25b5:899e:232:cb69]:%u", sc1.port_s);
		CHECK_STR(cu, ec);
	}
	pump(40000);
	CHECK(E.eps[0]->closed);	/* the unprotected endpoint is gone once its transaction drained */
	CHECK(!p->closed);
	pump(250000);	/* 290 s after the 200 */
	CHECK_EQ(p->nsent, 1);
	pump(15000);	/* past 300 s: refresh (and its retransmissions, nobody answers yet) */
	CHECK(p->nsent >= 2);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_REFRESH); CHECK(st.registered); CHECK_EQ(st.refreshes, 1);
	CHECK(!fakeep_parse(p, 1, &m));
	CHECK_STR(m.method, "REGISTER"); CHECK_STR(sip_hdr(&m, "Expires", 0), "8000");
	CHECK_EQ(atoi(sip_hdr(&m, "CSeq", 0)), (int)cseq1 + 2);
	CHECK_STR(sip_hdr(&m, "Authorization", 0), x);	/* the last credentials again */
	CHECK(sip_hdr(&m, "Security-Verify", 0) != NULL);
	sip_msg_free(&m);
	reply_200(p, 600, PC0);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_REGISTERED);
	CHECK_EQ(E.n_install, 1); CHECK_EQ(E.neps, 2); CHECK_EQ(E.n_up, 1);
	n_before = p->nsent;
	pump(290000);
	CHECK_EQ(p->nsent, n_before);
	pump(15000);
	CHECK(p->nsent > n_before);
	CHECK(!fakeep_parse(p, n_before, &m));
	CHECK_EQ(atoi(sip_hdr(&m, "CSeq", 0)), (int)cseq1 + 3);
	sip_msg_free(&m);
	(void)t0;
	teardown();

	/* ===== duplicate / retransmitted 401 on the unprotected endpoint are ignored ===== */
	setup(2);
	reg_set_link(E.r, &LINK);
	u = E.eps[0];
	reply_401(u, 1);
	reply_401(u, 1);	/* the network repeats it before our AKA finished */
	CHECK_EQ(E.n_aka, 1);
	pump(10);
	CHECK_EQ(E.neps, 2); p = E.eps[1];
	reply_401(u, 1);	/* ... and again after the protected REGISTER went out */
	pump(10);
	CHECK_EQ(E.n_aka, 1); CHECK_EQ(E.neps, 2); CHECK_EQ(E.n_install, 1);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_PROT);
	reply_200(p, 600, PC0);
	reply_401(u, 1);
	pump(10);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_REGISTERED); CHECK_EQ(E.n_aka, 1); CHECK_EQ(E.n_install, 1);
	teardown();

	/* ===== 406 PORT-C/S DUPLICATED: immediate retry with other ports, then the next P-CSCF ===== */
	setup(2);
	reg_set_link(E.r, &LINK);
	u = E.eps[0];
	CHECK(!last_msg(u, &m)); get_sc(&m, &sc1);
	{
		struct addr src = A(PC0, 5060);

		send_resp(u, &m, 406, "NOT ACCEPTABLE", "Reason: SIP;cause=5112;text=\"SBC3A/MREGX:PORT-C/S DUPLICATED\"\r\nWarning: 301 abc \"Incompatible network address type\"\r\n", &src);
	}
	sip_msg_free(&m);
	pump(0);
	CHECK_EQ(E.neps, 2);
	u = E.eps[1];
	CHECK(sent_to(u, 0, PC0, 5060));
	CHECK(!last_msg(u, &m)); get_sc(&m, &sc2);
	CHECK(sc2.port_c != sc1.port_c && sc2.port_s != sc1.port_s && sc2.port_c != sc1.port_s && sc2.port_s != sc1.port_c);
	CHECK(sc2.spi_c != sc1.spi_c && sc2.spi_s != sc1.spi_s);
	sip_msg_free(&m);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.attempts, 2);
	for (i = 0; i < 3; i++) {	/* 406 again: retries 2 and 3, then the bound is hit */
		struct addr src = A(PC0, 5060);

		u = last_ep(false);
		CHECK(!last_msg(u, &m));
		send_resp(u, &m, 406, "NOT ACCEPTABLE", "Reason: SIP;cause=5112;text=\"SBC3A/MREGX:PORT-C/S DUPLICATED\"\r\n", &src);
		sip_msg_free(&m);
		pump(300);
	}
	/* attempts: #1, #2, #3, #4 on P-CSCF 0 (three retries), then #5 on P-CSCF 1 */
	reg_get_status(E.r, &st);
	CHECK_EQ(st.attempts, 5);
	u = last_ep(false);
	CHECK(sent_to(u, 0, PC1, 5060));
	finish_registration(600, PC1);
	p = last_ep(true);
	CHECK(sent_to(p, 0, PC1, NET_PORT_S));
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_REGISTERED); CHECK_STR(st.pcscf, PC1);
	CHECK_EQ(E.n_install, 1);
	teardown();

	/* ===== AKA synchronisation failure -> REGISTER with auts -> new challenge ===== */
	setup(2);
	E.aka_script[0] = AKA_SYNC_FAIL; E.n_aka_script = 1;
	reg_set_link(E.r, &LINK);
	u = E.eps[0];
	CHECK(!last_msg(u, &m)); cseq1 = atoi(sip_hdr(&m, "CSeq", 0)); snprintf(x, sizeof(x), "%s", sip_hdr(&m, "Call-ID", 0)); sip_msg_free(&m);
	reply_401(u, 1);
	pump(10);
	CHECK_EQ(E.n_aka, 1); CHECK_EQ(E.n_install, 0); CHECK_EQ(u->nsent, 2);
	CHECK(!last_msg(u, &m));
	CHECK_STR(sip_hdr(&m, "Call-ID", 0), x);
	CHECK_EQ(atoi(sip_hdr(&m, "CSeq", 0)), (int)cseq1 + 1);
	{
		const char *a = sip_hdr(&m, "Authorization", 0), *q;
		uint8_t au[20];
		char b[40] = "";

		CHECK(a && strstr(a, "response=\"\"") && strstr(a, "auts=\"") && strstr(a, "nonce=\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\""));
		q = a ? strstr(a, "auts=\"") : NULL;
		if (q) {
			q += 6;
			snprintf(b, sizeof(b), "%.*s", (int)strcspn(q, "\""), q);
		}
		CHECK_EQ(b64_decode(b, au, sizeof(au)), 14);
		CHECK(au[0] == 0xA0 && au[13] == 0xAD);
	}
	CHECK_EQ(E.neps, 1);	/* still the same unprotected endpoint */
	sip_msg_free(&m);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_UNPROT);
	reply_401(u, 9);
	pump(10);
	CHECK_EQ(E.n_aka, 2); CHECK(E.last_rand[0] == 9);
	CHECK_EQ(E.n_install, 1);
	finish_registration(600, PC0);
	teardown();

	/* repeated synchronisation failures give up on this P-CSCF */
	setup(2);
	for (i = 0; i < 4; i++) E.aka_script[i] = AKA_SYNC_FAIL;
	E.n_aka_script = 4;
	reg_set_link(E.r, &LINK);
	u = E.eps[0];
	for (i = 0; i < 4; i++) {
		reply_401(u, 1 + i);
		pump(10);
	}
	CHECK_EQ(E.n_aka, 4);
	pump(300);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.attempts, 2); CHECK_STR(st.pcscf, PC1);
	CHECK(sent_to(last_ep(false), 0, PC1, 5060));
	teardown();

	/* AKA card error (MAC failure): the attempt fails, counted as an authentication failure */
	setup(2);
	E.aka_script[0] = AKA_ERR; E.n_aka_script = 1;
	reg_set_link(E.r, &LINK);
	reply_401(E.eps[0], 1);
	pump(300);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.auth_failures, 1); CHECK_EQ(st.attempts, 2); CHECK_EQ(E.n_install, 0);
	CHECK(strstr(st.last_error, "9862") != NULL);
	teardown();

	/* ===== timeout -> next P-CSCF -> exponential backoff (5, 10, 20, 40 s, capped) ===== */
	setup(2);
	{
		struct reg_cfg c;
		static const unsigned expect_at[] = { 0, 8200, 21200, 29400, 47400, 55600, 83600, 91800, 139800, 148000, 196000 };

		reg_cfg_defaults(&c);
		c.backoff_max_ms = 40000;
		reg_set_cfg(E.r, &c);
		reg_set_link(E.r, &LINK);
		t0 = ev_now_ms();
		for (i = 0; i < 2100; i++) {
			pump(100);
			if (i == 150) {	/* 15 s: the second P-CSCF is still waiting for its answer */
				reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_UNPROT); CHECK_STR(st.pcscf, PC1);
			}
			if (i == 180) {	/* 18 s: everything failed once */
				reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_BACKOFF); CHECK(strstr(st.reason, "retry in 5 s") != NULL);
			}
		}
		CHECK(E.neps >= 11);
		for (i = 0; i < 11 && i < E.neps; i++) {
			t_checks++;
			if (E.opened_at[i] - t0 != expect_at[i]) {
				t_fails++;
				printf("FAIL %s:%d: attempt %d started at +%llu ms, expected +%u\n", __FILE__, __LINE__, i,
				       (unsigned long long)(E.opened_at[i] - t0), expect_at[i]);
			}
		}
		CHECK(sent_to(E.eps[0], 0, PC0, 5060)); CHECK(sent_to(E.eps[1], 0, PC1, 5060)); CHECK(sent_to(E.eps[2], 0, PC0, 5060));
		CHECK_EQ(E.n_install, 0);
	}
	reg_set_link(E.r, &(struct ims_link){ .reason = "bearer-lost" });
	check_clean();
	teardown();

	/* ===== the link (bearer / modem) disappears in every state: everything is released ===== */
	/* UNPROT */
	setup(2);
	reg_set_link(E.r, &LINK);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_UNPROT);
	{ struct ims_link nl = not_ready("bearer-lost"); reg_set_link(E.r, &nl); }
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_WAIT_LINK); CHECK_STR(st.reason, "bearer-lost");
	check_clean(); CHECK_EQ(E.n_install, 0); CHECK_EQ(E.n_down, 0);
	pump(100000); CHECK_EQ(E.neps, 1);	/* nothing starts again by itself */
	teardown();
	/* AKA in progress: the AKA request is cancelled */
	setup(2);
	E.aka_script[0] = 100; E.n_aka_script = 1;
	reg_set_link(E.r, &LINK);
	reply_401(E.eps[0], 1);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_AKA); CHECK(E.aka_pending);
	{ struct ims_link nl = not_ready("modem-searching"); reg_set_link(E.r, &nl); }
	CHECK(!E.aka_pending);
	check_clean(); CHECK_EQ(E.n_install, 0);
	teardown();
	/* an AKA that never completes: the step timer fails the attempt after 20 s */
	setup(2);
	E.aka_script[0] = 100; E.n_aka_script = 1;
	reg_set_link(E.r, &LINK);
	reply_401(E.eps[0], 1);
	pump(19000); reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_AKA);
	pump(1500);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_UNPROT); CHECK_STR(st.pcscf, PC1);
	CHECK(!E.aka_pending);
	teardown();
	/* PROT: SAs installed, protected REGISTER out */
	setup(2);
	reg_set_link(E.r, &LINK);
	reply_401(E.eps[0], 1); pump(10);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_PROT); CHECK_EQ(E.n_install, 1); CHECK_EQ(E.n_remove, 0);
	{ struct ims_link nl = not_ready("bearer-lost"); reg_set_link(E.r, &nl); }
	CHECK_EQ(E.n_remove, 1);
	check_clean();
	teardown();
	/* REGISTERED, then the link comes back: registers again */
	go_registered(2);
	CHECK_EQ(E.n_up, 1);
	{ struct ims_link nl = not_ready("bearer-lost"); reg_set_link(E.r, &nl); }
	CHECK_EQ(E.n_down, 1); CHECK_STR(E.down_reason, "IMS link lost");
	reg_get_status(E.r, &st); CHECK(!st.registered); CHECK_EQ(st.state, RS_WAIT_LINK);
	CHECK(reg_context(E.r) == NULL);
	check_clean();
	n_before = E.neps;
	reg_set_link(E.r, &LINK);
	CHECK_EQ(E.neps, n_before + 1);
	finish_registration(600, PC0);
	CHECK_EQ(E.n_up, 2);
	reg_get_status(E.r, &st); CHECK(st.registered);
	teardown();
	/* REFRESH in flight */
	go_registered(2);
	pump(301000);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_REFRESH);
	{ struct ims_link nl = not_ready("bearer-lost"); reg_set_link(E.r, &nl); }
	CHECK_EQ(E.n_down, 1);
	check_clean();
	teardown();
	/* REAUTH before and after the new SAs are installed */
	go_registered(2);
	pump(301000);
	reply_401(last_ep(true), 5);	/* the refresh is challenged */
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_REAUTH); CHECK(st.registered);
	{ struct ims_link nl = not_ready("bearer-lost"); reg_set_link(E.r, &nl); }
	CHECK_EQ(E.n_down, 1);
	check_clean(); CHECK_EQ(E.n_install, 1);
	teardown();
	go_registered(2);
	pump(301000);
	reply_401(last_ep(true), 5);
	reply_401(last_ep(false), 6); pump(10);
	CHECK_EQ(E.n_install, 2);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_REAUTH);
	{ struct ims_link nl = not_ready("bearer-lost"); reg_set_link(E.r, &nl); }
	CHECK_EQ(E.n_remove, 2);
	check_clean();
	teardown();
	/* BACKOFF */
	setup(1);
	reg_set_link(E.r, &LINK);
	pump(9000);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_BACKOFF);
	{ struct ims_link nl = not_ready("bearer-lost"); reg_set_link(E.r, &nl); }
	n_before = E.neps;
	pump(1000000); CHECK_EQ(E.neps, n_before);
	check_clean();
	teardown();

	/* ===== re-authentication keeps the registration; the old set is retired only after the new one succeeded ===== */
	go_registered(2);
	CHECK_EQ(E.neps, 2); p = E.eps[1];
	pump(301000);	/* refresh: nobody has answered */
	reply_401(p, 5);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_REAUTH); CHECK(st.registered); CHECK_EQ(st.auth_failures, 1);
	CHECK(reg_context(E.r) != NULL);
	CHECK_EQ(E.neps, 3);
	u = last_ep(false);
	CHECK(u == E.eps[2]);
	CHECK(sent_to(u, 0, PC0, 5060));	/* the same P-CSCF first */
	CHECK(!last_msg(u, &m)); get_sc(&m, &sc2); sip_msg_free(&m);
	CHECK(sc2.port_c != E.sas[0].port_uc && sc2.port_s != E.sas[0].port_us && sc2.spi_c != E.sas[0].spi_uc);
	reply_401(u, 7);
	pump(10);
	CHECK_EQ(E.n_install, 2); CHECK_EQ(E.neps, 4); CHECK_EQ(E.n_remove, 0);
	CHECK(E.sas[1].port_uc == sc2.port_c && E.sas[1].reqid != E.sas[0].reqid);
	CHECK(E.sas[1].port_uc != E.sas[0].port_uc);
	p2 = E.eps[3];
	reg_get_status(E.r, &st); CHECK(st.registered); CHECK_EQ(st.state, RS_REAUTH);
	CHECK(reg_context(E.r)->ep == p->ep);	/* still the old endpoint until the new registration is accepted */
	reply_200(p2, 600, PC0);
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_REGISTERED); CHECK_EQ(E.n_replaced, 1); CHECK_EQ(E.n_up, 1); CHECK_EQ(E.n_down, 0);
	CHECK_EQ(st.port_s, sc2.port_s); CHECK_EQ(st.reauths, 1);
	CHECK(reg_context(E.r)->ep == p2->ep);
	CHECK_EQ(E.n_remove, 0);	/* drain: the old SAs stay for a while */
	/* a late request on the old endpoint is still answered */
	n_before = p->nsent;
	inject_req(p, "OPTIONS", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
	CHECK_EQ(p->nsent, n_before + 1); CHECK_EQ(last_status(p), 200);
	pump(4800); CHECK_EQ(E.n_remove, 0);
	pump(400);
	CHECK_EQ(E.n_remove, 1);
	CHECK(E.removed[0].spi_uc == E.sas[0].spi_uc && E.removed[0].port_uc == E.sas[0].port_uc);
	pump(60000);
	CHECK(p->closed); CHECK(E.eps[2]->closed); CHECK(!p2->closed);
	/* the next refresh uses the new endpoint */
	n_before = p2->nsent;
	pump(300000);
	CHECK(p2->nsent > n_before);
	teardown();

	/* refresh with no answer: re-authentication on both P-CSCFs, then the registration is lost and we back off */
	go_registered(2);
	pump(301000);
	pump(8000);	/* the refresh guard (8 s) fires: REAUTH starts */
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_REAUTH); CHECK(st.registered);
	pump(8300);	/* P-CSCF 0 gave no answer, now P-CSCF 1 */
	reg_get_status(E.r, &st); CHECK_STR(st.pcscf, PC1); CHECK(st.registered);
	pump(8300);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_BACKOFF); CHECK(!st.registered);
	CHECK_EQ(E.n_down, 1); CHECK_EQ(E.n_remove, 1);
	{ struct ims_link nl = not_ready("bearer-lost"); reg_set_link(E.r, &nl); }
	check_clean();
	teardown();

	/* refresh answered 403 */
	go_registered(2);
	pump(301000);
	{
		struct addr src = A(PC0, NET_PORT_C);

		CHECK(!last_msg(last_ep(true), &m));
		send_resp(last_ep(true), &m, 403, "Forbidden", NULL, &src);
		sip_msg_free(&m);
	}
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_BACKOFF); CHECK(strstr(st.reason, "forbidden") != NULL); CHECK(!st.registered);
	CHECK_EQ(E.n_down, 1);
	teardown();

	/* registration expires without a successful refresh (answers keep failing) */
	go_registered(1);
	pump(301000);
	reply_401(last_ep(true), 5);	/* refresh challenged, the only P-CSCF never answers the re-authentication */
	pump(20000);
	reg_get_status(E.r, &st); CHECK(!st.registered); CHECK_EQ(E.n_down, 1);
	teardown();

	/* ===== de-registration on shutdown ===== */
	go_registered(2);
	p = E.eps[1];
	n_before = p->nsent;
	shut_n = 0;
	reg_shutdown(E.r, shut_cb, NULL);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_DEREG);
	CHECK_EQ(p->nsent, n_before + 1);
	CHECK(!last_msg(p, &m));
	CHECK_STR(m.method, "REGISTER"); CHECK_STR(sip_hdr(&m, "Expires", 0), "0");
	CHECK(!fakeep_parse(p, 0, &m2));
	CHECK_EQ(atoi(sip_hdr(&m, "CSeq", 0)), atoi(sip_hdr(&m2, "CSeq", 0)) + 1);
	CHECK_STR(sip_hdr(&m, "Call-ID", 0), sip_hdr(&m2, "Call-ID", 0));
	sip_msg_free(&m2);
	CHECK(sip_hdr(&m, "Security-Verify", 0) != NULL);
	sip_msg_free(&m);
	CHECK_EQ(shut_n, 0);
	{
		struct addr src = A(PC0, NET_PORT_C);

		CHECK(!last_msg(p, &m));
		snprintf(x, sizeof(x), "Contact: %s;expires=0\r\nExpires: 0\r\n", sip_hdr(&m, "Contact", 0));
		send_resp(p, &m, 200, "OK", x, &src);
		sip_msg_free(&m);
	}
	pump(10);
	CHECK_EQ(shut_n, 1); CHECK_EQ(E.n_down, 1);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_IDLE); CHECK(!st.registered);
	check_clean();
	pump(100000); CHECK_EQ(shut_n, 1);
	teardown();
	/* the network does not answer: bounded by 2 s */
	go_registered(2);
	shut_n = 0;
	reg_shutdown(E.r, shut_cb, NULL);
	pump(1900); CHECK_EQ(shut_n, 0);
	pump(200); CHECK_EQ(shut_n, 1);
	check_clean();
	teardown();
	/* never registered: immediate */
	setup(2);
	reg_set_link(E.r, &LINK);
	shut_n = 0;
	reg_shutdown(E.r, shut_cb, NULL);
	pump(10); CHECK_EQ(shut_n, 1);
	check_clean();
	teardown();
	/* shutdown during AKA with SAs about to be installed */
	setup(2);
	E.aka_script[0] = 100; E.n_aka_script = 1;
	reg_set_link(E.r, &LINK);
	reply_401(E.eps[0], 1);
	shut_n = 0;
	reg_shutdown(E.r, shut_cb, NULL);
	pump(10); CHECK_EQ(shut_n, 1); CHECK(!E.aka_pending);
	check_clean();
	teardown();

	/* ===== waiting states from the modem layer ===== */
	setup(2);
	{ struct ims_link nl = not_ready("no-pcscf"); reg_set_link(E.r, &nl); }
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_WAIT_LINK); CHECK_STR(st.reason, "no-pcscf"); CHECK_EQ(E.neps, 0);
	{ struct ims_link nl = not_ready("modem-ims-active"); reg_set_link(E.r, &nl); }
	reg_get_status(E.r, &st); CHECK_STR(st.reason, "modem-ims-active"); CHECK_EQ(E.neps, 0);
	LINK.pcscf_src = PCSCF_STATIC;
	snprintf(LINK.pcscf[0], sizeof(LINK.pcscf[0]), "2001:db8::5");
	LINK.n_pcscf = 1;
	reg_set_link(E.r, &LINK);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_UNPROT); CHECK_STR(st.pcscf, "2001:db8::5"); CHECK_EQ(st.pcscf_source, PCSCF_STATIC);
	CHECK(sent_to(E.eps[0], 0, "2001:db8::5", 5060));
	teardown();

	/* ===== 403 Forbidden: long backoff, no rotation ===== */
	setup(2);
	reg_set_link(E.r, &LINK);
	{
		struct addr src = A(PC0, 5060);

		CHECK(!last_msg(E.eps[0], &m));
		send_resp(E.eps[0], &m, 403, "Forbidden", NULL, &src);
		sip_msg_free(&m);
	}
	reg_get_status(E.r, &st);
	CHECK_EQ(st.state, RS_BACKOFF); CHECK(strstr(st.reason, "forbidden") != NULL); CHECK_EQ(st.auth_failures, 1);
	pump(899000); CHECK_EQ(E.neps, 1);
	pump(2000); CHECK_EQ(E.neps, 2); CHECK(sent_to(E.eps[1], 0, PC0, 5060));
	teardown();

	/* ===== 423 Interval Too Brief ===== */
	setup(2);
	reg_set_link(E.r, &LINK);
	u = E.eps[0];
	{
		struct addr src = A(PC0, 5060);

		CHECK(!last_msg(u, &m)); cseq1 = atoi(sip_hdr(&m, "CSeq", 0));
		send_resp(u, &m, 423, "Interval Too Brief", "Min-Expires: 1800\r\n", &src);
		sip_msg_free(&m);
	}
	CHECK_EQ(u->nsent, 2);
	CHECK(!last_msg(u, &m));
	CHECK_STR(sip_hdr(&m, "Expires", 0), "1800"); CHECK_EQ(atoi(sip_hdr(&m, "CSeq", 0)), (int)cseq1 + 1);
	sip_msg_free(&m);
	finish_registration(1800, PC0);
	p = last_ep(true);
	CHECK(!fakeep_parse(p, 0, &m)); CHECK_STR(sip_hdr(&m, "Expires", 0), "1800"); sip_msg_free(&m);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_REGISTERED); CHECK(st.expires_in_s > 1790);
	n_before = p->nsent;
	pump(890000); CHECK_EQ(p->nsent, n_before);
	pump(15000); CHECK(p->nsent > n_before);
	teardown();

	/* granted time: Contact expires wins over the Expires header; no Contact param: the header; neither: what we asked */
	setup(2);
	reg_set_link(E.r, &LINK);
	reply_401(E.eps[0], 1); pump(10);
	p = last_ep(true);
	{
		struct addr src = A(PC0, NET_PORT_C);

		CHECK(!last_msg(p, &m));
		snprintf(x, sizeof(x), "Contact: %s;expires=120\r\nExpires: 3600\r\nService-Route: <sip:orig@scscf.lte-lguplus.co.kr;lr>\r\nP-Associated-URI: <sip:01051226862@lte-lguplus.co.kr>, <tel:+821051226862>\r\n", sip_hdr(&m, "Contact", 0));
		send_resp(p, &m, 200, "OK", x, &src);
		sip_msg_free(&m);
	}
	reg_get_status(E.r, &st); CHECK(st.expires_in_s >= 118 && st.expires_in_s <= 120);
	ctx = reg_context(E.r);
	CHECK(ctx && ctx->n_service_route == 1 && !strcmp(ctx->service_route[0], "<sip:orig@scscf.lte-lguplus.co.kr;lr>"));
	CHECK_STR(st.assoc_uri, "sip:01051226862@lte-lguplus.co.kr");
	n_before = p->nsent;
	pump(61000);	/* refresh at half of 120 s */
	CHECK(p->nsent > n_before);
	teardown();

	/* ===== an unusable 401: no Security-Server -> next P-CSCF without AKA ===== */
	setup(2);
	reg_set_link(E.r, &LINK);
	{
		struct addr src = A(PC0, 5060);

		CHECK(!last_msg(E.eps[0], &m));
		make_401(x, sizeof(x), 1, false);
		send_resp(E.eps[0], &m, 401, "UNAUTHORIZED", x, &src);
		sip_msg_free(&m);
	}
	CHECK_EQ(E.n_aka, 0);
	pump(300);
	CHECK(sent_to(last_ep(false), 0, PC1, 5060));
	reg_get_status(E.r, &st); CHECK(strstr(st.last_error, "Security-Server") != NULL);
	teardown();

	/* ===== SA installation fails: nothing leaks, next P-CSCF ===== */
	setup(2);
	E.install_fail = true;
	reg_set_link(E.r, &LINK);
	reply_401(E.eps[0], 1);
	pump(10);
	CHECK_EQ(E.n_install, 0); CHECK_EQ(E.neps, 1);	/* no protected endpoint was opened */
	pump(300);
	CHECK(sent_to(last_ep(false), 0, PC1, 5060));
	E.install_fail = false;
	finish_registration(600, PC1);
	reg_get_status(E.r, &st); CHECK(st.registered); CHECK_EQ(E.n_install, 1);
	teardown();

	/* ===== endpoint cannot be opened (every port in use) ===== */
	setup(2);
	E.open_fail = true;
	reg_set_link(E.r, &LINK);
	reg_get_status(E.r, &st);
	CHECK_EQ(E.neps, 0);
	pump(300);
	pump(300);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_BACKOFF);
	E.open_fail = false;
	pump(6000);
	CHECK_EQ(E.neps, 1);
	teardown();

	/* ===== 401 to the protected REGISTER (stale nonce): fresh attempt, same P-CSCF, new ports ===== */
	setup(2);
	reg_set_link(E.r, &LINK);
	reply_401(E.eps[0], 1); pump(10);
	p = last_ep(true);
	CHECK(!fakeep_parse(E.eps[0], 0, &m)); get_sc(&m, &sc1); sip_msg_free(&m);
	reply_401(p, 3);
	reg_get_status(E.r, &st); CHECK_EQ(st.auth_failures, 1);
	CHECK_EQ(E.n_remove, 1);	/* the SAs of the failed attempt are gone at once */
	pump(10);
	u = last_ep(false);
	CHECK(u != E.eps[0] && sent_to(u, 0, PC0, 5060));
	CHECK(!last_msg(u, &m)); get_sc(&m, &sc2); sip_msg_free(&m);
	CHECK(sc2.port_c != sc1.port_c && sc2.spi_c != sc1.spi_c);
	finish_registration(600, PC0);
	reg_get_status(E.r, &st); CHECK(st.registered); CHECK_EQ(E.n_install, 2);
	teardown();

	/* ===== link change: new local address -> everything released and registered again ===== */
	go_registered(2);
	{
		struct ims_link l2 = LINK;

		l2.seq++;	/* same content: nothing happens */
		reg_set_link(E.r, &l2);
		CHECK_EQ(E.n_down, 0); CHECK_EQ(E.neps, 2);
		addr_set(&l2.br.local, "2001:4430:141:990a:1111:2222:3333:4444", 0);
		reg_set_link(E.r, &l2);
		CHECK_EQ(E.n_down, 1); CHECK_EQ(E.n_remove, 1);
		reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_UNPROT);
		LINK = l2;
		finish_registration(600, PC0);
		CHECK_EQ(E.n_up, 2);
		CHECK(addr_equal_ip(&E.sas[1].ue, &l2.br.local));
	}
	teardown();

	/* ===== manual control ===== */
	go_registered(2);
	shut_n = 0;
	reg_set_enabled(E.r, false);
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_DEREG);
	{
		struct addr src = A(PC0, NET_PORT_C);

		CHECK(!last_msg(E.eps[1], &m));
		CHECK_STR(sip_hdr(&m, "Expires", 0), "0");
		send_resp(E.eps[1], &m, 200, "OK", "Expires: 0\r\n", &src);
		sip_msg_free(&m);
	}
	reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_IDLE); CHECK(!st.registered); CHECK_EQ(E.n_down, 1);
	n_before = E.neps;
	reg_set_link(E.r, &LINK);	/* a link event while disabled does nothing */
	pump(10000); CHECK_EQ(E.neps, n_before);
	reg_set_enabled(E.r, true);
	CHECK_EQ(E.neps, n_before + 1);
	finish_registration(600, PC0);
	CHECK_EQ(E.n_up, 2);
	teardown();

	/* ===== configuration changes ===== */
	go_registered(2);
	{
		struct reg_cfg c;

		reg_cfg_defaults(&c);
		snprintf(c.pani, sizeof(c.pani), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=1234567890ABCDEF");
		c.backoff_max_ms = 600000;
		CHECK(reg_set_cfg(E.r, &c));	/* the PANI is part of every request: re-register to use it */
		reg_get_status(E.r, &st); CHECK_EQ(st.state, RS_UNPROT);
		CHECK(!last_msg(last_ep(false), &m));
		CHECK_STR(sip_hdr(&m, "P-Access-Network-Info", 0), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=1234567890ABCDEF");
		sip_msg_free(&m);
		c.backoff_max_ms = 300000;
		CHECK(!reg_set_cfg(E.r, &c));	/* timing only: no restart */
		c.pcscf_port = 5061;
		CHECK(reg_set_cfg(E.r, &c));
		CHECK(sent_to(last_ep(false), 0, PC0, 5061));
	}
	teardown();

	/* ===== incoming requests ===== */
	go_registered(2);
	p = E.eps[1];
	{
		static const char *RPDATA = "013e07912801022981120019040b811050216268f200086211025061646306d14cc2a4d2b8";
		uint8_t body[64];
		int bn = hex_decode(RPDATA, body, sizeof(body)), k;
		struct addr ro = A(PC0, NET_PORT_S);
		const char *sms_hdr = "Accept-contact: *;+g.3gpp.smsip;require;explicit\r\nContent-Type: application/vnd.3gpp.sms\r\n"
				      "P-Asserted-Identity: <sip:ipsmgw.lte-lguplus.co.kr>\r\nP-Called-Party-Id: <sip:01051226862@lte-lguplus.co.kr>\r\n";

		/* OPTIONS, NOTIFY */
		n_before = p->nsent;
		inject_req(p, "OPTIONS", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
		CHECK_EQ(p->nsent, n_before + 1);
		CHECK(!last_msg(p, &m)); CHECK_EQ(m.status, 200); CHECK(sip_hdr(&m, "Allow", 0) != NULL); CHECK(sip_hdr(&m, "Accept", 0) != NULL);
		CHECK(addr_equal(&p->sent[p->nsent - 1].dst, &ro));	/* responses go from port-c to the P-CSCF port-s */
		sip_msg_free(&m);
		inject_req(p, "NOTIFY", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
		CHECK_EQ(last_status(p), 200);
		/* MT SMS: 200, then RP-ACK as a new MESSAGE */
		n_before = p->nsent;
		inject_req(p, "MESSAGE", "sip:01051226862@lte-lguplus.co.kr", sms_hdr, body, bn);
		CHECK_EQ(p->nsent, n_before + 2);
		CHECK(!fakeep_parse(p, n_before, &m));
		CHECK_EQ(m.status, 200);
		CHECK(addr_equal(&p->sent[n_before].dst, &ro));
		snprintf(x, sizeof(x), "%s", sip_hdr(&m, "Call-ID", 0));
		sip_msg_free(&m);
		CHECK(!fakeep_parse(p, n_before + 1, &m2));
		CHECK(!m2.is_resp); CHECK_STR(m2.method, "MESSAGE"); CHECK_STR(m2.ruri, "sip:ipsmgw.lte-lguplus.co.kr");
		CHECK(addr_equal(&p->sent[n_before + 1].dst, &ro));
		CHECK(!strncmp(sip_hdr(&m2, "From", 0), "<sip:01051226862@lte-lguplus.co.kr>;tag=", 40));
		CHECK_STR(sip_hdr(&m2, "To", 0), "<sip:ipsmgw.lte-lguplus.co.kr>");
		CHECK(strcmp(sip_hdr(&m2, "Call-ID", 0), x) != 0);
		snprintf(x, sizeof(x), "in-MESSAGE-%d", n_before);
		CHECK_STR(sip_hdr(&m2, "In-Reply-To", 0), x);
		CHECK_STR(sip_hdr(&m2, "Route", 0), "<sip:[2001:4430:5:405::43]:5071;lr>");
		CHECK(sip_hdr(&m2, "P-Access-Network-Info", 0) != NULL);
		CHECK_STR(sip_hdr(&m2, "Security-Verify", 0), "ipsec-3gpp; mod=trans; alg=hmac-md5-96; ealg=null; spi-c=3417264; spi-s=3417263; port-c=5073; port-s=5071");
		CHECK_STR(sip_hdr(&m2, "Content-Type", 0), "application/vnd.3gpp.sms");
		CHECK_STR(sip_hdr(&m2, "Allow", 0), "MESSAGE");
		CHECK_STR(sip_hdr(&m2, "Request-Disposition", 0), "no-fork");
		CHECK_STR(sip_hdr(&m2, "Accept-Contact", 0), "*;+g.3gpp.smsip");
		CHECK(m2.body_len == 2 && m2.body[0] == 0x02 && m2.body[1] == 0x3e);
		CHECK_STR(sip_hdr(&m2, "Content-Length", 0), "2");
		{
			struct sip_via v;

			{ struct reg_status s2; reg_get_status(E.r, &s2); CHECK(!sip_top_via(&m2, &v)); CHECK_EQ(v.port, s2.port_s); }
		}
		/* the network accepts it (202) */
		{
			struct addr src = A(PC0, NET_PORT_C);

			send_resp(p, &m2, 202, "Accepted", NULL, &src);
		}
		sip_msg_free(&m2);
		reg_get_status(E.r, &st); CHECK_EQ(st.sms_received, 1);
		/* RP-ACK from the network (our MO SMS): 200, nothing sent back */
		{
			static const uint8_t rpack[] = { 0x03, 0xae, 0x41, 0x09, 0x01, 0x00, 0x62, 0x11, 0x02, 0x50, 0x73, 0x14, 0x63 };

			n_before = p->nsent;
			inject_req(p, "MESSAGE", "sip:01051226862@lte-lguplus.co.kr", sms_hdr, rpack, sizeof(rpack));
			CHECK_EQ(p->nsent, n_before + 1); CHECK_EQ(last_status(p), 200);
			static const uint8_t rperr[] = { 0x05, 0x11, 0x01, 0x16 };
			inject_req(p, "MESSAGE", "sip:01051226862@lte-lguplus.co.kr", sms_hdr, rperr, sizeof(rperr));
			CHECK_EQ(p->nsent, n_before + 2); CHECK_EQ(last_status(p), 200);
		}
		/* no PAI: the From URI is the target; a message without the RP header is only acknowledged */
		n_before = p->nsent;
		inject_req(p, "MESSAGE", "sip:01051226862@lte-lguplus.co.kr", "Content-Type: application/vnd.3gpp.sms\r\n", body, bn);
		CHECK_EQ(p->nsent, n_before + 2);
		CHECK(!fakeep_parse(p, n_before + 1, &m2)); CHECK_STR(m2.ruri, "sip:ipsmgw.lte-lguplus.co.kr"); sip_msg_free(&m2);
		n_before = p->nsent;
		inject_req(p, "MESSAGE", "sip:01051226862@lte-lguplus.co.kr", "Content-Type: application/vnd.3gpp.sms\r\n", body, 1);
		CHECK_EQ(p->nsent, n_before + 1); CHECK_EQ(last_status(p), 200);
		/* other content types */
		inject_req(p, "MESSAGE", "sip:01051226862@lte-lguplus.co.kr", "Content-Type: text/plain\r\n", (const uint8_t *)"hi", 2);
		CHECK_EQ(last_status(p), 415);
		/* calls are not supported yet */
		inject_req(p, "INVITE", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
		CHECK_EQ(last_status(p), 480);
		inject_req(p, "BYE", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
		CHECK_EQ(last_status(p), 481);
		inject_req(p, "UPDATE", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
		CHECK_EQ(last_status(p), 481);
		inject_req(p, "REGISTER", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
		CHECK_EQ(last_status(p), 405);
		inject_req(p, "FOO", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
		CHECK_EQ(last_status(p), 501);
		/* CANCEL for an unknown transaction: 481 from the transaction layer */
		inject_req(p, "CANCEL", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
		CHECK_EQ(last_status(p), 481);
		/* extension handler table: consulted first, unhandled requests keep the built-in answers */
		{
			struct reg_handlers h = { .on_invite = hx_invite, .on_message = hx_message, .on_in_dialog = hx_in_dialog, .on_ack = hx_ack };
			static const uint8_t rpd[] = { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00 };
			struct reg_status s3;

			memset(&HX, 0, sizeof(HX));
			reg_set_handlers(E.r, &h);
			HX.take = true; HX.status = 486;
			inject_req(p, "INVITE", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
			CHECK_EQ(HX.invite, 1); CHECK_EQ(last_status(p), 486);
			HX.status = 202;
			reg_get_status(E.r, &s3); n_before = (int)s3.sms_received;
			inject_req(p, "MESSAGE", "sip:01051226862@lte-lguplus.co.kr", "Content-Type: application/vnd.3gpp.sms\r\n", rpd, sizeof(rpd));
			CHECK_EQ(HX.message, 1); CHECK_EQ(last_status(p), 202);
			reg_get_status(E.r, &s3); CHECK_EQ(s3.sms_received, (unsigned)n_before);	/* the module owns it: no built-in SMS handling */
			HX.status = 200;
			inject_req(p, "BYE", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
			CHECK_EQ(HX.in_dialog, 1); CHECK_EQ(last_status(p), 200);
			inject_req(p, "OPTIONS", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);	/* never offered */
			CHECK_EQ(HX.invite + HX.message + HX.in_dialog, 3); CHECK_EQ(last_status(p), 200);
			/* handler declines: built-in behaviour */
			HX.take = false;
			inject_req(p, "INVITE", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
			CHECK_EQ(HX.invite, 2); CHECK_EQ(last_status(p), 480);
			inject_req(p, "UPDATE", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
			CHECK_EQ(HX.in_dialog, 2); CHECK_EQ(last_status(p), 481);
			inject_req(p, "MESSAGE", "sip:01051226862@lte-lguplus.co.kr", "Content-Type: text/plain\r\n", (const uint8_t *)"hi", 2);
			CHECK_EQ(HX.message, 2); CHECK_EQ(last_status(p), 415);
			/* a slot left NULL */
			h.on_invite = NULL;
			reg_set_handlers(E.r, &h);
			inject_req(p, "INVITE", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
			CHECK_EQ(HX.invite, 2); CHECK_EQ(last_status(p), 480);
			/* ACK without transaction reaches on_ack; cleared table: nothing */
			{
				struct addr asrc = A(PC0, NET_PORT_C);
				const char *ack = "ACK sip:x@y SIP/2.0\r\nVia: SIP/2.0/UDP [2001:4430:5:405::43]:5071;branch=z9hG4bK-ack1\r\n"
						  "From: <sip:a@b>;tag=1\r\nTo: <sip:c@d>;tag=2\r\nCall-ID: ack-1\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n";

				fakeep_rx(p, &asrc, ack);
				CHECK_EQ(HX.ack, 1);
				reg_set_handlers(E.r, NULL);
				fakeep_rx(p, &asrc, ack);
				CHECK_EQ(HX.ack, 1);
			}
			inject_req(p, "INVITE", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
			CHECK_EQ(HX.invite, 2); CHECK_EQ(last_status(p), 480);
		}
		(void)k;
	}
	teardown();

	/* requests on the unprotected endpoint get 403 */
	setup(2);
	reg_set_link(E.r, &LINK);
	u = E.eps[0];
	n_before = u->nsent;
	inject_req(u, "OPTIONS", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
	CHECK_EQ(u->nsent, n_before + 1); CHECK_EQ(last_status(u), 403);
	inject_req(u, "MESSAGE", "sip:01051226862@lte-lguplus.co.kr", "Content-Type: application/vnd.3gpp.sms\r\n", (const uint8_t *)"\x01\x01", 2);
	CHECK_EQ(last_status(u), 403);
	{	/* the extension table is never consulted for the unprotected endpoint */
		struct reg_handlers h = { .on_invite = hx_invite, .on_message = hx_message, .on_in_dialog = hx_in_dialog };

		memset(&HX, 0, sizeof(HX)); HX.take = true; HX.status = 200;
		reg_set_handlers(E.r, &h);
		inject_req(u, "INVITE", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
		CHECK_EQ(HX.invite, 0); CHECK_EQ(last_status(u), 403);
	}
	teardown();

	/* reg_send needs a registration */
	setup(2);
	reg_set_link(E.r, &LINK);
	{
		struct reg_req q = { .method = "MESSAGE", .ruri = "sip:x@y" };

		CHECK_EQ(reg_send(E.r, &q, NULL, NULL), -ENOTCONN);
	}
	teardown();
	/* ===== P-Access-Network-Info: explicit config > live serving cell > legacy default ===== */
	{
		static const char *LIVE1 = "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=45006AAAA0000001";
		static const char *LIVE2 = "3GPP-E-UTRAN-TDD; utran-cell-id-3gpp=45006BBBB0000002";
		struct reg_cfg c;
		struct reg_status st2;
		struct sip_msg m2;
		struct fakeep *pp;
		struct reg_req q = { .method = "MESSAGE", .ruri = "sip:x@y", .content_type = "text/plain" };

		reg_cfg_defaults(&c);
		CHECK_STR(c.pani, "");	/* default: derive */
		CHECK_STR(c.user_agent, "");

		/* nothing known: the legacy value, so the registration never fails for lack of cell data */
		setup(2);
		E.live_pani = NULL;
		reg_set_link(E.r, &LINK);
		CHECK(!last_msg(last_ep(false), &m2));
		CHECK_STR(sip_hdr(&m2, "P-Access-Network-Info", 0), REG_PANI_LEGACY);
		sip_msg_free(&m2);
		reg_get_status(E.r, &st2); CHECK_EQ(st2.pani_source, PANI_DEFAULT); CHECK_STR(st2.pani, REG_PANI_LEGACY);
		CHECK_STR(reg_pani_source_name(st2.pani_source), "default");
		E.live_pani = "";	/* an empty live value is "unknown" too */
		finish_registration(600, PC0);
		CHECK_STR(reg_context(E.r)->pani, REG_PANI_LEGACY);
		teardown();

		/* live value: used in the REGISTERs, and read afresh by every request and by reg_context() */
		setup(2);
		E.live_pani = LIVE1;
		reg_set_link(E.r, &LINK);
		CHECK(!last_msg(last_ep(false), &m2));
		CHECK_STR(sip_hdr(&m2, "P-Access-Network-Info", 0), LIVE1);
		sip_msg_free(&m2);
		reply_401(last_ep(false), 1);
		pump(10);
		pp = last_ep(true);
		CHECK(!last_msg(pp, &m2));
		CHECK_STR(sip_hdr(&m2, "P-Access-Network-Info", 0), LIVE1);
		sip_msg_free(&m2);
		reply_200(pp, 600, PC0);
		CHECK(reg_is_registered(E.r));
		CHECK_STR(reg_context(E.r)->pani, LIVE1);
		reg_get_status(E.r, &st2); CHECK_EQ(st2.pani_source, PANI_LIVE); CHECK_STR(st2.pani, LIVE1);
		CHECK_STR(reg_pani_source_name(st2.pani_source), "cell");
		E.live_pani = LIVE2;	/* the cell changed: the next request and the context carry it */
		CHECK_STR(reg_context(E.r)->pani, LIVE2);
		CHECK_EQ(reg_send(E.r, &q, NULL, NULL), 0);
		CHECK(!last_msg(pp, &m2));
		CHECK_STR(m2.method, "MESSAGE");
		CHECK_STR(sip_hdr(&m2, "P-Access-Network-Info", 0), LIVE2);
		sip_msg_free(&m2);
		teardown();

		/* explicit configuration wins */
		setup(2);
		snprintf(c.pani, sizeof(c.pani), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=1234567890ABCDEF");
		reg_set_cfg(E.r, &c);
		E.live_pani = LIVE1;
		reg_set_link(E.r, &LINK);
		CHECK(!last_msg(last_ep(false), &m2));
		CHECK_STR(sip_hdr(&m2, "P-Access-Network-Info", 0), "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=1234567890ABCDEF");
		sip_msg_free(&m2);
		finish_registration(600, PC0);
		CHECK_STR(reg_context(E.r)->pani, "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=1234567890ABCDEF");
		reg_get_status(E.r, &st2); CHECK_EQ(st2.pani_source, PANI_CONFIG);
		teardown();
	}

	/* ===== User-Agent on everything we originate ===== */
	{
		static const char *UA = "TTA-VoLTE/3.0 imsd/0.1 Device_Type/Android_Phone OMD";
		struct reg_cfg c;
		struct sip_msg m2;
		struct fakeep *pp, *uu;
		struct reg_req q = { .method = "MESSAGE", .ruri = "sip:x@y", .content_type = "text/plain" };
		struct addr src = A(PC0, NET_PORT_S);

		setup(2);
		reg_cfg_defaults(&c);
		snprintf(c.user_agent, sizeof(c.user_agent), "%s", UA);
		reg_set_cfg(E.r, &c);
		CHECK_STR(reg_user_agent(E.r), UA);
		reg_set_link(E.r, &LINK);
		uu = last_ep(false);
		CHECK(!last_msg(uu, &m2));	/* unprotected REGISTER */
		CHECK_STR(sip_hdr(&m2, "User-Agent", 0), UA);
		sip_msg_free(&m2);
		reply_401(uu, 1);
		pump(10);
		pp = last_ep(true);
		CHECK(!last_msg(pp, &m2));	/* protected REGISTER */
		CHECK_STR(m2.method, "REGISTER");
		CHECK_STR(sip_hdr(&m2, "User-Agent", 0), UA);
		sip_msg_free(&m2);
		reply_200(pp, 600, PC0);
		CHECK(reg_is_registered(E.r));
		CHECK_EQ(reg_send(E.r, &q, NULL, NULL), 0);	/* MESSAGE */
		CHECK(!last_msg(pp, &m2));
		CHECK_STR(m2.method, "MESSAGE");
		CHECK_STR(sip_hdr(&m2, "User-Agent", 0), UA);
		sip_msg_free(&m2);
		(void)src;
		inject_req(pp, "OPTIONS", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);	/* response we build */
		CHECK(!last_msg(pp, &m2));
		CHECK_EQ(m2.status, 200);
		CHECK_STR(sip_hdr(&m2, "User-Agent", 0), UA);
		CHECK(sip_hdr(&m2, "Allow", 0) != NULL);	/* the answer's own headers are still there */
		sip_msg_free(&m2);
		inject_req(pp, "NOTIFY", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
		CHECK(!last_msg(pp, &m2)); CHECK_EQ(m2.status, 200); CHECK_STR(sip_hdr(&m2, "User-Agent", 0), UA);
		sip_msg_free(&m2);
		inject_req(pp, "BYE", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);	/* 481 */
		CHECK(!last_msg(pp, &m2)); CHECK_EQ(m2.status, 481); CHECK_STR(sip_hdr(&m2, "User-Agent", 0), UA);
		sip_msg_free(&m2);
		/* de-registration */
		reg_set_enabled(E.r, false);
		CHECK(!last_msg(pp, &m2));
		CHECK_STR(m2.method, "REGISTER"); CHECK_STR(sip_hdr(&m2, "Expires", 0), "0");
		CHECK_STR(sip_hdr(&m2, "User-Agent", 0), UA);
		sip_msg_free(&m2);
		teardown();

		/* no configured User-Agent: no header anywhere */
		go_registered(2);
		pp = last_ep(true);
		CHECK_STR(reg_user_agent(E.r), "");
		CHECK_EQ(reg_send(E.r, &q, NULL, NULL), 0);
		CHECK(!last_msg(pp, &m2)); CHECK(!sip_hdr(&m2, "User-Agent", 0)); sip_msg_free(&m2);
		inject_req(pp, "OPTIONS", "sip:01051226862@lte-lguplus.co.kr", NULL, NULL, 0);
		CHECK(!last_msg(pp, &m2)); CHECK_EQ(m2.status, 200); CHECK(!sip_hdr(&m2, "User-Agent", 0)); sip_msg_free(&m2);
		teardown();
	}
	(void)i; (void)res; (void)resp; (void)expect; (void)ctx; (void)t0; (void)hdr_int; (void)ep_index;

	integration();
}
