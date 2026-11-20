/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SMS relay as a core module: the real core, registrar / lan, Gm registration (mock endpoints, xfrm and AKA as in
 * test_reg.c) and the relay. The "network" injects into / reads from the protected Gm endpoint, a fake LAN client
 * registers on the LAN endpoint. Covers MT delivery, MO with the SMSC / PSI rules, the lost paths, the late
 * reg_send response after stop, LAN restarts and the built-in fallback when no module is loaded.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"
#include "fakeep.h"
#include "evloop_fake.h"
#include "../core.h"
#include "../smsrelay/smsrelay_mod.h"
#include "../mms/mms_mod.h"
#include "../mms/mmsbearer.h"
#include "../mms/t_vectors.h"
#include "../util/codec.h"
#include "../util/evloop.h"

#define MAXEP 16
#define NET_PORT_C 5073
#define NET_PORT_S 5071
#define PC0 "2001:4430:5:405::43"
#define CLIENT_IP "192.168.68.10"
#define CLIENT_PORT 5062

static struct {
	struct fakeep *lan_eps[MAXEP];	/* what core opened as the LAN endpoint (generation by generation) */
	int n_lan;
	struct fakeep *gm_eps[MAXEP];	/* what the registration opened */
	struct sip_ep_cfg gm_cfg[MAXEP];
	int n_gm;
	char lan_ip[32];
	/* card values */
	char sim_smsc[32], sim_psi[160], sim_imsi[24];
	int n_pani;
	/* aka */
	imsmodem_aka_cb aka_cb;
	void *aka_arg;
	struct ev_timer *aka_t;
	uint8_t rand[16];
	int n_install, n_remove;
	int n_lan_binding;
} T;

static struct imsd_config CFG;
static bool g_with_mms, g_mms_off;	/* the MMS module is loaded / switched off by config */
static bool g_env;			/* the on-demand MMS bearer environment (fake uqmid, nft, rtnetlink) is set */
static char g_mms_apn[64];		/* uci mms_apn */
static struct core *C;
static int seq;

static struct addr A(const char *ip, int port)
{
	struct addr a;

	addr_set(&a, ip, port);
	return a;
}

/* ---- core / reg mocks ---- */
static struct sip_endpoint *t_open_lan(void *ctx, const struct sip_ep_cfg *cfg)
{
	(void)ctx;
	T.lan_eps[T.n_lan] = fakeep_open(cfg);
	return T.lan_eps[T.n_lan++]->ep;
}

static int t_lan_addr(void *ctx, const char *ifname, const struct addr *prefer, struct addr *out)
{
	(void)ctx; (void)ifname; (void)prefer;
	if (!T.lan_ip[0])
		return -1;
	return addr_set(out, T.lan_ip, 0);
}

static void t_binding(void *ctx, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why)
{
	(void)ctx; (void)ev; (void)b; (void)why;
	T.n_lan_binding++;
}

static struct sip_endpoint *t_open_gm(void *ctx, const struct sip_ep_cfg *cfg)
{
	(void)ctx;
	T.gm_cfg[T.n_gm] = *cfg;
	T.gm_eps[T.n_gm] = fakeep_open(cfg);
	return T.gm_eps[T.n_gm++]->ep;
}

static void aka_fire(void *arg)
{
	struct aka_result r;
	imsmodem_aka_cb cb = T.aka_cb;
	int i;

	(void)arg;
	memset(&r, 0, sizeof(r));
	r.status = AKA_OK;
	r.sw = 0x9000;
	r.res_len = 8;
	for (i = 0; i < 8; i++)
		r.res[i] = T.rand[i] ^ 0x5A;
	for (i = 0; i < 16; i++) {
		r.ck[i] = 0x20 + i;
		r.ik[i] = 0x40 + i;
	}
	cb(T.aka_arg, &r);
}

static int t_aka(void *ctx, const uint8_t rand[16], const uint8_t autn[16], imsmodem_aka_cb cb, void *arg)
{
	(void)ctx; (void)autn;
	memcpy(T.rand, rand, 16);
	T.aka_cb = cb;
	T.aka_arg = arg;
	if (!T.aka_t)
		T.aka_t = ev_timer_new(aka_fire, NULL);
	ev_timer_set(T.aka_t, 0);
	return 0;
}

static void t_aka_cancel(void *ctx, void *arg)
{
	(void)ctx; (void)arg;
	ev_timer_cancel(T.aka_t);
}

static int t_install(void *ctx, const struct xfrm_sa_params *p)
{
	(void)ctx; (void)p;
	T.n_install++;
	return 0;
}

static void t_remove(void *ctx, const struct xfrm_sa_params *p)
{
	(void)ctx; (void)p;
	T.n_remove++;
}

static const char *p_smsc(void *ctx) { (void)ctx; return T.sim_smsc; }
static const char *p_psi(void *ctx) { (void)ctx; return T.sim_psi; }
static const char *p_imsi(void *ctx) { (void)ctx; return T.sim_imsi; }
static void p_pani(void *ctx) { (void)ctx; T.n_pani++; }

/* ---- network side ---- */
static struct fakeep *gm_ep(void)
{
	int i;

	for (i = T.n_gm - 1; i >= 0; i--)
		if (T.gm_cfg[i].split_tx && !T.gm_eps[i]->closed)
			return T.gm_eps[i];
	return NULL;
}

static struct fakeep *gm_unprot(void)
{
	int i;

	for (i = T.n_gm - 1; i >= 0; i--)
		if (!T.gm_cfg[i].split_tx && !T.gm_eps[i]->closed)
			return T.gm_eps[i];
	return NULL;
}

static struct fakeep *lan_ep(void)
{
	return T.n_lan ? T.lan_eps[T.n_lan - 1] : NULL;
}

/* answer sent[idx] of f as its peer would: status, with a To tag, from the address it went to */
static void answer_sent(struct fakeep *f, int idx, int status, const char *extra)
{
	struct sip_msg m;
	char b[3000];
	struct addr src = f->sent[idx].dst;

	CHECK(!fakeep_parse(f, idx, &m));
	snprintf(b, sizeof(b), "SIP/2.0 %d X\r\nVia: %s\r\nFrom: %s\r\nTo: %s;tag=peer%d\r\nCall-ID: %s\r\nCSeq: %s\r\n%s"
		 "Content-Length: 0\r\n\r\n", status, sip_hdr(&m, "Via", 0), sip_hdr(&m, "From", 0), sip_hdr(&m, "To", 0), status,
		 sip_hdr(&m, "Call-ID", 0), sip_hdr(&m, "CSeq", 0), extra ? extra : "");
	sip_msg_free(&m);
	fakeep_rx(f, &src, b);
}

static void register_gm(void)
{
	struct sip_msg m;
	struct fakeep *u, *p;
	struct ims_link l;
	uint8_t raw[32];
	char nonce[64], x[900];
	int i;

	memset(&l, 0, sizeof(l));
	l.ready = true;
	snprintf(l.id.impi, sizeof(l.id.impi), "450061051226862@lte-lguplus.co.kr");
	snprintf(l.id.impu, sizeof(l.id.impu), "sip:01051226862@lte-lguplus.co.kr");
	snprintf(l.id.domain, sizeof(l.id.domain), "lte-lguplus.co.kr");
	snprintf(l.id.user, sizeof(l.id.user), "01051226862");
	snprintf(l.id.imei, sizeof(l.id.imei), "86883708-366218-5");
	snprintf(l.br.ifname, sizeof(l.br.ifname), "wwan0");
	addr_set(&l.br.local, "2001:4430:141:990a:25b5:899e:232:cb69", 0);
	l.br.prefix = 64;
	l.br.mtu = 1400;
	l.n_pcscf = 1;
	snprintf(l.pcscf[0], sizeof(l.pcscf[0]), PC0);
	l.pcscf_src = PCSCF_NETWORK;
	l.seq = 1;
	reg_set_link(core_reg(C), &l);
	u = gm_unprot();
	CHECK(u != NULL);
	if (!u)
		return;
	CHECK(!fakeep_parse(u, u->nsent - 1, &m));
	for (i = 0; i < 32; i++)
		raw[i] = 1 + i;
	b64_encode(raw, 32, nonce, sizeof(nonce));
	snprintf(x, sizeof(x), "WWW-Authenticate: Digest realm=\"lte-lguplus.co.kr\",nonce=\"%s\",algorithm=AKAv1-MD5\r\n"
		 "Security-Server: ipsec-3gpp; mod=trans; alg=hmac-md5-96; ealg=null; spi-c=3417264; spi-s=3417263; port-c=5073; port-s=5071\r\n", nonce);
	{
		char b[4096];
		struct addr src = A(PC0, 5060);

		snprintf(b, sizeof(b), "SIP/2.0 401 UNAUTHORIZED\r\nVia: %s\r\nFrom: %s\r\nTo: %s;tag=net401\r\nCall-ID: %s\r\nCSeq: %s\r\n%sContent-Length: 0\r\n\r\n",
			 sip_hdr(&m, "Via", 0), sip_hdr(&m, "From", 0), sip_hdr(&m, "To", 0), sip_hdr(&m, "Call-ID", 0), sip_hdr(&m, "CSeq", 0), x);
		fakeep_rx(u, &src, b);
	}
	sip_msg_free(&m);
	evfake_advance(10);
	p = gm_ep();
	CHECK(p != NULL);
	if (!p)
		return;
	CHECK(!fakeep_parse(p, p->nsent - 1, &m));
	{
		char b[4096], ex[600];
		struct addr src = A(PC0, NET_PORT_C);

		snprintf(ex, sizeof(ex), "Contact: %s;expires=600\r\nExpires: 600\r\nP-Associated-URI: <sip:01051226862@lte-lguplus.co.kr>\r\n",
			 sip_hdr(&m, "Contact", 0));
		snprintf(b, sizeof(b), "SIP/2.0 200 OK\r\nVia: %s\r\nFrom: %s\r\nTo: %s;tag=net200\r\nCall-ID: %s\r\nCSeq: %s\r\n%sContent-Length: 0\r\n\r\n",
			 sip_hdr(&m, "Via", 0), sip_hdr(&m, "From", 0), sip_hdr(&m, "To", 0), sip_hdr(&m, "Call-ID", 0), sip_hdr(&m, "CSeq", 0), ex);
		fakeep_rx(p, &src, b);
	}
	sip_msg_free(&m);
	CHECK(reg_is_registered(core_reg(C)));
}

#define CAP_GSM7 "01680791280102298172" "00" "26" "040b811050216268f2" "0000" "62110250731463" "15" "e9f6bc1e0685e1ad747b0e9ab7e7207a794e07"
static int mt_n;

/* an RP message from the network (MESSAGE application/vnd.3gpp.sms) on the protected endpoint */
static void net_rx(const char *call_id, const uint8_t *body, size_t n)
{
	struct fakeep *p = gm_ep();
	char buf[1500];
	struct addr src = A(PC0, NET_PORT_C);
	int l;

	l = snprintf(buf, sizeof(buf), "MESSAGE sip:01051226862@lte-lguplus.co.kr SIP/2.0\r\n"
		     "Via: SIP/2.0/UDP [2001:4430:5:405::43]:5071;branch=z9hG4bKsm%d;rport\r\nMax-Forwards: 66\r\n"
		     "To: <sip:01051226862@lte-lguplus.co.kr>\r\nFrom: <sip:ipsmgw.lte-lguplus.co.kr>;tag=az%d\r\nCall-ID: %s\r\n"
		     "CSeq: 512124776 MESSAGE\r\nContent-Type: application/vnd.3gpp.sms\r\nP-Asserted-Identity: <sip:ipsmgw.lte-lguplus.co.kr>\r\n"
		     "Content-Length: %zu\r\n\r\n", mt_n, mt_n, call_id, n);
	mt_n++;
	memcpy(buf + l, body, n);
	fakeep_rx_n(p, &src, buf, l + n);
}

static void net_rx_hex(const char *call_id, const char *hex)
{
	uint8_t b[300];
	int n = hex_decode(hex, b, sizeof(b));

	CHECK(n > 0);
	net_rx(call_id, b, n);
}

/* index of the first request with that method sent on f from `from` on, -1 */
static int find_req(const struct fakeep *f, const char *method, int from)
{
	int i;

	for (i = from; i < f->nsent; i++) {
		struct sip_msg m;
		bool hit;

		if (fakeep_parse(f, i, &m))
			continue;
		hit = !m.is_resp && !strcmp(m.method, method);
		sip_msg_free(&m);
		if (hit)
			return i;
	}
	return -1;
}

/* status of the last response on f with that Call-ID, -1 if none */
static int resp_for(const struct fakeep *f, const char *call_id)
{
	int i;

	for (i = f->nsent - 1; i >= 0; i--) {
		struct sip_msg m;
		const char *c;
		int st = -1;

		if (fakeep_parse(f, i, &m))
			continue;
		c = sip_hdr(&m, "Call-ID", 0);
		if (m.is_resp && c && !strcmp(c, call_id))
			st = m.status;
		sip_msg_free(&m);
		if (st >= 0)
			return st;
	}
	return -1;
}

/* body of sent[i] into out, returns its length */
static size_t body_of(const struct fakeep *f, int i, uint8_t *out, size_t cap)
{
	struct sip_msg m;
	size_t n = 0;

	if (!fakeep_parse(f, i, &m)) {
		n = m.body_len < cap ? m.body_len : cap;
		memcpy(out, m.body, n);
		sip_msg_free(&m);
	}
	return n;
}

static char HDR[400];
static const char *hdr_at(const struct fakeep *f, int i, const char *name)
{
	struct sip_msg m;
	const char *v;

	HDR[0] = 0;
	if (!fakeep_parse(f, i, &m)) {
		v = sip_hdr(&m, name, 0);
		if (v)
			snprintf(HDR, sizeof(HDR), "%s", v);
		sip_msg_free(&m);
	}
	return HDR;
}

static char RURI[300];
static const char *ruri_at(const struct fakeep *f, int i)
{
	struct sip_msg m;

	RURI[0] = 0;
	if (!fakeep_parse(f, i, &m)) {
		snprintf(RURI, sizeof(RURI), "%s", m.ruri);
		sip_msg_free(&m);
	}
	return RURI;
}

/* ---- LAN side ---- */
static void lan_req(const char *method, const char *ruri, const char *call_id, const char *extra, const char *ct,
		    const char *body)
{
	char m[2000];
	struct addr src = A(CLIENT_IP, CLIENT_PORT);
	size_t bl = body ? strlen(body) : 0;

	snprintf(m, sizeof(m), "%s %s SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bKsmlan%d;rport\r\nFrom: <sip:1000@192.168.68.1>;tag=a%d\r\n"
		 "To: <%s>\r\nCall-ID: %s\r\nCSeq: 1 %s\r\nMax-Forwards: 70\r\n%s%s%sContent-Length: %zu\r\n\r\n%s",
		 method, ruri, CLIENT_IP, CLIENT_PORT, seq, seq, ruri, call_id, method, extra ? extra : "",
		 ct ? "Content-Type: " : "", ct ? ct : "", bl, body ? body : "");
	if (ct) {	/* the Content-Type line needs its CRLF */
		char *p = strstr(m, ct);

		memmove(p + strlen(ct) + 2, p + strlen(ct), strlen(p + strlen(ct)) + 1);
		memcpy(p + strlen(ct), "\r\n", 2);
	}
	seq++;
	fakeep_rx(lan_ep(), &src, m);
}

static void lan_register(void)
{
	lan_req("REGISTER", "sip:192.168.68.1", "reg1@client", "Contact: <sip:1000@" CLIENT_IP ":5062>;expires=600\r\nUser-Agent: TestPhone/1.0\r\n", NULL, NULL);
	CHECK_EQ(resp_for(lan_ep(), "reg1@client"), 200);
}

/* ---- fixture ---- */
/* ---- the environment of the on-demand MMS bearer: a fake uqmid that only knows the SIM, a fake nft, a fake rtnetlink ---- */
static char E_imsi[24], E_plmn[8], E_modem[32];
static struct { uq_cb cb; void *arg; struct ev_timer *t; struct uq_req rq; } E_call;

static void e_fire(void *arg)
{
	struct uq_res r;
	uq_cb cb = E_call.cb;

	(void)arg;
	memset(&r, 0, sizeof(r));
	if (E_call.rq.op == UQ_SIM_GET && E_imsi[0])
		snprintf(r.imsi, sizeof(r.imsi), "%s", E_imsi);
	else
		r.err = UQ_E_FAILED;
	cb(E_call.arg, &r);
}

static void *e_uq_call(void *ctx, const struct uq_req *rq, uq_cb cb, void *arg)
{
	(void)ctx;
	if (!E_call.t)
		E_call.t = ev_timer_new(e_fire, NULL);
	E_call.cb = cb;
	E_call.arg = arg;
	E_call.rq = *rq;
	ev_timer_set(E_call.t, 0);
	return &E_call;
}

static void e_uq_cancel(void *ctx, void *h)
{
	(void)ctx; (void)h;
	ev_timer_cancel(E_call.t);
}

static int e_apply(void *ctx, const struct netcfg_params *p) { (void)ctx; (void)p; return 0; }
static void e_remove(void *ctx, const struct netcfg_params *p) { (void)ctx; (void)p; }
static const char *e_modem(void *ctx) { (void)ctx; return E_modem; }
static const char *e_plmn(void *ctx) { (void)ctx; return E_plmn; }
static void *e_run(void *ctx, const char *const *argv, const char *in, void (*cb)(void *, int, const char *), void *arg)
{
	(void)ctx; (void)argv; (void)in; (void)cb; (void)arg;
	errno = ENOENT;
	return NULL;
}
static void e_cancel(void *ctx, void *h) { (void)ctx; (void)h; }

static void env_set(void)
{
	static struct uq_ops uq;
	static struct netcfg_ops net;
	static struct guard_exec_ops ex;
	struct mms_mod_env e;

	uq.call = e_uq_call;
	uq.cancel = e_uq_cancel;
	net.apply = e_apply;
	net.remove = e_remove;
	ex.run = e_run;
	ex.cancel = e_cancel;
	memset(&e, 0, sizeof(e));
	e.uq = &uq;
	e.net = &net;
	e.exec = &ex;
	e.modem = e_modem;
	e.net_plmn = e_plmn;
	mms_mod_set_env(&e);
}

static void setup(const char *lan_ip, bool with_module)
{
	struct core_ops ops = { .open_ep = t_open_lan, .lan_addr = t_lan_addr, .on_binding = t_binding };
	struct core_params pp = { .smsc = p_smsc, .sms_psi = p_psi, .imsi = p_imsi, .pani_refresh = p_pani };
	struct reg_ops ro;

	memset(&T, 0, sizeof(T));
	seq = 1;
	mt_n = 0;
	snprintf(T.lan_ip, sizeof(T.lan_ip), "%s", lan_ip);
	snprintf(T.sim_smsc, sizeof(T.sim_smsc), "+821080010585");
	snprintf(T.sim_imsi, sizeof(T.sim_imsi), "450061051226862");	/* LG U+: the operator table has the PSI */
	evfake_reset();
	config_defaults(&CFG);
	CFG.mms = !g_mms_off;
	snprintf(CFG.mms_apn, sizeof(CFG.mms_apn), "%s", g_mms_apn);
	snprintf(CFG.mms_dir, sizeof(CFG.mms_dir), "/tmp/imsd-mms-smsmod-test");
	C = core_new(&CFG, &ops);
	CHECK(C != NULL);
	core_set_params(C, &pp);
	if (with_module)
		CHECK_EQ(core_add_module(C, &smsrelay_module), 0);
	if (g_with_mms)
		CHECK_EQ(core_add_module(C, &mms_module), 0);
	memset(&ro, 0, sizeof(ro));
	ro.aka = t_aka;
	ro.aka_cancel = t_aka_cancel;
	ro.xfrm_install = t_install;
	ro.xfrm_remove = t_remove;
	ro.open_ep = t_open_gm;
	if (g_env)
		env_set();
	CHECK_EQ(core_start(C, &ro), 0);
	register_gm();
}

static void teardown(void)
{
	int i;

	core_stop(C);
	core_free(C);
	mms_mod_set_env(NULL);
	ev_timer_free(E_call.t);
	E_call.t = NULL;
	for (i = 0; i < T.n_lan; i++)
		fakeep_destroy(T.lan_eps[i]);
	for (i = 0; i < T.n_gm; i++)
		fakeep_destroy(T.gm_eps[i]);
	ev_timer_free(T.aka_t);
	C = NULL;
}

/* ---- tests ---- */
static void t_mt_delivered(void)
{
	struct fakeep *g, *l;
	struct smsrelay_status st;
	uint8_t b[64];
	int i, ni;

	setup("192.168.68.1", true);
	g = gm_ep();
	l = lan_ep();
	lan_register();
	CHECK(smsrelay_mod_status(&st));
	net_rx_hex("mt1@ims", CAP_GSM7);
	CHECK_EQ(resp_for(g, "mt1@ims"), 200);		/* the network's MESSAGE is answered at once */
	i = find_req(l, "MESSAGE", 0);
	CHECK(i >= 0);
	if (i >= 0) {
		CHECK_STR(ruri_at(l, i), "sip:1000@" CLIENT_IP ":5062");
		CHECK(strstr(hdr_at(l, i, "From"), "01051226862") != NULL);
		CHECK(strstr(hdr_at(l, i, "Content-Type"), "text/plain") != NULL);
		CHECK_STR(hdr_at(l, i, "X-SMS-SMSC"), "+821020921827");
		CHECK_EQ(body_of(l, i, b, sizeof(b)), 21);
		CHECK(!memcmp(b, "imsua ap-ims sms test", 21));
		ni = g->nsent;
		answer_sent(l, i, 200, NULL);		/* the client takes it: RP-ACK goes to the network */
		i = find_req(g, "MESSAGE", ni);
		CHECK(i >= 0);
		if (i >= 0) {
			CHECK_STR(ruri_at(g, i), "sip:ipsmgw.lte-lguplus.co.kr");
			CHECK_EQ(body_of(g, i, b, sizeof(b)), 2);
			CHECK(b[0] == 0x02 && b[1] == 0x68);
			answer_sent(g, i, 202, NULL);
		}
	}
	CHECK(smsrelay_mod_status(&st));
	CHECK_EQ(st.mt_received, 1);
	CHECK_EQ(st.mt_delivered, 1);
	CHECK_EQ(st.mt_lost_no_client, 0);
	evfake_advance(1000);
	teardown();
}

static void t_mt_no_client(void)
{
	struct fakeep *g;
	struct smsrelay_status st;
	uint8_t b[16];
	int i;

	setup("192.168.68.1", true);
	g = gm_ep();
	net_rx_hex("mt2@ims", CAP_GSM7);		/* nobody registered on the LAN */
	CHECK_EQ(resp_for(g, "mt2@ims"), 200);
	i = find_req(g, "MESSAGE", 0);
	CHECK(i >= 0);
	if (i >= 0) {
		CHECK_EQ(body_of(g, i, b, sizeof(b)), 2);
		CHECK(b[0] == 0x02 && b[1] == 0x68);	/* RP-ACK anyway (policy ack), logged as lost */
		answer_sent(g, i, 202, NULL);
	}
	CHECK(smsrelay_mod_status(&st));
	CHECK_EQ(st.mt_lost_no_client, 1);
	CHECK(st.last_error[0] != 0);
	/* policy rperror22 from the configuration, picked up without a reload call */
	snprintf(CFG.sms_lost_policy, sizeof(CFG.sms_lost_policy), "rperror22");
	net_rx_hex("mt3@ims", "01690791280102298172" "00" "26" "040b811050216268f2" "0000" "62110250731463" "15"
		   "e9f6bc1e0685e1ad747b0e9ab7e7207a794e07");
	i = find_req(g, "MESSAGE", i + 1);
	CHECK(i >= 0);
	if (i >= 0) {
		CHECK_EQ(body_of(g, i, b, sizeof(b)), 4);
		CHECK(b[0] == 0x04 && b[1] == 0x69 && b[3] == 22);
	}
	evfake_advance(70000);
	teardown();
}

/* no LAN address at start: the relay exists without lan, RP-ACKs and logs; the LAN comes up later and works */
static void t_lan_late_and_restart(void)
{
	struct fakeep *g, *l;
	struct smsrelay_status st;
	uint8_t b[16];
	int i, ni;

	setup("", true);
	CHECK(core_lan(C) == NULL);
	g = gm_ep();
	net_rx_hex("mt4@ims", CAP_GSM7);
	i = find_req(g, "MESSAGE", 0);
	CHECK(i >= 0);
	if (i >= 0) {
		CHECK_EQ(body_of(g, i, b, sizeof(b)), 2);
		CHECK(b[0] == 0x02);
		answer_sent(g, i, 202, NULL);
	}
	CHECK(smsrelay_mod_status(&st));
	CHECK_EQ(st.mt_lost_no_client, 1);
	/* the LAN appears */
	snprintf(T.lan_ip, sizeof(T.lan_ip), "192.168.68.1");
	evfake_advance(5000);
	CHECK(core_lan(C) != NULL);
	lan_register();
	l = lan_ep();
	net_rx_hex("mt5@ims", "016a0791280102298172" "00" "26" "040b811050216268f2" "0000" "62110250731463" "15"
		   "e9f6bc1e0685e1ad747b0e9ab7e7207a794e07");
	CHECK(find_req(l, "MESSAGE", 0) >= 0);
	/* the LAN restarts while the delivery is in flight (nobody answered): ends as lost, RP-ACK to the network */
	ni = g->nsent;
	CFG.keepalive = CFG.keepalive + 7;
	core_reload(C);
	i = find_req(g, "MESSAGE", ni);
	CHECK(i >= 0);
	if (i >= 0) {
		CHECK_EQ(body_of(g, i, b, sizeof(b)), 2);
		CHECK(b[0] == 0x02 && b[1] == 0x6a);
		answer_sent(g, i, 202, NULL);
	}
	CHECK(smsrelay_mod_status(&st));
	CHECK_EQ(st.mt_pending, 0);
	CHECK(core_lan(C) != NULL);
	/* and works again on the new LAN object */
	lan_register();
	l = lan_ep();
	net_rx_hex("mt6@ims", "016b0791280102298172" "00" "26" "040b811050216268f2" "0000" "62110250731463" "15"
		   "e9f6bc1e0685e1ad747b0e9ab7e7207a794e07");
	i = find_req(l, "MESSAGE", 0);
	CHECK(i >= 0);
	if (i >= 0)
		answer_sent(l, i, 200, NULL);
	evfake_advance(70000);
	teardown();
}

/* the client's MESSAGE: Request-URI is the destination number */
static void mo_send(const char *cid, const char *text)
{
	lan_req("MESSAGE", "sip:01012345678@192.168.68.1", cid, NULL, "text/plain;charset=utf-8", text);
}

static void t_mo_sim_smsc(void)
{
	struct fakeep *g;
	struct smsrelay_status st;
	uint8_t b[300];
	size_t n;
	int i, n_pani;

	setup("192.168.68.1", true);
	g = gm_ep();
	lan_register();
	n_pani = T.n_pani;
	mo_send("mo1@client", "hello");
	CHECK(T.n_pani > n_pani);			/* the serving cell data is refreshed before the send */
	i = find_req(g, "MESSAGE", 0);
	CHECK(i >= 0);
	if (i < 0)
		goto out;
	CHECK_STR(ruri_at(g, i), "sip:ipsmgw.lte-lguplus.co.kr");
	n = body_of(g, i, b, sizeof(b));
	CHECK(n > 11);
	CHECK(b[0] == 0x00 && b[2] == 0x00);		/* RP-DATA ms -> n, no RP-OA */
	CHECK(!memcmp(b + 3, "\x07\x91\x28\x01\x08\x10\x50\x58", 8));	/* RP-DA as the handset: +821080010585 */
	answer_sent(g, i, 202, NULL);
	CHECK_EQ(resp_for(lan_ep(), "mo1@client"), -1);	/* waits for the RP-ACK */
	{
		uint8_t ack[2] = { 0x03, b[1] };

		net_rx("ack1@ims", ack, 2);
	}
	CHECK_EQ(resp_for(g, "ack1@ims"), 200);
	CHECK_EQ(resp_for(lan_ep(), "mo1@client"), 200);
	CHECK(smsrelay_mod_status(&st));
	CHECK_EQ(st.mo_submitted, 1);
	CHECK_EQ(st.mo_acked, 1);
	CHECK_STR(st.smsc, "+821080010585");
	CHECK_STR(st.smsc_source, "sim");
	CHECK_STR(st.sms_psi, "sip:ipsmgw.lte-lguplus.co.kr");
	CHECK_STR(st.sms_psi_source, "carrier");
out:
	evfake_advance(70000);
	teardown();
}

static void t_mo_no_smsc(void)
{
	struct fakeep *g;
	struct smsrelay_status st;

	setup("192.168.68.1", true);
	g = gm_ep();
	lan_register();
	T.sim_smsc[0] = 0;
	mo_send("mo2@client", "hello");
	CHECK_EQ(resp_for(lan_ep(), "mo2@client"), 503);
	CHECK_EQ(find_req(g, "MESSAGE", 0), -1);
	CHECK(strstr(hdr_at(lan_ep(), lan_ep()->nsent - 1, "Warning"), "no SMSC: not on the SIM and not configured (imsd.main.smsc)") != NULL);
	CHECK(smsrelay_mod_status(&st));
	CHECK_STR(st.smsc_source, "none");
	/* the card delivers it later */
	snprintf(T.sim_smsc, sizeof(T.sim_smsc), "+821080010585");
	mo_send("mo3@client", "hello");
	CHECK(find_req(g, "MESSAGE", 0) >= 0);
	evfake_advance(70000);
	teardown();
}

static void t_mo_config_wins(void)
{
	struct fakeep *g;
	struct smsrelay_status st;
	uint8_t b[300];
	int i;

	setup("192.168.68.1", true);
	g = gm_ep();
	lan_register();
	/* the option changed after start (reload): the next message uses it */
	snprintf(CFG.smsc, sizeof(CFG.smsc), "+821099999999");
	smsrelay_mod_reload();
	mo_send("mo4@client", "hello");
	i = find_req(g, "MESSAGE", 0);
	CHECK(i >= 0);
	if (i >= 0) {
		CHECK(body_of(g, i, b, sizeof(b)) > 11);
		CHECK(!memcmp(b + 3, "\x07\x91\x28\x01\x99\x99\x99\x99", 8));
	}
	CHECK(smsrelay_mod_status(&st));
	CHECK_STR(st.smsc, "+821099999999");
	CHECK_STR(st.smsc_source, "config");
	evfake_advance(70000);
	teardown();
}

/* unknown operator, no PSI on the card, none configured: refused with 503 and a reason */
static void t_mo_no_psi(void)
{
	struct fakeep *g;
	struct smsrelay_status st;

	setup("192.168.68.1", true);
	g = gm_ep();
	lan_register();
	snprintf(T.sim_imsi, sizeof(T.sim_imsi), "310260000000001");
	mo_send("mo8@client", "hello");
	CHECK_EQ(resp_for(lan_ep(), "mo8@client"), 503);
	CHECK_EQ(find_req(g, "MESSAGE", 0), -1);
	CHECK(strstr(hdr_at(lan_ep(), lan_ep()->nsent - 1, "Warning"), "no SMS gateway") != NULL);
	CHECK(smsrelay_mod_status(&st));
	CHECK_STR(st.sms_psi, ""); CHECK_STR(st.sms_psi_source, "none");
	CHECK(strstr(st.last_error, "no SMS gateway") != NULL);
	teardown();
}

static void t_mo_psi(void)
{
	struct fakeep *g;
	int i;

	setup("192.168.68.1", true);
	g = gm_ep();
	lan_register();
	/* nothing configured, the card has none: the operator table (LG U+) */
	mo_send("mo4b@client", "hello");
	i = find_req(g, "MESSAGE", 0);
	CHECK(i >= 0);
	if (i >= 0) {
		CHECK_STR(ruri_at(g, i), "sip:ipsmgw.lte-lguplus.co.kr");
		answer_sent(g, i, 480, NULL);
	}
	evfake_advance(1000);
	snprintf(T.sim_psi, sizeof(T.sim_psi), "sip:card-gw.example.net");
	mo_send("mo6@client", "hello");
	i = find_req(g, "MESSAGE", i + 1);
	CHECK(i >= 0);
	if (i >= 0) {
		CHECK_STR(ruri_at(g, i), "sip:card-gw.example.net");	/* EF_PSISMSC beats the table */
		answer_sent(g, i, 480, NULL);
	}
	evfake_advance(1000);
	snprintf(CFG.sms_psi, sizeof(CFG.sms_psi), "sip:cfg-gw.example.net");
	smsrelay_mod_reload();
	mo_send("mo5@client", "hello");
	i = find_req(g, "MESSAGE", i + 1);
	CHECK(i >= 0);
	if (i >= 0)
		CHECK_STR(ruri_at(g, i), "sip:cfg-gw.example.net");	/* the explicit option beats the card */
	evfake_advance(70000);
	teardown();
}

/* reg_send cannot be cancelled: the answer to an MO segment arrives after the relay was freed */
static void t_late_response(void)
{
	struct fakeep *g;
	int i;

	setup("192.168.68.1", true);
	g = gm_ep();
	lan_register();
	mo_send("mo7@client", "hello");
	i = find_req(g, "MESSAGE", 0);
	CHECK(i >= 0);
	smsrelay_module.stop(C, NULL);			/* relay freed, registration and its request still alive */
	{
		struct smsrelay_status st;

		CHECK(!smsrelay_mod_status(&st));
	}
	CHECK_EQ(resp_for(lan_ep(), "mo7@client"), 503);	/* failed on stop */
	if (i >= 0)
		answer_sent(g, i, 202, NULL);		/* late response: dropped, no use of the freed relay */
	/* an MT RP-DATA now finds no module: the built-in handling still answers */
	net_rx_hex("late1@ims", CAP_GSM7);
	CHECK_EQ(resp_for(g, "late1@ims"), 200);
	evfake_advance(70000);
	teardown();
}

static void t_restart_cycles(void)
{
	int k;

	for (k = 0; k < 3; k++) {
		struct smsrelay_status st;

		setup("192.168.68.1", true);
		lan_register();
		CHECK(smsrelay_mod_status(&st));
		mo_send("moc@client", "cycle");
		net_rx_hex("cyc@ims", CAP_GSM7);	/* MT in flight, MO in flight: everything released at stop */
		teardown();
	}
	{
		struct smsrelay_status st;

		CHECK(!smsrelay_mod_status(&st));
	}
}

/* no module loaded: gm/reg.c keeps the built-in handling (RP-ACK, other types 415) */
static void t_builtin_fallback(void)
{
	struct fakeep *g;
	uint8_t b[16];
	int i;

	setup("192.168.68.1", false);
	g = gm_ep();
	net_rx_hex("fb1@ims", CAP_GSM7);
	CHECK_EQ(resp_for(g, "fb1@ims"), 200);
	i = find_req(g, "MESSAGE", 0);
	CHECK(i >= 0);
	if (i >= 0) {
		CHECK_EQ(body_of(g, i, b, sizeof(b)), 2);
		CHECK(b[0] == 0x02 && b[1] == 0x68);
	}
	evfake_advance(70000);
	teardown();
}

/* the MMS module behind the SMS relay: a WAP push of two real RP-DATA reaches the manager, every segment is acknowledged at once */
static void t_mms_wiring(void)
{
	struct fakeep *g;
	struct mms_status st;
	int i, nreply = 0;

	g_with_mms = true;
	setup("192.168.68.1", true);
	g = gm_ep();
	lan_register();
	CHECK(mms_mod_status(&st));
	CHECK_EQ(st.notifications, 0);
	net_rx_hex("mm1@ims", V_RPDU1);
	i = find_req(g, "MESSAGE", 0);
	CHECK(i >= 0);						/* RP-ACK for segment 1 already on its way */
	CHECK(mms_mod_status(&st)); CHECK_EQ(st.notifications, 0);
	net_rx_hex("mm2@ims", V_RPDU2);
	for (i = 0; (i = find_req(g, "MESSAGE", i)) >= 0; i++)
		nreply++;
	CHECK_EQ(nreply, 2);
	CHECK(mms_mod_status(&st));
	CHECK_EQ(st.notifications, 1); CHECK_EQ(st.pending, 1);	/* the IMS link is not up: the fetch waits */
	CHECK_EQ(resp_for(lan_ep(), "mm1@ims"), -1);
	{	/* the LAN client heard nothing (no binary notice): only its REGISTER answer was sent */
		int n = 0;

		for (i = 0; (i = find_req(lan_ep(), "MESSAGE", i)) >= 0; i++)
			n++;
		CHECK_EQ(n, 0);
	}
	/* the bench fetch needs a plain http URL */
	CHECK_EQ(mms_mod_fetch("https://x/", "", ""), -ENOTSUP);
	CHECK_EQ(mms_mod_fetch("http://192.0.2.1/x", "", ""), 0);
	CHECK(mms_mod_status(&st)); CHECK_EQ(st.pending, 2);
	evfake_advance(70000);
	teardown();					/* pending jobs and the push hook go away cleanly */
	CHECK(!mms_mod_status(&st));
	CHECK_EQ(mms_mod_fetch("http://x/", "", ""), -ESHUTDOWN);
	/* a second life of the daemon works the same */
	setup("192.168.68.1", true);
	net_rx_hex("mm3@ims", V_RPDU1);
	net_rx_hex("mm4@ims", V_RPDU2);
	CHECK(mms_mod_status(&st)); CHECK_EQ(st.notifications, 1);
	evfake_advance(70000);
	teardown();
	/* mms = 0: the push is acknowledged and dropped */
	g_mms_off = true;
	setup("192.168.68.1", true);
	net_rx_hex("mm5@ims", V_RPDU1);
	net_rx_hex("mm6@ims", V_RPDU2);
	CHECK(mms_mod_status(&st)); CHECK_EQ(st.notifications, 0); CHECK_EQ(st.pending, 0);
	evfake_advance(70000);
	teardown();
	g_mms_off = false;
	/* without the MMS module a push is acknowledged and dropped as well */
	g_with_mms = false;
	setup("192.168.68.1", true);
	net_rx_hex("mm7@ims", V_RPDU1);
	net_rx_hex("mm8@ims", V_RPDU2);
	CHECK(!mms_mod_status(&st));
	evfake_advance(70000);
	teardown();
}

static int rel_n;
static void rel_cb(void *arg) { (void)arg; rel_n++; }

/* which data connection the MMS client uses: the IMS PDN (LG U+), the on-demand bearer (an operator with an MMS APN, also for a SIM whose
 * identity is read through uqmid on the circuit switched backend), and what the backend may hand to the manager */
static void t_mms_provider(void)
{
	struct mmsb_status bs;

	g_with_mms = true;
	g_env = true;
	/* LG U+ on IMS: no MMS APN in its entry, the IMS PDN carries the MMS: the notifications are not for a bearer (CS keeps the notice) */
	snprintf(E_modem, sizeof(E_modem), "uqmid.modem.0");
	E_imsi[0] = E_plmn[0] = 0;
	setup("192.168.68.1", true);
	CHECK(!mms_mod_bearer_selected());
	CHECK(!mms_mod_push_ready());
	CHECK(!mms_mod_identity_pending());
	CHECK(mms_mod_bearer_status(&bs));
	CHECK_STR(bs.state, "idle");
	rel_n = 0;
	mms_mod_release(rel_cb, NULL, 1000);
	CHECK_EQ(rel_n, 1);				/* idle: at once */
	teardown();

	/* the SIM of Korea Cable Telecom: the operator table has an MMS APN, the core's IMSI is known */
	setup("192.168.68.1", true);
	snprintf(T.sim_imsi, sizeof(T.sim_imsi), "450119876543210");
	CHECK(mms_mod_bearer_selected());
	CHECK(mms_mod_push_ready());
	CHECK(!mms_mod_identity_pending());
	teardown();

	/* circuit switched backend: no IMS side, so no IMSI from the core; the bearer module reads the SIM through uqmid */
	setup("192.168.68.1", true);
	T.sim_imsi[0] = 0;
	snprintf(E_imsi, sizeof(E_imsi), "450119876543210");
	CHECK(!mms_mod_push_ready());
	CHECK(mms_mod_identity_pending());		/* a notification waits for it instead of being refused */
	mms_mod_poke();
	evfake_advance(100);
	CHECK(mms_mod_bearer_selected());
	CHECK(mms_mod_push_ready());
	CHECK(!mms_mod_identity_pending());
	teardown();

	/* an MVNO with no entry of its own: the registered network decides */
	setup("192.168.68.1", true);
	T.sim_imsi[0] = 0;
	snprintf(E_imsi, sizeof(E_imsi), "450129999999999");
	snprintf(E_plmn, sizeof(E_plmn), "45005");
	mms_mod_poke();
	evfake_advance(100);
	CHECK(mms_mod_bearer_selected());
	snprintf(E_plmn, sizeof(E_plmn), "45099");
	CHECK(!mms_mod_bearer_selected());
	CHECK(!mms_mod_push_ready());
	CHECK(!mms_mod_identity_pending());		/* the IMSI is known: the answer is final */
	teardown();

	/* uci mms_apn makes a bearer for an operator that is not in the table */
	snprintf(g_mms_apn, sizeof(g_mms_apn), "mms.example");
	setup("192.168.68.1", true);
	snprintf(T.sim_imsi, sizeof(T.sim_imsi), "310260123456789");
	CHECK(mms_mod_bearer_selected());
	CHECK(mms_mod_push_ready());
	teardown();
	g_mms_apn[0] = 0;

	/* MMS switched off: nothing is handed to the manager */
	g_mms_off = true;
	setup("192.168.68.1", true);
	snprintf(T.sim_imsi, sizeof(T.sim_imsi), "450119876543210");
	CHECK(!mms_mod_push_ready());
	teardown();
	g_mms_off = false;

	/* without the environment (the host tests of the other kind, the IMS-only build) the IMS PDN is the only provider */
	g_env = false;
	setup("192.168.68.1", true);
	snprintf(T.sim_imsi, sizeof(T.sim_imsi), "450119876543210");
	CHECK(!mms_mod_bearer_selected());
	CHECK(!mms_mod_bearer_status(&bs));
	teardown();
	g_with_mms = false;
}

void test_smsmod(void)
{
	t_mt_delivered();
	t_mt_no_client();
	t_lan_late_and_restart();
	t_mo_sim_smsc();
	t_mo_no_smsc();
	t_mo_config_wins();
	t_mo_psi();
	t_mo_no_psi();
	t_late_response();
	t_restart_cycles();
	t_builtin_fallback();
	t_mms_wiring();
	t_mms_provider();
}
