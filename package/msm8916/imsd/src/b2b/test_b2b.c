/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Scenario tests of the call module (b2b/): the real core, LAN registrar / lan, Gm registration (mock endpoints, xfrm
 * and AKA), gmcall, SDP negotiation and the REAL media bridge (loopback sockets). The "network" injects into / reads
 * from the protected Gm endpoint, fake LAN phones register on the LAN endpoint. Every scenario ends with the resource
 * balance (sockets, bridges, transactions, calls).
 */
#include <dirent.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include "../test/test.h"
#include "../test/fakeep.h"
#include "../test/evloop_fake.h"
#include "b2b.h"
#include "../smsrelay/smsrelay_mod.h"
#include "../media/amr.h"
#include "../media/codec.h"
#include "../media/rtp.h"
#include "../util/codec.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/rtpsock.h"
#include "../util/sys.h"

int t_checks, t_fails, t_skipped;

#define MAXEP 16
#define NET_PORT_C 5073
#define PC0 "2001:4430:5:405::43"
/* the AMR-WB downlink recording of a live line is not part of the tree: $IMSD_TEST_CAPDIR/l1/mt/rtp_rx.bin; the
 * scenarios that replay it are skipped without it */
static const char *cap_file(void)
{
	static char path[512];
	const char *d = getenv("IMSD_TEST_CAPDIR");

	if (!d || !*d || snprintf(path, sizeof(path), "%s/l1/mt/rtp_rx.bin", d) >= (int)sizeof(path))
		return NULL;
	return path;
}

static bool cap_have(const char *what)
{
	const char *p = cap_file();
	FILE *f = p ? fopen(p, "rb") : NULL;

	if (f) {
		fclose(f);
		return true;
	}
	t_skipped++;
	printf("  SKIP %s: needs the capture $IMSD_TEST_CAPDIR/l1/mt/rtp_rx.bin\n", what);
	return false;
}

static struct {
	struct fakeep *lan_eps[MAXEP];
	int n_lan;
	struct fakeep *gm_eps[MAXEP];
	struct sip_ep_cfg gm_cfg[MAXEP];
	int n_gm;
	char lan_ip[32];
	imsmodem_aka_cb aka_cb;
	void *aka_arg;
	struct ev_timer *aka_t;
	uint8_t rand[16];
	int n_notice;
	char last_notice[64];
	int n_pani;
	int base_txn;
} T;

static struct imsd_config CFG;
static const struct br_pcmdev_ops *g_pcm;	/* the fake modem sound card of the CS scenarios */
static struct core *C;
static int seq;
static int g_branch = -1, g_nbranch = -1;	/* force the Via branch (CANCEL) of phone / network requests */

static struct addr A(const char *ip, int port)
{
	struct addr a;

	addr_set(&a, ip, port);
	return a;
}

/* ---- core / reg mocks (as in test/test_smsmod.c) ---- */
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

static int t_install(void *ctx, const struct xfrm_sa_params *p) { (void)ctx; (void)p; return 0; }
static void t_remove(void *ctx, const struct xfrm_sa_params *p) { (void)ctx; (void)p; }
static bool g_sms;
static const char *p_smsc(void *ctx) { (void)ctx; return "+821080010585"; }
static const char *p_imsi(void *ctx) { (void)ctx; return "450061051226862"; }
static const char *p_domain(void *ctx) { (void)ctx; return "lte-lguplus.co.kr"; }
static void p_pani(void *ctx) { (void)ctx; T.n_pani++; }

/* real loopback RTP sockets for both legs */
static int t_rtp_lan(void *ctx, struct addr *bound)
{
	struct addr a = A("127.0.0.1", 0);

	(void)ctx;
	return rtpsock_open(&a, NULL, 30000, 30098, bound);
}

static int t_rtp_car(void *ctx, const struct addr *local, const char *netdev, struct addr *bound)
{
	struct addr a = A("127.0.0.1", 0);

	(void)ctx; (void)local; (void)netdev;
	return rtpsock_open(&a, NULL, 31000, 31098, bound);
}

static void t_notice(void *arg, const struct b2b_notice *n)
{
	(void)arg;
	T.n_notice++;
	snprintf(T.last_notice, sizeof(T.last_notice), "%u:%s", n->id, n->event);
}

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

/* ---- message helpers ---- */

/* text of a response to sent[idx] of f: Via / From / To (+tag) / Call-ID / CSeq copied, extra headers, optional SDP */
static char RESP[6000];
static const char *build_resp(struct fakeep *f, int idx, int status, const char *totag, const char *extra, const char *sdp)
{
	struct sip_msg m;
	const char *to;
	char to2[400];
	int o;

	RESP[0] = 0;
	if (fakeep_parse(f, idx, &m)) {
		CHECK(0);
		return RESP;
	}
	to = sip_hdr(&m, "To", 0);
	if (totag && !strstr(to, ";tag="))
		snprintf(to2, sizeof(to2), "%s;tag=%s", to, totag);
	else
		snprintf(to2, sizeof(to2), "%s", to);
	o = snprintf(RESP, sizeof(RESP), "SIP/2.0 %d X\r\nVia: %s\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %s\r\n%s",
		     status, sip_hdr(&m, "Via", 0), sip_hdr(&m, "From", 0), to2, sip_hdr(&m, "Call-ID", 0), sip_hdr(&m, "CSeq", 0),
		     extra ? extra : "");
	if (sdp)
		o += snprintf(RESP + o, sizeof(RESP) - o, "Content-Type: application/sdp\r\nContent-Length: %zu\r\n\r\n%s", strlen(sdp), sdp);
	else
		snprintf(RESP + o, sizeof(RESP) - o, "Content-Length: 0\r\n\r\n");
	sip_msg_free(&m);
	return RESP;
}

static void reply(struct fakeep *f, int idx, int status, const char *totag, const char *extra, const char *sdp, const struct addr *src)
{
	struct addr s = src ? *src : f->sent[idx].dst;

	fakeep_rx(f, &s, build_resp(f, idx, status, totag, extra, sdp));
}

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

/* first request with that method sent from `from` on to the given destination port (a LAN phone) */
static int find_req_to(const struct fakeep *f, const char *method, int from, int port)
{
	int i;

	for (i = from; i < f->nsent; i++) {
		struct sip_msg m;
		bool hit;

		if (fakeep_parse(f, i, &m))
			continue;
		hit = !m.is_resp && !strcmp(m.method, method) && addr_port(&f->sent[i].dst) == port;
		sip_msg_free(&m);
		if (hit)
			return i;
	}
	return -1;
}

/* index of the first response with this status for call_id from `from` on, -1 */
static int find_resp(const struct fakeep *f, const char *call_id, int status, int from)
{
	int i;

	for (i = from; i < f->nsent; i++) {
		struct sip_msg m;
		const char *c;
		bool hit = false;

		if (fakeep_parse(f, i, &m))
			continue;
		c = sip_hdr(&m, "Call-ID", 0);
		hit = m.is_resp && m.status == status && c && !strcmp(c, call_id);
		sip_msg_free(&m);
		if (hit)
			return i;
	}
	return -1;
}

static int last_status(const struct fakeep *f, const char *call_id)
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

static char HDR[600];
static const char *hdr_at(const struct fakeep *f, int i, const char *name)
{
	struct sip_msg m;
	const char *v;

	HDR[0] = 0;
	if (i >= 0 && !fakeep_parse(f, i, &m)) {
		v = sip_hdr(&m, name, 0);
		if (v)
			snprintf(HDR, sizeof(HDR), "%s", v);
		sip_msg_free(&m);
	}
	return HDR;
}

static char BODY[4000];
static const char *body_at(const struct fakeep *f, int i)
{
	struct sip_msg m;

	BODY[0] = 0;
	if (i >= 0 && !fakeep_parse(f, i, &m)) {
		size_t n = m.body_len < sizeof(BODY) - 1 ? m.body_len : sizeof(BODY) - 1;

		memcpy(BODY, m.body, n);
		BODY[n] = 0;
		sip_msg_free(&m);
	}
	return BODY;
}

static int sdp_port(const char *sdp)
{
	const char *p = strstr(sdp, "m=audio ");

	return p ? atoi(p + 8) : 0;
}

/* ---- registration of the line ---- */
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

		snprintf(ex, sizeof(ex), "Contact: %s;expires=6000\r\nExpires: 6000\r\nP-Associated-URI: <sip:01051226862@lte-lguplus.co.kr>\r\n",
			 sip_hdr(&m, "Contact", 0));
		snprintf(b, sizeof(b), "SIP/2.0 200 OK\r\nVia: %s\r\nFrom: %s\r\nTo: %s;tag=net200\r\nCall-ID: %s\r\nCSeq: %s\r\n%sContent-Length: 0\r\n\r\n",
			 sip_hdr(&m, "Via", 0), sip_hdr(&m, "From", 0), sip_hdr(&m, "To", 0), sip_hdr(&m, "Call-ID", 0), sip_hdr(&m, "CSeq", 0), ex);
		fakeep_rx(p, &src, b);
	}
	sip_msg_free(&m);
	CHECK(reg_is_registered(core_reg(C)));
}

/* ---- LAN phones ---- */
#define NPHONE 3
static int phone_port(int k) { return 5062 + k; }
static char PIP[NPHONE][24];
static const char *phone_ip(int k) { snprintf(PIP[k], sizeof(PIP[k]), "192.168.68.%d", 10 + k); return PIP[k]; }

/* a request from phone k; to_tag NULL: out of dialog */
static void phone_req(int k, const char *method, const char *ruri, const char *call_id, const char *from_tag,
		      const char *to_tag, unsigned cseq, const char *extra, const char *ctype, const char *body)
{
	char m[6000], to[300];
	struct addr src = A(phone_ip(k), phone_port(k));
	size_t bl = body ? strlen(body) : 0;

	if (to_tag)
		snprintf(to, sizeof(to), "<sip:114@192.168.68.1>;tag=%s", to_tag);
	else
		snprintf(to, sizeof(to), "<%s>", ruri);
	snprintf(m, sizeof(m), "%s %s SIP/2.0\r\nVia: SIP/2.0/UDP %s:%d;branch=z9hG4bKph%d;rport\r\nFrom: <sip:1000@192.168.68.1>;tag=%s\r\n"
		 "To: %s\r\nCall-ID: %s\r\nCSeq: %u %s\r\nMax-Forwards: 70\r\nContact: <sip:1000@%s:%d>\r\n%s",
		 method, ruri, phone_ip(k), phone_port(k), g_branch >= 0 ? g_branch : seq++, from_tag, to, call_id, cseq, method, phone_ip(k), phone_port(k),
		 extra ? extra : "");
	if (ctype)
		snprintf(m + strlen(m), sizeof(m) - strlen(m), "Content-Type: %s\r\n", ctype);
	snprintf(m + strlen(m), sizeof(m) - strlen(m), "Content-Length: %zu\r\n\r\n%s", bl, body ? body : "");
	fakeep_rx(lan_ep(), &src, m);
}

static void phone_register(int k)
{
	char cid[40];

	snprintf(cid, sizeof(cid), "reg%d@phone", k);
	phone_req(k, "REGISTER", "sip:192.168.68.1", cid, "r1", NULL, 1, "Expires: 3600\r\nUser-Agent: TestPhone/1.0\r\n", NULL, NULL);
	CHECK_EQ(last_status(lan_ep(), cid), 200);
}

static char SDPB[2000];
/* a phone's offer: codecs 0 = opus g722 pcma, 1 = pcma only */
static const char *phone_sdp(int k, int port, int which, const char *dir)
{
	snprintf(SDPB, sizeof(SDPB), "v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio %d RTP/AVP %s\r\n"
		 "%sa=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=ptime:20\r\na=%s\r\n",
		 phone_ip(k), port, which ? "8 101" : "111 9 8 101",
		 which ? "a=rtpmap:8 PCMA/8000\r\n" : "a=rtpmap:111 opus/48000/2\r\na=rtpmap:9 G722/8000\r\na=rtpmap:8 PCMA/8000\r\n", dir);
	return SDPB;
}

static char CSDP[1500];
/* what the network answers / offers: AMR-WB octet-aligned PT 100, telephone-event 107 */
static const char *car_sdp(int port, const char *dir)
{
	snprintf(CSDP, sizeof(CSDP), "v=0\r\no=vIBCF 1 1 IN IP4 127.0.0.1\r\ns=QC VOIP\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio %d RTP/AVP 100 107\r\n"
		 "b=AS:49\r\na=ptime:20\r\na=maxptime:240\r\na=rtpmap:100 AMR-WB/16000/1\r\na=fmtp:100 octet-align=1;mode-change-capability=2;max-red=0\r\n"
		 "a=rtpmap:107 telephone-event/16000\r\na=fmtp:107 0-15\r\na=%s\r\n", port, dir);
	return CSDP;
}

static const struct addr *pcscf(void)
{
	static struct addr a;

	a = A(PC0, NET_PORT_C);
	return &a;
}

/* request from the network (protected endpoint) */
static void net_req(const char *method, const char *call_id, const char *from, const char *to, unsigned cseq, const char *extra,
		    const char *sdp)
{
	char m[5000];
	static int n;

	snprintf(m, sizeof(m), "%s sip:01051226862@[2001:4430:141:990a:25b5:899e:232:cb69]:5071 SIP/2.0\r\n"
		 "Via: SIP/2.0/UDP [2001:4430:5:405::43]:5071;branch=z9hG4bKnet%d\r\nMax-Forwards: 60\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\n"
		 "CSeq: %u %s\r\nContact: <sip:[2001:4430:5:405::43]:5071>\r\n%s", method, g_nbranch >= 0 ? g_nbranch : n++, from, to, call_id, cseq, method,
		 extra ? extra : "");
	if (sdp)
		snprintf(m + strlen(m), sizeof(m) - strlen(m), "Content-Type: application/sdp\r\nContent-Length: %zu\r\n\r\n%s", strlen(sdp), sdp);
	else
		snprintf(m + strlen(m), sizeof(m) - strlen(m), "Content-Length: 0\r\n\r\n");
	fakeep_rx(gm_ep(), pcscf(), m);
}

static void net_invite(const char *call_id, const char *from_uri, const char *pai, const char *car_audio_sdp)
{
	char from[200], extra[300];

	snprintf(from, sizeof(from), "<%s>;tag=nettag", from_uri);
	snprintf(extra, sizeof(extra), "Supported: timer\r\nSession-Expires: 600;refresher=uac\r\nP-Asserted-Identity: %s\r\n", pai);
	net_req("INVITE", call_id, from, "<tel:01051226862;phone-context=lte-lguplus.co.kr>", 1, extra, car_audio_sdp);
}

/* ---- loop helpers ---- */
static void pump(int ms)
{
	int i;

	for (i = 0; i < ms / 10 + 1; i++) {
		usleep(10000);
		bridge_events_dispatch(core_bridge_event, C);
	}
}

static int fd_count(void)
{
	DIR *d = opendir("/proc/self/fd");
	int n = 0;

	if (!d)
		return -1;
	while (readdir(d))
		n++;
	closedir(d);
	return n;
}

static int FD0;

static void setup(bool phones)
{
	struct core_ops ops = { .open_ep = t_open_lan, .lan_addr = t_lan_addr };
	struct core_params pp = { .domain = p_domain, .pani_refresh = p_pani, .smsc = p_smsc, .imsi = p_imsi };
	struct b2b_ops bo = { .rtp_lan = t_rtp_lan, .rtp_carrier = t_rtp_car, .pcm_ops = g_pcm };
	struct reg_ops ro;
	int i;

	memset(&T, 0, sizeof(T));
	seq = 1;
	snprintf(T.lan_ip, sizeof(T.lan_ip), "192.168.68.1");
	evfake_reset();
	config_defaults(&CFG);
	CFG.ring_timeout_s = 60;
	CFG.rtp_timeout_s = 30;
	FD0 = fd_count();
	CHECK(bridge_engine_start() == 0);
	C = core_new(&CFG, &ops);
	CHECK(C != NULL);
	core_set_params(C, &pp);
	b2b_set_ops(&bo);
	b2b_set_notify(t_notice, NULL);
	b2b_select_backend(B2B_BE_GM);
	if (g_sms)
		CHECK_EQ(core_add_module(C, &smsrelay_module), 0);
	CHECK_EQ(core_add_module(C, &b2b_module), 0);
	memset(&ro, 0, sizeof(ro));
	ro.aka = t_aka;
	ro.aka_cancel = t_aka_cancel;
	ro.xfrm_install = t_install;
	ro.xfrm_remove = t_remove;
	ro.open_ep = t_open_gm;
	CHECK_EQ(core_start(C, &ro), 0);
	register_gm();
	if (phones)
		for (i = 0; i < NPHONE; i++)
			phone_register(i);
	T.base_txn = (int)txn_layer_count(core_txn(C));
}

/* end the scenario: everything must be released. check_clean = the call is over, expect nothing left */
static void finish(const char *name, bool check_clean)
{
	int i, tries;

	if (check_clean) {
		struct b2b_counters cn;

		evfake_advance(70000);	/* transaction timers (64*T1) and gmcall reaping */
		for (tries = 0; tries < 100 && bridge_count() > 0; tries++)
			pump(10);
		b2b_get_counters(&cn);
		if (cn.active || bridge_count() || (int)txn_layer_count(core_txn(C)) > T.base_txn + 1) {
			printf("  %s: leftovers: calls %u bridges %d txns %d (base %d)\n", name, cn.active, bridge_count(),
			       (int)txn_layer_count(core_txn(C)), T.base_txn);
			CHECK(0);
		}
		CHECK_EQ(cn.active, 0);
		CHECK_EQ(bridge_count(), 0);
	}
	core_stop(C);
	core_free(C);
	for (i = 0; i < T.n_lan; i++)
		fakeep_destroy(T.lan_eps[i]);
	for (i = 0; i < T.n_gm; i++)
		fakeep_destroy(T.gm_eps[i]);
	ev_timer_free(T.aka_t);
	C = NULL;
	bridge_engine_stop();
	i = fd_count();
	if (i != FD0) {
		printf("  %s: file descriptors %d -> %d\n", name, FD0, i);
		CHECK(0);
	}
}

/* ---- real RTP peers (the "carrier" and the "phone" of the end-to-end tests) ---- */
struct peer {
	int fd;
	int port;
};

static void peer_open(struct peer *p)
{
	struct sockaddr_in sa;
	socklen_t l = sizeof(sa);

	p->fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	CHECK(p->fd >= 0 && bind(p->fd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	getsockname(p->fd, (struct sockaddr *)&sa, &l);
	p->port = ntohs(sa.sin_port);
}

static void peer_close(struct peer *p)
{
	close(p->fd);
	p->fd = -1;
}

static void peer_send(const struct peer *p, int to_port, const void *d, size_t n)
{
	struct sockaddr_in sa;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons((uint16_t)to_port);
	sendto(p->fd, d, n, 0, (struct sockaddr *)&sa, sizeof(sa));
}

struct rxpkt {
	uint8_t pt;
	uint16_t seq;
	uint32_t ts;
	size_t plen;
	uint8_t first[4];
	int src_port;
};

/* everything queued on the peer's socket after waiting up to wait_ms for the first packet */
static int peer_drain(const struct peer *p, struct rxpkt *out, int max, int wait_ms)
{
	int n = 0;
	uint8_t buf[1500];

	for (;;) {
		struct pollfd pf = { .fd = p->fd, .events = POLLIN };
		struct sockaddr_in sa;
		socklen_t sl = sizeof(sa);
		ssize_t r;
		struct rtp_pkt rp;

		if (poll(&pf, 1, n ? 0 : wait_ms) <= 0)
			break;
		r = recvfrom(p->fd, buf, sizeof(buf), 0, (struct sockaddr *)&sa, &sl);
		if (r <= 0 || n >= max)
			break;
		if (rtp_parse(buf, (size_t)r, &rp))
			continue;
		out[n].pt = rp.h.pt;
		out[n].seq = rp.h.seq;
		out[n].ts = rp.h.ts;
		out[n].plen = rp.plen;
		memset(out[n].first, 0, 4);
		memcpy(out[n].first, rp.payload, rp.plen < 4 ? rp.plen : 4);
		out[n].src_port = ntohs(sa.sin_port);
		n++;
	}
	return n;
}

/* AMR-WB octet-aligned packet: CMR byte, TOC byte (F=0, FT, Q) */
static bool is_nodata(const struct rxpkt *r)
{
	return r->plen >= 2 && ((r->first[1] >> 3) & 0xf) == 15;
}

static int count_speech(const struct rxpkt *r, int n)
{
	int i, c = 0;

	for (i = 0; i < n; i++)
		if (r[i].plen >= 3 && ((r[i].first[1] >> 3) & 0xf) <= 8)
			c++;
	return c;
}

/* the captured AMR-WB downlink replayed by the "carrier": n packets starting at record `from`, 20 ms apart */
static int replay_capture(const struct peer *car, int to_port, int from, int n, uint16_t *seq0, uint32_t *ts0)
{
	FILE *f = cap_file() ? fopen(cap_file(), "rb") : NULL;
	uint8_t hdr[13], pl[400], pk[600];
	int rec = 0, sent = 0;

	if (!f)
		return -1;
	while (sent < n && fread(hdr, 1, 13, f) == 13) {
		unsigned len = (unsigned)(hdr[11] | hdr[12] << 8);
		int l;

		if (len > sizeof(pl) || fread(pl, 1, len, f) != len)
			break;
		if (rec++ < from)
			continue;
		l = rtp_build(pk, sizeof(pk), false, 100, (*seq0)++, *ts0, 0xCAFE0001u, pl, len);
		*ts0 += 320;
		if (l > 0)
			peer_send(car, to_port, pk, (size_t)l);
		sent++;
		usleep(20000);
		bridge_events_dispatch(core_bridge_event, C);
	}
	fclose(f);
	return sent;
}

/* PCMA tone from the "phone" toward the bridge */
static void send_pcma(const struct peer *ph, int to_port, int n, uint16_t *seq0, uint32_t *ts0)
{
	struct codec *c = codec_create(CODEC_PCMA, NULL);
	int16_t pcm[160];
	uint8_t pl[400], pk[600];
	int i, k;

	for (i = 0; i < n; i++) {
		int l;

		for (k = 0; k < 160; k++)
			pcm[k] = (int16_t)(8000 * ((((i * 160 + k) / 4) & 1) ? 1 : -1));	/* square wave, 1 kHz */
		l = codec_encode(c, pcm, pl, sizeof(pl));
		l = rtp_build(pk, sizeof(pk), i == 0, 8, (*seq0)++, *ts0, 0xBEEF0002u, pl, (size_t)l);
		*ts0 += 160;
		peer_send(ph, to_port, pk, (size_t)l);
		usleep(20000);
		bridge_events_dispatch(core_bridge_event, C);
	}
	codec_destroy(c);
}

/* ---- scenario building blocks ---- */

/* a LAN phone calls 114; returns the index of the carrier INVITE in gm_ep sent[] */
static int mo_start(int k, const char *cid, int phone_media_port, int pcma_only)
{
	int gi;

	phone_req(k, "INVITE", "sip:114@192.168.68.1", cid, "ft1", NULL, 1, "Allow: INVITE, ACK, CANCEL, BYE, UPDATE, INFO\r\n",
		  "application/sdp", phone_sdp(k, phone_media_port, pcma_only, "sendrecv"));
	CHECK_EQ(last_status(lan_ep(), cid), 100);
	gi = find_req(gm_ep(), "INVITE", 0);
	CHECK(gi >= 0);
	return gi;
}

/* To tag / contact URI of our response idx to the phone, to build ACK / BYE / re-INVITE */
static char TT[200], CT[200];
static void dialog_of(const struct fakeep *l, int idx)
{
	char c[200] = "";
	const char *v;

	sip_tag(hdr_at(l, idx, "To"), TT, sizeof(TT));
	v = hdr_at(l, idx, "Contact");
	if (v[0])
		sip_uri_of(v, c, sizeof(c));
	snprintf(CT, sizeof(CT), "%s", c);
}

static void mo_answer(int gi, const char *tag, int car_port)
{
	reply(gm_ep(), gi, 200, tag, "Contact: <sip:[2001:4430:5:405::43]:5071>\r\n", car_sdp(car_port, "sendrecv"), pcscf());
}

static bool call_state(const char *dir, const char *state)
{
	struct b2b_info rows[8];
	int n = b2b_list(rows, 8), i;

	for (i = 0; i < n && i < 8; i++)
		if (!strcmp(rows[i].dir, dir) && !strcmp(rows[i].state, state))
			return true;
	return false;
}

/* ---- scenarios ---- */
static void t_mo_early_answer_e2e(void)
{
	struct fakeep *l, *g;
	struct peer car, ph;
	struct rxpkt rx[400];
	int gi, i183, i200, n, nsp, sent_before, got_before, ia;
	int car_port, our_cport, our_lport;
	uint16_t cseq16 = 100, pseq = 500;
	uint32_t cts = 1000, pts = 8000;
	char b183[2000];

	printf("  mo early media, answer, audio both ways\n");
	setup(true);
	l = lan_ep();
	g = gm_ep();
	peer_open(&car);
	peer_open(&ph);
	car_port = car.port;
	gi = mo_start(0, "mo1@phone", ph.port, 1);
	if (gi < 0)
		goto out;
	our_cport = sdp_port(body_at(g, gi));
	CHECK(our_cport >= 31000);
	CHECK(strstr(hdr_at(g, gi, "To"), "tel:114;phone-context=lte-lguplus.co.kr") != NULL);	/* ISIM domain */
	CHECK(strstr(hdr_at(g, gi, "User-Agent"), "TTA-VoLTE/3.0 imsd/") != NULL);
	CHECK(T.n_pani >= 1);
	reply(g, gi, 180, "tagA", "Contact: <sip:[2001:4430:5:405::43]:5071>\r\n", NULL, pcscf());
	CHECK(find_resp(l, "mo1@phone", 180, 0) >= 0);
	reply(g, gi, 183, "tagA", "Contact: <sip:[2001:4430:5:405::43]:5071>\r\n", car_sdp(car_port, "sendrecv"), pcscf());
	i183 = find_resp(l, "mo1@phone", 183, 0);
	CHECK(i183 >= 0);
	snprintf(b183, sizeof(b183), "%s", body_at(l, i183));
	our_lport = sdp_port(b183);
	CHECK(our_lport >= 30000 && our_lport <= 30098);
	CHECK(strstr(b183, "PCMA/8000") != NULL);
	CHECK(bridge_count() == 1);
	/* the carrier leg sends first: AMR-WB NO_DATA toward the network although the phone has sent nothing */
	pump(100);
	n = peer_drain(&car, rx, 400, 300);
	CHECK(n >= 3);
	if (n >= 3) {
		CHECK_EQ(rx[0].pt, 100);
		CHECK(is_nodata(&rx[0]));
		CHECK_EQ(rx[0].src_port, our_cport);
	}
	mo_answer(gi, "tagA", car_port);
	i200 = find_resp(l, "mo1@phone", 200, 0);
	CHECK(i200 >= 0);
	CHECK_STR(body_at(l, i200), b183);		/* the 200 carries the SAME answer as the 183 */
	dialog_of(l, i200);
	CHECK(call_state("out", "answering"));
	phone_req(0, "ACK", CT, "mo1@phone", "ft1", TT, 1, NULL, NULL, NULL);
	CHECK(call_state("out", "up"));
	/* audio from the network reaches the phone as PCMA */
	if (cap_have("network audio replay (mo_early_answer_e2e)")) {
		nsp = replay_capture(&car, our_cport, 0, 60, &cseq16, &cts);
		CHECK(nsp == 60);
		n = peer_drain(&ph, rx, 400, 300);
		CHECK(n >= 40);
		if (n)
			CHECK_EQ(rx[0].pt, 8);
	}
	/* and the phone's audio reaches the network as AMR-WB speech frames */
	got_before = peer_drain(&car, rx, 400, 0);
	(void)got_before;
	sent_before = 40;
	send_pcma(&ph, our_lport, sent_before, &pseq, &pts);
	n = peer_drain(&car, rx, 400, 300);
	nsp = count_speech(rx, n);
	CHECK(nsp >= 20);
	printf("    %d packets to the network, %d speech frames\n", n, nsp);
	/* the phone hangs up */
	phone_req(0, "BYE", CT, "mo1@phone", "ft1", TT, 2, NULL, NULL, NULL);
	CHECK_EQ(last_status(l, "mo1@phone"), 200);
	ia = find_req(g, "BYE", 0);
	CHECK(ia >= 0);
	if (ia >= 0)
		reply(g, ia, 200, NULL, NULL, NULL, pcscf());
out:
	peer_close(&car);
	peer_close(&ph);
	finish("mo_e2e", true);
}

static void t_mo_603_after_early(void)
{
	struct fakeep *l, *g;
	int gi, i183, i603;

	printf("  mo rejected with 603 after announcement\n");
	setup(true);
	l = lan_ep();
	g = gm_ep();
	gi = mo_start(0, "mo2@phone", 40000, 0);
	reply(g, gi, 183, "tagA", "Contact: <sip:[2001:4430:5:405::43]:5071>\r\n", car_sdp(41000, "sendrecv"), pcscf());
	i183 = find_resp(l, "mo2@phone", 183, 0);
	CHECK(i183 >= 0);
	CHECK(strstr(body_at(l, i183), "opus/48000") != NULL);	/* the client's first choice */
	reply(g, gi, 603, "tagA", "Warning: 399 lte-lguplus.co.kr \"Decline\"\r\n", NULL, pcscf());
	i603 = find_resp(l, "mo2@phone", 603, 0);
	CHECK(i603 > i183);			/* the final failure comes after the early media */
	CHECK(strstr(hdr_at(l, i603, "Reason"), "cause=603") != NULL);
	CHECK(strstr(hdr_at(l, i603, "Warning"), "399") != NULL);
	phone_req(0, "ACK", "sip:114@192.168.68.1", "mo2@phone", "ft1", NULL, 1, NULL, NULL, NULL);
	finish("mo_603", true);
}

static void t_mo_statuses(void)
{
	static const int in[] = { 486, 480, 404, 503, 408, 401, 302, 500 };
	static const int out[] = { 486, 480, 404, 503, 480, 480, 480, 500 };
	size_t i;

	printf("  carrier failures passed to the client\n");
	for (i = 0; i < sizeof(in) / sizeof(in[0]); i++) {
		char cid[32];
		int gi;

		setup(true);
		snprintf(cid, sizeof(cid), "mo3-%zu@phone", i);
		gi = mo_start(0, cid, 40000, 1);
		reply(gm_ep(), gi, in[i], "tagX", NULL, NULL, pcscf());
		if (in[i] == 302 || in[i] == 401)
			evfake_advance(100);
		CHECK_EQ(last_status(lan_ep(), cid), out[i]);
		finish("mo_status", true);
	}
}

static void t_mo_cancel(void)
{
	struct fakeep *l, *g;
	int gi, ic;

	printf("  client CANCEL while ringing\n");
	setup(true);
	l = lan_ep();
	g = gm_ep();
	gi = mo_start(0, "mo4@phone", 40000, 1);
	reply(g, gi, 180, "tagA", NULL, NULL, pcscf());
	CHECK(find_resp(l, "mo4@phone", 180, 0) >= 0);
	g_branch = seq - 1;
	phone_req(0, "CANCEL", "sip:114@192.168.68.1", "mo4@phone", "ft1", NULL, 1, NULL, NULL, NULL);
	g_branch = -1;
	CHECK(find_resp(l, "mo4@phone", 487, 0) >= 0);
	ic = find_req(g, "CANCEL", 0);
	CHECK(ic >= 0);
	if (ic >= 0) {
		reply(g, ic, 200, NULL, NULL, NULL, pcscf());
		reply(g, gi, 487, "tagA", NULL, NULL, pcscf());
	}
	finish("mo_cancel", true);
}

static void t_mo_dialog_change(void)
{
	struct fakeep *l, *g;
	struct peer car1, car2, ph;
	struct rxpkt rx[300];
	int gi, i183, i200, n1, n2, br1;
	char b183[2000];

	printf("  mo: the 2xx comes on another dialog with another media port\n");
	setup(true);
	l = lan_ep();
	g = gm_ep();
	peer_open(&car1);
	peer_open(&car2);
	peer_open(&ph);
	gi = mo_start(0, "mo5@phone", ph.port, 1);
	reply(g, gi, 183, "tagA", "Contact: <sip:[2001:4430:5:405::43]:5071>\r\n", car_sdp(car1.port, "sendrecv"), pcscf());
	i183 = find_resp(l, "mo5@phone", 183, 0);
	snprintf(b183, sizeof(b183), "%s", body_at(l, i183));
	pump(120);
	n1 = peer_drain(&car1, rx, 300, 200);
	CHECK(n1 >= 3);
	br1 = bridge_count();
	reply(g, gi, 200, "tagB", "Contact: <sip:[2001:4430:5:405::43]:5071>\r\n", car_sdp(car2.port, "sendrecv"), pcscf());
	i200 = find_resp(l, "mo5@phone", 200, 0);
	CHECK(i200 >= 0);
	CHECK_STR(body_at(l, i200), b183);		/* the client leg is untouched */
	CHECK_EQ(bridge_count(), br1);
	pump(100);
	n2 = peer_drain(&car2, rx, 300, 300);
	CHECK(n2 >= 3);				/* the carrier leg follows the new port */
	n1 = peer_drain(&car1, rx, 300, 0);
	pump(100);
	n1 = peer_drain(&car1, rx, 300, 100);
	CHECK(n1 <= 1);
	dialog_of(l, i200);
	phone_req(0, "ACK", CT, "mo5@phone", "ft1", TT, 1, NULL, NULL, NULL);
	b2b_call_hangup(1);
	CHECK(find_req(g, "BYE", 0) >= 0);
	peer_close(&car1);
	peer_close(&car2);
	peer_close(&ph);
	finish("mo_dialog_change", true);
}

static void t_mo_refusals(void)
{
	printf("  mo: refusals before the carrier is involved\n");
	setup(true);
	{
		struct addr src = A(phone_ip(0), phone_port(0));
		int n = lan_ep()->nsent;

		fakeep_rx_n(lan_ep(), &src, "\r\n\r\n", 4);		/* RFC 5626 keep-alive: answered with one CRLF */
		CHECK_EQ(lan_ep()->nsent, n + 1);
		CHECK_EQ(lan_ep()->sent[n].len, 2);
		fakeep_rx_n(lan_ep(), &src, "\r\n", 2);		/* a pong: ignored */
		CHECK_EQ(lan_ep()->nsent, n + 1);
	}
	phone_req(0, "INVITE", "sip:114@192.168.68.1", "bad1@phone", "t1", NULL, 1, NULL, NULL, NULL);
	CHECK_EQ(last_status(lan_ep(), "bad1@phone"), 488);			/* no SDP offer */
	phone_req(0, "INVITE", "sip:114@192.168.68.1", "bad2@phone", "t1", NULL, 1, "Require: 100rel\r\n", "application/sdp",
		  phone_sdp(0, 40000, 0, "sendrecv"));
	CHECK_EQ(last_status(lan_ep(), "bad2@phone"), 420);
	phone_req(0, "INVITE", "sip:114@192.168.68.1", "bad3@phone", "t1", NULL, 1, NULL, "application/sdp",
		  "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n");
	CHECK_EQ(last_status(lan_ep(), "bad3@phone"), 488);			/* nothing we speak */
	phone_req(0, "INVITE", "sip:@192.168.68.1", "bad4@phone", "t1", NULL, 1, NULL, "application/sdp", phone_sdp(0, 40000, 0, "sendrecv"));
	CHECK_EQ(last_status(lan_ep(), "bad4@phone"), 404);
	CHECK_EQ(find_req(gm_ep(), "INVITE", 0), -1);
	finish("mo_refusals", true);
	/* the line is not registered */
	setup(true);
	reg_set_enabled(core_reg(C), false);
	evfake_advance(3000);
	phone_req(0, "INVITE", "sip:114@192.168.68.1", "bad5@phone", "t1", NULL, 1, NULL, "application/sdp", phone_sdp(0, 40000, 0, "sendrecv"));
	CHECK_EQ(last_status(lan_ep(), "bad5@phone"), 503);
	finish("mo_unreg", true);
}

/* ---- incoming ---- */
static int mt_start(const char *cid, const char *from_uri, const char *pai, int car_port)
{
	net_invite(cid, from_uri, pai, car_sdp(car_port, "sendrecv"));
	return 0;
}

static void answer_phone(int k, int fork_idx, const char *tag, int port, const char *sdp_dir)
{
	struct fakeep *l = lan_ep();
	char ex[200];

	snprintf(ex, sizeof(ex), "Contact: <sip:1000@%s:%d>\r\n", phone_ip(k), phone_port(k));
	reply(l, fork_idx, 200, tag, ex, phone_sdp(k, port, 1, sdp_dir), NULL);
}

static void t_mt_three_devices(void)
{
	struct fakeep *l, *g;
	int ip[NPHONE], k, i180, i200, ic, ia, ib;
	struct peer car, ph;
	char fcid[160], ex[200];

	printf("  mt: three devices ring, one answers\n");
	setup(true);
	l = lan_ep();
	g = gm_ep();
	peer_open(&car);
	peer_open(&ph);
	mt_start("mt1@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", car.port);
	i180 = find_resp(g, "mt1@ims", 180, 0);
	CHECK(i180 >= 0);					/* the network hears ringing */
	for (k = 0; k < NPHONE; k++) {
		ip[k] = find_req_to(l, "INVITE", 0, phone_port(k));
		CHECK(ip[k] >= 0);
	}
	if (ip[0] < 0 || ip[1] < 0 || ip[2] < 0)
		goto out;
	CHECK(strstr(hdr_at(l, ip[0], "From"), "01099998888@192.168.68.1") != NULL);
	snprintf(fcid, sizeof(fcid), "%s", hdr_at(l, ip[0], "Call-ID"));
	CHECK(strstr(body_at(l, ip[0]), "opus/48000") != NULL);
	CHECK(strstr(body_at(l, ip[0]), "AMR") == NULL);
	CHECK(sdp_port(body_at(l, ip[0])) >= 30000);
	reply(l, ip[0], 180, "pt0", NULL, NULL, NULL);
	reply(l, ip[1], 180, "pt1", NULL, NULL, NULL);
	reply(l, ip[2], 180, "pt2", NULL, NULL, NULL);
	CHECK_EQ(bridge_count(), 0);				/* nothing yet: nobody answered */
	answer_phone(1, ip[1], "pt1", ph.port, "sendrecv");
	i200 = find_resp(g, "mt1@ims", 200, 0);
	CHECK(i200 >= 0);					/* the carrier is answered */
	CHECK(strstr(hdr_at(g, i200, "User-Agent"), "TTA-VoLTE/3.0 imsd/") != NULL);
	evfake_advance(1200);
	CHECK(find_resp(g, "mt1@ims", 200, i200 + 1) >= 0);	/* no ACK yet: the 200 is retransmitted */
	CHECK(strstr(body_at(g, i200), "AMR-WB") != NULL);
	CHECK_EQ(bridge_count(), 1);
	ia = find_req_to(l, "ACK", 0, phone_port(1));
	CHECK(ia >= 0);						/* the winner is ACKed by us */
	ic = find_req_to(l, "CANCEL", 0, phone_port(0));
	CHECK(ic >= 0);
	CHECK(find_req_to(l, "CANCEL", 0, phone_port(2)) >= 0);
	CHECK(find_req_to(l, "CANCEL", 0, phone_port(1)) < 0);
	CHECK(strstr(hdr_at(l, ic, "Reason"), "Call completed elsewhere") != NULL);
	reply(l, ip[0], 487, "pt0", NULL, NULL, NULL);
	reply(l, ip[2], 487, "pt2", NULL, NULL, NULL);
	/* the network's ACK, then the call is up */
	{
		char to[200], from[200];

		snprintf(to, sizeof(to), "%s", hdr_at(g, i200, "To"));
		snprintf(from, sizeof(from), "%s", hdr_at(g, i200, "From"));
		snprintf(ex, sizeof(ex), "%s", "");
		net_req("ACK", "mt1@ims", from, to, 1, ex, NULL);
	}
	{
		int before = g->nsent;

		evfake_advance(3000);
		CHECK_EQ(find_resp(g, "mt1@ims", 200, before), -1);	/* the ACK reached gmcall through the Gm handler chain */
	}
	CHECK(call_state("in", "up"));
	/* the phone hangs up: BYE to the network */
	phone_req(1, "BYE", "sip:imsd@192.168.68.1:5060", fcid, "x", "x", 2, NULL, NULL, NULL);
	ib = find_req(g, "BYE", 0);
	(void)ib;
	{
		/* the dialog: our From tag (generated) / the phone's To tag pt1 */
		char ftag[80] = "";

		sip_tag(hdr_at(l, ip[1], "From"), ftag, sizeof(ftag));
		phone_req(1, "BYE", "sip:imsd@192.168.68.1:5060", fcid, "pt1", ftag, 2, NULL, NULL, NULL);
	}
	CHECK(find_req(g, "BYE", 0) >= 0);
	ib = find_req(g, "BYE", 0);
	if (ib >= 0)
		reply(g, ib, 200, NULL, NULL, NULL, pcscf());
out:
	peer_close(&car);
	peer_close(&ph);
	finish("mt_three", true);
}

static void t_mt_no_device(void)
{
	printf("  mt: no device registered -> 480\n");
	setup(false);
	mt_start("mt2@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", 41000);
	CHECK_EQ(last_status(gm_ep(), "mt2@ims"), 480);
	finish("mt_nodev", true);
}

static void t_mt_all_busy(void)
{
	struct fakeep *l = NULL;
	int k, i;

	printf("  mt: every device busy -> 486; one busy, one declines -> 480\n");
	setup(true);
	l = lan_ep();
	mt_start("mt3@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", 41000);
	for (k = 0; k < NPHONE; k++) {
		i = find_req_to(l, "INVITE", 0, phone_port(k));
		CHECK(i >= 0);
		if (i >= 0)
			reply(l, i, 486, "pb", NULL, NULL, NULL);
	}
	CHECK_EQ(last_status(gm_ep(), "mt3@ims"), 486);
	finish("mt_busy", true);
	setup(true);
	l = lan_ep();
	mt_start("mt3b@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", 41000);
	for (k = 0; k < NPHONE; k++) {
		i = find_req_to(l, "INVITE", 0, phone_port(k));
		if (i >= 0)
			reply(l, i, k == 0 ? 486 : 603, "pb", NULL, NULL, NULL);
	}
	CHECK_EQ(last_status(gm_ep(), "mt3b@ims"), 480);
	finish("mt_declined", true);
}

static void t_mt_caller_cancels(void)
{
	struct fakeep *l, *g;
	int k, i;

	printf("  mt: the caller hangs up while the phones ring\n");
	setup(true);
	l = lan_ep();
	g = gm_ep();
	g_nbranch = 7777;
	mt_start("mt4@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", 41000);
	for (k = 0; k < NPHONE; k++)
		reply(l, find_req_to(l, "INVITE", 0, phone_port(k)), 180, "pc", NULL, NULL, NULL);
	net_req("CANCEL", "mt4@ims", "<sip:01099998888@lte-lguplus.co.kr>;tag=nettag", "<tel:01051226862;phone-context=lte-lguplus.co.kr>", 1,
		NULL, NULL);
	g_nbranch = -1;
	CHECK(find_resp(g, "mt4@ims", 487, 0) >= 0);
	for (k = 0; k < NPHONE; k++) {
		i = find_req_to(l, "CANCEL", 0, phone_port(k));
		CHECK(i >= 0);
	}
	for (k = 0; k < NPHONE; k++)
		reply(l, find_req_to(l, "INVITE", 0, phone_port(k)), 487, "pc", NULL, NULL, NULL);
	finish("mt_cancel", true);
}

static void t_mt_two_answer(void)
{
	struct fakeep *l;
	int i0, i1, ia, ib;
	struct peer car, ph;

	printf("  mt: two devices answer at once\n");
	setup(true);
	l = lan_ep();
	peer_open(&car);
	peer_open(&ph);
	mt_start("mt5@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", car.port);
	i0 = find_req_to(l, "INVITE", 0, phone_port(0));
	i1 = find_req_to(l, "INVITE", 0, phone_port(1));
	answer_phone(0, i0, "pw0", ph.port, "sendrecv");
	answer_phone(1, i1, "pw1", ph.port, "sendrecv");
	CHECK(find_req_to(l, "ACK", 0, phone_port(0)) >= 0);
	ia = find_req_to(l, "ACK", 0, phone_port(1));
	ib = find_req_to(l, "BYE", 0, phone_port(1));
	CHECK(ia >= 0 && ib >= 0);			/* the extra answer is ACKed and ended */
	CHECK(find_req_to(l, "BYE", 0, phone_port(0)) < 0);
	CHECK_EQ(bridge_count(), 1);
	b2b_end_all("test");
	peer_close(&car);
	peer_close(&ph);
	finish("mt_two", true);
}

static void t_mt_anonymous(void)
{
	struct fakeep *l;
	int i;

	printf("  mt: caller identity (anonymous, display name)\n");
	setup(true);
	l = lan_ep();
	mt_start("mt6@ims", "sip:anonymous@anonymous.invalid", "<sip:anonymous@anonymous.invalid>", 41000);
	i = find_req_to(l, "INVITE", 0, phone_port(0));
	CHECK(i >= 0);
	CHECK(strstr(hdr_at(l, i, "From"), "Anonymous") != NULL);
	CHECK(strstr(hdr_at(l, i, "From"), "anonymous@anonymous.invalid") != NULL);
	b2b_end_all("test");
	finish("mt_anon", false);
	setup(true);
	l = lan_ep();
	mt_start("mt7@ims", "sip:+821012345678@lte-lguplus.co.kr", "\"Kim\" <sip:+821012345678@lte-lguplus.co.kr>", 41000);
	i = find_req_to(l, "INVITE", 0, phone_port(0));
	CHECK(i >= 0);
	CHECK(strstr(hdr_at(l, i, "From"), "+821012345678@192.168.68.1") != NULL);
	b2b_end_all("test");
	finish("mt_num", false);
}

static void t_mt_ring_timeout(void)
{
	printf("  mt: ring timeout\n");
	setup(true);
	CFG.ring_timeout_s = 20;
	mt_start("mt8@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", 41000);
	{
		int k;

		for (k = 0; k < NPHONE; k++)
			reply(lan_ep(), find_req_to(lan_ep(), "INVITE", 0, phone_port(k)), 180, "pq", NULL, NULL, NULL);
	}
	evfake_advance(19000);
	CHECK_EQ(last_status(gm_ep(), "mt8@ims"), 180);
	evfake_advance(2000);
	CHECK_EQ(last_status(gm_ep(), "mt8@ims"), 480);
	CHECK(find_req_to(lan_ep(), "CANCEL", 0, phone_port(0)) >= 0);
	{
		int k;

		for (k = 0; k < NPHONE; k++)
			reply(lan_ep(), find_req_to(lan_ep(), "INVITE", 0, phone_port(k)), 487, "pq", NULL, NULL, NULL);
	}
	finish("mt_ring", true);
}


/* ---- established calls ---- */
struct est {
	int gi, cport, lport, ph_port;
	char cid[40];
	unsigned cseq;
	char ttag[200], contact[200], car_from[300], car_to[300], car_cid[160];
};

/* a LAN phone calls 114, the network answers at once (no early media), the phone ACKs */
static void mo_est(struct est *e, const char *cid, int car_port, int ph_port, int pcma_only)
{
	struct fakeep *l = lan_ep(), *g = gm_ep();
	int i200;

	memset(e, 0, sizeof(*e));
	snprintf(e->cid, sizeof(e->cid), "%s", cid);
	e->ph_port = ph_port;
	e->gi = mo_start(0, cid, ph_port, pcma_only);
	e->cport = sdp_port(body_at(g, e->gi));
	snprintf(e->car_from, sizeof(e->car_from), "%s", hdr_at(g, e->gi, "From"));
	snprintf(e->car_to, sizeof(e->car_to), "%s;tag=tagA", hdr_at(g, e->gi, "To"));
	snprintf(e->car_cid, sizeof(e->car_cid), "%s", hdr_at(g, e->gi, "Call-ID"));
	mo_answer(e->gi, "tagA", car_port);
	i200 = find_resp(l, cid, 200, 0);
	CHECK(i200 >= 0);
	dialog_of(l, i200);
	snprintf(e->ttag, sizeof(e->ttag), "%s", TT);
	snprintf(e->contact, sizeof(e->contact), "%s", CT);
	e->lport = sdp_port(body_at(l, i200));
	phone_req(0, "ACK", e->contact, cid, "ft1", e->ttag, 1, NULL, NULL, NULL);
	e->cseq = 1;
	CHECK(call_state("out", "up"));
}

static int phone_reinvite(struct est *e, int port, int pcma_only, const char *dir)
{
	int n = lan_ep()->nsent;

	phone_req(0, "INVITE", e->contact, e->cid, "ft1", e->ttag, ++e->cseq, NULL, "application/sdp", phone_sdp(0, port, pcma_only, dir));
	return find_resp(lan_ep(), e->cid, 200, n);
}

static void phone_ack(struct est *e)
{
	phone_req(0, "ACK", e->contact, e->cid, "ft1", e->ttag, e->cseq, NULL, NULL, NULL);
}

static void t_hold_resume(void)
{
	struct fakeep *l, *g;
	struct est e;
	struct peer car, ph;
	int i, ci;

	printf("  hold and resume from the client\n");
	setup(true);
	l = lan_ep();
	g = gm_ep();
	peer_open(&car);
	peer_open(&ph);
	mo_est(&e, "hold1@phone", car.port, ph.port, 1);
	i = phone_reinvite(&e, ph.port, 1, "sendonly");
	CHECK(i >= 0);
	if (i >= 0)
		CHECK(strstr(body_at(l, i), "a=recvonly") != NULL);	/* RFC 3264: our answer to sendonly */
	phone_ack(&e);
	ci = find_req(g, "INVITE", e.gi + 1);
	CHECK(ci >= 0);						/* mirrored to the network */
	if (ci >= 0) {
		CHECK(strstr(body_at(g, ci), "a=sendonly") != NULL);
		reply(g, ci, 200, NULL, "Contact: <sip:[2001:4430:5:405::43]:5071>\r\n", car_sdp(car.port, "recvonly"), pcscf());
	}
	CHECK(call_state("out", "hold"));
	/* the same SDP again (a session refresh) changes nothing and is not forwarded */
	i = g->nsent;
	{
		int j = phone_reinvite(&e, ph.port, 1, "sendonly");

		CHECK(j >= 0);
		phone_ack(&e);
		CHECK_EQ(find_req(g, "INVITE", i), -1);
	}
	i = phone_reinvite(&e, ph.port, 1, "sendrecv");
	CHECK(i >= 0);
	if (i >= 0)
		CHECK(strstr(body_at(l, i), "a=sendrecv") != NULL);
	phone_ack(&e);
	ci = find_req(g, "INVITE", ci + 1);
	CHECK(ci >= 0);
	if (ci >= 0) {
		CHECK(strstr(body_at(g, ci), "a=sendrecv") != NULL);
		reply(g, ci, 200, NULL, "Contact: <sip:[2001:4430:5:405::43]:5071>\r\n", car_sdp(car.port, "sendrecv"), pcscf());
	}
	CHECK(call_state("out", "up"));
	/* a refresh without a body gets our SDP back */
	phone_req(0, "INVITE", e.contact, e.cid, "ft1", e.ttag, ++e.cseq, NULL, NULL, NULL);
	i = find_resp(l, e.cid, 200, l->nsent - 1);
	CHECK(i >= 0 && strstr(body_at(l, i), "m=audio") != NULL);
	phone_ack(&e);
	/* the network refuses the next hold: the call goes on */
	i = phone_reinvite(&e, ph.port, 1, "inactive");
	phone_ack(&e);
	ci = find_req(g, "INVITE", ci + 1);
	CHECK(ci >= 0);
	if (ci >= 0)
		reply(g, ci, 488, NULL, NULL, NULL, pcscf());
	CHECK(call_state("out", "hold") || call_state("out", "up"));
	b2b_call_hangup(1);
	peer_close(&car);
	peer_close(&ph);
	finish("hold", true);
}

static void t_remote_hold_and_bye(void)
{
	struct fakeep *l, *g;
	struct est e;
	int n0, i;
	struct peer car, ph;

	printf("  remote hold, carrier BYE\n");
	setup(true);
	l = lan_ep();
	g = gm_ep();
	peer_open(&car);
	peer_open(&ph);
	mo_est(&e, "rh1@phone", car.port, ph.port, 1);
	n0 = l->nsent;
	net_req("INVITE", e.car_cid, e.car_to, e.car_from, 5, "Supported: timer\r\n", car_sdp(car.port, "sendonly"));
	CHECK(find_resp(g, e.car_cid, 200, 0) >= 0);
	CHECK(call_state("out", "hold"));
	net_req("ACK", e.car_cid, e.car_to, e.car_from, 5, NULL, NULL);
	CHECK_EQ(l->nsent, n0);				/* the phone is not disturbed */
	net_req("INVITE", e.car_cid, e.car_to, e.car_from, 6, "Supported: timer\r\n", car_sdp(car.port, "sendrecv"));
	net_req("ACK", e.car_cid, e.car_to, e.car_from, 6, NULL, NULL);
	CHECK(call_state("out", "up"));
	CHECK_EQ(l->nsent, n0);
	net_req("BYE", e.car_cid, e.car_to, e.car_from, 7, NULL, NULL);
	i = find_req_to(l, "BYE", 0, phone_port(0));
	CHECK(i >= 0);
	if (i >= 0)
		reply(l, i, 200, NULL, NULL, NULL, NULL);
	peer_close(&car);
	peer_close(&ph);
	finish("remote_hold", true);
}

static void t_reg_down(void)
{
	struct fakeep *l;
	struct est e;
	struct peer car, ph;

	printf("  registration lost in a call\n");
	setup(true);
	l = lan_ep();
	peer_open(&car);
	peer_open(&ph);
	mo_est(&e, "rd1@phone", car.port, ph.port, 1);
	reg_set_enabled(core_reg(C), false);
	evfake_advance(3000);
	CHECK(find_req_to(l, "BYE", 0, phone_port(0)) >= 0);	/* the client is told */
	peer_close(&car);
	peer_close(&ph);
	finish("reg_down", true);
	/* during setup: the client gets a final response */
	setup(true);
	phone_req(0, "INVITE", "sip:114@192.168.68.1", "rd2@phone", "ft1", NULL, 1, NULL, "application/sdp", phone_sdp(0, 40000, 1, "sendrecv"));
	reg_set_enabled(core_reg(C), false);
	evfake_advance(3000);
	CHECK(last_status(lan_ep(), "rd2@phone") >= 400);
	finish("reg_down_setup", true);
}

static void t_rtp_timeout(void)
{
	struct fakeep *l;
	struct est e;
	struct peer car, ph;
	int i;

	printf("  no RTP from the network: hang up\n");
	setup(true);
	CFG.rtp_timeout_s = 1;
	l = lan_ep();
	peer_open(&car);
	peer_open(&ph);
	mo_est(&e, "to1@phone", car.port, ph.port, 1);
	for (i = 0; i < 30 && find_req(gm_ep(), "BYE", 0) < 0; i++)
		pump(100);
	CHECK(find_req(gm_ep(), "BYE", 0) >= 0);
	CHECK(find_req_to(l, "BYE", 0, phone_port(0)) >= 0);
	peer_close(&car);
	peer_close(&ph);
	finish("rtp_timeout", true);
	/* off: nothing happens */
	setup(true);
	CFG.rtp_timeout_s = 0;
	peer_open(&car);
	peer_open(&ph);
	mo_est(&e, "to2@phone", car.port, ph.port, 1);
	pump(1500);
	CHECK(find_req(gm_ep(), "BYE", 0) < 0);
	b2b_call_hangup(1);
	peer_close(&car);
	peer_close(&ph);
	finish("rtp_timeout_off", true);
}

static void t_info_dtmf(void)
{
	struct est e;
	struct peer car, ph;
	struct rxpkt rx[300];
	int n, i, te = 0;

	printf("  SIP INFO DTMF -> RFC 4733\n");
	setup(true);
	peer_open(&car);
	peer_open(&ph);
	mo_est(&e, "dt1@phone", car.port, ph.port, 1);
	pump(60);
	peer_drain(&car, rx, 300, 100);
	phone_req(0, "INFO", e.contact, e.cid, "ft1", e.ttag, ++e.cseq, NULL, "application/dtmf-relay", "Signal=5\r\nDuration=160\r\n");
	CHECK_EQ(last_status(lan_ep(), e.cid), 200);
	pump(400);
	n = peer_drain(&car, rx, 300, 300);
	for (i = 0; i < n; i++)
		if (rx[i].pt == 107 && rx[i].plen == 4 && rx[i].first[0] == 5)
			te++;
	CHECK(te >= 4);
	phone_req(0, "INFO", e.contact, e.cid, "ft1", e.ttag, ++e.cseq, NULL, "application/foo", "x");
	CHECK_EQ(last_status(lan_ep(), e.cid), 200);
	b2b_call_hangup(1);
	peer_close(&car);
	peer_close(&ph);
	finish("info", true);
}

static void t_client_media_change(void)
{
	struct fakeep *l, *g;
	struct est e;
	struct peer car, ph, ph2;
	struct rxpkt rx[300];
	uint16_t cs = 10;
	uint32_t ct = 500;
	int i, n, pcma = 0, opus = 0;
	bool have_cap;

	printf("  client moves its RTP port, then switches codec\n");
	setup(true);
	l = lan_ep();
	g = gm_ep();
	peer_open(&car);
	peer_open(&ph);
	peer_open(&ph2);
	mo_est(&e, "mc1@phone", car.port, ph.port, 1);
	i = g->nsent;
	i = phone_reinvite(&e, ph2.port, 1, "sendrecv");
	CHECK(i >= 0);
	phone_ack(&e);
	CHECK_EQ(find_req(g, "INVITE", e.gi + 1), -1);		/* the network does not need to know */
	pump(50);
	have_cap = cap_have("network audio replay (media_change)");
	if (have_cap)
		replay_capture(&car, e.cport, 0, 25, &cs, &ct);
	n = peer_drain(&ph2, rx, 300, 300);
	CHECK(!have_cap || n >= 10);
	n = peer_drain(&ph, rx, 300, 50);
	CHECK(n <= 1);
	/* codec: the offer now has Opus first */
	i = phone_reinvite(&e, ph2.port, 0, "sendrecv");
	CHECK(i >= 0 && strstr(body_at(l, i), "opus/48000") != NULL);
	phone_ack(&e);
	CHECK_EQ(find_req(g, "INVITE", e.gi + 1), -1);
	pump(100);
	peer_drain(&ph2, rx, 300, 50);
	if (have_cap)
		replay_capture(&car, e.cport, 30, 30, &cs, &ct);
	n = peer_drain(&ph2, rx, 300, 300);
	for (i = 0; i < n; i++) {
		pcma += rx[i].pt == 8;
		opus += rx[i].pt == 111;
	}
	CHECK(!have_cap || opus >= 15);
	CHECK(!have_cap || opus > pcma);
	b2b_call_hangup(1);
	peer_close(&car);
	peer_close(&ph);
	peer_close(&ph2);
	finish("media_change", true);
}

static void t_lan_restart_and_stop(void)
{
	struct est e;
	struct peer car, ph;
	struct fakeep *l0, *g0;

	printf("  LAN side restart and daemon stop with calls up\n");
	setup(true);
	peer_open(&car);
	peer_open(&ph);
	l0 = lan_ep();
	mo_est(&e, "lr1@phone", car.port, ph.port, 1);
	snprintf(CFG.lan_ifname, sizeof(CFG.lan_ifname), "br-guest");
	core_reload(C);
	CHECK(find_req_to(l0, "BYE", 0, phone_port(0)) >= 0);
	CHECK(find_req(gm_ep(), "BYE", 0) >= 0);
	peer_close(&car);
	peer_close(&ph);
	finish("lan_restart", true);
	setup(true);
	peer_open(&car);
	peer_open(&ph);
	l0 = lan_ep();
	mo_est(&e, "st1@phone", car.port, ph.port, 1);
	mt_start("st2@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", car.port);
	g0 = gm_ep();
	b2b_end_all("test");
	core_stop(C);
	CHECK(find_req_to(l0, "BYE", 0, phone_port(0)) >= 0);
	CHECK(find_req(g0, "BYE", 0) >= 0);
	CHECK(find_resp(g0, "st2@ims", 480, 0) >= 0);
	peer_close(&car);
	peer_close(&ph);
	finish("stop", false);
}

/* ---- bench ---- */
static void write_wav(const char *path, int rate, int secs)
{
	FILE *f = fopen(path, "wb");
	uint32_t n = (uint32_t)(rate * secs), v;
	uint16_t h;
	uint32_t i;

	CHECK(f != NULL);
	if (!f)
		return;
	fwrite("RIFF", 1, 4, f);
	v = 36 + n * 2;
	fwrite(&v, 4, 1, f);
	fwrite("WAVEfmt ", 1, 8, f);
	v = 16;
	fwrite(&v, 4, 1, f);
	h = 1;
	fwrite(&h, 2, 1, f);
	fwrite(&h, 2, 1, f);
	v = (uint32_t)rate;
	fwrite(&v, 4, 1, f);
	v = (uint32_t)rate * 2;
	fwrite(&v, 4, 1, f);
	h = 2;
	fwrite(&h, 2, 1, f);
	h = 16;
	fwrite(&h, 2, 1, f);
	fwrite("data", 1, 4, f);
	v = n * 2;
	fwrite(&v, 4, 1, f);
	for (i = 0; i < n; i++) {
		int16_t x = (int16_t)(6000 * ((i / 8) & 1 ? 1 : -1));

		fwrite(&x, 2, 1, f);
	}
	fclose(f);
}

static void t_bench_out(void)
{
	struct fakeep *g;
	struct peer car;
	struct rxpkt rx[400];
	struct b2b_info rows[4];
	unsigned id = 0;
	uint16_t cs = 1;
	uint32_t ct = 100;
	int gi, n, k;
	long sz = 0;
	FILE *f;
	const char *play = "/tmp/imsd-b2b-play.wav", *rec = "/tmp/imsd-b2b-rec.wav";
	char hdr[5] = "";

	printf("  bench call: PCM file leg\n");
	write_wav(play, 16000, 2);
	unlink(rec);
	setup(false);
	g = gm_ep();
	peer_open(&car);
	CHECK_EQ(b2b_bench_dial("", play, rec, 16000, &id), -EINVAL);
	CHECK_EQ(b2b_bench_dial("01051226862", play, rec, 44100, &id), -EINVAL);
	CHECK_EQ(b2b_bench_dial("01051226862", play, rec, 16000, &id), 0);
	gi = find_req(g, "INVITE", 0);
	CHECK(gi >= 0);
	CHECK(strstr(hdr_at(g, gi, "To"), "tel:01051226862;phone-context=lte-lguplus.co.kr") != NULL);
	reply(g, gi, 183, "tagA", "Contact: <sip:[2001:4430:5:405::43]:5071>\r\n", car_sdp(car.port, "sendrecv"), pcscf());
	CHECK_EQ(bridge_count(), 1);
	pump(100);
	n = peer_drain(&car, rx, 400, 200);
	CHECK(n >= 3 && count_speech(rx, n) == 0);	/* early media: only keep-alives, the file waits for the answer */
	mo_answer(gi, "tagA", car.port);
	pump(600);
	n = peer_drain(&car, rx, 400, 300);
	CHECK(count_speech(rx, n) >= 10);		/* the play file is sent */
	CHECK_EQ(b2b_list(rows, 4), 1);
	CHECK(rows[0].bench && !strcmp(rows[0].client_codec, "pcm") && !strcmp(rows[0].carrier_codec, "AMR-WB"));
	CHECK(!strcmp(rows[0].state, "up") && rows[0].bridge && rows[0].stats.leg[0].tx_pkts > 10);
	if (cap_have("network audio replay (bench_out)")) {
		k = replay_capture(&car, sdp_port(body_at(g, gi)), 0, 40, &cs, &ct);
		CHECK(k == 40);
	}
	CHECK(T.n_notice >= 3);
	CHECK_EQ(b2b_call_hangup(id), 0);
	CHECK(find_req(g, "BYE", 0) >= 0);
	CHECK_EQ(b2b_call_hangup(99), -ENOENT);
	peer_close(&car);
	finish("bench_out", true);
	f = fopen(rec, "rb");
	CHECK(f != NULL);
	if (f) {
		if (fread(hdr, 1, 4, f) != 4)
			hdr[0] = 0;
		fseek(f, 0, SEEK_END);
		sz = ftell(f);
		fclose(f);
	}
	CHECK_STR(hdr, "RIFF");
	CHECK(sz > 44 + 16000);				/* the recorded downlink */
}

static void t_bench_in(void)
{
	struct fakeep *g;
	unsigned id = 0;
	struct b2b_info rows[4];
	int n;

	printf("  bench: incoming call answered / rejected over ubus\n");
	setup(false);
	g = gm_ep();
	CFG.bench_incoming = true;
	net_invite("bi1@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", car_sdp(41000, "sendrecv"));
	CHECK_EQ(last_status(g, "bi1@ims"), 180);
	n = b2b_list(rows, 4);
	CHECK_EQ(n, 1);
	id = rows[0].id;
	CHECK(rows[0].bench && !strcmp(rows[0].dir, "in") && !strcmp(rows[0].state, "ringing"));
	CHECK_STR(rows[0].number, "01099998888");
	CHECK_EQ(b2b_bench_answer(id, "", "/tmp/imsd-b2b-rec2.wav", 0), 0);
	CHECK(find_resp(g, "bi1@ims", 200, 0) >= 0);
	CHECK_EQ(bridge_count(), 1);
	CHECK_EQ(b2b_call_hangup(id), 0);
	CHECK(find_req(g, "BYE", 0) >= 0);
	net_invite("bi2@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", car_sdp(41000, "sendrecv"));
	n = b2b_list(rows, 4);
	CHECK_EQ(n, 1);
	CHECK_EQ(b2b_call_reject(rows[0].id, 603), 0);
	CHECK_EQ(last_status(g, "bi2@ims"), 603);
	CHECK_EQ(b2b_call_reject(rows[0].id, 603), -ENOENT);
	finish("bench_in", true);
	/* without bench_incoming the line has no taker: 480 */
	setup(false);
	net_invite("bi3@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", car_sdp(41000, "sendrecv"));
	CHECK_EQ(last_status(gm_ep(), "bi3@ims"), 480);
	finish("bench_off", true);
}


static void t_stray_2xx(void)
{
	struct est e;
	struct peer car, ph;
	struct fakeep *g;
	int i, ia, ib;

	printf("  a forked 2xx long after the transaction ended is ACKed and ended\n");
	setup(true);
	g = gm_ep();
	peer_open(&car);
	peer_open(&ph);
	mo_est(&e, "sx1@phone", car.port, ph.port, 1);
	evfake_advance(40000);			/* the INVITE client transaction is gone */
	i = g->nsent;
	reply(g, e.gi, 200, "tagZ", "Contact: <sip:[2001:4430:5:405::43]:5071>\r\n", car_sdp(car.port, "sendrecv"), pcscf());
	ia = find_req(g, "ACK", i);
	ib = find_req(g, "BYE", i);
	CHECK(ia >= 0 && ib >= 0);
	if (ib >= 0)
		CHECK(strstr(hdr_at(g, ib, "To"), "tagZ") != NULL);
	CHECK(call_state("out", "up"));		/* the real call is not disturbed */
	b2b_call_hangup(1);
	peer_close(&car);
	peer_close(&ph);
	finish("stray", true);
}

/* teardown order: both modules, a call up, a fork running, an SMS in flight; the core stops under ASan */
static void t_stop_order(void)
{
	struct est e;
	struct peer car, ph;
	int round;

	printf("  core stop with calls, a fork and an SMS in flight (both modules), twice\n");
	g_sms = true;
	for (round = 0; round < 2; round++) {
		setup(true);
		peer_open(&car);
		peer_open(&ph);
		mo_est(&e, "so1@phone", car.port, ph.port, 1);
		mt_start("so2@ims", "sip:01099998888@lte-lguplus.co.kr", "<sip:01099998888@lte-lguplus.co.kr>", car.port);
		phone_req(1, "MESSAGE", "sip:01012345678@192.168.68.1", "sms1@phone", "m1", NULL, 1, NULL, "text/plain;charset=utf-8", "hi");
		CHECK(find_req(gm_ep(), "MESSAGE", 0) >= 0);		/* the RP-DATA is out, the network has not answered */
		core_stop(C);
		peer_close(&car);
		peer_close(&ph);
		finish("stop_order", false);
	}
	g_sms = false;
}

/* ====================================================================================================================
 * Circuit switched carrier (PCM kind): a fake struct carrier_call_ops backend and a fake modem sound card (eventfd clock,
 * tone downlink, recorded uplink) under the REAL core, LAN registrar, B2BUA and media bridge.
 * ================================================================================================================== */
static struct pfake {
	pthread_mutex_t mu;
	pthread_t th;
	atomic_bool run;
	int efd;
	unsigned pending, opens, closes, writes, ul_nonzero;
	bool gone;
	double phase;
} PF = { .mu = PTHREAD_MUTEX_INITIALIZER, .efd = -1 };

static void *pf_clock(void *arg)
{
	(void)arg;
	while (atomic_load(&PF.run)) {
		usleep(20000);
		pthread_mutex_lock(&PF.mu);
		PF.pending++;
		eventfd_write(PF.efd, 1);
		pthread_mutex_unlock(&PF.mu);
	}
	return NULL;
}

static void *pf_open(const char *spec, unsigned rate, unsigned frames)
{
	(void)spec;
	if (rate != 8000 || frames != 160) {
		errno = EINVAL;
		return NULL;
	}
	pthread_mutex_lock(&PF.mu);
	PF.opens++;
	pthread_mutex_unlock(&PF.mu);
	return &PF;
}

static int pf_fd(void *d) { (void)d; return PF.efd; }

static int pf_read(void *d, int16_t *pcm, unsigned frames)
{
	uint64_t j;
	unsigned i;
	int r;

	(void)d;
	pthread_mutex_lock(&PF.mu);
	if (PF.gone) {
		r = -ENODEV;
	} else if (!PF.pending) {
		if (eventfd_read(PF.efd, &j) < 0) { /* clear already */ }
		r = 0;
	} else {
		PF.pending--;
		for (i = 0; i < frames; i++) {
			pcm[i] = (int16_t)(8000 * sin(PF.phase));
			PF.phase += 2 * 3.14159265358979 * 400.0 / 8000.0;
		}
		r = (int)frames;
	}
	pthread_mutex_unlock(&PF.mu);
	return r;
}

static int pf_write(void *d, const int16_t *pcm, unsigned frames)
{
	unsigned i;
	int r = (int)frames;

	(void)d;
	pthread_mutex_lock(&PF.mu);
	if (PF.gone) {
		r = -ENODEV;
	} else {
		PF.writes++;
		for (i = 0; i < frames; i++)
			if (pcm[i]) {
				PF.ul_nonzero++;
				break;
			}
	}
	pthread_mutex_unlock(&PF.mu);
	return r;
}

static void pf_close(void *d)
{
	(void)d;
	pthread_mutex_lock(&PF.mu);
	PF.closes++;
	pthread_mutex_unlock(&PF.mu);
}

static const struct br_pcmdev_ops pf_ops = { .name = "fake", .open = pf_open, .poll_fd = pf_fd, .read = pf_read, .write = pf_write, .close = pf_close };

/* the fake carrier backend */
struct fcc {
	bool used, ended, released, answered, rejected, hangup, hold, media_failed;
	int reject_status, mf_err;
	cc_event_cb cb;
	void *arg;
	enum cc_state st;
	enum cc_dir dir;
	char digits[16];
	int ndig;
	struct cc_identity remote;
	unsigned id;
	const struct addr *answer_rtp;
};

static struct fcc FC[8];
static struct {
	cc_incoming_cb in_cb;
	void *in_arg;
	int dial_rc, ndial;
	char target[48];
	bool n_local_rtp;
} FB;

static bool fc_live(void)
{
	int i;

	for (i = 0; i < 8; i++)
		if (FC[i].used && !FC[i].ended && !FC[i].released)
			return true;
	return false;
}

static void fb_set_incoming(void *be, cc_incoming_cb cb, void *arg) { (void)be; FB.in_cb = cb; FB.in_arg = arg; }

static int fb_dial(void *be, const struct cc_dial *d, cc_event_cb cb, void *arg, struct carrier_call **out)
{
	int i;

	(void)be;
	FB.ndial++;
	snprintf(FB.target, sizeof(FB.target), "%s", d->target);
	FB.n_local_rtp = addr_port(&d->local_rtp) != 0;
	if (FB.dial_rc)
		return FB.dial_rc;
	if (fc_live())
		return -EBUSY;			/* the PCM path is single */
	for (i = 0; i < 8 && FC[i].used; i++)
		;
	if (i == 8)
		return -ENOBUFS;
	memset(&FC[i], 0, sizeof(FC[i]));
	FC[i].used = true;
	FC[i].cb = cb;
	FC[i].arg = arg;
	FC[i].st = CC_ST_DIALING;
	FC[i].dir = CC_MO;
	FC[i].id = (unsigned)i + 1;
	snprintf(FC[i].remote.number, sizeof(FC[i].remote.number), "%s", d->target);
	*out = (struct carrier_call *)&FC[i];
	return 0;
}

static unsigned fb_count(const void *be) { (void)be; return fc_live() ? 1 : 0; }
static int fb_list(const void *be, struct cc_info *out, int max) { (void)be; (void)out; (void)max; return 0; }
static void fb_set_handler(struct carrier_call *c, cc_event_cb cb, void *arg) { struct fcc *f = (struct fcc *)c; f->cb = cb; f->arg = arg; }
static int fb_ring(struct carrier_call *c) { (void)c; return 0; }
static int fb_answer(struct carrier_call *c, const struct addr *rtp)
{
	struct fcc *f = (struct fcc *)c;

	f->answered = true;
	f->answer_rtp = rtp;
	f->st = CC_ST_ANSWERING;
	return 0;
}
static int fb_reject(struct carrier_call *c, int status) { struct fcc *f = (struct fcc *)c; f->rejected = true; f->reject_status = status; return 0; }
static int fb_hangup(struct carrier_call *c) { ((struct fcc *)c)->hangup = true; return 0; }
static void fb_release(struct carrier_call *c) { struct fcc *f = (struct fcc *)c; f->released = true; f->hangup = true; }
static int fb_set_hold(struct carrier_call *c, bool h) { ((struct fcc *)c)->hold = h; return 0; }
static int fb_send_dtmf(struct carrier_call *c, char d)
{
	struct fcc *f = (struct fcc *)c;

	if (f->ndig < (int)sizeof(f->digits) - 1)
		f->digits[f->ndig++] = d;
	return 0;
}
static void fb_media_failed(struct carrier_call *c, int err) { struct fcc *f = (struct fcc *)c; f->media_failed = true; f->mf_err = err; }
static bool fb_get_media(const struct carrier_call *c, struct sdpn_media *o) { (void)c; (void)o; return false; }
static enum cc_state fb_state(const struct carrier_call *c) { return ((const struct fcc *)c)->st; }
static enum cc_dir fb_direction(const struct carrier_call *c) { return ((const struct fcc *)c)->dir; }
static const struct cc_identity *fb_remote(const struct carrier_call *c) { return &((const struct fcc *)c)->remote; }
static unsigned fb_id(const struct carrier_call *c) { return ((const struct fcc *)c)->id; }
static uint64_t fb_talk_ms(const struct carrier_call *c) { (void)c; return 0; }

static const struct carrier_call_ops fb_ops = {
	.name = "cs", .media_kind = CC_MEDIA_PCM, .set_incoming = fb_set_incoming, .dial = fb_dial, .count = fb_count, .list = fb_list,
	.set_handler = fb_set_handler, .ring = fb_ring, .answer = fb_answer, .reject = fb_reject, .hangup = fb_hangup,
	.release = fb_release, .set_hold = fb_set_hold, .send_dtmf = fb_send_dtmf, .media_failed = fb_media_failed,
	.get_media = fb_get_media, .state = fb_state, .direction = fb_direction, .remote = fb_remote, .id = fb_id, .talk_ms = fb_talk_ms,
};

/* inject an event of call f from the "loop" */
static void fev(struct fcc *f, enum cc_event_type t, int status, bool by_remote, const char *reason)
{
	struct cc_event e;

	memset(&e, 0, sizeof(e));
	e.type = t;
	e.status = status;
	e.by_remote = by_remote;
	e.media_kind = t == CC_EV_EARLY_MEDIA ? CC_MEDIA_PCM : CC_MEDIA_NONE;
	e.early = t == CC_EV_EARLY_MEDIA;
	snprintf(e.reason, sizeof(e.reason), "%s", reason ? reason : "");
	if (t == CC_EV_ANSWERED)
		f->st = CC_ST_CONNECTED;
	if (t == CC_EV_FAILED || t == CC_EV_CANCELLED || t == CC_EV_TERMINATED) {
		f->ended = true;
		f->st = CC_ST_ENDED;
	}
	if (f->cb)
		f->cb((struct carrier_call *)f, &e, f->arg);
}

/* a network call: the B2BUA's incoming callback; returns the fake call or NULL when it was refused */
static struct fcc *fb_incoming(const char *number)
{
	struct cc_incoming in;
	struct fcc *f;
	int i;

	for (i = 0; i < 8 && FC[i].used; i++)
		;
	f = &FC[i];
	memset(f, 0, sizeof(*f));
	f->used = true;
	f->dir = CC_MT;
	f->st = CC_ST_INCOMING;
	f->id = (unsigned)i + 1;
	snprintf(f->remote.number, sizeof(f->remote.number), "%s", number);
	memset(&in, 0, sizeof(in));
	snprintf(in.caller.number, sizeof(in.caller.number), "%s", number);
	in.media_kind = CC_MEDIA_PCM;
	in.backend_cs = true;
	if (!FB.in_cb || FB.in_cb((struct carrier_call *)f, &in, FB.in_arg)) {
		f->used = false;
		return NULL;
	}
	return f;
}

static struct carrier_backend FBE;

static void cs_setup(void)
{
	if (PF.efd < 0)
		PF.efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);	/* before setup(): part of the descriptor baseline */
	memset(FC, 0, sizeof(FC));
	memset(&FB, 0, sizeof(FB));
	PF.pending = PF.opens = PF.closes = PF.writes = PF.ul_nonzero = 0;
	PF.gone = false;
	PF.phase = 0;
	g_pcm = &pf_ops;
	setup(true);
	FBE.ops = &fb_ops;
	FBE.be = &FB;
	b2b_set_cs_backend(&FBE);
	b2b_select_backend(B2B_BE_CS);
	atomic_store(&PF.run, true);
	pthread_create(&PF.th, NULL, pf_clock, NULL);
}

static void cs_finish(const char *name)
{
	finish(name, true);
	atomic_store(&PF.run, false);
	pthread_join(PF.th, NULL);
	g_pcm = NULL;
	b2b_select_backend(B2B_BE_GM);
}

/* a phone calls 114 over the CS backend; returns the fake call (NULL when the dial was refused) */
static struct fcc *cs_mo_start(int k, const char *cid, int phone_port_media, int which)
{
	int i;

	phone_req(k, "INVITE", "sip:114@192.168.68.1", cid, "ft1", NULL, 1, "Allow: INVITE, ACK, CANCEL, BYE, UPDATE, INFO\r\n",
		  "application/sdp", phone_sdp(k, phone_port_media, which, "sendrecv"));
	for (i = 7; i >= 0; i--)
		if (FC[i].used && FC[i].dir == CC_MO && !FC[i].ended && !FC[i].released)
			return &FC[i];
	return NULL;
}

static void send_te(const struct peer *ph, int to_port, int ev, uint16_t *seq, uint32_t ts)
{
	uint8_t pl[4], pk[64];
	int i, l;

	for (i = 0; i < 6; i++) {
		int end = i >= 3;
		unsigned dur = 160u * (unsigned)(i + 1);

		pl[0] = (uint8_t)ev;
		pl[1] = (uint8_t)((end ? 0x80 : 0) | 10);
		pl[2] = (uint8_t)(dur >> 8);
		pl[3] = (uint8_t)dur;
		l = rtp_build(pk, sizeof(pk), i == 0, 101, (*seq)++, ts, 0xBEEF0003u, pl, 4);
		peer_send(ph, to_port, pk, (size_t)l);
		usleep(20000);
		bridge_events_dispatch(core_bridge_event, C);
	}
}

static void t_cs_mo_early(void)
{
	struct fakeep *l, *g;
	struct peer ph;
	struct rxpkt rx[400];
	struct fcc *f;
	int i183, i200, i180, n, lport;
	uint16_t pseq = 900;
	uint32_t pts = 100;
	char b183[2000];

	printf("  cs: mo with early media, answer, audio both ways, DTMF, hold, LAN hangup\n");
	cs_setup();
	l = lan_ep();
	g = gm_ep();
	peer_open(&ph);
	f = cs_mo_start(0, "cs1@phone", ph.port, 0);
	CHECK(f != NULL);
	if (!f)
		goto out;
	CHECK_EQ(last_status(l, "cs1@phone"), 100);
	CHECK_STR(FB.target, "114");
	CHECK(!FB.n_local_rtp);					/* no carrier RTP address for a PCM call */
	CHECK(find_req(g, "INVITE", 0) < 0);			/* nothing towards the IMS side */
	CHECK_EQ(bridge_count(), 0);
	fev(f, CC_EV_PROGRESS, 180, false, "");
	fev(f, CC_EV_RINGING, 180, false, "");
	i180 = find_resp(l, "cs1@phone", 180, 0);
	CHECK(i180 >= 0);
	CHECK_EQ(find_resp(l, "cs1@phone", 183, 0), -1);
	CHECK_EQ(bridge_count(), 0);
	fev(f, CC_EV_EARLY_MEDIA, 183, false, "");
	i183 = find_resp(l, "cs1@phone", 183, 0);
	CHECK(i183 >= 0);
	snprintf(b183, sizeof(b183), "%s", body_at(l, i183));
	lport = sdp_port(b183);
	CHECK(lport >= 30000 && lport <= 30098);
	CHECK(strstr(b183, "AMR") == NULL);			/* narrowband offer to the LAN device */
	CHECK(strstr(b183, "PCMA/8000") != NULL);		/* narrowband: the 8 kHz codec although the phone offered opus / G.722 */
	CHECK(strstr(b183, "opus") == NULL && strstr(b183, "G722") == NULL);
	CHECK_EQ(bridge_count(), 1);
	CHECK(call_state("out", "early-media"));
	pump(300);
	CHECK_EQ(PF.opens, 1);					/* the PCM device was opened by the bridge's carrier leg */
	n = peer_drain(&ph, rx, 400, 300);
	CHECK(n >= 10);						/* the network ringback reaches the phone */
	fev(f, CC_EV_ANSWERED, 0, false, "");
	i200 = find_resp(l, "cs1@phone", 200, 0);
	CHECK(i200 >= 0);
	CHECK_STR(body_at(l, i200), b183);			/* the 200 carries the SAME answer as the 183 */
	dialog_of(l, i200);
	phone_req(0, "ACK", CT, "cs1@phone", "ft1", TT, 1, NULL, NULL, NULL);
	CHECK(call_state("out", "up"));
	/* DTMF: RFC 4733 key down from the phone and SIP INFO are sent with the call control, in order */
	send_te(&ph, lport, 5, &pseq, pts);
	phone_req(0, "INFO", CT, "cs1@phone", "ft1", TT, 2, NULL, "application/dtmf-relay", "Signal=7\r\nDuration=160\r\n");
	CHECK_EQ(last_status(l, "cs1@phone"), 200);
	pump(100);
	CHECK_STR(f->digits, "57");
	CHECK(!f->hold);
	/* hold from the phone: no hold on the CS call, silence to the modem */
	{
		int k = l->nsent;

		phone_req(0, "INVITE", CT, "cs1@phone", "ft1", TT, 3, NULL, "application/sdp", phone_sdp(0, ph.port, 0, "sendonly"));
		CHECK(find_resp(l, "cs1@phone", 200, k) >= 0);
		CHECK(f->hold);
		phone_req(0, "ACK", CT, "cs1@phone", "ft1", TT, 3, NULL, NULL, NULL);
		phone_req(0, "INVITE", CT, "cs1@phone", "ft1", TT, 4, NULL, "application/sdp", phone_sdp(0, ph.port, 0, "sendrecv"));
		CHECK(!f->hold);
		phone_req(0, "ACK", CT, "cs1@phone", "ft1", TT, 4, NULL, NULL, NULL);
	}
	/* the phone hangs up: the carrier call is released (hung up) */
	phone_req(0, "BYE", CT, "cs1@phone", "ft1", TT, 5, NULL, NULL, NULL);
	CHECK_EQ(last_status(l, "cs1@phone"), 200);
	CHECK(f->released && f->hangup);
	CHECK_EQ(bridge_count(), 0);
out:
	peer_close(&ph);
	cs_finish("cs_mo_early");
}

static void t_cs_mo_no_early(void)
{
	struct fakeep *l;
	struct peer ph;
	struct fcc *f;
	int i200;

	printf("  cs: mo answered without early media, the network ends the call\n");
	cs_setup();
	l = lan_ep();
	peer_open(&ph);
	f = cs_mo_start(0, "cs2@phone", ph.port, 1);
	CHECK(f != NULL);
	if (!f)
		goto out;
	fev(f, CC_EV_RINGING, 180, false, "");
	CHECK(find_resp(l, "cs2@phone", 180, 0) >= 0);
	CHECK_EQ(bridge_count(), 0);
	fev(f, CC_EV_ANSWERED, 0, false, "");			/* no EARLY_MEDIA came: the bridge opens now */
	CHECK_EQ(bridge_count(), 1);
	i200 = find_resp(l, "cs2@phone", 200, 0);
	CHECK(i200 >= 0);
	CHECK(strstr(body_at(l, i200), "PCMA/8000") != NULL);
	dialog_of(l, i200);
	phone_req(0, "ACK", CT, "cs2@phone", "ft1", TT, 1, NULL, NULL, NULL);
	CHECK(call_state("out", "up"));
	fev(f, CC_EV_TERMINATED, 0, true, "hangup by the network");
	CHECK(find_req_to(l, "BYE", 0, phone_port(0)) >= 0);	/* the phone is told */
	CHECK_EQ(bridge_count(), 0);
out:
	peer_close(&ph);
	cs_finish("cs_mo_noearly");
}

static void t_cs_mo_failures(void)
{
	struct fakeep *l;
	struct fcc *f;
	int rc, i;
	static const struct { int dial_rc; int status; } d[] = { { -ENOTCONN, 503 }, { -EINVAL, 484 }, { -ENOBUFS, 486 }, { -EBUSY, 486 } };

	printf("  cs: dial errors, network refusals, busy second call, no backend\n");
	cs_setup();
	l = lan_ep();
	for (i = 0; i < 4; i++) {
		char cid[32];

		snprintf(cid, sizeof(cid), "cs3-%d@phone", i);
		FB.dial_rc = d[i].dial_rc;
		f = cs_mo_start(0, cid, 40000, 1);
		CHECK(f == NULL);
		CHECK_EQ(last_status(l, cid), d[i].status);
		phone_req(0, "ACK", "sip:114@192.168.68.1", cid, "ft1", NULL, 1, NULL, NULL, NULL);
	}
	FB.dial_rc = 0;
	/* the network fails the call before the alerting state: 503, after a short alerting: 603 */
	f = cs_mo_start(0, "cs3-f1@phone", 40000, 1);
	CHECK(f != NULL);
	if (f) {
		fev(f, CC_EV_FAILED, 503, false, "no service");
		CHECK_EQ(last_status(l, "cs3-f1@phone"), 503);
		CHECK_EQ(bridge_count(), 0);
		phone_req(0, "ACK", "sip:114@192.168.68.1", "cs3-f1@phone", "ft1", NULL, 1, NULL, NULL, NULL);
	}
	f = cs_mo_start(0, "cs3-f2@phone", 40000, 1);
	CHECK(f != NULL);
	if (f) {
		fev(f, CC_EV_FAILED, 603, false, "declined");
		CHECK_EQ(last_status(l, "cs3-f2@phone"), 603);
		phone_req(0, "ACK", "sip:114@192.168.68.1", "cs3-f2@phone", "ft1", NULL, 1, NULL, NULL, NULL);
	}
	/* a second call while the first one is up: the PCM path is single, 486 */
	f = cs_mo_start(0, "cs3-up@phone", 40000, 1);
	CHECK(f != NULL);
	if (f) {
		fev(f, CC_EV_ANSWERED, 0, false, "");
		rc = find_resp(l, "cs3-up@phone", 200, 0);
		CHECK(rc >= 0);
		dialog_of(l, rc);
		phone_req(0, "ACK", CT, "cs3-up@phone", "ft1", TT, 1, NULL, NULL, NULL);
		cs_mo_start(1, "cs3-2nd@phone", 40002, 1);
		CHECK_EQ(last_status(l, "cs3-2nd@phone"), 486);
		CHECK(call_state("out", "up"));
		phone_req(0, "BYE", CT, "cs3-up@phone", "ft1", TT, 2, NULL, NULL, NULL);
		CHECK(f->released);
	}
	/* no backend selected: 503 */
	b2b_select_backend(B2B_BE_NONE);
	CHECK(cs_mo_start(0, "cs3-none@phone", 40000, 1) == NULL);
	CHECK_EQ(last_status(l, "cs3-none@phone"), 503);
	cs_finish("cs_mo_fail");
}

static void t_cs_mt(void)
{
	struct fakeep *l;
	struct peer ph;
	struct fcc *f;
	int ip[NPHONE], k;
	char fcid[160], ftag[80] = "";

	printf("  cs: incoming call forked to three devices, one answers, then hangs up\n");
	cs_setup();
	l = lan_ep();
	peer_open(&ph);
	f = fb_incoming("01099998888");
	CHECK(f != NULL);
	if (!f)
		goto out;
	for (k = 0; k < NPHONE; k++) {
		ip[k] = find_req_to(l, "INVITE", 0, phone_port(k));
		CHECK(ip[k] >= 0);
	}
	if (ip[0] < 0 || ip[1] < 0 || ip[2] < 0)
		goto out;
	CHECK(strstr(hdr_at(l, ip[0], "From"), "01099998888@192.168.68.1") != NULL);
	CHECK(strstr(body_at(l, ip[0]), "AMR") == NULL);
	snprintf(fcid, sizeof(fcid), "%s", hdr_at(l, ip[0], "Call-ID"));
	CHECK(!f->answered);
	CHECK_EQ(bridge_count(), 0);
	for (k = 0; k < NPHONE; k++)
		reply(l, ip[k], 180, k == 0 ? "pt0" : k == 1 ? "pt1" : "pt2", NULL, NULL, NULL);
	answer_phone(1, ip[1], "pt1", ph.port, "sendrecv");
	CHECK(f->answered);
	CHECK(f->answer_rtp == NULL);				/* no carrier RTP address */
	CHECK_EQ(bridge_count(), 1);
	CHECK(find_req_to(l, "ACK", 0, phone_port(1)) >= 0);
	CHECK(find_req_to(l, "CANCEL", 0, phone_port(0)) >= 0);
	CHECK(find_req_to(l, "CANCEL", 0, phone_port(2)) >= 0);
	reply(l, ip[0], 487, "pt0", NULL, NULL, NULL);
	reply(l, ip[2], 487, "pt2", NULL, NULL, NULL);
	fev(f, CC_EV_ANSWERED, 0, false, "");			/* the confirmation of the accept changes nothing */
	CHECK(call_state("in", "up"));
	pump(200);
	CHECK_EQ(PF.opens, 1);
	sip_tag(hdr_at(l, ip[1], "From"), ftag, sizeof(ftag));
	phone_req(1, "BYE", "sip:imsd@192.168.68.1:5060", fcid, "pt1", ftag, 2, NULL, NULL, NULL);
	CHECK_EQ(last_status(l, fcid), 200);
	CHECK(f->released && f->hangup);
	CHECK_EQ(bridge_count(), 0);
out:
	peer_close(&ph);
	cs_finish("cs_mt");
}

static void t_cs_mt_other(void)
{
	struct fakeep *l;
	struct fcc *f;
	int ip, i;

	printf("  cs: incoming call: caller gives up, devices busy, ring timeout\n");
	cs_setup();
	l = lan_ep();
	/* the caller hangs up while it rings */
	f = fb_incoming("01099998888");
	CHECK(f != NULL);
	if (f) {
		for (i = 0; i < NPHONE; i++) {
			ip = find_req_to(l, "INVITE", 0, phone_port(i));
			CHECK(ip >= 0);
			if (ip >= 0)
				reply(l, ip, 180, "x", NULL, NULL, NULL);
		}
		fev(f, CC_EV_CANCELLED, 487, true, "caller gave up");
		CHECK(find_req_to(l, "CANCEL", 0, phone_port(0)) >= 0);
		for (i = 0; i < NPHONE; i++) {
			ip = find_req_to(l, "INVITE", 0, phone_port(i));
			if (ip >= 0)
				reply(l, ip, 487, "x", NULL, NULL, NULL);
		}
	}
	/* every device busy: the carrier call is rejected */
	f = fb_incoming("01077776666");
	CHECK(f != NULL);
	if (f) {
		for (i = 0; i < NPHONE; i++) {
			ip = find_req_to(l, "INVITE", 0, phone_port(i));
			ip = find_req_to(l, "INVITE", ip + 1, phone_port(i));	/* the second INVITE of each phone is this call's */
			CHECK(ip >= 0);
			if (ip >= 0)
				reply(l, ip, 486, "b", NULL, NULL, NULL);
		}
		CHECK(f->rejected);
		CHECK_EQ(f->reject_status, 486);
	}
	/* nobody answers: rejected after the ring timeout */
	f = fb_incoming("01055554444");
	CHECK(f != NULL);
	if (f) {
		evfake_advance(61000);
		CHECK(f->rejected);
		CHECK_EQ(f->reject_status, 480);
	}
	cs_finish("cs_mt_other");
}

static void t_cs_mt_nodev(void)
{
	printf("  cs: incoming call without a LAN device is refused\n");
	g_pcm = &pf_ops;
	setup(false);
	FBE.ops = &fb_ops;
	FBE.be = &FB;
	memset(FC, 0, sizeof(FC));
	memset(&FB, 0, sizeof(FB));
	b2b_set_cs_backend(&FBE);
	CHECK(fb_incoming("01099998888") == NULL);
	finish("cs_mt_nodev", true);
	g_pcm = NULL;
}

static void t_cs_pcm_lost(void)
{
	struct fakeep *l;
	struct peer ph;
	struct fcc *f;
	int i, i503;

	printf("  cs: the PCM device vanishes: 503 before the answer, hang up after it\n");
	/* before the answer, during the early media */
	cs_setup();
	l = lan_ep();
	peer_open(&ph);
	f = cs_mo_start(0, "cs5@phone", ph.port, 1);
	CHECK(f != NULL);
	if (f) {
		fev(f, CC_EV_EARLY_MEDIA, 183, false, "");
		CHECK_EQ(bridge_count(), 1);
		pump(200);
		pthread_mutex_lock(&PF.mu);
		PF.gone = true;
		eventfd_write(PF.efd, 1);
		pthread_mutex_unlock(&PF.mu);
		for (i = 0; i < 100 && !f->media_failed; i++)
			pump(10);
		CHECK(f->media_failed);
		CHECK_EQ(f->mf_err, ENODEV);
		i503 = find_resp(l, "cs5@phone", 503, 0);
		CHECK(i503 >= 0);
		CHECK(f->released);
		phone_req(0, "ACK", "sip:114@192.168.68.1", "cs5@phone", "ft1", NULL, 1, NULL, NULL, NULL);
	}
	peer_close(&ph);
	cs_finish("cs_lost_early");
	/* established call */
	cs_setup();
	l = lan_ep();
	peer_open(&ph);
	f = cs_mo_start(0, "cs6@phone", ph.port, 1);
	CHECK(f != NULL);
	if (f) {
		int i200;

		fev(f, CC_EV_ANSWERED, 0, false, "");
		i200 = find_resp(l, "cs6@phone", 200, 0);
		CHECK(i200 >= 0);
		dialog_of(l, i200);
		phone_req(0, "ACK", CT, "cs6@phone", "ft1", TT, 1, NULL, NULL, NULL);
		pump(200);
		pthread_mutex_lock(&PF.mu);
		PF.gone = true;
		eventfd_write(PF.efd, 1);
		pthread_mutex_unlock(&PF.mu);
		for (i = 0; i < 100 && !f->media_failed; i++)
			pump(10);
		CHECK(f->media_failed);
		CHECK(find_req_to(l, "BYE", 0, phone_port(0)) >= 0);
		CHECK(f->released);
	}
	peer_close(&ph);
	cs_finish("cs_lost_up");
}

/* the IMS path is unaffected by a CS backend that is plugged in: calls go where the selection says */
static void t_cs_select(void)
{
	struct fakeep *l, *g;
	struct fcc *f;
	int gi;

	printf("  cs: backend selection: gm calls with the CS backend present, a CS call keeps its backend\n");
	cs_setup();
	l = lan_ep();
	g = gm_ep();
	b2b_select_backend(B2B_BE_GM);
	CHECK_EQ(b2b_selected_backend(), B2B_BE_GM);
	phone_req(0, "INVITE", "sip:114@192.168.68.1", "sel1@phone", "ft1", NULL, 1, NULL, "application/sdp", phone_sdp(0, 40000, 1, "sendrecv"));
	CHECK_EQ(last_status(l, "sel1@phone"), 100);
	gi = find_req(g, "INVITE", 0);
	CHECK(gi >= 0);						/* IMS INVITE */
	CHECK_EQ(FB.ndial, 0);
	b2b_end_all("test");
	b2b_select_backend(B2B_BE_CS);
	f = cs_mo_start(0, "sel2@phone", 40000, 1);
	CHECK(f != NULL);
	CHECK_EQ(FB.ndial, 1);
	CHECK_EQ(find_req(g, "INVITE", gi + 1), -1);
	b2b_select_backend(B2B_BE_GM);				/* the running CS call is not touched by a switch */
	CHECK_EQ(b2b_active_calls(), 1u);
	CHECK(f && !f->hangup);
	CHECK_EQ(b2b_call_hangup(2), 0);
	CHECK(f && f->released);
	cs_finish("cs_select");
}

/* bench calls (ubus call_dial / call_answer) use the CS backend too: the LAN leg is a PCM file */
static void t_cs_bench(void)
{
	unsigned id = 0;
	struct fcc *f;
	int rc;

	printf("  cs: bench call over the CS backend\n");
	cs_setup();
	rc = b2b_bench_dial("114", "", "", 8000, &id);
	CHECK_EQ(rc, 0);
	f = &FC[0];
	CHECK(f->used && !FB.n_local_rtp);
	CHECK_STR(FB.target, "114");
	fev(f, CC_EV_EARLY_MEDIA, 183, false, "");
	CHECK_EQ(bridge_count(), 1);
	fev(f, CC_EV_ANSWERED, 0, false, "");
	CHECK(call_state("out", "up"));
	pump(100);
	CHECK(b2b_call_hangup(id) == 0);
	CHECK(f->released);
	cs_finish("cs_bench");
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	imsd_log_level(getenv("B2B_LOG") ? atoi(getenv("B2B_LOG")) : LOG_ERR);
	t_mo_early_answer_e2e();
	t_mo_603_after_early();
	t_mo_statuses();
	t_mo_cancel();
	t_mo_dialog_change();
	t_mo_refusals();
	t_mt_three_devices();
	t_mt_no_device();
	t_mt_all_busy();
	t_mt_caller_cancels();
	t_mt_two_answer();
	t_mt_anonymous();
	t_mt_ring_timeout();
	t_hold_resume();
	t_remote_hold_and_bye();
	t_reg_down();
	t_rtp_timeout();
	t_info_dtmf();
	t_client_media_change();
	t_lan_restart_and_stop();
	t_bench_out();
	t_bench_in();
	t_stray_2xx();
	t_stop_order();
	t_cs_mo_early();
	t_cs_mo_no_early();
	t_cs_mo_failures();
	t_cs_mt();
	t_cs_mt_other();
	t_cs_mt_nodev();
	t_cs_pcm_lost();
	t_cs_select();
	t_cs_bench();
	if (t_skipped)
		printf("%d capture based parts skipped (IMSD_TEST_CAPDIR not set)\n", t_skipped);
	printf("test_b2b: %d checks, %d failures\n", t_checks, t_fails);
	return t_fails ? 1 : 0;
}
