/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Host tests of the SMS relay (run under ASan/UBSan by the Makefile): fake event loop with a virtual clock, the real
 * lan + registrar with fake LAN devices, a fake Gm side (struct smsrelay_ops mock, a fake endpoint + txn layer for
 * what the network sends). make -C src/smsrelay test
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "../ua/test_ua.h"
#include "../util/codec.h"
#include "../smscodec/tpdu.h"
#include "../sms/rp.h"
#include "smsfmt.h"
#include "smsrelay.h"
#include "../mms/mmspdu.h"
#include "../mms/t_vectors.h"
#include "../mms/wsp.h"
#include "../store/store.h"
#include <unistd.h>

int t_checks, t_fails;

/* ------------------------------------------------------------------ */
/* fixture                                                             */

#define MAXSENT 64
static struct {
	struct uaw w;
	struct fakeep *gm;
	struct txn_layer *gtl;
	struct smsrelay *sr;
	bool registered;
	char sim_smsc[32], card_psi[160], imsi[24];	/* what the host reads from the card */
	int send_rc;
	struct gm_sent {
		char ruri[256], call_id[128], extra[600], ct[64];
		uint8_t body[300];
		size_t blen;
		smsrelay_gm_resp_cb cb;
		void *arg;
	} sent[MAXSENT];
	int nsent;
	int branch;
	int lanmsg;
	struct store *st;		/* store mode (want_store): inline file backend in sdir, or a real writer thread */
	char sdir[96];
	struct {			/* WAP pushes handed to the host */
		int n;
		char from[48];
		unsigned port;
		uint8_t data[400];
		size_t len;
	} push;
} G;

static bool m_registered(void *ctx)
{
	(void)ctx;
	return G.registered;
}

static const char *m_smsc(void *ctx)
{
	(void)ctx;
	return G.sim_smsc;
}

static const char *m_psi(void *ctx)
{
	(void)ctx;
	return G.card_psi;
}

static const char *m_imsi(void *ctx)
{
	(void)ctx;
	return G.imsi;
}

static void m_own(void *ctx, char *out, size_t n)
{
	(void)ctx;
	snprintf(out, n, "+821051226862");
}

static void m_push(void *ctx, const char *from, unsigned port, const uint8_t *data, size_t len)
{
	(void)ctx;
	G.push.n++;
	snprintf(G.push.from, sizeof(G.push.from), "%s", from);
	G.push.port = port;
	G.push.len = len < sizeof(G.push.data) ? len : sizeof(G.push.data);
	memcpy(G.push.data, data, G.push.len);
}

/* the circuit switched side: what cssms would do (cssms_submit, cssms_in_done), driven by the tests */
static struct {
	bool active, push_active;
	int submit_rc;
	int nsubmit;
	struct cssms_submit last;
	char dest[32], text[4000];
	cssms_done_cb cb;
	void *arg;
	int ndone;
	unsigned done_id;
	bool done_taken;
	unsigned next_id;
	int nkick;
} CS;

static bool m_cs_active(void *ctx)
{
	(void)ctx;
	return CS.active;
}

static bool m_cs_push(void *ctx)
{
	(void)ctx;
	return CS.push_active;
}

static int m_cs_submit(void *ctx, const struct cssms_submit *q, cssms_done_cb cb, void *arg)
{
	(void)ctx;
	if (CS.submit_rc)
		return CS.submit_rc;
	CS.nsubmit++;
	CS.last = *q;
	snprintf(CS.dest, sizeof(CS.dest), "%s", q->dest);
	snprintf(CS.text, sizeof(CS.text), "%s", q->text);
	CS.cb = cb;
	CS.arg = arg;
	return 0;
}

static void m_cs_kick(void *ctx)
{
	(void)ctx;
	CS.nkick++;
}

static void m_cs_in_done(void *ctx, unsigned id, bool taken)
{
	(void)ctx;
	CS.ndone++;
	CS.done_id = id;
	CS.done_taken = taken;
}

static int m_send(void *ctx, const struct smsrelay_gm_req *q, smsrelay_gm_resp_cb cb, void *arg)
{
	struct gm_sent *s;

	(void)ctx;
	if (G.send_rc)
		return G.send_rc;
	if (G.nsent >= MAXSENT)
		return -1;
	s = &G.sent[G.nsent++];
	snprintf(s->ruri, sizeof(s->ruri), "%s", q->ruri);
	snprintf(s->call_id, sizeof(s->call_id), "%s", q->call_id);
	snprintf(s->extra, sizeof(s->extra), "%s", q->extra ? q->extra : "");
	snprintf(s->ct, sizeof(s->ct), "%s", q->content_type);
	memcpy(s->body, q->body, q->body_len);
	s->blen = q->body_len;
	s->cb = cb;
	s->arg = arg;
	return 0;
}

/* the network's SIP answer to the i-th request we sent */
static void m_answer(int i, int status)
{
	smsrelay_gm_resp_cb cb = G.sent[i].cb;

	G.sent[i].cb = NULL;
	cb(G.sent[i].arg, status, NULL);
}

static void gm_thunk(struct txn_layer *tl, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
		     const struct sip_msg *req, void *arg)
{
	(void)tl; (void)arg;
	if (!st)
		return;
	if (!smsrelay_on_gm_request(G.sr, st, ep, src, req)) {
		struct sip_resp_parts p = { .status = 415 };

		txn_server_reply(st, &p);
	}
}

/* store mode: the LAN registrar events go to the store, as the core module does it in the daemon */
static bool want_store, store_thread, store_noload;
static lan_binding_cb orig_binding;

static void store_binding(struct lan *l, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why, void *arg)
{
	if (orig_binding)
		orig_binding(l, ev, b, why, arg);
	if (G.st)
		store_on_binding(G.st, ev, b, why);
}

static void store_tweak(struct lan_cfg *c)
{
	orig_binding = c->on_binding;
	c->on_binding = store_binding;
}

static int64_t st_wall(void *ctx)
{
	(void)ctx;
	return 1795134300;
}

/* settle: the inline backend's completions, then the timers due now */
static void ssettle(void)
{
	int i;

	for (i = 0; i < 12; i++) {
		if (G.st)
			store_sync(G.st);
		evfake_advance(0);
	}
}

static void world(void (*tweak)(struct smsrelay_cfg *c), int ndev)
{
	struct smsrelay_cfg c;
	struct smsrelay_ops ops = { .registered = m_registered, .send = m_send, .smsc = m_smsc, .sms_psi = m_psi, .imsi = m_imsi, .push = m_push, .own_number = m_own,
				    .cs_active = m_cs_active, .cs_submit = m_cs_submit, .push_active = m_cs_push, .cs_in_done = m_cs_in_done, .cs_kick = m_cs_kick };
	struct txn_cfg tc;
	struct lan_hooks h;
	int k;

	char sdir[96] = "";

	if (G.sdir[0])
		snprintf(sdir, sizeof(sdir), "%s", G.sdir);	/* a restart of the same store */
	memset(&G, 0, sizeof(G));
	memset(&CS, 0, sizeof(CS));
	snprintf(G.sdir, sizeof(G.sdir), "%s", sdir);
	G.registered = true;
	snprintf(G.sim_smsc, sizeof(G.sim_smsc), "+821020921821");
	snprintf(G.imsi, sizeof(G.imsi), "450061051226862");
	uaw_init(&G.w, want_store ? store_tweak : NULL, false);
	if (want_store) {
		struct store_cfg sc;
		struct store_ops so;

		store_cfg_defaults(&sc);
		if (!G.sdir[0]) {
			snprintf(G.sdir, sizeof(G.sdir), "/tmp/imsd-sms-store-XXXXXX");
			CHECK(mkdtemp(G.sdir) != NULL);
		}
		snprintf(sc.dir, sizeof(sc.dir), "%s", G.sdir);
		memset(&so, 0, sizeof(so));
		so.wall = st_wall;
		so.inline_io = !store_thread;
		G.st = store_new(&sc, &so);
		CHECK(G.st != NULL);
		ops.store = G.st;
		if (store_thread) {
			int k;

			for (k = 0; k < 500 && !store_usable(G.st); k++) {
				usleep(1000);
				store_sync(G.st);
			}
		} else if (!store_noload) {
			ssettle();
		}
	}
	G.gm = fakeep_new("gm", false, NULL);
	memset(&tc, 0, sizeof(tc));
	tc.on_request = gm_thunk;
	G.gtl = txn_layer_new(&tc);
	txn_layer_attach(G.gtl, G.gm->ep);
	smsrelay_cfg_defaults(&c);
	c.rp_mr_start = 0xae;
	c.tp_mr_start = 0x14;
	c.concat_ref_start = 0x30;
	if (tweak)
		tweak(&c);
	G.sr = smsrelay_new(G.w.lan, &c, &ops);
	memset(&h, 0, sizeof(h));
	h.on_message = smsrelay_on_lan_message;
	h.arg = G.sr;
	lan_set_hooks(G.w.lan, &h);
	for (k = 1; k <= ndev; k++)
		dev_register(&G.w, k);
	fakeep_clear(G.w.f);
}

static void unworld(void)
{
	smsrelay_free(G.sr);
	txn_layer_free(G.gtl);
	fakeep_free(G.gm);
	if (G.st) {
		store_free(G.st);		/* before uaw_fini: that resets the fake event loop, which owns the store's timers */
		G.st = NULL;
	}
	uaw_fini(&G.w);
}

/* the store world is gone for good (its directory is removed) */
static void unworld_final(void)
{
	char cmd[160];

	unworld();
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", G.sdir);
	if (G.sdir[0] && system(cmd))
		CHECK(0);
	G.sdir[0] = 0;
}

/* a device that declares Accept */
static void dev_register_accept(int k, const char *accept)
{
	char ct[128], cid[32], ex[160];

	snprintf(ct, sizeof(ct), "<sip:u%d@%s:5060>;expires=600", k, dev_ip(k));
	snprintf(cid, sizeof(cid), "dev%d-reg", k);
	snprintf(ex, sizeof(ex), "User-Agent: TestPhone\r\nAccept: %s\r\n", accept);
	uaw_rx(&G.w, dev_ip(k), 5060, mk_register(dev_ip(k), ct, 1, cid, -1, ex));
}

/* a device with feature tags (and, with ip != NULL, at another address) */
static void dev_register_feat(int k, const char *params)
{
	char ct[200], cid[32];

	snprintf(ct, sizeof(ct), "<sip:u%d@%s:5060>%s;expires=600", k, dev_ip(k), params);
	snprintf(cid, sizeof(cid), "dev%d-reg", k);
	uaw_rx(&G.w, dev_ip(k), 5060, mk_register(dev_ip(k), ct, 1, cid, -1, "User-Agent: TestPhone\r\n"));
}

/* ---- network side injection ---- */
static void gm_rx(const char *call_id, const uint8_t *body, size_t n, const char *extra, const char *ct)
{
	char buf[1500];
	struct addr src;
	int l;

	G.branch++;
	l = snprintf(buf, sizeof(buf),
		     "MESSAGE sip:01051226862@[2001:db8::1]:5060 SIP/2.0\r\n"
		     "Via: SIP/2.0/UDP [2001:db8::53]:1357;branch=z9hG4bKgm%d;rport\r\n"
		     "Max-Forwards: 66\r\nTo: <sip:01051226862@lte-lguplus.co.kr>\r\n"
		     "From: <sip:ipsmgw.lte-lguplus.co.kr>;tag=az%d\r\nCall-ID: %s\r\nCSeq: 512124776 MESSAGE\r\n"
		     "Content-Type: %s\r\n%sP-Asserted-Identity: <sip:ipsmgw.lte-lguplus.co.kr>\r\n"
		     "Content-Length: %zu\r\n\r\n",
		     G.branch, G.branch, call_id, ct ? ct : "application/vnd.3gpp.sms", extra ? extra : "", n);
	memcpy(buf + l, body, n);
	addr_set(&src, "2001:db8::53", 7539);
	fakeep_rx_n(G.gm, &src, buf, l + n);
}

static void gm_rx_hex(const char *call_id, const char *hex, const char *extra)
{
	uint8_t b[300];
	int n = hex_decode(hex, b, sizeof(b));

	CHECK(n > 0);
	gm_rx(call_id, b, n, extra, NULL);
}

/* ---- LAN side ---- */
static const char *LAN_SRV = "192.168.68.1";

/* a MESSAGE from device k; returns the Call-ID (static) */
static const char *lan_msg(int k, const char *ruri, const char *ct, const char *body, size_t blen)
{
	static char cids[16][32];
	char *cid = cids[G.lanmsg & 15];
	char buf[3000];
	int l;

	snprintf(cid, 32, "lm%d@dev", ++G.lanmsg);
	if (ct)
		l = snprintf(buf, sizeof(buf),
			     "MESSAGE %s SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bKlm%d;rport\r\n"
			     "From: <sip:alice@%s>;tag=t%d\r\nTo: <%s>\r\nCall-ID: %s\r\nCSeq: 1 MESSAGE\r\nMax-Forwards: 70\r\n"
			     "Content-Type: %s\r\nContent-Length: %zu\r\n\r\n",
			     ruri, dev_ip(k), G.lanmsg, LAN_SRV, G.lanmsg, ruri, cid, ct, blen);
	else
		l = snprintf(buf, sizeof(buf),
			     "MESSAGE %s SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bKlm%d;rport\r\n"
			     "From: <sip:alice@%s>;tag=t%d\r\nTo: <%s>\r\nCall-ID: %s\r\nCSeq: 1 MESSAGE\r\nMax-Forwards: 70\r\n"
			     "Content-Length: %zu\r\n\r\n",
			     ruri, dev_ip(k), G.lanmsg, LAN_SRV, G.lanmsg, ruri, cid, blen);
	memcpy(buf + l, body, blen);
	{
		struct addr a = ua_addr(dev_ip(k), 5060);

		fakeep_rx_n(G.w.f, &a, buf, l + blen);
	}
	return cid;
}

static const char *lan_text(int k, const char *ruri, const char *body)
{
	return lan_msg(k, ruri, "text/plain; charset=utf-8", body, strlen(body));
}

/* index of the last response sent to the LAN with that Call-ID, -1 */
static int lresp(const char *call_id)
{
	int i, r = -1;

	for (i = 0; i < G.w.f->nsent; i++) {
		struct sip_msg m;

		if (fakeep_parse(G.w.f, i, &m))
			continue;
		if (m.is_resp && sip_hdr(&m, "Call-ID", 0) && !strcmp(sip_hdr(&m, "Call-ID", 0), call_id))
			r = i;
		sip_msg_free(&m);
	}
	return r;
}

static int lstat(const char *call_id)
{
	int i = lresp(call_id);

	return i < 0 ? 0 : sent_status(G.w.f, i);
}

static int lnresp(const char *call_id, int status)
{
	int i, n = 0;

	for (i = 0; i < G.w.f->nsent; i++) {
		struct sip_msg m;

		if (fakeep_parse(G.w.f, i, &m))
			continue;
		if (m.is_resp && m.status == status && sip_hdr(&m, "Call-ID", 0) && !strcmp(sip_hdr(&m, "Call-ID", 0), call_id))
			n++;
		sip_msg_free(&m);
	}
	return n;
}

static const char *lhdr(const char *call_id, const char *h, char *out, size_t n)
{
	int i = lresp(call_id);

	out[0] = 0;
	if (i >= 0)
		sent_hdr(G.w.f, i, h, out, n);
	return out;
}

static int dev_count(int k)
{
	int n = 0;

	while (find_sent(G.w.f, dev_ip(k), 5060, "MESSAGE", n) >= 0)
		n++;
	return n;
}

/* answer the newest MESSAGE that device k received */
static void dev_answer(int k, int status)
{
	int n = dev_count(k), i;

	CHECK(n > 0);
	i = find_sent(G.w.f, dev_ip(k), 5060, "MESSAGE", n - 1);
	dev_reply_idx(&G.w, i, k, status, "tg", NULL);
}

/* nth MESSAGE received by device k, parsed; caller frees */
static bool dev_parse(int k, int nth, struct sip_msg *m)
{
	int i = find_sent(G.w.f, dev_ip(k), 5060, "MESSAGE", nth);

	if (i < 0)
		return false;
	return !fakeep_parse(G.w.f, i, m);
}

static const char *bodystr(const struct sip_msg *m)
{
	return (const char *)m->body;
}

static bool has(const char *hay, const char *needle)
{
	return strstr(hay, needle) != NULL;
}

static int gm_status(int i)
{
	return sent_status(G.gm, i);
}

static const char *hexs(const uint8_t *b, size_t n)
{
	static char h[8][700];
	static int k;
	char *o = h[k++ & 7];

	hex_encode(b, n, o);
	return o;
}

#define CAP_UCS2 "013e0791280102298112" "00" "19" "040b811050216268f2" "0008" "62110250616463" "06" "d14cc2a4d2b8"
#define CAP_UCS2_3F "013f0791280102298112" "00" "19" "040b811050216268f2" "0008" "62110250616463" "06" "d14cc2a4d2b8"
#define CAP_GSM7 "01680791280102298172" "00" "26" "040b811050216268f2" "0000" "62110250731463" "15" "e9f6bc1e0685e1ad747b0e9ab7e7207a794e07"
#define CAP_MO_RP "00ae0007912801022981122001" "14" "0b811050216268f2" "0000" "15" "e9f6bc1e0685e1ad747b0e9ab7e7207a794e07"

/* ------------------------------------------------------------------ */
/* unit tests of the helpers                                           */

static void t_rpx(void)
{
	struct rp_addr a, b;
	char s[40];
	uint8_t out[64], e[4];
	struct rp_data d;
	const uint8_t *tp;
	size_t tn;
	uint8_t in[300];
	int n;

	CHECK(!rp_addr_from_str("+821020921821", &a));
	CHECK_EQ(a.len, 7);
	CHECK_STR(hexs(a.b, a.len), "91280102298112");
	CHECK(!rp_addr_to_str(&a, s, sizeof(s)));
	CHECK_STR(s, "+821020921821");
	CHECK(!rp_addr_from_str("01051226862", &b));
	CHECK_STR(hexs(b.b, b.len), "811050216268f2");
	CHECK(!rp_addr_to_str(&b, s, sizeof(s)));
	CHECK_STR(s, "01051226862");
	CHECK(rp_addr_from_str("", &b) < 0);
	CHECK(rp_addr_from_str("+", &b) < 0);
	CHECK(rp_addr_from_str("12a", &b) < 0);
	CHECK(rp_addr_from_str("123456789012345678901", &b) < 0);
	CHECK(!rp_addr_from_str("*100#", &b));
	CHECK(!rp_addr_to_str(&b, s, sizeof(s)));
	CHECK_STR(s, "*100#");
	CHECK(rp_addr_to_str(&a, s, 5) < 0);

	n = hex_decode(CAP_UCS2, in, sizeof(in));
	CHECK(!rp_parse_data(in, n, &d));
	CHECK_EQ(d.mti, 1);
	CHECK_EQ(d.mr, 0x3e);
	CHECK_EQ(d.oa.len, 7);
	CHECK_EQ(d.da.len, 0);
	CHECK_EQ(d.ud_len, 25);
	CHECK_EQ(d.ud[0], 0x04);
	CHECK(rp_parse_data(in, n - 1, &d) < 0);	/* UD length claims more than there is */
	CHECK(rp_parse_data(in, 4, &d) < 0);
	in[0] = 0x03;
	CHECK(rp_parse_data(in, n, &d) < 0);

	n = hex_decode(CAP_MO_RP, in, sizeof(in));
	CHECK(!rp_parse_data(in, n, &d));
	CHECK_EQ(d.mti, 0);
	CHECK_EQ(d.oa.len, 0);
	CHECK_EQ(d.da.len, 7);
	CHECK_EQ(d.ud_len, 32);
	n = rp_build_data_ms_n(0xae, &d.da, d.ud, d.ud_len, out, sizeof(out));
	CHECK_EQ(n, 44);
	CHECK_STR(hexs(out, n), CAP_MO_RP);
	CHECK(rp_build_data_ms_n(1, &d.da, d.ud, d.ud_len, out, 20) < 0);
	CHECK(rp_build_data_ms_n(1, &d.da, d.ud, 234, out, sizeof(out)) < 0);

	rp_build_error(7, 22, e);
	CHECK_STR(hexs(e, 4), "04070116");

	n = hex_decode("03ae4109010062110250731463", in, sizeof(in));
	CHECK(!rp_report_tpdu(in, n, &tp, &tn));
	CHECK_EQ(tn, 9);
	CHECK_EQ(tp[0], 1);
	n = hex_decode("03ae", in, sizeof(in));
	CHECK(!rp_report_tpdu(in, n, &tp, &tn));
	CHECK(tp == NULL && tn == 0);
	n = hex_decode("05ae011b", in, sizeof(in));
	CHECK(!rp_report_tpdu(in, n, &tp, &tn));
	n = hex_decode("05ae021b0041", in, sizeof(in));
	CHECK(rp_report_tpdu(in, n, &tp, &tn) < 0);
	n = hex_decode("05ae0116410a", in, sizeof(in));
	CHECK(rp_report_tpdu(in, n, &tp, &tn) < 0);
	CHECK_STR(rp_cause_text(22), "memory capacity exceeded");
	CHECK_STR(rp_cause_text(200), "unspecified cause");
	CHECK(rp_cause_temporary(42) && !rp_cause_temporary(1));
}

static void t_fmt(void)
{
	char o[64], u[SMSFMT_USER_MAX], d[SMSFMT_DISP_MAX];
	struct tp_addr a;
	struct tp_scts t;
	uint8_t p[7] = { 0x62, 0x11, 0x02, 0x50, 0x73, 0x14, 0x63 };

	CHECK_EQ(smsfmt_dest("sip:01012345678@192.168.68.1", o, sizeof(o)), 0);
	CHECK_STR(o, "01012345678");
	CHECK_EQ(smsfmt_dest("sip:+8210-1234-5678@x;user=phone", o, sizeof(o)), 0);
	CHECK_STR(o, "+821012345678");
	CHECK_EQ(smsfmt_dest("tel:+82-10-1234-5678;phone-context=x", o, sizeof(o)), 0);
	CHECK_STR(o, "+821012345678");
	CHECK_EQ(smsfmt_dest("sip:%2B8210%20123%2D4567@x", o, sizeof(o)), 0);
	CHECK_STR(o, "+82101234567");
	CHECK_EQ(smsfmt_dest("sip:*123%23@x", o, sizeof(o)), 0);
	CHECK_STR(o, "*123#");
	CHECK_EQ(smsfmt_dest("sip:bob@x", o, sizeof(o)), SMSFMT_E_NOTNUM);
	CHECK_EQ(smsfmt_dest("sip:010x@x", o, sizeof(o)), SMSFMT_E_NOTNUM);
	CHECK_EQ(smsfmt_dest("sip:192.168.68.1", o, sizeof(o)), SMSFMT_E_NOTNUM);
	CHECK_EQ(smsfmt_dest("http://x", o, sizeof(o)), SMSFMT_E_NOTNUM);
	CHECK_EQ(smsfmt_dest("sip:010+12@x", o, sizeof(o)), SMSFMT_E_NOTNUM);
	CHECK_EQ(smsfmt_dest("sip:+@x", o, sizeof(o)), SMSFMT_E_LENGTH);
	CHECK_EQ(smsfmt_dest("sip:123456789012345678901@x", o, sizeof(o)), SMSFMT_E_LENGTH);
	CHECK_EQ(smsfmt_dest("sip:%zz@x", o, sizeof(o)), SMSFMT_E_NOTNUM);

	memset(&a, 0, sizeof(a));
	snprintf(a.str, sizeof(a.str), "+821012345678");
	CHECK_EQ(smsfmt_sender(&a, u, sizeof(u), d, sizeof(d)), 0);
	CHECK_STR(u, "+821012345678");
	CHECK_STR(d, "");
	snprintf(a.str, sizeof(a.str), "*12#");
	smsfmt_sender(&a, u, sizeof(u), d, sizeof(d));
	CHECK_STR(u, "*12%23");
	a.alnum = true;
	snprintf(a.str, sizeof(a.str), "KT \"Info\"<x>\\\n");
	CHECK_EQ(smsfmt_sender(&a, u, sizeof(u), d, sizeof(d)), 1);
	CHECK_STR(u, "alnum.KT--Info--x---");
	CHECK_STR(d, "KT ?Info??x???");

	tp_scts_decode(p, &t);
	CHECK(!smsfmt_iso(&t, o, sizeof(o)));
	CHECK_STR(o, "2026-11-20T05:37:41+09:00");
	CHECK(!smsfmt_date(t.epoch, o, sizeof(o)));
	CHECK_STR(o, "Thu, 19 Nov 2026 20:37:41 GMT");
	t.tz_quarters = -22;
	smsfmt_iso(&t, o, sizeof(o));
	CHECK_STR(o, "2026-11-20T05:37:41-05:30");
	t.valid = false;
	CHECK(smsfmt_iso(&t, o, sizeof(o)) < 0);
	smsfmt_quote_safe("abcdefghijklmnop", o, 10);
	CHECK_STR(o, "abcdef...");
	smsfmt_quote_safe("a\"b\\c\r\n", o, sizeof(o));
	CHECK_STR(o, "a?b?c??");
}

/* ------------------------------------------------------------------ */
/* MT                                                                  */

static void check_rp_reply(int i, uint8_t mr, const char *call_id, bool ack, uint8_t cause)
{
	CHECK(i < G.nsent);
	if (i >= G.nsent)
		return;
	CHECK_STR(G.sent[i].ruri, "sip:ipsmgw.lte-lguplus.co.kr");
	CHECK_STR(G.sent[i].ct, "application/vnd.3gpp.sms");
	if (ack) {
		CHECK_EQ(G.sent[i].blen, 2);
		CHECK_EQ(G.sent[i].body[0], 0x02);
	} else {
		CHECK_EQ(G.sent[i].blen, 4);
		CHECK_EQ(G.sent[i].body[0], 0x04);
		CHECK_EQ(G.sent[i].body[2], 0x01);
		CHECK_EQ(G.sent[i].body[3], cause);
	}
	CHECK_EQ(G.sent[i].body[1], mr);
	CHECK(has(G.sent[i].extra, "Allow: MESSAGE\r\n"));
	CHECK(has(G.sent[i].extra, "Request-Disposition: no-fork\r\n"));
	CHECK(has(G.sent[i].extra, "Accept-Contact: *;+g.3gpp.smsip\r\n"));
	if (call_id) {
		char w[160];

		snprintf(w, sizeof(w), "In-Reply-To: %s\r\n", call_id);
		CHECK(has(G.sent[i].extra, w));
	}
}

static void t_mt_ucs2_gsm7(void)
{
	struct sip_msg m;
	char v[300];
	struct smsrelay_status s;
	int k;

	world(NULL, 3);
	gm_rx_hex("NTEyMTI0@ims", CAP_UCS2, "In-Reply-To: x\r\n");
	CHECK_EQ(gm_status(0), 200);
	CHECK_EQ(G.nsent, 0);			/* the RP reply waits for the LAN */
	for (k = 1; k <= 3; k++)
		CHECK_EQ(dev_count(k), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK_STR(sip_hdr(&m, "Content-Type", 0), "text/plain; charset=utf-8");
	CHECK(has(sip_hdr(&m, "From", 0), "<sip:01051226862@"));
	CHECK_STR(sip_hdr(&m, "Date", 0), "Thu, 19 Nov 2026 20:16:46 GMT");
	CHECK_STR(sip_hdr(&m, "X-SMS-Timestamp", 0), "2026-11-20T05:16:46+09:00");
	CHECK_STR(sip_hdr(&m, "X-SMS-SMSC", 0), "+821020921821");
	CHECK(!sip_hdr(&m, "X-SMS-Class", 0));
	CHECK(!sip_hdr(&m, "X-SMS-Concat", 0));
	CHECK_STR(bodystr(&m), "\xed\x85\x8c\xec\x8a\xa4\xed\x8a\xb8");	/* "테스트" */
	CHECK(has(sip_hdr(&m, "To", 0), "sip:alice@"));
	sip_msg_free(&m);
	dev_answer(1, 200);
	CHECK_EQ(G.nsent, 0);			/* the others are still open */
	dev_answer(2, 486);
	dev_answer(3, 480);
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x3e, "NTEyMTI0@ims", true, 0);
	(void)v;
	m_answer(0, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_received, 1);
	CHECK_EQ(s.mt_delivered, 1);
	CHECK_EQ(s.mt_lost_no_client + s.mt_lost_failed, 0);
	CHECK_STR(s.smsc, "+821020921821");		/* the SIM's: an RP-OA is not learned */
	CHECK_STR(s.smsc_source, "sim");
	fakeep_clear(G.w.f);

	gm_rx_hex("second@ims", CAP_GSM7, NULL);
	CHECK(dev_parse(2, 0, &m));
	CHECK_STR(bodystr(&m), "imsua ap-ims sms test");
	CHECK_STR(sip_hdr(&m, "X-SMS-SMSC", 0), "+821020921827");
	sip_msg_free(&m);
	dev_answer(1, 200);
	dev_answer(2, 200);
	dev_answer(3, 200);
	CHECK_EQ(G.nsent, 2);
	check_rp_reply(1, 0x68, "second@ims", true, 0);
	m_answer(1, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_delivered, 2);
	CHECK_STR(s.smsc, "+821020921821");		/* the RP-OA is only reported to the clients */
	CHECK(s.last_error[0] == 0);
	unworld();
}

static void t_mt_nobody(void)
{
	struct smsrelay_status s;

	world(NULL, 0);
	gm_rx_hex("c1@ims", CAP_GSM7, NULL);
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x68, "c1@ims", true, 0);
	m_answer(0, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_lost_no_client, 1);
	CHECK_EQ(s.mt_delivered, 0);
	CHECK(has(s.last_error, "lost"));
	unworld();
}

static void pol22(struct smsrelay_cfg *c)
{
	c->lost_policy = SMSRELAY_LOST_RPERROR22;
}

static void t_mt_nobody_error22(void)
{
	world(pol22, 0);
	gm_rx_hex("c2@ims", CAP_GSM7, NULL);
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x68, "c2@ims", false, 22);
	m_answer(0, 202);
	/* the retransmission is answered the same way, still without delivery */
	gm_rx_hex("c2b@ims", CAP_GSM7, NULL);
	CHECK_EQ(G.nsent, 2);
	check_rp_reply(1, 0x68, "c2b@ims", false, 22);
	m_answer(1, 202);
	unworld();

	/* with a registered client that refuses: still an RP-ACK even under the alternative policy */
	world(pol22, 1);
	gm_rx_hex("c3@ims", CAP_GSM7, NULL);
	dev_answer(1, 486);
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x68, "c3@ims", true, 0);
	m_answer(0, 202);
	unworld();
}

static void t_mt_timeout(void)
{
	struct smsrelay_status s;

	world(NULL, 3);
	gm_rx_hex("t1@ims", CAP_GSM7, NULL);
	dev_answer(2, 200);
	evfake_advance(4900);
	CHECK_EQ(G.nsent, 0);
	evfake_advance(200);			/* lan_wait_ms 5000: the other two never answered */
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x68, "t1@ims", true, 0);
	m_answer(0, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_delivered, 1);
	CHECK_EQ(s.mt_lost_failed, 0);
	unworld();

	world(NULL, 2);
	gm_rx_hex("t2@ims", CAP_GSM7, NULL);
	evfake_advance(5100);
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x68, "t2@ims", true, 0);
	m_answer(0, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_delivered, 0);
	CHECK_EQ(s.mt_lost_failed, 1);
	evfake_advance(70000);			/* the detached forks finish quietly */
	unworld();
}

static void t_mt_dup(void)
{
	struct smsrelay_status s;

	world(NULL, 2);
	gm_rx_hex("d1@ims", CAP_UCS2, NULL);
	/* retransmitted while the first copy is still being delivered: ignored */
	gm_rx_hex("d1b@ims", CAP_UCS2, NULL);
	CHECK_EQ(G.nsent, 0);
	CHECK_EQ(dev_count(1), 1);
	dev_answer(1, 200);
	dev_answer(2, 200);
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x3e, "d1@ims", true, 0);
	m_answer(0, 202);
	/* our RP-ACK was lost: the network sends it again */
	gm_rx_hex("d1c@ims", CAP_UCS2, NULL);
	CHECK_EQ(G.nsent, 2);
	check_rp_reply(1, 0x3e, "d1c@ims", true, 0);
	m_answer(1, 202);
	CHECK_EQ(dev_count(1), 1);
	CHECK_EQ(dev_count(2), 1);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_duplicates, 2);
	CHECK_EQ(s.mt_delivered, 1);
	/* after the cache entry expired it is a new message */
	evfake_advance(121000);
	gm_rx_hex("d1d@ims", CAP_UCS2, NULL);
	CHECK_EQ(dev_count(1), 2);
	dev_answer(1, 200);
	dev_answer(2, 200);
	m_answer(2, 202);
	/* same MR but different content is not a duplicate */
	gm_rx_hex("d2@ims", "013e0791280102298112" "00" "19" "040b811050216268f2" "0008" "62110250616463" "06" "d14cc2a4d2b9", NULL);
	CHECK_EQ(dev_count(1), 3);
	dev_answer(1, 200);
	dev_answer(2, 200);
	m_answer(3, 202);
	unworld();
}

/* SMS-DELIVER with UCS2 text and an optional UDH, OA given as digits or alphanumeric */
static int mk_deliver(uint8_t *out, const char *oa_digits, const uint8_t *oa_raw, size_t oa_raw_len, int oa_len_field,
		      uint8_t toa, const uint8_t *udh, size_t udhn, const uint8_t *ucs2, size_t un, uint8_t dcs, uint8_t mr)
{
	uint8_t t[200];
	size_t p = 0, i;
	struct rp_addr a;
	int n = 0;

	t[p++] = udh ? 0x44 : 0x04;
	if (oa_digits) {
		size_t nd = strlen(oa_digits);

		t[p++] = (uint8_t)nd;
		t[p++] = toa;
		rp_addr_from_str(oa_digits, &a);
		memcpy(t + p, a.b + 1, a.len - 1);
		p += a.len - 1;
	} else {
		t[p++] = (uint8_t)oa_len_field;
		t[p++] = toa;
		memcpy(t + p, oa_raw, oa_raw_len);
		p += oa_raw_len;
	}
	t[p++] = 0;
	t[p++] = dcs;
	{
		static const uint8_t scts[7] = { 0x62, 0x11, 0x02, 0x50, 0x61, 0x64, 0x63 };

		memcpy(t + p, scts, 7);
		p += 7;
	}
	t[p++] = (uint8_t)((udh ? udhn : 0) + un);
	if (udh) {
		memcpy(t + p, udh, udhn);
		p += udhn;
	}
	memcpy(t + p, ucs2, un);
	p += un;
	/* RP-DATA n->ms: 01 MR 07 91 SMSC | 00 | len TPDU */
	out[n++] = 0x01;
	out[n++] = mr;
	out[n++] = 0x07;
	memcpy(out + n, "\x91\x28\x01\x02\x29\x81\x12", 7);
	n += 7;
	out[n++] = 0;
	out[n++] = (uint8_t)p;
	for (i = 0; i < p; i++)
		out[n++] = t[i];
	return n;
}

static void t_mt_concat(void)
{
	uint8_t rp[200];
	/* "안녕" */
	static const uint8_t txt[4] = { 0xc5, 0x48, 0xb1, 0x55 };
	uint8_t udh[6] = { 0x05, 0x00, 0x03, 0x12, 0x03, 0x02 };
	struct sip_msg m;
	int n, i;
	char cid[32];

	world(NULL, 2);
	for (i = 1; i <= 3; i++) {
		udh[5] = (uint8_t)i;
		n = mk_deliver(rp, "01051226862", NULL, 0, 0, 0x81, udh, 6, txt, 4, 0x08, (uint8_t)(10 + i));
		snprintf(cid, sizeof(cid), "cc%d@ims", i);
		gm_rx(cid, rp, n, NULL, NULL);
		CHECK_EQ(dev_count(1), i);
		CHECK(dev_parse(1, i - 1, &m));
		{
			char want[64], b[64];

			snprintf(want, sizeof(want), "ref=18;seq=%d;total=3", i);
			CHECK_STR(sip_hdr(&m, "X-SMS-Concat", 0), want);
			snprintf(b, sizeof(b), "(%d/3) \xec\x95\x88\xeb\x85\x95", i);
			CHECK_STR(bodystr(&m), b);
		}
		sip_msg_free(&m);
		dev_answer(1, 200);
		dev_answer(2, 200);
		CHECK_EQ(G.nsent, i);
		check_rp_reply(i - 1, (uint8_t)(10 + i), cid, true, 0);
		m_answer(i - 1, 202);
	}
	unworld();
}

static void noprefix(struct smsrelay_cfg *c)
{
	c->concat_prefix = false;
}

static void t_mt_concat_noprefix(void)
{
	uint8_t rp[200];
	static const uint8_t txt[4] = { 0xc5, 0x48, 0xb1, 0x55 };
	const uint8_t udh[6] = { 0x05, 0x00, 0x03, 0x12, 0x02, 0x02 };
	struct sip_msg m;
	int n;

	world(noprefix, 1);
	n = mk_deliver(rp, "01051226862", NULL, 0, 0, 0x81, udh, 6, txt, 4, 0x08, 5);
	gm_rx("np@ims", rp, n, NULL, NULL);
	CHECK(dev_parse(1, 0, &m));
	CHECK_STR(sip_hdr(&m, "X-SMS-Concat", 0), "ref=18;seq=2;total=2");
	CHECK_STR(bodystr(&m), "\xec\x95\x88\xeb\x85\x95");
	sip_msg_free(&m);
	dev_answer(1, 200);
	m_answer(0, 202);
	unworld();
}

static void t_mt_alnum(void)
{
	uint8_t rp[200];
	static const uint8_t txt[4] = { 0xc5, 0x48, 0xb1, 0x55 };
	/* "Info\"x": 6 chars GSM 7-bit packed; the quote only has to survive sanitising */
	uint8_t packed[8];
	const char *name = "Info\"x";
	int bits = 0, i, n, nbytes;
	struct sip_msg m;
	char v[200];

	memset(packed, 0, sizeof(packed));
	for (i = 0; name[i]; i++, bits += 7) {
		unsigned c = (unsigned char)name[i];

		packed[bits / 8] |= (uint8_t)(c << (bits % 8));
		if (bits % 8 > 1)
			packed[bits / 8 + 1] |= (uint8_t)(c >> (8 - bits % 8));
	}
	nbytes = (bits + 7) / 8;
	world(NULL, 1);
	n = mk_deliver(rp, NULL, packed, nbytes, (bits + 3) / 4, 0xd0, NULL, 0, txt, 4, 0x08, 9);
	gm_rx("al@ims", rp, n, NULL, NULL);
	CHECK_EQ(dev_count(1), 1);
	CHECK(dev_parse(1, 0, &m));
	snprintf(v, sizeof(v), "%s", sip_hdr(&m, "From", 0));
	CHECK(has(v, "\"Info?x\""));
	CHECK(has(v, "<sip:alnum.Info-x@"));
	CHECK_STR(sip_hdr(&m, "X-SMS-Sender", 0), "Info?x");
	sip_msg_free(&m);
	dev_answer(1, 200);
	m_answer(0, 202);
	unworld();
}

static const char *SR_TPDU = "02" "2a" "0b811050216268f2" "62110250616463" "62110250626463" "00";

static void t_mt_status_report(void)
{
	char rp[200];
	struct smsrelay_status s;

	/* option off (default): acknowledged and logged only */
	world(NULL, 2);
	snprintf(rp, sizeof(rp), "0155" "0791280102298112" "00" "%02x%s", (unsigned)(strlen(SR_TPDU) / 2), SR_TPDU);
	gm_rx_hex("sr1@ims", rp, NULL);
	CHECK_EQ(dev_count(1), 0);
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x55, "sr1@ims", true, 0);
	m_answer(0, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_reports, 1);
	unworld();
}

static void reports_on(struct smsrelay_cfg *c)
{
	c->delivery_reports = true;
}

static void t_mt_status_report_notice(void)
{
	char rp[200];
	struct sip_msg m;

	world(reports_on, 2);
	snprintf(rp, sizeof(rp), "0155" "0791280102298112" "00" "%02x%s", (unsigned)(strlen(SR_TPDU) / 2), SR_TPDU);
	gm_rx_hex("sr2@ims", rp, NULL);
	CHECK_EQ(dev_count(1), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK(has(bodystr(&m), "delivered"));
	CHECK(has(bodystr(&m), "01051226862"));
	CHECK_STR(sip_hdr(&m, "X-SMS-Report", 0), "mr=42;status=0x00;final=yes");
	CHECK(has(sip_hdr(&m, "From", 0), "<sip:01051226862@"));
	sip_msg_free(&m);
	dev_answer(1, 200);
	dev_answer(2, 200);
	check_rp_reply(0, 0x55, "sr2@ims", true, 0);
	m_answer(0, 202);
	unworld();
}

static void t_mt_binary_accept(void)
{
	struct sip_msg m;
	uint8_t rp[200];
	/* SMS-DELIVER DCS 0x04 (8-bit), 5 data bytes */
	const char *tp = "04" "0b811050216268f2" "00" "04" "62110250616463" "05" "0102030405";
	char h[300];

	world(NULL, 0);
	dev_register_accept(1, "application/octet-stream, text/plain");
	dev_register_accept(2, "text/plain");
	dev_register(&G.w, 3);
	fakeep_clear(G.w.f);
	snprintf(h, sizeof(h), "0177" "0791280102298112" "00" "%02x%s", (unsigned)(strlen(tp) / 2), tp);
	(void)rp;
	gm_rx_hex("bin@ims", h, NULL);
	CHECK_EQ(dev_count(1), 1);
	CHECK_EQ(dev_count(2), 1);
	CHECK_EQ(dev_count(3), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK_STR(sip_hdr(&m, "Content-Type", 0), "application/octet-stream");
	CHECK_EQ(m.body_len, 5);
	CHECK(!memcmp(m.body, "\x01\x02\x03\x04\x05", 5));
	sip_msg_free(&m);
	CHECK(dev_parse(2, 0, &m));
	CHECK_STR(sip_hdr(&m, "Content-Type", 0), "text/plain; charset=utf-8");
	CHECK(has(bodystr(&m), "[binary SMS, 5 bytes, data coding 0x04] 0102030405"));
	sip_msg_free(&m);
	CHECK(dev_parse(3, 0, &m));		/* no Accept declared: not assumed to take binary */
	CHECK_STR(sip_hdr(&m, "Content-Type", 0), "text/plain; charset=utf-8");
	sip_msg_free(&m);
	dev_answer(1, 200);
	CHECK_EQ(G.nsent, 0);
	dev_answer(2, 486);
	dev_answer(3, 486);
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x77, "bin@ims", true, 0);
	m_answer(0, 202);
	unworld();
}

/* ---- WAP push (MMS notification) ---- */

/* a single binary SMS-DELIVER with port addressing (and optionally concatenation): RP-DATA bytes */
static int mk_push_sms(uint8_t *out, uint8_t mr, unsigned dport, const uint8_t *data, size_t dn, int concat_ref, int total, int seq)
{
	uint8_t udh[16];
	size_t k = 1;

	udh[k++] = 0x05; udh[k++] = 4; udh[k++] = (uint8_t)(dport >> 8); udh[k++] = (uint8_t)dport; udh[k++] = 0x23; udh[k++] = 0xf0;
	if (concat_ref >= 0) {
		udh[k++] = 0x00; udh[k++] = 3; udh[k++] = (uint8_t)concat_ref; udh[k++] = (uint8_t)total; udh[k++] = (uint8_t)seq;
	}
	udh[0] = (uint8_t)(k - 1);
	return mk_deliver(out, "0100000004", NULL, 0, 0, 0x81, udh, k, data, dn, 0x04, mr);
}

static void t_wap_push(void)
{
	struct smsrelay_status s;
	uint8_t notif[200];
	size_t nn = hex_decode(V_NOTIF_PUSH, notif, sizeof(notif));
	struct wsp_push p;
	struct mms_notif nf;
	int i;

	CHECK_EQ(nn, 127);
	/* the two captured RP-DATA: each is acknowledged at once, the message is handed on after the second; the LAN hears nothing */
	world(NULL, 1);
	gm_rx_hex("p1@ims", V_RPDU1, NULL);
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x2b, "p1@ims", true, 0);
	CHECK_EQ(G.push.n, 0);
	m_answer(0, 202);
	gm_rx_hex("p2@ims", V_RPDU2, NULL);
	CHECK_EQ(G.nsent, 2);
	check_rp_reply(1, 0x2c, "p2@ims", true, 0);
	m_answer(1, 202);
	CHECK_EQ(G.push.n, 1); CHECK_STR(G.push.from, "0100000004"); CHECK_EQ(G.push.port, 2948);
	CHECK_EQ(G.push.len, 127); CHECK(!memcmp(G.push.data, notif, 127));
	CHECK_EQ(wsp_parse_push(G.push.data, G.push.len, &p), 0);
	CHECK_STR(p.ct.type, "application/vnd.wap.mms-message");
	CHECK_EQ(mms_decode_notification(p.body, p.body_len, &nf), 0);
	CHECK_STR(nf.tid, "AvBt6f7q"); CHECK_STR(nf.location, "http://omammsc.uplus.co.kr:9095/?AvBt6f7q");
	CHECK_EQ(dev_count(1), 0);			/* no "binary SMS" notice */
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_push_segments, 2); CHECK_EQ(s.mt_push_messages, 1); CHECK_EQ(s.mt_delivered, 0); CHECK_EQ(s.mt_errors, 0);
	/* a retransmission of a segment (our RP-ACK was lost): acknowledged again, not assembled again */
	gm_rx_hex("p2b@ims", V_RPDU2, NULL);
	CHECK_EQ(G.nsent, 3);
	check_rp_reply(2, 0x2c, "p2b@ims", true, 0);
	m_answer(2, 202);
	CHECK_EQ(G.push.n, 1);
	unworld();

	/* out of order: the second segment first */
	world(NULL, 1);
	gm_rx_hex("o2@ims", V_RPDU2, NULL);
	CHECK_EQ(G.nsent, 1); CHECK_EQ(G.push.n, 0);
	gm_rx_hex("o1@ims", V_RPDU1, NULL);
	CHECK_EQ(G.nsent, 2); CHECK_EQ(G.push.n, 1); CHECK_EQ(G.push.len, 127); CHECK(!memcmp(G.push.data, notif, 127));
	CHECK_EQ(dev_count(1), 0);
	unworld();

	/* a missing segment: after 5 minutes the first one is dropped, a late second one does not complete anything */
	world(NULL, 1);
	gm_rx_hex("m1@ims", V_RPDU1, NULL);
	evfake_advance(290000);
	gm_rx_hex("m2@ims", V_RPDU2, NULL);			/* inside the window: completes */
	CHECK_EQ(G.push.n, 1);
	unworld();
	world(NULL, 1);
	gm_rx_hex("t1@ims", V_RPDU1, NULL);
	evfake_advance(301000);
	gm_rx_hex("t2@ims", V_RPDU2, NULL);
	CHECK_EQ(G.nsent, 2); CHECK_EQ(G.push.n, 0);		/* both acknowledged, nothing assembled */
	smsrelay_get_status(G.sr, &s); CHECK_EQ(s.mt_push_messages, 0);
	/* ... and the retransmission of segment 1 now completes the pair (a new assembly) */
	evfake_advance(130000);
	gm_rx_hex("t1b@ims", V_RPDU1, NULL);
	CHECK_EQ(G.push.n, 1);
	unworld();

	/* single segment push (no concatenation) to the push port */
	world(NULL, 1);
	{
		uint8_t rp[260];
		int n = mk_push_sms(rp, 0x51, 2948, notif, 117, -1, 0, 0);

		gm_rx("s1@ims", rp, (size_t)n, NULL, NULL);
		CHECK_EQ(G.nsent, 1); check_rp_reply(0, 0x51, "s1@ims", true, 0);
		CHECK_EQ(G.push.n, 1); CHECK_EQ(G.push.len, 117);
		CHECK_EQ(dev_count(1), 0);
		/* the push port 2949 (secure, WTLS): acknowledged and dropped */
		n = mk_push_sms(rp, 0x52, 2949, notif, 20, -1, 0, 0);
		gm_rx("s2@ims", rp, (size_t)n, NULL, NULL);
		CHECK_EQ(G.nsent, 2); check_rp_reply(1, 0x52, "s2@ims", true, 0);
		CHECK_EQ(G.push.n, 1); CHECK_EQ(dev_count(1), 0);
		/* another port with port addressing keeps the old behaviour: the binary notice goes to the LAN */
		n = mk_push_sms(rp, 0x53, 9200, notif, 20, -1, 0, 0);
		gm_rx("s3@ims", rp, (size_t)n, NULL, NULL);
		CHECK_EQ(G.push.n, 1); CHECK_EQ(dev_count(1), 1);
		dev_answer(1, 200);
		CHECK_EQ(G.nsent, 3);
		check_rp_reply(2, 0x53, "s3@ims", true, 0);
	}
	unworld();

	/* a later segment without port addressing joins the message of the first; a stray one is an ordinary binary SMS */
	world(NULL, 1);
	{
		uint8_t rp[260], b1[120], udh[8] = { 5, 0x00, 3, 0x61, 2, 2 };
		int n;

		memcpy(b1, notif, 110);
		n = mk_push_sms(rp, 0x60, 2948, b1, 110, 0x61, 2, 1);
		gm_rx("c1@ims", rp, (size_t)n, NULL, NULL);
		CHECK_EQ(G.push.n, 0);
		n = mk_deliver(rp, "0100000004", NULL, 0, 0, 0x81, udh, 6, notif + 110, 17, 0x04, 0x61);
		gm_rx("c2@ims", rp, (size_t)n, NULL, NULL);
		CHECK_EQ(G.push.n, 1); CHECK_EQ(G.push.len, 127); CHECK(!memcmp(G.push.data, notif, 127));
		CHECK_EQ(dev_count(1), 0);
		udh[3] = 0x77;				/* another reference: nobody is assembling it */
		n = mk_deliver(rp, "0100000004", NULL, 0, 0, 0x81, udh, 6, notif + 110, 17, 0x04, 0x62);
		gm_rx("c3@ims", rp, (size_t)n, NULL, NULL);
		CHECK_EQ(G.push.n, 1); CHECK_EQ(dev_count(1), 1);
	}
	unworld();

	/* bounded: more than 8 incomplete pushes, and more than 16 segments */
	world(NULL, 1);
	for (i = 0; i < 12; i++) {
		uint8_t rp[260];
		char cid[24];
		int n = mk_push_sms(rp, (uint8_t)(0x70 + i), 2948, notif, 100, 0x80 + i, 2, 1);

		snprintf(cid, sizeof(cid), "b%d@ims", i);
		gm_rx(cid, rp, (size_t)n, NULL, NULL);
	}
	CHECK_EQ(G.nsent, 12); CHECK_EQ(G.push.n, 0);
	{
		uint8_t rp[260];
		int n = mk_push_sms(rp, 0x90, 2948, notif, 100, 0x30, 20, 1);

		gm_rx("big@ims", rp, (size_t)n, NULL, NULL);
		CHECK_EQ(G.nsent, 13); CHECK_EQ(G.push.n, 0);	/* 20 segments: refused (and acknowledged) */
	}
	unworld();
}

static void onepending(struct smsrelay_cfg *c)
{
	c->mt_max_pending = 1;
}

static void t_mt_errors(void)
{
	struct sip_msg m;
	struct smsrelay_status s;

	/* overload: second message in flight -> RP-ERROR 42, and its retransmission later is accepted */
	world(onepending, 1);
	gm_rx_hex("e1@ims", CAP_GSM7, NULL);
	gm_rx_hex("e2@ims", CAP_UCS2, NULL);
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x3e, "e2@ims", false, 42);
	m_answer(0, 202);
	dev_answer(1, 200);
	CHECK_EQ(G.nsent, 2);
	check_rp_reply(1, 0x68, "e1@ims", true, 0);
	m_answer(1, 202);
	gm_rx_hex("e3@ims", CAP_UCS2, NULL);		/* the network's retry gets through */
	CHECK_EQ(dev_count(1), 2);
	dev_answer(1, 200);
	check_rp_reply(2, 0x3e, "e3@ims", true, 0);
	m_answer(2, 202);
	unworld();

	/* malformed RP-DATA, and an SMS-SUBMIT TPDU where a DELIVER belongs */
	world(NULL, 1);
	gm_rx_hex("e4@ims", "01 55 07 91 28 01 02 29 81 12 00 20 04 0b", NULL);
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x55, "e4@ims", false, 96);
	m_answer(0, 202);
	gm_rx_hex("e5@ims", "01 56 07 91 28 01 02 29 81 12 00 06 01 00 03 81 10 50", NULL);
	CHECK_EQ(G.nsent, 2);
	check_rp_reply(1, 0x56, "e5@ims", false, 111);
	m_answer(1, 202);
	CHECK_EQ(dev_count(1), 0);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_errors, 2);
	/* a MESSAGE that is not SMS is not consumed */
	{
		uint8_t b[] = "hello";

		gm_rx("e6@ims", b, 5, NULL, "text/plain");
		CHECK_EQ(gm_status(2), 415);
	}
	(void)m;
	unworld();
}

/* ------------------------------------------------------------------ */
/* MO                                                                  */

static void t_mo_basic(void)
{
	const char *cid;
	char v[200];
	uint8_t rp[64];
	struct smsrelay_status s;
	int n;

	world(NULL, 2);
	cid = lan_msg(1, "sip:01051226862@192.168.68.1", NULL, "imsua ap-ims sms test", 21);
	CHECK_EQ(lstat(cid), 0);			/* no answer until the outcome is known */
	CHECK_EQ(G.nsent, 1);
	CHECK_STR(G.sent[0].ruri, "sip:ipsmgw.lte-lguplus.co.kr");
	CHECK_STR(G.sent[0].ct, "application/vnd.3gpp.sms");
	CHECK_STR(hexs(G.sent[0].body, G.sent[0].blen), CAP_MO_RP);
	CHECK(has(G.sent[0].extra, "Allow: MESSAGE\r\n"));
	CHECK(has(G.sent[0].extra, "Request-Disposition: no-fork\r\n"));
	CHECK(has(G.sent[0].extra, "Accept-Contact: *;+g.3gpp.smsip\r\n"));
	CHECK(!has(G.sent[0].extra, "P-Preferred-Identity"));
	CHECK(!has(G.sent[0].extra, "In-Reply-To"));
	m_answer(0, 202);
	CHECK_EQ(lstat(cid), 0);
	/* the network's report arrives as a MESSAGE with In-Reply-To = our Call-ID */
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[0].call_id);
	gm_rx_hex("net1@ims", "03ae4109010062110250731463", v);
	CHECK_EQ(gm_status(0), 200);
	CHECK_EQ(lstat(cid), 200);
	CHECK_STR(lhdr(cid, "X-SMS-Parts", v, sizeof(v)), "1");
	CHECK_STR(lhdr(cid, "X-SMS-Timestamp", v, sizeof(v)), "2026-11-20T05:37:41+09:00");
	CHECK_EQ(lnresp(cid, 200), 1);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mo_submitted, 1);
	CHECK_EQ(s.mo_acked, 1);
	CHECK_EQ(s.mo_failed, 0);
	CHECK_EQ(s.mo_queue_len, 0);
	CHECK_EQ(s.mo_segments_sent, 1);

	/* second message: counters moved on (RP-MR 0xaf, TP-MR 0x15), tel: URI with separators, international TOA */
	cid = lan_text(2, "tel:+82-10-5122-6862", "hi");
	CHECK_EQ(G.nsent, 2);
	n = hex_decode(hexs(G.sent[1].body, G.sent[1].blen), rp, sizeof(rp));
	CHECK(n > 0);
	CHECK_EQ(rp[1], 0xaf);
	CHECK(has(hexs(G.sent[1].body, G.sent[1].blen), "0c91280115228626"));
	m_answer(1, 200);					/* 200 instead of 202 is fine too */
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[1].call_id);
	gm_rx_hex("net2@ims", "03af", v);			/* RP-ACK without user data */
	CHECK_EQ(lstat(cid), 200);
	CHECK_STR(lhdr(cid, "X-SMS-Timestamp", v, sizeof(v)), "");
	unworld();
}

/* ---- carbon copies of sent SMS ---- */

static void carbon_split(struct smsrelay_cfg *c)
{
	c->text_split = 200;
}

static void carbon_off(struct smsrelay_cfg *c)
{
	c->carbons = false;
}

static const char *H(const struct sip_msg *m, const char *name)
{
	const char *v = sip_hdr(m, name, 0);

	return v ? v : "";
}

static void carbon_finish(int i, const char *cid_unused)
{
	char v[200];

	(void)cid_unused;
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[i].call_id);
	m_answer(i, 202);
	gm_rx_hex("netc@ims", "03ae4109010062110250731463", v);
}

/* every segment of a message of nseg segments answered and acknowledged by the network (the last report carries the time) */
static void carbon_finish_n(int nseg, int mr0)
{
	int i;
	char v[200], rp[64];

	for (i = 0; i < nseg; i++) {
		CHECK(G.nsent > i);
		if (G.nsent <= i)
			return;
		snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[i].call_id);
		snprintf(rp, sizeof(rp), "03%02x%s", mr0 + i, i == nseg - 1 ? "4109010062110250731463" : "");
		m_answer(i, 202);
		gm_rx_hex("netc@ims", rp, v);
	}
}

static void t_mo_carbons(void)
{
	const char *cid;
	struct sip_msg m;
	struct smsrelay_status s;
	char v[200];

	/* three devices: the sender and another one want copies, the third does not */
	world(NULL, 0);
	dev_register_feat(1, ";+g.imsd.carbons");
	dev_register_feat(2, ";+g.imsd.mms;+g.imsd.carbons");
	dev_register_feat(3, "");
	fakeep_clear(G.w.f);
	cid = lan_msg(1, "sip:01051226862@192.168.68.1", NULL, "hello \xed\x95\x9c\xea\xb8\x80", 9);
	CHECK_EQ(lstat(cid), 0);
	CHECK_EQ(dev_count(2), 0);			/* not before the network acknowledged */
	carbon_finish(0, cid);
	CHECK_EQ(lstat(cid), 200);
	CHECK_EQ(dev_count(1), 0);			/* not to the sender */
	CHECK_EQ(dev_count(3), 0);			/* not to a device without the tag */
	CHECK_EQ(dev_count(2), 1);
	CHECK(dev_parse(2, 0, &m));
	CHECK_STR(H(&m, "Content-Type"), "text/plain; charset=utf-8");
	CHECK(has(H(&m, "From"), "sip:+821051226862@"));
	CHECK_STR(H(&m, "X-IMSD-Carbon"), "sent");
	CHECK_STR(H(&m, "X-IMSD-Peer"), "01051226862");
	CHECK_STR(H(&m, "X-SMS-Timestamp"), "2026-11-20T05:37:41+09:00");
	CHECK_STR(H(&m, "X-SMS-Parts"), "1");
	CHECK_STR(H(&m, "X-SMS-Part"), "");		/* one MESSAGE: no part header, no marker */
	CHECK_EQ(strlen(H(&m, "X-IMSD-Carbon-ID")), 16);
	CHECK_EQ(m.body_len, 9);
	CHECK(!memcmp(m.body, "hello \xed\x95\x9c\xea\xb8\x80", 9));
	sip_msg_free(&m);
	dev_answer(2, 200);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.carbons_sent, 1); CHECK_EQ(s.carbons_failed, 0);
	/* a second message has another id */
	{
		char id1[40];

		CHECK(dev_parse(2, 0, &m));
		snprintf(id1, sizeof(id1), "%s", H(&m, "X-IMSD-Carbon-ID"));
		sip_msg_free(&m);
		G.nsent = 0;
		cid = lan_text(1, "sip:01051226862@192.168.68.1", "again");
		snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[0].call_id);
		m_answer(0, 202);
		gm_rx_hex("netc2@ims", "03af4109010062110250731463", v);
		CHECK_EQ(dev_count(2), 2);
		CHECK(dev_parse(2, 1, &m));
		CHECK(strcmp(id1, H(&m, "X-IMSD-Carbon-ID")) != 0);
		sip_msg_free(&m);
	}
	unworld();

	/* a sender with no binding (an unregistered source): every device that wants copies gets one */
	world(NULL, 0);
	dev_register_feat(1, ";+g.imsd.carbons");
	dev_register_feat(2, ";+g.imsd.carbons");
	dev_register_feat(3, "");
	fakeep_clear(G.w.f);
	cid = lan_msg(5, "sip:01051226862@192.168.68.1", NULL, "from nowhere", 12);
	CHECK_EQ(G.nsent, 1);
	/* RP-ACK without user data: no network time, the copy carries the time of the gateway */
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[0].call_id);
	m_answer(0, 202);
	gm_rx_hex("netd@ims", "03ae", v);
	CHECK_EQ(lstat(cid), 200);
	CHECK_EQ(dev_count(1), 1); CHECK_EQ(dev_count(2), 1); CHECK_EQ(dev_count(3), 0);
	CHECK(dev_parse(1, 0, &m));
	CHECK(strlen(H(&m, "X-SMS-Timestamp")) == 25 && !strcmp(H(&m, "X-SMS-Timestamp") + 19, "+00:00"));
	sip_msg_free(&m);
	unworld();

	/* a text that needs more than one SIP MESSAGE: pieces in order, same id, X-SMS-Part, marker, lossless; one at a time */
	world(carbon_split, 0);
	dev_register_feat(1, "");
	dev_register_feat(2, ";+g.imsd.carbons");
	fakeep_clear(G.w.f);
	{
		char text[700] = "";
		char back[700] = "";
		int i, n = 0;
		char id[40] = "";

		for (i = 0; i < 12; i++)	/* 12 lines of 12 Hangul + LF: 156 characters (3 SMS segments), 444 bytes (3 pieces of 188) */
			strcat(text, "\xea\xb0\x80\xeb\x82\x98\xeb\x8b\xa4\xeb\x9d\xbc\xeb\xa7\x88\xeb\xb0\x94\xec\x82\xac\xec\x95\x84\xec\x9e\x90\xec\xb0\xa8\xec\xb9\xb4\xed\x83\x80\n");
		cid = lan_msg(1, "sip:01051226862@192.168.68.1", NULL, text, strlen(text));
		carbon_finish_n(3, 0xae);
		CHECK_EQ(G.nsent, 3);
		for (;;) {
			char want[16];

			CHECK_EQ(dev_count(2), n + 1);
			CHECK(dev_parse(2, n, &m));
			if (n == 0)
				snprintf(id, sizeof(id), "%s", H(&m, "X-IMSD-Carbon-ID"));
			CHECK_STR(H(&m, "X-IMSD-Carbon-ID"), id);
			CHECK_STR(H(&m, "X-SMS-Parts"), "3");		/* the air interface used three segments: unrelated to X-SMS-Part */
			snprintf(v, sizeof(v), "%d/", n + 1);
			CHECK(!strncmp(H(&m, "X-SMS-Part"), v, strlen(v)));
			snprintf(want, sizeof(want), "(%d/", n + 1);
			CHECK(!strncmp(bodystr(&m), want, strlen(want)));
			strcat(back, strchr(bodystr(&m), ')') + 2);
			sip_msg_free(&m);
			n++;
			dev_answer(2, 200);
			if (dev_count(2) == n)
				break;
			CHECK(n < 10);
		}
		CHECK(n >= 3);
		CHECK_STR(back, text);
		smsrelay_get_status(G.sr, &s);
		CHECK_EQ(s.carbons_sent, 1);
	}
	unworld();

	/* switched off */
	world(carbon_off, 0);
	dev_register_feat(2, ";+g.imsd.carbons");
	fakeep_clear(G.w.f);
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "quiet");
	carbon_finish(0, cid);
	CHECK_EQ(lstat(cid), 200);
	CHECK_EQ(dev_count(2), 0);
	unworld();

	/* a failed send makes no copy */
	world(NULL, 0);
	dev_register_feat(2, ";+g.imsd.carbons");
	fakeep_clear(G.w.f);
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "nope");
	m_answer(0, 603);
	CHECK_EQ(dev_count(2), 0);
	unworld();
}

static void t_mo_long(void)
{
	char text[700];
	const char *cid;
	char v[200];
	int i;
	uint8_t first_ref = 0;
	struct smsrelay_status s;

	text[0] = 0;
	for (i = 0; i < 150; i++)
		strcat(text, "\xea\xb0\x80");	/* 150 x U+AC00 */
	world(NULL, 1);
	cid = lan_text(1, "sip:01051226862@x", text);
	CHECK_EQ(G.nsent, 1);
	for (i = 0; i < 3; i++) {
		const uint8_t *b = G.sent[i].body;

		CHECK_EQ(G.nsent, i + 1);
		CHECK_EQ(b[1], 0xae + i);
		/* RP header 00 mr 00 | 07 91 .. 6 | len = 12 octets, then the TPDU: [13] TP-MR, [28] concat ref, [30] sequence */
		CHECK_EQ(b[12] & 0x41, 0x41);			/* SUBMIT + UDHI */
		CHECK_EQ(b[12 + 1], 0x14 + i);			/* TP-MR per segment */
		if (i == 0)
			first_ref = b[28];
		CHECK_EQ(b[28], first_ref);	/* concat reference identical */
		CHECK_EQ(b[30], i + 1);	/* sequence */
		m_answer(i, 202);
		CHECK_EQ(lstat(cid), 0);
		snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[i].call_id);
		gm_rx_hex("netl@ims", i == 0 ? "03ae" : i == 1 ? "03af" : "03b04109010062110250731463", v);
	}
	CHECK_EQ(G.nsent, 3);
	CHECK_EQ(lnresp(cid, 200), 1);
	CHECK_STR(lhdr(cid, "X-SMS-Parts", v, sizeof(v)), "3");
	CHECK_STR(lhdr(cid, "X-SMS-Timestamp", v, sizeof(v)), "2026-11-20T05:37:41+09:00");
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mo_acked, 1);
	CHECK_EQ(s.mo_segments_sent, 3);
	unworld();
}

static void t_mo_failures(void)
{
	const char *cid;
	char v[200];

	/* SIP 603 (barred line) -> 403 */
	world(NULL, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	m_answer(0, 603);
	CHECK_EQ(lstat(cid), 403);
	CHECK(has(lhdr(cid, "Warning", v, sizeof(v)), "603"));
	unworld();

	/* other SIP failures */
	world(NULL, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	m_answer(0, 486);
	CHECK_EQ(lstat(cid), 503);
	CHECK_STR(lhdr(cid, "Retry-After", v, sizeof(v)), "30");
	cid = lan_text(1, "sip:01051226862@x", "hello");
	m_answer(1, 404);
	CHECK_EQ(lstat(cid), 502);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	m_answer(2, 0);
	CHECK_EQ(lstat(cid), 504);
	unworld();

	/* RP-ERROR: permanent (1) -> 502, temporary (41) -> 503, with the cause text */
	world(NULL, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	m_answer(0, 202);
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[0].call_id);
	gm_rx_hex("er1@ims", "05ae0101", v);
	CHECK_EQ(lstat(cid), 502);
	CHECK(has(lhdr(cid, "Warning", v, sizeof(v)), "unassigned (unallocated) number"));
	cid = lan_text(1, "sip:01051226862@x", "hello");
	m_answer(1, 202);
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[1].call_id);
	gm_rx_hex("er2@ims", "05af0129", v);
	CHECK_EQ(lstat(cid), 503);
	CHECK(has(lhdr(cid, "Warning", v, sizeof(v)), "temporary failure"));
	unworld();

	/* a report with a foreign In-Reply-To or MR is ignored */
	world(NULL, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	m_answer(0, 202);
	gm_rx_hex("er3@ims", "03ae", "In-Reply-To: somebody-else\r\n");
	gm_rx_hex("er4@ims", "03ff", NULL);
	CHECK_EQ(gm_status(0), 200);
	CHECK_EQ(lstat(cid), 0);
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[0].call_id);
	gm_rx_hex("er5@ims", "03ae", v);
	CHECK_EQ(lstat(cid), 200);
	unworld();

	/* the report overtakes the SIP answer */
	world(NULL, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[0].call_id);
	gm_rx_hex("er6@ims", "03ae", v);
	CHECK_EQ(lstat(cid), 0);
	m_answer(0, 202);
	CHECK_EQ(lstat(cid), 200);
	unworld();

	/* ... but a SIP rejection still wins */
	world(NULL, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[0].call_id);
	gm_rx_hex("er7@ims", "03ae", v);
	m_answer(0, 603);
	CHECK_EQ(lstat(cid), 403);
	unworld();
}

static void shortreport(struct smsrelay_cfg *c)
{
	c->report_timeout_ms = 10000;
}

static void t_mo_timeouts(void)
{
	const char *cid;
	char v[200];
	struct smsrelay_status s;

	/* report timeout shorter than the reply deadline -> 504 */
	world(shortreport, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	m_answer(0, 202);
	evfake_advance(9900);
	CHECK_EQ(lstat(cid), 0);
	evfake_advance(200);
	CHECK_EQ(lstat(cid), 504);
	CHECK(has(lhdr(cid, "Warning", v, sizeof(v)), "no delivery report"));
	evfake_advance(60000);
	CHECK_EQ(lnresp(cid, 504), 1);
	unworld();

	/* defaults: the 28 s deadline comes first -> 202, the eventual failure is only logged; a late report is stray */
	world(NULL, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	m_answer(0, 202);
	evfake_advance(27900);
	CHECK_EQ(lstat(cid), 0);
	evfake_advance(200);
	CHECK_EQ(lstat(cid), 202);
	evfake_advance(2000);			/* report timeout at 30 s */
	CHECK_EQ(lstat(cid), 202);
	CHECK_EQ(lnresp(cid, 202), 1);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mo_failed, 1);
	CHECK_EQ(s.mo_queue_len, 0);
	evfake_advance(60000);
	unworld();

	/* 202 at the deadline, success afterwards: counted, no second answer */
	world(NULL, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	m_answer(0, 202);
	evfake_advance(28100);
	CHECK_EQ(lstat(cid), 202);
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[0].call_id);
	gm_rx_hex("tm1@ims", "03ae", v);
	CHECK_EQ(lnresp(cid, 200), 0);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mo_acked, 1);
	unworld();

	/* no SIP answer at all: the transaction layer of reg_send reports 0 -> 504 (mock answers 0) */
	world(NULL, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	evfake_advance(1000);
	m_answer(0, 0);
	CHECK_EQ(lstat(cid), 504);
	unworld();
}

static void t_mo_registration(void)
{
	const char *c1, *c2, *c3;
	char v[200];

	/* not registered: 480 at once, nothing sent */
	world(NULL, 1);
	G.registered = false;
	c1 = lan_text(1, "sip:01051226862@x", "hello");
	CHECK_EQ(lstat(c1), 480);
	CHECK_EQ(G.nsent, 0);
	unworld();

	/* registration goes down with one in flight and one queued */
	world(NULL, 2);
	c1 = lan_text(1, "sip:01051226862@x", "one");
	c2 = lan_text(2, "sip:01051226862@x", "two");
	CHECK_EQ(G.nsent, 1);
	m_answer(0, 202);
	G.registered = false;
	smsrelay_on_reg_event(G.sr, SMSRELAY_REG_DOWN);
	CHECK_EQ(lstat(c1), 480);
	CHECK_EQ(lstat(c2), 480);
	{
		struct smsrelay_status s;

		smsrelay_get_status(G.sr, &s);
		CHECK_EQ(s.mo_queue_len, 0);
		CHECK_EQ(s.mo_failed, 2);
	}
	/* a stale network answer / report after that is harmless */
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[0].call_id);
	gm_rx_hex("rd1@ims", "03ae", v);
	CHECK_EQ(gm_status(0), 200);
	/* back up */
	G.registered = true;
	smsrelay_on_reg_event(G.sr, SMSRELAY_REG_UP);
	c3 = lan_text(1, "sip:01051226862@x", "three");
	CHECK_EQ(G.nsent, 2);
	m_answer(1, 202);
	smsrelay_on_reg_event(G.sr, SMSRELAY_REG_REPLACED);
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[1].call_id);
	gm_rx_hex("rd2@ims", "03af", v);
	CHECK_EQ(lstat(c3), 200);
	unworld();

	/* down while waiting for the SIP answer; the stale callback arrives later */
	world(NULL, 1);
	c1 = lan_text(1, "sip:01051226862@x", "one");
	smsrelay_on_reg_event(G.sr, SMSRELAY_REG_DOWN);
	CHECK_EQ(lstat(c1), 480);
	m_answer(0, 0);
	unworld();

	/* send() fails with -ENOTCONN */
	world(NULL, 1);
	G.send_rc = -107;
	c1 = lan_text(1, "sip:01051226862@x", "one");
	CHECK_EQ(lstat(c1), 480);
	G.send_rc = -12;
	c1 = lan_text(1, "sip:01051226862@x", "one");
	CHECK_EQ(lstat(c1), 503);
	unworld();
}

static void queue2(struct smsrelay_cfg *c)
{
	c->queue_max = 2;
}

static void t_mo_queue(void)
{
	const char *c1, *c2, *c3, *c4;
	char v[200];
	struct smsrelay_status s;

	world(queue2, 3);
	c1 = lan_text(1, "sip:01051226862@x", "one");
	c2 = lan_text(2, "sip:01051226863@x", "two");
	c3 = lan_text(3, "sip:01051226864@x", "three");
	CHECK_EQ(G.nsent, 1);				/* one in flight at a time */
	CHECK_EQ(lstat(c3), 503);
	CHECK_STR(lhdr(c3, "Retry-After", v, sizeof(v)), "10");
	CHECK(has(lhdr(c3, "Warning", v, sizeof(v)), "queue is full"));
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mo_queue_len, 2);
	m_answer(0, 202);
	CHECK_EQ(G.nsent, 1);
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[0].call_id);
	gm_rx_hex("q1@ims", "03ae", v);
	CHECK_EQ(lstat(c1), 200);
	CHECK_EQ(G.nsent, 2);				/* the second goes out after the first one's report */
	CHECK(has(hexs(G.sent[1].body, G.sent[1].blen), "0b811050216268f3"));
	CHECK_EQ(G.sent[1].body[1], 0xaf);
	m_answer(1, 202);
	snprintf(v, sizeof(v), "In-Reply-To: %s\r\n", G.sent[1].call_id);
	gm_rx_hex("q2@ims", "03af", v);
	CHECK_EQ(lstat(c2), 200);
	/* room again */
	c4 = lan_text(1, "sip:01051226862@x", "four");
	CHECK_EQ(G.nsent, 3);
	m_answer(2, 603);
	CHECK_EQ(lstat(c4), 403);
	unworld();

	/* a message waiting in the queue hits the reply deadline while the one in front is still stuck */

	world(NULL, 2);
	c1 = lan_text(1, "sip:01051226862@x", "one");
	m_answer(0, 202);
	evfake_advance(10000);
	c2 = lan_text(2, "sip:01051226862@x", "two");
	CHECK_EQ(G.nsent, 1);
	evfake_advance(18100);				/* c1: 28.1 s -> 202 */
	CHECK_EQ(lstat(c1), 202);
	CHECK_EQ(lstat(c2), 0);
	evfake_advance(2000);				/* c1's report times out at 30 s: c2 starts */
	CHECK_EQ(G.nsent, 2);
	evfake_advance(10000);				/* c2: 28 s after its own arrival */
	CHECK_EQ(lstat(c2), 202);
	m_answer(1, 202);
	evfake_advance(100000);
	unworld();
}

static void cfgsmsc(struct smsrelay_cfg *c)
{
	snprintf(c->smsc, sizeof(c->smsc), "+821099999999");
}

static void t_mo_smsc(void)
{
	const char *cid;
	char wv[200];
	struct smsrelay_status s;
	struct rp_data rd;

	/* nothing known (no SIM value, no config): 503 with an explanation */
	world(NULL, 2);
	G.sim_smsc[0] = 0;
	cid = lan_text(1, "sip:01051226862@x", "hello");
	CHECK_EQ(lstat(cid), 503);
	CHECK(has(lhdr(cid, "Warning", wv, sizeof(wv)), "no SMSC: not on the SIM and not configured (imsd.main.smsc)"));
	CHECK_EQ(G.nsent, 0);
	smsrelay_get_status(G.sr, &s);
	CHECK_STR(s.smsc_source, "none");
	CHECK_STR(s.smsc, "");
	/* an incoming SMS does not teach it any more */
	gm_rx_hex("sm1@ims", CAP_GSM7, NULL);
	dev_answer(1, 200);
	dev_answer(2, 200);
	m_answer(0, 202);
	G.nsent = 0;
	cid = lan_text(1, "sip:01051226862@x", "hello");
	CHECK_EQ(lstat(cid), 503);
	CHECK_EQ(G.nsent, 0);
	/* the SIM value appears later (evaluated at each message): used, RP-DA exactly like the handset's */
	snprintf(G.sim_smsc, sizeof(G.sim_smsc), "+821080010585");
	cid = lan_text(1, "sip:01051226862@x", "hello");
	CHECK_EQ(G.nsent, 1);
	CHECK(!rp_parse_data(G.sent[0].body, G.sent[0].blen, &rd));
	CHECK_EQ(rd.da.len, 7);
	/* the whole element on the wire: length octet 07, then TON/NPI 91 and the swapped nibbles */
	CHECK(G.sent[0].blen > 11 && G.sent[0].body[2] == 0x00);
	CHECK(!memcmp(G.sent[0].body + 3, "\x07\x91\x28\x01\x08\x10\x50\x58", 8));
	smsrelay_get_status(G.sr, &s);
	CHECK_STR(s.smsc, "+821080010585");
	CHECK_STR(s.smsc_source, "sim");
	unworld();

	/* explicit config wins over the SIM */
	world(cfgsmsc, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	CHECK_EQ(G.nsent, 1);
	CHECK(has(hexs(G.sent[0].body, G.sent[0].blen), "0791280199999999"));
	smsrelay_get_status(G.sr, &s);
	CHECK_STR(s.smsc, "+821099999999");
	CHECK_STR(s.smsc_source, "config");
	unworld();
}

static void cfgpsi(struct smsrelay_cfg *c)
{
	snprintf(c->sms_psi, sizeof(c->sms_psi), "sip:cfg.example.net");
}

static void t_mo_psi(void)
{
	struct smsrelay_status s;

	/* nothing configured, nothing on the card: the operator table of the IMSI (LG U+) */
	world(NULL, 1);
	lan_text(1, "sip:01051226862@x", "hello");
	CHECK_EQ(G.nsent, 1);
	CHECK_STR(G.sent[0].ruri, "sip:ipsmgw.lte-lguplus.co.kr");
	smsrelay_get_status(G.sr, &s);
	CHECK_STR(s.sms_psi, "sip:ipsmgw.lte-lguplus.co.kr"); CHECK_STR(s.sms_psi_source, "carrier");
	unworld();
	/* the card's EF_PSISMSC beats the table, evaluated per message */
	world(NULL, 1);
	snprintf(G.card_psi, sizeof(G.card_psi), "sip:smsgw.example.net");
	lan_text(1, "sip:01051226862@x", "hello");
	CHECK_EQ(G.nsent, 1);
	CHECK_STR(G.sent[0].ruri, "sip:smsgw.example.net");
	smsrelay_get_status(G.sr, &s);
	CHECK_STR(s.sms_psi_source, "sim");
	unworld();
	/* the explicit option beats the card */
	world(cfgpsi, 1);
	snprintf(G.card_psi, sizeof(G.card_psi), "sip:smsgw.example.net");
	lan_text(1, "sip:01051226862@x", "hello");
	CHECK_EQ(G.nsent, 1);
	CHECK_STR(G.sent[0].ruri, "sip:cfg.example.net");
	smsrelay_get_status(G.sr, &s);
	CHECK_STR(s.sms_psi_source, "config");
	unworld();
	/* unknown operator, nothing on the card, nothing configured: refused with 503 */
	world(NULL, 1);
	snprintf(G.imsi, sizeof(G.imsi), "310260000000001");
	lan_text(1, "sip:01051226862@x", "hello");
	CHECK_EQ(G.nsent, 0);
	smsrelay_get_status(G.sr, &s);
	CHECK_STR(s.sms_psi, ""); CHECK_STR(s.sms_psi_source, "none");
	CHECK(strstr(s.last_error, "no SMS gateway") != NULL);
	unworld();
}

static void ppi_srr(struct smsrelay_cfg *c)
{
	c->delivery_reports = true;
	snprintf(c->p_preferred_identity, sizeof(c->p_preferred_identity), "<sip:01051226862@lte-lguplus.co.kr>");
	c->vp_minutes = 60;
	c->mo_require_registered = true;
}

static void t_mo_options(void)
{
	const char *cid;

	world(ppi_srr, 1);
	cid = lan_text(1, "sip:01051226862@x", "hello");
	CHECK_EQ(G.nsent, 1);
	CHECK(has(G.sent[0].extra, "P-Preferred-Identity: <sip:01051226862@lte-lguplus.co.kr>\r\n"));
	CHECK_EQ(G.sent[0].body[12] & 0x20, 0x20);		/* TP-SRR */
	CHECK_EQ(G.sent[0].body[12] & 0x18, 0x10);		/* relative VP present */
	/* a device that is not registered is refused when configured so */
	{
		static const char m[] = "MESSAGE sip:01051226862@192.168.68.1 SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.68.99:5060;branch=z9hG4bKzz;rport\r\n"
			"From: <sip:x@y>;tag=1\r\nTo: <sip:01051226862@y>\r\nCall-ID: unreg@x\r\nCSeq: 1 MESSAGE\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi";
		struct addr a = ua_addr("192.168.68.99", 5060);

		fakeep_rx(G.w.f, &a, m);
		CHECK_EQ(lstat("unreg@x"), 403);
	}
	(void)cid;
	unworld();
}

static void seg2(struct smsrelay_cfg *c)
{
	c->max_segments = 2;
}

static void t_mo_validation(void)
{
	const char *cid;
	char v[200], big[800];
	int i;

	world(seg2, 1);
	cid = lan_text(1, "sip:bob@x", "hello");
	CHECK_EQ(lstat(cid), 404);
	cid = lan_text(1, "sip:+@x", "hello");
	CHECK_EQ(lstat(cid), 484);
	cid = lan_text(1, "sip:123456789012345678901@x", "hello");
	CHECK_EQ(lstat(cid), 484);
	cid = lan_msg(1, "sip:01051226862@x", "text/plain", "", 0);
	CHECK_EQ(lstat(cid), 400);
	cid = lan_msg(1, "sip:01051226862@x", "text/html", "<b>x</b>", 8);
	CHECK_EQ(lstat(cid), 415);
	CHECK_STR(lhdr(cid, "Accept", v, sizeof(v)), "text/plain; charset=utf-8");
	cid = lan_msg(1, "sip:01051226862@x", "text/plain; charset=iso-8859-1", "x", 1);
	CHECK_EQ(lstat(cid), 415);
	cid = lan_msg(1, "sip:01051226862@x", "application/vnd.3gpp.sms", "x", 1);
	CHECK_EQ(lstat(cid), 415);
	cid = lan_msg(1, "sip:01051226862@x", "text/plain; charset=utf-8", "\xff\xfe", 2);
	CHECK_EQ(lstat(cid), 400);
	big[0] = 0;
	for (i = 0; i < 150; i++)
		strcat(big, "\xea\xb0\x80");
	cid = lan_text(1, "sip:01051226862@x", big);		/* 3 segments, limit 2 */
	CHECK_EQ(lstat(cid), 413);
	CHECK_EQ(G.nsent, 0);
	cid = lan_msg(1, "sip:01051226862@x", "TEXT/Plain ; Charset=\"US-ASCII\"", "ok", 2);
	CHECK_EQ(lstat(cid), 0);
	CHECK_EQ(G.nsent, 1);
	m_answer(0, 603);
	CHECK_EQ(lstat(cid), 403);
	unworld();
}

static void t_shutdown(void)
{
	const char *c1, *c2;

	world(NULL, 2);
	c1 = lan_text(1, "sip:01051226862@x", "one");
	c2 = lan_text(2, "sip:01051226862@x", "two");
	gm_rx_hex("sd1@ims", CAP_GSM7, NULL);
	smsrelay_free(G.sr);
	CHECK_EQ(lstat(c1), 503);
	CHECK_EQ(lstat(c2), 503);
	/* the pending Gm callback of the first segment must not be called after free: the integrator frees reg first.
	 * Here only drop it. */
	G.sr = smsrelay_new(G.w.lan, &(struct smsrelay_cfg){ .queue_max = 1 }, &(struct smsrelay_ops){ .registered = m_registered, .send = m_send });
	unworld();
}


/* ------------------------------------------------------------------ */
/* store mode                                                          */

/* device k registers with an instance of its own (the identity), feature tags in params, extra header lines */
static reg_id_t dev_reg_s(int k, const char *params, const char *extra)
{
	char ct[260], cid[32], ex[200];
	static int n;
	struct addr a = ua_addr(dev_ip(k), 5060);

	snprintf(ct, sizeof(ct), "<sip:u%d@%s:5060>%s;+sip.instance=\"<urn:uuid:0000000%d>\";expires=600", k, dev_ip(k), params, k);
	snprintf(cid, sizeof(cid), "ds%d-%d", k, ++n);
	snprintf(ex, sizeof(ex), "User-Agent: TestPhone\r\n%s", extra ? extra : "");
	uaw_rx(&G.w, dev_ip(k), 5060, mk_register(dev_ip(k), ct, n, cid, -1, ex));
	ssettle();
	return reg_identify(lan_registrar(G.w.lan), &a, NULL);
}

static void dev_away(int k)
{
	struct addr a = ua_addr(dev_ip(k), 5060);

	reg_remove(lan_registrar(G.w.lan), reg_identify(lan_registrar(G.w.lan), &a, NULL));
	ssettle();
}

static void t_store_sms(void)
{
	struct sip_msg m;
	struct smsrelay_status s;
	struct store_status ss;
	char live_ts[64], live_smsc[64], live_text[300], live_from[200];
	int k;

	/* what the live path sends, for comparison */
	world(NULL, 1);
	gm_rx_hex("l0@ims", CAP_GSM7, NULL);
	CHECK_EQ(dev_count(1), 1);
	CHECK(dev_parse(1, 0, &m));
	snprintf(live_ts, sizeof(live_ts), "%s", H(&m, "X-SMS-Timestamp"));
	snprintf(live_smsc, sizeof(live_smsc), "%s", H(&m, "X-SMS-SMSC"));
	snprintf(live_from, sizeof(live_from), "%s", H(&m, "From"));
	snprintf(live_text, sizeof(live_text), "%.*s", (int)m.body_len, (const char *)m.body);
	CHECK_STR(H(&m, "X-IMSD-Seq"), "");
	sip_msg_free(&m);
	unworld();

	/* a message that arrives while the (known) device is away: acknowledged to the network from the store at once, delivered at the
	 * device's next REGISTER, with X-IMSD-Seq and the same content as live */
	want_store = true;
	world(NULL, 0);
	dev_reg_s(1, "", NULL);
	dev_away(1);
	G.nsent = 0;
	gm_rx_hex("s1@ims", CAP_GSM7, NULL);
	ssettle();
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x68, "s1@ims", true, 0);
	m_answer(0, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_stored == 1 && s.mt_lost_no_client == 0 && s.mt_lost_failed == 0 && s.mt_store_fallback == 0);
	CHECK_EQ(dev_count(1), 0);
	dev_reg_s(1, "", NULL);
	CHECK_EQ(dev_count(1), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	CHECK_STR(H(&m, "X-SMS-Timestamp"), live_ts);
	CHECK_STR(H(&m, "X-SMS-SMSC"), live_smsc);
	CHECK(!strncmp(H(&m, "From"), live_from, strcspn(live_from, ";")));	/* the tag is random */
	{
		char t[300];

		snprintf(t, sizeof(t), "%.*s", (int)m.body_len, (const char *)m.body);
		CHECK_STR(t, live_text);
	}
	sip_msg_free(&m);
	dev_answer(1, 200);
	ssettle();
	store_get_status(G.st, &ss);
	CHECK(ss.items == 1 && ss.dev[0].cursor == 1 && ss.dev[0].lag == 0);

	/* a message with the device registered: the RP-ACK does not wait for the device, the device gets it with the next number */
	G.nsent = 0;
	gm_rx_hex("s2@ims", CAP_UCS2, NULL);
	ssettle();
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x3e, "s2@ims", true, 0);
	m_answer(0, 202);
	CHECK_EQ(dev_count(1), 2);
	CHECK(dev_parse(1, 1, &m));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "2");
	sip_msg_free(&m);
	dev_answer(1, 200);
	ssettle();

	/* the device reports an older position: the second message comes again, identical, with its original number */
	CHECK_EQ(dev_count(1), 2);
	dev_reg_s(1, "", "X-IMSD-Ack-Seq: 1\r\n");
	CHECK_EQ(dev_count(1), 3);
	CHECK(dev_parse(1, 2, &m));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "2");
	sip_msg_free(&m);
	dev_answer(1, 200);
	ssettle();
	CHECK_EQ(dev_count(1), 3);
	/* a repeat of RP-DATA 1 within the retransmission window while the cache still knows it */
	G.nsent = 0;
	gm_rx_hex("s1b@ims", CAP_GSM7, NULL);
	ssettle();
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x68, "s1b@ims", true, 0);
	m_answer(0, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_duplicates, 1);
	store_get_status(G.st, &ss);
	CHECK_EQ(ss.items, 2);

	/* a restart of the daemon: the numbers go on, and a repeat of the network's RP-DATA creates no second item (the cache is gone) */
	unworld();
	world(NULL, 0);
	store_get_status(G.st, &ss);
	CHECK(ss.items == 2 && ss.head_seq >= 2);
	G.nsent = 0;
	gm_rx_hex("s1c@ims", CAP_GSM7, NULL);
	ssettle();
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x68, "s1c@ims", true, 0);
	m_answer(0, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_duplicates, 1); CHECK_EQ(s.mt_stored, 0);
	store_get_status(G.st, &ss);
	CHECK_EQ(ss.items, 2);
	/* the device registers without the header: it had reported position 1 before, which is what the gateway starts from again (its 200s
	 * after that were only a volatile position): message 2 comes once more, with its number */
	dev_reg_s(1, "", NULL);
	CHECK_EQ(dev_count(1), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "2");
	sip_msg_free(&m);
	dev_answer(1, 200);
	ssettle();
	fakeep_clear(G.w.f);
	/* a new message after the restart has a number above all earlier ones */
	gm_rx_hex("s3@ims", CAP_UCS2_3F, NULL);
	ssettle();
	CHECK_EQ(dev_count(1), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK(atoi(H(&m, "X-IMSD-Seq")) > 2);
	sip_msg_free(&m);
	dev_answer(1, 200);
	ssettle();
	unworld_final();

	/* the disk is full: the message is not lost, it takes the live path (acknowledged after the LAN delivery, no store number), and the
	 * status says why; nobody registered = lost as before, logged */
	world(NULL, 1);
	dev_reg_s(1, "", NULL);
	fakeep_clear(G.w.f);
	sio_fault.points = SIO_FP_LOGWRITE;
	sio_fault.err = ENOSPC;
	sio_fault.count = -1;
	G.nsent = 0;
	gm_rx_hex("f1@ims", CAP_GSM7, NULL);
	ssettle();
	CHECK_EQ(G.nsent, 0);				/* waits for the LAN, as without a store */
	CHECK_EQ(dev_count(1), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "");
	sip_msg_free(&m);
	dev_answer(1, 200);
	ssettle();
	CHECK_EQ(G.nsent, 1);
	check_rp_reply(0, 0x68, "f1@ims", true, 0);
	m_answer(0, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_store_fallback == 1 && s.mt_stored == 0 && s.mt_delivered == 1);
	CHECK(!store_usable(G.st));
	store_get_status(G.st, &ss);
	CHECK(!ss.healthy && ss.error[0]);
	dev_away(1);
	G.nsent = 0;
	gm_rx_hex("f2@ims", CAP_UCS2, NULL);
	ssettle();
	CHECK_EQ(G.nsent, 1);
	m_answer(0, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_lost_no_client, 1);
	/* space is back: the store recovers by itself */
	sio_fault.points = 0;
	evfake_advance(31000);
	ssettle();
	CHECK(store_usable(G.st));
	G.nsent = 0;
	evfake_advance(130000);			/* the network's retransmission cache forgot f2 */
	gm_rx_hex("f3@ims", CAP_UCS2, "");
	ssettle();
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_stored, 1);
	CHECK_EQ(G.nsent, 1);
	m_answer(0, 202);
	unworld_final();

	/* a slow store (real writer thread, stalled): after store_ack_wait_ms the live path takes over, and the late item is dropped again */
	store_thread = true;
	world(NULL, 0);
	sio_fault.stall_ms = 300;
	{
		struct smsrelay_cfg c;

		smsrelay_cfg_defaults(&c);
		c.store_ack_wait_ms = 100;
		smsrelay_set_cfg(G.sr, &c);
	}
	G.nsent = 0;
	gm_rx_hex("w1@ims", CAP_GSM7, NULL);
	CHECK_EQ(G.nsent, 0);
	evfake_advance(150);
	CHECK_EQ(G.nsent, 1);				/* no device: the live path acknowledges (and logs the loss) */
	m_answer(0, 202);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_store_fallback == 1 && s.mt_lost_no_client == 1);
	for (k = 0; k < 400; k++) {
		usleep(2000);
		store_sync(G.st);
		store_get_status(G.st, &ss);
		if (ss.dropped)
			break;
	}
	sio_fault.stall_ms = 0;
	store_sync(G.st);
	store_get_status(G.st, &ss);
	CHECK(ss.dropped == 1 && ss.items == 0);
	store_thread = false;
	unworld_final();

	/* carbons: the sender and another device that want copies, a third that does not; one of them is away */
	world(NULL, 0);
	dev_reg_s(1, ";+g.imsd.carbons", NULL);
	dev_reg_s(2, ";+g.imsd.mms;+g.imsd.carbons", NULL);
	dev_reg_s(3, "", NULL);
	dev_reg_s(4, ";+g.imsd.carbons", NULL);
	dev_away(4);
	fakeep_clear(G.w.f);
	{
		const char *cid = lan_msg(1, "sip:01051226862@192.168.68.1", NULL, "hello", 5);

		carbon_finish(0, cid);
		ssettle();
		CHECK_EQ(lstat(cid), 200);
	}
	CHECK_EQ(dev_count(1), 0);
	CHECK_EQ(dev_count(3), 0);
	CHECK_EQ(dev_count(2), 1);
	CHECK(dev_parse(2, 0, &m));
	CHECK_STR(H(&m, "X-IMSD-Carbon"), "sent");
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	CHECK_STR(H(&m, "X-IMSD-Peer"), "01051226862");
	{
		char cid1[40];

		snprintf(cid1, sizeof(cid1), "%s", H(&m, "X-IMSD-Carbon-ID"));
		sip_msg_free(&m);
		dev_answer(2, 200);
		ssettle();
		smsrelay_get_status(G.sr, &s);
		CHECK_EQ(s.carbons_stored, 1);
		/* the sender asks for everything again (from another registration): never its own message */
		dev_reg_s(1, ";+g.imsd.carbons", "X-IMSD-Ack-Seq: 0\r\n");
		CHECK_EQ(dev_count(1), 0);
		/* the device that was away gets the copy, with the same carbon id */
		dev_reg_s(4, ";+g.imsd.carbons", NULL);
		CHECK_EQ(dev_count(4), 1);
		CHECK(dev_parse(4, 0, &m));
		CHECK_STR(H(&m, "X-IMSD-Carbon-ID"), cid1);
		CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
		sip_msg_free(&m);
		dev_answer(4, 200);
		ssettle();
		/* the device without the tag never gets it, also not when it registers again */
		dev_reg_s(3, "", "X-IMSD-Ack-Seq: 0\r\n");
		CHECK_EQ(dev_count(3), 0);
	}
	unworld_final();
	want_store = false;
}

/* ------------------------------------------------------------------ */
/* circuit switched SMS                                                */

static int cs_in(enum cssms_kind kind, const char *from, const char *ts, const char *text, const uint8_t *data, size_t dlen)
{
	struct cssms_in m;

	memset(&m, 0, sizeof(m));
	m.kind = kind;
	snprintf(m.from, sizeof(m.from), "%s", from);
	m.from_alnum = from[0] && !strpbrk(from, "0123456789+") ;
	snprintf(m.ts, sizeof(m.ts), "%s", ts);
	m.text = text;
	m.data = data;
	m.data_len = dlen;
	m.sms_class = -1;
	m.parts = 1;
	m.id = ++CS.next_id;
	return smsrelay_cs_in(G.sr, &m);
}

static int cs_text(const char *from, const char *ts, const char *text)
{
	return cs_in(CSSMS_TEXT, from, ts, text, NULL, 0);
}

static void cs_report_cfg(struct smsrelay_cfg *c)
{
	c->delivery_reports = true;
}

static void cs_finish(int status, const char *text, unsigned parts)
{
	struct cssms_result r;
	cssms_done_cb cb = CS.cb;

	memset(&r, 0, sizeof(r));
	r.status = status;
	snprintf(r.text, sizeof(r.text), "%s", text);
	r.parts = parts;
	CS.cb = NULL;
	cb(CS.arg, &r);
}

static void t_cs_mt(void)
{
	struct sip_msg m;
	struct smsrelay_status s;
	char live_from[200], live_date[64];
	struct cssms_in in;
	int rc;

	/* the IMS message with the same content, for comparison */
	world(NULL, 1);
	gm_rx_hex("l0@ims", CAP_GSM7, NULL);
	CHECK(dev_parse(1, 0, &m));
	snprintf(live_from, sizeof(live_from), "%s", H(&m, "From"));
	snprintf(live_date, sizeof(live_date), "%s", H(&m, "Date"));
	sip_msg_free(&m);
	unworld();

	/* without a store: the LAN MESSAGE of the IMS one; taken at once, no RP-ACK, no network traffic */
	world(NULL, 2);
	rc = cs_text("01051226862", "2026-11-20T05:37:41+09:00", "imsua ap-ims sms test");
	CHECK_EQ(rc, CSSMS_TAKEN);
	CHECK_EQ(dev_count(1), 1); CHECK_EQ(dev_count(2), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK_STR(H(&m, "Content-Type"), "text/plain; charset=utf-8");
	CHECK(!strncmp(H(&m, "From"), live_from, strcspn(live_from, ";")));
	CHECK_STR(H(&m, "Date"), live_date);
	CHECK_STR(H(&m, "X-SMS-Timestamp"), "2026-11-20T05:37:41+09:00");
	CHECK_STR(H(&m, "X-SMS-Class"), "");
	CHECK_STR(H(&m, "X-SMS-Concat"), "");
	CHECK_STR(H(&m, "X-SMS-Part"), "");
	CHECK_STR(bodystr(&m), "imsua ap-ims sms test");
	sip_msg_free(&m);
	dev_answer(1, 200);
	dev_answer(2, 486);
	CHECK_EQ(G.nsent, 0);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_received == 1 && s.mt_delivered == 1 && s.mt_lost_failed == 0);
	/* the same message again (the delete failed, the modem offers it twice): once */
	fakeep_clear(G.w.f);
	CHECK_EQ(cs_text("01051226862", "2026-11-20T05:37:41+09:00", "imsua ap-ims sms test"), CSSMS_TAKEN);
	CHECK_EQ(dev_count(1), 0);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_received == 2 && s.mt_duplicates == 1 && s.mt_delivered == 1);
	/* other text, other time, same sender: not a duplicate */
	CHECK_EQ(cs_text("01051226862", "2026-11-20T05:37:42+09:00", "imsua ap-ims sms test"), CSSMS_TAKEN);
	CHECK_EQ(dev_count(1), 1);
	dev_answer(1, 200);
	dev_answer(2, 200);

	/* alphanumeric sender, class, UTC timestamp, a Korean text */
	fakeep_clear(G.w.f);
	memset(&in, 0, sizeof(in));
	in.kind = CSSMS_TEXT;
	snprintf(in.from, sizeof(in.from), "KT-Info");
	in.from_alnum = true;
	snprintf(in.ts, sizeof(in.ts), "2026-11-20T00:00:00Z");
	in.text = "\xed\x85\x8c\xec\x8a\xa4\xed\x8a\xb8";
	in.sms_class = 1;
	in.id = ++CS.next_id;
	CHECK_EQ(smsrelay_cs_in(G.sr, &in), CSSMS_TAKEN);
	CHECK(dev_parse(1, 0, &m));
	CHECK(has(H(&m, "From"), "alnum.KT-Info"));
	CHECK(has(H(&m, "From"), "\"KT-Info\""));
	CHECK_STR(H(&m, "X-SMS-Sender"), "KT-Info");
	CHECK_STR(H(&m, "X-SMS-Class"), "1");
	CHECK_STR(H(&m, "X-SMS-Timestamp"), "2026-11-20T00:00:00+00:00");
	CHECK_STR(H(&m, "Date"), "Fri, 20 Nov 2026 00:00:00 GMT");
	CHECK_STR(bodystr(&m), "\xed\x85\x8c\xec\x8a\xa4\xed\x8a\xb8");
	sip_msg_free(&m);
	dev_answer(1, 200);
	dev_answer(2, 200);

	/* store off, nobody registered: NOT taken (the modem keeps it); once a device registers the offer is taken and delivered */
	unworld();
	world(NULL, 0);
	CHECK_EQ(cs_text("0101", "2026-11-20T05:37:41+09:00", "later"), -EAGAIN);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_lost_no_client == 0 && s.cs_rx_deferred == 1);
	CHECK_EQ(CS.ndone, 0);
	dev_register(&G.w, 1);
	smsrelay_cs_kick(G.sr);
	CHECK_EQ(CS.nkick, 1);
	CHECK_EQ(cs_text("0101", "2026-11-20T05:37:41+09:00", "later"), CSSMS_TAKEN);
	CHECK_EQ(dev_count(1), 1);
	dev_answer(1, 200);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_delivered == 1 && s.cs_rx_deferred == 1 && s.mt_lost_failed == 0);
	/* the same text offered once more: a duplicate now (it was delivered) */
	fakeep_clear(G.w.f);
	CHECK_EQ(cs_text("0101", "2026-11-20T05:37:41+09:00", "later"), CSSMS_TAKEN);
	CHECK_EQ(dev_count(1), 0);
	unworld();
}

static void t_cs_mt_long(void)
{
	struct sip_msg m;
	char text[3000];
	char all[3100];
	int i, k;
	struct smsrelay_status s;

	/* a joined message of 2500 bytes: ONE logical message, pieces of 1000 bytes one after the other, each answered before the next */
	for (i = 0; i < 2500; i++)
		text[i] = (char)('a' + i % 26);
	text[2500] = 0;
	world(NULL, 1);
	CHECK_EQ(cs_text("+821012345678", "2026-11-20T05:37:41+09:00", text), CSSMS_TAKEN);
	all[0] = 0;
	for (k = 0; k < 3; k++) {
		char mark[32];

		CHECK_EQ(dev_count(1), k + 1);
		if (dev_count(1) != k + 1)
			break;
		CHECK(dev_parse(1, k, &m));
		snprintf(mark, sizeof(mark), "%d/3", k + 1);
		CHECK_STR(H(&m, "X-SMS-Part"), mark);
		CHECK_STR(H(&m, "X-SMS-Timestamp"), "2026-11-20T05:37:41+09:00");
		snprintf(mark, sizeof(mark), "(%d/3) ", k + 1);
		CHECK(!strncmp(bodystr(&m), mark, strlen(mark)));
		strncat(all, bodystr(&m) + strlen(mark), m.body_len - strlen(mark));
		sip_msg_free(&m);
		dev_answer(1, 200);
	}
	CHECK_EQ(dev_count(1), 3);
	CHECK_STR(all, text);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_received == 1 && s.mt_delivered == 1);
	unworld();
}

static void t_cs_backlog_report_mms(void)
{
	struct sip_msg m;
	struct smsrelay_status s;
	struct cssms_in in;
	uint8_t push[] = { 0x01, 0x06, 0x22, 0xbe, 0x00, 0x01, 0x02, 0x03 };

	/* backlog: delivered like the others, the original time kept */
	world(NULL, 1);
	memset(&in, 0, sizeof(in));
	in.kind = CSSMS_TEXT;
	snprintf(in.from, sizeof(in.from), "+821099998888");
	snprintf(in.ts, sizeof(in.ts), "2026-01-02T03:04:05+09:00");
	in.text = "from before the restart";
	in.sms_class = -1;
	in.backlog = true;
	in.id = ++CS.next_id;
	CHECK_EQ(smsrelay_cs_in(G.sr, &in), CSSMS_TAKEN);
	CHECK(dev_parse(1, 0, &m));
	CHECK_STR(H(&m, "X-SMS-Timestamp"), "2026-01-02T03:04:05+09:00");
	CHECK_STR(H(&m, "Date"), "Thu, 01 Jan 2026 18:04:05 GMT");
	CHECK_STR(bodystr(&m), "from before the restart");
	sip_msg_free(&m);
	dev_answer(1, 200);
	unworld();

	/* reports: off, nothing goes to the LAN; on, the notice of the IMS path */
	world(NULL, 1);
	memset(&in, 0, sizeof(in));
	in.kind = CSSMS_REPORT;
	snprintf(in.from, sizeof(in.from), "+821012345678");
	snprintf(in.discharge_ts, sizeof(in.discharge_ts), "2026-11-20T09:00:05+09:00");
	in.message_reference = 42;
	in.delivery_state = 0;
	in.sms_class = -1;
	in.id = ++CS.next_id;
	CHECK_EQ(smsrelay_cs_in(G.sr, &in), CSSMS_TAKEN);
	CHECK_EQ(dev_count(1), 0);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_reports == 1 && s.mt_received == 1);
	unworld();
	world(cs_report_cfg, 1);
	in.id = ++CS.next_id;
	CHECK_EQ(smsrelay_cs_in(G.sr, &in), CSSMS_TAKEN);
	CHECK_EQ(dev_count(1), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK_STR(bodystr(&m), "[Delivery report] SMS to +821012345678: delivered");
	CHECK_STR(H(&m, "X-SMS-Report"), "mr=42;status=0x00;final=yes");
	CHECK_STR(H(&m, "X-SMS-Timestamp"), "2026-11-20T09:00:05+09:00");
	sip_msg_free(&m);
	dev_answer(1, 200);
	in.delivery_state = 0x41;
	in.id = ++CS.next_id;
	CHECK_EQ(smsrelay_cs_in(G.sr, &in), CSSMS_TAKEN);
	CHECK(dev_parse(1, 1, &m));
	CHECK(has(bodystr(&m), "FAILED (status 0x41)"));
	sip_msg_free(&m);
	dev_answer(1, 200);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_reports == 2 && s.mt_delivered == 0);
	unworld();

	/* an MMS notification in CS mode (the MMS manager is not active): the binary notice, counted */
	world(NULL, 1);
	memset(&in, 0, sizeof(in));
	in.kind = CSSMS_DATA;
	snprintf(in.from, sizeof(in.from), "+82101111");
	snprintf(in.ts, sizeof(in.ts), "2026-11-20T09:00:05+09:00");
	in.data = push;
	in.data_len = sizeof(push);
	in.wsp_push = in.mms_hint = true;
	in.sms_class = -1;
	in.id = ++CS.next_id;
	CHECK_EQ(smsrelay_cs_in(G.sr, &in), CSSMS_TAKEN);
	CHECK_EQ(G.push.n, 0);
	CHECK_EQ(dev_count(1), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK(has(bodystr(&m), "[binary SMS, 8 bytes, data coding 0x04] 0106"));
	sip_msg_free(&m);
	dev_answer(1, 200);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.cs_mms_unhandled == 1 && s.mt_push_messages == 0);
	unworld();

	/* ... and the same where the MMS manager is active: it gets the push, port 2948, no notice */
	world(NULL, 1);
	CS.push_active = true;
	in.id = ++CS.next_id;
	CHECK_EQ(smsrelay_cs_in(G.sr, &in), CSSMS_TAKEN);
	CHECK_EQ(G.push.n, 1);
	CHECK(G.push.port == 2948 && G.push.len == sizeof(push) && !memcmp(G.push.data, push, sizeof(push)));
	CHECK_STR(G.push.from, "+82101111");
	CHECK_EQ(dev_count(1), 0);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.cs_mms_unhandled == 0 && s.mt_push_messages == 1);
	/* other binary data is a notice either way */
	in.wsp_push = in.mms_hint = false;
	in.id = ++CS.next_id;
	CHECK_EQ(smsrelay_cs_in(G.sr, &in), CSSMS_TAKEN);
	CHECK_EQ(dev_count(1), 1);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.cs_mms_unhandled == 0 && G.push.n == 1);
	dev_answer(1, 200);
	unworld();
}

static void t_cs_store(void)
{
	struct sip_msg m;
	struct smsrelay_status s;
	struct store_status ss;
	char live_ts[64], live_text[300];

	/* IMS item for comparison */
	world(NULL, 1);
	gm_rx_hex("l0@ims", CAP_GSM7, NULL);
	CHECK(dev_parse(1, 0, &m));
	snprintf(live_ts, sizeof(live_ts), "%s", H(&m, "X-SMS-Timestamp"));
	snprintf(live_text, sizeof(live_text), "%.*s", (int)m.body_len, (const char *)m.body);
	sip_msg_free(&m);
	unworld();

	want_store = true;
	world(NULL, 0);
	dev_reg_s(1, "", NULL);
	dev_away(1);
	/* the modem's copy is deleted (done) only when the item is durable */
	CHECK_EQ(cs_text("01051226862", "2026-11-20T05:37:41+09:00", "imsua ap-ims sms test"), CSSMS_PENDING);
	CHECK_EQ(CS.ndone, 0);
	ssettle();
	CHECK_EQ(CS.ndone, 1);
	CHECK(CS.done_taken && CS.done_id == CS.next_id);
	CHECK_EQ(G.nsent, 0);					/* no RP-ACK */
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_stored == 1 && s.mt_received == 1 && s.mt_lost_no_client == 0 && s.mt_store_fallback == 0);
	store_get_status(G.st, &ss);
	CHECK_EQ(ss.items, 1);
	{
		struct store_info li[4];

		CHECK_EQ(store_list(G.st, 0, li, 4), 1);
		CHECK(li[0].type == STORE_SMS && !strcmp(li[0].peer, "01051226862"));
	}
	/* the device comes back: the message of the IMS path, plus X-IMSD-Seq */
	CHECK_EQ(dev_count(1), 0);
	dev_reg_s(1, "", NULL);
	CHECK_EQ(dev_count(1), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	CHECK_STR(H(&m, "X-SMS-Timestamp"), live_ts);
	CHECK_STR(bodystr(&m), live_text);
	sip_msg_free(&m);
	dev_answer(1, 200);
	ssettle();
	/* a duplicate after the cache forgot it: the store knows it, dropped (taken), no second item */
	evfake_advance(130000);
	ssettle();
	CHECK_EQ(cs_text("01051226862", "2026-11-20T05:37:41+09:00", "imsua ap-ims sms test"), CSSMS_TAKEN);
	ssettle();
	store_get_status(G.st, &ss);
	CHECK_EQ(ss.items, 1);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.mt_duplicates, 1);
	/* a long joined message: ONE item, pieces on delivery */
	{
		char text[2300];
		int i;

		for (i = 0; i < 2200; i++)
			text[i] = (char)('A' + i % 26);
		text[2200] = 0;
		CHECK_EQ(cs_text("01051226862", "2026-11-20T06:00:00+09:00", text), CSSMS_PENDING);
		ssettle();
		store_get_status(G.st, &ss);
		CHECK_EQ(ss.items, 2);
		CHECK_EQ(CS.ndone, 2);
		CHECK_EQ(dev_count(1), 2);
		CHECK(dev_parse(1, 1, &m));
		CHECK_STR(H(&m, "X-IMSD-Seq"), "2");
		CHECK_STR(H(&m, "X-SMS-Part"), "1/3");
		sip_msg_free(&m);
		dev_answer(1, 200);
		ssettle();
		CHECK_EQ(dev_count(1), 3);
		dev_answer(1, 200);
		ssettle();
		CHECK_EQ(dev_count(1), 4);
		dev_answer(1, 200);
		ssettle();
	}
	/* an MMS notification: stored as the notice, counted */
	{
		uint8_t push[] = { 0x01, 0x06, 0x22, 0xbe };

		CHECK_EQ(cs_in(CSSMS_DATA, "+82101111", "2026-11-20T07:00:00+09:00", NULL, push, sizeof(push)), CSSMS_PENDING);
		ssettle();
		smsrelay_get_status(G.sr, &s);
		CHECK_EQ(s.mt_stored, 3);
	}
	unworld_final();
	want_store = false;
}

/* store on: never taken before the store has it durable or a device answered 2xx */
static void t_cs_store_defer(void)
{
	struct smsrelay_status s;
	struct sip_msg m;
	const char *ts = "2026-11-20T05:37:41+09:00";

	/* offered before the store is loaded: not taken (no live path, no LOST), the store becoming ready kicks cssms */
	want_store = true;
	store_noload = true;
	world(NULL, 0);
	CHECK(!store_usable(G.st));
	CHECK_EQ(cs_text("0101", ts, "early"), -EAGAIN);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.cs_rx_deferred == 1 && s.mt_lost_no_client == 0 && s.mt_lost_failed == 0 && s.mt_store_fallback == 0);
	CHECK_EQ(CS.nkick, 0);
	store_noload = false;
	ssettle();
	CHECK(store_usable(G.st));
	CHECK(CS.nkick >= 1);
	CHECK_EQ(cs_text("0101", ts, "early"), CSSMS_PENDING);
	ssettle();
	CHECK(CS.ndone == 1 && CS.done_taken);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_stored == 1 && s.cs_rx_deferred == 1);
	unworld_final();

	/* the store accepts nothing and nobody is registered: not taken, and the retry is not taken for a duplicate */
	world(NULL, 0);
	sio_fault.points = SIO_FP_LOGWRITE;
	sio_fault.err = ENOSPC;
	sio_fault.count = -1;
	CHECK_EQ(cs_text("0102", ts, "nostore"), CSSMS_PENDING);
	ssettle();
	CHECK(CS.ndone == 1 && !CS.done_taken);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_lost_no_client == 0 && s.cs_rx_deferred == 1);
	CHECK_EQ(cs_text("0102", ts, "nostore"), -EAGAIN);	/* store unhealthy now: the same */
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_duplicates == 0 && s.cs_rx_deferred == 2);
	/* a device registers and answers 200: taken (live) */
	dev_register(&G.w, 1);
	fakeep_clear(G.w.f);
	CHECK_EQ(cs_text("0102", ts, "nostore"), CSSMS_PENDING);
	CHECK_EQ(dev_count(1), 1);
	CHECK(dev_parse(1, 0, &m));
	CHECK_STR(bodystr(&m), "nostore");
	sip_msg_free(&m);
	CHECK_EQ(CS.ndone, 1);
	dev_answer(1, 200);
	CHECK(CS.ndone == 2 && CS.done_taken);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_delivered == 1 && s.mt_lost_failed == 0);
	/* a device that refuses: not taken either */
	CHECK_EQ(cs_text("0103", ts, "refused"), CSSMS_PENDING);
	dev_answer(1, 486);
	CHECK(CS.ndone == 3 && !CS.done_taken);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mt_lost_failed == 0 && s.cs_rx_deferred == 3);
	sio_fault.points = 0;
	unworld_final();
	want_store = false;
}

static void t_cs_mo(void)
{
	const char *cid;
	struct smsrelay_status s;
	struct sip_msg m;
	char v[200];

	/* the registration to the IMS network does not matter: the backend is CS */
	world(NULL, 1);
	CS.active = true;
	G.registered = false;
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "hello cs");
	CHECK_EQ(CS.nsubmit, 1);
	CHECK(!strcmp(CS.dest, "01051226862") && !strcmp(CS.text, "hello cs") && !CS.last.delivery_report && CS.last.vp_minutes == 0);
	CHECK_EQ(G.nsent, 0);
	CHECK_EQ(lstat(cid), 0);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mo_submitted == 1 && s.mo_queue_len == 1);
	cs_finish(200, "", 1);
	CHECK_EQ(lstat(cid), 200);
	CHECK_STR(lhdr(cid, "X-SMS-Parts", v, sizeof(v)), "1");
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mo_acked == 1 && s.mo_failed == 0 && s.mo_segments_sent == 1 && s.mo_queue_len == 0);

	/* several parts */
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "long one");
	cs_finish(200, "", 3);
	CHECK_STR(lhdr(cid, "X-SMS-Parts", v, sizeof(v)), "3");
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mo_acked == 2 && s.mo_segments_sent == 4);

	/* the results of cssms */
	{
		static const struct { int st; int want; } R[] = { { 400, 400 }, { 403, 403 }, { 413, 413 }, { 480, 480 }, { 484, 484 },
			{ 502, 502 }, { 503, 503 }, { 504, 504 }, { 599, 502 } };
		unsigned i;

		for (i = 0; i < sizeof(R) / sizeof(R[0]); i++) {
			cid = lan_text(1, "sip:01051226862@192.168.68.1", "x");
			cs_finish(R[i].st, "modem said no", 1);
			CHECK_EQ(lstat(cid), R[i].want);
			if (R[i].want == 503)
				CHECK_STR(lhdr(cid, "Retry-After", v, sizeof(v)), "30");
			CHECK(has(lhdr(cid, "Warning", v, sizeof(v)), "modem said no"));
		}
		smsrelay_get_status(G.sr, &s);
		CHECK_EQ(s.mo_failed, 9);
		CHECK(s.last_error[0]);
	}
	/* synchronous refusals */
	{
		static const struct { int rc; int want; } R[] = { { -EINVAL, 400 }, { -EDESTADDRREQ, 484 }, { -E2BIG, 413 }, { -ENOTCONN, 480 },
			{ -ENOBUFS, 503 }, { -ENOMEM, 503 } };
		unsigned i;

		for (i = 0; i < sizeof(R) / sizeof(R[0]); i++) {
			CS.submit_rc = R[i].rc;
			cid = lan_text(1, "sip:01051226862@192.168.68.1", "x");
			CHECK_EQ(lstat(cid), R[i].want);
			if (R[i].want == 503)
				CHECK_STR(lhdr(cid, "Retry-After", v, sizeof(v)), "10");
		}
		CS.submit_rc = 0;
		smsrelay_get_status(G.sr, &s);
		CHECK_EQ(s.mo_queue_len, 0);
	}
	/* the LAN side's own checks come first, as over IMS */
	cid = lan_msg(1, "sip:01051226862@192.168.68.1", "image/png", "x", 1);
	CHECK_EQ(lstat(cid), 415);
	cid = lan_text(1, "sip:alice@192.168.68.1", "x");
	CHECK_EQ(lstat(cid), 404);
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "");
	CHECK_EQ(lstat(cid), 400);
	CHECK_EQ(CS.nsubmit, 11);

	/* no outcome within the deadline: 202, the real result is only logged */
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "slow");
	evfake_advance(28100);
	CHECK_EQ(lstat(cid), 202);
	cs_finish(200, "", 1);
	CHECK_EQ(lnresp(cid, 202), 1);
	CHECK_EQ(lnresp(cid, 200), 0);
	/* the reports option and the validity period go to cssms */
	unworld();
	world(cs_report_cfg, 1);
	CS.active = true;
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "report me");
	CHECK(CS.last.delivery_report);
	cs_finish(200, "", 1);
	CHECK_EQ(lstat(cid), 200);

	/* the backend is chosen per message: CS, then IMS (a segment goes to the network), then CS again */
	CS.active = false;
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "over ims");
	CHECK(CS.nsubmit == 1 && G.nsent == 1);
	carbon_finish(0, cid);
	CHECK_EQ(lstat(cid), 200);
	CS.active = true;
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "over cs again");
	CHECK(CS.nsubmit == 2 && G.nsent == 1);
	/* the switch while one is in flight does not move it */
	CS.active = false;
	cs_finish(200, "", 1);
	CHECK_EQ(lstat(cid), 200);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.mo_submitted == 3 && s.mo_acked == 3);
	unworld();

	/* carbons: the other device gets the copy when cssms accepted, with the parts; not the sender, not a device without the tag */
	world(NULL, 0);
	CS.active = true;
	dev_register_feat(1, ";+g.imsd.carbons");
	dev_register_feat(2, ";+g.imsd.carbons");
	dev_register_feat(3, "");
	fakeep_clear(G.w.f);
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "copy me");
	CHECK_EQ(dev_count(2), 0);
	cs_finish(200, "", 2);
	CHECK_EQ(dev_count(1), 0); CHECK_EQ(dev_count(2), 1); CHECK_EQ(dev_count(3), 0);
	CHECK(dev_parse(2, 0, &m));
	CHECK_STR(H(&m, "X-IMSD-Carbon"), "sent");
	CHECK_STR(H(&m, "X-IMSD-Peer"), "01051226862");
	CHECK_STR(H(&m, "X-SMS-Parts"), "2");
	CHECK_EQ(strlen(H(&m, "X-IMSD-Carbon-ID")), 16);
	CHECK_STR(bodystr(&m), "copy me");
	sip_msg_free(&m);
	dev_answer(2, 200);
	/* a failed message has no copy */
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "no copy");
	cs_finish(503, "busy", 1);
	CHECK_EQ(dev_count(2), 1);
	smsrelay_get_status(G.sr, &s);
	CHECK(s.carbons_sent == 1 && s.carbons_failed == 0);
	unworld();

	/* the relay stops with a message in cssms' hands: the client gets 503, cssms' late answer is harmless */
	world(NULL, 1);
	CS.active = true;
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "stopping");
	CHECK_EQ(CS.nsubmit, 1);
	smsrelay_free(G.sr);
	G.sr = NULL;
	CHECK_EQ(lstat(cid), 503);
	cs_finish(503, "shutting down", 0);
	unworld();
}

static void t_cs_mo_store(void)
{
	const char *cid;
	struct smsrelay_status s;

	/* with the store: the carbon copy is an item, like over IMS */
	want_store = true;
	world(NULL, 0);
	CS.active = true;
	dev_reg_s(1, ";+g.imsd.carbons", NULL);
	dev_reg_s(2, ";+g.imsd.carbons", NULL);
	cid = lan_text(1, "sip:01051226862@192.168.68.1", "stored copy");
	cs_finish(200, "", 1);
	ssettle();
	CHECK_EQ(lstat(cid), 200);
	smsrelay_get_status(G.sr, &s);
	CHECK_EQ(s.carbons_stored, 1);
	unworld_final();
	want_store = false;
}

int main(void)
{
	imsd_log_level(LOG_CRIT);
	t_rpx();
	printf("rpx            %d checks, %d failures\n", t_checks, t_fails);
	{
		int c0 = t_checks, f0 = t_fails;

		t_fmt();
		printf("fmt            %d checks, %d failures\n", t_checks - c0, t_fails - f0);
	}
#define RUN(f) do { int c0 = t_checks, f0 = t_fails; f(); printf("%-22s %4d checks, %d failures\n", #f, t_checks - c0, t_fails - f0); } while (0)
	RUN(t_mt_ucs2_gsm7);
	RUN(t_mt_nobody);
	RUN(t_mt_nobody_error22);
	RUN(t_mt_timeout);
	RUN(t_mt_dup);
	RUN(t_mt_concat);
	RUN(t_mt_concat_noprefix);
	RUN(t_mt_alnum);
	RUN(t_mt_status_report);
	RUN(t_mt_status_report_notice);
	RUN(t_mt_binary_accept);
	RUN(t_wap_push);
	RUN(t_mt_errors);
	RUN(t_mo_basic);
	RUN(t_mo_carbons);
	RUN(t_mo_long);
	RUN(t_mo_failures);
	RUN(t_mo_timeouts);
	RUN(t_mo_registration);
	RUN(t_mo_queue);
	RUN(t_mo_smsc);
	RUN(t_mo_psi);
	RUN(t_mo_options);
	RUN(t_mo_validation);
	RUN(t_shutdown);
	RUN(t_store_sms);
	RUN(t_cs_mt);
	RUN(t_cs_mt_long);
	RUN(t_cs_backlog_report_mms);
	RUN(t_cs_store);
	RUN(t_cs_store_defer);
	RUN(t_cs_mo);
	RUN(t_cs_mo_store);
	printf("smsrelay: %d checks, %d failures\n", t_checks, t_fails);
	return t_fails ? 1 : 0;
}
