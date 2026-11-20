/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Host tests of the MMS proxy: the HTTP server on real loopback sockets (fake event loop, virtual time), the relay to a fake MMSC on the
 * mock network, fetch allow-list and cache, idempotent sends, acknowledgements with mixed device populations, raw notifications and
 * carbon copies on the real LAN side (registrar, fork) with fake devices.
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "../ua/test_ua.h"
#include "../ua/lan_text.h"
#include "t_common.h"
#include "httpd.h"
#include "mms_lan.h"
#include "mmsproxy.h"
#include "mmsrender.h"
#include "wsp.h"
#include "../util/codec.h"
#include "../store/store.h"

#define UA "TTA-VoLTE/3.0 imsd/0.1 Device_Type/Android_Phone OMD"
#define MMS_CT "application/vnd.wap.mms-message"

/* the verified exchange with the MMSC of LG U+ (M-Send.req 84 bytes, M-Send.conf) */
static const char SEND_REQ_HEX[] =
	"8c8098696d736454303031008d928901819730313035313232363836322f545950453d504c4d4e0096696d736420746573740084a3010418038381ea696d7364204d4d5320ebb09cec8ba020ec8b9ced97982031";
static const char SEND_CONF_HEX[] =
	"8c8198696d736454303031008d929280931f35eaeba994ec8b9ceca780eab08020ec84b1eab3b5eca081ec9cbceba19c20eca084ec86a1eb9098ec9788ec8ab5eb8b88eb8ba42e008b327542747955793300";

#define NRB 12
struct pf {
	struct uaw w;
	struct mms_lan *ml;
	struct mocknet mn;
	struct mms *m;
	struct mmsproxy *px;
	struct mms_cfg cfg;
	struct mmsproxy_cfg pcfg;
	struct mms_link link;
	char dir[64];
	unsigned port;
	uint8_t rb[NRB][4600];
	int nrb;
	uint8_t big[2][70000];
	uint8_t ok_empty[256];
	size_t ok_empty_n;
	struct store *st;		/* the store tests: an inline-backend store in <dir>/s */
};
static struct pf *PF;
static bool pf_want_store;
static int64_t pf_clock = 1795134300;
static lan_binding_cb pf_orig_binding;
static unsigned port_seq;

/* the circuit switched tests: the manager's data connection is a real on-demand bearer on the fake modem (t_bearer.c) */
static struct brig *pf_rig;
static bool pf_want_rig;
static char pf_imsi_s[24], pf_plmn_s[8];

static void pf_link(void *ctx, struct mms_link *out)
{
	(void)ctx;
	if (pf_rig)
		brig_mms_link(pf_rig, out);
	else
		*out = PF->link;
}

static void pf_want(void *ctx, bool w)
{
	(void)ctx;
	if (pf_rig)
		mmsb_want(pf_rig->b, w);
}

static int pf_gate(void *ctx, const struct addr *dst, void (*done)(void *arg, int err), void *arg)
{
	(void)ctx;
	return pf_rig ? mmsb_gate(pf_rig->b, dst, done, arg) : -ENETDOWN;
}

static void pf_gate_cancel(void *ctx, void *arg)
{
	(void)ctx;
	if (pf_rig)
		mmsb_gate_cancel(pf_rig->b, arg);
}

static const char *pf_imsi_fn(void *ctx)
{
	(void)ctx;
	return pf_imsi_s;
}

static const char *pf_plmn_fn(void *ctx)
{
	(void)ctx;
	return pf_plmn_s;
}

static void pf_rig_changed(void *arg)
{
	(void)arg;
	if (PF && PF->m)
		mms_link_changed(PF->m);
}

static const char *pf_host(void *ctx)
{
	(void)ctx;
	return "192.168.68.1";
}

static int64_t pf_wall(void *ctx)
{
	(void)ctx;
	return pf_clock;
}

/* the LAN registrar events go to the store as the core module does it in the daemon */
static void pf_binding(struct lan *l, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why, void *arg)
{
	if (pf_orig_binding)
		pf_orig_binding(l, ev, b, why, arg);
	if (PF && PF->st)
		store_on_binding(PF->st, ev, b, why);
}

static void pf_tweak_lan(struct lan_cfg *c)
{
	pf_orig_binding = c->on_binding;
	c->on_binding = pf_binding;
}

static void pf_spin_hook(void)
{
	if (PF && PF->st)
		store_sync(PF->st);
}

static void pf_devices(void *ctx, unsigned *nm, unsigned *nt)
{
	mms_lan_devices(ctx, nm, nt);
	if (!mmsproxy_listening(PF->px)) {
		*nt += *nm;
		*nm = 0;
	}
}

static const char *pf_proxy_base(void *ctx)
{
	(void)ctx;
	return mmsproxy_base_url(PF->px);
}

static bool pf_own_unknown;

static void pf_own(void *ctx, char *out, size_t n)
{
	(void)ctx;
	snprintf(out, n, "%s", pf_own_unknown ? "" : "+821051226862");
}

static void pf_init(void (*tweak)(struct mms_cfg *, struct mmsproxy_cfg *))
{
	struct pf *f = calloc(1, sizeof(*f));
	struct mms_ops ops;
	struct mmsproxy_ops po;
	struct mock_dns_rule rule;
	struct addr a;
	char sub[96];

	PF = f;
	pf_clock = 1795134300;
	uaw_init(&f->w, pf_want_store ? pf_tweak_lan : NULL, false);
	f->ml = mms_lan_new();
	mms_lan_set(f->ml, f->w.lan);
	mock_init(&f->mn);
	if (pf_want_rig) {
		pf_rig = brig_new();
		pf_rig->on_changed = pf_rig_changed;
	}
	mms_cfg_defaults(&f->cfg);
	snprintf(f->cfg.user_agent, sizeof(f->cfg.user_agent), "%s", UA);
	snprintf(f->cfg.mmsc, sizeof(f->cfg.mmsc), "http://mmsc.test:9084/");
	snprintf(f->dir, sizeof(f->dir), "/tmp/imsd-mms-px-XXXXXX");
	CHECK(mkdtemp(f->dir) != NULL);
	snprintf(f->cfg.dir, sizeof(f->cfg.dir), "%s/m", f->dir);
	mmsproxy_cfg_defaults(&f->pcfg);
	f->port = 20000 + (unsigned)(getpid() % 1000) * 2 + (port_seq++ % 10) * 1100;	/* below the ephemeral range: no clash with client sockets */
	f->pcfg.port = f->port;
	f->pcfg.store_keep_days = 30;	/* the rig keeps an age limit so that the expiry of a copy is known */
	snprintf(sub, sizeof(sub), "%s/p", f->dir);
	snprintf(f->pcfg.dir, sizeof(f->pcfg.dir), "%s", sub);
	f->pcfg.ifname[0] = 0;
	if (pf_want_store) {
		struct store_cfg sc;
		struct store_ops so;
		char sd[96];

		store_cfg_defaults(&sc);
		snprintf(sd, sizeof(sd), "%s/s", f->dir);
		snprintf(sc.dir, sizeof(sc.dir), "%s", sd);
		memset(&so, 0, sizeof(so));
		so.wall = pf_wall;
		so.inline_io = true;
		f->st = store_new(&sc, &so);
		CHECK(f->st != NULL);
		spin_hook = pf_spin_hook;
	}
	if (tweak)
		tweak(&f->cfg, &f->pcfg);
	f->pcfg.max_size = f->cfg.max_size;
	f->link.up = true;
	snprintf(f->link.netdev, sizeof(f->link.netdev), "wwan0");
	addr_set(&f->link.local, "2001:4430:141:990a::cb69", 0);
	addr_set(&a, "2001:4430:8000:20:0:1:0:1", 0);
	f->link.dns[0] = a;
	f->link.n_dns = 1;
	f->link.seq = 1;
	memset(&ops, 0, sizeof(ops));
	ops.link = pf_link;
	ops.want = pf_want;
	ops.gate = pf_gate;
	ops.gate_cancel = pf_gate_cancel;
	ops.imsi = pf_imsi_fn;
	ops.net_plmn = pf_plmn_fn;
	ops.deliver = mms_lan_deliver;
	ops.deliver_raw = mms_lan_deliver_raw;
	ops.deliver_abort = mms_lan_abort;
	ops.devices = pf_devices;
	ops.proxy_base = pf_proxy_base;
	ops.lan_host = pf_host;
	ops.wall = pf_wall;
	ops.net = &f->mn.ops;
	ops.ctx = f->ml;
	ops.store = f->st;
	f->m = mms_new(&f->cfg, &ops);
	CHECK(f->m != NULL);
	memset(&po, 0, sizeof(po));
	po.wall = pf_wall;
	po.own_number = pf_own;
	po.store = f->st;
	f->px = mmsproxy_new(&f->pcfg, &po, f->m);
	CHECK(f->px != NULL);
	addr_set(&a, "127.0.0.1", 0);
	mmsproxy_set_lan(f->px, f->w.lan, &a);
	memset(&rule, 0, sizeof(rule));
	rule.name = "mmsc.test"; rule.type = 28; rule.ttl = 3600; rule.n = 1; addr_set(&rule.addr[0], "2001:db8::10", 0);
	mock_dns_add(&f->mn, &rule);
	rule.name = "omammsc.uplus.co.kr";
	mock_dns_add(&f->mn, &rule);
	f->ok_empty_n = http_ok(f->ok_empty, sizeof(f->ok_empty), 200, "text/plain", "", 0);
}

static void pf_fini(struct pf *f)
{
	char cmd[128];

	mmsproxy_free(f->px);
	mms_free(f->m);
	f->m = NULL;
	if (pf_rig) {
		brig_free(pf_rig);
		pf_rig = NULL;
	}
	pf_imsi_s[0] = pf_plmn_s[0] = 0;
	mms_lan_free(f->ml);
	mock_free(&f->mn);
	spin_hook = NULL;
	store_free(f->st);		/* before uaw_fini: that resets the fake event loop, which owns the store's timers */
	f->st = NULL;
	uaw_fini(&f->w);
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", f->dir);
	if (system(cmd) < 0)
		CHECK(0);
	free(f);
	PF = NULL;
}

/* the next upstream connection is answered with this HTTP response */
static void pf_resp(struct pf *f, int status, const char *ctype, const void *body, size_t n)
{
	struct mock_resp r;
	uint8_t *b = f->rb[f->nrb++ % NRB];

	memset(&r, 0, sizeof(r));
	r.n = http_ok(b, sizeof(f->rb[0]), status, ctype, body, n);
	r.d = b;
	CHECK(r.n > 0);
	mock_respond(&f->mn, &r);
}

static void pf_resp_ok_empty(struct pf *f)
{
	mock_respond(&f->mn, &(struct mock_resp){ .d = f->ok_empty, .n = f->ok_empty_n });
}

static int n_posts(const struct pf *f)
{
	int i, n = 0;

	for (i = 0; i < f->mn.n_conn; i++)
		n += !strncmp(mock_req(&f->mn, i), "POST ", 5);
	return n;
}

static int n_gets(const struct pf *f)
{
	int i, n = 0;

	for (i = 0; i < f->mn.n_conn; i++)
		n += !strncmp(mock_req(&f->mn, i), "GET ", 4);
	return n;
}

/* ------------------------------------------------------------------ */
/* a client with real sockets                                          */

struct hc {
	int fd;
	uint8_t *out;
	size_t out_n, out_off;
	uint8_t buf[72000];
	size_t n;
	bool closed;
	int status;
	size_t body_off;
};

static struct hc *hc_new(unsigned port, const char *ip)
{
	struct hc *c = calloc(1, sizeof(*c));
	struct sockaddr_in sa;

	c->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port);
	inet_pton(AF_INET, ip, &sa.sin_addr);
	if (connect(c->fd, (struct sockaddr *)&sa, sizeof(sa)) && errno != EINPROGRESS) {
		close(c->fd);
		c->fd = -1;
	}
	return c;
}

static void hc_free(struct hc *c)
{
	if (c->fd >= 0)
		close(c->fd);
	free(c->out);
	free(c);
}

static void hc_put(struct hc *c, const void *d, size_t n)
{
	c->out = realloc(c->out, c->out_n + n);
	memcpy(c->out + c->out_n, d, n);
	c->out_n += n;
}

static void hc_puts(struct hc *c, const char *s)
{
	hc_put(c, s, strlen(s));
}

static void hc_io(struct hc *c)
{
	if (c->fd < 0 || c->closed)
		return;
	while (c->out_off < c->out_n) {
		ssize_t w = send(c->fd, c->out + c->out_off, c->out_n - c->out_off, MSG_NOSIGNAL);

		if (w <= 0)
			break;
		c->out_off += (size_t)w;
	}
	for (;;) {
		ssize_t r;

		if (c->n >= sizeof(c->buf) - 1)
			break;
		r = recv(c->fd, c->buf + c->n, sizeof(c->buf) - 1 - c->n, 0);
		if (r > 0) {
			c->n += (size_t)r;
			continue;
		}
		if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != ENOTCONN))
			c->closed = true;
		break;
	}
	c->buf[c->n] = 0;
}

/* run the loop until every client saw its connection close (or rounds run out) */
static void hc_wait(struct hc **cs, int n, int rounds)
{
	int i, r;

	for (r = 0; r < rounds; r++) {
		bool all = true;

		spin(1);
		for (i = 0; i < n; i++) {
			hc_io(cs[i]);
			all = all && (cs[i]->closed || cs[i]->fd < 0);
		}
		if (all)
			return;
	}
}

/* the final response: status line, header lookup, body */
static void hc_parse(struct hc *c)
{
	char *p = (char *)c->buf, *e;

	c->status = 0;
	c->body_off = 0;
	while ((e = strstr(p, "\r\n\r\n"))) {
		int st = 0;

		if (sscanf(p, "HTTP/1.%*d %d", &st) != 1)
			return;
		c->status = st;
		c->body_off = (size_t)(e + 4 - (char *)c->buf);
		if (st >= 200)
			return;
		p = e + 4;
	}
}

static const char *hc_hdr(const struct hc *c, const char *name, char *out, size_t n)
{
	const char *p = (const char *)c->buf, *end = strstr(p, "\r\n\r\n");
	size_t nl = strlen(name);

	out[0] = 0;
	while (end && p < end) {
		const char *e = strstr(p, "\r\n");

		if (!strncasecmp(p, name, nl) && p[nl] == ':') {
			const char *v = p + nl + 1;

			while (*v == ' ')
				v++;
			snprintf(out, n, "%.*s", (int)(e - v), v);
			return out;
		}
		p = e + 2;
	}
	return NULL;
}

static const uint8_t *hc_body(const struct hc *c, size_t *n)
{
	*n = c->n - c->body_off;
	return c->buf + c->body_off;
}

static bool hc_has(const struct hc *c, const char *s)
{
	return strstr((const char *)c->buf, s) != NULL;
}

/* one whole request on a fresh connection */
static struct hc *hc_request(struct pf *f, const char *method, const char *path, const char *ctype, const void *body, size_t bl,
			     const char *extra)
{
	struct hc *c = hc_new(f->port, "127.0.0.1");
	char h[600];
	int l;

	l = snprintf(h, sizeof(h), "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n%s%s%s%s", method, path,
		     ctype ? "Content-Type: " : "", ctype ? ctype : "", ctype ? "\r\n" : "", extra ? extra : "");
	if (!strcmp(method, "POST"))
		l += snprintf(h + l, sizeof(h) - (size_t)l, "Content-Length: %zu\r\n", bl);
	l += snprintf(h + l, sizeof(h) - (size_t)l, "\r\n");
	hc_put(c, h, (size_t)l);
	if (bl)
		hc_put(c, body, bl);
	hc_wait(&c, 1, 600);
	hc_parse(c);
	return c;
}

static struct hc *hc_get(struct pf *f, const char *path)
{
	return hc_request(f, "GET", path, NULL, NULL, 0, NULL);
}

static struct hc *hc_post(struct pf *f, const void *body, size_t n)
{
	return hc_request(f, "POST", "/mms", MMS_CT, body, n, NULL);
}

/* ------------------------------------------------------------------ */
/* LAN devices                                                         */

static reg_id_t dev_reg_at(struct pf *f, const char *ip, int port, int k, const char *params)
{
	char ct[400], cid[32];
	struct addr a = ua_addr(ip, port);

	snprintf(ct, sizeof(ct), "<sip:u%d@%s:%d>%s;expires=600", k, ip, port, params);
	snprintf(cid, sizeof(cid), "px%d-reg", k);
	uaw_rx(&f->w, ip, port, mk_register(ip, ct, 1, cid, -1, "User-Agent: TestPhone\r\n"));
	return reg_identify(lan_registrar(f->w.lan), &a, NULL);
}

static int msg_count(struct pf *f, const char *ip, int port)
{
	int n = 0;

	while (find_sent(f->w.f, ip, port, "MESSAGE", n) >= 0)
		n++;
	return n;
}

static bool msg_parse(struct pf *f, const char *ip, int port, int nth, struct sip_msg *m)
{
	int i = find_sent(f->w.f, ip, port, "MESSAGE", nth);

	return i >= 0 && !fakeep_parse(f->w.f, i, m);
}

static void msg_answer(struct pf *f, const char *ip, int port, int k, int nth, int status)
{
	int i = find_sent(f->w.f, ip, port, "MESSAGE", nth);
	struct sip_msg m;
	struct sip_resp_parts p;
	struct buf b;
	struct addr src = ua_addr(ip, port);
	char ct[96];

	CHECK(i >= 0);
	if (i < 0)
		return;
	CHECK(!fakeep_parse(f->w.f, i, &m));
	snprintf(ct, sizeof(ct), "<sip:u%d@%s:%d>", k, ip, port);
	memset(&p, 0, sizeof(p));
	p.status = status;
	p.to_tag = "tg";
	p.contact = ct;
	buf_init(&b, 0);
	CHECK(!sip_build_response(&b, &m, &p));
	fakeep_rx_n(f->w.f, &src, b.p, b.len);
	buf_free(&b);
	sip_msg_free(&m);
}

static const char *H(const struct sip_msg *m, const char *name)
{
	const char *v = sip_hdr(m, name, 0);

	return v ? v : "";
}

/* a M-Retrieve.conf with one text part */
static void make_conf(struct pb *p, const char *tid, const char *text)
{
	struct pb body = { .n = 0 }, e = { .n = 0 };
	uint8_t ct[8];
	size_t cl = ct_wk_charset(ct, 0x03, 106);

	mp_entry(&e, ct, cl, NULL, 0, text, strlen(text));
	build_multipart(&body, 1, &e);
	cl = ct_wk(ct, 0x23);
	p->n = 0;
	build_retrieve(p, tid, 0x92, "01012345678/TYPE=PLMN", "subj", 1795134000, ct, cl, body.d, body.n);
}

static const char *NURL = "http://mmsc.test:9095/?m1";

static void notify(struct pf *f, const char *tid, const char *url, const char *subject, struct pb *raw)
{
	struct pb n = { .n = 0 }, p = { .n = 0 };

	build_notif(&n, tid, 0x92, "01012345678/TYPE=PLMN", subject, 4000, 600, url);
	build_push(&p, n.d, n.n);
	if (raw)
		*raw = n;
	mms_on_push(f->m, "0100000004", 2948, p.d, p.n);
}

static void urlenc(const char *in, char *out, size_t cap)
{
	size_t k = 0;

	for (; *in && k + 4 < cap; in++) {
		if (isalnum((unsigned char)*in) || *in == '-' || *in == '.' || *in == '_' || *in == '~')
			out[k++] = *in;
		else
			k += (size_t)snprintf(out + k, cap - k, "%%%02X", (unsigned char)*in);
	}
	out[k] = 0;
}

static struct hc *hc_fetch(struct pf *f, const char *url)
{
	char enc[900], path[1000];

	urlenc(url, enc, sizeof(enc));
	snprintf(path, sizeof(path), "/mms/fetch?url=%s", enc);
	return hc_get(f, path);
}

/* ------------------------------------------------------------------ */
/* the HTTP server                                                     */

static void t_http_server(void)
{
	struct pf *f;
	struct hc *c, *cs[10];
	char v[200];
	int i;
	struct mmsproxy_status ps;
	uint8_t pdu[8];
	size_t pl = hexv("8c83980000", pdu, sizeof(pdu));	/* not a real PDU: only the type matters here */

	(void)pl;
	pf_init(NULL);
	f = PF;
	CHECK(mmsproxy_listening(f->px));
	/* status document and the size header on every response */
	c = hc_get(f, "/mms");
	CHECK_EQ(c->status, 200);
	CHECK(hc_hdr(c, "Content-Type", v, sizeof(v)) && !strcmp(v, "application/json"));
	CHECK(hc_hdr(c, "X-MMS-Max-Size", v, sizeof(v)) && !strcmp(v, "1048576"));
	CHECK(hc_hdr(c, "Connection", v, sizeof(v)) && !strcasecmp(v, "close"));
	{
		size_t n;
		const uint8_t *b = hc_body(c, &n);

		CHECK(n && !strncmp((const char *)b, "{\"proxy\":\"imsd\",\"mmsc_known\":true,\"mmsc\":\"http://mmsc.test:9084/\",\"max_size\":1048576}", n - 1));
	}
	hc_free(c);
	c = hc_get(f, "/mms/");
	CHECK_EQ(c->status, 200);
	hc_free(c);
	/* routing and methods */
	c = hc_get(f, "/nope"); CHECK_EQ(c->status, 404); CHECK(hc_hdr(c, "X-MMS-Max-Size", v, sizeof(v))); hc_free(c);
	c = hc_get(f, "/mms/sent/zz"); CHECK_EQ(c->status, 404); hc_free(c);
	c = hc_request(f, "PUT", "/mms", NULL, NULL, 0, NULL); CHECK_EQ(c->status, 405); CHECK(hc_has(c, "Allow: GET, POST, OPTIONS")); hc_free(c);
	c = hc_request(f, "DELETE", "/mms", NULL, NULL, 0, NULL); CHECK_EQ(c->status, 405); hc_free(c);
	c = hc_request(f, "HEAD", "/mms", NULL, NULL, 0, NULL); CHECK_EQ(c->status, 405); hc_free(c);
	c = hc_request(f, "OPTIONS", "/mms", NULL, NULL, 0, NULL); CHECK_EQ(c->status, 204); CHECK(hc_has(c, "Allow: GET, POST, OPTIONS")); hc_free(c);
	c = hc_request(f, "POST", "/mms/fetch", MMS_CT, "x", 1, NULL); CHECK_EQ(c->status, 405); hc_free(c);
	c = hc_request(f, "POST", "/mms", "text/plain", "x", 1, NULL); CHECK_EQ(c->status, 415); hc_free(c);
	c = hc_request(f, "POST", "/mms", MMS_CT, "x", 1, NULL); CHECK_EQ(c->status, 400); hc_free(c);	/* not a PDU */
	c = hc_request(f, "POST", "/mms", MMS_CT, "\x8c\x84", 2, NULL); CHECK_EQ(c->status, 400); hc_free(c);	/* a type that is not accepted here */
	/* garbage, versions, bad headers */
	c = hc_new(f->port, "127.0.0.1"); hc_puts(c, "\x01\x02garbage\r\n\r\n"); hc_wait(&c, 1, 300); hc_parse(c); CHECK_EQ(c->status, 400); hc_free(c);
	c = hc_new(f->port, "127.0.0.1"); hc_puts(c, "GET /mms HTTP/2.0\r\n\r\n"); hc_wait(&c, 1, 300); hc_parse(c); CHECK_EQ(c->status, 505); hc_free(c);
	c = hc_new(f->port, "127.0.0.1"); hc_puts(c, "GET mms HTTP/1.1\r\n\r\n"); hc_wait(&c, 1, 300); hc_parse(c); CHECK_EQ(c->status, 400); hc_free(c);
	c = hc_new(f->port, "127.0.0.1"); hc_puts(c, "GET /mms HTTP/1.1\r\nbad header line\r\n\r\n"); hc_wait(&c, 1, 300); hc_parse(c); CHECK_EQ(c->status, 400); hc_free(c);
	c = hc_new(f->port, "127.0.0.1"); hc_puts(c, "POST /mms HTTP/1.1\r\nContent-Type: " MMS_CT "\r\n\r\n"); hc_wait(&c, 1, 300); hc_parse(c);
	CHECK_EQ(c->status, 411); hc_free(c);
	c = hc_new(f->port, "127.0.0.1"); hc_puts(c, "POST /mms HTTP/1.1\r\nContent-Type: " MMS_CT "\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
	hc_wait(&c, 1, 300); hc_parse(c); CHECK_EQ(c->status, 411); hc_free(c);
	c = hc_new(f->port, "127.0.0.1"); hc_puts(c, "POST /mms HTTP/1.1\r\nContent-Type: " MMS_CT "\r\nContent-Length: 12x\r\n\r\n");
	hc_wait(&c, 1, 300); hc_parse(c); CHECK_EQ(c->status, 400); hc_free(c);
	/* header block too large: 431 */
	c = hc_new(f->port, "127.0.0.1");
	hc_puts(c, "GET /mms HTTP/1.1\r\nX-Pad: ");
	{
		char pad[9000];

		memset(pad, 'a', sizeof(pad));
		hc_put(c, pad, sizeof(pad));
	}
	hc_wait(&c, 1, 400); hc_parse(c); CHECK_EQ(c->status, 431); hc_free(c);
	/* body larger than the cap: 413 from the Content-Length alone, with and without Expect: nothing of the body is read */
	{
		char h[300];

		c = hc_new(f->port, "127.0.0.1");
		snprintf(h, sizeof(h), "POST /mms HTTP/1.1\r\nContent-Type: " MMS_CT "\r\nContent-Length: %u\r\n\r\n", f->cfg.max_size + 1);
		hc_puts(c, h);
		hc_wait(&c, 1, 300); hc_parse(c); CHECK_EQ(c->status, 413); hc_free(c);
		c = hc_new(f->port, "127.0.0.1");
		snprintf(h, sizeof(h), "POST /mms HTTP/1.1\r\nContent-Type: " MMS_CT "\r\nContent-Length: %u\r\nExpect: 100-continue\r\n\r\n",
			 f->cfg.max_size + 1);
		hc_puts(c, h);
		hc_wait(&c, 1, 300); hc_parse(c); CHECK_EQ(c->status, 413); CHECK(!hc_has(c, "100 Continue")); hc_free(c);
		/* Expect with an acceptable size: 100 Continue, then the body is taken */
		c = hc_new(f->port, "127.0.0.1");
		hc_puts(c, "POST /mms HTTP/1.1\r\nContent-Type: " MMS_CT "\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n");
		for (i = 0; i < 60; i++) {
			spin(1);
			hc_io(c);
		}
		CHECK(hc_has(c, "HTTP/1.1 100 Continue\r\n\r\n"));
		CHECK(!hc_has(c, "HTTP/1.1 400"));
		hc_puts(c, "\x8c\x85");		/* M-Acknowledge.ind */
		hc_wait(&c, 1, 300); hc_parse(c); CHECK_EQ(c->status, 200); hc_free(c);
		c = hc_new(f->port, "127.0.0.1");
		hc_puts(c, "POST /mms HTTP/1.1\r\nContent-Type: " MMS_CT "\r\nContent-Length: 2\r\nExpect: 200-ok\r\n\r\n");
		hc_wait(&c, 1, 300); hc_parse(c); CHECK_EQ(c->status, 417); hc_free(c);
	}
	/* pipelined requests: one answer, then the connection is closed; keep-alive is not honoured */
	c = hc_new(f->port, "127.0.0.1");
	hc_puts(c, "GET /mms HTTP/1.1\r\nConnection: keep-alive\r\n\r\nGET /mms HTTP/1.1\r\n\r\n");
	hc_wait(&c, 1, 300); hc_parse(c);
	CHECK_EQ(c->status, 200); CHECK(c->closed);
	{
		const char *p = strstr((const char *)c->buf, "HTTP/1.1 ");

		CHECK(p && !strstr(p + 5, "HTTP/1.1 "));
	}
	hc_free(c);
	/* a client that sends nothing, a head that never ends, a body that never comes: dropped by the timeouts */
	c = hc_new(f->port, "127.0.0.1");
	hc_puts(c, "GET /mms HT");
	for (i = 0; i < 20; i++) {
		spin(2);
		hc_io(c);
	}
	CHECK(!c->closed);
	evfake_advance(11000);
	spin(5);
	hc_io(c);
	CHECK(c->closed);
	hc_parse(c); CHECK_EQ(c->status, 408);
	hc_free(c);
	c = hc_new(f->port, "127.0.0.1");
	hc_puts(c, "POST /mms HTTP/1.1\r\nContent-Type: " MMS_CT "\r\nContent-Length: 10\r\n\r\nab");
	for (i = 0; i < 20; i++) {
		spin(2);
		hc_io(c);
	}
	CHECK(!c->closed);
	evfake_advance(12000);
	spin(5);
	hc_io(c);
	CHECK(c->closed);
	hc_free(c);
	/* a trickle that keeps the idle timer alive is cut by the total time for the request */
	c = hc_new(f->port, "127.0.0.1");
	hc_puts(c, "GET /mms HTTP/1.1\r\n");
	for (i = 0; i < 12 && !c->closed; i++) {
		char one[] = "X-A: b\r\n";

		hc_io(c);
		spin(2);
		hc_put(c, one, 1 + (size_t)(i % 3));
		hc_io(c);
		evfake_advance(4000);
		spin(2);
		hc_io(c);
	}
	CHECK(c->closed);
	hc_free(c);
	/* connection limit: eight idle connections hold the slots, the ninth is told 503 */
	for (i = 0; i < 8; i++) {
		cs[i] = hc_new(f->port, "127.0.0.1");
		hc_puts(cs[i], "GET /mms HT");
		hc_io(cs[i]);
		spin(3);
	}
	spin(10);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.conns, 8);
	cs[8] = hc_new(f->port, "127.0.0.1");
	hc_wait(&cs[8], 1, 300);
	hc_parse(cs[8]);
	CHECK_EQ(cs[8]->status, 503);
	hc_free(cs[8]);
	for (i = 0; i < 8; i++)
		hc_free(cs[i]);
	spin(10);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.conns, 0);
	c = hc_get(f, "/mms");
	CHECK_EQ(c->status, 200);		/* the slots are free again */
	hc_free(c);
	/* a client that leaves right after its request */
	c = hc_new(f->port, "127.0.0.1");
	hc_puts(c, "GET /mms HTTP/1.1\r\n\r\n");
	hc_io(c);
	hc_free(c);
	spin(20);
	pf_fini(f);
}

/* ------------------------------------------------------------------ */
/* helpers on the "real" bytes                                         */

static size_t send_req(uint8_t *out, size_t cap)
{
	return hexv(SEND_REQ_HEX, out, cap);
}

static size_t send_conf(uint8_t *out, size_t cap)
{
	return hexv(SEND_CONF_HEX, out, cap);
}

static void t_relay(void)
{
	struct pf *f;
	uint8_t req[200], conf[200];
	size_t rn = send_req(req, sizeof(req)), cn = send_conf(conf, sizeof(conf)), bn;
	struct hc *c;
	char v[200];
	const uint8_t *b;
	const uint8_t *ub;
	struct mmsproxy_status ps;

	CHECK_EQ(rn, 84);
	/* the verified exchange: the request goes out unchanged, the answer comes back unchanged */
	pf_init(NULL);
	f = PF;
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 200);
	CHECK(hc_hdr(c, "Content-Type", v, sizeof(v)) && !strcmp(v, MMS_CT));
	b = hc_body(c, &bn);
	CHECK_EQ(bn, cn); CHECK(bn == cn && !memcmp(b, conf, cn));
	CHECK_EQ(f->mn.n_conn, 1);
	CHECK(!strncmp(mock_req(&f->mn, 0), "POST / HTTP/1.1\r\nHost: mmsc.test:9084\r\n", 38));
	CHECK(strstr(mock_req(&f->mn, 0), "User-Agent: " UA "\r\n") != NULL);
	CHECK(strstr(mock_req(&f->mn, 0), "Content-Type: application/vnd.wap.mms-message\r\n") != NULL);
	CHECK(strstr(mock_req(&f->mn, 0), "Accept: */*, application/vnd.wap.mms-message, application/vnd.wap.sic\r\n") != NULL);
	CHECK(strstr(mock_req(&f->mn, 0), "Content-Length: 84\r\n") != NULL);
	ub = mock_req_body(&f->mn, 0, &bn);
	CHECK_EQ(bn, rn); CHECK(bn == rn && !memcmp(ub, req, rn));
	hc_free(c);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.relayed_sends, 1); CHECK_EQ(ps.send_failures, 0);
	pf_fini(f);

	/* the MMSC refuses: its status and body are relayed as they are, counted as a failure */
	pf_init(NULL);
	f = PF;
	pf_resp(f, 500, "text/plain", "oops", 4);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 500);
	b = hc_body(c, &bn);
	CHECK(bn == 4 && !memcmp(b, "oops", 4));
	hc_free(c);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.relayed_sends, 1); CHECK_EQ(ps.send_failures, 1);
	pf_fini(f);

	/* the MMSC cannot be reached: 502; does not answer: 504 */
	pf_init(NULL);
	f = PF;
	mock_respond(&f->mn, &(struct mock_resp){ .connect_rc = -ECONNREFUSED });
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 502);
	hc_free(c);
	mock_respond(&f->mn, &(struct mock_resp){ .silent = true });
	{
		struct hc *cc = hc_new(f->port, "127.0.0.1");
		char h[200];

		snprintf(h, sizeof(h), "POST /mms HTTP/1.1\r\nContent-Type: " MMS_CT "\r\nContent-Length: %zu\r\n\r\n", rn);
		hc_puts(cc, h);
		hc_put(cc, req, rn);
		for (int i = 0; i < 40; i++) {
			spin(2);
			hc_io(cc);
		}
		CHECK(!cc->closed);
		evfake_advance(25000);
		hc_wait(&cc, 1, 300);
		hc_parse(cc);
		CHECK_EQ(cc->status, 504);
		hc_free(cc);
	}
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.send_failures, 2);
	pf_fini(f);

	/* the IMS link is down: 503, nothing is sent; no MMSC known: 503 */
	pf_init(NULL);
	f = PF;
	f->link.up = false;
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 503); CHECK_EQ(f->mn.n_conn, 0);
	hc_free(c);
	f->link.up = true;
	f->cfg.mmsc[0] = 0;
	mms_set_cfg(f->m, &f->cfg);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 503); CHECK_EQ(f->mn.n_conn, 0);
	hc_free(c);
	c = hc_get(f, "/mms");
	CHECK(strstr((const char *)c->buf, "\"mmsc_known\":false,\"mmsc\":null") != NULL);
	hc_free(c);
	pf_fini(f);

	/* a PDU that does not parse is 400, a message above the cap is 413 before it is read */
	pf_init(NULL);
	f = PF;
	{
		uint8_t bad[40];

		memcpy(bad, req, 30);
		bad[2] = 0x98; bad[3] = 'x';		/* a header that runs off the end */
		memset(bad + 4, 0x97, 26);
		c = hc_post(f, bad, 30);
		CHECK_EQ(c->status, 400);
		hc_free(c);
		c = hc_post(f, req, 20);		/* an M-Send.req cut inside the headers */
		CHECK_EQ(c->status, 400);
		hc_free(c);
		c = hc_post(f, req, 12);		/* ... or before its content type */
		CHECK_EQ(c->status, 400);
		hc_free(c);
	}
	CHECK_EQ(f->mn.n_conn, 0);
	pf_fini(f);

	/* a message of 600 KiB goes through (more than the old 4 KiB limit of the HTTP client's request body) and arrives whole */
	pf_init(NULL);
	f = PF;
	{
		uint8_t *big = f->big[0];
		struct pb h = { .n = 0 };
		size_t total;

		pb_u8(&h, 0x8c); pb_u8(&h, 0x80); pb_u8(&h, 0x98); pb_text(&h, "BIG1"); pb_u8(&h, 0x8d); pb_u8(&h, 0x92);
		pb_u8(&h, 0x89); pb_u8(&h, 1); pb_u8(&h, 0x81); pb_u8(&h, 0x97); pb_text(&h, "01051226862/TYPE=PLMN");
		pb_u8(&h, 0x84); pb_u8(&h, 0xa3);
		memcpy(big, h.d, h.n);
		total = h.n;
		memset(big + total, 0x5a, 60000);
		total += 60000;
		pf_resp(f, 200, MMS_CT, conf, cn);
		c = hc_post(f, big, total);
		CHECK_EQ(c->status, 200);
		ub = mock_req_body(&f->mn, 0, &bn);
		CHECK_EQ(bn, total); CHECK(bn == total && !memcmp(ub, big, total));
		hc_free(c);
	}
	pf_fini(f);
}

static void tw_small(struct mms_cfg *c, struct mmsproxy_cfg *p)
{
	(void)p;
	c->max_size = 4096;
}

static void t_relay_limits(void)
{
	struct pf *f;
	uint8_t req[200], conf[200], big[4200];
	size_t rn = send_req(req, sizeof(req)), cn = send_conf(conf, sizeof(conf));
	struct hc *c;
	char v[100];

	pf_init(tw_small);
	f = PF;
	memset(big, 0, sizeof(big));
	memcpy(big, req, rn);
	c = hc_post(f, big, 4097);
	CHECK_EQ(c->status, 413);
	CHECK(hc_hdr(c, "X-MMS-Max-Size", v, sizeof(v)) && !strcmp(v, "4096"));
	hc_free(c);
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, big, 4096);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	pf_fini(f);
}

/* ------------------------------------------------------------------ */
/* idempotent sends                                                    */

static void t_idempotent(void)
{
	struct pf *f;
	uint8_t req[200], req2[200], conf[200];
	size_t rn = send_req(req, sizeof(req)), cn = send_conf(conf, sizeof(conf)), bn;
	struct hc *c, *c2, *cs[2];
	const uint8_t *b;
	struct mmsproxy_status ps;
	char h[200];

	pf_init(NULL);
	f = PF;
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 1);
	/* the same transaction id and body again: the stored answer, the MMSC is not contacted */
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 200);
	b = hc_body(c, &bn);
	CHECK(bn == cn && !memcmp(b, conf, cn));
	CHECK(hc_hdr(c, "Content-Type", h, sizeof(h)) && !strcmp(h, MMS_CT));
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 1);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.send_repeats, 1); CHECK_EQ(ps.relayed_sends, 1);
	/* the same transaction id with another body: 409 */
	memcpy(req2, req, rn);
	req2[rn - 1] ^= 1;
	c = hc_post(f, req2, rn);
	CHECK_EQ(c->status, 409);
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 1);
	/* ten minutes later it is a new message again */
	evfake_advance(601000);
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req2, rn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 2);
	pf_fini(f);

	/* two posts of the same message at the same time: one request to the MMSC, both get its answer */
	pf_init(NULL);
	f = PF;
	pf_resp(f, 200, MMS_CT, conf, cn);
	cs[0] = hc_new(f->port, "127.0.0.1");
	cs[1] = hc_new(f->port, "127.0.0.1");
	snprintf(h, sizeof(h), "POST /mms HTTP/1.1\r\nContent-Type: " MMS_CT "\r\nContent-Length: %zu\r\n\r\n", rn);
	hc_puts(cs[0], h); hc_put(cs[0], req, rn);
	hc_puts(cs[1], h); hc_put(cs[1], req, rn);
	hc_wait(cs, 2, 800);
	hc_parse(cs[0]); hc_parse(cs[1]);
	CHECK_EQ(cs[0]->status, 200); CHECK_EQ(cs[1]->status, 200);
	b = hc_body(cs[1], &bn);
	CHECK(bn == cn && !memcmp(b, conf, cn));
	CHECK_EQ(f->mn.n_conn, 1);
	hc_free(cs[0]); hc_free(cs[1]);
	pf_fini(f);

	/* a failure is not remembered: the retry with the same transaction id goes to the MMSC again; an HTTP error status is not either */
	pf_init(NULL);
	f = PF;
	mock_respond(&f->mn, &(struct mock_resp){ .connect_rc = -ECONNREFUSED });
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 502); hc_free(c);
	pf_resp(f, 503, "text/plain", "busy", 4);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 503); hc_free(c);
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 200); hc_free(c);
	CHECK_EQ(f->mn.n_conn, 3);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 200); hc_free(c);
	CHECK_EQ(f->mn.n_conn, 3);
	(void)c2;
	pf_fini(f);

	/* at most four relays at a time: the fifth is told 503 */
	pf_init(NULL);
	f = PF;
	{
		struct hc *many[5];
		int i;

		for (i = 0; i < 5; i++) {
			uint8_t r[200];

			memcpy(r, req, rn);
			r[10] = (uint8_t)('A' + i);		/* another transaction id each */
			mock_respond(&f->mn, &(struct mock_resp){ .silent = true });
			many[i] = hc_new(f->port, "127.0.0.1");
			snprintf(h, sizeof(h), "POST /mms HTTP/1.1\r\nContent-Type: " MMS_CT "\r\nContent-Length: %zu\r\n\r\n", rn);
			hc_puts(many[i], h); hc_put(many[i], r, rn);
		}
		for (i = 0; i < 60; i++) {
			int k;

			spin(2);
			for (k = 0; k < 5; k++)
				hc_io(many[k]);
		}
		{
			int n503 = 0;

			for (i = 0; i < 5; i++) {
				hc_parse(many[i]);
				n503 += many[i]->status == 503;
			}
			CHECK_EQ(n503, 1);		/* whichever came last */
		}
		CHECK_EQ(f->mn.n_conn, 4);
		for (i = 0; i < 5; i++)
			hc_free(many[i]);
	}
	pf_fini(f);
}

/* ------------------------------------------------------------------ */
/* fetch: allow-list, cache                                            */

static void t_fetch(void)
{
	struct pf *f;
	struct pb conf = { .n = 0 };
	struct hc *c, *cs[2];
	const uint8_t *b;
	size_t bn;
	char v[100];
	struct mmsproxy_status ps;

	make_conf(&conf, "RT1", "hello");
	pf_init(NULL);
	f = PF;
	/* no notification yet: only the MMSC's host is allowed */
	c = hc_fetch(f, "http://evil.test/x"); CHECK_EQ(c->status, 403); hc_free(c);
	pf_fini(f);

	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.11", 5060, 1, ";+g.imsd.mms");
	notify(f, "T1", NURL, "subj", NULL);
	spin(20);
	CHECK_EQ(f->mn.n_conn, 0);			/* the raw path: nothing fetched by imsd */
	/* announced URL: allowed, whatever its host */
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	c = hc_fetch(f, NURL);
	CHECK_EQ(c->status, 200);
	CHECK(hc_hdr(c, "Content-Type", v, sizeof(v)) && !strcmp(v, MMS_CT));
	b = hc_body(c, &bn);
	CHECK(bn == conf.n && !memcmp(b, conf.d, conf.n));
	CHECK(strstr(mock_req(&f->mn, 0), "GET /?m1 HTTP/1.1\r\nHost: mmsc.test:9095\r\n") != NULL);
	CHECK(strstr(mock_req(&f->mn, 0), "User-Agent: " UA "\r\n") != NULL);
	hc_free(c);
	/* a URL on the MMSC's host that no notification named: allowed; another host: 403; garbage: 400 */
	pf_resp_ok_empty(f); pf_resp_ok_empty(f);		/* the confirmations of the first fetch */
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	c = hc_fetch(f, "http://mmsc.test:9999/other"); CHECK_EQ(c->status, 200); hc_free(c);
	c = hc_fetch(f, "http://evil.test:9095/?m1"); CHECK_EQ(c->status, 403); hc_free(c);
	c = hc_fetch(f, "http://192.168.1.1/admin"); CHECK_EQ(c->status, 403); hc_free(c);
	c = hc_get(f, "/mms/fetch"); CHECK_EQ(c->status, 400); hc_free(c);
	c = hc_get(f, "/mms/fetch?url="); CHECK_EQ(c->status, 400); hc_free(c);
	c = hc_get(f, "/mms/fetch?url=%zz"); CHECK_EQ(c->status, 400); hc_free(c);
	c = hc_get(f, "/mms/fetch?url=http%3A%2F%2Fmmsc.test%2Fx%20HTTP%2F1.1%0D%0AX-Evil%3A%201"); CHECK_EQ(c->status, 400); hc_free(c);	/* header injection */
	c = hc_get(f, "/mms/fetch?url=http%3A%2F%2Fmmsc.test%2Fx%0D%0AX-Evil%3A%201"); CHECK_EQ(c->status, 400); hc_free(c);
	c = hc_fetch(f, "https://mmsc.test/x"); CHECK_EQ(c->status, 400); hc_free(c);
	c = hc_fetch(f, "ftp://mmsc.test/x"); CHECK_EQ(c->status, 400); hc_free(c);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.denied, 2);
	CHECK_EQ(n_gets(f), 2);
	pf_fini(f);

	/* cache: two concurrent fetches make one request to the MMSC, a later one is served from the cache */
	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.11", 5060, 1, ";+g.imsd.mms");
	notify(f, "T1", NURL, "subj", NULL);
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	{
		char enc[900], path[1000], req[1100];
		int l;

		urlenc(NURL, enc, sizeof(enc));
		snprintf(path, sizeof(path), "/mms/fetch?url=%s", enc);
		l = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: x\r\n\r\n", path);
		cs[0] = hc_new(f->port, "127.0.0.1");
		cs[1] = hc_new(f->port, "127.0.0.1");
		hc_put(cs[0], req, (size_t)l);
		hc_put(cs[1], req, (size_t)l);
		hc_wait(cs, 2, 800);
		hc_parse(cs[0]); hc_parse(cs[1]);
		CHECK_EQ(cs[0]->status, 200); CHECK_EQ(cs[1]->status, 200);
		b = hc_body(cs[1], &bn);
		CHECK(bn == conf.n && !memcmp(b, conf.d, conf.n));
		hc_free(cs[0]); hc_free(cs[1]);
	}
	CHECK_EQ(n_gets(f), 1);
	pf_resp_ok_empty(f); pf_resp_ok_empty(f);		/* NotifyResp and Acknowledge of the first fetch */
	c = hc_fetch(f, NURL);
	CHECK_EQ(c->status, 200);
	b = hc_body(c, &bn);
	CHECK(bn == conf.n && !memcmp(b, conf.d, conf.n));
	CHECK(hc_hdr(c, "Content-Type", v, sizeof(v)) && !strcmp(v, MMS_CT));
	hc_free(c);
	CHECK_EQ(n_gets(f), 1);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.fetches, 1); CHECK_EQ(ps.cache_hits, 2); CHECK_EQ(ps.cache_entries, 1);
	/* after the cache lifetime: a new request to the MMSC (the message is still announced: its notification lives) */
	evfake_advance(601000);
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	c = hc_fetch(f, NURL);
	CHECK_EQ(c->status, 200); hc_free(c);
	CHECK_EQ(n_gets(f), 2);
	pf_fini(f);

	/* the cache is switched off with mms_proxy_cache 0; an answer that is not 200 is passed on and not kept; the MMSC does not answer: 504 */
	pf_init(NULL);
	f = PF;
	f->pcfg.cache_s = 0;
	mmsproxy_set_cfg(f->px, &f->pcfg);
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp(f, 404, "text/plain", "gone", 4);
	c = hc_fetch(f, "http://mmsc.test:9095/a"); CHECK_EQ(c->status, 200); hc_free(c);
	c = hc_fetch(f, "http://mmsc.test:9095/a"); CHECK_EQ(c->status, 200); hc_free(c);
	CHECK_EQ(n_gets(f), 2);
	c = hc_fetch(f, "http://mmsc.test:9095/b"); CHECK_EQ(c->status, 404);
	b = hc_body(c, &bn);
	CHECK(bn == 4 && !memcmp(b, "gone", 4));
	hc_free(c);
	f->link.up = false;
	c = hc_fetch(f, "http://mmsc.test:9095/a"); CHECK_EQ(c->status, 503); hc_free(c);
	pf_fini(f);
}

/* ------------------------------------------------------------------ */
/* acknowledgements, raw notifications, mixed device populations        */

static void check_ack_pair(struct pf *f, int ci, const char *tid, const char *ack_tid)
{
	uint8_t want[96];
	const uint8_t *got;
	size_t gn, wn;

	wn = mms_encode_notifyresp(tid, 0x92, MMS_ST_RETRIEVED, want, sizeof(want));
	got = mock_req_body(&f->mn, ci, &gn);
	CHECK(gn == wn && got && !memcmp(got, want, wn));
	CHECK(!strncmp(mock_req(&f->mn, ci), "POST / HTTP/1.1\r\nHost: mmsc.test:9084\r\n", 38));
	if (ack_tid) {
		wn = mms_encode_acknowledge(ack_tid, 0x92, want, sizeof(want));
		got = mock_req_body(&f->mn, ci + 1, &gn);
		CHECK(gn == wn && got && !memcmp(got, want, wn));
	}
}

static void t_raw_only(void)
{
	struct pf *f;
	struct pb conf = { .n = 0 };
	struct hc *c;
	struct sip_msg m;
	struct mms_status st;
	uint8_t cap[256];
	struct wsp_push wp;

	/* the notification (127-byte push) as received from the carrier: the body of the SIP MESSAGE is the MMS PDU, byte for byte */
	{
		size_t cn = hexv("0006246170706c69636174696f6e2f766e642e7761702e6d6d732d6d65737361676500af84b4878c8298417642743666"
				 "3771008d928a808e0201f08805810303f1f483687474703a2f2f6f6d616d6d73632e75706c75732e636f2e6b723a3930"
				 "39352f3f417642743666377100890580313134009609ea5b4c4720552b5d00", cap, sizeof(cap));

		CHECK_EQ(cn, 127);
		CHECK_EQ(wsp_parse_push(cap, cn, &wp), 0);
	}
	make_conf(&conf, "AvBt6f7q-R", "from the network");
	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.11", 5060, 1, ";+g.imsd.mms;+g.imsd.carbons");
	fakeep_clear(f->w.f);
	mms_on_push(f->m, "0100000004", 2948, cap, 127);
	spin(60);
	CHECK_EQ(f->mn.n_conn, 0);			/* imsd fetches nothing and confirms nothing yet */
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 1);
	CHECK(msg_parse(f, "192.168.68.11", 5060, 0, &m));
	CHECK_STR(H(&m, "Content-Type"), MMS_CT);
	CHECK_EQ(m.body_len, wp.body_len);
	CHECK(m.body_len == wp.body_len && !memcmp(m.body, wp.body, wp.body_len));
	CHECK(strstr(H(&m, "From"), "sip:114@") != NULL);
	CHECK_STR(H(&m, "X-MMS"), "1");
	CHECK_STR(H(&m, "X-MMS-Transaction-ID"), "AvBt6f7q");
	CHECK_STR(H(&m, "X-MMS-Proxy"), PF->px ? mmsproxy_base_url(f->px) : "");
	CHECK(!strncmp(H(&m, "X-MMS-Proxy"), "http://127.0.0.1:", 16));
	CHECK_STR(H(&m, "X-MMS-Max-Size"), "1048576");
	CHECK_STR(H(&m, "X-SMS-Timestamp"), "2026-11-20T00:25:00+00:00");
	CHECK_STR(H(&m, "X-MMS-Subject"), "");
	CHECK_STR(H(&m, "X-MMS-Content-Location"), "http://omammsc.uplus.co.kr:9095/?AvBt6f7q");
	CHECK_STR(H(&m, "X-MMS-Size"), "496");
	CHECK_STR(H(&m, "X-MMS-Expiry"), "2026-11-23T00:14:08+00:00");	/* 258548 s after the arrival */
	sip_msg_free(&m);
	msg_answer(f, "192.168.68.11", 5060, 1, 0, 200);
	spin(10);
	mms_get_status(f->m, &st);
	CHECK_EQ(st.notifications, 1); CHECK_EQ(st.raw_delivered, 1); CHECK_EQ(st.delivered, 0); CHECK_EQ(st.lost_no_client, 0);
	/* the first proxied fetch is what imsd confirms: M-NotifyResp.ind (Retrieved), then M-Acknowledge.ind with the id of the retrieve-conf */
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp_ok_empty(f);
	pf_resp_ok_empty(f);
	c = hc_fetch(f, "http://omammsc.uplus.co.kr:9095/?AvBt6f7q");
	CHECK_EQ(c->status, 200);
	hc_free(c);
	spin(80);
	CHECK_EQ(f->mn.n_conn, 3);
	CHECK_EQ(n_gets(f), 1); CHECK_EQ(n_posts(f), 2);
	check_ack_pair(f, 1, "AvBt6f7q", "AvBt6f7q-R");
	/* more fetches (cache), the device's own confirmations: nothing more goes to the MMSC */
	c = hc_fetch(f, "http://omammsc.uplus.co.kr:9095/?AvBt6f7q"); CHECK_EQ(c->status, 200); hc_free(c);
	{
		uint8_t nr[64], ak[64];
		size_t nn = mms_encode_notifyresp("AvBt6f7q", 0x92, MMS_ST_RETRIEVED, nr, sizeof(nr));
		size_t an = mms_encode_acknowledge("AvBt6f7q-R", 0x92, ak, sizeof(ak));

		c = hc_post(f, nr, nn); CHECK_EQ(c->status, 200); CHECK(c->n - c->body_off == 0); hc_free(c);
		c = hc_post(f, ak, an); CHECK_EQ(c->status, 200); hc_free(c);
	}
	spin(80);
	CHECK_EQ(f->mn.n_conn, 3);
	mms_get_status(f->m, &st);
	CHECK_EQ(st.acked, 2); CHECK_EQ(st.proxy_acks, 1);
	/* the same message announced again under a new transaction id after the device fetched it: not passed on, confirmed */
	fakeep_clear(f->w.f);
	pf_resp_ok_empty(f);
	notify(f, "T9", "http://mmsc.test:9095/?m9", "", NULL);	/* other content: delivered */
	spin(40);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 1);
	pf_fini(f);

	/* a device that confirms (M-NotifyResp.ind Retrieved) without having fetched through the proxy triggers imsd's confirmation, once */
	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.11", 5060, 1, ";+g.imsd.mms");
	notify(f, "T2", NURL, "x", NULL);
	spin(20);
	{
		uint8_t nr[64];
		size_t nn = mms_encode_notifyresp("T2", 0x92, MMS_ST_RETRIEVED, nr, sizeof(nr));
		uint8_t unk[64];
		size_t un = mms_encode_notifyresp("UNKNOWN", 0x92, MMS_ST_RETRIEVED, unk, sizeof(unk));
		uint8_t rej[64];
		size_t rn = mms_encode_notifyresp("T2", 0x92, MMS_ST_REJECTED, rej, sizeof(rej));

		pf_resp_ok_empty(f);
		c = hc_post(f, unk, un); CHECK_EQ(c->status, 200); hc_free(c);
		c = hc_post(f, rej, rn); CHECK_EQ(c->status, 200); hc_free(c);
		spin(40);
		CHECK_EQ(f->mn.n_conn, 0);		/* unknown tid / another status: swallowed */
		c = hc_post(f, nr, nn); CHECK_EQ(c->status, 200); hc_free(c);
		c = hc_post(f, nr, nn); CHECK_EQ(c->status, 200); hc_free(c);
		spin(60);
		CHECK_EQ(f->mn.n_conn, 1);
		check_ack_pair(f, 0, "T2", NULL);
	}
	pf_fini(f);
}

static void t_mixed(void)
{
	struct pf *f;
	struct pb conf = { .n = 0 }, raw = { .n = 0 };
	struct hc *c;
	struct sip_msg m;
	struct mms_status st;

	make_conf(&conf, "RTM", "mixed text");
	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.11", 5060, 1, ";+g.imsd.mms");		/* the MMS client */
	dev_reg_at(f, "192.168.68.12", 5060, 2, "");			/* a softphone */
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp_ok_empty(f);
	pf_resp_ok_empty(f);
	notify(f, "TM1", NURL, "mixed", &raw);
	spin(200);
	/* the client has the original notification and nothing else, the softphone the text; one confirmation pair upstream */
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 1);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 1);
	CHECK(msg_parse(f, "192.168.68.11", 5060, 0, &m));
	CHECK_STR(H(&m, "Content-Type"), MMS_CT);
	CHECK(m.body_len == raw.n && !memcmp(m.body, raw.d, raw.n));
	CHECK_STR(H(&m, "X-MMS-Transaction-ID"), "TM1");
	sip_msg_free(&m);
	CHECK(msg_parse(f, "192.168.68.12", 5060, 0, &m));
	CHECK_STR(H(&m, "Content-Type"), "text/plain; charset=utf-8");
	CHECK(strstr((const char *)m.body, "mixed text") != NULL);
	CHECK_STR(H(&m, "X-MMS-Transaction-ID"), "");
	sip_msg_free(&m);
	msg_answer(f, "192.168.68.11", 5060, 1, 0, 200);
	msg_answer(f, "192.168.68.12", 5060, 2, 0, 200);
	spin(60);
	CHECK_EQ(f->mn.n_conn, 3);
	CHECK_EQ(n_gets(f), 1); CHECK_EQ(n_posts(f), 2);
	check_ack_pair(f, 1, "TM1", "RTM");
	/* now the client fetches through the proxy (a second GET: the text path does not feed the cache): no further confirmation */
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	c = hc_fetch(f, NURL); CHECK_EQ(c->status, 200); hc_free(c);
	spin(80);
	CHECK_EQ(n_gets(f), 2); CHECK_EQ(n_posts(f), 2);
	mms_get_status(f->m, &st);
	CHECK_EQ(st.delivered, 1); CHECK_EQ(st.raw_delivered, 1); CHECK_EQ(st.acked, 2); CHECK_EQ(st.proxy_acks, 0);
	/* the duplicate suppression of the text path still works: the same message again under a new transaction id */
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp_ok_empty(f);
	pf_resp_ok_empty(f);
	notify(f, "TM2", "http://mmsc.test:9095/?m2", "mixed", NULL);
	spin(200);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 0);	/* text: same content as a delivered message, not delivered again */
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 0);	/* original: the earlier one was fetched through the proxy */
	CHECK_EQ(n_posts(f), 4);				/* but confirmed (NotifyResp + Acknowledge) */
	mms_get_status(f->m, &st);
	CHECK_EQ(st.duplicates, 1);
	pf_fini(f);

	/* the proxy is down: the MMS client gets the text like everybody */
	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.11", 5060, 1, ";+g.imsd.mms");
	f->pcfg.port = 0;
	mmsproxy_set_cfg(f->px, &f->pcfg);
	CHECK(!mmsproxy_listening(f->px));
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp_ok_empty(f);
	pf_resp_ok_empty(f);
	notify(f, "TM3", NURL, "mixed", NULL);
	spin(200);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 1);
	CHECK(msg_parse(f, "192.168.68.11", 5060, 0, &m));
	CHECK_STR(H(&m, "Content-Type"), "text/plain; charset=utf-8");
	sip_msg_free(&m);
	pf_fini(f);

	/* nobody registered: lost, as before (raw or text) */
	pf_init(NULL);
	f = PF;
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp_ok_empty(f);
	pf_resp_ok_empty(f);
	notify(f, "TM4", NURL, "mixed", NULL);
	spin(200);
	mms_get_status(f->m, &st);
	CHECK_EQ(st.lost_no_client, 1);
	pf_fini(f);
}

static void t_renotify(void)
{
	struct pf *f;
	struct pb conf = { .n = 0 };
	struct mms_status st;
	struct hc *c;

	make_conf(&conf, "RTN", "again");
	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.11", 5060, 1, ";+g.imsd.mms");
	fakeep_clear(f->w.f);
	/* the MMSC announces the same message twice under two transaction ids (nobody fetched the first): both reach the client */
	notify(f, "A1", "http://mmsc.test:9095/?a1", "same", NULL);
	spin(30);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 1);
	notify(f, "A1", "http://mmsc.test:9095/?a1", "same", NULL);	/* the same transaction id: a repeat, ignored */
	spin(30);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 1);
	notify(f, "A2", "http://mmsc.test:9095/?a2", "same", NULL);
	spin(30);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 2);
	/* the client fetches the second one: confirmed for A2 (with the acknowledge), and A1, which nobody will fetch, is confirmed as well */
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp_ok_empty(f); pf_resp_ok_empty(f); pf_resp_ok_empty(f);
	c = hc_fetch(f, "http://mmsc.test:9095/?a2"); CHECK_EQ(c->status, 200); hc_free(c);
	spin(100);
	CHECK_EQ(n_gets(f), 1); CHECK_EQ(n_posts(f), 3);
	check_ack_pair(f, 1, "A2", "RTN");
	{
		uint8_t want[64];
		size_t wn = mms_encode_notifyresp("A1", 0x92, MMS_ST_RETRIEVED, want, sizeof(want)), gn;
		const uint8_t *got = mock_req_body(&f->mn, 3, &gn);

		CHECK(gn == wn && got && !memcmp(got, want, wn));
	}
	/* the third announcement of the same message (the MMSC did not believe the confirmations): confirmed, not passed on */
	pf_resp_ok_empty(f); pf_resp_ok_empty(f);
	notify(f, "A3", "http://mmsc.test:9095/?a3", "same", NULL);
	spin(100);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 2);
	CHECK_EQ(n_posts(f), 5);
	check_ack_pair(f, 4, "A3", "RTN");
	mms_get_status(f->m, &st);
	CHECK_EQ(st.duplicates, 2);			/* the repeat of A1 and A3 */
	/* a different message is not mistaken for it */
	notify(f, "B1", "http://mmsc.test:9095/?b1", "other", NULL);
	spin(30);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 3);
	pf_fini(f);
}

/* ------------------------------------------------------------------ */
/* carbon copies of sent MMS                                           */

static void tw_keep1(struct mms_cfg *c, struct mmsproxy_cfg *p)
{
	(void)c;
	p->keep_messages = 1;
}

static struct hc *hc_px(struct pf *f, const char *method, const char *uri, const char *ctype, const void *body, size_t bl);

/* The announcement of a sent MMS: the content type and the headers of a received raw notification, the body an M-Notification.ind that the
 * tree's own decoder reads back; seq 0 = live without the store (no X-IMSD-Seq). */
static void carbon_check(struct pf *f, const struct sip_msg *m, size_t rn, unsigned long seq, const char *from, const char *subject,
			 int64_t expiry)
{
	struct mms_notif nf;
	char url[200], v[200], iso[48];

	CHECK_STR(H(m, "Content-Type"), MMS_CT);
	snprintf(v, sizeof(v), "%zu", m->body_len);
	CHECK_STR(H(m, "Content-Length"), v);
	CHECK_EQ(mms_decode_notification(m->body, m->body_len, &nf), 0);
	snprintf(url, sizeof(url), "http://127.0.0.1:%u/mms/sent/%s", f->port, H(m, "X-IMSD-Carbon-ID"));
	CHECK_EQ(strlen(H(m, "X-IMSD-Carbon-ID")), 32);
	CHECK_STR(nf.tid, H(m, "X-IMSD-Carbon-ID"));
	CHECK_EQ(nf.version, MMS_VERSION_1_2);
	CHECK_STR(nf.from, from);
	CHECK_STR(nf.subject, subject);
	CHECK_EQ(nf.msg_class, 0);
	CHECK(nf.has_size && nf.size == rn);
	CHECK(nf.has_expiry && !nf.expiry_relative && nf.expiry == expiry);
	CHECK_STR(nf.location, url);
	CHECK_STR(H(m, "X-MMS-Location"), url);
	CHECK_STR(H(m, "X-MMS-Content-Location"), url);
	CHECK_STR(H(m, "X-MMS"), "1");
	CHECK_STR(H(m, "X-MMS-Transaction-ID"), H(m, "X-IMSD-Carbon-ID"));
	snprintf(v, sizeof(v), "http://127.0.0.1:%u/mms", f->port);
	CHECK_STR(H(m, "X-MMS-Proxy"), v);
	snprintf(v, sizeof(v), "%u", f->pcfg.max_size);
	CHECK_STR(H(m, "X-MMS-Max-Size"), v);
	snprintf(v, sizeof(v), "%zu", rn);
	CHECK_STR(H(m, "X-MMS-Size"), v);
	lan_text_iso(expiry, iso, sizeof(iso));
	CHECK_STR(H(m, "X-MMS-Expiry"), iso);
	CHECK_STR(H(m, "X-SMS-Timestamp"), "2026-11-20T00:25:00+00:00");
	CHECK_STR(H(m, "X-IMSD-Carbon"), "sent");
	if (seq) {
		snprintf(v, sizeof(v), "%lu", seq);
		CHECK_STR(H(m, "X-IMSD-Seq"), v);
	} else {
		CHECK_STR(H(m, "X-IMSD-Seq"), "");
	}
}

/* no subject, own number unknown, exact wire form of the notification */
static void t_carbons_mms_notif(void)
{
	struct pf *f;
	uint8_t req[200], conf[200], nr[64];
	size_t rn = send_req(req, sizeof(req)), cn = send_conf(conf, sizeof(conf)), nn;
	struct hc *c;
	struct sip_msg m;
	struct mms_notif nf;
	uint8_t want[300];
	size_t wn;
	char id[40];
	const uint8_t *b;
	size_t bn;

	/* a send without a subject: strip the Subject header (96 <len> ... ) from the PDU: 96 'imsd test' 00 */
	{
		uint8_t *sp = memmem(req, rn, "\x96imsd test", 10);

		CHECK(sp != NULL);
		memmove(sp, sp + 11, rn - (size_t)(sp + 11 - req));
		rn -= 11;
	}
	pf_own_unknown = true;
	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.12", 5060, 2, ";+g.imsd.carbons");
	dev_reg_at(f, "192.168.68.13", 5060, 3, ";+g.imsd.mms");	/* no carbons: nothing */
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn); CHECK_EQ(c->status, 200); hc_free(c);
	spin(40);
	pf_own_unknown = false;
	CHECK_EQ(msg_count(f, "192.168.68.13", 5060), 0);
	CHECK(msg_parse(f, "192.168.68.12", 5060, 0, &m));
	CHECK_STR(H(&m, "X-MMS-Subject"), "");
	snprintf(id, sizeof(id), "%s", H(&m, "X-IMSD-Carbon-ID"));
	CHECK(strstr(H(&m, "From"), "sip:imsd@") != NULL);
	CHECK_EQ(mms_decode_notification(m.body, m.body_len, &nf), 0);
	CHECK_STR(nf.from, "");
	CHECK_STR(nf.subject, "");
	/* exactly: type, tid, version 1.2, From = insert-address-token, class personal, size, expiry (absolute, 7 days), content location */
	{
		char url[200];
		struct pb pw = { .n = 0 };
		uint64_t ex = 1795134300ull + 7 * 86400;

		snprintf(url, sizeof(url), "http://127.0.0.1:%u/mms/sent/%s", f->port, id);
		pb_u8(&pw, 0x8c); pb_u8(&pw, 0x82); pb_u8(&pw, 0x98); pb_text(&pw, id); pb_u8(&pw, 0x8d); pb_u8(&pw, 0x92);
		pb_u8(&pw, 0x89); pb_u8(&pw, 1); pb_u8(&pw, 0x81);
		pb_u8(&pw, 0x8a); pb_u8(&pw, 0x80);
		pb_u8(&pw, 0x8e); pb_long(&pw, rn);
		pb_u8(&pw, 0x88); pb_u8(&pw, 6); pb_u8(&pw, 0x80); pb_long(&pw, ex);
		pb_u8(&pw, 0x83); pb_text(&pw, url);
		wn = pw.n;
		memcpy(want, pw.d, wn);
	}
	CHECK(m.body_len == wn && !memcmp(m.body, want, wn));
	sip_msg_free(&m);
	msg_answer(f, "192.168.68.12", 5060, 2, 0, 200);
	spin(10);
	/* the announced URL gives the M-Send.req, not a retrieve.conf */
	{
		char path[100];

		snprintf(path, sizeof(path), "/mms/sent/%s", id);
		c = hc_get(f, path);
		CHECK_EQ(c->status, 200);
		b = hc_body(c, &bn);
		CHECK(bn == rn && !memcmp(b, req, rn));
		hc_free(c);
	}
	/* a client that answers the announcement as for a received MMS: swallowed (200, nothing forwarded, no fetch) */
	nn = mms_encode_notifyresp(id, MMS_VERSION_1_2, MMS_ST_RETRIEVED, nr, sizeof(nr));
	{
		unsigned posts = f->mn.n_conn;

		c = hc_post(f, nr, nn); CHECK_EQ(c->status, 200); hc_free(c);
		nn = mms_encode_acknowledge(id, MMS_VERSION_1_2, nr, sizeof(nr));
		c = hc_post(f, nr, nn); CHECK_EQ(c->status, 200); hc_free(c);
		spin(30);
		CHECK_EQ(f->mn.n_conn, posts);
	}
	pf_fini(f);
}

/* the announced URL through the forward proxy form: an absolute-URI request to the gateway's own listener */
static void t_carbons_mms_proxyform(void)
{
	struct pf *f;
	uint8_t req[200], conf[200];
	size_t rn = send_req(req, sizeof(req)), cn = send_conf(conf, sizeof(conf)), bn;
	struct hc *c;
	struct sip_msg m;
	char id[40], url[200], pth[200];
	const uint8_t *b;
	struct mmsproxy_status ps;

	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.12", 5060, 2, ";+g.imsd.carbons");
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn); CHECK_EQ(c->status, 200); hc_free(c);
	spin(40);
	CHECK(msg_parse(f, "192.168.68.12", 5060, 0, &m));
	snprintf(url, sizeof(url), "%s", H(&m, "X-MMS-Content-Location"));
	snprintf(id, sizeof(id), "%s", H(&m, "X-IMSD-Carbon-ID"));
	sip_msg_free(&m);
	CHECK(strstr(url, "http://127.0.0.1:") == url);
	c = hc_px(f, "GET", url, NULL, NULL, 0);
	CHECK_EQ(c->status, 200);
	b = hc_body(c, &bn);
	CHECK(bn == rn && !memcmp(b, req, rn));
	hc_free(c);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.denied, 0);
	CHECK_EQ(f->mn.n_conn, 1);					/* only the send itself went to the MMSC */
	/* the same with another spelling of the host's case and an unknown id: 404 from the gateway, not a request to the operator */
	snprintf(pth, sizeof(pth), "http://127.0.0.1:%u/mms/sent/%032d", f->port, 7);
	c = hc_px(f, "GET", pth, NULL, NULL, 0);
	CHECK_EQ(c->status, 404);
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 1);
	/* another host with the same path is not ours: the old rule (not announced: 403) */
	snprintf(pth, sizeof(pth), "http://other.test:%u/mms/sent/%s", f->port, id);
	c = hc_px(f, "GET", pth, NULL, NULL, 0);
	CHECK_EQ(c->status, 403);
	hc_free(c);
	pf_fini(f);
}

static void t_carbons_mms(void)
{
	struct pf *f;
	uint8_t req[200], req2[200], conf[200];
	size_t rn = send_req(req, sizeof(req)), cn = send_conf(conf, sizeof(conf)), bn;
	struct hc *c;
	struct sip_msg m;
	char id[40], loc[200], path[100];
	const uint8_t *b;
	struct mmsproxy_status ps;

	pf_init(tw_keep1);
	f = PF;
	/* the sender (the HTTP client's address 127.0.0.1), another device that wants copies, one that does not, one with the tags that
	 * is the sender's twin on the same IP (also excluded) */
	dev_reg_at(f, "127.0.0.1", 5070, 1, ";+g.imsd.mms;+g.imsd.carbons");
	dev_reg_at(f, "127.0.0.1", 5071, 4, ";+g.imsd.carbons");
	dev_reg_at(f, "192.168.68.12", 5060, 2, ";+g.imsd.carbons");
	dev_reg_at(f, "192.168.68.13", 5060, 3, "");
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	spin(40);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 1);
	CHECK_EQ(msg_count(f, "192.168.68.13", 5060), 0);
	CHECK_EQ(msg_count(f, "127.0.0.1", 5070), 0);
	CHECK_EQ(msg_count(f, "127.0.0.1", 5071), 0);
	CHECK(msg_parse(f, "192.168.68.12", 5060, 0, &m));
	/* announced like a received MMS: the headers of a raw notification, the body an M-Notification.ind made by the gateway */
	carbon_check(f, &m, rn, 0, "+821051226862", "imsd test", 1795134300 + 7 * 86400);
	CHECK(strstr(H(&m, "From"), "sip:+821051226862@") != NULL);
	CHECK_STR(H(&m, "X-IMSD-Carbon"), "sent");
	CHECK_STR(H(&m, "X-MMS"), "1");
	CHECK_STR(H(&m, "X-MMS-Message-ID"), "2uBtyUy3");
	CHECK_STR(H(&m, "X-IMSD-Peer"), "01051226862");
	CHECK_STR(H(&m, "X-MMS-Subject"), "imsd test");
	CHECK_STR(H(&m, "X-SMS-Timestamp"), "2026-11-20T00:25:00+00:00");
	snprintf(loc, sizeof(loc), "%s", H(&m, "X-MMS-Location"));
	snprintf(id, sizeof(id), "%s", H(&m, "X-IMSD-Carbon-ID"));
	CHECK_EQ(strlen(id), 32);
	snprintf(path, sizeof(path), "http://127.0.0.1:%u/mms/sent/%s", f->port, id);
	CHECK_STR(loc, path);
	sip_msg_free(&m);
	msg_answer(f, "192.168.68.12", 5060, 2, 0, 200);
	spin(10);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.carbons_sent, 1);
	/* the stored request, as many times as the copy is kept */
	snprintf(path, sizeof(path), "/mms/sent/%s", id);
	c = hc_get(f, path);
	CHECK_EQ(c->status, 200);
	b = hc_body(c, &bn);
	CHECK(bn == rn && !memcmp(b, req, rn));
	{
		char ct[100];

		CHECK(hc_hdr(c, "Content-Type", ct, sizeof(ct)) && !strcmp(ct, MMS_CT));
	}
	hc_free(c);
	c = hc_get(f, path); CHECK_EQ(c->status, 200); hc_free(c);
	/* a rejected send (Response-Status other than OK) is no copy */
	{
		uint8_t bad[200];

		memcpy(bad, conf, cn);
		bad[7] = 0x81;			/* 8c 81 98 .. 00 8d 92 92 <status> */
		memcpy(req2, req, rn);
		req2[10] = 'X';
		bad[3] = 'X';
		{
			uint8_t *p = memchr(bad + 4, 0x92, 20);

			if (p && p[1] == 0x92)
				p[2] = 0xc1;	/* error-unspecified */
		}
		fakeep_clear(f->w.f);
		pf_resp(f, 200, MMS_CT, bad, cn);
		c = hc_post(f, req2, rn);
		CHECK_EQ(c->status, 200); hc_free(c);
		spin(30);
		CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 0);
	}
	/* a second accepted send: the store keeps one message only, the first copy is gone (404) */
	req2[10] = 'Y';
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req2, rn);
	CHECK_EQ(c->status, 200); hc_free(c);
	spin(30);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 1);
	c = hc_get(f, path); CHECK_EQ(c->status, 404); hc_free(c);
	/* the copy is announced again by nobody; a repeat of the post is answered from memory and sends no second copy */
	fakeep_clear(f->w.f);
	c = hc_post(f, req2, rn); CHECK_EQ(c->status, 200); hc_free(c);
	spin(30);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 0);
	/* carbons switched off */
	f->pcfg.carbons = false;
	mmsproxy_set_cfg(f->px, &f->pcfg);
	req2[10] = 'Z';
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req2, rn);
	CHECK_EQ(c->status, 200); hc_free(c);
	spin(30);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 0);
	pf_fini(f);

	/* several recipients: To, Cc, Bcc in this order, numbers without /TYPE, e-mail kept, at most 20, the header says when it cut */
	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.12", 5060, 2, ";+g.imsd.carbons");
	{
		struct pb p = { .n = 0 };
		int i;

		pb_u8(&p, 0x8c); pb_u8(&p, 0x80); pb_u8(&p, 0x98); pb_text(&p, "MR1"); pb_u8(&p, 0x8d); pb_u8(&p, 0x92);
		pb_u8(&p, 0x89); pb_u8(&p, 1); pb_u8(&p, 0x81);
		pb_u8(&p, 0x81); pb_text(&p, "+821044444444/TYPE=PLMN");
		pb_u8(&p, 0x82); pb_text(&p, "+821033333333/TYPE=PLMN");
		pb_u8(&p, 0x97); pb_text(&p, "+821011111111/TYPE=PLMN");
		pb_u8(&p, 0x97); pb_text(&p, "user@example.com");
		pb_u8(&p, 0x84); pb_u8(&p, 0xa3); pb_u8(&p, 0);
		fakeep_clear(f->w.f);
		pf_resp(f, 200, MMS_CT, conf, cn);
		c = hc_post(f, p.d, p.n);
		CHECK_EQ(c->status, 200); hc_free(c);
		spin(30);
		CHECK(msg_parse(f, "192.168.68.12", 5060, 0, &m));
		CHECK_STR(H(&m, "X-IMSD-Peer"), "+821011111111,user@example.com,+821033333333,+821044444444");
		CHECK_STR(H(&m, "X-IMSD-Peer-Truncated"), "");
		sip_msg_free(&m);
		p.n = 0;
		pb_u8(&p, 0x8c); pb_u8(&p, 0x80); pb_u8(&p, 0x98); pb_text(&p, "MR2"); pb_u8(&p, 0x8d); pb_u8(&p, 0x92);
		for (i = 0; i < 23; i++) {
			char a[40];

			snprintf(a, sizeof(a), "+8210%08d/TYPE=PLMN", i);
			pb_u8(&p, 0x97); pb_text(&p, a);
		}
		pb_u8(&p, 0x84); pb_u8(&p, 0xa3); pb_u8(&p, 0);
		fakeep_clear(f->w.f);
		pf_resp(f, 200, MMS_CT, conf, cn);
		c = hc_post(f, p.d, p.n);
		CHECK_EQ(c->status, 200); hc_free(c);
		spin(30);
		CHECK(msg_parse(f, "192.168.68.12", 5060, 0, &m));
		{
			const char *peer = H(&m, "X-IMSD-Peer"), *q;
			int cnt = 1;

			for (q = peer; *q; q++)
				cnt += *q == ',';
			CHECK_EQ(cnt, 20);
			CHECK(strstr(peer, "+821000000019") != NULL && strstr(peer, "+821000000020") == NULL);
		}
		CHECK_STR(H(&m, "X-IMSD-Peer-Truncated"), "1");
		sip_msg_free(&m);
	}
	pf_fini(f);

	/* a sender that no binding matches: nobody is excluded */
	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.12", 5060, 2, ";+g.imsd.carbons");
	dev_reg_at(f, "192.168.68.14", 5060, 4, ";+g.imsd.carbons");
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn); CHECK_EQ(c->status, 200); hc_free(c);
	spin(30);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 1);
	CHECK_EQ(msg_count(f, "192.168.68.14", 5060), 1);
	pf_fini(f);
}

/* ------------------------------------------------------------------ */
/* the listener follows the LAN                                        */

static void t_lan_lifecycle(void)
{
	struct pf *f;
	struct hc *c;
	struct addr a;
	struct mmsproxy_status ps;
	char want[100];

	pf_init(NULL);
	f = PF;
	CHECK(mmsproxy_listening(f->px));
	snprintf(want, sizeof(want), "http://127.0.0.1:%u/mms", f->port);
	CHECK_STR(mmsproxy_base_url(f->px), want);
	mmsproxy_get_status(f->px, &ps);
	CHECK(ps.listening); CHECK_EQ(ps.port, f->port); CHECK_STR(ps.address, "127.0.0.1");
	/* the LAN side goes down: nothing listens */
	mmsproxy_set_lan(f->px, NULL, NULL);
	CHECK(!mmsproxy_listening(f->px));
	CHECK_STR(mmsproxy_base_url(f->px), "");
	c = hc_new(f->port, "127.0.0.1");
	hc_wait(&c, 1, 50);
	CHECK(c->closed || c->fd < 0);
	hc_free(c);
	mmsproxy_get_status(f->px, &ps);
	CHECK(!ps.listening);
	/* it comes back on the same, then on another address */
	addr_set(&a, "127.0.0.1", 0);
	mmsproxy_set_lan(f->px, f->w.lan, &a);
	CHECK(mmsproxy_listening(f->px));
	c = hc_get(f, "/mms"); CHECK_EQ(c->status, 200); hc_free(c);
	addr_set(&a, "127.0.0.2", 0);
	mmsproxy_set_lan(f->px, f->w.lan, &a);
	snprintf(want, sizeof(want), "http://127.0.0.2:%u/mms", f->port);
	CHECK_STR(mmsproxy_base_url(f->px), want);
	c = hc_new(f->port, "127.0.0.2");
	hc_puts(c, "GET /mms HTTP/1.1\r\n\r\n");
	hc_wait(&c, 1, 300); hc_parse(c);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	c = hc_new(f->port, "127.0.0.1");		/* not on the old one any more */
	hc_puts(c, "GET /mms HTTP/1.1\r\n\r\n");
	hc_wait(&c, 1, 100); hc_parse(c);
	CHECK_EQ(c->status, 0);
	hc_free(c);
	/* the port is a configuration option: moved, switched off, switched on */
	f->pcfg.port = f->port + 1;
	mmsproxy_set_cfg(f->px, &f->pcfg);
	snprintf(want, sizeof(want), "http://127.0.0.2:%u/mms", f->port + 1);
	CHECK_STR(mmsproxy_base_url(f->px), want);
	f->pcfg.port = 0;
	mmsproxy_set_cfg(f->px, &f->pcfg);
	CHECK(!mmsproxy_listening(f->px));
	f->pcfg.port = f->port;
	mmsproxy_set_cfg(f->px, &f->pcfg);
	CHECK(mmsproxy_listening(f->px));
	/* a port that is taken: not listening, the error says so, the listener comes up when the port is free */
	{
		struct pf *g;
		unsigned p = f->port;

		(void)g;
		mmsproxy_set_lan(f->px, NULL, NULL);
		{
			int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
			struct sockaddr_in sa;

			setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

			memset(&sa, 0, sizeof(sa));
			sa.sin_family = AF_INET;
			sa.sin_port = htons((uint16_t)p);
			inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
			CHECK_EQ(bind(s, (struct sockaddr *)&sa, sizeof(sa)), 0);
			CHECK_EQ(listen(s, 1), 0);
			addr_set(&a, "127.0.0.1", 0);
			mmsproxy_set_lan(f->px, f->w.lan, &a);
			CHECK(!mmsproxy_listening(f->px));
			mmsproxy_get_status(f->px, &ps);
			CHECK(ps.error[0] != 0);
			close(s);
			evfake_advance(5100);
			spin(5);
			CHECK(mmsproxy_listening(f->px));
		}
	}
	pf_fini(f);
}

/* ------------------------------------------------------------------ */
/* lossless splitting                                                  */

static void t_split_roundtrip(void)
{
	static const char *const T[] = {
		"짧은 문장",
		"",
		"x",
		"줄 하나\n줄 둘\n줄 셋\n한글 text line number 4\n\n\n끝\n",
		"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nx\n\n\n",
		"trailing blanks and newlines   \n \n\n\n",
		"leading newlines\n\n\n  and spaces   \r\nCRLF line\r\n\r\nend\r\n",
	};
	char text[2600];
	unsigned splits[] = { 200, 250, 1000 };
	size_t i, k;
	int round;

	/* a long line without any line break, Korean only, mostly empty lines */
	for (round = 0; round < 4; round++) {
		size_t l = 0;

		text[0] = 0;
		for (i = 0; l < 2300; i++) {
			const char *s;

			switch (round) {
			case 0: s = "가나다라마바사아자차카타파하"; break;
			case 1: s = "abcdefghij"; break;
			case 2: s = i % 7 == 6 ? "\n한 줄\n" : "\n\n"; break;
			default: s = "줄 line\r\n"; break;
			}
			strcat(text, s);
			l = strlen(text);
		}
		for (k = 0; k < 3; k++) {
			struct lan_pieces lp;
			char *back = malloc(strlen(text) + 1);
			size_t o = 0;
			unsigned n;

			CHECK_EQ(lan_pieces_make(&lp, text, strlen(text), splits[k]), 0);
			for (n = 0; n < lp.n; n++) {
				const char *s = lp.text[n];
				char mk[24];

				CHECK(strlen(s) <= splits[k]);
				if (lp.n > 1) {
					snprintf(mk, sizeof(mk), "(%u/%u) ", n + 1, lp.n);
					CHECK(!strncmp(s, mk, strlen(mk)));
					s += strlen(mk);
				}
				memcpy(back + o, s, strlen(s));
				o += strlen(s);
			}
			back[o] = 0;
			if (!lp.truncated)
				CHECK_STR(back, text);
			CHECK(!lp.truncated || strlen(text) > 15 * (splits[k] - 12));
			lan_pieces_free(&lp);
			free(back);
		}
	}
	for (i = 0; i < sizeof(T) / sizeof(T[0]); i++)
		for (k = 0; k < 3; k++) {
			struct lan_pieces lp;
			char back[3000];
			size_t o = 0;
			unsigned n;

			CHECK_EQ(lan_pieces_make(&lp, T[i], strlen(T[i]), splits[k]), 0);
			for (n = 0; n < lp.n; n++) {
				const char *s = lp.text[n];

				if (lp.n > 1) {
					char mk[24];

					snprintf(mk, sizeof(mk), "(%u/%u) ", n + 1, lp.n);
					CHECK(!strncmp(s, mk, strlen(mk)));
					s += strlen(mk);
				}
				memcpy(back + o, s, strlen(s));
				o += strlen(s);
			}
			back[o] = 0;
			CHECK(!lp.truncated);
			CHECK_STR(back, T[i]);
			lan_pieces_free(&lp);
		}
	/* a cut right after a line break when there is one in the second half; the pieces are exact slices */
	{
		size_t off[8], len[8];
		bool tr;
		unsigned n = lan_text_split("aaaa bbbb\ncccc dddd\neeee ffff", 29, 24, off, len, 8, &tr);

		CHECK_EQ(n, 2); CHECK_EQ(off[0], 0); CHECK_EQ(len[0], 20); CHECK_EQ(off[1], 20); CHECK_EQ(len[1], 9);
		n = lan_text_split("한한한한한한한한한한", 30, 16, off, len, 8, &tr);
		CHECK_EQ(n, 2); CHECK_EQ(len[0], 15); CHECK_EQ(len[1], 15);
	}
}

/* the standard forward proxy form: absolute URIs on the same listener */
static struct hc *hc_px(struct pf *f, const char *method, const char *uri, const char *ctype, const void *body, size_t bl)
{
	return hc_request(f, method, uri, ctype, body, bl, "Proxy-Connection: keep-alive\r\n");
}

static void t_std_proxy(void)
{
	struct pf *f;
	uint8_t req[200], conf[200], nr[64];
	size_t rn = send_req(req, sizeof(req)), cn = send_conf(conf, sizeof(conf)), bn, nn;
	struct pb rc = { .n = 0 };
	struct hc *c;
	const uint8_t *b;
	struct mmsproxy_status ps;

	make_conf(&rc, "RT1", "hello");
	pf_init(NULL);
	f = PF;
	/* the JSON names the MMSC */
	c = hc_get(f, "/mms");
	CHECK_EQ(c->status, 200);
	CHECK(hc_has(c, "\"mmsc_known\":true,\"mmsc\":\"http://mmsc.test:9084/\""));
	hc_free(c);
	/* POST of an M-Send.req with an absolute URI: relayed to the MMSC (the URI names another host), a repeat is answered from memory */
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_px(f, "POST", "http://other.test:9084/", MMS_CT, req, rn);
	CHECK_EQ(c->status, 200);
	b = hc_body(c, &bn);
	CHECK(bn == cn && !memcmp(b, conf, cn));
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 1);
	CHECK(!strncmp(mock_req(&f->mn, 0), "POST / HTTP/1.1\r\nHost: mmsc.test:9084\r\n", 38));
	c = hc_px(f, "POST", "http://mmsc.test:9084/", MMS_CT, req, rn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 1);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.relayed_sends, 1); CHECK_EQ(ps.send_repeats, 1);
	/* M-NotifyResp.ind / M-Acknowledge.ind: 200, not forwarded; another PDU type: 400 */
	nn = mms_encode_notifyresp("AvBt6f7q", MMS_VERSION_1_2, MMS_ST_RETRIEVED, nr, sizeof(nr));
	c = hc_px(f, "POST", "http://mmsc.test:9084/", MMS_CT, nr, nn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	nn = mms_encode_acknowledge("AvBt6f7q", MMS_VERSION_1_2, nr, sizeof(nr));
	c = hc_px(f, "POST", "http://mmsc.test:9084/", MMS_CT, nr, nn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 1);
	c = hc_px(f, "POST", "http://mmsc.test:9084/", MMS_CT, rc.d, rc.n);
	CHECK_EQ(c->status, 400);
	hc_free(c);
	/* GET with an absolute URI is the fetch (here: not in a store, the existing path to the MMSC) */
	pf_resp(f, 200, MMS_CT, rc.d, rc.n);
	c = hc_px(f, "GET", "http://mmsc.test:9095/?m1", NULL, NULL, 0);
	CHECK_EQ(c->status, 200);
	b = hc_body(c, &bn);
	CHECK(bn == rc.n && !memcmp(b, rc.d, rc.n));
	hc_free(c);
	CHECK(strstr(mock_req(&f->mn, 1), "GET /?m1 HTTP/1.1\r\nHost: mmsc.test:9095\r\n") != NULL);
	/* refused: CONNECT, schemes, other hosts, other methods, a POST that is not an MMS PDU */
	c = hc_px(f, "CONNECT", "mmsc.test:443", NULL, NULL, 0); CHECK_EQ(c->status, 501); hc_free(c);
	c = hc_px(f, "GET", "https://mmsc.test/x", NULL, NULL, 0); CHECK_EQ(c->status, 400); hc_free(c);
	c = hc_px(f, "GET", "ftp://mmsc.test/x", NULL, NULL, 0); CHECK_EQ(c->status, 400); hc_free(c);
	c = hc_px(f, "GET", "http://evil.test/x", NULL, NULL, 0); CHECK_EQ(c->status, 403); hc_free(c);
	c = hc_px(f, "POST", "http://evil.test/x", "text/plain", "abc", 3); CHECK_EQ(c->status, 403); hc_free(c);
	c = hc_px(f, "PUT", "http://mmsc.test:9084/", NULL, NULL, 0); CHECK_EQ(c->status, 405); hc_free(c);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.denied, 2);
	CHECK_EQ(f->mn.n_conn, 2);
	/* the origin form keeps working */
	c = hc_get(f, "/mms"); CHECK_EQ(c->status, 200); hc_free(c);
	pf_fini(f);
}

/* the extra headers of the raw notification */
static void t_notif_headers(void)
{
	struct pf *f;
	struct sip_msg m;
	struct pb n = { .n = 0 }, p = { .n = 0 };

	pf_init(NULL);
	f = PF;
	dev_reg_at(f, "192.168.68.11", 5060, 1, ";+g.imsd.mms");
	notify(f, "H1", NURL, "subj", NULL);			/* size 4000, expires 600 s after the arrival (1795134300) */
	spin(20);
	CHECK(msg_parse(f, "192.168.68.11", 5060, 0, &m));
	CHECK_STR(H(&m, "X-MMS-Content-Location"), NURL);
	CHECK_STR(H(&m, "X-MMS-Size"), "4000");
	CHECK_STR(H(&m, "X-MMS-Expiry"), "2026-11-20T00:35:00+00:00");
	CHECK_STR(H(&m, "X-MMS-Transaction-ID"), "H1");
	sip_msg_free(&m);
	/* no expiry in the PDU: no header; a location with a non-ASCII byte: no header (the others stay) */
	build_notif(&n, "H2", 0x92, "01012345678/TYPE=PLMN", "subj", 77, -1, "http://mmsc.test:9095/?m\xc3\xa9");
	build_push(&p, n.d, n.n);
	mms_on_push(f->m, "0100000004", 2948, p.d, p.n);
	spin(20);
	CHECK(msg_parse(f, "192.168.68.11", 5060, 1, &m));
	CHECK_STR(H(&m, "X-MMS-Transaction-ID"), "H2");
	CHECK_STR(H(&m, "X-MMS-Content-Location"), "");
	CHECK_STR(H(&m, "X-MMS-Expiry"), "");
	CHECK_STR(H(&m, "X-MMS-Size"), "77");
	CHECK_EQ(m.body_len, n.n);
	sip_msg_free(&m);
	pf_fini(f);
}

void test_mms_proxy(void)
{
	t_split_roundtrip();
	t_http_server();
	t_relay();
	t_relay_limits();
	t_idempotent();
	t_fetch();
	t_raw_only();
	t_mixed();
	t_renotify();
	t_carbons_mms();
	t_carbons_mms_notif();
	t_carbons_mms_proxyform();
	t_lan_lifecycle();
	t_std_proxy();
	t_notif_headers();
}


/* ------------------------------------------------------------------ */
/* the circuit switched backend: on-demand bearer, operator proxy                                  */

#define INST(n) ";+sip.instance=\"<urn:uuid:0000000" #n ">\""
static void pf_init_store(void (*tweak)(struct mms_cfg *, struct mmsproxy_cfg *));
static reg_id_t dev_reg_x(struct pf *f, const char *ip, int port, int k, const char *params, const char *extra);
static void conf_att(struct pb *p, const char *tid, const char *text);

static void cs_tweak(struct mms_cfg *c, struct mmsproxy_cfg *p)
{
	(void)p;
	c->mmsc[0] = 0;			/* the operator table decides */
}

static void cs_tweak_uci(struct mms_cfg *c, struct mmsproxy_cfg *p)
{
	(void)p;
	snprintf(c->mmsc, sizeof(c->mmsc), "http://mmsc.example/mms");
	snprintf(c->mms_proxy, sizeof(c->mms_proxy), "proxy.example:8080");
	snprintf(c->mms_user_agent, sizeof(c->mms_user_agent), "UA/9");
	snprintf(c->mms_accept, sizeof(c->mms_accept), "a/b");
}

static void pf_cs_init(bool store)
{
	struct mock_dns_rule rule;

	pf_want_rig = true;
	snprintf(pf_imsi_s, sizeof(pf_imsi_s), "450119876543210");		/* Korea Cable Telecom: an MVNO with its own table entry */
	snprintf(pf_plmn_s, sizeof(pf_plmn_s), "45005");
	if (store)
		pf_init_store(cs_tweak);
	else
		pf_init(cs_tweak);
	pf_want_rig = false;
	memset(&rule, 0, sizeof(rule));
	rule.name = "smart.nate.com"; rule.type = 1; rule.ttl = 3600; rule.n = 2;
	addr_set(&rule.addr[0], "211.188.208.21", 0);
	addr_set(&rule.addr[1], "211.188.197.41", 0);
	mock_dns_add(&PF->mn, &rule);
}

static bool starts(const char *s, const char *prefix)
{
	return !strncmp(s, prefix, strlen(prefix));
}

static void host_of(const struct addr *a, char *out, size_t n)
{
	addr_host(a, out, n);
}

/* everything that went out on the mock network: DNS only to the bearer's servers, TCP only to the proxy, all bound to the bearer */
static void cs_check_traffic(struct pf *f)
{
	int i;
	char h[48];

	for (i = 0; i < f->mn.n_usent; i++) {
		host_of(&f->mn.usent[i].dst, h, sizeof(h));
		CHECK(!strcmp(h, "223.62.230.7") || !strcmp(h, "113.217.240.31"));
		CHECK_EQ(addr_port(&f->mn.usent[i].dst), 53);
	}
	if (f->mn.n_usent) {
		CHECK_STR(f->mn.udp_netdev, "wwan0");
		host_of(&f->mn.udp_local, h, sizeof(h));
		CHECK_STR(h, "10.110.48.33");
	}
	for (i = 0; i < f->mn.n_conn; i++) {
		host_of(&f->mn.conn[i].dst, h, sizeof(h));
		CHECK(!strcmp(h, "211.188.208.21") || !strcmp(h, "211.188.197.41"));
		CHECK_EQ(addr_port(&f->mn.conn[i].dst), 9093);
		CHECK_STR(f->mn.conn[i].netdev, "wwan0");
		host_of(&f->mn.conn[i].local, h, sizeof(h));
		CHECK_STR(h, "10.110.48.33");
	}
}

static void t_cs_lan_send(void)
{
	struct pf *f;
	uint8_t req[200], conf[200], req2[200];
	size_t rn = send_req(req, sizeof(req)), cn = send_conf(conf, sizeof(conf)), bn;
	struct hc *c;
	const uint8_t *b;
	const char *q;
	char h[48];

	pf_cs_init(false);
	f = PF;
	CHECK_EQ(rn, 84);
	/* nothing is up before there is work */
	CHECK_STR(pf_rig->log, "");
	/* a device posts an M-Send.req: the bearer comes up for it, the guard first, the request goes to the operator's MMS proxy in the
	 * absolute-URI form with the Host of the MMSC and the headers of the carrier entry */
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 200);
	b = hc_body(c, &bn);
	CHECK(bn == cn && !memcmp(b, conf, cn));
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 1);
	q = mock_req(&f->mn, 0);
	CHECK(starts(q, "POST http://omms.nate.com:9082/oma_mms HTTP/1.1\r\nHost: omms.nate.com:9082\r\n"));
	CHECK(strstr(q, "Accept: */*, application/vnd.wap.mms-message, application/vnd.wap.sic\r\n") != NULL);
	CHECK(strstr(q, "User-Agent: Android-Mms/2.0\r\n") != NULL);
	CHECK(strstr(q, "Content-Type: application/vnd.wap.mms-message\r\n") != NULL);
	CHECK(strstr(q, "Content-Length: 84\r\n") != NULL);
	{
		const uint8_t *ub = mock_req_body(&f->mn, 0, &bn);

		CHECK(bn == rn && !memcmp(ub, req, rn));
	}
	host_of(&f->mn.conn[0].dst, h, sizeof(h));
	CHECK_STR(h, "211.188.208.21");			/* the first A record of the proxy */
	CHECK(f->mn.n_usent >= 1);
	cs_check_traffic(f);
	CHECK_STR(pf_rig->log, "G+ CREATE:lte.sktelecom.com:ipv4v6 CONNECT V6OFF GA:wwan0 NET+ GT:211.188.208.21 . 9093");
	/* the carrier MMSC is what the proxy publishes */
	c = hc_get(f, "/mms");
	CHECK_EQ(c->status, 200);
	b = hc_body(c, &bn);
	CHECK(strstr((const char *)b, "\"mmsc\":\"http://omms.nate.com:9082/oma_mms\"") != NULL);
	CHECK(strstr((const char *)b, "\"mmsc_known\":true") != NULL);
	hc_free(c);
	/* a second message in the standard forward-proxy form (the device's own "MMS proxy" setting) within the linger: the same bearer */
	memcpy(req2, req, rn);
	req2[10] = 'X';
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_px(f, "POST", "http://omms.nate.com:9082/oma_mms", MMS_CT, req2, rn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 2);
	CHECK(starts(mock_req(&f->mn, 1), "POST http://omms.nate.com:9082/oma_mms HTTP/1.1\r\n"));
	CHECK_EQ(pf_rig->created, 1);
	cs_check_traffic(f);
	/* a fetch of a URL on the MMSC's host (no notification named it): also through the proxy */
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_fetch(f, "http://omms.nate.com:9082/oma_mms?x=1");
	CHECK_EQ(c->status, 200);
	hc_free(c);
	CHECK(starts(mock_req(&f->mn, 2), "GET http://omms.nate.com:9082/oma_mms?x=1 HTTP/1.1\r\nHost: omms.nate.com:9082\r\n"));
	/* a URL nobody announced, on another host: refused, nothing goes out */
	c = hc_fetch(f, "http://evil.test/x");
	CHECK_EQ(c->status, 403);
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 3);
	cs_check_traffic(f);
	CHECK(strstr(pf_rig->log, "GT:") == strstr(pf_rig->log, "GT:211.188.208.21 . 9093"));
	CHECK(strstr(pf_rig->log, "GT:211.188.197.41") == NULL);		/* the second A record was never needed */
	/* the work is over: the bearer goes after the linger */
	advance(25000);
	CHECK(strstr(pf_rig->log, "NET- V6ON DISC DEL G-") != NULL);
	CHECK_EQ(pf_rig->live, 0);
	/* the next send brings a new one up */
	pf_resp(f, 200, MMS_CT, conf, cn);
	req2[10] = 'Y';
	c = hc_px(f, "POST", "http://omms.nate.com:9082/oma_mms", MMS_CT, req2, rn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	CHECK_EQ(pf_rig->created, 2);
	CHECK_EQ(pf_rig->max_live, 1);
	/* the bearer cannot be brought up: the device gets 503 after the wait, nothing goes out */
	advance(25000);
	pf_rig->connect_fail_n = 1000;
	{
		struct mmsproxy_status ps;
		int conns = f->mn.n_conn;

		req2[10] = 'Z';
		c = hc_px(f, "POST", "http://omms.nate.com:9082/oma_mms", MMS_CT, req2, rn);
		if (!c->status) {		/* the device waits while the bearer is retried (50 s at most) */
			advance(55000);
			hc_wait(&c, 1, 50);
			hc_parse(c);
		}
		CHECK_EQ(c->status, 503);
		hc_free(c);
		CHECK_EQ(f->mn.n_conn, conns);
		mmsproxy_get_status(f->px, &ps);
		CHECK(ps.send_failures >= 1);
	}
	pf_rig->connect_fail_n = 0;
	/* blocked by someone else's bearer: the device is told at once */
	advance(70000);
	snprintf(pf_rig->foreign_path, sizeof(pf_rig->foreign_path), "/bearer/wan");
	snprintf(pf_rig->foreign_apn, sizeof(pf_rig->foreign_apn), "lte.sktelecom.com");
	snprintf(pf_rig->foreign_if, sizeof(pf_rig->foreign_if), "wwan0");
	advance(70000);
	req2[10] = 'W';
	c = hc_px(f, "POST", "http://omms.nate.com:9082/oma_mms", MMS_CT, req2, rn);
	CHECK_EQ(c->status, 503);
	b = hc_body(c, &bn);
	CHECK(strstr((const char *)b, "not touched") != NULL);
	hc_free(c);
	CHECK(!pf_rig->foreign_touched);
	pf_fini(f);
}

static void t_cs_store_flow(void)
{
	struct pf *f;
	struct pb conf = { .n = 0 }, raw = { .n = 0 };
	struct sip_msg m;
	struct mms_status st;
	struct store_status ss;
	struct hc *c;
	const char *q;
	char h[48];
	reg_id_t idu;
	int i;
	static const char CL[] = "http://bmms.nate.com:9083/mmsd12/1SoBK4Q8U01";

	pf_cs_init(true);
	f = PF;
	idu = dev_reg_x(f, "192.168.68.11", 5060, 1, INST(1), NULL);
	CHECK(idu != REG_ID_NONE);
	fakeep_clear(f->w.f);
	conf_att(&conf, "1SoBK4Q8U01", "imsd CS MMS test");
	/* the first A record of the operator proxy refuses the connection: the second one is tried */
	mock_respond(&f->mn, &(struct mock_resp){ .connect_rc = -ECONNREFUSED });
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp_ok_empty(f);
	pf_resp_ok_empty(f);
	/* a notification whose Content-Location host and port differ from the MMSC's */
	notify(f, "1SoBK4Q8U01", CL, "cs test", &raw);
	spin(150);
	CHECK_EQ(f->mn.n_conn, 4);
	host_of(&f->mn.conn[0].dst, h, sizeof(h));
	CHECK_STR(h, "211.188.208.21");
	host_of(&f->mn.conn[1].dst, h, sizeof(h));
	CHECK_STR(h, "211.188.197.41");			/* failover to the second A record */
	q = mock_req(&f->mn, 1);
	CHECK(starts(q, "GET http://bmms.nate.com:9083/mmsd12/1SoBK4Q8U01 HTTP/1.1\r\nHost: bmms.nate.com:9083\r\n"));
	CHECK(strstr(q, "User-Agent: Android-Mms/2.0\r\n") != NULL);
	CHECK(strstr(q, "Accept: */*, application/vnd.wap.mms-message, application/vnd.wap.sic\r\n") != NULL);
	/* M-NotifyResp.ind and M-Acknowledge.ind go to the MMSC URL through the proxy as well */
	for (i = 2; i < 4; i++)
		CHECK(starts(mock_req(&f->mn, i), "POST http://omms.nate.com:9082/oma_mms HTTP/1.1\r\nHost: omms.nate.com:9082\r\n"));
	mms_get_status(f->m, &st);
	CHECK_EQ(st.notifications, 1); CHECK_EQ(st.retrieved, 1); CHECK_EQ(st.acked, 2); CHECK_EQ(st.ack_failed, 0); CHECK_EQ(st.stored, 1);
	CHECK_STR(st.mmsc, "http://omms.nate.com:9082/oma_mms");
	CHECK_STR(st.mmsc_source, "carrier");
	CHECK_STR(st.apn, "lte.sktelecom.com");
	CHECK_STR(st.proxy, "smart.nate.com:9093");
	CHECK_STR(st.operator_match, "sim");
	CHECK(st.on_demand);
	store_get_status(f->st, &ss);
	CHECK_EQ(ss.items, 1);
	/* the text device got it (store item, X-IMSD-Seq) */
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 1);
	CHECK(msg_parse(f, "192.168.68.11", 5060, 0, &m));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	CHECK_STR(H(&m, "X-MMS"), "1");
	CHECK(strstr((const char *)m.body, "imsd CS MMS test") != NULL);
	sip_msg_free(&m);
	msg_answer(f, "192.168.68.11", 5060, 1, 0, 200);
	cs_check_traffic(f);
	/* the guard let through exactly the two proxy addresses, in the order they were tried */
	CHECK_STR(pf_rig->log, "G+ CREATE:lte.sktelecom.com:ipv4v6 CONNECT V6OFF GA:wwan0 NET+ GT:211.188.208.21 . 9093 GT:211.188.197.41 . 9093");
	/* a device asks for the announced Content-Location: the store has it, no bearer is needed */
	advance(25000);
	CHECK(strstr(pf_rig->log, "G-") != NULL);
	{
		int conns = f->mn.n_conn, created = pf_rig->created;

		c = hc_fetch(f, CL);
		CHECK_EQ(c->status, 200);
		hc_free(c);
		CHECK_EQ(f->mn.n_conn, conns);
		CHECK_EQ(pf_rig->created, created);
	}
	pf_fini(f);
}

static void t_cs_carrier_variants(void)
{
	struct pf *f;
	uint8_t req[200], conf[200];
	size_t rn = send_req(req, sizeof(req)), cn = send_conf(conf, sizeof(conf));
	struct hc *c;

	/* an MVNO without an entry of its own: the registered network (45005) selects the SKT values */
	pf_want_rig = true;
	snprintf(pf_imsi_s, sizeof(pf_imsi_s), "450129999999999");
	snprintf(pf_plmn_s, sizeof(pf_plmn_s), "45005");
	pf_init(cs_tweak);
	pf_want_rig = false;
	f = PF;
	{
		struct mock_dns_rule rule;

		memset(&rule, 0, sizeof(rule));
		rule.name = "smart.nate.com"; rule.type = 1; rule.ttl = 3600; rule.n = 1;
		addr_set(&rule.addr[0], "211.188.208.21", 0);
		mock_dns_add(&f->mn, &rule);
	}
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	CHECK(starts(mock_req(&f->mn, 0), "POST http://omms.nate.com:9082/oma_mms HTTP/1.1\r\n"));
	pf_fini(f);

	/* neither the SIM nor the network is known to the table: no MMSC, no bearer, 503 with the reason, nothing goes out */
	pf_want_rig = true;
	snprintf(pf_imsi_s, sizeof(pf_imsi_s), "450129999999999");
	snprintf(pf_plmn_s, sizeof(pf_plmn_s), "45099");
	pf_init(cs_tweak);
	pf_want_rig = false;
	f = PF;
	pf_rig->prof_ok = false;
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 503);
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, 0);
	CHECK_STR(pf_rig->log, "");
	pf_fini(f);

	/* KT (no MMS proxy in its entry, not tested on a live network): HTTP straight to the MMSC, its name resolved by the bearer's DNS, the
	 * resolved address let through the guard */
	pf_want_rig = true;
	snprintf(pf_imsi_s, sizeof(pf_imsi_s), "450080020509251");
	snprintf(pf_plmn_s, sizeof(pf_plmn_s), "45008");
	pf_init(cs_tweak);
	pf_want_rig = false;
	f = PF;
	{
		struct mock_dns_rule rule;

		memset(&rule, 0, sizeof(rule));
		rule.name = "mmsc.ktfwing.com"; rule.type = 1; rule.ttl = 3600; rule.n = 1;
		addr_set(&rule.addr[0], "203.0.113.9", 0);
		mock_dns_add(&f->mn, &rule);
	}
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	CHECK(starts(mock_req(&f->mn, 0), "POST / HTTP/1.1\r\nHost: mmsc.ktfwing.com:9082\r\n"));
	CHECK(strstr(mock_req(&f->mn, 0), "User-Agent: " UA "\r\n") != NULL);	/* no operator user agent: imsd's own */
	{
		char h[48];

		addr_host(&f->mn.conn[0].dst, h, sizeof(h));
		CHECK_STR(h, "203.0.113.9");
		CHECK_EQ(addr_port(&f->mn.conn[0].dst), 9082);
	}
	CHECK(strstr(pf_rig->log, "GT:203.0.113.9 . 9082") != NULL);
	pf_fini(f);

	/* uci overrides (apn, proxy, user agent) beat the table */
	pf_want_rig = true;
	snprintf(pf_imsi_s, sizeof(pf_imsi_s), "450119876543210");
	pf_init(cs_tweak_uci);
	pf_want_rig = false;
	f = PF;
	{
		struct mock_dns_rule rule;

		memset(&rule, 0, sizeof(rule));
		rule.name = "proxy.example"; rule.type = 1; rule.ttl = 3600; rule.n = 1;
		addr_set(&rule.addr[0], "198.51.100.7", 0);
		mock_dns_add(&f->mn, &rule);
	}
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	CHECK(starts(mock_req(&f->mn, 0), "POST http://mmsc.example/mms HTTP/1.1\r\nHost: mmsc.example\r\n"));
	CHECK(strstr(mock_req(&f->mn, 0), "User-Agent: UA/9\r\n") != NULL);
	CHECK(strstr(mock_req(&f->mn, 0), "Accept: a/b\r\n") != NULL);
	{
		char h[48];

		addr_host(&f->mn.conn[0].dst, h, sizeof(h));
		CHECK_STR(h, "198.51.100.7");
		CHECK_EQ(addr_port(&f->mn.conn[0].dst), 8080);
	}
	pf_fini(f);
}

/* ------------------------------------------------------------------ */
/* store mode                                                          */

static reg_id_t dev_reg_x(struct pf *f, const char *ip, int port, int k, const char *params, const char *extra)
{
	char ct[400], cid[32], ex[200];
	struct addr a = ua_addr(ip, port);
	static int n;

	snprintf(ct, sizeof(ct), "<sip:u%d@%s:%d>%s;expires=600", k, ip, port, params);
	snprintf(cid, sizeof(cid), "sx%d-%d", k, ++n);
	snprintf(ex, sizeof(ex), "User-Agent: TestPhone\r\n%s", extra ? extra : "");
	uaw_rx(&f->w, ip, port, mk_register(ip, ct, n, cid, -1, ex));
	spin(20);
	return reg_identify(lan_registrar(f->w.lan), &a, NULL);
}

#define INST(n) ";+sip.instance=\"<urn:uuid:0000000" #n ">\""

static void conf_att(struct pb *p, const char *tid, const char *text)
{
	struct pb body = { .n = 0 }, e = { .n = 0 };
	uint8_t ct[16], h[160];
	size_t cl, hl;

	cl = ct_wk_charset(ct, 0x03, 106);
	hl = ph_cid_loc(h, "txt", "t.txt");
	mp_entry(&e, ct, cl, h, hl, text, strlen(text));
	cl = ct_wk(ct, 0x1e);
	hl = ph_cid_loc(h, "img1", "pic.jpg");
	mp_entry(&e, ct, cl, h, hl, "JPEGBYTES", 9);
	build_multipart(&body, 2, &e);
	cl = ct_wk(ct, 0x23);
	p->n = 0;
	build_retrieve(p, tid, 0x92, "01012345678/TYPE=PLMN", "subj", 1795134000, ct, cl, body.d, body.n);
}

static void pf_init_store(void (*tweak)(struct mms_cfg *, struct mmsproxy_cfg *))
{
	pf_want_store = true;
	pf_init(tweak);
	pf_want_store = false;
	spin(10);
	CHECK(store_usable(PF->st));
}

static int count_dir(const char *path)
{
	char cmd[300];
	FILE *fp;
	int n = 0, c;

	snprintf(cmd, sizeof(cmd), "ls '%s' 2>/dev/null | wc -l", path);
	fp = popen(cmd, "r");
	if (fp && fscanf(fp, "%d", &c) == 1)
		n = c;
	if (fp)
		pclose(fp);
	return n;
}

/* the 32 hex digit directory of the first attachment link in a text */
static bool link_dir(const char *text, char *dir)
{
	const char *p = strstr(text, "/imsd-mms/");

	if (!p)
		return false;
	snprintf(dir, 33, "%.32s", p + 10);
	return true;
}

static void t_store_flow(void)
{
	struct pf *f;
	struct pb conf = { .n = 0 }, raw = { .n = 0 }, conf2 = { .n = 0 };
	struct hc *c;
	struct sip_msg m;
	struct mms_status st;
	struct store_status ss;
	reg_id_t idu, idt;
	char text1[1200], dir1[40] = "", dir2[40] = "", path[200], ts1[48], tid1[48];
	const uint8_t *b;
	size_t bn;
	char cmd[300];
	int conns;

	conf_att(&conf, "S1-R", "hello from the store");
	pf_init_store(NULL);
	f = PF;
	/* two known devices (one text device, one +g.imsd.mms), both gone when the message arrives */
	idu = dev_reg_x(f, "192.168.68.11", 5060, 1, INST(1), NULL);
	idt = dev_reg_x(f, "192.168.68.12", 5060, 2, ";+g.imsd.mms;+g.imsd.carbons" INST(2), NULL);
	CHECK(idu != REG_ID_NONE && idt != REG_ID_NONE);
	reg_remove(lan_registrar(f->w.lan), idu);
	reg_remove(lan_registrar(f->w.lan), idt);
	spin(10);
	fakeep_clear(f->w.f);
	/* the gateway retrieves it itself although only a +g.imsd.mms device existed, confirms once, stores it, and loses nothing */
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp_ok_empty(f);
	pf_resp_ok_empty(f);
	notify(f, "S1", NURL, "subj", &raw);
	spin(120);
	CHECK_EQ(n_gets(f), 1);
	CHECK_EQ(n_posts(f), 2);
	check_ack_pair(f, 1, "S1", "S1-R");
	mms_get_status(f->m, &st);
	CHECK(st.stored == 1 && st.lost_no_client == 0 && st.raw_lost == 0 && st.store_fallback == 0);
	store_get_status(f->st, &ss);
	CHECK(ss.items == 1 && ss.head_seq == 1 && ss.healthy);
	CHECK(ss.ndev == 2);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060) + msg_count(f, "192.168.68.12", 5060), 0);
	conns = f->mn.n_conn;

	/* days later (the notification expired long ago) the +g.imsd.mms device registers: it gets the original notification, byte exact */
	pf_clock += 3 * 86400;
	evfake_advance(3ull * 86400 * 1000);
	spin(20);
	dev_reg_x(f, "192.168.68.12", 5060, 2, ";+g.imsd.mms;+g.imsd.carbons" INST(2), NULL);
	spin(40);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 1);
	CHECK(msg_parse(f, "192.168.68.12", 5060, 0, &m));
	CHECK_STR(H(&m, "Content-Type"), MMS_CT);
	CHECK(m.body_len == raw.n && !memcmp(m.body, raw.d, raw.n));	/* the PDU has NUL bytes in it: nothing is cut */
	{
		char cl[24];

		snprintf(cl, sizeof(cl), "%zu", raw.n);
		CHECK_STR(H(&m, "Content-Length"), cl);
	}
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	CHECK_STR(H(&m, "X-MMS-Transaction-ID"), "S1");
	CHECK_STR(H(&m, "X-SMS-Timestamp"), "2026-11-20T00:25:00+00:00");	/* the arrival, not the time of the redelivery */
	CHECK(!strncmp(H(&m, "X-MMS-Proxy"), "http://127.0.0.1:", 16));
	CHECK_STR(H(&m, "X-MMS-Encoding"), "");
	CHECK_STR(H(&m, "X-MMS-Content-Location"), NURL);	/* rendered at delivery: the same on a redelivery */
	CHECK_STR(H(&m, "X-MMS-Size"), "4000");
	CHECK_STR(H(&m, "X-MMS-Expiry"), "2026-11-20T00:35:00+00:00");
	snprintf(ts1, sizeof(ts1), "%s", H(&m, "X-SMS-Timestamp"));
	snprintf(tid1, sizeof(tid1), "%s", H(&m, "X-MMS-Transaction-ID"));
	sip_msg_free(&m);
	msg_answer(f, "192.168.68.12", 5060, 2, 0, 200);
	spin(20);
	/* and fetches through the proxy: answered from the store, the MMSC is not contacted (its copy is long gone) */
	c = hc_fetch(f, NURL);
	CHECK_EQ(c->status, 200);
	b = hc_body(c, &bn);
	CHECK(bn == conf.n && !memcmp(b, conf.d, conf.n));
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, conns);
	{
		struct mmsproxy_status ps;

		mmsproxy_get_status(f->px, &ps);
		CHECK(ps.store_hits == 1 && ps.fetches == 0);
	}
	/* the standard proxy form: GET with the absolute Content-Location is served from the store as well */
	c = hc_request(f, "GET", NURL, NULL, NULL, 0, "Proxy-Connection: keep-alive\r\n");
	CHECK_EQ(c->status, 200);
	b = hc_body(c, &bn);
	CHECK(bn == conf.n && !memcmp(b, conf.d, conf.n));
	hc_free(c);
	CHECK_EQ(f->mn.n_conn, conns);
	{
		struct mmsproxy_status ps;

		mmsproxy_get_status(f->px, &ps);
		CHECK(ps.store_hits == 2 && ps.fetches == 0);
	}
	/* a URL that is not in the store goes the old way (here: refused, nobody announced it) */
	c = hc_fetch(f, "http://evil.test/x");
	CHECK_EQ(c->status, 403);
	hc_free(c);

	/* the text device: the rendered text, attachment link, X-IMSD-Seq; the attachment is written to the web directory at delivery time */
	CHECK_EQ(count_dir(f->cfg.dir), 0);
	dev_reg_x(f, "192.168.68.11", 5060, 1, INST(1), NULL);
	spin(40);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 1);
	CHECK(msg_parse(f, "192.168.68.11", 5060, 0, &m));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	CHECK_STR(H(&m, "X-MMS"), "1");
	CHECK_STR(H(&m, "X-SMS-Timestamp"), "2026-11-20T00:20:00+00:00");	/* the Date of the message */
	snprintf(text1, sizeof(text1), "%.*s", (int)m.body_len, (const char *)m.body);
	sip_msg_free(&m);
	CHECK(strstr(text1, "hello from the store") != NULL);
	CHECK(link_dir(text1, dir1));
	snprintf(path, sizeof(path), "%s/%s/pic.jpg", f->cfg.dir, dir1);
	CHECK_EQ(access(path, R_OK), 0);
	msg_answer(f, "192.168.68.11", 5060, 1, 0, 200);
	spin(20);
	/* the web directory is tmpfs and may lose it: a redelivery writes it again (the app reports an older position) */
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'/*", f->cfg.dir);
	if (system(cmd)) { }
	CHECK_EQ(access(path, R_OK), -1);
	dev_reg_x(f, "192.168.68.11", 5060, 1, INST(1), "X-IMSD-Ack-Seq: 0\r\n");
	spin(40);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 2);
	CHECK(msg_parse(f, "192.168.68.11", 5060, 1, &m));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	{
		char text2[1200];

		snprintf(text2, sizeof(text2), "%.*s", (int)m.body_len, (const char *)m.body);
		CHECK(link_dir(text2, dir2));
		CHECK(strcmp(dir1, dir2) != 0);
		snprintf(path, sizeof(path), "%s/%s/pic.jpg", f->cfg.dir, dir2);
		CHECK_EQ(access(path, R_OK), 0);
		/* otherwise identical: the same text, the same sender, the same timestamp */
		memcpy(strstr(text2, dir2), dir1, 32);
		CHECK_STR(text2, text1);
	}
	sip_msg_free(&m);
	msg_answer(f, "192.168.68.11", 5060, 1, 1, 200);
	spin(20);
	/* the +g.imsd.mms device gets exactly the same MESSAGE again, headers and body */
	dev_reg_x(f, "192.168.68.12", 5060, 2, ";+g.imsd.mms;+g.imsd.carbons" INST(2), "X-IMSD-Ack-Seq: 0\r\n");
	spin(40);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 2);
	CHECK(msg_parse(f, "192.168.68.12", 5060, 1, &m));
	CHECK_STR(H(&m, "X-SMS-Timestamp"), ts1);
	CHECK_STR(H(&m, "X-MMS-Transaction-ID"), tid1);
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	CHECK(m.body_len == raw.n && !memcmp(m.body, raw.d, raw.n));
	sip_msg_free(&m);
	msg_answer(f, "192.168.68.12", 5060, 2, 1, 200);
	spin(20);

	/* the MMSC announces the same message again under a new transaction id: confirmed, no second item, nothing sent to the devices */
	conf_att(&conf2, "S2-R", "hello from the store");
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf2.d, conf2.n);
	pf_resp_ok_empty(f);
	pf_resp_ok_empty(f);
	notify(f, "S2", "http://mmsc.test:9095/?m2", "subj", NULL);
	spin(120);
	CHECK_EQ(n_posts(f), 4);
	store_get_status(f->st, &ss);
	CHECK_EQ(ss.items, 1);
	mms_get_status(f->m, &st);
	CHECK(st.duplicates >= 1 && st.stored == 1);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060) + msg_count(f, "192.168.68.12", 5060), 0);

	/* purged: the fetch no longer finds it, and a device that comes back is not owed it */
	CHECK_EQ(store_purge(f->st, 0, true), 1);
	spin(20);
	store_get_status(f->st, &ss);
	CHECK_EQ(ss.items, 0);
	fakeep_clear(f->w.f);
	dev_reg_x(f, "192.168.68.12", 5060, 2, ";+g.imsd.mms;+g.imsd.carbons" INST(2), "X-IMSD-Ack-Seq: 0\r\n");
	spin(40);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 0);
	pf_fini(f);
}

static void t_store_failures(void)
{
	struct pf *f;
	struct pb conf = { .n = 0 }, raw = { .n = 0 };
	struct sip_msg m;
	struct mms_status st;
	char t[600];

	conf_att(&conf, "F1-R", "retry me");
	/* a transient failure: the item enters the store when the retrieval has finished; nothing is sent to a registered device earlier */
	pf_init_store(NULL);
	f = PF;
	dev_reg_x(f, "192.168.68.12", 5060, 2, ";+g.imsd.mms" INST(2), NULL);
	dev_reg_x(f, "192.168.68.11", 5060, 1, INST(1), NULL);
	fakeep_clear(f->w.f);
	pf_resp(f, 503, "text/plain", "busy", 4);
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp_ok_empty(f);
	pf_resp_ok_empty(f);
	notify(f, "F1", NURL, "subj", &raw);
	spin(60);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060) + msg_count(f, "192.168.68.11", 5060), 0);
	advance(5100);				/* the retry after 5 s (a longer wait would show the SIP retransmissions of the MESSAGE) */
	spin(120);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 1);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 1);
	CHECK_EQ(n_posts(f), 2);
	mms_get_status(f->m, &st);
	CHECK(st.stored == 1 && st.failed_stored == 0);
	pf_fini(f);

	/* a permanent failure: still an item. The +g.imsd.mms device gets the notification, the text device a notice; the MMSC is told nothing */
	pf_init_store(NULL);
	f = PF;
	dev_reg_x(f, "192.168.68.12", 5060, 2, ";+g.imsd.mms" INST(2), NULL);
	dev_reg_x(f, "192.168.68.11", 5060, 1, INST(1), NULL);
	fakeep_clear(f->w.f);
	pf_resp(f, 404, "text/plain", "gone", 4);
	notify(f, "F2", NURL, "subj", &raw);
	spin(120);
	CHECK_EQ(n_posts(f), 0);
	mms_get_status(f->m, &st);
	CHECK(st.failed == 1 && st.failed_stored == 1 && st.stored == 1);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 1);
	CHECK(msg_parse(f, "192.168.68.12", 5060, 0, &m));
	CHECK(m.body_len == raw.n && !memcmp(m.body, raw.d, raw.n));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	sip_msg_free(&m);
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 1);
	CHECK(msg_parse(f, "192.168.68.11", 5060, 0, &m));
	snprintf(t, sizeof(t), "%.*s", (int)m.body_len, (const char *)m.body);
	CHECK(strstr(t, "could not be retrieved") && strstr(t, "01012345678"));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	CHECK_STR(H(&m, "X-MMS"), "1");
	sip_msg_free(&m);
	/* the fetch of a failed item goes to the MMSC as before (nothing is in the store to serve) */
	pf_fini(f);

	/* the append fails after the retrieval (disk full): nothing is lost, the text is delivered live like without a store, and confirmed */
	pf_init_store(NULL);
	f = PF;
	dev_reg_x(f, "192.168.68.11", 5060, 1, INST(1), NULL);
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf.d, conf.n);
	pf_resp_ok_empty(f);
	pf_resp_ok_empty(f);
	sio_fault.points = SIO_FP_LOGWRITE;
	sio_fault.err = ENOSPC;
	sio_fault.count = -1;
	notify(f, "F3", NURL, "subj", NULL);
	spin(120);
	sio_fault.points = 0;
	CHECK_EQ(n_posts(f), 2);
	mms_get_status(f->m, &st);
	CHECK(st.store_fallback == 1 && st.stored == 0);
	CHECK(!store_usable(f->st));
	CHECK_EQ(msg_count(f, "192.168.68.11", 5060), 1);
	CHECK(msg_parse(f, "192.168.68.11", 5060, 0, &m));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "");			/* live delivery: no store number */
	sip_msg_free(&m);
	pf_fini(f);
}

static void t_store_carbons(void)
{
	struct pf *f;
	uint8_t req[200], conf[200];
	size_t rn = send_req(req, sizeof(req)), cn = send_conf(conf, sizeof(conf)), bn;
	struct hc *c;
	struct sip_msg m;
	char id[40], path[120];
	const uint8_t *b;
	struct mmsproxy_status ps;

	pf_init_store(NULL);
	f = PF;
	/* the sender (the HTTP client's address 127.0.0.1) and two other devices that want copies; one of them is away when it is sent */
	dev_reg_x(f, "127.0.0.1", 5070, 1, ";+g.imsd.mms;+g.imsd.carbons" INST(1), NULL);
	dev_reg_x(f, "192.168.68.12", 5060, 2, ";+g.imsd.carbons" INST(2), NULL);
	{
		reg_id_t away = dev_reg_x(f, "192.168.68.13", 5060, 3, ";+g.imsd.carbons" INST(3), NULL);

		reg_remove(lan_registrar(f->w.lan), away);
	}
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn);
	CHECK_EQ(c->status, 200);
	hc_free(c);
	spin(60);
	CHECK_EQ(msg_count(f, "192.168.68.12", 5060), 1);
	CHECK_EQ(msg_count(f, "127.0.0.1", 5070), 0);
	CHECK(msg_parse(f, "192.168.68.12", 5060, 0, &m));
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	carbon_check(f, &m, rn, 1, "+821051226862", "imsd test", 1795134300 + 30 * 86400);
	CHECK_STR(H(&m, "X-IMSD-Carbon"), "sent");
	CHECK_STR(H(&m, "X-MMS-Message-ID"), "2uBtyUy3");
	CHECK_STR(H(&m, "X-IMSD-Peer"), "01051226862");
	CHECK_STR(H(&m, "X-SMS-Timestamp"), "2026-11-20T00:25:00+00:00");
	snprintf(id, sizeof(id), "%s", H(&m, "X-IMSD-Carbon-ID"));
	CHECK_EQ(strlen(id), 32);
	sip_msg_free(&m);
	msg_answer(f, "192.168.68.12", 5060, 2, 0, 200);
	spin(20);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.carbons_stored, 1);
	/* served from the store, nothing in the tmpfs copies */
	snprintf(path, sizeof(path), "/mms/sent/%s", id);
	c = hc_get(f, path);
	CHECK_EQ(c->status, 200);
	b = hc_body(c, &bn);
	CHECK(bn == rn && !memcmp(b, req, rn));
	hc_free(c);
	CHECK_EQ(count_dir(f->pcfg.dir), 0);
	mmsproxy_get_status(f->px, &ps);
	CHECK_EQ(ps.store_hits, 1);
	/* the sender comes back from another port and asks for everything: its own message is not owed, also not in a redelivery */
	fakeep_clear(f->w.f);
	dev_reg_x(f, "127.0.0.1", 5072, 1, ";+g.imsd.mms;+g.imsd.carbons" INST(1), "X-IMSD-Ack-Seq: 0\r\n");
	spin(40);
	CHECK_EQ(msg_count(f, "127.0.0.1", 5072), 0);
	/* the device that was away gets it when it registers, with the same id and headers */
	dev_reg_x(f, "192.168.68.13", 5060, 3, ";+g.imsd.carbons" INST(3), NULL);
	spin(40);
	CHECK_EQ(msg_count(f, "192.168.68.13", 5060), 1);
	CHECK(msg_parse(f, "192.168.68.13", 5060, 0, &m));
	CHECK_STR(H(&m, "X-IMSD-Carbon-ID"), id);
	CHECK_STR(H(&m, "X-IMSD-Seq"), "1");
	carbon_check(f, &m, rn, 1, "+821051226862", "imsd test", 1795134300 + 30 * 86400);
	sip_msg_free(&m);
	/* gone from the store: 404 (and nothing in the old tmpfs copies either) */
	CHECK_EQ(store_purge(f->st, 0, true), 1);
	spin(10);
	c = hc_get(f, path);
	CHECK_EQ(c->status, 404);
	hc_free(c);
	pf_fini(f);
}

/* store mode: live and redelivered announcements are identical (headers and body), the sender is left out */
static void t_store_carbon_notif(void)
{
	struct pf *f;
	uint8_t req[200], conf[200];
	size_t rn = send_req(req, sizeof(req)), cn = send_conf(conf, sizeof(conf));
	struct hc *c;
	struct sip_msg m;
	uint8_t live[400];
	size_t ln;
	char lct[400], lcid[40];

	pf_init_store(NULL);
	f = PF;
	dev_reg_x(f, "127.0.0.1", 5070, 1, ";+g.imsd.mms;+g.imsd.carbons" INST(1), NULL);
	dev_reg_x(f, "192.168.68.12", 5060, 2, ";+g.imsd.carbons" INST(2), NULL);
	{
		reg_id_t away = dev_reg_x(f, "192.168.68.13", 5060, 3, ";+g.imsd.carbons" INST(3), NULL);

		reg_remove(lan_registrar(f->w.lan), away);
	}
	fakeep_clear(f->w.f);
	pf_resp(f, 200, MMS_CT, conf, cn);
	c = hc_post(f, req, rn); CHECK_EQ(c->status, 200); hc_free(c);
	spin(60);
	CHECK_EQ(msg_count(f, "127.0.0.1", 5070), 0);
	CHECK(msg_parse(f, "192.168.68.12", 5060, 0, &m));
	carbon_check(f, &m, rn, 1, "+821051226862", "imsd test", 1795134300 + 30 * 86400);
	CHECK(m.body_len <= sizeof(live));
	ln = m.body_len;
	memcpy(live, m.body, ln);
	snprintf(lct, sizeof(lct), "%s", H(&m, "X-MMS-Expiry"));
	snprintf(lcid, sizeof(lcid), "%s", H(&m, "X-IMSD-Carbon-ID"));
	sip_msg_free(&m);
	msg_answer(f, "192.168.68.12", 5060, 2, 0, 200);
	spin(20);
	/* the device that was away: the same body and headers from the store */
	dev_reg_x(f, "192.168.68.13", 5060, 3, ";+g.imsd.carbons" INST(3), NULL);
	spin(40);
	CHECK(msg_parse(f, "192.168.68.13", 5060, 0, &m));
	carbon_check(f, &m, rn, 1, "+821051226862", "imsd test", 1795134300 + 30 * 86400);
	CHECK(m.body_len == ln && !memcmp(m.body, live, ln));
	CHECK_STR(H(&m, "X-MMS-Expiry"), lct);
	CHECK_STR(H(&m, "X-IMSD-Carbon-ID"), lcid);
	sip_msg_free(&m);
	/* the sender coming back is owed nothing */
	fakeep_clear(f->w.f);
	dev_reg_x(f, "127.0.0.1", 5072, 1, ";+g.imsd.mms;+g.imsd.carbons" INST(1), "X-IMSD-Ack-Seq: 0\r\n");
	spin(40);
	CHECK_EQ(msg_count(f, "127.0.0.1", 5072), 0);
	pf_fini(f);
}

void test_mms_cs(void)
{
	t_cs_lan_send();
	t_cs_store_flow();
	t_cs_carrier_variants();
}

void test_mms_store(void)
{
	t_store_flow();
	t_store_failures();
	t_store_carbons();
	t_store_carbon_notif();
}
