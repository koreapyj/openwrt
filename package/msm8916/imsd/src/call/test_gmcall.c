/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Host tests of the carrier call leg. The "network" is the test: it parses the
 * messages the module sent through a fake endpoint and injects responses /
 * requests, among them the four exchanges captured on the live LG U+ network
 * (apims_research.md, P1 logs). The registered context is a mock; time is the
 * fake event loop's virtual clock. Run under ASan / UBSan by the Makefile.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "../test/test.h"
#include "../test/fakeep.h"
#include "../test/evloop_fake.h"
#include "../util/log.h"
#include "gmcall.h"
#include "test_gmcall_vec.h"

int t_checks, t_fails;

/* ------------------------------------------------------------------ */
/* world                                                               */

#define UE_IP "2001:4430:141:990a:25b5:899e:232:cb69"
#define PCSCF_A "2001:4430:5:401::53"	/* run1 / c1 */
#define PCSCF_B "2001:4430:4:405::43"	/* n1 / l1 */
#define MAXREC 40

struct rec {
	struct gmcall *call;
	int n;
	struct gmcall_event ev[MAXREC];
	struct sdpn_media media[MAXREC];
	int term;		/* terminal events seen */
	int events_after_term;
	bool in_api;		/* set by tests around API calls to detect re-entrant callbacks */
	int reentrant;
};

struct world {
	struct fakeep *f, *f2;
	struct txn_layer *tl;
	struct gmcall_mgr *m;
	struct reg_ctx ctx;
	bool registered;
	char sv[400];
	char sroute[2][96];
	char impu[96];
	struct addr pcscf, src;
	int unhandled, unhandled_ack;
	char unhandled_method[16];
	/* incoming */
	int n_incoming;
	int in_ret;
	int in_reject;		/* in_cb rejects with this status from inside the callback */
	bool in_ring;		/* in_cb calls gmcall_ring */
	struct gmcall_incoming last_in;
	struct sdpn_media last_in_media;
	struct gmcall *in_call;
	struct rec mt;
	struct gmcall_cfg cfg;
};
static struct world W;
static bool g_auto100;	/* the transaction layer sends 100 itself (then the TU must not send a second one) */

static struct addr A(const char *ip, int port)
{
	struct addr a;

	addr_set(&a, ip, port);
	return a;
}

static const struct reg_ctx *ctx_cb(void *arg)
{
	(void)arg;
	return W.registered ? &W.ctx : NULL;
}

static int contact_cb(void *arg, char *out, size_t n)
{
	char hp[96];

	(void)arg;
	if (!W.registered)
		return -1;
	addr_str(&W.ctx.ep->advertised, hp, sizeof(hp));
	snprintf(out, n, "sip:01039428657@%s", hp);
	return 0;
}

static const struct gmcall_reg_ops mock_ops = { ctx_cb, contact_cb };

static void rec_cb(struct gmcall *c, const struct gmcall_event *ev, void *arg)
{
	struct rec *r = arg;

	(void)c;
	if (r->in_api)
		r->reentrant++;
	if (r->term)
		r->events_after_term++;
	if (r->n >= MAXREC)
		return;
	r->ev[r->n] = *ev;
	if (ev->type == GMCALL_EV_MEDIA && ev->media) {
		r->media[r->n] = *ev->media;
		r->ev[r->n].media = &r->media[r->n];
	}
	r->n++;
	if (ev->type == GMCALL_EV_FAILED || ev->type == GMCALL_EV_CANCELLED || ev->type == GMCALL_EV_TERMINATED)
		r->term++;
}

static int rec_count(const struct rec *r, enum gmcall_event_type t)
{
	int i, n = 0;

	for (i = 0; i < r->n; i++)
		n += r->ev[i].type == t;
	return n;
}

static const struct gmcall_event *rec_nth(const struct rec *r, enum gmcall_event_type t, int nth)
{
	int i;

	for (i = 0; i < r->n; i++)
		if (r->ev[i].type == t && nth-- == 0)
			return &r->ev[i];
	return NULL;
}

static const struct gmcall_event *rec_last(const struct rec *r)
{
	return r->n ? &r->ev[r->n - 1] : NULL;
}

static int in_cb(struct gmcall *c, const struct gmcall_incoming *in, void *arg)
{
	(void)arg;
	W.n_incoming++;
	W.last_in = *in;
	W.last_in_media = *in->offered;
	W.last_in.offered = &W.last_in_media;
	W.in_call = c;
	memset(&W.mt, 0, sizeof(W.mt));
	W.mt.call = c;
	gmcall_set_handler(c, rec_cb, &W.mt);
	if (W.in_ring)
		gmcall_ring(c);
	if (W.in_reject)
		gmcall_reject(c, W.in_reject);
	return W.in_ret;
}

static void req_cb(struct txn_layer *tl, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
		   const struct sip_msg *req, void *arg)
{
	struct sip_resp_parts p;

	(void)tl; (void)arg;
	if (gmcall_on_request(W.m, st, ep, src, req))
		return;
	if (!st) {
		W.unhandled_ack++;
		return;
	}
	W.unhandled++;
	snprintf(W.unhandled_method, sizeof(W.unhandled_method), "%s", req->method);
	memset(&p, 0, sizeof(p));
	p.status = !strcmp(req->method, "INVITE") ? 480 : 481;	/* what reg.c does by default */
	txn_server_reply(st, &p);
}

static void stray_cb(struct txn_layer *tl, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *resp,
		     void *arg)
{
	(void)tl; (void)arg;
	gmcall_on_stray_response(W.m, ep, src, resp);
}

static struct fakeep *new_ep(const char *name, int adv_port)
{
	struct sip_ep_cfg c;

	memset(&c, 0, sizeof(c));
	c.name = name;
	c.kind = SIP_TP_UDP;
	c.rx_bind = A(UE_IP, 8001);
	c.has_adv = true;
	c.adv = A(UE_IP, adv_port);
	return fakeep_open(&c);
}

static void world_set_pcscf(const char *ip, int port_s, int port_c)
{
	W.pcscf = A(ip, port_s);
	W.src = A(ip, port_c);
	W.ctx.pcscf_ps = W.pcscf;
	snprintf(W.sv, sizeof(W.sv),
		 "ipsec-3gpp;q=0.1;alg=hmac-md5-96;ealg=null;spi-c=10586783;spi-s=10586782;port-c=%d;port-s=%d", port_c, port_s);
}

static struct rec R;

static void world_init(const char *pcscf, int port_s, int port_c, void (*tune)(struct gmcall_cfg *))
{
	struct txn_cfg tc;

	memset(&W, 0, sizeof(W));
	memset(&R, 0, sizeof(R));
	evfake_reset();
	W.f = new_ep("gm#1", 8901);
	memset(&tc, 0, sizeof(tc));
	tc.auto_100 = g_auto100;
	tc.on_request = req_cb;
	tc.on_stray_response = stray_cb;
	W.tl = txn_layer_new(&tc);
	txn_layer_attach(W.tl, W.f->ep);
	W.registered = true;
	W.ctx.ep = W.f->ep;
	snprintf(W.impu, sizeof(W.impu), "sip:01039428657@lte-lguplus.co.kr");
	W.ctx.impu = W.impu;
	W.ctx.assoc_uri = W.impu;
	W.ctx.pani = "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EB3161703";
	W.ctx.security_verify = W.sv;
	W.ctx.port_c = port_c;
	W.ctx.port_s = port_s;
	snprintf(W.sroute[0], sizeof(W.sroute[0]), "<sip:orig@scscf.lte-lguplus.co.kr:5060;lr>");
	W.ctx.service_route[0] = W.sroute[0];
	W.ctx.n_service_route = 1;
	world_set_pcscf(pcscf, port_s, port_c);
	gmcall_cfg_defaults(&W.cfg);
	W.cfg.tl = W.tl;
	W.cfg.reg = &mock_ops;
	W.cfg.on_incoming = in_cb;
	if (tune)
		tune(&W.cfg);
	W.m = gmcall_mgr_new(&W.cfg);
}

static void world_fini(void)
{
	CHECK_EQ(R.events_after_term + W.mt.events_after_term, 0);	/* the terminal event is the last */
	gmcall_mgr_free(W.m);
	txn_layer_free(W.tl);
	if (W.f2) {
		sip_ep_retire(W.f2->ep);
		CHECK(W.f2->closed);
		fakeep_destroy(W.f2);
	}
	sip_ep_retire(W.f->ep);
	CHECK(W.f->closed);	/* every dialog / transaction dropped its endpoint reference */
	fakeep_destroy(W.f);
	memset(&W, 0, sizeof(W));
}

/* ------------------------------------------------------------------ */
/* message helpers                                                     */

struct pm {
	struct sip_msg m;
	bool ok;
};

static bool parse_sent(struct fakeep *f, int i, struct pm *p)
{
	p->ok = i >= 0 && !fakeep_parse(f, i, &p->m);
	return p->ok;
}

static void pm_free(struct pm *p)
{
	if (p->ok)
		sip_msg_free(&p->m);
	p->ok = false;
}

static bool branch_of(struct fakeep *f, int i, char *out, size_t n)
{
	struct pm p;
	struct sip_via v;
	bool ok = false;

	out[0] = 0;
	if (parse_sent(f, i, &p)) {
		if (!sip_top_via(&p.m, &v)) {
			snprintf(out, n, "%s", v.branch);
			ok = true;
		}
		pm_free(&p);
	}
	return ok;
}

/*
 * index of the next NEW sent request with this method at or after from, -1.
 * Retransmissions (same branch as an earlier identical-method message) are skipped.
 */
static int find_req_on(struct fakeep *f, const char *method, int from)
{
	int i, j;

	for (i = from; i < f->nsent; i++) {
		struct pm p;
		bool hit;
		char b1[64], b2[64];

		if (!parse_sent(f, i, &p))
			continue;
		hit = !p.m.is_resp && !strcmp(p.m.method, method);
		pm_free(&p);
		if (!hit)
			continue;
		branch_of(f, i, b1, sizeof(b1));
		for (j = 0; j < i; j++) {
			struct pm q;
			bool same = false;

			if (parse_sent(f, j, &q)) {
				same = !q.m.is_resp && !strcmp(q.m.method, method) && branch_of(f, j, b2, sizeof(b2)) &&
				       !strcmp(b1, b2);
				pm_free(&q);
			}
			if (same)
				break;
		}
		if (j == i)
			return i;
	}
	return -1;
}

static int find_req(const char *method, int from)
{
	return find_req_on(W.f, method, from);
}

static int count_req(const char *method)
{
	int n = 0, i = -1;

	while ((i = find_req(method, i + 1)) >= 0)
		n++;
	return n;
}

static int find_resp(int status, const char *cseq_method, int from)
{
	int i;

	for (i = from; i < W.f->nsent; i++) {
		struct pm p;
		bool hit = false;
		char meth[16];
		uint32_t cs;

		if (!parse_sent(W.f, i, &p))
			continue;
		if (p.m.is_resp && p.m.status == status && !sip_cseq(&p.m, &cs, meth, sizeof(meth)))
			hit = !cseq_method || !strcmp(meth, cseq_method);
		pm_free(&p);
		if (hit)
			return i;
	}
	return -1;
}

static const char *H(const struct pm *p, const char *name)
{
	const char *v = sip_hdr(&p->m, name, 0);

	return v ? v : "";
}

static bool has_prefix(const char *s, const char *pre)
{
	return !strncmp(s, pre, strlen(pre));
}

/* token substitution: pairs of ("$KEY", value), NULL terminated; then LF -> CRLF and a correct Content-Length */
static char *wire(const char *tpl, ...)
{
	va_list ap;
	char *cur = strdup(tpl), *out;
	const char *k;
	size_t i, o = 0, n;
	const char *blank;
	char tmp[32];
	size_t bodylen;

	va_start(ap, tpl);
	while ((k = va_arg(ap, const char *))) {
		const char *v = va_arg(ap, const char *);
		char *p;
		size_t from = 0;

		while ((p = strstr(cur + from, k))) {	/* never rescan the inserted text */
			size_t kl = strlen(k), vl = strlen(v), cl = strlen(cur);
			char *nw = malloc(cl - kl + vl + 1);

			memcpy(nw, cur, (size_t)(p - cur));
			memcpy(nw + (p - cur), v, vl);
			strcpy(nw + (p - cur) + vl, p + kl);
			from = (size_t)(p - cur) + vl;
			free(cur);
			cur = nw;
		}
	}
	va_end(ap);
	n = strlen(cur);
	out = malloc(n * 2 + 64);
	for (i = 0; i < n; i++) {
		if (cur[i] == '\n' && (i == 0 || cur[i - 1] != '\r'))
			out[o++] = '\r';
		out[o++] = cur[i];
	}
	out[o] = 0;
	free(cur);
	/* Content-Length */
	blank = strstr(out, "\r\n\r\n");
	bodylen = blank ? strlen(blank + 4) : 0;
	{
		char *cl = strstr(out, "Content-Length:");

		if (cl && (cl < blank || !blank)) {
			char *eol = strstr(cl, "\r\n");
			size_t tail = strlen(eol);
			char *res = malloc(strlen(out) + 32);

			snprintf(tmp, sizeof(tmp), "%zu", bodylen);
			memcpy(res, out, (size_t)(cl - out));
			sprintf(res + (cl - out), "Content-Length: %s", tmp);
			memcpy(res + strlen(res), eol, tail + 1);
			free(out);
			out = res;
		}
	}
	return out;
}

static void inject_wire(char *w)
{
	fakeep_rx(W.f, &W.src, w);
	free(w);
}

/* a response template (see test_gmcall_vec.h) answering the request sent at index i */
static void respond_tpl(int i, const char *tpl, ...)
{
	struct pm p;
	va_list ap;
	char *cur, *out;
	const char *k;

	parse_sent(W.f, i, &p);
	va_start(ap, tpl);
	cur = strdup(tpl);
	{
		const char *keys[] = { "$VIA", "$FROM", "$CID", "$CSEQ", "$TO" };
		const char *vals[5];
		size_t kk;

		vals[0] = H(&p, "Via");
		vals[1] = H(&p, "From");
		vals[2] = H(&p, "Call-ID");
		vals[3] = H(&p, "CSeq");
		vals[4] = H(&p, "To");
		for (kk = 0; kk < 5; kk++) {
			out = wire(cur, keys[kk], vals[kk], (char *)NULL);
			free(cur);
			cur = out;
		}
	}
	while ((k = va_arg(ap, const char *))) {
		const char *v = va_arg(ap, const char *);

		out = wire(cur, k, v, (char *)NULL);
		free(cur);
		cur = out;
	}
	va_end(ap);
	pm_free(&p);
	fakeep_rx(W.f, &W.src, cur);
	free(cur);
}

/* simple generated response to the request at index i */
static void respond_simple(int i, int status, const char *to_tag, const char *extra, const char *sdp)
{
	struct pm p;
	char tpl[4096], to[400];

	parse_sent(W.f, i, &p);
	if (to_tag && !strstr(H(&p, "To"), "tag="))
		snprintf(to, sizeof(to), "%s;tag=%s", H(&p, "To"), to_tag);
	else
		snprintf(to, sizeof(to), "%s", H(&p, "To"));
	snprintf(tpl, sizeof(tpl), "SIP/2.0 %d %s\nVia: %s\nFrom: %s\nTo: %s\nCall-ID: %s\nCSeq: %s\n%s%sContent-Length: 0\n\n%s",
		 status, sip_reason_phrase(status), H(&p, "Via"), H(&p, "From"), to, H(&p, "Call-ID"), H(&p, "CSeq"),
		 extra ? extra : "", sdp ? "Content-Type: application/sdp\n" : "", sdp ? sdp : "");
	pm_free(&p);
	inject_wire(wire(tpl, (char *)NULL));
}

/* ------------------------------------------------------------------ */
/* common scenario steps                                                */

static struct gmcall *dial(const char *num, const char *ip, int port)
{
	struct gmcall_dial d;
	struct gmcall *c = NULL;
	int rc;

	memset(&R, 0, sizeof(R));
	memset(&d, 0, sizeof(d));
	d.target = num;
	d.local_rtp = A(ip, port);
	rc = gmcall_dial(W.m, &d, rec_cb, &R, &c);
	CHECK_EQ(rc, 0);
	R.call = c;
	return c;
}

static const char *dialog_tag(const struct pm *p)
{
	static char tag[160];

	sip_tag(H(p, "To"), tag, sizeof(tag));
	return tag;
}

#include "test_gmcall_cases.h"

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	imsd_log_level(getenv("T_LOG") ? atoi(getenv("T_LOG")) : LOG_ERR);
	run_cases();
	printf("test_gmcall: %d checks, %d failures\n", t_checks, t_fails);
	return t_fails ? 1 : 0;
}
