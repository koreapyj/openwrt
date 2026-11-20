/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <strings.h>
#include "test_ua.h"

struct addr ua_addr(const char *ip, int port)
{
	struct addr a;

	addr_set(&a, ip, port);
	return a;
}

static void on_binding(struct lan *l, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why, void *arg)
{
	struct uaw *w = arg;

	(void)l;
	if (w->nbev < MAXLOG) {
		w->bev[w->nbev].ev = ev;
		w->bev[w->nbev].id = b->id;
		w->bev[w->nbev].why = why;
		snprintf(w->bev[w->nbev].contact, sizeof(w->bev[0].contact), "%s", b->contact);
		w->nbev++;
	}
}

static void note_hook(struct uaw *w, const struct lan_peer *peer, const struct sip_msg *req, struct txn_server *st)
{
	w->hk.last_registered = peer->registered;
	w->hk.last_id = peer->id;
	snprintf(w->hk.last_method, sizeof(w->hk.last_method), "%s", req->method);
	w->hk.st = st;
	if (st && w->hk.autoreply) {
		struct sip_resp_parts p = { .status = 200 };

		txn_server_reply(st, &p);
	}
}

static void h_invite(struct lan *l, const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req, void *arg)
{
	struct uaw *w = arg;

	(void)l;
	w->hk.invite++;
	note_hook(w, p, req, st);
}

static void h_in_dialog(struct lan *l, const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req, void *arg)
{
	struct uaw *w = arg;

	(void)l;
	w->hk.in_dialog++;
	note_hook(w, p, req, st);
}

static void h_message(struct lan *l, const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req, void *arg)
{
	struct uaw *w = arg;

	(void)l;
	w->hk.message++;
	note_hook(w, p, req, st);
}

static void h_ack(struct lan *l, const struct lan_peer *p, const struct sip_msg *req, void *arg)
{
	struct uaw *w = arg;

	(void)l;
	w->hk.ack++;
	note_hook(w, p, req, NULL);
}

static struct uaw *g_w;

static void thunk_req(struct txn_layer *tl, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
		      const struct sip_msg *req, void *arg)
{
	(void)arg;
	lan_on_request(tl, st, ep, src, req, g_w->lan);
}

void uaw_init(struct uaw *w, void (*tweak)(struct lan_cfg *c), bool with_hooks)
{
	struct lan_cfg c;
	struct txn_cfg tc;

	memset(w, 0, sizeof(*w));
	g_w = w;
	evfake_reset();
	w->f = fakeep_new("lan", false, NULL);
	memset(&tc, 0, sizeof(tc));
	tc.auto_100 = true;
	tc.on_request = thunk_req;
	w->tl = txn_layer_new(&tc);
	txn_layer_attach(w->tl, w->f->ep);
	memset(&c, 0, sizeof(c));
	c.tl = w->tl;
	c.ep = w->f->ep;
	c.on_binding = on_binding;
	c.arg = w;
	if (with_hooks) {
		c.hooks.on_invite = h_invite;
		c.hooks.on_in_dialog = h_in_dialog;
		c.hooks.on_message = h_message;
		c.hooks.on_ack = h_ack;
		c.hooks.arg = w;
	}
	if (tweak)
		tweak(&c);
	w->lan = lan_new(&c);
}

void uaw_fini(struct uaw *w)
{
	lan_free(w->lan);		/* before the txn layer: it detaches live client transactions */
	txn_layer_free(w->tl);
	fakeep_free(w->f);
	evfake_reset();
}

void uaw_rx(struct uaw *w, const char *ip, int port, const char *msg)
{
	struct addr a = ua_addr(ip, port);

	fakeep_rx(w->f, &a, msg);
}

int sent_status(const struct fakeep *f, int i)
{
	struct sip_msg m;
	int s = 0;

	if (!fakeep_parse(f, i, &m)) {
		s = m.is_resp ? m.status : 0;
		sip_msg_free(&m);
	}
	return s;
}

const char *sent_method(const struct fakeep *f, int i, char *out)
{
	struct sip_msg m;

	out[0] = 0;
	if (!fakeep_parse(f, i, &m)) {
		if (!m.is_resp)
			snprintf(out, 16, "%s", m.method);
		sip_msg_free(&m);
	}
	return out;
}

const char *sent_hdr(const struct fakeep *f, int i, const char *name, char *out, size_t n)
{
	struct sip_msg m;

	out[0] = 0;
	if (!fakeep_parse(f, i, &m)) {
		const char *v = sip_hdr(&m, name, 0);

		if (v)
			snprintf(out, n, "%s", v);
		sip_msg_free(&m);
	}
	return out;
}

int find_sent(const struct fakeep *f, const char *ip, int port, const char *method, int nth)
{
	struct addr a = ua_addr(ip, port);
	char mm[16];
	int i;

	for (i = 0; i < f->nsent; i++) {
		if (!addr_equal(&f->sent[i].dst, &a) || strcmp(sent_method(f, i, mm), method))
			continue;
		if (nth-- == 0)
			return i;
	}
	return -1;
}

int count_sent(const struct fakeep *f, const char *method)
{
	char mm[16];
	int i, n = 0;

	for (i = 0; i < f->nsent; i++)
		if (!strcmp(sent_method(f, i, mm), method))
			n++;
	return n;
}

int last_resp(const struct fakeep *f)
{
	int i;

	for (i = f->nsent - 1; i >= 0; i--)
		if (sent_status(f, i))
			return i;
	return -1;
}

const char *mk_register(const char *src_ip, const char *contact, int cseq, const char *call_id, int expires_hdr,
			const char *extra)
{
	static char bufs[8][2048];
	static int k, uniq;
	char *b = bufs[k++ & 7];
	char exp[48] = "", ct[512] = "";

	if (contact)
		snprintf(ct, sizeof(ct), "Contact: %s\r\n", contact);
	if (expires_hdr >= 0)
		snprintf(exp, sizeof(exp), "Expires: %d\r\n", expires_hdr);
	snprintf(b, 2048, "REGISTER sip:192.168.68.1 SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bKr%d;rport\r\n"
		 "From: <sip:alice@192.168.68.1>;tag=tg%s\r\nTo: <sip:alice@192.168.68.1>\r\nCall-ID: %s\r\n"
		 "CSeq: %d REGISTER\r\nMax-Forwards: 70\r\n%s%s%sContent-Length: 0\r\n\r\n",
		 src_ip, ++uniq, call_id, call_id, cseq, ct, exp, extra ? extra : "");
	return b;
}

const char *dev_ip(int k)
{
	static char bufs[8][24];
	static int n;
	char *b = bufs[n++ & 7];

	snprintf(b, 24, "192.168.68.%d", 10 + k);
	return b;
}

reg_id_t dev_register(struct uaw *w, int k)
{
	char ct[128], cid[32];
	struct addr a = ua_addr(dev_ip(k), 5060);

	snprintf(ct, sizeof(ct), "<sip:u%d@%s:5060>;expires=600", k, dev_ip(k));
	snprintf(cid, sizeof(cid), "dev%d-reg", k);
	uaw_rx(w, dev_ip(k), 5060, mk_register(dev_ip(k), ct, 1, cid, -1, "User-Agent: TestPhone\r\n"));
	return reg_identify(lan_registrar(w->lan), &a, NULL);
}

void dev_reply_idx(struct uaw *w, int idx, int k, int status, const char *to_tag, const char *extra)
{
	struct sip_msg m;
	struct sip_resp_parts p;
	struct buf b;
	struct addr src = ua_addr(dev_ip(k), 5060);
	char ct[96], ex[256];

	CHECK(!fakeep_parse(w->f, idx, &m));
	snprintf(ct, sizeof(ct), "<sip:u%d@%s:5060>", k, dev_ip(k));
	snprintf(ex, sizeof(ex), "%s", extra ? extra : "");
	memset(&p, 0, sizeof(p));
	p.status = status;
	p.to_tag = to_tag;
	p.contact = status >= 200 && status < 300 ? ct : NULL;
	p.extra = ex;
	buf_init(&b, 0);
	CHECK(!sip_build_response(&b, &m, &p));
	fakeep_rx_n(w->f, &src, b.p, b.len);
	buf_free(&b);
	sip_msg_free(&m);
}

bool dev_reply(struct uaw *w, int k, const char *method, int status, const char *to_tag)
{
	int i = find_sent(w->f, dev_ip(k), 5060, method, 0);

	if (i < 0)
		return false;
	dev_reply_idx(w, i, k, status, to_tag, NULL);
	return true;
}

void fork_cb(struct lan_fork *f, struct lan_fork_event *ev, void *arg)
{
	struct fork_rec *r = arg;
	int n = r->n;

	(void)f;
	if (n >= MAXLOG)
		return;
	r->ev[n].type = ev->type;
	r->ev[n].id = ev->id;
	r->ev[n].status = ev->status;
	r->ev[n].cause = ev->cause;
	r->ev[n].is_winner = ev->is_winner;
	r->ev[n].winner = ev->winner;
	r->ev[n].nok = ev->nok;
	r->ev[n].nresults = ev->nresults > 8 ? 8 : ev->nresults;
	if (ev->results)
		memcpy(r->ev[n].res, ev->results, r->ev[n].nresults * sizeof(r->ev[n].res[0]));
	r->ev[n].had_dlg = ev->dlg != NULL;
	r->count[ev->type]++;
	r->n++;
	if (ev->dlg && r->ndlg < 8) {
		r->dlg[r->ndlg++] = *ev->dlg;
		if (r->take)
			ev->take_dlg = true;	/* ownership (and the endpoint reference) moves to us */
		else
			sip_ep_ref(r->dlg[r->ndlg - 1].ep);	/* our own reference; the lan releases its copy */
	}
}

int fr_find(const struct fork_rec *r, enum lan_fork_ev_type t, int from)
{
	int i;

	for (i = from; i < r->n; i++)
		if (r->ev[i].type == t)
			return i;
	return -1;
}

void fr_release(struct fork_rec *r)
{
	int i;

	for (i = 0; i < r->ndlg; i++)
		dlg_release(&r->dlg[i]);
	r->ndlg = 0;
}

void mk_invite_req(struct lan_req *q, const char *body)
{
	memset(q, 0, sizeof(*q));
	q->method = "INVITE";
	q->from_user = "+821012345678";
	q->from_display = "Alice \"A\"";
	q->content_type = body ? "application/sdp" : NULL;
	q->body = (const uint8_t *)body;
	q->body_len = body ? strlen(body) : 0;
}
