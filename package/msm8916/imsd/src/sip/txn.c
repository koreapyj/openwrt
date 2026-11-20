/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>
#include "txn.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define TIMER_D_MS 32000u

/* ------------------------------------------------------------------ */
/* per-transaction timer slots on one ev_timer                          */

enum { SL_RTX, SL_TMO, SL_LINGER, SL_ERR, SL_N };

struct txn_timer {
	struct ev_timer *t;
	uint64_t due[SL_N];
	unsigned armed;		/* bit mask */
};

static void tm_resched(struct txn_timer *tm)
{
	uint64_t best = 0, now = ev_now_ms();
	int i, any = 0;

	for (i = 0; i < SL_N; i++)
		if ((tm->armed >> i & 1) && (!any || tm->due[i] < best)) {
			best = tm->due[i];
			any = 1;
		}
	if (!any)
		ev_timer_cancel(tm->t);
	else
		ev_timer_set(tm->t, best > now ? best - now : 0);
}

static void tm_arm(struct txn_timer *tm, int slot, uint64_t delay)
{
	tm->due[slot] = ev_now_ms() + delay;
	tm->armed |= 1u << slot;
	tm_resched(tm);
}

static void tm_disarm(struct txn_timer *tm, int slot)
{
	tm->armed &= ~(1u << slot);
	tm_resched(tm);
}

/* earliest slot that is due (ties: lowest slot number), -1 if none */
static int tm_take(struct txn_timer *tm)
{
	uint64_t now = ev_now_ms(), best = 0;
	int i, s = -1;

	for (i = 0; i < SL_N; i++)
		if ((tm->armed >> i & 1) && tm->due[i] <= now && (s < 0 || tm->due[i] < best)) {
			s = i;
			best = tm->due[i];
		}
	if (s >= 0)
		tm->armed &= ~(1u << s);
	return s;
}

static bool hard_err(int r)
{
	return r < 0 && r != -EAGAIN && r != -EWOULDBLOCK && r != -ENOBUFS && r != -ENOMEM;
}

/* ------------------------------------------------------------------ */
/* layer                                                               */

enum cs { CS_TRYING, CS_PROCEEDING, CS_COMPLETED, CS_ACCEPTED };
enum ss { SS_TRYING, SS_PROCEEDING, SS_COMPLETED, SS_CONFIRMED, SS_ACCEPTED };

struct txn_client {
	struct txn_client *next;
	struct txn_layer *tl;
	struct sip_endpoint *ep;
	struct addr dst;
	uint8_t *req;
	size_t req_len;
	uint8_t *ack;		/* INVITE with a final non-2xx: the ACK we generated */
	size_t ack_len;
	char branch[SIP_VIA_BRANCH_MAX];
	char method[16];
	bool invite;
	enum cs state;
	unsigned interval;
	unsigned rtx;
	struct txn_timer tm;
	txn_client_cb cb;
	void *arg;
	bool cancelled;		/* txn_client_cancel was called */
	bool cancel_pending;	/* ... and no provisional seen yet */
	txn_client_cb cancel_cb;
	void *cancel_arg;
	char *cancel_extra;	/* header lines for the CANCEL, kept while it is pending */
};

struct skey {
	char branch[SIP_VIA_BRANCH_MAX];
	char host[64];
	uint16_t port;
	char method[16];
};

struct txn_server {
	struct txn_server *next;
	struct txn_layer *tl;
	struct sip_endpoint *ep;
	struct addr src, dest;
	struct sip_msg req;
	struct skey key;
	bool invite;
	enum ss state;
	uint8_t *last;
	size_t last_len;
	int last_status;
	char to_tag[24];
	bool have_tag;
	char cancel_reason[160];	/* Reason header of the CANCEL that cancelled this INVITE, "" if none */
	unsigned interval;
	struct txn_timer tm;
	txn_server_cb cb;
	void *arg;
};

struct txn_layer {
	struct txn_cfg cfg;
	struct txn_client *clients;
	struct txn_server *servers;
	unsigned count;
};

static unsigned T1(const struct txn_layer *tl) { return tl->cfg.t1_ms; }

struct txn_layer *txn_layer_new(const struct txn_cfg *cfg)
{
	struct txn_layer *tl = calloc(1, sizeof(*tl));

	if (!tl)
		return NULL;
	if (cfg)
		tl->cfg = *cfg;
	if (!tl->cfg.t1_ms)
		tl->cfg.t1_ms = 500;
	if (!tl->cfg.t2_ms)
		tl->cfg.t2_ms = 4000;
	if (!tl->cfg.t4_ms)
		tl->cfg.t4_ms = 5000;
	if (!tl->cfg.max_txns)
		tl->cfg.max_txns = 256;
	return tl;
}

unsigned txn_layer_count(const struct txn_layer *tl)
{
	return tl->count;
}

/* ------------------------------------------------------------------ */
/* destination of responses                                            */

void txn_response_dest(const struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, struct addr *dst)
{
	struct sip_via v;

	*dst = *src;
	if (ep->has_resp_override) {
		*dst = ep->resp_override;
		return;
	}
	if (ep->reliable || sip_top_via(req, &v) || v.rport >= 0)
		return;		/* same connection / rport: back to the source */
	if (addr_set(dst, v.received[0] ? v.received : v.host, v.port ? v.port : 5060))
		*dst = *src;	/* sent-by is a name: no DNS in the loop, use the source */
}

/* ------------------------------------------------------------------ */
/* client transactions                                                 */

static void client_unlink(struct txn_client *c)
{
	struct txn_client **pp;

	for (pp = &c->tl->clients; *pp; pp = &(*pp)->next)
		if (*pp == c) {
			*pp = c->next;
			break;
		}
	c->tl->count--;
}

static void client_terminate(struct txn_client *c)
{
	client_unlink(c);
	if (c->cb)
		c->cb(c, TXN_CLI_TERMINATED, NULL, NULL, NULL, c->arg);
	ev_timer_free(c->tm.t);
	sip_ep_unref(c->ep);
	free(c->req);
	free(c->ack);
	free(c->cancel_extra);
	free(c);
}

static void client_deliver(struct txn_client *c, const struct sip_msg *resp, struct sip_endpoint *rx_ep, const struct addr *src)
{
	if (c->cb)
		c->cb(c, TXN_CLI_RESPONSE, resp, rx_ep, src, c->arg);
}

static void client_timer(void *arg);

struct txn_client *txn_client_start(struct txn_layer *tl, const struct txn_client_req *r)
{
	struct txn_client *c;
	struct sip_msg m;
	struct sip_via v;
	int rc;

	if (tl->count >= tl->cfg.max_txns) {
		LOGW("txn: transaction limit (%u) reached, client request refused", tl->cfg.max_txns);
		return NULL;
	}
	rc = sip_parse(r->data, r->len, &m);
	if (rc || m.is_resp || sip_top_via(&m, &v) || !v.branch[0]) {
		if (!rc)
			sip_msg_free(&m);
		LOGW("txn: refusing malformed client request");
		return NULL;
	}
	c = calloc(1, sizeof(*c));
	if (!c) {
		sip_msg_free(&m);
		return NULL;
	}
	c->req = malloc(r->len);
	c->tm.t = ev_timer_new(client_timer, c);
	if (!c->req || !c->tm.t) {
		ev_timer_free(c->tm.t);
		free(c->req);
		free(c);
		sip_msg_free(&m);
		return NULL;
	}
	memcpy(c->req, r->data, r->len);
	c->req_len = r->len;
	memcpy(c->branch, v.branch, sizeof(c->branch));
	memcpy(c->method, m.method, sizeof(c->method));
	c->invite = !strcmp(m.method, "INVITE");
	sip_msg_free(&m);
	c->tl = tl;
	c->ep = sip_ep_ref(r->ep);
	c->dst = r->dst;
	c->cb = r->cb;
	c->arg = r->arg;
	c->state = CS_TRYING;
	c->interval = T1(tl);
	c->next = tl->clients;
	tl->clients = c;
	tl->count++;

	rc = sip_ep_send(c->ep, &c->dst, c->req, c->req_len);
	if (hard_err(rc)) {
		tm_arm(&c->tm, SL_ERR, 0);
		return c;
	}
	if (!c->ep->reliable)
		tm_arm(&c->tm, SL_RTX, c->interval);
	tm_arm(&c->tm, SL_TMO, 64ull * T1(tl));
	return c;
}

void txn_client_detach(struct txn_client *c)
{
	c->cb = NULL;
	c->cancel_cb = NULL;
}

const char *txn_client_branch(const struct txn_client *c) { return c->branch; }
struct sip_endpoint *txn_client_endpoint(const struct txn_client *c) { return c->ep; }
const struct addr *txn_client_dest(const struct txn_client *c) { return &c->dst; }
bool txn_client_cancel_pending(const struct txn_client *c) { return c->cancel_pending; }
unsigned txn_client_retransmits(const struct txn_client *c) { return c->rtx; }

/* route headers copied from req into out */
static void copy_routes(struct buf *out, const struct sip_msg *req)
{
	int i;

	for (i = 0; i < req->nh; i++)
		if (!strcasecmp(req->hdr[i].name, "Route"))
			buf_printf(out, "Route: %s\r\n", req->hdr[i].val);
}

static int top_via_value(const struct sip_msg *m, char *out, size_t n)
{
	struct sip_list it;

	sip_list_init(&it, m, "Via");
	return sip_list_next(&it, out, n) == 1 ? 0 : -1;
}

/* ACK for a non-2xx final response (RFC 3261 17.1.1.3) */
static int build_ack(const struct txn_client *c, const struct sip_msg *resp, struct buf *out)
{
	struct sip_msg req;
	struct buf routes;
	char via[320];
	const char *to = sip_hdr(resp, "To", 0);
	uint32_t cs;
	struct sip_req_parts p;
	int rc = -1;

	if (sip_parse(c->req, c->req_len, &req))
		return -1;
	buf_init(&routes, 4096);
	copy_routes(&routes, &req);
	if (!to || top_via_value(&req, via, sizeof(via)) || sip_cseq(&req, &cs, NULL, 0) || !buf_ok(&routes))
		goto out;
	memset(&p, 0, sizeof(p));
	p.method = "ACK";
	p.ruri = req.ruri;
	p.via = via;
	p.from = sip_hdr(&req, "From", 0);
	p.to = to;
	p.call_id = sip_hdr(&req, "Call-ID", 0);
	p.cseq = cs;
	p.route = routes.len ? buf_cstr(&routes) : NULL;
	if (!p.from || !p.call_id)
		goto out;
	rc = sip_build_request(out, &p);
out:
	buf_free(&routes);
	sip_msg_free(&req);
	return rc;
}

static int build_cancel(const struct txn_client *c, const char *extra, struct buf *out)
{
	struct sip_msg req;
	struct buf routes;
	char via[320];
	uint32_t cs;
	struct sip_req_parts p;
	int rc = -1;

	if (sip_parse(c->req, c->req_len, &req))
		return -1;
	buf_init(&routes, 4096);
	copy_routes(&routes, &req);
	if (top_via_value(&req, via, sizeof(via)) || sip_cseq(&req, &cs, NULL, 0) || !buf_ok(&routes))
		goto out;
	memset(&p, 0, sizeof(p));
	p.method = "CANCEL";
	p.ruri = req.ruri;
	p.via = via;
	p.from = sip_hdr(&req, "From", 0);
	p.to = sip_hdr(&req, "To", 0);
	p.call_id = sip_hdr(&req, "Call-ID", 0);
	p.cseq = cs;
	p.extra = extra && extra[0] ? extra : NULL;
	p.route = routes.len ? buf_cstr(&routes) : NULL;
	if (!p.from || !p.to || !p.call_id)
		goto out;
	rc = sip_build_request(out, &p);
out:
	buf_free(&routes);
	sip_msg_free(&req);
	return rc;
}

static int send_cancel(struct txn_client *inv, const char *extra, txn_client_cb cb, void *arg)
{
	struct buf b;
	struct txn_client_req r;
	int rc = -1;

	buf_init(&b, 0);
	if (build_cancel(inv, extra, &b))
		goto out;
	r.ep = inv->ep;
	r.dst = inv->dst;
	r.data = b.p;
	r.len = b.len;
	r.cb = cb;
	r.arg = arg;
	rc = txn_client_start(inv->tl, &r) ? 0 : -1;
	/* RFC 3261 9.1: a UAS that never answers the CANCEL must not hold the INVITE transaction (and a slot)
	 * forever: from now on the INVITE has 64*T1 to reach a final response, then it times out. */
	if (!rc)
		tm_arm(&inv->tm, SL_TMO, 64ull * T1(inv->tl));
out:
	buf_free(&b);
	return rc;
}

int txn_client_cancel_ex(struct txn_client *inv, const char *extra_headers, txn_client_cb cb, void *arg)
{
	if (!inv->invite || inv->cancelled || (inv->state != CS_TRYING && inv->state != CS_PROCEEDING))
		return -1;
	if (inv->state == CS_PROCEEDING) {
		if (send_cancel(inv, extra_headers, cb, arg))
			return -1;
		inv->cancelled = true;
		return 0;
	}
	if (extra_headers && extra_headers[0]) {
		inv->cancel_extra = strdup(extra_headers);
		if (!inv->cancel_extra)
			return -1;
	}
	inv->cancelled = true;
	inv->cancel_pending = true;
	inv->cancel_cb = cb;
	inv->cancel_arg = arg;
	return 0;
}

int txn_client_cancel(struct txn_client *inv, txn_client_cb cb, void *arg)
{
	return txn_client_cancel_ex(inv, NULL, cb, arg);
}

static void client_send_ack_again(struct txn_client *c)
{
	if (c->ack)
		sip_ep_send(c->ep, &c->dst, c->ack, c->ack_len);
}

static void client_on_response(struct txn_client *c, const struct sip_msg *resp, struct sip_endpoint *rx_ep, const struct addr *src)
{
	struct txn_layer *tl = c->tl;
	int st = resp->status;

	if (c->invite) {
		switch (c->state) {
		case CS_TRYING:
		case CS_PROCEEDING:
			if (st < 200) {
				c->state = CS_PROCEEDING;
				tm_disarm(&c->tm, SL_RTX);
				if (!c->cancelled || c->cancel_pending)	/* after a CANCEL the 64*T1 guard keeps running */
					tm_disarm(&c->tm, SL_TMO);
				if (c->cancel_pending) {
					c->cancel_pending = false;
					if (send_cancel(c, c->cancel_extra, c->cancel_cb, c->cancel_arg)) {
						LOGW("txn: pending CANCEL could not be sent");
						tm_arm(&c->tm, SL_TMO, 64ull * T1(tl));	/* Timer B was disarmed: keep the transaction bounded */
					}
					free(c->cancel_extra);
					c->cancel_extra = NULL;
				}
				client_deliver(c, resp, rx_ep, src);
			} else if (st < 300) {
				c->state = CS_ACCEPTED;
				c->cancel_pending = false;
				tm_disarm(&c->tm, SL_RTX);
				tm_disarm(&c->tm, SL_TMO);
				tm_arm(&c->tm, SL_LINGER, 64ull * T1(tl));
				client_deliver(c, resp, rx_ep, src);
			} else {
				struct buf b;

				c->cancel_pending = false;
				buf_init(&b, 0);
				if (!build_ack(c, resp, &b)) {
					c->ack = buf_steal(&b, &c->ack_len);
					client_send_ack_again(c);
				} else {
					LOGW("txn: cannot build ACK for %d", st);
					buf_free(&b);
				}
				c->state = CS_COMPLETED;
				tm_disarm(&c->tm, SL_RTX);
				tm_disarm(&c->tm, SL_TMO);
				tm_arm(&c->tm, SL_LINGER, c->ep->reliable ? 0 : TIMER_D_MS);
				client_deliver(c, resp, rx_ep, src);
			}
			break;
		case CS_ACCEPTED:
			if (st >= 200 && st < 300)
				client_deliver(c, resp, rx_ep, src);
			break;
		case CS_COMPLETED:
			if (st >= 300)
				client_send_ack_again(c);	/* retransmitted final: ACK again, absorb */
			break;
		}
		return;
	}
	/* non-INVITE */
	switch (c->state) {
	case CS_TRYING:
	case CS_PROCEEDING:
		if (st < 200) {
			if (c->state == CS_TRYING) {	/* E continues at T2 from now on */
				c->state = CS_PROCEEDING;
				c->interval = tl->cfg.t2_ms;
				if (!c->ep->reliable)
					tm_arm(&c->tm, SL_RTX, c->interval);
			}
			client_deliver(c, resp, rx_ep, src);
		} else {
			c->state = CS_COMPLETED;
			tm_disarm(&c->tm, SL_RTX);
			tm_disarm(&c->tm, SL_TMO);
			tm_arm(&c->tm, SL_LINGER, c->ep->reliable ? 0 : tl->cfg.t4_ms);
			client_deliver(c, resp, rx_ep, src);
		}
		break;
	default:
		break;		/* Completed: absorb */
	}
}

static void client_timer(void *arg)
{
	struct txn_client *c = arg;
	struct txn_layer *tl = c->tl;
	int slot = tm_take(&c->tm), rc;

	if (slot < 0) {
		tm_resched(&c->tm);
		return;
	}
	switch (slot) {
	case SL_RTX:
		if (c->state == CS_COMPLETED || c->state == CS_ACCEPTED)
			break;
		rc = sip_ep_send(c->ep, &c->dst, c->req, c->req_len);
		c->rtx++;
		if (hard_err(rc)) {
			tm_arm(&c->tm, SL_ERR, 0);
			break;
		}
		if (c->invite)		/* Timer A doubles without a cap */
			c->interval *= 2;
		else if (c->state == CS_PROCEEDING)
			c->interval = tl->cfg.t2_ms;
		else
			c->interval = c->interval * 2 > tl->cfg.t2_ms ? tl->cfg.t2_ms : c->interval * 2;
		tm_arm(&c->tm, SL_RTX, c->interval);
		break;
	case SL_TMO:
		LOGD("txn: client %s %s timed out", c->method, c->branch);
		if (c->cb)
			c->cb(c, TXN_CLI_TIMEOUT, NULL, NULL, NULL, c->arg);
		client_terminate(c);
		return;
	case SL_LINGER:
		client_terminate(c);
		return;
	case SL_ERR:
		if (c->cb)
			c->cb(c, TXN_CLI_TRANSPORT_ERROR, NULL, NULL, NULL, c->arg);
		client_terminate(c);
		return;
	}
	tm_resched(&c->tm);
}

/* ------------------------------------------------------------------ */
/* server transactions                                                 */

static uint64_t fnv(uint64_t h, const char *s)
{
	for (; *s; s++)
		h = (h ^ (uint8_t)*s) * 1099511628211ull;
	return (h ^ '|') * 1099511628211ull;
}

static int make_key(const struct sip_msg *m, struct skey *k)
{
	struct sip_via v;
	size_t i;

	memset(k, 0, sizeof(*k));
	if (sip_top_via(m, &v))
		return -1;
	if (!strncmp(v.branch, SIP_MAGIC_COOKIE, 7) && v.branch[7]) {
		memcpy(k->branch, v.branch, sizeof(k->branch));
	} else {	/* RFC 2543 style request: Call-ID, CSeq, From tag, R-URI */
		const char *cid = sip_hdr(m, "Call-ID", 0), *cs = sip_hdr(m, "CSeq", 0), *from = sip_hdr(m, "From", 0);
		char tag[96] = "";
		uint64_t h = 14695981039346656037ull;

		if (!cid || !cs)
			return -1;
		if (from)
			sip_tag(from, tag, sizeof(tag));
		h = fnv(h, cid);
		h = fnv(h, cs);
		h = fnv(h, tag);
		h = fnv(h, m->ruri);
		snprintf(k->branch, sizeof(k->branch), "~%016llx", (unsigned long long)h);
	}
	for (i = 0; v.host[i] && i < sizeof(k->host) - 1; i++)
		k->host[i] = tolower((unsigned char)v.host[i]);
	k->port = v.port ? v.port : 5060;
	snprintf(k->method, sizeof(k->method), "%s", !strcmp(m->method, "ACK") ? "INVITE" : m->method);
	return 0;
}

static bool key_eq(const struct skey *a, const struct skey *b)
{
	return a->port == b->port && !strcmp(a->branch, b->branch) && !strcmp(a->host, b->host) &&
	       !strcmp(a->method, b->method);
}

static struct txn_server *server_find(struct txn_layer *tl, const struct skey *k)
{
	struct txn_server *s;

	for (s = tl->servers; s; s = s->next)
		if (key_eq(&s->key, k))
			return s;
	return NULL;
}

static void server_timer(void *arg);

static void server_terminate(struct txn_server *s)
{
	struct txn_server **pp;

	for (pp = &s->tl->servers; *pp; pp = &(*pp)->next)
		if (*pp == s) {
			*pp = s->next;
			break;
		}
	s->tl->count--;
	if (s->cb)
		s->cb(s, TXN_SRV_TERMINATED, s->arg);
	ev_timer_free(s->tm.t);
	sip_ep_unref(s->ep);
	sip_msg_free(&s->req);
	free(s->last);
	free(s);
}

static struct txn_server *server_create(struct txn_layer *tl, struct sip_endpoint *ep, const struct addr *src,
					const uint8_t *data, size_t len, const struct skey *k)
{
	struct txn_server *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;
	if (sip_parse(data, len, &s->req)) {
		free(s);
		return NULL;
	}
	s->tm.t = ev_timer_new(server_timer, s);
	if (!s->tm.t) {
		sip_msg_free(&s->req);
		free(s);
		return NULL;
	}
	s->tl = tl;
	s->ep = sip_ep_ref(ep);
	s->src = *src;
	s->key = *k;
	s->invite = !strcmp(s->req.method, "INVITE");
	s->state = s->invite ? SS_PROCEEDING : SS_TRYING;
	txn_response_dest(ep, src, &s->req, &s->dest);
	s->next = tl->servers;
	tl->servers = s;
	tl->count++;
	return s;
}

void txn_server_set_cb(struct txn_server *st, txn_server_cb cb, void *arg)
{
	st->cb = cb;
	st->arg = arg;
}

const struct sip_msg *txn_server_request(const struct txn_server *st) { return &st->req; }
struct sip_endpoint *txn_server_endpoint(const struct txn_server *st) { return st->ep; }
const struct addr *txn_server_src(const struct txn_server *st) { return &st->src; }
const struct addr *txn_server_dest(const struct txn_server *st) { return &st->dest; }
int txn_server_last_status(const struct txn_server *st) { return st->last_status; }
bool txn_server_is_invite(const struct txn_server *st) { return st->invite; }
const char *txn_server_cancel_reason(const struct txn_server *st) { return st ? st->cancel_reason : ""; }

const char *txn_server_to_tag(struct txn_server *st)
{
	if (!st->have_tag) {
		rnd_token(st->to_tag, 12);
		st->have_tag = true;
	}
	return st->to_tag;
}

int txn_server_reply_raw(struct txn_server *st, int status, const uint8_t *data, size_t len)
{
	struct txn_layer *tl = st->tl;
	uint8_t *copy;
	int rc;

	if (status < 100 || status > 699 || !len)
		return -EINVAL;
	if (st->state == SS_COMPLETED || st->state == SS_CONFIRMED || st->state == SS_ACCEPTED)
		return -EINVAL;		/* a final response was already sent */
	if (st->last_status >= 200)
		return -EINVAL;
	copy = malloc(len);
	if (!copy)
		return -ENOMEM;
	memcpy(copy, data, len);
	free(st->last);
	st->last = copy;
	st->last_len = len;
	st->last_status = status;

	if (st->invite) {
		if (status < 200) {
			st->state = SS_PROCEEDING;
		} else if (status < 300) {
			st->state = SS_ACCEPTED;
			tm_arm(&st->tm, SL_LINGER, 64ull * T1(tl));	/* Timer L */
		} else {
			st->state = SS_COMPLETED;
			st->interval = T1(tl);
			if (!st->ep->reliable)
				tm_arm(&st->tm, SL_RTX, st->interval);	/* Timer G */
			tm_arm(&st->tm, SL_TMO, 64ull * T1(tl));	/* Timer H */
		}
	} else if (status < 200) {
		st->state = SS_PROCEEDING;
	} else {
		st->state = SS_COMPLETED;
		tm_arm(&st->tm, SL_LINGER, st->ep->reliable ? 0 : 64ull * T1(tl));	/* Timer J */
	}
	rc = sip_ep_send(st->ep, &st->dest, copy, len);
	return rc;
}

int txn_server_reply(struct txn_server *st, const struct sip_resp_parts *p)
{
	struct sip_resp_parts q = *p;
	struct buf b;
	int rc;

	q.src = &st->src;
	if (!q.to_tag && q.status > 100)
		q.to_tag = txn_server_to_tag(st);
	buf_init(&b, 0);
	if (sip_build_response(&b, &st->req, &q)) {
		buf_free(&b);
		return -EINVAL;
	}
	rc = txn_server_reply_raw(st, q.status, b.p, b.len);
	buf_free(&b);
	return rc;
}

static void server_ack(struct txn_server *s)
{
	if (s->state != SS_COMPLETED)
		return;
	s->state = SS_CONFIRMED;
	tm_disarm(&s->tm, SL_RTX);
	tm_disarm(&s->tm, SL_TMO);
	tm_arm(&s->tm, SL_LINGER, s->ep->reliable ? 0 : s->tl->cfg.t4_ms);	/* Timer I */
}

static void server_timer(void *arg)
{
	struct txn_server *s = arg;
	int slot = tm_take(&s->tm);

	if (slot < 0) {
		tm_resched(&s->tm);
		return;
	}
	switch (slot) {
	case SL_RTX:		/* Timer G */
		if (s->state == SS_COMPLETED && s->last) {
			sip_ep_send(s->ep, &s->dest, s->last, s->last_len);
			s->interval = s->interval * 2 > s->tl->cfg.t2_ms ? s->tl->cfg.t2_ms : s->interval * 2;
			tm_arm(&s->tm, SL_RTX, s->interval);
		}
		break;
	case SL_TMO:		/* Timer H */
		LOGD("txn: server %s %s: no ACK", s->key.method, s->key.branch);
		if (s->cb)
			s->cb(s, TXN_SRV_TIMEOUT, s->arg);
		server_terminate(s);
		return;
	case SL_LINGER:		/* I, J, L */
		server_terminate(s);
		return;
	default:
		break;
	}
	tm_resched(&s->tm);
}

static void server_simple_reply(struct txn_server *s, int status)
{
	struct sip_resp_parts p;

	memset(&p, 0, sizeof(p));
	p.status = status;
	txn_server_reply(s, &p);
}

/* ------------------------------------------------------------------ */
/* receive path                                                        */

int txn_respond_stateless(struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, const struct sip_resp_parts *p)
{
	struct sip_resp_parts q = *p;
	struct buf b;
	struct addr dst;
	int rc = -EINVAL;

	q.src = src;
	buf_init(&b, 0);
	if (!sip_build_response(&b, req, &q)) {
		txn_response_dest(ep, src, req, &dst);
		rc = sip_ep_send(ep, &dst, b.p, b.len);
	}
	buf_free(&b);
	return rc;
}

static void handle_response(struct txn_layer *tl, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *m)
{
	struct sip_via v;
	char method[16];
	uint32_t cs;
	struct txn_client *c;

	if (sip_top_via(m, &v) || sip_cseq(m, &cs, method, sizeof(method))) {
		LOGD("txn: dropping response without Via/CSeq");
		return;
	}
	for (c = tl->clients; c; c = c->next)
		if (!strcmp(c->branch, v.branch) && !strcmp(c->method, method)) {
			client_on_response(c, m, ep, src);
			return;
		}
	if (tl->cfg.on_stray_response)
		tl->cfg.on_stray_response(tl, ep, src, m, tl->cfg.arg);
}

static void handle_cancel(struct txn_layer *tl, struct sip_endpoint *ep, const struct addr *src,
			  const uint8_t *data, size_t len, const struct sip_msg *m, const struct skey *k)
{
	struct skey ik = *k;
	struct txn_server *inv, *cs;

	snprintf(ik.method, sizeof(ik.method), "INVITE");
	inv = server_find(tl, &ik);
	if (tl->count >= tl->cfg.max_txns) {
		struct sip_resp_parts p = { .status = 503 };

		txn_respond_stateless(ep, src, m, &p);
		return;
	}
	cs = server_create(tl, ep, src, data, len, k);
	if (!cs)
		return;
	if (!inv) {
		server_simple_reply(cs, 481);
		return;
	}
	server_simple_reply(cs, 200);
	if (!inv->cancel_reason[0]) {
		const char *rs = sip_hdr(m, "Reason", 0);

		if (rs)
			snprintf(inv->cancel_reason, sizeof(inv->cancel_reason), "%s", rs);
	}
	if (inv->state == SS_PROCEEDING && inv->cb)
		inv->cb(inv, TXN_SRV_CANCELLED, inv->arg);
}

static void handle_request(struct txn_layer *tl, struct sip_endpoint *ep, const struct addr *src,
			   const uint8_t *data, size_t len, const struct sip_msg *m)
{
	struct skey k;
	struct txn_server *s;
	bool is_ack = !strcmp(m->method, "ACK");

	if (make_key(m, &k)) {
		LOGD("txn: dropping request without usable Via");
		return;
	}
	s = server_find(tl, &k);
	if (s) {
		if (is_ack) {
			if (s->state == SS_COMPLETED || s->state == SS_CONFIRMED) {
				server_ack(s);	/* confirmed: absorbed */
				return;
			}
			if (s->state == SS_PROCEEDING)
				return;
			/* ACK after a 2xx that reused the branch: let the TU see it */
		} else {
			if (s->last && (s->state != SS_TRYING))
				sip_ep_send(s->ep, &s->dest, s->last, s->last_len);	/* retransmitted request: repeat the last response */
			return;
		}
	}
	if (is_ack) {
		if (tl->cfg.on_request)
			tl->cfg.on_request(tl, NULL, ep, src, m, tl->cfg.arg);
		return;
	}
	if (!strcmp(m->method, "CANCEL")) {
		handle_cancel(tl, ep, src, data, len, m, &k);
		return;
	}
	if (tl->count >= tl->cfg.max_txns) {
		struct sip_resp_parts p = { .status = 503 };

		LOGW("txn: transaction limit reached, answering %s with 503", m->method);
		txn_respond_stateless(ep, src, m, &p);
		return;
	}
	s = server_create(tl, ep, src, data, len, &k);
	if (!s)
		return;
	if (s->invite && tl->cfg.auto_100) {
		struct sip_resp_parts p = { .status = 100 };

		txn_server_reply(s, &p);
	}
	if (tl->cfg.on_request)
		tl->cfg.on_request(tl, s, ep, src, &s->req, tl->cfg.arg);
}

static void layer_rx(struct sip_endpoint *ep, const struct addr *src, const uint8_t *data, size_t len, void *arg)
{
	struct txn_layer *tl = arg;
	struct sip_msg m;
	int rc;
	size_t i;

	/* RFC 5626 keep-alive ("\r\n\r\n" ping, "\r\n" pong): answered with a single CRLF on unreliable transports, never logged */
	for (i = 0; i < len && (data[i] == '\r' || data[i] == '\n'); i++)
		;
	if (i == len && len >= 2) {
		if (len >= 4 && !ep->reliable)
			sip_ep_send(ep, src, "\r\n", 2);
		return;
	}
	rc = sip_parse(data, len, &m);
	if (rc) {
		char a[INET6_ADDRSTRLEN + 8] = "?";

		addr_str(src, a, sizeof(a));
		LOGD("%s: dropping unparsable message from %s (%d)", ep->name, a, rc);
		return;
	}
	if (m.is_resp)
		handle_response(tl, ep, src, &m);
	else
		handle_request(tl, ep, src, data, len, &m);
	sip_msg_free(&m);
}

void txn_layer_attach(struct txn_layer *tl, struct sip_endpoint *ep)
{
	sip_ep_set_rx(ep, layer_rx, tl);
}

void txn_layer_free(struct txn_layer *tl)
{
	if (!tl)
		return;
	while (tl->clients) {
		struct txn_client *c = tl->clients;

		tl->clients = c->next;
		ev_timer_free(c->tm.t);
		sip_ep_unref(c->ep);
		free(c->req);
		free(c->ack);
		free(c->cancel_extra);
		free(c);
	}
	while (tl->servers) {
		struct txn_server *s = tl->servers;

		tl->servers = s->next;
		ev_timer_free(s->tm.t);
		sip_ep_unref(s->ep);
		sip_msg_free(&s->req);
		free(s->last);
		free(s);
	}
	free(tl);
}

/* ------------------------------------------------------------------ */
/* 2xx retransmission helper                                           */

struct sip_rtx {
	struct sip_endpoint *ep;
	struct addr dst;
	uint8_t *data;
	size_t len;
	unsigned interval, t2;
	unsigned count;
	uint64_t giveup_at, next_at;
	struct ev_timer *t;
	sip_rtx_cb cb;
	void *arg;
};

static void rtx_arm(struct sip_rtx *r)
{
	uint64_t now = ev_now_ms(), at = r->giveup_at;

	if (!r->ep->reliable && r->next_at < at)
		at = r->next_at;
	ev_timer_set(r->t, at > now ? at - now : 0);
}

static void rtx_free(struct sip_rtx *r)
{
	ev_timer_free(r->t);
	sip_ep_unref(r->ep);
	free(r->data);
	free(r);
}

static void rtx_timer(void *arg)
{
	struct sip_rtx *r = arg;
	uint64_t now = ev_now_ms();

	if (now >= r->giveup_at) {
		sip_rtx_cb cb = r->cb;
		void *a = r->arg;

		if (cb)
			cb(r, a);
		rtx_free(r);
		return;
	}
	if (!r->ep->reliable && now >= r->next_at) {
		sip_ep_send(r->ep, &r->dst, r->data, r->len);
		r->count++;
		r->interval = r->interval * 2 > r->t2 ? r->t2 : r->interval * 2;
		r->next_at = now + r->interval;
	}
	rtx_arm(r);
}

struct sip_rtx *sip_rtx_start(struct sip_endpoint *ep, const struct addr *dst, const uint8_t *data, size_t len,
			      unsigned t1_ms, unsigned t2_ms, sip_rtx_cb on_giveup, void *arg)
{
	struct sip_rtx *r = calloc(1, sizeof(*r));
	uint64_t now = ev_now_ms();

	if (!r)
		return NULL;
	if (!t1_ms)
		t1_ms = 500;
	if (!t2_ms)
		t2_ms = 4000;
	r->data = malloc(len);
	r->t = ev_timer_new(rtx_timer, r);
	if (!r->data || !r->t) {
		ev_timer_free(r->t);
		free(r->data);
		free(r);
		return NULL;
	}
	memcpy(r->data, data, len);
	r->len = len;
	r->ep = sip_ep_ref(ep);
	r->dst = *dst;
	r->interval = t1_ms;
	r->t2 = t2_ms;
	r->next_at = now + t1_ms;
	r->giveup_at = now + 64ull * t1_ms;
	r->cb = on_giveup;
	r->arg = arg;
	rtx_arm(r);
	return r;
}

void sip_rtx_stop(struct sip_rtx *r)
{
	if (r)
		rtx_free(r);
}

unsigned sip_rtx_count(const struct sip_rtx *r)
{
	return r->count;
}

struct sip_rtx *txn_server_start_2xx_rtx(struct txn_server *st, unsigned t1_ms, unsigned t2_ms, sip_rtx_cb on_giveup, void *arg)
{
	if (!st->last || st->last_status < 200 || st->last_status >= 300)
		return NULL;
	return sip_rtx_start(st->ep, &st->dest, st->last, st->last_len,
			     t1_ms ? t1_ms : st->tl->cfg.t1_ms, t2_ms ? t2_ms : st->tl->cfg.t2_ms, on_giveup, arg);
}
