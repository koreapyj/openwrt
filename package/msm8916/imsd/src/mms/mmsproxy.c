/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The MMS proxy, see mmsproxy.h. */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "mmsproxy.h"
#include "httpd.h"
#include "mmsrender.h"
#include "mmsstore.h"
#include "mmsitem.h"
#include "mms_lan.h"
#include "../ua/lan_text.h"
#include "../util/buf.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define MMS_CT		"application/vnd.wap.mms-message"
#define RELAYS_MAX	4
#define WAIT_MAX	8		/* = the connection limit of the server */
#define FETCH_TAB	32
#define SEND_TAB	32
#define SEND_TTL_MS	(10u * 60 * 1000)
#define SEND_KEEP_MAX	(8 * 1024)	/* an answer of the MMSC kept for repeats: an M-Send.conf is tiny */
#define SEND_CONF_MAX	(64 * 1024)
#define SEND_TIMEOUT_MS	60000u
#define SEND_IDLE_MS	20000u
#define FETCH_TIMEOUT_MS 90000u
#define FETCH_IDLE_MS	20000u
#define SWEEP_MS	30000u
#define RETRY_MS	5000u
#define WALL_PLAUSIBLE	1600000000
#define SENT_FILE	"sent.pdu"
#define FETCH_FILE	"fetch.pdu"

void mmsproxy_cfg_defaults(struct mmsproxy_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->port = 8090;
	c->cache_s = 600;
	c->carbons = true;
	c->max_size = 1024 * 1024;
	snprintf(c->dir, sizeof(c->dir), "/tmp/imsd-mms-proxy");
	c->keep_messages = 50;
	c->keep_bytes = 16 * 1024 * 1024;
	c->keep_days = 7;
	c->store_keep_days = 0;
}

/* a response of the MMSC (or of the proxy itself) to hand to a connection */
struct fetch {
	struct mmsproxy *p;
	bool used, running;
	bool await_link;
	char url[MMS_URL_MAX];
	struct http_req *req;
	struct httpd_conn *wait[WAIT_MAX];
	unsigned nwait;
	/* done and cached */
	bool cached;
	char dir[33];
	char ctype[96];
	uint64_t expire;
};

struct sendent {
	struct mmsproxy *p;
	bool used, running, kept;
	bool await_link;		/* waiting for the on-demand MMS data connection (mms_link_wait) */
	char tid[MMS_ID_MAX];		/* "" = the PDU has none: no repeat detection */
	uint64_t hash;
	size_t len;
	uint64_t at;
	struct http_req *req;
	struct httpd_conn *wait[WAIT_MAX];
	unsigned nwait;
	uint8_t *pdu;			/* the request, while it runs (stored as the carbon copy afterwards) */
	struct addr client;
	/* the answer */
	int status;
	char ctype[96];
	uint8_t *body;
	size_t blen;
};

struct mmsproxy;

enum sreq_kind { SR_FETCH, SR_SENT };
struct sreq {
	bool used;
	enum sreq_kind kind;
	struct mmsproxy *p;
	struct httpd_conn *c;
	uint32_t token;
	char key[MMS_URL_MAX];	/* the URL / the id asked for */
};

struct carbon_job;

struct mmsproxy {
	struct mmsproxy_cfg cfg;
	struct mmsproxy_ops ops;
	struct mms *mms;
	struct httpd *hd;
	struct mmsstore *store;
	struct lan *lan;
	struct lan_seqs *seqs;
	struct addr laddr;
	bool have_laddr;
	char base[200];
	char error[96];
	struct ev_timer *retry, *sweep;
	struct fetch fetch[FETCH_TAB];
	struct sendent send[SEND_TAB];
	struct sreq sreq[WAIT_MAX];
	unsigned relays;
	struct mmsproxy_status st;
};

/* a relay in flight is MMS work: the on-demand data connection is kept for it */
static void relay_inc(struct mmsproxy *p)
{
	p->relays++;
	mms_work(p->mms, 1);
}

static void relay_dec(struct mmsproxy *p)
{
	p->relays--;
	mms_work(p->mms, -1);
}

static int64_t wall(const struct mmsproxy *p)
{
	return p->ops.wall ? p->ops.wall(p->ops.ctx) : (int64_t)time(NULL);
}

static int64_t mmsstore_wall(void *ctx)
{
	return wall(ctx);
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */

static int hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	c = tolower(c);
	return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

int mmsproxy_urldecode(const char *in, size_t n, char *out, size_t cap)
{
	size_t i, k = 0;

	if (!cap)
		return -1;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)in[i];

		if (c == '%') {
			int h, l;

			if (i + 2 >= n)
				return -1;
			h = hexval(in[i + 1]);
			l = hexval(in[i + 2]);
			if (h < 0 || l < 0)
				return -1;
			c = (unsigned char)(h * 16 + l);
			i += 2;
		}
		if (k + 1 >= cap)
			return -1;
		out[k++] = (char)c;
	}
	out[k] = 0;
	return 0;
}

int mmsproxy_query_get(const char *query, const char *name, char *out, size_t cap)
{
	size_t nl = strlen(name);
	const char *p = query;

	while (*p) {
		const char *e = p + strcspn(p, "&");

		if ((size_t)(e - p) > nl && !strncmp(p, name, nl) && p[nl] == '=')
			return mmsproxy_urldecode(p + nl + 1, (size_t)(e - p) - nl - 1, out, cap);
		p = *e ? e + 1 : e;
	}
	return -1;
}

static uint64_t fnv(const uint8_t *d, size_t n)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	for (i = 0; i < n; i++) {
		h ^= d[i];
		h *= 0x100000001b3ull;
	}
	return h ^ (uint64_t)n;
}

static bool ct_is(const char *ct, const char *type)
{
	size_t l = strlen(type);

	return !strncasecmp(ct, type, l) && (ct[l] == 0 || ct[l] == ';' || ct[l] == ' ');
}

/* a header value that may go on a response line */
static bool clean_ct(const char *ct)
{
	for (; *ct; ct++)
		if ((unsigned char)*ct < 0x20 || (unsigned char)*ct == 0x7f)
			return false;
	return true;
}

static void reply_text(struct httpd_conn *c, int status, const char *text, const char *extra)
{
	char b[160];
	int n = snprintf(b, sizeof(b), "%s\n", text);

	httpd_respond(c, status, "text/plain; charset=utf-8", extra, b, n > 0 ? (size_t)n : 0, false);
}

/* ------------------------------------------------------------------ */
/* carbon copies of sent MMS                                           */

static void carbon_done(void *arg, int nok)
{
	struct mmsproxy *p = arg;

	if (nok > 0) {
		p->st.carbons_sent++;
	} else {
		p->st.carbons_failed++;
		LOGI("mmsproxy: the carbon copy of a sent message was taken by nobody");
	}
}

/* ids of the carbon capable bindings except the ones the client came from (same source IP) */
static unsigned carbon_targets(struct mmsproxy *p, const struct addr *client, reg_id_t *out, unsigned max)
{
	struct registrar *r = lan_registrar(p->lan);
	const struct reg_binding *b;
	reg_id_t id = REG_ID_NONE;
	unsigned n = 0;

	while (n < max && (b = reg_next(r, id))) {
		id = b->id;
		if ((b->features & REG_F_CARBONS) && reg_allows(b, "MESSAGE") && !addr_equal_ip(&b->src, client))
			out[n++] = b->id;
	}
	return n;
}

/* what a carbon copy says about the sent message, fixed when the copy is made */
static void carbon_fill(struct mmsproxy *p, const struct mms_head *rq, const struct mms_head *conf, const char *id,
			struct mms_carbon_item *ci)
{
	size_t pl = 0;
	int k, i, total = 0;

	memset(ci, 0, sizeof(*ci));
	snprintf(ci->id, sizeof(ci->id), "%s", id);
	mmsr_oneline(conf->message_id, ci->mid, sizeof(ci->mid));
	mmsr_oneline(rq->subject, ci->subject, sizeof(ci->subject));
	ci->time = wall(p);
	ci->peers[0] = 0;
	for (k = 0; k < 3; k++)
		for (i = 0; i < rq->n_rcpt[k]; i++) {
			size_t al = strlen(rq->rcpt[k][i]);

			if (total >= MMS_HEAD_RCPT || pl + al + 2 > 900) {
				ci->trunc = true;
				continue;
			}
			if (strpbrk(rq->rcpt[k][i], "\r\n,"))
				continue;
			pl += (size_t)snprintf(ci->peers + pl, sizeof(ci->peers) - pl, "%s%s", total ? "," : "", rq->rcpt[k][i]);
			total++;
		}
	if (rq->rcpt_more)
		ci->trunc = true;
}

/* the headers of the carbon MESSAGE; 0 when they do not fit */
static int carbon_headers(const struct mmsproxy *p, const struct mms_carbon_item *ci, uint64_t seq, char *extra, size_t n)
{
	size_t e = 0;
	char ts[48];

	e += (size_t)snprintf(extra + e, n - e, "X-IMSD-Carbon: sent\r\nX-IMSD-Carbon-ID: %s\r\n"
			      "X-MMS-Location: %s/sent/%s\r\n", ci->id, p->base, ci->id);
	if (ci->mid[0] && e < n)
		e += (size_t)snprintf(extra + e, n - e, "X-MMS-Message-ID: %s\r\n", ci->mid);
	if (ci->peers[0] && e < n)
		e += (size_t)snprintf(extra + e, n - e, "X-IMSD-Peer: %s\r\n", ci->peers);
	if (ci->trunc && e < n)
		e += (size_t)snprintf(extra + e, n - e, "X-IMSD-Peer-Truncated: 1\r\n");
	if (ci->subject[0] && e < n)
		e += (size_t)snprintf(extra + e, n - e, "X-MMS-Subject: %s\r\n", ci->subject);
	if (ci->time >= WALL_PLAUSIBLE && e < n) {
		lan_text_iso(ci->time, ts, sizeof(ts));
		e += (size_t)snprintf(extra + e, n - e, "X-SMS-Timestamp: %s\r\n", ts);
	}
	if (seq && e < n)
		e += (size_t)snprintf(extra + e, n - e, "X-IMSD-Seq: %llu\r\n", (unsigned long long)seq);
	return e < n ? 0 : -1;
}

/*
 * The carbon copy of a sent MMS is announced like a received MMS: a SIP MESSAGE with the headers and the body of a raw notification
 * (mms_lan_raw_headers, the same builder as for a received one) plus the carbon headers. The body is an M-Notification.ind made here
 * whose Content-Location is the gateway's URL of the stored M-Send.req.
 */
struct carbon_msg {
	char extra[1900];
	uint8_t pdu[1400];
	size_t len;
};

/* 0, or -1 when something does not fit. pdu_size: size of the stored M-Send.req. in_store: where the copy lives decides its expiry */
static int carbon_build(struct mmsproxy *p, const struct mms_carbon_item *ci, uint64_t seq, bool in_store, size_t pdu_size,
			struct carbon_msg *m)
{
	char url[MMS_URL_MAX], own[96], from[sizeof(own) + 16], cb[1500];
	unsigned days = in_store ? p->cfg.store_keep_days : p->cfg.keep_days;
	int64_t expiry = 0;
	struct mms_raw r;
	size_t e;

	if (carbon_headers(p, ci, seq, cb, sizeof(cb)))
		return -1;
	snprintf(url, sizeof(url), "%s/sent/%s", p->base, ci->id);
	own[0] = 0;
	if (p->ops.own_number)
		p->ops.own_number(p->ops.ctx, own, sizeof(own));
	if (own[0] && !strpbrk(own, "\r\n/"))
		snprintf(from, sizeof(from), "%s/TYPE=PLMN", own);
	else
		own[0] = from[0] = 0;
	if (days && ci->time >= WALL_PLAUSIBLE)
		expiry = ci->time + (int64_t)days * 86400;
	m->len = mms_encode_notification(ci->id, MMS_VERSION_1_2, from[0] ? from : NULL, ci->subject[0] ? ci->subject : NULL,
					 (uint32_t)pdu_size, expiry, url, m->pdu, sizeof(m->pdu));
	if (!m->len)
		return -1;
	memset(&r, 0, sizeof(r));
	r.pdu = m->pdu;
	r.len = m->len;
	snprintf(r.from, sizeof(r.from), "%s", own);
	snprintf(r.tid, sizeof(r.tid), "%s", ci->id);
	snprintf(r.proxy, sizeof(r.proxy), "%s", p->base);
	r.max_size = p->cfg.max_size;
	r.ts = ci->time;
	r.seq = seq;
	e = mms_lan_raw_headers(&r, m->extra, sizeof(m->extra));
	if (!e || e + strlen(cb) >= sizeof(m->extra))
		return -1;
	memcpy(m->extra + e, cb, strlen(cb) + 1);
	return 0;
}

static void carbon_user(struct mmsproxy *p, char *user, size_t n)
{
	user[0] = 0;
	if (p->ops.own_number)
		p->ops.own_number(p->ops.ctx, user, n);
	if (!user[0])
		snprintf(user, n, "imsd");
}

/* live delivery to the carbon devices except the sender (no store, or it did not take the copy) */
static void carbon_send(struct mmsproxy *p, const struct mms_carbon_item *ci, const struct addr *client, size_t pdu_len)
{
	struct lan_seq_cfg c;
	reg_id_t ids[LAN_SELECT_MAX];
	char user[96];
	struct carbon_msg *m;
	unsigned n;

	if (!p->cfg.carbons || !p->lan || !p->base[0])
		return;
	n = carbon_targets(p, client, ids, LAN_SELECT_MAX);
	if (!n)
		return;
	carbon_user(p, user, sizeof(user));
	m = malloc(sizeof(*m));
	if (!m)
		return;
	if (carbon_build(p, ci, 0, false, pdu_len, m)) {
		free(m);
		return;		/* cannot happen with these sizes */
	}
	memset(&c, 0, sizeof(c));
	c.from_user = user;
	c.extra = m->extra;
	c.content_type = MMS_CT;
	c.body = m->pdu;
	c.body_len = m->len;
	c.include = ids;
	c.ninclude = n;
	c.include_set = true;
	c.done = carbon_done;
	c.arg = p;
	if (lan_seq_start(p->seqs, &c))
		p->st.carbons_failed++;
	free(m);
}

/* the store hands over a carbon item for one binding */
static int carbon_st_deliver(void *ctx, const struct store_item *it, reg_id_t b, uint32_t features, void (*done)(void *, int), void *arg)
{
	struct mmsproxy *p = ctx;
	struct mms_carbon_item *ci = malloc(sizeof(*ci));
	struct carbon_msg *m = malloc(sizeof(*m));
	struct lan_seq_cfg c;
	char user[96];
	int rc;

	(void)features;
	if (!ci || !m) {
		free(ci);
		free(m);
		return -ENOMEM;
	}
	if (mmsc_parse(it->meta, it->meta_len, ci)) {
		LOGW("mmsproxy: stored carbon item %llu is not readable, skipped", (unsigned long long)it->seq);
		free(ci);
		free(m);
		return 1;
	}
	if (!it->body_len || !p->lan || !p->base[0] ||
	    carbon_build(p, ci, it->seq, true, it->body_len, m)) {
		free(ci);
		free(m);
		return -ENOENT;
	}
	carbon_user(p, user, sizeof(user));
	memset(&c, 0, sizeof(c));
	c.from_user = user;
	c.extra = m->extra;
	c.content_type = MMS_CT;
	c.body = m->pdu;
	c.body_len = m->len;
	c.include = &b;
	c.ninclude = 1;
	c.include_set = true;
	c.done = done;
	c.arg = arg;
	rc = lan_seq_start(p->seqs, &c);
	free(ci);
	free(m);
	return rc;
}

static bool carbon_st_needs_body(void *ctx, uint8_t type, uint32_t features, bool has_body)
{
	(void)ctx;
	(void)type;
	(void)features;
	(void)has_body;
	return true;
}

static void carbon_st_abort(void *ctx, void *arg)
{
	struct mmsproxy *p = ctx;

	lan_seqs_abort(p->seqs, arg);
}

static void carbon_store_cb(void *arg, int status, uint64_t seq, const struct store_add *a)
{
	struct mmsproxy *p = arg;

	(void)seq;
	(void)a;
	if (status == 0)
		p->st.carbons_stored++;
	else
		LOGW("mmsproxy: the carbon copy of a sent message could not be stored (%s): not delivered to the devices", strerror(-status));
}

/* ------------------------------------------------------------------ */
/* answering the connections that wait for a relay                     */

static void wait_add(struct httpd_conn **w, unsigned *n, struct httpd_conn *c)
{
	w[(*n)++] = c;
}

static void wait_del(struct httpd_conn **w, unsigned *n, struct httpd_conn *c)
{
	unsigned i;

	for (i = 0; i < *n; i++)
		if (w[i] == c) {
			w[i] = w[--*n];
			return;
		}
}

static void answer_all(struct httpd_conn **w, unsigned *n, int status, const char *ctype, const void *body, size_t len)
{
	unsigned i, k = *n;
	struct httpd_conn *c[WAIT_MAX];

	memcpy(c, w, k * sizeof(c[0]));
	*n = 0;
	for (i = 0; i < k; i++)
		httpd_respond(c[i], status, ctype && ctype[0] && clean_ct(ctype) ? ctype : NULL, NULL, body, len, false);
}

static void answer_all_text(struct httpd_conn **w, unsigned *n, int status, const char *text)
{
	char b[320];
	int l = snprintf(b, sizeof(b), "%s\n", text);

	answer_all(w, n, status, "text/plain; charset=utf-8", b, l > 0 ? (size_t)l : 0);
}

static int err_status(int err)
{
	return err == HTTP_E_TIMEOUT ? 504 : 502;
}

static void err_text(int err, char *out, size_t n)
{
	snprintf(out, n, "the MMSC could not be reached: %s", http_strerror(err));
}

/* ------------------------------------------------------------------ */
/* sends                                                               */

static void send_free(struct sendent *s)
{
	struct mmsproxy *p = s->p;

	free(s->pdu);
	free(s->body);
	memset(s, 0, sizeof(*s));
	s->p = p;
}

static struct sendent *send_find(struct mmsproxy *p, const char *tid)
{
	unsigned i;
	uint64_t now = ev_now_ms();

	for (i = 0; i < SEND_TAB; i++) {
		struct sendent *s = &p->send[i];

		if (s->used && !s->running && now - s->at >= SEND_TTL_MS)
			send_free(s);
		if (s->used && tid[0] && !strcmp(s->tid, tid))
			return s;
	}
	return NULL;
}

static struct sendent *send_alloc(struct mmsproxy *p)
{
	unsigned i;
	struct sendent *old = NULL;

	for (i = 0; i < SEND_TAB; i++)
		if (!p->send[i].used)
			return &p->send[i];
	for (i = 0; i < SEND_TAB; i++)	/* the oldest finished one goes */
		if (!p->send[i].running && (!old || p->send[i].at < old->at))
			old = &p->send[i];
	if (old)
		send_free(old);
	return old;
}

/* The operator accepted the message: keep the PDU for the devices that want a copy and tell them */
static void send_accepted(struct mmsproxy *p, struct sendent *s, const struct mms_head *conf)
{
	struct mms_head *rq;
	struct mms_carbon_item *ci;
	struct mmsstore_file f;
	reg_id_t ids[LAN_SELECT_MAX];
	char dir[33];
	bool st = p->ops.store && store_usable(p->ops.store);

	if (!p->cfg.carbons)
		return;
	if (!st && (!p->lan || !p->base[0] || !carbon_targets(p, &s->client, ids, LAN_SELECT_MAX)))
		return;
	rq = malloc(sizeof(*rq));
	ci = malloc(sizeof(*ci));
	if (!rq || !ci || mms_decode_head(s->pdu, s->len, rq)) {
		free(rq);
		free(ci);
		return;
	}
	if (st) {
		/* into the store: delivered to the carbon devices that are there, and to those that register later; the sender (every device behind
		 * the client's address) is excluded by identity, so also on every redelivery */
		uint8_t meta[1600];
		struct store_add a;
		uint64_t ex[SIO_EXCL_MAX];
		unsigned nex = 0;
		size_t n;
		char id[33];

		rnd_token(id, 32);
		carbon_fill(p, rq, conf, id, ci);
		n = mmsc_pack(ci, meta, sizeof(meta));
		if (p->lan) {
			struct registrar *r = lan_registrar(p->lan);
			const struct reg_binding *b;
			reg_id_t bid = REG_ID_NONE;

			while (nex < SIO_EXCL_MAX && (b = reg_next(r, bid))) {
				char ident[96];

				bid = b->id;
				if (addr_equal_ip(&b->src, &s->client)) {
					store_identity(b, ident, sizeof(ident));
					ex[nex++] = store_hash(ident);
				}
			}
		}
		memset(&a, 0, sizeof(a));
		a.type = STORE_CARBON_MMS;
		a.time = ci->time;
		a.peer = rq->n_rcpt[0] ? rq->rcpt[0][0] : "";
		a.lookup = store_hash(id);
		a.excl = ex;
		a.nexcl = nex;
		a.meta = meta;
		a.meta_len = n;
		a.body = s->pdu;
		a.body_len = s->len;
		a.owner = p;
		if (n && !store_add(p->ops.store, &a, carbon_store_cb, p, NULL)) {
			free(rq);
			free(ci);
			return;
		}
		LOGW("mmsproxy: cannot store the carbon copy, delivering live");
	}
	if (!p->lan || !p->base[0] || !carbon_targets(p, &s->client, ids, LAN_SELECT_MAX)) {
		free(rq);
		free(ci);
		return;
	}
	memset(&f, 0, sizeof(f));
	f.name = SENT_FILE;
	f.type = MMS_CT;
	f.data = s->pdu;
	f.len = s->len;
	if (mmsstore_save(p->store, &f, 1, dir) || !f.ok) {
		LOGW("mmsproxy: cannot keep the sent message for the carbon copies");
		p->st.carbons_failed++;
		free(rq);
		free(ci);
		return;
	}
	carbon_fill(p, rq, conf, dir, ci);
	carbon_send(p, ci, &s->client, s->len);
	free(rq);
	free(ci);
}

static void on_send_done(void *arg, int err, const struct http_resp *r)
{
	struct sendent *s = arg;
	struct mmsproxy *p = s->p;

	s->req = NULL;
	s->running = false;
	relay_dec(p);
	if (err) {
		char t[120];

		p->st.send_failures++;
		err_text(err, t, sizeof(t));
		LOGI("mmsproxy: send relay failed: %s", http_strerror(err));
		answer_all_text(s->wait, &s->nwait, err_status(err), t);
		send_free(s);		/* not remembered: the device may try again */
		return;
	}
	p->st.relayed_sends++;
	answer_all(s->wait, &s->nwait, r->status, r->content_type, r->body, r->len);
	if (r->status != 200) {
		p->st.send_failures++;
		LOGI("mmsproxy: the MMSC answered the send with HTTP %d", r->status);
		send_free(s);
		return;
	}
	{
		struct mms_head *conf = malloc(sizeof(*conf));

		if (conf && !mms_decode_head(r->body, r->len, conf) && conf->type == MMS_T_SEND_CONF) {
			LOGI("mmsproxy: send answered by the MMSC, response status 0x%02x", conf->response_status >= 0 ? conf->response_status : 0);
			if (conf->response_status == 0x80)
				send_accepted(p, s, conf);
		}
		free(conf);
	}
	free(s->pdu);
	s->pdu = NULL;
	if (s->tid[0] && r->len <= SEND_KEEP_MAX) {	/* a repeat of this send gets this answer */
		s->body = malloc(r->len + 1);
		if (s->body) {
			memcpy(s->body, r->body, r->len);
			s->blen = r->len;
			s->status = r->status;
			snprintf(s->ctype, sizeof(s->ctype), "%s", r->content_type);
			s->kept = true;
			s->at = ev_now_ms();
			return;
		}
	}
	send_free(s);
}

/* "http://host:port" of a URL, for comparing the origin of two URLs */
static size_t url_origin_len(const char *u)
{
	const char *e = strstr(u, "://");

	if (!e)
		return strlen(u);
	e += 3;
	return (size_t)(e + strcspn(e, "/?#") - u);
}

static void send_start(struct mmsproxy *p, struct sendent *s)
{
	struct mms_upstream u;
	struct http_opts o;

	mms_upstream(p->mms, &u);
	memset(&o, 0, sizeof(o));
	o.method = "POST";
	o.url = u.mmsc;
	o.headers = u.post_headers;
	o.proxy_host = u.proxy_host;
	o.proxy_port = u.proxy_port;
	o.body = s->pdu;
	o.body_len = s->len;
	o.max_body = SEND_CONF_MAX;
	o.timeout_ms = SEND_TIMEOUT_MS;
	o.idle_ms = SEND_IDLE_MS;
	LOGI("mmsproxy: relaying a message of %zu bytes to the MMSC", s->len);
	s->req = http_request(mms_http(p->mms), &u.bind, &o, on_send_done, s);
	if (!s->req) {
		relay_dec(p);
		answer_all_text(s->wait, &s->nwait, 502, "cannot start the request to the MMSC");
		send_free(s);
	}
}

/* the on-demand data connection came up (or did not) for a send that waited for it */
static void send_link(void *arg, bool up)
{
	struct sendent *s = arg;
	struct mmsproxy *p = s->p;

	s->await_link = false;
	if (!up) {
		struct mms_upstream u;

		mms_upstream(p->mms, &u);
		relay_dec(p);
		p->st.send_failures++;
		answer_all_text(s->wait, &s->nwait, 503, u.down_text);
		send_free(s);
		return;
	}
	send_start(p, s);
}

static void handle_send(struct mmsproxy *p, struct httpd_conn *c, const struct httpd_req *rq, const struct mms_head *h, const char *uri)
{
	struct mms_upstream u;
	struct sendent *s;
	uint64_t hash = fnv(rq->body, rq->body_len);
	bool wait = false;

	if (h->has_tid && (s = send_find(p, h->tid))) {
		if (s->hash != hash || s->len != rq->body_len) {
			reply_text(c, 409, "this transaction id was used for another message", NULL);
			return;
		}
		if (s->running) {
			if (s->nwait >= WAIT_MAX) {
				reply_text(c, 503, "busy", "Retry-After: 2\r\n");
				return;
			}
			wait_add(s->wait, &s->nwait, c);
			return;
		}
		if (s->kept) {
			p->st.send_repeats++;
			httpd_respond(c, s->status, s->ctype[0] && clean_ct(s->ctype) ? s->ctype : NULL, NULL, s->body, s->blen, false);
			return;
		}
	}
	mms_upstream(p->mms, &u);
	if (!u.link_up) {
		if (!u.can_wait) {
			reply_text(c, 503, u.down_text, "Retry-After: 5\r\n");
			return;
		}
		wait = true;		/* on demand: the bearer is being brought up for this send */
	}
	if (!u.mmsc[0]) {
		reply_text(c, 503, "no MMSC is known for this operator", NULL);
		return;
	}
	if (uri) {		/* a standard proxy request: the PDU goes to the line's MMSC whatever the URI names */
		size_t ul = url_origin_len(uri);

		if (ul != url_origin_len(u.mmsc) || strncasecmp(uri, u.mmsc, ul))
			LOGD("mmsproxy: a proxied POST names another host than the MMSC, relayed to the MMSC");
	}
	if (p->relays >= RELAYS_MAX) {
		reply_text(c, 503, "too many messages in flight", "Retry-After: 2\r\n");
		return;
	}
	s = send_alloc(p);
	if (!s) {
		reply_text(c, 503, "busy", "Retry-After: 2\r\n");
		return;
	}
	s->used = true;
	s->running = true;
	snprintf(s->tid, sizeof(s->tid), "%s", h->has_tid ? h->tid : "");
	s->hash = hash;
	s->len = rq->body_len;
	s->at = ev_now_ms();
	s->client = *httpd_peer(c);
	s->pdu = malloc(rq->body_len + 1);
	if (!s->pdu) {
		send_free(s);
		reply_text(c, 503, "out of memory", NULL);
		return;
	}
	memcpy(s->pdu, rq->body, rq->body_len);
	relay_inc(p);
	wait_add(s->wait, &s->nwait, c);
	if (wait) {
		s->await_link = true;
		if (mms_link_wait(p->mms, send_link, s) < 0)
			send_link(s, false);
		return;
	}
	send_start(p, s);
}

/* ------------------------------------------------------------------ */
/* fetches and the cache                                               */

static void fetch_drop(struct mmsproxy *p, struct fetch *f)
{
	if (f->cached)
		mmsstore_remove(p->store, f->dir);
	memset(f, 0, sizeof(*f));
	f->p = p;
}

static struct fetch *fetch_find(struct mmsproxy *p, const char *url)
{
	unsigned i;
	uint64_t now = ev_now_ms();

	for (i = 0; i < FETCH_TAB; i++) {
		struct fetch *f = &p->fetch[i];

		if (f->used && f->cached && now >= f->expire)
			fetch_drop(p, f);
		if (f->used && !strcmp(f->url, url))
			return f;
	}
	return NULL;
}

static struct fetch *fetch_alloc(struct mmsproxy *p)
{
	unsigned i;
	struct fetch *old = NULL;

	for (i = 0; i < FETCH_TAB; i++)
		if (!p->fetch[i].used)
			return &p->fetch[i];
	for (i = 0; i < FETCH_TAB; i++)
		if (!p->fetch[i].running && (!old || p->fetch[i].expire < old->expire))
			old = &p->fetch[i];
	if (old)
		fetch_drop(p, old);
	return old;
}

static void on_fetch_done(void *arg, int err, const struct http_resp *r)
{
	struct fetch *f = arg;
	struct mmsproxy *p = f->p;

	f->req = NULL;
	f->running = false;
	relay_dec(p);
	p->st.fetches++;
	if (err) {
		char t[120];

		p->st.fetch_failures++;
		err_text(err, t, sizeof(t));
		LOGI("mmsproxy: fetch failed: %s", http_strerror(err));
		answer_all_text(f->wait, &f->nwait, err_status(err), t);
		fetch_drop(p, f);
		return;
	}
	answer_all(f->wait, &f->nwait, r->status, r->content_type, r->body, r->len);
	if (r->status != 200) {
		p->st.fetch_failures++;
		LOGI("mmsproxy: the MMSC answered the fetch with HTTP %d", r->status);
		fetch_drop(p, f);
		return;
	}
	mms_proxy_fetched(p->mms, f->url, r->body, r->len);	/* the first fetch of a message: the confirmation to the MMSC */
	if (p->cfg.cache_s) {
		struct mmsstore_file sf;

		memset(&sf, 0, sizeof(sf));
		sf.name = FETCH_FILE;
		sf.type = MMS_CT;
		sf.data = r->body;
		sf.len = r->len;
		if (!mmsstore_save(p->store, &sf, 1, f->dir) && sf.ok) {
			f->cached = true;
			f->expire = ev_now_ms() + (uint64_t)p->cfg.cache_s * 1000;
			snprintf(f->ctype, sizeof(f->ctype), "%s", r->content_type);
			return;
		}
		LOGW("mmsproxy: cannot cache the fetched message");
	}
	fetch_drop(p, f);
}

/* ---- answers from the store (asynchronous: the file layer reads in its own thread) ---- */

static void fetch_upstream(struct mmsproxy *p, struct httpd_conn *c, const char *url_in);

static void sreq_free(struct sreq *r)
{
	if (r->used && r->token)
		store_read_cancel(r->p->ops.store, r->token);
	memset(r, 0, sizeof(*r));
}

/* the store answered (or could not): a hit is the stored message, else the old way (the MMSC for a fetch, the tmpfs copy for a sent message) */
static void sreq_done(void *arg, int err, const struct store_item *it)
{
	struct sreq *r = arg;
	struct mmsproxy *p = r->p;
	struct httpd_conn *c = r->c;
	enum sreq_kind kind = r->kind;
	char key[MMS_URL_MAX];
	bool ok = false;

	snprintf(key, sizeof(key), "%s", r->key);
	memset(r, 0, sizeof(*r));		/* the read is over: nothing to cancel any more */
	if (!err && it && it->body && it->body_len) {
		if (kind == SR_FETCH && it->type == STORE_MMS) {
			struct mms_item *mi = malloc(sizeof(*mi));

			ok = mi && !mmsi_parse(it->meta, it->meta_len, mi) && (mi->flags & MMSI_HAS_BODY) && !strcmp(mi->location, key);
			free(mi);
		} else if (kind == SR_SENT && it->type == STORE_CARBON_MMS) {
			struct mms_carbon_item *ci = malloc(sizeof(*ci));

			ok = ci && !mmsc_parse(it->meta, it->meta_len, ci) && !strcmp(ci->id, key);
			free(ci);
		}
		if (ok) {
			p->st.store_hits++;
			httpd_respond(c, 200, MMS_CT, NULL, it->body, it->body_len, false);
			return;
		}
	}
	if (kind == SR_FETCH)
		fetch_upstream(p, c, key);		/* not (or no longer) in the store, or the retrieval failed: as without a store */
	else
		reply_text(c, 404, "no such message (never kept, or no longer)", NULL);
}

/* is key (a Content-Location / the id of a carbon copy) an item of the message store? true: the read is under way, the answer follows */
static bool store_lookup(struct mmsproxy *p, struct httpd_conn *c, enum sreq_kind kind, const char *key)
{
	struct sreq *r = NULL;
	uint64_t seq;
	unsigned i;

	if (!p->ops.store || !store_usable(p->ops.store))
		return false;
	if (store_find_lookup(p->ops.store, kind == SR_FETCH ? STORE_MMS : STORE_CARBON_MMS, store_hash(key), &seq))
		return false;
	for (i = 0; i < WAIT_MAX && !r; i++)
		if (!p->sreq[i].used)
			r = &p->sreq[i];
	if (!r)
		return false;
	memset(r, 0, sizeof(*r));
	r->used = true;
	r->kind = kind;
	r->p = p;
	r->c = c;
	snprintf(r->key, sizeof(r->key), "%s", key);
	if (store_read(p->ops.store, seq, true, sreq_done, r, &r->token)) {
		memset(r, 0, sizeof(*r));
		return false;
	}
	return true;
}

/* the common entry of GET /mms/fetch?url= and of a proxied GET: the URL is checked, then the store, then the allow-list and the MMSC */
static void fetch_url(struct mmsproxy *p, struct httpd_conn *c, const char *url)
{
	struct http_url hu;

	if (strlen(url) >= MMS_URL_MAX) {
		reply_text(c, 400, "the URL is too long", NULL);
		return;
	}
	if (!clean_ct(url) || strchr(url, ' ') || http_parse_url(url, &hu) || hu.https) {	/* no control characters / blanks: nothing to inject into the request */
		reply_text(c, 400, "only plain http:// URLs can be fetched", NULL);
		return;
	}
	if (store_lookup(p, c, SR_FETCH, url))
		return;
	fetch_upstream(p, c, url);
}

static void handle_fetch(struct mmsproxy *p, struct httpd_conn *c, const struct httpd_req *rq)
{
	char url[MMS_URL_MAX];

	if (mmsproxy_query_get(rq->query, "url", url, sizeof(url)) || !url[0]) {
		reply_text(c, 400, "url= is missing or not a percent-encoded URL", NULL);
		return;
	}
	fetch_url(p, c, url);
}


static void fetch_start(struct mmsproxy *p, struct fetch *f)
{
	struct mms_upstream u;
	struct http_opts o;

	mms_upstream(p->mms, &u);
	memset(&o, 0, sizeof(o));
	o.method = "GET";
	o.url = f->url;
	o.headers = u.get_headers;
	o.proxy_host = u.proxy_host;
	o.proxy_port = u.proxy_port;
	o.max_body = p->cfg.max_size;
	o.timeout_ms = FETCH_TIMEOUT_MS;
	o.idle_ms = FETCH_IDLE_MS;
	LOGI("mmsproxy: fetching a message for a device");
	f->req = http_request(mms_http(p->mms), &u.bind, &o, on_fetch_done, f);
	if (!f->req) {
		relay_dec(p);
		answer_all_text(f->wait, &f->nwait, 502, "cannot start the request to the MMSC");
		fetch_drop(p, f);
	}
}

static void fetch_link(void *arg, bool up)
{
	struct fetch *f = arg;
	struct mmsproxy *p = f->p;

	f->await_link = false;
	if (!up) {
		struct mms_upstream u;

		mms_upstream(p->mms, &u);
		relay_dec(p);
		p->st.fetch_failures++;
		answer_all_text(f->wait, &f->nwait, 503, u.down_text);
		fetch_drop(p, f);
		return;
	}
	fetch_start(p, f);
}

static void fetch_upstream(struct mmsproxy *p, struct httpd_conn *c, const char *url_in)
{
	char url[MMS_URL_MAX];
	struct mms_upstream u;
	struct fetch *f;
	bool wait = false;

	snprintf(url, sizeof(url), "%s", url_in);
	if (!mms_url_allowed(p->mms, url)) {
		p->st.denied++;
		LOGI("mmsproxy: fetch of a URL that was not announced to this gateway refused");
		reply_text(c, 403, "this URL was not announced by a notification (and is not on the MMSC's host)", NULL);
		return;
	}
	f = fetch_find(p, url);
	if (f && f->cached) {
		uint8_t *buf;
		size_t len;

		if (!mmsstore_read(p->store, f->dir, FETCH_FILE, p->cfg.max_size + 4096u, &buf, &len)) {
			p->st.cache_hits++;
			httpd_respond(c, 200, f->ctype[0] && clean_ct(f->ctype) ? f->ctype : NULL, NULL, buf, len, true);
			return;
		}
		fetch_drop(p, f);		/* evicted from the store */
		f = NULL;
	}
	if (f && f->running) {
		if (f->nwait >= WAIT_MAX) {
			reply_text(c, 503, "busy", "Retry-After: 2\r\n");
			return;
		}
		p->st.cache_hits++;
		wait_add(f->wait, &f->nwait, c);
		return;
	}
	mms_upstream(p->mms, &u);
	if (!u.link_up) {
		if (!u.can_wait) {
			reply_text(c, 503, u.down_text, "Retry-After: 5\r\n");
			return;
		}
		wait = true;
	}
	if (p->relays >= RELAYS_MAX) {
		reply_text(c, 503, "too many messages in flight", "Retry-After: 2\r\n");
		return;
	}
	f = fetch_alloc(p);
	if (!f) {
		reply_text(c, 503, "busy", "Retry-After: 2\r\n");
		return;
	}
	f->used = true;
	f->running = true;
	snprintf(f->url, sizeof(f->url), "%s", url);
	relay_inc(p);
	wait_add(f->wait, &f->nwait, c);
	if (wait) {
		f->await_link = true;
		if (mms_link_wait(p->mms, fetch_link, f) < 0)
			fetch_link(f, false);
		return;
	}
	fetch_start(p, f);
}

/* ------------------------------------------------------------------ */
/* the server                                                          */

static bool is_id(const char *s)
{
	size_t i;

	for (i = 0; i < 32; i++)
		if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i]))
			return false;
	return s[32] == 0;
}

enum route { R_NONE, R_ROOT, R_FETCH, R_SENT };

static enum route route_of(const char *path, const char **id)
{
	if (!strcmp(path, "/mms") || !strcmp(path, "/mms/"))
		return R_ROOT;
	if (!strcmp(path, "/mms/fetch"))
		return R_FETCH;
	if (!strncmp(path, "/mms/sent/", 10)) {
		*id = path + 10;
		return R_SENT;
	}
	return R_NONE;
}

/* a request of the standard proxy form: GET / POST with an absolute URI */
static bool is_proxied(const struct httpd_req *rq)
{
	return rq->path[0] != '/';
}

/* an absolute-URI request that names this gateway's own listener (a client that uses the gateway as its HTTP proxy asks it for the copy of a
 * sent message announced by its own URL): the id of /mms/sent/<id>, else NULL */
static const char *own_sent_id(const struct mmsproxy *p, const struct httpd_req *rq, char *idbuf, size_t n)
{
	struct http_url hu, bu;
	const char *id = NULL;

	if (!p->base[0] || http_parse_url(rq->target, &hu) || hu.https || http_parse_url(p->base, &bu))
		return NULL;
	if (strcasecmp(hu.host, bu.host) || hu.port != bu.port || route_of(hu.path, &id) != R_SENT || !is_id(id))
		return NULL;
	snprintf(idbuf, n, "%.32s", id);
	return idbuf;
}

static int on_head(void *ctx, const struct httpd_req *rq)
{
	struct mmsproxy *p = ctx;
	const char *id = NULL;
	bool post = !strcmp(rq->method, "POST");

	if (is_proxied(rq)) {
		if (strncasecmp(rq->target, "http://", 7))
			return 400;		/* https:// and other schemes: not tunnelled, not relayed */
		if (post && !ct_is(rq->content_type, MMS_CT)) {
			p->st.denied++;		/* a POST that is not an MMS PDU: not an operation of this proxy */
			return 403;
		}
		return 0;
	}
	switch (route_of(rq->path, &id)) {
	case R_ROOT:
		if (post && !ct_is(rq->content_type, MMS_CT))
			return 415;
		return 0;
	case R_FETCH:
		return post ? 405 : 0;
	case R_SENT:
		return post ? 405 : is_id(id) ? 0 : 404;
	default:
		return 404;
	}
}

static void handle_status(struct mmsproxy *p, struct httpd_conn *c)
{
	struct mms_upstream u;
	char b[HTTP_MAX_URL + 120], m[HTTP_MAX_URL + 4];
	bool known;
	size_t i;
	int n;

	mms_upstream(p->mms, &u);
	known = u.mmsc[0];
	for (i = 0; u.mmsc[i]; i++)		/* a URL that needs JSON escaping is not published */
		if ((unsigned char)u.mmsc[i] < 0x20 || u.mmsc[i] == '"' || u.mmsc[i] == '\\' || (unsigned char)u.mmsc[i] >= 0x7f)
			u.mmsc[0] = 0;
	if (u.mmsc[0])
		snprintf(m, sizeof(m), "\"%s\"", u.mmsc);
	else
		snprintf(m, sizeof(m), "null");
	n = snprintf(b, sizeof(b), "{\"proxy\":\"imsd\",\"mmsc_known\":%s,\"mmsc\":%s,\"max_size\":%u}\n",
		     known ? "true" : "false", m, p->cfg.max_size);
	httpd_respond(c, 200, "application/json", NULL, b, n > 0 && (size_t)n < sizeof(b) ? (size_t)n : 0, false);
}

static void handle_sent(struct mmsproxy *p, struct httpd_conn *c, const char *id)
{
	uint8_t *buf;
	size_t len;

	if (store_lookup(p, c, SR_SENT, id))
		return;

	if (mmsstore_read(p->store, id, SENT_FILE, p->cfg.max_size + 4096u, &buf, &len)) {
		reply_text(c, 404, "no such message (never kept, or no longer)", NULL);
		return;
	}
	httpd_respond(c, 200, MMS_CT, NULL, buf, len, true);
}

static void handle_post(struct mmsproxy *p, struct httpd_conn *c, const struct httpd_req *rq, const char *uri)
{
	struct mms_head *h = malloc(sizeof(*h));

	if (!h) {
		reply_text(c, 503, "out of memory", NULL);
		return;
	}
	if (!rq->body_len || mms_decode_head(rq->body, rq->body_len, h)) {
		reply_text(c, 400, "not an MMS PDU", NULL);
		free(h);
		return;
	}
	switch (h->type) {
	case MMS_T_SEND_REQ:
		if (!h->has_content_type) {
			reply_text(c, 400, "an M-Send.req without a body", NULL);
			break;
		}
		handle_send(p, c, rq, h, uri);
		break;
	case MMS_T_NOTIFYRESP_IND:
		/* imsd confirms to the MMSC itself, once; the device's own confirmation is only a trigger for a message it has not fetched
		 * through the proxy (and is never forwarded) */
		if (h->has_tid && h->status >= 0)
			mms_proxy_notify_resp(p->mms, h->tid, h->status);
		httpd_respond(c, 200, NULL, NULL, NULL, 0, false);
		break;
	case MMS_T_ACKNOWLEDGE_IND:
		httpd_respond(c, 200, NULL, NULL, NULL, 0, false);
		break;
	default:
		reply_text(c, 400, "this PDU type is not accepted here", NULL);
		break;
	}
	free(h);
}

static void on_request(void *ctx, struct httpd_conn *c, const struct httpd_req *rq)
{
	struct mmsproxy *p = ctx;
	const char *id = NULL;

	if (is_proxied(rq)) {		/* the same two operations as /mms/fetch and POST /mms, for a client that uses this as its HTTP proxy */
		if (!strcmp(rq->method, "POST"))
			handle_post(p, c, rq, rq->target);
		else if (!strcmp(rq->method, "GET")) {
			char sid[40];

			if (own_sent_id(p, rq, sid, sizeof(sid)))
				handle_sent(p, c, sid);
			else
				fetch_url(p, c, rq->target);
		}
		else
			reply_text(c, 403, "not an MMS operation", NULL);
		return;
	}
	switch (route_of(rq->path, &id)) {
	case R_ROOT:
		if (!strcmp(rq->method, "POST"))
			handle_post(p, c, rq, NULL);
		else
			handle_status(p, c);
		break;
	case R_FETCH:
		handle_fetch(p, c, rq);
		break;
	case R_SENT:
		handle_sent(p, c, id);
		break;
	default:
		reply_text(c, 404, "not found", NULL);
		break;
	}
}

static void on_gone(void *ctx, struct httpd_conn *c)
{
	struct mmsproxy *p = ctx;
	unsigned i;

	for (i = 0; i < SEND_TAB; i++)
		wait_del(p->send[i].wait, &p->send[i].nwait, c);
	for (i = 0; i < FETCH_TAB; i++)
		wait_del(p->fetch[i].wait, &p->fetch[i].nwait, c);
	for (i = 0; i < WAIT_MAX; i++)
		if (p->sreq[i].used && p->sreq[i].c == c)
			sreq_free(&p->sreq[i]);
}

/* ------------------------------------------------------------------ */
/* listener, configuration                                             */

static void hd_cfg(const struct mmsproxy *p, struct httpd_cfg *c)
{
	httpd_cfg_defaults(c);
	c->max_body = p->cfg.max_size;
	snprintf(c->extra_headers, sizeof(c->extra_headers), "X-MMS-Max-Size: %u\r\n", p->cfg.max_size);
}

static void store_cfg(const struct mmsproxy_cfg *c, struct mmsstore_cfg *o)
{
	memset(o, 0, sizeof(*o));
	snprintf(o->dir, sizeof(o->dir), "%s", c->dir);
	o->keep_messages = c->keep_messages;
	o->keep_bytes = c->keep_bytes;
	o->keep_days = c->keep_days;
}

static void listen_update(struct mmsproxy *p)
{
	struct addr a;
	char host[64];
	int rc;

	httpd_unlisten(p->hd);
	ev_timer_cancel(p->retry);
	p->base[0] = 0;
	p->error[0] = 0;
	if (!p->cfg.port)
		return;
	if (!p->have_laddr) {
		snprintf(p->error, sizeof(p->error), "the LAN side is down");
		return;
	}
	a = p->laddr;
	addr_set_port(&a, (uint16_t)p->cfg.port);
	rc = httpd_listen(p->hd, &a, p->cfg.ifname);
	if (rc) {
		snprintf(p->error, sizeof(p->error), "cannot listen on port %u: %s", p->cfg.port, strerror(-rc));
		LOGW("mmsproxy: %s, trying again in %u s", p->error, RETRY_MS / 1000);
		ev_timer_set(p->retry, RETRY_MS);
		return;
	}
	addr_uri_host(&a, host, sizeof(host));
	snprintf(p->base, sizeof(p->base), "http://%s:%u/mms", host, p->cfg.port);
	LOGI("mmsproxy: listening on %s", p->base);
}

static void on_retry(void *arg)
{
	listen_update(arg);
}

static void on_sweep(void *arg)
{
	struct mmsproxy *p = arg;
	unsigned i;
	uint64_t now = ev_now_ms();

	for (i = 0; i < FETCH_TAB; i++)
		if (p->fetch[i].used && p->fetch[i].cached && now >= p->fetch[i].expire)
			fetch_drop(p, &p->fetch[i]);
	for (i = 0; i < SEND_TAB; i++)
		if (p->send[i].used && !p->send[i].running && now - p->send[i].at >= SEND_TTL_MS)
			send_free(&p->send[i]);
	mmsstore_sweep(p->store);
	ev_timer_set(p->sweep, SWEEP_MS);
}

struct mmsproxy *mmsproxy_new(const struct mmsproxy_cfg *cfg, const struct mmsproxy_ops *ops, struct mms *mms)
{
	struct mmsproxy *p = calloc(1, sizeof(*p));
	struct httpd_cfg hc;
	struct httpd_ops ho;
	struct mmsstore_cfg sc;
	unsigned i;

	if (!p)
		return NULL;
	p->cfg = *cfg;
	p->ops = *ops;
	p->mms = mms;
	for (i = 0; i < SEND_TAB; i++)
		p->send[i].p = p;
	for (i = 0; i < FETCH_TAB; i++)
		p->fetch[i].p = p;
	hd_cfg(p, &hc);
	memset(&ho, 0, sizeof(ho));
	ho.on_head = on_head;
	ho.on_request = on_request;
	ho.on_gone = on_gone;
	p->hd = httpd_new(&hc, &ho, p);
	store_cfg(cfg, &sc);
	p->store = mmsstore_new(&sc, mmsstore_wall, p);
	p->seqs = lan_seqs_new();
	p->retry = ev_timer_new(on_retry, p);
	p->sweep = ev_timer_new(on_sweep, p);
	if (!p->hd || !p->store || !p->seqs || !p->retry || !p->sweep) {
		mmsproxy_free(p);
		return NULL;
	}
	ev_timer_set(p->sweep, SWEEP_MS);
	if (ops->store) {
		struct store_handler h;

		memset(&h, 0, sizeof(h));
		h.needs_body = carbon_st_needs_body;
		h.deliver = carbon_st_deliver;
		h.abort = carbon_st_abort;
		h.ctx = p;
		store_set_handler(ops->store, STORE_CARBON_MMS, &h);
	}
	return p;
}

void mmsproxy_free(struct mmsproxy *p)
{
	unsigned i;

	if (!p)
		return;
	if (p->ops.store) {
		unsigned k;

		store_set_handler(p->ops.store, STORE_CARBON_MMS, NULL);
		store_detach(p->ops.store, p);
		for (k = 0; k < WAIT_MAX; k++)
			sreq_free(&p->sreq[k]);
	}
	httpd_free(p->hd);		/* waiting requests are reported: they leave the lists */
	mms_link_wait_cancel(p->mms, NULL);	/* every waiter of the proxy */
	mms_work(p->mms, -(int)p->relays);	/* the relays below are cancelled */
	p->relays = 0;
	for (i = 0; i < SEND_TAB; i++) {
		http_cancel(p->send[i].req);
		free(p->send[i].pdu);
		free(p->send[i].body);
	}
	for (i = 0; i < FETCH_TAB; i++)
		http_cancel(p->fetch[i].req);
	lan_seqs_free(p->seqs);
	mmsstore_free(p->store);
	ev_timer_free(p->retry);
	ev_timer_free(p->sweep);
	free(p);
}

void mmsproxy_set_cfg(struct mmsproxy *p, const struct mmsproxy_cfg *cfg)
{
	struct httpd_cfg hc;
	struct mmsstore_cfg sc;
	bool relisten = cfg->port != p->cfg.port || strcmp(cfg->ifname, p->cfg.ifname);

	p->cfg = *cfg;
	hd_cfg(p, &hc);
	httpd_set_cfg(p->hd, &hc);
	store_cfg(cfg, &sc);
	mmsstore_set_cfg(p->store, &sc);
	if (relisten)
		listen_update(p);
}

void mmsproxy_set_lan(struct mmsproxy *p, struct lan *l, const struct addr *a)
{
	p->lan = l;
	lan_seqs_set(p->seqs, l);
	p->have_laddr = l && a;
	if (a)
		p->laddr = *a;
	listen_update(p);
}

bool mmsproxy_listening(const struct mmsproxy *p)
{
	return httpd_listening(p->hd);
}

const char *mmsproxy_base_url(const struct mmsproxy *p)
{
	return httpd_listening(p->hd) ? p->base : "";
}

void mmsproxy_get_status(const struct mmsproxy *p, struct mmsproxy_status *s)
{
	unsigned i;

	*s = p->st;
	s->listening = httpd_listening(p->hd);
	s->port = httpd_port(p->hd);
	if (s->listening)
		addr_host(&p->laddr, s->address, sizeof(s->address));
	s->conns = httpd_conns(p->hd);
	for (i = 0; i < FETCH_TAB; i++)
		s->cache_entries += p->fetch[i].used && p->fetch[i].cached;
	snprintf(s->error, sizeof(s->error), "%s", p->error);
}
