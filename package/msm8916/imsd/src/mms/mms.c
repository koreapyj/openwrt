/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * MMS reception manager, see mms.h.
 *
 * Specifications relied on: OMA-TS-MMS_ENC-V1_2 (PDU encoding: header fields 7.2/7.3), OMA-TS-MMS_CTR-V1_2 (transaction
 * flows: retrieval by HTTP GET of X-Mms-Content-Location, M-NotifyResp.ind and M-Acknowledge.ind by HTTP POST to the MMSC),
 * WAP-230-WSP (binary encoding, Push PDU), WAP-251-PushMessage (push over WDP port 2948).
 *
 * Failure policy of a retrieval (see on_get):
 *   transient  DNS / connect / timeout / connection loss / protocol error / HTTP 5xx, 408, 429
 *              -> retried after 5 s, 30 s and 2 min, while the message has not expired
 *   permanent  HTTP 4xx, other statuses, an unparseable answer, an https:// location, an m-retrieve-conf that carries an
 *              error status -> given up, nothing is sent to the MMSC
 *   too big    notification size or answer above mms_max_size -> M-NotifyResp.ind with status Rejected (0x82), the answer a
 *              handset gives for a message it refuses to download. Unrecognised (0x84) is for content the client cannot
 *              handle and is not used.
 * Not logged above debug level: subjects and texts of messages.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "mms.h"
#include "http.h"
#include "mmsstore.h"
#include "mmsitem.h"
#include "../carrier.h"
#include "../util/buf.h"
#include "../util/evloop.h"
#include "../ua/lan_text.h"
#include "../util/log.h"

#define RETRIES		3
#define DONE_RING	16
#define DONE_TTL_MS	(3600u * 1000)
#define SEEN_RING	32		/* content identities of delivered messages */
#define SEEN_TTL_MS	(24ull * 3600 * 1000)
#define BODY_TEXT_MAX	(16 * 1024)
#define GET_TIMEOUT_MS	90000u
#define GET_IDLE_MS	20000u
#define POST_TIMEOUT_MS	20000u
#define POST_IDLE_MS	10000u
#define LINK_WAITERS	8
#define LINK_WAIT_MS	50000u
#define ACCEPT_DEFAULT	"*/*, application/vnd.wap.mms-message, application/vnd.wap.sic"
#define URL_DIR		"imsd-mms"
#define WALL_PLAUSIBLE	1600000000	/* an earlier wall clock was not set yet: absolute expiry is ignored */
#define NOTIF_RING	32		/* notifications remembered for the proxy: allow-list of fetches, fetched state */
#define NOTIF_TTL_MS	(24ull * 3600 * 1000)	/* lifetime of a notification that names no expiry */
#define ACK_JOB_TTL_MS	(10u * 60 * 1000)

static const unsigned BACKOFF_MS[RETRIES] = { 5000, 30000, 120000 };

struct job {
	bool used;
	bool bench;
	char tid[MMS_ID_MAX];
	char url[MMS_URL_MAX];
	char from[MMS_ADDR_MAX];
	char subject[MMS_SUBJ_MAX];
	uint8_t version;
	bool has_size;
	uint32_t size;
	uint64_t expire_ms;		/* monotonic, 0 = none */
	int64_t expire_wall;		/* Unix time, 0 = none */
	unsigned attempt;
	uint64_t not_before;
	unsigned long seq;
	bool exclude_mms;		/* the text goes only to the devices without +g.imsd.mms */
	bool store;			/* store mode: the result goes into the store */
	int64_t arrive;			/* wall clock of the notification */
	uint8_t pdu[1024];		/* the original m-notification-ind (store mode) */
	size_t pdu_len;
	/* confirmation only (no retrieval): the MMSC is told that the message was retrieved by a device through the proxy */
	bool ack_only, send_ack;
	char ack_tid[MMS_ID_MAX];	/* transaction id of the m-retrieve-conf the device fetched, "" = none */
	uint8_t ack_version;
};

/* a notification seen: the MMS proxy may fetch its Content-Location while it lives */
struct notif {
	bool used;
	bool raw;			/* the original was passed to the devices with +g.imsd.mms */
	bool ack_on_fetch;		/* no text device: imsd confirms when the first proxied fetch completed */
	bool fetched, acked;
	char tid[MMS_ID_MAX];
	char url[MMS_URL_MAX];
	uint8_t version;
	uint64_t at, expire_ms;		/* monotonic; expire_ms 0: at + NOTIF_TTL_MS */
	int64_t expire_wall;
	uint64_t ident;			/* from, subject, size: the message as announced, whatever the transaction id */
	char ack_tid[MMS_ID_MAX];
};

enum phase { PH_IDLE, PH_GET, PH_POST };

static void store_message(struct mms *m, const struct job *j, const struct mms_retrieve *rv, const uint8_t *body, size_t blen,
			  uint64_t content_id);
static void store_failed_item(struct mms *m, const struct job *j, bool toobig);


struct mms {
	struct mms_cfg cfg;
	struct mms_ops ops;
	const struct net_ops *net;
	struct dns *dns;
	struct http *http;
	struct mmsstore *store;
	struct job q[MMS_QUEUE];
	unsigned long seq;
	struct job *cur;
	enum phase phase;
	struct http_req *req;
	struct ev_timer *timer;
	struct mms_link link;
	bool waiting_logged;
	/* the confirmations of the job being finished */
	uint8_t resp[2][96];
	size_t resp_len[2];
	const char *resp_name[2];
	int post_idx, n_post;
	struct { char tid[MMS_ID_MAX]; uint64_t at; } done[DONE_RING];
	unsigned done_next;
	struct { uint64_t id; uint64_t at; bool used; } seen[SEEN_RING];
	unsigned seen_next;
	struct notif nt[NOTIF_RING];
	unsigned nt_next;
	struct mms_status st;
	char derived_mmsc[160];
	char post_url[HTTP_MAX_URL];	/* of the request in flight */
	bool warned_no_mmsc;
	/* work that wants the on-demand data connection */
	int work;			/* relays of the proxy in flight */
	bool want_sent;
	struct { void (*cb)(void *arg, bool up); void *arg; uint64_t deadline; bool used; } lw[LINK_WAITERS];
	struct ev_timer *lw_timer;
};

void mms_cfg_defaults(struct mms_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->enable = true;
	c->max_size = 1024 * 1024;
	snprintf(c->dir, sizeof(c->dir), "/tmp/imsd-mms");
	c->keep_messages = 50;
	c->keep_bytes = 16 * 1024 * 1024;
	c->keep_days = 7;
	c->text_split = 1000;
}

static void set_err(struct mms *m, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void set_err(struct mms *m, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(m->st.last_error, sizeof(m->st.last_error), fmt, ap);
	va_end(ap);
}

static int64_t wall(const struct mms *m)
{
	return m->ops.wall ? m->ops.wall(m->ops.ctx) : (int64_t)time(NULL);
}

static int64_t mmsstore_wall(void *ctx)
{
	return wall(ctx);
}

static void store_cfg(const struct mms_cfg *c, struct mmsstore_cfg *o)
{
	memset(o, 0, sizeof(*o));
	snprintf(o->dir, sizeof(o->dir), "%s", c->dir);
	o->keep_messages = c->keep_messages;
	o->keep_bytes = c->keep_bytes;
	o->keep_days = c->keep_days;
}

static void pump(struct mms *m);
static void on_lw_timer(void *arg);

static void on_timer(void *arg)
{
	pump(arg);
}

static bool mms_st_needs_body(void *ctx, uint8_t type, uint32_t features, bool has_body);
static int mms_st_deliver(void *ctx, const struct store_item *si, reg_id_t b, uint32_t features, void (*done)(void *, int), void *arg);
static void mms_st_abort(void *ctx, void *arg);

struct mms *mms_new(const struct mms_cfg *cfg, const struct mms_ops *ops)
{
	struct mms *m = calloc(1, sizeof(*m));
	struct mmsstore_cfg sc;

	if (!m)
		return NULL;
	m->cfg = *cfg;
	m->ops = *ops;
	m->net = ops->net ? ops->net : net_real_ops();
	store_cfg(cfg, &sc);
	m->dns = dns_new(m->net);
	m->http = m->dns ? http_new(m->net, m->dns) : NULL;
	m->store = mmsstore_new(&sc, mmsstore_wall, m);
	m->timer = ev_timer_new(on_timer, m);
	m->lw_timer = ev_timer_new(on_lw_timer, m);
	if (!m->dns || !m->http || !m->store || !m->timer || !m->lw_timer) {
		mms_free(m);
		return NULL;
	}
	if (ops->link)
		ops->link(ops->ctx, &m->link);
	if (ops->store) {
		struct store_handler h;

		memset(&h, 0, sizeof(h));
		h.needs_body = mms_st_needs_body;
		h.deliver = mms_st_deliver;
		h.abort = mms_st_abort;
		h.ctx = m;
		store_set_handler(ops->store, STORE_MMS, &h);
	}
	return m;
}

void mms_free(struct mms *m)
{
	if (!m)
		return;
	if (m->ops.store) {
		store_set_handler(m->ops.store, STORE_MMS, NULL);
		store_detach(m->ops.store, m);
	}
	if (m->ops.deliver_abort)
		m->ops.deliver_abort(m->ops.ctx, m);
	ev_timer_free(m->timer);
	ev_timer_free(m->lw_timer);
	http_free(m->http);
	dns_free(m->dns);
	mmsstore_free(m->store);
	free(m);
}

void mms_set_cfg(struct mms *m, const struct mms_cfg *cfg)
{
	struct mmsstore_cfg sc;

	m->cfg = *cfg;
	store_cfg(cfg, &sc);
	mmsstore_set_cfg(m->store, &sc);
}

/* ------------------------------------------------------------------ */
/* queue                                                               */

static unsigned pending(const struct mms *m)
{
	unsigned i, n = 0;

	for (i = 0; i < MMS_QUEUE; i++)
		n += m->q[i].used;
	return n;
}

static bool recently_done(struct mms *m, const char *tid)
{
	unsigned i;
	uint64_t now = ev_now_ms();

	for (i = 0; i < DONE_RING; i++)
		if (m->done[i].tid[0] && now - m->done[i].at < DONE_TTL_MS && !strcmp(m->done[i].tid, tid))
			return true;
	return false;
}

static bool known_tid(struct mms *m, const char *tid)
{
	unsigned i;

	for (i = 0; i < MMS_QUEUE; i++)
		if (m->q[i].used && !m->q[i].bench && !strcmp(m->q[i].tid, tid))
			return true;
	return recently_done(m, tid);
}

/* ---- identity of a delivered message, independent of transaction id, message id and Content-Location ---- */

static uint64_t fnv(uint64_t h, const void *p, size_t n)
{
	const uint8_t *b = p;
	size_t i;

	for (i = 0; i < n; i++) {
		h ^= b[i];
		h *= 0x100000001b3ull;
	}
	return h;
}

/* length first, so that field boundaries matter */
static uint64_t fnv_field(uint64_t h, const void *p, size_t n)
{
	uint64_t l = n;

	return fnv(fnv(h, &l, sizeof(l)), p, n);
}

static uint64_t content_id(const struct mms_retrieve *rv, const struct job *j)
{
	uint64_t h = 0xcbf29ce484222325ull, v;
	const char *from = rv->from[0] ? rv->from : j->from;
	unsigned i;

	h = fnv_field(h, from, strlen(from));
	v = rv->has_date ? (uint64_t)rv->date : 0;
	h = fnv_field(h, &v, sizeof(v));
	h = fnv_field(h, rv->subject, strlen(rv->subject));
	v = rv->nparts;
	h = fnv_field(h, &v, sizeof(v));
	for (i = 0; i < rv->nparts; i++) {
		const struct mms_part *p = &rv->part[i];

		h = fnv_field(h, p->type, strlen(p->type));
		h = fnv_field(h, p->filename, strlen(p->filename));
		h = fnv_field(h, p->data, p->len);
	}
	return h;
}

/* minutes since the identity was delivered, or -1 when it is not in the ring (or older than 24 h) */
static int seen_age_min(const struct mms *m, uint64_t id)
{
	uint64_t now = ev_now_ms();
	unsigned i;

	for (i = 0; i < SEEN_RING; i++)
		if (m->seen[i].used && m->seen[i].id == id && now - m->seen[i].at < SEEN_TTL_MS)
			return (int)((now - m->seen[i].at) / 60000);
	return -1;
}

static void seen_add(struct mms *m, uint64_t id)
{
	unsigned i;

	for (i = 0; i < SEEN_RING; i++)		/* a repeat refreshes its entry */
		if (m->seen[i].used && m->seen[i].id == id) {
			m->seen[i].at = ev_now_ms();
			return;
		}
	m->seen[m->seen_next % SEEN_RING].id = id;
	m->seen[m->seen_next % SEEN_RING].at = ev_now_ms();
	m->seen[m->seen_next % SEEN_RING].used = true;
	m->seen_next++;
}

/* ---- notifications seen (the proxy's allow-list and fetched state) ---- */

static uint64_t notif_ident(const struct mms_notif *nf)
{
	uint64_t h = 0xcbf29ce484222325ull, v = nf->has_size ? nf->size : 0;

	h = fnv_field(h, nf->from, strlen(nf->from));
	h = fnv_field(h, nf->subject, strlen(nf->subject));
	return fnv_field(h, &v, sizeof(v));
}

static bool notif_live(const struct mms *m, const struct notif *n)
{
	uint64_t now = ev_now_ms();

	if (!n->used)
		return false;
	if (n->expire_ms)
		return now < n->expire_ms;
	if (n->expire_wall && wall(m) >= WALL_PLAUSIBLE)
		return wall(m) < n->expire_wall;
	return now - n->at < NOTIF_TTL_MS;
}

static struct notif *notif_find_tid(struct mms *m, const char *tid)
{
	unsigned i;

	for (i = 0; i < NOTIF_RING; i++)
		if (m->nt[i].raw && notif_live(m, &m->nt[i]) && !strcmp(m->nt[i].tid, tid))
			return &m->nt[i];
	return NULL;
}

static struct notif *notif_find_ident(struct mms *m, uint64_t ident)
{
	unsigned i;

	for (i = 0; i < NOTIF_RING; i++)
		if (m->nt[i].raw && m->nt[i].ident == ident && notif_live(m, &m->nt[i]))
			return &m->nt[i];
	return NULL;
}

static struct notif *notif_add(struct mms *m, const struct mms_notif *nf, uint64_t ident)
{
	struct notif *n = &m->nt[m->nt_next++ % NOTIF_RING];

	memset(n, 0, sizeof(*n));
	n->used = true;
	snprintf(n->tid, sizeof(n->tid), "%s", nf->tid);
	snprintf(n->url, sizeof(n->url), "%s", nf->location);
	n->version = nf->version;
	n->at = ev_now_ms();
	n->ident = ident;
	if (nf->has_expiry) {
		if (nf->expiry_relative)
			n->expire_ms = n->at + (uint64_t)(nf->expiry > 366 * 86400 ? 366 * 86400 : nf->expiry) * 1000;
		else
			n->expire_wall = nf->expiry;
	}
	return n;
}

static void job_done(struct mms *m, struct job *j)
{
	if (!j->bench && j->tid[0]) {
		snprintf(m->done[m->done_next % DONE_RING].tid, MMS_ID_MAX, "%s", j->tid);
		m->done[m->done_next % DONE_RING].at = ev_now_ms();
		m->done_next++;
	}
	memset(j, 0, sizeof(*j));
	m->cur = NULL;
	m->phase = PH_IDLE;
	ev_timer_set(m->timer, 0);		/* the next job, outside of this call chain */
}

static void job_fail(struct mms *m, struct job *j, const char *why)
{
	m->st.failed++;
	set_err(m, "%s: %s", j->bench ? "fetch" : "retrieval", why);
	LOGW("mms: giving up on message %s: %s", j->bench ? "(fetch)" : j->tid, why);
	if (j->store && !j->bench)
		store_failed_item(m, j, false);
	job_done(m, j);
}

static bool expired(struct mms *m, const struct job *j, uint64_t at_ms)
{
	if (j->expire_ms && at_ms >= j->expire_ms)
		return true;
	return j->expire_wall && wall(m) >= WALL_PLAUSIBLE && wall(m) >= j->expire_wall;
}

static void refresh_link(struct mms *m)
{
	memset(&m->link, 0, sizeof(m->link));
	if (m->ops.link)
		m->ops.link(m->ops.ctx, &m->link);
}

static void make_bind(const struct mms *m, struct dns_bind *b)
{
	int i;

	memset(b, 0, sizeof(*b));
	b->local = m->link.local;
	snprintf(b->netdev, sizeof(b->netdev), "%s", m->link.netdev);
	for (i = 0; i < m->link.n_dns && i < DNS_MAX_SERVERS; i++)
		b->server[b->n_server++] = m->link.dns[i];
	if (m->link.on_demand && m->ops.gate) {		/* the traffic guard of the on-demand bearer: every TCP destination is let through first */
		b->gate = m->ops.gate;
		b->gate_cancel = m->ops.gate_cancel;
		b->gate_ctx = m->ops.ctx;
	}
}

/* ------------------------------------------------------------------ */
/* POST of M-NotifyResp.ind / M-Acknowledge.ind                         */

/* scheme://host:port/ of a URL */
static int origin_of(const char *url, char *out, size_t n)
{
	struct http_url u;
	bool v6;

	if (http_parse_url(url, &u) && !u.https)
		return -1;
	if (u.https)
		return -1;
	v6 = strchr(u.host, ':') != NULL;
	snprintf(out, n, u.port == 80 ? (v6 ? "http://[%s]/" : "http://%s/") : (v6 ? "http://[%s]:%u/" : "http://%s:%u/"), u.host,
		 u.port);
	return 0;
}

/* The operator's MMS values: uci overrides, else the table entry matched by the SIM's MCC/MNC, then by the registered network (carrier.h).
 * The SIM's own files are never consulted. */
static void profile(const struct mms *m, struct carrier_mms *o)
{
	struct carrier_mms_cfg c;

	c.mmsc = m->cfg.mmsc;
	c.apn = m->cfg.mms_apn;
	c.ip_type = m->cfg.mms_ip_type;
	c.proxy = m->cfg.mms_proxy;
	c.user_agent = m->cfg.mms_user_agent;
	c.accept = m->cfg.mms_accept;
	carrier_resolve_mms(&c, m->ops.imsi ? m->ops.imsi(m->ops.ctx) : NULL, m->ops.net_plmn ? m->ops.net_plmn(m->ops.ctx) : NULL, o);
}

static void resolve_mmsc(const struct mms *m, struct carrier_val *v)
{
	struct carrier_mms p;

	profile(m, &p);
	snprintf(v->value, sizeof(v->value), "%s", p.mmsc);
	v->source = p.mmsc_source;
}

/* Accept, User-Agent, x-wap-profile (CRLF terminated lines); the operator entry's / uci's values win over the defaults */
static void build_headers(const struct mms *m, const struct carrier_mms *p, char *out, size_t n, bool post)
{
	snprintf(out, n, "Accept: %s\r\nUser-Agent: %s\r\n%s%s%s%s", p->accept[0] ? p->accept : ACCEPT_DEFAULT,
		 p->user_agent[0] ? p->user_agent : m->cfg.user_agent, m->cfg.uaprof[0] ? "x-wap-profile: " : "", m->cfg.uaprof,
		 m->cfg.uaprof[0] ? "\r\n" : "", post ? "Content-Type: application/vnd.wap.mms-message\r\n" : "");
}

static void post_next(struct mms *m);

static void on_post(void *arg, int err, const struct http_resp *r)
{
	struct mms *m = arg;

	m->req = NULL;
	if (err) {
		m->st.ack_failed++;
		LOGI("mms: %s to the MMSC failed: %s", m->resp_name[m->post_idx], http_strerror(err));
	} else if (r->status / 100 == 2) {
		m->st.acked++;
		LOGI("mms: %s accepted by the MMSC (HTTP %d)", m->resp_name[m->post_idx], r->status);
	} else {
		m->st.ack_failed++;
		if (r->status == 404 || r->status == 405) {
			LOGW("mms: %s refused by %s with HTTP %d: the MMSC URL is wrong for this operator (set imsd.main.mmsc)",
			     m->resp_name[m->post_idx], m->post_url, r->status);
			set_err(m, "%s refused with HTTP %d: wrong MMSC URL", m->resp_name[m->post_idx], r->status);
		} else {
			LOGI("mms: %s answered HTTP %d by the MMSC", m->resp_name[m->post_idx], r->status);
		}
	}
	m->post_idx++;
	post_next(m);
}

static void post_next(struct mms *m)
{
	struct job *j = m->cur;
	char url[HTTP_MAX_URL], hdr[640];
	struct http_opts o;
	struct dns_bind b;
	struct carrier_val mv;
	struct carrier_mms cp;

	if (!j)
		return;
	if (m->post_idx >= m->n_post) {
		job_done(m, j);
		return;
	}
	resolve_mmsc(m, &mv);
	if (mv.value[0]) {
		snprintf(url, sizeof(url), "%s", mv.value);
	} else {
		if (!m->warned_no_mmsc) {
			m->warned_no_mmsc = true;
			LOGW("mms: the MMSC URL is unknown for this operator (not configured, not in the operator table): "
			     "the confirmations go to the server of the Content-Location, which may refuse them");
		}
		if (origin_of(j->url, url, sizeof(url))) {
			LOGI("mms: no MMSC URL for the %s (the Content-Location is not plain http)", m->resp_name[m->post_idx]);
			m->post_idx++;
			post_next(m);
			return;
		}
		snprintf(m->derived_mmsc, sizeof(m->derived_mmsc), "%.159s", url);
	}
	snprintf(m->post_url, sizeof(m->post_url), "%s", url);
	profile(m, &cp);
	build_headers(m, &cp, hdr, sizeof(hdr), true);
	memset(&o, 0, sizeof(o));
	o.method = "POST";
	o.url = url;
	o.headers = hdr;
	o.proxy_host = cp.proxy_host;
	o.proxy_port = cp.proxy_port;
	o.body = m->resp[m->post_idx];
	o.body_len = m->resp_len[m->post_idx];
	o.max_body = 64 * 1024;
	o.timeout_ms = POST_TIMEOUT_MS;
	o.idle_ms = POST_IDLE_MS;
	make_bind(m, &b);
	LOGI("mms: sending %s to the MMSC", m->resp_name[m->post_idx]);
	m->req = http_request(m->http, &b, &o, on_post, m);
	if (!m->req) {
		LOGI("mms: cannot start the %s (out of memory)", m->resp_name[m->post_idx]);
		m->post_idx++;
		post_next(m);
	}
}

static void start_posts(struct mms *m, struct job *j)
{
	m->phase = PH_POST;
	m->post_idx = 0;
	(void)j;
	post_next(m);
}

/* ------------------------------------------------------------------ */
/* delivery of a retrieved message                                     */

static void deliver_done(void *arg, int nok)
{
	struct mms *m = arg;

	if (nok > 0) {
		m->st.delivered++;
		LOGI("mms: message delivered to %d LAN client(s)", nok);
	} else {
		m->st.lost_no_client++;
		set_err(m, "message lost: no LAN client accepted it");
		LOGW("mms: LOST message: no LAN client accepted it");
	}
}

static bool is_attachment(const struct mms_part *p)
{
	return !mmsr_is_smil(p) && (!mmsr_is_text(p) || (p->disposition == 1 && p->filename[0]));
}

static void first_line(const char *s, char *out, size_t n)
{
	size_t l = strcspn(s, "\r\n");

	if (l >= n)
		l = n - 1;
	memcpy(out, s, l);
	out[l] = 0;
	while (l && (out[l - 1] == ' ' || out[l - 1] == '\t'))
		out[--l] = 0;
}

static const char *url_base(const struct mms *m, char *buf, size_t n)
{
	const char *h;

	if (m->cfg.url_base[0])
		return m->cfg.url_base;
	h = m->ops.lan_host ? m->ops.lan_host(m->ops.ctx) : "";
	if (h && h[0])
		snprintf(buf, n, "http://%s/" URL_DIR "/", h);
	else
		snprintf(buf, n, "/" URL_DIR "/");
	return buf;
}

/* retrieved: attachments to the store, text to the LAN. Returns the number of MESSAGE pieces (0 = nothing sent) */
/*
 * Render a retrieved message for the text devices and hand it to the LAN delivery. Live path (done == NULL): to every text device
 * (devices with +g.imsd.mms left out when j->exclude_mms), counted and logged as lost when nobody takes it. Store path (done set):
 * to ONE binding (target) with X-IMSD-Seq, the result is only returned: 0 started (done follows), else -errno.
 */
static int deliver_message(struct mms *m, const struct job *j, const struct mms_retrieve *rv, reg_id_t target, uint64_t seq,
			   void (*done)(void *arg, int nok), void *darg)
{
	int ret = 0;
	unsigned order[MMS_MAX_PARTS], n, i, nfile = 0;
	struct mmsstore_file files[MMS_MAX_PARTS];
	const struct mms_part *fp[MMS_MAX_PARTS];
	struct buf text, body;
	char dir[33], base[200], line1[MMS_SUBJ_MAX + 4], size[24];
	const char *subject;
	struct mms_out *out = NULL;
	struct lan_pieces lp;
	size_t blen;
	unsigned np;
	bool trunc, saved = false;
	int rc;

	memset(&lp, 0, sizeof(lp));
	n = mmsr_order(rv->part, rv->nparts, order);
	buf_init(&text, 64 * 1024);
	buf_init(&body, 64 * 1024);
	memset(files, 0, sizeof(files));
	for (i = 0; i < n; i++) {
		const struct mms_part *p = &rv->part[order[i]];

		if (is_attachment(p)) {
			files[nfile].name = p->filename[0] ? p->filename : p->location;
			files[nfile].type = p->type;
			files[nfile].idx = order[i] + 1;
			files[nfile].data = p->data;
			files[nfile].len = p->len;
			fp[nfile++] = p;
		} else if (mmsr_is_text(p)) {
			if (text.len && text.p[text.len - 1] != '\n')
				buf_putc(&text, '\n');
			mmsr_part_text(p, &text);
		}
	}
	if (nfile) {
		rc = mmsstore_save(m->store, files, nfile, dir);
		saved = rc == 0;
		if (rc)
			LOGW("mms: cannot store the attachments (%s)", strerror(-rc));
	}
	subject = rv->subject[0] ? rv->subject : j->subject;
	/* cut the text at the cap on a character boundary */
	if (text.len > BODY_TEXT_MAX) {
		size_t c = BODY_TEXT_MAX;

		while (c && ((unsigned char)text.p[c] & 0xc0) == 0x80)
			c--;
		text.len = c;
		text.p[c] = 0;
		buf_puts(&text, "\n[text truncated]");
	}
	/* the subject, unless the text starts with it */
	line1[0] = 0;
	if (subject[0]) {
		char fl[MMS_SUBJ_MAX + 4], bracket[MMS_SUBJ_MAX + 4];
		size_t sl = strlen(subject);
		bool wrapped = sl >= 2 && subject[0] == '[' && subject[sl - 1] == ']';

		first_line(buf_cstr(&text), fl, sizeof(fl));
		snprintf(bracket, sizeof(bracket), wrapped ? "%s" : "[%s]", subject);
		if (strcmp(fl, subject) && strcmp(fl, bracket))
			snprintf(line1, sizeof(line1), "%s", bracket);
	}
	if (line1[0]) {
		buf_puts(&body, line1);
		if (text.len)
			buf_putc(&body, '\n');
	}
	buf_add(&body, text.p, text.len);
	if (nfile) {
		char bb[200];
		const char *ub = url_base(m, bb, sizeof(bb));

		snprintf(base, sizeof(base), "%s", ub);
		if (body.len)
			buf_puts(&body, "\n\n");
		for (i = 0; i < nfile; i++) {
			mmsr_human_size(files[i].len, size, sizeof(size));
			if (i)
				buf_putc(&body, '\n');
			if (saved && files[i].ok) {
				buf_printf(&body, "%s (%s, %s) %s%s/%s", files[i].saved, fp[i]->type, size, base, dir, files[i].saved);
			} else {
				char nm[72];

				mmsstore_clean_name(files[i].name, files[i].type, files[i].idx, nm, sizeof(nm));
				buf_printf(&body, "%s (%s, %s) [not saved]", nm, fp[i]->type, size);
			}
		}
	}
	if (!body.len)
		buf_puts(&body, "(empty MMS)");
	blen = body.len;
	if (lan_pieces_make(&lp, buf_cstr(&body), blen, m->cfg.text_split)) {
		LOGW("mms: out of memory delivering a message");
		ret = -ENOMEM;
		goto done;
	}
	out = calloc(1, sizeof(*out));
	if (!out) {
		LOGW("mms: out of memory delivering a message");
		ret = -ENOMEM;
		goto done;
	}
	np = lp.n;
	trunc = lp.truncated;
	for (i = 0; i < np; i++)
		out->text[i] = lp.text[i];
	out->exclude_mms = j->exclude_mms;
	out->target = target;
	out->seq = seq;
	out->n = np;
	snprintf(out->from, sizeof(out->from), "%s", rv->from[0] ? rv->from : j->from);
	snprintf(out->subject, sizeof(out->subject), "%s", subject);
	snprintf(out->message_id, sizeof(out->message_id), "%s", rv->message_id[0] ? rv->message_id : rv->has_tid ? rv->tid : j->tid);
	out->has_ts = rv->has_date;
	out->ts = rv->date;
	LOGI("mms: message from %s: %u text piece(s), %u attachment(s)%s", out->from[0] ? out->from : "(unknown)", np, nfile,
	     trunc ? ", text truncated" : "");
	LOGD("mms: subject \"%s\"", subject);
	rc = m->ops.deliver ? m->ops.deliver(m->ops.ctx, out, done ? done : deliver_done, done ? darg : m) : -ENOENT;
	if (done) {
		ret = rc;
	} else if (rc == -ENOENT || rc == -ENOTCONN) {
		m->st.lost_no_client++;
		set_err(m, "message from %s lost: no LAN client registered", out->from);
		LOGW("mms: LOST message from %s (id %s, %zu bytes of text, %u attachment(s)): no LAN client is registered",
		     out->from, out->message_id, blen, nfile);
	} else if (rc) {
		m->st.lost_no_client++;
		set_err(m, "message from %s lost: delivery failed (%d)", out->from, rc);
		LOGW("mms: LOST message from %s (id %s): cannot deliver (%s)", out->from, out->message_id, strerror(-rc));
	}
done:
	free(out);
	lan_pieces_free(&lp);
	buf_free(&text);
	buf_free(&body);
	return ret;
}

/* ------------------------------------------------------------------ */
/* retrieval                                                           */

static void queue_resp(struct mms *m, const char *name, size_t len)
{
	m->resp_name[m->n_post] = name;
	m->resp_len[m->n_post] = len;
	m->n_post++;
}

static void prepare_notifyresp(struct mms *m, const struct job *j, unsigned status)
{
	size_t l = mms_encode_notifyresp(j->tid, j->version, status, m->resp[m->n_post], sizeof(m->resp[0]));

	if (l)
		queue_resp(m, "M-NotifyResp.ind", l);
}

static void job_retry(struct mms *m, struct job *j, const char *why)
{
	uint64_t now = ev_now_ms();

	if (j->attempt >= RETRIES) {
		job_fail(m, j, why);
		return;
	}
	j->not_before = now + BACKOFF_MS[j->attempt];
	j->attempt++;
	if (expired(m, j, j->not_before)) {
		job_fail(m, j, "expired before the next attempt");
		return;
	}
	LOGI("mms: retrieval of %s failed (%s), retry %u of %u in %u s", j->bench ? "(fetch)" : j->tid, why, j->attempt, RETRIES,
	     BACKOFF_MS[j->attempt - 1] / 1000);
	set_err(m, "retrieval: %s (retrying)", why);
	m->cur = NULL;
	m->phase = PH_IDLE;
	ev_timer_set(m->timer, 0);
}

static void reject_job(struct mms *m, struct job *j, const char *why)
{
	m->st.rejected++;
	set_err(m, "message refused: %s", why);
	LOGI("mms: refusing message %s: %s", j->bench ? "(fetch)" : j->tid, why);
	if (j->store && !j->bench)
		store_failed_item(m, j, true);
	m->n_post = 0;
	if (!j->bench)
		prepare_notifyresp(m, j, MMS_ST_REJECTED);
	start_posts(m, j);
}

static void got_conf(struct mms *m, struct job *j, const uint8_t *body, size_t len)
{
	struct mms_retrieve *rv = malloc(sizeof(*rv));

	if (!rv) {
		job_retry(m, j, "out of memory");
		return;
	}
	if (mms_decode_retrieve(body, len, rv)) {
		free(rv);
		job_fail(m, j, "the answer is not a valid m-retrieve-conf");
		return;
	}
	if (rv->retrieve_status >= 0 && rv->retrieve_status != 0x80) {
		int s = rv->retrieve_status;

		free(rv);
		if (s >= 0xc0 && s < 0xe0) {		/* transient failure codes */
			job_retry(m, j, "the MMSC reports a transient retrieve error");
			return;
		}
		job_fail(m, j, "the MMSC reports a permanent retrieve error");
		return;
	}
	m->st.retrieved++;
	LOGI("mms: retrieved %zu bytes, version %u.%u, %u part(s)", len, (rv->version >> 4) & 7, rv->version & 15, rv->nparts);
	{
		uint64_t id = content_id(rv, j);
		int age = j->bench ? -1 : seen_age_min(m, id);	/* an explicit fetch is always delivered */
		bool dup = age >= 0;

		if (!dup && j->store && !j->bench)	/* also a message stored before a restart */
			dup = !store_find_dedup(m->ops.store, STORE_MMS, id, 0, NULL);
		if (dup) {
			m->st.duplicates++;
			if (age >= 0)
				LOGI("mms: message %s is a duplicate of a message delivered %d min ago, not delivered again (confirmed)", j->tid, age);
			else
				LOGI("mms: message %s is a duplicate of a stored message, no second item (confirmed)", j->tid);
		} else {
			if (j->store)
				store_message(m, j, rv, body, len, id);
			else
				deliver_message(m, j, rv, REG_ID_NONE, 0, NULL, NULL);
			if (!j->bench)		/* also a message that was lost for lack of a LAN client: it is confirmed below */
				seen_add(m, id);
		}
	}
	/* the message was retrieved: tell the MMSC whatever became of the delivery to the LAN */
	m->n_post = 0;
	if (!j->bench) {
		size_t l;

		prepare_notifyresp(m, j, MMS_ST_RETRIEVED);
		if (rv->has_tid) {
			l = mms_encode_acknowledge(rv->tid, rv->version ? rv->version : j->version, m->resp[m->n_post],
						   sizeof(m->resp[0]));
			if (l)
				queue_resp(m, "M-Acknowledge.ind", l);
		}
	}
	free(rv);
	start_posts(m, j);
}

static void on_get(void *arg, int err, const struct http_resp *r)
{
	struct mms *m = arg;
	struct job *j = m->cur;
	char why[64];

	m->req = NULL;
	if (!j || m->phase != PH_GET)
		return;
	if (err == HTTP_E_TOOBIG) {
		reject_job(m, j, "larger than mms_max_size");
		return;
	}
	if (err == HTTP_E_UNSUPPORTED || err == HTTP_E_URL || err == HTTP_E_REDIRECT || err == HTTP_E_ARG) {
		job_fail(m, j, http_strerror(err));
		return;
	}
	if (err) {
		snprintf(why, sizeof(why), "%s", http_strerror(err));
		job_retry(m, j, why);
		return;
	}
	if (r->status == 200) {
		got_conf(m, j, r->body, r->len);
		return;
	}
	snprintf(why, sizeof(why), "HTTP %d", r->status);
	if (r->status >= 500 || r->status == 408 || r->status == 429)
		job_retry(m, j, why);
	else
		job_fail(m, j, why);
}

static void start_get(struct mms *m, struct job *j)
{
	char hdr[640];
	struct http_opts o;
	struct dns_bind b;
	struct carrier_mms cp;

	profile(m, &cp);
	build_headers(m, &cp, hdr, sizeof(hdr), false);
	memset(&o, 0, sizeof(o));
	o.method = "GET";
	o.url = j->url;
	o.headers = hdr;
	o.proxy_host = cp.proxy_host;
	o.proxy_port = cp.proxy_port;
	o.max_body = m->cfg.max_size;
	o.timeout_ms = GET_TIMEOUT_MS;
	o.idle_ms = GET_IDLE_MS;
	make_bind(m, &b);
	m->phase = PH_GET;
	LOGI("mms: retrieving %s (attempt %u)", j->bench ? "a fetched message" : j->tid, j->attempt + 1);
	m->req = http_request(m->http, &b, &o, on_get, m);
	if (!m->req)
		job_retry(m, j, "out of memory");
}

static void start_ack(struct mms *m, struct job *j)
{
	m->n_post = 0;
	prepare_notifyresp(m, j, MMS_ST_RETRIEVED);
	if (j->send_ack && j->ack_tid[0]) {
		size_t l = mms_encode_acknowledge(j->ack_tid, j->ack_version ? j->ack_version : j->version, m->resp[m->n_post],
						  sizeof(m->resp[0]));

		if (l)
			queue_resp(m, "M-Acknowledge.ind", l);
	}
	start_posts(m, j);
}

/* is there MMS work now (a job that can run, the one running, a relay of the proxy, a request waiting for the link)? The on-demand data
 * connection is asked for as long as there is, released after its linger when there is not. */
static void update_want(struct mms *m)
{
	bool w = m->cur != NULL || m->work > 0;
	uint64_t now = ev_now_ms();
	unsigned i;

	for (i = 0; i < MMS_QUEUE && !w; i++)
		w = m->q[i].used && m->q[i].not_before <= now;
	for (i = 0; i < LINK_WAITERS && !w; i++)
		w = m->lw[i].used;
	if (w == m->want_sent)
		return;
	m->want_sent = w;
	if (m->ops.want)
		m->ops.want(m->ops.ctx, w);
}

static void pump(struct mms *m)
{
	struct job *best = NULL;
	uint64_t now = ev_now_ms(), wake = 0;
	unsigned i;

	update_want(m);
	if (m->cur)
		return;
	for (i = 0; i < MMS_QUEUE; i++) {
		struct job *j = &m->q[i];

		if (!j->used)
			continue;
		if (j->not_before <= now) {
			if (!best || j->seq < best->seq)
				best = j;
		} else if (!wake || j->not_before < wake) {
			wake = j->not_before;
		}
	}
	if (!best) {
		if (wake)
			ev_timer_set(m->timer, wake - now);
		return;
	}
	if (expired(m, best, now)) {
		job_fail(m, best, "expired");
		return;
	}
	refresh_link(m);
	if (!m->link.up) {
		if (!m->waiting_logged) {
			if (m->link.on_demand)
				LOGI("mms: %u message(s) waiting for the MMS data connection (%s)", pending(m), m->link.reason[0] ? m->link.reason : "coming up");
			else
				LOGI("mms: %u message(s) waiting for the IMS link", pending(m));
		}
		m->waiting_logged = true;
		return;
	}
	m->waiting_logged = false;
	m->cur = best;
	if (best->ack_only) {
		start_ack(m, best);
		return;
	}
	if (!best->bench && best->has_size && best->size > m->cfg.max_size) {
		reject_job(m, best, "larger than mms_max_size");
		return;
	}
	start_get(m, best);
}

/* requests of the proxy that wait for the on-demand link: answered when it is up, or after LINK_WAIT_MS, or when it cannot come up */
static void link_waiters(struct mms *m)
{
	unsigned i;
	uint64_t now = ev_now_ms();
	bool any = false;

	for (i = 0; i < LINK_WAITERS; i++) {
		void (*cb)(void *, bool);
		void *arg;
		bool up = m->link.up;

		if (!m->lw[i].used)
			continue;
		if (!up && m->link.available && now < m->lw[i].deadline) {
			any = true;
			continue;
		}
		cb = m->lw[i].cb;
		arg = m->lw[i].arg;
		memset(&m->lw[i], 0, sizeof(m->lw[i]));
		cb(arg, up);
	}
	for (i = 0; i < LINK_WAITERS; i++)
		any = any || m->lw[i].used;
	if (any)
		ev_timer_set(m->lw_timer, 1000);
	else
		ev_timer_cancel(m->lw_timer);
	update_want(m);
}

static void on_lw_timer(void *arg)
{
	struct mms *m = arg;

	refresh_link(m);
	link_waiters(m);
}

int mms_link_wait(struct mms *m, void (*cb)(void *arg, bool up), void *arg)
{
	unsigned i;

	refresh_link(m);
	if (m->link.up)
		return 1;
	if (!m->link.on_demand || !m->link.available)
		return -ENETDOWN;
	for (i = 0; i < LINK_WAITERS; i++)
		if (!m->lw[i].used) {
			m->lw[i].used = true;
			m->lw[i].cb = cb;
			m->lw[i].arg = arg;
			m->lw[i].deadline = ev_now_ms() + LINK_WAIT_MS;
			ev_timer_set(m->lw_timer, 1000);
			update_want(m);
			return 0;
		}
	return -ENOBUFS;
}

void mms_link_wait_cancel(struct mms *m, void *arg)
{
	unsigned i;

	for (i = 0; i < LINK_WAITERS; i++)
		if (m->lw[i].used && (!arg || m->lw[i].arg == arg))
			memset(&m->lw[i], 0, sizeof(m->lw[i]));
	update_want(m);
}

void mms_work(struct mms *m, int delta)
{
	m->work += delta;
	if (m->work < 0)
		m->work = 0;
	update_want(m);
	if (!m->work)
		ev_timer_set(m->timer, 0);
}

void mms_link_changed(struct mms *m)
{
	struct mms_link old = m->link;

	refresh_link(m);
	link_waiters(m);
	if (old.up == m->link.up && old.seq == m->link.seq && !memcmp(old.netdev, m->link.netdev, sizeof(old.netdev)) &&
	    addr_equal(&old.local, &m->link.local)) {
		if (strcmp(old.reason, m->link.reason) || old.available != m->link.available)
			ev_timer_set(m->timer, 0);		/* the reason changed: status, and the queue looks again */
		return;
	}
	dns_flush(m->dns);
	if (m->cur) {		/* in flight over the old link: stop it and start again (no attempt is used up) */
		struct job *j = m->cur;

		http_cancel(m->req);
		m->req = NULL;
		if (m->phase == PH_GET) {
			LOGI("mms: IMS link changed during the retrieval, starting again");
			j->not_before = ev_now_ms();
			m->cur = NULL;
			m->phase = PH_IDLE;
		} else {
			LOGI("mms: IMS link changed, the confirmations to the MMSC are dropped");
			job_done(m, j);
			return;
		}
	}
	m->waiting_logged = false;
	ev_timer_set(m->timer, 0);
}

/* ------------------------------------------------------------------ */
/* input                                                               */

static struct job *job_alloc(struct mms *m)
{
	unsigned i;

	for (i = 0; i < MMS_QUEUE; i++)
		if (!m->q[i].used) {
			memset(&m->q[i], 0, sizeof(m->q[i]));
			m->q[i].used = true;
			m->q[i].seq = ++m->seq;
			m->q[i].not_before = ev_now_ms();
			return &m->q[i];
		}
	return NULL;
}

/* a confirmation without a retrieval of our own: M-NotifyResp.ind (Retrieved) and, with ack_tid, M-Acknowledge.ind */
static void queue_ack(struct mms *m, const char *tid, const char *url, uint8_t version, const char *ack_tid, bool send_ack)
{
	struct job *j = job_alloc(m);

	if (!j) {
		m->st.ack_failed++;
		set_err(m, "queue full, confirmation of %s dropped", tid);
		LOGW("mms: queue full, the confirmation of %s is dropped", tid);
		return;
	}
	j->ack_only = true;
	j->send_ack = send_ack && ack_tid && ack_tid[0];
	snprintf(j->tid, sizeof(j->tid), "%s", tid);
	snprintf(j->url, sizeof(j->url), "%s", url);
	snprintf(j->ack_tid, sizeof(j->ack_tid), "%s", ack_tid ? ack_tid : "");
	j->version = version;
	j->expire_ms = ev_now_ms() + ACK_JOB_TTL_MS;
	m->st.proxy_acks++;
	ev_timer_set(m->timer, 0);
}

static void raw_done(void *arg, int nok)
{
	struct mms *m = arg;

	if (nok > 0) {
		m->st.raw_delivered++;
		LOGI("mms: original notification delivered to %d device(s)", nok);
	} else {
		m->st.raw_lost++;
		set_err(m, "notification lost: no MMS client accepted it");
		LOGW("mms: LOST notification: no device with +g.imsd.mms accepted it");
	}
}

static void deliver_raw_pdu(struct mms *m, const char *from, const char *tid, const uint8_t *pdu, size_t len)
{
	struct mms_raw r;
	int rc;

	memset(&r, 0, sizeof(r));
	r.pdu = pdu;
	r.len = len;
	snprintf(r.from, sizeof(r.from), "%s", from);
	snprintf(r.tid, sizeof(r.tid), "%s", tid);
	snprintf(r.proxy, sizeof(r.proxy), "%s", m->ops.proxy_base(m->ops.ctx));
	r.max_size = m->cfg.max_size;
	r.ts = wall(m);
	rc = m->ops.deliver_raw(m->ops.ctx, &r, raw_done, m);
	if (rc) {
		m->st.raw_lost++;
		set_err(m, "notification lost: delivery failed (%d)", rc);
		LOGW("mms: LOST notification %s from %s: cannot deliver (%s)", tid, from, strerror(-rc));
	}
}

static void deliver_raw(struct mms *m, const struct mms_notif *nf, const uint8_t *pdu, size_t len)
{
	deliver_raw_pdu(m, nf->from, nf->tid, pdu, len);
}

/* ------------------------------------------------------------------ */
/* the store                                                           */

static void item_fill(const struct job *j, const struct mms_retrieve *rv, struct mms_item *it)
{
	memset(it, 0, sizeof(*it));
	it->arrive = j->arrive;
	it->size = j->has_size ? j->size : 0;
	snprintf(it->from, sizeof(it->from), "%s", rv && rv->from[0] ? rv->from : j->from);
	snprintf(it->subject, sizeof(it->subject), "%s", rv && rv->subject[0] ? rv->subject : j->subject);
	snprintf(it->tid, sizeof(it->tid), "%s", j->tid);
	snprintf(it->mid, sizeof(it->mid), "%s", rv ? (rv->message_id[0] ? rv->message_id : rv->has_tid ? rv->tid : j->tid) : j->tid);
	snprintf(it->location, sizeof(it->location), "%s", j->url);
	it->pdu = j->pdu;
	it->pdu_len = j->pdu_len;
}

/* what the live path did with a message: text to the text devices, the original notification to the +g.imsd.mms devices */
static void legacy_item(struct mms *m, const struct mms_item *it, const uint8_t *body, size_t blen)
{
	unsigned nm = 0, nt = 0;

	if (m->ops.devices && m->ops.deliver_raw && m->ops.proxy_base)
		m->ops.devices(m->ops.ctx, &nm, &nt);
	if (nm && !m->ops.proxy_base(m->ops.ctx)[0]) {
		nt += nm;
		nm = 0;
	}
	if (body && (nm == 0 || nt > 0)) {
		struct job *jj = calloc(1, sizeof(*jj));
		struct mms_retrieve *rv = malloc(sizeof(*rv));

		if (jj && rv && !mms_decode_retrieve(body, blen, rv)) {
			snprintf(jj->from, sizeof(jj->from), "%s", it->from);
			snprintf(jj->subject, sizeof(jj->subject), "%s", it->subject);
			snprintf(jj->tid, sizeof(jj->tid), "%s", it->tid);
			jj->exclude_mms = nm > 0;
			deliver_message(m, jj, rv, REG_ID_NONE, 0, NULL, NULL);
		}
		free(jj);
		free(rv);
	} else if (!body) {
		LOGW("mms: the retrieval of message %s failed and the store did not take it", it->tid);
	}
	if (nm && it->pdu_len)
		deliver_raw_pdu(m, it->from, it->tid, it->pdu, it->pdu_len);
}

static void mms_store_cb(void *arg, int status, uint64_t seq, const struct store_add *a)
{
	struct mms *m = arg;
	struct mms_item it;

	if (status == 0) {
		m->st.stored++;
		LOGI("mms: stored as item %llu", (unsigned long long)seq);
		return;
	}
	m->st.store_fallback++;
	LOGW("mms: cannot store the message (%s), delivering live", strerror(-status));
	if (!mmsi_parse(a->meta, a->meta_len, &it))
		legacy_item(m, &it, a->body, a->body_len);
}

static void store_put(struct mms *m, const struct mms_item *it, const uint8_t *body, size_t blen, uint64_t dedup)
{
	uint8_t meta[3000];
	struct store_add a;
	size_t n = mmsi_pack(it, meta, sizeof(meta));

	if (n) {
		memset(&a, 0, sizeof(a));
		a.type = STORE_MMS;
		a.time = it->arrive;
		a.peer = it->from;
		a.dedup = dedup;
		a.lookup = store_hash(it->location);
		a.meta = meta;
		a.meta_len = n;
		a.body = body;
		a.body_len = blen;
		a.owner = m;
		if (!store_add(m->ops.store, &a, mms_store_cb, m, NULL))
			return;
	}
	m->st.store_fallback++;
	legacy_item(m, it, body, blen);
}

static void store_message(struct mms *m, const struct job *j, const struct mms_retrieve *rv, const uint8_t *body, size_t blen,
			  uint64_t content_id)
{
	struct mms_item it;

	item_fill(j, rv, &it);
	it.flags = MMSI_HAS_BODY;
	LOGI("mms: message from %s: %zu bytes into the store", it.from[0] ? it.from : "(unknown)", blen);
	store_put(m, &it, body, blen, content_id);
}

static void store_failed_item(struct mms *m, const struct job *j, bool toobig)
{
	struct mms_item it;

	item_fill(j, NULL, &it);
	it.flags = MMSI_FAILED | (toobig ? MMSI_TOOBIG : 0);
	m->st.failed_stored++;
	store_put(m, &it, NULL, 0, 0);
}

static bool tagged_eff(struct mms *m, uint32_t features)
{
	return (features & REG_F_MMS) && m->ops.proxy_base && m->ops.proxy_base(m->ops.ctx)[0];
}

static bool mms_st_needs_body(void *ctx, uint8_t type, uint32_t features, bool has_body)
{
	struct mms *m = ctx;

	return type == STORE_MMS && has_body && !tagged_eff(m, features);
}

static void mms_st_abort(void *ctx, void *arg)
{
	struct mms *m = ctx;

	if (m->ops.deliver_abort)
		m->ops.deliver_abort(m->ops.ctx, arg);
}

/* the store hands over one item for one binding: the original notification, the rendered text, or the notice */
static int mms_st_deliver(void *ctx, const struct store_item *si, reg_id_t b, uint32_t features, void (*done)(void *, int), void *arg)
{
	struct mms *m = ctx;
	struct mms_item *it = malloc(sizeof(*it));
	int rc;

	if (!it)
		return -ENOMEM;
	if (mmsi_parse(si->meta, si->meta_len, it)) {
		LOGW("mms: stored item %llu is not readable, skipped", (unsigned long long)si->seq);
		free(it);
		return 1;
	}
	if (tagged_eff(m, features) && it->pdu_len && m->ops.deliver_raw) {
		struct mms_raw r;

		memset(&r, 0, sizeof(r));
		r.pdu = it->pdu;
		r.len = it->pdu_len;
		snprintf(r.from, sizeof(r.from), "%s", it->from);
		snprintf(r.tid, sizeof(r.tid), "%s", it->tid);
		snprintf(r.proxy, sizeof(r.proxy), "%s", m->ops.proxy_base(m->ops.ctx));
		r.max_size = m->cfg.max_size;
		r.ts = it->arrive;
		r.target = b;
		r.seq = si->seq;
		rc = m->ops.deliver_raw(m->ops.ctx, &r, done, arg);
		free(it);
		return rc;
	}
	if (si->body && (it->flags & MMSI_HAS_BODY)) {
		struct job *jj = calloc(1, sizeof(*jj));
		struct mms_retrieve *rv = malloc(sizeof(*rv));

		if (!jj || !rv) {
			free(jj);
			free(rv);
			free(it);
			return -ENOMEM;
		}
		if (mms_decode_retrieve(si->body, si->body_len, rv)) {
			LOGW("mms: stored message %llu does not decode, skipped", (unsigned long long)si->seq);
			free(jj);
			free(rv);
			free(it);
			return 1;
		}
		snprintf(jj->from, sizeof(jj->from), "%s", it->from);
		snprintf(jj->subject, sizeof(jj->subject), "%s", it->subject);
		snprintf(jj->tid, sizeof(jj->tid), "%s", it->tid);
		rc = deliver_message(m, jj, rv, b, si->seq, done, arg);
		free(jj);
		free(rv);
		free(it);
		return rc;
	}
	/* no body: the retrieval failed for good (or a tagged device without a usable proxy): a short notice for the text devices */
	{
		struct mms_out *out = calloc(1, sizeof(*out));
		char note[256];

		if (!out || !m->ops.deliver) {
			free(out);
			free(it);
			return m->ops.deliver ? -ENOMEM : -ENOENT;
		}
		snprintf(note, sizeof(note), "[MMS] A multimedia message from %s could not be retrieved%s.", it->from[0] ? it->from : "unknown",
			 (it->flags & MMSI_TOOBIG) ? " (it is larger than the allowed size)" : "");
		snprintf(out->from, sizeof(out->from), "%s", it->from);
		snprintf(out->message_id, sizeof(out->message_id), "%s", it->tid);
		out->has_ts = it->arrive >= WALL_PLAUSIBLE;
		out->ts = it->arrive;
		out->target = b;
		out->seq = si->seq;
		out->n = 1;
		out->text[0] = note;
		rc = m->ops.deliver(m->ops.ctx, out, done, arg);
		free(out);
		free(it);
		return rc;
	}
}

void mms_on_push(struct mms *m, const char *from, unsigned port, const uint8_t *data, size_t n)
{
	struct wsp_push p;
	struct mms_notif nf;
	struct job *j;
	struct notif *prev;
	unsigned nm = 0, nt = 0;
	uint64_t ident;
	bool is_mms, again;

	if (!m->cfg.enable) {
		LOGI("mms: WAP push from %s on port %u ignored (mms is disabled)", from, port);
		return;
	}
	if (wsp_parse_push(data, n, &p)) {
		LOGI("mms: WAP push from %s on port %u is not a WSP push PDU (%zu bytes), dropped", from, port, n);
		return;
	}
	is_mms = !strcasecmp(p.ct.type, "application/vnd.wap.mms-message") ||
		 (p.has_app_id && !strcasecmp(p.app_id, "x-wap-application:mms.ua"));
	if (!is_mms) {
		LOGI("mms: WAP push from %s on port %u, content type %s, application %s: not MMS, dropped", from, port, p.ct.type,
		     p.has_app_id ? p.app_id : "-");
		return;
	}
	if (mms_decode_notification(p.body, p.body_len, &nf)) {
		if (p.body_len >= 2 && p.body[0] == 0x8c)
			LOGI("mms: push from %s carries MMS PDU type 0x%02x, not handled", from, p.body[1]);
		else
			LOGW("mms: malformed MMS notification from %s (%zu bytes)", from, p.body_len);
		set_err(m, "malformed or unsupported MMS notification");
		return;
	}
	if (known_tid(m, nf.tid) || notif_find_tid(m, nf.tid)) {
		m->st.duplicates++;
		LOGI("mms: notification %s is a repeat, ignored", nf.tid);
		return;
	}
	if (m->ops.devices && m->ops.deliver_raw && m->ops.proxy_base)
		m->ops.devices(m->ops.ctx, &nm, &nt);
	if (nm && !m->ops.proxy_base(m->ops.ctx)[0]) {		/* nothing to fetch through: they get the text like the others */
		nt += nm;
		nm = 0;
	}
	ident = notif_ident(&nf);
	if (m->ops.store && store_usable(m->ops.store)) {
		/* store mode: retrieve it ourselves in every case; the item is made when that is over */
		struct notif *n;

		j = job_alloc(m);
		if (!j) {
			m->st.failed++;
			set_err(m, "queue full, notification dropped");
			LOGW("mms: queue full (%d), notification %s dropped", MMS_QUEUE, nf.tid);
			return;
		}
		snprintf(j->tid, sizeof(j->tid), "%s", nf.tid);
		snprintf(j->url, sizeof(j->url), "%s", nf.location);
		snprintf(j->from, sizeof(j->from), "%s", nf.from);
		snprintf(j->subject, sizeof(j->subject), "%s", nf.subject);
		j->version = nf.version;
		j->has_size = nf.has_size;
		j->size = nf.size;
		j->store = true;
		j->arrive = wall(m);
		if (p.body_len <= sizeof(j->pdu)) {
			memcpy(j->pdu, p.body, p.body_len);
			j->pdu_len = p.body_len;
		}
		if (nf.has_expiry) {
			if (nf.expiry_relative)
				j->expire_ms = ev_now_ms() + (uint64_t)(nf.expiry > 366 * 86400 ? 366 * 86400 : nf.expiry) * 1000;
			else
				j->expire_wall = nf.expiry;
		}
		m->st.notifications++;
		n = notif_add(m, &nf, ident);
		n->raw = true;			/* a repeat of this transaction id is recognised */
		LOGI("mms: notification %s from %s, %u bytes, to be retrieved into the store from %s", nf.tid,
		     nf.from[0] ? nf.from : "(unknown)", nf.has_size ? nf.size : 0, nf.location);
		LOGD("mms: notification subject \"%s\"", nf.subject);
		ev_timer_set(m->timer, 0);
		return;
	}
	prev = nm ? notif_find_ident(m, ident) : NULL;
	/* The same message announced again under a new transaction id: when a device fetched the earlier one the new
	 * notification is only confirmed (a device that has the message must not get it twice) */
	again = prev && prev->fetched;
	if (nm && !nt && again) {
		struct notif *n;

		m->st.duplicates++;
		LOGI("mms: notification %s repeats the message of %s that was fetched, not passed on again (confirmed)", nf.tid, prev->tid);
		n = notif_add(m, &nf, ident);
		n->raw = n->fetched = n->acked = true;
		snprintf(n->ack_tid, sizeof(n->ack_tid), "%s", prev->ack_tid);
		queue_ack(m, nf.tid, nf.location, nf.version, prev->ack_tid, true);
		return;
	}
	if (nm || nt)
		LOGI("mms: %u device(s) take the original notification, %u the text", nm, nt);
	if (nm == 0 || nt > 0) {		/* the text path: imsd retrieves the message itself */
		j = job_alloc(m);
		if (!j) {
			m->st.failed++;
			set_err(m, "queue full, notification dropped");
			LOGW("mms: queue full (%d), notification %s dropped", MMS_QUEUE, nf.tid);
			return;
		}
		snprintf(j->tid, sizeof(j->tid), "%s", nf.tid);
		snprintf(j->url, sizeof(j->url), "%s", nf.location);
		snprintf(j->from, sizeof(j->from), "%s", nf.from);
		snprintf(j->subject, sizeof(j->subject), "%s", nf.subject);
		j->version = nf.version;
		j->has_size = nf.has_size;
		j->size = nf.size;
		j->exclude_mms = nm > 0;
		if (nf.has_expiry) {
			if (nf.expiry_relative)
				j->expire_ms = ev_now_ms() + (uint64_t)(nf.expiry > 366 * 86400 ? 366 * 86400 : nf.expiry) * 1000;
			else
				j->expire_wall = nf.expiry;
		}
	}
	m->st.notifications++;
	{
		struct notif *n = notif_add(m, &nf, ident);

		n->raw = nm && !again;
		n->ack_on_fetch = nm && !nt;
	}
	LOGI("mms: notification %s from %s, %u bytes, to be fetched from %s", nf.tid, nf.from[0] ? nf.from : "(unknown)",
	     nf.has_size ? nf.size : 0, nf.location);
	LOGD("mms: notification subject \"%s\"", nf.subject);
	if (nm && !again)
		deliver_raw(m, &nf, p.body, p.body_len);
	ev_timer_set(m->timer, 0);
}

int mms_fetch(struct mms *m, const char *url, const char *from, const char *subject)
{
	struct http_url u;
	struct job *j;
	int rc = http_parse_url(url, &u);

	if (rc == HTTP_E_UNSUPPORTED)
		return -ENOTSUP;
	if (rc || strlen(url) >= MMS_URL_MAX)
		return -EINVAL;
	j = job_alloc(m);
	if (!j)
		return -EBUSY;
	j->bench = true;
	snprintf(j->url, sizeof(j->url), "%s", url);
	snprintf(j->from, sizeof(j->from), "%s", from ? from : "");
	snprintf(j->subject, sizeof(j->subject), "%s", subject ? subject : "");
	LOGI("mms: fetch of %s queued", url);
	ev_timer_set(m->timer, 0);
	return 0;
}

void mms_get_status(const struct mms *m, struct mms_status *s)
{
	*s = m->st;
	s->pending = pending(m);
	{
		struct carrier_val v;

		resolve_mmsc(m, &v);
		snprintf(s->mmsc, sizeof(s->mmsc), "%s", v.value[0] ? v.value : m->derived_mmsc);
		snprintf(s->mmsc_source, sizeof(s->mmsc_source), "%s", v.source);
	}
	{
		struct carrier_mms cp;

		profile(m, &cp);
		snprintf(s->operator_name, sizeof(s->operator_name), "%s", cp.name);
		snprintf(s->operator_match, sizeof(s->operator_match), "%s", cp.how);
		snprintf(s->apn, sizeof(s->apn), "%s", cp.apn);
		if (cp.proxy_host[0])
			snprintf(s->proxy, sizeof(s->proxy), "%s:%u", cp.proxy_host, cp.proxy_port);
		snprintf(s->user_agent, sizeof(s->user_agent), "%s", cp.user_agent[0] ? cp.user_agent : m->cfg.user_agent);
		s->entry_tested = cp.tested;
		s->on_demand = m->link.on_demand;
		snprintf(s->link_reason, sizeof(s->link_reason), "%s", m->link.up ? "" : m->link.reason);
	}
	mmsstore_stats(m->store, &s->store_messages, &s->store_bytes);
}

/* ------------------------------------------------------------------ */
/* the MMS proxy                                                       */

struct http *mms_http(struct mms *m)
{
	return m->http;
}

void mms_upstream(struct mms *m, struct mms_upstream *u)
{
	struct carrier_mms cp;

	memset(u, 0, sizeof(*u));
	refresh_link(m);
	profile(m, &cp);
	u->link_up = m->link.up;
	u->can_wait = !m->link.up && m->link.on_demand && m->link.available;
	if (m->link.on_demand)
		snprintf(u->down_text, sizeof(u->down_text), "the MMS data connection is not available%s%.160s", m->link.reason[0] ? ": " : "",
			 m->link.reason);
	else
		snprintf(u->down_text, sizeof(u->down_text), "the IMS link is down");
	make_bind(m, &u->bind);
	snprintf(u->mmsc, sizeof(u->mmsc), "%s", cp.mmsc[0] ? cp.mmsc : m->derived_mmsc);
	snprintf(u->proxy_host, sizeof(u->proxy_host), "%s", cp.proxy_host);
	u->proxy_port = cp.proxy_port;
	build_headers(m, &cp, u->get_headers, sizeof(u->get_headers), false);
	build_headers(m, &cp, u->post_headers, sizeof(u->post_headers), true);
	u->max_size = m->cfg.max_size;
}

bool mms_url_allowed(struct mms *m, const char *url)
{
	struct http_url u, mu;
	struct carrier_val v;
	unsigned i;

	for (i = 0; i < NOTIF_RING; i++)
		if (notif_live(m, &m->nt[i]) && !strcmp(m->nt[i].url, url))
			return true;
	resolve_mmsc(m, &v);
	if (http_parse_url(url, &u) || u.https || http_parse_url(v.value[0] ? v.value : m->derived_mmsc, &mu) || mu.https)
		return false;
	return !strcasecmp(u.host, mu.host);
}

void mms_proxy_fetched(struct mms *m, const char *url, const uint8_t *body, size_t len)
{
	struct mms_retrieve *rv;
	struct notif *n = NULL;
	unsigned i;

	for (i = 0; i < NOTIF_RING; i++)
		if (notif_live(m, &m->nt[i]) && !strcmp(m->nt[i].url, url)) {
			n = &m->nt[i];
			break;
		}
	if (!n || n->fetched)
		return;
	rv = malloc(sizeof(*rv));
	if (!rv)
		return;
	if (mms_decode_retrieve(body, len, rv) || (rv->retrieve_status >= 0 && rv->retrieve_status != 0x80)) {
		free(rv);
		return;
	}
	n->fetched = true;
	snprintf(n->ack_tid, sizeof(n->ack_tid), "%s", rv->has_tid ? rv->tid : "");
	LOGI("mms: message %s was fetched through the proxy", n->tid);
	if (n->ack_on_fetch && !n->acked) {
		n->acked = true;
		queue_ack(m, n->tid, n->url, rv->version ? rv->version : n->version, n->ack_tid, true);
		/* the same message announced under other transaction ids that nobody fetched: confirmed as well, so that the MMSC stops */
		for (i = 0; i < NOTIF_RING; i++) {
			struct notif *o = &m->nt[i];

			if (o != n && o->raw && o->ack_on_fetch && !o->fetched && o->ident == n->ident && notif_live(m, o)) {
				o->fetched = o->acked = true;
				snprintf(o->ack_tid, sizeof(o->ack_tid), "%s", n->ack_tid);
				queue_ack(m, o->tid, o->url, o->version, "", false);
			}
		}
	}
	free(rv);
}

/* a device sent M-NotifyResp.ind to the proxy: Retrieved for a message it did not fetch through the proxy is a trigger for imsd's own
 * confirmation (once); nothing else is ever forwarded */
void mms_proxy_notify_resp(struct mms *m, const char *tid, unsigned status)
{
	struct notif *n = notif_find_tid(m, tid);

	if (!n || status != MMS_ST_RETRIEVED || n->acked)
		return;
	n->fetched = true;
	if (n->ack_on_fetch) {
		n->acked = true;
		queue_ack(m, n->tid, n->url, n->version, n->ack_tid, n->ack_tid[0] != 0);
	}
}
