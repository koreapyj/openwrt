/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SMS relay, see smsrelay.h for the architecture. Answers to the LAN client of an MO message (smsrelay_on_lan_message):
 *   200  every segment acknowledged by the network (X-SMS-Parts, X-SMS-Timestamp of the submit report)
 *   202  outcome still unknown at reply_deadline_ms; the eventual outcome is only logged
 *   400  empty body / body not valid UTF-8        404  Request-URI is not a phone number
 *   484  number empty or longer than 20 digits    413  more than max_segments SMS segments
 *   415  not text/plain, or charset other than utf-8 / us-ascii      403  network barred it (SIP 403/603), or device not registered
 *   480  not registered on the network (also: registration lost while queued / in flight)
 *   502  RP-ERROR with a permanent cause, or an odd SIP failure       503  SMSC unknown, queue full (Retry-After),
 *   temporary RP-ERROR / SIP 480-5xx           504  no answer / no report within report_timeout_ms
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "smsrelay.h"
#include "smsfmt.h"
#include "wappush.h"
#include "../carrier.h"
#include "../sms/rp.h"
#include "../smscodec/tpdu.h"
#include "../ua/lan_text.h"
#include "../util/buf.h"
#include "../util/codec.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"
#include "../store/pack.h"

#define SMS_CT		"application/vnd.3gpp.sms"
#define SMS_GM_EXTRA	"Allow: MESSAGE\r\nRequest-Disposition: no-fork\r\nAccept-Contact: *;+g.3gpp.smsip\r\n"
#define DD_N		32
#define DD_TTL_MS	120000u
#define HEX_EXCERPT	24

/* ------------------------------------------------------------------ */
/* state                                                               */

struct mt_job;
struct mo_msg;

struct dedup {
	bool used;
	bool done;		/* the reply to the network was sent */
	int cause;		/* 0: RP-ACK, else RP-ERROR cause */
	uint64_t key;
	uint64_t t_ms;
};

enum cb_kind { CB_MO_SEG, CB_RP_REPLY };
struct cbctx {
	struct cbctx *next;
	struct smsrelay *sr;
	enum cb_kind kind;
	uint32_t token;
	uint8_t mr;
};

struct mt_fork {
	struct mt_job *job;
	int idx;
};

struct mt_job {
	struct mt_job *next;
	struct smsrelay *sr;
	uint8_t mr;
	char call_id[128];
	char ruri[256];
	uint64_t key;
	struct lan_fork *fork[2];
	struct mt_fork mf[2];
	int started;		/* forks started */
	int complete;		/* forks COMPLETEd */
	int live;		/* forks not yet DONE / detached */
	int nok_b, nok_c;
	int fork_err;		/* errno of a failed fork start other than ENOENT, else 0 */
	bool finished;
	bool is_report;
	struct ev_timer *timer;
	char peer[TP_ADDR_MAX];
	size_t text_len;
	char text[TP_MAX_TEXT + 160];	/* kept for the "lost" warning */
};

enum mo_state { MO_QUEUED, MO_WAIT_SIP, MO_WAIT_REPORT };

struct mo_msg {
	struct mo_msg *next;
	struct smsrelay *sr;
	struct txn_server *st;
	char dest[24];
	struct rp_addr smsc;
	struct tp_pdu *pdu;
	unsigned nseg, cur;
	size_t text_len;
	enum mo_state state;
	uint8_t rp_mr;
	char call_id[96];
	uint32_t token;
	bool early;		/* report arrived before the SIP answer */
	bool early_err;
	int early_cause;
	struct tp_scts early_scts;
	bool have_scts;
	struct tp_scts scts;
	bool replied, late;
	reg_id_t sender;	/* the binding the MESSAGE came from, REG_ID_NONE for an unregistered source */
	char *text;		/* the original text, for the carbon copies */
	struct ev_timer *dl_timer, *seg_timer;
};

/* an incoming SMS that is being stored (store mode): the RP-ACK goes when it is durable */
struct st_job {
	struct st_job *next;
	struct smsrelay *sr;
	char ruri[256], call_id[128];
	uint8_t mr;
	uint64_t key, seq;
	bool is_report;
	struct ev_timer *timer;
	uint8_t meta[320];
	size_t meta_len;
};

/* circuit switched path */
struct cs_job {			/* an incoming CS message being stored: the modem's copy is deleted when it is durable */
	struct cs_job *next;
	struct smsrelay *sr;
	unsigned id;
	uint64_t key, seq;
	struct ev_timer *timer;
	uint8_t *meta;
	size_t meta_len;
};
struct cs_live {		/* an incoming CS message in live delivery (no store) */
	struct cs_live *next;
	struct smsrelay *sr;
	bool is_report;
	bool keep;		/* the store is enabled: the modem's copy is deleted only when a device took it (cs_in_done) */
	unsigned id;
	uint64_t key;
	char peer[48];
	char text[400];
};
struct cs_mo {			/* an MO message in the hands of cssms */
	struct cs_mo *next;
	struct smsrelay *sr;
	struct txn_server *st;
	char dest[24];
	char *text;
	reg_id_t sender;
	bool replied, late, orphan;
	struct ev_timer *dl_timer;
};

struct smsrelay {
	struct cs_job *cj;
	struct cs_live *cl;
	struct cs_mo *cmo;
	unsigned cmo_n;
	struct st_job *sj;
	unsigned sj_n;
	struct lan *lan;
	struct smsrelay_cfg cfg;
	struct smsrelay_ops ops;
	struct smsrelay_status c;	/* counters part only */
	struct dedup dd[DD_N];
	struct mt_job *mt;
	unsigned mt_n;		/* jobs alive (a finished job lingers until its forks ended) */
	unsigned mt_active;	/* jobs not yet answered to the network */
	struct mo_msg *q_head, *q_tail;
	unsigned qn;
	struct cbctx *cbs;
	struct wappush *wp;
	struct lan_seqs *seqs;	/* carbon copies in progress */
	uint8_t rp_mr, tp_mr, concat_ref;
	uint32_t token;
	bool failing;
};

static void set_err(struct smsrelay *sr, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static size_t carbon_extra(const char *id, const char *dest, unsigned nseg, const char *ts, uint64_t seq, char *extra, size_t n);
static void carbon_meta_parse(const uint8_t *meta, size_t n, char *id, char *ts, char *dest, unsigned *nseg, reg_id_t *sender,
			      const uint8_t **text, size_t *tl);
static int st_deliver(void *ctx, const struct store_item *it, reg_id_t b, uint32_t features, void (*done)(void *, int), void *arg);
static int st_carbon_deliver(void *ctx, const struct store_item *it, reg_id_t b, uint32_t features, void (*done)(void *, int),
			     void *arg);
static void st_abort(void *ctx, void *arg);
static void cs_mo_start(struct smsrelay *sr, const struct lan_peer *peer, struct txn_server *st, const struct sip_msg *req,
			const char *dest);
static bool cs_is_meta(const uint8_t *meta, size_t n);
static int cs_deliver_item(struct smsrelay *sr, const struct store_item *it, reg_id_t b, void (*done)(void *, int), void *arg);
static void set_err(struct smsrelay *sr, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(sr->c.last_error, sizeof(sr->c.last_error), fmt, ap);
	va_end(ap);
}

void smsrelay_cfg_defaults(struct smsrelay_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->concat_prefix = true;
	c->lan_wait_ms = 5000;
	c->mt_max_pending = 16;
	c->max_segments = 10;
	c->queue_max = 8;
	c->report_timeout_ms = 30000;
	c->reply_deadline_ms = 28000;
	c->rp_mr_start = c->tp_mr_start = c->concat_ref_start = -1;
	c->carbons = true;
	c->text_split = 1000;
	c->store_ack_wait_ms = 3000;
}

static void cfg_clamp(struct smsrelay_cfg *c)
{
	if (c->max_segments < 1)
		c->max_segments = 1;
	if (c->max_segments > 32)
		c->max_segments = 32;
	if (c->queue_max < 1)
		c->queue_max = 1;
	if (c->queue_max > 64)
		c->queue_max = 64;
	if (c->mt_max_pending < 1)
		c->mt_max_pending = 1;
	if (c->mt_max_pending > 64)
		c->mt_max_pending = 64;
	if (c->text_split < 200 || c->text_split > 1400)
		c->text_split = 1000;
	if (c->store_ack_wait_ms < 100 || c->store_ack_wait_ms > 20000)
		c->store_ack_wait_ms = 3000;
	c->smsc[sizeof(c->smsc) - 1] = 0;
	c->sms_psi[sizeof(c->sms_psi) - 1] = 0;
	c->p_preferred_identity[sizeof(c->p_preferred_identity) - 1] = 0;
}

/* a complete WAP push from the reassembly: to the host (the MMS client) */
static void push_done(void *arg, const char *from, unsigned port, const uint8_t *data, size_t len)
{
	struct smsrelay *sr = arg;

	sr->c.mt_push_messages++;
	if (sr->ops.push)
		sr->ops.push(sr->ops.ctx, from, port, data, len);
	else
		LOGI("sms: WAP push from %s on port %u (%zu bytes) dropped: no handler", from, port, len);
}

/* the store became usable: cssms offers the messages it kept again at once */
static void cs_store_ready(void *arg)
{
	struct smsrelay *sr = arg;

	if (sr->ops.cs_kick)
		sr->ops.cs_kick(sr->ops.ctx);
}

struct smsrelay *smsrelay_new(struct lan *lan, const struct smsrelay_cfg *cfg, const struct smsrelay_ops *ops)
{
	struct smsrelay *sr;
	uint8_t r[3];

	if (!cfg || !ops || !ops->send || !ops->registered)
		return NULL;
	sr = calloc(1, sizeof(*sr));
	if (!sr)
		return NULL;
	sr->lan = lan;
	sr->cfg = *cfg;
	cfg_clamp(&sr->cfg);
	sr->ops = *ops;
	sr->wp = wappush_new(push_done, sr);
	sr->seqs = lan_seqs_new();
	if (!sr->wp || !sr->seqs) {
		wappush_free(sr->wp);
		lan_seqs_free(sr->seqs);
		free(sr);
		return NULL;
	}
	lan_seqs_set(sr->seqs, lan);
	if (sr->ops.store) {
		struct store_handler h;

		memset(&h, 0, sizeof(h));
		h.deliver = st_deliver;
		h.abort = st_abort;
		h.ctx = sr;
		store_set_handler(sr->ops.store, STORE_SMS, &h);
		h.deliver = st_carbon_deliver;
		store_set_handler(sr->ops.store, STORE_CARBON_SMS, &h);
		store_set_usable_cb(sr->ops.store, cs_store_ready, sr);
	}
	rnd_bytes(r, sizeof(r));
	sr->rp_mr = cfg->rp_mr_start >= 0 ? (uint8_t)cfg->rp_mr_start : r[0];
	sr->tp_mr = cfg->tp_mr_start >= 0 ? (uint8_t)cfg->tp_mr_start : r[1];
	sr->concat_ref = cfg->concat_ref_start >= 0 ? (uint8_t)cfg->concat_ref_start : r[2];
	return sr;
}

void smsrelay_set_cfg(struct smsrelay *sr, const struct smsrelay_cfg *cfg)
{
	sr->cfg = *cfg;
	cfg_clamp(&sr->cfg);
}

/* ------------------------------------------------------------------ */
/* small helpers                                                       */

static void lan_reply(struct txn_server *st, int status, const char *warn, const char *hdrs)
{
	struct sip_resp_parts p;
	char extra[512], w[160];

	if (!st)
		return;
	memset(&p, 0, sizeof(p));
	p.status = status;
	extra[0] = 0;
	if (warn && warn[0]) {
		smsfmt_quote_safe(warn, w, sizeof(w));
		snprintf(extra, sizeof(extra), "Warning: 399 imsd \"%s\"\r\n", w);
	}
	if (hdrs && strlen(extra) + strlen(hdrs) < sizeof(extra))
		strcat(extra, hdrs);
	p.extra = extra[0] ? extra : NULL;
	txn_server_reply(st, &p);
}

static struct cbctx *cb_new(struct smsrelay *sr, enum cb_kind kind, uint32_t token, uint8_t mr)
{
	struct cbctx *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	c->sr = sr;
	c->kind = kind;
	c->token = token;
	c->mr = mr;
	c->next = sr->cbs;
	sr->cbs = c;
	return c;
}

static void cb_free(struct smsrelay *sr, struct cbctx *c)
{
	struct cbctx **pp;

	for (pp = &sr->cbs; *pp; pp = &(*pp)->next) {
		if (*pp == c) {
			*pp = c->next;
			break;
		}
	}
	free(c);
}

static void new_call_id(char *out, size_t n)
{
	char tok[25];

	rnd_token(tok, 24);
	snprintf(out, n, "%s@imsd", tok);
}

static bool ci_has(const char *hay, const char *needle)
{
	return hay && strcasestr(hay, needle);
}

/* ------------------------------------------------------------------ */
/* SMSC                                                                */

/*
 * The RP address to use as RP-DA (evaluated at every MO message): the explicit configuration, else what the host
 * reads from the card (ops->smsc, EF_SMSP), else none. Source name in *src. false if none.
 */
static bool smsc_get(const struct smsrelay *sr, struct rp_addr *a, const char **src)
{
	const char *sim = sr->ops.smsc ? sr->ops.smsc(sr->ops.ctx) : NULL;
	struct carrier_val v;

	carrier_resolve_smsc(sr->cfg.smsc, sim, &v);
	*src = v.source;
	if (v.value[0] && !rp_addr_from_str(v.value, a))
		return true;
	*src = "none";
	return false;
}

/* Request-URI of the MO MESSAGE: the configured one, else the card's EF_PSISMSC, else the operator table (carrier.h) */
static void psi_get(const struct smsrelay *sr, struct carrier_val *v)
{
	const char *card = sr->ops.sms_psi ? sr->ops.sms_psi(sr->ops.ctx) : NULL;
	const char *imsi = sr->ops.imsi ? sr->ops.imsi(sr->ops.ctx) : NULL;

	carrier_resolve_sms_psi(sr->cfg.sms_psi, card, imsi, v);
}

void smsrelay_get_status(const struct smsrelay *sr, struct smsrelay_status *s)
{
	struct rp_addr a;
	struct carrier_val v;
	const char *src;

	*s = sr->c;
	s->mo_queue_len = sr->qn + sr->cmo_n;
	s->mt_pending = sr->mt_active;
	s->smsc[0] = 0;
	if (smsc_get(sr, &a, &src))
		rp_addr_to_str(&a, s->smsc, sizeof(s->smsc));
	snprintf(s->smsc_source, sizeof(s->smsc_source), "%s", src);
	psi_get(sr, &v);
	snprintf(s->sms_psi, sizeof(s->sms_psi), "%s", v.value);
	snprintf(s->sms_psi_source, sizeof(s->sms_psi_source), "%s", v.source);
}

/* ------------------------------------------------------------------ */
/* duplicate cache                                                     */

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

static uint64_t dd_key(const struct rp_data *rd)
{
	uint64_t h = 0xcbf29ce484222325ull;

	h = fnv(h, rd->oa.b, rd->oa.len);
	h = fnv(h, &rd->mr, 1);
	return fnv(h, rd->ud, rd->ud_len);
}

static struct dedup *dd_find(struct smsrelay *sr, uint64_t key)
{
	uint64_t now = ev_now_ms();
	int i;

	for (i = 0; i < DD_N; i++) {
		struct dedup *d = &sr->dd[i];

		if (d->used && now - d->t_ms > DD_TTL_MS)
			d->used = false;
		if (d->used && d->key == key)
			return d;
	}
	return NULL;
}

static void dd_del(struct smsrelay *sr, uint64_t key)
{
	struct dedup *d = key ? dd_find(sr, key) : NULL;

	if (d)
		d->used = false;
}

static struct dedup *dd_add(struct smsrelay *sr, uint64_t key)
{
	struct dedup *best = &sr->dd[0];
	int i;

	for (i = 0; i < DD_N; i++) {
		struct dedup *d = &sr->dd[i];

		if (!d->used) {
			best = d;
			break;
		}
		if (d->t_ms < best->t_ms)
			best = d;
	}
	memset(best, 0, sizeof(*best));
	best->used = true;
	best->key = key;
	best->t_ms = ev_now_ms();
	return best;
}

/* ------------------------------------------------------------------ */
/* RP replies to the network                                           */

static void rp_reply_done(void *arg, int status, const struct sip_msg *resp)
{
	struct cbctx *c = arg;

	(void)resp;
	if (status == 200 || status == 202)
		LOGI("sms: RP reply for MR=%u accepted by the network (%d)", c->mr, status);
	else if (status)
		LOGW("sms: RP reply for MR=%u answered %d", c->mr, status);
	else
		LOGW("sms: RP reply for MR=%u got no answer", c->mr);
	cb_free(c->sr, c);
}

/* RP-ACK (cause 0) or RP-ERROR to the network for an RP-DATA we received */
static void send_rp_reply(struct smsrelay *sr, const char *ruri, const char *in_reply_to, uint8_t mr, int cause)
{
	uint8_t body[4];
	size_t n;
	char extra[400], cid[48];
	struct smsrelay_gm_req q;
	struct cbctx *c;
	int rc;

	if (!ruri || !ruri[0]) {
		LOGW("sms: no address to send the RP reply for MR=%u to", mr);
		return;
	}
	if (cause) {
		rp_build_error(mr, (uint8_t)cause, body);
		n = 4;
	} else {
		rp_build_ack(mr, body);
		n = 2;
	}
	snprintf(extra, sizeof(extra), SMS_GM_EXTRA "%s%s%s", in_reply_to && in_reply_to[0] ? "In-Reply-To: " : "",
		 in_reply_to && in_reply_to[0] ? in_reply_to : "", in_reply_to && in_reply_to[0] ? "\r\n" : "");
	new_call_id(cid, sizeof(cid));
	memset(&q, 0, sizeof(q));
	q.ruri = ruri;
	q.call_id = cid;
	q.extra = extra;
	q.content_type = SMS_CT;
	q.body = body;
	q.body_len = n;
	c = cb_new(sr, CB_RP_REPLY, 0, mr);
	if (!c) {
		set_err(sr, "out of memory sending the RP reply");
		return;
	}
	LOGI("sms: sending %s for MR=%u to %s", cause ? "RP-ERROR" : "RP-ACK", mr, ruri);
	rc = sr->ops.send(sr->ops.ctx, &q, rp_reply_done, c);
	if (rc) {
		LOGW("sms: cannot send the RP reply for MR=%u (%d)", mr, rc);
		set_err(sr, "cannot send the RP reply (%d)", rc);
		cb_free(sr, c);
	}
}

/* ------------------------------------------------------------------ */
/* MT: network -> LAN                                                  */

/* what goes to the LAN clients */
struct lan_msg {
	char user[SMSFMT_USER_MAX], disp[SMSFMT_DISP_MAX];
	char extra[768];
	char text[TP_MAX_TEXT + 160];
	const uint8_t *bin;	/* application/octet-stream alternative for clients that Accept it */
	size_t bin_len;
	char peer[TP_ADDR_MAX];
};

static void hdr_ts(struct buf *b, const struct tp_scts *t, bool with_date)
{
	char s[48];

	if (!t->valid)
		return;
	if (with_date && !smsfmt_date(t->epoch, s, sizeof(s)))
		buf_printf(b, "Date: %s\r\n", s);
	if (!smsfmt_iso(t, s, sizeof(s)))
		buf_printf(b, "X-SMS-Timestamp: %s\r\n", s);
}

static void build_deliver(const struct rp_data *rd, const struct tp_sms *s, bool prefix, struct lan_msg *m)
{
	struct buf b;
	char smsc[32], qs[SMSFMT_DISP_MAX * 2], hx[HEX_EXCERPT * 2 + 1];
	char pre[24] = "";
	size_t nh;

	memset(m, 0, sizeof(*m));
	snprintf(m->peer, sizeof(m->peer), "%s", s->addr.str);
	smsfmt_sender(&s->addr, m->user, sizeof(m->user), m->disp, sizeof(m->disp));
	buf_init_fixed(&b, m->extra, sizeof(m->extra));
	hdr_ts(&b, &s->scts, true);
	if (!rp_addr_to_str(&rd->oa, smsc, sizeof(smsc)))
		buf_printf(&b, "X-SMS-SMSC: %s\r\n", smsc);
	if (s->msg_class >= 0)
		buf_printf(&b, "X-SMS-Class: %d\r\n", s->msg_class);
	if (s->concat.present)
		buf_printf(&b, "X-SMS-Concat: ref=%u;seq=%u;total=%u\r\n", s->concat.ref, s->concat.seq, s->concat.total);
	if (s->addr.alnum) {
		smsfmt_quote_safe(s->addr.str, qs, sizeof(qs));
		buf_printf(&b, "X-SMS-Sender: %s\r\n", qs);
	}
	if (!buf_ok(&b))
		m->extra[0] = 0;	/* cannot happen with these sizes; drop the optional headers rather than send a cut one */
	if (prefix && s->concat.present && s->concat.total > 1)
		snprintf(pre, sizeof(pre), "(%u/%u) ", s->concat.seq, s->concat.total);
	if (s->has_text) {
		if (s->text_len)
			snprintf(m->text, sizeof(m->text), "%s%s", pre, s->text);
		else if (s->mwi)
			snprintf(m->text, sizeof(m->text), "%s(message waiting indication: %s %s)", pre,
				 s->mwi_type == 0 ? "voicemail" : s->mwi_type == 1 ? "fax" : s->mwi_type == 2 ? "email" : "other",
				 s->mwi_active ? "set" : "cleared");
		else
			snprintf(m->text, sizeof(m->text), "%s(empty message)", pre);
		return;
	}
	nh = s->data_len > HEX_EXCERPT ? HEX_EXCERPT : s->data_len;
	hex_encode(s->data, nh, hx);
	snprintf(m->text, sizeof(m->text), "%s[binary SMS, %zu bytes, data coding 0x%02x] %s%s", pre, s->data_len, s->dcs, hx,
		 nh < s->data_len ? "... (truncated)" : "");
	m->bin = s->data;
	m->bin_len = s->data_len;
}

static void build_report(const struct rp_data *rd, const struct tp_status_report *r, struct lan_msg *m)
{
	struct buf b;
	char smsc[32], what[96];

	memset(m, 0, sizeof(*m));
	snprintf(m->peer, sizeof(m->peer), "%s", r->ra.str);
	smsfmt_sender(&r->ra, m->user, sizeof(m->user), m->disp, sizeof(m->disp));
	if (tp_status_is_success(r->st))
		snprintf(what, sizeof(what), "delivered");
	else if (!tp_status_is_final(r->st))
		snprintf(what, sizeof(what), "pending, the network is still trying (status 0x%02x)", r->st);
	else
		snprintf(what, sizeof(what), "FAILED (status 0x%02x)", r->st);
	snprintf(m->text, sizeof(m->text), "[Delivery report] SMS to %s: %s", r->ra.str, what);
	buf_init_fixed(&b, m->extra, sizeof(m->extra));
	hdr_ts(&b, &r->dt, true);
	if (!rp_addr_to_str(&rd->oa, smsc, sizeof(smsc)))
		buf_printf(&b, "X-SMS-SMSC: %s\r\n", smsc);
	buf_printf(&b, "X-SMS-Report: mr=%u;status=0x%02x;final=%s\r\n", r->mr, r->st, tp_status_is_final(r->st) ? "yes" : "no");
	if (!buf_ok(&b))
		m->extra[0] = 0;
}

static void mt_free(struct mt_job *j)
{
	struct smsrelay *sr = j->sr;
	struct mt_job **pp;

	for (pp = &sr->mt; *pp; pp = &(*pp)->next) {
		if (*pp == j) {
			*pp = j->next;
			break;
		}
	}
	sr->mt_n--;
	ev_timer_free(j->timer);
	free(j);
}

/* all forks answered, or the wait ran out: reply to the network and settle the books */
static void mt_finish(struct mt_job *j, bool timed_out)
{
	struct smsrelay *sr = j->sr;
	struct dedup *d;
	int cause = 0, i, nok = j->nok_b > j->nok_c ? j->nok_b : j->nok_c;

	if (j->finished)
		return;
	j->finished = true;
	sr->mt_active--;
	ev_timer_free(j->timer);
	j->timer = NULL;
	if (timed_out) {
		for (i = 0; i < 2; i++) {
			if (j->fork[i]) {
				lan_fork_detach(j->fork[i]);
				j->fork[i] = NULL;
				j->live--;
			}
		}
	}
	if (j->fork_err && j->started == 0) {
		cause = RP_CAUSE_TEMP_FAILURE;
		set_err(sr, "cannot start delivery to the LAN: %s", strerror(j->fork_err));
		LOGW("sms: cannot start delivery to the LAN (%s), answering RP-ERROR %d", strerror(j->fork_err), cause);
		sr->c.mt_errors++;
	} else if (nok > 0) {
		if (j->is_report)
			LOGI("sms: delivery report notice delivered to %d LAN client(s)", nok);
		else
			LOGI("sms: MT from %s len=%zu delivered to %d LAN client(s)", j->peer, j->text_len, nok);
		if (!j->is_report)
			sr->c.mt_delivered++;
	} else if (j->started == 0) {
		sr->c.mt_lost_no_client++;
		LOGW("sms: LOST %s from %s: no LAN client is registered. Text: %s", j->is_report ? "delivery report" : "message",
		     j->peer, j->text);
		set_err(sr, "SMS from %s lost: no LAN client registered", j->peer);
		if (sr->cfg.lost_policy == SMSRELAY_LOST_RPERROR22)
			cause = RP_CAUSE_MEMORY_EXCEEDED;
	} else {
		sr->c.mt_lost_failed++;
		LOGW("sms: LOST %s from %s: no LAN client accepted it%s. Text: %s", j->is_report ? "delivery report" : "message",
		     j->peer, timed_out ? " in time" : "", j->text);
		set_err(sr, "SMS from %s lost: no LAN client accepted it", j->peer);
	}
	d = dd_find(sr, j->key);
	if (d) {
		d->done = true;
		d->cause = cause;
		d->t_ms = ev_now_ms();
	}
	send_rp_reply(sr, j->ruri, j->call_id, j->mr, cause);
	if (j->live == 0)
		mt_free(j);
}

static void mt_timeout(void *arg)
{
	mt_finish(arg, true);
}

static void mt_fork_cb(struct lan_fork *f, struct lan_fork_event *ev, void *arg)
{
	struct mt_fork *mf = arg;
	struct mt_job *j = mf->job;

	(void)f;
	switch (ev->type) {
	case LAN_FORK_BRANCH_FINAL:
		if (ev->cause == LAN_BR_RESPONSE && ev->status >= 200 && ev->status < 300)
			j->nok_b++;
		break;
	case LAN_FORK_COMPLETE:
		j->nok_c += ev->nok;
		if (++j->complete == j->started)
			mt_finish(j, false);
		break;
	case LAN_FORK_DONE:
		j->fork[mf->idx] = NULL;
		if (--j->live == 0 && j->finished)
			mt_free(j);
		break;
	default:
		break;
	}
}

static bool accepts_octets(const struct reg_binding *b)
{
	return b->accept[0] && reg_accepts(b, "application/octet-stream");
}

/* start the LAN fork(s). Returns the number started; *err = errno of a hard failure (not ENOENT) */
static int mt_start_forks(struct mt_job *j, const struct lan_msg *m)
{
	struct smsrelay *sr = j->sr;
	struct registrar *rg;
	struct lan_req q;
	struct lan_fork_opts o;
	reg_id_t *ex = NULL;
	unsigned nb;
	int g, n = 0;

	if (!sr->lan)		/* LAN side down: nobody to deliver to */
		return 0;
	rg = lan_registrar(sr->lan);
	nb = reg_count(rg);

	memset(&q, 0, sizeof(q));
	q.method = "MESSAGE";
	q.from_user = m->user;
	q.from_display = m->disp[0] ? m->disp : NULL;
	q.extra = m->extra;
	if (m->bin && nb) {
		ex = calloc(nb, sizeof(*ex));
		if (!ex) {
			j->fork_err = ENOMEM;
			return 0;
		}
	}
	for (g = 0; g < (m->bin ? 2 : 1); g++) {
		const struct reg_binding *b = NULL;
		struct lan_fork *f;
		unsigned nex = 0;

		memset(&o, 0, sizeof(o));
		if (m->bin) {
			/* group 0: octet-stream to the clients that declared Accept for it; group 1: the text notice to the rest */
			while ((b = reg_next(rg, b ? b->id : REG_ID_NONE)) && nex < nb)
				if (accepts_octets(b) == (g == 1))
					ex[nex++] = b->id;
			o.exclude = ex;
			o.nexclude = nex;
			q.content_type = g == 0 ? "application/octet-stream" : "text/plain; charset=utf-8";
			q.body = g == 0 ? m->bin : (const uint8_t *)m->text;
			q.body_len = g == 0 ? m->bin_len : strlen(m->text);
		} else {
			q.content_type = "text/plain; charset=utf-8";
			q.body = (const uint8_t *)m->text;
			q.body_len = strlen(m->text);
		}
		j->mf[n].job = j;
		j->mf[n].idx = n;
		f = lan_fork_request(sr->lan, &q, &o, mt_fork_cb, &j->mf[n], NULL);
		if (!f) {
			if (errno != ENOENT)
				j->fork_err = errno;
			continue;
		}
		j->fork[n] = f;
		n++;
	}
	free(ex);
	return n;
}

static void mt_reply_err(struct smsrelay *sr, const struct sip_msg *req, uint8_t mr, int cause);

/* Request-URI of the reply to the network: P-Asserted-Identity, else From (as the network accepted); and the Call-ID to answer to */
static void req_origin(const struct sip_msg *req, char *ruri, size_t rn, char *call_id, size_t cn)
{
	const char *pai = sip_hdr(req, "P-Asserted-Identity", 0), *from = sip_hdr(req, "From", 0), *cid = sip_hdr(req, "Call-ID", 0);

	snprintf(call_id, cn, "%s", cid ? cid : "");
	ruri[0] = 0;
	if (!pai || sip_uri_of(pai, ruri, rn))
		if (!from || sip_uri_of(from, ruri, rn))
			ruri[0] = 0;
}

static void mt_deliver_o(struct smsrelay *sr, const char *ruri, const char *call_id, uint8_t mr, uint64_t key,
			 const struct lan_msg *m, bool is_report)
{
	struct mt_job *j;
	struct dedup *d;

	if (sr->mt_active >= sr->cfg.mt_max_pending || sr->mt_n >= 4 * sr->cfg.mt_max_pending) {
		LOGW("sms: too many incoming messages in flight, answering RP-ERROR %d", RP_CAUSE_CONGESTION);
		sr->c.mt_errors++;
		goto refuse;
	}
	j = calloc(1, sizeof(*j));
	if (!j)
		goto refuse;
	j->sr = sr;
	j->mr = mr;
	j->key = key;
	j->is_report = is_report;
	snprintf(j->peer, sizeof(j->peer), "%s", m->peer);
	j->text_len = strlen(m->text);
	snprintf(j->text, sizeof(j->text), "%s", m->text);
	snprintf(j->call_id, sizeof(j->call_id), "%s", call_id);
	snprintf(j->ruri, sizeof(j->ruri), "%s", ruri);
	j->next = sr->mt;
	sr->mt = j;
	sr->mt_n++;
	sr->mt_active++;
	j->timer = ev_timer_new(mt_timeout, j);
	j->started = mt_start_forks(j, m);
	j->live = j->started;
	if (j->started == 0 || !j->timer) {
		mt_finish(j, false);
		return;
	}
	ev_timer_set(j->timer, sr->cfg.lan_wait_ms);
	return;
refuse:
	d = dd_find(sr, key);
	if (d)
		d->used = false;
	send_rp_reply(sr, ruri, call_id, mr, RP_CAUSE_CONGESTION);
}

static void mt_deliver(struct smsrelay *sr, const struct sip_msg *req, const struct rp_data *rd, uint64_t key,
		       const struct lan_msg *m, bool is_report)
{
	char ruri[256], cid[128];

	req_origin(req, ruri, sizeof(ruri), cid, sizeof(cid));
	mt_deliver_o(sr, ruri, cid, rd->mr, key, m, is_report);
}

static void mt_reply_err(struct smsrelay *sr, const struct sip_msg *req, uint8_t mr, int cause)
{
	const char *p = sip_hdr(req, "P-Asserted-Identity", 0), *f = sip_hdr(req, "From", 0);
	char ruri[256] = "";

	if ((!p || sip_uri_of(p, ruri, sizeof(ruri))) && f)
		sip_uri_of(f, ruri, sizeof(ruri));
	send_rp_reply(sr, ruri, sip_hdr(req, "Call-ID", 0), mr, cause);
}

/* ---- WAP push: binary SMS-DELIVER with port addressing to the WAP push ports (or a later segment of one) ---- */

static bool is_wap_push(const struct smsrelay *sr, const struct tp_sms *s)
{
	if (s->has_text || s->mti != 0)
		return false;
	if (s->ports.present)
		return s->ports.dst == 2948 || s->ports.dst == 2949;
	/* port addressing may be sent in the first segment only: the rest belongs to a message we are assembling */
	return s->concat.present && wappush_pending(sr->wp, s->addr.str, s->concat.ref, s->concat.total);
}

static void on_push_segment(struct smsrelay *sr, const struct sip_msg *req, const struct rp_data *rd, uint64_t key,
			    const struct tp_sms *s)
{
	struct dedup *d;
	unsigned port = s->ports.present ? s->ports.dst : 0;

	sr->c.mt_push_segments++;
	LOGI("sms: WAP push segment from %s on port %u (%zu bytes%s)", s->addr.str, port, s->data_len,
	     s->concat.present ? ", concatenated" : "");
	/* a handset acknowledges the SMS whatever the WAP client does with it: RP-ACK now, a repeat is answered from the cache */
	d = dd_add(sr, key);
	d->done = true;
	d->cause = 0;
	mt_reply_err(sr, req, rd->mr, 0);
	if (port == 2949) {
		LOGI("sms: secure WAP push (port 2949, WTLS) from %s is not supported, dropped", s->addr.str);
		return;
	}
	wappush_segment(sr->wp, s->addr.str, port, s->concat.present ? s->concat.ref : 0,
			s->concat.present ? s->concat.total : 1, s->concat.present ? s->concat.seq : 1, s->data, s->data_len);
}

/* ---- the store: an incoming SMS ---- */

/* meta of STORE_SMS: bytes oa (the RP originator), u8 mr, bytes TPDU: enough to rebuild exactly the MESSAGE of the live path */
static size_t sms_pack(const struct rp_data *rd, uint8_t *out, size_t cap)
{
	struct pkw w;

	pkw_init(&w, out, cap);
	pkw_bytes(&w, rd->oa.b, rd->oa.len);
	pkw_u8(&w, rd->mr);
	pkw_bytes(&w, rd->ud, rd->ud_len);
	return w.ovf ? 0 : w.len;
}

/* rebuild the message for the LAN. 0, -1 (undecodable). *sp (malloc) must outlive m (m->bin points into it); free it. */
static int sms_render(const uint8_t *meta, size_t n, bool prefix, struct lan_msg *m, struct tp_sms **sp)
{
	struct pkr r;
	struct rp_data rd;
	const uint8_t *oa, *ud;
	size_t oal, udl;

	pkr_init(&r, meta, n);
	oa = pkr_bytes(&r, &oal);
	memset(&rd, 0, sizeof(rd));
	rd.mr = pkr_u8(&r);
	ud = pkr_bytes(&r, &udl);
	if (r.bad || oal > RP_ADDR_MAX || udl < 1)
		return -1;
	if (oal) {
		memcpy(rd.oa.b, oa, oal);
		rd.oa.len = (uint8_t)oal;
	}
	rd.ud = ud;
	rd.ud_len = udl;
	*sp = NULL;
	if ((ud[0] & 3) == 2) {
		struct tp_status_report sre;

		if (tp_decode_status_report(ud, udl, &sre))
			return -1;
		build_report(&rd, &sre, m);
		return 0;
	} else if ((ud[0] & 3) == 0) {
		struct tp_sms *s = malloc(sizeof(*s));

		if (!s)
			return -1;
		if (tp_decode_deliver(ud, udl, s)) {
			free(s);
			return -1;
		}
		build_deliver(&rd, s, prefix, m);
		*sp = s;
		return 0;
	}
	return -1;
}

/* the live path for a message the store did not take (the RP-ACK follows the LAN delivery, as without a store) */
static void st_fallback(struct st_job *j)
{
	struct smsrelay *sr = j->sr;
	struct lan_msg *m = malloc(sizeof(*m));
	struct tp_sms *s = NULL;

	sr->c.mt_store_fallback++;
	if (m && !sms_render(j->meta, j->meta_len, sr->cfg.concat_prefix, m, &s)) {
		mt_deliver_o(sr, j->ruri, j->call_id, j->mr, j->key, m, j->is_report);
	} else {
		sr->c.mt_errors++;
		send_rp_reply(sr, j->ruri, j->call_id, j->mr, RP_CAUSE_TEMP_FAILURE);
	}
	free(s);
	free(m);
}

static void st_job_free(struct st_job *j)
{
	struct st_job **pp;

	for (pp = &j->sr->sj; *pp; pp = &(*pp)->next)
		if (*pp == j) {
			*pp = j->next;
			break;
		}
	j->sr->sj_n--;
	ev_timer_free(j->timer);
	free(j);
}

static void st_added(void *arg, int status, uint64_t seq, const struct store_add *a)
{
	struct st_job *j = arg;
	struct smsrelay *sr = j->sr;
	struct dedup *d;

	(void)a;
	ev_timer_cancel(j->timer);
	if (status == 0) {
		sr->c.mt_stored++;
		LOGI("sms: stored as item %llu, acknowledging to the network", (unsigned long long)seq);
		d = dd_find(sr, j->key);
		if (d) {
			d->done = true;
			d->cause = 0;
			d->t_ms = ev_now_ms();
		}
		send_rp_reply(sr, j->ruri, j->call_id, j->mr, 0);
	} else {
		LOGW("sms: cannot store the message (%s), delivering live", strerror(-status));
		st_fallback(j);
	}
	st_job_free(j);
}

static void st_timeout(void *arg)
{
	struct st_job *j = arg;

	LOGW("sms: the store did not confirm within %u ms, delivering live", j->sr->cfg.store_ack_wait_ms);
	store_abandon(j->sr->ops.store, j->seq);
	st_fallback(j);
	st_job_free(j);
}

/*
 * Incoming SMS into the store. true: taken (the RP-ACK follows when the append is durable, or the live path after
 * store_ack_wait_ms / on failure); false: the caller delivers live as without a store.
 */
static bool sms_store_try(struct smsrelay *sr, const struct sip_msg *req, const struct rp_data *rd, uint64_t key, bool is_report,
			  const char *peer, bool dd_exists)
{
	struct st_job *j;
	struct store_add a;
	uint8_t meta[320];
	size_t ml;
	uint64_t seq;

	if (!sr->ops.store || !store_usable(sr->ops.store) || sr->sj_n >= sr->cfg.mt_max_pending)
		return false;
	if (!store_find_dedup(sr->ops.store, STORE_SMS, key, 600, &seq)) {
		/* a retransmission after the cache forgot it (or after a restart): it is in the store, acknowledge again */
		sr->c.mt_duplicates++;
		LOGI("sms: RP-DATA MR=%u is already stored as item %llu, acknowledging again", rd->mr, (unsigned long long)seq);
		mt_reply_err(sr, req, rd->mr, 0);
		return true;
	}
	ml = sms_pack(rd, meta, sizeof(meta));
	if (!ml)
		return false;
	j = calloc(1, sizeof(*j));
	if (!j)
		return false;
	j->sr = sr;
	j->mr = rd->mr;
	j->key = key;
	j->is_report = is_report;
	memcpy(j->meta, meta, ml);
	j->meta_len = ml;
	req_origin(req, j->ruri, sizeof(j->ruri), j->call_id, sizeof(j->call_id));
	j->timer = ev_timer_new(st_timeout, j);
	memset(&a, 0, sizeof(a));
	a.type = STORE_SMS;
	a.peer = peer;
	a.dedup = key;
	a.meta = meta;
	a.meta_len = ml;
	a.owner = sr;
	if (!j->timer || store_add(sr->ops.store, &a, st_added, j, &j->seq)) {
		ev_timer_free(j->timer);
		free(j);
		return false;
	}
	j->next = sr->sj;
	sr->sj = j;
	sr->sj_n++;
	if (!dd_exists)
		dd_add(sr, key);
	ev_timer_set(j->timer, sr->cfg.store_ack_wait_ms);
	return true;
}

/* delivery of a stored item to ONE binding (store handler) */
static int st_deliver(void *ctx, const struct store_item *it, reg_id_t b, uint32_t features, void (*done)(void *, int), void *arg)
{
	struct smsrelay *sr = ctx;
	struct lan_msg *m;
	struct tp_sms *s = NULL;
	const struct reg_binding *bb;
	struct lan_seq_cfg c;
	char extra[900];
	const char *txt[1];
	int rc;

	(void)features;
	if (!sr->lan)
		return -ENOENT;
	bb = reg_find(lan_registrar(sr->lan), b);
	if (!bb)
		return -ENOENT;
	if (cs_is_meta(it->meta, it->meta_len))
		return cs_deliver_item(sr, it, b, done, arg);
	m = malloc(sizeof(*m));
	if (!m)
		return -ENOMEM;
	if (sms_render(it->meta, it->meta_len, sr->cfg.concat_prefix, m, &s)) {
		LOGW("sms: stored item %llu cannot be decoded, skipped", (unsigned long long)it->seq);
		free(m);
		return 1;
	}
	snprintf(extra, sizeof(extra), "%sX-IMSD-Seq: %llu\r\n", m->extra, (unsigned long long)it->seq);
	memset(&c, 0, sizeof(c));
	c.from_user = m->user;
	c.from_display = m->disp[0] ? m->disp : NULL;
	c.extra = extra;
	c.include = &b;
	c.ninclude = 1;
	c.include_set = true;
	c.done = done;
	c.arg = arg;
	if (m->bin && accepts_octets(bb)) {
		c.content_type = "application/octet-stream";
		c.body = m->bin;
		c.body_len = m->bin_len;
	} else {
		txt[0] = m->text;
		c.text = txt;
		c.n = 1;
	}
	rc = lan_seq_start(sr->seqs, &c);
	free(s);
	free(m);
	return rc;
}

static int st_carbon_deliver(void *ctx, const struct store_item *it, reg_id_t b, uint32_t features, void (*done)(void *, int),
			     void *arg)
{
	struct smsrelay *sr = ctx;
	struct lan_seq_cfg c;
	struct lan_pieces lp;
	char id[20], ts[48], dest[24], user[96] = "", extra[512], *text;
	unsigned nseg;
	reg_id_t sender;
	const uint8_t *t;
	size_t tl;
	int rc;

	(void)features;
	if (!sr->lan)
		return -ENOENT;
	carbon_meta_parse(it->meta, it->meta_len, id, ts, dest, &nseg, &sender, &t, &tl);
	text = strndup((const char *)t, tl);
	if (!text)
		return -ENOMEM;
	if (sr->ops.own_number)
		sr->ops.own_number(sr->ops.ctx, user, sizeof(user));
	if (!user[0])
		snprintf(user, sizeof(user), "imsd");
	if (carbon_extra(id, dest, nseg, ts, it->seq, extra, sizeof(extra)) >= sizeof(extra) ||
	    lan_pieces_make(&lp, text, tl, sr->cfg.text_split)) {
		free(text);
		return -ENOMEM;
	}
	memset(&c, 0, sizeof(c));
	c.from_user = user;
	c.extra = extra;
	c.part_hdr = "X-SMS-Part";
	c.text = lp.text;
	c.n = lp.n;
	c.include = &b;
	c.ninclude = 1;
	c.include_set = true;
	c.done = done;
	c.arg = arg;
	rc = lan_seq_start(sr->seqs, &c);
	lan_pieces_free(&lp);
	free(text);
	return rc;
}

static void st_abort(void *ctx, void *arg)
{
	struct smsrelay *sr = ctx;

	lan_seqs_abort(sr->seqs, arg);
}

static void on_rp_data(struct smsrelay *sr, const struct sip_msg *req)
{
	struct rp_data rd;
	struct dedup *d;
	uint64_t key;
	struct rp_info ri;
	struct lan_msg *m;

	if (rp_parse(req->body, req->body_len, &ri))
		return;
	sr->c.mt_received++;
	if (rp_parse_data(req->body, req->body_len, &rd)) {
		LOGW("sms: malformed RP-DATA (MR=%u, %zu bytes), answering RP-ERROR %d", ri.mr, req->body_len,
		     RP_CAUSE_INVALID_MANDATORY);
		set_err(sr, "malformed RP-DATA");
		sr->c.mt_errors++;
		mt_reply_err(sr, req, ri.mr, RP_CAUSE_INVALID_MANDATORY);
		return;
	}
	key = dd_key(&rd);
	d = dd_find(sr, key);
	if (d) {
		sr->c.mt_duplicates++;
		if (!d->done) {
			LOGI("sms: retransmitted RP-DATA MR=%u while the first copy is still being delivered, ignored", rd.mr);
			return;
		}
		LOGI("sms: retransmitted RP-DATA MR=%u, answering again without delivering", rd.mr);
		mt_reply_err(sr, req, rd.mr, d->cause);
		return;
	}
	m = malloc(sizeof(*m));
	if (!m) {
		mt_reply_err(sr, req, rd.mr, RP_CAUSE_TEMP_FAILURE);
		return;
	}
	if (rd.ud_len < 1) {
		goto bad;
	} else if ((rd.ud[0] & 3) == 2) {		/* SMS-STATUS-REPORT */
		struct tp_status_report sre;

		if (tp_decode_status_report(rd.ud, rd.ud_len, &sre))
			goto bad;
		sr->c.mt_reports++;
		LOGI("sms: status report from %s for MR=%u: status 0x%02x", sre.ra.str, sre.mr, sre.st);
		dd_add(sr, key);
		if (!sr->cfg.delivery_reports) {
			d = dd_find(sr, key);
			d->done = true;
			mt_reply_err(sr, req, rd.mr, 0);
		} else if (sms_store_try(sr, req, &rd, key, true, sre.ra.str, true)) {
			/* acknowledged when stored */
		} else {
			build_report(&rd, &sre, m);
			mt_deliver(sr, req, &rd, key, m, true);
		}
	} else if ((rd.ud[0] & 3) == 0) {		/* SMS-DELIVER */
		struct tp_sms *s = malloc(sizeof(*s));
		int rc;

		if (!s) {
			free(m);
			mt_reply_err(sr, req, rd.mr, RP_CAUSE_TEMP_FAILURE);
			return;
		}
		rc = tp_decode_deliver(rd.ud, rd.ud_len, s);
		if (rc) {
			LOGW("sms: cannot decode the SMS-DELIVER (%s)", tp_strerror(rc));
			free(s);
			goto bad;
		}
		if (is_wap_push(sr, s)) {
			on_push_segment(sr, req, &rd, key, s);
			free(s);
			free(m);
			return;
		}
		LOGI("sms: MT from %s len=%zu%s", s->addr.str, s->has_text ? s->text_len : s->data_len,
		     s->concat.present ? " (concatenated part)" : "");
		if (sms_store_try(sr, req, &rd, key, false, s->addr.str, false)) {
			free(s);
			free(m);
			return;
		}
		build_deliver(&rd, s, sr->cfg.concat_prefix, m);
		dd_add(sr, key);
		mt_deliver(sr, req, &rd, key, m, false);	/* m->bin points into s: delivered (forks started) before s is freed */
		free(s);
	} else {
		goto bad;
	}
	free(m);
	return;
bad:
	set_err(sr, "undecodable SMS TPDU");
	sr->c.mt_errors++;
	LOGW("sms: unsupported or undecodable TPDU (%zu bytes), answering RP-ERROR %d", rd.ud_len, RP_CAUSE_PROTOCOL_ERROR);
	free(m);
	mt_reply_err(sr, req, rd.mr, RP_CAUSE_PROTOCOL_ERROR);
}

/* ------------------------------------------------------------------ */
/* MO: LAN -> network                                                  */

static void mo_start_next(struct smsrelay *sr);
static void mo_send_seg(struct mo_msg *m);

static void mo_free(struct mo_msg *m)
{
	struct smsrelay *sr = m->sr;
	struct mo_msg **pp, *prev = NULL;

	for (pp = &sr->q_head; *pp; prev = *pp, pp = &(*pp)->next) {
		if (*pp == m) {
			*pp = m->next;
			if (sr->q_tail == m)
				sr->q_tail = prev;
			break;
		}
	}
	sr->qn--;
	if (m->st)
		txn_server_set_cb(m->st, NULL, NULL);
	ev_timer_free(m->dl_timer);
	ev_timer_free(m->seg_timer);
	free(m->pdu);
	free(m->text);
	free(m);
}

static void mo_srv_cb(struct txn_server *st, enum txn_srv_event ev, void *arg)
{
	struct mo_msg *m = arg;

	(void)st;
	if (ev == TXN_SRV_TERMINATED) {
		m->st = NULL;
		m->replied = true;
	}
}

/* ---- carbon copies ---- */

static void carbon_done(void *arg, int nok)
{
	struct smsrelay *sr = arg;

	if (nok > 0)
		sr->c.carbons_sent++;
	else
		sr->c.carbons_failed++;
}

/* the headers of a carbon copy; the id, the number of segments and the time are fixed when the item is made (a redelivery is identical) */
static size_t carbon_extra(const char *id, const char *dest, unsigned nseg, const char *ts, uint64_t seq, char *extra, size_t n)
{
	size_t e = (size_t)snprintf(extra, n, "X-IMSD-Carbon: sent\r\nX-IMSD-Carbon-ID: %s\r\nX-IMSD-Peer: %s\r\nX-SMS-Parts: %u\r\n", id, dest,
				    nseg);

	if (ts[0] && e < n)
		e += (size_t)snprintf(extra + e, n - e, "X-SMS-Timestamp: %s\r\n", ts);
	if (seq && e < n)
		e += (size_t)snprintf(extra + e, n - e, "X-IMSD-Seq: %llu\r\n", (unsigned long long)seq);
	return e;
}

/* the copy as live delivery to the carbon devices except the sender (no store, or the store failed) */
static void carbon_live(struct smsrelay *sr, const char *id, const char *dest, const char *text, unsigned nseg, const char *ts,
			reg_id_t sender)
{
	struct lan_seq_cfg c;
	struct lan_pieces lp;
	reg_id_t all[LAN_SELECT_MAX], ids[LAN_SELECT_MAX];
	char user[96] = "", extra[512];
	unsigned n, i, k = 0;

	if (!sr->lan)
		return;
	n = lan_select(sr->lan, REG_F_CARBONS, 0, all, LAN_SELECT_MAX);
	for (i = 0; i < n; i++)
		if (all[i] != sender || sender == REG_ID_NONE)
			ids[k++] = all[i];
	if (!k)
		return;
	if (sr->ops.own_number)
		sr->ops.own_number(sr->ops.ctx, user, sizeof(user));
	if (!user[0])
		snprintf(user, sizeof(user), "imsd");
	if (carbon_extra(id, dest, nseg, ts, 0, extra, sizeof(extra)) >= sizeof(extra) ||
	    lan_pieces_make(&lp, text, strlen(text), sr->cfg.text_split))
		return;
	memset(&c, 0, sizeof(c));
	c.from_user = user;
	c.extra = extra;
	c.part_hdr = "X-SMS-Part";
	c.text = lp.text;
	c.n = lp.n;
	c.include = ids;
	c.ninclude = k;
	c.include_set = true;
	c.done = carbon_done;
	c.arg = sr;
	if (lan_seq_start(sr->seqs, &c))
		sr->c.carbons_failed++;
	lan_pieces_free(&lp);
}

/* CARBON_SMS meta: u8 version 1, u8 nseg, str id, str ts, str dest, u32 sender binding (for the live fallback), bytes text */
static void carbon_meta_parse(const uint8_t *meta, size_t n, char *id, char *ts, char *dest, unsigned *nseg, reg_id_t *sender,
			      const uint8_t **text, size_t *tl)
{
	struct pkr r;

	pkr_init(&r, meta, n);
	pkr_u8(&r);
	*nseg = pkr_u8(&r);
	pkr_str(&r, id, 20);
	pkr_str(&r, ts, 48);
	pkr_str(&r, dest, 24);
	*sender = pkr_u32(&r);
	*text = pkr_bytes(&r, tl);
	if (r.bad || !*text) {
		id[0] = ts[0] = dest[0] = 0;
		*text = (const uint8_t *)"";
		*tl = 0;
	}
}

static void carbon_store_cb(void *arg, int status, uint64_t seq, const struct store_add *a)
{
	struct smsrelay *sr = arg;

	(void)seq;
	if (status == 0) {
		sr->c.carbons_stored++;
		return;
	}
	/* not stored: live delivery as before */
	{
		char id[20], ts[48], dest[24], *text;
		unsigned nseg;
		reg_id_t sender;
		const uint8_t *t;
		size_t tl;

		carbon_meta_parse(a->meta, a->meta_len, id, ts, dest, &nseg, &sender, &t, &tl);
		text = strndup((const char *)t, tl);
		if (text) {
			LOGW("sms: the carbon copy could not be stored (%s), delivering live", strerror(-status));
			carbon_live(sr, id, dest, text, nseg, ts, sender);
			free(text);
		}
	}
}

static void carbon_send(struct smsrelay *sr, const char *dest, const char *text, unsigned nseg, const struct tp_scts *scts, reg_id_t sender)
{
	char ts[48] = "", id[17];
	uint8_t meta[2400];
	struct pkw w;
	struct store_add a;
	uint64_t ex[1];
	size_t tl;

	if (!sr->cfg.carbons || !text)
		return;
	if (!scts || smsfmt_iso(scts, ts, sizeof(ts))) {
		ts[0] = 0;
		if (time(NULL) >= 1600000000)
			lan_text_iso((int64_t)time(NULL), ts, sizeof(ts));
	}
	rnd_token(id, 16);
	tl = strlen(text);
	if (sr->ops.store && store_usable(sr->ops.store) && tl <= sizeof(meta) - 120) {
		pkw_init(&w, meta, sizeof(meta));
		pkw_u8(&w, 1);
		pkw_u8(&w, (uint8_t)nseg);
		pkw_str(&w, id);
		pkw_str(&w, ts);
		pkw_str(&w, dest);
		pkw_u32(&w, sender);
		pkw_bytes(&w, text, tl);
		memset(&a, 0, sizeof(a));
		a.type = STORE_CARBON_SMS;
		a.peer = dest;
		a.meta = meta;
		a.meta_len = w.len;
		a.owner = sr;
		if (sr->lan && sender != REG_ID_NONE) {		/* the sender is excluded by identity, also on every redelivery */
			const struct reg_binding *b = reg_find(lan_registrar(sr->lan), sender);
			char ident[96];

			if (b) {
				store_identity(b, ident, sizeof(ident));
				ex[0] = store_hash(ident);
				a.excl = ex;
				a.nexcl = 1;
			}
		}
		if (!w.ovf && !store_add(sr->ops.store, &a, carbon_store_cb, sr, NULL))
			return;
	}
	carbon_live(sr, id, dest, text, nseg, ts, sender);
}

/* final outcome of a message: answer the client (unless the 202 went out), count, log, unlink. start_next false while failing everything */
static void mo_complete(struct mo_msg *m, int status, const char *text, bool start_next)
{
	struct smsrelay *sr = m->sr;
	bool ok = status == 200;
	const char *late = m->late ? " (after the 202 answer)" : "";

	if (ok) {
		sr->c.mo_acked++;
		LOGI("sms: MO to %s len=%zu: %u part(s) acknowledged by the network%s", m->dest, m->text_len, m->nseg, late);
	} else {
		sr->c.mo_failed++;
		set_err(sr, "MO to %s failed: %s", m->dest, text);
		LOGW("sms: MO to %s len=%zu failed: %s%s", m->dest, m->text_len, text, late);
	}
	if (!m->replied && m->st) {
		char hdrs[160] = "", ts[40];

		if (ok) {
			snprintf(hdrs, sizeof(hdrs), "X-SMS-Parts: %u\r\n", m->nseg);
			if (m->have_scts && !smsfmt_iso(&m->scts, ts, sizeof(ts)))
				snprintf(hdrs + strlen(hdrs), sizeof(hdrs) - strlen(hdrs), "X-SMS-Timestamp: %s\r\n", ts);
			lan_reply(m->st, 200, NULL, hdrs);
		} else {
			if (status == 503)
				snprintf(hdrs, sizeof(hdrs), "Retry-After: 30\r\n");
			lan_reply(m->st, status, text, hdrs);
		}
	}
	m->replied = true;
	if (ok)
		carbon_send(sr, m->dest, m->text, m->nseg, m->have_scts ? &m->scts : NULL, m->sender);
	mo_free(m);
	if (start_next)
		mo_start_next(sr);
}

static void mo_fail_all(struct smsrelay *sr, int status, const char *text)
{
	sr->failing = true;
	while (sr->q_head)
		mo_complete(sr->q_head, status, text, false);
	sr->failing = false;
}

static void mo_start_next(struct smsrelay *sr)
{
	if (sr->failing || !sr->q_head || sr->q_head->state != MO_QUEUED)
		return;
	mo_send_seg(sr->q_head);
}

static void mo_deadline(void *arg)
{
	struct mo_msg *m = arg;

	if (m->replied)
		return;
	lan_reply(m->st, 202, "outcome not known yet, see the router log", NULL);
	m->replied = true;
	m->late = true;
	LOGW("sms: MO to %s: no outcome within the reply deadline, answered 202", m->dest);
}

/* failure of the segment in flight -> status for the client */
static void mo_fail_net(struct mo_msg *m, int status, const char *text)
{
	mo_complete(m, status, text, true);
}

static void mo_on_report(struct mo_msg *m, bool err, int cause, const struct tp_scts *scts)
{
	char t[128];

	ev_timer_cancel(m->seg_timer);
	if (err) {
		snprintf(t, sizeof(t), "RP-ERROR from the network: cause %d (%s)", cause, rp_cause_text(cause));
		mo_fail_net(m, rp_cause_temporary(cause) ? 503 : 502, t);
		return;
	}
	if (scts && scts->valid) {
		m->scts = *scts;
		m->have_scts = true;
	}
	if (++m->cur >= m->nseg) {
		mo_complete(m, 200, NULL, true);
		return;
	}
	m->state = MO_QUEUED;
	mo_send_seg(m);
}

static void mo_report_timeout(void *arg)
{
	struct mo_msg *m = arg;
	char t[96];

	snprintf(t, sizeof(t), "no delivery report from the network for part %u/%u", m->cur + 1, m->nseg);
	mo_fail_net(m, 504, t);
}

static void mo_sip_done(void *arg, int status, const struct sip_msg *resp)
{
	struct cbctx *c = arg;
	struct smsrelay *sr = c->sr;
	struct mo_msg *m = sr->q_head;
	uint32_t token = c->token;
	char t[128];

	(void)resp;
	cb_free(sr, c);
	if (!m || m->state != MO_WAIT_SIP || m->token != token)
		return;			/* stale: the message was failed meanwhile */
	LOGD("sms: MO segment %u/%u: SIP answer %d", m->cur + 1, m->nseg, status);
	if (status >= 200 && status < 300) {
		m->state = MO_WAIT_REPORT;
		ev_timer_set(m->seg_timer, sr->cfg.report_timeout_ms);
		if (m->early)
			mo_on_report(m, m->early_err, m->early_cause, &m->early_scts);
		return;
	}
	if (status == 0) {
		mo_fail_net(m, 504, "no answer from the network to the SMS");
		return;
	}
	snprintf(t, sizeof(t), "network answered %d %s", status, sip_reason_phrase(status));
	if (status == 403 || status == 603)
		mo_fail_net(m, 403, t);
	else if (status == 408 || status == 504)
		mo_fail_net(m, 504, t);
	else if (status == 480 || status == 486 || status == 503 || status >= 500)
		mo_fail_net(m, 503, t);
	else
		mo_fail_net(m, 502, t);
}

static void mo_send_seg(struct mo_msg *m)
{
	struct smsrelay *sr = m->sr;
	uint8_t rp[256];
	struct smsrelay_gm_req q;
	struct carrier_val psi;
	struct cbctx *c;
	char extra[400];
	int n, rc;

	if (!sr->ops.registered(sr->ops.ctx)) {
		mo_complete(m, 480, "not registered on the network", true);
		return;
	}
	m->rp_mr = sr->rp_mr++;
	m->early = false;
	n = rp_build_data_ms_n(m->rp_mr, &m->smsc, m->pdu[m->cur].data, m->pdu[m->cur].len, rp, sizeof(rp));
	if (n < 0) {
		mo_complete(m, 502, "cannot build the RP-DATA", true);
		return;
	}
	psi_get(sr, &psi);
	if (!psi.value[0]) {		/* vanished since the MO was accepted */
		mo_complete(m, 503, "no SMS gateway", true);
		return;
	}
	new_call_id(m->call_id, sizeof(m->call_id));
	snprintf(extra, sizeof(extra), "%s%s%s" SMS_GM_EXTRA, sr->cfg.p_preferred_identity[0] ? "P-Preferred-Identity: " : "",
		 sr->cfg.p_preferred_identity, sr->cfg.p_preferred_identity[0] ? "\r\n" : "");
	memset(&q, 0, sizeof(q));
	q.ruri = psi.value;
	q.call_id = m->call_id;
	q.extra = extra;
	q.content_type = SMS_CT;
	q.body = rp;
	q.body_len = (size_t)n;
	m->token = ++sr->token;
	m->state = MO_WAIT_SIP;
	c = cb_new(sr, CB_MO_SEG, m->token, m->rp_mr);
	if (!c) {
		mo_complete(m, 503, "out of memory", true);
		return;
	}
	rc = sr->ops.send(sr->ops.ctx, &q, mo_sip_done, c);
	if (rc) {
		cb_free(sr, c);
		mo_complete(m, rc == -ENOTCONN ? 480 : 503, rc == -ENOTCONN ? "not registered on the network" : "cannot send to the network", true);
		return;
	}
	sr->c.mo_segments_sent++;
	LOGI("sms: MO to %s: sending part %u/%u (RP-MR=%u)", m->dest, m->cur + 1, m->nseg, m->rp_mr);
}

static void on_rp_report(struct smsrelay *sr, const struct sip_msg *req, const struct rp_info *ri)
{
	struct mo_msg *m = sr->q_head;
	const char *irt = sip_hdr(req, "In-Reply-To", 0);
	const uint8_t *tp;
	size_t tpn;
	bool err = ri->mti == RP_ERROR_N_MS;
	struct tp_scts scts;
	int cause = ri->cause;

	if (!m || (m->state != MO_WAIT_SIP && m->state != MO_WAIT_REPORT) || m->rp_mr != ri->mr ||
	    (irt && irt[0] && strcmp(irt, m->call_id))) {
		LOGW("sms: %s MR=%u does not match any message in flight, ignored", rp_mti_name(ri->mti), ri->mr);
		return;
	}
	memset(&scts, 0, sizeof(scts));
	if (!rp_report_tpdu(req->body, req->body_len, &tp, &tpn) && tp) {
		struct tp_submit_report r;

		if (!tp_decode_submit_report(tp, tpn, err, &r)) {
			scts = r.scts;
			if (err)
				LOGD("sms: RP-ERROR TP-FCS 0x%02x", r.fcs);
		}
	}
	LOGI("sms: %s from the network, MR=%u%s", rp_mti_name(ri->mti), ri->mr, err ? "" : " (MO SMS accepted by the SMSC)");
	if (m->state == MO_WAIT_SIP) {
		m->early = true;
		m->early_err = err;
		m->early_cause = cause;
		m->early_scts = scts;
		return;
	}
	mo_on_report(m, err, cause, &scts);
}

/* ---- LAN hook ---- */

static bool ct_text_ok(const char *ct)
{
	char media[64], cs[32];
	const char *semi;
	size_t n;

	if (!ct)
		return true;
	while (*ct == ' ' || *ct == '\t')
		ct++;
	if (!*ct)
		return true;
	semi = strchr(ct, ';');
	n = semi ? (size_t)(semi - ct) : strlen(ct);
	while (n && (ct[n - 1] == ' ' || ct[n - 1] == '\t'))
		n--;
	if (n >= sizeof(media))
		return false;
	memcpy(media, ct, n);
	media[n] = 0;
	if (strcasecmp(media, "text/plain"))
		return false;
	if (semi && sip_params_get(semi, "charset", cs, sizeof(cs)) == 1)
		return !strcasecmp(cs, "utf-8") || !strcasecmp(cs, "utf8") || !strcasecmp(cs, "us-ascii");
	return true;
}

void smsrelay_on_lan_message(struct lan *l, const struct lan_peer *peer, struct txn_server *st,
			     const struct sip_msg *req, void *arg)
{
	struct smsrelay *sr = arg;
	struct tp_submit_req tq;
	struct tp_pdu *pdu;
	struct mo_msg *m;
	char dest[24];
	int n, rc;

	(void)l;
	if (sr->cfg.mo_require_registered && !peer->registered) {
		lan_reply(st, 403, "register first", NULL);
		return;
	}
	if (!ct_text_ok(sip_hdr(req, "Content-Type", 0))) {
		lan_reply(st, 415, "only text/plain; charset=utf-8 is accepted", "Accept: text/plain; charset=utf-8\r\n");
		return;
	}
	if (req->body_len == 0) {
		lan_reply(st, 400, "empty message", NULL);
		return;
	}
	rc = smsfmt_dest(req->ruri, dest, sizeof(dest));
	if (rc == SMSFMT_E_NOTNUM) {
		lan_reply(st, 404, "the Request-URI user part is not a phone number", NULL);
		return;
	} else if (rc) {
		lan_reply(st, 484, "phone number empty or longer than 20 digits", NULL);
		return;
	}
	if (sr->ops.cs_active && sr->ops.cs_submit && sr->ops.cs_active(sr->ops.ctx)) {	/* the backend is fixed here, per message */
		cs_mo_start(sr, peer, st, req, dest);
		return;
	}
	pdu = calloc(sr->cfg.max_segments, sizeof(*pdu));
	if (!pdu) {
		lan_reply(st, 503, "out of memory", "Retry-After: 30\r\n");
		return;
	}
	memset(&tq, 0, sizeof(tq));
	tq.dest = dest;
	tq.text = (const char *)req->body;
	tq.text_len = req->body_len;
	tq.mr = sr->tp_mr;
	tq.concat_ref = sr->concat_ref;
	tq.status_report = sr->cfg.delivery_reports;
	tq.vp_minutes = sr->cfg.vp_minutes;
	n = tp_encode_submit(&tq, pdu, sr->cfg.max_segments);
	if (n < 0) {
		free(pdu);
		if (n == TP_E_TOOLONG)
			lan_reply(st, 413, "message needs too many SMS segments", NULL);
		else if (n == TP_E_ADDR)
			lan_reply(st, 484, "bad destination number", NULL);
		else
			lan_reply(st, 400, n == TP_E_UTF8 ? "text is not valid UTF-8" : tp_strerror(n), NULL);
		return;
	}
	if (!sr->ops.registered(sr->ops.ctx)) {
		free(pdu);
		lan_reply(st, 480, "not registered on the network", NULL);
		return;
	}
	m = calloc(1, sizeof(*m));
	if (!m) {
		free(pdu);
		lan_reply(st, 503, "out of memory", "Retry-After: 30\r\n");
		return;
	} else {
		const char *src;

		if (!smsc_get(sr, &m->smsc, &src)) {
			free(pdu);
			free(m);
			set_err(sr, "MO refused: no SMSC");
			lan_reply(st, 503, "no SMSC: not on the SIM and not configured (imsd.main.smsc)", NULL);
			return;
		}
	}
	{
		struct carrier_val psi;

		psi_get(sr, &psi);
		if (!psi.value[0]) {
			free(pdu);
			free(m);
			set_err(sr, "MO refused: no SMS gateway (PSI)");
			lan_reply(st, 503, "no SMS gateway: unknown operator, not on the SIM and not configured (imsd.main.sms_psi)", NULL);
			return;
		}
	}
	if (sr->qn >= sr->cfg.queue_max) {
		free(pdu);
		free(m);
		lan_reply(st, 503, "SMS queue is full", "Retry-After: 10\r\n");
		return;
	}
	m->sr = sr;
	m->st = st;
	m->pdu = pdu;
	m->sender = peer->id;
	m->nseg = (unsigned)n;
	m->text_len = req->body_len;
	snprintf(m->dest, sizeof(m->dest), "%s", dest);
	m->dl_timer = ev_timer_new(mo_deadline, m);
	m->seg_timer = ev_timer_new(mo_report_timeout, m);
	if (!m->dl_timer || !m->seg_timer) {
		ev_timer_free(m->dl_timer);
		ev_timer_free(m->seg_timer);
		free(pdu);
		free(m);
		lan_reply(st, 503, "out of memory", "Retry-After: 30\r\n");
		return;
	}
	if (sr->cfg.carbons)
		m->text = strndup((const char *)req->body, req->body_len);	/* NULL: no carbon copy, nothing else is lost */
	sr->tp_mr = (uint8_t)(sr->tp_mr + n);
	if (n > 1)
		sr->concat_ref++;
	txn_server_set_cb(st, mo_srv_cb, m);
	ev_timer_set(m->dl_timer, sr->cfg.reply_deadline_ms);
	if (sr->q_tail)
		sr->q_tail->next = m;
	else
		sr->q_head = m;
	sr->q_tail = m;
	sr->qn++;
	sr->c.mo_submitted++;
	LOGI("sms: MO to %s len=%zu in %d part(s), queue %u", dest, req->body_len, n, sr->qn);
	if (sr->q_head == m)
		mo_send_seg(m);
}

/* ------------------------------------------------------------------ */
/* circuit switched SMS (cs/cssms.h)                                   */

/*
 * Meta of a STORE_SMS item that came from the circuit switched path (the IMS layout starts with the RP originator's length, at most
 * 11, so the magic cannot be mistaken for it): u32 magic, u8 kind (cssms_kind), u8 alnum, u8 class + 1 (0: none), str from, str
 * SMSC timestamp (ISO 8601 or ""), str discharge timestamp (reports), u8 message reference, u8 TP-Status, bytes text / data.
 * The rendering to the LAN (cs_render) gives the MESSAGE the IMS path makes of the same content.
 */
#define CS_MAGIC 0x31534d43u
#define CS_META_MAX 2560

struct cs_msg {
	uint8_t kind, mr, st;
	bool alnum;
	int cls;
	char from[48], ts[32], dts[32];
	const uint8_t *pl;
	size_t pl_len;
};

struct cs_out {
	char user[SMSFMT_USER_MAX], disp[SMSFMT_DISP_MAX], extra[800];
	char *text;
	size_t text_len;
	const uint8_t *bin;
	size_t bin_len;
};

static bool cs_is_meta(const uint8_t *meta, size_t n)
{
	struct pkr r;

	pkr_init(&r, meta, n);
	return pkr_u32(&r) == CS_MAGIC && !r.bad;
}

static size_t cs_pack(const struct cssms_in *m, uint8_t *out, size_t cap)
{
	struct pkw w;
	const void *pl = m->kind == CSSMS_DATA ? (const void *)m->data : (const void *)(m->text ? m->text : "");
	size_t pn = m->kind == CSSMS_DATA ? m->data_len : m->kind == CSSMS_TEXT && m->text ? strlen(m->text) : 0;

	pkw_init(&w, out, cap);
	pkw_u32(&w, CS_MAGIC);
	pkw_u8(&w, (uint8_t)m->kind);
	pkw_u8(&w, m->from_alnum);
	pkw_u8(&w, m->sms_class < 0 || m->sms_class > 3 ? 0 : (uint8_t)(m->sms_class + 1));
	pkw_str(&w, m->from);
	pkw_str(&w, m->ts);
	pkw_str(&w, m->discharge_ts);
	pkw_u8(&w, (uint8_t)m->message_reference);
	pkw_u8(&w, (uint8_t)m->delivery_state);
	pkw_bytes(&w, pl, pn);
	return w.ovf ? 0 : w.len;
}

static int cs_unpack(const uint8_t *meta, size_t n, struct cs_msg *c)
{
	struct pkr r;
	unsigned cl;

	memset(c, 0, sizeof(*c));
	pkr_init(&r, meta, n);
	if (pkr_u32(&r) != CS_MAGIC)
		return -1;
	c->kind = pkr_u8(&r);
	c->alnum = pkr_u8(&r);
	cl = pkr_u8(&r);
	c->cls = cl ? (int)cl - 1 : -1;
	pkr_str(&r, c->from, sizeof(c->from));
	pkr_str(&r, c->ts, sizeof(c->ts));
	pkr_str(&r, c->dts, sizeof(c->dts));
	c->mr = pkr_u8(&r);
	c->st = pkr_u8(&r);
	c->pl = pkr_bytes(&r, &c->pl_len);
	if (r.bad || !c->pl || c->kind > CSSMS_REPORT)
		return -1;
	return 0;
}

/* "2026-11-20T09:00:00+09:00" (or Z, or without zone) -> the SCTS fields the IMS path renders its headers from */
static void cs_scts(const char *iso, struct tp_scts *t)
{
	int y, mo, d, h, mi, s, n = 0, tzh = 0, tzm = 0;
	const char *p;
	struct tm tm;

	memset(t, 0, sizeof(*t));
	if (sscanf(iso, "%d-%d-%dT%d:%d:%d%n", &y, &mo, &d, &h, &mi, &s, &n) != 6 || n <= 0 || y < 2000 || y > 2099 || mo < 1 ||
	    mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 || mi > 59 || s < 0 || s > 60)
		return;
	p = iso + n;
	if (*p == '.')
		while (*++p >= '0' && *p <= '9')
			;
	if ((*p == '+' || *p == '-') && sscanf(p + 1, "%d:%d", &tzh, &tzm) >= 1) {
		t->tz_quarters = (tzh * 60 + tzm) / 15;
		if (*p == '-')
			t->tz_quarters = -t->tz_quarters;
	}
	t->year = y;
	t->mon = mo;
	t->day = d;
	t->hour = h;
	t->min = mi;
	t->sec = s;
	memset(&tm, 0, sizeof(tm));
	tm.tm_year = y - 1900;
	tm.tm_mon = mo - 1;
	tm.tm_mday = d;
	tm.tm_hour = h;
	tm.tm_min = mi;
	tm.tm_sec = s;
	t->epoch = (int64_t)timegm(&tm) - (int64_t)t->tz_quarters * 900;
	t->valid = true;
}

/* the MESSAGE for the LAN; o->text is malloc'd (the caller frees it, also after an error), o->bin points into c->pl */
static int cs_render(const struct cs_msg *c, struct cs_out *o)
{
	struct tp_addr a;
	struct tp_scts t;
	struct buf b;
	char qs[SMSFMT_DISP_MAX * 2];

	memset(o, 0, sizeof(*o));
	memset(&a, 0, sizeof(a));
	a.alnum = c->alnum;
	snprintf(a.str, sizeof(a.str), "%s", c->from);
	smsfmt_sender(&a, o->user, sizeof(o->user), o->disp, sizeof(o->disp));
	buf_init_fixed(&b, o->extra, sizeof(o->extra));
	cs_scts(c->kind == CSSMS_REPORT ? c->dts : c->ts, &t);
	hdr_ts(&b, &t, true);
	if (c->kind == CSSMS_REPORT) {
		char what[96];

		if (tp_status_is_success(c->st))
			snprintf(what, sizeof(what), "delivered");
		else if (!tp_status_is_final(c->st))
			snprintf(what, sizeof(what), "pending, the network is still trying (status 0x%02x)", c->st);
		else
			snprintf(what, sizeof(what), "FAILED (status 0x%02x)", c->st);
		o->text = malloc(160 + sizeof(c->from));
		if (!o->text)
			return -ENOMEM;
		snprintf(o->text, 160 + sizeof(c->from), "[Delivery report] SMS to %s: %s", c->from, what);
		buf_printf(&b, "X-SMS-Report: mr=%u;status=0x%02x;final=%s\r\n", c->mr, c->st, tp_status_is_final(c->st) ? "yes" : "no");
	} else {
		if (c->cls >= 0)
			buf_printf(&b, "X-SMS-Class: %d\r\n", c->cls);
		if (c->alnum) {
			smsfmt_quote_safe(c->from, qs, sizeof(qs));
			buf_printf(&b, "X-SMS-Sender: %s\r\n", qs);
		}
		if (c->kind == CSSMS_DATA) {
			char hx[HEX_EXCERPT * 2 + 1];
			size_t nh = c->pl_len > HEX_EXCERPT ? HEX_EXCERPT : c->pl_len;

			hex_encode(c->pl, nh, hx);
			o->text = malloc(160 + sizeof(hx));
			if (!o->text)
				return -ENOMEM;
			snprintf(o->text, 160 + sizeof(hx), "[binary SMS, %zu bytes, data coding 0x04] %s%s", c->pl_len, hx,
				 nh < c->pl_len ? "... (truncated)" : "");
			o->bin = c->pl;
			o->bin_len = c->pl_len;
		} else if (c->pl_len) {
			o->text = strndup((const char *)c->pl, c->pl_len);
			if (!o->text)
				return -ENOMEM;
		} else {
			o->text = strdup("(empty message)");
			if (!o->text)
				return -ENOMEM;
		}
	}
	if (!buf_ok(&b))
		o->extra[0] = 0;
	o->text_len = strlen(o->text);
	return 0;
}

/* start the delivery of a rendered message: to the binding *inc (a store item: X-IMSD-Seq seq), or to every eligible one (inc NULL) */
static int cs_go(struct smsrelay *sr, const struct cs_out *o, const reg_id_t *inc, uint64_t seq, void (*done)(void *, int), void *arg)
{
	struct lan_seq_cfg c;
	struct lan_pieces lp;
	char extra[sizeof(o->extra) + 48];
	int rc;

	if (!sr->lan)
		return -ENOENT;
	snprintf(extra, sizeof(extra), "%s", o->extra);
	if (seq)
		snprintf(extra + strlen(extra), sizeof(extra) - strlen(extra), "X-IMSD-Seq: %llu\r\n", (unsigned long long)seq);
	memset(&c, 0, sizeof(c));
	c.from_user = o->user;
	c.from_display = o->disp[0] ? o->disp : NULL;
	c.extra = extra;
	c.done = done;
	c.arg = arg;
	if (inc) {
		c.include = inc;
		c.ninclude = 1;
		c.include_set = true;
	}
	if (o->bin && inc) {
		const struct reg_binding *bb = reg_find(lan_registrar(sr->lan), *inc);

		if (bb && accepts_octets(bb)) {
			c.content_type = "application/octet-stream";
			c.body = o->bin;
			c.body_len = o->bin_len;
			return lan_seq_start(sr->seqs, &c);
		}
	}
	if (lan_pieces_make(&lp, o->text, o->text_len, sr->cfg.text_split))
		return -ENOMEM;
	c.part_hdr = "X-SMS-Part";
	c.text = lp.text;
	c.n = lp.n;
	rc = lan_seq_start(sr->seqs, &c);
	lan_pieces_free(&lp);
	return rc;
}

/* store handler: a CS item to ONE binding (0 started, 1 nothing to send, -errno) */
static int cs_deliver_item(struct smsrelay *sr, const struct store_item *it, reg_id_t b, void (*done)(void *, int), void *arg)
{
	struct cs_msg c;
	struct cs_out o;
	int rc;

	if (cs_unpack(it->meta, it->meta_len, &c)) {
		LOGW("sms: stored item %llu cannot be decoded, skipped", (unsigned long long)it->seq);
		return 1;
	}
	rc = cs_render(&c, &o);
	if (!rc)
		rc = cs_go(sr, &o, &b, it->seq, done, arg);
	free(o.text);
	return rc;
}

static void cs_in_done(struct smsrelay *sr, unsigned id, bool taken)
{
	if (sr->ops.cs_in_done)
		sr->ops.cs_in_done(sr->ops.ctx, id, taken);
}

static void cs_live_free(struct cs_live *l)
{
	struct cs_live **pp;

	for (pp = &l->sr->cl; *pp; pp = &(*pp)->next)
		if (*pp == l) {
			*pp = l->next;
			break;
		}
	free(l);
}

/* a live delivery ended without its callback: a kept message goes back to the modem */
static void cs_live_abort(struct cs_live *l)
{
	struct smsrelay *sr = l->sr;
	bool keep = l->keep;
	unsigned id = l->id;

	dd_del(sr, l->key);
	cs_live_free(l);
	if (keep)
		cs_in_done(sr, id, false);
}

static void cs_live_done(void *arg, int nok)
{
	struct cs_live *l = arg;
	struct smsrelay *sr = l->sr;
	bool keep = l->keep;
	unsigned id = l->id;

	if (nok > 0) {
		LOGI("sms: CS %s from %s delivered to %d LAN client(s)", l->is_report ? "delivery report" : "message", l->peer, nok);
		if (!l->is_report)
			sr->c.mt_delivered++;
	} else if (keep) {
		/* the store has not got it and nobody took it: the modem keeps it, cssms offers it again */
		sr->c.cs_rx_deferred++;
		dd_del(sr, l->key);
		LOGW("sms: a CS message could not be stored or delivered, it stays in the modem and is offered again");
	} else {
		sr->c.mt_lost_failed++;
		LOGW("sms: LOST %s from %s: no LAN client accepted it. Text: %s", l->is_report ? "delivery report" : "message", l->peer, l->text);
		set_err(sr, "SMS from %s lost: no LAN client accepted it", l->peer);
	}
	cs_live_free(l);
	if (keep)
		cs_in_done(sr, id, nok > 0);
}

/* the live path of a CS message. Returns CSSMS_TAKEN, CSSMS_PENDING (keep: the answer comes with cs_in_done) or -EAGAIN (not taken:
 * nobody to deliver to; with keep also: the delivery cannot be started). keep = the store is enabled: a message is taken only once a
 * device took it. Without the store only "no LAN client registered" keeps the message in the modem, the rest is logged as lost. */
static int cs_live(struct smsrelay *sr, const uint8_t *meta, size_t ml, unsigned id, uint64_t key, bool keep)
{
	struct cs_msg c;
	struct cs_out o;
	struct cs_live *l;
	struct dedup *d;
	int rc, ret = CSSMS_TAKEN;

	if (cs_unpack(meta, ml, &c) || cs_render(&c, &o)) {
		sr->c.mt_errors++;
		set_err(sr, "CS SMS lost: cannot render it");
		LOGW("sms: LOST a CS message: cannot render it");
		return CSSMS_TAKEN;
	}
	l = calloc(1, sizeof(*l));
	if (!l) {
		rc = -ENOMEM;
	} else {
		l->sr = sr;
		l->is_report = c.kind == CSSMS_REPORT;
		l->keep = keep;
		l->id = id;
		l->key = key;
		snprintf(l->peer, sizeof(l->peer), "%s", c.from);
		snprintf(l->text, sizeof(l->text), "%s", o.text);
		rc = cs_go(sr, &o, NULL, 0, cs_live_done, l);
	}
	if (rc == 0) {
		l->next = sr->cl;
		sr->cl = l;
		if (key) {
			d = dd_find(sr, key);
			if (!d)
				d = dd_add(sr, key);
			d->done = true;
		}
		if (keep)
			ret = CSSMS_PENDING;
	} else if (rc == -ENOENT || keep) {
		sr->c.cs_rx_deferred++;
		LOGW("sms: a CS message cannot be delivered now (%s), it stays in the modem and is offered again",
		     rc == -ENOENT ? "no LAN client is registered" : "cannot start the delivery to the LAN");
		free(l);
		ret = -EAGAIN;
	} else {
		sr->c.mt_lost_failed++;
		set_err(sr, "SMS from %s lost: cannot start the delivery to the LAN", c.from);
		LOGW("sms: LOST %s from %s: cannot start the delivery to the LAN. Text: %s",
		     c.kind == CSSMS_REPORT ? "delivery report" : "message", c.from, o.text);
		free(l);
	}
	free(o.text);
	return ret;
}

static void cs_job_free(struct cs_job *j)
{
	struct cs_job **pp;

	for (pp = &j->sr->cj; *pp; pp = &(*pp)->next)
		if (*pp == j) {
			*pp = j->next;
			break;
		}
	ev_timer_free(j->timer);
	free(j->meta);
	free(j);
}

/* the store did not take the message: a device that answers 2xx takes it, otherwise the modem keeps it. Returns what cs_live returns. */
static int cs_job_fallback(struct cs_job *j)
{
	j->sr->c.mt_store_fallback++;
	dd_del(j->sr, j->key);
	return cs_live(j->sr, j->meta, j->meta_len, j->id, j->key, true);
}

static void cs_added(void *arg, int status, uint64_t seq, const struct store_add *a)
{
	struct cs_job *j = arg;
	struct smsrelay *sr = j->sr;
	unsigned id = j->id;
	struct dedup *d;
	int taken = CSSMS_TAKEN;

	(void)a;
	ev_timer_cancel(j->timer);
	if (status == 0) {
		sr->c.mt_stored++;
		LOGI("sms: CS message stored as item %llu", (unsigned long long)seq);
		d = dd_find(sr, j->key);
		if (d)
			d->done = true;
	} else {
		LOGW("sms: cannot store the CS message (%s), trying the LAN devices", strerror(-status));
		taken = cs_job_fallback(j);
		if (taken == CSSMS_PENDING) {	/* cs_live_done answers */
			cs_job_free(j);
			return;
		}
	}
	cs_job_free(j);
	cs_in_done(sr, id, taken == CSSMS_TAKEN);
}

static void cs_timeout(void *arg)
{
	struct cs_job *j = arg;
	struct smsrelay *sr = j->sr;
	unsigned id = j->id;

	int rc;

	LOGW("sms: the store did not confirm the CS message within %u ms, trying the LAN devices", sr->cfg.store_ack_wait_ms);
	store_abandon(sr->ops.store, j->seq);
	rc = cs_job_fallback(j);
	cs_job_free(j);
	if (rc != CSSMS_PENDING)
		cs_in_done(sr, id, rc == CSSMS_TAKEN);
}

/* (sender, SMSC timestamp, text hash); 0: no timestamp, nothing to recognise it by */
static uint64_t cs_key(const struct cssms_in *m)
{
	uint64_t h = fnv(0xcbf29ce484222325ull, "cs-sms", 6);
	const void *pl = m->kind == CSSMS_DATA ? (const void *)m->data : (const void *)m->text;
	size_t pn = m->kind == CSSMS_DATA ? m->data_len : m->text ? strlen(m->text) : 0;
	uint8_t k[3] = { (uint8_t)m->kind, (uint8_t)m->message_reference, (uint8_t)m->delivery_state };
	const char *ts = m->kind == CSSMS_REPORT ? m->discharge_ts : m->ts;

	if (!ts[0])
		return 0;
	h = fnv(h, m->from, strlen(m->from) + 1);
	h = fnv(h, ts, strlen(ts) + 1);
	if (m->kind == CSSMS_REPORT)
		h = fnv(h, k, sizeof(k));
	if (pl)
		h = fnv(h, pl, pn);
	return h ? h : 1;
}

int smsrelay_cs_in(struct smsrelay *sr, const struct cssms_in *m)
{
	uint8_t meta[CS_META_MAX];
	size_t ml;
	uint64_t key, seq;
	struct cs_job *j;
	struct store_add a;
	struct dedup *d;
	bool report = m->kind == CSSMS_REPORT;

	sr->c.mt_received++;
	if (report) {
		sr->c.mt_reports++;
		LOGI("sms: CS status report from %s for MR=%u: status 0x%02x", m->from, m->message_reference, m->delivery_state);
		if (!sr->cfg.delivery_reports)
			return CSSMS_TAKEN;
	} else {
		LOGI("sms: CS MT from %s len=%zu%s%s", m->from, m->kind == CSSMS_DATA ? m->data_len : m->text ? strlen(m->text) : 0,
		     m->multipart ? " (concatenated)" : "", m->backlog ? " (backlog)" : "");
	}
	if (m->truncated)
		LOGW("sms: CS message from %s was cut by the size limit", m->from);
	if (m->kind == CSSMS_DATA && m->wsp_push && m->mms_hint) {
		if (sr->ops.push && sr->ops.push_active && sr->ops.push_active(sr->ops.ctx)) {
			sr->c.mt_push_messages++;
			sr->ops.push(sr->ops.ctx, m->from, 2948, m->data, m->data_len);
			return CSSMS_TAKEN;
		}
		sr->c.cs_mms_unhandled++;
		LOGI("sms: MMS notification from %s received over the circuit switched path: MMS is not available here, only the notice goes on",
		     m->from);
	}
	key = cs_key(m);
	if (key && dd_find(sr, key)) {
		sr->c.mt_duplicates++;
		LOGI("sms: CS message from %s is a duplicate, dropped", m->from);
		return CSSMS_TAKEN;
	}
	ml = cs_pack(m, meta, sizeof(meta));
	if (!ml) {
		sr->c.mt_errors++;
		set_err(sr, "CS SMS from %s lost: too large", m->from);
		LOGW("sms: LOST a CS message from %s: too large", m->from);
		return CSSMS_TAKEN;
	}
	if (sr->ops.store && !store_usable(sr->ops.store)) {
		struct store_status ss;

		store_get_status(sr->ops.store, &ss);
		if (!ss.ready) {		/* still loading: cs_store_ready() makes cssms offer it again */
			sr->c.cs_rx_deferred++;
			LOGI("sms: CS message from %s: the store is not loaded yet, it stays in the modem for now", m->from);
			return -EAGAIN;
		}
	}
	if (sr->ops.store && store_usable(sr->ops.store)) {
		if (key && !store_find_dedup(sr->ops.store, STORE_SMS, key, 0, &seq)) {
			sr->c.mt_duplicates++;
			LOGI("sms: CS message from %s is already stored as item %llu, dropped", m->from, (unsigned long long)seq);
			return CSSMS_TAKEN;
		}
		j = calloc(1, sizeof(*j));
		if (j) {
			j->sr = sr;
			j->id = m->id;
			j->key = key;
			j->meta = malloc(ml);
			j->timer = ev_timer_new(cs_timeout, j);
			if (j->meta && j->timer) {
				memcpy(j->meta, meta, ml);
				j->meta_len = ml;
				memset(&a, 0, sizeof(a));
				a.type = STORE_SMS;
				a.peer = m->from;
				a.dedup = key;
				a.meta = meta;
				a.meta_len = ml;
				a.owner = sr;
				if (!store_add(sr->ops.store, &a, cs_added, j, &j->seq)) {
					j->next = sr->cj;
					sr->cj = j;
					if (key) {
						d = dd_add(sr, key);
						d->done = false;
					}
					ev_timer_set(j->timer, sr->cfg.store_ack_wait_ms);
					return CSSMS_PENDING;
				}
			}
			ev_timer_free(j->timer);
			free(j->meta);
			free(j);
		}
	}
	return cs_live(sr, meta, ml, m->id, key, sr->ops.store != NULL);
}

/* ---- MO over the circuit switched path ---- */

static void cs_mo_unlink(struct cs_mo *m)
{
	struct cs_mo **pp;

	for (pp = &m->sr->cmo; *pp; pp = &(*pp)->next)
		if (*pp == m) {
			*pp = m->next;
			m->sr->cmo_n--;
			break;
		}
}

static void cs_mo_srv_cb(struct txn_server *st, enum txn_srv_event ev, void *arg)
{
	struct cs_mo *m = arg;

	(void)st;
	if (ev == TXN_SRV_TERMINATED) {
		m->st = NULL;
		m->replied = true;
	}
}

static void cs_mo_deadline(void *arg)
{
	struct cs_mo *m = arg;

	if (m->replied)
		return;
	lan_reply(m->st, 202, "outcome not known yet, see the router log", NULL);
	m->replied = true;
	m->late = true;
	LOGW("sms: MO to %s: no outcome within the reply deadline, answered 202", m->dest);
}

static void cs_mo_free(struct cs_mo *m)
{
	if (m->st)
		txn_server_set_cb(m->st, NULL, NULL);
	ev_timer_free(m->dl_timer);
	free(m->text);
	free(m);
}

/* cssms_done_cb: exactly once */
static void cs_mo_done(void *arg, const struct cssms_result *r)
{
	struct cs_mo *m = arg;
	struct smsrelay *sr = m->sr;
	bool ok = r->status == 200;
	unsigned parts = r->parts ? r->parts : 1;
	const char *late;

	if (m->orphan) {			/* the relay is gone */
		free(m->text);
		free(m);
		return;
	}
	late = m->late ? " (after the 202 answer)" : "";
	cs_mo_unlink(m);
	if (ok) {
		sr->c.mo_acked++;
		sr->c.mo_segments_sent += parts;
		LOGI("sms: MO to %s len=%zu: %u part(s) accepted by the circuit switched path%s", m->dest, strlen(m->text), parts, late);
	} else {
		sr->c.mo_failed++;
		set_err(sr, "MO to %s failed: %s", m->dest, r->text);
		LOGW("sms: MO to %s len=%zu failed: %s%s", m->dest, strlen(m->text), r->text, late);
	}
	if (!m->replied && m->st) {
		char hdrs[160] = "";
		int status = r->status;

		if (ok) {
			snprintf(hdrs, sizeof(hdrs), "X-SMS-Parts: %u\r\n", parts);
			lan_reply(m->st, 200, NULL, hdrs);
		} else {
			if (status != 400 && status != 403 && status != 413 && status != 480 && status != 484 && status != 502 &&
			    status != 503 && status != 504)
				status = 502;
			if (status == 503)
				snprintf(hdrs, sizeof(hdrs), "Retry-After: 30\r\n");
			lan_reply(m->st, status, r->text, hdrs);
		}
	}
	m->replied = true;
	if (ok)
		carbon_send(sr, m->dest, m->text, parts, NULL, m->sender);
	cs_mo_free(m);
}

static void cs_mo_start(struct smsrelay *sr, const struct lan_peer *peer, struct txn_server *st, const struct sip_msg *req,
			const char *dest)
{
	struct cs_mo *m = calloc(1, sizeof(*m));
	struct cssms_submit q;
	int rc;

	if (!m) {
		lan_reply(st, 503, "out of memory", "Retry-After: 30\r\n");
		return;
	}
	m->text = strndup((const char *)req->body, req->body_len);
	m->dl_timer = ev_timer_new(cs_mo_deadline, m);
	if (!m->text || !m->dl_timer) {
		ev_timer_free(m->dl_timer);
		free(m->text);
		free(m);
		lan_reply(st, 503, "out of memory", "Retry-After: 30\r\n");
		return;
	}
	m->sr = sr;
	m->st = st;
	m->sender = peer->id;
	snprintf(m->dest, sizeof(m->dest), "%s", dest);
	memset(&q, 0, sizeof(q));
	q.dest = dest;
	q.text = m->text;
	q.delivery_report = sr->cfg.delivery_reports;
	q.vp_minutes = sr->cfg.vp_minutes;
	rc = sr->ops.cs_submit(sr->ops.ctx, &q, cs_mo_done, m);
	if (rc) {
		int status = cssms_status_of_errno(rc);

		free(m->text);
		ev_timer_free(m->dl_timer);
		free(m);
		lan_reply(st, status, status == 413 ? "message needs too many SMS segments" : status == 484 ? "bad destination number" :
			  status == 400 ? "empty or not valid UTF-8" : status == 480 ? "the circuit switched line cannot send SMS now" :
			  "SMS queue is full", status == 503 ? "Retry-After: 10\r\n" : NULL);
		return;
	}
	txn_server_set_cb(st, cs_mo_srv_cb, m);
	ev_timer_set(m->dl_timer, sr->cfg.reply_deadline_ms);
	m->next = sr->cmo;
	sr->cmo = m;
	sr->cmo_n++;
	sr->c.mo_submitted++;
	LOGI("sms: MO to %s len=%zu over the circuit switched path, %u in flight", dest, req->body_len, sr->cmo_n);
}

/* ------------------------------------------------------------------ */
/* Gm entry, registration                                              */

bool smsrelay_on_gm_request(struct smsrelay *sr, struct txn_server *st, struct sip_endpoint *ep,
			    const struct addr *src, const struct sip_msg *req)
{
	struct rp_info ri;
	struct sip_resp_parts p;

	(void)ep;
	(void)src;
	if (!sip_is_method(req, "MESSAGE") || !ci_has(sip_hdr(req, "Content-Type", 0), SMS_CT))
		return false;
	memset(&p, 0, sizeof(p));
	p.status = 200;
	txn_server_reply(st, &p);
	if (rp_parse(req->body, req->body_len, &ri)) {
		LOGW("sms: MESSAGE with a body shorter than the RP header (%zu bytes)", req->body_len);
		return true;
	}
	switch (ri.mti) {
	case RP_DATA_N_MS:
		on_rp_data(sr, req);
		break;
	case RP_ACK_N_MS:
	case RP_ERROR_N_MS:
		on_rp_report(sr, req, &ri);
		break;
	default:
		LOGW("sms: unexpected %s MR=%u", rp_mti_name(ri.mti), ri.mr);
	}
	return true;
}

void smsrelay_on_reg_event(struct smsrelay *sr, enum smsrelay_reg_ev ev)
{
	if (ev == SMSRELAY_REG_DOWN && sr->q_head) {
		LOGW("sms: registration lost, failing %u queued MO message(s)", sr->qn);
		mo_fail_all(sr, 480, "registration to the network lost");
	}
}

void smsrelay_free(struct smsrelay *sr)
{
	if (!sr)
		return;
	mo_fail_all(sr, 503, "service stopping");
	while (sr->mt) {
		struct mt_job *j = sr->mt;
		int i;

		for (i = 0; i < 2; i++)
			if (j->fork[i])
				lan_fork_detach(j->fork[i]);
		mt_free(j);
	}
	while (sr->cbs)
		cb_free(sr, sr->cbs);
	if (sr->ops.store) {
		store_set_handler(sr->ops.store, STORE_SMS, NULL);
		store_set_handler(sr->ops.store, STORE_CARBON_SMS, NULL);
		store_set_usable_cb(sr->ops.store, NULL, NULL);
		store_detach(sr->ops.store, sr);
	}
	while (sr->sj) {
		struct st_job *j = sr->sj;

		store_abandon(sr->ops.store, j->seq);
		st_job_free(j);
	}
	while (sr->cj) {
		struct cs_job *j = sr->cj;

		store_abandon(sr->ops.store, j->seq);
		cs_job_free(j);
	}
	while (sr->cl)
		cs_live_abort(sr->cl);
	while (sr->cmo) {		/* cssms answers later: the entry stays until then, without the relay */
		struct cs_mo *m = sr->cmo;

		if (!m->replied && m->st)
			lan_reply(m->st, 503, "service stopping", "Retry-After: 30\r\n");
		if (m->st)
			txn_server_set_cb(m->st, NULL, NULL);
		m->st = NULL;
		ev_timer_free(m->dl_timer);
		m->dl_timer = NULL;
		m->orphan = true;
		sr->cmo = m->next;
		sr->cmo_n--;
	}
	wappush_free(sr->wp);
	lan_seqs_free(sr->seqs);
	free(sr);
}

void smsrelay_cs_kick(struct smsrelay *sr)
{
	if (sr->ops.cs_kick)
		sr->ops.cs_kick(sr->ops.ctx);
}

void smsrelay_set_lan(struct smsrelay *sr, struct lan *lan)
{
	struct mt_job *j;

	sr->lan = lan;
	lan_seqs_set(sr->seqs, lan);
	if (lan)
		return;
	/* the LAN object goes away: everything that depends on it ends now (forks die with lan_free) */
	mo_fail_all(sr, 503, "LAN side restarting");
	while (sr->cl)			/* the sequences of the live CS deliveries were aborted without a callback */
		cs_live_abort(sr->cl);
	while ((j = sr->mt)) {
		int i;

		if (!j->finished)
			mt_finish(j, true);
		if (sr->mt == j) {
			for (i = 0; i < 2; i++)
				if (j->fork[i])
					lan_fork_detach(j->fork[i]);
			mt_free(j);
		}
	}
}
