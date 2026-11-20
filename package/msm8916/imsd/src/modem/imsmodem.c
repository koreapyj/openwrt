/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * imsmodem: the modem side of imsd (see imsmodem.h).
 *
 * Structure: every asynchronous step is a "job" (m->job). Exactly one main
 * job runs at a time; when it completes step() looks at the knowledge
 * collected so far and starts the next job, so every event (modem added or
 * removed, state change, bearer lost, timer) only has to update the
 * knowledge and call step(). The AKA service shares the ISIM logical
 * channel with the identity read through the small "channel job" executor
 * (cj_*): one APDU in flight, reopen the channel once on errors.
 *
 * Staleness: every uqmid call carries the generation m->gen of the modem it
 * was started for; replies of an older generation are dropped silently.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "imsmodem.h"
#include "isim.h"
#include "../util/codec.h"
#include "../util/evloop.h"
#include "../util/log.h"

#define AKA_QUEUE 4

enum job {
	J_NONE, J_LIST, J_MGET, J_SIM, J_ENABLE, J_ISIM, J_QRTR,
	J_ADOPT, J_CREATE, J_CONNECT, J_BGET,
};

enum bstate { BS_NONE, BS_CREATED, BS_CONNECTED, BS_UP };

struct pend {
	struct pend *next;
	bool is_cell;		/* serving cell query: survives bearer resets */
	struct imsmodem *m;
	unsigned gen;
	bool fire;		/* fire and forget: survives resets, counted for shutdown */
	bool is_cj;		/* belongs to the ISIM channel executor, not to a main job */
	bool immediate_fail;
	void *h;
	struct ev_timer *t;
	void (*fn)(struct imsmodem *m, const struct uq_res *res, void *arg);
	void *arg;
};

enum cj_kind { CJ_NONE, CJ_IDENT, CJ_AKA, CJ_SIMX };
enum ident_step { IS_SEL_IMPI, IS_RD_IMPI, IS_SEL_DOM, IS_RD_DOM, IS_SEL_IMPU, IS_REC_IMPU, IS_SEL_PCSCF, IS_REC_PCSCF };

/* extra SIM reads: EF_PSISMSC on the ISIM, then EF_SMSP (and EF_PSISMSC when the ISIM had none) on the USIM */
enum simx_step { XS_SEL_ISIM_PSI, XS_RD_ISIM_PSI, XS_OPEN_USIM, XS_SEL_SMSP, XS_REC_SMSP, XS_SEL_USIM_PSI, XS_RD_USIM_PSI };

struct aka_req {
	uint8_t rand[16], autn[16];
	imsmodem_aka_cb cb;
	void *arg;
	bool cancelled;
};

struct cjob {
	enum cj_kind kind;
	bool retried;
	/* identity read */
	enum ident_step step;
	int rec;
	uint8_t le;
	bool le_retry;
	char impi[128], domain[96], impu[160];
	/* extra SIM reads */
	enum simx_step xs;
	int uchan;		/* logical channel of the USIM application */
	bool uopen;
	uint8_t grle;		/* != 0: GET RESPONSE pending after 61xx */
	char smsc[32], psi[160];
	/* AKA */
	struct aka_sm sm;
	struct aka_req cur;
};

struct imsmodem {
	struct imsmodem_cfg cfg;
	struct imsmodem_ops ops;
	unsigned gen;
	struct pend *pends;
	int nfire;
	bool stopping, in_step, again;
	void (*shut_done)(void *);
	void *shut_arg;
	struct ev_timer *t_shut;

	enum job job;
	bool uq_up;
	/* modem */
	char mpath[UQ_PATH];
	char mdev[96];
	char mstate[16];
	bool got_get;
	char imei_fmt[24];
	char mbearers[UQ_MAX_BEARERS][UQ_PATH];
	int n_mbearers;
	bool adopt_done;
	int adopt_i;
	bool enable_tried;
	/* identity */
	bool sim_got;
	char sim_key[64];
	char imsi[24];		/* of the SIM, "" until read */
	bool id_ready;
	struct ims_identity id;
	bool cache_valid;
	char cache_key[64];
	struct ims_identity cache;
	/* modem IMS */
	int ims_present;	/* -1 unknown */
	void *qh;
	struct ev_timer *t_ims;
	/* bearer */
	enum bstate bst;
	struct ims_bearer br;
	char br_pcscf[UQ_MAX_PCSCF][48];
	int br_n_pcscf;
	bool net_applied;
	struct netcfg_params net;
	/* retry */
	struct ev_timer *t_retry;
	bool in_backoff;
	unsigned retry_n;
	struct ev_timer *t_recheck;	/* no-pcscf: look at the bearer again */
	/* status */
	char reason[64];
	char last_error[160];
	struct ims_link pub;
	/* SIM extras and serving cell */
	char smsc[32];
	char sms_psi[160];
	bool simx_done;
	char simx_key[64];
	char pani[80], cell_str[96];
	bool cell_inflight, pani_auto, hold_used, holding;
	struct ev_timer *t_hold;
	/* ISIM channel */
	int chan;
	bool chan_open;
	struct ev_timer *t_chan;
	struct cjob cj;
	struct aka_req aq[AKA_QUEUE];
	int naq;
};

static void step(struct imsmodem *m);
static void publish(struct imsmodem *m);

void imsmodem_cfg_defaults(struct imsmodem_cfg *c)
{
	memset(c, 0, sizeof(*c));
	snprintf(c->apn, sizeof(c->apn), "IMS");
	snprintf(c->ip_type, sizeof(c->ip_type), "ipv6");
	c->profile_id = 6;
	c->route_table = 1006;
}

static unsigned t_or(unsigned v, unsigned d)
{
	return v ? v : d;
}

/* ------------------------------------------------------------------ */
/* small helpers                                                       */

static void set_reason(struct imsmodem *m, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void set_reason(struct imsmodem *m, const char *fmt, ...)
{
	char r[sizeof(m->reason)];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(r, sizeof(r), fmt, ap);
	va_end(ap);
	if (strcmp(r, m->reason)) {
		LOGI("modem: %s", r[0] ? r : "(ready)");
		memcpy(m->reason, r, sizeof(r));
	}
}

static void set_error(struct imsmodem *m, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void set_error(struct imsmodem *m, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(m->last_error, sizeof(m->last_error), fmt, ap);
	va_end(ap);
	LOGW("modem: %s", m->last_error);
}

static const char *uq_errname(const struct uq_res *r)
{
	static char b[160];

	switch (r->err) {
	case UQ_E_TIMEOUT: return "timeout";
	case UQ_E_GONE: return "object gone";
	case UQ_E_STATE: snprintf(b, sizeof(b), "wrong state: %s", r->errmsg); return b;
	case UQ_E_CONN: return "ubus connection problem";
	case UQ_E_BAD: return "bad reply";
	default: snprintf(b, sizeof(b), "%s", r->errmsg[0] ? r->errmsg : "failed"); return b;
	}
}

static bool modem_state_ok(const char *s)
{
	return !strcmp(s, "registered") || !strcmp(s, "connecting") || !strcmp(s, "connected") || !strcmp(s, "disconnecting");
}

/* ------------------------------------------------------------------ */
/* pending uqmid calls                                                 */

static void pend_unlink(struct imsmodem *m, struct pend *p)
{
	struct pend **pp;

	for (pp = &m->pends; *pp; pp = &(*pp)->next)
		if (*pp == p) {
			*pp = p->next;
			return;
		}
}

static void shut_check(struct imsmodem *m);

static void pend_complete(struct pend *p, const struct uq_res *res)
{
	struct imsmodem *m = p->m;
	void (*fn)(struct imsmodem *, const struct uq_res *, void *) = p->fn;
	void *arg = p->arg;
	bool fire = p->fire, stale = p->gen != m->gen;

	pend_unlink(m, p);
	ev_timer_free(p->t);
	free(p);
	if (fire) {
		m->nfire--;
		if (res->err)
			LOGD("modem: cleanup call failed: %s", uq_errname(res));
		shut_check(m);
		return;
	}
	if (!stale)
		fn(m, res, arg);
}

static void pend_backend_cb(void *arg, const struct uq_res *res)
{
	struct pend *p = arg;

	p->h = NULL;
	pend_complete(p, res);
}

static void pend_timeout(void *arg)
{
	struct pend *p = arg;
	struct uq_res r;

	memset(&r, 0, sizeof(r));
	r.err = p->immediate_fail ? UQ_E_CONN : UQ_E_TIMEOUT;
	if (p->h && p->m->ops.uq.cancel)
		p->m->ops.uq.cancel(p->m->ops.uq.ctx, p->h);
	p->h = NULL;
	pend_complete(p, &r);
}

enum pkind { PK_JOB, PK_CJ, PK_FIRE, PK_CELL };

static void call(struct imsmodem *m, const struct uq_req *rq, unsigned timeout_ms, enum pkind kind,
		 void (*fn)(struct imsmodem *, const struct uq_res *, void *), void *arg)
{
	bool fire = kind == PK_FIRE;
	struct pend *p = calloc(1, sizeof(*p));

	if (!p)
		return;
	p->m = m;
	p->gen = m->gen;
	p->fire = fire;
	p->is_cj = kind == PK_CJ;
	p->is_cell = kind == PK_CELL;
	p->fn = fn;
	p->arg = arg;
	p->t = ev_timer_new(pend_timeout, p);
	if (!p->t) {
		free(p);
		return;
	}
	p->next = m->pends;
	m->pends = p;
	if (fire)
		m->nfire++;
	p->h = m->ops.uq.call(m->ops.uq.ctx, rq, pend_backend_cb, p);
	if (!p->h) {
		p->immediate_fail = true;
		ev_timer_set(p->t, 0);
		return;
	}
	ev_timer_set(p->t, timeout_ms);
}

/* mode 0: main job calls only; 1: also the channel executor; 2: everything including fire and forget */
static void cancel_pends(struct imsmodem *m, int mode)
{
	struct pend **pp = &m->pends;

	while (*pp) {
		struct pend *p = *pp;

		if ((p->fire && mode < 2) || (p->is_cj && mode < 1) || (p->is_cell && mode < 1)) {
			pp = &p->next;
			continue;
		}
		*pp = p->next;
		if (p->h && m->ops.uq.cancel)
			m->ops.uq.cancel(m->ops.uq.ctx, p->h);
		if (p->fire)
			m->nfire--;
		ev_timer_free(p->t);
		free(p);
	}
}

/* only the channel executor's calls */
static void cancel_cj_pends(struct imsmodem *m)
{
	struct pend **pp = &m->pends;

	while (*pp) {
		struct pend *p = *pp;

		if (!p->is_cj) {
			pp = &p->next;
			continue;
		}
		*pp = p->next;
		if (p->h && m->ops.uq.cancel)
			m->ops.uq.cancel(m->ops.uq.ctx, p->h);
		ev_timer_free(p->t);
		free(p);
	}
}

static void fire_delete_bearer(struct imsmodem *m, const char *bearer)
{
	struct uq_req rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_DELETE_BEARER;
	snprintf(rq.obj, sizeof(rq.obj), "%s", m->mpath);
	snprintf(rq.str, sizeof(rq.str), "%s", bearer);
	LOGI("modem: deleting bearer %s", bearer);
	call(m, &rq, t_or(m->cfg.call_timeout_ms, 15000), PK_FIRE, NULL, NULL);
}

static void fire_chan_close(struct imsmodem *m, int chan)
{
	struct uq_req rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_CHAN_CLOSE;
	snprintf(rq.obj, sizeof(rq.obj), "%s", m->mpath);
	rq.num = chan;
	call(m, &rq, t_or(m->cfg.call_timeout_ms, 15000), PK_FIRE, NULL, NULL);
}

/* ------------------------------------------------------------------ */
/* link publication                                                    */

static bool family_ok(const char *pcscf, const struct addr *local)
{
	struct addr a;

	if (addr_set(&a, pcscf, 0))
		return false;
	return addr_family(&a) == addr_family(local);
}

static void build_link(struct imsmodem *m, struct ims_link *l)
{
	int i;

	memset(l, 0, sizeof(*l));
	l->id = m->id;
	l->br = m->br;
	snprintf(l->reason, sizeof(l->reason), "%s", m->reason);
	if (!(m->bst == BS_UP && m->net_applied && m->id_ready))
		return;
	for (i = 0; i < m->br_n_pcscf && l->n_pcscf < IMS_MAX_PCSCF; i++)
		if (family_ok(m->br_pcscf[i], &m->br.local))
			snprintf(l->pcscf[l->n_pcscf++], sizeof(l->pcscf[0]), "%s", m->br_pcscf[i]);
	if (l->n_pcscf) {
		l->pcscf_src = PCSCF_NETWORK;
	} else {
		for (i = 0; i < m->cfg.n_static && l->n_pcscf < IMS_MAX_PCSCF; i++)
			if (family_ok(m->cfg.static_pcscf[i], &m->br.local))
				snprintf(l->pcscf[l->n_pcscf++], sizeof(l->pcscf[0]), "%s", m->cfg.static_pcscf[i]);
		if (l->n_pcscf)
			l->pcscf_src = PCSCF_STATIC;
	}
	l->ready = l->n_pcscf > 0;
}

static void publish(struct imsmodem *m)
{
	struct ims_link nl;

	build_link(m, &nl);
	if (!nl.ready)
		m->holding = false;
	else if (!m->pub.ready) {
		/* a handset sends the serving cell in the first REGISTER: give the cell query up to 1 s, once */
		if (!m->hold_used && m->cell_inflight && !m->pani[0]) {
			m->hold_used = true;
			m->holding = true;
			ev_timer_set(m->t_hold, 1000);
			LOGD("modem: holding the link for the serving cell (max 1 s)");
		}
		if (m->holding)
			return;
	}
	if (nl.ready) {
		if (m->reason[0])
			set_reason(m, "%s", "");
		nl.reason[0] = 0;
	}
	nl.seq = m->pub.seq;
	if (!memcmp(&nl, &m->pub, sizeof(nl)))
		return;
	if (nl.ready && !m->pub.ready) {
		char ah[64] = "";

		addr_host(&nl.br.local, ah, sizeof(ah));
		LOGI("modem: IMS link ready: %s %s/%d mtu %d, %d P-CSCF (%s)", nl.br.ifname, ah, nl.br.prefix, nl.br.mtu,
		     nl.n_pcscf, nl.pcscf_src == PCSCF_NETWORK ? "from the network" : "static list");
	}
	else if (!nl.ready && m->pub.ready)
		LOGI("modem: IMS link lost (%s)", nl.reason[0] ? nl.reason : "released");
	nl.seq = ++m->pub.seq;
	m->pub = nl;
	if (m->ops.on_link)
		m->ops.on_link(m->ops.arg, &m->pub);
}

/* ------------------------------------------------------------------ */
/* retry / backoff                                                     */

static void retry_fire(void *arg)
{
	struct imsmodem *m = arg;

	m->in_backoff = false;
	step(m);
}

static void schedule_retry(struct imsmodem *m)
{
	unsigned mn = t_or(m->cfg.retry_min_ms, 5000), mx = t_or(m->cfg.retry_max_ms, 60000);
	uint64_t d = mn;
	unsigned i;

	for (i = 0; i < m->retry_n && d < mx; i++)
		d *= 2;
	if (d > mx)
		d = mx;
	m->retry_n++;
	m->in_backoff = true;
	LOGI("modem: retrying in %llu s", (unsigned long long)(d / 1000));
	ev_timer_set(m->t_retry, d);
}

/* ------------------------------------------------------------------ */
/* teardown pieces                                                     */

static void release_bearer(struct imsmodem *m, bool delete_remote)
{
	if (m->net_applied) {
		m->ops.net.remove(m->ops.net.ctx, &m->net);
		m->net_applied = false;
	}
	if (m->br.path[0] && delete_remote && m->br.ours && m->mpath[0] && m->uq_up)
		fire_delete_bearer(m, m->br.path);
	memset(&m->br, 0, sizeof(m->br));
	m->br_n_pcscf = 0;
	m->bst = BS_NONE;
	ev_timer_cancel(m->t_recheck);
	if (m->job == J_CREATE || m->job == J_CONNECT || m->job == J_BGET || m->job == J_ADOPT) {
		/* the call in flight belongs to the bearer that is going away */
		cancel_pends(m, 0);
		m->job = J_NONE;
	}
	publish(m);
}

static void abort_aka(struct imsmodem *m, bool report)
{
	int i;

	if (m->cj.kind == CJ_AKA && !m->cj.cur.cancelled && report && m->cj.cur.cb) {
		struct aka_result r;

		memset(&r, 0, sizeof(r));
		r.status = AKA_ERR;
		r.sw = -1;
		m->cj.cur.cb(m->cj.cur.arg, &r);
	}
	if (m->cj.kind == CJ_AKA)
		m->cj.kind = CJ_NONE;
	for (i = 0; report && i < m->naq; i++) {
		struct aka_result r;

		memset(&r, 0, sizeof(r));
		r.status = AKA_ERR;
		r.sw = -1;
		if (m->aq[i].cb && !m->aq[i].cancelled)
			m->aq[i].cb(m->aq[i].arg, &r);
	}
	m->naq = 0;
}

/* the modem object is gone / unusable: forget everything learnt about it */
static void drop_modem(struct imsmodem *m, const char *why)
{
	LOGI("modem: dropping modem %s (%s)", m->mpath[0] ? m->mpath : "-", why);
	m->gen++;
	cancel_pends(m, 1);
	if (m->qh) {
		m->ops.qrtr.cancel(m->ops.qrtr.ctx, m->qh);
		m->qh = NULL;
	}
	m->job = J_NONE;
	abort_aka(m, true);
	m->cj.kind = CJ_NONE;
	m->chan_open = false;
	ev_timer_cancel(m->t_chan);
	release_bearer(m, false);	/* the bearer objects went with the modem */
	if (m->mpath[0] && m->ops.uq.watch_modem)
		m->ops.uq.watch_modem(m->ops.uq.ctx, NULL);
	m->mpath[0] = 0;
	m->mdev[0] = 0;
	m->mstate[0] = 0;
	m->got_get = false;
	m->imei_fmt[0] = 0;
	m->n_mbearers = 0;
	m->adopt_done = false;
	m->enable_tried = false;
	m->sim_got = false;
	m->imsi[0] = 0;
	m->id_ready = false;
	memset(&m->id, 0, sizeof(m->id));
	m->smsc[0] = m->sms_psi[0] = m->simx_key[0] = 0;
	m->simx_done = false;
	m->pani[0] = m->cell_str[0] = 0;
	m->cell_inflight = m->pani_auto = m->hold_used = m->holding = false;
	ev_timer_cancel(m->t_hold);
	m->ims_present = -1;
	ev_timer_cancel(m->t_ims);
	ev_timer_cancel(m->t_retry);
	m->in_backoff = false;
	m->retry_n = 0;
}

/* ------------------------------------------------------------------ */
/* ISIM channel executor                                               */

static void cj_begin(struct imsmodem *m);
static void cj_issue(struct imsmodem *m);

static void chan_idle(void *arg)
{
	struct imsmodem *m = arg;

	if (m->chan_open && m->cj.kind == CJ_NONE) {
		fire_chan_close(m, m->chan);
		m->chan_open = false;
	}
}

static void cj_aka_next(struct imsmodem *m);

/* finish the current channel job; err != 0: a text */
static void cj_finish(struct imsmodem *m, const char *err);

static void cj_apdu_cb(struct imsmodem *m, const struct uq_res *res, void *arg);
static void simx_issue(struct imsmodem *m);
static void simx_err(struct imsmodem *m, const char *err);
static void simx_maybe_start(struct imsmodem *m);
static bool overrides_complete(const struct imsmodem *m);

/* the logical channel the current channel job talks on */
static int cj_chan(const struct imsmodem *m)
{
	return m->cj.kind == CJ_SIMX && m->cj.xs >= XS_SEL_SMSP ? m->cj.uchan : m->chan;
}

static void cj_send(struct imsmodem *m, const uint8_t *apdu, size_t n)
{
	struct uq_req rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_APDU;
	snprintf(rq.obj, sizeof(rq.obj), "%s", m->mpath);
	rq.num = cj_chan(m);
	memcpy(rq.data, apdu, n);
	rq.n = n;
	call(m, &rq, t_or(m->cfg.call_timeout_ms, 15000), PK_CJ, cj_apdu_cb, NULL);
}

static void cj_open_cb(struct imsmodem *m, const struct uq_res *res, void *arg)
{
	(void)arg;
	if (res->err) {
		cj_finish(m, uq_errname(res));
		return;
	}
	if (res->sw1 != 0x90 && res->sw1 != 0x61 && !(res->sw1 == 0 && res->sw2 == 0)) {
		char e[64];

		snprintf(e, sizeof(e), "ISIM channel open: sw %02x%02x", res->sw1, res->sw2);
		cj_finish(m, e);
		return;
	}
	m->chan = res->channel;
	m->chan_open = true;
	LOGD("modem: ISIM logical channel %d open", m->chan);
	cj_issue(m);
}

static void cj_begin(struct imsmodem *m)
{
	struct uq_req rq;

	ev_timer_cancel(m->t_chan);
	if (m->chan_open) {
		cj_issue(m);
		return;
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_CHAN_OPEN;
	snprintf(rq.obj, sizeof(rq.obj), "%s", m->mpath);
	snprintf(rq.str, sizeof(rq.str), "%s", ISIM_AID_DEFAULT);
	call(m, &rq, t_or(m->cfg.call_timeout_ms, 15000), PK_CJ, cj_open_cb, NULL);
}

static void ident_issue(struct imsmodem *m)
{
	struct cjob *c = &m->cj;
	uint8_t a[8];
	size_t n = 0;

	switch (c->step) {
	case IS_SEL_IMPI: n = isim_apdu_select(m->chan, ISIM_FID_IMPI, a); break;
	case IS_SEL_DOM: n = isim_apdu_select(m->chan, ISIM_FID_DOMAIN, a); break;
	case IS_SEL_IMPU: n = isim_apdu_select(m->chan, ISIM_FID_IMPU, a); break;
	case IS_SEL_PCSCF: n = isim_apdu_select(m->chan, ISIM_FID_PCSCF, a); break;
	case IS_RD_IMPI:
	case IS_RD_DOM: n = isim_apdu_read_binary(m->chan, c->le, a); break;
	case IS_REC_IMPU:
	case IS_REC_PCSCF: n = isim_apdu_read_record(m->chan, c->rec, c->le, a); break;
	}
	cj_send(m, a, n);
}

static void cj_issue(struct imsmodem *m)
{
	struct cjob *c = &m->cj;

	if (c->kind == CJ_IDENT) {
		ident_issue(m);
	} else if (c->kind == CJ_AKA) {
		uint8_t apdu[AKA_APDU_MAX];
		size_t n;
		struct aka_cfg ac = { .p2 = 0x81, .cla_from_channel = 1, .channel = m->chan };

		aka_sm_start(&c->sm, &ac, c->cur.rand, c->cur.autn, apdu, &n);
		cj_send(m, apdu, n);
	} else if (c->kind == CJ_SIMX) {
		simx_issue(m);
	}
}

static void ident_next(struct imsmodem *m, enum ident_step s, int rec)
{
	m->cj.step = s;
	m->cj.rec = rec;
	m->cj.le = 0;
	m->cj.le_retry = false;
	ident_issue(m);
}

static void ident_resp(struct imsmodem *m, const uint8_t *d, size_t n)
{
	struct cjob *c = &m->cj;
	char val[96];
	int sw, dl = isim_split_sw(d, n, &sw), l;
	char e[96];

	if (dl < 0) {
		cj_finish(m, "ISIM: short card response");
		return;
	}
	switch (c->step) {
	case IS_SEL_IMPI: case IS_SEL_DOM: case IS_SEL_IMPU: case IS_SEL_PCSCF:
		if (sw != 0x9000 && (sw >> 8) != 0x61) {
			if (c->step == IS_SEL_PCSCF) {
				cj_finish(m, NULL);	/* informational file missing: fine */
				return;
			}
			snprintf(e, sizeof(e), "ISIM: SELECT failed, sw %04x", sw);
			cj_finish(m, e);
			return;
		}
		if (c->step == IS_SEL_IMPI) ident_next(m, IS_RD_IMPI, 0);
		else if (c->step == IS_SEL_DOM) ident_next(m, IS_RD_DOM, 0);
		else if (c->step == IS_SEL_IMPU) ident_next(m, IS_REC_IMPU, 1);
		else ident_next(m, IS_REC_PCSCF, 1);
		return;
	case IS_RD_IMPI: case IS_RD_DOM:
		if ((sw >> 8) == 0x6C && !c->le_retry) {
			c->le = sw & 0xff;
			c->le_retry = true;
			ident_issue(m);
			return;
		}
		l = sw == 0x9000 ? isim_tlv80(d, dl, val, sizeof(val)) : -1;
		if (l < 0) {
			snprintf(e, sizeof(e), "ISIM: cannot read %s (sw %04x)", c->step == IS_RD_IMPI ? "EF_IMPI" : "EF_DOMAIN", sw);
			cj_finish(m, e);
			return;
		}
		if (c->step == IS_RD_IMPI) {
			snprintf(c->impi, sizeof(c->impi), "%s", val);
			ident_next(m, IS_SEL_DOM, 0);
		} else {
			snprintf(c->domain, sizeof(c->domain), "%s", val);
			ident_next(m, IS_SEL_IMPU, 0);
		}
		return;
	case IS_REC_IMPU:
		if ((sw >> 8) == 0x6C && !c->le_retry) {
			c->le = sw & 0xff;
			c->le_retry = true;
			ident_issue(m);
			return;
		}
		if (sw == 0x9000) {
			l = isim_tlv80(d, dl, val, sizeof(val));
			if (l > 0) {
				if (isim_impu_usable(val)) {
					LOGI("modem: ISIM IMPU record %d: %s", c->rec, val);
					snprintf(c->impu, sizeof(c->impu), "%s", val);
					ident_next(m, IS_SEL_PCSCF, 0);
					return;
				}
				LOGI("modem: ISIM IMPU record %d skipped (emergency or not a SIP URI): %s", c->rec, val);
			}
			if (c->rec < 8) {
				c->rec++;
				c->le = 0;
				c->le_retry = false;
				ident_issue(m);
				return;
			}
		} else if (c->rec == 1) {
			snprintf(e, sizeof(e), "ISIM: cannot read EF_IMPU (sw %04x)", sw);
			cj_finish(m, e);
			return;
		}
		cj_finish(m, "ISIM: no usable IMPU (only emergency identities)");
		return;
	case IS_REC_PCSCF:
		if (sw == 0x9000 && isim_tlv80(d, dl, val, sizeof(val)) > 1 && c->rec <= 4) {
			/* 80 len <type> <name>: informational only, the FQDNs do not offer sec-agree */
			LOGI("modem: ISIM P-CSCF record %d (informational, not used): %s", c->rec, val + 1);
			c->rec++;
			c->le = 0;
			c->le_retry = false;
			ident_issue(m);
			return;
		}
		cj_finish(m, NULL);
		return;
	}
}

/* ---- extra SIM reads (SMSC, SMS PSI) ---- */

static void simx_next(struct imsmodem *m, enum simx_step xs, int rec)
{
	m->cj.xs = xs;
	m->cj.rec = rec;
	m->cj.le = 0;
	m->cj.le_retry = false;
	m->cj.grle = 0;
	simx_issue(m);
}

static void simx_end(struct imsmodem *m)
{
	struct cjob *c = &m->cj;

	if (c->uopen)
		fire_chan_close(m, c->uchan);
	c->uopen = false;
	snprintf(m->smsc, sizeof(m->smsc), "%s", c->smsc);
	snprintf(m->sms_psi, sizeof(m->sms_psi), "%s", c->psi);
	snprintf(m->simx_key, sizeof(m->simx_key), "%s", m->sim_key);
	m->simx_done = true;
	LOGI("modem: SIM: SMSC %s, SMS PSI %s", m->smsc[0] ? m->smsc : "none", m->sms_psi[0] ? m->sms_psi : "none");
	c->kind = CJ_NONE;
	ev_timer_set(m->t_chan, t_or(m->cfg.chan_idle_ms, 20000));
	cj_aka_next(m);
}

static void simx_uopen_cb(struct imsmodem *m, const struct uq_res *res, void *arg)
{
	(void)arg;
	if (res->err) {
		simx_err(m, uq_errname(res));
		return;
	}
	if (res->sw1 != 0x90 && res->sw1 != 0x61 && !(res->sw1 == 0 && res->sw2 == 0)) {
		char e[64];

		snprintf(e, sizeof(e), "USIM channel open: sw %02x%02x", res->sw1, res->sw2);
		simx_err(m, e);
		return;
	}
	m->cj.uchan = res->channel;
	m->cj.uopen = true;
	LOGD("modem: USIM logical channel %d open", res->channel);
	simx_next(m, XS_SEL_SMSP, 0);
}

static void simx_open_usim(struct imsmodem *m)
{
	struct uq_req rq;

	/* the card has few logical channels and the modem holds some: never keep the ISIM one open next to the USIM one */
	if (m->chan_open) {
		fire_chan_close(m, m->chan);
		m->chan_open = false;
	}
	m->cj.xs = XS_OPEN_USIM;
	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_CHAN_OPEN;
	snprintf(rq.obj, sizeof(rq.obj), "%s", m->mpath);
	snprintf(rq.str, sizeof(rq.str), "%s", USIM_AID);
	call(m, &rq, t_or(m->cfg.call_timeout_ms, 15000), PK_CJ, simx_uopen_cb, NULL);
}

static void simx_issue(struct imsmodem *m)
{
	struct cjob *c = &m->cj;
	uint8_t a[8];
	size_t n = 0;
	int ch = cj_chan(m);

	if (c->xs == XS_OPEN_USIM) {
		simx_open_usim(m);
		return;
	}
	if (c->grle) {
		n = isim_apdu_get_response(ch, c->grle, a);
	} else {
		switch (c->xs) {
		case XS_SEL_ISIM_PSI:
		case XS_SEL_USIM_PSI: n = isim_apdu_select(ch, ISIM_FID_PSISMSC, a); break;
		case XS_SEL_SMSP: n = isim_apdu_select(ch, USIM_FID_SMSP, a); break;
		case XS_RD_ISIM_PSI:
		case XS_RD_USIM_PSI: n = isim_apdu_read_binary(ch, c->le, a); break;
		case XS_REC_SMSP: n = isim_apdu_read_record(ch, 1, c->le, a); break;
		case XS_OPEN_USIM: break;
		}
	}
	cj_send(m, a, n);
}

/* the file at the current step is not there / unusable: go on with what is left */
static void simx_skip(struct imsmodem *m)
{
	struct cjob *c = &m->cj;

	switch (c->xs) {
	case XS_SEL_ISIM_PSI: case XS_RD_ISIM_PSI:
		simx_open_usim(m);
		return;
	case XS_OPEN_USIM: case XS_SEL_SMSP: case XS_REC_SMSP:
		if (!c->psi[0] && c->uopen) {
			simx_next(m, XS_SEL_USIM_PSI, 0);
			return;
		}
		break;
	case XS_SEL_USIM_PSI: case XS_RD_USIM_PSI:
		break;
	}
	simx_end(m);
}

static void simx_err(struct imsmodem *m, const char *err)
{
	LOGD("modem: SIM extras: %s", err ? err : "failed");
	simx_skip(m);
}

static void simx_resp(struct imsmodem *m, const uint8_t *d, size_t n)
{
	struct cjob *c = &m->cj;
	int sw, dl = isim_split_sw(d, n, &sw);

	if (dl < 0) {
		simx_err(m, "short card response");
		return;
	}
	switch (c->xs) {
	case XS_SEL_ISIM_PSI: case XS_SEL_SMSP: case XS_SEL_USIM_PSI:
		if (sw != 0x9000 && (sw >> 8) != 0x61) {
			LOGD("modem: SIM extras: SELECT sw %04x (file not present)", sw);
			simx_skip(m);
			return;
		}
		simx_next(m, c->xs == XS_SEL_ISIM_PSI ? XS_RD_ISIM_PSI : c->xs == XS_SEL_SMSP ? XS_REC_SMSP : XS_RD_USIM_PSI, 0);
		return;
	case XS_RD_ISIM_PSI: case XS_RD_USIM_PSI: case XS_REC_SMSP:
		if ((sw >> 8) == 0x6C && !c->le_retry) {
			c->le = sw & 0xff;
			c->le_retry = true;
			simx_issue(m);
			return;
		}
		if ((sw >> 8) == 0x61 && !c->grle) {
			c->grle = sw & 0xff;
			simx_issue(m);
			return;
		}
		if (sw != 0x9000) {
			LOGD("modem: SIM extras: read sw %04x", sw);
			simx_skip(m);
			return;
		}
		if (c->xs == XS_REC_SMSP) {
			int l = isim_smsp_parse(d, dl, c->smsc, sizeof(c->smsc));

			if (l < 0)
				LOGD("modem: SIM extras: EF_SMSP record not usable");
		} else if (isim_psismsc_parse(d, dl, c->psi, sizeof(c->psi)) < 0) {
			LOGD("modem: SIM extras: EF_PSISMSC holds no URI");
		}
		simx_skip(m);
		return;
	case XS_OPEN_USIM:
		return;
	}
}

static void simx_start(struct imsmodem *m)
{
	struct cjob *c;

	m->smsc[0] = m->sms_psi[0] = 0;
	memset(&m->cj, 0, sizeof(m->cj));
	c = &m->cj;
	c->kind = CJ_SIMX;
	if (overrides_complete(m)) {	/* the ISIM is not used at all in this configuration */
		simx_open_usim(m);
		return;
	}
	c->xs = XS_SEL_ISIM_PSI;
	cj_begin(m);
}

/* the SIM read runs once per SIM, in the background, when the channel executor is idle (the AKA service has priority) */
static void simx_maybe_start(struct imsmodem *m)
{
	if (m->stopping || !m->uq_up || !m->mpath[0] || !m->id_ready || m->cj.kind != CJ_NONE || m->naq || !modem_state_ok(m->mstate))
		return;
	if (m->simx_done && !strcmp(m->simx_key, m->sim_key))
		return;
	simx_start(m);
}

/* an AKA request needs the channel: give up the extras (they run again when the executor is idle) */
static void simx_abort(struct imsmodem *m)
{
	cancel_cj_pends(m);
	if (m->cj.uopen)
		fire_chan_close(m, m->cj.uchan);
	if (m->cj.xs < XS_SEL_SMSP && m->chan_open) {
		fire_chan_close(m, m->chan);	/* an APDU may have been in flight on it */
		m->chan_open = false;
	}
	m->cj.kind = CJ_NONE;
}

static void aka_resp(struct imsmodem *m, const uint8_t *d, size_t n)
{
	struct cjob *c = &m->cj;
	uint8_t apdu[AKA_APDU_MAX];
	size_t an;

	switch (aka_sm_feed(&c->sm, d, n, apdu, &an)) {
	case AKA_STEP_SEND:
		cj_send(m, apdu, an);
		return;
	case AKA_STEP_DONE:
		cj_finish(m, NULL);
		return;
	case AKA_STEP_FAIL:
		LOGW("modem: AKA failed on the card (sw %04x)", c->sm.res.sw < 0 ? 0 : c->sm.res.sw);
		cj_finish(m, NULL);	/* the result carries status ERR and the status word */
		return;
	}
}

static void cj_apdu_cb(struct imsmodem *m, const struct uq_res *res, void *arg)
{
	struct cjob *c = &m->cj;

	(void)arg;
	if (res->err && c->kind == CJ_SIMX) {
		if (c->xs < XS_SEL_SMSP)
			m->chan_open = false;
		simx_err(m, uq_errname(res));
		return;
	}
	if (res->err) {
		if (!c->retried && res->err != UQ_E_GONE && c->kind != CJ_NONE) {
			LOGI("modem: ISIM APDU failed (%s), reopening the channel once", uq_errname(res));
			c->retried = true;
			m->chan_open = false;
			cj_begin(m);
			return;
		}
		m->chan_open = false;	/* state unknown: open a fresh channel next time */
		if (c->kind == CJ_AKA)
			aka_sm_abort(&c->sm);
		cj_finish(m, uq_errname(res));
		return;
	}
	if (c->kind == CJ_IDENT)
		ident_resp(m, res->data, res->n);
	else if (c->kind == CJ_SIMX)
		simx_resp(m, res->data, res->n);
	else if (c->kind == CJ_AKA)
		aka_resp(m, res->data, res->n);
}

static void ident_done(struct imsmodem *m, const char *err);

static void cj_finish(struct imsmodem *m, const char *err)
{
	struct cjob *c = &m->cj;
	enum cj_kind k = c->kind;

	if (k == CJ_NONE)
		return;
	ev_timer_set(m->t_chan, t_or(m->cfg.chan_idle_ms, 20000));
	if (k == CJ_SIMX) {	/* only reached with an error from the channel open */
		simx_err(m, err);
		return;
	}
	if (k == CJ_IDENT) {
		c->kind = CJ_NONE;
		ident_done(m, err);
		cj_aka_next(m);
	} else {
		struct aka_req cur = c->cur;
		struct aka_result r;

		c->kind = CJ_NONE;
		if (err) {
			memset(&r, 0, sizeof(r));
			r.status = AKA_ERR;
			r.sw = -1;
			LOGW("modem: AKA: %s", err);
		} else {
			r = *aka_sm_result(&c->sm);
		}
		memset(&c->sm, 0, sizeof(c->sm));
		memset(&c->cur, 0, sizeof(c->cur));
		if (cur.cb && !cur.cancelled)
			cur.cb(cur.arg, &r);
		memset(&r, 0, sizeof(r));	/* keys */
		cj_aka_next(m);
	}
}

static void cj_aka_next(struct imsmodem *m)
{
	if (m->cj.kind != CJ_NONE || m->stopping || !m->mpath[0])
		return;
	if (!m->naq) {
		simx_maybe_start(m);
		return;
	}
	memset(&m->cj, 0, sizeof(m->cj));
	m->cj.kind = CJ_AKA;
	m->cj.cur = m->aq[0];
	memmove(&m->aq[0], &m->aq[1], sizeof(m->aq[0]) * (--m->naq));
	if (m->cj.cur.cancelled) {
		m->cj.kind = CJ_NONE;
		cj_aka_next(m);
		return;
	}
	cj_begin(m);
}

int imsmodem_aka(struct imsmodem *m, const uint8_t rand[16], const uint8_t autn[16], imsmodem_aka_cb cb, void *arg)
{
	struct aka_req *q;

	if (m->stopping)
		return -ESHUTDOWN;
	if (!m->mpath[0] || !m->uq_up)
		return -ENODEV;
	if (m->naq >= AKA_QUEUE)
		return -ENOMEM;
	q = &m->aq[m->naq++];
	memset(q, 0, sizeof(*q));
	memcpy(q->rand, rand, 16);
	memcpy(q->autn, autn, 16);
	q->cb = cb;
	q->arg = arg;
	if (m->cj.kind == CJ_SIMX)
		simx_abort(m);
	cj_aka_next(m);
	return 0;
}

void imsmodem_aka_cancel(struct imsmodem *m, void *arg)
{
	int i;

	if (m->cj.kind == CJ_AKA && m->cj.cur.arg == arg)
		m->cj.cur.cancelled = true;
	for (i = 0; i < m->naq; i++)
		if (m->aq[i].arg == arg)
			m->aq[i].cancelled = true;
}

/* ------------------------------------------------------------------ */
/* identity                                                            */

static void apply_overrides(struct imsmodem *m, struct ims_identity *id)
{
	char host[96];

	if (m->cfg.o_impi[0]) snprintf(id->impi, sizeof(id->impi), "%s", m->cfg.o_impi);
	if (m->cfg.o_impu[0]) snprintf(id->impu, sizeof(id->impu), "%s", m->cfg.o_impu);
	if (m->cfg.o_domain[0]) snprintf(id->domain, sizeof(id->domain), "%s", m->cfg.o_domain);
	id->user[0] = 0;
	if (!isim_impu_split(id->impu, id->user, sizeof(id->user), host, sizeof(host)) && !id->domain[0])
		snprintf(id->domain, sizeof(id->domain), "%s", host);
	snprintf(id->imei, sizeof(id->imei), "%s", m->imei_fmt);
}

static bool overrides_complete(const struct imsmodem *m)
{
	return m->cfg.o_impi[0] && m->cfg.o_impu[0] && m->cfg.o_domain[0];
}

static void ident_done(struct imsmodem *m, const char *err)
{
	struct cjob *c = &m->cj;

	m->job = J_NONE;
	if (err) {
		set_error(m, "ISIM identity read failed: %s", err);
		set_reason(m, "isim-error");
		schedule_retry(m);
		return;
	}
	if (!c->impi[0] || !c->domain[0] || !c->impu[0]) {
		set_error(m, "ISIM identity incomplete");
		set_reason(m, "isim-error");
		schedule_retry(m);
		return;
	}
	memset(&m->cache, 0, sizeof(m->cache));
	snprintf(m->cache.impi, sizeof(m->cache.impi), "%s", c->impi);
	snprintf(m->cache.impu, sizeof(m->cache.impu), "%s", c->impu);
	snprintf(m->cache.domain, sizeof(m->cache.domain), "%s", c->domain);
	snprintf(m->cache_key, sizeof(m->cache_key), "%s", m->sim_key);
	m->cache_valid = true;
	m->id = m->cache;
	apply_overrides(m, &m->id);
	m->id_ready = true;
	/* uqmid does not always report the IMSI (seen empty on the UFI): the private identity of an ISIM is
	 * <IMSI>@<home domain> (TS 23.003 13.3), so take the IMSI from there when the user part is all digits */
	if (!m->imsi[0]) {
		size_t n = strspn(m->id.impi, "0123456789");

		if (n >= 14 && n <= 15 && m->id.impi[n] == '@' && n < sizeof(m->imsi)) {
			memcpy(m->imsi, m->id.impi, n);
			m->imsi[n] = 0;
		}
	}
	LOGI("modem: identity: impi %s impu %s domain %s%s%s", m->id.impi, m->id.impu, m->id.domain,
	     m->id.imei[0] ? " imei " : "", m->id.imei);
	m->retry_n = 0;
	step(m);
}

/* ------------------------------------------------------------------ */
/* serving cell (P-Access-Network-Info)                                */

bool imsmodem_earfcn_is_tdd(unsigned earfcn)
{
	return earfcn >= 36000 && earfcn <= 60254;
}

int imsmodem_pani_format(const char *plmn, unsigned tac, unsigned eci, bool tdd, char *out, size_t n)
{
	size_t i, l = strlen(plmn);
	int r;

	if (l != 5 && l != 6)
		return -1;
	for (i = 0; i < l; i++)
		if (plmn[i] < '0' || plmn[i] > '9')
			return -1;
	if (tac > 0xFFFF || eci > 0xFFFFFFF)
		return -1;
	r = snprintf(out, n, "3GPP-E-UTRAN-%s; utran-cell-id-3gpp=%s%04X%07X", tdd ? "TDD" : "FDD", plmn, tac, eci);
	return r < 0 || (size_t)r >= n ? -1 : 0;
}

static void on_cell(struct imsmodem *m, const struct uq_res *r, void *arg)
{
	(void)arg;
	m->cell_inflight = false;
	if (r->err) {
		LOGD("modem: cell info: %s", uq_errname(r));
	} else if (!r->cell_valid) {
		LOGD("modem: cell info: no serving LTE cell");
	} else {
		char pani[sizeof(m->pani)], cs[sizeof(m->cell_str)];
		bool tdd = r->cell_has_earfcn && imsmodem_earfcn_is_tdd(r->cell_earfcn);

		if (imsmodem_pani_format(r->cell_plmn, r->cell_tac, r->cell_ci, tdd, pani, sizeof(pani))) {
			LOGW("modem: cell info: unusable serving cell data (plmn %s)", r->cell_plmn);
		} else {
			if (r->cell_has_earfcn)
				snprintf(cs, sizeof(cs), "lte %s tac %X ci %X earfcn %u", r->cell_plmn, r->cell_tac, r->cell_ci, r->cell_earfcn);
			else
				snprintf(cs, sizeof(cs), "lte %s tac %X ci %X", r->cell_plmn, r->cell_tac, r->cell_ci);
			if (strcmp(pani, m->pani))
				LOGI("modem: serving cell: %s", cs);
			memcpy(m->pani, pani, sizeof(pani));
			memcpy(m->cell_str, cs, sizeof(cs));
		}
	}
	if (m->holding) {
		m->holding = false;
		ev_timer_cancel(m->t_hold);
		publish(m);
		step(m);
	}
}

static void cell_start(struct imsmodem *m)
{
	struct uq_req rq;

	if (m->cell_inflight)
		return;
	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_CELL_INFO;
	snprintf(rq.obj, sizeof(rq.obj), "%s", m->mpath);
	m->cell_inflight = true;
	call(m, &rq, t_or(m->cfg.call_timeout_ms, 15000), PK_CELL, on_cell, NULL);
}

void imsmodem_pani_refresh(struct imsmodem *m)
{
	if (!m || m->stopping || !m->uq_up || !m->mpath[0] || !modem_state_ok(m->mstate))
		return;
	cell_start(m);
}

static void hold_fire(void *arg)
{
	struct imsmodem *m = arg;

	if (!m->holding)
		return;
	LOGD("modem: no serving cell within 1 s, going on without");
	m->holding = false;
	publish(m);
	step(m);
}

/* ------------------------------------------------------------------ */
/* job completions                                                     */

static bool pin_matches(const struct imsmodem *m, const char *path, const char *device)
{
	return !m->cfg.modem_pin[0] || !strcmp(m->cfg.modem_pin, device) || !strcmp(m->cfg.modem_pin, path);
}

static void adopt_modem(struct imsmodem *m, const char *path, const char *device)
{
	snprintf(m->mpath, sizeof(m->mpath), "%s", path);
	snprintf(m->mdev, sizeof(m->mdev), "%s", device);
	m->got_get = false;
	m->ims_present = -1;
	LOGI("modem: using %s (%s)", path, device);
	if (m->ops.uq.watch_modem)
		m->ops.uq.watch_modem(m->ops.uq.ctx, path);
}

static void on_list(struct imsmodem *m, const struct uq_res *r, void *arg)
{
	int i;

	(void)arg;
	m->job = J_NONE;
	if (r->err) {
		set_error(m, "uqmid list: %s", uq_errname(r));
		schedule_retry(m);
		return;
	}
	for (i = 0; i < r->n_modems; i++)
		if (pin_matches(m, r->modems[i].path, r->modems[i].device))
			break;
	if (i == r->n_modems) {
		set_reason(m, "no-modem");
		schedule_retry(m);	/* modem.added normally arrives first */
		return;
	}
	if (r->n_modems > 1 && !m->cfg.modem_pin[0])
		LOGW("modem: %d modems present and none pinned, using the first (%s)", r->n_modems, r->modems[i].path);
	adopt_modem(m, r->modems[i].path, r->modems[i].device);
	m->retry_n = 0;
	step(m);
}

static void on_mget(struct imsmodem *m, const struct uq_res *r, void *arg)
{
	int i;

	(void)arg;
	m->job = J_NONE;
	if (r->err == UQ_E_GONE) {
		drop_modem(m, "object gone");
		step(m);
		return;
	}
	if (r->err) {
		set_error(m, "modem get: %s", uq_errname(r));
		schedule_retry(m);
		return;
	}
	snprintf(m->mstate, sizeof(m->mstate), "%s", r->state);
	m->imei_fmt[0] = 0;
	if (r->imei[0] && ims_format_imei(r->imei, m->imei_fmt, sizeof(m->imei_fmt)))
		LOGW("modem: unusable IMEI '%s'", r->imei);
	m->n_mbearers = r->n_bearer_paths;
	for (i = 0; i < r->n_bearer_paths && i < UQ_MAX_BEARERS; i++)
		snprintf(m->mbearers[i], UQ_PATH, "%s", r->bearer_paths[i]);
	m->got_get = true;
	if (strcmp(m->mstate, "disabled"))
		m->enable_tried = false;
	LOGI("modem: %s state %s, imei %s", m->mpath, m->mstate, m->imei_fmt[0] ? m->imei_fmt : "unknown");
	m->retry_n = 0;
	step(m);
}

static void on_enable(struct imsmodem *m, const struct uq_res *r, void *arg)
{
	(void)arg;
	m->job = J_NONE;
	if (r->err) {
		set_error(m, "enabling the modem: %s", uq_errname(r));
		schedule_retry(m);
		return;
	}
	m->got_get = false;	/* re-read the state */
	step(m);
}

static void on_sim(struct imsmodem *m, const struct uq_res *r, void *arg)
{
	(void)arg;
	m->job = J_NONE;
	if (r->err == UQ_E_GONE) {
		drop_modem(m, "object gone");
		step(m);
		return;
	}
	if (r->err) {
		set_error(m, "sim get: %s", uq_errname(r));
		set_reason(m, "sim-error");
		schedule_retry(m);
		return;
	}
	snprintf(m->sim_key, sizeof(m->sim_key), "%s/%s", r->iccid, r->imsi);
	snprintf(m->imsi, sizeof(m->imsi), "%s", r->imsi);
	m->sim_got = true;
	LOGI("modem: SIM %s", m->sim_key);
	m->retry_n = 0;
	step(m);
}

static void on_qrtr(void *arg, int present)
{
	struct imsmodem *m = arg;

	m->qh = NULL;
	m->job = J_NONE;
	if (present < 0) {
		LOGW("modem: QRTR lookup failed (%d), assuming the modem IMS is off", present);
		present = 0;
	}
	m->ims_present = present > 0 ? 1 : 0;
	if (present > 0) {
		set_reason(m, "modem-ims-active");
		LOGW("modem: the modem's own IMS is active (%d QRTR IMS services), not touching the IMS bearer; re-check in %u s",
		     present, t_or(m->cfg.ims_recheck_ms, 30000) / 1000);
		ev_timer_set(m->t_ims, t_or(m->cfg.ims_recheck_ms, 30000));
	}
	step(m);
}

static void ims_recheck(void *arg)
{
	struct imsmodem *m = arg;

	m->ims_present = -1;
	step(m);
}

/* fill the bearer from a bearer get reply. 0, or -1 with the problem logged */
static int bearer_fill(struct imsmodem *m, const struct uq_res *r)
{
	const struct uq_ipcfg *ip = r->ip6.present && r->ip6.address[0] ? &r->ip6 : (r->ip4.present && r->ip4.address[0] ? &r->ip4 : NULL);
	int i;

	if (!r->ifname[0]) {
		set_error(m, "bearer has no network interface");
		return -1;
	}
	if (!ip || addr_set(&m->br.local, ip->address, 0)) {
		set_error(m, "bearer has no usable IP address");
		return -1;
	}
	snprintf(m->br.ifname, sizeof(m->br.ifname), "%s", r->ifname);
	m->br.prefix = ip->prefix;
	m->br.mtu = ip->mtu;
	m->br.n_dns = 0;
	if (ip->dns1[0]) snprintf(m->br.dns[m->br.n_dns++], sizeof(m->br.dns[0]), "%s", ip->dns1);
	if (ip->dns2[0]) snprintf(m->br.dns[m->br.n_dns++], sizeof(m->br.dns[0]), "%s", ip->dns2);
	m->br_n_pcscf = 0;
	for (i = 0; i < r->n_pcscf && i < UQ_MAX_PCSCF; i++)
		snprintf(m->br_pcscf[m->br_n_pcscf++], sizeof(m->br_pcscf[0]), "%s", r->pcscf[i]);
	return 0;
}

static int apply_netcfg(struct imsmodem *m)
{
	int r;

	memset(&m->net, 0, sizeof(m->net));
	snprintf(m->net.ifname, sizeof(m->net.ifname), "%s", m->br.ifname);
	m->net.local = m->br.local;
	m->net.prefix = m->br.prefix;
	m->net.mtu = m->br.mtu;
	m->net.table = m->cfg.route_table;
	m->net.rule_pref = m->cfg.rule_pref;
	r = m->ops.net.apply(m->ops.net.ctx, &m->net);
	if (r) {
		set_error(m, "configuring %s failed: %s", m->br.ifname, strerror(-r));
		return r;
	}
	m->net_applied = true;
	return 0;
}

static void bearer_failed(struct imsmodem *m, const char *reason)
{
	set_reason(m, "%s", reason);
	release_bearer(m, true);
	schedule_retry(m);
}

static void on_bget(struct imsmodem *m, const struct uq_res *r, void *arg)
{
	(void)arg;
	m->job = J_NONE;
	if (r->err) {
		set_error(m, "bearer get: %s", uq_errname(r));
		bearer_failed(m, "bearer-error");
		return;
	}
	if (!r->connected && strcmp(r->status, "connected")) {
		set_error(m, "bearer is %s after connect", r->status);
		bearer_failed(m, "bearer-error");
		return;
	}
	if (bearer_fill(m, r)) {
		bearer_failed(m, "bearer-error");
		return;
	}
	if (!m->net_applied && apply_netcfg(m)) {
		bearer_failed(m, "netcfg-error");
		return;
	}
	m->bst = BS_UP;
	m->retry_n = 0;
	m->last_error[0] = 0;
	if (!m->br_n_pcscf)
		LOGW("modem: bearer has no P-CSCF from the network%s", m->cfg.n_static ? "; using the static list" : "");
	{
		struct ims_link l;

		build_link(m, &l);
		if (!l.n_pcscf) {
			set_reason(m, "no-pcscf");
			ev_timer_set(m->t_recheck, 30000);
		} else {
			set_reason(m, "%s", "");
		}
	}
	publish(m);
	step(m);
}

static void recheck_bearer(void *arg)
{
	struct imsmodem *m = arg;

	if (m->bst == BS_UP && !m->pub.ready) {
		m->bst = BS_CONNECTED;	/* ask for the bearer info again */
		step(m);
	}
}

static void on_connect(struct imsmodem *m, const struct uq_res *r, void *arg)
{
	(void)arg;
	m->job = J_NONE;
	if (r->err) {
		set_error(m, "bearer connect failed: %s%s", uq_errname(r),
			  strstr(r->errmsg, "201") ? " (the modem's own IMS may be holding the IMS PDN)" : "");
		bearer_failed(m, "bearer-error");
		return;
	}
	m->bst = BS_CONNECTED;
	step(m);
}

static void on_create(struct imsmodem *m, const struct uq_res *r, void *arg)
{
	(void)arg;
	m->job = J_NONE;
	if (r->err || !r->path[0]) {
		set_error(m, "create_bearer failed: %s", r->err ? uq_errname(r) : "no path in the reply");
		set_reason(m, "bearer-error");
		schedule_retry(m);
		return;
	}
	snprintf(m->br.path, sizeof(m->br.path), "%s", r->path);
	m->br.ours = true;
	m->bst = BS_CREATED;
	LOGI("modem: created bearer %s (apn %s, %s, profile %d)", r->path, m->cfg.apn, m->cfg.ip_type, m->cfg.profile_id);
	step(m);
}

static void on_adopt(struct imsmodem *m, const struct uq_res *r, void *arg)
{
	(void)arg;
	m->job = J_NONE;
	if (!r->err && !strcasecmp(r->apn, m->cfg.apn)) {
		snprintf(m->br.path, sizeof(m->br.path), "%s", m->mbearers[m->adopt_i]);
		m->br.ours = true;	/* an IMS bearer left behind by an earlier imsd run */
		m->bst = r->connected ? BS_CONNECTED : BS_CREATED;
		m->adopt_done = true;
		LOGI("modem: adopting existing bearer %s (apn %s, %s)", m->br.path, r->apn, r->status);
	} else {
		m->adopt_i++;
		if (m->adopt_i >= m->n_mbearers)
			m->adopt_done = true;
	}
	step(m);
}

/* ------------------------------------------------------------------ */
/* the stepper                                                         */

static void start_simple(struct imsmodem *m, enum job j, enum uq_op op, const char *obj, unsigned to,
			 void (*fn)(struct imsmodem *, const struct uq_res *, void *))
{
	struct uq_req rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = op;
	snprintf(rq.obj, sizeof(rq.obj), "%s", obj);
	m->job = j;
	call(m, &rq, to, PK_JOB, fn, NULL);
}

static void step_once(struct imsmodem *m)
{
	unsigned to = t_or(m->cfg.call_timeout_ms, 15000);
	struct uq_req rq;

	if (m->stopping || m->job != J_NONE)
		return;
	if (!m->uq_up) {
		set_reason(m, "waiting-for-uqmid");
		return;
	}
	if (m->in_backoff)
		return;
	if (!m->mpath[0]) {
		set_reason(m, "no-modem");
		start_simple(m, J_LIST, UQ_LIST, "uqmid", to, on_list);
		return;
	}
	if (!m->got_get) {
		start_simple(m, J_MGET, UQ_MODEM_GET, m->mpath, to, on_mget);
		return;
	}
	if (!modem_state_ok(m->mstate)) {
		release_bearer(m, true);
		if (!strcmp(m->mstate, "disabled") && m->cfg.manage_modem && !m->enable_tried) {
			m->enable_tried = true;
			set_reason(m, "enabling-modem");
			memset(&rq, 0, sizeof(rq));
			rq.op = UQ_ENABLE;
			rq.flag = true;
			snprintf(rq.obj, sizeof(rq.obj), "%s", m->mpath);
			m->job = J_ENABLE;
			call(m, &rq, 60000, PK_JOB, on_enable, NULL);
			return;
		}
		set_reason(m, "modem-%s", m->mstate);
		publish(m);
		return;
	}
	if (!m->id_ready) {
		if (overrides_complete(m)) {
			memset(&m->id, 0, sizeof(m->id));
			apply_overrides(m, &m->id);
			m->id_ready = true;
			m->again = true;
			return;
		}
		if (!m->sim_got) {
			set_reason(m, "reading-sim");
			start_simple(m, J_SIM, UQ_SIM_GET, m->mpath, to, on_sim);
			return;
		}
		if (m->cache_valid && !strcmp(m->cache_key, m->sim_key)) {
			m->id = m->cache;
			apply_overrides(m, &m->id);
			m->id_ready = true;
			LOGI("modem: identity from cache (same SIM): impu %s", m->id.impu);
			m->again = true;
			return;
		}
		set_reason(m, "reading-isim");
		m->job = J_ISIM;
		memset(&m->cj, 0, sizeof(m->cj));
		m->cj.kind = CJ_IDENT;
		m->cj.step = IS_SEL_IMPI;
		cj_begin(m);
		return;
	}
	simx_maybe_start(m);
	if (!m->pani_auto) {
		m->pani_auto = true;
		cell_start(m);
	}
	if (m->ims_present < 0) {
		m->job = J_QRTR;
		m->qh = m->ops.qrtr.start(m->ops.qrtr.ctx, on_qrtr, m);
		if (!m->qh) {
			m->job = J_NONE;
			LOGW("modem: QRTR lookup could not start, assuming the modem IMS is off");
			m->ims_present = 0;
			m->again = true;
		}
		return;
	}
	if (m->ims_present > 0) {
		set_reason(m, "modem-ims-active");
		release_bearer(m, true);
		return;
	}
	switch (m->bst) {
	case BS_NONE:
		if (!m->adopt_done && m->n_mbearers > 0) {
			if (m->adopt_i >= m->n_mbearers) {
				m->adopt_done = true;
				m->again = true;
				return;
			}
			set_reason(m, "looking-for-bearer");
			memset(&rq, 0, sizeof(rq));
			rq.op = UQ_BEARER_GET;
			snprintf(rq.obj, sizeof(rq.obj), "%s", m->mbearers[m->adopt_i]);
			m->job = J_ADOPT;
			call(m, &rq, to, PK_JOB, on_adopt, NULL);
			return;
		}
		set_reason(m, "creating-bearer");
		memset(&rq, 0, sizeof(rq));
		rq.op = UQ_CREATE_BEARER;
		snprintf(rq.obj, sizeof(rq.obj), "%s", m->mpath);
		snprintf(rq.str, sizeof(rq.str), "%s", m->cfg.apn);
		snprintf(rq.str2, sizeof(rq.str2), "%s", m->cfg.ip_type);
		rq.num = m->cfg.profile_id;
		m->job = J_CREATE;
		call(m, &rq, to, PK_JOB, on_create, NULL);
		return;
	case BS_CREATED:
		set_reason(m, "connecting-bearer");
		start_simple(m, J_CONNECT, UQ_BEARER_CONNECT, m->br.path, t_or(m->cfg.connect_timeout_ms, 45000), on_connect);
		return;
	case BS_CONNECTED:
		start_simple(m, J_BGET, UQ_BEARER_GET, m->br.path, to, on_bget);
		return;
	case BS_UP:
		publish(m);
		return;
	}
}

static void step(struct imsmodem *m)
{
	if (m->in_step) {
		m->again = true;
		return;
	}
	m->in_step = true;
	do {
		m->again = false;
		step_once(m);
	} while (m->again);
	m->in_step = false;
}

/* ------------------------------------------------------------------ */
/* events                                                              */

void imsmodem_uqmid_up(struct imsmodem *m, bool up)
{
	if (up == m->uq_up)
		return;
	m->uq_up = up;
	LOGI("modem: uqmid %s", up ? "reachable" : "gone");
	if (!up) {
		drop_modem(m, "uqmid gone");
		set_reason(m, "waiting-for-uqmid");
		publish(m);
	} else {
		m->retry_n = 0;
	}
	step(m);
}

void imsmodem_ev_modem_added(struct imsmodem *m, const char *path, const char *device)
{
	if (m->mpath[0] || m->stopping || !pin_matches(m, path, device)) {
		LOGD("modem: ignoring added modem %s", path);
		return;
	}
	adopt_modem(m, path, device);
	ev_timer_cancel(m->t_retry);
	m->in_backoff = false;
	step(m);
}

void imsmodem_ev_modem_removed(struct imsmodem *m, const char *path)
{
	if (strcmp(m->mpath, path))
		return;
	drop_modem(m, "removed");
	step(m);
}

void imsmodem_ev_state(struct imsmodem *m, const char *modem_path, const char *new_state)
{
	if (strcmp(m->mpath, modem_path))
		return;
	if (!strcmp(m->mstate, new_state))
		return;
	LOGI("modem: state %s -> %s", m->mstate, new_state);
	snprintf(m->mstate, sizeof(m->mstate), "%s", new_state);
	if (strcmp(new_state, "disabled"))
		m->enable_tried = false;
	if (!modem_state_ok(new_state)) {
		release_bearer(m, true);
		m->ims_present = -1;
	}
	step(m);
}

void imsmodem_ev_bearer(struct imsmodem *m, const char *modem_path, const char *bearer_path, bool connected)
{
	if (strcmp(m->mpath, modem_path) || !m->br.path[0] || strcmp(m->br.path, bearer_path))
		return;
	if (connected) {
		LOGD("modem: bearer %s connected", bearer_path);
		return;
	}
	if (m->bst == BS_CONNECTED || m->bst == BS_UP) {
		set_error(m, "IMS bearer %s was disconnected", bearer_path);
		set_reason(m, "bearer-lost");
		release_bearer(m, true);
		m->retry_n = 0;
		schedule_retry(m);
	}
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                           */

struct imsmodem *imsmodem_new(const struct imsmodem_cfg *cfg, const struct imsmodem_ops *ops)
{
	struct imsmodem *m = calloc(1, sizeof(*m));

	if (!m)
		return NULL;
	m->cfg = *cfg;
	m->ops = *ops;
	m->ims_present = -1;
	m->t_retry = ev_timer_new(retry_fire, m);
	m->t_ims = ev_timer_new(ims_recheck, m);
	m->t_recheck = ev_timer_new(recheck_bearer, m);
	m->t_chan = ev_timer_new(chan_idle, m);
	m->t_hold = ev_timer_new(hold_fire, m);
	if (!m->t_retry || !m->t_ims || !m->t_recheck || !m->t_chan || !m->t_hold) {
		imsmodem_free(m);
		return NULL;
	}
	snprintf(m->reason, sizeof(m->reason), "waiting-for-uqmid");
	return m;
}

void imsmodem_free(struct imsmodem *m)
{
	if (!m)
		return;
	cancel_pends(m, 2);
	if (m->qh)
		m->ops.qrtr.cancel(m->ops.qrtr.ctx, m->qh);
	if (m->net_applied)
		m->ops.net.remove(m->ops.net.ctx, &m->net);
	ev_timer_free(m->t_retry);
	ev_timer_free(m->t_ims);
	ev_timer_free(m->t_recheck);
	ev_timer_free(m->t_chan);
	ev_timer_free(m->t_hold);
	ev_timer_free(m->t_shut);
	memset(m, 0, sizeof(*m));
	free(m);
}

bool imsmodem_set_cfg(struct imsmodem *m, const struct imsmodem_cfg *nc)
{
	const struct imsmodem_cfg *o = &m->cfg;
	bool id_changed = strcmp(o->o_impi, nc->o_impi) || strcmp(o->o_impu, nc->o_impu) || strcmp(o->o_domain, nc->o_domain);
	bool pin_changed = strcmp(o->modem_pin, nc->modem_pin);
	bool br_changed = strcmp(o->apn, nc->apn) || strcmp(o->ip_type, nc->ip_type) || o->profile_id != nc->profile_id ||
			  o->route_table != nc->route_table || o->rule_pref != nc->rule_pref;
	bool restart = id_changed || pin_changed || br_changed;

	m->cfg = *nc;	/* m->net keeps the parameters the running configuration was applied with */
	if (pin_changed && m->mpath[0] && !pin_matches(m, m->mpath, m->mdev)) {
		drop_modem(m, "pin changed");
	} else {
		if (id_changed) {
			m->id_ready = false;
			memset(&m->id, 0, sizeof(m->id));
		}
		if (id_changed || br_changed)
			release_bearer(m, true);
	}
	if (restart) {
		m->retry_n = 0;
		m->in_backoff = false;
		ev_timer_cancel(m->t_retry);
	}
	publish(m);
	step(m);
	return restart;
}

static void shut_finish(struct imsmodem *m)
{
	void (*d)(void *) = m->shut_done;
	void *a = m->shut_arg;

	m->shut_done = NULL;
	ev_timer_cancel(m->t_shut);
	if (d)
		d(a);
}

static void shut_check(struct imsmodem *m)
{
	if (m->stopping && m->shut_done && !m->nfire)
		shut_finish(m);
}

static void shut_timeout(void *arg)
{
	struct imsmodem *m = arg;

	if (m->nfire)
		LOGW("modem: shutdown: %d cleanup call(s) did not finish in time", m->nfire);
	shut_finish(m);
}

void imsmodem_shutdown(struct imsmodem *m, void (*done)(void *arg), void *arg, unsigned timeout_ms)
{
	m->stopping = true;
	m->shut_done = done;
	m->shut_arg = arg;
	ev_timer_cancel(m->t_retry);
	ev_timer_cancel(m->t_ims);
	ev_timer_cancel(m->t_recheck);
	ev_timer_cancel(m->t_chan);
	ev_timer_cancel(m->t_hold);
	m->holding = false;
	cancel_pends(m, 1);
	m->cell_inflight = false;
	if (m->qh) {
		m->ops.qrtr.cancel(m->ops.qrtr.ctx, m->qh);
		m->qh = NULL;
	}
	m->job = J_NONE;
	abort_aka(m, true);
	if (m->cj.kind == CJ_SIMX && m->cj.uopen && m->mpath[0] && m->uq_up)
		fire_chan_close(m, m->cj.uchan);
	m->cj.kind = CJ_NONE;
	if (m->chan_open && m->mpath[0] && m->uq_up) {
		fire_chan_close(m, m->chan);
		m->chan_open = false;
	}
	set_reason(m, "stopping");
	release_bearer(m, true);
	if (!m->t_shut)
		m->t_shut = ev_timer_new(shut_timeout, m);
	if (m->t_shut)
		ev_timer_set(m->t_shut, m->nfire ? timeout_ms : 0);
	else
		shut_finish(m);
}

/* ------------------------------------------------------------------ */
/* status                                                              */

const struct ims_link *imsmodem_link(const struct imsmodem *m) { return &m->pub; }
const char *imsmodem_reason(const struct imsmodem *m) { return m->reason; }
const char *imsmodem_last_error(const struct imsmodem *m) { return m->last_error; }
const char *imsmodem_modem_path(const struct imsmodem *m) { return m->mpath; }
const char *imsmodem_modem_state(const struct imsmodem *m) { return m->mstate; }
bool imsmodem_ims_active(const struct imsmodem *m) { return m->ims_present > 0; }
const char *imsmodem_smsc(const struct imsmodem *m) { return m->smsc; }
const char *imsmodem_sms_psi(const struct imsmodem *m) { return m->sms_psi; }
const char *imsmodem_imsi(const struct imsmodem *m) { return m->imsi; }
const char *imsmodem_pani(const struct imsmodem *m) { return m->pani; }
const char *imsmodem_cell_info(const struct imsmodem *m) { return m->cell_str; }

const char *imsmodem_state_name(const struct imsmodem *m)
{
	if (m->stopping) return "stopping";
	if (!m->uq_up) return "no-uqmid";
	if (!m->mpath[0] || !m->got_get) return "no-modem";
	if (!modem_state_ok(m->mstate)) return "modem-wait";
	if (!m->id_ready) return "identity";
	if (m->ims_present > 0) return "modem-ims-active";
	if (m->bst != BS_UP) return "bearer";
	if (!m->pub.ready && m->holding) return "bearer";
	return m->pub.ready ? "ready" : "no-pcscf";
}
