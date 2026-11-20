/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Gm registration state machine.
 *
 *   IDLE (not enabled) / WAIT_LINK (no usable IMS link)
 *        | link ready
 *        v
 *   UNPROT   REGISTER on an ordinary endpoint to P-CSCF:5060, no credentials
 *        | 401 (WWW-Authenticate AKAv1-MD5, Security-Server)      406 dup ports: new ports, same P-CSCF
 *        v                                                        401 + AUTS resync: REGISTER with auts, stay here
 *   AKA      ISIM AUTHENTICATE through imsmodem (RES, CK, IK or AUTS)
 *        v
 *   SA_INSTALL  4 SAs + 4 policies (xfrm), protected endpoint port-c -> P-CSCF port-s, rx on port-s
 *        v
 *   PROT     REGISTER with the digest response + Security-Verify on the protected endpoint
 *        | 200
 *        v
 *   REGISTERED --(half of the granted time)--> REFRESH --200--> REGISTERED
 *        |                                        | 401 / timeout / error
 *        |                                        v
 *        |                                      REAUTH: a complete new attempt (new ports, SPIs, SAs, endpoint)
 *        |                                        | 200: the old set is retired and its SAs removed after
 *        |                                        |      drain_ms; the registration never drops
 *        |                                        | every P-CSCF failed: everything released -> BACKOFF
 *        | shutdown / manual deregister
 *        v
 *   DEREG    REGISTER Expires: 0, at most dereg_timeout_ms, then everything is released
 *
 *   any failure of an attempt -> next P-CSCF of the list; after the whole list failed: BACKOFF
 *   (5 s doubling to 15 min); 403 -> BACKOFF at the cap with reason "forbidden"; losing the link
 *   (bearer / modem) releases everything and returns to WAIT_LINK.
 *
 * Resources of an attempt (unprotected endpoint, protected endpoint, SAs) are released the moment
 * the attempt is abandoned; a registered set only after its replacement was accepted.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "reg.h"
#include "regmsg.h"
#include "secagree.h"
#include "../sms/rp.h"
#include "../util/codec.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define MAX_HOOKS 4
#define NDRAIN 2

struct reg_set {
	bool used;
	struct xfrm_sa_params sa;
	bool sa_up;
	struct sip_endpoint *ep;
	struct sec_client sc;
	struct addr pc_ps;		/* P-CSCF address, port-s */
	char sec_verify[640];
	char auth[1200];		/* last Authorization value, reused for refresh / de-registration */
	char call_id[128];
	uint32_t cseq;
};

enum at_stage { AT_UNPROT, AT_AKA, AT_PROT };
enum fail_kind { F_NORMAL, F_DUP, F_AUTH, F_FORBIDDEN };

struct attempt {
	struct reg *r;
	enum at_stage stage;
	bool reauth;
	int pidx;
	struct addr pc;			/* P-CSCF, port 0 */
	struct addr pc_un;		/* P-CSCF:5060 */
	struct sip_endpoint *ep_un;
	struct reg_set set;
	struct sec_client sc;
	char call_id[128];
	uint32_t cseq;
	struct digest_challenge ch;
	char opaque[128];
	struct sec_ent chosen;
	char sec_verify[640];
	char unprot_auth[1200];
	struct txn_client *txn;
	struct ev_timer *t_step;
	bool aka_pending;
	int resync;
	bool min_exp_retry;
};

struct drain {
	struct reg *r;
	struct reg_set s;
	struct ev_timer *t;
};

struct reg_hook {
	reg_hook_cb cb;
	void *arg;
};

struct send_ctx;

struct reg {
	struct reg_cfg cfg;
	struct reg_ops ops;
	struct txn_layer *tl;
	struct ims_link link;
	bool have_link;
	bool enabled, stopping;
	enum reg_state state;
	char reason[96];
	char last_error[160];
	struct attempt *at;
	struct reg_set cur;
	struct drain dr[NDRAIN];
	struct txn_client *rtxn;	/* refresh / de-registration */
	struct ev_timer *t_refresh, *t_exp, *t_next, *t_dereg, *t_done;
	int pcscf_idx, round_fails, dup_retries, auth_retries;
	unsigned bo_n;
	int exp_req;			/* requested registration time (raised by 423) */
	uint16_t recent[16];
	int nrecent;
	int nsets;			/* name counter for endpoints */
	/* registration data */
	char pau[256];
	char sroute[REG_MAX_SROUTE][256];
	int n_sroute;
	int granted_s;
	uint64_t registered_at, expires_at;
	bool refresh_min_exp_retry;
	/* shutdown / manual deregistration */
	void (*done)(void *);
	void *done_arg;
	/* counters */
	unsigned n_attempts, n_ok, n_auth_fail, n_fail, n_sms, n_reauth, n_refresh;
	struct reg_hook hooks[MAX_HOOKS];
	struct reg_ctx ctx;
	struct reg_handlers hnd;
	bool own_tl;
	struct send_ctx *sends;	/* reg_send() requests in flight */
	char pani[160];		/* the value in use, see cur_pani() */
	enum reg_pani_src pani_src;
	bool legacy_logged;
};

static void attempt_begin(struct reg *r);
static void attempt_fail(struct attempt *at, enum fail_kind kind, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void refresh_cb(struct txn_client *c, enum txn_cli_event ev, const struct sip_msg *resp,
		       struct sip_endpoint *rx_ep, const struct addr *src, void *arg);

void reg_cfg_defaults(struct reg_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->pcscf_port = 5060;
	c->expires = 8000;
	c->pani[0] = 0;		/* derive from the serving cell, see reg_ops.pani */
	c->port_min = 8000;
	c->port_max = 8999;
	c->backoff_min_ms = 5000;
	c->backoff_max_ms = 900000;
	c->step_timeout_ms = 8000;
	c->aka_timeout_ms = 20000;
	c->drain_ms = 5000;
	c->dereg_timeout_ms = 2000;
	c->next_pcscf_ms = 200;
	c->max_dup_retries = 3;
}

const char *reg_pani_source_name(enum reg_pani_src s)
{
	return s == PANI_CONFIG ? "config" : s == PANI_LIVE ? "cell" : "default";
}

const char *reg_state_name(enum reg_state s)
{
	static const char *const n[] = { "idle", "wait-link", "unprotected-register", "aka", "sa-install",
					 "protected-register", "registered", "refresh", "reauth", "deregistering", "backoff" };
	return (unsigned)s < sizeof(n) / sizeof(n[0]) ? n[s] : "?";
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */

static void set_state(struct reg *r, enum reg_state s, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void set_state(struct reg *r, enum reg_state s, const char *fmt, ...)
{
	va_list ap;

	if (fmt) {
		va_start(ap, fmt);
		vsnprintf(r->reason, sizeof(r->reason), fmt, ap);
		va_end(ap);
	}
	if (r->state != s)
		LOGI("reg: %s -> %s%s%s", reg_state_name(r->state), reg_state_name(s), r->reason[0] ? ": " : "", r->reason);
	r->state = s;
}

static void notify(struct reg *r, enum reg_event ev, const char *reason)
{
	int i;

	for (i = 0; i < MAX_HOOKS; i++)
		if (r->hooks[i].cb)
			r->hooks[i].cb(r->hooks[i].arg, ev, reason);
}

int reg_add_hook(struct reg *r, reg_hook_cb cb, void *arg)
{
	int i;

	for (i = 0; i < MAX_HOOKS; i++)
		if (!r->hooks[i].cb) {
			r->hooks[i].cb = cb;
			r->hooks[i].arg = arg;
			return 0;
		}
	return -1;
}

void reg_remove_hook(struct reg *r, reg_hook_cb cb, void *arg)
{
	int i;

	for (i = 0; i < MAX_HOOKS; i++)
		if (r->hooks[i].cb == cb && r->hooks[i].arg == arg)
			memset(&r->hooks[i], 0, sizeof(r->hooks[i]));
}

static uint16_t pick_port(struct reg *r)
{
	unsigned lo = r->cfg.port_min, hi = r->cfg.port_max, p;
	int i, k;

	if (hi <= lo)
		hi = lo + 1000;
	for (k = 0; k < 64; k++) {
		p = rnd_range(lo, hi);
		for (i = 0; i < r->nrecent; i++)
			if (r->recent[i] == p)
				break;
		if (i < r->nrecent)
			continue;
		break;
	}
	if (r->nrecent == (int)(sizeof(r->recent) / sizeof(r->recent[0])))
		memmove(r->recent, r->recent + 1, sizeof(r->recent) - sizeof(r->recent[0])), r->nrecent--;
	r->recent[r->nrecent++] = p;
	return p;
}

static uint32_t pick_spi(void)
{
	return rnd_range(256, 0x7fffffff);
}

static void set_release(struct reg *r, struct reg_set *s)
{
	if (s->sa_up) {
		r->ops.xfrm_remove(r->ops.ctx, &s->sa);
		s->sa_up = false;
	}
	if (s->ep) {
		sip_ep_retire(s->ep);
		s->ep = NULL;
	}
	memset(s, 0, sizeof(*s));
}

static void rtxn_drop(struct reg *r)
{
	if (r->rtxn) {
		txn_client_detach(r->rtxn);
		r->rtxn = NULL;
	}
}

/* ------------------------------------------------------------------ */
/* attempt lifecycle                                                   */

static void at_txn_drop(struct attempt *at)
{
	if (at->txn) {
		txn_client_detach(at->txn);
		at->txn = NULL;
	}
}

static void attempt_free(struct attempt *at)
{
	struct reg *r = at->r;

	at_txn_drop(at);
	if (at->aka_pending) {
		r->ops.aka_cancel(r->ops.ctx, at);
		at->aka_pending = false;
	}
	ev_timer_free(at->t_step);
	set_release(r, &at->set);
	if (at->ep_un)
		sip_ep_retire(at->ep_un);
	memset(at->ch.rand, 0, sizeof(at->ch.rand));
	if (r->at == at)
		r->at = NULL;
	free(at);
}

static void at_step_timeout(void *arg)
{
	struct attempt *at = arg;

	at_txn_drop(at);
	attempt_fail(at, F_NORMAL, "no answer from the P-CSCF (%s)",
		     at->stage == AT_UNPROT ? "unprotected REGISTER" : at->stage == AT_AKA ? "AKA" : "protected REGISTER");
}

static void at_arm(struct attempt *at, unsigned ms)
{
	ev_timer_set(at->t_step, ms);
}

static void schedule_next(struct reg *r, unsigned ms)
{
	ev_timer_set(r->t_next, ms);
}

/* end of a failed registration: release what is registered and wait */
static void lose_registration(struct reg *r, const char *why);

static void go_backoff(struct reg *r, bool forbidden)
{
	uint64_t d = r->cfg.backoff_min_ms;
	unsigned i;

	if (r->cur.used)
		lose_registration(r, forbidden ? "forbidden" : "all P-CSCFs failed");
	for (i = 0; i < r->bo_n && d < r->cfg.backoff_max_ms; i++)
		d *= 2;
	if (forbidden || d > r->cfg.backoff_max_ms)
		d = r->cfg.backoff_max_ms;
	r->bo_n++;
	r->round_fails = 0;
	r->dup_retries = 0;
	r->auth_retries = 0;
	set_state(r, RS_BACKOFF, "%s; retry in %llu s", forbidden ? "forbidden" : "all P-CSCFs failed",
		  (unsigned long long)(d / 1000));
	schedule_next(r, d);
}

static void attempt_fail(struct attempt *at, enum fail_kind kind, const char *fmt, ...)
{
	struct reg *r = at->r;
	int pidx = at->pidx, n = r->link.n_pcscf ? r->link.n_pcscf : 1;
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(r->last_error, sizeof(r->last_error), fmt, ap);
	va_end(ap);
	LOGW("reg: attempt via P-CSCF %s failed: %s", r->link.pcscf[pidx % n], r->last_error);
	attempt_free(at);
	r->n_fail++;
	if (r->stopping || !r->enabled || !r->link.ready)
		return;
	if (kind == F_FORBIDDEN) {
		r->n_auth_fail++;
		go_backoff(r, true);
		return;
	}
	if (kind == F_DUP && ++r->dup_retries <= r->cfg.max_dup_retries) {
		LOGI("reg: retrying the same P-CSCF with new ports and SPIs (%d)", r->dup_retries);
		set_state(r, r->cur.used ? RS_REAUTH : RS_UNPROT, "retrying with new ports");
		schedule_next(r, 0);
		return;
	}
	if (kind == F_AUTH) {
		r->n_auth_fail++;
		if (++r->auth_retries <= 2) {
			set_state(r, r->cur.used ? RS_REAUTH : RS_UNPROT, "re-authenticating");
			schedule_next(r, 0);
			return;
		}
	}
	r->dup_retries = 0;
	r->auth_retries = 0;
	r->pcscf_idx = (pidx + 1) % n;
	if (++r->round_fails >= n) {
		go_backoff(r, false);
	} else {
		set_state(r, r->cur.used ? RS_REAUTH : RS_UNPROT, "next P-CSCF %s", r->link.pcscf[r->pcscf_idx]);
		schedule_next(r, r->cfg.next_pcscf_ms);
	}
}

/* ------------------------------------------------------------------ */
/* sending REGISTER                                                    */

static int at_send(struct attempt *at, struct sip_endpoint *ep, const struct addr *dst, const struct buf *msg,
		   txn_client_cb cb)
{
	struct txn_client_req q;

	memset(&q, 0, sizeof(q));
	q.ep = ep;
	q.dst = *dst;
	q.data = msg->p;
	q.len = msg->len;
	q.cb = cb;
	q.arg = at;
	at->txn = txn_client_start(at->r->tl, &q);
	return at->txn ? 0 : -1;
}

/*
 * P-Access-Network-Info in use: the explicit configuration, else the live serving cell (reg_ops.pani), else the
 * legacy fixed value so that a missing cell never prevents the registration. Re-evaluated on every use.
 */
static const char *cur_pani(struct reg *r)
{
	const char *v = NULL;

	if (r->cfg.pani[0]) {
		v = r->cfg.pani;
		r->pani_src = PANI_CONFIG;
	} else if (r->ops.pani && (v = r->ops.pani(r->ops.ctx)) && v[0]) {
		r->pani_src = PANI_LIVE;
	} else {
		v = REG_PANI_LEGACY;
		r->pani_src = PANI_DEFAULT;
		if (!r->legacy_logged) {
			r->legacy_logged = true;
			LOGI("reg: no serving cell data, using the default P-Access-Network-Info");
		}
	}
	snprintf(r->pani, sizeof(r->pani), "%s", v);
	return r->pani;
}

static void fill_params(struct reg *r, struct regmsg_params *p)
{
	memset(p, 0, sizeof(*p));
	p->domain = r->link.id.domain;
	p->impu = r->link.id.impu;
	p->user = r->link.id.user;
	p->imei = r->link.id.imei;
	p->pani = cur_pani(r);
	p->user_agent = r->cfg.user_agent;
	p->expires = r->exp_req;
}

static void unprot_cb(struct txn_client *c, enum txn_cli_event ev, const struct sip_msg *resp,
		      struct sip_endpoint *rx_ep, const struct addr *src, void *arg);
static void prot_cb(struct txn_client *c, enum txn_cli_event ev, const struct sip_msg *resp,
		    struct sip_endpoint *rx_ep, const struct addr *src, void *arg);

static int at_send_unprot(struct attempt *at, const char *auth)
{
	struct reg *r = at->r;
	struct regmsg_params p;
	struct buf b;
	int rc;

	fill_params(r, &p);
	p.adv = &at->ep_un->advertised;
	p.pcscf = &at->pc_un;
	p.call_id = at->call_id;
	p.cseq = ++at->cseq;
	p.authorization = auth;
	p.sc = &at->sc;
	buf_init(&b, SIP_MAX_MSG);
	rc = regmsg_build_register(&b, &p, NULL);
	if (!rc) {
		LOGD("reg: sending unprotected REGISTER (CSeq %u)", at->cseq);
		at_txn_drop(at);
		rc = at_send(at, at->ep_un, &at->pc_un, &b, unprot_cb);
	}
	buf_free(&b);
	return rc;
}

static int at_send_prot(struct attempt *at)
{
	struct reg *r = at->r;
	struct reg_set *s = &at->set;
	struct regmsg_params p;
	struct buf b;
	int rc;

	fill_params(r, &p);
	p.adv = &s->ep->advertised;
	p.pcscf = &s->pc_ps;
	p.call_id = s->call_id;
	p.cseq = ++s->cseq;
	p.authorization = s->auth;
	p.is_protected = true;
	p.security_verify = s->sec_verify;
	p.sc = &s->sc;
	buf_init(&b, SIP_MAX_MSG);
	rc = regmsg_build_register(&b, &p, NULL);
	if (!rc) {
		at_txn_drop(at);
		rc = at_send(at, s->ep, &s->pc_ps, &b, prot_cb);
	}
	buf_free(&b);
	return rc;
}

/* ------------------------------------------------------------------ */
/* AKA and SA installation                                             */

static int at_install(struct attempt *at, const struct aka_result *ar)
{
	struct reg *r = at->r;
	struct reg_set *s = &at->set;
	char uri[140], resp[33], ha[64];
	struct addr ue = r->link.br.local;
	int rc;

	addr_set_port(&ue, 0);
	snprintf(uri, sizeof(uri), "sip:%s", r->link.id.domain);
	digest_response(r->link.id.impi, at->ch.realm, ar->res, ar->res_len, at->ch.nonce, "REGISTER", uri, resp);
	if (regmsg_authorization(s->auth, sizeof(s->auth), r->link.id.impi, at->ch.realm, r->link.id.domain, at->ch.nonce,
				 at->opaque, resp, NULL))
		return -EMSGSIZE;
	snprintf(s->sec_verify, sizeof(s->sec_verify), "%s", at->sec_verify);
	snprintf(s->call_id, sizeof(s->call_id), "%s", at->call_id);
	s->cseq = at->cseq;
	s->sc = at->sc;
	s->pc_ps = at->pc;
	addr_set_port(&s->pc_ps, at->chosen.port_s);

	memset(&s->sa, 0, sizeof(s->sa));
	s->sa.ue = ue;
	s->sa.pcscf = at->pc;
	addr_set_port(&s->sa.pcscf, 0);
	s->sa.spi_uc = at->sc.spi_c;
	s->sa.spi_us = at->sc.spi_s;
	s->sa.spi_pc = at->chosen.spi_c;
	s->sa.spi_ps = at->chosen.spi_s;
	s->sa.port_uc = at->sc.port_c;
	s->sa.port_us = at->sc.port_s;
	s->sa.port_pc = at->chosen.port_c;
	s->sa.port_ps = at->chosen.port_s;
	s->sa.sha1 = at->chosen.sha1;
	memcpy(s->sa.ik, ar->ik, 16);
	do {
		s->sa.reqid = rnd_range(1000, 100000) & ~3u;
	} while (s->sa.reqid == r->cur.sa.reqid);
	s->sa.proto = IPPROTO_UDP;

	set_state(r, RS_SA_INSTALL, NULL);
	rc = r->ops.xfrm_install(r->ops.ctx, &s->sa);
	memset(s->sa.ik, 0, sizeof(s->sa.ik));	/* only the key is secret; the rest is needed to remove the SAs */
	if (rc)
		return rc;
	s->sa_up = true;
	s->used = true;
	addr_host(&at->pc, ha, sizeof(ha));
	LOGI("reg: SAs installed (%s, P-CSCF %s: uc %u->ps %u, us %u<-pc %u)", at->chosen.sha1 ? "hmac-sha-1-96" : "hmac-md5-96", ha,
	     at->sc.port_c, at->chosen.port_s, at->sc.port_s, at->chosen.port_c);
	return 0;
}

static int at_open_prot(struct attempt *at)
{
	struct reg *r = at->r;
	struct reg_set *s = &at->set;
	struct sip_ep_cfg c;
	char name[24];

	snprintf(name, sizeof(name), "gm#%d", ++r->nsets);
	memset(&c, 0, sizeof(c));
	c.name = name;
	c.kind = SIP_TP_UDP;
	c.rx_bind = r->link.br.local;
	addr_set_port(&c.rx_bind, at->sc.port_s);
	c.split_tx = true;
	c.tx_bind = r->link.br.local;
	addr_set_port(&c.tx_bind, at->sc.port_c);
	c.netdev = r->link.br.ifname;
	c.has_adv = true;
	c.adv = c.rx_bind;
	c.has_resp_override = true;
	c.resp_override = s->pc_ps;
	c.reliable = false;
	s->ep = r->ops.open_ep(r->ops.ctx, &c);
	if (!s->ep)
		return -errno ? -errno : -EIO;
	txn_layer_attach(r->tl, s->ep);
	return 0;
}

static void aka_done(void *arg, const struct aka_result *ar)
{
	struct attempt *at = arg;
	struct reg *r = at->r;
	int rc;

	at->aka_pending = false;
	if (ar->status == AKA_SYNC_FAIL) {
		char b64[40], auth[1200];

		if (++at->resync > 3) {
			attempt_fail(at, F_NORMAL, "AKA resynchronisation failed repeatedly");
			return;
		}
		LOGI("reg: AKA sync failure, REGISTER with AUTS (%d)", at->resync);
		if (b64_encode(ar->auts, ar->auts_len, b64, sizeof(b64)) < 0 ||
		    regmsg_authorization(auth, sizeof(auth), r->link.id.impi, at->ch.realm, r->link.id.domain, at->ch.nonce,
					 at->opaque, NULL, b64)) {
			attempt_fail(at, F_NORMAL, "cannot build the AUTS authorization");
			return;
		}
		snprintf(at->unprot_auth, sizeof(at->unprot_auth), "%s", auth);
		at->stage = AT_UNPROT;
		set_state(r, r->cur.used ? RS_REAUTH : RS_UNPROT, "resynchronising (AUTS)");
		if (at_send_unprot(at, auth)) {
			attempt_fail(at, F_NORMAL, "cannot send the resynchronisation REGISTER");
			return;
		}
		at_arm(at, r->cfg.step_timeout_ms);
		return;
	}
	if (ar->status != AKA_OK) {
		r->n_auth_fail++;
		attempt_fail(at, F_NORMAL, "AKA failed (card status %04x)", ar->sw < 0 ? 0 : ar->sw);
		return;
	}
	LOGI("reg: AKA ok, installing the security association");
	rc = at_install(at, ar);
	if (rc) {
		attempt_fail(at, F_NORMAL, "SA installation failed: %s", strerror(-rc));
		return;
	}
	rc = at_open_prot(at);
	if (rc) {
		attempt_fail(at, F_NORMAL, "cannot open the protected endpoint: %s", strerror(-rc));
		return;
	}
	at->stage = AT_PROT;
	set_state(r, r->cur.used ? RS_REAUTH : RS_PROT, "protected REGISTER");
	if (at_send_prot(at)) {
		attempt_fail(at, F_NORMAL, "cannot send the protected REGISTER");
		return;
	}
	at_arm(at, r->cfg.step_timeout_ms);
}

/* the 401 to the unprotected REGISTER: challenge + Security-Server */
static void at_on_challenge(struct attempt *at, const struct sip_msg *resp)
{
	struct reg *r = at->r;
	const char *wa = sip_hdr(resp, "WWW-Authenticate", 0);
	struct sec_ent se[SEC_MAX_ENT];
	int n, sel, rc;

	if (!wa || digest_parse_challenge(wa, &at->ch)) {
		attempt_fail(at, F_NORMAL, "401 without a usable WWW-Authenticate");
		return;
	}
	at->opaque[0] = 0;
	sip_kv_get(wa, "opaque", at->opaque, sizeof(at->opaque));
	if (!at->ch.aka) {
		attempt_fail(at, F_NORMAL, "challenge is not AKAv1-MD5 (algorithm %s)", at->ch.algorithm);
		return;
	}
	if (sec_server_value(resp, at->sec_verify, sizeof(at->sec_verify))) {
		attempt_fail(at, F_NORMAL, "401 without Security-Server (this P-CSCF does not offer IPsec sec-agree)");
		return;
	}
	n = sec_parse(at->sec_verify, se, SEC_MAX_ENT);
	sel = sec_select(se, n);
	if (sel < 0) {
		attempt_fail(at, F_NORMAL, "no usable Security-Server mechanism: %s", at->sec_verify);
		return;
	}
	at->chosen = se[sel];
	LOGI("reg: 401 challenge from P-CSCF %s; Security-Server: %s mod=%s spi-c=%u spi-s=%u port-c=%d port-s=%d",
	     r->link.pcscf[at->pidx % (r->link.n_pcscf ? r->link.n_pcscf : 1)], at->chosen.alg, at->chosen.mod,
	     at->chosen.spi_c, at->chosen.spi_s, at->chosen.port_c, at->chosen.port_s);
	at->stage = AT_AKA;
	set_state(r, RS_AKA, "AKA on the ISIM");
	at->aka_pending = true;
	rc = r->ops.aka(r->ops.ctx, at->ch.rand, at->ch.autn, aka_done, at);
	if (rc) {
		at->aka_pending = false;
		attempt_fail(at, F_NORMAL, "cannot start AKA: %s", strerror(-rc));
		return;
	}
	at_arm(at, r->cfg.aka_timeout_ms);
}

/* 423 Interval Too Brief: raise the requested time and send the same REGISTER again. true if handled */
static bool at_min_expires(struct attempt *at, const struct sip_msg *resp)
{
	struct reg *r = at->r;
	const char *me = sip_hdr(resp, "Min-Expires", 0);
	int v = me ? atoi(me) : 0;

	if (resp->status != 423 || at->min_exp_retry || v <= 0)
		return false;
	at->min_exp_retry = true;
	r->exp_req = v;
	LOGI("reg: 423 Interval Too Brief, requesting %d s", v);
	if (at->stage == AT_UNPROT ? at_send_unprot(at, at->unprot_auth) : at_send_prot(at)) {
		attempt_fail(at, F_NORMAL, "cannot resend the REGISTER");
		return true;
	}
	at_arm(at, r->cfg.step_timeout_ms);
	return true;
}

static void unprot_cb(struct txn_client *c, enum txn_cli_event ev, const struct sip_msg *resp,
		      struct sip_endpoint *rx_ep, const struct addr *src, void *arg)
{
	struct attempt *at = arg;

	(void)c; (void)rx_ep; (void)src;
	switch (ev) {
	case TXN_CLI_TERMINATED:
		at->txn = NULL;
		return;
	case TXN_CLI_TIMEOUT:
		at->txn = NULL;
		attempt_fail(at, F_NORMAL, "unprotected REGISTER timed out");
		return;
	case TXN_CLI_TRANSPORT_ERROR:
		at->txn = NULL;
		attempt_fail(at, F_NORMAL, "transport error sending the unprotected REGISTER");
		return;
	case TXN_CLI_RESPONSE:
		break;
	}
	if (resp->status < 200)
		return;
	if (at->stage != AT_UNPROT) {	/* a retransmitted 401 after we moved on */
		LOGD("reg: ignoring late %d on the unprotected endpoint", resp->status);
		return;
	}
	if (resp->status == 401)
		at_on_challenge(at, resp);
	else if (at_min_expires(at, resp))
		return;
	else if (resp->status == 406)
		attempt_fail(at, F_DUP, "406 %s (ports or SPIs already in use at the P-CSCF)", sip_hdr(resp, "Reason", 0) ? sip_hdr(resp, "Reason", 0) : "");
	else if (resp->status == 403)
		attempt_fail(at, F_FORBIDDEN, "403 Forbidden to the unprotected REGISTER");
	else
		attempt_fail(at, F_NORMAL, "unexpected %d %s to the unprotected REGISTER", resp->status, resp->reason);
}

/* ------------------------------------------------------------------ */
/* success                                                             */

static void arm_registered_timers(struct reg *r)
{
	uint64_t half = (uint64_t)r->granted_s * 500;

	if (half < 1000)
		half = 1000;
	ev_timer_set(r->t_refresh, half);
	ev_timer_set(r->t_exp, (uint64_t)r->granted_s * 1000);
	r->expires_at = ev_now_ms() + (uint64_t)r->granted_s * 1000;
}

/* parse the 200 OK: granted time, P-Associated-URI, Service-Route */
static void parse_200(struct reg *r, const struct sip_msg *resp, const struct reg_set *s)
{
	struct sip_list it;
	char el[512], port[16], ex[24];
	const char *h;
	int granted = -1, first = -1;

	snprintf(port, sizeof(port), ":%u", s->sc.port_s);
	sip_list_init(&it, resp, "Contact");
	while (sip_list_next(&it, el, sizeof(el)) == 1) {
		struct sip_nameaddr na;

		if (sip_nameaddr_parse(el, &na))
			continue;
		if (sip_params_get(na.params, "expires", ex, sizeof(ex)) == 1) {
			if (first < 0)
				first = atoi(ex);
			if (strstr(na.uri, port))
				granted = atoi(ex);
		}
	}
	if (granted < 0)
		granted = first;
	if (granted < 0 && (h = sip_hdr(resp, "Expires", 0)))
		granted = atoi(h);
	if (granted <= 0)
		granted = r->exp_req;
	r->granted_s = granted;

	r->pau[0] = 0;
	sip_list_init(&it, resp, "P-Associated-URI");
	if (sip_list_next(&it, el, sizeof(el)) == 1)
		sip_uri_of(el, r->pau, sizeof(r->pau));
	r->n_sroute = 0;
	sip_list_init(&it, resp, "Service-Route");
	while (r->n_sroute < REG_MAX_SROUTE && sip_list_next(&it, el, sizeof(el)) == 1)
		snprintf(r->sroute[r->n_sroute++], sizeof(r->sroute[0]), "%.255s", el);
}

static void drain_fire(void *arg)
{
	struct drain *d = arg;

	set_release(d->r, &d->s);
}

static void drain_set(struct reg *r, struct reg_set *old)
{
	int i, slot = -1;

	for (i = 0; i < NDRAIN; i++)
		if (!r->dr[i].s.used) {
			slot = i;
			break;
		}
	if (slot < 0) {		/* all busy: the oldest (slot 0) goes now */
		slot = 0;
		set_release(r, &r->dr[0].s);
	}
	if (!r->dr[slot].t)
		r->dr[slot].t = ev_timer_new(drain_fire, &r->dr[slot]);
	r->dr[slot].r = r;
	r->dr[slot].s = *old;
	memset(old, 0, sizeof(*old));
	if (r->dr[slot].t)
		ev_timer_set(r->dr[slot].t, r->cfg.drain_ms);
	else
		set_release(r, &r->dr[slot].s);
}

static void promote(struct attempt *at, const struct sip_msg *resp)
{
	struct reg *r = at->r;
	bool replaced = r->cur.used;
	char ha[64];

	rtxn_drop(r);
	ev_timer_cancel(r->t_dereg);
	if (replaced)
		drain_set(r, &r->cur);
	parse_200(r, resp, &at->set);
	r->cur = at->set;
	memset(&at->set, 0, sizeof(at->set));
	r->pcscf_idx = at->pidx;
	addr_host(&at->pc, ha, sizeof(ha));
	attempt_free(at);
	r->at = NULL;
	r->n_ok++;
	if (replaced)
		r->n_reauth++;
	r->round_fails = r->dup_retries = r->auth_retries = 0;
	r->bo_n = 0;
	r->registered_at = replaced ? r->registered_at : ev_now_ms();
	r->last_error[0] = 0;
	arm_registered_timers(r);
	r->reason[0] = 0;
	set_state(r, RS_REGISTERED, NULL);
	LOGI("reg: REGISTERED via P-CSCF %s (protected %u->%u): P-Associated-URI %s, granted %d s, refresh in %d s",
	     ha, r->cur.sc.port_c, r->cur.sa.port_ps, r->pau[0] ? r->pau : "(none)", r->granted_s, r->granted_s / 2);
	notify(r, replaced ? REG_EV_REPLACED : REG_EV_UP, "registered");
}

static void prot_cb(struct txn_client *c, enum txn_cli_event ev, const struct sip_msg *resp,
		    struct sip_endpoint *rx_ep, const struct addr *src, void *arg)
{
	struct attempt *at = arg;

	(void)c; (void)rx_ep; (void)src;
	switch (ev) {
	case TXN_CLI_TERMINATED:
		at->txn = NULL;
		return;
	case TXN_CLI_TIMEOUT:
		at->txn = NULL;
		attempt_fail(at, F_NORMAL, "protected REGISTER timed out");
		return;
	case TXN_CLI_TRANSPORT_ERROR:
		at->txn = NULL;
		attempt_fail(at, F_NORMAL, "transport error sending the protected REGISTER");
		return;
	case TXN_CLI_RESPONSE:
		break;
	}
	if (resp->status < 200)
		return;
	if (resp->status == 200)
		promote(at, resp);
	else if (at_min_expires(at, resp))
		return;
	else if (resp->status == 401)
		attempt_fail(at, F_AUTH, "401 to the protected REGISTER (stale nonce or resynchronisation)");
	else if (resp->status == 403)
		attempt_fail(at, F_FORBIDDEN, "403 Forbidden to the protected REGISTER");
	else if (resp->status == 406)
		attempt_fail(at, F_DUP, "406 to the protected REGISTER");
	else
		attempt_fail(at, F_NORMAL, "%d %s to the protected REGISTER", resp->status, resp->reason);
}

/* ------------------------------------------------------------------ */
/* start of an attempt                                                 */

static void attempt_begin(struct reg *r)
{
	struct attempt *at;
	struct sip_ep_cfg c;
	char name[24], ha[64];
	int n = r->link.n_pcscf, i;
	bool reauth = r->cur.used;

	if (r->stopping || !r->enabled || !r->link.ready || r->at || !n)
		return;
	at = calloc(1, sizeof(*at));
	if (!at)
		return;
	at->r = r;
	at->reauth = reauth;
	at->pidx = r->pcscf_idx % n;
	r->at = at;
	r->n_attempts++;
	at->t_step = ev_timer_new(at_step_timeout, at);
	if (!at->t_step || addr_set(&at->pc, r->link.pcscf[at->pidx], 0)) {
		attempt_fail(at, F_NORMAL, "bad P-CSCF address '%s'", r->link.pcscf[at->pidx]);
		return;
	}
	at->pc_un = at->pc;
	addr_set_port(&at->pc_un, r->cfg.pcscf_port);
	at->sc.port_c = pick_port(r);
	at->sc.port_s = pick_port(r);
	at->sc.spi_c = pick_spi();
	do {
		at->sc.spi_s = pick_spi();
	} while (at->sc.spi_s == at->sc.spi_c);
	snprintf(at->call_id, sizeof(at->call_id), "%u_%u@", rnd32(), rnd32());
	addr_host(&r->link.br.local, at->call_id + strlen(at->call_id), sizeof(at->call_id) - strlen(at->call_id));
	at->cseq = rnd32() % 100000000;

	for (i = 0; i < 5 && !at->ep_un; i++) {
		snprintf(name, sizeof(name), "gm-un#%d", ++r->nsets);
		memset(&c, 0, sizeof(c));
		c.name = name;
		c.kind = SIP_TP_UDP;
		c.rx_bind = r->link.br.local;
		addr_set_port(&c.rx_bind, pick_port(r));
		c.netdev = r->link.br.ifname;
		at->ep_un = r->ops.open_ep(r->ops.ctx, &c);
	}
	if (!at->ep_un) {
		attempt_fail(at, F_NORMAL, "cannot open the unprotected endpoint: %s", strerror(errno));
		return;
	}
	txn_layer_attach(r->tl, at->ep_un);
	addr_host(&at->pc, ha, sizeof(ha));
	LOGI("reg: REGISTER attempt %u via P-CSCF [%s]:%d (%s list, index %d of %d)%s", r->n_attempts, ha, r->cfg.pcscf_port,
	     r->link.pcscf_src == PCSCF_NETWORK ? "network" : "static", at->pidx + 1, n, reauth ? ", re-authentication" : "");
	at->stage = AT_UNPROT;
	set_state(r, reauth ? RS_REAUTH : RS_UNPROT, NULL);
	r->reason[0] = 0;
	if (regmsg_authorization(at->unprot_auth, sizeof(at->unprot_auth), r->link.id.impi, r->link.id.domain,
				 r->link.id.domain, "", "", NULL, NULL) || at_send_unprot(at, at->unprot_auth)) {
		attempt_fail(at, F_NORMAL, "cannot send the unprotected REGISTER");
		return;
	}
	at_arm(at, r->cfg.step_timeout_ms);
}

static void next_fire(void *arg)
{
	struct reg *r = arg;

	attempt_begin(r);
}

/* ------------------------------------------------------------------ */
/* refresh, expiry, de-registration                                    */

static void rtxn_start(struct reg *r, int expires, txn_client_cb cb)
{
	struct reg_set *s = &r->cur;
	struct regmsg_params p;
	struct txn_client_req q;
	struct buf b;

	fill_params(r, &p);
	p.expires = expires;
	p.adv = &s->ep->advertised;
	p.pcscf = &s->pc_ps;
	p.call_id = s->call_id;
	p.cseq = ++s->cseq;
	p.authorization = s->auth;
	p.is_protected = true;
	p.security_verify = s->sec_verify;
	p.sc = &s->sc;
	buf_init(&b, SIP_MAX_MSG);
	rtxn_drop(r);
	if (!regmsg_build_register(&b, &p, NULL)) {
		memset(&q, 0, sizeof(q));
		q.ep = s->ep;
		q.dst = s->pc_ps;
		q.data = b.p;
		q.len = b.len;
		q.cb = cb;
		q.arg = r;
		r->rtxn = txn_client_start(r->tl, &q);
	}
	buf_free(&b);
}

static void lose_registration(struct reg *r, const char *why)
{
	bool was = r->cur.used;

	ev_timer_cancel(r->t_refresh);
	ev_timer_cancel(r->t_exp);
	ev_timer_cancel(r->t_dereg);
	rtxn_drop(r);
	if (r->at)
		attempt_free(r->at);
	set_release(r, &r->cur);
	r->pau[0] = 0;
	r->n_sroute = 0;
	if (was) {
		LOGW("reg: registration lost (%s)", why);
		notify(r, REG_EV_DOWN, why);
	}
}

/* the refresh failed or was challenged: authenticate from scratch while the old registration still works */
static void start_reauth(struct reg *r, const char *why)
{
	LOGI("reg: re-authentication needed (%s)", why);
	rtxn_drop(r);
	set_state(r, RS_REAUTH, "%s", why);
	r->round_fails = 0;
	attempt_begin(r);
}

static void refresh_cb(struct txn_client *c, enum txn_cli_event ev, const struct sip_msg *resp,
		       struct sip_endpoint *rx_ep, const struct addr *src, void *arg)
{
	struct reg *r = arg;

	(void)c; (void)rx_ep; (void)src;
	switch (ev) {
	case TXN_CLI_TERMINATED:
		r->rtxn = NULL;
		return;
	case TXN_CLI_TIMEOUT:
		r->rtxn = NULL;
		start_reauth(r, "refresh REGISTER timed out");
		return;
	case TXN_CLI_TRANSPORT_ERROR:
		r->rtxn = NULL;
		start_reauth(r, "transport error on refresh");
		return;
	case TXN_CLI_RESPONSE:
		break;
	}
	if (resp->status < 200)
		return;
	ev_timer_cancel(r->t_dereg);
	if (resp->status == 200) {
		parse_200(r, resp, &r->cur);
		arm_registered_timers(r);
		r->reason[0] = 0;
	set_state(r, RS_REGISTERED, NULL);
		r->refresh_min_exp_retry = false;
		LOGI("reg: refreshed, granted %d s, next refresh in %d s", r->granted_s, r->granted_s / 2);
		return;
	}
	if (resp->status == 423 && !r->refresh_min_exp_retry && sip_hdr(resp, "Min-Expires", 0)) {
		r->refresh_min_exp_retry = true;
		r->exp_req = atoi(sip_hdr(resp, "Min-Expires", 0));
		rtxn_start(r, r->exp_req, refresh_cb);
		return;
	}
	if (resp->status == 403) {
		r->n_auth_fail++;
		snprintf(r->last_error, sizeof(r->last_error), "403 Forbidden to the refresh REGISTER");
		rtxn_drop(r);
		go_backoff(r, true);
		return;
	}
	if (resp->status == 401)
		r->n_auth_fail++;
	{
		char why[64];

		snprintf(why, sizeof(why), "refresh answered %d", resp->status);
		start_reauth(r, why);
	}
}

static void refresh_fire(void *arg)
{
	struct reg *r = arg;

	if (!r->cur.used || r->state != RS_REGISTERED)
		return;
	LOGI("reg: refreshing the registration");
	r->n_refresh++;
	r->refresh_min_exp_retry = false;
	set_state(r, RS_REFRESH, NULL);
	r->reason[0] = 0;
	rtxn_start(r, r->exp_req, refresh_cb);
	if (!r->rtxn) {
		start_reauth(r, "cannot send the refresh REGISTER");
		return;
	}
	ev_timer_set(r->t_dereg, r->cfg.step_timeout_ms);	/* answer guard (the transaction would take 32 s) */
}

/* t_dereg doubles as the guard of a refresh and of a de-registration */
static void finish_dereg(struct reg *r);

static void guard_fire(void *arg)
{
	struct reg *r = arg;

	if (r->state == RS_DEREG) {
		finish_dereg(r);
		return;
	}
	if (r->state == RS_REFRESH) {
		rtxn_drop(r);
		start_reauth(r, "no answer to the refresh REGISTER");
	}
}

static void exp_fire(void *arg)
{
	struct reg *r = arg;

	if (!r->cur.used)
		return;
	LOGW("reg: registration expired without a successful refresh");
	snprintf(r->last_error, sizeof(r->last_error), "registration expired");
	lose_registration(r, "expired");
	r->round_fails = 0;
	if (r->link.ready && r->enabled && !r->stopping) {
		set_state(r, RS_UNPROT, "re-registering after expiry");
		schedule_next(r, 0);
	}
}

static void done_fire(void *arg)
{
	struct reg *r = arg;
	void (*d)(void *) = r->done;
	void *a = r->done_arg;

	r->done = NULL;
	if (d)
		d(a);
}

static void finish_dereg(struct reg *r)
{
	ev_timer_cancel(r->t_dereg);
	rtxn_drop(r);
	lose_registration(r, "de-registered");
	set_state(r, r->stopping ? RS_IDLE : (r->enabled ? RS_WAIT_LINK : RS_IDLE), r->stopping ? "stopped" : "de-registered");
	if (r->done)
		ev_timer_set(r->t_done, 0);
}

static void dereg_cb(struct txn_client *c, enum txn_cli_event ev, const struct sip_msg *resp,
		     struct sip_endpoint *rx_ep, const struct addr *src, void *arg)
{
	struct reg *r = arg;

	(void)c; (void)rx_ep; (void)src;
	if (ev == TXN_CLI_TERMINATED) {
		r->rtxn = NULL;
		return;
	}
	if (ev == TXN_CLI_RESPONSE) {
		if (resp->status < 200)
			return;
		LOGI("reg: de-REGISTER answered %d", resp->status);
	} else {
		LOGW("reg: de-REGISTER got no answer");
	}
	if (ev != TXN_CLI_RESPONSE)
		r->rtxn = NULL;
	finish_dereg(r);
}

static void begin_dereg(struct reg *r)
{
	ev_timer_cancel(r->t_refresh);
	ev_timer_cancel(r->t_exp);
	ev_timer_cancel(r->t_next);
	if (r->at)
		attempt_free(r->at);
	if (!r->cur.used) {
		finish_dereg(r);
		return;
	}
	set_state(r, RS_DEREG, NULL);
	r->reason[0] = 0;
	rtxn_start(r, 0, dereg_cb);
	if (!r->rtxn) {
		finish_dereg(r);
		return;
	}
	ev_timer_set(r->t_dereg, r->cfg.dereg_timeout_ms);
}

void reg_shutdown(struct reg *r, void (*done)(void *arg), void *arg)
{
	r->stopping = true;
	r->done = done;
	r->done_arg = arg;
	ev_timer_cancel(r->t_next);
	begin_dereg(r);
}

void reg_set_enabled(struct reg *r, bool enabled)
{
	if (r->stopping || r->enabled == enabled)
		return;
	r->enabled = enabled;
	LOGI("reg: manual %s", enabled ? "register" : "deregister");
	if (!enabled) {
		begin_dereg(r);
		return;
	}
	set_state(r, RS_WAIT_LINK, "waiting for the IMS link");
	if (r->have_link && r->link.ready) {
		r->pcscf_idx = r->round_fails = r->dup_retries = r->auth_retries = 0;
		r->bo_n = 0;
		attempt_begin(r);
	}
}

/* ------------------------------------------------------------------ */
/* link handling                                                       */

static bool link_same(const struct ims_link *a, const struct ims_link *b)
{
	int i;

	if (strcmp(a->br.ifname, b->br.ifname) || !addr_equal(&a->br.local, &b->br.local) || strcmp(a->id.impu, b->id.impu) ||
	    strcmp(a->id.impi, b->id.impi) || strcmp(a->id.domain, b->id.domain) || strcmp(a->id.imei, b->id.imei) ||
	    a->n_pcscf != b->n_pcscf)
		return false;
	for (i = 0; i < a->n_pcscf; i++)
		if (strcmp(a->pcscf[i], b->pcscf[i]))
			return false;
	return true;
}

static void release_all(struct reg *r, const char *why)
{
	int i;

	ev_timer_cancel(r->t_next);
	if (r->state == RS_DEREG)
		r->state = RS_IDLE;
	lose_registration(r, why);
	for (i = 0; i < NDRAIN; i++) {
		if (r->dr[i].s.used)
			set_release(r, &r->dr[i].s);
		if (r->dr[i].t)
			ev_timer_cancel(r->dr[i].t);
	}
	if (r->at)
		attempt_free(r->at);
}

static void start_registration(struct reg *r)
{
	r->pcscf_idx = r->round_fails = r->dup_retries = r->auth_retries = 0;
	r->bo_n = 0;
	r->exp_req = r->cfg.expires;
	attempt_begin(r);
}

void reg_set_link(struct reg *r, const struct ims_link *l)
{
	bool was_ready = r->have_link && r->link.ready;
	bool same = r->have_link && link_same(&r->link, l);

	r->link = *l;
	r->have_link = true;
	if (r->stopping || !r->enabled)
		return;
	if (!l->ready) {
		if (was_ready || r->state != RS_WAIT_LINK) {
			release_all(r, "IMS link lost");
			if (was_ready)
				LOGW("reg: IMS link lost (%s), everything released", l->reason);
		}
		set_state(r, RS_WAIT_LINK, "%s", l->reason[0] ? l->reason : "no IMS link");
		return;
	}
	if (!was_ready) {
		start_registration(r);
	} else if (!same) {
		LOGI("reg: IMS link changed, registering again");
		release_all(r, "IMS link changed");
		start_registration(r);
	}
}

bool reg_set_cfg(struct reg *r, const struct reg_cfg *c)
{
	bool restart = c->pcscf_port != r->cfg.pcscf_port || c->expires != r->cfg.expires || strcmp(c->pani, r->cfg.pani) || strcmp(c->user_agent, r->cfg.user_agent) ||
		       c->port_min != r->cfg.port_min || c->port_max != r->cfg.port_max;

	r->cfg = *c;
	if (restart && !r->stopping && r->enabled && r->have_link && r->link.ready) {
		LOGI("reg: configuration changed, registering again");
		release_all(r, "configuration changed");
		start_registration(r);
	}
	return restart;
}

/* ------------------------------------------------------------------ */
/* registered context and requests inside the registration             */

bool reg_is_registered(const struct reg *r)
{
	return r->cur.used && r->cur.ep;
}

const struct reg_ctx *reg_context(const struct reg *r)
{
	struct reg_ctx *c = (struct reg_ctx *)&r->ctx;
	int i;

	if (!reg_is_registered(r))
		return NULL;
	memset(c, 0, sizeof(*c));
	c->ep = r->cur.ep;
	c->pcscf_ps = r->cur.pc_ps;
	c->security_verify = r->cur.sec_verify;
	for (i = 0; i < r->n_sroute; i++)
		c->service_route[c->n_service_route++] = r->sroute[i];
	c->impu = r->link.id.impu;
	c->assoc_uri = r->pau;
	c->pani = cur_pani((struct reg *)r);
	c->port_c = r->cur.sc.port_c;
	c->port_s = r->cur.sc.port_s;
	c->expires_in_ms = r->expires_at > ev_now_ms() ? (int64_t)(r->expires_at - ev_now_ms()) : 0;
	return c;
}

int reg_contact_uri(const struct reg *r, char *out, size_t n)
{
	if (!reg_is_registered(r))
		return -1;
	return regmsg_contact_uri(out, n, r->link.id.user, &r->cur.ep->advertised);
}

struct send_ctx {
	struct send_ctx *next;
	struct reg *r;
	reg_resp_cb cb;
	void *arg;
	struct txn_client *c;
};

static void send_cb(struct txn_client *c, enum txn_cli_event ev, const struct sip_msg *resp, struct sip_endpoint *rx_ep,
		    const struct addr *src, void *arg)
{
	struct send_ctx *x = arg;

	(void)c; (void)rx_ep; (void)src;
	switch (ev) {
	case TXN_CLI_RESPONSE:
		if (resp->status >= 200 && x->cb) {
			reg_resp_cb cb = x->cb;

			x->cb = NULL;
			cb(x->arg, resp->status, resp);
		}
		return;
	case TXN_CLI_TIMEOUT:
	case TXN_CLI_TRANSPORT_ERROR:
		if (x->cb) {
			reg_resp_cb cb = x->cb;

			x->cb = NULL;
			cb(x->arg, 0, NULL);
		}
		return;
	case TXN_CLI_TERMINATED: {
		struct send_ctx **pp;

		for (pp = &x->r->sends; *pp; pp = &(*pp)->next)
			if (*pp == x) {
				*pp = x->next;
				break;
			}
		free(x);
		return;
	}
	}
}

int reg_send(struct reg *r, const struct reg_req *q, reg_resp_cb cb, void *arg)
{
	struct reg_set *s = &r->cur;
	char via[200], from[260], to[300], call_id[160], branch[SIP_BRANCH_LEN], route1[160], ha[64];
	struct buf route, extra, out;
	struct sip_req_parts p;
	struct txn_client_req cr;
	struct send_ctx *x;
	int i, rc = -EMSGSIZE;

	if (!reg_is_registered(r))
		return -ENOTCONN;
	sip_new_branch(branch);
	if (sip_via_make(via, sizeof(via), "UDP", &s->ep->advertised, branch, false))
		return -EINVAL;
	snprintf(from, sizeof(from), "<%s>;tag=%u", r->link.id.impu, rnd32());
	if (q->to)
		snprintf(to, sizeof(to), "%s", q->to);
	else
		snprintf(to, sizeof(to), "<%s>", q->ruri);
	if (q->call_id) {
		snprintf(call_id, sizeof(call_id), "%s", q->call_id);
	} else {
		addr_host(&r->link.br.local, ha, sizeof(ha));
		snprintf(call_id, sizeof(call_id), "%u_%u@%s", rnd32(), rnd32(), ha);
	}
	regmsg_route(route1, sizeof(route1), &s->pc_ps);
	buf_init(&route, 2048);
	buf_puts(&route, route1);
	for (i = 0; i < r->n_sroute; i++)
		buf_printf(&route, "Route: %s\r\n", r->sroute[i]);
	buf_init(&extra, 8192);
	buf_printf(&extra, "P-Access-Network-Info: %s\r\n", cur_pani(r));
	if (r->cfg.user_agent[0])
		buf_printf(&extra, "User-Agent: %s\r\n", r->cfg.user_agent);
	buf_printf(&extra, "Security-Verify: %s\r\n", s->sec_verify);
	if (q->extra)
		buf_puts(&extra, q->extra);
	memset(&p, 0, sizeof(p));
	p.method = q->method;
	p.ruri = q->ruri;
	p.via = via;
	p.from = from;
	p.to = to;
	p.call_id = call_id;
	p.cseq = q->cseq ? q->cseq : rnd32() % 900000000 + 1;
	p.route = buf_cstr(&route);
	p.contact = q->contact;
	p.extra = buf_cstr(&extra);
	p.content_type = q->content_type;
	p.body = q->body;
	p.body_len = q->body_len;
	buf_init(&out, SIP_MAX_MSG);
	x = calloc(1, sizeof(*x));
	if (x && buf_ok(&route) && buf_ok(&extra) && !sip_build_request(&out, &p)) {
		x->cb = cb;
		x->arg = arg;
		memset(&cr, 0, sizeof(cr));
		cr.ep = s->ep;
		cr.dst = s->pc_ps;
		cr.data = out.p;
		cr.len = out.len;
		cr.cb = send_cb;
		cr.arg = x;
		x->r = r;
		x->c = txn_client_start(r->tl, &cr);
		if (x->c) {
			x->next = r->sends;
			r->sends = x;
			rc = 0;
			LOGD("reg: sent %s to %s", q->method, q->ruri);
		} else {
			rc = -ENOBUFS;
		}
	} else if (!x) {
		rc = -ENOMEM;
	}
	if (rc)
		free(x);
	buf_free(&route);
	buf_free(&extra);
	buf_free(&out);
	return rc;
}

/* ------------------------------------------------------------------ */
/* incoming requests on the protected endpoint                         */

static void reply(struct reg *r, struct txn_server *st, int status, const char *extra)
{
	struct sip_resp_parts p;
	char ex[512];

	memset(&p, 0, sizeof(p));
	p.status = status;
	p.extra = extra;
	if (r->cfg.user_agent[0]) {
		snprintf(ex, sizeof(ex), "User-Agent: %s\r\n%s", r->cfg.user_agent, extra ? extra : "");
		p.extra = ex;
	}
	txn_server_reply(st, &p);
}

static void rpack_done(void *arg, int status, const struct sip_msg *resp)
{
	(void)arg; (void)resp;
	if (status == 202 || status == 200)
		LOGI("sms: RP-ACK accepted by the network (%d)", status);
	else if (status)
		LOGW("sms: RP-ACK answered %d", status);
	else
		LOGW("sms: RP-ACK got no answer");
}

static void handle_sms(struct reg *r, struct txn_server *st, const struct sip_msg *req)
{
	struct rp_info ri;
	char hex[1100], ruri[300], extra[400];
	const char *pai, *cid;
	uint8_t ack[2];
	struct reg_req q;
	size_t n = req->body_len;

	reply(r, st, 200, NULL);
	r->n_sms++;
	hex_encode(req->body, n > 500 ? 500 : n, hex);
	if (rp_parse(req->body, n, &ri)) {
		LOGW("sms: MESSAGE with a body shorter than the RP header (%zu bytes)", n);
		return;
	}
	LOGI("sms: %s MR=%u (%zu bytes): %s", rp_mti_name(ri.mti), ri.mr, n, hex);
	switch (ri.mti) {
	case RP_DATA_N_MS:
		pai = sip_hdr(req, "P-Asserted-Identity", 0);
		ruri[0] = 0;
		if (!pai || sip_uri_of(pai, ruri, sizeof(ruri)))
			if (!sip_hdr(req, "From", 0) || sip_uri_of(sip_hdr(req, "From", 0), ruri, sizeof(ruri)))
				return;
		cid = sip_hdr(req, "Call-ID", 0);
		rp_build_ack(ri.mr, ack);
		snprintf(extra, sizeof(extra), "Allow: MESSAGE\r\nRequest-Disposition: no-fork\r\n%s%s%sAccept-Contact: *;+g.3gpp.smsip\r\n",
			 cid ? "In-Reply-To: " : "", cid ? cid : "", cid ? "\r\n" : "");
		memset(&q, 0, sizeof(q));
		q.method = "MESSAGE";
		q.ruri = ruri;
		q.extra = extra;
		q.content_type = "application/vnd.3gpp.sms";
		q.body = ack;
		q.body_len = 2;
		LOGI("sms: sending RP-ACK for MR=%u to %s", ri.mr, ruri);
		if (reg_send(r, &q, rpack_done, NULL))
			LOGW("sms: cannot send the RP-ACK");
		break;
	case RP_ACK_N_MS:
		LOGI("sms: RP-ACK from the network, MR=%u (our SMS was accepted)", ri.mr);
		break;
	case RP_ERROR_N_MS:
		LOGW("sms: RP-ERROR from the network, MR=%u cause=%d", ri.mr, ri.cause);
		break;
	default:
		LOGW("sms: unexpected %s", rp_mti_name(ri.mti));
	}
}

static bool is_unprot_ep(const struct reg *r, const struct sip_endpoint *ep)
{
	return r->at && r->at->ep_un == ep;
}

void reg_set_handlers(struct reg *r, const struct reg_handlers *h)
{
	if (h)
		r->hnd = *h;
	else
		memset(&r->hnd, 0, sizeof(r->hnd));
}

static bool has_to_tag(const struct sip_msg *req)
{
	const char *to = sip_hdr(req, "To", 0);
	char tag[96];

	return to && !sip_tag(to, tag, sizeof(tag)) && tag[0];
}

/* the extension table (see reg.h): true when a handler took the request */
static bool ext_handle(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
		       const struct sip_msg *req)
{
	const struct reg_handlers *h = &r->hnd;
	bool tagged = has_to_tag(req);

	if (sip_is_method(req, "INVITE") && !tagged)
		return h->on_invite && h->on_invite(r, st, ep, src, req, h->arg);
	if (sip_is_method(req, "MESSAGE") && !tagged)
		return h->on_message && h->on_message(r, st, ep, src, req, h->arg);
	if (tagged || sip_is_method(req, "BYE") || sip_is_method(req, "UPDATE") || sip_is_method(req, "INFO") ||
	    sip_is_method(req, "PRACK") || sip_is_method(req, "NOTIFY") || sip_is_method(req, "REFER"))
		return h->on_in_dialog && h->on_in_dialog(r, st, ep, src, req, h->arg);
	return false;
}

void reg_on_request(struct txn_layer *tl, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
		    const struct sip_msg *req, void *arg)
{
	struct reg *r = arg;
	const char *ct;

	(void)tl;
	if (!st) {	/* ACK */
		if (r->hnd.on_ack && !is_unprot_ep(r, ep))
			r->hnd.on_ack(r, NULL, ep, src, req, r->hnd.arg);
		return;
	}
	LOGD("reg: %s from the network on %s", req->method, ep->name);
	if (is_unprot_ep(r, ep)) {
		reply(r, st, 403, NULL);
		return;
	}
	if (ext_handle(r, st, ep, src, req))
		return;
	if (sip_is_method(req, "OPTIONS")) {
		reply(r, st, 200, "Allow: " REG_ALLOW "\r\nAccept: application/sdp\r\n");
	} else if (sip_is_method(req, "NOTIFY")) {
		reply(r, st, 200, NULL);
	} else if (sip_is_method(req, "MESSAGE")) {
		ct = sip_hdr(req, "Content-Type", 0);
		if (ct && strcasestr(ct, "application/vnd.3gpp.sms"))
			handle_sms(r, st, req);
		else
			reply(r, st, 415, "Accept: application/vnd.3gpp.sms\r\n");
	} else if (sip_is_method(req, "INVITE")) {
		LOGI("reg: INVITE rejected with 480 (calls are not supported yet)");
		reply(r, st, 480, NULL);
	} else if (sip_is_method(req, "BYE") || sip_is_method(req, "INFO") || sip_is_method(req, "UPDATE") ||
		   sip_is_method(req, "PRACK")) {
		reply(r, st, 481, NULL);
	} else if (sip_is_method(req, "REGISTER") || sip_is_method(req, "SUBSCRIBE") || sip_is_method(req, "REFER") ||
		   sip_is_method(req, "PUBLISH")) {
		reply(r, st, 405, "Allow: " REG_ALLOW "\r\n");
	} else {
		reply(r, st, 501, NULL);
	}
}

void reg_on_stray(struct txn_layer *tl, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *resp, void *arg)
{
	(void)tl; (void)src; (void)arg;
	LOGD("reg: ignoring stray %d on %s", resp->status, ep->name);
}

/* ------------------------------------------------------------------ */
/* lifecycle and status                                                */

struct reg *reg_new(const struct reg_cfg *cfg, const struct reg_ops *ops)
{
	struct reg *r = calloc(1, sizeof(*r));
	struct txn_cfg tc;

	if (!r)
		return NULL;
	r->cfg = *cfg;
	r->ops = *ops;
	r->enabled = true;
	r->state = RS_WAIT_LINK;
	r->exp_req = cfg->expires;
	snprintf(r->reason, sizeof(r->reason), "waiting for the IMS link");
	if (ops->tl) {
		r->tl = ops->tl;
	} else {
		memset(&tc, 0, sizeof(tc));
		tc.on_request = reg_on_request;
		tc.on_stray_response = reg_on_stray;
		tc.arg = r;
		r->tl = txn_layer_new(&tc);
		r->own_tl = true;
	}
	r->t_refresh = ev_timer_new(refresh_fire, r);
	r->t_exp = ev_timer_new(exp_fire, r);
	r->t_next = ev_timer_new(next_fire, r);
	r->t_dereg = ev_timer_new(guard_fire, r);
	r->t_done = ev_timer_new(done_fire, r);
	if (!r->tl || !r->t_refresh || !r->t_exp || !r->t_next || !r->t_dereg || !r->t_done) {
		reg_free(r);
		return NULL;
	}
	return r;
}

void reg_free(struct reg *r)
{
	int i;

	if (!r)
		return;
	release_all(r, "shutdown");
	while (r->sends) {	/* in-flight reg_send() requests: no callback any more, the transaction layer finishes them */
		struct send_ctx *x = r->sends;

		r->sends = x->next;
		txn_client_detach(x->c);
		free(x);
	}
	for (i = 0; i < NDRAIN; i++)
		ev_timer_free(r->dr[i].t);
	ev_timer_free(r->t_refresh);
	ev_timer_free(r->t_exp);
	ev_timer_free(r->t_next);
	ev_timer_free(r->t_dereg);
	ev_timer_free(r->t_done);
	if (r->own_tl)
		txn_layer_free(r->tl);
	free(r);
}

void reg_get_status(const struct reg *r, struct reg_status *s)
{
	uint64_t now = ev_now_ms();
	int n = r->link.n_pcscf;

	memset(s, 0, sizeof(*s));
	s->state = r->state;
	s->state_name = reg_state_name(r->state);
	s->registered = reg_is_registered(r);
	if (r->state == RS_WAIT_LINK && r->have_link && r->link.reason[0])
		snprintf(s->reason, sizeof(s->reason), "%s", r->link.reason);
	else
		snprintf(s->reason, sizeof(s->reason), "%s", r->reason);
	snprintf(s->last_error, sizeof(s->last_error), "%s", r->last_error);
	snprintf(s->impu, sizeof(s->impu), "%s", r->link.id.impu);
	snprintf(s->impi, sizeof(s->impi), "%s", r->link.id.impi);
	snprintf(s->domain, sizeof(s->domain), "%s", r->link.id.domain);
	if (n)
		snprintf(s->pcscf, sizeof(s->pcscf), "%s", r->link.pcscf[(r->at ? r->at->pidx : r->pcscf_idx) % n]);
	s->pcscf_port_s = s->registered ? ntohs(r->cur.pc_ps.sa.sin6_port) : 0;
	s->pcscf_source = r->link.pcscf_src;
	s->port_c = s->registered ? r->cur.sc.port_c : 0;
	s->port_s = s->registered ? r->cur.sc.port_s : 0;
	s->expires_in_s = s->registered ? (r->expires_at > now ? (int64_t)((r->expires_at - now) / 1000) : 0) : -1;
	s->registered_since_s = s->registered ? (int64_t)((now - r->registered_at) / 1000) : -1;
	s->attempts = r->n_attempts;
	s->successes = r->n_ok;
	s->auth_failures = r->n_auth_fail;
	s->failures = r->n_fail;
	s->sms_received = r->n_sms;
	s->reauths = r->n_reauth;
	s->refreshes = r->n_refresh;
	snprintf(s->assoc_uri, sizeof(s->assoc_uri), "%s", r->pau);
	snprintf(s->pani, sizeof(s->pani), "%s", cur_pani((struct reg *)r));
	s->pani_source = r->pani_src;
}

const char *reg_user_agent(const struct reg *r)
{
	return r->cfg.user_agent;
}
