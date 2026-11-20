/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SMS relay as a core module: glue between struct core (Gm registration, LAN object, configuration, SIM
 * parameters) and the relay of smsrelay.c, see smsrelay_mod.h.
 *
 * reg_send() has no cancel and reg_free() drops pending requests without calling them back, so a response may
 * arrive after smsrelay_free() (the relay is gone, the registration is not) and an unanswered request never calls
 * back at all. A heap token handed to reg_send would therefore either dangle or leak. The requests are
 * tracked in a static slot table instead: the argument given to reg_send is the address of a slot, which is valid for
 * the life of the process; stop() invalidates every slot, so a late callback finds its slot unused and returns.
 * Slots are handed out round-robin, so a slot is not reused right after it was released.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "smsrelay_mod.h"
#include "../store/store_mod.h"
#include "../util/log.h"

#define NSLOT 128

struct slot {
	bool used;
	smsrelay_gm_resp_cb cb;
	void *arg;
};

static struct {
	struct core *c;
	struct smsrelay *sr;
	struct smsrelay_cfg cfg;	/* what the relay runs with */
	struct slot slot[NSLOT];
	unsigned next;
} G;

/* the WAP push consumer (the MMS module), installed by it at its start; kept outside G, which start() wipes */
static smsrelay_mod_push_cb push_cb;
static void *push_arg;

void smsrelay_mod_set_push(smsrelay_mod_push_cb cb, void *arg)
{
	push_cb = cb;
	push_arg = arg;
}

static void sync_cfg(void);

/* the circuit switched hooks, set by main(); outside G like the push consumer */
static struct smsrelay_mod_cs cs_hk;

void smsrelay_mod_set_cs(const struct smsrelay_mod_cs *cs)
{
	memset(&cs_hk, 0, sizeof(cs_hk));
	if (cs)
		cs_hk = *cs;
}

int smsrelay_mod_cs_in(const struct cssms_in *m)
{
	if (!G.sr)
		return -ENOTCONN;
	sync_cfg();
	return smsrelay_cs_in(G.sr, m);
}

void smsrelay_mod_cs_kick(void)
{
	if (G.sr)
		smsrelay_cs_kick(G.sr);
}

static void m_cs_kick(void *ctx)
{
	(void)ctx;
	if (cs_hk.kick)
		cs_hk.kick(cs_hk.ctx);
}

static bool m_cs_active(void *ctx)
{
	(void)ctx;
	return cs_hk.sms_active && cs_hk.sms_active(cs_hk.ctx);
}

static int m_cs_submit(void *ctx, const struct cssms_submit *q, cssms_done_cb cb, void *arg)
{
	(void)ctx;
	return cs_hk.submit ? cs_hk.submit(cs_hk.ctx, q, cb, arg) : -ENOTCONN;
}

static bool m_push_active(void *ctx)
{
	(void)ctx;
	return cs_hk.push_active && cs_hk.push_active(cs_hk.ctx);
}

static void m_cs_in_done(void *ctx, unsigned id, bool taken)
{
	(void)ctx;
	if (cs_hk.in_done)
		cs_hk.in_done(cs_hk.ctx, id, taken);
}

static void m_push(void *ctx, const char *from, unsigned port, const uint8_t *data, size_t len)
{
	(void)ctx;
	if (push_cb)
		push_cb(push_arg, from, port, data, len);
	else
		LOGI("sms: WAP push from %s on port %u (%zu bytes) dropped: nobody handles it", from, port, len);
}

static void gm_resp(void *arg, int status, const struct sip_msg *resp)
{
	struct slot *s = arg;
	smsrelay_gm_resp_cb cb;
	void *a;

	if (!s->used)		/* the relay was stopped meanwhile */
		return;
	cb = s->cb;
	a = s->arg;
	s->used = false;
	cb(a, status, resp);
}

static bool m_registered(void *ctx)
{
	(void)ctx;
	return G.c && core_reg(G.c) && reg_is_registered(core_reg(G.c));
}

static int m_send(void *ctx, const struct smsrelay_gm_req *q, smsrelay_gm_resp_cb cb, void *arg)
{
	struct reg_req r;
	struct slot *s = NULL;
	unsigned i;
	int rc;

	(void)ctx;
	if (!G.c || !core_reg(G.c))
		return -ENOTCONN;
	for (i = 0; i < NSLOT; i++) {
		struct slot *t = &G.slot[(G.next + i) % NSLOT];

		if (!t->used) {
			s = t;
			G.next = (G.next + i + 1) % NSLOT;
			break;
		}
	}
	if (!s)
		return -ENOMEM;
	memset(&r, 0, sizeof(r));
	r.method = "MESSAGE";
	r.ruri = q->ruri;
	r.call_id = q->call_id;
	r.extra = q->extra;
	r.content_type = q->content_type;
	r.body = q->body;
	r.body_len = q->body_len;
	s->used = true;
	s->cb = cb;
	s->arg = arg;
	core_pani_refresh(G.c);		/* async hint: the serving cell data for the next requests */
	rc = reg_send(core_reg(G.c), &r, gm_resp, s);
	if (rc)
		s->used = false;
	return rc;
}

static const char *m_smsc(void *ctx)
{
	(void)ctx;
	return G.c ? core_param_smsc(G.c) : "";
}

static const char *m_psi(void *ctx)
{
	(void)ctx;
	return G.c ? core_param_sms_psi(G.c) : "";
}

static const char *m_imsi(void *ctx)
{
	(void)ctx;
	return G.c ? core_param_imsi(G.c) : "";
}

static void m_own_number(void *ctx, char *out, size_t n)
{
	(void)ctx;
	core_own_number(G.c, out, n);
}

static void build_cfg(struct smsrelay_cfg *o)
{
	const struct imsd_config *c = core_cfg(G.c);

	smsrelay_cfg_defaults(o);
	o->concat_prefix = c->sms_concat_prefix;
	o->delivery_reports = c->sms_delivery_reports;
	o->lost_policy = !strcmp(c->sms_lost_policy, "rperror22") ? SMSRELAY_LOST_RPERROR22 : SMSRELAY_LOST_ACK;
	snprintf(o->smsc, sizeof(o->smsc), "%s", c->smsc);
	snprintf(o->sms_psi, sizeof(o->sms_psi), "%s", c->sms_psi);
	o->carbons = c->carbons;
	o->text_split = c->mms_text_split;
}

static void sync_cfg(void)
{
	struct smsrelay_cfg n;

	if (!G.sr)
		return;
	build_cfg(&n);
	if (!memcmp(&n, &G.cfg, sizeof(n)))
		return;
	G.cfg = n;
	smsrelay_set_cfg(G.sr, &n);
}

void smsrelay_mod_reload(void)
{
	sync_cfg();
}

static void reg_hook(void *arg, enum reg_event ev, const char *reason)
{
	(void)arg;
	(void)reason;
	if (G.sr)
		smsrelay_on_reg_event(G.sr, ev == REG_EV_UP ? SMSRELAY_REG_UP : ev == REG_EV_DOWN ? SMSRELAY_REG_DOWN :
							      SMSRELAY_REG_REPLACED);
}

static int mod_start(struct core *c, void *arg)
{
	struct smsrelay_ops ops;

	(void)arg;
	if (G.sr)
		return -EBUSY;
	memset(&G, 0, sizeof(G));
	G.c = c;
	build_cfg(&G.cfg);
	memset(&ops, 0, sizeof(ops));
	ops.registered = m_registered;
	ops.send = m_send;
	ops.smsc = m_smsc;
	ops.sms_psi = m_psi;
	ops.imsi = m_imsi;
	ops.push = m_push;
	ops.own_number = m_own_number;
	ops.cs_active = m_cs_active;
	ops.cs_submit = m_cs_submit;
	ops.push_active = m_push_active;
	ops.cs_in_done = m_cs_in_done;
	ops.cs_kick = m_cs_kick;
	ops.store = store_mod_get();
	G.sr = smsrelay_new(core_lan(c), &G.cfg, &ops);
	if (!G.sr) {
		G.c = NULL;
		return -ENOMEM;
	}
	if (reg_add_hook(core_reg(c), reg_hook, NULL)) {
		smsrelay_free(G.sr);
		G.sr = NULL;
		G.c = NULL;
		return -ENOSPC;
	}
	return 0;
}

static void mod_stop(struct core *c, void *arg)
{
	unsigned i;

	(void)arg;
	if (!G.sr)
		return;
	reg_remove_hook(core_reg(c), reg_hook, NULL);
	smsrelay_free(G.sr);
	G.sr = NULL;
	G.c = NULL;
	for (i = 0; i < NSLOT; i++)
		G.slot[i].used = false;
}

static void mod_lan_state(struct core *c, struct lan *l, void *arg)
{
	(void)c;
	(void)arg;
	if (G.sr)
		smsrelay_set_lan(G.sr, l);
}

static void lan_message(struct lan *l, const struct lan_peer *peer, struct txn_server *st, const struct sip_msg *req,
			void *arg)
{
	(void)arg;
	if (!G.sr) {
		struct sip_resp_parts p = { .status = 503 };

		txn_server_reply(st, &p);
		return;
	}
	sync_cfg();
	smsrelay_on_lan_message(l, peer, st, req, G.sr);
}

static bool gm_message(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
		       const struct sip_msg *req, void *arg)
{
	(void)r;
	(void)arg;
	if (!G.sr)
		return false;
	sync_cfg();
	return smsrelay_on_gm_request(G.sr, st, ep, src, req);
}

static const struct lan_hooks LAN_HOOKS = { .on_message = lan_message };
static const struct reg_handlers GM_HANDLERS = { .on_message = gm_message };

const struct core_module smsrelay_module = {
	.name = "smsrelay",
	.start = mod_start,
	.stop = mod_stop,
	.lan_state = mod_lan_state,
	.lan_hooks = &LAN_HOOKS,
	.gm_handlers = &GM_HANDLERS,
};

bool smsrelay_mod_status(struct smsrelay_status *out)
{
	if (!G.sr)
		return false;
	sync_cfg();
	smsrelay_get_status(G.sr, out);
	return true;
}
