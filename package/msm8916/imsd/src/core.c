/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "core.h"
#include "util/evloop.h"
#include "util/ifaddr.h"
#include "util/log.h"
#include "util/rtpsock.h"
#include "util/sys.h"

#define MAX_MODULES	8
#define LAN_RETRY_MS	5000u	/* no address / bind failed: try again */
#define LAN_RECHECK_MS	30000u	/* LAN up on a derived address: is it still configured? */

struct core {
	const struct imsd_config *cfg;
	struct imsd_config applied;	/* configuration the LAN side was built from */
	struct core_ops ops;
	struct core_params params;
	const struct core_module *mod[MAX_MODULES];
	bool mod_up[MAX_MODULES];
	int n_mod;
	/* merged lan hook owners */
	const struct core_module *own_invite, *own_in_dialog, *own_message, *own_ack, *own_bridge;
	bool running;
	struct txn_layer *tl;
	struct reg *reg;
	struct lan *lan;
	struct sip_endpoint *lan_ep;
	struct addr lan_addr;		/* address in use while up */
	struct ev_timer *lan_t;
	const char *lan_state;
	char lan_reason[256];
};

/* ------------------------------------------------------------------ */
/* request routing                                                     */

static void reject(struct txn_server *st, int status)
{
	struct sip_resp_parts p;

	if (!st)
		return;
	memset(&p, 0, sizeof(p));
	p.status = status;
	txn_server_reply(st, &p);
}

static void core_on_request(struct txn_layer *tl, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
			    const struct sip_msg *req, void *arg)
{
	struct core *c = arg;

	if (c->lan && ep == c->lan_ep)
		lan_on_request(tl, st, ep, src, req, c->lan);
	else if (c->reg)
		reg_on_request(tl, st, ep, src, req, c->reg);
	else
		reject(st, 503);
}

static void core_on_stray(struct txn_layer *tl, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *resp,
			  void *arg)
{
	struct core *c = arg;
	int i;

	for (i = 0; i < c->n_mod; i++)
		if (c->mod_up[i] && c->mod[i]->on_stray)
			c->mod[i]->on_stray(c, ep, src, resp, c->mod[i]->arg);
	if (c->reg && !(c->lan && ep == c->lan_ep))
		reg_on_stray(tl, ep, src, resp, c->reg);
}

/* ---- Gm extension table: ask the modules in registration order ---- */

#define GM_CHAIN(slot) \
static bool gm_##slot(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src, \
		      const struct sip_msg *req, void *arg) \
{ \
	struct core *c = arg; \
	int i; \
	for (i = 0; i < c->n_mod; i++) { \
		const struct reg_handlers *h = c->mod[i]->gm_handlers; \
		if (c->mod_up[i] && h && h->slot && h->slot(r, st, ep, src, req, h->arg)) \
			return true; \
	} \
	return false; \
}
GM_CHAIN(on_invite)
GM_CHAIN(on_message)
GM_CHAIN(on_in_dialog)
GM_CHAIN(on_ack)

static void install_gm_handlers(struct core *c)
{
	struct reg_handlers h;
	int i;

	memset(&h, 0, sizeof(h));
	h.arg = c;
	for (i = 0; i < c->n_mod; i++) {
		const struct reg_handlers *m = c->mod[i]->gm_handlers;

		if (!c->mod_up[i] || !m)
			continue;
		if (m->on_invite)
			h.on_invite = gm_on_invite;
		if (m->on_message)
			h.on_message = gm_on_message;
		if (m->on_in_dialog)
			h.on_in_dialog = gm_on_in_dialog;
		if (m->on_ack)
			h.on_ack = gm_on_ack;
	}
	reg_set_handlers(c->reg, &h);
}

/* ---- LAN hooks: one owner per slot ---- */

static void lh_invite(struct lan *l, const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req, void *arg)
{
	const struct core_module *m = ((struct core *)arg)->own_invite;

	m->lan_hooks->on_invite(l, p, st, req, m->lan_hooks->arg);
}

static void lh_in_dialog(struct lan *l, const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req, void *arg)
{
	const struct core_module *m = ((struct core *)arg)->own_in_dialog;

	m->lan_hooks->on_in_dialog(l, p, st, req, m->lan_hooks->arg);
}

static void lh_message(struct lan *l, const struct lan_peer *p, struct txn_server *st, const struct sip_msg *req, void *arg)
{
	struct core *c = arg;
	const struct core_module *m = c->own_message;

	if (c->ops.lan_message_gate && c->ops.lan_message_gate(c->ops.ctx, st, req))
		return;
	m->lan_hooks->on_message(l, p, st, req, m->lan_hooks->arg);
}

static void lh_ack(struct lan *l, const struct lan_peer *p, const struct sip_msg *req, void *arg)
{
	const struct core_module *m = ((struct core *)arg)->own_ack;

	m->lan_hooks->on_ack(l, p, req, m->lan_hooks->arg);
}

static void build_lan_hooks(const struct core *c, struct lan_hooks *h)
{
	memset(h, 0, sizeof(*h));
	h->arg = (void *)c;
	if (c->own_invite)
		h->on_invite = lh_invite;
	if (c->own_in_dialog)
		h->on_in_dialog = lh_in_dialog;
	if (c->own_message)
		h->on_message = lh_message;
	if (c->own_ack)
		h->on_ack = lh_ack;
}

static bool mod_is_up(const struct core *c, const struct core_module *m)
{
	int i;

	for (i = 0; i < c->n_mod; i++)
		if (c->mod[i] == m)
			return c->mod_up[i];
	return false;
}

/* ------------------------------------------------------------------ */
/* modules                                                             */

int core_add_module(struct core *c, const struct core_module *m)
{
	const struct lan_hooks *h = m ? m->lan_hooks : NULL;

	if (!m || c->running)
		return -EINVAL;
	if (c->n_mod >= MAX_MODULES)
		return -ENOSPC;
	if ((h && h->on_invite && c->own_invite) || (h && h->on_in_dialog && c->own_in_dialog) ||
	    (h && h->on_message && c->own_message) || (h && h->on_ack && c->own_ack) ||
	    (m->bridge_event && c->own_bridge))
		return -EBUSY;
	if (h && h->on_invite)
		c->own_invite = m;
	if (h && h->on_in_dialog)
		c->own_in_dialog = m;
	if (h && h->on_message)
		c->own_message = m;
	if (h && h->on_ack)
		c->own_ack = m;
	if (m->bridge_event)
		c->own_bridge = m;
	c->mod[c->n_mod++] = m;
	return 0;
}

void core_bridge_event(void *core, const struct br_event *ev)
{
	struct core *c = core;

	if (c->own_bridge && mod_is_up(c, c->own_bridge))
		c->own_bridge->bridge_event(c->own_bridge->arg, ev);
}

/* ------------------------------------------------------------------ */
/* LAN side                                                            */

static void lan_arm(struct core *c, unsigned ms)
{
	ev_timer_set(c->lan_t, ms);
}

static void lan_notify(struct core *c, struct lan *l)
{
	int i;

	for (i = 0; i < c->n_mod; i++)
		if (c->mod_up[i] && c->mod[i]->lan_state)
			c->mod[i]->lan_state(c, l, c->mod[i]->arg);
}

static void lan_binding(struct lan *l, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why, void *arg)
{
	struct core *c = arg;

	int i;

	(void)l;
	for (i = 0; i < c->n_mod; i++)
		if (c->mod_up[i] && c->mod[i]->on_binding)
			c->mod[i]->on_binding(c, ev, b, why, c->mod[i]->arg);
	if (c->ops.on_binding)
		c->ops.on_binding(c->ops.ctx, ev, b, why);
}

static void lan_down(struct core *c, const char *state, const char *reason)
{
	if (c->lan) {
		lan_notify(c, NULL);
		lan_free(c->lan);
		c->lan = NULL;
	}
	if (c->lan_ep) {
		sip_ep_set_rx(c->lan_ep, NULL, NULL);	/* lingering transactions keep it open, but nothing new enters */
		sip_ep_retire(c->lan_ep);
		c->lan_ep = NULL;
	}
	c->lan_state = state;
	snprintf(c->lan_reason, sizeof(c->lan_reason), "%s", reason ? reason : "");
}

static void lan_try(struct core *c)
{
	const struct imsd_config *cfg = c->cfg;
	struct sip_ep_cfg ec;
	struct lan_cfg lc;
	struct addr a;
	struct sip_endpoint *ep;

	c->applied = *cfg;
	if (cfg->lan_addr[0]) {
		addr_set(&a, cfg->lan_addr, (uint16_t)cfg->lan_sip_port);
	} else {
		int rc = c->ops.lan_addr(c->ops.ctx, cfg->lan_ifname, NULL, &a);

		if (rc) {
			lan_down(c, "waiting for address", NULL);
			snprintf(c->lan_reason, sizeof(c->lan_reason), "interface %s has no IPv4 address yet", cfg->lan_ifname);
			LOGW("lan: %s, trying again every %u s", c->lan_reason, LAN_RETRY_MS / 1000);
			lan_arm(c, LAN_RETRY_MS);
			return;
		}
	}
	addr_set_port(&a, (uint16_t)cfg->lan_sip_port);
	memset(&ec, 0, sizeof(ec));
	ec.name = "lan";
	ec.kind = SIP_TP_UDP;
	ec.rx_bind = a;
	ec.netdev = cfg->lan_ifname;
	ec.has_adv = true;
	ec.adv = a;
	ep = c->ops.open_ep(c->ops.ctx, &ec);
	if (!ep) {
		char as[64], why[48];

		addr_str(&a, as, sizeof(as));
		snprintf(why, sizeof(why), "%s", strerror(errno ? errno : EIO));
		lan_down(c, "error", NULL);
		snprintf(c->lan_reason, sizeof(c->lan_reason), "cannot listen on %s (%.31s): %s", as, cfg->lan_ifname, why);
		LOGW("lan: %s, trying again every %u s", c->lan_reason, LAN_RETRY_MS / 1000);
		lan_arm(c, LAN_RETRY_MS);
		return;
	}
	memset(&lc, 0, sizeof(lc));
	lc.tl = c->tl;
	lc.ep = ep;
	lc.user_agent = cfg->user_agent;
	lc.reg.min_expires = cfg->reg_min_expires;
	lc.reg.max_expires = cfg->reg_max_expires;
	lc.reg.default_expires = cfg->reg_default_expires;
	lc.reg.max_bindings = cfg->max_bindings;
	lc.reg.keepalive_s = cfg->keepalive;
	lc.on_binding = lan_binding;
	lc.arg = c;
	build_lan_hooks(c, &lc.hooks);
	c->lan = lan_new(&lc);
	if (!c->lan) {
		sip_ep_retire(ep);
		lan_down(c, "error", "out of memory");
		lan_arm(c, LAN_RETRY_MS);
		return;
	}
	txn_layer_attach(c->tl, ep);
	c->lan_ep = ep;		/* the creator's reference stays with core */
	c->lan_addr = a;
	c->lan_state = "up";
	c->lan_reason[0] = 0;
	{
		char as[64];

		addr_str(&a, as, sizeof(as));
		LOGI("lan: SIP on %s (%s), registrar limits %u..%u s, %u bindings", as, cfg->lan_ifname, cfg->reg_min_expires,
		     cfg->reg_max_expires, cfg->max_bindings);
	}
	lan_notify(c, c->lan);
	if (!cfg->lan_addr[0])
		lan_arm(c, LAN_RECHECK_MS);
}

static void lan_timer(void *arg)
{
	struct core *c = arg;
	struct addr now;

	if (!c->running)
		return;
	if (c->lan) {	/* periodic check of a derived address */
		if (c->ops.lan_addr(c->ops.ctx, c->cfg->lan_ifname, &c->lan_addr, &now) || !addr_equal_ip(&now, &c->lan_addr)) {
			LOGI("lan: the address of %s changed, restarting the LAN side", c->cfg->lan_ifname);
			lan_down(c, "waiting for address", NULL);
			lan_try(c);
		} else {
			lan_arm(c, LAN_RECHECK_MS);
		}
		return;
	}
	lan_try(c);
}

void core_reload(struct core *c)
{
	if (!c->running)
		return;
	if (!c->lan || config_lan_changed(&c->applied, c->cfg)) {
		if (c->lan)
			LOGI("lan: LAN options changed, restarting the LAN side");
		lan_down(c, "stopped", NULL);
		ev_timer_cancel(c->lan_t);
		lan_try(c);
	}
	c->applied = *c->cfg;
}

void core_lan_info(const struct core *c, struct core_lan_info *out)
{
	memset(out, 0, sizeof(*out));
	out->state = c->running ? c->lan_state : "stopped";
	snprintf(out->reason, sizeof(out->reason), "%s", c->lan_reason);
	snprintf(out->ifname, sizeof(out->ifname), "%s", c->cfg->lan_ifname);
	out->up = c->lan != NULL;
	if (out->up)
		out->addr = c->lan_addr;
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                           */

static struct sip_endpoint *def_open_ep(void *ctx, const struct sip_ep_cfg *cfg)
{
	(void)ctx;
	return sip_ep_open(cfg);
}

static int def_lan_addr(void *ctx, const char *ifname, const struct addr *prefer, struct addr *out)
{
	(void)ctx;
	return ifaddr_first_v4(ifname, prefer, out);
}

struct core *core_new(const struct imsd_config *cfg, const struct core_ops *ops)
{
	struct core *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	c->cfg = cfg;
	if (ops)
		c->ops = *ops;
	if (!c->ops.open_ep)
		c->ops.open_ep = def_open_ep;
	if (!c->ops.lan_addr)
		c->ops.lan_addr = def_lan_addr;
	c->lan_state = "stopped";
	c->lan_t = ev_timer_new(lan_timer, c);
	if (!c->lan_t) {
		free(c);
		return NULL;
	}
	return c;
}

void core_free(struct core *c)
{
	if (!c)
		return;
	core_stop(c);
	ev_timer_free(c->lan_t);
	free(c);
}

int core_start(struct core *c, const struct reg_ops *ro)
{
	struct txn_cfg tc;
	struct reg_ops r2;
	int i;

	if (c->running)
		return -EALREADY;
	memset(&tc, 0, sizeof(tc));
	tc.on_request = core_on_request;
	tc.on_stray_response = core_on_stray;
	tc.arg = c;
	c->tl = txn_layer_new(&tc);
	if (!c->tl)
		return -ENOMEM;
	r2 = *ro;
	r2.tl = c->tl;
	c->reg = reg_new(&c->cfg->reg, &r2);
	if (!c->reg) {
		txn_layer_free(c->tl);
		c->tl = NULL;
		return -ENOMEM;
	}
	c->running = true;
	for (i = 0; i < c->n_mod; i++) {
		int rc = c->mod[i]->start ? c->mod[i]->start(c, c->mod[i]->arg) : 0;

		if (rc) {
			LOGE("module %s: start failed: %s", c->mod[i]->name ? c->mod[i]->name : "?", strerror(-rc));
			continue;
		}
		c->mod_up[i] = true;
	}
	install_gm_handlers(c);
	lan_try(c);
	c->applied = *c->cfg;
	return 0;
}

void core_stop(struct core *c)
{
	int i;

	if (!c->running)
		return;
	ev_timer_cancel(c->lan_t);
	for (i = c->n_mod - 1; i >= 0; i--) {
		if (c->mod_up[i]) {
			if (c->mod[i]->lan_state && c->lan)
				c->mod[i]->lan_state(c, NULL, c->mod[i]->arg);
			if (c->mod[i]->stop)
				c->mod[i]->stop(c, c->mod[i]->arg);
		}
	}
	for (i = 0; i < c->n_mod; i++)
		c->mod_up[i] = false;
	/* LAN before the transaction layer; the Gm registration before it as well (it detaches its endpoints) */
	if (c->lan) {
		lan_free(c->lan);
		c->lan = NULL;
	}
	if (c->lan_ep) {
		sip_ep_set_rx(c->lan_ep, NULL, NULL);
		sip_ep_retire(c->lan_ep);
		c->lan_ep = NULL;
	}
	reg_free(c->reg);
	c->reg = NULL;
	txn_layer_free(c->tl);
	c->tl = NULL;
	c->running = false;
	c->lan_state = "stopped";
	c->lan_reason[0] = 0;
}

bool core_running(const struct core *c) { return c->running; }
const struct imsd_config *core_cfg(const struct core *c) { return c->cfg; }
struct txn_layer *core_txn(struct core *c) { return c->tl; }
struct reg *core_reg(struct core *c) { return c->reg; }
struct lan *core_lan(struct core *c) { return c->lan; }

void core_set_params(struct core *c, const struct core_params *p)
{
	if (p)
		c->params = *p;
	else
		memset(&c->params, 0, sizeof(c->params));
}

const char *core_param_smsc(const struct core *c)
{
	const char *s = c->params.smsc ? c->params.smsc(c->params.ctx) : NULL;

	return s ? s : "";
}

const char *core_param_sms_psi(const struct core *c)
{
	const char *s = c->params.sms_psi ? c->params.sms_psi(c->params.ctx) : NULL;

	return s ? s : "";
}

const char *core_param_imsi(const struct core *c)
{
	const char *s = c->params.imsi ? c->params.imsi(c->params.ctx) : NULL;

	return s ? s : "";
}

const char *core_param_domain(const struct core *c)
{
	const char *s = c->params.domain ? c->params.domain(c->params.ctx) : NULL;

	return s ? s : "";
}

const char *core_param_ims_netdev(const struct core *c)
{
	const char *s = c->params.ims_netdev ? c->params.ims_netdev(c->params.ctx) : NULL;

	return s ? s : "";
}

void core_param_ims_link(const struct core *c, struct core_ims_link *out)
{
	memset(out, 0, sizeof(*out));
	if (c->params.ims_link)
		c->params.ims_link(c->params.ctx, out);
}

void core_pani_refresh(struct core *c)
{
	if (c->params.pani_refresh)
		c->params.pani_refresh(c->params.ctx);
}

/* ------------------------------------------------------------------ */
/* RTP sockets                                                         */

int core_rtp_open_lan(struct core *c, struct addr *bound)
{
	if (!c->lan)
		return -ENOTCONN;
	return rtpsock_open(&c->lan_addr, c->cfg->lan_ifname, c->cfg->rtp_port_min, c->cfg->rtp_port_max, bound);
}

int core_rtp_open_carrier(struct core *c, const struct addr *local, const char *netdev, struct addr *bound)
{
	return rtpsock_open(local, netdev, c->cfg->carrier_rtp_port_min, c->cfg->carrier_rtp_port_max, bound);
}

void core_uri_number(const char *u, char *out, size_t n)
{
	size_t l;

	if (!n)
		return;
	out[0] = 0;
	if (!u)
		return;
	if (!strncasecmp(u, "sips:", 5))
		u += 5;
	else if (!strncasecmp(u, "sip:", 4))
		u += 4;
	else if (!strncasecmp(u, "tel:", 4))
		u += 4;
	l = strcspn(u, "@;>");
	if (l >= n)
		l = n - 1;
	memcpy(out, u, l);
	out[l] = 0;
}

void core_own_number(const struct core *c, char *out, size_t n)
{
	const struct reg_ctx *x = c && c->reg ? reg_context(c->reg) : NULL;

	if (!n)
		return;
	out[0] = 0;
	if (x)
		core_uri_number(x->assoc_uri && x->assoc_uri[0] ? x->assoc_uri : x->impu, out, n);
}
