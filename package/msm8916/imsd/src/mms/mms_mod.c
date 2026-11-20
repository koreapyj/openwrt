/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The MMS client as a core module, see mms_mod.h. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "mms_mod.h"
#include "mms_lan.h"
#include "mmsproxy.h"
#include "../carrier.h"
#include "../smsrelay/smsrelay_mod.h"
#include "../store/store_mod.h"
#include "../util/log.h"

static struct mms_mod_env ENV;
static bool env_set;

static struct {
	struct core *c;
	struct mmsb *b;
	struct mms *m;
	struct mms_lan *ml;
	struct mmsproxy *px;
	struct mms_cfg cfg;
	struct mmsproxy_cfg pcfg;
	char host[64];
} G;

static const char *cur_imsi(void)
{
	const char *s = G.c ? core_param_imsi(G.c) : "";

	if ((!s || !s[0]) && G.b)
		s = mmsb_imsi(G.b);
	return s ? s : "";
}

static const char *cur_plmn(void)
{
	const char *s = env_set && ENV.net_plmn ? ENV.net_plmn(ENV.ctx) : "";

	return s ? s : "";
}

/* the operator's MMS values: uci overrides, else the table entry of the SIM / the registered network */
static void cur_profile(struct carrier_mms *o)
{
	const struct imsd_config *c = core_cfg(G.c);
	struct carrier_mms_cfg cc;

	cc.mmsc = c->mmsc;
	cc.apn = c->mms_apn;
	cc.ip_type = c->mms_ip_type;
	cc.proxy = c->mms_proxy;
	cc.user_agent = c->mms_user_agent;
	cc.accept = c->mms_accept;
	carrier_resolve_mms(&cc, cur_imsi(), cur_plmn(), o);
}

bool mms_mod_bearer_selected(void)
{
	struct carrier_mms p;

	if (!G.m || !G.b)
		return false;
	cur_profile(&p);
	return !p.via_ims;
}

static void m_link(void *ctx, struct mms_link *out)
{
	struct core_ims_link l;

	(void)ctx;
	if (mms_mod_bearer_selected()) {
		struct mmsb_link bl;

		mmsb_link(G.b, &bl);
		out->on_demand = true;
		out->available = bl.available;
		out->up = bl.up;
		memcpy(out->netdev, bl.netdev, sizeof(out->netdev));
		out->local = bl.local;
		memcpy(out->dns, bl.dns, sizeof(out->dns));
		out->n_dns = bl.n_dns;
		out->seq = bl.seq;
		snprintf(out->reason, sizeof(out->reason), "%s", bl.up ? "" : bl.reason);
		return;
	}
	core_param_ims_link(G.c, &l);
	out->up = l.up;
	memcpy(out->netdev, l.netdev, sizeof(out->netdev));
	out->local = l.local;
	memcpy(out->dns, l.dns, sizeof(out->dns));
	out->n_dns = l.n_dns;
	out->seq = l.seq;
}

static void m_want(void *ctx, bool wanted)
{
	(void)ctx;
	if (G.b)
		mmsb_want(G.b, wanted);
}

static int m_gate(void *ctx, const struct addr *dst, void (*done)(void *arg, int err), void *arg)
{
	(void)ctx;
	return G.b ? mmsb_gate(G.b, dst, done, arg) : -ENETDOWN;
}

static void m_gate_cancel(void *ctx, void *arg)
{
	(void)ctx;
	if (G.b)
		mmsb_gate_cancel(G.b, arg);
}

static const char *m_net_plmn(void *ctx)
{
	(void)ctx;
	return cur_plmn();
}

/* the provider side asks: is there an on-demand bearer to bring up for this line, and which */
static bool b_profile(void *ctx, struct mmsb_profile *out, char *why, size_t why_n)
{
	struct carrier_mms p;

	(void)ctx;
	if (!G.c || !core_cfg(G.c)->mms) {
		snprintf(why, why_n, "MMS is switched off");
		return false;
	}
	cur_profile(&p);
	if (p.via_ims) {
		snprintf(why, why_n, "no MMS APN is known for this operator (the MMS client uses the IMS PDN)");
		return false;
	}
	snprintf(out->apn, sizeof(out->apn), "%s", p.apn);
	snprintf(out->ip_type, sizeof(out->ip_type), "%s", p.ip_type);
	return true;
}

static void b_changed(void *ctx)
{
	(void)ctx;
	mms_mod_link_changed();
}

static const char *b_modem(void *ctx)
{
	(void)ctx;
	return env_set && ENV.modem ? ENV.modem(ENV.ctx) : "";
}

static bool b_voice(void *ctx)
{
	(void)ctx;
	return env_set && ENV.voice_call && ENV.voice_call(ENV.ctx);
}

static void b_ipv6(void *ctx, const char *ifname, bool disable)
{
	(void)ctx;
	if (ENV.ipv6_disable)
		ENV.ipv6_disable(ENV.ctx, ifname, disable);
}

static void b_marker_load(void *ctx, char *modem, size_t mn, char *bearer, size_t bn)
{
	(void)ctx;
	modem[0] = bearer[0] = 0;
	if (ENV.marker_load)
		ENV.marker_load(ENV.ctx, modem, mn, bearer, bn);
}

static void b_marker_save(void *ctx, const char *modem, const char *bearer)
{
	(void)ctx;
	if (ENV.marker_save)
		ENV.marker_save(ENV.ctx, modem, bearer);
}

static void b_marker_clear(void *ctx)
{
	(void)ctx;
	if (ENV.marker_clear)
		ENV.marker_clear(ENV.ctx);
}

static void bearer_cfg(struct mmsb_cfg *o)
{
	const struct imsd_config *c = core_cfg(G.c);

	mmsb_cfg_defaults(o);
	o->linger_ms = c->mms_bearer_linger_s * 1000u;
	o->route_table = c->mms_route_table;
}

static int m_deliver(void *ctx, const struct mms_out *m, void (*done)(void *arg, int nok), void *arg)
{
	(void)ctx;
	return G.ml ? mms_lan_deliver(G.ml, m, done, arg) : -ENOENT;
}

static void m_abort(void *ctx, void *arg)
{
	(void)ctx;
	if (G.ml)
		mms_lan_abort(G.ml, arg);
}

static const char *m_imsi(void *ctx)
{
	(void)ctx;
	return G.c ? cur_imsi() : "";
}

static const char *m_lan_host(void *ctx)
{
	struct core_lan_info li;

	(void)ctx;
	core_lan_info(G.c, &li);
	G.host[0] = 0;
	if (li.up)
		addr_host(&li.addr, G.host, sizeof(G.host));
	return G.host;
}

static void m_devices(void *ctx, unsigned *n_mms, unsigned *n_text)
{
	(void)ctx;
	mms_lan_devices(G.ml, n_mms, n_text);
	if (!G.px || !mmsproxy_listening(G.px)) {	/* nothing to fetch through: everybody gets the text */
		*n_text += *n_mms;
		*n_mms = 0;
	}
}

static int m_deliver_raw(void *ctx, const struct mms_raw *r, void (*done)(void *arg, int nok), void *arg)
{
	(void)ctx;
	return G.ml ? mms_lan_deliver_raw(G.ml, r, done, arg) : -ENOENT;
}

static const char *m_proxy_base(void *ctx)
{
	(void)ctx;
	return G.px ? mmsproxy_base_url(G.px) : "";
}

static void p_own_number(void *ctx, char *out, size_t n)
{
	(void)ctx;
	core_own_number(G.c, out, n);
}

static void build_pcfg(struct mmsproxy_cfg *o)
{
	const struct imsd_config *c = core_cfg(G.c);

	mmsproxy_cfg_defaults(o);
	o->port = c->mms_proxy_port;
	o->cache_s = c->mms_proxy_cache;
	o->carbons = c->carbons;
	o->max_size = c->mms_max_size;
	snprintf(o->ifname, sizeof(o->ifname), "%s", c->lan_ifname);
	snprintf(o->dir, sizeof(o->dir), "%.80s-proxy", c->mms_dir);
	o->keep_messages = c->mms_keep_messages;
	o->keep_bytes = c->mms_keep_bytes;
	o->keep_days = c->mms_keep_days;
	o->store_keep_days = c->store_keep_days;
}

static void px_lan(struct lan *l)
{
	struct core_lan_info li;

	if (!G.px)
		return;
	core_lan_info(G.c, &li);
	mmsproxy_set_lan(G.px, l, l && li.up ? &li.addr : NULL);
}

static void build_cfg(struct mms_cfg *o)
{
	const struct imsd_config *c = core_cfg(G.c);

	mms_cfg_defaults(o);
	o->enable = c->mms;
	snprintf(o->mmsc, sizeof(o->mmsc), "%s", c->mmsc);
	snprintf(o->uaprof, sizeof(o->uaprof), "%s", c->mms_uaprof);
	snprintf(o->mms_apn, sizeof(o->mms_apn), "%s", c->mms_apn);
	snprintf(o->mms_ip_type, sizeof(o->mms_ip_type), "%s", c->mms_ip_type);
	snprintf(o->mms_proxy, sizeof(o->mms_proxy), "%s", c->mms_proxy);
	snprintf(o->mms_user_agent, sizeof(o->mms_user_agent), "%s", c->mms_user_agent);
	snprintf(o->mms_accept, sizeof(o->mms_accept), "%s", c->mms_accept);
	config_ims_user_agent(c, o->user_agent, sizeof(o->user_agent));
	o->max_size = c->mms_max_size;
	snprintf(o->dir, sizeof(o->dir), "%s", c->mms_dir);
	snprintf(o->url_base, sizeof(o->url_base), "%s", c->mms_url_base);
	o->keep_messages = c->mms_keep_messages;
	o->keep_bytes = c->mms_keep_bytes;
	o->keep_days = c->mms_keep_days;
	o->text_split = c->mms_text_split;
}

static void sync_cfg(void)
{
	struct mms_cfg n;
	struct mmsproxy_cfg pn;

	if (!G.m)
		return;
	build_pcfg(&pn);
	if (G.px && memcmp(&pn, &G.pcfg, sizeof(pn))) {
		G.pcfg = pn;
		mmsproxy_set_cfg(G.px, &pn);
	}
	if (G.b) {
		struct mmsb_cfg bc;

		bearer_cfg(&bc);
		mmsb_set_cfg(G.b, &bc);
	}
	build_cfg(&n);
	if (!memcmp(&n, &G.cfg, sizeof(n)))
		return;
	G.cfg = n;
	mms_set_cfg(G.m, &n);
	if (G.b)
		mmsb_poke(G.b);		/* an APN / MMS switch in uci changes the provider */
}

void mms_mod_reload(void)
{
	sync_cfg();
}

static void on_push(void *arg, const char *from, unsigned port, const uint8_t *data, size_t len)
{
	(void)arg;
	if (!G.m)
		return;
	sync_cfg();
	mms_on_push(G.m, from, port, data, len);
}

static int mod_start(struct core *c, void *arg)
{
	struct mms_ops ops;

	(void)arg;
	if (G.m)
		return -EBUSY;
	memset(&G, 0, sizeof(G));
	G.c = c;
	build_cfg(&G.cfg);
	memset(&ops, 0, sizeof(ops));
	ops.link = m_link;
	ops.deliver = m_deliver;
	ops.deliver_abort = m_abort;
	ops.lan_host = m_lan_host;
	ops.imsi = m_imsi;
	ops.devices = m_devices;
	ops.deliver_raw = m_deliver_raw;
	ops.proxy_base = m_proxy_base;
	ops.net_plmn = m_net_plmn;
	ops.want = m_want;
	ops.gate = m_gate;
	ops.gate_cancel = m_gate_cancel;
	ops.store = store_mod_get();
	if (env_set && ENV.uq && ENV.net && ENV.exec) {
		struct mmsb_ops bo;
		struct mmsb_cfg bc;

		memset(&bo, 0, sizeof(bo));
		bo.uq = *ENV.uq;
		bo.net = *ENV.net;
		bo.ipv6_disable = b_ipv6;
		bo.exec = *ENV.exec;
		bo.modem = b_modem;
		bo.profile = b_profile;
		bo.changed = b_changed;
		bo.voice_call = b_voice;
		bo.marker_load = b_marker_load;
		bo.marker_save = b_marker_save;
		bo.marker_clear = b_marker_clear;
		bearer_cfg(&bc);
		G.b = mmsb_new(&bc, &bo);
	}
	G.ml = mms_lan_new();
	if (!G.ml)
		return -ENOMEM;
	mms_lan_set(G.ml, core_lan(c));
	G.m = mms_new(&G.cfg, &ops);
	if (!G.m) {
		mms_lan_free(G.ml);
		mmsb_free(G.b);
		memset(&G, 0, sizeof(G));
		return -ENOMEM;
	}
	{
		struct mmsproxy_ops po;

		memset(&po, 0, sizeof(po));
		po.own_number = p_own_number;
		po.store = store_mod_get();
		build_pcfg(&G.pcfg);
		G.px = mmsproxy_new(&G.pcfg, &po, G.m);
		if (!G.px) {
			mms_free(G.m);
			mms_lan_free(G.ml);
			mmsb_free(G.b);
			memset(&G, 0, sizeof(G));
			return -ENOMEM;
		}
		px_lan(core_lan(c));
	}
	smsrelay_mod_set_push(on_push, NULL);
	return 0;
}

static void mod_stop(struct core *c, void *arg)
{
	(void)c;
	(void)arg;
	if (!G.m)
		return;
	smsrelay_mod_set_push(NULL, NULL);
	mmsproxy_free(G.px);	/* uses the manager's HTTP client: first */
	G.px = NULL;
	mms_free(G.m);		/* aborts its deliveries through ops.deliver_abort */
	G.m = NULL;
	mmsb_free(G.b);		/* the bearer was released by mms_mod_release() before (no remote cleanup here) */
	G.b = NULL;
	mms_lan_free(G.ml);
	memset(&G, 0, sizeof(G));
}

static void mod_lan_state(struct core *c, struct lan *l, void *arg)
{
	(void)c;
	(void)arg;
	if (G.ml)
		mms_lan_set(G.ml, l);
	px_lan(l);
}

const struct core_module mms_module = {
	.name = "mms",
	.start = mod_start,
	.stop = mod_stop,
	.lan_state = mod_lan_state,
};

void mms_mod_link_changed(void)
{
	if (G.m)
		mms_link_changed(G.m);
}

bool mms_mod_status(struct mms_status *out)
{
	if (!G.m)
		return false;
	sync_cfg();
	mms_get_status(G.m, out);
	return true;
}

int mms_mod_fetch(const char *url, const char *from, const char *subject)
{
	if (!G.m)
		return -ESHUTDOWN;
	sync_cfg();
	return mms_fetch(G.m, url, from, subject);
}

bool mms_mod_proxy_status(struct mmsproxy_status *out)
{
	if (!G.px)
		return false;
	mmsproxy_get_status(G.px, out);
	return true;
}

void mms_mod_set_env(const struct mms_mod_env *e)
{
	if (e) {
		ENV = *e;
		env_set = true;
	} else {
		memset(&ENV, 0, sizeof(ENV));
		env_set = false;
	}
}

bool mms_mod_push_ready(void)
{
	return G.m && core_cfg(G.c)->mms && mms_mod_bearer_selected();
}

bool mms_mod_identity_pending(void)
{
	struct carrier_mms p;

	if (!G.m || !G.b || !core_cfg(G.c)->mms)
		return false;
	if (core_cfg(G.c)->mms_apn[0])
		return false;
	cur_profile(&p);
	return !strcmp(p.how, "none") && !cur_imsi()[0];	/* nothing matched and the IMSI is not known yet: the answer may still change */
}

void mms_mod_poke(void)
{
	if (G.b)
		mmsb_poke(G.b);
}

void mms_mod_release(void (*done)(void *arg), void *arg, unsigned timeout_ms)
{
	if (!G.b) {
		if (done)
			done(arg);
		return;
	}
	mmsb_shutdown(G.b, done, arg, timeout_ms);
}

bool mms_mod_bearer_status(struct mmsb_status *out)
{
	if (!G.b)
		return false;
	mmsb_get_status(G.b, out);
	return true;
}
