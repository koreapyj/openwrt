/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * imsd: AP side IMS stack daemon.
 *
 * Modem handling (uqmid over ubus, ISIM identity, IMS bearer and netdev, QRTR
 * check of the modem's own IMS), the Gm registration with IPsec, the LAN side
 * (SIP registrar for the softphones, src/core.c) and the media engine thread.
 * Configuration comes from uci (libuci), SIGHUP re-reads it.
 *
 *   -l <level>   log level, overrides the config   (error|warn|notice|info|debug)
 *   -C <dir>     uci config directory              (default /etc/config)
 *   -S           also log to stderr
 *   -V           print the version and exit
 *
 * SIGTERM / SIGINT: de-register (at most 2 s), delete our bearer, remove the
 * netdev configuration, then exit. A second signal exits at once.
 */
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/signalfd.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include "carrier.h"
#include "config.h"
#include "core.h"
#include "gm/reg.h"
#include "media/bridge.h"
#include "b2b/b2b.h"
#include "cs/csbackend.h"
#include "cs/cscall.h"
#include "cs/csmedia.h"
#include "cs/csubus.h"
#include "cs/cssms.h"
#include "gm/xfrm.h"
#include "modem/imsmodem.h"
#include "modem/uqmid_ubus.h"
#include "smsrelay/smsrelay_mod.h"
#include "mms/mms_mod.h"
#include "mms/mmsb_io.h"
#include "mms/mmsguard.h"
#include "modem/netcfg.h"
#include "store/store_mod.h"
#include "ua/regpersist_mod.h"
#include "util/evloop.h"
#include "util/log.h"
#include "util/sys.h"

#ifndef IMSD_VERSION
#define IMSD_VERSION "0.1"
#endif

#define LAG_TICK_MS	20u	/* watchdog timer period */
#define LAG_WARN_MS	100u	/* an iteration blocked at least this long is reported */
#define STOP_HARD_MS	4500u	/* procd kills after 5 s */

static struct imsd_daemon {
	struct imsd_config cfg;
	const char *confdir;
	int level_override;	/* -l, -1 = none */
	struct ubus_auto_conn ubus;
	struct ubus_object obj;
	struct ubus_object_type obj_type;
	struct ubus_method methods[13];
	struct blob_buf bb;
	struct uloop_timeout lag;
	uint64_t lag_expected;
	struct uloop_fd sigfd;
	struct uloop_timeout exit_t;
	struct uloop_timeout hard_t;
	struct imsmodem *modem;		/* the IMS side: NULL while the backend is not IMS (ims_phase) */
	struct reg *reg;
	struct core *core;
	/* backend selection (cs/csbackend.h): the circuit switched call path exists unless backend=ims */
	struct csline *cs_line;
	struct cscall_mgr *cs_mgr;
	struct cssms *cs_sms;		/* SMS through the modem, with the call path */
	struct carrier_backend cs_be;
	struct backend_cfg bkc;
	struct backend_state bk_st;
	struct backend_out bk;
	struct uloop_timeout bk_t;
	enum ims_phase { IMS_OFF, IMS_ON, IMS_DEREG, IMS_RELEASING } ims_phase;
	uint64_t ims_t0;
	struct uloop_fd bridge_fd;
	bool bridge_fd_on;
	bool stopping;
	bool svc_stopping;	/* a service stop (reload with enabled=0) is in progress */
	int stop_wait;		/* parts of the stop that are still running: the modem side, the MMS bearer */
} D;

/* ------------------------------------------------------------------ */
/* loop lag watchdog                                                   */

static void lag_cb(struct uloop_timeout *t)
{
	uint64_t now = mono_ms();
	uint64_t lag = now > D.lag_expected ? now - D.lag_expected : 0;

	if (lag + LAG_TICK_MS >= LAG_WARN_MS)
		LOGW("main loop blocked: timer fired %llu ms late (an iteration took >= %u ms)",
		     (unsigned long long)lag, LAG_WARN_MS);
	D.lag_expected = now + LAG_TICK_MS;
	uloop_timeout_set(t, LAG_TICK_MS);
}

/* ------------------------------------------------------------------ */
/* glue between the modules                                            */

static void on_link(void *arg, const struct ims_link *l)
{
	(void)arg;
	if (D.reg)
		reg_set_link(D.reg, l);
	mms_mod_link_changed();		/* the MMS client fetches over the IMS bearer */
}

static const char *reg_pani(void *ctx)
{
	(void)ctx;
	return D.modem ? imsmodem_pani(D.modem) : "";
}

/* what the modules take from the SIM / modem (core.h struct core_params) */
static const char *par_smsc(void *ctx)
{
	(void)ctx;
	return D.modem ? imsmodem_smsc(D.modem) : "";
}

static const char *par_psi(void *ctx)
{
	(void)ctx;
	return D.modem ? imsmodem_sms_psi(D.modem) : "";
}

static const char *par_imsi(void *ctx)
{
	(void)ctx;
	return D.modem ? imsmodem_imsi(D.modem) : "";
}

static const char *par_domain(void *ctx)
{
	(void)ctx;
	return D.modem ? imsmodem_link(D.modem)->id.domain : "";
}

static const char *par_netdev(void *ctx)
{
	(void)ctx;
	return D.modem ? imsmodem_link(D.modem)->br.ifname : "";
}

static void par_ims_link(void *ctx, struct core_ims_link *out)
{
	const struct ims_link *l;
	int i;

	(void)ctx;
	if (!D.modem)
		return;
	l = imsmodem_link(D.modem);
	out->seq = l->seq;
	out->up = l->ready && l->br.ifname[0];
	snprintf(out->netdev, sizeof(out->netdev), "%s", l->br.ifname);
	out->local = l->br.local;
	for (i = 0; i < l->br.n_dns && i < 4; i++)
		if (!addr_set(&out->dns[out->n_dns], l->br.dns[i], 53))
			out->n_dns++;
}

static void par_pani_refresh(void *ctx)
{
	(void)ctx;
	if (D.modem)
		imsmodem_pani_refresh(D.modem);
}

/* ---- what the MMS data connection needs from the modem side (mms/mms_mod.h struct mms_mod_env) ---- */

static const char *mmsenv_modem(void *ctx)
{
	const char *p = D.cs_line ? csline_modem(D.cs_line) : "";

	(void)ctx;
	if (p && p[0])
		return p;
	return D.modem ? imsmodem_modem_path(D.modem) : "";
}

static const char *mmsenv_plmn(void *ctx)
{
	const struct csline_status *ls = D.cs_line ? csline_status(D.cs_line) : NULL;

	(void)ctx;
	return ls ? ls->operator_code : "";
}

static bool mmsenv_voice_call(void *ctx)
{
	struct cscall_status cs;

	(void)ctx;
	if (!D.cs_mgr)
		return false;
	cscall_mgr_status(D.cs_mgr, &cs);
	return cs.live > 0;
}

static int reg_aka(void *ctx, const uint8_t rand[16], const uint8_t autn[16], imsmodem_aka_cb cb, void *arg)
{
	(void)ctx;
	return D.modem ? imsmodem_aka(D.modem, rand, autn, cb, arg) : -ENODEV;
}

static void reg_aka_cancel(void *ctx, void *arg)
{
	(void)ctx;
	if (D.modem)
		imsmodem_aka_cancel(D.modem, arg);
}

static int reg_xfrm_install(void *ctx, const struct xfrm_sa_params *p)
{
	(void)ctx;
	return xfrm_sa_install(p);
}

static void reg_xfrm_remove(void *ctx, const struct xfrm_sa_params *p)
{
	int failed;

	(void)ctx;
	failed = xfrm_sa_remove(p);
	if (failed)
		LOGW("xfrm: %d object(s) could not be removed", failed);
}

static struct sip_endpoint *reg_open_ep(void *ctx, const struct sip_ep_cfg *cfg)
{
	(void)ctx;
	return sip_ep_open(cfg);
}

struct notify_req {
	struct ubus_notify_request req;
};

static void notify_done(struct ubus_notify_request *req, int idx, int ret)
{
	(void)idx; (void)ret;
	free(container_of(req, struct notify_req, req));
}

static void call_notice(void *arg, const struct b2b_notice *n);

static void reg_hook(void *arg, enum reg_event ev, const char *reason)
{
	struct ubus_context *ctx = &D.ubus.ctx;
	struct notify_req *n;
	struct blob_buf b = {};

	(void)arg;
	LOGI("registration %s (%s)", ev == REG_EV_DOWN ? "down" : ev == REG_EV_UP ? "up" : "replaced", reason ? reason : "");
	if (!D.obj.has_subscribers || !D.obj.id)
		return;
	n = calloc(1, sizeof(*n));
	if (!n)
		return;
	blob_buf_init(&b, 0);
	blobmsg_add_u8(&b, "registered", ev != REG_EV_DOWN);
	blobmsg_add_string(&b, "reason", reason ? reason : "");
	if (ubus_notify_async(ctx, &D.obj, "registration", b.head, &n->req)) {
		free(n);
	} else {
		n->req.complete_cb = notify_done;
		ubus_complete_request_async(ctx, &n->req.req);
	}
	blob_buf_free(&b);
}

/* ------------------------------------------------------------------ */
/* modules plugged into the core                                       */

/*
 * The call control and the SMS relay register here (struct core_module, see core.h):
 *     static const struct core_module *const modules[] = { &call_module, &smsrelay_module };
 * Their LAN hooks, Gm handlers and media-event handler are installed by core when the services start.
 */
static const struct core_module *const modules[] = { &store_module, &smsrelay_module, &b2b_module, &mms_module, &regpersist_module, NULL };

static void lan_binding_notify(void *arg, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why)
{
	struct ubus_context *ctx = &D.ubus.ctx;
	struct notify_req *n;
	struct blob_buf bb = {};
	const char *name;

	(void)arg; (void)why;
	switch (ev) {
	case REG_EV_ADDED:
		name = "added";
		smsrelay_mod_cs_kick();		/* CS messages kept in the modem for want of a device are offered again */
		break;
	case REG_EV_REMOVED:
		name = "removed";
		break;
	default:
		return;		/* refreshes and reachability flips are not events for subscribers */
	}
	LOGI("lan: binding %s: %s (%s)", name, b->contact, b->ua[0] ? b->ua : "no user agent");
	if (!D.obj.has_subscribers || !D.obj.id)
		return;
	n = calloc(1, sizeof(*n));
	if (!n)
		return;
	blob_buf_init(&bb, 0);
	blobmsg_add_string(&bb, "event", name);
	blobmsg_add_string(&bb, "contact", b->contact);
	blobmsg_add_string(&bb, "user_agent", b->ua);
	if (ubus_notify_async(ctx, &D.obj, "lan.binding", bb.head, &n->req)) {
		free(n);
	} else {
		n->req.complete_cb = notify_done;
		ubus_complete_request_async(ctx, &n->req.req);
	}
	blob_buf_free(&bb);
}

static void bridge_fd_cb(struct uloop_fd *u, unsigned int events)
{
	(void)u; (void)events;
	bridge_events_dispatch(core_bridge_event, D.core);
}

static void media_start(void)
{
	if (bridge_engine_start()) {
		LOGW("media: cannot start the media engine: %s", strerror(errno));
		return;
	}
	D.bridge_fd.fd = bridge_event_fd();
	D.bridge_fd.cb = bridge_fd_cb;
	if (D.bridge_fd.fd >= 0 && !uloop_fd_add(&D.bridge_fd, ULOOP_READ))
		D.bridge_fd_on = true;
	LOGI("media: engine started");
}

static void media_stop(void)
{
	if (D.bridge_fd_on) {
		uloop_fd_delete(&D.bridge_fd);
		D.bridge_fd_on = false;
	}
	bridge_engine_stop();
}

/* ------------------------------------------------------------------ */
/* services (modem + registration)                                     */

static bool svc_running(void)
{
	return D.modem || D.reg;
}

static enum backend_mode bk_mode(void)
{
	enum backend_mode m = BACKEND_AUTO;

	backend_mode_parse(D.cfg.backend, &m);
	return m;
}

static void bk_cfg_load(void)
{
	backend_cfg_defaults(&D.bkc);
	D.bkc.mode = bk_mode();
	D.bkc.ims_grace_ms = D.cfg.ims_grace_s * 1000u;
	D.bkc.switch_delay_ms = D.cfg.backend_switch_delay_s * 1000u;
	D.bkc.cs_to_ims_ms = D.cfg.backend_ims_settle_s * 1000u;
}

static void bk_schedule(void)
{
	if (D.reg)
		uloop_timeout_set(&D.bk_t, 0);	/* from the loop, never from inside the module that reported the event */
}

/* ---- the circuit switched call path (csline + cscall on uqmid, b2b gets it as a carrier backend) ---- */

static void cs_line_status(void *arg, const struct csline_status *s)
{
	(void)arg; (void)s;
	mms_mod_poke();		/* the MMS bearer follows the modem object and the registered network */
	bk_schedule();
}

static void cs_cfg_fill(struct csline_cfg *lc, struct cscall_cfg *cc)
{
	csline_cfg_defaults(lc);
	snprintf(lc->modem_pin, sizeof(lc->modem_pin), "%s", D.cfg.modem.modem_pin);
	lc->manage_modem = D.cfg.modem.manage_modem;
	lc->allow_roaming = D.cfg.cs_allow_roaming;
	cscall_cfg_defaults(cc);
	cc->early_media = D.cfg.cs_early_media;
	cc->ring_timeout_s = D.cfg.cs_ring_timeout_s;
	cc->short_ring_ms = D.cfg.cs_short_ring_ms;
}

/* ---- SMS over the circuit switched line (cssms) into the SMS relay ---- */

static int cs_sms_in(void *arg, const struct cssms_in *m)
{
	(void)arg;
	/* an MMS notification while the operator is not known yet (the SIM identity is being read): it stays in the modem and is offered again */
	if (m->kind == CSSMS_DATA && m->wsp_push && m->mms_hint && D.bk.backend != BK_IMS && mms_mod_identity_pending()) {
		LOGI("mms: notification from %s waits for the SIM identity", m->from);
		return -EAGAIN;
	}
	return smsrelay_mod_cs_in(m);
}

static void cs_sms_cfg_fill(struct cssms_cfg *sc)
{
	struct smsrelay_cfg rc;

	cssms_cfg_defaults(sc);
	smsrelay_cfg_defaults(&rc);
	sc->max_segments = rc.max_segments;	/* the relay's limit: the same 413 as over IMS */
	sc->queue_max = rc.queue_max;
	sc->incomplete_ms = D.cfg.cs_sms_incomplete_s * 1000u;
	sc->on_message = cs_sms_in;
}

/* the circuit switched backend carries the SMS now (per message: asked when the LAN MESSAGE arrives) */
static bool cs_sms_active(void *ctx)
{
	(void)ctx;
	return D.cs_sms && D.bk.backend == BK_CS;
}

static int cs_sms_submit(void *ctx, const struct cssms_submit *q, cssms_done_cb cb, void *arg)
{
	(void)ctx;
	return D.cs_sms ? cssms_submit(D.cs_sms, q, cb, arg) : -ENOTCONN;
}

/* the MMS manager takes the notification when the IMS backend is active (the IMS PDN, or the on-demand bearer for an operator with an MMS
 * APN), or, on the circuit switched backend, when the operator has an MMS APN (the on-demand bearer: mms/mmsbearer.h) */
static bool cs_sms_push_active(void *ctx)
{
	(void)ctx;
	return D.bk.backend == BK_IMS || mms_mod_push_ready();
}

static void cs_sms_in_done(void *ctx, unsigned id, bool taken)
{
	(void)ctx;
	if (D.cs_sms)
		cssms_in_done(D.cs_sms, id, taken);
}

static void cs_sms_kick(void *ctx)
{
	(void)ctx;
	if (D.cs_sms)
		cssms_kick(D.cs_sms);
}

static void cs_start(void)
{
	struct csline_cfg lc;
	struct cscall_cfg cc;
	struct csline_listener lst;

	if (D.cs_line)
		return;
	cs_cfg_fill(&lc, &cc);
	D.cs_line = csline_new(&lc, csub_ops());
	D.cs_mgr = D.cs_line ? cscall_mgr_new(D.cs_line, &cc) : NULL;
	if (D.cs_mgr) {
		struct cssms_cfg sc;
		struct smsrelay_mod_cs hk;

		cs_sms_cfg_fill(&sc);
		D.cs_sms = cssms_new(D.cs_line, &sc);
		if (!D.cs_sms)
			LOGE("cs: out of memory, SMS over the circuit switched line is not available");
		memset(&hk, 0, sizeof(hk));
		hk.sms_active = cs_sms_active;
		hk.submit = cs_sms_submit;
		hk.push_active = cs_sms_push_active;
		hk.in_done = cs_sms_in_done;
		hk.kick = cs_sms_kick;
		smsrelay_mod_set_cs(&hk);
	}
	if (!D.cs_mgr) {
		LOGE("cs: out of memory, the circuit switched call path is not available");
		csline_free(D.cs_line);
		D.cs_line = NULL;
		return;
	}
	memset(&lst, 0, sizeof(lst));
	lst.on_status = cs_line_status;
	csline_add_listener(D.cs_line, &lst);
	cscall_carrier_backend(D.cs_mgr, &D.cs_be);
	b2b_set_cs_backend(&D.cs_be);
	LOGI("cs: call path started (pcm device '%s', early media %s, ring timeout %u s)", D.cfg.cs_pcm_device,
	     D.cfg.cs_early_media ? "on" : "off", D.cfg.cs_ring_timeout_s);
	if (D.ubus.ctx.sock.fd >= 0 && D.obj.id)
		csub_resync(&D.ubus.ctx);
}

static void cs_stop(void)
{
	if (!D.cs_line)
		return;
	b2b_set_cs_backend(NULL);	/* ends its calls and drops the incoming hook before the manager goes */
	smsrelay_mod_set_cs(NULL);
	cssms_free(D.cs_sms);		/* fails the MO messages in flight (503) */
	D.cs_sms = NULL;
	cscall_mgr_free(D.cs_mgr);
	csline_free(D.cs_line);
	D.cs_mgr = NULL;
	D.cs_line = NULL;
	memset(&D.cs_be, 0, sizeof(D.cs_be));
	LOGI("cs: call path stopped");
}

/* ---- the IMS side (modem link + Gm registration; the reg object itself lives with the core) ---- */

static int ims_start(bool resync)
{
	struct imsmodem_ops mo;

	memset(&mo, 0, sizeof(mo));
	mo.uq = *uqb_ops();
	mo.net = *netcfg_io_ops();
	mo.qrtr = *qrtr_io_ops();
	mo.on_link = on_link;
	D.modem = imsmodem_new(&D.cfg.modem, &mo);
	if (!D.modem)
		return -ENOMEM;
	reg_set_enabled(D.reg, true);
	D.ims_phase = IMS_ON;
	LOGI("ims: started: apn %s %s profile %d, %d static P-CSCF, table %u, ports %u-%u", D.cfg.modem.apn,
	     D.cfg.modem.ip_type, D.cfg.modem.profile_id, D.cfg.modem.n_static, D.cfg.modem.route_table,
	     D.cfg.reg.port_min, D.cfg.reg.port_max);
	if (resync && D.ubus.ctx.sock.fd >= 0 && D.obj.id)
		uqb_resync(&D.ubus.ctx);
	return 0;
}

static void modem_stopped(void *arg);

static void ims_released(void *arg)
{
	struct imsmodem *m = D.modem;

	(void)arg;
	if (D.stopping || D.svc_stopping) {
		modem_stopped(NULL);	/* the stop path frees the object */
		return;
	}
	D.modem = NULL;
	imsmodem_free(m);
	D.ims_phase = IMS_OFF;
	mms_mod_link_changed();
	LOGI("ims: stopped (bearer released, not registered)");
	bk_schedule();
}

static void ims_release(void)
{
	D.ims_phase = IMS_RELEASING;
	imsmodem_shutdown(D.modem, ims_released, NULL, 3000);
}

static void ims_begin_stop(const char *why)
{
	LOGI("ims: stopping (%s)", why);
	reg_set_enabled(D.reg, false);		/* de-REGISTER on the protected endpoint, SAs removed */
	D.ims_phase = IMS_DEREG;
	D.ims_t0 = mono_ms();
}

/* auto: IMS is attempted while the modem is on LTE (a handset does the same); on 2G / 3G there is no IMS for us */
static bool ims_wanted(const struct backend_in *in)
{
	switch (D.bkc.mode) {
	case BACKEND_IMS:
		return true;
	case BACKEND_CS:
		return false;
	default:
		return in->rat == CSRAT_LTE || (in->rat == CSRAT_NONE && D.ims_phase != IMS_OFF);
	}
}

static void bk_inputs(struct backend_in *in)
{
	const struct csline_status *ls = D.cs_line ? csline_status(D.cs_line) : NULL;
	const char *r = D.modem ? imsmodem_reason(D.modem) : "";

	memset(in, 0, sizeof(*in));
	if (ls) {
		in->rat = ls->rat;
		in->cs_voice_ok = ls->voice_ok;
		in->cs_sms_ok = ls->sms_ok;
	}
	in->ims_registered = D.ims_phase == IMS_ON && D.reg && reg_is_registered(D.reg);
	in->ims_possible = strcmp(r, "isim-error") && strcmp(r, "modem-ims-active");
	in->call_active = b2b_active_calls() > 0;
}

static void bk_eval(void)
{
	struct backend_in in;
	struct backend_out out;
	enum b2b_backend sel;
	bool idle, want_cs = D.bkc.mode != BACKEND_IMS;

	if (!D.reg || D.stopping || D.svc_stopping)
		return;
	idle = b2b_active_calls() == 0;
	if (want_cs && !D.cs_line)
		cs_start();
	else if (!want_cs && D.cs_line && idle)
		cs_stop();
	mms_mod_poke();		/* the provider of the MMS data connection follows the backend / carrier */
	bk_inputs(&in);
	backend_decide(&D.bkc, &D.bk_st, &in, mono_ms(), &out);
	if (out.backend != D.bk.backend || strcmp(out.reason, D.bk.reason)) {
		LOGI("backend: %s (%s)%s", backend_name(out.backend), out.reason, out.voice_ok ? "" : ", not usable yet");
		if (out.backend != D.bk.backend)
			LOGI("backend: new calls go %s", out.backend == BK_CS ? "circuit switched" : out.backend == BK_IMS ? "over IMS" : "nowhere yet");
	}
	D.bk = out;
	sel = out.backend == BK_IMS ? B2B_BE_GM : (out.backend == BK_CS && D.cs_mgr) ? B2B_BE_CS : B2B_BE_NONE;
	b2b_select_backend(sel);
	switch (D.ims_phase) {
	case IMS_OFF:
		if (ims_wanted(&in) && idle && ims_start(true))
			LOGE("ims: out of memory");
		break;
	case IMS_ON:
		if (!ims_wanted(&in) && idle)
			ims_begin_stop(D.bkc.mode == BACKEND_CS ? "backend cs" : "the modem left LTE");
		break;
	case IMS_DEREG: {
		struct reg_status rs;

		reg_get_status(D.reg, &rs);
		if (rs.state == RS_IDLE || mono_ms() - D.ims_t0 > 4000)
			ims_release();
		break;
	}
	case IMS_RELEASING:
		break;
	}
}

static void bk_cb(struct uloop_timeout *t)
{
	bk_eval();
	uloop_timeout_set(t, D.ims_phase == IMS_DEREG || D.ims_phase == IMS_RELEASING ? 250 : 1000);
}

/* LAN MESSAGE while the circuit switched backend serves the line: the relay sends it through cssms; refused here only when there is
 * no SMS path at all (neither the IMS one nor cssms) */
static bool lan_message_gate(void *ctx, struct txn_server *st, const struct sip_msg *req)
{
	struct sip_resp_parts p;

	(void)ctx; (void)req;
	if (D.bk.backend != BK_CS || !st || D.cs_sms)
		return false;
	memset(&p, 0, sizeof(p));
	p.status = 503;
	p.reason = "SMS not available on this line yet";
	p.extra = "Warning: 399 imsd \"SMS not available on this line yet\"\r\n";
	txn_server_reply(st, &p);
	return true;
}

static void svc_start(void)
{
	struct reg_ops ro;

	if (svc_running())
		return;
	memset(&ro, 0, sizeof(ro));
	ro.aka = reg_aka;
	ro.aka_cancel = reg_aka_cancel;
	ro.xfrm_install = reg_xfrm_install;
	ro.xfrm_remove = reg_xfrm_remove;
	ro.open_ep = reg_open_ep;
	ro.pani = reg_pani;
	media_start();		/* before the modules: they create bridges in start() */
	{
		struct core_params cp;

		memset(&cp, 0, sizeof(cp));
		cp.smsc = par_smsc;
		cp.sms_psi = par_psi;
		cp.imsi = par_imsi;
		cp.domain = par_domain;
		cp.pani_refresh = par_pani_refresh;
		cp.ims_netdev = par_netdev;
		cp.ims_link = par_ims_link;
		core_set_params(D.core, &cp);	/* the getters look at D.modem when called */
	}
	{
		struct mms_mod_env me;

		memset(&me, 0, sizeof(me));
		me.uq = uqb_ops();
		me.net = netcfg_io_ops();
		me.ipv6_disable = mmsb_io_ipv6_disable;
		me.exec = guard_exec_real();
		me.modem = mmsenv_modem;
		me.net_plmn = mmsenv_plmn;
		me.voice_call = mmsenv_voice_call;
		me.marker_load = mmsb_io_marker_load;
		me.marker_save = mmsb_io_marker_save;
		me.marker_clear = mmsb_io_marker_clear;
		mms_mod_set_env(&me);
	}
	if (core_start(D.core, &ro))
		D.reg = NULL;
	else
		D.reg = core_reg(D.core);
	D.ims_phase = IMS_OFF;
	bk_cfg_load();
	memset(&D.bk_st, 0, sizeof(D.bk_st));
	memset(&D.bk, 0, sizeof(D.bk));
	D.bk.reason = "starting";
	if (!D.reg || (D.bkc.mode == BACKEND_IMS && ims_start(false))) {
		LOGE("out of memory");
		core_stop(D.core);
		media_stop();
		imsmodem_free(D.modem);
		D.reg = NULL;
		D.modem = NULL;
		D.ims_phase = IMS_OFF;
		return;
	}
	reg_add_hook(D.reg, reg_hook, NULL);
	b2b_set_notify(call_notice, NULL);
	if (D.bkc.mode != BACKEND_IMS) {
		reg_set_enabled(D.reg, false);	/* no IMS link will exist until the backend switches to IMS */
		cs_start();
	}
	LOGI("services started: backend %s (%s)", backend_mode_name(D.bkc.mode),
	     D.bkc.mode == BACKEND_IMS ? "IMS only" : D.bkc.mode == BACKEND_CS ? "circuit switched only, IMS is not touched" :
	     "IMS on LTE when it registers, else circuit switched");
	if ((D.modem || D.reg) && D.ubus.ctx.sock.fd >= 0 && D.obj.id)
		uqb_resync(&D.ubus.ctx);	/* ubus is already up: subscribe now (the MMS bearer calls uqmid through it as well) */
	uloop_timeout_set(&D.bk_t, 0);
}

static void svc_free(void)
{
	struct imsmodem *m = D.modem;

	uloop_timeout_cancel(&D.bk_t);
	cs_stop();		/* its calls end and the manager goes before the modules / the transaction layer */
	D.reg = NULL;
	D.modem = NULL;
	D.ims_phase = IMS_OFF;
	core_stop(D.core);	/* modules, LAN, Gm registration, transaction layer (in that order) */
	media_stop();		/* after the modules destroyed their bridges */
	imsmodem_free(m);
}

static void stop_part_done(void)
{
	if (D.stop_wait > 0 && --D.stop_wait > 0)
		return;
	uloop_timeout_set(&D.exit_t, 0);
}

static void modem_stopped(void *arg)
{
	(void)arg;
	LOGI("modem side released");
	stop_part_done();
}

static void mms_released(void *arg)
{
	(void)arg;
	LOGI("MMS data connection released");
	stop_part_done();
}

static void reg_stopped(void *arg)
{
	(void)arg;
	if (D.modem && D.ims_phase != IMS_RELEASING)
		imsmodem_shutdown(D.modem, modem_stopped, NULL, 2000);
	else if (!D.modem)
		modem_stopped(NULL);
	/* else: the IMS side is being released already, ims_released() reports it */
}

static void exit_cb(struct uloop_timeout *t)
{
	(void)t;
	svc_free();
	if (D.svc_stopping) {
		D.svc_stopping = false;
		LOGI("services stopped (disabled by configuration)");
		return;
	}
	uloop_end();
}

static void hard_cb(struct uloop_timeout *t)
{
	(void)t;
	LOGW("shutdown did not finish in time, exiting");
	uloop_end();
}

static void begin_stop(bool exit_after)
{
	if (D.stopping) {
		if (exit_after) {
			LOGW("second stop request, exiting at once");
			uloop_end();
		}
		return;
	}
	if (exit_after) {
		D.stopping = true;
		uloop_timeout_set(&D.hard_t, STOP_HARD_MS);
	} else {
		D.svc_stopping = true;
	}
	if (!svc_running()) {
		uloop_timeout_set(&D.exit_t, 0);
		return;
	}
	LOGI("stopping: ending calls, de-registering");
	D.stop_wait = 2;
	mms_mod_release(mms_released, NULL, 2500);	/* the on-demand bearer and its traffic guard go in parallel with the IMS side */
	b2b_end_all("daemon stopping");	/* BYE / CANCEL to both sides while the registration still carries them */
	if (D.reg)
		reg_shutdown(D.reg, reg_stopped, NULL);
	else
		reg_stopped(NULL);
}

static void do_reload(void)
{
	struct imsd_config nc;
	char err[160];
	bool was = D.cfg.enabled, mr = false, rr = false;

	if (D.stopping || D.svc_stopping)
		return;
	if (config_load_uci(&nc, D.confdir, err, sizeof(err))) {
		LOGE("reload: %s; keeping the running configuration", err);
		return;
	}
	if (D.level_override >= 0)
		nc.log_level = D.level_override;
	imsd_log_level(nc.log_level);
	D.cfg = nc;
	LOGI("reload: configuration read (enabled %d)", nc.enabled);
	if (nc.enabled && !was) {
		svc_start();
	} else if (!nc.enabled && was) {
		begin_stop(false);
	} else if (nc.enabled && svc_running()) {
		mr = D.modem && imsmodem_set_cfg(D.modem, &nc.modem);
		rr = reg_set_cfg(D.reg, &nc.reg);
		bk_cfg_load();
		if (D.cs_line) {
			struct csline_cfg lc;
			struct cscall_cfg cc;

			cs_cfg_fill(&lc, &cc);
			csline_set_cfg(D.cs_line, &lc);
			cscall_mgr_set_cfg(D.cs_mgr, &cc);
			if (D.cs_sms) {
				struct cssms_cfg sc;

				cs_sms_cfg_fill(&sc);
				cssms_set_cfg(D.cs_sms, &sc);
			}
			b2b_set_cs_backend(&D.cs_be);	/* set_cfg replaced the incoming hook */
		}
		bk_schedule();		/* backend switch / the circuit switched path appears or goes */
		core_reload(D.core);
		store_mod_reload();
		mms_mod_reload();	/* mms_proxy_port / mms_proxy_cache / carbons / MMS limits take effect now */
		LOGI("reload: applied%s%s", mr ? ", modem link restarted" : "", rr ? ", registering again" : "");
	}
}

/* ------------------------------------------------------------------ */
/* signals                                                             */

static void sig_cb(struct uloop_fd *u, unsigned int events)
{
	struct signalfd_siginfo si;

	(void)events;
	while (read(u->fd, &si, sizeof(si)) == (ssize_t)sizeof(si)) {
		if (si.ssi_signo == SIGHUP) {
			LOGI("SIGHUP: reloading the configuration");
			do_reload();
		} else {
			LOGI("signal %u: shutting down", si.ssi_signo);
			begin_stop(true);
		}
	}
}

static int setup_signals(void)
{
	sigset_t set;
	int fd;

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	sigprocmask(SIG_BLOCK, &set, NULL);	/* before uloop_run installs its own handlers: these stay ours */
	fd = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
	if (fd < 0)
		return -1;
	D.sigfd.fd = fd;
	D.sigfd.cb = sig_cb;
	return uloop_fd_add(&D.sigfd, ULOOP_READ);
}

/* ------------------------------------------------------------------ */
/* ubus object imsd                                                    */

static const char *source_name(enum pcscf_source s)
{
	return s == PCSCF_NETWORK ? "network" : s == PCSCF_STATIC ? "static" : "none";
}

struct lan_status_ctx {
	struct blob_buf *b;
};

static void lan_binding_row(const struct lan_binding_status *s, void *arg)
{
	struct lan_status_ctx *x = arg;
	void *t = blobmsg_open_table(x->b, NULL);

	blobmsg_add_u32(x->b, "id", s->id);
	blobmsg_add_string(x->b, "aor", s->aor);
	blobmsg_add_string(x->b, "contact", s->contact);
	blobmsg_add_string(x->b, "source", s->source);
	blobmsg_add_string(x->b, "target", s->target);
	blobmsg_add_string(x->b, "user_agent", s->user_agent);
	blobmsg_add_string(x->b, "instance", s->instance);
	blobmsg_add_u32(x->b, "expires_in", s->expires_in);
	blobmsg_add_u32(x->b, "age", s->age);
	blobmsg_add_u8(x->b, "reachable", s->reachable);
	blobmsg_add_u8(x->b, "answered", s->answered);
	blobmsg_add_u8(x->b, "restored", s->restored);
	blobmsg_add_u32(x->b, "registers", (uint32_t)s->n_register);
	{
		void *fa = blobmsg_open_array(x->b, "features");

		if (s->features & REG_F_MMS)
			blobmsg_add_string(x->b, NULL, "mms");
		if (s->features & REG_F_CARBONS)
			blobmsg_add_string(x->b, NULL, "carbons");
		blobmsg_close_array(x->b, fa);
	}
	blobmsg_close_table(x->b, t);
}

static void add_lan_status(struct blob_buf *b)
{
	struct core_lan_info li;
	struct lan_stats st;
	struct lan_status_ctx x = { b };
	void *t, *a, *c;
	char ah[64] = "";

	core_lan_info(D.core, &li);
	t = blobmsg_open_table(b, "lan");
	blobmsg_add_string(b, "state", li.state);
	blobmsg_add_string(b, "reason", li.reason);
	blobmsg_add_string(b, "ifname", li.ifname);
	if (li.up)
		addr_host(&li.addr, ah, sizeof(ah));
	blobmsg_add_string(b, "address", ah);
	blobmsg_add_u32(b, "port", li.up ? addr_port(&li.addr) : 0);
	blobmsg_add_u8(b, "listening", li.up);
	if (core_lan(D.core)) {
		lan_status(core_lan(D.core), &st, NULL, NULL);
		blobmsg_add_u32(b, "bindings_count", st.bindings);
		a = blobmsg_open_array(b, "bindings");
		lan_status(core_lan(D.core), NULL, lan_binding_row, &x);
		blobmsg_close_array(b, a);
		c = blobmsg_open_table(b, "counters");
		blobmsg_add_u32(b, "requests", (uint32_t)st.rx_requests);
		blobmsg_add_u32(b, "registers", (uint32_t)st.rx_register);
		blobmsg_add_u32(b, "register_ok", (uint32_t)st.reg.ok);
		blobmsg_add_u32(b, "register_rejected", (uint32_t)(st.reg.rejected_423 + st.reg.rejected_503 +
								      st.reg.rejected_400 + st.reg.rejected_500));
		blobmsg_add_u32(b, "options", (uint32_t)st.rx_options);
		blobmsg_add_u32(b, "invites", (uint32_t)st.rx_invite);
		blobmsg_add_u32(b, "messages", (uint32_t)st.rx_message);
		blobmsg_add_u32(b, "unregistered_sources", (uint32_t)st.rx_unregistered);
		blobmsg_add_u32(b, "bindings_added", (uint32_t)st.reg.added);
		blobmsg_add_u32(b, "bindings_removed", (uint32_t)st.reg.removed);
		blobmsg_add_u32(b, "bindings_expired", (uint32_t)st.reg.expired);
		blobmsg_add_u32(b, "forks_active", (uint32_t)st.forks_active);
		blobmsg_close_table(b, c);
	}
	blobmsg_close_table(b, t);
}

static void add_media_status(struct blob_buf *b)
{
	void *t = blobmsg_open_table(b, "media");

	blobmsg_add_u8(b, "engine_running", bridge_engine_running());
	blobmsg_add_u32(b, "bridges_active", (uint32_t)bridge_count());
	blobmsg_close_table(b, t);
}

/* ---- calls ---- */

static void add_call_row(struct blob_buf *b, const struct b2b_info *i)
{
	void *t = blobmsg_open_table(b, NULL), *l;
	int k;

	blobmsg_add_u32(b, "id", i->id);
	blobmsg_add_string(b, "direction", i->dir);
	blobmsg_add_string(b, "state", i->state);
	blobmsg_add_string(b, "carrier", i->carrier_name);
	blobmsg_add_string(b, "number", i->number);
	blobmsg_add_u8(b, "bench", i->bench);
	blobmsg_add_string(b, "carrier_codec", i->carrier_codec);
	blobmsg_add_string(b, "client_codec", i->client_codec);
	blobmsg_add_u32(b, "age_s", (uint32_t)(i->age_ms / 1000));
	blobmsg_add_u32(b, "duration_s", (uint32_t)(i->talk_ms / 1000));
	if (i->bridge) {
		for (k = 0; k < 2; k++) {
			const struct bridge_leg_stats *s = &i->stats.leg[k];

			l = blobmsg_open_table(b, k == BR_CARRIER ? "carrier_leg" : "client_leg");
			blobmsg_add_u64(b, "rx_packets", s->rx_pkts);
			blobmsg_add_u64(b, "tx_packets", s->tx_pkts);
			blobmsg_add_u32(b, "rx_lost", s->rx_lost);
			blobmsg_add_u32(b, "rx_dropped", s->rx_dropped);
			blobmsg_add_u32(b, "tx_errors", s->tx_err);
			blobmsg_close_table(b, l);
		}
	}
	blobmsg_close_table(b, t);
}

static void add_calls_list(struct blob_buf *b, const char *name)
{
	struct b2b_info rows[16];
	int n = b2b_list(rows, 16), i;
	void *a = blobmsg_open_array(b, name);

	for (i = 0; i < n && i < 16; i++)
		add_call_row(b, &rows[i]);
	blobmsg_close_array(b, a);
}

static void add_calls_status(struct blob_buf *b)
{
	struct b2b_counters c;
	void *t;

	if (!b2b_running())
		return;
	b2b_get_counters(&c);
	t = blobmsg_open_table(b, "calls");
	blobmsg_add_u32(b, "active", c.active);
	blobmsg_add_u32(b, "outgoing", (uint32_t)c.out_total);
	blobmsg_add_u32(b, "incoming", (uint32_t)c.in_total);
	blobmsg_add_u32(b, "answered", (uint32_t)c.answered);
	blobmsg_add_u32(b, "failed", (uint32_t)c.failed);
	blobmsg_add_u32(b, "missed", (uint32_t)c.missed);
	blobmsg_add_u32(b, "rejected_no_device", (uint32_t)c.no_device);
	blobmsg_add_u32(b, "rtp_timeouts", (uint32_t)c.rtp_timeouts);
	add_calls_list(b, "list");
	blobmsg_close_table(b, t);
}

static const char *backend_state_text(void)
{
	switch (D.ims_phase) {
	case IMS_DEREG: return "stopping IMS (de-registering)";
	case IMS_RELEASING: return "stopping IMS (releasing the bearer)";
	default: return "IMS not in use";
	}
}

static void add_backend_status(struct blob_buf *b)
{
	void *t = blobmsg_open_table(b, "backend");

	blobmsg_add_string(b, "mode", backend_mode_name(D.bkc.mode));
	blobmsg_add_string(b, "active", backend_name(D.bk.backend));
	blobmsg_add_string(b, "reason", D.bk.reason ? D.bk.reason : "");
	blobmsg_close_table(b, t);
}

/* the circuit switched line, its call and the PCM path of the call that uses it */
static void add_cs_status(struct blob_buf *b)
{
	const struct csline_status *ls;
	struct cscall_status cs;
	struct b2b_info rows[16];
	struct cs_pcm_stats ps;
	void *t, *c;
	int n, i;
	bool have = false;

	if (!D.cs_line || !D.cs_mgr)
		return;
	ls = csline_status(D.cs_line);
	t = blobmsg_open_table(b, "cs");
	blobmsg_add_u8(b, "usable", ls->voice_ok);
	blobmsg_add_u8(b, "sms_usable", ls->sms_ok);
	blobmsg_add_string(b, "reason", ls->reason);
	blobmsg_add_string(b, "rat", csline_rat_name(ls->rat));
	blobmsg_add_string(b, "reg_state", ls->reg_state);
	blobmsg_add_string(b, "operator_code", ls->operator_code);
	blobmsg_add_string(b, "operator_name", ls->operator_name);
	blobmsg_add_string(b, "own_number", ls->own_number);
	blobmsg_add_string(b, "modem", ls->modem);
	blobmsg_add_string(b, "modem_state", ls->modem_state);
	blobmsg_add_u8(b, "roaming", ls->roaming);
	cscall_mgr_status(D.cs_mgr, &cs);
	c = blobmsg_open_table(b, "call");
	blobmsg_add_u32(b, "live", cs.live);
	blobmsg_add_u32(b, "active_id", cs.active_id);
	blobmsg_add_u32(b, "waiting", cs.waiting);
	blobmsg_add_string(b, "waiting_number", cs.waiting_number);
	blobmsg_add_u32(b, "foreign", cs.foreign);
	blobmsg_add_u32(b, "mo", (uint32_t)cs.mo);
	blobmsg_add_u32(b, "mt", (uint32_t)cs.mt);
	blobmsg_add_u32(b, "answered", (uint32_t)cs.answered);
	blobmsg_add_u32(b, "failed", (uint32_t)cs.failed);
	blobmsg_add_u32(b, "busy_refused", (uint32_t)cs.busy_refused);
	blobmsg_add_u32(b, "waiting_total", (uint32_t)cs.waiting_total);
	blobmsg_add_u32(b, "dtmf_sent", (uint32_t)cs.dtmf_sent);
	blobmsg_add_u32(b, "dtmf_dropped", (uint32_t)cs.dtmf_dropped);
	blobmsg_add_u32(b, "lost_modem", (uint32_t)cs.lost_modem);
	blobmsg_add_u32(b, "glare", (uint32_t)cs.glare);
	blobmsg_add_string(b, "last_end", cs.last_end);
	blobmsg_close_table(b, c);
	if (D.cs_sms) {
		struct cssms_status ss;
		struct smsrelay_status rs;

		cssms_get_status(D.cs_sms, &ss);
		memset(&rs, 0, sizeof(rs));
		smsrelay_mod_status(&rs);
		c = blobmsg_open_table(b, "sms");
		blobmsg_add_u8(b, "usable", ls->sms_ok);
		blobmsg_add_u8(b, "drained", ss.drained);
		blobmsg_add_u32(b, "work_len", ss.work_len);
		blobmsg_add_u32(b, "incomplete", ss.incomplete);
		blobmsg_add_u32(b, "mo_queue", ss.mo_queue);
		blobmsg_add_u32(b, "rx_text", (uint32_t)ss.rx_text);
		blobmsg_add_u32(b, "rx_data", (uint32_t)ss.rx_data);
		blobmsg_add_u32(b, "rx_reports", (uint32_t)ss.rx_reports);
		blobmsg_add_u32(b, "rx_backlog", (uint32_t)ss.rx_backlog);
		blobmsg_add_u32(b, "rx_deferred", (uint32_t)rs.cs_rx_deferred);
		blobmsg_add_u32(b, "rx_kept", (uint32_t)ss.rx_kept);
		blobmsg_add_u32(b, "rx_dropped_incomplete", (uint32_t)ss.rx_dropped_incomplete);
		blobmsg_add_u32(b, "rx_deleted", (uint32_t)ss.rx_deleted);
		blobmsg_add_u32(b, "rx_delete_failed", (uint32_t)ss.rx_delete_failed);
		blobmsg_add_u32(b, "rx_overflow", (uint32_t)ss.rx_overflow);
		blobmsg_add_u32(b, "mo_ok", (uint32_t)ss.mo_ok);
		blobmsg_add_u32(b, "mo_failed", (uint32_t)ss.mo_failed);
		blobmsg_add_u32(b, "mms_notifications_unhandled", (uint32_t)rs.cs_mms_unhandled);
		blobmsg_add_string(b, "last_error", ss.last_error);
		blobmsg_close_table(b, c);
	}
	n = b2b_list(rows, 16);
	memset(&ps, 0, sizeof(ps));
	for (i = 0; i < n && i < 16; i++) {
		if (!strcmp(rows[i].carrier_name, "cs") && rows[i].bridge) {
			cs_media_stats(&rows[i].stats, &ps);
			have = true;
			break;
		}
	}
	c = blobmsg_open_table(b, "pcm");
	blobmsg_add_u8(b, "active", have);
	blobmsg_add_string(b, "device", D.cfg.cs_pcm_device[0] ? D.cfg.cs_pcm_device : "auto");
	blobmsg_add_u32(b, "rx_periods", (uint32_t)ps.rx_periods);
	blobmsg_add_u32(b, "tx_periods", (uint32_t)ps.tx_periods);
	blobmsg_add_u32(b, "xrun_rx", ps.xrun_rx);
	blobmsg_add_u32(b, "xrun_tx", ps.xrun_tx);
	blobmsg_add_u32(b, "ul_drop", ps.ul_drop);
	blobmsg_add_u32(b, "ul_fill", ps.ul_fill);
	blobmsg_add_u32(b, "ul_idle", ps.ul_idle);
	blobmsg_add_u32(b, "ul_full", ps.ul_full);
	blobmsg_add_u32(b, "errors", ps.errors);
	blobmsg_add_u32(b, "ul_depth", ps.ul_depth);
	blobmsg_add_u8(b, "lost", ps.lost);
	blobmsg_close_table(b, c);
	blobmsg_close_table(b, t);
}

static void add_sms_status(struct blob_buf *b)
{
	struct smsrelay_status s;
	void *t;

	if (!smsrelay_mod_status(&s))
		return;
	t = blobmsg_open_table(b, "sms");
	blobmsg_add_u32(b, "received", (uint32_t)s.mt_received);
	blobmsg_add_u32(b, "stored", (uint32_t)s.mt_stored);
	blobmsg_add_u32(b, "store_fallback", (uint32_t)s.mt_store_fallback);
	blobmsg_add_u32(b, "delivered_live", (uint32_t)s.mt_delivered);
	blobmsg_add_u32(b, "delivered", (uint32_t)s.mt_delivered);
	blobmsg_add_u32(b, "lost_no_client", (uint32_t)s.mt_lost_no_client);
	blobmsg_add_u32(b, "lost_failed", (uint32_t)s.mt_lost_failed);
	blobmsg_add_u32(b, "duplicates", (uint32_t)s.mt_duplicates);
	blobmsg_add_u32(b, "status_reports", (uint32_t)s.mt_reports);
	blobmsg_add_u32(b, "errors", (uint32_t)s.mt_errors);
	blobmsg_add_u32(b, "sent", (uint32_t)s.mo_submitted);
	blobmsg_add_u32(b, "sent_acked", (uint32_t)s.mo_acked);
	blobmsg_add_u32(b, "sent_failed", (uint32_t)s.mo_failed);
	blobmsg_add_u32(b, "queue", s.mo_queue_len);
	blobmsg_add_u32(b, "carbons_sent", (uint32_t)s.carbons_sent);
	blobmsg_add_u32(b, "carbons_failed", (uint32_t)s.carbons_failed);
	blobmsg_add_u32(b, "carbons_stored", (uint32_t)s.carbons_stored);
	blobmsg_add_string(b, "smsc", s.smsc);
	blobmsg_add_string(b, "smsc_source", s.smsc_source);
	blobmsg_add_string(b, "sms_psi", s.sms_psi);
	blobmsg_add_string(b, "sms_psi_source", s.sms_psi_source);
	blobmsg_add_string(b, "last_error", s.last_error);
	blobmsg_close_table(b, t);
}

static void add_mms_status(struct blob_buf *b)
{
	struct mms_status s;
	void *t;

	if (!mms_mod_status(&s))
		return;
	t = blobmsg_open_table(b, "mms");
	blobmsg_add_u32(b, "notifications", (uint32_t)s.notifications);
	blobmsg_add_u32(b, "retrieved", (uint32_t)s.retrieved);
	blobmsg_add_u32(b, "stored", (uint32_t)s.stored);
	blobmsg_add_u32(b, "store_fallback", (uint32_t)s.store_fallback);
	blobmsg_add_u32(b, "failed_stored", (uint32_t)s.failed_stored);
	blobmsg_add_u32(b, "delivered", (uint32_t)s.delivered);
	blobmsg_add_u32(b, "failed", (uint32_t)s.failed);
	blobmsg_add_u32(b, "lost_no_client", (uint32_t)s.lost_no_client);
	blobmsg_add_u32(b, "rejected", (uint32_t)s.rejected);
	blobmsg_add_u32(b, "duplicates", (uint32_t)s.duplicates);
	blobmsg_add_u32(b, "acked", (uint32_t)s.acked);
	blobmsg_add_u32(b, "ack_failed", (uint32_t)s.ack_failed);
	blobmsg_add_u32(b, "pending", s.pending);
	blobmsg_add_string(b, "mmsc", s.mmsc);
	blobmsg_add_string(b, "mmsc_source", s.mmsc_source);
	blobmsg_add_string(b, "operator", s.operator_name);
	blobmsg_add_string(b, "operator_match", s.operator_match);
	blobmsg_add_u8(b, "operator_tested", s.entry_tested);
	blobmsg_add_string(b, "apn", s.apn);
	blobmsg_add_string(b, "proxy", s.proxy);
	blobmsg_add_string(b, "user_agent", s.user_agent);
	blobmsg_add_string(b, "provider", s.on_demand ? "bearer" : "ims");
	blobmsg_add_string(b, "link_reason", s.link_reason);
	{
		struct mmsb_status bs;

		if (mms_mod_bearer_status(&bs)) {
			void *bt = blobmsg_open_table(b, "bearer"), *gt;

			blobmsg_add_string(b, "state", bs.state);
			blobmsg_add_string(b, "reason", bs.reason);
			blobmsg_add_string(b, "netdev", bs.netdev);
			blobmsg_add_string(b, "address", bs.address);
			blobmsg_add_u8(b, "want", bs.want);
			blobmsg_add_u32(b, "connects", (uint32_t)bs.connects);
			blobmsg_add_u32(b, "failures", (uint32_t)bs.failures);
			blobmsg_add_u32(b, "blocked", (uint32_t)bs.scans_blocked);
			blobmsg_add_string(b, "last_error", bs.last_error);
			blobmsg_close_table(b, bt);
			gt = blobmsg_open_table(b, "guard");
			blobmsg_add_u8(b, "installed", bs.guard.installed);
			blobmsg_add_u8(b, "armed", bs.guard.armed);
			blobmsg_add_u32(b, "accepted", (uint32_t)bs.guard.accepted);
			blobmsg_add_u32(b, "dropped", (uint32_t)bs.guard.dropped);
			blobmsg_add_u32(b, "failures", (uint32_t)bs.guard.failures);
			blobmsg_add_string(b, "last_error", bs.guard.last_error);
			blobmsg_close_table(b, gt);
		}
	}
	blobmsg_add_u32(b, "stored_messages", s.store_messages);
	blobmsg_add_u32(b, "stored_bytes", (uint32_t)s.store_bytes);
	blobmsg_add_string(b, "last_error", s.last_error);
	blobmsg_add_u32(b, "raw_delivered", (uint32_t)s.raw_delivered);
	blobmsg_add_u32(b, "raw_lost", (uint32_t)s.raw_lost);
	blobmsg_add_u32(b, "proxy_acks", (uint32_t)s.proxy_acks);
	{
		struct mmsproxy_status ps;

		if (mms_mod_proxy_status(&ps)) {
			void *pt = blobmsg_open_table(b, "proxy");

			blobmsg_add_u8(b, "listening", ps.listening);
			blobmsg_add_string(b, "address", ps.address);
			blobmsg_add_u32(b, "port", ps.port);
			blobmsg_add_u32(b, "connections", ps.conns);
			blobmsg_add_u32(b, "relayed_sends", (uint32_t)ps.relayed_sends);
			blobmsg_add_u32(b, "send_failures", (uint32_t)ps.send_failures);
			blobmsg_add_u32(b, "send_repeats", (uint32_t)ps.send_repeats);
			blobmsg_add_u32(b, "fetches", (uint32_t)ps.fetches);
			blobmsg_add_u32(b, "fetch_failures", (uint32_t)ps.fetch_failures);
			blobmsg_add_u32(b, "cache_hits", (uint32_t)ps.cache_hits);
			blobmsg_add_u32(b, "cache_entries", ps.cache_entries);
			blobmsg_add_u32(b, "denied", (uint32_t)ps.denied);
			blobmsg_add_u32(b, "carbons_sent", (uint32_t)ps.carbons_sent);
			blobmsg_add_u32(b, "carbons_failed", (uint32_t)ps.carbons_failed);
			blobmsg_add_u32(b, "carbons_stored", (uint32_t)ps.carbons_stored);
			blobmsg_add_u32(b, "store_hits", (uint32_t)ps.store_hits);
			blobmsg_add_string(b, "error", ps.error);
			blobmsg_close_table(b, pt);
		}
	}
	blobmsg_close_table(b, t);
}

static void add_store_status(struct blob_buf *b)
{
	static struct store_status s;	/* not on the stack: 32 device rows */
	void *t, *arr;
	unsigned i;

	t = blobmsg_open_table(b, "store");
	if (!store_mod_status(&s)) {
		blobmsg_add_u8(b, "enabled", 0);
		blobmsg_close_table(b, t);
		return;
	}
	blobmsg_add_u8(b, "enabled", 1);
	blobmsg_add_string(b, "dir", s.dir);
	blobmsg_add_u8(b, "ready", s.ready);
	blobmsg_add_u8(b, "healthy", s.healthy);
	blobmsg_add_string(b, "error", s.error);
	blobmsg_add_u32(b, "items", s.items);
	blobmsg_add_u64(b, "bytes", s.bytes);
	blobmsg_add_u64(b, "first_seq", s.first_seq);
	blobmsg_add_u64(b, "head_seq", s.head_seq);
	blobmsg_add_u32(b, "added", (uint32_t)s.added);
	blobmsg_add_u32(b, "evicted", (uint32_t)s.evicted);
	blobmsg_add_u32(b, "torn_records", (uint32_t)s.torn_records);
	blobmsg_add_u32(b, "dropped", (uint32_t)s.dropped);
	blobmsg_add_u32(b, "add_failed", (uint32_t)s.add_failed);
	blobmsg_add_u32(b, "add_abandoned", (uint32_t)s.add_abandoned);
	blobmsg_add_u32(b, "delivered", (uint32_t)s.delivered);
	blobmsg_add_u32(b, "delivery_failures", (uint32_t)s.delivery_failures);
	blobmsg_add_u32(b, "read_errors", (uint32_t)s.read_errors);
	blobmsg_add_u32(b, "bodies_missing", (uint32_t)s.bodies_missing);
	blobmsg_add_u32(b, "compactions", (uint32_t)s.compactions);
	blobmsg_add_u32(b, "io_errors", (uint32_t)s.io_errors);
	blobmsg_add_u64(b, "log_bytes", s.log_bytes);
	arr = blobmsg_open_array(b, "devices");
	for (i = 0; i < s.ndev; i++) {
		void *d = blobmsg_open_table(b, NULL);

		blobmsg_add_string(b, "id", s.dev[i].id);
		blobmsg_add_u8(b, "registered", s.dev[i].registered);
		blobmsg_add_u64(b, "cursor", s.dev[i].cursor);
		if (s.dev[i].uses_ack)
			blobmsg_add_u64(b, "reported_cursor", s.dev[i].reported);
		blobmsg_add_u64(b, "lag", s.dev[i].lag);
		blobmsg_add_u32(b, "last_seen_s", s.dev[i].last_seen_s < 0 ? 0 : (uint32_t)s.dev[i].last_seen_s);
		blobmsg_add_u32(b, "delivered", (uint32_t)s.dev[i].delivered);
		blobmsg_add_u32(b, "missed", (uint32_t)s.dev[i].missed);
		blobmsg_add_u32(b, "failures", (uint32_t)s.dev[i].failures);
		blobmsg_close_table(b, d);
	}
	blobmsg_close_array(b, arr);
	blobmsg_close_table(b, t);
}

static int status_cb(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		     const char *method, struct blob_attr *msg)
{
	struct blob_buf *b = &D.bb;
	struct reg_status st;
	void *a, *t;
	char ah[64] = "";

	(void)obj; (void)method; (void)msg;
	blob_buf_init(b, 0);
	blobmsg_add_string(b, "version", IMSD_VERSION);
	blobmsg_add_u8(b, "enabled", D.cfg.enabled);
	if (!D.reg) {
		blobmsg_add_string(b, "state", "disabled");
		blobmsg_add_string(b, "reason", D.cfg.enabled ? "starting" : "disabled by configuration (imsd.main.enabled=0)");
		blobmsg_add_u8(b, "registered", false);
	} else if (!D.modem) {
		blobmsg_add_string(b, "state", "ims-off");
		blobmsg_add_string(b, "reason", backend_state_text());
		blobmsg_add_u8(b, "registered", false);
	} else {
		const struct ims_link *l = imsmodem_link(D.modem);

		reg_get_status(D.reg, &st);
		blobmsg_add_string(b, "state", st.state_name);
		blobmsg_add_string(b, "reason", st.reason);
		blobmsg_add_u8(b, "registered", st.registered);
		blobmsg_add_string(b, "impu", st.impu);
		blobmsg_add_string(b, "impi", st.impi);
		blobmsg_add_string(b, "domain", st.domain);
		blobmsg_add_string(b, "assoc_uri", st.assoc_uri);
		t = blobmsg_open_table(b, "pcscf");
		blobmsg_add_string(b, "address", st.pcscf);
		blobmsg_add_u32(b, "port_s", st.pcscf_port_s);
		blobmsg_add_string(b, "source", source_name(st.pcscf_source));
		blobmsg_close_table(b, t);
		t = blobmsg_open_table(b, "bearer");
		blobmsg_add_string(b, "path", l->br.path);
		blobmsg_add_string(b, "interface", l->br.ifname);
		if (l->br.ifname[0])
			addr_host(&l->br.local, ah, sizeof(ah));
		blobmsg_add_string(b, "address", ah);
		blobmsg_add_u32(b, "prefix", l->br.prefix);
		blobmsg_add_u32(b, "mtu", l->br.mtu);
		blobmsg_close_table(b, t);
		blobmsg_add_u32(b, "expires_in", st.expires_in_s < 0 ? 0 : (uint32_t)st.expires_in_s);
		blobmsg_add_u32(b, "registered_since", st.registered_since_s < 0 ? 0 : (uint32_t)st.registered_since_s);
		t = blobmsg_open_table(b, "protected_ports");
		blobmsg_add_u32(b, "port_c", st.port_c);
		blobmsg_add_u32(b, "port_s", st.port_s);
		blobmsg_close_table(b, t);
		blobmsg_add_string(b, "last_error", st.last_error[0] ? st.last_error : imsmodem_last_error(D.modem));
		t = blobmsg_open_table(b, "counters");
		blobmsg_add_u32(b, "register_attempts", st.attempts);
		blobmsg_add_u32(b, "register_successes", st.successes);
		blobmsg_add_u32(b, "auth_failures", st.auth_failures);
		blobmsg_add_u32(b, "failures", st.failures);
		blobmsg_add_u32(b, "refreshes", st.refreshes);
		blobmsg_add_u32(b, "reauths", st.reauths);
		blobmsg_add_u32(b, "sms_received", st.sms_received);
		blobmsg_close_table(b, t);
		t = blobmsg_open_table(b, "modem");
		blobmsg_add_string(b, "state", imsmodem_state_name(D.modem));
		blobmsg_add_string(b, "reason", imsmodem_reason(D.modem));
		blobmsg_add_string(b, "object", imsmodem_modem_path(D.modem));
		blobmsg_add_string(b, "modem_state", imsmodem_modem_state(D.modem));
		blobmsg_add_u8(b, "modem_ims_active", imsmodem_ims_active(D.modem));
		blobmsg_add_string(b, "last_error", imsmodem_last_error(D.modem));
		blobmsg_add_string(b, "smsc", imsmodem_smsc(D.modem));
		blobmsg_add_string(b, "sms_psi_card", imsmodem_sms_psi(D.modem));
		blobmsg_add_string(b, "cell", imsmodem_cell_info(D.modem));
		{
			const struct carrier *co = carrier_find(imsmodem_imsi(D.modem));

			blobmsg_add_string(b, "operator", co ? co->name : "");	/* built-in operator table entry, "" = unknown operator */
		}
		blobmsg_close_table(b, t);
		t = blobmsg_open_table(b, "access_network");
		blobmsg_add_string(b, "pani", st.pani);
		blobmsg_add_string(b, "source", reg_pani_source_name(st.pani_source));
		blobmsg_close_table(b, t);
	}
	if (D.reg)
		add_backend_status(b);
	add_cs_status(b);
	add_lan_status(b);
	add_calls_status(b);
	add_sms_status(b);
	add_mms_status(b);
	add_store_status(b);
	add_media_status(b);
	a = blobmsg_open_array(b, "unsupported");
	blobmsg_add_string(b, NULL, "emergency-calls");
	blobmsg_close_array(b, a);
	ubus_send_reply(ctx, req, b->head);
	return 0;
}

static int register_cb(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		       const char *method, struct blob_attr *msg)
{
	(void)ctx; (void)obj; (void)req; (void)method; (void)msg;
	if (!D.reg || !D.modem)		/* no IMS side while the backend is circuit switched */
		return UBUS_STATUS_NOT_SUPPORTED;
	reg_set_enabled(D.reg, true);
	return 0;
}

static int deregister_cb(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
			 const char *method, struct blob_attr *msg)
{
	(void)ctx; (void)obj; (void)req; (void)method; (void)msg;
	if (!D.reg || !D.modem)
		return UBUS_STATUS_NOT_SUPPORTED;
	reg_set_enabled(D.reg, false);
	return 0;
}

static int reload_cb(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		     const char *method, struct blob_attr *msg)
{
	(void)ctx; (void)obj; (void)req; (void)method; (void)msg;
	do_reload();
	return 0;
}

static int lan_flush_cb(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
			const char *method, struct blob_attr *msg)
{
	(void)ctx; (void)obj; (void)req; (void)method; (void)msg;
	if (!core_lan(D.core))
		return UBUS_STATUS_NOT_SUPPORTED;
	LOGI("lan: all bindings dropped (ubus lan_flush)");
	reg_flush(lan_registrar(core_lan(D.core)));
	return 0;
}

static int err_reply(struct ubus_context *ctx, struct ubus_request_data *req, int rc)
{
	struct blob_buf *b = &D.bb;

	blob_buf_init(b, 0);
	blobmsg_add_string(b, "error", strerror(-rc));
	ubus_send_reply(ctx, req, b->head);
	return rc == -ENOENT ? UBUS_STATUS_NOT_FOUND : rc == -EINVAL || rc == -ENAMETOOLONG ? UBUS_STATUS_INVALID_ARGUMENT :
	       UBUS_STATUS_UNKNOWN_ERROR;
}

enum { CD_NUMBER, CD_PLAY, CD_RECORD, CD_RATE, __CD_MAX };
static const struct blobmsg_policy call_dial_policy[__CD_MAX] = {
	[CD_NUMBER] = { "number", BLOBMSG_TYPE_STRING },
	[CD_PLAY] = { "play", BLOBMSG_TYPE_STRING },
	[CD_RECORD] = { "record", BLOBMSG_TYPE_STRING },
	[CD_RATE] = { "rate", BLOBMSG_TYPE_INT32 },
};

static int call_dial_cb(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
			const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__CD_MAX];
	unsigned id = 0;
	int rc;

	(void)obj; (void)method;
	blobmsg_parse(call_dial_policy, __CD_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[CD_NUMBER])
		return UBUS_STATUS_INVALID_ARGUMENT;
	rc = b2b_bench_dial(blobmsg_get_string(tb[CD_NUMBER]), tb[CD_PLAY] ? blobmsg_get_string(tb[CD_PLAY]) : "",
			    tb[CD_RECORD] ? blobmsg_get_string(tb[CD_RECORD]) : "", tb[CD_RATE] ? blobmsg_get_u32(tb[CD_RATE]) : 0,
			    &id);
	if (rc)
		return err_reply(ctx, req, rc);
	blob_buf_init(&D.bb, 0);
	blobmsg_add_u32(&D.bb, "id", id);
	ubus_send_reply(ctx, req, D.bb.head);
	return 0;
}

enum { SL_FROM, SL_LIMIT, __SL_MAX };
static const struct blobmsg_policy store_list_policy[__SL_MAX] = {
	[SL_FROM] = { "from", BLOBMSG_TYPE_INT64 },
	[SL_LIMIT] = { "limit", BLOBMSG_TYPE_INT32 },
};

/* the index of the store, without payloads: seq, type, peer, time, size */
static int store_list_cb(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg)
{
	struct blob_attr *tb[__SL_MAX];
	struct store_info *li;
	uint64_t from = 0;
	unsigned limit = 50, n, i;
	void *arr;

	(void)obj; (void)method;
	blobmsg_parse(store_list_policy, __SL_MAX, tb, blob_data(msg), blob_len(msg));
	if (tb[SL_FROM])
		from = blobmsg_get_u64(tb[SL_FROM]);
	if (tb[SL_LIMIT])
		limit = blobmsg_get_u32(tb[SL_LIMIT]);
	if (limit < 1 || limit > 500)
		limit = 500;
	if (!store_mod_get())
		return UBUS_STATUS_NOT_FOUND;
	li = calloc(limit, sizeof(*li));
	if (!li)
		return UBUS_STATUS_UNKNOWN_ERROR;
	n = store_list(store_mod_get(), from, li, limit);
	blob_buf_init(&D.bb, 0);
	arr = blobmsg_open_array(&D.bb, "items");
	for (i = 0; i < n; i++) {
		void *t = blobmsg_open_table(&D.bb, NULL);
		const char *type = li[i].type == STORE_SMS ? "sms" : li[i].type == STORE_MMS ? "mms" :
				   li[i].type == STORE_CARBON_SMS ? "carbon_sms" : "carbon_mms";

		blobmsg_add_u64(&D.bb, "seq", li[i].seq);
		blobmsg_add_string(&D.bb, "type", type);
		blobmsg_add_string(&D.bb, "peer", li[i].peer);
		blobmsg_add_u64(&D.bb, "time", (uint64_t)li[i].time);
		blobmsg_add_u32(&D.bb, "size", li[i].size);
		blobmsg_add_u8(&D.bb, "durable", li[i].durable);
		blobmsg_close_table(&D.bb, t);
	}
	blobmsg_close_array(&D.bb, arr);
	ubus_send_reply(ctx, req, D.bb.head);
	free(li);
	return 0;
}

enum { SP_BEFORE, SP_ALL, __SP_MAX };
static const struct blobmsg_policy store_purge_policy[__SP_MAX] = {
	[SP_BEFORE] = { "before_seq", BLOBMSG_TYPE_INT64 },
	[SP_ALL] = { "all", BLOBMSG_TYPE_BOOL },
};

/* administration / tests: remove every item below before_seq, or all of them */
static int store_purge_cb(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	struct blob_attr *tb[__SP_MAX];
	unsigned n;
	bool all;

	(void)obj; (void)method;
	blobmsg_parse(store_purge_policy, __SP_MAX, tb, blob_data(msg), blob_len(msg));
	all = tb[SP_ALL] && blobmsg_get_bool(tb[SP_ALL]);
	if (!all && !tb[SP_BEFORE])
		return UBUS_STATUS_INVALID_ARGUMENT;
	if (!store_mod_get())
		return UBUS_STATUS_NOT_FOUND;
	n = store_purge(store_mod_get(), all ? 0 : blobmsg_get_u64(tb[SP_BEFORE]), all);
	blob_buf_init(&D.bb, 0);
	blobmsg_add_u32(&D.bb, "removed", n);
	ubus_send_reply(ctx, req, D.bb.head);
	return 0;
}

enum { MF_URL, MF_FROM, MF_SUBJECT, __MF_MAX };
static const struct blobmsg_policy mms_fetch_policy[__MF_MAX] = {
	[MF_URL] = { "url", BLOBMSG_TYPE_STRING },
	[MF_FROM] = { "from", BLOBMSG_TYPE_STRING },
	[MF_SUBJECT] = { "subject", BLOBMSG_TYPE_STRING },
};

/* bench: fetch the MMS at a Content-Location as if a notification had announced it (the result is logged and delivered) */
static int mms_fetch_cb(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
			const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__MF_MAX];
	int rc;

	(void)obj; (void)method;
	blobmsg_parse(mms_fetch_policy, __MF_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[MF_URL])
		return UBUS_STATUS_INVALID_ARGUMENT;
	rc = mms_mod_fetch(blobmsg_get_string(tb[MF_URL]), tb[MF_FROM] ? blobmsg_get_string(tb[MF_FROM]) : "",
			   tb[MF_SUBJECT] ? blobmsg_get_string(tb[MF_SUBJECT]) : "");
	if (rc)
		return err_reply(ctx, req, rc);
	blob_buf_init(&D.bb, 0);
	blobmsg_add_string(&D.bb, "queued", blobmsg_get_string(tb[MF_URL]));
	ubus_send_reply(ctx, req, D.bb.head);
	return 0;
}

enum { CH_ID, CH_PLAY, CH_RECORD, CH_RATE, CH_STATUS, __CH_MAX };
static const struct blobmsg_policy call_id_policy[__CH_MAX] = {
	[CH_ID] = { "id", BLOBMSG_TYPE_INT32 },
	[CH_PLAY] = { "play", BLOBMSG_TYPE_STRING },
	[CH_RECORD] = { "record", BLOBMSG_TYPE_STRING },
	[CH_RATE] = { "rate", BLOBMSG_TYPE_INT32 },
	[CH_STATUS] = { "status", BLOBMSG_TYPE_INT32 },
};

static int call_id_method(struct ubus_context *ctx, struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[__CH_MAX];
	unsigned id;
	int rc;

	blobmsg_parse(call_id_policy, __CH_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[CH_ID])
		return UBUS_STATUS_INVALID_ARGUMENT;
	id = blobmsg_get_u32(tb[CH_ID]);
	if (!strcmp(method, "call_hangup"))
		rc = b2b_call_hangup(id);
	else if (!strcmp(method, "call_reject"))
		rc = b2b_call_reject(id, tb[CH_STATUS] ? (int)blobmsg_get_u32(tb[CH_STATUS]) : 486);
	else
		rc = b2b_bench_answer(id, tb[CH_PLAY] ? blobmsg_get_string(tb[CH_PLAY]) : "",
				      tb[CH_RECORD] ? blobmsg_get_string(tb[CH_RECORD]) : "", tb[CH_RATE] ? blobmsg_get_u32(tb[CH_RATE]) : 0);
	return rc ? err_reply(ctx, req, rc) : 0;
}

static int call_id_cb(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		      const char *method, struct blob_attr *msg)
{
	(void)obj;
	return call_id_method(ctx, req, method, msg);
}

static int calls_cb(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		    const char *method, struct blob_attr *msg)
{
	(void)obj; (void)method; (void)msg;
	blob_buf_init(&D.bb, 0);
	add_calls_list(&D.bb, "calls");
	ubus_send_reply(ctx, req, D.bb.head);
	return 0;
}

static void call_notice(void *arg, const struct b2b_notice *n)
{
	struct ubus_context *ctx = &D.ubus.ctx;
	struct notify_req *r;
	struct blob_buf b = {};

	(void)arg;
	if (!D.obj.has_subscribers || !D.obj.id)
		return;
	r = calloc(1, sizeof(*r));
	if (!r)
		return;
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "id", n->id);
	blobmsg_add_string(&b, "event", n->event);
	blobmsg_add_string(&b, "direction", n->dir);
	blobmsg_add_string(&b, "number", n->number);
	if (n->status)
		blobmsg_add_u32(&b, "status", (uint32_t)n->status);
	blobmsg_add_string(&b, "reason", n->reason);
	if (ubus_notify_async(ctx, &D.obj, "call", b.head, &r->req)) {
		free(r);
	} else {
		r->req.complete_cb = notify_done;
		ubus_complete_request_async(ctx, &r->req.req);
	}
	blob_buf_free(&b);
}

static void ubus_connected(struct ubus_context *ctx)
{
	int r = ubus_add_object(ctx, &D.obj);

	if (r)
		LOGE("ubus: cannot add object imsd: %s", ubus_strerror(r));
	else
		LOGI("ubus: connected, object imsd registered");
	if (D.modem || D.reg)
		uqb_on_connect(ctx);		/* the MMS bearer calls uqmid through it also when there is no IMS side */
	if (D.cs_line)
		csub_on_connect(ctx);	/* backend=ims never touches uqmid through the CS path */
}

static void ctx_init_ubus(void)
{
	D.methods[0] = (struct ubus_method)UBUS_METHOD_NOARG("status", status_cb);
	D.methods[1] = (struct ubus_method)UBUS_METHOD_NOARG("register", register_cb);
	D.methods[2] = (struct ubus_method)UBUS_METHOD_NOARG("deregister", deregister_cb);
	D.methods[3] = (struct ubus_method)UBUS_METHOD_NOARG("reload", reload_cb);
	D.methods[4] = (struct ubus_method)UBUS_METHOD_NOARG("lan_flush", lan_flush_cb);
	D.methods[5] = (struct ubus_method)UBUS_METHOD("call_dial", call_dial_cb, call_dial_policy);
	D.methods[6] = (struct ubus_method)UBUS_METHOD("call_hangup", call_id_cb, call_id_policy);
	D.methods[7] = (struct ubus_method)UBUS_METHOD("call_answer", call_id_cb, call_id_policy);
	D.methods[8] = (struct ubus_method)UBUS_METHOD("call_reject", call_id_cb, call_id_policy);
	D.methods[9] = (struct ubus_method)UBUS_METHOD_NOARG("calls", calls_cb);
	D.methods[10] = (struct ubus_method)UBUS_METHOD("mms_fetch", mms_fetch_cb, mms_fetch_policy);
	D.methods[11] = (struct ubus_method)UBUS_METHOD("store_list", store_list_cb, store_list_policy);
	D.methods[12] = (struct ubus_method)UBUS_METHOD("store_purge", store_purge_cb, store_purge_policy);
	D.obj_type = (struct ubus_object_type)UBUS_OBJECT_TYPE("imsd", D.methods);
	D.obj.name = "imsd";
	D.obj.type = &D.obj_type;
	D.obj.methods = D.methods;
	D.obj.n_methods = ARRAY_SIZE(D.methods);
	D.ubus.cb = ubus_connected;
	D.ubus.path = NULL;
}

static void usage(const char *p)
{
	fprintf(stderr, "usage: %s [-l level] [-C confdir] [-S] [-V]\n", p);
}

int main(int argc, char **argv)
{
	int opt, to_stderr = 0;
	char err[160];

	D.level_override = -1;
	while ((opt = getopt(argc, argv, "l:C:SVh")) != -1) {
		switch (opt) {
		case 'l':
			D.level_override = imsd_log_parse_level(optarg);
			if (D.level_override < 0) {
				fprintf(stderr, "bad log level %s\n", optarg);
				return 2;
			}
			break;
		case 'C':
			D.confdir = optarg;
			break;
		case 'S':
			to_stderr = 1;
			break;
		case 'V':
			printf("imsd %s\n", IMSD_VERSION);
			return 0;
		default:
			usage(argv[0]);
			return 2;
		}
	}

	imsd_log_open("imsd", to_stderr);
	if (config_load_uci(&D.cfg, D.confdir, err, sizeof(err))) {
		LOGE("configuration: %s", err);
		return 1;
	}
	if (D.level_override >= 0)
		D.cfg.log_level = D.level_override;
	imsd_log_level(D.cfg.log_level);
	LOGI("imsd %s starting (%s)", IMSD_VERSION, D.cfg.enabled ? "enabled" : "disabled by configuration");

	uloop_init();
	{
		struct core_ops co;
		int i;

		memset(&co, 0, sizeof(co));
		co.on_binding = lan_binding_notify;
		co.lan_message_gate = lan_message_gate;
		D.core = core_new(&D.cfg, &co);
		if (!D.core) {
			LOGE("out of memory");
			return 1;
		}
		for (i = 0; modules[i]; i++) {
			int rc = core_add_module(D.core, modules[i]);

			if (rc)
				LOGE("module %s not loaded: %s", modules[i]->name, strerror(-rc));
		}
	}
	if (setup_signals())
		LOGW("cannot set up signal handling: %s", strerror(errno));
	D.exit_t.cb = exit_cb;
	D.hard_t.cb = hard_cb;
	uqb_init(&D.modem);
	csub_init(&D.cs_line);
	D.bk_t.cb = bk_cb;
	ctx_init_ubus();
	D.ubus.ctx.sock.fd = -1;
	if (D.cfg.enabled)
		svc_start();
	ubus_auto_connect(&D.ubus);
	D.lag_expected = mono_ms() + LAG_TICK_MS;
	D.lag.cb = lag_cb;
	uloop_timeout_set(&D.lag, LAG_TICK_MS);

	uloop_run();

	LOGI("imsd stopped");
	uloop_timeout_cancel(&D.lag);
	uloop_timeout_cancel(&D.exit_t);
	uloop_timeout_cancel(&D.hard_t);
	svc_free();
	core_free(D.core);
	uqb_shutdown();
	csub_shutdown();
	ubus_auto_shutdown(&D.ubus);
	blob_buf_free(&D.bb);
	uloop_done();
	return 0;
}
