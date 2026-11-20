/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The on-demand MMS data connection, see mmsbearer.h. */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "mmsbearer.h"
#include "../util/evloop.h"
#include "../util/log.h"

enum st { S_IDLE, S_GUARD, S_SCAN, S_CREATE, S_CONNECT, S_GET, S_ARM, S_UP, S_DOWN, S_BACKOFF, S_BLOCKED };
enum scan_ph { SC_GET, SC_DISC, SC_DEL };
enum down_ph { D_DISC, D_DEL, D_GUARD, D_FIN };

struct mmsb {
	struct mmsb_cfg cfg;
	struct mmsb_ops ops;
	enum st st;
	bool want, stopping, busy;
	struct mmsguard *g;
	void *h;				/* the uqmid call in flight */
	void (*jcb)(struct mmsb *b, const struct uq_res *r);
	struct ev_timer *t_job, *t_linger, *t_retry, *t_check, *t_shut, *t_ident, *t_notify;
	/* session */
	char mpath[UQ_PATH];
	struct mmsb_profile prof;
	char bpath[UQ_PATH];
	bool ours;
	char ifname[16];
	struct addr local;
	int prefix, mtu;
	struct addr dns[4];
	int n_dns;
	bool v6off, net_applied;
	struct netcfg_params net;
	/* scan */
	char known[UQ_MAX_BEARERS][UQ_PATH];
	int nknown, scan_i;
	enum scan_ph scan_ph;
	char fif[UQ_MAX_BEARERS][16];
	int nfif;
	char marker_m[UQ_PATH], marker_b[UQ_PATH];
	/* teardown */
	enum down_ph dph;
	bool down_remote, fail_after, blocked_after;
	char fail_reason[160];
	void (*shut_done)(void *);
	void *shut_arg;
	/* identity */
	char imsi[24];
	char imsi_modem[UQ_PATH];
	void *ih;
	bool ident_busy, ident_wait;
	/* status */
	unsigned seq, retry_n;
	char reason[160], last_error[96];
	bool avail;
	unsigned long connects, failures, blocked;
	bool in_step, again;
	bool linger_armed;
};

void mmsb_cfg_defaults(struct mmsb_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->linger_ms = 20000;
	c->route_table = 1007;
	c->call_timeout_ms = 15000;
	c->connect_timeout_ms = 45000;
	c->retry_min_ms = 5000;
	c->retry_max_ms = 60000;
	c->blocked_retry_ms = 30000;
	c->check_ms = 15000;
}

static void step(struct mmsb *b);
static void continue_down(struct mmsb *b);

static void set_reason(struct mmsb *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void set_reason(struct mmsb *b, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(b->reason, sizeof(b->reason), fmt, ap);
	va_end(ap);
}

static void set_error(struct mmsb *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void set_error(struct mmsb *b, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(b->last_error, sizeof(b->last_error), fmt, ap);
	va_end(ap);
}

static void linger_arm(struct mmsb *b)
{
	if (b->linger_armed)
		return;
	b->linger_armed = true;
	ev_timer_set(b->t_linger, b->cfg.linger_ms);
}

static void linger_cancel(struct mmsb *b)
{
	b->linger_armed = false;
	ev_timer_cancel(b->t_linger);
}

/* the owner is told from the loop, never from inside a call of this module */
static void changed(struct mmsb *b)
{
	b->seq++;
	ev_timer_set(b->t_notify, 0);
}

static void on_notify(void *arg)
{
	struct mmsb *b = arg;

	if (b->ops.changed)
		b->ops.changed(b->ops.ctx);
}

/* ---- the uqmid call in flight (one at a time) ---- */

static void job_done(struct mmsb *b, const struct uq_res *r)
{
	void (*cb)(struct mmsb *, const struct uq_res *) = b->jcb;

	b->h = NULL;
	b->busy = false;
	b->jcb = NULL;
	ev_timer_cancel(b->t_job);
	if (cb)
		cb(b, r);
}

static void job_cb(void *arg, const struct uq_res *r)
{
	job_done(arg, r);
}

static void job_timeout(void *arg)
{
	struct mmsb *b = arg;
	struct uq_res r;

	if (b->h && b->ops.uq.cancel)
		b->ops.uq.cancel(b->ops.uq.ctx, b->h);
	memset(&r, 0, sizeof(r));
	r.err = UQ_E_TIMEOUT;
	snprintf(r.errmsg, sizeof(r.errmsg), "no answer");
	job_done(b, &r);
}

static void job(struct mmsb *b, struct uq_req *rq, unsigned timeout_ms, void (*cb)(struct mmsb *, const struct uq_res *))
{
	b->busy = true;
	b->jcb = cb;
	b->h = b->ops.uq.call(b->ops.uq.ctx, rq, job_cb, b);
	if (!b->h) {		/* out of memory: report from the loop, never from inside the call */
		ev_timer_set(b->t_job, 0);
		return;
	}
	ev_timer_set(b->t_job, timeout_ms);
}

static const char *errtext(const struct uq_res *r)
{
	return r->errmsg[0] ? r->errmsg : r->err == UQ_E_TIMEOUT ? "timeout" : r->err == UQ_E_GONE ? "gone" : "failed";
}

/* ---- identity (IMSI) ---- */

static void ident_cb(void *arg, const struct uq_res *r)
{
	struct mmsb *b = arg;

	b->ih = NULL;
	b->ident_busy = false;
	if (!r->err && r->imsi[0]) {
		snprintf(b->imsi, sizeof(b->imsi), "%s", r->imsi);
		snprintf(b->imsi_modem, sizeof(b->imsi_modem), "%s", b->ops.modem ? b->ops.modem(b->ops.ctx) : "");
		changed(b);
		step(b);
		return;
	}
	b->ident_wait = true;
	ev_timer_set(b->t_ident, 5000);
}

static void ident_retry(void *arg)
{
	struct mmsb *b = arg;

	b->ident_wait = false;
	step(b);
}

static void ident_step(struct mmsb *b)
{
	const char *mp = b->ops.modem ? b->ops.modem(b->ops.ctx) : "";
	struct uq_req rq;

	if (!mp || !mp[0]) {
		b->imsi[0] = 0;
		b->imsi_modem[0] = 0;
		return;
	}
	if (b->imsi[0] && !strcmp(b->imsi_modem, mp))
		return;
	b->imsi[0] = 0;			/* another modem object: another SIM perhaps */
	b->imsi_modem[0] = 0;
	if (b->ident_busy || b->ident_wait)
		return;
	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_SIM_GET;
	snprintf(rq.obj, sizeof(rq.obj), "%s", mp);
	b->ident_busy = true;
	b->ih = b->ops.uq.call(b->ops.uq.ctx, &rq, ident_cb, b);
	if (!b->ih) {
		b->ident_busy = false;
		b->ident_wait = true;
		ev_timer_set(b->t_ident, 5000);
	}
}

const char *mmsb_imsi(const struct mmsb *b)
{
	return b->imsi;
}

/* ---- teardown ---- */

static void net_remove(struct mmsb *b)
{
	if (b->net_applied) {
		b->ops.net.remove(b->ops.net.ctx, &b->net);
		b->net_applied = false;
	}
	if (b->v6off && b->ops.ipv6_disable)
		b->ops.ipv6_disable(b->ops.ctx, b->ifname, false);
	b->v6off = false;
}

/* from now on nothing is connected / configured by us any more except what continue_down() still removes */
static void begin_down(struct mmsb *b, bool remote)
{
	if (b->st == S_DOWN)
		return;
	linger_cancel(b);
	ev_timer_cancel(b->t_check);
	if (b->h && b->ops.uq.cancel)
		b->ops.uq.cancel(b->ops.uq.ctx, b->h);
	b->h = NULL;
	b->busy = false;
	b->jcb = NULL;
	ev_timer_cancel(b->t_job);
	b->st = S_DOWN;
	b->down_remote = remote;
	b->dph = D_DISC;
	net_remove(b);
	set_reason(b, "closing");
	changed(b);
	continue_down(b);
}

static void down_job_cb(struct mmsb *b, const struct uq_res *r)
{
	if (r->err)
		LOGD("mms: bearer cleanup: %s", errtext(r));
	continue_down(b);
}

static void guard_removed(void *arg, int err)
{
	struct mmsb *b = arg;

	b->busy = false;
	if (err)
		LOGW("mms: traffic guard could not be removed (%s): the table stays and keeps dropping", strerror(-err));
	b->dph = D_FIN;
	continue_down(b);
}

static void finish_down(struct mmsb *b)
{
	bool fail = b->fail_after, blocked = b->blocked_after;
	unsigned delay = 0;

	b->fail_after = b->blocked_after = false;
	b->bpath[0] = 0;
	b->ours = false;
	b->ifname[0] = 0;
	b->n_dns = 0;
	memset(&b->local, 0, sizeof(b->local));
	b->nknown = b->nfif = 0;
	if (b->shut_done || b->stopping) {
		void (*d)(void *) = b->shut_done;
		void *a = b->shut_arg;

		b->shut_done = NULL;
		b->st = S_IDLE;
		ev_timer_cancel(b->t_shut);
		set_reason(b, "stopped");
		changed(b);
		if (d)
			d(a);
		return;
	}
	if (fail) {
		if (blocked) {
			b->st = S_BLOCKED;
			delay = b->cfg.blocked_retry_ms;
		} else {
			bool call = b->ops.voice_call && b->ops.voice_call(b->ops.ctx);

			delay = call ? b->cfg.retry_min_ms : b->cfg.retry_min_ms << (b->retry_n < 6 ? b->retry_n : 6);
			if (delay > b->cfg.retry_max_ms)
				delay = b->cfg.retry_max_ms;
			b->retry_n++;
			b->st = S_BACKOFF;
			if (call)
				LOGI("mms: the data connection failed during a voice call, trying again in %u s", delay / 1000);
		}
		set_reason(b, "%s (retry in %u s)", b->fail_reason, delay / 1000);
		ev_timer_set(b->t_retry, delay);
	} else {
		b->st = S_IDLE;
		set_reason(b, "idle");
	}
	changed(b);
	step(b);
}

static void continue_down(struct mmsb *b)
{
	struct uq_req rq;
	bool remote = b->down_remote && b->ours && b->bpath[0] && b->mpath[0];

	for (;;) {
		memset(&rq, 0, sizeof(rq));
		switch (b->dph) {
		case D_DISC:
			b->dph = D_DEL;
			if (remote) {
				rq.op = UQ_BEARER_DISCONNECT;
				snprintf(rq.obj, sizeof(rq.obj), "%s", b->bpath);
				LOGI("mms: disconnecting the MMS bearer");
				job(b, &rq, b->cfg.call_timeout_ms, down_job_cb);
				return;
			}
			continue;
		case D_DEL:
			b->dph = D_GUARD;
			if (remote) {
				rq.op = UQ_DELETE_BEARER;
				snprintf(rq.obj, sizeof(rq.obj), "%s", b->mpath);
				snprintf(rq.str, sizeof(rq.str), "%s", b->bpath);
				job(b, &rq, b->cfg.call_timeout_ms, down_job_cb);
				return;
			}
			continue;
		case D_GUARD:
			if (b->ours && b->ops.marker_clear)
				b->ops.marker_clear(b->ops.ctx);
			b->dph = D_FIN;
			b->busy = true;
			mmsguard_remove(b->g, guard_removed, b);
			return;
		case D_FIN:
			finish_down(b);
			return;
		}
	}
}

static void fail(struct mmsb *b, bool blocked, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void fail(struct mmsb *b, bool blocked, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(b->fail_reason, sizeof(b->fail_reason), fmt, ap);
	va_end(ap);
	set_error(b, "%s", b->fail_reason);
	if (blocked) {
		b->blocked++;
		LOGW("mms: %s", b->fail_reason);
	} else {
		b->failures++;
		LOGI("mms: the MMS data connection failed: %s", b->fail_reason);
	}
	b->fail_after = true;
	b->blocked_after = blocked;
	begin_down(b, true);		/* what is ours (b->ours) is cleaned up, what is not is left alone */
}

/* ---- bring-up ---- */

static void create_cb(struct mmsb *b, const struct uq_res *r);

static void do_create(struct mmsb *b)
{
	struct uq_req rq;
	int i;

	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_CREATE_BEARER;
	snprintf(rq.obj, sizeof(rq.obj), "%s", b->mpath);
	snprintf(rq.str, sizeof(rq.str), "%s", b->prof.apn);
	snprintf(rq.str2, sizeof(rq.str2), "%s", b->prof.ip_type);
	rq.num = 0;			/* no profile: the APN and the IP type are the whole request (uqmid: create_bearer) */
	b->st = S_CREATE;
	set_reason(b, "creating the bearer");
	for (i = 0; i < b->nknown; i++)
		LOGD("mms: existing bearer %s", b->known[i]);
	job(b, &rq, b->cfg.call_timeout_ms, create_cb);
}

static void scan_next(struct mmsb *b);

static void scan_leftover_cb(struct mmsb *b, const struct uq_res *r)
{
	struct uq_req rq;

	(void)r;
	memset(&rq, 0, sizeof(rq));
	if (b->scan_ph == SC_DISC) {
		b->scan_ph = SC_DEL;
		rq.op = UQ_DELETE_BEARER;
		snprintf(rq.obj, sizeof(rq.obj), "%s", b->mpath);
		snprintf(rq.str, sizeof(rq.str), "%s", b->known[b->scan_i]);
		job(b, &rq, b->cfg.call_timeout_ms, scan_leftover_cb);
		return;
	}
	if (b->ops.marker_clear)
		b->ops.marker_clear(b->ops.ctx);
	b->marker_b[0] = 0;
	b->known[b->scan_i][0] = 0;	/* gone: a create that returns this path would be a different bearer */
	b->scan_i++;
	scan_next(b);
}

static void scan_get_cb(struct mmsb *b, const struct uq_res *r)
{
	const char *path = b->known[b->scan_i];

	if (!r->err && b->marker_b[0] && !strcmp(path, b->marker_b)) {	/* ours from a previous run: clean it up */
		struct uq_req rq;

		LOGI("mms: removing the MMS bearer %s left behind by an earlier run", path);
		memset(&rq, 0, sizeof(rq));
		rq.op = UQ_BEARER_DISCONNECT;
		snprintf(rq.obj, sizeof(rq.obj), "%s", path);
		b->scan_ph = SC_DISC;
		job(b, &rq, b->cfg.call_timeout_ms, scan_leftover_cb);
		return;
	}
	if (!r->err && (r->connected || !strcmp(r->status, "connected"))) {
		if (!strcasecmp(r->apn, b->prof.apn)) {
			fail(b, true, "another bearer for the APN %s is connected on %s (not created by imsd): not touched, MMS is not available",
			     b->prof.apn, r->ifname[0] ? r->ifname : "a netdev");
			return;
		}
		if (r->ifname[0] && b->nfif < UQ_MAX_BEARERS)
			snprintf(b->fif[b->nfif++], sizeof(b->fif[0]), "%s", r->ifname);
	}
	b->scan_i++;
	scan_next(b);
}

static void scan_next(struct mmsb *b)
{
	struct uq_req rq;

	if (b->scan_i >= b->nknown) {
		do_create(b);
		return;
	}
	b->scan_ph = SC_GET;
	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_BEARER_GET;
	snprintf(rq.obj, sizeof(rq.obj), "%s", b->known[b->scan_i]);
	job(b, &rq, b->cfg.call_timeout_ms, scan_get_cb);
}

static void mget_cb(struct mmsb *b, const struct uq_res *r)
{
	int i;

	if (r->err) {
		fail(b, false, "reading the modem: %s", errtext(r));
		return;
	}
	b->nknown = 0;
	for (i = 0; i < r->n_bearer_paths && i < UQ_MAX_BEARERS; i++)
		snprintf(b->known[b->nknown++], UQ_PATH, "%s", r->bearer_paths[i]);
	b->scan_i = 0;
	scan_next(b);
}

static void guard_installed(void *arg, int err)
{
	struct mmsb *b = arg;
	struct uq_req rq;

	if (b->st != S_GUARD)
		return;		/* cancelled by a teardown that started meanwhile */
	b->busy = false;
	if (err) {
		fail(b, false, "the traffic guard could not be installed (%s): no MMS bearer", strerror(-err));
		return;
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_MODEM_GET;
	snprintf(rq.obj, sizeof(rq.obj), "%s", b->mpath);
	b->st = S_SCAN;
	set_reason(b, "looking at the modem's bearers");
	if (b->ops.marker_load) {
		b->marker_m[0] = b->marker_b[0] = 0;
		b->ops.marker_load(b->ops.ctx, b->marker_m, sizeof(b->marker_m), b->marker_b, sizeof(b->marker_b));
		if (strcmp(b->marker_m, b->mpath))
			b->marker_b[0] = 0;		/* of another modem object: not ours to touch */
	}
	b->nfif = 0;
	job(b, &rq, b->cfg.call_timeout_ms, mget_cb);
}

static void check_cb(struct mmsb *b, const struct uq_res *r);

static void arm_check(struct mmsb *b)
{
	ev_timer_set(b->t_check, b->cfg.check_ms);
}

static void up_now(struct mmsb *b)
{
	b->st = S_UP;
	b->retry_n = 0;
	b->last_error[0] = 0;
	b->connects++;
	set_reason(b, "%s", "");
	LOGI("mms: the MMS data connection is up (%s)", b->ifname);
	arm_check(b);
	if (!b->want && !b->stopping)
		linger_arm(b);
	changed(b);
}

static void armed_cb(void *arg, int err)
{
	struct mmsb *b = arg;
	int r;

	if (b->st != S_ARM)
		return;
	b->busy = false;
	if (err) {
		fail(b, false, "the traffic guard could not take the netdev (%s)", strerror(-err));
		return;
	}
	memset(&b->net, 0, sizeof(b->net));
	snprintf(b->net.ifname, sizeof(b->net.ifname), "%s", b->ifname);
	b->net.local = b->local;
	b->net.prefix = b->prefix;
	b->net.mtu = b->mtu;
	b->net.table = b->cfg.route_table;
	b->net.rule_pref = 0;
	r = b->ops.net.apply(b->ops.net.ctx, &b->net);
	if (r) {
		fail(b, false, "configuring %s failed: %s", b->ifname, strerror(-r));
		return;
	}
	b->net_applied = true;
	up_now(b);
}

static void bget_cb(struct mmsb *b, const struct uq_res *r)
{
	const struct uq_ipcfg *ip;
	int i, rc;

	if (r->err) {
		fail(b, false, "bearer get: %s", errtext(r));
		return;
	}
	if (!r->connected && strcmp(r->status, "connected")) {
		fail(b, false, "the bearer is %s after connect", r->status);
		return;
	}
	if (!r->ifname[0]) {
		fail(b, false, "the bearer has no network interface");
		return;
	}
	for (i = 0; i < b->nfif; i++)
		if (!strcmp(b->fif[i], r->ifname)) {
			/* ours came up on a netdev that another connected bearer already uses: do not configure it */
			fail(b, true, "the bearer came up on %s, which another bearer (not created by imsd) is using: not touched, MMS is not available",
			     r->ifname);
			return;
		}
	ip = r->ip4.present && r->ip4.address[0] ? &r->ip4 : (r->ip6.present && r->ip6.address[0] ? &r->ip6 : NULL);
	if (!ip || addr_set(&b->local, ip->address, 0)) {
		fail(b, false, "the bearer has no usable IP address");
		return;
	}
	snprintf(b->ifname, sizeof(b->ifname), "%s", r->ifname);
	b->prefix = ip->prefix;
	b->mtu = ip->mtu;
	b->n_dns = 0;
	if (ip->dns1[0] && !addr_set(&b->dns[b->n_dns], ip->dns1, 53))
		b->n_dns++;
	if (ip->dns2[0] && !addr_set(&b->dns[b->n_dns], ip->dns2, 53))
		b->n_dns++;
	if (!b->n_dns) {
		fail(b, false, "the bearer has no DNS servers");
		return;
	}
	/* IPv4-only: IPv6 is switched off on the netdev (no router solicitation, no link-local address) */
	if (!(r->ip6.present && r->ip6.address[0]) && b->ops.ipv6_disable) {
		b->ops.ipv6_disable(b->ops.ctx, b->ifname, true);
		b->v6off = true;
	}
	b->st = S_ARM;
	set_reason(b, "arming the traffic guard");
	b->busy = true;
	rc = mmsguard_arm(b->g, b->ifname, b->dns, b->n_dns, armed_cb, b);
	if (rc) {
		b->busy = false;
		fail(b, false, "the traffic guard refused the netdev (%s)", strerror(-rc));
	}
}

static void connect_cb(struct mmsb *b, const struct uq_res *r)
{
	struct uq_req rq;

	if (r->err) {
		fail(b, false, "bearer connect: %s", errtext(r));
		return;
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_BEARER_GET;
	snprintf(rq.obj, sizeof(rq.obj), "%s", b->bpath);
	b->st = S_GET;
	job(b, &rq, b->cfg.call_timeout_ms, bget_cb);
}

static void create_cb(struct mmsb *b, const struct uq_res *r)
{
	struct uq_req rq;
	int i;

	if (r->err || !r->path[0]) {
		fail(b, false, "create_bearer: %s", r->err ? errtext(r) : "no path in the reply");
		return;
	}
	for (i = 0; i < b->nknown; i++)
		if (b->known[i][0] && !strcmp(b->known[i], r->path)) {
			b->ours = false;
			snprintf(b->bpath, sizeof(b->bpath), "%s", r->path);
			fail(b, true, "a bearer with the same settings (%s) already exists and was not created by imsd: not touched, MMS is not available",
			     r->path);
			return;
		}
	snprintf(b->bpath, sizeof(b->bpath), "%s", r->path);
	b->ours = true;
	if (b->ops.marker_save)
		b->ops.marker_save(b->ops.ctx, b->mpath, b->bpath);
	LOGI("mms: created the MMS bearer %s (APN %s, %s)", b->bpath, b->prof.apn, b->prof.ip_type);
	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_BEARER_CONNECT;
	snprintf(rq.obj, sizeof(rq.obj), "%s", b->bpath);
	b->st = S_CONNECT;
	set_reason(b, "connecting the bearer");
	job(b, &rq, b->cfg.connect_timeout_ms, connect_cb);
}

static void begin_up(struct mmsb *b)
{
	snprintf(b->mpath, sizeof(b->mpath), "%s", b->ops.modem(b->ops.ctx));
	b->st = S_GUARD;
	b->busy = true;
	set_reason(b, "installing the traffic guard");
	LOGI("mms: bringing up the MMS data connection (APN %s)", b->prof.apn);
	changed(b);
	if (mmsguard_install(b->g, guard_installed, b)) {
		b->busy = false;
		fail(b, false, "the traffic guard could not be started: no MMS bearer");
	}
}

/* ---- liveness ---- */

static void check_cb(struct mmsb *b, const struct uq_res *r)
{
	if (b->st != S_UP)
		return;
	if (r->err == UQ_E_TIMEOUT) {
		arm_check(b);
		step(b);
		return;
	}
	if (r->err || (!r->connected && strcmp(r->status, "connected"))) {
		LOGI("mms: the MMS bearer is gone (%s)", r->err ? errtext(r) : r->status);
		b->fail_after = false;
		begin_down(b, true);
		return;
	}
	arm_check(b);
	step(b);
}

static void on_check(void *arg)
{
	struct mmsb *b = arg;
	struct uq_req rq;

	if (b->st != S_UP)
		return;
	if (b->busy) {
		arm_check(b);
		return;
	}
	memset(&rq, 0, sizeof(rq));
	rq.op = UQ_BEARER_GET;
	snprintf(rq.obj, sizeof(rq.obj), "%s", b->bpath);
	job(b, &rq, b->cfg.call_timeout_ms, check_cb);
}

static void on_linger(void *arg)
{
	struct mmsb *b = arg;

	b->linger_armed = false;
	if (b->st == S_UP && !b->want) {
		LOGI("mms: no more MMS work, releasing the data connection");
		b->fail_after = false;
		begin_down(b, true);
	}
}

static void on_retry(void *arg)
{
	struct mmsb *b = arg;

	if (b->st == S_BACKOFF || b->st == S_BLOCKED) {
		b->st = S_IDLE;
		set_reason(b, "idle");
		step(b);
	}
}

/* ---- the stepper ---- */

static void step_once(struct mmsb *b)
{
	struct mmsb_profile p;
	char why[96] = "";
	const char *mp;
	bool pok;

	ident_step(b);
	mp = b->ops.modem ? b->ops.modem(b->ops.ctx) : "";
	if (!mp)
		mp = "";
	pok = b->ops.profile && b->ops.profile(b->ops.ctx, &p, why, sizeof(why));
	if (!pok)
		memset(&p, 0, sizeof(p));
	b->avail = pok && mp[0] && !b->stopping;
	/* an active session whose inputs changed (backend / provider switch, modem gone, another APN) goes down now */
	if (b->st != S_IDLE && b->st != S_DOWN && b->st != S_BACKOFF && b->st != S_BLOCKED &&
	    (b->stopping || !pok || strcmp(mp, b->mpath) || strcmp(p.apn, b->prof.apn) || strcmp(p.ip_type, b->prof.ip_type))) {
		bool gone = strcmp(mp, b->mpath) != 0;

		b->fail_after = false;
		LOGI("mms: releasing the MMS data connection (%s)", b->stopping ? "shutdown" : gone ? "the modem changed" : "the provider changed");
		begin_down(b, !gone);
		return;
	}
	if (b->st == S_DOWN) {
		if (!b->busy)
			continue_down(b);
		return;
	}
	if (b->busy)
		return;
	switch (b->st) {
	case S_IDLE:
	case S_BACKOFF:
	case S_BLOCKED:
		if (b->stopping)
			return;
		if (!pok) {
			set_reason(b, "%s", why[0] ? why : "no MMS APN for this operator");
			return;
		}
		if (!mp[0]) {
			set_reason(b, "no modem");
			return;
		}
		if (b->st != S_IDLE)
			return;		/* the retry timer brings it back to idle */
		if (!b->want) {
			set_reason(b, "idle");
			return;
		}
		b->prof = p;
		begin_up(b);
		return;
	case S_UP:
		if (b->want)
			linger_cancel(b);
		else
			linger_arm(b);
		return;
	default:
		return;
	}
}

static void step(struct mmsb *b)
{
	if (b->in_step) {
		b->again = true;
		return;
	}
	b->in_step = true;
	do {
		b->again = false;
		step_once(b);
	} while (b->again);
	b->in_step = false;
}

/* ---- public ---- */

static void guard_lost(void *arg)
{
	struct mmsb *b = arg;

	if (b->st == S_UP || b->st == S_ARM || b->st == S_GET || b->st == S_CONNECT || b->st == S_CREATE || b->st == S_SCAN)
		fail(b, false, "the traffic guard was lost: %s", "the bearer is released");
}

static void on_shut_timeout(void *arg)
{
	struct mmsb *b = arg;
	void (*d)(void *) = b->shut_done;
	void *a = b->shut_arg;

	b->shut_done = NULL;
	LOGW("mms: the MMS bearer was not released in time");
	if (d)
		d(a);
}

struct mmsb *mmsb_new(const struct mmsb_cfg *cfg, const struct mmsb_ops *ops)
{
	struct mmsb *b = calloc(1, sizeof(*b));

	if (!b)
		return NULL;
	b->cfg = *cfg;
	b->ops = *ops;
	b->g = mmsguard_new(&ops->exec, guard_lost, b);
	b->t_job = ev_timer_new(job_timeout, b);
	b->t_linger = ev_timer_new(on_linger, b);
	b->t_retry = ev_timer_new(on_retry, b);
	b->t_check = ev_timer_new(on_check, b);
	b->t_shut = ev_timer_new(on_shut_timeout, b);
	b->t_ident = ev_timer_new(ident_retry, b);
	b->t_notify = ev_timer_new(on_notify, b);
	if (!b->g || !b->t_notify || !b->t_job || !b->t_linger || !b->t_retry || !b->t_check || !b->t_shut || !b->t_ident) {
		mmsb_free(b);
		return NULL;
	}
	set_reason(b, "idle");
	return b;
}

void mmsb_free(struct mmsb *b)
{
	if (!b)
		return;
	if (b->h && b->ops.uq.cancel)
		b->ops.uq.cancel(b->ops.uq.ctx, b->h);
	if (b->ih && b->ops.uq.cancel)
		b->ops.uq.cancel(b->ops.uq.ctx, b->ih);
	net_remove(b);
	mmsguard_free(b->g);
	ev_timer_free(b->t_job);
	ev_timer_free(b->t_linger);
	ev_timer_free(b->t_retry);
	ev_timer_free(b->t_check);
	ev_timer_free(b->t_shut);
	ev_timer_free(b->t_ident);
	ev_timer_free(b->t_notify);
	free(b);
}

void mmsb_set_cfg(struct mmsb *b, const struct mmsb_cfg *cfg)
{
	b->cfg = *cfg;
}

void mmsb_want(struct mmsb *b, bool want)
{
	if (b->want == want)
		return;
	b->want = want;
	if (want)
		linger_cancel(b);
	step(b);
}

void mmsb_poke(struct mmsb *b)
{
	step(b);
}

void mmsb_link(const struct mmsb *b, struct mmsb_link *out)
{
	memset(out, 0, sizeof(*out));
	out->seq = b->seq;
	{
		struct mmsb_profile p;
		char why[8];
		const char *mp = b->ops.modem ? b->ops.modem(b->ops.ctx) : "";

		out->available = !b->stopping && mp && mp[0] && b->ops.profile && b->ops.profile(b->ops.ctx, &p, why, sizeof(why)) && b->st != S_BLOCKED;
	}
	snprintf(out->reason, sizeof(out->reason), "%s", b->reason);
	if (b->st != S_UP)
		return;
	out->up = true;
	snprintf(out->netdev, sizeof(out->netdev), "%s", b->ifname);
	out->local = b->local;
	memcpy(out->dns, b->dns, sizeof(out->dns));
	out->n_dns = b->n_dns;
}

int mmsb_gate(void *vb, const struct addr *dst, void (*done)(void *arg, int err), void *arg)
{
	struct mmsb *b = vb;

	if (b->st != S_UP)
		return -ENETDOWN;
	return mmsguard_gate(b->g, dst, done, arg);
}

void mmsb_gate_cancel(void *vb, void *arg)
{
	struct mmsb *b = vb;

	mmsguard_gate_cancel(b->g, arg);
}

void mmsb_shutdown(struct mmsb *b, void (*done)(void *arg), void *arg, unsigned timeout_ms)
{
	b->stopping = true;
	b->want = false;
	if (b->st == S_IDLE || b->st == S_BACKOFF || b->st == S_BLOCKED) {
		ev_timer_cancel(b->t_retry);
		b->st = S_IDLE;
		if (done)
			done(arg);
		return;
	}
	b->shut_done = done;
	b->shut_arg = arg;
	ev_timer_set(b->t_shut, timeout_ms);
	step(b);
}

void mmsb_get_status(const struct mmsb *b, struct mmsb_status *s)
{
	static const char *const names[] = { "idle", "installing-guard", "scanning", "creating", "connecting", "getting", "arming-guard",
					     "up", "closing", "backoff", "blocked" };

	memset(s, 0, sizeof(*s));
	s->state = names[b->st];
	snprintf(s->reason, sizeof(s->reason), "%s", b->reason);
	snprintf(s->last_error, sizeof(s->last_error), "%s", b->last_error);
	if (b->st == S_UP) {
		snprintf(s->netdev, sizeof(s->netdev), "%s", b->ifname);
		addr_host(&b->local, s->address, sizeof(s->address));
	}
	snprintf(s->apn, sizeof(s->apn), "%s", b->prof.apn);
	s->want = b->want;
	s->connects = b->connects;
	s->failures = b->failures;
	s->scans_blocked = b->blocked;
	s->retry_n = b->retry_n;
	mmsguard_stats(b->g, &s->guard);
}
