/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The on-demand MMS bearer and its traffic guard on a fake uqmid / rtnetlink / nft (the rig), and the CS-mode MMS flow on top of them:
 * bearer lifecycle, guard order and rules, fail-closed behaviour, proxy request form, DNS through the bearer's servers, failover.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "t_common.h"
#include "t_vectors.h"
#include "mmsguard.h"
#include "../util/evloop.h"
#include "../util/log.h"

#define APN "lte.sktelecom.com"
#define LOGSZ 4096

/* ------------------------------------------------------------------ */
/* the rig                                                             */

static struct brig *R;

struct fcall {
	struct brig *r;
	struct uq_req rq;
	uq_cb cb;
	void *arg;
	struct ev_timer *t;
	bool live;
};
static struct fcall FC[24];

struct fexec {
	struct brig *r;
	char script[2048];
	char kind;		/* 'l' list, 's' script */
	void (*cb)(void *arg, int status, const char *out);
	void *arg;
	struct ev_timer *t;
	bool live;
};
static struct fexec FE[24];

static void lg(struct brig *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void lg(struct brig *r, const char *fmt, ...)
{
	va_list ap;
	size_t n = strlen(r->log);

	va_start(ap, fmt);
	if (n && n + 2 < LOGSZ)
		r->log[n++] = ' ';
	vsnprintf(r->log + n, LOGSZ - n, fmt, ap);
	va_end(ap);
}

static void fill_ours(struct brig *r, struct uq_res *o)
{
	snprintf(o->ifname, sizeof(o->ifname), "wwan0");
	o->ip4.present = true;
	snprintf(o->ip4.address, sizeof(o->ip4.address), "10.110.48.33");
	o->ip4.prefix = 30;
	snprintf(o->ip4.gateway, sizeof(o->ip4.gateway), "10.110.48.34");
	snprintf(o->ip4.dns1, sizeof(o->ip4.dns1), "223.62.230.7");
	snprintf(o->ip4.dns2, sizeof(o->ip4.dns2), "113.217.240.31");
	o->ip4.mtu = 1440;
	if (r->v6) {
		o->ip6.present = true;
		snprintf(o->ip6.address, sizeof(o->ip6.address), "2001:db8::2");
		o->ip6.prefix = 64;
		snprintf(o->ip6.dns1, sizeof(o->ip6.dns1), "2001:db8::53");
	}
}

/* 0 none, 1 created, 2 connected; per bearer path */
static int ours_state;
static char ours_path[40];
static bool leftover_alive;

static void fake_result(struct brig *r, const struct uq_req *q, struct uq_res *o)
{
	int i;

	memset(o, 0, sizeof(*o));
	switch (q->op) {
	case UQ_SIM_GET:
		if (!r->imsi[0]) {
			o->err = UQ_E_FAILED;
			break;
		}
		snprintf(o->imsi, sizeof(o->imsi), "%s", r->imsi);
		break;
	case UQ_MODEM_GET:
		if (r->foreign_path[0])
			snprintf(o->bearer_paths[o->n_bearer_paths++], UQ_PATH, "%s", r->foreign_path);
		if (leftover_alive)
			snprintf(o->bearer_paths[o->n_bearer_paths++], UQ_PATH, "%s", r->leftover_path);
		if (ours_state)
			snprintf(o->bearer_paths[o->n_bearer_paths++], UQ_PATH, "%s", ours_path);
		break;
	case UQ_BEARER_GET:
		if (r->foreign_path[0] && !strcmp(q->obj, r->foreign_path)) {
			snprintf(o->status, sizeof(o->status), "connected");
			o->connected = true;
			snprintf(o->apn, sizeof(o->apn), "%s", r->foreign_apn);
			snprintf(o->ifname, sizeof(o->ifname), "%s", r->foreign_if);
		} else if (leftover_alive && !strcmp(q->obj, r->leftover_path)) {
			snprintf(o->status, sizeof(o->status), "connected");
			o->connected = true;
			snprintf(o->apn, sizeof(o->apn), "%s", APN);
			snprintf(o->ifname, sizeof(o->ifname), "wwan0");
		} else if (ours_state && !strcmp(q->obj, ours_path)) {
			snprintf(o->status, sizeof(o->status), "%s", ours_state == 2 ? "connected" : "disconnected");
			o->connected = ours_state == 2;
			snprintf(o->apn, sizeof(o->apn), "%s", r->apn);
			if (ours_state == 2)
				fill_ours(r, o);
		} else {
			o->err = UQ_E_GONE;
		}
		break;
	case UQ_CREATE_BEARER:
		lg(r, "CREATE:%s:%s", q->str, q->str2);
		if (r->create_fail_n > 0) {
			r->create_fail_n--;
			o->err = UQ_E_FAILED;
			break;
		}
		if (r->create_returns_foreign) {
			snprintf(o->path, sizeof(o->path), "%s", r->foreign_path);
			break;
		}
		r->created++;
		snprintf(ours_path, sizeof(ours_path), "/bearer/mms%d", r->created);
		ours_state = 1;
		r->live++;
		if (r->live > r->max_live)
			r->max_live = r->live;
		snprintf(o->path, sizeof(o->path), "%s", ours_path);
		break;
	case UQ_BEARER_CONNECT:
		if (r->foreign_path[0] && !strcmp(q->obj, r->foreign_path)) {
			r->foreign_touched = true;
			break;
		}
		lg(r, "CONNECT");
		if (r->connect_fail_n > 0) {
			r->connect_fail_n--;
			o->err = UQ_E_FAILED;
			snprintf(o->errmsg, sizeof(o->errmsg), "no service");
			break;
		}
		ours_state = 2;
		break;
	case UQ_BEARER_DISCONNECT:
		if (r->foreign_path[0] && !strcmp(q->obj, r->foreign_path)) {
			r->foreign_touched = true;
			break;
		}
		lg(r, "DISC");
		if (leftover_alive && !strcmp(q->obj, r->leftover_path))
			break;
		if (ours_state)
			ours_state = 1;
		break;
	case UQ_DELETE_BEARER:
		if (r->foreign_path[0] && !strcmp(q->str, r->foreign_path)) {
			r->foreign_touched = true;
			break;
		}
		lg(r, "DEL");
		if (leftover_alive && !strcmp(q->str, r->leftover_path)) {
			leftover_alive = false;
			break;
		}
		if (ours_state && !strcmp(q->str, ours_path)) {
			ours_state = 0;
			r->live--;
		}
		break;
	default:
		o->err = UQ_E_BAD;
		break;
	}
	(void)i;
}

static void fcall_fire(void *arg)
{
	struct fcall *c = arg;
	struct uq_res res;
	uq_cb cb = c->cb;
	void *a = c->arg;

	fake_result(c->r, &c->rq, &res);
	ev_timer_free(c->t);
	c->t = NULL;
	c->live = false;
	cb(a, &res);
}

static void *fq_call(void *ctx, const struct uq_req *rq, uq_cb cb, void *arg)
{
	struct brig *r = ctx;
	unsigned i;
	unsigned delay = 0;

	for (i = 0; i < 24; i++)
		if (!FC[i].live) {
			FC[i].live = true;
			FC[i].r = r;
			FC[i].rq = *rq;
			FC[i].cb = cb;
			FC[i].arg = arg;
			FC[i].t = ev_timer_new(fcall_fire, &FC[i]);
			if (rq->op == UQ_BEARER_CONNECT)
				delay = r->connect_delay_ms;
			else if (rq->op == UQ_BEARER_DISCONNECT)
				delay = r->disc_delay_ms;
			ev_timer_set(FC[i].t, delay);
			return &FC[i];
		}
	return NULL;
}

static void fq_cancel(void *ctx, void *h)
{
	struct fcall *c = h;

	(void)ctx;
	ev_timer_free(c->t);
	c->t = NULL;
	c->live = false;
}

static void fexec_fire(void *arg)
{
	struct fexec *e = arg;
	struct brig *r = e->r;
	char out[512] = "";
	int status = 0;

	if (e->kind == 'l') {
		if (r->exec_fail_poll)
			status = 1;
		else
			snprintf(out, sizeof(out), "table inet imsd_mms {\n\tcounter acc {\n\t\tpackets %lu bytes 99\n\t}\n\tcounter drp {\n\t\tpackets %lu bytes 0\n\t}\n}\n",
				 r->acc, r->drp);
	} else if (strstr(e->script, "add table inet imsd_mms")) {
		lg(r, "G+");
		status = r->exec_fail_install ? 1 : 0;
	} else if (strstr(e->script, " ifs { \"")) {
		const char *q = strstr(e->script, " ifs { \"") + 8;

		lg(r, "GA:%.*s", (int)strcspn(q, "\""), q);
		status = r->exec_fail_arm ? 1 : 0;
	} else if (strstr(e->script, " tcp4 {") || strstr(e->script, " tcp6 {")) {
		const char *q = strchr(e->script, '{') + 2;
		const char *end = strstr(q, " }");

		lg(r, "GT:%.*s", (int)(end ? end - q : 0), q);
		status = r->exec_fail_gate ? 1 : 0;
	} else if (strstr(e->script, "destroy table")) {
		lg(r, "G-");
	}
	{
		void (*cb)(void *, int, const char *) = e->cb;
		void *a = e->arg;

		ev_timer_free(e->t);
		e->t = NULL;
		e->live = false;
		cb(a, status, out);
	}
}

static void *fx_run(void *ctx, const char *const *argv, const char *stdin_text, void (*cb)(void *arg, int status, const char *out), void *arg)
{
	struct brig *r = ctx;
	unsigned i;

	for (i = 0; i < 24; i++)
		if (!FE[i].live) {
			FE[i].live = true;
			FE[i].r = r;
			FE[i].kind = !strcmp(argv[1], "list") ? 'l' : 's';
			snprintf(FE[i].script, sizeof(FE[i].script), "%s", stdin_text ? stdin_text : "");
			FE[i].cb = cb;
			FE[i].arg = arg;
			FE[i].t = ev_timer_new(fexec_fire, &FE[i]);
			ev_timer_set(FE[i].t, 0);
			return &FE[i];
		}
	errno = EAGAIN;
	return NULL;
}

static void fx_cancel(void *ctx, void *h)
{
	struct fexec *e = h;

	(void)ctx;
	ev_timer_free(e->t);
	e->t = NULL;
	e->live = false;
}

static int fn_apply(void *ctx, const struct netcfg_params *p)
{
	struct brig *r = ctx;

	if (r->net_apply_rc)
		return r->net_apply_rc;
	lg(r, "NET+");
	r->last_net = *p;
	return 0;
}

static void fn_remove(void *ctx, const struct netcfg_params *p)
{
	struct brig *r = ctx;

	(void)p;
	lg(r, "NET-");
}

static void f_v6(void *ctx, const char *ifname, bool disable)
{
	(void)ifname;
	lg(ctx, disable ? "V6OFF" : "V6ON");
}

static const char *f_modem(void *ctx)
{
	return ((struct brig *)ctx)->modem;
}

static bool f_profile(void *ctx, struct mmsb_profile *o, char *why, size_t n)
{
	struct brig *r = ctx;

	if (!r->prof_ok) {
		snprintf(why, n, "no MMS APN is known for this operator");
		return false;
	}
	snprintf(o->apn, sizeof(o->apn), "%s", r->apn);
	snprintf(o->ip_type, sizeof(o->ip_type), "%s", r->ip_type);
	return true;
}

static void f_changed(void *ctx)
{
	struct brig *r = ctx;

	r->changed_n++;
	if (r->on_changed)
		r->on_changed(r->on_changed_arg);
}

static bool f_voice(void *ctx)
{
	return ((struct brig *)ctx)->voice_call;
}

static void f_mload(void *ctx, char *m, size_t mn, char *b, size_t bn)
{
	struct brig *r = ctx;

	snprintf(m, mn, "%s", r->marker_modem);
	snprintf(b, bn, "%s", r->marker_bearer);
}

static void f_msave(void *ctx, const char *m, const char *b)
{
	struct brig *r = ctx;

	snprintf(r->marker_modem, sizeof(r->marker_modem), "%s", m);
	snprintf(r->marker_bearer, sizeof(r->marker_bearer), "%s", b);
}

static void f_mclear(void *ctx)
{
	struct brig *r = ctx;

	r->marker_modem[0] = r->marker_bearer[0] = 0;
}

struct brig *brig_new(void)
{
	struct brig *r = calloc(1, sizeof(*r));
	struct mmsb_ops o;
	struct mmsb_cfg c;

	R = r;
	memset(FC, 0, sizeof(FC));
	memset(FE, 0, sizeof(FE));
	ours_state = 0;
	leftover_alive = false;
	r->prof_ok = true;
	snprintf(r->apn, sizeof(r->apn), APN);
	snprintf(r->ip_type, sizeof(r->ip_type), "ipv4v6");
	snprintf(r->modem, sizeof(r->modem), "uqmid.modem.0");
	snprintf(r->imsi, sizeof(r->imsi), "450119876543210");
	snprintf(r->plmn, sizeof(r->plmn), "45005");
	snprintf(r->leftover_path, sizeof(r->leftover_path), "/bearer/old");
	memset(&o, 0, sizeof(o));
	o.uq.call = fq_call;
	o.uq.cancel = fq_cancel;
	o.uq.ctx = r;
	o.net.apply = fn_apply;
	o.net.remove = fn_remove;
	o.net.ctx = r;
	o.ipv6_disable = f_v6;
	o.exec.run = fx_run;
	o.exec.cancel = fx_cancel;
	o.exec.ctx = r;
	o.modem = f_modem;
	o.profile = f_profile;
	o.changed = f_changed;
	o.voice_call = f_voice;
	o.marker_load = f_mload;
	o.marker_save = f_msave;
	o.marker_clear = f_mclear;
	o.ctx = r;
	mmsb_cfg_defaults(&c);
	r->b = mmsb_new(&c, &o);
	CHECK(r->b != NULL);
	return r;
}

void brig_free(struct brig *r)
{
	unsigned i;

	mmsb_free(r->b);
	for (i = 0; i < 24; i++) {
		ev_timer_free(FC[i].t);
		ev_timer_free(FE[i].t);
	}
	memset(FC, 0, sizeof(FC));
	memset(FE, 0, sizeof(FE));
	R = NULL;
	free(r);
}

void brig_mms_link(struct brig *r, struct mms_link *out)
{
	struct mmsb_link l;

	mmsb_link(r->b, &l);
	out->on_demand = true;
	out->available = l.available;
	out->up = l.up;
	memcpy(out->netdev, l.netdev, sizeof(out->netdev));
	out->local = l.local;
	memcpy(out->dns, l.dns, sizeof(out->dns));
	out->n_dns = l.n_dns;
	out->seq = l.seq;
	snprintf(out->reason, sizeof(out->reason), "%s", l.up ? "" : l.reason);
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */

static bool has(const struct brig *r, const char *s)
{
	return strstr(r->log, s) != NULL;
}

static int pos(const struct brig *r, const char *s)
{
	const char *p = strstr(r->log, s);

	return p ? (int)(p - r->log) : -1;
}

static bool is_up(struct brig *r)
{
	struct mmsb_link l;

	mmsb_link(r->b, &l);
	return l.up;
}

static const char *state(struct brig *r)
{
	static struct mmsb_status s;

	mmsb_get_status(r->b, &s);
	return s.state;
}

/* ------------------------------------------------------------------ */
/* tests                                                               */

static int g_done, g_err = 99;

static void done_cb(void *arg, int err)
{
	(void)arg;
	g_done++;
	g_err = err;
}

static void shut_cb(void *arg)
{
	(void)arg;
	g_done++;
}

static void t_lifecycle(void)
{
	struct brig *r;
	struct mmsb_link l;
	struct mmsb_status st;

	evfake_reset();
	r = brig_new();
	/* idle: nothing is touched, no bearer exists until there is work */
	spin(20);
	advance(1000);
	CHECK_STR(r->log, "");
	CHECK_STR(state(r), "idle");
	CHECK(!is_up(r));
	mmsb_link(r->b, &l);
	CHECK(l.available);
	/* work: guard first, then the bearer, then the IPv6 switch, the guard takes the netdev, only then the address */
	mmsb_want(r->b, true);
	advance(500);
	CHECK_STR(r->log, "G+ CREATE:lte.sktelecom.com:ipv4v6 CONNECT V6OFF GA:wwan0 NET+");
	CHECK(pos(r, "G+") < pos(r, "CREATE") && pos(r, "GA:wwan0") < pos(r, "NET+"));
	CHECK(is_up(r));
	mmsb_link(r->b, &l);
	CHECK_STR(l.netdev, "wwan0");
	{
		char h[48];

		addr_host(&l.local, h, sizeof(h));
		CHECK_STR(h, "10.110.48.33");
		CHECK_EQ(l.n_dns, 2);
		addr_host(&l.dns[0], h, sizeof(h));
		CHECK_STR(h, "223.62.230.7");
		CHECK_EQ(addr_port(&l.dns[0]), 53);
	}
	/* the netdev configuration: its own table, the address, the prefix and MTU of the bearer */
	CHECK_STR(r->last_net.ifname, "wwan0");
	CHECK_EQ(r->last_net.table, 1007);
	CHECK_EQ(r->last_net.prefix, 30);
	CHECK_EQ(r->last_net.mtu, 1440);
	mmsb_get_status(r->b, &st);
	CHECK_STR(st.state, "up");
	CHECK(st.guard.installed && st.guard.armed);
	CHECK_EQ(st.connects, 1);
	/* the marker names the bearer while it exists */
	CHECK_STR(r->marker_bearer, "/bearer/mms1");
	/* work ends: it stays for the linger (20 s), then goes: address, bearer, guard, in this order */
	mmsb_want(r->b, false);
	advance(19000);
	CHECK(is_up(r));
	advance(2000);
	CHECK(!is_up(r));
	CHECK_STR(r->log, "G+ CREATE:lte.sktelecom.com:ipv4v6 CONNECT V6OFF GA:wwan0 NET+ NET- V6ON DISC DEL G-");
	CHECK_STR(r->marker_bearer, "");
	CHECK_STR(state(r), "idle");
	CHECK_EQ(r->live, 0);
	mmsb_get_status(r->b, &st);
	CHECK(!st.guard.installed);
	/* work again within the linger keeps the same bearer (no second one) */
	r->log[0] = 0;
	mmsb_want(r->b, true);
	advance(500);
	mmsb_want(r->b, false);
	advance(15000);
	mmsb_want(r->b, true);
	advance(10000);
	CHECK(is_up(r));
	CHECK_EQ(r->created, 2);
	CHECK_EQ(r->max_live, 1);
	mmsb_want(r->b, false);
	advance(25000);
	CHECK(!is_up(r));
	brig_free(r);
}

static void t_guard_order_and_failures(void)
{
	struct brig *r;
	struct mmsb_status st;

	/* the guard cannot be installed: no bearer is created at all, the retry is after 5 s */
	evfake_reset();
	r = brig_new();
	r->exec_fail_install = true;
	mmsb_want(r->b, true);
	advance(1000);
	CHECK(!has(r, "CREATE"));
	CHECK(!is_up(r));
	CHECK_STR(state(r), "backoff");
	mmsb_get_status(r->b, &st);
	CHECK(strstr(st.reason, "traffic guard") != NULL);
	CHECK(st.guard.failures >= 1);
	advance(4500);
	CHECK(!has(r, "CREATE") && pos(r, "G+") >= 0);
	r->exec_fail_install = false;
	advance(12000);
	CHECK(is_up(r));
	CHECK(pos(r, "G+") < pos(r, "CREATE"));
	mmsb_want(r->b, false);
	advance(25000);
	brig_free(r);

	/* the guard cannot take the netdev: the bearer is released again without an address ever being configured */
	evfake_reset();
	r = brig_new();
	r->exec_fail_arm = true;
	mmsb_want(r->b, true);
	advance(1000);
	CHECK(!has(r, "NET+"));
	CHECK(has(r, "CONNECT") && has(r, "DISC") && has(r, "DEL") && has(r, "G-"));
	CHECK(!is_up(r));
	CHECK_EQ(r->live, 0);
	brig_free(r);

	/* the address cannot be configured: released, guard removed, nothing left */
	evfake_reset();
	r = brig_new();
	r->net_apply_rc = -EIO;
	mmsb_want(r->b, true);
	advance(1000);
	CHECK(!has(r, "NET+") && has(r, "DEL") && has(r, "G-"));
	CHECK_EQ(r->live, 0);
	brig_free(r);

	/* the guard is lost while the bearer is up (the table disappeared): the bearer is released at once */
	evfake_reset();
	r = brig_new();
	mmsb_want(r->b, true);
	advance(500);
	CHECK(is_up(r));
	r->exec_fail_poll = true;
	advance(6000);
	CHECK(!is_up(r));
	CHECK(has(r, "NET- V6ON DISC DEL G-"));
	CHECK_STR(state(r), "backoff");
	r->exec_fail_poll = false;
	advance(10000);
	CHECK(is_up(r));
	mmsb_want(r->b, false);
	advance(25000);
	brig_free(r);

	/* the counters come from the table and are summed over the sessions */
	evfake_reset();
	r = brig_new();
	mmsb_want(r->b, true);
	advance(500);
	r->acc = 21;
	r->drp = 3;
	advance(5500);
	mmsb_get_status(r->b, &st);
	CHECK_EQ(st.guard.accepted, 21);
	CHECK_EQ(st.guard.dropped, 3);
	r->acc = 25;
	mmsb_want(r->b, false);
	advance(25000);			/* the last read happens before the table is deleted */
	mmsb_get_status(r->b, &st);
	CHECK_EQ(st.guard.accepted, 25);
	CHECK_EQ(st.guard.dropped, 3);
	r->acc = 4;
	r->drp = 0;
	mmsb_want(r->b, true);
	advance(6000);
	mmsb_get_status(r->b, &st);
	CHECK_EQ(st.guard.accepted, 29);
	mmsb_want(r->b, false);
	advance(25000);
	brig_free(r);
}

static void t_gate(void)
{
	struct brig *r;
	struct addr a, b;
	int rc;

	evfake_reset();
	r = brig_new();
	addr_set(&a, "211.188.208.21", 9093);
	addr_set(&b, "211.188.197.41", 9093);
	CHECK_EQ(mmsb_gate(r->b, &a, done_cb, NULL), -ENETDOWN);	/* no bearer: nothing is allowed */
	mmsb_want(r->b, true);
	advance(500);
	CHECK(is_up(r));
	g_done = 0;
	rc = mmsb_gate(r->b, &a, done_cb, NULL);
	CHECK_EQ(rc, 1);
	CHECK_EQ(g_done, 0);					/* asynchronous */
	advance(100);
	CHECK_EQ(g_done, 1); CHECK_EQ(g_err, 0);
	CHECK(has(r, "GT:211.188.208.21 . 9093"));
	CHECK_EQ(mmsb_gate(r->b, &a, done_cb, NULL), 0);	/* already allowed */
	CHECK_EQ(mmsb_gate(r->b, &b, done_cb, NULL), 1);
	CHECK_EQ(mmsb_gate(r->b, &a, done_cb, NULL), 0);
	advance(100);
	CHECK(has(r, "GT:211.188.197.41 . 9093"));
	/* a refused allow-rule: the caller gets the error, nothing connects */
	r->exec_fail_gate = true;
	addr_set(&a, "203.0.113.5", 80);
	g_done = 0;
	CHECK_EQ(mmsb_gate(r->b, &a, done_cb, NULL), 1);
	advance(100);
	CHECK_EQ(g_done, 1); CHECK(g_err < 0);
	/* a cancelled waiter is not called */
	r->exec_fail_gate = false;
	addr_set(&a, "203.0.113.6", 80);
	g_done = 0;
	CHECK_EQ(mmsb_gate(r->b, &a, done_cb, &g_done), 1);
	mmsb_gate_cancel(r->b, &g_done);
	advance(100);
	CHECK_EQ(g_done, 0);
	mmsb_want(r->b, false);
	advance(25000);
	/* the table is gone with the bearer: the cached rules too */
	CHECK_EQ(mmsb_gate(r->b, &a, done_cb, NULL), -ENETDOWN);
	brig_free(r);
}

static void t_backoff_and_voice(void)
{
	struct brig *r;
	char *p;
	int n;

	/* a failed connect: retried after 5 s, 10 s, ... and the bearer of each attempt is deleted */
	evfake_reset();
	r = brig_new();
	r->connect_fail_n = 2;
	mmsb_want(r->b, true);
	advance(1000);
	CHECK(!is_up(r));
	CHECK_STR(state(r), "backoff");
	CHECK_EQ(r->live, 0);
	advance(3500);
	for (n = 0, p = r->log; (p = strstr(p, "CONNECT")) != NULL; p++)
		n++;
	CHECK_EQ(n, 1);					/* not yet at 4.5 s */
	advance(1000);
	for (n = 0, p = r->log; (p = strstr(p, "CONNECT")) != NULL; p++)
		n++;
	CHECK_EQ(n, 2);					/* after 5 s */
	advance(8000);
	for (n = 0, p = r->log; (p = strstr(p, "CONNECT")) != NULL; p++)
		n++;
	CHECK_EQ(n, 2);					/* the second wait is 10 s */
	advance(2500);
	CHECK(is_up(r));
	CHECK_EQ(r->max_live, 1);
	mmsb_want(r->b, false);
	advance(25000);
	brig_free(r);

	/* during a voice call the retry stays at 5 s and the connect works again right after the call */
	evfake_reset();
	r = brig_new();
	r->voice_call = true;
	r->connect_fail_n = 100;
	mmsb_want(r->b, true);
	advance(40000);
	for (n = 0, p = r->log; (p = strstr(p, "CONNECT")) != NULL; p++)
		n++;
	CHECK(n >= 6);
	r->voice_call = false;
	r->connect_fail_n = 0;
	advance(12000);
	CHECK(is_up(r));
	mmsb_want(r->b, false);
	advance(25000);
	brig_free(r);

	/* a connect that stalls past the timeout */
	evfake_reset();
	r = brig_new();
	r->connect_delay_ms = 100000;
	mmsb_want(r->b, true);
	advance(46000);
	CHECK(!is_up(r));
	CHECK(has(r, "DEL"));
	brig_free(r);
}

static void t_teardown_race(void)
{
	struct brig *r;

	/* work arrives while the bearer is being taken down: it waits for the end of the teardown and then starts a new bring-up */
	evfake_reset();
	r = brig_new();
	r->disc_delay_ms = 3000;
	mmsb_want(r->b, true);
	advance(500);
	CHECK(is_up(r));
	mmsb_want(r->b, false);
	advance(20500);					/* the linger is over, the disconnect is under way */
	CHECK_STR(state(r), "closing");
	CHECK(!has(r, "G- G+"));
	mmsb_want(r->b, true);
	advance(500);
	CHECK_STR(state(r), "closing");			/* not interrupted */
	CHECK_EQ(r->created, 1);
	advance(6000);
	CHECK(is_up(r));
	CHECK_EQ(r->created, 2);
	CHECK_EQ(r->max_live, 1);			/* never two bearers */
	CHECK(pos(r, "G- G+") > 0 || pos(r, "G-") < pos(r, "CREATE:lte.sktelecom.com:ipv4v6 CONNECT V6OFF GA:wwan0 NET+ NET-") + 200);
	mmsb_want(r->b, false);
	advance(30000);
	CHECK(!is_up(r));
	brig_free(r);
}

static void t_provider_switch_and_shutdown(void)
{
	struct brig *r;
	struct mmsb_link l;

	/* the provider is switched away (another backend / operator: no MMS APN any more): the bearer is released, nothing new is created */
	evfake_reset();
	r = brig_new();
	mmsb_want(r->b, true);
	advance(500);
	CHECK(is_up(r));
	r->prof_ok = false;
	mmsb_poke(r->b);
	advance(500);
	CHECK(!is_up(r));
	CHECK(has(r, "NET- V6ON DISC DEL G-"));
	mmsb_link(r->b, &l);
	CHECK(!l.available);
	CHECK(strstr(l.reason, "no MMS APN") != NULL);
	r->log[0] = 0;
	advance(5000);
	CHECK_STR(r->log, "");				/* wants it, but there is no bearer to bring up */
	r->prof_ok = true;
	mmsb_poke(r->b);
	advance(500);
	CHECK(is_up(r));
	/* another APN (uci) while up: released, then the new one is used */
	snprintf(r->apn, sizeof(r->apn), "mms.example");
	mmsb_poke(r->b);
	advance(1500);
	CHECK(has(r, "CREATE:mms.example:ipv4v6"));
	CHECK(is_up(r));
	CHECK_EQ(r->max_live, 1);
	/* the modem object goes away (modem restart): no remote cleanup is possible, the local state is dropped */
	r->log[0] = 0;
	r->modem[0] = 0;
	mmsb_poke(r->b);
	advance(500);
	CHECK(!is_up(r));
	CHECK(has(r, "NET-") && !has(r, "DISC") && has(r, "G-"));
	brig_free(r);

	/* shutdown while up: everything is released, done runs once, nothing is brought up again */
	evfake_reset();
	r = brig_new();
	mmsb_want(r->b, true);
	advance(500);
	CHECK(is_up(r));
	g_done = 0;
	mmsb_shutdown(r->b, shut_cb, NULL, 2500);
	advance(1000);
	CHECK_EQ(g_done, 1);
	CHECK(has(r, "NET- V6ON DISC DEL G-"));
	CHECK_EQ(r->live, 0);
	r->log[0] = 0;
	mmsb_want(r->b, true);
	advance(2000);
	CHECK_STR(r->log, "");
	brig_free(r);

	/* shutdown while idle: at once */
	evfake_reset();
	r = brig_new();
	g_done = 0;
	mmsb_shutdown(r->b, shut_cb, NULL, 2500);
	CHECK_EQ(g_done, 1);
	brig_free(r);

	/* shutdown in the middle of the bring-up */
	evfake_reset();
	r = brig_new();
	r->connect_delay_ms = 4000;
	mmsb_want(r->b, true);
	advance(300);
	g_done = 0;
	mmsb_shutdown(r->b, shut_cb, NULL, 2500);
	advance(2000);
	CHECK_EQ(g_done, 1);
	CHECK(!is_up(r));
	CHECK(has(r, "DEL") && has(r, "G-"));
	CHECK_EQ(r->live, 0);
	brig_free(r);
}

static void t_foreign(void)
{
	struct brig *r;
	struct mmsb_link l;
	struct mmsb_status st;

	/* netifd's wan holds a connected bearer of the same APN: it is not touched, MMS is unavailable, with a reason */
	evfake_reset();
	r = brig_new();
	snprintf(r->foreign_path, sizeof(r->foreign_path), "/bearer/wan");
	snprintf(r->foreign_apn, sizeof(r->foreign_apn), "%s", APN);
	snprintf(r->foreign_if, sizeof(r->foreign_if), "wwan0");
	mmsb_want(r->b, true);
	advance(1500);
	CHECK(!is_up(r));
	CHECK(!has(r, "CREATE") && !has(r, "CONNECT") && !has(r, "NET+"));
	CHECK(!r->foreign_touched);
	CHECK_STR(state(r), "blocked");
	mmsb_link(r->b, &l);
	CHECK(!l.available);
	CHECK(strstr(l.reason, "not touched") != NULL && strstr(l.reason, "wwan0") != NULL);
	mmsb_get_status(r->b, &st);
	CHECK_EQ(st.scans_blocked, 1);
	/* the wan goes away: the next look (30 s) brings MMS up */
	r->foreign_path[0] = 0;
	advance(31000);
	CHECK(is_up(r));
	mmsb_want(r->b, false);
	advance(25000);
	brig_free(r);

	/* another bearer (other APN) on the netdev our bearer comes up on: ours is released, the other one is left alone */
	evfake_reset();
	r = brig_new();
	snprintf(r->foreign_path, sizeof(r->foreign_path), "/bearer/wan");
	snprintf(r->foreign_apn, sizeof(r->foreign_apn), "internet");
	snprintf(r->foreign_if, sizeof(r->foreign_if), "wwan0");
	mmsb_want(r->b, true);
	advance(1500);
	CHECK(!is_up(r));
	CHECK(!has(r, "NET+") && !has(r, "GA:"));
	CHECK(has(r, "CONNECT") && has(r, "DISC") && has(r, "DEL"));
	CHECK(!r->foreign_touched);
	CHECK_EQ(r->live, 0);
	mmsb_link(r->b, &l);
	CHECK(strstr(l.reason, "wwan0") != NULL);
	brig_free(r);

	/* a disconnected other bearer on another netdev does not matter */
	evfake_reset();
	r = brig_new();
	snprintf(r->foreign_path, sizeof(r->foreign_path), "/bearer/wan");
	snprintf(r->foreign_apn, sizeof(r->foreign_apn), "internet");
	snprintf(r->foreign_if, sizeof(r->foreign_if), "wwan1");
	mmsb_want(r->b, true);
	advance(1500);
	CHECK(is_up(r));
	CHECK(!r->foreign_touched);
	mmsb_want(r->b, false);
	advance(25000);
	CHECK(!r->foreign_touched);
	brig_free(r);

	/* create_bearer answers with an existing bearer (same settings): it is not connected, not configured, not deleted */
	evfake_reset();
	r = brig_new();
	snprintf(r->foreign_path, sizeof(r->foreign_path), "/bearer/wan");
	snprintf(r->foreign_apn, sizeof(r->foreign_apn), "other");
	snprintf(r->foreign_if, sizeof(r->foreign_if), "wwan1");
	r->create_returns_foreign = true;
	mmsb_want(r->b, true);
	advance(1500);
	CHECK(!is_up(r));
	CHECK(has(r, "CREATE") && !has(r, "CONNECT") && !has(r, "DEL") && !has(r, "NET+"));
	CHECK(!r->foreign_touched);
	CHECK_STR(state(r), "blocked");
	brig_free(r);

	/* a bearer of an earlier run (the marker names it): disconnected and deleted before a new one is made */
	evfake_reset();
	r = brig_new();
	leftover_alive = true;
	snprintf(r->marker_modem, sizeof(r->marker_modem), "uqmid.modem.0");
	snprintf(r->marker_bearer, sizeof(r->marker_bearer), "/bearer/old");
	mmsb_want(r->b, true);
	advance(1500);
	CHECK(is_up(r));
	CHECK(pos(r, "DISC DEL") >= 0 && pos(r, "DISC DEL") < pos(r, "CREATE"));
	CHECK(!leftover_alive);
	CHECK_STR(r->marker_bearer, "/bearer/mms1");
	mmsb_want(r->b, false);
	advance(25000);
	brig_free(r);

	/* the same connected bearer WITHOUT a marker is somebody else's */
	evfake_reset();
	r = brig_new();
	leftover_alive = true;
	mmsb_want(r->b, true);
	advance(1500);
	CHECK(!is_up(r));
	CHECK(leftover_alive);
	CHECK_STR(state(r), "blocked");
	brig_free(r);
	leftover_alive = false;
}

static void t_variants(void)
{
	struct brig *r;
	struct mmsb_link l;

	/* a dual stack bearer keeps IPv6 on the netdev (the guard drops it anyway) */
	evfake_reset();
	r = brig_new();
	r->v6 = true;
	mmsb_want(r->b, true);
	advance(500);
	CHECK(is_up(r));
	CHECK(!has(r, "V6OFF"));
	mmsb_want(r->b, false);
	advance(25000);
	CHECK(!has(r, "V6ON"));
	brig_free(r);

	/* no modem yet / no MMS APN: unavailable with a reason, nothing is created */
	evfake_reset();
	r = brig_new();
	r->modem[0] = 0;
	mmsb_want(r->b, true);
	advance(2000);
	mmsb_link(r->b, &l);
	CHECK(!l.available); CHECK_STR(r->log, "");
	snprintf(r->modem, sizeof(r->modem), "uqmid.modem.0");
	mmsb_poke(r->b);
	advance(1000);
	CHECK(is_up(r));
	mmsb_want(r->b, false);
	advance(25000);
	brig_free(r);

	/* the IMSI is read through uqmid when the modem path is known; a failed read is retried */
	evfake_reset();
	r = brig_new();
	mmsb_poke(r->b);
	spin(20);
	CHECK_STR(mmsb_imsi(r->b), "450119876543210");
	r->modem[0] = 0;
	mmsb_poke(r->b);
	CHECK_STR(mmsb_imsi(r->b), "");
	r->imsi[0] = 0;
	snprintf(r->modem, sizeof(r->modem), "uqmid.modem.1");
	mmsb_poke(r->b);
	advance(1000);
	CHECK_STR(mmsb_imsi(r->b), "");
	snprintf(r->imsi, sizeof(r->imsi), "450051234567890");
	advance(6000);
	CHECK_STR(mmsb_imsi(r->b), "450051234567890");
	brig_free(r);

	/* the owner is told about every change from the loop, never from inside the call */
	evfake_reset();
	r = brig_new();
	spin(20);
	r->changed_n = 0;
	mmsb_want(r->b, true);
	CHECK_EQ(r->changed_n, 0);
	advance(500);
	CHECK(r->changed_n >= 1);
	mmsb_want(r->b, false);
	advance(25000);
	brig_free(r);
}

/* ---- the guard script and a real child process ---- */

static void t_guard_script(void)
{
	char s[2048];
	size_t n = mmsguard_script_install(s, sizeof(s));

	CHECK(n > 0 && n < sizeof(s));
	/* a table of its own, replaced atomically; nothing in fw4's table */
	CHECK(strstr(s, "add table inet imsd_mms\ndelete table inet imsd_mms\ntable inet imsd_mms {") == s);
	CHECK(strstr(s, "set ifs { type ifname; }") != NULL);
	CHECK(strstr(s, "type filter hook output priority -10; policy accept;\n\t\toifname @ifs jump mmsout") != NULL);
	CHECK(strstr(s, "ip daddr @dns4 udp dport 53 counter name \"acc\" accept") != NULL);
	CHECK(strstr(s, "ip daddr @dns4 tcp dport 53 counter name \"acc\" accept") != NULL);
	CHECK(strstr(s, "ip6 daddr @dns6 udp dport 53 counter name \"acc\" accept") != NULL);
	CHECK(strstr(s, "ip daddr . tcp dport @tcp4 counter name \"acc\" accept") != NULL);
	CHECK(strstr(s, "ip6 daddr . tcp dport @tcp6 counter name \"acc\" accept") != NULL);
	CHECK(strstr(s, "\t\tcounter name \"drp\" drop\n\t}\n\tchain mmsfwd") != NULL);	/* the last rule of the output chain drops everything else */
	CHECK(strstr(s, "type filter hook forward priority -10; policy accept;\n\t\tiifname @ifs counter name \"drp\" drop\n\t\toifname @ifs counter name \"drp\" drop") != NULL);
	/* no accept for anything but DNS and the allowed TCP set */
	{
		const char *p = s;
		int accepts = 0;

		while ((p = strstr(p, " accept")) != NULL) {
			accepts++;
			p++;
		}
		CHECK_EQ(accepts, 8);			/* six rules plus "policy accept" twice */
	}
}

static const char *mkdir_tmp(char *buf, size_t n)
{
	snprintf(buf, n, "/tmp/imsd-guard-XXXXXX");
	return mkdtemp(buf);
}

static void write_file(const char *path, const char *text, int mode)
{
	FILE *f = fopen(path, "w");

	CHECK(f != NULL);
	if (!f)
		return;
	fputs(text, f);
	fclose(f);
	chmod(path, mode);
}

static void spin_real(int *flag)
{
	int i;

	for (i = 0; i < 400 && !*flag; i++) {
		advance(100);
		usleep(3000);
	}
}

static char child_out[1024];
static int child_status = 99, child_done;

static void child_cb(void *arg, int status, const char *out)
{
	(void)arg;
	child_status = status;
	snprintf(child_out, sizeof(child_out), "%s", out);
	child_done++;
}

static void t_real_exec(void)
{
	char dir[64], path[128], old[1024], *oldp = getenv("PATH"), np[1200], got[512];
	const struct guard_exec_ops *x = guard_exec_real();
	const char *argv[] = { "nft", "-f", "-", NULL };
	const char *argv_l[] = { "nft", "list", "table", "inet", "imsd_mms", NULL };
	FILE *f;
	void *h;
	struct mmsguard *g;
	int i;

	snprintf(old, sizeof(old), "%s", oldp ? oldp : "/usr/bin:/bin");
	CHECK(mkdir_tmp(dir, sizeof(dir)) != NULL);
	snprintf(path, sizeof(path), "%s/nft", dir);
	write_file(path,
		   "#!/bin/sh\n"
		   "if [ \"$1\" = list ]; then printf 'table inet imsd_mms {\\n\\tcounter acc {\\n\\t\\tpackets 7 bytes 1\\n\\t}\\n}\\n'; exit 0; fi\n"
		   "cat > \"$(dirname \"$0\")/stdin\"\n"
		   "case \"$(cat \"$(dirname \"$0\")/stdin\")\" in *FAIL*) exit 3;; esac\n"
		   "exit 0\n", 0755);
	snprintf(np, sizeof(np), "%s:%s", dir, old);
	setenv("PATH", np, 1);
	evfake_reset();
	/* the script reaches the child's stdin, its exit status comes back, from the loop, without blocking */
	child_done = 0;
	h = x->run(x->ctx, argv, "add table inet imsd_mms\n", child_cb, NULL);
	CHECK(h != NULL);
	CHECK_EQ(child_done, 0);
	spin_real(&child_done);
	CHECK_EQ(child_done, 1); CHECK_EQ(child_status, 0);
	snprintf(path, sizeof(path), "%s/stdin", dir);
	f = fopen(path, "r");
	CHECK(f != NULL);
	if (f) {
		got[fread(got, 1, sizeof(got) - 1, f)] = 0;
		fclose(f);
		CHECK_STR(got, "add table inet imsd_mms\n");
	}
	child_done = 0;
	h = x->run(x->ctx, argv, "FAIL\n", child_cb, NULL);
	CHECK(h != NULL);
	spin_real(&child_done);
	CHECK_EQ(child_done, 1); CHECK_EQ(child_status, 3);
	/* a big script does not deadlock on the pipe */
	{
		char *big = malloc(300000);

		memset(big, 'x', 299999);
		big[299999] = 0;
		child_done = 0;
		h = x->run(x->ctx, argv, big, child_cb, NULL);
		CHECK(h != NULL);
		spin_real(&child_done);
		CHECK_EQ(child_done, 1); CHECK_EQ(child_status, 0);
		free(big);
	}
	child_done = 0;
	h = x->run(x->ctx, argv_l, NULL, child_cb, NULL);
	CHECK(h != NULL);
	spin_real(&child_done);
	CHECK_EQ(child_done, 1); CHECK_EQ(child_status, 0);
	CHECK(strstr(child_out, "packets 7") != NULL);
	/* a cancelled child never calls back */
	child_done = 0;
	h = x->run(x->ctx, argv, "FAIL\n", child_cb, NULL);
	x->cancel(x->ctx, h);
	for (i = 0; i < 20; i++) {
		advance(100);
		usleep(3000);
	}
	CHECK_EQ(child_done, 0);
	CHECK_EQ(evfake_fd_watches(), 0);
	/* the guard on top of the real runner: install, arm, a rule, remove */
	g = mmsguard_new(x, NULL, NULL);
	g_done = 0;
	CHECK_EQ(mmsguard_install(g, done_cb, NULL), 0);
	spin_real(&g_done);
	CHECK_EQ(g_done, 1); CHECK_EQ(g_err, 0);
	CHECK(mmsguard_installed(g));
	snprintf(path, sizeof(path), "%s/stdin", dir);
	f = fopen(path, "r");
	if (f) {
		char big2[4096];

		big2[fread(big2, 1, sizeof(big2) - 1, f)] = 0;
		fclose(f);
		CHECK(strstr(big2, "add table inet imsd_mms\ndelete table inet imsd_mms\ntable inet imsd_mms {") == big2);
	}
	{
		struct addr dns[2];

		addr_set(&dns[0], "223.62.230.7", 53);
		addr_set(&dns[1], "113.217.240.31", 53);
		g_done = 0;
		CHECK_EQ(mmsguard_arm(g, "wwan0", dns, 2, done_cb, NULL), 0);
		spin_real(&g_done);
		CHECK_EQ(g_done, 1); CHECK_EQ(g_err, 0);
		f = fopen(path, "r");
		if (f) {
			got[fread(got, 1, sizeof(got) - 1, f)] = 0;
			fclose(f);
			CHECK_STR(got, "add element inet imsd_mms ifs { \"wwan0\" }\nadd element inet imsd_mms dns4 { 223.62.230.7, 113.217.240.31 }\n");
		}
		CHECK_EQ(mmsguard_arm(g, "wwan0; flush ruleset", dns, 2, done_cb, NULL), -EINVAL);	/* nothing but a plain name goes into a script */
	}
	g_done = 0;
	mmsguard_remove(g, done_cb, NULL);
	spin_real(&g_done);
	CHECK_EQ(g_done, 1);
	{
		struct guard_stats gs;

		mmsguard_stats(g, &gs);
		CHECK(!gs.installed);
		CHECK_EQ(gs.accepted, 0);	/* the fake table listing has no drp counter: nothing is added */
	}
	mmsguard_free(g);
	/* nft is not there: fail closed, the error comes from the loop */
	setenv("PATH", "/nonexistent-imsd-test", 1);
	g = mmsguard_new(x, NULL, NULL);
	g_done = 0;
	g_err = 0;
	CHECK_EQ(mmsguard_install(g, done_cb, NULL), 0);
	CHECK_EQ(g_done, 0);
	spin_real(&g_done);
	CHECK_EQ(g_done, 1); CHECK(g_err < 0);
	CHECK(!mmsguard_installed(g));
	mmsguard_free(g);
	setenv("PATH", old, 1);
	snprintf(path, sizeof(path), "%s/nft", dir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/stdin", dir);
	unlink(path);
	rmdir(dir);
}

void test_mms_bearer(void)
{
	t_guard_script();
	t_lifecycle();
	t_guard_order_and_failures();
	t_gate();
	t_backoff_and_voice();
	t_teardown_race();
	t_provider_switch_and_shutdown();
	t_foreign();
	t_variants();
	t_real_exec();
}
