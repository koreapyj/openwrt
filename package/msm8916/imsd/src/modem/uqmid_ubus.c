/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * uqmid over ubus, see uqmid_ubus.h.
 *
 * Deviation from "no synchronous ubus": libubus exports no asynchronous
 * object lookup or subscribe, so ubus_lookup_id(), ubus_lookup() (wildcard,
 * for the sim.* and bearer.* objects) and ubus_subscribe() are used. They
 * are request/reply exchanges with ubusd, answered from memory, and never
 * wait for uqmid; every call to uqmid itself is asynchronous.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include "uqmid_ubus.h"
#include "../util/evloop.h"
#include "../util/log.h"

/* util/codec.h clashes with libubox/utils.h (b64_*): only the hex helpers are needed here */
int hex_decode(const char *s, uint8_t *out, size_t max);
void hex_encode(const uint8_t *in, size_t n, char *out);

#define MGR_RETRY_MS 2000

struct uqh {
	struct ubus_request req;
	struct uq_req rq;
	struct uq_res *res;
	uq_cb cb;
	void *arg;
	struct ev_timer *t;
	bool started;
};

static struct {
	struct ubus_context *ctx;
	struct imsmodem **target;
	struct ubus_subscriber mgr, mod;
	bool mgr_reg, mod_reg;
	bool mgr_sub, mod_sub;
	char mod_path[UQ_PATH];
	uint32_t mod_id;
	struct ev_timer *retry;
	void (*orig_lost)(struct ubus_context *ctx);
} U;

#define TARGET() (U.target ? *U.target : NULL)

/* ------------------------------------------------------------------ */
/* blob helpers                                                        */

static bool bm_int(struct blob_attr *a, int *v)
{
	switch (blobmsg_type(a)) {
	case BLOBMSG_TYPE_INT8: *v = blobmsg_get_u8(a); return true;
	case BLOBMSG_TYPE_INT16: *v = blobmsg_get_u16(a); return true;
	case BLOBMSG_TYPE_INT32: *v = (int)blobmsg_get_u32(a); return true;
	case BLOBMSG_TYPE_INT64: *v = (int)blobmsg_get_u64(a); return true;
	}
	return false;
}

static void bm_str(struct blob_attr *a, char *dst, size_t n)
{
	if (blobmsg_type(a) == BLOBMSG_TYPE_STRING)
		snprintf(dst, n, "%s", blobmsg_get_string(a));
}

/* one entry of get_cell_info "cells": the first serving LTE cell with a cell id is the one reported */
static void parse_cell(struct blob_attr *t, struct uq_res *r)
{
	struct blob_attr *cur;
	size_t rem;
	char type[12] = "", plmn[16] = "", tac[16] = "", ci[16] = "";
	bool serving = false, has_earfcn = false;
	int earfcn = 0;

	if (r->cell_valid || blobmsg_type(t) != BLOBMSG_TYPE_TABLE)
		return;
	blobmsg_for_each_attr(cur, t, rem) {
		const char *k = blobmsg_name(cur);

		if (!strcmp(k, "cell_type")) bm_str(cur, type, sizeof(type));
		else if (!strcmp(k, "serving") && blobmsg_type(cur) == BLOBMSG_TYPE_BOOL) serving = blobmsg_get_bool(cur);
		else if (!strcmp(k, "operator_id")) bm_str(cur, plmn, sizeof(plmn));
		else if (!strcmp(k, "tac")) bm_str(cur, tac, sizeof(tac));
		else if (!strcmp(k, "ci")) bm_str(cur, ci, sizeof(ci));
		else if (!strcmp(k, "earfcn") && bm_int(cur, &earfcn)) has_earfcn = true;
	}
	if (strcmp(type, "lte") || !serving || !plmn[0] || !tac[0] || !ci[0] || strlen(plmn) >= sizeof(r->cell_plmn))
		return;
	memcpy(r->cell_plmn, plmn, strlen(plmn) + 1);	/* the length was checked above */
	r->cell_tac = strtoul(tac, NULL, 16);
	r->cell_ci = strtoul(ci, NULL, 16);
	r->cell_has_earfcn = has_earfcn;
	r->cell_earfcn = earfcn;
	r->cell_valid = true;
}

static void parse_ipcfg(struct blob_attr *t, struct uq_ipcfg *c)
{
	struct blob_attr *cur;
	size_t rem;
	int v;

	if (blobmsg_type(t) != BLOBMSG_TYPE_TABLE)
		return;
	c->present = true;
	blobmsg_for_each_attr(cur, t, rem) {
		const char *k = blobmsg_name(cur);

		if (!strcmp(k, "address")) bm_str(cur, c->address, sizeof(c->address));
		else if (!strcmp(k, "gateway")) bm_str(cur, c->gateway, sizeof(c->gateway));
		else if (!strcmp(k, "dns1")) bm_str(cur, c->dns1, sizeof(c->dns1));
		else if (!strcmp(k, "dns2")) bm_str(cur, c->dns2, sizeof(c->dns2));
		else if (!strcmp(k, "prefix") && bm_int(cur, &v)) c->prefix = v;
		else if (!strcmp(k, "mtu") && bm_int(cur, &v)) c->mtu = v;
	}
}

/* ------------------------------------------------------------------ */
/* request completion                                                  */

static void uqh_free(struct uqh *h)
{
	ev_timer_free(h->t);
	free(h->res);
	free(h);
}

static void uqh_finish(struct uqh *h)
{
	uq_cb cb = h->cb;
	void *arg = h->arg;
	struct uq_res *res = h->res;

	h->res = NULL;
	uqh_free(h);
	cb(arg, res);
	free(res);
}

static void uqh_timer(void *arg)
{
	uqh_finish(arg);
}

/* immediate failure: completed from a zero timer, never inside call() */
static void *uqh_fail(struct uqh *h, int err, const char *msg)
{
	h->res->err = err;
	snprintf(h->res->errmsg, sizeof(h->res->errmsg), "%s", msg);
	ev_timer_set(h->t, 0);
	return h;
}

static void data_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct uqh *h = req->priv;
	struct uq_res *r = h->res;
	struct blob_attr *cur, *e;
	size_t rem, rem2;
	int v;

	(void)type;
	blobmsg_for_each_attr(cur, msg, rem) {
		const char *k = blobmsg_name(cur);

		/* error replies of uqmid: {"error", "message", "connection_error": {name, message}} */
		if (!strcmp(k, "message")) {
			bm_str(cur, r->errmsg, sizeof(r->errmsg));
			continue;
		}
		if (!strcmp(k, "connection_error") && blobmsg_type(cur) == BLOBMSG_TYPE_TABLE) {
			blobmsg_for_each_attr(e, cur, rem2)
				if (!strcmp(blobmsg_name(e), "message") && blobmsg_type(e) == BLOBMSG_TYPE_STRING)
					snprintf(r->errmsg, sizeof(r->errmsg), "%s", blobmsg_get_string(e));
			continue;
		}
		switch (h->rq.op) {
		case UQ_LIST:
			if (!strcmp(k, "modems") && blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY)
				blobmsg_for_each_attr(e, cur, rem2) {
					struct blob_attr *f;
					size_t rem3;

					if (r->n_modems >= UQ_MAX_MODEMS || blobmsg_type(e) != BLOBMSG_TYPE_TABLE)
						continue;
					blobmsg_for_each_attr(f, e, rem3) {
						const char *fk = blobmsg_name(f);

						if (!strcmp(fk, "path")) bm_str(f, r->modems[r->n_modems].path, UQ_PATH);
						else if (!strcmp(fk, "device")) bm_str(f, r->modems[r->n_modems].device, sizeof(r->modems[0].device));
						else if (!strcmp(fk, "state")) bm_str(f, r->modems[r->n_modems].state, sizeof(r->modems[0].state));
					}
					r->n_modems++;
				}
			break;
		case UQ_MODEM_GET:
			if (!strcmp(k, "state")) bm_str(cur, r->state, sizeof(r->state));
			else if (!strcmp(k, "imei")) bm_str(cur, r->imei, sizeof(r->imei));
			else if (!strcmp(k, "bearers") && blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY) {
				blobmsg_for_each_attr(e, cur, rem2) {
					if (r->n_bearer_paths < UQ_MAX_BEARERS && blobmsg_type(e) == BLOBMSG_TYPE_STRING)
						snprintf(r->bearer_paths[r->n_bearer_paths++], UQ_PATH, "%s", blobmsg_get_string(e));
				}
			}
			break;
		case UQ_SIM_GET:
			if (!strcmp(k, "imsi")) bm_str(cur, r->imsi, sizeof(r->imsi));
			else if (!strcmp(k, "sim_identifier")) bm_str(cur, r->iccid, sizeof(r->iccid));
			break;
		case UQ_CREATE_BEARER:
			if (!strcmp(k, "path")) bm_str(cur, r->path, sizeof(r->path));
			break;
		case UQ_BEARER_GET:
			if (!strcmp(k, "status")) bm_str(cur, r->status, sizeof(r->status));
			else if (!strcmp(k, "interface")) bm_str(cur, r->ifname, sizeof(r->ifname));
			else if (!strcmp(k, "connected") && blobmsg_type(cur) == BLOBMSG_TYPE_BOOL) r->connected = blobmsg_get_bool(cur);
			else if (!strcmp(k, "ip4_config")) parse_ipcfg(cur, &r->ip4);
			else if (!strcmp(k, "ip6_config")) parse_ipcfg(cur, &r->ip6);
			else if (!strcmp(k, "pcscf") && blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY) {
				blobmsg_for_each_attr(e, cur, rem2) {
					if (r->n_pcscf < UQ_MAX_PCSCF && blobmsg_type(e) == BLOBMSG_TYPE_STRING)
						snprintf(r->pcscf[r->n_pcscf++], sizeof(r->pcscf[0]), "%s", blobmsg_get_string(e));
				}
			} else if (!strcmp(k, "properties") && blobmsg_type(cur) == BLOBMSG_TYPE_TABLE) {
				blobmsg_for_each_attr(e, cur, rem2) {
					if (!strcmp(blobmsg_name(e), "apn")) bm_str(e, r->apn, sizeof(r->apn));
					else if (!strcmp(blobmsg_name(e), "ip_type")) bm_str(e, r->ip_type, sizeof(r->ip_type));
				}
			}
			break;
		case UQ_CHAN_OPEN:
			if (!strcmp(k, "channel_id") && bm_int(cur, &v)) r->channel = v;
			else if (!strcmp(k, "sw1") && bm_int(cur, &v)) r->sw1 = v;
			else if (!strcmp(k, "sw2") && bm_int(cur, &v)) r->sw2 = v;
			break;
		case UQ_APDU:
			if (!strcmp(k, "response") && blobmsg_type(cur) == BLOBMSG_TYPE_STRING) {
				int n = hex_decode(blobmsg_get_string(cur), r->data, sizeof(r->data));

				if (n < 0)
					r->err = UQ_E_BAD;
				else
					r->n = n;
			}
			break;
		case UQ_CELL_INFO:
			if (!strcmp(k, "cells") && blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY)
				blobmsg_for_each_attr(e, cur, rem2)
					parse_cell(e, r);
			break;
		default:
			break;
		}
	}
}

static int map_status(int ret)
{
	switch (ret) {
	case UBUS_STATUS_OK: return UQ_OK;
	case UBUS_STATUS_NOT_FOUND:
	case UBUS_STATUS_METHOD_NOT_FOUND: return UQ_E_GONE;
	case UBUS_STATUS_PERMISSION_DENIED: return UQ_E_STATE;
	case UBUS_STATUS_TIMEOUT: return UQ_E_TIMEOUT;
	case UBUS_STATUS_CONNECTION_FAILED: return UQ_E_CONN;
	default: return UQ_E_FAILED;
	}
}

static void complete_cb(struct ubus_request *req, int ret)
{
	struct uqh *h = req->priv;

	if (!h->res->err)
		h->res->err = map_status(ret);
	if (h->res->err && !h->res->errmsg[0])
		snprintf(h->res->errmsg, sizeof(h->res->errmsg), "%s", ubus_strerror(ret));
	h->started = false;
	uqh_finish(h);
}

/* ------------------------------------------------------------------ */
/* object lookup helpers                                               */

struct find_ctx {
	char path[UQ_PATH];
	bool found;
};

static void find_first_cb(struct ubus_context *ctx, struct ubus_object_data *o, void *priv)
{
	struct find_ctx *f = priv;

	(void)ctx;
	if (!f->found && o->path) {
		snprintf(f->path, sizeof(f->path), "%s", o->path);
		f->found = true;
	}
}

static bool find_object(const char *pattern, char *out, size_t n)
{
	struct find_ctx f = { .found = false };

	if (ubus_lookup(U.ctx, pattern, find_first_cb, &f) || !f.found)
		return false;
	snprintf(out, n, "%s", f.path);
	return true;
}

/* ------------------------------------------------------------------ */
/* calls                                                               */

static void *uq_call(void *ctx_unused, const struct uq_req *rq, uq_cb cb, void *arg)
{
	struct uqh *h = calloc(1, sizeof(*h));
	struct blob_buf bb = {};
	char path[UQ_PATH + 24], hex[2 * UQ_DATA_MAX + 1];
	const char *method = NULL;
	uint32_t id;
	int r;

	(void)ctx_unused;
	if (!h)
		return NULL;
	h->rq = *rq;
	h->cb = cb;
	h->arg = arg;
	h->res = calloc(1, sizeof(*h->res));
	h->t = ev_timer_new(uqh_timer, h);
	if (!h->res || !h->t) {
		uqh_free(h);
		return NULL;
	}
	if (!U.ctx)
		return uqh_fail(h, UQ_E_CONN, "no ubus connection");

	snprintf(path, sizeof(path), "%s", rq->obj);
	switch (rq->op) {
	case UQ_LIST: snprintf(path, sizeof(path), "uqmid"); method = "list"; break;
	case UQ_MODEM_GET: method = "get"; break;
	case UQ_SIM_GET: {
		char pat[UQ_PATH + 8];

		snprintf(pat, sizeof(pat), "%s.sim.*", rq->obj);
		if (!find_object(pat, path, sizeof(path)))
			return uqh_fail(h, UQ_E_GONE, "no sim object");
		method = "get";
		break;
	}
	case UQ_ENABLE: method = "enable"; break;
	case UQ_CREATE_BEARER: method = "create_bearer"; break;
	case UQ_BEARER_CONNECT: method = "connect"; break;
	case UQ_BEARER_GET: method = "get"; break;
	case UQ_BEARER_DISCONNECT: method = "disconnect"; break;
	case UQ_DELETE_BEARER: method = "delete_bearer"; break;
	case UQ_CHAN_OPEN: method = "uim_channel_open"; break;
	case UQ_APDU: method = "uim_apdu_send"; break;
	case UQ_CHAN_CLOSE: method = "uim_channel_close"; break;
	case UQ_CELL_INFO: method = "get_cell_info"; break;
	}
	if (!method)
		return uqh_fail(h, UQ_E_BAD, "unknown operation");

	blob_buf_init(&bb, 0);
	switch (rq->op) {
	case UQ_ENABLE: blobmsg_add_u8(&bb, "enable", rq->flag); break;
	case UQ_CREATE_BEARER:
		blobmsg_add_string(&bb, "apn", rq->str);
		blobmsg_add_string(&bb, "ip_type", rq->str2);
		if (rq->num > 0)		/* 0 = no profile (the on-demand MMS bearer: APN and IP type only) */
			blobmsg_add_u32(&bb, "profile_id", rq->num);
		break;
	case UQ_DELETE_BEARER: blobmsg_add_string(&bb, "path", rq->str); break;
	case UQ_CHAN_OPEN: blobmsg_add_string(&bb, "aid", rq->str); break;
	case UQ_CHAN_CLOSE: blobmsg_add_u32(&bb, "channel_id", rq->num); break;
	case UQ_APDU:
		hex_encode(rq->data, rq->n, hex);
		blobmsg_add_u32(&bb, "channel_id", rq->num);
		blobmsg_add_string(&bb, "apdu", hex);
		break;
	default: break;
	}

	if (ubus_lookup_id(U.ctx, path, &id)) {
		blob_buf_free(&bb);
		return uqh_fail(h, UQ_E_GONE, "object not found");
	}
	r = ubus_invoke_async(U.ctx, id, method, bb.head, &h->req);
	blob_buf_free(&bb);
	if (r)
		return uqh_fail(h, map_status(r) ? map_status(r) : UQ_E_FAILED, ubus_strerror(r));
	h->req.priv = h;
	h->req.data_cb = data_cb;
	h->req.complete_cb = complete_cb;
	h->started = true;
	ubus_complete_request_async(U.ctx, &h->req);
	return h;
}

static void uq_cancel(void *ctx_unused, void *handle)
{
	struct uqh *h = handle;

	(void)ctx_unused;
	if (h->started && U.ctx)
		ubus_abort_request(U.ctx, &h->req);
	uqh_free(h);
}

/* ------------------------------------------------------------------ */
/* subscriptions                                                       */

static int mgr_notify(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		      const char *method, struct blob_attr *msg)
{
	struct blob_attr *cur;
	size_t rem;
	char path[UQ_PATH] = "", device[96] = "";
	struct imsmodem *m = TARGET();

	(void)ctx; (void)obj; (void)req;
	blobmsg_for_each_attr(cur, msg, rem) {
		if (!strcmp(blobmsg_name(cur), "path")) bm_str(cur, path, sizeof(path));
		else if (!strcmp(blobmsg_name(cur), "device")) bm_str(cur, device, sizeof(device));
	}
	LOGD("uqmid: %s %s", method, path);
	if (!m || !path[0])
		return 0;
	if (!strcmp(method, "modem.added"))
		imsmodem_ev_modem_added(m, path, device);
	else if (!strcmp(method, "modem.removed"))
		imsmodem_ev_modem_removed(m, path);
	return 0;
}

static int mod_notify(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		      const char *method, struct blob_attr *msg)
{
	struct blob_attr *cur;
	size_t rem;
	char path[UQ_PATH] = "", nstate[16] = "";
	struct imsmodem *m = TARGET();

	(void)ctx; (void)obj; (void)req;
	if (!m)
		return 0;
	blobmsg_for_each_attr(cur, msg, rem) {
		if (!strcmp(blobmsg_name(cur), "path")) bm_str(cur, path, sizeof(path));
		else if (!strcmp(blobmsg_name(cur), "new")) bm_str(cur, nstate, sizeof(nstate));
	}
	LOGD("uqmid: %s %s%s", method, path, nstate);
	if (!strcmp(method, "state_changed") && nstate[0])
		imsmodem_ev_state(m, U.mod_path, nstate);
	else if (!strcmp(method, "bearer.connected"))
		imsmodem_ev_bearer(m, U.mod_path, path, true);
	else if (!strcmp(method, "bearer.disconnected"))
		imsmodem_ev_bearer(m, U.mod_path, path, false);
	return 0;
}

static void manager_try(void *arg);

static void mgr_removed(struct ubus_context *ctx, struct ubus_subscriber *s, uint32_t id)
{
	struct imsmodem *m = TARGET();

	(void)ctx; (void)s; (void)id;
	LOGW("uqmid: the uqmid object disappeared");
	U.mgr_sub = false;
	U.mod_sub = false;
	if (m)
		imsmodem_uqmid_up(m, false);
	ev_timer_set(U.retry, MGR_RETRY_MS);
}

static void mod_removed(struct ubus_context *ctx, struct ubus_subscriber *s, uint32_t id)
{
	struct imsmodem *m = TARGET();

	(void)ctx; (void)s; (void)id;
	U.mod_sub = false;
	if (m && U.mod_path[0])
		imsmodem_ev_modem_removed(m, U.mod_path);
}

static void uq_watch_modem(void *ctx_unused, const char *path)
{
	uint32_t id;

	(void)ctx_unused;
	if (U.ctx && U.mod_sub && U.mod_id) {
		ubus_unsubscribe(U.ctx, &U.mod, U.mod_id);
		U.mod_sub = false;
	}
	U.mod_path[0] = 0;
	U.mod_id = 0;
	if (!path || !path[0] || !U.ctx)
		return;
	snprintf(U.mod_path, sizeof(U.mod_path), "%s", path);
	if (ubus_lookup_id(U.ctx, path, &id)) {
		LOGW("uqmid: cannot find %s to follow its notifications", path);
		return;
	}
	if (ubus_subscribe(U.ctx, &U.mod, id)) {
		LOGW("uqmid: cannot subscribe to %s", path);
		return;
	}
	U.mod_id = id;
	U.mod_sub = true;
	LOGD("uqmid: following %s", path);
}

static void manager_try(void *arg)
{
	uint32_t id;
	struct imsmodem *m = TARGET();

	(void)arg;
	if (!U.ctx || U.mgr_sub)
		return;
	if (ubus_lookup_id(U.ctx, "uqmid", &id) || ubus_subscribe(U.ctx, &U.mgr, id)) {
		ev_timer_set(U.retry, MGR_RETRY_MS);
		return;
	}
	U.mgr_sub = true;
	LOGI("uqmid: found, subscribed to modem.added / modem.removed");
	if (m)
		imsmodem_uqmid_up(m, true);
}

static void conn_lost(struct ubus_context *ctx)
{
	struct imsmodem *m = TARGET();

	LOGW("ubus: connection lost");
	U.ctx = NULL;
	U.mgr_sub = U.mod_sub = false;
	U.mgr_reg = U.mod_reg = false;
	ev_timer_cancel(U.retry);
	if (m)
		imsmodem_uqmid_up(m, false);
	if (U.orig_lost)
		U.orig_lost(ctx);
}

void uqb_init(struct imsmodem **target)
{
	memset(&U, 0, sizeof(U));
	U.target = target;
	U.mgr.cb = mgr_notify;
	U.mgr.remove_cb = mgr_removed;
	U.mod.cb = mod_notify;
	U.mod.remove_cb = mod_removed;
	U.retry = ev_timer_new(manager_try, NULL);
}

void uqb_on_connect(struct ubus_context *ctx)
{
	U.ctx = ctx;
	U.mgr_sub = U.mod_sub = false;
	U.orig_lost = ctx->connection_lost;
	if (U.orig_lost != conn_lost)
		ctx->connection_lost = conn_lost;
	else
		U.orig_lost = NULL;
	if (!(U.mgr_reg = !ubus_register_subscriber(ctx, &U.mgr)))
		LOGE("uqmid: cannot register the manager subscriber");
	if (!(U.mod_reg = !ubus_register_subscriber(ctx, &U.mod)))
		LOGE("uqmid: cannot register the modem subscriber");
	manager_try(NULL);
}

void uqb_resync(struct ubus_context *ctx)
{
	struct imsmodem *m = TARGET();

	if (!U.ctx) {		/* never connected: the subscribers are not registered yet */
		uqb_on_connect(ctx);
		return;
	}
	if (U.mgr_sub) {
		if (m)
			imsmodem_uqmid_up(m, true);	/* a new imsmodem: it lists the modems itself */
	} else {
		manager_try(NULL);
	}
}

static const struct uq_ops ops = { .call = uq_call, .cancel = uq_cancel, .watch_modem = uq_watch_modem };

const struct uq_ops *uqb_ops(void)
{
	return &ops;
}

void uqb_shutdown(void)
{
	ev_timer_free(U.retry);
	U.retry = NULL;
	U.ctx = NULL;
}
