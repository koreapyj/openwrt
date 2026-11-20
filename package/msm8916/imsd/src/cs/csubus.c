/* SPDX-License-Identifier: GPL-2.0-or-later */
/* uqmid over ubus for the circuit switched backend, see csubus.h. Structure after modem/uqmid_ubus.c. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include "csubus.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

/* util/codec.h clashes with libubox/utils.h (b64_*): only the hex helpers are needed here */
int hex_decode(const char *s, uint8_t *out, size_t max);
void hex_encode(const uint8_t *in, size_t n, char *out);

#define MGR_RETRY_MS 2000

struct csh {
	struct ubus_request req;
	struct csu_req rq;
	char *text;
	uint8_t *data;
	struct csu_res *res;
	csu_cb cb;
	void *arg;
	struct ev_timer *t;
	bool started;
};

static struct {
	struct ubus_context *ctx;
	struct csline **target;
	struct ubus_subscriber mgr, mod;
	bool mgr_sub, mod_sub;
	char mod_path[CSU_PATH];
	uint32_t mod_id;
	struct ev_timer *retry;
	void (*orig_lost)(struct ubus_context *ctx);
} U;

#define TARGET() (U.target ? *U.target : NULL)

/* ------------------------------------------------------------------ blob helpers */

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

/* "end_reason": {"value": 146, "name": "user-busy"} */
static void end_reason_parse(struct blob_attr *t, int *value, char *name, size_t n)
{
	struct blob_attr *e;
	size_t rem;

	if (blobmsg_type(t) != BLOBMSG_TYPE_TABLE)
		return;
	blobmsg_for_each_attr(e, t, rem) {
		const char *k = blobmsg_name(e);

		if (!strcmp(k, "value") && bm_int(e, value)) { /* parsed */ }
		else if (!strcmp(k, "name")) bm_str(e, name, n);
	}
}

static bool bm_bool(struct blob_attr *a)
{
	return blobmsg_type(a) == BLOBMSG_TYPE_BOOL ? blobmsg_get_bool(a) : (blobmsg_type(a) != BLOBMSG_TYPE_STRING && blobmsg_get_u8(a));
}

static void path_array(struct blob_attr *cur, struct csu_res *r)
{
	struct blob_attr *e;
	size_t rem;

	blobmsg_for_each_attr(e, cur, rem)
		if (r->n_paths < CSU_MAX_PATHS && blobmsg_type(e) == BLOBMSG_TYPE_STRING)
			snprintf(r->paths[r->n_paths++], CSU_PATH, "%s", blobmsg_get_string(e));
}

/* ------------------------------------------------------------------ completion */

static void csh_free(struct csh *h)
{
	ev_timer_free(h->t);
	free(h->res);
	free(h->text);
	free(h->data);
	free(h);
}

static void csh_finish(struct csh *h)
{
	csu_cb cb = h->cb;
	void *arg = h->arg;
	struct csu_res *res = h->res;

	h->res = NULL;
	csh_free(h);
	cb(arg, res);
	free(res);
}

static void csh_timer(void *arg)
{
	csh_finish(arg);
}

static void *csh_fail(struct csh *h, int err, const char *msg)
{
	h->res->err = err;
	snprintf(h->res->errmsg, sizeof(h->res->errmsg), "%s", msg);
	ev_timer_set(h->t, 0);
	return h;
}

static void data_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct csh *h = req->priv;
	struct csu_res *r = h->res;
	struct blob_attr *cur, *e;
	size_t rem, rem2;
	int v;

	(void)type;
	blobmsg_for_each_attr(cur, msg, rem) {
		const char *k = blobmsg_name(cur);

		/* error replies of uqmid: {"error": name, "message": text} (uqmid/ubus.c:uqmid_ubus_reply_error) */
		if (!strcmp(k, "error")) {
			bm_str(cur, r->errname, sizeof(r->errname));
			continue;
		}
		if (!strcmp(k, "message")) {
			bm_str(cur, r->errmsg, sizeof(r->errmsg));
			continue;
		}
		switch (h->rq.op) {
		case CSU_LIST:
			if (!strcmp(k, "modems") && blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY)
				blobmsg_for_each_attr(e, cur, rem2) {
					struct blob_attr *f;
					size_t rem3;

					if (r->n_modems >= CSU_MAX_MODEMS || blobmsg_type(e) != BLOBMSG_TYPE_TABLE)
						continue;
					blobmsg_for_each_attr(f, e, rem3) {
						const char *fk = blobmsg_name(f);

						if (!strcmp(fk, "path")) bm_str(f, r->modems[r->n_modems].path, CSU_PATH);
						else if (!strcmp(fk, "device")) bm_str(f, r->modems[r->n_modems].device, sizeof(r->modems[0].device));
						else if (!strcmp(fk, "state")) bm_str(f, r->modems[r->n_modems].state, sizeof(r->modems[0].state));
					}
					r->n_modems++;
				}
			break;
		case CSU_MODEM_GET:
			if (!strcmp(k, "state")) bm_str(cur, r->state, sizeof(r->state));
			else if (!strcmp(k, "power_state")) bm_str(cur, r->power_state, sizeof(r->power_state));
			else if (!strcmp(k, "registration_state")) bm_str(cur, r->reg_state, sizeof(r->reg_state));
			else if (!strcmp(k, "operator_code")) bm_str(cur, r->operator_code, sizeof(r->operator_code));
			else if (!strcmp(k, "operator_name")) bm_str(cur, r->operator_name, sizeof(r->operator_name));
			else if (!strcmp(k, "emergency_only")) r->emergency_only = bm_bool(cur);
			else if (!strcmp(k, "access_technologies") && blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY) {
				blobmsg_for_each_attr(e, cur, rem2) {
					size_t n = strlen(r->act);

					if (blobmsg_type(e) == BLOBMSG_TYPE_STRING && n + 2 < sizeof(r->act))
						snprintf(r->act + n, sizeof(r->act) - n, "%s%s", n ? " " : "", blobmsg_get_string(e));
				}
			} else if (!strcmp(k, "own_numbers") && blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY) {
				blobmsg_for_each_attr(e, cur, rem2) {
					if (!r->own_number[0])
						bm_str(e, r->own_number, sizeof(r->own_number));
				}
			}
			break;
		case CSU_CALL_CREATE:
		case CSU_SMS_CREATE:
			if (!strcmp(k, "path")) bm_str(cur, r->path, sizeof(r->path));
			break;
		case CSU_CALL_GET:
			if (!strcmp(k, "state")) bm_str(cur, r->call_state, sizeof(r->call_state));
			else if (!strcmp(k, "state_reason")) bm_str(cur, r->call_reason, sizeof(r->call_reason));
			else if (!strcmp(k, "direction")) bm_str(cur, r->call_dir, sizeof(r->call_dir));
			else if (!strcmp(k, "number")) bm_str(cur, r->call_number, sizeof(r->call_number));
			else if (!strcmp(k, "qmi_call_id") && bm_int(cur, &v)) r->call_qmi_id = v;
			else if (!strcmp(k, "cc_cause") && bm_int(cur, &v)) r->end_cause = v;	/* only when the modem sent one */
			else if (!strcmp(k, "end_reason")) end_reason_parse(cur, &r->end_reason, r->end_reason_name, sizeof(r->end_reason_name));
			break;
		case CSU_CALL_LIST:
			if (!strcmp(k, "calls") && blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY)
				path_array(cur, r);
			break;
		case CSU_SMS_LIST:
			if (!strcmp(k, "messages") && blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY)
				path_array(cur, r);
			break;
		case CSU_SMS_GET:
			if (!strcmp(k, "state")) bm_str(cur, r->sms_state, sizeof(r->sms_state));
			else if (!strcmp(k, "pdu_type")) bm_str(cur, r->sms_pdu, sizeof(r->sms_pdu));
			else if (!strcmp(k, "number")) bm_str(cur, r->sms_number, sizeof(r->sms_number));
			else if (!strcmp(k, "timestamp")) bm_str(cur, r->sms_timestamp, sizeof(r->sms_timestamp));
			else if (!strcmp(k, "discharge_timestamp")) bm_str(cur, r->sms_discharge, sizeof(r->sms_discharge));
			else if (!strcmp(k, "text") && blobmsg_type(cur) == BLOBMSG_TYPE_STRING) {
				const char *t = blobmsg_get_string(cur);

				r->sms_has_text = true;
				if (strlen(t) >= sizeof(r->sms_text))
					r->sms_text_cut = true;
				snprintf(r->sms_text, sizeof(r->sms_text), "%s", t);
			} else if (!strcmp(k, "data") && blobmsg_type(cur) == BLOBMSG_TYPE_STRING) {
				int n = hex_decode(blobmsg_get_string(cur), r->sms_data, sizeof(r->sms_data));

				if (n < 0) {
					r->sms_text_cut = true;		/* too long for the buffer (or not hex): flagged, what fits is kept */
					n = (int)(strlen(blobmsg_get_string(cur)) / 2 < sizeof(r->sms_data) ? 0 : sizeof(r->sms_data));
				}
				r->sms_has_data = true;
				r->sms_data_len = (size_t)n;
			} else if (!strcmp(k, "class") && bm_int(cur, &v)) r->sms_class = (v < 0 || v > 3) ? -1 : v;
			else if (!strcmp(k, "multipart")) r->sms_multipart = bm_bool(cur);
			else if (!strcmp(k, "max_parts") && bm_int(cur, &v)) r->sms_max_parts = v;
			else if (!strcmp(k, "received_parts") && bm_int(cur, &v)) r->sms_parts = v;
			else if (!strcmp(k, "message_reference") && bm_int(cur, &v)) r->sms_msgref = (unsigned)v;
			else if (!strcmp(k, "delivery_state") && bm_int(cur, &v)) r->sms_delivery_state = (unsigned)v;
			break;
		default:
			break;
		}
	}
}

static int map_status(int ret)
{
	switch (ret) {
	case UBUS_STATUS_OK: return CSU_OK;
	case UBUS_STATUS_NOT_FOUND:
	case UBUS_STATUS_METHOD_NOT_FOUND: return CSU_E_GONE;
	case UBUS_STATUS_PERMISSION_DENIED: return CSU_E_STATE;
	case UBUS_STATUS_INVALID_ARGUMENT: return CSU_E_ARGS;
	case UBUS_STATUS_TIMEOUT: return CSU_E_TIMEOUT;
	case UBUS_STATUS_CONNECTION_FAILED: return CSU_E_CONN;
	default: return CSU_E_FAILED;
	}
}

static void complete_cb(struct ubus_request *req, int ret)
{
	struct csh *h = req->priv;

	if (!h->res->err)
		h->res->err = map_status(ret);
	/* uqmid's own "in-progress" is a plain UNKNOWN_ERROR on the wire; its name tells */
	if (h->res->err == CSU_E_FAILED && !strcmp(h->res->errname, "in-progress"))
		h->res->err = CSU_E_BUSY;
	if (h->res->err && !h->res->errmsg[0])
		snprintf(h->res->errmsg, sizeof(h->res->errmsg), "%s", ubus_strerror(ret));
	h->started = false;
	csh_finish(h);
}

/* ------------------------------------------------------------------ calls */

static void *cs_call(void *ctx_unused, const struct csu_req *rq, csu_cb cb, void *arg)
{
	struct csh *h = calloc(1, sizeof(*h));
	struct blob_buf bb = {};
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
	h->t = ev_timer_new(csh_timer, h);
	if (!h->res || !h->t) {
		csh_free(h);
		return NULL;
	}
	h->res->sms_class = -1;
	if (rq->text) {
		h->text = strdup(rq->text);
		h->rq.text = h->text;
	}
	if (rq->data && rq->data_len) {
		h->data = malloc(rq->data_len);
		if (h->data)
			memcpy(h->data, rq->data, rq->data_len);
		h->rq.data = h->data;
	}
	if ((rq->text && !h->text) || (rq->data && rq->data_len && !h->data)) {
		csh_free(h);
		return NULL;
	}
	if (!U.ctx)
		return csh_fail(h, CSU_E_CONN, "no ubus connection");

	switch (rq->op) {
	case CSU_ENABLE: method = "enable"; break;
	case CSU_LIST: method = "list"; break;
	case CSU_MODEM_GET: case CSU_CALL_GET: case CSU_SMS_GET: method = "get"; break;
	case CSU_CALL_CREATE: method = "voice_create_call"; break;
	case CSU_CALL_START: method = "start"; break;
	case CSU_CALL_ACCEPT: method = "accept"; break;
	case CSU_CALL_HANGUP: method = "hangup"; break;
	case CSU_CALL_DTMF: method = "send_dtmf"; break;
	case CSU_CALL_DELETE: method = "voice_delete_call"; break;
	case CSU_CALL_LIST: method = "voice_list_calls"; break;
	case CSU_SMS_CREATE: method = "messaging_create"; break;
	case CSU_SMS_SEND: method = "send"; break;
	case CSU_SMS_DELETE: method = "messaging_delete"; break;
	case CSU_SMS_LIST: method = "messaging_list"; break;
	}
	if (!method)
		return csh_fail(h, CSU_E_BAD, "unknown operation");

	blob_buf_init(&bb, 0);
	switch (rq->op) {
	case CSU_ENABLE: blobmsg_add_u8(&bb, "enable", rq->flag); break;
	case CSU_CALL_CREATE: blobmsg_add_string(&bb, "number", rq->str); break;
	case CSU_CALL_DTMF: blobmsg_add_string(&bb, "dtmf", rq->str); break;
	case CSU_CALL_DELETE:
	case CSU_SMS_DELETE: blobmsg_add_string(&bb, "path", rq->str); break;
	case CSU_SMS_CREATE:
		blobmsg_add_string(&bb, "number", rq->str);
		if (h->rq.text) {
			blobmsg_add_string(&bb, "text", h->rq.text);
		} else if (h->rq.data) {
			char *hex = malloc(2 * rq->data_len + 1);

			if (hex) {
				hex_encode(h->rq.data, rq->data_len, hex);
				blobmsg_add_string(&bb, "data", hex);
				free(hex);
			}
		}
		if (rq->sms_class >= 0)
			blobmsg_add_u32(&bb, "class", (uint32_t)rq->sms_class);
		if (rq->dra)
			blobmsg_add_u8(&bb, "delivery_report_request", 1);
		if (rq->validity_min)
			blobmsg_add_u32(&bb, "validity", rq->validity_min);
		break;
	default: break;
	}

	if (ubus_lookup_id(U.ctx, rq->op == CSU_LIST ? "uqmid" : rq->obj, &id)) {
		blob_buf_free(&bb);
		return csh_fail(h, CSU_E_GONE, "object not found");
	}
	r = ubus_invoke_async(U.ctx, id, method, bb.head, &h->req);
	blob_buf_free(&bb);
	if (r)
		return csh_fail(h, map_status(r) ? map_status(r) : CSU_E_FAILED, ubus_strerror(r));
	h->req.priv = h;
	h->req.data_cb = data_cb;
	h->req.complete_cb = complete_cb;
	h->started = true;
	ubus_complete_request_async(U.ctx, &h->req);
	return h;
}

static void cs_cancel(void *ctx_unused, void *handle)
{
	struct csh *h = handle;

	(void)ctx_unused;
	if (h->started && U.ctx)
		ubus_abort_request(U.ctx, &h->req);
	csh_free(h);
}

/* ------------------------------------------------------------------ subscriptions */

static int mgr_notify(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		      const char *method, struct blob_attr *msg)
{
	struct blob_attr *cur;
	size_t rem;
	char path[CSU_PATH] = "", device[96] = "";
	struct csline *l = TARGET();

	(void)ctx; (void)obj; (void)req;
	blobmsg_for_each_attr(cur, msg, rem) {
		if (!strcmp(blobmsg_name(cur), "path")) bm_str(cur, path, sizeof(path));
		else if (!strcmp(blobmsg_name(cur), "device")) bm_str(cur, device, sizeof(device));
	}
	if (!l || !path[0])
		return 0;
	if (!strcmp(method, "modem.added"))
		csline_ev_modem_added(l, path, device);
	else if (!strcmp(method, "modem.removed"))
		csline_ev_modem_removed(l, path);
	return 0;
}

static int mod_notify(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req,
		      const char *method, struct blob_attr *msg)
{
	struct blob_attr *cur;
	size_t rem;
	struct csu_notify n;
	struct csline *l = TARGET();
	int v = 0;

	(void)ctx; (void)obj; (void)req;
	if (!l)
		return 0;
	memset(&n, 0, sizeof(n));
	snprintf(n.method, sizeof(n.method), "%s", method);
	blobmsg_for_each_attr(cur, msg, rem) {
		const char *k = blobmsg_name(cur);

		if (!strcmp(k, "path")) bm_str(cur, n.path, sizeof(n.path));
		else if (!strcmp(k, "old")) bm_str(cur, n.old_state, sizeof(n.old_state));
		else if (!strcmp(k, "new")) bm_str(cur, n.new_state, sizeof(n.new_state));
		else if (!strcmp(k, "reason")) bm_str(cur, n.reason, sizeof(n.reason));
		else if (!strcmp(k, "received")) n.received = bm_bool(cur);
		else if (!strcmp(k, "cc_cause") && bm_int(cur, &v)) n.cc_cause = v;
		else if (!strcmp(k, "end_reason")) end_reason_parse(cur, &n.end_reason, n.end_reason_name, sizeof(n.end_reason_name));
		else if (!strcmp(k, "operator_code")) bm_str(cur, n.operator_code, sizeof(n.operator_code));
		else if (!strcmp(k, "operator_name")) bm_str(cur, n.operator_name, sizeof(n.operator_name));
	}
	csline_ev_notify(l, &n);
	return 0;
}

static void manager_try(void *arg);

static void mgr_removed(struct ubus_context *ctx, struct ubus_subscriber *s, uint32_t id)
{
	struct csline *l = TARGET();

	(void)ctx; (void)s; (void)id;
	LOGW("cs: the uqmid object disappeared");
	U.mgr_sub = false;
	U.mod_sub = false;
	if (l)
		csline_ev_uqmid_up(l, false);
	ev_timer_set(U.retry, MGR_RETRY_MS);
}

static void mod_removed(struct ubus_context *ctx, struct ubus_subscriber *s, uint32_t id)
{
	struct csline *l = TARGET();

	(void)ctx; (void)s; (void)id;
	U.mod_sub = false;
	if (l && U.mod_path[0])
		csline_ev_modem_removed(l, U.mod_path);
}

static void cs_watch_modem(void *ctx_unused, const char *path)
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
	if (ubus_lookup_id(U.ctx, path, &id) || ubus_subscribe(U.ctx, &U.mod, id)) {
		LOGW("cs: cannot follow the notifications of %s", path);
		return;
	}
	U.mod_id = id;
	U.mod_sub = true;
}

static void manager_try(void *arg)
{
	uint32_t id;
	struct csline *l = TARGET();

	(void)arg;
	if (!U.ctx || U.mgr_sub)
		return;
	if (ubus_lookup_id(U.ctx, "uqmid", &id) || ubus_subscribe(U.ctx, &U.mgr, id)) {
		ev_timer_set(U.retry, MGR_RETRY_MS);
		return;
	}
	U.mgr_sub = true;
	LOGI("cs: uqmid found, subscribed to modem.added / modem.removed");
	if (l)
		csline_ev_uqmid_up(l, true);
}

static void conn_lost(struct ubus_context *ctx)
{
	struct csline *l = TARGET();

	LOGW("cs: ubus connection lost");
	U.ctx = NULL;
	U.mgr_sub = U.mod_sub = false;
	ev_timer_cancel(U.retry);
	if (l)
		csline_ev_uqmid_up(l, false);
	if (U.orig_lost)
		U.orig_lost(ctx);
}

void csub_init(struct csline **target)
{
	memset(&U, 0, sizeof(U));
	U.target = target;
	U.mgr.cb = mgr_notify;
	U.mgr.remove_cb = mgr_removed;
	U.mod.cb = mod_notify;
	U.mod.remove_cb = mod_removed;
	U.retry = ev_timer_new(manager_try, NULL);
}

void csub_on_connect(struct ubus_context *ctx)
{
	U.ctx = ctx;
	U.mgr_sub = U.mod_sub = false;
	U.orig_lost = ctx->connection_lost;
	if (U.orig_lost != conn_lost)
		ctx->connection_lost = conn_lost;
	else
		U.orig_lost = NULL;
	if (ubus_register_subscriber(ctx, &U.mgr))
		LOGE("cs: cannot register the manager subscriber");
	if (ubus_register_subscriber(ctx, &U.mod))
		LOGE("cs: cannot register the modem subscriber");
	manager_try(NULL);
}

void csub_resync(struct ubus_context *ctx)
{
	struct csline *l = TARGET();

	if (!U.ctx) {
		csub_on_connect(ctx);
		return;
	}
	if (U.mgr_sub) {
		if (l)
			csline_ev_uqmid_up(l, true);	/* a new line: it lists the modems itself */
	} else {
		manager_try(NULL);
	}
}

static const struct csu_ops ops = { .call = cs_call, .cancel = cs_cancel, .watch_modem = cs_watch_modem };

const struct csu_ops *csub_ops(void)
{
	return &ops;
}

void csub_shutdown(void)
{
	ev_timer_free(U.retry);
	U.retry = NULL;
	U.ctx = NULL;
}
