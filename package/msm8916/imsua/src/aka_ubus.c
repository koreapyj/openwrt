/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <libubox/blobmsg.h>
#include <libubus.h>
#include "aka.h"
#include "util.h"

struct aka_ubus {
	struct ubus_context *ctx;
	uint32_t id;
	int channel;
	int slot;
	char path[64];
};
static struct aka_ubus *cur;

static int attr_int(struct blob_attr *a, int dflt)
{
	if (!a) return dflt;
	switch (blobmsg_type(a)) {
	case BLOBMSG_TYPE_INT8: return blobmsg_get_u8(a);
	case BLOBMSG_TYPE_INT16: return blobmsg_get_u16(a);
	case BLOBMSG_TYPE_INT32: return blobmsg_get_u32(a);
	case BLOBMSG_TYPE_INT64: return (int)blobmsg_get_u64(a);
	}
	return dflt;
}

static void find_cb(struct ubus_context *c, struct ubus_object_data *o, void *priv)
{
	char *out = priv;
	const char *p = o->path;
	size_t i;

	if (strncmp(p, "uqmid.modem.", 12)) return;
	for (i = 12; p[i]; i++) if (!isdigit((unsigned char)p[i])) return;
	if (i == 12 || out[0]) return;
	strlcpy_(out, p, 64);
}

struct res { int channel, sw1, sw2; char resp[1200]; int have, got_resp; char err[128]; };

static void inv_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct res *r = req->priv;
	struct blob_attr *c;
	size_t rem;

	if (!msg) return;
	blobmsg_for_each_attr(c, msg, rem) {
		const char *n = blobmsg_name(c);
		if (!strcmp(n, "channel_id")) r->channel = attr_int(c, -1);
		else if (!strcmp(n, "sw1")) r->sw1 = attr_int(c, -1);
		else if (!strcmp(n, "sw2")) r->sw2 = attr_int(c, -1);
		else if (!strcmp(n, "response") && blobmsg_type(c) == BLOBMSG_TYPE_STRING)
			{ strlcpy_(r->resp, blobmsg_get_string(c), sizeof(r->resp)); r->got_resp = 1; }
		else if (!strcmp(n, "message") && blobmsg_type(c) == BLOBMSG_TYPE_STRING)
			strlcpy_(r->err, blobmsg_get_string(c), sizeof(r->err));
	}
	r->have = 1;
}

static int call(struct aka_ubus *u, const char *method, struct blob_buf *b, struct res *r)
{
	int rc;

	memset(r, 0, sizeof(*r));
	r->channel = r->sw1 = r->sw2 = -1;
	rc = ubus_invoke(u->ctx, u->id, method, b->head, inv_cb, r, 15000);
	if (rc) ilog("ubus %s %s failed: %s", u->path, method, ubus_strerror(rc));
	return rc;
}

struct aka_ubus *aka_ubus_open(const char *sock, const char *modem_path, const char *aid, int slot)
{
	struct aka_ubus *u = calloc(1, sizeof(*u));
	struct blob_buf b = {};
	struct res r;

	u->ctx = ubus_connect(sock);
	if (!u->ctx) { ilog("ubus_connect failed"); free(u); return NULL; }
	if (modem_path && modem_path[0]) strlcpy_(u->path, modem_path, sizeof(u->path));
	else ubus_lookup(u->ctx, NULL, find_cb, u->path);
	if (!u->path[0] || ubus_lookup_id(u->ctx, u->path, &u->id)) {
		ilog("uqmid modem object not found on ubus");
		ubus_free(u->ctx); free(u); return NULL;
	}
	ilog("ISIM: using %s", u->path);
	u->slot = slot;
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "aid", aid);
	if (slot > 0) blobmsg_add_u32(&b, "slot", slot);
	if (call(u, "uim_channel_open", &b, &r) || r.channel <= 0) {
		ilog("uim_channel_open failed: channel=%d sw=%02x%02x", r.channel, r.sw1 & 0xff, r.sw2 & 0xff);
		blob_buf_free(&b); ubus_free(u->ctx); free(u); return NULL;
	}
	blob_buf_free(&b);
	u->channel = r.channel;
	ilog("ISIM: channel %d opened (sw=%02x%02x)", r.channel, r.sw1 & 0xff, r.sw2 & 0xff);
	cur = u;
	return u;
}

void aka_ubus_close(struct aka_ubus *u)
{
	struct blob_buf b = {};
	struct res r;

	if (!u) return;
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "channel_id", u->channel);
	if (u->slot > 0) blobmsg_add_u32(&b, "slot", u->slot);
	call(u, "uim_channel_close", &b, &r);
	blob_buf_free(&b);
	ilog("ISIM: channel %d closed", u->channel);
	ubus_free(u->ctx);
	if (cur == u) cur = NULL;
	free(u);
}

int aka_ubus_channel(const struct aka_ubus *u) { return u->channel; }

int aka_ubus_apdu(void *ctx, const uint8_t *apdu, size_t n, uint8_t *resp, size_t *rn)
{
	struct aka_ubus *u = ctx;
	struct blob_buf b = {};
	struct res r;
	char hex[1100];
	int l, rc;

	bin2hex(apdu, n, hex);
	ilog("APDU > %s", hex);
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "apdu", hex);
	blobmsg_add_u32(&b, "channel_id", u->channel);
	if (u->slot > 0) blobmsg_add_u32(&b, "slot", u->slot);
	rc = call(u, "uim_apdu_send", &b, &r);
	blob_buf_free(&b);
	if (rc || !r.have || !r.got_resp) { if (r.err[0]) ilog("uim_apdu_send error: %s", r.err); return -1; }
	ilog("APDU < %s", r.resp);
	l = hex2bin(r.resp, resp, *rn);
	if (l < 0) return -1;
	*rn = l;
	return 0;
}
