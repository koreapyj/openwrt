/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mockworld.h"
#include "../util/codec.h"
#include "../util/evloop.h"

struct world W;

void world_reset(void)
{
	memset(&W, 0, sizeof(W));
	W.modem_exists = true;
	snprintf(W.mpath, sizeof(W.mpath), "uqmid.modem.0");
	snprintf(W.mdev, sizeof(W.mdev), "/sys/devices/platform/soc/modem");
	snprintf(W.state, sizeof(W.state), "registered");
	snprintf(W.imei, sizeof(W.imei), "868837083662185");
	snprintf(W.imsi, sizeof(W.imsi), "450061051226862");
	snprintf(W.iccid, sizeof(W.iccid), "8982060010512268620");
	snprintf(W.ifname, sizeof(W.ifname), "wwan0");
	snprintf(W.addr, sizeof(W.addr), "2001:4430:141:990a:25b5:899e:232:cb69");
	W.prefix = 64;
	W.mtu = 1400;
	snprintf(W.pcscf[0], sizeof(W.pcscf[0]), "2001:4430:5:405::43");
	snprintf(W.pcscf[1], sizeof(W.pcscf[1]), "2001:4430:4:405::43");
	W.n_pcscf = 2;
	snprintf(W.connect_err, sizeof(W.connect_err), "Call failed: type 2 reason 201");
	snprintf(W.impi, sizeof(W.impi), "450061051226862@lte-lguplus.co.kr");
	snprintf(W.domain, sizeof(W.domain), "lte-lguplus.co.kr");
	snprintf(W.impu[0], sizeof(W.impu[0]), "sip:01051226862@sos.lte-lguplus.co.kr");
	snprintf(W.impu[1], sizeof(W.impu[1]), "sip:01051226862@lte-lguplus.co.kr");
	snprintf(W.impu[2], sizeof(W.impu[2]), "sip:01051226862@lte-lguplus.co.kr");
	W.n_impu = 3;
	snprintf(W.fqdn[0], sizeof(W.fqdn[0]), "wifi.lteims.co.kr");
	snprintf(W.fqdn[1], sizeof(W.fqdn[1]), "pcscf1.lteims.co.kr");
	snprintf(W.fqdn[2], sizeof(W.fqdn[2]), "pcscf2.lteims.co.kr");
	W.n_fqdn = 3;
	W.cell_present = true;
	snprintf(W.cell_plmn, sizeof(W.cell_plmn), "45006");
	W.cell_tac = 0x20EB;
	W.cell_ci = 0x3161703;
	W.cell_has_earfcn = true;
	W.cell_earfcn = 1300;
}

/* the test SIM's EF_SMSP record 1: "SMS Centre", SMSC +821080010585 */
void world_set_smsp(void)
{
	static const uint8_t rec[44] = {
		0x53, 0x4d, 0x53, 0x20, 0x43, 0x65, 0x6e, 0x74, 0x72, 0x65, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xe9,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x07, 0x91, 0x28, 0x01, 0x08, 0x10, 0x50, 0x58, 0xff, 0xff, 0xff, 0xff,
		0x00, 0xff, 0xff };

	memcpy(W.smsp, rec, sizeof(rec));
	W.smsp_len = sizeof(rec);
}

int world_bearers(void)
{
	int i, n = 0;

	for (i = 0; i < 6; i++)
		n += W.br[i].used;
	return n;
}

/* ---- the fake uqmid ---- */
struct mh {
	struct uq_req rq;
	uq_cb cb;
	void *arg;
	struct ev_timer *t;
};

static size_t rec80(const char *s, size_t total, uint8_t *out, int typebyte)
{
	size_t l = strlen(s) + (typebyte >= 0);

	memset(out, 0xFF, total);
	out[0] = 0x80;
	out[1] = l;
	if (typebyte >= 0)
		out[2] = typebyte;
	memcpy(out + 2 + (typebyte >= 0), s, strlen(s));
	return total;
}

static void sw(struct uq_res *r, size_t dl, int sw16)
{
	r->data[dl] = sw16 >> 8;
	r->data[dl + 1] = sw16 & 0xff;
	r->n = dl + 2;
}

static void apdu(const struct uq_req *rq, struct uq_res *r)
{
	int ins = rq->data[1], ch = rq->num;
	size_t dl;
	int i;
	bool usim = ch >= 1 && ch <= 7 && !strcmp(W.chan_aid[ch], "A0000000871002");

	if (usim)
		W.n_usim_apdu++;
	else
		W.n_apdu++;
	if (W.fail_apdu > 0) {
		W.fail_apdu--;
		W.chan_open[ch & 7] = false;
		r->err = UQ_E_FAILED;
		snprintf(r->errmsg, sizeof(r->errmsg), "channel closed");
		return;
	}
	if (ch < 1 || ch > 7 || !W.chan_open[ch]) {
		r->err = UQ_E_FAILED;
		snprintf(r->errmsg, sizeof(r->errmsg), "no such channel");
		return;
	}
	switch (ins) {
	case 0xA4:
		W.selected = (rq->data[5] << 8) | rq->data[6];
		if (usim) {
			W.n_usim_select++;
			sw(r, 0, (W.selected == 0x6F42 && W.smsp_len) || (W.selected == 0x6FE5 && W.psi_usim_len) ? 0x9000 : 0x6A82);
			break;
		}
		W.n_select++;
		if (W.selected == 0x6FE5)
			sw(r, 0, W.psi_isim_len ? 0x9000 : 0x6A82);
		else
			sw(r, 0, W.selected == 0x6F09 && !W.n_fqdn ? 0x6A82 : 0x9000);
		break;
	case 0xB0:
		if (usim) {
			if (W.selected == 0x6FE5 && W.psi_usim_len) {
				memcpy(r->data, W.psi_usim, W.psi_usim_len);
				sw(r, W.psi_usim_len, 0x9000);
			} else
				sw(r, 0, 0x6A82);
			break;
		}
		if (W.selected == 0x6FE5) {
			if (W.psi_isim_len) {
				memcpy(r->data, W.psi_isim, W.psi_isim_len);
				sw(r, W.psi_isim_len, 0x9000);
			} else
				sw(r, 0, 0x6A82);
			break;
		}
		W.n_read++;
		if (W.read_fail && W.selected == 0x6F02) { sw(r, 0, 0x6982); break; }
		if (W.selected == 0x6F02) dl = rec80(W.impi, 64, r->data, -1);
		else if (W.selected == 0x6F03) dl = rec80(W.domain, 64, r->data, -1);
		else { sw(r, 0, 0x6A82); break; }
		sw(r, dl, 0x9000);
		break;
	case 0xB2: {
		int rec = rq->data[2];

		if (usim) {
			if (W.selected != 0x6F42 || !W.smsp_len || rec != 1) { sw(r, 0, 0x6A83); break; }
			if (W.smsp_6c && rq->data[4] == 0) { sw(r, 0, 0x6C00 | W.smsp_len); break; }
			if (W.smsp_61) { sw(r, 0, 0x6100 | W.smsp_len); break; }
			memcpy(r->data, W.smsp, W.smsp_len);
			sw(r, W.smsp_len, 0x9000);
			break;
		}
		W.n_read++;
		if (W.selected == 0x6F04 && rec >= 1 && rec <= W.n_impu)
			dl = rec80(W.impu[rec - 1], 64, r->data, -1);
		else if (W.selected == 0x6F09 && rec >= 1 && rec <= W.n_fqdn)
			dl = rec80(W.fqdn[rec - 1], 40, r->data, 0);
		else { sw(r, 0, 0x6A83); break; }
		sw(r, dl, 0x9000);
		break;
	}
	case 0x88:
		memcpy(W.rand, rq->data + 6, 16);
		if (W.aka_mode == 2)
			sw(r, 0, 0x9862);
		else
			sw(r, 0, 0x612c);
		break;
	case 0xC0:
		if (usim && W.selected == 0x6F42) {
			memcpy(r->data, W.smsp, W.smsp_len);
			sw(r, W.smsp_len, 0x9000);
			break;
		}
		if (W.aka_mode == 1) {
			r->data[0] = 0xDC; r->data[1] = 14;
			for (i = 0; i < 14; i++) r->data[2 + i] = 0xA0 + i;
			sw(r, 16, 0x9000);
		} else {
			size_t n = 0;

			r->data[n++] = 0xDB; r->data[n++] = 8;
			for (i = 0; i < 8; i++) r->data[n++] = W.rand[i] ^ 0x5A;
			r->data[n++] = 16; for (i = 0; i < 16; i++) r->data[n++] = 0x20 + i;
			r->data[n++] = 16; for (i = 0; i < 16; i++) r->data[n++] = 0x40 + i;
			sw(r, n, 0x9000);
		}
		break;
	default:
		sw(r, 0, 0x6D00);
	}
}

static void ipcfg(struct uq_ipcfg *c)
{
	c->present = true;
	snprintf(c->address, sizeof(c->address), "%s", W.addr);
	c->prefix = W.prefix;
	c->mtu = W.mtu;
	snprintf(c->dns1, sizeof(c->dns1), "2001:4430:4:601::1");
}

static int find_br(const char *path)
{
	int i;

	for (i = 0; i < 6; i++)
		if (W.br[i].used && !strcmp(W.br[i].path, path))
			return i;
	return -1;
}

static void fire(void *arg)
{
	struct mh *h = arg;
	struct uq_res *r = calloc(1, sizeof(*r));
	const struct uq_req *rq = &h->rq;
	uq_cb cb = h->cb;
	void *cbarg = h->arg;
	int i, b;

	W.n_call[rq->op]++;
	switch (rq->op) {
	case UQ_LIST:
		if (W.modem_exists) {
			r->n_modems = 1;
			snprintf(r->modems[0].path, UQ_PATH, "%s", W.mpath);
			snprintf(r->modems[0].device, 96, "%s", W.mdev);
			snprintf(r->modems[0].state, 16, "%s", W.state);
		}
		break;
	case UQ_MODEM_GET:
		if (!W.modem_exists || strcmp(rq->obj, W.mpath)) { r->err = UQ_E_GONE; break; }
		snprintf(r->state, sizeof(r->state), "%s", W.state);
		snprintf(r->imei, sizeof(r->imei), "%s", W.imei);
		for (i = 0; i < 6; i++)
			if (W.br[i].used)
				snprintf(r->bearer_paths[r->n_bearer_paths++], UQ_PATH, "%s", W.br[i].path);
		break;
	case UQ_SIM_GET:
		if (!W.modem_exists) { r->err = UQ_E_GONE; break; }
		snprintf(r->imsi, sizeof(r->imsi), "%s", W.imsi);
		snprintf(r->iccid, sizeof(r->iccid), "%s", W.iccid);
		break;
	case UQ_ENABLE:
		W.n_enable++;
		snprintf(W.state, sizeof(W.state), "registered");
		break;
	case UQ_CREATE_BEARER:
		W.last_create = *rq;
		if (W.create_fail) { r->err = UQ_E_FAILED; snprintf(r->errmsg, sizeof(r->errmsg), "Cannot add new bearer: already reached maximum"); break; }
		for (i = 0; i < 6 && W.br[i].used; i++) ;
		if (i == 6) { r->err = UQ_E_FAILED; break; }
		W.br[i].used = true;
		snprintf(W.br[i].path, 64, "uqmid.modem.0.bearer.%d", W.next_br++);
		snprintf(W.br[i].apn, 32, "%.31s", rq->str);
		snprintf(W.br[i].status, 16, "disconnected");
		snprintf(r->path, UQ_PATH, "%s", W.br[i].path);
		break;
	case UQ_BEARER_CONNECT:
		b = find_br(rq->obj);
		if (b < 0) { r->err = UQ_E_GONE; break; }
		if (W.connect_fail) { r->err = UQ_E_FAILED; snprintf(r->errmsg, sizeof(r->errmsg), "%s", W.connect_err); break; }
		snprintf(W.br[b].status, 16, "connected");
		break;
	case UQ_BEARER_GET:
		b = find_br(rq->obj);
		if (b < 0) { r->err = UQ_E_GONE; break; }
		snprintf(r->status, sizeof(r->status), "%s", W.br[b].status);
		r->connected = !strcmp(W.br[b].status, "connected");
		snprintf(r->apn, sizeof(r->apn), "%s", W.br[b].apn);
		if (r->connected) {
			snprintf(r->ifname, sizeof(r->ifname), "%s", W.ifname);
			if (strchr(W.addr, ':')) ipcfg(&r->ip6); else ipcfg(&r->ip4);
			for (i = 0; i < W.n_pcscf; i++)
				snprintf(r->pcscf[r->n_pcscf++], 48, "%s", W.pcscf[i]);
		}
		break;
	case UQ_DELETE_BEARER:
		W.n_delete++;
		b = find_br(rq->str);
		if (b >= 0)
			W.br[b].used = false;
		else
			r->err = UQ_E_GONE;
		break;
	case UQ_BEARER_DISCONNECT:
		break;
	case UQ_CHAN_OPEN:
		if (!strcmp(rq->str, "A0000000871002")) {
			W.n_usim_open++;
			if (W.usim_open_fail) { r->sw1 = 0x6A; r->sw2 = 0x82; break; }
		} else {
			W.n_chan_open++;
		}
		r->channel = ++W.chan_next;
		if (r->channel > 7) r->channel = W.chan_next = 1;
		W.chan_open[r->channel] = true;
		snprintf(W.chan_aid[r->channel], sizeof(W.chan_aid[0]), "%.19s", rq->str);
		r->sw1 = 0x90;
		break;
	case UQ_CHAN_CLOSE:
		if (!strcmp(W.chan_aid[rq->num & 7], "A0000000871002"))
			W.n_usim_close++;
		else
			W.n_chan_close++;
		W.chan_open[rq->num & 7] = false;
		W.chan_aid[rq->num & 7][0] = 0;
		break;
	case UQ_CELL_INFO:
		if (W.cell_fail) { r->err = UQ_E_FAILED; snprintf(r->errmsg, sizeof(r->errmsg), "Couldn't get cell info"); break; }
		if (!W.cell_present)
			break;
		r->cell_valid = true;
		snprintf(r->cell_plmn, sizeof(r->cell_plmn), "%s", W.cell_plmn);
		r->cell_tac = W.cell_tac;
		r->cell_ci = W.cell_ci;
		r->cell_has_earfcn = W.cell_has_earfcn;
		r->cell_earfcn = W.cell_earfcn;
		break;
	case UQ_APDU:
		apdu(rq, r);
		break;
	}
	ev_timer_free(h->t);
	free(h);
	cb(cbarg, r);
	free(r);
}

static void *mw_call(void *ctx, const struct uq_req *rq, uq_cb cb, void *arg)
{
	struct mh *h = calloc(1, sizeof(*h));

	(void)ctx;
	h->rq = *rq;
	h->cb = cb;
	h->arg = arg;
	h->t = ev_timer_new(fire, h);
	if (rq->op == UQ_APDU && W.hang_psi_select && rq->n >= 7 && rq->data[1] == 0xA4 && rq->data[5] == 0x6F && rq->data[6] == 0xE5 &&
	    rq->num >= 1 && rq->num <= 7 && strcmp(W.chan_aid[rq->num], "A0000000871002"))
		W.n_call[rq->op]++;
	else if (!W.hang[rq->op])
		ev_timer_set(h->t, 0);
	else
		W.n_call[rq->op]++;
	return h;
}

static void mw_cancel(void *ctx, void *handle)
{
	struct mh *h = handle;

	(void)ctx;
	ev_timer_free(h->t);
	free(h);
}

static void mw_watch(void *ctx, const char *path)
{
	(void)ctx;
	W.n_watch++;
	snprintf(W.last_watch, sizeof(W.last_watch), "%s", path ? path : "");
}

/* ---- netcfg ---- */
static int net_apply(void *ctx, const struct netcfg_params *p)
{
	(void)ctx;
	if (W.net_fail)
		return -EIO;
	W.net_apply++;
	W.net_active = true;
	W.net_last = *p;
	return 0;
}

static void net_remove(void *ctx, const struct netcfg_params *p)
{
	(void)ctx; (void)p;
	W.net_remove++;
	W.net_active = false;
}

/* ---- qrtr ---- */
struct qh {
	qrtr_done_cb done;
	void *arg;
	struct ev_timer *t;
};

static void qfire(void *arg)
{
	struct qh *q = arg;
	qrtr_done_cb d = q->done;
	void *a = q->arg;

	ev_timer_free(q->t);
	free(q);
	d(a, W.qrtr_present);
}

static void *q_start(void *ctx, qrtr_done_cb done, void *arg)
{
	struct qh *q = calloc(1, sizeof(*q));

	(void)ctx;
	W.n_qrtr++;
	q->done = done;
	q->arg = arg;
	q->t = ev_timer_new(qfire, q);
	if (!W.qrtr_hang)
		ev_timer_set(q->t, 0);
	return q;
}

static void q_cancel(void *ctx, void *h)
{
	struct qh *q = h;

	(void)ctx;
	ev_timer_free(q->t);
	free(q);
}

static void on_link(void *arg, const struct ims_link *l)
{
	(void)arg;
	W.n_link++;
	W.link = *l;
}

struct imsmodem_ops world_ops(void)
{
	struct imsmodem_ops o;

	memset(&o, 0, sizeof(o));
	o.uq.call = mw_call;
	o.uq.cancel = mw_cancel;
	o.uq.watch_modem = mw_watch;
	o.net.apply = net_apply;
	o.net.remove = net_remove;
	o.qrtr.start = q_start;
	o.qrtr.cancel = q_cancel;
	o.on_link = on_link;
	return o;
}
