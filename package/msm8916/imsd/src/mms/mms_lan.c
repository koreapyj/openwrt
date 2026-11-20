/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Delivery of a retrieved MMS to the LAN devices, see mms_lan.h. */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mms_lan.h"
#include "../smscodec/tpdu.h"
#include "../smsrelay/smsfmt.h"
#include "../ua/lan_text.h"
#include "../util/log.h"

struct rawdel {
	struct rawdel *next;
	struct mms_lan *d;
	void (*done)(void *arg, int nok);
	void *arg;
	struct lan_text *cur;
};

struct mms_lan {
	struct lan *lan;
	struct lan_seqs *seqs;
	struct rawdel *raw;
};

struct mms_lan *mms_lan_new(void)
{
	struct mms_lan *d = calloc(1, sizeof(*d));

	if (d) {
		d->seqs = lan_seqs_new();
		if (!d->seqs) {
			free(d);
			return NULL;
		}
	}
	return d;
}

static void raw_free(struct rawdel *rd)
{
	struct rawdel **pp;

	for (pp = &rd->d->raw; *pp; pp = &(*pp)->next)
		if (*pp == rd) {
			*pp = rd->next;
			break;
		}
	lan_text_detach(rd->cur);
	free(rd);
}

void mms_lan_abort(void *ctx, void *arg)
{
	struct mms_lan *d = ctx;
	struct rawdel *rd, *nx;

	lan_seqs_abort(d->seqs, arg);
	for (rd = d->raw; rd; rd = nx) {
		nx = rd->next;
		if (rd->arg == arg)
			raw_free(rd);
	}
}

void mms_lan_free(struct mms_lan *d)
{
	if (!d)
		return;
	while (d->raw)
		raw_free(d->raw);
	lan_seqs_free(d->seqs);
	free(d);
}

void mms_lan_set(struct mms_lan *d, struct lan *l)
{
	d->lan = l;
	lan_seqs_set(d->seqs, l);
	if (!l)
		while (d->raw)
			raw_free(d->raw);	/* the object the forks run on goes away: they end without a callback */
}

void mms_lan_devices(void *ctx, unsigned *n_mms, unsigned *n_text)
{
	struct mms_lan *d = ctx;
	reg_id_t ids[LAN_SELECT_MAX];

	*n_mms = lan_select(d->lan, REG_F_MMS, 0, ids, LAN_SELECT_MAX);
	*n_text = lan_select(d->lan, 0, REG_F_MMS, ids, LAN_SELECT_MAX);
}

void mms_lan_sender(const char *from, char *user, size_t un, char *disp, size_t dn)
{
	struct tp_addr a;
	size_t k;
	bool number = true;
	char u[SMSFMT_USER_MAX], dd[SMSFMT_DISP_MAX];

	memset(&a, 0, sizeof(a));
	for (k = 0; from[k]; k++)
		if (!(isdigit((unsigned char)from[k]) || from[k] == '*' || from[k] == '#' || (from[k] == '+' && !k)))
			number = false;
	if (!from[0]) {
		snprintf(a.str, sizeof(a.str), "unknown");
		number = false;
	} else {
		snprintf(a.str, sizeof(a.str), "%.47s", from);
	}
	a.alnum = !number;
	smsfmt_sender(&a, u, sizeof(u), dd, sizeof(dd));
	snprintf(user, un, "%s", u);
	snprintf(disp, dn, "%s", dd);
}

int mms_lan_deliver(void *ctx, const struct mms_out *m, void (*done)(void *arg, int nok), void *arg)
{
	struct mms_lan *d = ctx;
	struct lan_seq_cfg c;
	char user[SMSFMT_USER_MAX], disp[SMSFMT_DISP_MAX];
	char subj[MMS_SUBJ_MAX], ts[80], extra[1024];
	reg_id_t excl[LAN_SELECT_MAX];
	size_t e;

	if (!d->lan)
		return -ENOENT;
	if (!m->n || m->n > LAN_PIECES_MAX)
		return -EINVAL;
	memset(&c, 0, sizeof(c));
	mms_lan_sender(m->from, user, sizeof(user), disp, sizeof(disp));
	mmsr_oneline(m->subject, subj, sizeof(subj));
	e = (size_t)snprintf(extra, sizeof(extra), "X-MMS: 1\r\n");
	if (subj[0])
		e += (size_t)snprintf(extra + e, sizeof(extra) - e, "X-MMS-Subject: %s\r\n", subj);
	if (m->message_id[0]) {
		char id[MMS_ID_MAX];

		mmsr_oneline(m->message_id, id, sizeof(id));
		e += (size_t)snprintf(extra + e, sizeof(extra) - e, "X-MMS-Message-ID: %s\r\n", id);
	}
	if (m->has_ts) {
		lan_text_iso(m->ts, ts, sizeof(ts));
		if (ts[0])
			e += (size_t)snprintf(extra + e, sizeof(extra) - e, "X-SMS-Timestamp: %s\r\n", ts);
	}
	if (m->seq)
		e += (size_t)snprintf(extra + e, sizeof(extra) - e, "X-IMSD-Seq: %llu\r\n", (unsigned long long)m->seq);
	if (e >= sizeof(extra))
		extra[0] = 0;	/* cannot happen with these sizes: no optional headers rather than a cut one */
	c.from_user = user;
	c.from_display = disp;
	c.extra = extra;
	c.part_hdr = "X-MMS-Part";
	c.text = m->text;
	c.n = m->n;
	if (m->target) {
		c.include = &m->target;
		c.ninclude = 1;
		c.include_set = true;
	} else if (m->exclude_mms) {
		c.exclude = excl;
		c.nexclude = lan_select(d->lan, REG_F_MMS, 0, excl, LAN_SELECT_MAX);
	}
	c.done = done;
	c.arg = arg;
	return lan_seq_start(d->seqs, &c);
}

static void raw_done(void *arg, int nok)
{
	struct rawdel *rd = arg;
	void (*done)(void *, int) = rd->done;
	void *a = rd->arg;

	rd->cur = NULL;
	raw_free(rd);
	done(a, nok);
}

/* append one header line unless it does not fit whole */
static void put_hdr(char *extra, size_t cap, size_t *e, const char *name, const char *val)
{
	int n;

	if (*e >= cap)
		return;
	n = snprintf(extra + *e, cap - *e, "%s: %s\r\n", name, val);
	if (n > 0 && (size_t)n < cap - *e)
		*e += (size_t)n;
	else
		extra[*e] = 0;
}

/* the facts of the notification the device needs to fetch it through a standard proxy; each one only when known and valid in a header */
static void raw_headers(const struct mms_raw *r, char *extra, size_t cap, size_t *e)
{
	struct mms_notif *nf = malloc(sizeof(*nf));
	const char *p;
	char v[80];
	int64_t ex;

	if (!nf)
		return;
	if (mms_decode_notification(r->pdu, r->len, nf)) {
		free(nf);
		return;
	}
	for (p = nf->location; *p && (unsigned char)*p >= 0x20 && (unsigned char)*p < 0x7f; p++)
		;
	if (nf->location[0] && !*p)
		put_hdr(extra, cap, e, "X-MMS-Content-Location", nf->location);
	if (nf->has_expiry) {
		ex = nf->expiry_relative ? r->ts + nf->expiry : nf->expiry;
		if (nf->expiry >= 0 && ex >= 1600000000) {
			lan_text_iso(ex, v, sizeof(v));
			if (v[0])
				put_hdr(extra, cap, e, "X-MMS-Expiry", v);
		}
	}
	if (nf->has_size) {
		snprintf(v, sizeof(v), "%u", (unsigned)nf->size);
		put_hdr(extra, cap, e, "X-MMS-Size", v);
	}
	free(nf);
}

size_t mms_lan_raw_headers(const struct mms_raw *r, char *extra, size_t cap)
{
	char ts[80], tid[MMS_ID_MAX];
	size_t e;

	mmsr_oneline(r->tid, tid, sizeof(tid));
	e = (size_t)snprintf(extra, cap, "X-MMS: 1\r\nX-MMS-Transaction-ID: %s\r\nX-MMS-Proxy: %s\r\nX-MMS-Max-Size: %u\r\n",
			     tid, r->proxy, r->max_size);
	lan_text_iso(r->ts, ts, sizeof(ts));
	if (ts[0] && e < cap)
		e += (size_t)snprintf(extra + e, cap - e, "X-SMS-Timestamp: %s\r\n", ts);
	if (r->seq && e < cap)
		e += (size_t)snprintf(extra + e, cap - e, "X-IMSD-Seq: %llu\r\n", (unsigned long long)r->seq);
	if (e >= cap)
		e = 0;
	extra[e] = 0;
	raw_headers(r, extra, cap, &e);
	return e;
}

int mms_lan_deliver_raw(void *ctx, const struct mms_raw *r, void (*done)(void *arg, int nok), void *arg)
{
	struct mms_lan *d = ctx;
	struct rawdel *rd;
	struct lan_text_opts o;
	char user[SMSFMT_USER_MAX], disp[SMSFMT_DISP_MAX], extra[1792];
	reg_id_t inc[LAN_SELECT_MAX];

	if (!d->lan)
		return -ENOENT;
	rd = calloc(1, sizeof(*rd));
	if (!rd)
		return -ENOMEM;
	rd->d = d;
	rd->done = done;
	rd->arg = arg;
	mms_lan_sender(r->from, user, sizeof(user), disp, sizeof(disp));
	mms_lan_raw_headers(r, extra, sizeof(extra));
	memset(&o, 0, sizeof(o));
	o.from_user = user;
	o.from_display = disp;
	o.extra = extra;
	o.content_type = "application/vnd.wap.mms-message";
	o.body = r->pdu;
	o.body_len = r->len;
	o.fork.include_set = true;
	o.fork.include = inc;
	if (r->target) {
		inc[0] = r->target;
		o.fork.ninclude = 1;
	} else {
		o.fork.ninclude = lan_select(d->lan, REG_F_MMS, 0, inc, LAN_SELECT_MAX);
	}
	rd->next = d->raw;
	d->raw = rd;
	rd->cur = lan_text_send_ex(d->lan, &o, raw_done, rd);
	if (!rd->cur) {
		int err = errno ? errno : EIO;

		raw_free(rd);
		return -err;
	}
	return 0;
}
