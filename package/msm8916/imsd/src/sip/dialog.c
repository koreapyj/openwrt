/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "dialog.h"
#include "../util/log.h"
#include "../util/sys.h"

static int cpy(char *dst, size_t n, const char *s)
{
	return str_copy(dst, s, n) >= n ? -1 : 0;
}

/* collect Record-Route elements of m into out[] (document order); count, or -1 on overflow */
static int collect_rr(const struct sip_msg *m, char out[][256], int max)
{
	struct sip_list it;
	char el[256];
	int n = 0, r;

	sip_list_init(&it, m, "Record-Route");
	while ((r = sip_list_next(&it, el, sizeof(el))) > 0) {
		if (n >= max)
			return -1;
		memcpy(out[n++], el, sizeof(el));
	}
	return r < 0 ? -1 : n;
}

static int fill_target(struct sip_dialog *d, const struct sip_msg *m)
{
	const char *ct = sip_hdr(m, "Contact", 0);
	char uri[256];

	if (!ct)
		return 0;
	if (sip_uri_of(ct, uri, sizeof(uri)))
		return -1;
	return cpy(d->remote_target, sizeof(d->remote_target), uri);
}

int dlg_refresh_target(struct sip_dialog *d, const struct sip_msg *m)
{
	return fill_target(d, m);
}

/* UAC: route set from a response; reversed order */
static int fill_route_uac(struct sip_dialog *d, const struct sip_msg *m, bool is_2xx)
{
	char rr[DLG_MAX_ROUTES][256];
	int n = collect_rr(m, rr, DLG_MAX_ROUTES), k;

	if (n < 0)
		return -1;
	if (!n && !is_2xx)
		return 0;	/* a provisional without Record-Route keeps what we have */
	d->nroute = 0;
	for (k = n - 1; k >= 0; k--)
		memcpy(d->route[d->nroute++], rr[k], 256);
	return 0;
}

/* ---- dlgset ---- */

int dlgset_init(struct dlgset *s, struct sip_endpoint *ep, const char *call_id, const char *local_tag,
		const char *local_uri, const char *remote_uri, uint32_t invite_cseq)
{
	memset(s, 0, sizeof(*s));
	s->answered = -1;
	s->invite_cseq = invite_cseq;
	if (cpy(s->call_id, sizeof(s->call_id), call_id) || cpy(s->local_tag, sizeof(s->local_tag), local_tag) ||
	    cpy(s->local_uri, sizeof(s->local_uri), local_uri) || cpy(s->remote_uri, sizeof(s->remote_uri), remote_uri))
		return -1;
	s->ep = sip_ep_ref(ep);
	return 0;
}

void dlgset_release(struct dlgset *s)
{
	int i;

	for (i = 0; i < DLG_MAX_DIALOGS; i++)
		if (s->d[i].used)
			dlg_release(&s->d[i]);
	if (s->ep)
		sip_ep_unref(s->ep);
	s->ep = NULL;
}

int dlgset_find(const struct dlgset *s, const char *tag)
{
	int i;

	for (i = 0; i < DLG_MAX_DIALOGS; i++)
		if (s->d[i].used && !strcmp(s->d[i].remote_tag, tag))
			return i;
	return -1;
}

static int dlg_get(struct dlgset *s, const char *tag)
{
	int i = dlgset_find(s, tag);
	struct sip_dialog *d;

	if (i >= 0)
		return i;
	for (i = 0; i < DLG_MAX_DIALOGS; i++)
		if (!s->d[i].used)
			break;
	if (i == DLG_MAX_DIALOGS) {
		LOGW("dialog: too many early dialogs for call %s", s->call_id);
		return -1;
	}
	d = &s->d[i];
	memset(d, 0, sizeof(*d));
	d->used = true;
	d->is_uac = true;
	d->state = DLG_EARLY;
	d->local_cseq = s->invite_cseq;
	if (cpy(d->remote_tag, sizeof(d->remote_tag), tag) || cpy(d->call_id, sizeof(d->call_id), s->call_id) ||
	    cpy(d->local_tag, sizeof(d->local_tag), s->local_tag) ||
	    cpy(d->local_uri, sizeof(d->local_uri), s->local_uri) ||
	    cpy(d->remote_uri, sizeof(d->remote_uri), s->remote_uri)) {
		d->used = false;
		return -1;
	}
	d->ep = sip_ep_ref(s->ep);
	return i;
}

static bool has_sdp(const struct sip_msg *m)
{
	const char *ct = sip_hdr(m, "Content-Type", 0);

	return m->body_len > 0 && ct && strcasestr(ct, "application/sdp");
}

int dlgset_on_response(struct dlgset *s, const struct sip_msg *m, struct dlg_ev *ev, int max)
{
	char tag[160], meth[16];
	uint32_t cs;
	const char *to;
	int n = 0, di;
	struct sip_dialog *d;
	bool sdp;

	if (!m->is_resp || sip_cseq(m, &cs, meth, sizeof(meth)) || strcasecmp(meth, "INVITE") || cs != s->invite_cseq)
		return 0;
	if (m->status == 100)
		return 0;
	if (m->status >= 300) {
		s->final_status = m->status;
		return 0;	/* ACK is the transaction's business; no dialog */
	}
	to = sip_hdr(m, "To", 0);
	if (!to || sip_tag(to, tag, sizeof(tag)) || !tag[0])
		return 0;	/* a dialog needs a To tag */
	di = dlg_get(s, tag);
	if (di < 0)
		return 0;
	d = &s->d[di];
	sdp = has_sdp(m);

	if (m->status < 200) {
		const char *req = sip_hdr(m, "Require", 0), *rs = sip_hdr(m, "RSeq", 0);

		fill_route_uac(d, m, false);
		fill_target(d, m);
		if (req && strcasestr(req, "100rel") && rs) {
			uint32_t r = strtoul(rs, NULL, 10);

			if (r != d->last_rseq && n < max) {	/* retransmitted 1xx: no second PRACK */
				d->last_rseq = r;
				ev[n].type = DLG_EV_PRACK;
				ev[n].dlg = di;
				ev[n].rseq = r;
				n++;
			}
		}
	} else {
		bool dup = d->state == DLG_CONFIRMED;

		fill_route_uac(d, m, true);
		fill_target(d, m);
		d->state = DLG_CONFIRMED;
		if (s->answered < 0)
			s->answered = di;
		if (n < max) {
			ev[n].type = dup ? DLG_EV_DUP_2XX : DLG_EV_ACK;
			ev[n].dlg = di;
			ev[n].rseq = 0;
			n++;
		}
		if (dup)
			sdp = false;
	}
	if (sdp) {
		d->sdp_seen = true;
		if (n < max) {
			ev[n].type = DLG_EV_SDP;
			ev[n].dlg = di;
			ev[n].rseq = 0;
			n++;
		}
	}
	return n;
}

struct sip_dialog *dlgset_bye_target(struct dlgset *s)
{
	return s->answered >= 0 ? &s->d[s->answered] : NULL;
}

/* ---- UAS ---- */

int dlg_init_uas(struct sip_dialog *d, struct sip_endpoint *ep, const struct sip_msg *req, const char *local_tag)
{
	const char *from = sip_hdr(req, "From", 0), *to = sip_hdr(req, "To", 0), *cid = sip_hdr(req, "Call-ID", 0);
	char rr[DLG_MAX_ROUTES][256];
	int n, i;
	uint32_t cs;

	memset(d, 0, sizeof(*d));
	if (!from || !to || !cid || sip_cseq(req, &cs, NULL, 0))
		return -1;
	if (cpy(d->call_id, sizeof(d->call_id), cid) || cpy(d->local_tag, sizeof(d->local_tag), local_tag) ||
	    sip_tag(from, d->remote_tag, sizeof(d->remote_tag)) ||
	    sip_uri_of(to, d->local_uri, sizeof(d->local_uri)) ||
	    sip_uri_of(from, d->remote_uri, sizeof(d->remote_uri)) || fill_target(d, req))
		return -1;
	n = collect_rr(req, rr, DLG_MAX_ROUTES);
	if (n < 0)
		return -1;
	for (i = 0; i < n; i++)	/* UAS: in order */
		memcpy(d->route[d->nroute++], rr[i], 256);
	d->remote_cseq = cs;
	d->has_remote_cseq = true;
	d->local_cseq = rnd_range(1, 0x7fffffff);
	d->state = DLG_EARLY;
	d->used = true;
	d->ep = sip_ep_ref(ep);
	return 0;
}

void dlg_release(struct sip_dialog *d)
{
	if (d->ep)
		sip_ep_unref(d->ep);
	d->ep = NULL;
	d->used = false;
	d->state = DLG_TERMINATED;
}

void dlg_confirm(struct sip_dialog *d)
{
	if (d->state == DLG_EARLY)
		d->state = DLG_CONFIRMED;
}

/* ---- common ---- */

uint32_t dlg_next_cseq(struct sip_dialog *d)
{
	return ++d->local_cseq;
}

bool dlg_match_request(const struct sip_dialog *d, const struct sip_msg *req)
{
	const char *cid = sip_hdr(req, "Call-ID", 0), *from = sip_hdr(req, "From", 0), *to = sip_hdr(req, "To", 0);
	char ft[160], tt[160];

	if (!cid || !from || !to || strcmp(cid, d->call_id))
		return false;
	if (sip_tag(from, ft, sizeof(ft)) || sip_tag(to, tt, sizeof(tt)))
		return false;
	return !strcmp(ft, d->remote_tag) && !strcmp(tt, d->local_tag);
}

bool dlg_match_response(const struct sip_dialog *d, const struct sip_msg *resp)
{
	const char *cid = sip_hdr(resp, "Call-ID", 0), *from = sip_hdr(resp, "From", 0), *to = sip_hdr(resp, "To", 0);
	char ft[160], tt[160];

	if (!cid || !from || !to || strcmp(cid, d->call_id))
		return false;
	if (sip_tag(from, ft, sizeof(ft)) || sip_tag(to, tt, sizeof(tt)))
		return false;
	return !strcmp(ft, d->local_tag) && !strcmp(tt, d->remote_tag);
}

int dlg_check_remote_cseq(struct sip_dialog *d, const struct sip_msg *req)
{
	uint32_t cs;

	if (sip_cseq(req, &cs, NULL, 0))
		return -1;
	if (!strcmp(req->method, "ACK") || !strcmp(req->method, "CANCEL"))
		return 0;
	if (d->has_remote_cseq && (int32_t)(cs - d->remote_cseq) <= 0)
		return -1;
	d->remote_cseq = cs;
	d->has_remote_cseq = true;
	return 0;
}

int dlg_route(const struct sip_dialog *d, char *ruri, size_t ruri_sz, struct buf *rh)
{
	int i;

	if (!d->remote_target[0])
		return -1;
	if (!d->nroute)
		return cpy(ruri, ruri_sz, d->remote_target);
	if (strcasestr(d->route[0], ";lr")) {	/* loose routing */
		if (cpy(ruri, ruri_sz, d->remote_target))
			return -1;
		for (i = 0; i < d->nroute; i++)
			buf_printf(rh, "Route: %s\r\n", d->route[i]);
	} else {				/* strict routing: first route becomes the R-URI, target goes last */
		struct sip_nameaddr na;

		if (sip_nameaddr_parse(d->route[0], &na) || cpy(ruri, ruri_sz, na.uri))
			return -1;
		for (i = 1; i < d->nroute; i++)
			buf_printf(rh, "Route: %s\r\n", d->route[i]);
		buf_printf(rh, "Route: <%s>\r\n", d->remote_target);
	}
	return buf_ok(rh) ? 0 : -1;
}

int dlg_build_request(struct sip_dialog *d, struct buf *out, const struct dlg_req_opts *o, uint32_t *cseq_used)
{
	char ruri[256], from[340], to[520];
	struct buf rh;
	struct sip_req_parts p;
	int rc;

	buf_init(&rh, 4096);
	if (dlg_route(d, ruri, sizeof(ruri), &rh)) {
		buf_free(&rh);
		return -1;
	}
	snprintf(from, sizeof(from), "<%s>;tag=%s", d->local_uri, d->local_tag);
	if (d->remote_tag[0])
		snprintf(to, sizeof(to), "<%s>;tag=%s", d->remote_uri, d->remote_tag);
	else
		snprintf(to, sizeof(to), "<%s>", d->remote_uri);
	memset(&p, 0, sizeof(p));
	p.method = o->method;
	p.ruri = ruri;
	p.via = o->via;
	p.from = from;
	p.to = to;
	p.call_id = d->call_id;
	p.cseq = o->cseq ? o->cseq : dlg_next_cseq(d);
	p.route = rh.len ? buf_cstr(&rh) : NULL;
	p.contact = o->contact;
	p.extra = o->extra;
	p.content_type = o->content_type;
	p.body = o->body;
	p.body_len = o->body_len;
	if (cseq_used)
		*cseq_used = p.cseq;
	rc = sip_build_request(out, &p);
	buf_free(&rh);
	return rc;
}
