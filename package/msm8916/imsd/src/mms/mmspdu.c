/* SPDX-License-Identifier: GPL-2.0-or-later */
/* MMS PDU decoding / encoding, see mmspdu.h. Header codes: OMA-TS-MMS_ENC-V1_2 section 7.3, table 8. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "mmspdu.h"

enum {
	H_BCC = 0x81, H_CC = 0x82, H_LOCATION = 0x83, H_CONTENT_TYPE = 0x84, H_DATE = 0x85, H_DELIVERY_REPORT = 0x86,
	H_EXPIRY = 0x88, H_FROM = 0x89, H_CLASS = 0x8a, H_MESSAGE_ID = 0x8b, H_TYPE = 0x8c, H_VERSION = 0x8d,
	H_SIZE = 0x8e, H_PRIORITY = 0x8f, H_READ_REPORT = 0x90, H_RETRIEVE_STATUS = 0x99, H_SUBJECT = 0x96,
	H_TO = 0x97, H_TID = 0x98, H_STATUS = 0x95, H_RESPONSE_STATUS = 0x92,
};

void mms_clean_address(const char *in, char *out, size_t n)
{
	const char *t = strcasestr(in, "/TYPE=");
	size_t l = t ? (size_t)(t - in) : strlen(in);

	if (!n)
		return;
	if (l >= n)
		l = n - 1;
	memcpy(out, in, l);
	out[l] = 0;
}

/* copy, cut to fit */
static void copy_str(char *dst, size_t n, const char *s)
{
	size_t l = strlen(s);

	if (!n)
		return;
	if (l >= n)
		l = n - 1;
	memcpy(dst, s, l);
	dst[l] = 0;
}

/* Yes (0x80) / No (0x81) */
static int yesno(struct wsp_rd *r, int *v)
{
	uint8_t b;

	if (wsp_u8(r, &b) || (b != 0x80 && b != 0x81))
		return -1;
	*v = b == 0x80;
	return 0;
}

static int class_value(struct wsp_rd *r, int *v)
{
	uint8_t b;

	if (!wsp_left(r))
		return -1;
	b = r->p[r->pos];
	if (b >= 0x80) {
		r->pos++;
		*v = b <= 0x83 ? b - 0x80 : -1;
		return 0;
	}
	*v = -1;
	return wsp_skip_value(r);
}

/* From-value: Value-length (Address-present-token Encoded-string-value | Insert-address-token) */
static int from_value(struct wsp_rd *r, char *out, size_t n, bool *hidden)
{
	struct wsp_rd s;
	size_t l;
	uint8_t tok;
	char raw[MMS_ADDR_MAX * 2];

	if (wsp_value_length(r, &l) || wsp_sub(r, l, &s) || wsp_u8(&s, &tok))
		return -1;
	out[0] = 0;
	if (hidden)
		*hidden = tok == 0x81;
	if (tok == 0x80) {
		if (wsp_encoded_string(&s, raw, sizeof(raw)))
			return -1;
		mms_clean_address(raw, out, n);
	}
	return 0;
}

static int addr_value(struct wsp_rd *r, char (*list)[MMS_ADDR_MAX], int *cnt)
{
	char raw[MMS_ADDR_MAX * 2];

	if (wsp_encoded_string(r, raw, sizeof(raw)))
		return -1;
	if (*cnt < MMS_MAX_RCPT)
		mms_clean_address(raw, list[(*cnt)++], MMS_ADDR_MAX);
	return 0;
}

static int version_value(struct wsp_rd *r, uint8_t *v)
{
	uint8_t b;

	if (wsp_u8(r, &b) || b < 0x80)
		return -1;
	*v = b;
	return 0;
}

/* Expiry-value: Value-length (Absolute-token Date-value | Relative-token Delta-seconds-value) */
static int expiry_value(struct wsp_rd *r, bool *rel, int64_t *secs)
{
	struct wsp_rd s;
	size_t l;
	uint8_t tok;
	uint64_t v;

	if (wsp_value_length(r, &l) || wsp_sub(r, l, &s) || wsp_u8(&s, &tok) || (tok != 0x80 && tok != 0x81) ||
	    wsp_integer(&s, &v) || v > 0x7fffffffffffffffull)
		return -1;
	*rel = tok == 0x81;
	*secs = (int64_t)v;
	return 0;
}

/* Content-Location / Message-ID / Transaction-Id: Text-string (a Quote prefix is dropped) */
static int id_value(struct wsp_rd *r, char *out, size_t n)
{
	bool tr;

	return wsp_text(r, out, n, &tr);
}

/* ------------------------------------------------------------------ */
/* M-Notification.ind                                                  */

int mms_decode_notification(const uint8_t *d, size_t n, struct mms_notif *o)
{
	struct wsp_rd r;
	uint8_t b;
	bool first = true, have_tid = false, have_loc = false;

	memset(o, 0, sizeof(*o));
	o->msg_class = -1;
	o->delivery_report = -1;
	wsp_rd_init(&r, d, n);
	while (wsp_left(&r)) {
		int rc = 0;

		if (wsp_u8(&r, &b))
			return -1;
		if (first && b != H_TYPE)
			return -1;
		if (b < 0x80) {		/* application header: token-text name, then a value */
			r.pos--;
			if (wsp_header_name(&r, &(bool){ false }, &(unsigned){ 0 }, (char[48]){ 0 }, 48) || wsp_skip_value(&r))
				return -1;
			continue;
		}
		switch (b) {
		case H_TYPE:
			if (wsp_u8(&r, &b) || b != MMS_T_NOTIFICATION_IND)
				return -1;
			first = false;
			continue;
		case H_TID:
			rc = id_value(&r, o->tid, sizeof(o->tid));
			have_tid = !rc && o->tid[0];
			break;
		case H_VERSION:
			rc = version_value(&r, &o->version);
			break;
		case H_FROM:
			rc = from_value(&r, o->from, sizeof(o->from), NULL);
			break;
		case H_SUBJECT:
			rc = wsp_encoded_string(&r, o->subject, sizeof(o->subject));
			break;
		case H_CLASS:
			rc = class_value(&r, &o->msg_class);
			break;
		case H_SIZE: {
			uint64_t v;

			rc = wsp_integer(&r, &v);
			if (!rc) {
				o->has_size = true;
				o->size = v > 0xffffffffull ? 0xffffffffu : (uint32_t)v;
			}
			break;
		}
		case H_EXPIRY:
			rc = expiry_value(&r, &o->expiry_relative, &o->expiry);
			o->has_expiry = !rc;
			break;
		case H_LOCATION:
			rc = id_value(&r, o->location, sizeof(o->location));
			have_loc = !rc && o->location[0];
			break;
		case H_DELIVERY_REPORT:
			rc = yesno(&r, &o->delivery_report);
			break;
		default:
			rc = wsp_skip_value(&r);
			break;
		}
		if (rc)
			return -1;
	}
	return !first && have_tid && have_loc ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* M-Retrieve.conf                                                     */

static void part_headers(struct wsp_rd *h, struct mms_part *p)
{
	while (wsp_left(h)) {
		bool wk;
		unsigned code;
		char name[48];

		if (wsp_header_name(h, &wk, &code, name, sizeof(name)))
			return;
		if (wk && code == 0x40) {		/* Content-ID: quoted-string "<id>" */
			char t[WSP_NAME_MAX];

			if (wsp_text(h, t, sizeof(t), NULL))
				return;
			if (t[0] == '<' && t[strlen(t) - 1] == '>') {
				t[strlen(t) - 1] = 0;
				memmove(t, t + 1, strlen(t));
			}
			copy_str(p->content_id, sizeof(p->content_id), t);
			continue;
		}
		if (wk && code == 0x0e) {		/* Content-Location */
			if (wsp_text(h, p->location, sizeof(p->location), NULL))
				return;
			continue;
		}
		if (wk && (code == 0x2e || code == 0x45) && wsp_left(h) && h->p[h->pos] <= 31) {	/* Content-Disposition */
			struct wsp_rd s;
			size_t l;
			uint8_t tok;
			struct wsp_ctype dp;

			if (wsp_value_length(h, &l) || wsp_sub(h, l, &s))
				return;
			if (wsp_u8(&s, &tok))
				continue;
			if (tok >= 0x80) {
				p->disposition = tok <= 0x82 ? tok - 0x80 : -1;
			} else {
				s.pos--;
				if (wsp_text(&s, name, sizeof(name), NULL))
					continue;
				p->disposition = !strcasecmp(name, "attachment") ? 1 : !strcasecmp(name, "inline") ? 2 :
						 !strcasecmp(name, "form-data") ? 0 : -1;
			}
			memset(&dp, 0, sizeof(dp));
			wsp_parse_params(&s, &dp);
			if (dp.filename[0])
				copy_str(p->filename, sizeof(p->filename), dp.filename);
			else if (dp.name[0] && !p->filename[0])
				copy_str(p->filename, sizeof(p->filename), dp.name);
			continue;
		}
		if (wsp_skip_value(h))
			return;
	}
}

/* multipart body: nEntries, then per entry HeadersLen DataLen ContentType Headers Data (WAP-230 8.5) */
static int decode_multipart(struct wsp_rd *r, struct mms_retrieve *o)
{
	uint32_t ne, i;

	if (wsp_uintvar(r, &ne))
		return -1;
	if (ne > wsp_left(r) / 2)		/* an entry takes at least HeadersLen and DataLen */
		return -1;
	for (i = 0; i < ne; i++) {
		uint32_t hl, dl;
		struct wsp_rd h;
		struct mms_part *p;
		struct mms_part dummy;
		struct wsp_ctype ct;
		const uint8_t *data;

		if (wsp_uintvar(r, &hl) || wsp_uintvar(r, &dl) || hl > wsp_left(r) || dl > wsp_left(r) - hl)
			return -1;
		wsp_sub(r, hl, &h);
		data = r->p + r->pos;
		r->pos += dl;
		p = o->nparts < MMS_MAX_PARTS ? &o->part[o->nparts] : &dummy;
		memset(p, 0, sizeof(*p));
		p->disposition = -1;
		p->data = data;
		p->len = dl;
		if (wsp_content_type(&h, &ct))
			return -1;
		copy_str(p->type, sizeof(p->type), ct.type);
		p->charset = ct.charset;
		copy_str(p->filename, sizeof(p->filename), ct.filename[0] ? ct.filename : ct.name);
		part_headers(&h, p);
		if (o->nparts < MMS_MAX_PARTS)
			o->nparts++;
		else
			o->parts_dropped++;
	}
	return 0;
}

int mms_decode_retrieve(const uint8_t *d, size_t n, struct mms_retrieve *o)
{
	struct wsp_rd r;
	uint8_t b;
	bool first = true, have_ct = false;

	memset(o, 0, sizeof(*o));
	o->priority = o->msg_class = o->delivery_report = o->read_report = o->retrieve_status = -1;
	wsp_rd_init(&r, d, n);
	while (!have_ct && wsp_left(&r)) {
		int rc = 0;

		if (wsp_u8(&r, &b))
			return -1;
		if (first && b != H_TYPE)
			return -1;
		if (b < 0x80) {
			r.pos--;
			if (wsp_header_name(&r, &(bool){ false }, &(unsigned){ 0 }, (char[48]){ 0 }, 48) || wsp_skip_value(&r))
				return -1;
			continue;
		}
		switch (b) {
		case H_TYPE:
			if (wsp_u8(&r, &b) || b != MMS_T_RETRIEVE_CONF)
				return -1;
			first = false;
			continue;
		case H_TID:
			rc = id_value(&r, o->tid, sizeof(o->tid));
			o->has_tid = !rc && o->tid[0];
			break;
		case H_VERSION:
			rc = version_value(&r, &o->version);
			break;
		case H_MESSAGE_ID:
			rc = id_value(&r, o->message_id, sizeof(o->message_id));
			break;
		case H_DATE: {
			uint64_t v;

			rc = wsp_integer(&r, &v);
			if (!rc && v <= 0x7fffffffffffffffull) {
				o->has_date = true;
				o->date = (int64_t)v;
			}
			break;
		}
		case H_FROM:
			rc = from_value(&r, o->from, sizeof(o->from), &o->from_hidden);
			break;
		case H_TO:
			rc = addr_value(&r, o->to, &o->n_to);
			break;
		case H_CC:
			rc = addr_value(&r, o->cc, &o->n_cc);
			break;
		case H_SUBJECT:
			rc = wsp_encoded_string(&r, o->subject, sizeof(o->subject));
			break;
		case H_CLASS:
			rc = class_value(&r, &o->msg_class);
			break;
		case H_PRIORITY:
			if (wsp_u8(&r, &b) || b < 0x80)
				return -1;
			o->priority = b <= 0x82 ? b - 0x80 : -1;
			break;
		case H_DELIVERY_REPORT:
			rc = yesno(&r, &o->delivery_report);
			break;
		case H_READ_REPORT:
			rc = yesno(&r, &o->read_report);
			break;
		case H_RETRIEVE_STATUS:
			rc = wsp_u8(&r, &b);
			o->retrieve_status = rc ? -1 : b;
			break;
		case H_CONTENT_TYPE:
			rc = wsp_content_type(&r, &o->ct);
			have_ct = !rc;
			break;
		default:
			rc = wsp_skip_value(&r);
			break;
		}
		if (rc)
			return -1;
	}
	if (first || !have_ct)
		return -1;
	if (!strncasecmp(o->ct.type, "application/vnd.wap.multipart.", 30) || !strncasecmp(o->ct.type, "multipart/", 10)) {
		o->multipart = true;
		return decode_multipart(&r, o);
	}
	/* a single body: one part */
	o->part[0].disposition = -1;
	copy_str(o->part[0].type, sizeof(o->part[0].type), o->ct.type);
	o->part[0].charset = o->ct.charset;
	copy_str(o->part[0].filename, sizeof(o->part[0].filename), o->ct.filename[0] ? o->ct.filename : o->ct.name);
	o->part[0].data = r.p + r.pos;
	o->part[0].len = wsp_left(&r);
	o->nparts = 1;
	return 0;
}

int mms_decode_head(const uint8_t *d, size_t n, struct mms_head *o)
{
	struct wsp_rd r;
	uint8_t b;
	bool first = true;

	memset(o, 0, sizeof(*o));
	o->response_status = o->status = -1;
	wsp_rd_init(&r, d, n);
	while (wsp_left(&r)) {
		int rc = 0;

		if (wsp_u8(&r, &b))
			return -1;
		if (first && b != H_TYPE)
			return -1;
		if (b < 0x80) {
			r.pos--;
			if (wsp_header_name(&r, &(bool){ false }, &(unsigned){ 0 }, (char[48]){ 0 }, 48) || wsp_skip_value(&r))
				return -1;
			continue;
		}
		switch (b) {
		case H_TYPE:
			if (wsp_u8(&r, &o->type) || o->type < 0x80)
				return -1;
			first = false;
			continue;
		case H_TID:
			rc = id_value(&r, o->tid, sizeof(o->tid));
			o->has_tid = !rc && o->tid[0];
			break;
		case H_VERSION:
			rc = version_value(&r, &o->version);
			break;
		case H_MESSAGE_ID:
			rc = id_value(&r, o->message_id, sizeof(o->message_id));
			break;
		case H_TO:
		case H_CC:
		case H_BCC: {
			char raw[MMS_ADDR_MAX * 2];
			int k = b == H_TO ? 0 : b == H_CC ? 1 : 2;

			rc = wsp_encoded_string(&r, raw, sizeof(raw));
			if (rc)
				break;
			if (o->n_rcpt[k] < MMS_HEAD_RCPT)
				mms_clean_address(raw, o->rcpt[k][o->n_rcpt[k]++], MMS_ADDR_MAX);
			else
				o->rcpt_more = true;
			break;
		}
		case H_SUBJECT:
			rc = wsp_encoded_string(&r, o->subject, sizeof(o->subject));
			break;
		case H_RESPONSE_STATUS:
			rc = wsp_u8(&r, &b);
			o->response_status = rc ? -1 : b;
			break;
		case H_STATUS:
			rc = wsp_u8(&r, &b);
			o->status = rc ? -1 : b;
			break;
		case H_CONTENT_TYPE: {
			struct wsp_ctype ct;

			rc = wsp_content_type(&r, &ct);
			o->has_content_type = !rc;
			if (!rc)
				return 0;
			break;
		}
		default:
			rc = wsp_skip_value(&r);
			break;
		}
		if (rc)
			return -1;
	}
	return first ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/* encoding                                                            */

size_t mms_encode_notifyresp(const char *tid, uint8_t version, unsigned status, uint8_t *out, size_t cap)
{
	size_t l = strlen(tid), k = 0;

	if (cap < 2 + 1 + l + 1 + 2 + 2 || strchr(tid, 0) == NULL)
		return 0;
	out[k++] = H_TYPE;
	out[k++] = MMS_T_NOTIFYRESP_IND;
	out[k++] = H_TID;
	memcpy(out + k, tid, l);
	k += l;
	out[k++] = 0;
	out[k++] = H_VERSION;
	out[k++] = version ? version : MMS_VERSION_1_2;
	out[k++] = H_STATUS;
	out[k++] = (uint8_t)status;
	return k;
}

size_t mms_encode_acknowledge(const char *tid, uint8_t version, uint8_t *out, size_t cap)
{
	size_t l = strlen(tid), k = 0;

	if (cap < 2 + 1 + l + 1 + 2)
		return 0;
	out[k++] = H_TYPE;
	out[k++] = MMS_T_ACKNOWLEDGE_IND;
	out[k++] = H_TID;
	memcpy(out + k, tid, l);
	k += l;
	out[k++] = 0;
	out[k++] = H_VERSION;
	out[k++] = version ? version : MMS_VERSION_1_2;
	return k;
}

/* an output cursor that never writes past its end */
struct pdu_out {
	uint8_t *p;
	size_t cap, n;
	bool ovf;
};

static void po_u8(struct pdu_out *o, unsigned b)
{
	if (o->n < o->cap)
		o->p[o->n++] = (uint8_t)b;
	else
		o->ovf = true;
}

/* length of a Text-string on the wire: a string starting with a high byte needs the Quote */
static size_t po_tlen(const char *s)
{
	return strlen(s) + 1 + ((uint8_t)s[0] >= 0x80);
}

static void po_text(struct pdu_out *o, const char *s)
{
	size_t l = strlen(s) + 1, i;

	if ((uint8_t)s[0] >= 0x80)
		po_u8(o, 0x7f);
	for (i = 0; i < l; i++)
		po_u8(o, (uint8_t)s[i]);
}

/* Long-integer: length octet and the big-endian value */
static void po_long(struct pdu_out *o, uint64_t v)
{
	unsigned k = 1;
	uint64_t t = v >> 8;

	while (t) {
		k++;
		t >>= 8;
	}
	po_u8(o, k);
	while (k--)
		po_u8(o, (unsigned)(v >> (8 * k)) & 0xff);
}

/* Value-length: a Short-length below 31, else the quote 31 and a uintvar */
static void po_vlen(struct pdu_out *o, size_t l)
{
	if (l < 31) {
		po_u8(o, (unsigned)l);
		return;
	}
	po_u8(o, 31);
	if (l >= 128)
		po_u8(o, 0x80 | (unsigned)(l >> 7));
	po_u8(o, (unsigned)(l & 0x7f));
}

size_t mms_encode_notification(const char *tid, uint8_t version, const char *from, const char *subject_utf8, uint32_t size, int64_t expiry,
			       const char *location, uint8_t *out, size_t cap)
{
	struct pdu_out o = { out, cap, 0, false };

	if (!tid[0] || !location[0] || strlen(tid) > 200 || strlen(location) > 500 || (from && strlen(from) > 200) ||
	    (subject_utf8 && strlen(subject_utf8) > 200) || expiry < 0)
		return 0;
	po_u8(&o, H_TYPE);
	po_u8(&o, MMS_T_NOTIFICATION_IND);
	po_u8(&o, H_TID);
	po_text(&o, tid);
	po_u8(&o, H_VERSION);
	po_u8(&o, version ? version : MMS_VERSION_1_2);
	po_u8(&o, H_FROM);
	if (from) {
		po_vlen(&o, 1 + po_tlen(from));
		po_u8(&o, 0x80);			/* Address-present-token */
		po_text(&o, from);
	} else {
		po_u8(&o, 1);
		po_u8(&o, 0x81);			/* Insert-address-token */
	}
	if (subject_utf8 && subject_utf8[0]) {
		size_t l = po_tlen(subject_utf8);

		po_u8(&o, H_SUBJECT);
		po_vlen(&o, 1 + l);
		po_u8(&o, 0xea);			/* charset utf-8 (MIBenum 106) */
		po_text(&o, subject_utf8);
	}
	po_u8(&o, H_CLASS);
	po_u8(&o, 0x80);				/* personal */
	po_u8(&o, H_SIZE);
	po_long(&o, size);
	if (expiry) {
		struct pdu_out t = { (uint8_t[12]){ 0 }, 12, 0, false };

		po_u8(&t, 0x80);			/* Absolute-token */
		po_long(&t, (uint64_t)expiry);
		po_u8(&o, H_EXPIRY);
		po_vlen(&o, t.n);
		for (size_t i = 0; i < t.n; i++)
			po_u8(&o, t.p[i]);
	}
	po_u8(&o, H_LOCATION);
	po_text(&o, location);
	return o.ovf ? 0 : o.n;
}
