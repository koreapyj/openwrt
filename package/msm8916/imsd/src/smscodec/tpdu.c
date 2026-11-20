/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "tpdu.h"
#include "gsm7.h"
#include "euckr.h"
#include "utf8.h"
#include "../util/buf.h"

const char *tp_strerror(int err)
{
	switch (err) {
	case 0: return "ok";
	case TP_E_ARG: return "bad argument";
	case TP_E_TRUNC: return "truncated TPDU";
	case TP_E_MTI: return "unexpected message type";
	case TP_E_ADDR: return "bad address";
	case TP_E_COMPRESSED: return "compressed user data not supported";
	case TP_E_UDL: return "user data length out of range";
	case TP_E_UDH: return "malformed user data header";
	case TP_E_UTF8: return "invalid UTF-8 text";
	case TP_E_TOOLONG: return "text too long";
	case TP_E_VP: return "validity period not representable";
	case TP_E_OVERFLOW: return "internal buffer overflow";
	}
	return "unknown error";
}

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

/* two decimal digits in a swapped-nibble octet; -1 if a nibble is not a digit */
static int bcd2(uint8_t b)
{
	unsigned lo = b & 0x0F, hi = b >> 4;

	if (lo > 9 || hi > 9)
		return -1;
	return (int)(lo * 10 + hi);
}

/* days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm) */
static int64_t days_from_civil(int y, int m, int d)
{
	int64_t yy = y - (m <= 2);
	int64_t era = (yy >= 0 ? yy : yy - 399) / 400;
	int64_t yoe = yy - era * 400;
	int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
	int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

	return era * 146097 + doe - 719468;
}

static bool days_in_month_ok(int y, int m, int d)
{
	static const uint8_t dm[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	int max = dm[m - 1];

	if (m == 2 && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)))
		max = 29;
	return d >= 1 && d <= max;
}

void tp_scts_decode(const uint8_t p[7], struct tp_scts *t)
{
	int v[6], i;
	bool ok = true;
	uint8_t tz = p[6];

	memset(t, 0, sizeof(*t));
	for (i = 0; i < 6; i++) {
		v[i] = bcd2(p[i]);
		if (v[i] < 0) {
			ok = false;
			v[i] = 0;
		}
	}
	/* TZ: bit 3 of the first nibble is the sign, the rest are quarter hours (TS 23.040 9.2.3.11) */
	t->tz_quarters = (int)((tz & 0x07) * 10 + (tz >> 4));
	if (tz & 0x08)
		t->tz_quarters = -t->tz_quarters;
	if ((tz >> 4) > 9 || (tz & 0x07) > 7)
		ok = false;
	t->year = 2000 + v[0];
	t->mon = v[1];
	t->day = v[2];
	t->hour = v[3];
	t->min = v[4];
	t->sec = v[5];
	if (ok && (t->mon < 1 || t->mon > 12 || !days_in_month_ok(t->year, t->mon, t->day) ||
		   t->hour > 23 || t->min > 59 || t->sec > 59))
		ok = false;
	t->valid = ok;
	if (ok)
		t->epoch = days_from_civil(t->year, t->mon, t->day) * 86400 + t->hour * 3600 + t->min * 60 +
			   t->sec - (int64_t)t->tz_quarters * 900;
}

/*
 * Address field: length octet (digits, or useful semi-octets for an
 * alphanumeric address), TOA, then ceil(len/2) octets. Returns the octets
 * consumed or a TP_E_*.
 */
static int parse_addr(const uint8_t *p, size_t n, struct tp_addr *a)
{
	static const char digit[16] = "0123456789*#abc?";
	unsigned len, i;
	size_t octets;
	struct buf b;

	memset(a, 0, sizeof(*a));
	if (n < 2)
		return TP_E_TRUNC;
	len = p[0];
	if (len > 20)
		return TP_E_ADDR;
	octets = (len + 1) / 2;
	if (n < 2 + octets)
		return TP_E_TRUNC;
	a->ton = (p[1] >> 4) & 7;
	a->npi = p[1] & 15;
	buf_init_fixed(&b, a->str, sizeof(a->str));
	if (a->ton == 5) {
		uint8_t sept[20];
		size_t ns = len * 4 / 7;
		bool lossy = false;

		a->alnum = true;
		if (gsm7_unpack(p + 2, octets, 0, ns, sept) < 0)
			return TP_E_TRUNC;
		if (gsm7_to_utf8(sept, ns, &b, &lossy) < 0)
			return TP_E_OVERFLOW;
	} else {
		if (a->ton == 1)
			buf_putc(&b, '+');
		for (i = 0; i < len; i++) {
			uint8_t o = p[2 + i / 2];
			unsigned nib = (i & 1) ? o >> 4 : o & 15;

			buf_putc(&b, digit[nib]);
		}
	}
	if (!buf_ok(&b))
		return TP_E_OVERFLOW;
	return (int)(2 + octets);
}

/* ------------------------------------------------------------------ */
/* user data decode                                                   */
/* ------------------------------------------------------------------ */

static int parse_udh(struct tp_sms *s, const uint8_t *ie, size_t len)
{
	size_t i = 0;

	while (i < len) {
		uint8_t iei, iel;
		const uint8_t *d;

		if (i + 2 > len)
			return TP_E_UDH;
		iei = ie[i];
		iel = ie[i + 1];
		if (i + 2 + iel > len)
			return TP_E_UDH;
		d = ie + i + 2;
		if (iei == 0x00 || iei == 0x08) {
			bool wide = iei == 0x08;
			uint8_t total = wide ? d[2] : d[1], seq = wide ? d[3] : d[2];

			if (iel != (wide ? 4 : 3) || total < 1 || seq < 1 || seq > total) {
				s->flags |= TP_F_BAD_CONCAT;
			} else if (!s->concat.present) {
				s->concat.present = true;
				s->concat.ref16 = wide;
				s->concat.ref = wide ? (uint16_t)((d[0] << 8) | d[1]) : d[0];
				s->concat.total = total;
				s->concat.seq = seq;
			}
		} else if ((iei == 0x05 && iel == 4) || (iei == 0x04 && iel == 2)) {
			if (!s->ports.present) {
				s->ports.present = true;
				if (iei == 0x05) {
					s->ports.dst = (uint16_t)((d[0] << 8) | d[1]);
					s->ports.src = (uint16_t)((d[2] << 8) | d[3]);
				} else {
					s->ports.dst = d[0];
					s->ports.src = d[1];
				}
			}
		} else if ((iei == 0x24 || iei == 0x25) && iel == 1) {
			if (iei == 0x24)
				s->nls_single = d[0];
			else
				s->nls_locking = d[0];
			s->flags |= TP_F_NLS;
		}
		/* anything else: skipped (EMS, operator specific IEs ...) */
		i += 2u + iel;
	}
	return 0;
}

static int decode_dcs(struct tp_sms *s)
{
	uint8_t d = s->dcs;

	s->msg_class = -1;
	s->charset = TP_CS_GSM7;
	switch (d >> 6) {
	case 0:
	case 1:		/* general data coding / automatic deletion group */
		if (d & 0x20)
			return TP_E_COMPRESSED;
		if (d & 0x10)
			s->msg_class = d & 3;
		switch ((d >> 2) & 3) {
		case 0: s->charset = TP_CS_GSM7; break;
		case 1: s->charset = TP_CS_8BIT; break;
		case 2: s->charset = TP_CS_UCS2; break;
		default:
			s->charset = TP_CS_GSM7;	/* reserved: assume the default alphabet */
			s->flags |= TP_F_RESERVED_ALPHABET;
		}
		break;
	case 2:
		if (d == 0x84) {
			s->charset = TP_CS_KSC5601;
		} else {
			s->charset = TP_CS_UNKNOWN;
			s->flags |= TP_F_UNKNOWN_CHARSET;
		}
		break;
	default:
		switch (d >> 4) {
		case 0xC:
		case 0xD:
		case 0xE:
			s->charset = (d >> 4) == 0xE ? TP_CS_UCS2 : TP_CS_GSM7;
			s->mwi = true;
			s->mwi_active = d & 8;
			s->mwi_type = d & 3;
			break;
		default:	/* 0xF: data coding / message class */
			s->msg_class = d & 3;
			s->charset = (d & 4) ? TP_CS_8BIT : TP_CS_GSM7;
		}
	}
	return 0;
}

static int decode_ucs2(const uint8_t *p, size_t n, struct buf *out, bool *lossy)
{
	size_t i;
	char t[4];

	if (n & 1)
		*lossy = true;
	for (i = 0; i + 1 < n; i += 2) {
		uint32_t u = (uint32_t)(p[i] << 8) | p[i + 1], cp = u;
		int k;

		if (u >= 0xD800 && u <= 0xDBFF) {
			uint32_t l = 0;

			if (i + 3 < n)
				l = (uint32_t)(p[i + 2] << 8) | p[i + 3];
			if (l >= 0xDC00 && l <= 0xDFFF) {
				cp = 0x10000 + ((u - 0xD800) << 10) + (l - 0xDC00);
				i += 2;
			} else {
				cp = UTF8_REPLACEMENT;
				*lossy = true;
			}
		} else if (u >= 0xDC00 && u <= 0xDFFF) {
			cp = UTF8_REPLACEMENT;
			*lossy = true;
		}
		k = utf8_encode(cp, t);
		if (buf_add(out, t, (size_t)k) < 0)
			return -1;
	}
	return 0;
}

/* p points at the UDL octet */
static int decode_ud(struct tp_sms *s, const uint8_t *p, size_t n)
{
	unsigned udl;
	size_t ud_octets, hdr_oct = 0;
	const uint8_t *ud = p + 1;
	struct buf b;
	bool lossy = false;
	int r;

	if (n < 1)
		return TP_E_TRUNC;
	udl = p[0];
	buf_init_fixed(&b, s->text, sizeof(s->text));
	if (s->charset == TP_CS_GSM7) {
		if (udl > 160)
			return TP_E_UDL;
		ud_octets = gsm7_packed_len(udl, 0);
	} else {
		if (udl > TP_MAX_UD)
			return TP_E_UDL;
		ud_octets = udl;
	}
	if (n - 1 < ud_octets)
		return TP_E_TRUNC;

	if (s->udhi) {
		if (ud_octets < 1)
			return TP_E_UDH;
		hdr_oct = (size_t)ud[0] + 1;
		if (hdr_oct > ud_octets)
			return TP_E_UDH;
		if (s->charset == TP_CS_GSM7 && (hdr_oct * 8 + 6) / 7 > udl)
			return TP_E_UDH;
		s->udh_len = (uint8_t)(hdr_oct - 1);
		memcpy(s->udh, ud + 1, s->udh_len);
		r = parse_udh(s, ud + 1, s->udh_len);
		if (r < 0)
			return r;
	}

	switch (s->charset) {
	case TP_CS_GSM7: {
		uint8_t sept[160];
		size_t skip = (hdr_oct * 8 + 6) / 7;	/* septets taken by the header incl. fill bits */

		if (gsm7_unpack(ud, ud_octets, 0, udl, sept) < 0)
			return TP_E_TRUNC;
		r = gsm7_to_utf8(sept + skip, udl - skip, &b, &lossy);
		s->has_text = true;
		break;
	}
	case TP_CS_UCS2:
		r = decode_ucs2(ud + hdr_oct, ud_octets - hdr_oct, &b, &lossy);
		s->has_text = true;
		break;
	case TP_CS_KSC5601:
		s->data_len = ud_octets - hdr_oct;
		memcpy(s->data, ud + hdr_oct, s->data_len);
		r = euckr_to_utf8(ud + hdr_oct, ud_octets - hdr_oct, &b, &lossy);
		s->has_text = true;
		break;
	default:	/* 8BIT, UNKNOWN: raw */
		s->data_len = ud_octets - hdr_oct;
		memcpy(s->data, ud + hdr_oct, s->data_len);
		r = 0;
	}
	if (r < 0 || !buf_ok(&b))
		return TP_E_OVERFLOW;
	if (lossy)
		s->flags |= TP_F_LOSSY_TEXT;
	s->text_len = b.len;
	return 0;
}

int tp_decode_deliver(const uint8_t *t, size_t n, struct tp_sms *s)
{
	size_t pos = 1;
	int r;

	if (!t || !s)
		return TP_E_ARG;
	memset(s, 0, sizeof(*s));
	s->msg_class = -1;
	if (n < 1)
		return TP_E_TRUNC;
	if ((t[0] & 3) != 0)
		return TP_E_MTI;
	s->mti = 0;
	s->more_messages = !(t[0] & 0x04);
	s->sri = t[0] & 0x20;
	s->udhi = t[0] & 0x40;
	s->rp = t[0] & 0x80;
	r = parse_addr(t + pos, n - pos, &s->addr);
	if (r < 0)
		return r;
	pos += (size_t)r;
	if (n < pos + 2 + 7 + 1)
		return TP_E_TRUNC;
	s->pid = t[pos++];
	s->dcs = t[pos++];
	tp_scts_decode(t + pos, &s->scts);
	if (!s->scts.valid)
		s->flags |= TP_F_BAD_SCTS;
	pos += 7;
	r = decode_dcs(s);
	if (r < 0)
		return r;
	return decode_ud(s, t + pos, n - pos);
}

uint32_t tp_vp_decode(uint8_t vp)
{
	if (vp <= 143)
		return ((uint32_t)vp + 1) * 5;
	if (vp <= 167)
		return 720 + ((uint32_t)vp - 143) * 30;
	if (vp <= 196)
		return ((uint32_t)vp - 166) * 1440;
	return ((uint32_t)vp - 192) * 10080;
}

int tp_vp_encode(uint32_t m)
{
	if (m == 0)
		return TP_E_VP;
	if (m <= 720)
		return (int)((m + 4) / 5) - 1;
	if (m <= 1440)
		return 143 + (int)((m - 720 + 29) / 30);
	if (m <= 43200)
		return 166 + (int)((m + 1439) / 1440);
	if (m > 63u * 10080u)
		return TP_E_VP;
	return 192 + (int)((m + 10079) / 10080);
}

int tp_decode_submit(const uint8_t *t, size_t n, struct tp_sms *s)
{
	size_t pos = 2;
	unsigned vpf;
	int r;

	if (!t || !s)
		return TP_E_ARG;
	memset(s, 0, sizeof(*s));
	s->msg_class = -1;
	if (n < 2)
		return TP_E_TRUNC;
	if ((t[0] & 3) != 1)
		return TP_E_MTI;
	s->mti = 1;
	s->rd = t[0] & 0x04;
	vpf = (t[0] >> 3) & 3;
	s->srr = t[0] & 0x20;
	s->udhi = t[0] & 0x40;
	s->rp = t[0] & 0x80;
	s->mr = t[1];
	r = parse_addr(t + pos, n - pos, &s->addr);
	if (r < 0)
		return r;
	pos += (size_t)r;
	if (n < pos + 2)
		return TP_E_TRUNC;
	s->pid = t[pos++];
	s->dcs = t[pos++];
	if (vpf == 2) {
		if (n < pos + 1)
			return TP_E_TRUNC;
		s->vp_relative = true;
		s->vp_minutes = tp_vp_decode(t[pos]);
		pos += 1;
	} else if (vpf == 1 || vpf == 3) {
		pos += 7;
	}
	if (n < pos + 1)
		return TP_E_TRUNC;
	r = decode_dcs(s);
	if (r < 0)
		return r;
	return decode_ud(s, t + pos, n - pos);
}

/* ------------------------------------------------------------------ */
/* reports                                                            */
/* ------------------------------------------------------------------ */

bool tp_status_is_success(uint8_t st)
{
	return st <= 0x02;
}

bool tp_status_is_final(uint8_t st)
{
	return st <= 0x1F || (st >= 0x40 && st <= 0x7F);
}

int tp_decode_status_report(const uint8_t *t, size_t n, struct tp_status_report *r)
{
	size_t pos = 2;
	int k;

	if (!t || !r)
		return TP_E_ARG;
	memset(r, 0, sizeof(*r));
	if (n < 2)
		return TP_E_TRUNC;
	if ((t[0] & 3) != 2)
		return TP_E_MTI;
	r->more_messages = !(t[0] & 0x04);
	r->lp = t[0] & 0x08;
	r->srq = t[0] & 0x20;
	r->udhi = t[0] & 0x40;
	r->mr = t[1];
	k = parse_addr(t + pos, n - pos, &r->ra);
	if (k < 0)
		return k;
	pos += (size_t)k;
	if (n < pos + 15)
		return TP_E_TRUNC;
	tp_scts_decode(t + pos, &r->scts);
	tp_scts_decode(t + pos + 7, &r->dt);
	r->st = t[pos + 14];
	return 0;
}

int tp_decode_submit_report(const uint8_t *t, size_t n, bool is_error, struct tp_submit_report *r)
{
	size_t pos = 1;

	if (!t || !r)
		return TP_E_ARG;
	memset(r, 0, sizeof(*r));
	if (n < 1)
		return TP_E_TRUNC;
	if ((t[0] & 3) != 1)
		return TP_E_MTI;
	r->udhi = t[0] & 0x40;
	r->is_error = is_error;
	if (is_error) {
		if (n < pos + 1)
			return TP_E_TRUNC;
		r->fcs = t[pos++];
	}
	if (n < pos + 1)
		return TP_E_TRUNC;
	r->pi = t[pos];
	while (t[pos] & 0x80) {		/* extension bit: more PI octets */
		pos++;
		if (n < pos + 1)
			return TP_E_TRUNC;
	}
	pos++;
	if (n < pos + 7)
		return TP_E_TRUNC;
	tp_scts_decode(t + pos, &r->scts);
	pos += 7;
	if (r->pi & 1) {
		if (n < pos + 1)
			return TP_E_TRUNC;
		r->has_pid = true;
		r->pid = t[pos++];
	}
	if (r->pi & 2) {
		if (n < pos + 1)
			return TP_E_TRUNC;
		r->has_dcs = true;
		r->dcs = t[pos++];
	}
	return 0;
}

int tp_rp_user_data(const uint8_t *ie, size_t n, const uint8_t **tpdu, size_t *tpdu_len)
{
	if (!ie || !tpdu || !tpdu_len)
		return TP_E_ARG;
	if (n < 2)
		return TP_E_TRUNC;
	if (ie[0] != 0x41)
		return TP_E_MTI;
	if (n < 2u + ie[1])
		return TP_E_TRUNC;
	*tpdu = ie + 2;
	*tpdu_len = ie[1];
	return 0;
}

/* ------------------------------------------------------------------ */
/* SUBMIT encoder                                                     */
/* ------------------------------------------------------------------ */

static int encode_dest(const char *dest, uint8_t *out, size_t *len)
{
	unsigned nd = 0, i;
	const char *p = dest;
	uint8_t toa = 0x81;
	uint8_t dig[20];

	if (*p == '+') {
		toa = 0x91;
		p++;
	}
	for (; *p; p++) {
		uint8_t v;

		if (*p >= '0' && *p <= '9')
			v = (uint8_t)(*p - '0');
		else if (*p == '*')
			v = 0xA;
		else if (*p == '#')
			v = 0xB;
		else
			return TP_E_ADDR;
		if (nd >= 20)
			return TP_E_ADDR;
		dig[nd++] = v;
	}
	if (nd == 0)
		return TP_E_ADDR;
	out[0] = (uint8_t)nd;
	out[1] = toa;
	for (i = 0; i < nd; i += 2)
		out[2 + i / 2] = (uint8_t)(dig[i] | ((i + 1 < nd ? dig[i + 1] : 0xF) << 4));
	*len = 2 + (nd + 1) / 2;
	return 0;
}

struct seg_it {
	const char *p, *end;
	bool ucs2;
};

/* fills up to limit units (septets or UTF-16 units) and advances; the text was validated before */
static size_t seg_next(struct seg_it *it, size_t limit, uint16_t *u)
{
	size_t n = 0;

	while (it->p < it->end) {
		uint32_t cp = 0;
		uint16_t t[2];
		size_t c, i;
		int k = utf8_decode(it->p, (size_t)(it->end - it->p), &cp);

		if (k < 0)
			break;	/* cannot happen after validation */
		if (it->ucs2) {
			if (cp >= 0x10000) {
				t[0] = (uint16_t)(0xD800 + ((cp - 0x10000) >> 10));
				t[1] = (uint16_t)(0xDC00 + ((cp - 0x10000) & 0x3FF));
				c = 2;
			} else {
				t[0] = (uint16_t)cp;
				c = 1;
			}
		} else {
			uint8_t g[2];

			c = (size_t)gsm7_from_cp(cp, g);
			t[0] = g[0];
			t[1] = g[1];
		}
		if (n + c > limit)
			break;
		for (i = 0; i < c; i++)
			u[n++] = t[i];
		it->p += k;
	}
	return n;
}

int tp_encode_submit(const struct tp_submit_req *rq, struct tp_pdu *out, size_t max_out)
{
	uint8_t da[12];
	size_t dalen, nseg, i, limit_single, limit_multi;
	const char *p, *end;
	bool gsm_ok = true, multi;
	int vp = -1, r;
	struct seg_it it;
	uint16_t units[160];

	if (!rq || !out || !rq->dest || (!rq->text && rq->text_len) || max_out == 0)
		return TP_E_ARG;
	r = encode_dest(rq->dest, da, &dalen);
	if (r < 0)
		return r;
	if (rq->vp_minutes) {
		vp = tp_vp_encode(rq->vp_minutes);
		if (vp < 0)
			return vp;
	}
	/* validate the text and decide the alphabet */
	p = rq->text;
	end = rq->text + rq->text_len;
	while (p < end) {
		uint32_t cp;
		uint8_t g[2];
		int k = utf8_decode(p, (size_t)(end - p), &cp);

		if (k < 0 || cp == 0)
			return TP_E_UTF8;
		if (!gsm7_from_cp(cp, g))
			gsm_ok = false;
		p += k;
	}
	it.ucs2 = rq->force_ucs2 || !gsm_ok;
	limit_single = it.ucs2 ? 70 : 160;
	limit_multi = it.ucs2 ? 67 : 153;

	/* does it fit in one message? */
	it.p = rq->text;
	it.end = end;
	seg_next(&it, limit_single, units);
	multi = it.p < end;
	nseg = 1;
	if (multi) {
		it.p = rq->text;
		nseg = 0;
		while (it.p < end) {
			seg_next(&it, limit_multi, units);
			nseg++;
			if (nseg > TP_MAX_SEGMENTS)
				return TP_E_TOOLONG;
		}
	}
	if (nseg > max_out)
		return TP_E_TOOLONG;

	it.p = rq->text;
	for (i = 0; i < nseg; i++) {
		struct tp_pdu *o = &out[i];
		uint8_t *w = o->data;
		size_t n = seg_next(&it, multi ? limit_multi : limit_single, units), k;
		uint8_t udh[6] = { 5, 0x00, 3, rq->concat_ref, (uint8_t)nseg, (uint8_t)(i + 1) };

		memset(o, 0, sizeof(*o));
		w = o->data;
		*w++ = (uint8_t)(0x01 | (vp >= 0 ? 0x10 : 0) | (rq->status_report ? 0x20 : 0) | (multi ? 0x40 : 0));
		*w++ = (uint8_t)(rq->mr + i);
		memcpy(w, da, dalen);
		w += dalen;
		*w++ = 0x00;				/* PID */
		*w++ = it.ucs2 ? 0x08 : 0x00;		/* DCS */
		if (vp >= 0)
			*w++ = (uint8_t)vp;
		if (it.ucs2) {
			*w++ = (uint8_t)((multi ? 6 : 0) + n * 2);
			if (multi) {
				memcpy(w, udh, 6);
				w += 6;
			}
			for (k = 0; k < n; k++) {
				*w++ = (uint8_t)(units[k] >> 8);
				*w++ = (uint8_t)units[k];
			}
		} else {
			uint8_t sept[160];
			int pk;

			for (k = 0; k < n; k++)
				sept[k] = (uint8_t)units[k];
			*w++ = (uint8_t)((multi ? 7 : 0) + n);
			if (multi) {
				memcpy(w, udh, 6);
				w += 6;
			}
			pk = gsm7_pack(sept, n, multi ? 1 : 0, w, sizeof(o->data) - (size_t)(w - o->data));
			if (pk < 0)
				return TP_E_OVERFLOW;
			w += pk;
		}
		o->len = (size_t)(w - o->data);
		o->ucs2 = it.ucs2;
		o->seq = (uint8_t)(i + 1);
		o->total = (uint8_t)nseg;
	}
	return (int)nseg;
}
