/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WSP primitives for the MMS encapsulation, see wsp.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "wsp.h"
#include "../smscodec/euckr.h"
#include "../smscodec/utf8.h"
#include "../util/buf.h"

void wsp_rd_init(struct wsp_rd *r, const uint8_t *p, size_t len)
{
	r->p = p;
	r->len = p ? len : 0;
	r->pos = 0;
}

size_t wsp_left(const struct wsp_rd *r)
{
	return r->len - r->pos;
}

int wsp_sub(struct wsp_rd *r, size_t n, struct wsp_rd *sub)
{
	if (n > wsp_left(r))
		return -1;
	wsp_rd_init(sub, r->p + r->pos, n);
	r->pos += n;
	return 0;
}

int wsp_u8(struct wsp_rd *r, uint8_t *v)
{
	if (!wsp_left(r))
		return -1;
	*v = r->p[r->pos++];
	return 0;
}

int wsp_uintvar(struct wsp_rd *r, uint32_t *v)
{
	uint64_t x = 0;
	int i;

	for (i = 0; i < 5; i++) {
		uint8_t b;

		if (wsp_u8(r, &b))
			return -1;
		x = (x << 7) | (b & 0x7f);
		if (!(b & 0x80)) {
			if (x > 0xffffffffull)
				return -1;
			*v = (uint32_t)x;
			return 0;
		}
	}
	return -1;
}

int wsp_value_length(struct wsp_rd *r, size_t *len)
{
	uint8_t b;
	uint32_t v;

	if (wsp_u8(r, &b))
		return -1;
	if (b <= 30) {
		v = b;
	} else if (b == 31) {
		if (wsp_uintvar(r, &v))
			return -1;
	} else {
		return -1;
	}
	if (v > wsp_left(r))
		return -1;
	*len = v;
	return 0;
}

int wsp_integer(struct wsp_rd *r, uint64_t *v)
{
	uint8_t b;

	if (wsp_u8(r, &b))
		return -1;
	if (b & 0x80) {
		*v = b & 0x7f;
		return 0;
	}
	if (b < 1 || b > 8 || b > wsp_left(r))
		return -1;
	*v = 0;
	while (b--)
		*v = (*v << 8) | r->p[r->pos++];
	return 0;
}

int wsp_text(struct wsp_rd *r, char *out, size_t n, bool *trunc)
{
	size_t i = r->pos, k = 0;

	if (trunc)
		*trunc = false;
	if (i < r->len && (r->p[i] == 0x7f || r->p[i] == 0x22))
		i++;
	while (i < r->len && r->p[i]) {
		if (k + 1 < n)
			out[k++] = (char)r->p[i];
		else if (trunc)
			*trunc = true;
		i++;
	}
	if (i >= r->len)
		return -1;
	if (n)
		out[k] = 0;
	r->pos = i + 1;
	return 0;
}

int wsp_skip_value(struct wsp_rd *r)
{
	uint8_t b;

	if (wsp_u8(r, &b))
		return -1;
	if (b >= 0x80)
		return 0;
	if (b >= 32) {
		r->pos--;
		while (r->pos < r->len && r->p[r->pos])
			r->pos++;
		if (r->pos >= r->len)
			return -1;
		r->pos++;
		return 0;
	}
	if (b == 31) {
		uint32_t v;

		if (wsp_uintvar(r, &v) || v > wsp_left(r))
			return -1;
		r->pos += v;
		return 0;
	}
	if (b > wsp_left(r))
		return -1;
	r->pos += b;
	return 0;
}

/* ------------------------------------------------------------------ */
/* tables                                                              */

static const struct { unsigned mib; const char *name; } CHARSETS[] = {
	{ 3, "us-ascii" }, { 4, "iso-8859-1" }, { 106, "utf-8" }, { 36, "ks_c_5601-1987" }, { 38, "euc-kr" },
	{ 1000, "iso-10646-ucs-2" }, { 1013, "utf-16be" }, { 1014, "utf-16le" }, { 1015, "utf-16" },
	{ 17, "shift_jis" }, { 2025, "gb2312" }, { 2026, "big5" }, { 2252, "windows-1252" },
};

const char *wsp_charset_name(unsigned mib)
{
	size_t i;

	for (i = 0; i < sizeof(CHARSETS) / sizeof(CHARSETS[0]); i++)
		if (CHARSETS[i].mib == mib)
			return CHARSETS[i].name;
	return NULL;
}

static unsigned charset_by_name(const char *s)
{
	size_t i;

	for (i = 0; i < sizeof(CHARSETS) / sizeof(CHARSETS[0]); i++)
		if (!strcasecmp(CHARSETS[i].name, s))
			return CHARSETS[i].mib;
	if (!strcasecmp(s, "euckr") || !strcasecmp(s, "ks_c_5601") || !strcasecmp(s, "cp949"))
		return 38;
	if (!strcasecmp(s, "ucs-2") || !strcasecmp(s, "ucs2"))
		return 1000;
	return 0;
}

/* WAP-230 table 40 (WSP content type assignments), the registered part up to 0x58 */
static const char *const MEDIA[] = {
	"*/*", "text/*", "text/html", "text/plain", "text/x-hdml", "text/x-ttml", "text/x-vCalendar", "text/x-vCard",
	"text/vnd.wap.wml", "text/vnd.wap.wmlscript", "text/vnd.wap.wta-event", "multipart/*", "multipart/mixed",
	"multipart/form-data", "multipart/byteranges", "multipart/alternative",
	"application/*", "application/java-vm", "application/x-www-form-urlencoded", "application/x-hdmlc",
	"application/vnd.wap.wmlc", "application/vnd.wap.wmlscriptc", "application/vnd.wap.wta-eventc",
	"application/vnd.wap.uaprof", "application/vnd.wap.wtls-ca-certificate", "application/vnd.wap.wtls-user-certificate",
	"application/x-x509-ca-cert", "application/x-x509-user-cert",
	"image/*", "image/gif", "image/jpeg", "image/tiff", "image/png", "image/vnd.wap.wbmp",
	"application/vnd.wap.multipart.*", "application/vnd.wap.multipart.mixed", "application/vnd.wap.multipart.form-data",
	"application/vnd.wap.multipart.byteranges", "application/vnd.wap.multipart.alternative",
	"application/xml", "text/xml", "application/vnd.wap.wbxml", "application/x-x968-cross-cert",
	"application/x-x968-ca-cert", "application/x-x968-user-cert", "text/vnd.wap.si", "application/vnd.wap.sic",
	"text/vnd.wap.sl", "application/vnd.wap.slc", "text/vnd.wap.co", "application/vnd.wap.coc",
	"application/vnd.wap.multipart.related", "application/vnd.wap.sia", "text/vnd.wap.connectivity-xml",
	"application/vnd.wap.connectivity-wbxml", "application/pkcs7-mime", "application/vnd.wap.hashed-certificate",
	"application/vnd.wap.signed-certificate", "application/vnd.wap.cert-response", "application/xhtml+xml",
	"application/wml+xml", "text/css", "application/vnd.wap.mms-message", "application/vnd.wap.rollover-certificate",
	"application/vnd.wap.locc+wbxml", "application/vnd.wap.loc+xml", "application/vnd.syncml.dm+wbxml",
	"application/vnd.syncml.dm+xml", "application/vnd.syncml.notification", "application/vnd.wap.xhtml+xml",
	"application/vnd.wv.csp.cir", "application/vnd.oma.dd+xml", "application/vnd.oma.drm.message",
	"application/vnd.oma.drm.content", "application/vnd.oma.drm.rights+xml", "application/vnd.oma.drm.rights+wbxml",
	"application/vnd.wv.csp+xml", "application/vnd.wv.csp+wbxml", "application/vnd.syncml.ds.notification",
	"audio/*", "video/*",
};

const char *wsp_media_name(unsigned code, char *buf, size_t n)
{
	if (code < sizeof(MEDIA) / sizeof(MEDIA[0]))
		return MEDIA[code];
	snprintf(buf, n, "application/x-wap-%02x", code & 0xff);
	return buf;
}

/* ------------------------------------------------------------------ */
/* charset conversion                                                  */

static int put_cp(char *out, size_t cap, size_t *k, uint32_t cp)
{
	char t[4];
	int l;

	if (cp == 0)
		return 0;		/* NUL would end the string early */
	l = utf8_encode(cp, t);
	if (!l)
		l = utf8_encode(UTF8_REPLACEMENT, t);
	if (*k + (size_t)l + 1 > cap)
		return -1;
	memcpy(out + *k, t, (size_t)l);
	*k += (size_t)l;
	return 0;
}

size_t wsp_to_utf8(unsigned mib, const uint8_t *in, size_t n, char *out, size_t cap)
{
	size_t k = 0, i = 0;

	if (!cap)
		return 0;
	if (mib == 38 || mib == 36) {
		struct buf b;
		bool lossy = false;
		size_t j, m = 0;
		uint8_t *tmp = NULL;

		/* NUL bytes would truncate the result: euckr_to_utf8 takes them as plain ASCII, strip them first */
		for (j = 0; j < n; j++)
			m += in[j] != 0;
		if (m != n) {
			tmp = malloc(m ? m : 1);
			if (!tmp) {
				out[0] = 0;
				return 0;
			}
			for (j = 0, m = 0; j < n; j++)
				if (in[j])
					tmp[m++] = in[j];
			in = tmp;
			n = m;
		}
		buf_init_fixed(&b, out, cap);
		euckr_to_utf8(in, n, &b, &lossy);
		free(tmp);
		k = b.len;
		out[k] = 0;
		return k;
	}
	if (mib == 1000 || mib == 1013 || mib == 1014 || mib == 1015) {
		bool le = mib == 1014;

		if (mib == 1015 && n >= 2) {
			if (in[0] == 0xff && in[1] == 0xfe) {
				le = true;
				i = 2;
			} else if (in[0] == 0xfe && in[1] == 0xff) {
				i = 2;
			}
		}
		while (i + 1 < n) {
			uint32_t u = le ? (uint32_t)(in[i] | (in[i + 1] << 8)) : (uint32_t)((in[i] << 8) | in[i + 1]);

			i += 2;
			if (u >= 0xd800 && u < 0xdc00 && i + 1 < n) {
				uint32_t v = le ? (uint32_t)(in[i] | (in[i + 1] << 8)) : (uint32_t)((in[i] << 8) | in[i + 1]);

				if (v >= 0xdc00 && v < 0xe000) {
					u = 0x10000 + ((u - 0xd800) << 10) + (v - 0xdc00);
					i += 2;
				} else {
					u = UTF8_REPLACEMENT;
				}
			} else if (u >= 0xd800 && u < 0xe000) {
				u = UTF8_REPLACEMENT;
			}
			if (put_cp(out, cap, &k, u))
				break;
		}
		out[k] = 0;
		return k;
	}
	while (i < n) {
		uint32_t cp;

		if (mib == 4) {
			cp = in[i++];
		} else if (mib == 3) {
			cp = in[i] < 0x80 ? in[i] : UTF8_REPLACEMENT;
			i++;
		} else {
			int l = utf8_decode((const char *)in + i, n - i, &cp);

			if (l < 0) {
				cp = UTF8_REPLACEMENT;
				l = 1;
			}
			i += (size_t)l;
		}
		if (put_cp(out, cap, &k, cp))
			break;
	}
	out[k] = 0;
	return k;
}

int wsp_encoded_string(struct wsp_rd *r, char *out, size_t n)
{
	char raw[512];
	unsigned mib = 0;
	bool tr;

	if (!n)
		return -1;
	if (wsp_left(r) && r->p[r->pos] == 0) {		/* empty Text-string */
		r->pos++;
		out[0] = 0;
		return 0;
	}
	if (wsp_left(r) && r->p[r->pos] <= 31) {
		struct wsp_rd s;
		size_t l;
		uint64_t cs;

		if (wsp_value_length(r, &l) || wsp_sub(r, l, &s) || wsp_integer(&s, &cs))
			return -1;
		mib = (unsigned)cs;
		if (wsp_text(&s, raw, sizeof(raw), &tr))
			return -1;
	} else if (wsp_text(r, raw, sizeof(raw), &tr)) {
		return -1;
	}
	wsp_to_utf8(mib, (const uint8_t *)raw, strlen(raw), out, n);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Content-type-value                                                  */

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

/* Text-value: No-value (0x00) | Token-text | Quoted-string */
static int param_text(struct wsp_rd *r, char *out, size_t n)
{
	if (wsp_left(r) && r->p[r->pos] == 0) {
		r->pos++;
		out[0] = 0;
		return 0;
	}
	return wsp_text(r, out, n, NULL);
}

/* a media type value: short integer, long integer or text */
static int param_media(struct wsp_rd *r, char *out, size_t n)
{
	char t[32];

	if (!wsp_left(r))
		return -1;
	if (r->p[r->pos] >= 0x80 || r->p[r->pos] <= 30) {
		uint64_t v;

		if (wsp_integer(r, &v))
			return -1;
		copy_str(out, n, wsp_media_name((unsigned)v, t, sizeof(t)));
		return 0;
	}
	return wsp_text(r, out, n, NULL);
}

static int param_charset(struct wsp_rd *r, int *mib)
{
	char t[40];

	if (!wsp_left(r))
		return -1;
	if (r->p[r->pos] >= 0x80 || r->p[r->pos] <= 30) {
		uint64_t v;

		if (wsp_integer(r, &v))
			return -1;
		*mib = v > 100000 ? 0 : (int)v;
		return 0;
	}
	if (wsp_text(r, t, sizeof(t), NULL))
		return -1;
	*mib = (int)charset_by_name(t);
	return 0;
}

/* Parameters until the sub-reader is exhausted. An unknown typed parameter ends the list (its value length is unknown). */
void wsp_parse_params(struct wsp_rd *r, struct wsp_ctype *ct)
{
	while (wsp_left(r)) {
		uint8_t tok = r->p[r->pos];
		char name[24] = "", val[WSP_NAME_MAX];
		int rc = 0;

		if (tok & 0x80) {
			unsigned code = tok & 0x7f;

			r->pos++;
			switch (code) {
			case 0x01:
				rc = param_charset(r, &ct->charset);
				break;
			case 0x03:
			case 0x09:
				rc = param_media(r, ct->type_param, sizeof(ct->type_param));
				break;
			case 0x05:
			case 0x17:
				rc = param_text(r, ct->name, sizeof(ct->name));
				break;
			case 0x06:
			case 0x18:
				rc = param_text(r, ct->filename, sizeof(ct->filename));
				break;
			case 0x0a:
			case 0x19:
				rc = param_text(r, ct->start, sizeof(ct->start));
				break;
			case 0x0b: case 0x0c: case 0x0d: case 0x0f: case 0x1a: case 0x1b: case 0x1c: case 0x1d: case 0x12:
				rc = param_text(r, val, sizeof(val));
				break;
			case 0x00: case 0x02: case 0x07: case 0x08: case 0x0e: case 0x11:
			case 0x13: case 0x14: case 0x15: case 0x16:
				rc = wsp_skip_value(r);
				break;
			case 0x10:		/* Secure: no value */
				break;
			default:
				return;
			}
			if (rc)
				return;
		} else if (tok >= 0x20) {
			if (wsp_text(r, name, sizeof(name), NULL))
				return;
			if (!wsp_left(r))
				return;
			if (r->p[r->pos] >= 0x80 || r->p[r->pos] <= 30) {
				uint64_t v;

				if (wsp_integer(r, &v))
					return;
				if (!strcasecmp(name, "charset"))
					ct->charset = v > 100000 ? 0 : (int)v;
				continue;
			}
			if (param_text(r, val, sizeof(val)))
				return;
			if (!strcasecmp(name, "charset"))
				ct->charset = (int)charset_by_name(val);
			else if (!strcasecmp(name, "type"))
				copy_str(ct->type_param, sizeof(ct->type_param), val);
			else if (!strcasecmp(name, "name"))
				copy_str(ct->name, sizeof(ct->name), val);
			else if (!strcasecmp(name, "filename"))
				copy_str(ct->filename, sizeof(ct->filename), val);
			else if (!strcasecmp(name, "start"))
				copy_str(ct->start, sizeof(ct->start), val);
		} else {
			return;
		}
	}
}

int wsp_content_type(struct wsp_rd *r, struct wsp_ctype *ct)
{
	uint8_t b;
	struct wsp_rd s;
	size_t l;
	uint64_t v;

	memset(ct, 0, sizeof(*ct));
	if (!wsp_left(r))
		return -1;
	b = r->p[r->pos];
	if (b >= 0x80) {
		char t[32];

		r->pos++;
		copy_str(ct->type, sizeof(ct->type), wsp_media_name(b & 0x7f, t, sizeof(t)));
		return 0;
	}
	if (b >= 32)
		return wsp_text(r, ct->type, sizeof(ct->type), NULL);
	if (wsp_value_length(r, &l) || wsp_sub(r, l, &s) || !wsp_left(&s))
		return -1;
	if (s.p[s.pos] >= 0x80 || s.p[s.pos] <= 30) {
		char t[32];

		if (wsp_integer(&s, &v))
			return -1;
		copy_str(ct->type, sizeof(ct->type), wsp_media_name((unsigned)v, t, sizeof(t)));
	} else if (wsp_text(&s, ct->type, sizeof(ct->type), NULL)) {
		return -1;
	}
	wsp_parse_params(&s, ct);
	return 0;
}

int wsp_header_name(struct wsp_rd *r, bool *wellknown, unsigned *code, char *name, size_t n)
{
	uint8_t b;

	if (!wsp_left(r))
		return -1;
	b = r->p[r->pos];
	if (b & 0x80) {
		r->pos++;
		*wellknown = true;
		*code = b & 0x7f;
		if (n)
			name[0] = 0;
		return 0;
	}
	if (b < 32)
		return -1;		/* code page shift: not supported */
	*wellknown = false;
	*code = 0;
	return wsp_text(r, name, n, NULL);
}

/* ------------------------------------------------------------------ */
/* WSP Push                                                            */

static const char *const APP_IDS[] = {
	"x-wap-application:*", "x-wap-application:push.sia", "x-wap-application:wml.ua", "x-wap-application:wta.ua",
	"x-wap-application:mms.ua", "x-wap-application:push.syncml", "x-wap-application:loc.ua",
	"x-wap-application:syncml.dm", "x-wap-application:drm.ua", "x-wap-application:emn.ua", "x-wap-application:wv.ua",
};

int wsp_parse_push(const uint8_t *d, size_t n, struct wsp_push *out)
{
	struct wsp_rd r, h;
	uint8_t tid, type;
	uint32_t hl;

	memset(out, 0, sizeof(*out));
	wsp_rd_init(&r, d, n);
	if (wsp_u8(&r, &tid) || wsp_u8(&r, &type) || (type != 6 && type != 7) || wsp_uintvar(&r, &hl) ||
	    wsp_sub(&r, hl, &h))
		return -1;
	out->tid = tid;
	out->pdu_type = type;
	if (wsp_content_type(&h, &out->ct))
		return -1;
	while (wsp_left(&h)) {		/* headers are advisory: a malformed one ends the list */
		bool wk;
		unsigned code;
		char name[48];

		if (wsp_header_name(&h, &wk, &code, name, sizeof(name)))
			break;
		if (wk && code == 0x2f && wsp_left(&h)) {
			if (h.p[h.pos] >= 0x80) {
				unsigned id = h.p[h.pos++] & 0x7f;

				snprintf(out->app_id, sizeof(out->app_id), "%s",
					 id < sizeof(APP_IDS) / sizeof(APP_IDS[0]) ? APP_IDS[id] : "x-wap-application:unknown");
				out->has_app_id = true;
				continue;
			}
			if (h.p[h.pos] >= 32) {
				if (wsp_text(&h, out->app_id, sizeof(out->app_id), NULL))
					break;
				out->has_app_id = true;
				continue;
			}
		}
		if (wsp_skip_value(&h))
			break;
	}
	out->body = r.p + r.pos;
	out->body_len = wsp_left(&r);
	return 0;
}
