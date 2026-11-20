/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "amr.h"

/* RFC 4867 table 1 (class A+B+C bits) */
static const uint16_t nb_bits[16] = { 95, 103, 118, 134, 148, 159, 204, 244, 39,
				      0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0 };
static const uint16_t wb_bits[16] = { 132, 177, 253, 285, 317, 365, 397, 461, 477, 40,
				      0xffff, 0xffff, 0xffff, 0xffff, 0, 0 };
static const int nb_bps[8] = { 4750, 5150, 5900, 6700, 7400, 7950, 10200, 12200 };
static const int wb_bps[9] = { 6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850 };

int amr_frame_bits(enum amr_type t, unsigned ft)
{
	unsigned v;

	if (ft > 15)
		return -1;
	v = t == AMR_WB ? wb_bits[ft] : nb_bits[ft];
	return v == 0xffff ? -1 : (int)v;
}

int amr_frame_bytes(enum amr_type t, unsigned ft)
{
	int b = amr_frame_bits(t, ft);

	return b < 0 ? -1 : (b + 7) / 8;
}

int amr_max_mode(enum amr_type t)
{
	return t == AMR_WB ? 8 : 7;
}

bool amr_ft_is_speech(enum amr_type t, unsigned ft)
{
	return (int)ft <= amr_max_mode(t);
}

bool amr_ft_is_dtx(enum amr_type t, unsigned ft)
{
	if (t == AMR_WB)
		return ft == AMR_WB_FT_SID || ft == AMR_WB_FT_LOST || ft == AMR_FT_NO_DATA;
	return ft == AMR_NB_FT_SID || ft == AMR_FT_NO_DATA;
}

int amr_mode_bps(enum amr_type t, int mode)
{
	if (mode < 0 || mode > amr_max_mode(t))
		return 0;
	return t == AMR_WB ? wb_bps[mode] : nb_bps[mode];
}

void amr_frame_finish(struct amr_frame *fr)
{
	fr->data[0] = (uint8_t)((fr->ft << 3) | (fr->q ? 4 : 0));
}

int amr_frame_from_storage(enum amr_type t, struct amr_frame *fr, const uint8_t *st, size_t len)
{
	int nb;

	if (len < 1)
		return -1;
	fr->ft = (st[0] >> 3) & 0x0f;
	fr->q = (st[0] >> 2) & 1;
	nb = amr_frame_bytes(t, fr->ft);
	if (nb < 0 || len != (size_t)nb + 1)
		return -1;
	fr->nbytes = (uint8_t)nb;
	memcpy(fr->data + 1, st + 1, (size_t)nb);
	amr_frame_finish(fr);
	return 0;
}

/* ---- bit reader / writer (MSB first) ---- */

struct bitr {
	const uint8_t *p;
	size_t pos, total;	/* bit positions */
};

static int bitr_get(struct bitr *r, unsigned n, unsigned *v)
{
	unsigned x = 0;

	if (r->pos + n > r->total)
		return -1;
	while (n--) {
		x = (x << 1) | ((r->p[r->pos >> 3] >> (7 - (r->pos & 7))) & 1);
		r->pos++;
	}
	*v = x;
	return 0;
}

/* copy nbits bits starting at bit offset pos of p into dst (MSB first, zero padded) */
static void bits_extract(const uint8_t *p, size_t pos, unsigned nbits, uint8_t *dst)
{
	unsigned i, nb = (nbits + 7) / 8;

	memset(dst, 0, nb);
	if ((pos & 7) == 0) {
		memcpy(dst, p + (pos >> 3), nb);
	} else {
		unsigned sh = pos & 7;
		const uint8_t *s = p + (pos >> 3);

		for (i = 0; i < nb; i++) {
			/* the byte after the last may lie outside the frame; callers guarantee bounds via total */
			unsigned hi = s[i], lo = 0;

			if (i * 8 + (8 - sh) < nbits)
				lo = s[i + 1];
			dst[i] = (uint8_t)((hi << sh) | (lo >> (8 - sh)));
		}
	}
	if (nbits & 7)
		dst[nb - 1] &= (uint8_t)(0xff << (8 - (nbits & 7)));
}

int amr_parse(enum amr_type t, bool oa, const uint8_t *p, size_t len, struct amr_pdu *o)
{
	struct { uint8_t ft, q; } toc[AMR_MAX_FRAMES];
	unsigned n = 0, i;
	bool more = true;

	o->n = 0;
	if (len < 2)
		return -1;
	if (oa) {
		size_t pos = 1;

		o->cmr = p[0] >> 4;
		while (more) {
			uint8_t b;

			if (pos >= len || n >= AMR_MAX_FRAMES)
				return -1;
			b = p[pos++];
			more = b & 0x80;
			toc[n].ft = (b >> 3) & 0x0f;
			toc[n].q = (b >> 2) & 1;
			n++;
		}
		for (i = 0; i < n; i++) {
			int nb = amr_frame_bytes(t, toc[i].ft);

			if (nb < 0 || pos + (size_t)nb > len)
				return -1;
			o->f[i].ft = toc[i].ft;
			o->f[i].q = toc[i].q;
			o->f[i].nbytes = (uint8_t)nb;
			memcpy(o->f[i].data + 1, p + pos, (size_t)nb);
			/* clear pad bits so a repack is canonical */
			if (nb) {
				int bits = amr_frame_bits(t, toc[i].ft);

				if (bits & 7)
					o->f[i].data[nb] &= (uint8_t)(0xff << (8 - (bits & 7)));
			}
			amr_frame_finish(&o->f[i]);
			pos += (size_t)nb;
		}
	} else {
		struct bitr r = { p, 0, len * 8 };
		unsigned v = 0;

		bitr_get(&r, 4, &v);
		o->cmr = (uint8_t)v;
		while (more) {
			unsigned f, ft, q;

			if (n >= AMR_MAX_FRAMES || bitr_get(&r, 1, &f) || bitr_get(&r, 4, &ft) || bitr_get(&r, 1, &q))
				return -1;
			more = f;
			toc[n].ft = (uint8_t)ft;
			toc[n].q = (uint8_t)q;
			n++;
		}
		for (i = 0; i < n; i++) {
			int bits = amr_frame_bits(t, toc[i].ft);

			if (bits < 0 || r.pos + (size_t)bits > r.total)
				return -1;
			o->f[i].ft = toc[i].ft;
			o->f[i].q = toc[i].q;
			o->f[i].nbytes = (uint8_t)((bits + 7) / 8);
			if (bits)
				bits_extract(p, r.pos, (unsigned)bits, o->f[i].data + 1);
			amr_frame_finish(&o->f[i]);
			r.pos += (size_t)bits;
		}
	}
	o->n = n;
	return 0;
}

int amr_build(enum amr_type t, bool oa, unsigned cmr, const struct amr_frame *f, unsigned n,
	      uint8_t *out, size_t outsz)
{
	unsigned i;

	if (n == 0 || n > AMR_MAX_FRAMES || cmr > 15)
		return -1;
	for (i = 0; i < n; i++)
		if (amr_frame_bits(t, f[i].ft) < 0)
			return -1;
	if (oa) {
		size_t pos = 1 + n;

		for (i = 0; i < n; i++)
			pos += (size_t)amr_frame_bytes(t, f[i].ft);
		if (pos > outsz)
			return -1;
		out[0] = (uint8_t)(cmr << 4);
		for (i = 0; i < n; i++)
			out[1 + i] = (uint8_t)((i + 1 < n ? 0x80 : 0) | (f[i].ft << 3) | (f[i].q ? 4 : 0));
		pos = 1 + n;
		for (i = 0; i < n; i++) {
			int nb = amr_frame_bytes(t, f[i].ft);

			if (nb < 0)
				return -1;
			memcpy(out + pos, f[i].data + 1, (size_t)nb);
			if (nb) {
				int bits = amr_frame_bits(t, f[i].ft);

				if (bits & 7)
					out[pos + (size_t)nb - 1] &= (uint8_t)(0xff << (8 - (bits & 7)));
			}
			pos += (size_t)nb;
		}
		return (int)pos;
	} else {
		size_t bitpos = 4 + 6 * (size_t)n, total, k;

		for (i = 0; i < n; i++)
			bitpos += (size_t)amr_frame_bits(t, f[i].ft);
		total = (bitpos + 7) / 8;
		if (total > outsz)
			return -1;
		memset(out, 0, total);
		out[0] = (uint8_t)(cmr << 4);
		bitpos = 4;
#define PUTBITS(val, cnt) do { \
		unsigned _c = (cnt), _v = (val); \
		while (_c--) { \
			if ((_v >> _c) & 1) \
				out[bitpos >> 3] |= (uint8_t)(0x80 >> (bitpos & 7)); \
			bitpos++; \
		} \
	} while (0)
		for (i = 0; i < n; i++) {
			PUTBITS(i + 1 < n, 1);
			PUTBITS(f[i].ft, 4);
			PUTBITS(f[i].q ? 1 : 0, 1);
		}
		for (i = 0; i < n; i++) {
			unsigned bits = (unsigned)amr_frame_bits(t, f[i].ft);

			for (k = 0; k < bits; k++, bitpos++)
				if (f[i].data[1 + (k >> 3)] & (0x80 >> (k & 7)))
					out[bitpos >> 3] |= (uint8_t)(0x80 >> (bitpos & 7));
		}
#undef PUTBITS
		return (int)total;
	}
}

uint16_t amr_modeset_all(enum amr_type t)
{
	return (uint16_t)((1u << (amr_max_mode(t) + 1)) - 1);
}

uint16_t amr_modeset_parse(enum amr_type t, const char *s)
{
	uint16_t mask = 0;

	if (!s)
		return amr_modeset_all(t);
	while (isspace((unsigned char)*s))
		s++;
	if (!*s)
		return amr_modeset_all(t);
	for (;;) {
		char *e;
		long v;

		while (isspace((unsigned char)*s))
			s++;
		if (!isdigit((unsigned char)*s))
			return 0;
		v = strtol(s, &e, 10);
		if (v < 0 || v > amr_max_mode(t))
			return 0;
		mask |= (uint16_t)(1u << v);
		s = e;
		while (isspace((unsigned char)*s))
			s++;
		if (!*s)
			return mask;
		if (*s != ',')
			return 0;
		s++;
	}
}

int amr_mode_clamp(enum amr_type t, uint16_t mask, int req)
{
	int max = amr_max_mode(t), m;

	mask &= amr_modeset_all(t);
	if (req < 0)
		req = 0;
	if (req > max)
		req = max;
	if (!mask)
		return req;
	for (m = req; m >= 0; m--)
		if (mask & (1u << m))
			return m;
	for (m = req + 1; m <= max; m++)
		if (mask & (1u << m))
			return m;
	return req;
}

int amr_apply_cmr(enum amr_type t, uint16_t mask, int cur, unsigned cmr)
{
	if (cmr == AMR_CMR_NONE || (int)cmr > amr_max_mode(t))
		return cur;
	return amr_mode_clamp(t, mask, (int)cmr);
}
