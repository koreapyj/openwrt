/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_STORE_PACK_H
#define IMSD_STORE_PACK_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Tiny serializer for the item payloads (the "meta" of a store item): little endian integers, strings with a u16 length, byte
 * blobs with a u32 length. A reader never goes past the end: a short or damaged payload sets `bad` and returns zeros / empty.
 */
struct pkw {
	uint8_t *p;
	size_t len, cap;
	bool ovf;
};

static inline void pkw_init(struct pkw *w, void *buf, size_t cap)
{
	w->p = buf;
	w->len = 0;
	w->cap = cap;
	w->ovf = false;
}

static inline void pkw_raw(struct pkw *w, const void *d, size_t n)
{
	if (w->ovf || w->len + n > w->cap) {
		w->ovf = true;
		return;
	}
	memcpy(w->p + w->len, d, n);
	w->len += n;
}

static inline void pkw_u8(struct pkw *w, uint8_t v)
{
	pkw_raw(w, &v, 1);
}

static inline void pkw_u16(struct pkw *w, uint16_t v)
{
	uint8_t b[2] = { (uint8_t)v, (uint8_t)(v >> 8) };

	pkw_raw(w, b, 2);
}

static inline void pkw_u32(struct pkw *w, uint32_t v)
{
	uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };

	pkw_raw(w, b, 4);
}

static inline void pkw_u64(struct pkw *w, uint64_t v)
{
	pkw_u32(w, (uint32_t)v);
	pkw_u32(w, (uint32_t)(v >> 32));
}

static inline void pkw_str(struct pkw *w, const char *s)
{
	size_t n = s ? strlen(s) : 0;

	if (n > 0xffff)
		n = 0xffff;
	pkw_u16(w, (uint16_t)n);
	pkw_raw(w, s, n);
}

static inline void pkw_bytes(struct pkw *w, const void *d, size_t n)
{
	pkw_u32(w, (uint32_t)n);
	pkw_raw(w, d, n);
}

struct pkr {
	const uint8_t *p;
	size_t len, pos;
	bool bad;
};

static inline void pkr_init(struct pkr *r, const void *p, size_t n)
{
	r->p = p;
	r->len = n;
	r->pos = 0;
	r->bad = false;
}

static inline const uint8_t *pkr_take(struct pkr *r, size_t n)
{
	const uint8_t *q;

	if (r->bad || r->len - r->pos < n) {
		r->bad = true;
		return NULL;
	}
	q = r->p + r->pos;
	r->pos += n;
	return q;
}

static inline uint8_t pkr_u8(struct pkr *r)
{
	const uint8_t *q = pkr_take(r, 1);

	return q ? q[0] : 0;
}

static inline uint16_t pkr_u16(struct pkr *r)
{
	const uint8_t *q = pkr_take(r, 2);

	return q ? (uint16_t)(q[0] | (q[1] << 8)) : 0;
}

static inline uint32_t pkr_u32(struct pkr *r)
{
	const uint8_t *q = pkr_take(r, 4);

	return q ? (uint32_t)q[0] | ((uint32_t)q[1] << 8) | ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24) : 0;
}

static inline uint64_t pkr_u64(struct pkr *r)
{
	uint64_t lo = pkr_u32(r), hi = pkr_u32(r);

	return lo | (hi << 32);
}

/* a string into out (cap bytes, cut if longer, always terminated) */
static inline void pkr_str(struct pkr *r, char *out, size_t cap)
{
	size_t n = pkr_u16(r), c;
	const uint8_t *q = pkr_take(r, n);

	out[0] = 0;
	if (!q || !cap)
		return;
	c = n < cap - 1 ? n : cap - 1;
	memcpy(out, q, c);
	out[c] = 0;
}

/* a byte blob (points into the payload); *n = 0 and NULL when short */
static inline const uint8_t *pkr_bytes(struct pkr *r, size_t *n)
{
	size_t l = pkr_u32(r);
	const uint8_t *q = pkr_take(r, l);

	*n = q ? l : 0;
	return q;
}
#endif
