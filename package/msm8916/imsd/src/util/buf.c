/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "buf.h"

#define BUF_DEFAULT_MAX 65536

void buf_init(struct buf *b, size_t max)
{
	memset(b, 0, sizeof(*b));
	b->max = max ? max : BUF_DEFAULT_MAX;
}

void buf_init_fixed(struct buf *b, void *storage, size_t cap)
{
	memset(b, 0, sizeof(*b));
	b->p = storage;
	b->cap = cap;
	b->max = cap ? cap - 1 : 0;
	b->fixed = true;
	if (cap)
		b->p[0] = 0;
	else
		b->ovf = true;
}

void buf_free(struct buf *b)
{
	if (!b->fixed)
		free(b->p);
	memset(b, 0, sizeof(*b));
}

void buf_reset(struct buf *b)
{
	b->len = 0;
	b->ovf = b->fixed && b->cap == 0;
	if (b->p)
		b->p[0] = 0;
}

static int buf_ensure(struct buf *b, size_t add)
{
	size_t need, ncap;
	uint8_t *np;

	if (b->ovf)
		return -1;
	if (add > b->max || b->len > b->max - add)
		goto fail;
	need = b->len + add + 1;
	if (need <= b->cap)
		return 0;
	if (b->fixed)
		goto fail;
	ncap = b->cap ? b->cap : 256;
	while (ncap < need)
		ncap *= 2;
	if (ncap > b->max + 1)
		ncap = b->max + 1;
	np = realloc(b->p, ncap);
	if (!np)
		goto fail;
	b->p = np;
	b->cap = ncap;
	return 0;
fail:
	b->ovf = true;
	return -1;
}

int buf_add(struct buf *b, const void *data, size_t n)
{
	if (buf_ensure(b, n))
		return -1;
	if (n)
		memcpy(b->p + b->len, data, n);
	b->len += n;
	b->p[b->len] = 0;
	return 0;
}

int buf_puts(struct buf *b, const char *s)
{
	return buf_add(b, s, strlen(s));
}

int buf_putc(struct buf *b, char c)
{
	return buf_add(b, &c, 1);
}

int buf_printf(struct buf *b, const char *fmt, ...)
{
	va_list ap;
	char tmp[256];
	int r;

	va_start(ap, fmt);
	r = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (r < 0) {
		b->ovf = true;
		return -1;
	}
	if ((size_t)r < sizeof(tmp))
		return buf_add(b, tmp, r);
	/* long: format straight into the buffer */
	if (buf_ensure(b, r))
		return -1;
	va_start(ap, fmt);
	vsnprintf((char *)b->p + b->len, b->cap - b->len, fmt, ap);
	va_end(ap);
	b->len += r;
	return 0;
}

bool buf_ok(const struct buf *b)
{
	return !b->ovf;
}

const char *buf_cstr(const struct buf *b)
{
	return b->p ? (const char *)b->p : "";
}

uint8_t *buf_steal(struct buf *b, size_t *n)
{
	uint8_t *p;

	if (b->ovf || b->fixed || !b->p)
		return NULL;
	p = b->p;
	if (n)
		*n = b->len;
	memset(b, 0, sizeof(*b));
	return p;
}
