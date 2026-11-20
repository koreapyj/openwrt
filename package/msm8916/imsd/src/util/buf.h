/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UTIL_BUF_H
#define IMSD_UTIL_BUF_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Small growable byte buffer / string builder.
 *
 * Writes never truncate silently: when the data does not fit (fixed storage,
 * or growable storage at its max size) the sticky overflow flag is set, the
 * write is dropped completely and later writes are dropped too. Check
 * buf_ok() once after building.  The contents are always NUL terminated
 * (the terminator is not counted in len), so they may be used as a C string
 * when they are text.
 */
struct buf {
	uint8_t *p;
	size_t len, cap, max;
	bool fixed;	/* p is caller storage, never freed or grown */
	bool ovf;
};

/* growable buffer, content limited to max bytes (max == 0: 64 KiB) */
void buf_init(struct buf *b, size_t max);
/* buffer on caller storage of cap bytes (usable content: cap - 1) */
void buf_init_fixed(struct buf *b, void *storage, size_t cap);
/* free heap storage (no-op for fixed) and reset */
void buf_free(struct buf *b);
/* drop contents and the overflow flag, keep storage */
void buf_reset(struct buf *b);
/* 0 on success, -1 (and overflow flag) if it does not fit */
int buf_add(struct buf *b, const void *data, size_t n);
int buf_puts(struct buf *b, const char *s);
int buf_putc(struct buf *b, char c);
int buf_printf(struct buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* true if nothing overflowed */
bool buf_ok(const struct buf *b);
/* NUL terminated contents ("" when nothing was written yet) */
const char *buf_cstr(const struct buf *b);
/* hand heap contents to the caller (len in *n); the buf is reset. NULL on overflow/OOM. */
uint8_t *buf_steal(struct buf *b, size_t *n);
#endif
