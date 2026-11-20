/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "lan_text.h"
#include "../util/log.h"

struct lan_text {
	struct lan_fork *f;
	lan_text_cb cb;
	void *arg;
	int nok_b;
	bool called;
};

static void fork_cb(struct lan_fork *f, struct lan_fork_event *ev, void *arg)
{
	struct lan_text *t = arg;

	(void)f;
	switch (ev->type) {
	case LAN_FORK_BRANCH_FINAL:
		if (ev->cause == LAN_BR_RESPONSE && ev->status >= 200 && ev->status < 300)
			t->nok_b++;
		break;
	case LAN_FORK_COMPLETE:
		if (!t->called) {
			int nok = ev->nok > t->nok_b ? ev->nok : t->nok_b;

			t->called = true;
			t->cb(t->arg, nok);
			/* the answer is known: let the transactions end by themselves, nothing is reported any more. This also
			 * releases us when the LAN object goes away before the fork's DONE (which then never comes). */
			lan_fork_detach(t->f);
			free(t);
		}
		break;
	case LAN_FORK_DONE:
		if (!t->called) {		/* ended without COMPLETE: report what we counted */
			t->called = true;
			t->cb(t->arg, t->nok_b);
		}
		free(t);
		break;
	default:
		break;
	}
}

struct lan_text *lan_text_send_ex(struct lan *l, const struct lan_text_opts *o, lan_text_cb cb, void *arg)
{
	struct lan_text *t;
	struct lan_req q;

	if (!l || !cb) {
		errno = l ? EINVAL : ENOENT;
		return NULL;
	}
	t = calloc(1, sizeof(*t));
	if (!t)
		return NULL;
	t->cb = cb;
	t->arg = arg;
	memset(&q, 0, sizeof(q));
	q.method = "MESSAGE";
	q.from_user = o->from_user;
	q.from_display = o->from_display && o->from_display[0] ? o->from_display : NULL;
	q.extra = o->extra && o->extra[0] ? o->extra : NULL;
	q.content_type = o->body_len ? o->content_type : NULL;
	q.body = o->body;
	q.body_len = o->body_len;
	t->f = lan_fork_request(l, &q, &o->fork, fork_cb, t, NULL);
	if (!t->f) {
		int e = errno;

		free(t);
		errno = e;
		return NULL;
	}
	return t;
}

struct lan_text *lan_text_send(struct lan *l, const char *from_user, const char *from_display, const char *extra,
			       const char *text, lan_text_cb cb, void *arg)
{
	struct lan_text_opts o;

	memset(&o, 0, sizeof(o));
	o.from_user = from_user;
	o.from_display = from_display;
	o.extra = extra;
	o.content_type = "text/plain; charset=utf-8";
	o.body = (const uint8_t *)text;
	o.body_len = strlen(text);
	return lan_text_send_ex(l, &o, cb, arg);
}

void lan_text_detach(struct lan_text *t)
{
	if (!t)
		return;
	t->called = true;
	lan_fork_detach(t->f);		/* no more events: the fork finishes silently */
	free(t);
}

/* ------------------------------------------------------------------ */
/* which bindings                                                      */

unsigned lan_select(struct lan *l, uint32_t need, uint32_t forbid, reg_id_t *out, unsigned max)
{
	struct registrar *r = l ? lan_registrar(l) : NULL;
	const struct reg_binding *b;
	reg_id_t id = REG_ID_NONE;
	unsigned n = 0;

	while (r && n < max && (b = reg_next(r, id))) {
		id = b->id;
		if ((b->features & need) == need && !(b->features & forbid) && reg_allows(b, "MESSAGE"))
			out[n++] = b->id;
	}
	return n;
}

/* ------------------------------------------------------------------ */
/* lossless splitting                                                  */

unsigned lan_text_split(const char *s, size_t len, size_t limit, size_t *off, size_t *plen, unsigned max, bool *truncated)
{
	size_t pos = 0;
	unsigned k = 0;

	*truncated = false;
	if (limit < 16)
		limit = 16;
	while (pos < len) {
		size_t cut = len - pos;

		if (k == max) {
			*truncated = true;
			break;
		}
		if (cut > limit) {
			size_t c = limit, i;

			while (c > 0 && ((unsigned char)s[pos + c] & 0xc0) == 0x80)
				c--;
			for (i = c; i > limit / 2; i--)
				if (s[pos + i - 1] == '\n') {
					c = i;
					break;
				}
			cut = c;
		}
		off[k] = pos;
		plen[k] = cut;
		k++;
		pos += cut;
	}
	return k;
}

#define MARKER_ROOM	12		/* "(10/16) " and a margin */

int lan_pieces_make(struct lan_pieces *p, const char *s, size_t len, unsigned split)
{
	size_t off[LAN_PIECES_MAX], plen[LAN_PIECES_MAX], total = 0, o = 0;
	unsigned np, limit, i;

	memset(p, 0, sizeof(*p));
	limit = split > MARKER_ROOM + 16 ? split - MARKER_ROOM : 16;
	np = lan_text_split(s, len, len <= split ? len : limit, off, plen, LAN_PIECES_MAX, &p->truncated);
	if (!np) {
		off[0] = 0;
		plen[0] = 0;
		np = 1;
	}
	for (i = 0; i < np; i++)
		total += plen[i] + MARKER_ROOM + 1;
	p->mem = malloc(total + 1);
	if (!p->mem)
		return -ENOMEM;
	for (i = 0; i < np; i++) {
		p->text[i] = p->mem + o;
		if (np > 1)
			o += (size_t)snprintf(p->mem + o, total + 1 - o, "(%u/%u) ", i + 1, np);
		memcpy(p->mem + o, s + off[i], plen[i]);
		o += plen[i];
		p->mem[o++] = 0;
	}
	p->n = np;
	return 0;
}

void lan_pieces_free(struct lan_pieces *p)
{
	free(p->mem);
	memset(p, 0, sizeof(*p));
}

/* ------------------------------------------------------------------ */
/* pieces in sequence                                                  */

struct lan_seq {
	struct lan_seq *next;
	struct lan_seqs *o;
	void (*done)(void *arg, int nok);
	void *arg;
	char from_user[96], from_display[80];
	char extra[2048];
	char part_hdr[24];
	char ctype[64];
	uint8_t *bin;
	size_t bin_len;
	char *text[LAN_PIECES_MAX];
	unsigned n, idx;
	reg_id_t inc[LAN_SELECT_MAX], exc[LAN_SELECT_MAX];
	unsigned ninc, nexc;
	bool include_set;
	int nok_min;
	struct lan_text *cur;
};

struct lan_seqs {
	struct lan *lan;
	struct lan_seq *list;
};

struct lan_seqs *lan_seqs_new(void)
{
	return calloc(1, sizeof(struct lan_seqs));
}

static void seq_free(struct lan_seq *sq)
{
	struct lan_seq **pp;
	unsigned i;

	for (pp = &sq->o->list; *pp; pp = &(*pp)->next)
		if (*pp == sq) {
			*pp = sq->next;
			break;
		}
	lan_text_detach(sq->cur);
	for (i = 0; i < sq->n; i++)
		free(sq->text[i]);
	free(sq->bin);
	free(sq);
}

void lan_seqs_abort(struct lan_seqs *o, void *arg)
{
	struct lan_seq *sq, *nx;

	for (sq = o->list; sq; sq = nx) {
		nx = sq->next;
		if (sq->arg == arg)
			seq_free(sq);
	}
}

void lan_seqs_free(struct lan_seqs *o)
{
	if (!o)
		return;
	while (o->list)
		seq_free(o->list);
	free(o);
}

void lan_seqs_set(struct lan_seqs *o, struct lan *l)
{
	o->lan = l;
	if (!l)
		while (o->list)
			seq_free(o->list);	/* the object the forks run on goes away: they end without a callback */
}

static void seq_piece(struct lan_seq *sq);

static void seq_piece_done(void *arg, int nok)
{
	struct lan_seq *sq = arg;

	sq->cur = NULL;		/* the fork finishes by itself */
	if (nok < sq->nok_min)
		sq->nok_min = nok;
	if (nok > 0 && sq->idx + 1 < sq->n) {
		sq->idx++;
		seq_piece(sq);
		return;
	}
	{
		void (*done)(void *, int) = sq->done;
		void *a = sq->arg;
		int r = nok > 0 ? sq->nok_min : 0;

		seq_free(sq);
		if (done)
			done(a, r);
	}
}

/* 0, or -errno (nothing started) */
static int seq_piece_start(struct lan_seq *sq)
{
	struct lan_text_opts o;
	char extra[2100];

	memset(&o, 0, sizeof(o));
	snprintf(extra, sizeof(extra), "%s", sq->extra);
	if (sq->n > 1 && sq->part_hdr[0])
		snprintf(extra + strlen(extra), sizeof(extra) - strlen(extra), "%s: %u/%u\r\n", sq->part_hdr, sq->idx + 1, sq->n);
	o.from_user = sq->from_user;
	o.from_display = sq->from_display;
	o.extra = extra;
	if (sq->bin) {
		o.content_type = sq->ctype;
		o.body = sq->bin;
		o.body_len = sq->bin_len;
	} else {
		o.content_type = "text/plain; charset=utf-8";
		o.body = (const uint8_t *)sq->text[sq->idx];
		o.body_len = strlen(sq->text[sq->idx]);
	}
	o.fork.include = sq->inc;
	o.fork.ninclude = sq->ninc;
	o.fork.include_set = sq->include_set;
	o.fork.exclude = sq->exc;
	o.fork.nexclude = sq->nexc;
	sq->cur = lan_text_send_ex(sq->o->lan, &o, seq_piece_done, sq);
	return sq->cur ? 0 : -(errno ? errno : EIO);
}

static void seq_piece(struct lan_seq *sq)
{
	int rc = seq_piece_start(sq);

	if (rc) {
		void (*done)(void *, int) = sq->done;
		void *a = sq->arg;

		LOGW("lan: cannot deliver piece %u of %u (%s)", sq->idx + 1, sq->n, strerror(-rc));
		seq_free(sq);
		if (done)
			done(a, 0);
	}
}

int lan_seq_start(struct lan_seqs *o, const struct lan_seq_cfg *c)
{
	struct lan_seq *sq;
	unsigned i;
	int rc;

	if (!o->lan)
		return -ENOENT;
	if (c->body_len) {
		if (c->n || !c->body || !c->content_type || strlen(c->content_type) >= sizeof(((struct lan_seq *)0)->ctype))
			return -EINVAL;
	} else if (!c->n || c->n > LAN_PIECES_MAX) {
		return -EINVAL;
	}
	if (strlen(c->extra ? c->extra : "") > 1900)
		return -EINVAL;
	sq = calloc(1, sizeof(*sq));
	if (!sq)
		return -ENOMEM;
	sq->o = o;
	sq->done = c->done;
	sq->arg = c->arg;
	sq->n = c->n;
	sq->nok_min = 0x7fffffff;
	if (c->body_len) {
		sq->bin = malloc(c->body_len);
		if (!sq->bin) {
			free(sq);
			return -ENOMEM;
		}
		memcpy(sq->bin, c->body, c->body_len);
		sq->bin_len = c->body_len;
		snprintf(sq->ctype, sizeof(sq->ctype), "%s", c->content_type);
	}
	snprintf(sq->from_user, sizeof(sq->from_user), "%s", c->from_user ? c->from_user : "");
	snprintf(sq->from_display, sizeof(sq->from_display), "%s", c->from_display ? c->from_display : "");
	snprintf(sq->extra, sizeof(sq->extra), "%s", c->extra ? c->extra : "");
	snprintf(sq->part_hdr, sizeof(sq->part_hdr), "%s", c->part_hdr ? c->part_hdr : "");
	for (i = 0; i < c->n; i++) {
		sq->text[i] = strdup(c->text[i]);
		if (!sq->text[i]) {
			unsigned k;

			for (k = 0; k < i; k++)
				free(sq->text[k]);
			free(sq);
			return -ENOMEM;
		}
	}
	sq->ninc = c->ninclude > LAN_SELECT_MAX ? LAN_SELECT_MAX : c->ninclude;
	sq->nexc = c->nexclude > LAN_SELECT_MAX ? LAN_SELECT_MAX : c->nexclude;
	if (sq->ninc)
		memcpy(sq->inc, c->include, sq->ninc * sizeof(reg_id_t));
	if (sq->nexc)
		memcpy(sq->exc, c->exclude, sq->nexc * sizeof(reg_id_t));
	sq->include_set = c->include_set;
	sq->next = o->list;
	o->list = sq;
	rc = seq_piece_start(sq);
	if (rc) {
		for (i = 0; i < sq->n; i++) {
			free(sq->text[i]);
			sq->text[i] = NULL;
		}
		sq->n = 0;
		seq_free(sq);
		return rc;
	}
	return 0;
}

void lan_text_iso(int64_t t, char *out, size_t n)
{
	time_t tt = (time_t)t;
	struct tm tm;

	if (!gmtime_r(&tt, &tm)) {
		out[0] = 0;
		return;
	}
	snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d+00:00", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
		 tm.tm_sec);
}
