/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Persistent location table of the LAN registrar, see regpersist.h. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "regpersist.h"
#include "../store/sio.h"
#include "../util/addr.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define MAGIC		"IMSDREG1"
#define FILE_VERSION	1u
#define FILE_NAME	"bindings"
#define HDR_LEN		24u
#define REC_MAX		1536u
#define MAX_REC		256u		/* sanity bound on the count in a file */
#define URGENT_MS	1000u
#define LAZY_MS		60000u
#define CLOCK_OK	1577836800LL	/* 2020-01-01: an earlier wall clock has not been set (no NTP yet) */
#define SHADOW_MAX	32

struct shadow {
	reg_id_t id;
	uint64_t sig;
};

struct regpersist {
	struct regpersist_cfg cfg;
	struct sio *io;
	struct ev_fd *efd;
	struct ev_timer *t_wr;
	struct registrar *reg;
	struct sip_endpoint *ep;
	uint32_t gen;			/* attachment generation: completions of an older one are ignored */
	bool loaded, restoring, dirty, urgent, warned;
	uint64_t last_write_ms, due_ms;
	struct shadow sh[SHADOW_MAX];
	struct regpersist_stats st;
};

/* ------------------------------------------------------------------ */
/* byte buffers                                                        */

struct wbuf {
	uint8_t *p;
	size_t n, cap;
	bool bad;
};

static void w_raw(struct wbuf *w, const void *d, size_t n)
{
	if (w->bad || w->n + n > w->cap) {
		w->bad = true;
		return;
	}
	memcpy(w->p + w->n, d, n);
	w->n += n;
}

static void w_u(struct wbuf *w, uint64_t v, unsigned bytes)
{
	uint8_t b[8];
	unsigned i;

	for (i = 0; i < bytes; i++)
		b[i] = (uint8_t)(v >> (8 * i));
	w_raw(w, b, bytes);
}

static void w_str(struct wbuf *w, const char *s)
{
	size_t l = strlen(s);

	if (l > 0xffff) {
		w->bad = true;
		return;
	}
	w_u(w, l, 2);
	w_raw(w, s, l);
}

struct rbuf {
	const uint8_t *p;
	size_t n, o;
	bool bad;
};

static uint64_t r_u(struct rbuf *r, unsigned bytes)
{
	uint64_t v = 0;
	unsigned i;

	if (r->bad || r->o + bytes > r->n) {
		r->bad = true;
		return 0;
	}
	for (i = 0; i < bytes; i++)
		v |= (uint64_t)r->p[r->o + i] << (8 * i);
	r->o += bytes;
	return v;
}

static void r_str(struct rbuf *r, char *out, size_t cap)
{
	size_t l = (size_t)r_u(r, 2);

	if (r->bad || r->o + l > r->n || l >= cap) {
		r->bad = true;
		out[0] = 0;
		return;
	}
	memcpy(out, r->p + r->o, l);
	out[l] = 0;
	r->o += l;
}

/* ------------------------------------------------------------------ */
/* time                                                                */

static int64_t wall(const struct regpersist *p)
{
	return p->cfg.wall ? p->cfg.wall(p->cfg.ctx) : (int64_t)time(NULL);
}

/* ------------------------------------------------------------------ */
/* the file                                                            */

/* wall clock time of a monotonic ms stamp */
static int64_t to_wall(int64_t now_w, uint64_t now_ms, uint64_t ms)
{
	return ms >= now_ms ? now_w + (int64_t)((ms - now_ms) / 1000) : now_w - (int64_t)((now_ms - ms + 999) / 1000);
}

static void put_record(struct wbuf *w, const struct reg_binding *b, int64_t now_w, uint64_t now_ms)
{
	struct wbuf rec;
	uint8_t tmp[REC_MAX];
	char sh[64], th[64];
	uint8_t flags = (b->target_from_src ? 1 : 0) | (b->allow_known ? 2 : 0) | (b->answered ? 4 : 0);

	rec.p = tmp;
	rec.n = 0;
	rec.cap = sizeof(tmp);
	rec.bad = false;
	addr_host(&b->src, sh, sizeof(sh));
	addr_host(&b->target, th, sizeof(th));
	w_u(&rec, (uint64_t)to_wall(now_w, now_ms, b->expires_at_ms), 8);
	w_u(&rec, (uint64_t)to_wall(now_w, now_ms, b->registered_ms), 8);
	w_u(&rec, (uint64_t)to_wall(now_w, now_ms, b->refreshed_ms), 8);
	w_u(&rec, b->expires_s, 4);
	w_u(&rec, b->cseq, 4);
	w_u(&rec, b->allow, 4);
	w_u(&rec, b->features, 4);
	w_u(&rec, (uint32_t)b->q, 4);
	w_u(&rec, b->ack_seq, 8);
	w_u(&rec, b->ack_state, 1);
	w_u(&rec, flags, 1);
	w_u(&rec, b->ep ? (unsigned)b->ep->kind : 0, 1);
	w_u(&rec, 0, 1);
	w_u(&rec, addr_port(&b->src), 2);
	w_u(&rec, addr_port(&b->target), 2);
	w_str(&rec, b->aor);
	w_str(&rec, b->contact);
	w_str(&rec, b->instance);
	w_str(&rec, b->ua);
	w_str(&rec, b->accept);
	w_str(&rec, b->supported);
	w_str(&rec, b->call_id);
	w_str(&rec, sh);
	w_str(&rec, th);
	if (rec.bad) {
		w->bad = true;
		return;
	}
	w_u(w, rec.n, 4);
	w_raw(w, rec.p, rec.n);
}

/* serialize the registrar's table; the buffer is malloc()ed, NULL on failure */
static uint8_t *snapshot(const struct regpersist *p, size_t *len)
{
	struct wbuf w;
	const struct reg_binding *b;
	reg_id_t id = REG_ID_NONE;
	unsigned n = 0;
	int64_t now_w = wall(p);
	uint64_t now_ms = ev_now_ms();
	uint8_t *cnt;

	w.cap = HDR_LEN + (size_t)(p->reg ? reg_count(p->reg) : 0) * (4 + REC_MAX) + 4;
	w.p = malloc(w.cap);
	if (!w.p)
		return NULL;
	w.n = 0;
	w.bad = false;
	w_raw(&w, MAGIC, 8);
	w_u(&w, FILE_VERSION, 4);
	cnt = w.p + w.n;
	w_u(&w, 0, 4);
	w_u(&w, (uint64_t)now_w, 8);
	while (p->reg && n < MAX_REC && (b = reg_next(p->reg, id))) {
		id = b->id;
		put_record(&w, b, now_w, now_ms);
		n++;
	}
	cnt[0] = (uint8_t)n;
	cnt[1] = (uint8_t)(n >> 8);
	cnt[2] = (uint8_t)(n >> 16);
	cnt[3] = (uint8_t)(n >> 24);
	w_u(&w, sio_crc32(w.p, w.n), 4);
	if (w.bad) {
		free(w.p);
		return NULL;
	}
	*len = w.n;
	return w.p;
}

static void drain(struct regpersist *p);

/* submit the table now */
static bool write_now(struct regpersist *p)
{
	struct sio_req *r;
	size_t len = 0;
	uint8_t *buf;
	int rc;

	buf = snapshot(p, &len);
	if (!buf)
		return false;
	r = sio_req_new(SIO_BLOB_PUT);
	if (!r) {
		free(buf);
		return false;
	}
	snprintf(r->name, sizeof(r->name), "%s", FILE_NAME);
	r->body = buf;
	r->body_len = len;
	r->token = p->gen;
	rc = sio_submit(p->io, r);
	if (rc) {
		sio_req_free(r);
		return false;
	}
	p->st.writes++;
	p->last_write_ms = ev_now_ms();
	p->dirty = p->urgent = false;
	if (!p->cfg.inline_io)
		return true;
	drain(p);
	return true;
}

static void arm(struct regpersist *p, bool urgent)
{
	uint64_t now = ev_now_ms(), due;

	if (!p->reg)
		return;
	if (urgent)
		due = p->last_write_ms + URGENT_MS;
	else
		due = p->last_write_ms + LAZY_MS;
	if (due < now)
		due = now;
	if (!p->dirty || due < p->due_ms)
		p->due_ms = due;
	p->dirty = true;
	if (urgent)
		p->urgent = true;
	ev_timer_set(p->t_wr, p->due_ms > now ? p->due_ms - now : 0);
}

static void on_wr_timer(void *arg)
{
	struct regpersist *p = arg;

	if (!p->reg || !p->dirty)
		return;
	if (!p->loaded)			/* never overwrite the file before it was read: tried again when the load completes */
		return;
	if (!write_now(p)) {
		p->due_ms = ev_now_ms() + URGENT_MS;
		ev_timer_set(p->t_wr, URGENT_MS);
	}
}

/* ------------------------------------------------------------------ */
/* loading                                                             */

static bool parse_record(struct rbuf *r, struct reg_binding *b, int64_t *exp_w, int64_t *reg_w, unsigned *kind)
{
	char sh[64], th[64];
	uint8_t flags;
	uint16_t sp, tp;

	memset(b, 0, sizeof(*b));
	*exp_w = (int64_t)r_u(r, 8);
	*reg_w = (int64_t)r_u(r, 8);
	(void)r_u(r, 8);			/* refreshed_wall: informational */
	b->expires_s = (unsigned)r_u(r, 4);
	b->cseq = (uint32_t)r_u(r, 4);
	b->allow = (uint32_t)r_u(r, 4);
	b->features = (uint32_t)r_u(r, 4);
	b->q = (int)(int32_t)r_u(r, 4);
	b->ack_seq = r_u(r, 8);
	b->ack_state = (uint8_t)r_u(r, 1);
	flags = (uint8_t)r_u(r, 1);
	*kind = (unsigned)r_u(r, 1);
	(void)r_u(r, 1);
	sp = (uint16_t)r_u(r, 2);
	tp = (uint16_t)r_u(r, 2);
	r_str(r, b->aor, sizeof(b->aor));
	r_str(r, b->contact, sizeof(b->contact));
	r_str(r, b->instance, sizeof(b->instance));
	r_str(r, b->ua, sizeof(b->ua));
	r_str(r, b->accept, sizeof(b->accept));
	r_str(r, b->supported, sizeof(b->supported));
	r_str(r, b->call_id, sizeof(b->call_id));
	r_str(r, sh, sizeof(sh));
	r_str(r, th, sizeof(th));
	if (r->bad || addr_set(&b->src, sh, sp) || addr_set(&b->target, th, tp))
		return false;
	b->target_from_src = flags & 1;
	b->allow_known = flags & 2;
	b->answered = flags & 4;
	b->ack_state = REG_ACK_NONE;	/* see regpersist.h */
	b->ack_seq = 0;
	if (b->q < 0 || b->q > 1000)
		b->q = 1000;
	return true;
}

/* verify and apply the file; returns false when the file is not usable at all */
static bool restore(struct regpersist *p, const uint8_t *d, size_t n)
{
	struct rbuf r = { d, n, 0, false };
	uint32_t count, ver, i;
	int64_t saved, now_w = wall(p);
	uint64_t now_ms = ev_now_ms();
	bool clock_ok = now_w >= CLOCK_OK;

	if (n < HDR_LEN + 4 || memcmp(d, MAGIC, 8) || sio_crc32(d, n - 4) != (uint32_t)(d[n - 4] | d[n - 3] << 8 | d[n - 2] << 16 | (uint32_t)d[n - 1] << 24))
		return false;
	r.n = n - 4;
	r.o = 8;
	ver = (uint32_t)r_u(&r, 4);
	count = (uint32_t)r_u(&r, 4);
	saved = (int64_t)r_u(&r, 8);
	if (ver != FILE_VERSION || count > MAX_REC)
		return false;
	/* a file saved under an unset clock, or from the future (the clock was stepped back): its absolute times mean nothing */
	if (saved < CLOCK_OK || saved > now_w + 60)
		clock_ok = false;
	if (!clock_ok)
		LOGW("registrar: wall clock not usable for the saved bindings (now %lld, saved %lld): they get the minimum lifetime",
		     (long long)now_w, (long long)saved);
	p->restoring = true;
	for (i = 0; i < count; i++) {
		size_t len = (size_t)r_u(&r, 4);
		struct rbuf rr;
		struct reg_binding b;
		int64_t exp_w, reg_w;
		unsigned kind, remain;
		int rc;

		if (r.bad || len > REC_MAX || r.o + len > r.n) {
			p->restoring = false;
			return false;
		}
		rr.p = r.p + r.o;
		rr.n = len;
		rr.o = 0;
		rr.bad = false;
		r.o += len;
		if (!parse_record(&rr, &b, &exp_w, &reg_w, &kind)) {
			p->st.skipped++;
			continue;
		}
		if (clock_ok) {
			if (exp_w <= now_w) {
				p->st.expired++;
				continue;
			}
			remain = exp_w - now_w > 0x7fffffff ? 0x7fffffff : (unsigned)(exp_w - now_w);
			if (b.expires_s && remain > b.expires_s)
				remain = b.expires_s;	/* never longer than what was granted */
			if (reg_w < now_w && (uint64_t)(now_w - reg_w) * 1000ull < now_ms)
				b.registered_ms = now_ms - (uint64_t)(now_w - reg_w) * 1000ull;
			else
				b.registered_ms = reg_w < now_w ? 0 : now_ms;
		} else {
			remain = reg_min_expires(p->reg);
			b.registered_ms = now_ms;
		}
		if (!remain)
			remain = 1;
		if ((unsigned)p->ep->kind != kind) {
			p->st.skipped++;
			continue;
		}
		rc = reg_restore(p->reg, &b, p->ep, remain);
		if (rc == 0)
			p->st.restored++;
		else {
			p->st.skipped++;
			if (rc != -EEXIST)
				LOGW("registrar: cannot restore a binding: %s", strerror(-rc));
		}
	}
	p->restoring = false;
	return true;
}

static void note_shadow(struct regpersist *p, reg_id_t id, uint64_t sig, bool del)
{
	unsigned i;
	struct shadow *free_slot = NULL;

	for (i = 0; i < SHADOW_MAX; i++) {
		if (p->sh[i].id == id) {
			if (del)
				p->sh[i].id = REG_ID_NONE;
			else
				p->sh[i].sig = sig;
			return;
		}
		if (!p->sh[i].id && !free_slot)
			free_slot = &p->sh[i];
	}
	if (!del && free_slot) {
		free_slot->id = id;
		free_slot->sig = sig;
	}
}

static void handle(struct regpersist *p, struct sio_req *r)
{
	if (r->op == SIO_BLOB_PUT) {
		if (r->err) {
			p->st.write_errors++;
			if (!p->warned)
				LOGW("registrar: cannot write the bindings file: %s", strerror(-r->err));
			p->warned = true;
		} else
			p->warned = false;
		return;
	}
	if (r->op != SIO_BLOB_GET || r->token != p->gen || !p->reg)
		return;			/* of an attachment that is gone */
	p->st.restored = p->st.expired = p->st.skipped = 0;
	p->st.file_bad = false;
	if (r->err == -ENOENT)
		LOGI("registrar: no saved bindings");
	else if (r->err) {
		LOGW("registrar: cannot read the saved bindings: %s", strerror(-r->err));
		p->st.file_bad = true;
	} else if (!restore(p, r->body, r->body_len)) {
		LOGW("registrar: the saved bindings file does not verify (bad magic, version, length or CRC): ignored");
		p->st.file_bad = true;
	} else
		LOGI("registrar: saved bindings: %lu restored, %lu expired, %lu not usable", p->st.restored, p->st.expired,
		     p->st.skipped);
	p->loaded = true;
	p->st.loaded = true;
	if (p->dirty)
		arm(p, p->urgent);
}

static void drain(struct regpersist *p)
{
	struct sio_req *r;

	sio_ack(p->io);
	while ((r = sio_next(p->io))) {
		handle(p, r);
		sio_req_free(r);
	}
}

static void on_event_fd(void *arg, int fd)
{
	(void)fd;
	drain(arg);
}

void regpersist_stats(const struct regpersist *p, struct regpersist_stats *out)
{
	*out = p->st;
}

void regpersist_sync(struct regpersist *p)
{
	if (p->cfg.inline_io) {
		drain(p);
		return;
	}
	while (sio_outstanding(p->io)) {
		struct sio_req *r = sio_wait(p->io, 2000);

		if (!r)
			break;
		handle(p, r);
		sio_req_free(r);
	}
}

/* ------------------------------------------------------------------ */
/* life                                                                */

struct regpersist *regpersist_new(const struct regpersist_cfg *cfg)
{
	struct regpersist *p = calloc(1, sizeof(*p));

	if (!p)
		return NULL;
	p->cfg = *cfg;
	p->io = sio_open(cfg->dir, !cfg->inline_io, 4);
	p->t_wr = ev_timer_new(on_wr_timer, p);
	if (!p->io || !p->t_wr) {
		regpersist_free(p);
		return NULL;
	}
	if (!cfg->inline_io) {
		p->efd = ev_fd_add(sio_event_fd(p->io), on_event_fd, p);
		if (!p->efd) {
			regpersist_free(p);
			return NULL;
		}
	}
	return p;
}

void regpersist_free(struct regpersist *p)
{
	if (!p)
		return;
	regpersist_detach(p);
	ev_timer_free(p->t_wr);
	ev_fd_del(p->efd);
	sio_close(p->io);	/* the writer finishes the queued final write */
	free(p);
}

void regpersist_attach(struct regpersist *p, struct registrar *r, struct sip_endpoint *ep)
{
	struct sio_req *q;

	if (!p || !r || !ep)
		return;
	regpersist_detach(p);
	p->gen++;
	p->reg = r;
	p->ep = ep;
	p->loaded = p->dirty = p->urgent = false;
	p->last_write_ms = ev_now_ms();
	memset(p->sh, 0, sizeof(p->sh));
	memset(&p->st.restored, 0, 3 * sizeof(unsigned long));
	p->st.loaded = p->st.file_bad = false;
	q = sio_req_new(SIO_BLOB_GET);
	if (!q)
		return;		/* loaded stays false: nothing is ever written over the file */
	snprintf(q->name, sizeof(q->name), "%s", FILE_NAME);
	q->token = p->gen;
	if (sio_submit(p->io, q)) {
		sio_req_free(q);
		return;
	}
	if (p->cfg.inline_io)
		drain(p);
}

void regpersist_detach(struct regpersist *p)
{
	if (!p || !p->reg)
		return;
	if (p->loaded)
		write_now(p);
	ev_timer_cancel(p->t_wr);
	p->reg = NULL;
	p->ep = NULL;
	p->loaded = p->dirty = false;
}

static uint64_t fnv(uint64_t h, const char *s)
{
	for (; *s; s++)
		h = (h ^ (uint8_t)*s) * 1099511628211ull;
	return (h ^ 0xff) * 1099511628211ull;
}

/* what makes a REGISTER "more than a refresh" */
static uint64_t signature(const struct reg_binding *b)
{
	uint64_t h = 1469598103934665603ull;
	char a[64];

	h = fnv(h, b->aor);
	h = fnv(h, b->contact);
	h = fnv(h, b->instance);
	h = fnv(h, b->ua);
	h = fnv(h, b->accept);
	h = fnv(h, b->supported);
	addr_str(&b->src, a, sizeof(a));
	h = fnv(h, a);
	addr_str(&b->target, a, sizeof(a));
	h = fnv(h, a);
	h = (h ^ b->features) * 1099511628211ull;
	h = (h ^ (uint64_t)b->q) * 1099511628211ull;
	h = (h ^ b->expires_s) * 1099511628211ull;
	return h;
}

void regpersist_on_binding(struct regpersist *p, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why)
{
	unsigned i;
	uint64_t sig;
	bool changed = true;

	(void)why;
	if (!p || !p->reg)
		return;
	if (ev == REG_EV_REMOVED) {
		note_shadow(p, b->id, 0, true);
		arm(p, true);
		return;
	}
	if (ev != REG_EV_ADDED && ev != REG_EV_REFRESHED)
		return;
	sig = signature(b);
	if (ev == REG_EV_REFRESHED)
		for (i = 0; i < SHADOW_MAX; i++)
			if (p->sh[i].id == b->id && p->sh[i].sig == sig)
				changed = false;
	note_shadow(p, b->id, sig, false);
	if (p->restoring)
		return;			/* the file already says exactly this */
	arm(p, changed);
}
