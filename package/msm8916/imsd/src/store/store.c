/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Message store: index, devices, cursors, delivery engine. See store.h; the files are sio.h / sio.c. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "store.h"
#include "../util/evloop.h"
#include "../util/log.h"

#define ITEM_OVERHEAD	64u		/* what an index entry / record header is counted as, bytes */
#define CACHE_N		8
#define CACHE_BYTES	(4u * 1024 * 1024)
#define READ_MAX	8		/* reads (payload loads) in flight at once: bounds the RAM of concurrent deliveries */
#define RDQ_MAX		64
#define WALL_PLAUSIBLE	1600000000
#define SWEEP_MS	(3600u * 1000)
#define SEEN_DIRTY_S	3600		/* a changed last_seen alone is written only when it moved this far */

struct item {
	struct sio_entry e;
	bool durable, abandoned;
	store_add_cb cb;
	void *cb_arg, *owner;
};

enum dev_state { D_IDLE, D_READ, D_SEND, D_SLOT };

struct sdev {
	struct store *s;
	bool used;
	char id[SIO_DEVID_MAX];
	uint64_t hash;
	uint64_t cursor, pos, reported;
	bool uses_ack;
	int64_t last_seen, persisted_seen;
	bool registered;
	reg_id_t binding;
	uint32_t features;
	enum dev_state st;
	uint64_t cur_seq;
	uint32_t rd_token;
	bool stalled, retried;
	struct ev_timer *retry;
	unsigned long delivered, missed, failures;
};

struct cent {
	bool used;
	uint64_t seq, tick;
	struct sio_entry e;
	uint8_t *meta, *body;
	size_t meta_len, body_len;
	bool has_body;
	unsigned busy;
};

struct rdq {
	struct rdq *next;
	uint32_t token;
	uint64_t seq;
	bool want_body, submitted;
	store_read_cb cb;
	void *arg;
};

struct pendreg {
	bool used;
	reg_id_t id;
	char ident[SIO_DEVID_MAX];
	uint32_t features;
	uint8_t ack_state;
	uint64_t ack_seq;
};

struct store {
	struct store_cfg cfg;
	struct store_ops ops;
	struct sio *io;
	bool ready, healthy, load_sent, inline_io;
	void (*usable_cb)(void *);
	void *usable_arg;
	char error[96];
	struct item *it;
	unsigned n, cap;
	unsigned ndur;
	uint64_t bytes;
	uint64_t next_seq;
	struct sdev dev[STORE_MAX_DEV];
	struct pendreg pend[STORE_MAX_DEV];
	struct store_handler h[STORE_TYPE_MAX];
	struct cent cache[CACHE_N];
	uint64_t tick;
	struct rdq *rd;
	unsigned nrd, reads_out;
	uint32_t token;
	uint64_t evict_to;
	bool evict_persist;
	bool dirty, state_armed;
	struct ev_fd *efd;
	struct ev_timer *t_drain, *t_state, *t_probe, *t_sweep, *t_rd;
	struct store_status c;		/* counters only */
};

static const char *type_name(uint8_t t)
{
	return t == STORE_SMS ? "sms" : t == STORE_MMS ? "mms" : t == STORE_CARBON_SMS ? "carbon-sms" : t == STORE_CARBON_MMS ?
	       "carbon-mms" : "?";
}

/* ------------------------------------------------------------------ */
/* basics                                                              */

void store_cfg_defaults(struct store_cfg *c)
{
	memset(c, 0, sizeof(*c));
	snprintf(c->dir, sizeof(c->dir), "/srv/imsd");
	c->keep_messages = 500;
	c->keep_days = 0;
	c->keep_bytes = 32ull * 1024 * 1024;
	c->state_flush_ms = 10000;
	c->retry_ms = 30000;
	c->probe_ms = 30000;
}

static void cfg_clamp(struct store_cfg *c)
{
	if (c->keep_messages < 1)
		c->keep_messages = 1;
	if (c->keep_messages > 5000)
		c->keep_messages = 5000;
	if (c->keep_bytes < 65536)
		c->keep_bytes = 65536;
	if (!c->state_flush_ms)
		c->state_flush_ms = 10000;
	if (!c->retry_ms)
		c->retry_ms = 30000;
	if (!c->probe_ms)
		c->probe_ms = 30000;
	c->dir[sizeof(c->dir) - 1] = 0;
}

int64_t store_wall(const struct store *s)
{
	return s->ops.wall ? s->ops.wall(s->ops.ctx) : (int64_t)time(NULL);
}

uint64_t store_hash(const char *str)
{
	uint64_t h = 0xcbf29ce484222325ull;

	for (; *str; str++) {
		h ^= (uint8_t)*str;
		h *= 0x100000001b3ull;
	}
	return h ? h : 1;
}

void store_identity(const struct reg_binding *b, char *out, size_t n)
{
	if (b->instance[0]) {
		snprintf(out, n, "i:%s", b->instance);
	} else {
		const char *u = strchr(b->aor, ':'), *at;

		u = u ? u + 1 : b->aor;
		at = strchr(u, '@');
		snprintf(out, n, "u:%.*s", at ? (int)(at - u) : (int)strlen(u), u);
	}
	if (n >= SIO_DEVID_MAX)
		out[SIO_DEVID_MAX - 1] = 0;
}

static void short_id(const char *id, char *out, size_t n)
{
	const char *u = strstr(id, "urn:uuid:");

	if (u)
		snprintf(out, n, "%.8s", u + 9);
	else
		snprintf(out, n, "%.*s", (int)n - 1, id);
}

void store_set_usable_cb(struct store *s, void (*cb)(void *), void *arg)
{
	s->usable_cb = cb;
	s->usable_arg = arg;
}

static void notify_usable(struct store *s)
{
	if (s->usable_cb && s->ready && s->healthy)
		s->usable_cb(s->usable_arg);
}

bool store_usable(const struct store *s)
{
	return s && s->ready && s->healthy;
}

/* ------------------------------------------------------------------ */
/* index                                                               */

/* first index with seq > x */
static unsigned idx_after(const struct store *s, uint64_t x)
{
	unsigned lo = 0, hi = s->n;

	while (lo < hi) {
		unsigned mid = (lo + hi) / 2;

		if (s->it[mid].e.seq <= x)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

static struct item *item_find(struct store *s, uint64_t seq)
{
	unsigned i = idx_after(s, seq - 1);

	return i < s->n && s->it[i].e.seq == seq ? &s->it[i] : NULL;
}

static uint32_t item_size(const struct sio_entry *e)
{
	return e->meta_len + e->body_len + ITEM_OVERHEAD;
}

static void item_remove_at(struct store *s, unsigned i)
{
	memmove(&s->it[i], &s->it[i + 1], (s->n - i - 1) * sizeof(s->it[0]));
	s->n--;
}

/* ------------------------------------------------------------------ */
/* the file layer: submit, completions                                 */

static void kick(struct store *s)
{
	if (s->inline_io)
		ev_timer_set(s->t_drain, 0);
}

static int submit(struct store *s, struct sio_req *r)
{
	int rc = sio_submit(s->io, r);

	if (rc)
		sio_req_free(r);
	else
		kick(s);
	return rc;
}

static void set_unhealthy(struct store *s, int err, const char *what)
{
	bool was = s->healthy;

	s->healthy = false;
	s->c.io_errors++;
	snprintf(s->error, sizeof(s->error), "%s: %s", what, err == -ENOSPC ? "no space left on the store file system" :
		 strerror(-err));
	if (was)
		LOGE("store: %s: the store stops accepting messages (live delivery only) until this clears", s->error);
	ev_timer_set(s->t_probe, s->cfg.probe_ms);
}

static void flush_evict(struct store *s)
{
	struct sio_req *r;

	if (!s->evict_to || !s->io)
		return;
	r = sio_req_new(SIO_EVICT);
	if (!r)
		return;
	r->ent.seq = s->evict_to;
	r->persist = s->evict_persist;
	if (!submit(s, r)) {
		s->evict_to = 0;
		s->evict_persist = false;
	} else if (!s->state_armed) {
		s->state_armed = true;
		ev_timer_set(s->t_state, s->cfg.state_flush_ms);
	}
}

static void cache_drop(struct store *s, uint64_t seq)
{
	unsigned i;

	for (i = 0; i < CACHE_N; i++)
		if (s->cache[i].used && s->cache[i].seq == seq && !s->cache[i].busy) {
			free(s->cache[i].meta);
			free(s->cache[i].body);
			memset(&s->cache[i], 0, sizeof(s->cache[i]));
		}
}

/* ------------------------------------------------------------------ */
/* devices                                                             */

static bool addressed(const struct sdev *d, const struct item *it)
{
	unsigned i;

	if (it->e.type == STORE_CARBON_SMS || it->e.type == STORE_CARBON_MMS) {
		if (!(d->features & REG_F_CARBONS))
			return false;
		for (i = 0; i < it->e.nexcl; i++)
			if (it->e.excl[i] == d->hash)
				return false;
	}
	return true;
}

static void mark_dirty(struct store *s)
{
	s->dirty = true;
	if (!s->state_armed) {
		s->state_armed = true;
		ev_timer_set(s->t_state, s->cfg.state_flush_ms);
	}
}

/* the device has (or has passed over) everything up to seq */
static void dev_advance(struct sdev *d, uint64_t seq)
{
	if (seq <= d->pos)
		return;
	d->pos = seq;
	if (!d->uses_ack) {
		d->cursor = seq;
		mark_dirty(d->s);
	}
}

static void dev_pump(struct sdev *d);

static void dev_stall(struct sdev *d, const char *why)
{
	struct store *s = d->s;
	char sid[24];

	d->st = D_IDLE;
	d->stalled = true;
	d->failures++;
	s->c.delivery_failures++;
	short_id(d->id, sid, sizeof(sid));
	LOGI("store: delivery to device %s stopped at seq %llu: %s%s", sid, (unsigned long long)(d->cur_seq ? d->cur_seq : d->pos + 1), why,
	     d->retried ? "" : " (one retry follows)");
	if (!d->retried && d->retry)
		ev_timer_set(d->retry, s->cfg.retry_ms);
}

static void dev_retry(void *arg)
{
	struct sdev *d = arg;

	if (!d->used || !d->registered)
		return;
	d->retried = true;
	d->stalled = false;
	dev_pump(d);
}

static void dev_done(void *arg, int nok)
{
	struct sdev *d = arg;

	if (!d->used || d->st != D_SEND)
		return;
	d->st = D_IDLE;
	if (nok > 0) {
		d->delivered++;
		d->s->c.delivered++;
		dev_advance(d, d->cur_seq);
		d->cur_seq = 0;
		dev_pump(d);
	} else {
		dev_stall(d, "the device did not accept the message");
	}
}

static void dev_read_cb(void *arg, int err, const struct store_item *it)
{
	struct sdev *d = arg;
	struct store *s = d->s;
	const struct store_handler *h;
	int rc;

	d->rd_token = 0;
	if (!d->used || d->st != D_READ)
		return;
	d->st = D_IDLE;
	if (err == -ENOENT) {			/* evicted or purged meanwhile */
		dev_advance(d, d->cur_seq);
		d->cur_seq = 0;
		dev_pump(d);
		return;
	}
	if (err) {
		s->c.read_errors++;
		dev_stall(d, "cannot read the item from the store");
		return;
	}
	h = &s->h[it->type];
	if (!h->deliver) {
		dev_stall(d, "no handler for the item type");
		return;
	}
	d->st = D_SEND;
	rc = h->deliver(h->ctx, it, d->binding, d->features, dev_done, d);
	if (rc == 0)
		return;
	d->st = D_IDLE;
	if (rc == 1) {
		dev_advance(d, d->cur_seq);
		d->cur_seq = 0;
		dev_pump(d);
		return;
	}
	dev_stall(d, "cannot send to the device");
}

static void dev_pump(struct sdev *d)
{
	struct store *s = d->s;

	if (!s->ready || !d->used || !d->registered || (d->st != D_IDLE && d->st != D_SLOT))
		return;
	d->st = D_IDLE;
	for (;;) {
		unsigned i = idx_after(s, d->pos);
		struct item *it;
		const struct store_handler *h;
		bool want = false;
		int rc;

		if (i >= s->n)
			return;
		it = &s->it[i];
		if (!it->durable)
			return;
		if (it->abandoned || !addressed(d, it)) {
			dev_advance(d, it->e.seq);
			continue;
		}
		h = &s->h[it->e.type];
		if (!h->deliver) {
			dev_stall(d, "no handler for the item type");
			return;
		}
		if (h->needs_body)
			want = h->needs_body(h->ctx, it->e.type, d->features, it->e.body_len > 0);
		if (s->reads_out >= READ_MAX) {
			d->st = D_SLOT;
			return;
		}
		d->cur_seq = it->e.seq;
		rc = store_read(s, it->e.seq, want, dev_read_cb, d, &d->rd_token);
		if (rc) {
			dev_stall(d, "cannot queue the read");
			return;
		}
		d->st = D_READ;
		return;
	}
}

static void dev_stop(struct sdev *d)
{
	struct store *s = d->s;

	if (d->st == D_READ && d->rd_token)
		store_read_cancel(s, d->rd_token);
	if (d->st == D_SEND) {
		unsigned t;

		for (t = 1; t < STORE_TYPE_MAX; t++)
			if (s->h[t].abort)
				s->h[t].abort(s->h[t].ctx, d);
	}
	d->st = D_IDLE;
	d->rd_token = 0;
	d->cur_seq = 0;
	if (d->retry)
		ev_timer_cancel(d->retry);
}

static void dev_free(struct sdev *d)
{
	dev_stop(d);
	ev_timer_free(d->retry);
	memset(d, 0, sizeof(*d));
}

static struct sdev *dev_find(struct store *s, const char *id)
{
	unsigned i;

	for (i = 0; i < STORE_MAX_DEV; i++)
		if (s->dev[i].used && !strcmp(s->dev[i].id, id))
			return &s->dev[i];
	return NULL;
}

static struct sdev *dev_slot(struct store *s)
{
	unsigned i;
	struct sdev *old = NULL;

	for (i = 0; i < STORE_MAX_DEV; i++)
		if (!s->dev[i].used)
			return &s->dev[i];
	for (i = 0; i < STORE_MAX_DEV; i++) {
		struct sdev *d = &s->dev[i];

		if (!d->registered && (!old || d->last_seen < old->last_seen))
			old = d;
	}
	if (old) {
		char sid[24];

		short_id(old->id, sid, sizeof(sid));
		LOGW("store: more than %d devices: the record of the least recently seen one (%s) is dropped", STORE_MAX_DEV, sid);
		dev_free(old);
		mark_dirty(s);
	}
	return old;
}

static void dev_register(struct store *s, const char *ident, reg_id_t binding, uint32_t features, uint8_t ack_state, uint64_t ack_seq)
{
	struct sdev *d = dev_find(s, ident);
	uint64_t head = s->next_seq - 1;
	int64_t now = store_wall(s);
	char sid[24];
	bool created = false;

	if (!d) {
		d = dev_slot(s);
		if (!d) {
			LOGW("store: no room for another device record");
			return;
		}
		memset(d, 0, sizeof(*d));
		d->s = s;
		d->used = true;
		snprintf(d->id, sizeof(d->id), "%s", ident);
		d->hash = store_hash(d->id);
		d->cursor = d->pos = head;		/* first seen: from now on, no history */
		d->retry = ev_timer_new(dev_retry, d);
		created = true;
		mark_dirty(s);
	}
	short_id(d->id, sid, sizeof(sid));
	if (d->binding != binding || (ack_state == REG_ACK_OK && (ack_seq > head ? head : ack_seq) != d->pos))
		dev_stop(d);		/* what is in flight is repeated from the (possibly new) position / to the new binding */
	d->registered = true;
	d->binding = binding;
	d->features = features;
	d->stalled = false;
	d->retried = false;
	if (now > d->last_seen)
		d->last_seen = now;
	if (created || d->last_seen - d->persisted_seen >= SEEN_DIRTY_S) {
		d->persisted_seen = d->last_seen;
		mark_dirty(s);
	}
	if (ack_state == REG_ACK_BAD) {
		LOGW("store: device %s sent a malformed X-IMSD-Ack-Seq, ignored", sid);
		ack_state = REG_ACK_NONE;
	}
	if (ack_state == REG_ACK_OK) {
		uint64_t n = ack_seq > head ? head : ack_seq;

		if (ack_seq > head)
			LOGI("store: device %s reports seq %llu above the head %llu: clamped", sid, (unsigned long long)ack_seq,
			     (unsigned long long)head);
		else if (n < d->pos)
			LOGI("store: device %s reports seq %llu, below what was sent (%llu): sending again from there", sid,
			     (unsigned long long)n, (unsigned long long)d->pos);
		d->uses_ack = true;
		d->reported = ack_seq;
		d->cursor = d->pos = n;
		mark_dirty(s);
	} else if (d->uses_ack) {
		if (d->pos < d->cursor)
			d->pos = d->cursor;
	} else {
		d->pos = d->cursor > head ? head : d->cursor;
		d->cursor = d->pos;
	}
	LOGD("store: device %s registered (binding %u), position %llu, head %llu", sid, binding, (unsigned long long)d->pos,
	     (unsigned long long)head);
	dev_pump(d);
}

static void dev_unregister(struct store *s, reg_id_t binding)
{
	unsigned i;

	for (i = 0; i < STORE_MAX_DEV; i++) {
		struct sdev *d = &s->dev[i];

		if (d->used && d->registered && d->binding == binding) {
			dev_stop(d);
			d->registered = false;
			d->binding = REG_ID_NONE;
		}
	}
}

static void pump_all(struct store *s)
{
	unsigned i;

	for (i = 0; i < STORE_MAX_DEV; i++)
		if (s->dev[i].used && s->dev[i].registered && !s->dev[i].stalled)
			dev_pump(&s->dev[i]);
}

void store_on_binding(struct store *s, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why)
{
	char ident[SIO_DEVID_MAX];
	unsigned i;

	(void)why;
	if (!s)
		return;
	if (ev != REG_EV_ADDED && ev != REG_EV_REFRESHED && ev != REG_EV_REMOVED)
		return;
	if (ev == REG_EV_REMOVED) {
		for (i = 0; i < STORE_MAX_DEV; i++)
			if (s->pend[i].used && s->pend[i].id == b->id)
				s->pend[i].used = false;
		if (s->ready)
			dev_unregister(s, b->id);
		return;
	}
	store_identity(b, ident, sizeof(ident));
	if (!s->ready) {			/* the log is still being read: remember the registration, replay it afterwards */
		struct pendreg *p = NULL;

		for (i = 0; i < STORE_MAX_DEV && !p; i++)
			if (s->pend[i].used && s->pend[i].id == b->id)
				p = &s->pend[i];
		for (i = 0; i < STORE_MAX_DEV && !p; i++)
			if (!s->pend[i].used)
				p = &s->pend[i];
		if (!p)
			return;
		p->used = true;
		p->id = b->id;
		snprintf(p->ident, sizeof(p->ident), "%s", ident);
		p->features = b->features;
		p->ack_state = b->ack_state;
		p->ack_seq = b->ack_seq;
		return;
	}
	dev_register(s, ident, b->id, b->features, b->ack_state, b->ack_seq);
}

void store_lan_down(struct store *s)
{
	unsigned i;

	if (!s)
		return;
	for (i = 0; i < STORE_MAX_DEV; i++) {
		s->pend[i].used = false;
		if (s->dev[i].used) {
			dev_stop(&s->dev[i]);
			s->dev[i].registered = false;
			s->dev[i].binding = REG_ID_NONE;
		}
	}
}

/* ------------------------------------------------------------------ */
/* reading payloads                                                    */

static void cent_free(struct cent *c)
{
	free(c->meta);
	free(c->body);
	memset(c, 0, sizeof(*c));
}

/* the entry is handed to the callback, then it stays in the cache (or is freed when it is a temporary) */
static void rd_complete(struct store *s, struct rdq *q, int err, struct cent *c, bool temp)
{
	struct store_item it;

	if (err) {
		q->cb(q->arg, err, NULL);
		return;
	}
	memset(&it, 0, sizeof(it));
	it.seq = c->e.seq;
	it.type = c->e.type;
	it.flags = c->e.flags;
	it.time = c->e.time;
	it.peer = c->e.peer;
	it.meta = c->meta;
	it.meta_len = c->meta_len;
	it.body = c->has_body ? c->body : NULL;
	it.body_len = c->has_body ? c->body_len : 0;
	c->busy++;
	q->cb(q->arg, 0, &it);
	c->busy--;
	if (temp)
		cent_free(c);
	(void)s;
}

static void rd_unlink(struct store *s, struct rdq *q)
{
	struct rdq **pp;

	for (pp = &s->rd; *pp; pp = &(*pp)->next)
		if (*pp == q) {
			*pp = q->next;
			break;
		}
	s->nrd--;
	if (q->submitted)
		s->reads_out--;
}

static struct cent *cache_find(struct store *s, uint64_t seq, bool want_body)
{
	unsigned i;

	for (i = 0; i < CACHE_N; i++) {
		struct cent *c = &s->cache[i];

		if (c->used && c->seq == seq && (!want_body || c->has_body || !c->e.body_len))
			return c;
	}
	return NULL;
}

static struct cent *cache_insert(struct store *s, struct cent *src)
{
	struct cent *slot = NULL, *c;
	size_t total = 0;
	unsigned i;

	cache_drop(s, src->seq);
	for (;;) {
		total = 0;
		slot = NULL;
		for (i = 0; i < CACHE_N; i++) {
			c = &s->cache[i];
			if (c->used)
				total += c->meta_len + c->body_len;
			else if (!slot)
				slot = c;
		}
		if (slot && total + src->meta_len + src->body_len <= CACHE_BYTES)
			break;
		c = NULL;
		for (i = 0; i < CACHE_N; i++)
			if (s->cache[i].used && !s->cache[i].busy && (!c || s->cache[i].tick < c->tick))
				c = &s->cache[i];
		if (!c)
			return NULL;
		cent_free(c);
	}
	*slot = *src;
	slot->used = true;
	slot->tick = ++s->tick;
	return slot;
}

static void on_rd_timer(void *arg)
{
	struct store *s = arg;
	bool again = true;

	while (again) {
		struct rdq *q;

		again = false;
		for (q = s->rd; q; q = q->next) {
			struct cent *c;

			if (q->submitted)
				continue;
			c = cache_find(s, q->seq, q->want_body);
			rd_unlink(s, q);
			if (c) {
				c->tick = ++s->tick;
				rd_complete(s, q, 0, c, false);
			} else {
				q->cb(q->arg, -ENOENT, NULL);
			}
			free(q);
			again = true;
			break;
		}
	}
}

int store_read(struct store *s, uint64_t seq, bool want_body, store_read_cb cb, void *arg, uint32_t *token)
{
	struct rdq *q;
	struct sio_req *r;

	if (!s->ready)
		return -ENODEV;
	if (s->nrd >= RDQ_MAX)
		return -EBUSY;
	q = calloc(1, sizeof(*q));
	if (!q)
		return -ENOMEM;
	q->token = ++s->token ? s->token : ++s->token;
	q->seq = seq;
	q->want_body = want_body;
	q->cb = cb;
	q->arg = arg;
	if (cache_find(s, seq, want_body)) {
		q->next = s->rd;
		s->rd = q;
		s->nrd++;
		ev_timer_set(s->t_rd, 0);
	} else {
		r = sio_req_new(SIO_READ);
		if (!r) {
			free(q);
			return -ENOMEM;
		}
		r->ent.seq = seq;
		r->want_body = want_body;
		r->token = q->token;
		if (submit(s, r)) {
			free(q);
			return -EBUSY;
		}
		q->submitted = true;
		s->reads_out++;
		q->next = s->rd;
		s->rd = q;
		s->nrd++;
	}
	if (token)
		*token = q->token;
	return 0;
}

void store_read_cancel(struct store *s, uint32_t token)
{
	struct rdq *q;

	for (q = s->rd; q; q = q->next)
		if (q->token == token) {
			q->cb = NULL;		/* a submitted one is still accounted until its completion arrives */
			if (!q->submitted) {
				rd_unlink(s, q);
				free(q);
			}
			return;
		}
}

static void on_read_done(struct store *s, struct sio_req *r)
{
	struct rdq *q;
	unsigned i;

	for (q = s->rd; q && q->token != r->token; q = q->next)
		;
	if (!q)
		return;
	rd_unlink(s, q);
	if (!r->err && q->cb) {
		struct cent tmp, *c = &tmp;
		bool temp = true;

		memset(&tmp, 0, sizeof(tmp));
		tmp.used = true;
		tmp.seq = r->ent.seq;
		tmp.e = r->ent;
		tmp.meta = r->meta;
		tmp.meta_len = r->meta_len;
		tmp.body = r->body;
		tmp.body_len = r->body_len;
		tmp.has_body = r->want_body || !r->ent.body_len;
		r->meta = r->body = NULL;
		if (tmp.meta_len + tmp.body_len <= CACHE_BYTES / 2) {
			struct cent *slot = cache_insert(s, &tmp);

			if (slot) {
				c = slot;
				temp = false;
			}
		}
		rd_complete(s, q, 0, c, temp);
	} else if (q->cb) {
		if (r->err != -ENOENT)
			LOGW("store: cannot read item %llu: %s", (unsigned long long)q->seq, strerror(-r->err));
		rd_complete(s, q, r->err, NULL, false);
	}
	free(q);
	/* a read slot is free: devices that waited for one go on */
	for (i = 0; i < STORE_MAX_DEV; i++)
		if (s->dev[i].used && s->dev[i].st == D_SLOT)
			dev_pump(&s->dev[i]);
}

/* ------------------------------------------------------------------ */
/* retention                                                           */

static bool aged(const struct store *s, const struct item *it, int64_t now)
{
	return s->cfg.keep_days && now >= WALL_PLAUSIBLE && it->e.time >= WALL_PLAUSIBLE &&
	       now - it->e.time > (int64_t)s->cfg.keep_days * 86400;
}

static void evict_front(struct store *s)
{
	struct item *it = &s->it[0];
	unsigned i;

	for (i = 0; i < STORE_MAX_DEV; i++) {
		struct sdev *d = &s->dev[i];

		if (d->used && d->pos < it->e.seq && addressed(d, it))
			d->missed++;
	}
	cache_drop(s, it->e.seq);
	s->bytes -= item_size(&it->e);
	s->ndur--;
	s->c.evicted++;
	s->evict_to = it->e.seq + 1;
	item_remove_at(s, 0);
}

static void retention(struct store *s)
{
	int64_t now = store_wall(s);
	bool any = false;

	while (s->n && s->it[0].durable &&
	       (s->ndur > s->cfg.keep_messages || s->bytes > s->cfg.keep_bytes || aged(s, &s->it[0], now))) {
		evict_front(s);
		any = true;
	}
	if (any) {
		if (s->n && s->it[0].durable)
			s->evict_to = s->it[0].e.seq;
		flush_evict(s);
	}
}

unsigned store_purge(struct store *s, uint64_t before_seq, bool all)
{
	unsigned n = 0;

	if (!s->ready)
		return 0;
	if (all)
		before_seq = s->next_seq;
	while (s->n && s->it[0].durable && s->it[0].e.seq < before_seq) {
		evict_front(s);
		n++;
	}
	if (s->n && s->it[0].durable && s->it[0].e.seq < before_seq)
		before_seq = s->it[0].e.seq;
	s->evict_to = before_seq;
	s->evict_persist = true;
	flush_evict(s);
	LOGI("store: purge: %u item(s) removed", n);
	return n;
}

/* ------------------------------------------------------------------ */
/* adding                                                              */

int store_add(struct store *s, const struct store_add *a, store_add_cb cb, void *arg, uint64_t *seq)
{
	struct sio_req *r;
	struct item *it;
	unsigned i;
	int rc;

	if (!s || !store_usable(s))
		return -ENODEV;
	if (a->type < 1 || a->type >= STORE_TYPE_MAX || a->meta_len > SIO_META_MAX || a->body_len > SIO_BODY_MAX)
		return -EFBIG;
	if (s->n == s->cap) {
		unsigned nc = s->cap ? s->cap * 2 : 128;
		struct item *ni = realloc(s->it, nc * sizeof(*ni));

		if (!ni)
			return -ENOMEM;
		s->it = ni;
		s->cap = nc;
	}
	r = sio_req_new(SIO_APPEND);
	if (!r)
		return -ENOMEM;
	r->meta = malloc(a->meta_len ? a->meta_len : 1);
	r->body = malloc(a->body_len ? a->body_len : 1);
	if (!r->meta || !r->body) {
		sio_req_free(r);
		return -ENOMEM;
	}
	if (a->meta_len)
		memcpy(r->meta, a->meta, a->meta_len);
	if (a->body_len)
		memcpy(r->body, a->body, a->body_len);
	r->meta_len = a->meta_len;
	r->body_len = a->body_len;
	r->ent.seq = s->next_seq;
	r->ent.time = a->time ? a->time : store_wall(s);
	r->ent.type = a->type;
	r->ent.flags = a->type == STORE_CARBON_SMS || a->type == STORE_CARBON_MMS ? 1 : 0;
	r->ent.dedup = a->dedup;
	r->ent.lookup = a->lookup;
	r->ent.meta_len = (uint32_t)a->meta_len;
	r->ent.body_len = (uint32_t)a->body_len;
	for (i = 0; a->excl && i < a->nexcl && i < SIO_EXCL_MAX; i++)
		r->ent.excl[r->ent.nexcl++] = a->excl[i];
	snprintf(r->ent.peer, sizeof(r->ent.peer), "%s", a->peer ? a->peer : "");
	r->token = (uint32_t)r->ent.seq;
	it = &s->it[s->n];
	memset(it, 0, sizeof(*it));
	it->e = r->ent;
	it->cb = cb;
	it->cb_arg = arg;
	it->owner = a->owner;
	rc = submit(s, r);
	if (rc)
		return rc;
	s->n++;
	if (seq)
		*seq = s->next_seq;
	s->next_seq++;
	return 0;
}

bool store_abandon(struct store *s, uint64_t seq)
{
	struct item *it = item_find(s, seq);

	if (!it || it->durable || it->abandoned)
		return false;
	it->abandoned = true;
	it->cb = NULL;
	s->c.add_abandoned++;
	return true;
}

void store_detach(struct store *s, void *owner)
{
	unsigned i;

	if (!s)
		return;
	for (i = 0; i < s->n; i++)
		if (s->it[i].owner == owner) {
			s->it[i].cb = NULL;
			s->it[i].owner = NULL;
		}
}

static void on_append_done(struct store *s, struct sio_req *r)
{
	struct item *it = item_find(s, r->ent.seq);
	store_add_cb cb;
	void *arg;
	uint64_t seq = r->ent.seq;

	if (!it)
		return;
	cb = it->cb;
	arg = it->cb_arg;
	it->cb = NULL;
	if (r->err) {
		struct store_add a;

		memset(&a, 0, sizeof(a));
		a.type = it->e.type;
		a.time = it->e.time;
		a.peer = it->e.peer;
		a.dedup = it->e.dedup;
		a.lookup = it->e.lookup;
		a.meta = r->meta;
		a.meta_len = r->meta_len;
		a.body = r->body;
		a.body_len = r->body_len;
		a.owner = it->owner;
		s->c.add_failed++;
		item_remove_at(s, (unsigned)(it - s->it));
		set_unhealthy(s, r->err, "cannot append to the store");
		if (cb)
			cb(arg, r->err, seq, &a);
		return;
	}
	it->durable = true;
	s->ndur++;
	s->bytes += item_size(&it->e);
	s->c.added++;
	if (it->abandoned) {
		struct sio_req *d = sio_req_new(SIO_DROP);

		s->c.dropped++;
		s->ndur--;
		s->bytes -= item_size(&it->e);
		item_remove_at(s, (unsigned)(it - s->it));
		if (d) {
			d->ent.seq = seq;
			submit(s, d);
		}
		return;
	}
	LOGD("store: item %llu (%s) is durable", (unsigned long long)seq, type_name(it->e.type));
	if (cb)
		cb(arg, 0, seq, NULL);
	retention(s);
	pump_all(s);
}

/* ------------------------------------------------------------------ */
/* lookups                                                             */

int store_find_dedup(const struct store *s, uint8_t type, uint64_t key, unsigned max_age_s, uint64_t *seq)
{
	int64_t now = store_wall(s);
	unsigned i;

	if (!key)
		return -ENOENT;
	for (i = s->n; i-- > 0;) {
		const struct item *it = &s->it[i];

		if (it->e.type != type || it->e.dedup != key || it->abandoned)
			continue;
		if (max_age_s && now >= WALL_PLAUSIBLE && it->e.time >= WALL_PLAUSIBLE && now - it->e.time > (int64_t)max_age_s)
			return -ENOENT;
		if (seq)
			*seq = it->e.seq;
		return 0;
	}
	return -ENOENT;
}

int store_find_lookup(const struct store *s, uint8_t type, uint64_t key, uint64_t *seq)
{
	unsigned i;

	if (!key)
		return -ENOENT;
	for (i = s->n; i-- > 0;) {
		const struct item *it = &s->it[i];

		if (it->e.type == type && it->e.lookup == key && it->durable && !it->abandoned) {
			if (seq)
				*seq = it->e.seq;
			return 0;
		}
	}
	return -ENOENT;
}

/* ------------------------------------------------------------------ */
/* state, probe, sweep                                                 */

static unsigned build_devs(const struct store *s, struct sio_dev *out)
{
	unsigned i, n = 0;

	for (i = 0; i < STORE_MAX_DEV; i++) {
		const struct sdev *d = &s->dev[i];

		if (!d->used)
			continue;
		memset(&out[n], 0, sizeof(out[n]));
		snprintf(out[n].id, sizeof(out[n].id), "%s", d->id);
		out[n].cursor = d->cursor;
		out[n].reported = d->reported;
		out[n].flags = d->uses_ack ? SIO_DEV_ACK : 0;
		out[n].last_seen = d->last_seen;
		n++;
	}
	return n;
}

static bool flush_state(struct store *s)
{
	struct sio_req *r;

	if (!s->ready || !s->dirty)
		return true;
	r = sio_req_new(SIO_STATE);
	if (!r)
		return false;
	r->devs = calloc(STORE_MAX_DEV, sizeof(*r->devs));
	if (!r->devs) {
		sio_req_free(r);
		return false;
	}
	r->ndev = build_devs(s, r->devs);
	if (submit(s, r))
		return false;
	s->dirty = false;
	return true;
}

static void on_state_timer(void *arg)
{
	struct store *s = arg;

	s->state_armed = false;
	if (!flush_state(s)) {
		s->state_armed = true;
		ev_timer_set(s->t_state, s->cfg.state_flush_ms);
	}
	flush_evict(s);
	if (s->evict_to && !s->state_armed) {
		s->state_armed = true;
		ev_timer_set(s->t_state, s->cfg.state_flush_ms);
	}
}

static void sweep(struct store *s)
{
	int64_t now = store_wall(s);
	unsigned i;

	if (!s->ready)
		return;
	retention(s);
	if (now < WALL_PLAUSIBLE)
		return;
	for (i = 0; i < STORE_MAX_DEV; i++) {
		struct sdev *d = &s->dev[i];

		/* like the age limit of the items this compares wall clock times: only with keep_days set (a board with a trustworthy clock) */
		if (s->cfg.keep_days && d->used && !d->registered && d->last_seen && now - d->last_seen > (int64_t)STORE_DEV_DAYS * 86400) {
			char sid[24];

			short_id(d->id, sid, sizeof(sid));
			LOGI("store: device %s not seen for %d days: its record is dropped", sid, STORE_DEV_DAYS);
			dev_free(d);
			mark_dirty(s);
		}
	}
}

static void on_sweep_timer(void *arg)
{
	struct store *s = arg;

	sweep(s);
	ev_timer_set(s->t_sweep, SWEEP_MS);
}

static void on_probe_timer(void *arg)
{
	struct store *s = arg;
	struct sio_req *r;

	if (s->ready && s->healthy)
		return;
	r = sio_req_new(s->ready ? SIO_PROBE : SIO_LOAD);
	if (r && submit(s, r))
		ev_timer_set(s->t_probe, s->cfg.probe_ms);
	else if (!r)
		ev_timer_set(s->t_probe, s->cfg.probe_ms);
}

static void on_load_done(struct store *s, struct sio_req *r)
{
	struct sio_load *L = r->load;
	unsigned i;
	int64_t now = store_wall(s);

	if (!L || (r->err && !L->ent)) {
		set_unhealthy(s, r->err ? r->err : -EIO, "cannot open the store");
		return;
	}
	free(s->it);
	s->it = NULL;
	s->n = s->cap = 0;
	s->ndur = 0;
	s->bytes = 0;
	if (L->n) {
		s->it = calloc(L->n + 64, sizeof(*s->it));
		if (!s->it) {
			set_unhealthy(s, -ENOMEM, "cannot index the store");
			return;
		}
		s->cap = L->n + 64;
	}
	for (i = 0; i < L->n; i++) {
		s->it[s->n].e = L->ent[i];
		s->it[s->n].durable = true;
		s->bytes += item_size(&L->ent[i]);
		s->n++;
		s->ndur++;
	}
	s->next_seq = L->next_seq;
	for (i = 0; i < L->ndev && i < STORE_MAX_DEV; i++) {
		struct sdev *d = &s->dev[i];

		memset(d, 0, sizeof(*d));
		d->s = s;
		d->used = true;
		snprintf(d->id, sizeof(d->id), "%s", L->dev[i].id);
		d->hash = store_hash(d->id);
		d->cursor = L->dev[i].cursor > s->next_seq - 1 ? s->next_seq - 1 : L->dev[i].cursor;
		d->pos = d->cursor;
		d->reported = L->dev[i].reported;
		d->uses_ack = L->dev[i].flags & SIO_DEV_ACK;
		d->last_seen = d->persisted_seen = L->dev[i].last_seen;
		d->retry = ev_timer_new(dev_retry, d);
	}
	s->c.torn_records += L->torn;
	s->c.bodies_missing += L->bodies_missing;
	s->c.log_bytes = L->log_bytes;
	if (L->torn || L->bodies_missing || L->orphans || L->state_bad || L->log_reset)
		LOGW("store: loaded with repairs: %lu torn record(s), %lu item(s) without body, %lu orphan body file(s)%s%s", L->torn,
		     L->bodies_missing, L->orphans, L->state_bad ? ", state file lost" : "", L->log_reset ? ", log reset" : "");
	LOGI("store: %s: %u item(s) loaded, next sequence number %llu, %u device record(s)", s->cfg.dir, L->n,
	     (unsigned long long)s->next_seq, L->ndev);
	s->ready = true;
	s->healthy = true;
	s->error[0] = 0;
	if (r->err)
		set_unhealthy(s, r->err, "cannot write the state file");
	sweep(s);
	(void)now;
	/* registrations that arrived while loading */
	for (i = 0; i < STORE_MAX_DEV; i++)
		if (s->pend[i].used) {
			s->pend[i].used = false;
			dev_register(s, s->pend[i].ident, s->pend[i].id, s->pend[i].features, s->pend[i].ack_state, s->pend[i].ack_seq);
		}
	notify_usable(s);
}

static void handle(struct store *s, struct sio_req *r)
{
	switch (r->op) {
	case SIO_LOAD:
		on_load_done(s, r);
		break;
	case SIO_APPEND:
		on_append_done(s, r);
		break;
	case SIO_READ:
		on_read_done(s, r);
		break;
	case SIO_PROBE:
		if (r->err) {
			s->c.io_errors++;
			ev_timer_set(s->t_probe, s->cfg.probe_ms);
		} else if (!s->healthy) {
			s->healthy = true;
			s->error[0] = 0;
			LOGI("store: the file system accepts writes again, the store is back");
			notify_usable(s);
		}
		break;
	case SIO_STATE:
		if (r->err) {
			s->dirty = true;
			set_unhealthy(s, r->err, "cannot write the state file");
		}
		break;
	case SIO_EVICT:
	case SIO_DROP:
		if (r->err)
			set_unhealthy(s, r->err, "cannot update the log");
		break;
	case SIO_BLOB_PUT:	/* not used by the store */
	case SIO_BLOB_GET:
		break;
	}
}

static void drain(struct store *s)
{
	struct sio_req *r;

	sio_ack(s->io);
	while ((r = sio_next(s->io))) {
		handle(s, r);
		sio_req_free(r);
	}
}

static void on_event_fd(void *arg, int fd)
{
	(void)fd;
	drain(arg);
}

static void on_drain_timer(void *arg)
{
	drain(arg);
}

void store_sync(struct store *s)
{
	if (s->inline_io) {
		drain(s);
		return;
	}
	while (sio_outstanding(s->io)) {
		struct sio_req *r = sio_wait(s->io, 2000);

		if (!r)
			break;
		handle(s, r);
		sio_req_free(r);
	}
}

/* ------------------------------------------------------------------ */
/* life                                                                */

struct store *store_new(const struct store_cfg *cfg, const struct store_ops *ops)
{
	struct store *s = calloc(1, sizeof(*s));
	struct sio_req *r;

	if (!s)
		return NULL;
	s->cfg = *cfg;
	cfg_clamp(&s->cfg);
	if (ops)
		s->ops = *ops;
	s->inline_io = s->ops.inline_io;
	s->next_seq = 1;
	s->t_drain = ev_timer_new(on_drain_timer, s);
	s->t_state = ev_timer_new(on_state_timer, s);
	s->t_probe = ev_timer_new(on_probe_timer, s);
	s->t_sweep = ev_timer_new(on_sweep_timer, s);
	s->t_rd = ev_timer_new(on_rd_timer, s);
	s->io = sio_open(s->cfg.dir, !s->inline_io, 32);
	if (!s->t_drain || !s->t_state || !s->t_probe || !s->t_sweep || !s->t_rd || !s->io) {
		store_free(s);
		return NULL;
	}
	if (!s->inline_io) {
		s->efd = ev_fd_add(sio_event_fd(s->io), on_event_fd, s);
		if (!s->efd) {
			store_free(s);
			return NULL;
		}
	}
	r = sio_req_new(SIO_LOAD);
	if (!r || submit(s, r)) {
		store_free(s);
		return NULL;
	}
	s->load_sent = true;
	ev_timer_set(s->t_sweep, SWEEP_MS);
	return s;
}

void store_free(struct store *s)
{
	unsigned i;

	if (!s)
		return;
	if (s->io && s->ready) {
		s->dirty = true;
		flush_state(s);
	}
	for (i = 0; i < STORE_MAX_DEV; i++)
		if (s->dev[i].used)
			dev_free(&s->dev[i]);
	ev_fd_del(s->efd);
	sio_close(s->io);		/* the writer drains its queue first, then stops */
	ev_timer_free(s->t_drain);
	ev_timer_free(s->t_state);
	ev_timer_free(s->t_probe);
	ev_timer_free(s->t_sweep);
	ev_timer_free(s->t_rd);
	while (s->rd) {
		struct rdq *q = s->rd;

		s->rd = q->next;
		free(q);
	}
	for (i = 0; i < CACHE_N; i++)
		cent_free(&s->cache[i]);
	free(s->it);
	free(s);
}

void store_set_cfg(struct store *s, const struct store_cfg *cfg)
{
	struct store_cfg c = *cfg;

	cfg_clamp(&c);
	if (strcmp(c.dir, s->cfg.dir))
		LOGW("store: a changed store_dir (%s) takes effect after a restart", c.dir);
	snprintf(c.dir, sizeof(c.dir), "%s", s->cfg.dir);
	s->cfg = c;
	retention(s);
}

void store_set_handler(struct store *s, uint8_t type, const struct store_handler *h)
{
	unsigned i;

	if (type < 1 || type >= STORE_TYPE_MAX)
		return;

	if (h) {
		s->h[type] = *h;
		return;
	}
	memset(&s->h[type], 0, sizeof(s->h[type]));
	/* whatever was in flight through the removed handler is gone without a callback: those devices start over at their next pump */
	for (i = 0; i < STORE_MAX_DEV; i++)
		if (s->dev[i].used && (s->dev[i].st == D_SEND || s->dev[i].st == D_READ))
			dev_stop(&s->dev[i]);
}

/* ------------------------------------------------------------------ */
/* status                                                              */

void store_get_status(const struct store *s, struct store_status *st)
{
	unsigned i, k = 0;
	int64_t now = store_wall(s);
	struct sio_stats io;

	*st = s->c;
	st->ready = s->ready;
	st->healthy = s->healthy;
	snprintf(st->error, sizeof(st->error), "%s", s->error);
	snprintf(st->dir, sizeof(st->dir), "%s", s->cfg.dir);
	st->items = s->ndur;
	st->bytes = s->bytes;
	st->first_seq = s->n && s->it[0].durable ? s->it[0].e.seq : 0;
	st->head_seq = s->next_seq - 1;
	sio_get_stats(s->io, &io);
	st->compactions = io.compactions;
	st->log_bytes = io.log_bytes ? io.log_bytes : s->c.log_bytes;
	for (i = 0; i < STORE_MAX_DEV; i++) {
		const struct sdev *d = &s->dev[i];
		struct store_dev_status *o;
		unsigned j;

		if (!d->used)
			continue;
		o = &st->dev[k++];
		memset(o, 0, sizeof(*o));
		short_id(d->id, o->id, sizeof(o->id));
		o->registered = d->registered;
		o->uses_ack = d->uses_ack;
		o->cursor = d->cursor;
		o->reported = d->reported;
		o->pos = d->pos;
		for (j = idx_after(s, d->pos); j < s->n; j++)
			if (s->it[j].durable && addressed(d, &s->it[j]))
				o->lag++;
		o->last_seen_s = d->last_seen && now >= d->last_seen ? now - d->last_seen : -1;
		o->delivered = d->delivered;
		o->missed = d->missed;
		o->failures = d->failures;
	}
	st->ndev = k;
}

unsigned store_list(const struct store *s, uint64_t from, struct store_info *out, unsigned max)
{
	unsigned i, n = 0;

	for (i = idx_after(s, from ? from - 1 : 0); i < s->n && n < max; i++) {
		const struct item *it = &s->it[i];

		out[n].seq = it->e.seq;
		out[n].type = it->e.type;
		out[n].time = it->e.time;
		snprintf(out[n].peer, sizeof(out[n].peer), "%s", it->e.peer);
		out[n].size = item_size(&it->e) - ITEM_OVERHEAD;
		out[n].durable = it->durable;
		n++;
	}
	return n;
}
