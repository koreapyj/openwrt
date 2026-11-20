/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_STORE_STORE_H
#define IMSD_STORE_STORE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "sio.h"
#include "../ua/registrar.h"

/*
 * Persistent message store with per-device redelivery ("store and forward").
 *
 * MODEL
 *  1. Every user visible item (a received SMS, a received MMS, the carbon copy of a sent SMS, of a sent MMS) gets a line wide,
 *     strictly increasing sequence number when it enters the store. The counter survives restarts and is never reused (sio.h:
 *     reserved block).
 *  2. The store does not know whether "all devices have it". Items leave it only through the retention limits (count, age,
 *     bytes; oldest first) and store_purge(), never because of delivery state.
 *  3. Per device a cursor = the highest sequence number that device has. Device identity: the REGISTER Contact +sip.instance
 *     when there is one, else the user part of the registered AOR (plain phones therefore need distinct user names). A device
 *     seen for the first time (without X-IMSD-Ack-Seq) starts at the current head: it gets no history. Records of devices not
 *     seen for 30 days go; at most 32 are kept (the least recently seen, not registered, goes first; logged).
 *  4. The cursor moves when
 *       - the device reports it: REGISTER header "X-IMSD-Ack-Seq: n" (the highest number it has durably stored). It is
 *         authoritative: cursor = min(n, head), also backwards (the point: resend what the app lost), also for a device seen for
 *         the first time. A malformed value is ignored (logged);
 *       - a device that has never reported: it answered 2xx to the item's (last piece's) MESSAGE;
 *       - a device that reports: 2xx answers move only a volatile position that prevents resending within the registration; the
 *         next REGISTER with a header replaces it.
 *     Items the device is not addressed by (carbons for a device without +g.imsd.carbons, the sender's own carbon) are passed
 *     over silently, so that they are not delivered later either.
 *  5. Delivery: at every REGISTER of a device and whenever a new item became durable, every stored item above the position that
 *     is addressed to the device goes out strictly in sequence order, one at a time (a text in pieces: piece after piece), the next
 *     only after the previous one was answered 2xx. A failure stops the device; it is tried again at its next REGISTER and once
 *     after retry_ms while it stays registered. Items evicted before a device caught up are skipped (counted).
 *  6. Every MESSAGE that carries an item has "X-IMSD-Seq: <n>" (the handlers add it); a redelivery is identical to the first
 *     delivery (original timestamps and ids), no marker.
 *
 * FLASH: all file I/O runs in the writer thread (sio.c). The main loop keeps the authoritative index in RAM (no payloads: they are
 * read on demand, a small LRU cache holds the last ones). An item is deliverable only after its append is durable. Cursor changes
 * are written at most every state_flush_ms and at shutdown: after a crash a cursor may be stale, which only causes redelivery of
 * messages the device may already have (clients de-duplicate by X-IMSD-Seq).
 *
 * FAILURE: I/O errors / a full file system stop acceptance (store_usable() false, status shows the error); the callers fall back to
 * live-only delivery as before. A probe every probe_ms recovers when space is back.
 *
 * Everything here runs on the main loop and never blocks.
 */

enum store_type {
	STORE_SMS = 1,		/* a received SMS (or status report notice) */
	STORE_MMS = 2,		/* a received MMS: the notification, the retrieve-conf as body */
	STORE_CARBON_SMS = 3,	/* copy of an SMS that another device sent */
	STORE_CARBON_MMS = 4,	/* copy of an MMS another device sent: the M-Send.req as body */
	STORE_TYPE_MAX = 5,
};

#define STORE_MAX_DEV	32
#define STORE_DEV_DAYS	30

struct store_cfg {
	char dir[96];
	unsigned keep_messages;		/* 500 */
	unsigned keep_days;		/* 30, 0 = no age limit */
	uint64_t keep_bytes;		/* 32 MiB, meta and bodies */
	unsigned state_flush_ms;	/* 10000 */
	unsigned retry_ms;		/* 30000 */
	unsigned probe_ms;		/* 30000 */
};
void store_cfg_defaults(struct store_cfg *c);

struct store_ops {
	int64_t (*wall)(void *ctx);	/* Unix time; NULL: time() */
	bool inline_io;			/* tests: the inline file backend (sio.h) */
	void *ctx;
};

struct store;
/* starts loading (in the writer thread). NULL on out of memory / thread failure. */
struct store *store_new(const struct store_cfg *cfg, const struct store_ops *ops);
/* writes the cursors, stops the writer thread (joins), frees. Pending add callbacks are not called. */
void store_free(struct store *s);
void store_set_cfg(struct store *s, const struct store_cfg *cfg);
/* The LAN side is gone (the registrar was freed without events): every device is unregistered, deliveries in flight aborted */
void store_lan_down(struct store *s);
/* tests / shutdown only: wait until the writer has nothing outstanding and process the completions (blocks!) */
void store_sync(struct store *s);

/* a binding event of the LAN registrar (core module hook) */
void store_on_binding(struct store *s, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why);
/* identity of the device behind a binding ("i:<instance>" / "u:<user of the AOR>"), and its 64 bit hash (for item exclusions) */
void store_identity(const struct reg_binding *b, char *out, size_t n);
uint64_t store_hash(const char *s);

/* loaded and writable: items are accepted */
bool store_usable(const struct store *s);
/* cb(arg) runs from the event loop each time the store becomes usable (the load finished, or it is healthy again); cb NULL removes it */
void store_set_usable_cb(struct store *s, void (*cb)(void *), void *arg);
int64_t store_wall(const struct store *s);

/* ---- adding ---- */
struct store_add {
	uint8_t type;
	int64_t time;			/* 0: now */
	const char *peer;		/* number / address of the other party (index, listing; not text) */
	uint64_t dedup;			/* 0 = none: store_find_dedup() */
	uint64_t lookup;		/* 0 = none: store_find_lookup() (the Content-Location, the carbon id) */
	const uint64_t *excl;		/* device identity hashes this item is NOT addressed to (carbons: the sender) */
	unsigned nexcl;
	const void *meta;		/* type specific, see the modules (copied) */
	size_t meta_len;
	const void *body;		/* optional (copied) */
	size_t body_len;
	void *owner;			/* for store_detach() */
};
/* status 0: durable. status < 0: not stored (the item is gone; meta / body in `a` are valid during the call, for the fallback to live
 * delivery). Called from the event loop, never synchronously from store_add(). */
typedef void (*store_add_cb)(void *arg, int status, uint64_t seq, const struct store_add *a);
/* 0 queued (*seq = the number it got), or -errno at once: -ENODEV not usable, -EBUSY queue full, -EFBIG, -ENOMEM; cb is not called then */
int store_add(struct store *s, const struct store_add *a, store_add_cb cb, void *arg, uint64_t *seq);
/* the caller gave up waiting: when the item is not durable yet it is dropped again as soon as it is (true), cb is never called */
bool store_abandon(struct store *s, uint64_t seq);
/* an owner goes away: no callbacks to it */
void store_detach(struct store *s, void *owner);

/* ---- looking up ---- */
/* the newest item of the type with this dedup key that is at most max_age_s old (0: any age); not abandoned. 0 found / -ENOENT */
int store_find_dedup(const struct store *s, uint8_t type, uint64_t key, unsigned max_age_s, uint64_t *seq);
int store_find_lookup(const struct store *s, uint8_t type, uint64_t key, uint64_t *seq);

/* ---- reading a payload ---- */
struct store_item {
	uint64_t seq;
	uint8_t type;
	uint8_t flags;
	int64_t time;
	const char *peer;
	const uint8_t *meta;
	size_t meta_len;
	const uint8_t *body;		/* NULL unless asked for */
	size_t body_len;
};
/* err 0: it is valid during the call only. -ENOENT: gone (evicted / purged), other -errno: the file layer failed */
typedef void (*store_read_cb)(void *arg, int err, const struct store_item *it);
/* asynchronous, never calls back synchronously. 0 (token for store_read_cancel) / -EBUSY / -ENODEV / -ENOMEM */
int store_read(struct store *s, uint64_t seq, bool want_body, store_read_cb cb, void *arg, uint32_t *token);
void store_read_cancel(struct store *s, uint32_t token);

/* ---- delivery to the devices ---- */
struct store_handler {
	/* does delivering an item of this type to a device with these features need the body (asked before the read) */
	bool (*needs_body)(void *ctx, uint8_t type, uint32_t features, bool has_body);
	/*
	 * Send the item to ONE binding as SIP MESSAGE(s) (X-IMSD-Seq header included). 0: started, done(arg, nok) follows once from
	 * the event loop (nok > 0: the device answered 2xx to everything), never synchronously. 1: nothing to send for this device
	 * (counts as delivered). -errno: could not start (a failure). abort(ctx, arg) must stop a delivery started with that arg
	 * without calling done.
	 */
	int (*deliver)(void *ctx, const struct store_item *it, reg_id_t binding, uint32_t features,
		       void (*done)(void *arg, int nok), void *arg);
	void (*abort)(void *ctx, void *arg);
	void *ctx;
};
/* handler == NULL removes it */
void store_set_handler(struct store *s, uint8_t type, const struct store_handler *h);

/* ---- status / administration ---- */
struct store_dev_status {
	char id[24];			/* shortened */
	bool registered, uses_ack;
	uint64_t cursor, reported, pos;
	unsigned long lag;		/* items above the position addressed to it (pending) */
	int64_t last_seen_s;		/* seconds ago */
	unsigned long delivered, missed, failures;
};
struct store_status {
	bool ready, healthy;
	char error[96];
	char dir[96];
	unsigned items;
	uint64_t bytes, first_seq, head_seq;
	unsigned long added, evicted, dropped, torn_records, delivered, delivery_failures, add_failed, add_abandoned,
		      dedup_hits, bodies_missing, read_errors, compactions, io_errors;
	uint64_t log_bytes;
	unsigned ndev;
	struct store_dev_status dev[STORE_MAX_DEV];
};
void store_get_status(const struct store *s, struct store_status *st);

struct store_info {
	uint64_t seq;
	uint8_t type;
	int64_t time;
	char peer[SIO_PEER_MAX];
	uint32_t size;
	bool durable;
};
/* index entries with seq >= from, ascending, at most max; returns how many */
unsigned store_list(const struct store *s, uint64_t from, struct store_info *out, unsigned max);
/* remove every item with seq < before_seq (all: everything). Returns how many were removed. */
unsigned store_purge(struct store *s, uint64_t before_seq, bool all);
#endif
