/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_STORE_SIO_H
#define IMSD_STORE_SIO_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * File layer of the message store: ALL file I/O of the store (append, fsync, loading at start, compaction, reading of bodies,
 * the state file) happens in one dedicated writer thread, because flash (the device's eMMC / f2fs overlay) can stall for tens of
 * milliseconds. The main loop never calls into the file system: it submits requests (a bounded queue) and takes the
 * completions from sio_next(), woken through an eventfd (sio_event_fd), the same command / event pattern as media/bridge.c.
 * For tests there is an inline backend (sio_open(..., false)): the request runs in sio_submit() on the caller's thread and
 * its completion is queued like any other, so the state machines above it can be driven deterministically.
 *
 * Files in the store directory (mode 0700, created by the init script; the sub directory b/ is created here):
 *
 *   log        the record log (append only). 16 byte header: "IMSDLOG1", u32 version (1), u32 0. Then records:
 *                u32 len | u32 crc32(payload) | payload[len]          (little endian; len <= 256 KiB)
 *              payload byte 0 is the record type:
 *                1 ITEM   u8 1 | u8 type | u8 flags | u8 nexcl | u64 seq | i64 time | u64 dedup | u64 lookup | u32 meta_len |
 *                         u32 body_len | u32 body_crc | u16 peer_len | u64 excl[nexcl] | peer | meta
 *                2 PURGE  u8 2 | u64 keep_from     (everything with a smaller seq is gone; written for purge only)
 *                3 DROP   u8 3 | u64 seq          (this one item is gone)
 *              A torn write (power loss) leaves a short or wrong record at the end: the loader stops at the first record that
 *              does not verify (length, CRC, increasing seq), truncates the file there and counts it; earlier records are intact.
 *   b/<seq>    the body of an item (the MMS PDU), 16 hex digits, written and fsynced BEFORE the record that names it
 *   state      small file, rewritten atomically (temp file, fsync, rename, fsync of the directory): "IMSDST01", u32 version,
 *              u32 ndev, u64 reserved, ndev * (char id[96], u64 cursor, u64 reported, u32 flags, u32 0, i64 last_seen), u32 crc32.
 *              `reserved` is a sequence number block: no seq >= reserved was ever assigned, so after a crash (a torn last record, a
 *              stale state) the counter restarts at max(reserved, last record + 1) and a number is never reused.
 *   log.new, state.tmp   leftovers of a crash, removed at load
 *
 *   <name>     whole-file blobs of other users of the directory (SIO_BLOB_PUT / SIO_BLOB_GET; the LAN registrar's `bindings`): the
 *              caller supplies the bytes (req->body, body_len <= SIO_BLOB_MAX) and the format; PUT replaces atomically (temp file `<name>.tmp`,
 *              fsync, rename, fsync of the directory), GET returns the whole file in req->body (-ENOENT when there is none).
 *
 * Compaction (done by the writer when evicted records pile up): copy the live records to log.new, fsync, rename over log, fsync the
 * directory. Before the rename the old log is complete and valid, after it the new one is: there is no moment without a valid file.
 */

#define SIO_PEER_MAX	48
#define SIO_EXCL_MAX	4
#define SIO_DEVID_MAX	96
#define SIO_META_MAX	(128u * 1024)
#define SIO_BODY_MAX	(16u * 1024 * 1024)
#define SIO_RESERVE	64
#define SIO_BLOB_MAX	(512u * 1024)

/* an item as the index knows it (no offsets: those belong to the writer thread) */
struct sio_entry {
	uint64_t seq;
	int64_t time;
	uint8_t type, flags;
	uint8_t nexcl;
	uint64_t dedup, lookup;
	uint32_t meta_len, body_len, body_crc;
	uint64_t excl[SIO_EXCL_MAX];
	char peer[SIO_PEER_MAX];
};

/* a device record as persisted */
struct sio_dev {
	char id[SIO_DEVID_MAX];
	uint64_t cursor, reported;
	uint32_t flags;
	int64_t last_seen;
};
#define SIO_DEV_ACK	1u	/* the device reports its own cursor (X-IMSD-Ack-Seq) */

enum sio_op { SIO_LOAD = 1, SIO_APPEND, SIO_STATE, SIO_READ, SIO_EVICT, SIO_DROP, SIO_PROBE, SIO_BLOB_PUT, SIO_BLOB_GET };

struct sio_load {
	struct sio_entry *ent;		/* ascending seq */
	unsigned n;
	struct sio_dev *dev;
	unsigned ndev;
	uint64_t next_seq;		/* first number that may be assigned */
	unsigned long torn;		/* records cut off at the end (torn write / CRC) */
	unsigned long bodies_missing;	/* items dropped because their body file is missing or short */
	unsigned long orphans;		/* body files without an item, removed */
	bool state_bad;			/* the state file was unreadable (cursors lost) */
	bool log_reset;			/* the log had a bad header and was set aside */
	uint64_t log_bytes;
};

struct sio_req {
	struct sio_req *next;
	enum sio_op op;
	uint32_t token;			/* the caller's, echoed in the completion */
	struct sio_entry ent;		/* APPEND: the item; READ: .seq; EVICT: .seq = keep_from; DROP: .seq */
	uint8_t *meta, *body;		/* owned (free()d by sio_req_free): APPEND input, READ output */
	size_t meta_len, body_len;
	bool want_body;			/* READ */
	bool persist;			/* EVICT: write a PURGE record */
	struct sio_dev *devs;		/* STATE: the snapshot, owned */
	unsigned ndev;
	int err;			/* completion: 0 or -errno (-EBADMSG: CRC, -ENOENT: not there, -ECANCELED: test crash) */
	struct sio_load *load;		/* LOAD completion, owned */
	char name[24];			/* BLOB_PUT / BLOB_GET: file name in the directory ([A-Za-z0-9._-]) */
};
struct sio_req *sio_req_new(enum sio_op op);
void sio_req_free(struct sio_req *r);

struct sio_stats {
	unsigned long compactions, appends, errors;
	uint64_t log_bytes;
	unsigned live, dead;
};

struct sio;
/* dir: the store directory. threaded: a writer thread (false: inline backend). qmax: queue bound (0: 32). Does not touch the
 * file system. NULL on failure */
struct sio *sio_open(const char *dir, bool threaded, unsigned qmax);
/* the writer finishes what is queued, the thread is joined, queued completions are discarded. Never blocks on anything else. */
void sio_close(struct sio *s);
/* 0: queued (the request now belongs to sio), -EBUSY: queue full (not consumed). A LOAD always fits. */
int sio_submit(struct sio *s, struct sio_req *r);
/* next completion or NULL (the caller frees it with sio_req_free) */
struct sio_req *sio_next(struct sio *s);
/* clear the eventfd: call it BEFORE draining with sio_next() (a completion that arrives meanwhile re-arms it) */
void sio_ack(struct sio *s);
/* readable when completions are queued (threaded backend), -1 for the inline backend */
int sio_event_fd(const struct sio *s);
unsigned sio_outstanding(const struct sio *s);	/* submitted and not yet taken */
void sio_get_stats(struct sio *s, struct sio_stats *st);
/* threaded backend: wait up to ms for the next completion (tests / shutdown only, never from the main loop) */
struct sio_req *sio_wait(struct sio *s, unsigned ms);

uint32_t sio_crc32(const void *p, size_t n);

/* ---- fault injection for the tests ---- */
#define SIO_FP_BODY	1u	/* writing a body file */
#define SIO_FP_LOGWRITE	2u	/* appending a record (half of it is written first) */
#define SIO_FP_LOGSYNC	4u	/* fsync of the log */
#define SIO_FP_STATE	8u	/* the state file */
#define SIO_FP_READ	16u
#define SIO_FP_COMPACT	32u	/* copying records in the compaction */
struct sio_fault {
	unsigned points;	/* SIO_FP_* mask */
	int err;		/* errno to return (ENOSPC, EIO) */
	int count;		/* fail this many hits, -1: forever */
	unsigned stall_ms;	/* the writer sleeps this long before every request (queue tests) */
	int kill_step;		/* compaction: act as if the process died right after step 1..5 (returns -ECANCELED, no cleanup) */
};
extern struct sio_fault sio_fault;
#endif
