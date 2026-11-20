/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UA_REGPERSIST_H
#define IMSD_UA_REGPERSIST_H
#include <stdbool.h>
#include <stdint.h>
#include "registrar.h"

/*
 * Persistent location table of the LAN registrar: what Kamailio usrloc (db mode) and Asterisk PJSIP (contacts in astdb) do.
 * The bindings are written to <dir>/bindings, restored at start with their ORIGINAL absolute (wall clock) expiry, expired
 * ones are dropped, and a restored binding is an ordinary one (same add path and hooks as a live REGISTER; status shows
 * `restored` until its first real REGISTER). All file I/O runs in the store's writer thread layer (store/sio.c, blob ops):
 * the main loop never touches the file system.
 *
 * File `bindings` (little endian; atomic replace):
 *   "IMSDREG1" | u32 version (1) | u32 count | i64 saved_wall | count * record | u32 crc32 of everything before
 *   record: u32 len | payload[len]
 *     i64 expires_wall, registered_wall, refreshed_wall | u32 expires_s, cseq, allow, features | i32 q | u64 ack_seq |
 *     u8 ack_state, u8 flags (1 target_from_src, 2 allow_known, 4 answered), u8 transport (sip_tp_kind), u8 0 |
 *     u16 src_port, u16 target_port | strings, each u16 len + bytes: aor, contact, instance, ua, accept, supported, call_id,
 *     src_host, target_host
 * A file that does not verify (magic, version, length, CRC) is ignored and logged; the next write replaces it.
 *
 * Write policy: a binding added / removed / expired, or one whose contact, source, target, instance, features, UA, Accept /
 * Supported or q changed: written after at most 1 s (events within that second coalesce into one write). A pure refresh (only
 * the expiry, CSeq, Call-ID moved): at most one write per 60 s. A final write when the LAN side goes down / at shutdown.
 *
 * The device identity of the store ("i:<instance>" / "u:<user>") derives from instance and AOR, both saved. The
 * X-IMSD-Ack-Seq value of the last REGISTER is saved but a restored binding comes back with REG_ACK_NONE: the value may be up
 * to 60 s old and would move the store's position backwards; the store has its own persisted cursor.
 */
struct regpersist;

struct regpersist_cfg {
	const char *dir;		/* the store directory (sio.h) */
	bool inline_io;			/* tests: the inline file backend */
	int64_t (*wall)(void *ctx);	/* Unix time; NULL: time() */
	void *ctx;
};

struct regpersist_stats {
	unsigned long writes;		/* PUT requests submitted */
	unsigned long write_errors;
	unsigned long restored, expired, skipped;	/* of the last load: bindings re-created / dropped by expiry / unusable or not fitting */
	bool loaded;			/* the load of the current attachment finished */
	bool file_bad;			/* the file did not verify */
};

/* NULL on out of memory / no writer thread. Does not touch the file system. */
struct regpersist *regpersist_new(const struct regpersist_cfg *cfg);
/* final write when attached, stop the writer thread, free */
void regpersist_free(struct regpersist *p);

/* The LAN registrar came up: read the file (in the writer thread) and re-create the bindings on `ep` when it completes. */
void regpersist_attach(struct regpersist *p, struct registrar *r, struct sip_endpoint *ep);
/* The LAN registrar is about to go away: write its table now (when the load finished) and forget it. */
void regpersist_detach(struct regpersist *p);
/* registrar event (core module hook) */
void regpersist_on_binding(struct regpersist *p, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why);
void regpersist_stats(const struct regpersist *p, struct regpersist_stats *out);
/* tests / shutdown only: wait for the writer and process the completions (blocks) */
void regpersist_sync(struct regpersist *p);
#endif
