/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UA_LAN_TEXT_H
#define IMSD_UA_LAN_TEXT_H
#include "lan.h"

/*
 * "Deliver this text to the devices on the LAN": one SIP MESSAGE from a given sender to the eligible bindings
 * (lan_fork_request with the "all" semantics), reported as one number: how many devices answered 2xx. The SMS relay does
 * this for incoming SMS and for the carbon copies of the SMS a device sent, the MMS module for incoming MMS (text, original
 * notification) and for the carbon copies of the MMS a device sent.
 */
struct lan_text;
/* nok: devices that answered 2xx; called once, from the event loop, after every branch answered. The handle is invalid after
 * the call (do not lan_text_detach it from inside the callback) */
typedef void (*lan_text_cb)(void *arg, int nok);

/*
 * from_user / from_display as in struct lan_req, extra: optional complete header lines (CRLF each). NULL with errno
 * ENOENT when there is no eligible binding, EINVAL, ENOMEM, EAGAIN otherwise (cb is not called then).
 */
struct lan_text *lan_text_send(struct lan *l, const char *from_user, const char *from_display, const char *extra,
			       const char *text, lan_text_cb cb, void *arg);

struct lan_text_opts {
	const char *from_user, *from_display, *extra;
	const char *content_type;	/* NULL: none (only with an empty body) */
	const uint8_t *body;
	size_t body_len;
	struct lan_fork_opts fork;	/* include / exclude sets */
};
struct lan_text *lan_text_send_ex(struct lan *l, const struct lan_text_opts *o, lan_text_cb cb, void *arg);
/* the callback will not be called any more (only before it was called) */
void lan_text_detach(struct lan_text *t);

/* ---- which bindings ---- */
#define LAN_SELECT_MAX 64
/* ids of the bindings that have every feature bit of `need` and none of `forbid` and accept MESSAGE; returns how many (at most max) */
unsigned lan_select(struct lan *l, uint32_t need, uint32_t forbid, reg_id_t *out, unsigned max);

/* ---- splitting of a long text: lossless ---- */
#define LAN_PIECES_MAX 16
/*
 * Split s (len bytes of UTF-8) into contiguous pieces of at most limit bytes: the pieces are exact slices of s (nothing is
 * dropped or trimmed, concatenated they are s), cut only on UTF-8 character boundaries, right AFTER a line break when one
 * lies in the second half of the piece. At most max pieces; the rest is dropped and *truncated set. Returns the number of
 * pieces (0 for an empty text).
 */
unsigned lan_text_split(const char *s, size_t len, size_t limit, size_t *off, size_t *plen, unsigned max, bool *truncated);

/* The pieces of a message of at most `split` bytes per SIP MESSAGE: one piece as it is, or several, each starting with the
 * marker "(i/n) " (the only thing added) */
struct lan_pieces {
	char *mem;
	const char *text[LAN_PIECES_MAX];
	unsigned n;
	bool truncated;
};
int lan_pieces_make(struct lan_pieces *p, const char *s, size_t len, unsigned split);	/* 0 / -ENOMEM */
void lan_pieces_free(struct lan_pieces *p);

/* ---- several pieces, one after the other ---- */
/*
 * A text in pieces goes out as SIP MESSAGE pieces in order, each after the previous one was answered by at least one device;
 * a piece that no device took ends the delivery. Every piece carries the same headers; with more than one piece also
 * "<part_hdr>: i/n". The owner (lan_seqs) aborts what is running when the LAN object goes away.
 */
struct lan_seqs;
struct lan_seqs *lan_seqs_new(void);
void lan_seqs_free(struct lan_seqs *o);			/* aborts everything, no callbacks */
void lan_seqs_set(struct lan_seqs *o, struct lan *l);	/* NULL: the LAN is going away, everything running is aborted */
void lan_seqs_abort(struct lan_seqs *o, void *arg);	/* the deliveries started with this arg, no callbacks */

struct lan_seq_cfg {
	const char *from_user, *from_display;
	const char *extra;		/* header lines (CRLF each), at most 1900 bytes */
	const char *part_hdr;		/* e.g. "X-MMS-Part", NULL: none */
	const char *const *text;	/* n complete pieces (copied) */
	unsigned n;
	/* instead of text: ONE message with this content type and body (copied; n must be 0). For binary payloads. */
	const char *content_type;
	const uint8_t *body;
	size_t body_len;
	const reg_id_t *include;	/* include_set: only these bindings (copied, at most LAN_SELECT_MAX) */
	unsigned ninclude;
	bool include_set;
	const reg_id_t *exclude;	/* not these bindings (copied, at most LAN_SELECT_MAX) */
	unsigned nexclude;
	void (*done)(void *arg, int nok);	/* once, from the event loop: devices that took every piece (0: none / failed); NULL ok */
	void *arg;
};
/* 0: started (done follows, unless aborted); -ENOENT nobody to deliver to / no LAN; other -errno */
int lan_seq_start(struct lan_seqs *o, const struct lan_seq_cfg *c);

/* "2026-11-20T00:42:55+00:00" (UTC) */
void lan_text_iso(int64_t t, char *out, size_t n);
#endif
