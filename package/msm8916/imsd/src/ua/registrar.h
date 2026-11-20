/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UA_REGISTRAR_H
#define IMSD_UA_REGISTRAR_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../sip/msg.h"
#include "../sip/txn.h"

/*
 * LAN-side registrar / location service (RFC 3261 section 10), no
 * authentication. Every device on the LAN that registers represents the same
 * single mobile line, so address-of-record (AOR), user and domain are stored
 * but never checked.
 *
 * A binding is identified by an opaque, never reused reg_id that stays valid
 * until the binding is removed; other modules keep ids, not pointers. A
 * `const struct reg_binding *` returned by this API is only valid until the
 * registrar is mutated (REGISTER processed, expiry, reg_remove, any event
 * callback) -- re-resolve through reg_find() instead of holding it.
 *
 * Identity of a binding: (AOR, normalized Contact URI = scheme:user@host:port,
 * URI parameters such as rinstance= ignored). When the Contact carries a
 * +sip.instance, a binding of the same AOR and instance is replaced (same id,
 * new Contact), so a device that comes back from another port does not ring
 * twice.
 *
 * Where requests go (binding.target): the Contact host:port when the Contact
 * host is an IP literal equal to the REGISTER's source IP; if the Contact host
 * is a name (we never resolve) or a different IP (NAT, wrong interface
 * choice), the REGISTER's source address wins and target_from_src is set.
 */

struct registrar;
typedef uint32_t reg_id_t;
#define REG_ID_NONE 0

/* Allow / Accept method bits learned from REGISTER or later responses */
#define REG_M_INVITE	(1u << 0)
#define REG_M_ACK	(1u << 1)
#define REG_M_CANCEL	(1u << 2)
#define REG_M_BYE	(1u << 3)
#define REG_M_OPTIONS	(1u << 4)
#define REG_M_MESSAGE	(1u << 5)
#define REG_M_UPDATE	(1u << 6)
#define REG_M_INFO	(1u << 7)
#define REG_M_NOTIFY	(1u << 8)
#define REG_M_PRACK	(1u << 9)
#define REG_M_REFER	(1u << 10)

/* Feature tags of the Contact header (RFC 3840 style, with or without a value, any case; value 0 / false = off) */
#define REG_F_MMS	(1u << 0)	/* +g.imsd.mms: an MMS client, wants the original notifications and fetches through the MMS proxy */
#define REG_F_CARBONS	(1u << 1)	/* +g.imsd.carbons: wants copies of the messages the other devices of the line send */

/* X-IMSD-Ack-Seq header of a REGISTER: decimal digits only, at most 20 characters and not above 2^64-1; anything else is REG_ACK_BAD */
#define REG_ACK_NONE	0
#define REG_ACK_OK	1
#define REG_ACK_BAD	2

struct reg_binding {
	reg_id_t id;
	char aor[160];		/* normalized "scheme:user@host" of the To URI */
	char contact[256];	/* Contact URI exactly as registered: the Request-URI toward the device */
	char key[200];		/* normalized contact (scheme:user@host:port) used for matching */
	char instance[96];	/* +sip.instance value without quotes, "" if none */
	char ua[96];		/* User-Agent of the last REGISTER */
	char accept[96];	/* Accept header(s) of the last REGISTER ("" if none) */
	char supported[96];	/* Supported header(s) of the last REGISTER */
	struct addr src;	/* source of the last REGISTER */
	struct addr target;	/* destination for requests */
	bool target_from_src;	/* target is the source address, not the Contact host:port */
	struct sip_endpoint *ep;	/* endpoint the REGISTER arrived on (referenced) */
	uint64_t registered_ms;	/* ev_now_ms() of first registration */
	uint64_t refreshed_ms;	/* last REGISTER */
	uint64_t expires_at_ms;
	unsigned expires_s;	/* granted interval of the last REGISTER */
	int q;			/* q-value in thousandths, default 1000 */
	char call_id[128];	/* of the last REGISTER (ordering rule 10.3) */
	uint32_t cseq;
	uint32_t allow;		/* REG_M_* bits */
	uint32_t features;	/* REG_F_* of the last REGISTER */
	uint8_t ack_state;	/* X-IMSD-Ack-Seq of the last REGISTER: REG_ACK_NONE / REG_ACK_OK / REG_ACK_BAD */
	uint64_t ack_seq;	/* its value when REG_ACK_OK: the highest message sequence number the device has stored (see store/store.h) */
	bool allow_known;	/* the device declared an Allow header (REGISTER or a later response) */
	bool answered;		/* has ever answered a request we sent it (any response) */
	bool restored;		/* re-created from the persisted table at start; cleared by the first real REGISTER */
	bool reachable;		/* false after a failed keepalive/request; true again on any sign of life */
	unsigned long n_register, n_rx, n_tx, n_answered, n_timeouts;
	uint64_t last_rx_ms;
};

enum registrar_event {
	REG_EV_ADDED,		/* new binding */
	REG_EV_REFRESHED,	/* re-REGISTER of a known binding (contact/target may have changed) */
	REG_EV_REMOVED,		/* binding is gone (reason in reg_event_info.reason); b is a copy valid during the call */
	REG_EV_REACHABLE,	/* reachable flag flipped to true */
	REG_EV_UNREACHABLE,	/* reachable flag flipped to false */
};
enum reg_removal {
	REG_RM_NONE,
	REG_RM_EXPIRED,
	REG_RM_UNREGISTERED,	/* expires=0 / Contact: * */
	REG_RM_FLUSHED,		/* reg_remove() / reg_flush() */
};
/* Events are delivered synchronously after the table was updated; the callback must not call reg_handle_register. */
typedef void (*reg_event_cb)(struct registrar *r, enum registrar_event ev, const struct reg_binding *b,
			     enum reg_removal reason, void *arg);
/* Keepalive tick: send an OPTIONS ping toward binding id and report the outcome with reg_set_reachable(). */
typedef void (*reg_ping_cb)(struct registrar *r, reg_id_t id, void *arg);

struct registrar_cfg {
	unsigned min_expires;	/* default 60 */
	unsigned max_expires;	/* default 3600 */
	unsigned default_expires; /* when neither Contact nor Expires gives one; default 3600, clamped */
	unsigned max_bindings;	/* default 16; REGISTER that would exceed it gets 503, nothing is evicted */
	unsigned keepalive_s;	/* 0 = off (default); otherwise ping every binding this often */
	reg_event_cb on_event;
	reg_ping_cb ping;
	void *arg;
};

struct reg_stats {
	unsigned long registers, ok, rejected_423, rejected_503, rejected_400, rejected_500, queries;
	unsigned long added, refreshed, removed, expired;
};

/* cfg may be NULL (defaults). NULL on OOM. */
struct registrar *registrar_new(const struct registrar_cfg *cfg);
/* Drop everything silently (no events) and free. */
void registrar_free(struct registrar *r);

/*
 * Process a REGISTER and reply on st (200 with the full binding list of the AOR, 400, 420, 423, 500 or
 * 503). Returns the status sent. ep/src are where the request came from (bindings keep a reference on ep).
 */
int reg_handle_register(struct registrar *r, struct txn_server *st, struct sip_endpoint *ep,
			const struct addr *src, const struct sip_msg *req);

unsigned reg_count(const struct registrar *r);
const struct reg_binding *reg_find(const struct registrar *r, reg_id_t id);
/* iteration in ascending id order: the first binding with id > after (pass REG_ID_NONE to start); NULL at the end. Safe against removals. */
const struct reg_binding *reg_next(const struct registrar *r, reg_id_t after);
/*
 * Which binding does a request belong to? 1. source ip:port equals a binding's source or target, 2. the
 * request's Contact (if any) matches a binding key, 3. the source IP matches exactly one binding.
 * REG_ID_NONE if unknown. contact_uri may be NULL.
 */
reg_id_t reg_identify(const struct registrar *r, const struct addr *src, const char *contact_uri);
/* whether the device accepts method / content type (true when it never said otherwise) */
bool reg_allows(const struct reg_binding *b, const char *method);
bool reg_accepts(const struct reg_binding *b, const char *content_type);

/*
 * Re-create a binding from the persisted table (regpersist.h) through the normal add path: a fresh id, the event REG_EV_ADDED
 * (every module hook fires as for a live REGISTER), the expiry timer, `restored` = true. `in` carries the fields of a
 * binding as saved (aor, contact, key (recomputed), instance, ua, accept, supported, src, target, target_from_src, expires_s,
 * q, call_id, cseq, allow, allow_known, features, registered_ms (already translated to ev_now_ms()), answered); the rest is
 * reset. remain_s: seconds to live (>= 1). A binding that matches a live one (same AOR and key, or same instance) is left
 * alone: the live one wins. 0 added, -EEXIST matches a live binding, -ENOSPC table full, -EINVAL, -ENOMEM.
 */
int reg_restore(struct registrar *r, const struct reg_binding *in, struct sip_endpoint *ep, unsigned remain_s);

/* remove one binding (event REG_EV_REMOVED / REG_RM_FLUSHED). 0 / -1 */
int reg_remove(struct registrar *r, reg_id_t id);
void reg_flush(struct registrar *r);

/* bookkeeping for the modules that talk to devices */
void reg_note_rx(struct registrar *r, reg_id_t id);		/* a request from the device arrived (sign of life) */
void reg_note_tx(struct registrar *r, reg_id_t id);		/* we sent a request */
void reg_note_response(struct registrar *r, reg_id_t id, const struct sip_msg *resp);	/* any response: answered, reachable, learns Allow */
void reg_note_timeout(struct registrar *r, reg_id_t id);	/* a request got no answer: unreachable */
void reg_set_reachable(struct registrar *r, reg_id_t id, bool ok);

const struct reg_stats *reg_get_stats(const struct registrar *r);
unsigned reg_min_expires(const struct registrar *r);

/* "scheme:user@host" lower-cased host, port and parameters dropped; used for AORs. 0 / -1 */
int reg_normalize_aor(const char *uri, char *out, size_t n);
#endif
