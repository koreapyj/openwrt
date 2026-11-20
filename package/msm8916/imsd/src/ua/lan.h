/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UA_LAN_H
#define IMSD_UA_LAN_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "registrar.h"
#include "../sip/dialog.h"

/*
 * LAN-facing SIP side of imsd: request router, registrar owner, outbound
 * request and fork helpers. The LAN presents the one mobile line as a tiny SIP
 * provider with a single subscriber; every registered device represents it.
 *
 * Wiring (see lan_on_request): the integrator creates the lan, a txn_layer
 * whose txn_cfg.on_request thunk calls lan_on_request(), and attaches the LAN
 * endpoint with lan_attach(). Nothing here blocks or touches sockets besides
 * through the transaction layer. Callbacks are never invoked synchronously from
 * the call that provoked them (except hooks, which run inside lan_on_request).
 *
 * Advertised capabilities toward LAN devices (OPTIONS answers, INVITE Allow):
 *   Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER, MESSAGE, UPDATE, INFO, NOTIFY
 *   Accept: application/sdp, text/plain
 *   no Supported / Require: no 100rel (PRACK), no session timers, no replaces,
 *   no path, no outbound flows, no event packages (Allow-Events never sent).
 * Out-of-dialog responses of this layer carry "Server: <user_agent>".
 *
 * Response choices of the router when no hook is installed: INVITE 480, MESSAGE 503,
 * in-dialog request 481. Always: SUBSCRIBE 489 (no Allow-Events), PUBLISH 405 + Allow,
 * REFER 501 (logged), unsolicited NOTIFY 481 (200 for Event: keep-alive), unknown
 * method 501, out-of-dialog BYE/UPDATE/PRACK 481, INFO 200 when no in-dialog hook.
 */

struct lan;
struct lan_xact;
struct lan_fork;

/* The device a request came from, as far as it can be told. Pointers are only valid during the hook. */
struct lan_peer {
	reg_id_t id;			/* REG_ID_NONE: unregistered source (accepted, but flagged) */
	bool registered;
	const struct reg_binding *b;	/* NULL if !registered */
	struct addr src;
};

/*
 * Hooks fill in what this module deliberately does not implement. A hook that receives a server
 * transaction (st != NULL) owns the reply: it must answer through txn_server_reply (or arrange for it);
 * st stays valid until its TXN_SRV_TERMINATED callback (txn_server_set_cb). req is valid only during the call
 * (txn_server_request(st) stays valid as long as st). Any hook may be NULL.
 */
struct lan_hooks {
	/* new (out-of-dialog) INVITE. Cancellation arrives as TXN_SRV_CANCELLED on st. */
	void (*on_invite)(struct lan *l, const struct lan_peer *peer, struct txn_server *st, const struct sip_msg *req, void *arg);
	/* request carrying a To tag: BYE, re-INVITE, UPDATE, INFO, PRACK, NOTIFY, REFER-less stuff. */
	void (*on_in_dialog)(struct lan *l, const struct lan_peer *peer, struct txn_server *st, const struct sip_msg *req, void *arg);
	/* SIP MESSAGE (text/plain; charset=utf-8 for SMS) */
	void (*on_message)(struct lan *l, const struct lan_peer *peer, struct txn_server *st, const struct sip_msg *req, void *arg);
	/* ACK for a 2xx we sent (it has no transaction) or any ACK that matched none */
	void (*on_ack)(struct lan *l, const struct lan_peer *peer, const struct sip_msg *req, void *arg);
	void *arg;
};

typedef void (*lan_binding_cb)(struct lan *l, enum registrar_event ev, const struct reg_binding *b,
			       enum reg_removal reason, void *arg);

struct lan_cfg {
	struct txn_layer *tl;		/* may be NULL here and given with lan_attach() */
	struct sip_endpoint *ep;	/* LAN endpoint (bound to the LAN interface by the creator) */
	const char *user_agent;		/* default "imsd" */
	const char *contact_user;	/* user part of our LAN Contact and of OPTIONS pings; default "imsd" */
	struct registrar_cfg reg;		/* registrar limits; its on_event/ping/arg fields are ignored (set by lan) */
	lan_binding_cb on_binding;	/* binding added/refreshed/removed/(un)reachable, for the rest of the daemon */
	struct lan_hooks hooks;
	void *arg;			/* passed to on_binding */
};

/* cfg is copied (strings too). NULL on OOM. */
struct lan *lan_new(const struct lan_cfg *cfg);
/* Set the transaction layer and LAN endpoint (when not given in the cfg). The endpoint is referenced. */
void lan_attach(struct lan *l, struct txn_layer *tl, struct sip_endpoint *ep);
/* Stop everything: detaches running transactions and forks silently (no callbacks), drops bindings, frees. */
void lan_free(struct lan *l);
/* Replace the hook table (the later call/SMS modules install theirs here). */
void lan_set_hooks(struct lan *l, const struct lan_hooks *h);
struct registrar *lan_registrar(struct lan *l);
struct sip_endpoint *lan_endpoint(struct lan *l);

/*
 * txn_request_cb compatible router: pass the lan as txn_cfg.arg (or call it from a thunk). Requests
 * from endpoints other than the LAN endpoint are not special-cased; the integrator selects by endpoint.
 */
void lan_on_request(struct txn_layer *tl, struct txn_server *st, struct sip_endpoint *ep,
		    const struct addr *src, const struct sip_msg *req, void *arg);

/* identify the sending device (also usable by hooks for later requests of the same dialog) */
void lan_identify(struct lan *l, const struct addr *src, const struct sip_msg *req, struct lan_peer *peer);

/* ---------------- outbound out-of-dialog requests ---------------- */

/*
 * One request toward the LAN. Request-URI = the binding's registered Contact URI, To = the binding's AOR,
 * Via = the endpoint's advertised address, Max-Forwards 70, Contact = our LAN contact URI, User-Agent.
 * From = "display" <from_uri or sip:from_user@advertised-host>;tag=...
 */
struct lan_req {
	const char *method;
	const char *from_user;		/* the line's number / caller ID user part (required unless from_uri is given) */
	const char *from_display;	/* optional display name */
	const char *from_uri;		/* optional complete URI, overrides user@host */
	const char *call_id;		/* NULL: generated (forks share one Call-ID) */
	const char *from_tag;		/* NULL: generated */
	uint32_t cseq;			/* 0: 1 */
	const char *extra;		/* optional header lines, each ending in CRLF */
	const char *content_type;	/* only written with a body */
	const uint8_t *body;
	size_t body_len;
};

/* identifiers of the request that went out, for building dialogs (dlgset_init) / matching later */
struct lan_sent {
	char call_id[128];
	char from_tag[64];
	char from_uri[256];
	char to_uri[160];		/* the binding's AOR */
	uint32_t cseq;
	char branch[SIP_BRANCH_LEN];
};

/* resp/src only for TXN_CLI_RESPONSE; TXN_CLI_TERMINATED is always last and invalidates x */
typedef void (*lan_xact_cb)(struct lan_xact *x, enum txn_cli_event ev, const struct sip_msg *resp,
			    const struct addr *src, void *arg);

/*
 * Send req to binding id. Bookkeeping (answered / reachable / learned Allow / counters) is done for you.
 * NULL (errno ENOENT unknown binding, EINVAL bad request, ENOMEM / EAGAIN) on failure; `sent` may be NULL.
 */
struct lan_xact *lan_send_request(struct lan *l, reg_id_t id, const struct lan_req *req, lan_xact_cb cb, void *arg,
				  struct lan_sent *sent);
/* CANCEL an INVITE xact (RFC 3261 9.1: sent once a provisional was seen, otherwise pending until it arrives, dropped if a final comes first). extra: optional header lines for the CANCEL (e.g. Reason). 0 / -1 */
int lan_xact_cancel(struct lan_xact *x, const char *extra);
/* the callback will not be invoked any more; the transaction runs to its end */
void lan_xact_detach(struct lan_xact *x);
reg_id_t lan_xact_binding(const struct lan_xact *x);

/* ---------------- fork ---------------- */

/*
 * Fan a request out to bindings. Selection: every binding except opts->exclude, unreachable ones skipped
 * unless that would leave none (or opts->include_unreachable), bindings that declared an Allow without
 * the method skipped, bindings sharing a Contact (several AORs of one device) used once. The set is fixed at
 * start; devices registering later do not join. All branches share Call-ID, From (tag) and CSeq.
 *
 * INVITE ("race" semantics): first 2xx wins -> LAN_FORK_WINNER, all other branches are CANCELled with
 * "Reason: SIP;cause=200;text=\"Call completed elsewhere\"". A 2xx that arrives after that (or after
 * lan_fork_cancel) is reported as LAN_FORK_EXTRA_2XX: the caller must ACK it and BYE it. Any other
 * method ("all" semantics): every branch is answered independently, COMPLETE reports whether at least one
 * answered 2xx.
 *
 * Aggregate final status when no 2xx (RFC 3261 16.7, simplified; a branch is only final, never ends the fork
 * early -- not even a 486 or 6xx, other devices keep ringing): among all branches pick the lowest rank,
 * ties by lowest status:
 *   0 any 6xx   1 486 Busy Here   2 other 4xx (not 408/487)   3 5xx   4 3xx (reported as 480), 408 reply, 487
 *   5 synthetic: our timeout (408), transport error (503), binding removed (480)
 * No branch at all -> NULL from lan_fork_request with errno ENOENT (caller answers 480).
 */
struct lan_fork_opts {
	const reg_id_t *exclude;
	unsigned nexclude;
	const reg_id_t *include;	/* only these bindings (when include_set); an empty set reaches nobody (ENOENT) */
	unsigned ninclude;
	bool include_set;
	bool include_unreachable;
};

enum lan_branch_cause {
	LAN_BR_NONE,		/* no final response (cancelled by us before one arrived) */
	LAN_BR_RESPONSE,	/* real final response in status */
	LAN_BR_TIMEOUT,		/* Timer B/F: status 408 is synthetic */
	LAN_BR_TRANSPORT,	/* send failed: status 503 is synthetic */
	LAN_BR_REMOVED,		/* binding expired / was removed: branch cancelled, status 480 synthetic */
};

struct lan_branch_result {
	reg_id_t id;
	int status;		/* 0 if none */
	enum lan_branch_cause cause;
};

enum lan_fork_ev_type {
	LAN_FORK_PROVISIONAL,	/* id, status, resp: 1xx of one branch (INVITE: 100 included; call module decides what to relay) */
	LAN_FORK_BRANCH_FINAL,	/* id, status, cause: a branch failed or (MESSAGE etc.) completed; never for the INVITE winner */
	LAN_FORK_WINNER,	/* INVITE only, once: id, status, resp (the 2xx), dlg (confirmed UAC dialog, see below) */
	LAN_FORK_EXTRA_2XX,	/* INVITE only: second 2xx (other branch, cancelled branch, or other To tag): id, resp, dlg. ACK it, then BYE it */
	LAN_FORK_2XX_RETRANS,	/* retransmitted 2xx of a known dialog (is_winner tells which): ACK again */
	LAN_FORK_COMPLETE,	/* once: status (200 or aggregate failure), winner (INVITE), nok, results[]. Not sent after lan_fork_cancel */
	LAN_FORK_DONE,		/* last event; the fork handle is invalid afterwards (all transactions ended) */
};

struct lan_fork_event {
	enum lan_fork_ev_type type;
	reg_id_t id;
	int status;
	enum lan_branch_cause cause;
	const struct sip_msg *resp;	/* valid during the call only */
	const struct addr *src;
	/*
	 * WINNER / EXTRA_2XX: dialog built from the 2xx (is_uac, confirmed, ids, remote target, route set from
	 * Record-Route, local_cseq = the INVITE's CSeq) ready for dlg_build_request() ("ACK" with
	 * cseq = invite cseq, "BYE"). Valid during the call; to keep it set *take_dlg = true and copy *dlg (the
	 * copy owns an endpoint reference: dlg_release() it eventually).
	 */
	struct sip_dialog *dlg;
	bool take_dlg;
	bool is_winner;			/* 2XX_RETRANS */
	reg_id_t winner;		/* COMPLETE (INVITE success) */
	int nok;			/* COMPLETE: number of 2xx-answering branches (non-INVITE) / 1 on INVITE success */
	const struct lan_branch_result *results;	/* COMPLETE: one per branch, ascending binding id */
	int nresults;
	uint32_t invite_cseq;
};

typedef void (*lan_fork_cb)(struct lan_fork *f, struct lan_fork_event *ev, void *arg);

/* NULL + errno: ENOENT (no eligible binding), EINVAL, ENOMEM, EAGAIN (no transaction could be started) */
struct lan_fork *lan_fork_request(struct lan *l, const struct lan_req *req, const struct lan_fork_opts *opts,
				  lan_fork_cb cb, void *arg, struct lan_sent *sent);
/*
 * Cancel the whole fork (caller ring timeout, upstream CANCEL): CANCELs every branch still ringing without a
 * Reason. Later 2xx are EXTRA_2XX. No COMPLETE follows; DONE does. Idempotent.
 */
void lan_fork_cancel(struct lan_fork *f);
/* no more events for this fork (the caller's object went away); it finishes silently */
void lan_fork_detach(struct lan_fork *f);
int lan_fork_branches(const struct lan_fork *f);
/* Call-ID / From-tag shared by all branches (to match in-dialog requests later) */
const char *lan_fork_call_id(const struct lan_fork *f);

/* ---------------- status ---------------- */

struct lan_binding_status {
	reg_id_t id;
	const char *aor, *contact, *instance, *user_agent;
	char source[64], target[64];	/* "ip:port" */
	bool target_from_src;
	unsigned expires_in;		/* seconds left */
	unsigned age;			/* seconds since first registration */
	bool reachable, answered, allow_known;
	bool restored;			/* re-created from the saved table, no REGISTER since */
	uint32_t allow;
	uint32_t features;		/* REG_F_* */
	int q;
	unsigned long n_register, n_rx, n_tx, n_answered, n_timeouts;
};
struct lan_stats {
	unsigned bindings;
	unsigned long rx_requests, rx_unregistered, rx_register, rx_options, rx_invite, rx_message, rx_subscribe,
		      rx_other, rx_ack;
	unsigned long forks_started, forks_active;
	struct reg_stats reg;
};
typedef void (*lan_status_cb)(const struct lan_binding_status *s, void *arg);
/* Fill *st (may be NULL) and call cb for every live binding (may be NULL). The strings in the status are valid during the call. */
void lan_status(struct lan *l, struct lan_stats *st, lan_status_cb cb, void *arg);
#endif
