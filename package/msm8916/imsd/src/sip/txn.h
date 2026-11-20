/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SIP_TXN_H
#define IMSD_SIP_TXN_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "msg.h"
#include "transport.h"

/*
 * SIP transaction layer (RFC 3261 section 17, with the RFC 6026 "Accepted"
 * state after a 2xx so INVITE retransmissions / forked 2xx are absorbed or
 * passed up instead of being lost).
 *
 * Timers (unreliable endpoints): T1 500 ms, T2 4 s, T4 5 s: A,B,D,E,F,K for
 * clients and G,H,I,J (plus L/M = 64*T1 for the Accepted states) for servers.
 * Reliable endpoints (ep->reliable) skip A/E/G and use 0 for D/I/J/K.
 *
 * Matching: client responses match on top-Via branch + CSeq method regardless
 * of which endpoint/socket they arrived on. Server requests match on branch +
 * sent-by + method (ACK matches the INVITE; branches without the magic cookie
 * fall back to Call-ID|CSeq|From-tag).
 *
 * Everything is single threaded and non-blocking. Handles stay valid until the
 * TERMINATED event (always the last callback of a transaction). Callbacks must
 * not free the layer. Transactions hold an endpoint reference.
 */

struct txn_layer;
struct txn_client;
struct txn_server;

/* ---------------- layer ---------------- */

/*
 * New request from the network. st is the server transaction (already in
 * Trying/Proceeding; reply with txn_server_reply), or NULL for requests that
 * have no transaction: ACK for a 2xx (and any ACK that matched nothing).
 * req is valid only during the call (txn_server_request(st) stays valid).
 * CANCEL and retransmissions never reach this callback: the layer answers
 * CANCEL itself (200, or 481 if no INVITE matches) and raises
 * TXN_SRV_CANCELLED on the INVITE transaction.
 */
typedef void (*txn_request_cb)(struct txn_layer *tl, struct txn_server *st, struct sip_endpoint *ep,
			       const struct addr *src, const struct sip_msg *req, void *arg);
/* A response that matched no client transaction (late 2xx retransmission, forked 2xx): the TU may need to ACK it. */
typedef void (*txn_stray_cb)(struct txn_layer *tl, struct sip_endpoint *ep, const struct addr *src,
			     const struct sip_msg *resp, void *arg);

struct txn_cfg {
	unsigned t1_ms;		/* default 500 */
	unsigned t2_ms;		/* default 4000 */
	unsigned t4_ms;		/* default 5000 */
	unsigned max_txns;	/* client + server, default 256; over the limit new requests get a stateless 503, client sends fail */
	bool auto_100;		/* send 100 Trying immediately for server INVITE transactions */
	txn_request_cb on_request;
	txn_stray_cb on_stray_response;
	void *arg;
};

/* Create a layer (cfg may be NULL: defaults). NULL on OOM. */
struct txn_layer *txn_layer_new(const struct txn_cfg *cfg);
/* Destroy all transactions silently (no callbacks) and free the layer. Endpoints are left alone (detached). */
void txn_layer_free(struct txn_layer *tl);
/* Route everything received on ep into this layer (sets the endpoint's rx callback). */
void txn_layer_attach(struct txn_layer *tl, struct sip_endpoint *ep);
unsigned txn_layer_count(const struct txn_layer *tl);
/* Send a response without a transaction (e.g. to an ACK-less reject). Destination as for server transactions. 0 / -errno */
int txn_respond_stateless(struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, const struct sip_resp_parts *p);
/* Destination a response to req (received from src on ep) must go to: ep->resp_override if set, else RFC 3261 18.2.2 / RFC 3581 (received/rport, sent-by, fallback src). */
void txn_response_dest(const struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *req, struct addr *dst);

/* ---------------- client transactions ---------------- */

enum txn_cli_event {
	TXN_CLI_RESPONSE,	/* provisional or final response (resp valid); for INVITE also repeated/forked 2xx */
	TXN_CLI_TIMEOUT,	/* Timer B / F fired; terminated next */
	TXN_CLI_TRANSPORT_ERROR,/* hard send error; terminated next */
	TXN_CLI_TERMINATED,	/* last event, handle invalid afterwards */
};

/* resp / rx_ep / src are only set for TXN_CLI_RESPONSE; resp is valid only during the call */
typedef void (*txn_client_cb)(struct txn_client *c, enum txn_cli_event ev, const struct sip_msg *resp,
			      struct sip_endpoint *rx_ep, const struct addr *src, void *arg);

struct txn_client_req {
	struct sip_endpoint *ep;	/* send through this endpoint (referenced) */
	struct addr dst;
	const uint8_t *data;		/* complete request; must carry our branch in the top Via */
	size_t len;
	txn_client_cb cb;
	void *arg;
};

/* Start a client transaction for an already built request: sends it now and runs the timers. NULL on bad request / limit / OOM. A hard send failure is reported asynchronously as TXN_CLI_TRANSPORT_ERROR. */
struct txn_client *txn_client_start(struct txn_layer *tl, const struct txn_client_req *r);
/*
 * CANCEL an INVITE client transaction (RFC 3261 9.1). Sent immediately if a
 * provisional response was seen; before that it is marked pending and sent on
 * the first 1xx; dropped if a final response arrives first. The CANCEL is its
 * own client transaction reporting to cb/arg. 0 if sent/pending, -1 if not
 * cancellable (not an INVITE, final already received, already cancelled).
 */
int txn_client_cancel(struct txn_client *inv, txn_client_cb cb, void *arg);
/* Same, with extra_headers (zero or more complete header lines, each ending in CRLF, e.g.
 * "Reason: SIP;cause=200;text=\"Call completed elsewhere\"\r\n") added to the CANCEL. NULL = none.
 * RFC 3261 9.1: once the CANCEL is on the wire the INVITE transaction gets 64*T1 to see a final response;
 * if none arrives it reports TXN_CLI_TIMEOUT and terminates (so a phone that ignores the CANCEL cannot
 * hold a transaction slot forever). */
int txn_client_cancel_ex(struct txn_client *inv, const char *extra_headers, txn_client_cb cb, void *arg);
/* the callback will not be invoked any more (use when the TU object goes away); the transaction keeps running */
void txn_client_detach(struct txn_client *c);
const char *txn_client_branch(const struct txn_client *c);
struct sip_endpoint *txn_client_endpoint(const struct txn_client *c);
const struct addr *txn_client_dest(const struct txn_client *c);
bool txn_client_cancel_pending(const struct txn_client *c);
/* number of times the request was retransmitted so far */
unsigned txn_client_retransmits(const struct txn_client *c);

/* ---------------- server transactions ---------------- */

enum txn_srv_event {
	TXN_SRV_CANCELLED,	/* peer sent CANCEL for this INVITE (already answered with 200): send 487 */
	TXN_SRV_TIMEOUT,	/* Timer H: no ACK for the final non-2xx; terminated next */
	TXN_SRV_TERMINATED,	/* last event, handle invalid afterwards */
};
typedef void (*txn_server_cb)(struct txn_server *st, enum txn_srv_event ev, void *arg);

void txn_server_set_cb(struct txn_server *st, txn_server_cb cb, void *arg);
/* the request, owned by the transaction */
const struct sip_msg *txn_server_request(const struct txn_server *st);
struct sip_endpoint *txn_server_endpoint(const struct txn_server *st);
const struct addr *txn_server_src(const struct txn_server *st);
/* where responses go (computed per txn_response_dest) */
const struct addr *txn_server_dest(const struct txn_server *st);
/* To tag used for responses of this transaction (generated once, on first use) */
const char *txn_server_to_tag(struct txn_server *st);
/* Build and send a response from the stored request (p->src is filled in; p->to_tag defaults to txn_server_to_tag for status > 100). For INVITE: 1xx stays Proceeding, 2xx -> Accepted (use the 2xx helper for retransmission until ACK), >=300 -> Completed with Timer G. 0, -EINVAL (bad state / build error) or -errno from the send (retransmit timers still apply). */
int txn_server_reply(struct txn_server *st, const struct sip_resp_parts *p);
/* Same with caller-built bytes; status must match the status line. */
int txn_server_reply_raw(struct txn_server *st, int status, const uint8_t *data, size_t len);
/* last response sent (status 0 if none) and its bytes */
int txn_server_last_status(const struct txn_server *st);
bool txn_server_is_invite(const struct txn_server *st);
/* Full value of the Reason header of the CANCEL that cancelled this INVITE transaction (e.g.
 * SIP;cause=200;text="Call completed elsewhere"), truncated to 159 bytes; "" if there was none or st is NULL.
 * Valid inside the TXN_SRV_CANCELLED callback and for as long as st lives. The first CANCEL carrying a
 * Reason wins; retransmissions never replace it. */
const char *txn_server_cancel_reason(const struct txn_server *st);

/* ---------------- UAS 2xx retransmission helper ---------------- */

struct sip_rtx;
/* the 2xx was never ACKed within 64*T1 (r is freed right after the callback returns) */
typedef void (*sip_rtx_cb)(struct sip_rtx *r, void *arg);

/*
 * Retransmit a 2xx to INVITE until the TU sees the ACK (Timer G-like: T1,
 * doubling up to T2; gives up at 64*T1). The first transmission is done by
 * the caller / txn_server_reply; the first retransmission comes after T1.
 * data is copied. On reliable endpoints nothing is retransmitted but the
 * give-up timer still runs. NULL on OOM. t1/t2 of 0 use 500/4000 ms.
 */
struct sip_rtx *sip_rtx_start(struct sip_endpoint *ep, const struct addr *dst, const uint8_t *data, size_t len,
			      unsigned t1_ms, unsigned t2_ms, sip_rtx_cb on_giveup, void *arg);
/* stop and free (ACK received; NULL ok). Must not be called from its own callback. */
void sip_rtx_stop(struct sip_rtx *r);
unsigned sip_rtx_count(const struct sip_rtx *r);
/* Convenience for a server transaction that just sent a 2xx: retransmit st's last response to st's destination. */
struct sip_rtx *txn_server_start_2xx_rtx(struct txn_server *st, unsigned t1_ms, unsigned t2_ms, sip_rtx_cb on_giveup, void *arg);
#endif
