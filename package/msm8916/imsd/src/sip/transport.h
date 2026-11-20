/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SIP_TRANSPORT_H
#define IMSD_SIP_TRANSPORT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../util/addr.h"

/*
 * SIP endpoints.
 *
 * An endpoint is "where we send from, receive on, and what we tell the peer":
 *   - an rx socket (we receive on it) and a tx socket (we send from it). For
 *     ordinary endpoints they are the same socket; for a protected Gm
 *     endpoint (TS 33.203) tx = port-c and rx = port-s (split_tx).
 *   - an advertised (addr, port) used for Via sent-by and Contact (port-s for
 *     Gm), independent of the bind addresses.
 *   - an optional fixed response destination: every response of a server
 *     transaction goes there instead of the address derived from Via/source
 *     (Gm: P-CSCF port-s).
 *   - a reliable flag; the transaction layer disables retransmission timers
 *     on reliable endpoints.
 * Several endpoints coexist (unprotected, one protected per registration,
 * LAN). Endpoints are reference counted: transactions and dialogs take a
 * reference (sip_ep_ref) so a retired endpoint keeps working until drained.
 *
 * Sockets are AF_INET6 dual-stack (IPv4 as v4-mapped), non-blocking, bound to
 * an explicit address and optionally a netdev (SO_BINDTODEVICE). Sends use
 * MSG_DONTWAIT; EAGAIN/ENOBUFS drops the datagram and logs (never waits).
 *
 * TCP / stream transport: NOT IMPLEMENTED YET (SIP_TP_TCP -> sip_ep_open()
 * fails with ENOTSUP). The API is shaped for it: a stream endpoint connects
 * from tx_bind (port-c) to the peer's port-s and accepts on rx_bind (port-s),
 * frames the byte stream with sip_frame_len() (Content-Length) and hands every
 * complete message to sip_ep_deliver(); sip_ep_send() queues bytes (bounded
 * queue, close + error on overflow) for the connection to dst. Callers
 * (txn, dialog) need no change: they only use sip_ep_send / rx callback /
 * ep->reliable.
 */

enum sip_tp_kind { SIP_TP_UDP, SIP_TP_TCP };

struct sip_endpoint;

/* a complete SIP message arrived; data valid only during the call */
typedef void (*sip_rx_cb)(struct sip_endpoint *ep, const struct addr *src,
			  const uint8_t *data, size_t len, void *arg);

/* transport backend operations (UDP below; tests plug in fakes) */
struct sip_ep_ops {
	/* queue/send one message to dst. 0, or -errno (-EAGAIN: dropped, retry later) */
	int (*send)(struct sip_endpoint *ep, const struct addr *dst, const void *data, size_t len);
	/* release backend resources (sockets, watchers); the endpoint itself is freed by the caller */
	void (*close)(struct sip_endpoint *ep);
};

struct sip_ep_cfg {
	const char *name;		/* for logs, e.g. "gm#3", "lan" (copied) */
	enum sip_tp_kind kind;
	struct addr rx_bind;		/* local address/port of the receive socket (port 0 = ephemeral) */
	bool split_tx;			/* separate tx socket bound to tx_bind */
	struct addr tx_bind;
	const char *netdev;		/* SO_BINDTODEVICE or NULL */
	bool has_adv;			/* advertised address; default: the rx socket's local address */
	struct addr adv;
	bool has_resp_override;		/* all responses go to resp_override */
	struct addr resp_override;
	bool reliable;			/* default for UDP false, TCP true; custom backends set it explicitly */
	sip_rx_cb rx_cb;
	void *rx_arg;
};

struct sip_endpoint {
	char name[24];
	enum sip_tp_kind kind;
	bool reliable;
	bool retired;
	struct addr local_rx, local_tx;	/* actual bound addresses */
	struct addr advertised;
	bool has_resp_override;
	struct addr resp_override;
	sip_rx_cb rx_cb;
	void *rx_arg;
	/* counters */
	unsigned long tx_ok, tx_dropped, tx_err, rx_msgs;
	/* private */
	int refs;
	const struct sip_ep_ops *ops;
	void *priv;
};

/* Open a UDP endpoint (creates and binds the sockets, starts watching rx). NULL + errno on failure; refs == 1 (the creator's). */
struct sip_endpoint *sip_ep_open(const struct sip_ep_cfg *cfg);
/* Endpoint on a custom backend (tests, future stream transports). No sockets are created. refs == 1. */
struct sip_endpoint *sip_ep_create_custom(const struct sip_ep_cfg *cfg, const struct sip_ep_ops *ops, void *priv);
struct sip_endpoint *sip_ep_ref(struct sip_endpoint *ep);
/* drop a reference; at zero the backend is closed and the endpoint freed (NULL ok) */
void sip_ep_unref(struct sip_endpoint *ep);
/* Mark retired (no new transactions/dialogs should start on it) and drop the creator's reference. It keeps receiving and sending until the last reference goes. */
void sip_ep_retire(struct sip_endpoint *ep);
void sip_ep_set_rx(struct sip_endpoint *ep, sip_rx_cb cb, void *arg);
/* Send one message through the tx socket to dst. 0, or -errno; -EAGAIN means dropped (queue full), logged. */
int sip_ep_send(struct sip_endpoint *ep, const struct addr *dst, const void *data, size_t len);
/* Hand a received message to the endpoint's rx callback (used by backends; tests call it directly). */
void sip_ep_deliver(struct sip_endpoint *ep, const struct addr *src, const uint8_t *data, size_t len);
#endif
