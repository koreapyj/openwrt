/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CORE_H
#define IMSD_CORE_H
#include <stdbool.h>
#include <stddef.h>
#include "config.h"
#include "gm/reg.h"
#include "media/bridge.h"
#include "sip/txn.h"
#include "ua/lan.h"
#include "util/addr.h"

/*
 * The hub that the later modules (call control, SMS relay) plug into.
 *
 * The daemon has ONE transaction layer. core owns it and routes every incoming request by the endpoint it
 * arrived on:
 *     LAN endpoint        -> lan_on_request()           (registrar, OPTIONS, hooks below)
 *     any Gm endpoint     -> reg_on_request()           (protected endpoint: handler table below first,
 *                                                        then today's built-in answers; unprotected: 403)
 * It also owns the LAN side: the LAN endpoint (UDP, SO_BINDTODEVICE lan_ifname, address lan_addr or the first
 * IPv4 address of the interface, retried on a timer while the interface has none), the struct lan and the
 * struct reg (Gm registration, created here on top of the shared transaction layer).
 *
 * A module is a static `struct core_module`. It is registered once (core_add_module, from main()) and is
 * started / stopped with the services (imsd.main.enabled=1). Everything it needs is reachable from the
 * struct core given to its callbacks:
 *     core_cfg()   live configuration (the pointer stays valid; the contents change on reload)
 *     core_txn()   the shared transaction layer
 *     core_reg()   Gm registration: reg_context() / reg_send() / reg_is_registered() ... (gm/reg.h)
 *     core_lan()   the LAN object (registrar, lan_send_request, lan_fork_request ...); NULL while the LAN side
 *                  is down (no address yet): use the lan_state callback or test for NULL at use time
 *     core_rtp_open_lan() / core_rtp_open_carrier()   RTP sockets from the configured port ranges
 * and it supplies, declaratively, the hooks it wants installed:
 *     lan_hooks    struct lan_hooks (ua/lan.h): on_invite / on_in_dialog / on_message / on_ack. One module per
 *                  slot (core_add_module fails with -EBUSY when a slot is already taken).
 *     gm_handlers  struct reg_handlers (gm/reg.h): the extension table consulted first for requests on the
 *                  protected Gm endpoint. Several modules may fill the same slot: they are asked in
 *                  registration order until one returns true (take the request).
 *     bridge_event receives every media engine event (bridge_events_dispatch is called from the main loop).
 *                  One module only (-EBUSY).
 * All callbacks run on the main loop thread and must not block. `arg` is handed back to every callback.
 */

struct core;

struct core_module {
	const char *name;
	/* Services are up: transaction layer and Gm registration exist (the LAN object may not yet). The module
	 * may allocate its state here and use the accessors. Return 0, or -errno: the module is then left out
	 * (no stop() call, its hooks are not installed) and the failure is logged. NULL ok. */
	int (*start)(struct core *c, void *arg);
	/* Services are going down: release everything (calls, bridges, transactions you started) BEFORE this
	 * returns; lan, reg and the transaction layer are freed afterwards. NULL ok. */
	void (*stop)(struct core *c, void *arg);
	/* A LAN object came up (l != NULL, all hooks already installed) or is about to go away (l == NULL and
	 * the old object still valid through core_lan() until you return; drop forks / xacts that use it). A LAN
	 * restart (address change, reload of a LAN option) is a down + up. NULL ok. */
	void (*lan_state)(struct core *c, struct lan *l, void *arg);
	const struct lan_hooks *lan_hooks;		/* NULL: none. The table is not copied: keep it alive. */
	const struct reg_handlers *gm_handlers;		/* NULL: none. Not copied. */
	/* a LAN registrar event (binding added / refreshed / removed / reachability): every module sees them, from the main loop.
	 * b is valid during the call only. NULL ok. */
	void (*on_binding)(struct core *c, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why, void *arg);
	/* a response that matched no client transaction (late / forked 2xx): every module sees them. NULL ok. */
	void (*on_stray)(struct core *c, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *resp,
			 void *arg);
	/* media engine events (bridge.h) */
	void (*bridge_event)(void *arg, const struct br_event *ev);
	void *arg;
};

/* System dependencies, injectable for the host tests (NULL entries: the real ones). */
struct core_ops {
	struct sip_endpoint *(*open_ep)(void *ctx, const struct sip_ep_cfg *cfg);	/* default sip_ep_open */
	/* IPv4 address of ifname (prefer: keep this one if still present); 0 / -1. default ifaddr_first_v4 */
	int (*lan_addr)(void *ctx, const char *ifname, const struct addr *prefer, struct addr *out);
	/* a LAN binding was added / refreshed / removed / flipped reachability */
	void (*on_binding)(void *ctx, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why);
	/* optional: asked before a LAN SIP MESSAGE goes to the module that owns the slot; true = handled (the gate answered st) */
	bool (*lan_message_gate)(void *ctx, struct txn_server *st, const struct sip_msg *req);
	void *ctx;
};

/*
 * What a real handset takes from the SIM / modem and the modules need: supplied by main() from imsmodem (the
 * host tests use fakes). Every getter returns "" while unknown. Pointers are only valid until the next call.
 *     smsc          USIM EF_SMSP service centre ("+821080010585")
 *     sms_psi       EF_PSISMSC SIP URI of the SMS gateway when the card has one
 *     imsi          IMSI of the SIM (operator table); never logged or shown
 *     domain        ISIM home network domain (default phone-context)
 *     pani_refresh  start an asynchronous refresh of the serving cell data (P-Access-Network-Info); never blocks
 */
/* the IMS bearer for modules that send their own traffic over it (the MMS client): everything is "" / 0 while there is none */
struct core_ims_link {
	bool up;		/* bearer connected, netdev configured, registration link ready */
	char netdev[16];
	struct addr local;	/* the bearer's address, port 0 */
	struct addr dns[4];	/* DNS servers of the bearer, port 53 */
	int n_dns;
	unsigned seq;		/* changes whenever the link does */
};

struct core_params {
	const char *(*smsc)(void *ctx);
	const char *(*sms_psi)(void *ctx);
	const char *(*imsi)(void *ctx);		/* IMSI of the SIM: selects the built-in operator table (carrier.h) */
	const char *(*domain)(void *ctx);
	void (*pani_refresh)(void *ctx);
	const char *(*ims_netdev)(void *ctx);	/* interface name of the IMS bearer: the carrier RTP sockets bind to it */
	void (*ims_link)(void *ctx, struct core_ims_link *out);	/* the IMS bearer: address, netdev, DNS servers */
	void *ctx;
};
void core_set_params(struct core *c, const struct core_params *p);	/* copied; NULL clears */
const char *core_param_smsc(const struct core *c);
const char *core_param_sms_psi(const struct core *c);
const char *core_param_imsi(const struct core *c);
const char *core_param_domain(const struct core *c);
/* the line's own number (user part of the public identity we registered, "+82..."), "" while not registered */
void core_own_number(const struct core *c, char *out, size_t n);
/* the number of a public identity: "sip:+8210...@ims.example;user=phone" / "tel:+8210..." -> "+8210..." ("" when there is none) */
void core_uri_number(const char *uri, char *out, size_t n);
const char *core_param_ims_netdev(const struct core *c);
void core_param_ims_link(const struct core *c, struct core_ims_link *out);	/* zeroed (up false) when unknown */
void core_pani_refresh(struct core *c);

/* cfg is not copied: the daemon keeps it alive and updates it on reload (then calls core_reload). */
struct core *core_new(const struct imsd_config *cfg, const struct core_ops *ops);
/* free; core_stop() first when running */
void core_free(struct core *c);
/* Register a module (up to 8; before core_start; the struct must outlive the core). 0, -EBUSY (slot taken), -ENOSPC, -EINVAL */
int core_add_module(struct core *c, const struct core_module *m);

/* Create the transaction layer and the Gm registration (ro: struct reg_ops without tl; core sets it), start the
 * modules, then open the LAN side (it may stay pending, see core_lan_info). 0 / -errno */
int core_start(struct core *c, const struct reg_ops *ro);
/* Stop the modules, free lan, reg and the transaction layer. Idempotent. */
void core_stop(struct core *c);
bool core_running(const struct core *c);
/* The configuration object changed: restarts the LAN side when a LAN option changed (config_lan_changed
 * against what is running); the caller applies the reg / modem parts itself (reg_set_cfg). */
void core_reload(struct core *c);

const struct imsd_config *core_cfg(const struct core *c);
struct txn_layer *core_txn(struct core *c);
struct reg *core_reg(struct core *c);
struct lan *core_lan(struct core *c);	/* NULL when the LAN side is not up */

struct core_lan_info {
	const char *state;	/* "up", "waiting for address", "error", "stopped" */
	char reason[256];	/* why not up */
	char ifname[32];
	struct addr addr;	/* listening address and port, valid when up */
	bool up;
};
void core_lan_info(const struct core *c, struct core_lan_info *out);

/*
 * RTP sockets (bound, non-blocking, dual-stack AF_INET6, even port; see util/rtpsock.h). The LAN leg is bound to
 * the LAN address and lan_ifname with cfg rtp_port_min..max; the carrier leg to `local` (the IMS bearer address)
 * and `netdev` with carrier_rtp_port_min..max. fd >= 0 with *bound set, or -errno (-ENOTCONN: LAN down,
 * -EADDRINUSE: range exhausted).
 */
int core_rtp_open_lan(struct core *c, struct addr *bound);
int core_rtp_open_carrier(struct core *c, const struct addr *local, const char *netdev, struct addr *bound);

/* main loop glue: pass to bridge_events_dispatch(core_bridge_event, core) when bridge_event_fd() is readable */
void core_bridge_event(void *core, const struct br_event *ev);
#endif
