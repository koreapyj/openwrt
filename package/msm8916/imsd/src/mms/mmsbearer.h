/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_MMSBEARER_H
#define IMSD_MMS_MMSBEARER_H
#include <stdbool.h>
#include <stddef.h>
#include "mmsguard.h"
#include "../modem/netcfg.h"
#include "../modem/uqmid.h"
#include "../util/addr.h"

/*
 * The on-demand MMS data connection: what Android does for MMS on an operator whose MMS APN is not the IMS APN. When there is MMS work
 * (a notification to retrieve, a confirmation to send, an M-Send.req from the LAN proxy, a fetch that the store cannot answer) a data
 * bearer is brought up through uqmid with the carrier's MMS APN, used for the MMS traffic only, kept while work is pending plus a
 * short linger (mms_bearer_linger, default 20 s), then disconnected and deleted. At most one such bearer exists; none is created while
 * there is no work.
 *
 * Bring-up, each step asynchronous (never blocks the main loop):
 *   1. traffic guard installed (mmsguard.h: nothing but MMS traffic may leave through this bearer). Fails: no bearer at all.
 *   2. scan of the modem's bearers: a bearer that a previous imsd run left (marker, below) is disconnected and deleted; a CONNECTED bearer
 *      of the same APN that imsd did not create (netifd's wan) is not touched and MMS is reported unavailable.
 *   3. create_bearer (APN, IP type of the carrier entry, no profile), connect, get (address, prefix, gateway, DNS, netdev) exactly like
 *      the IMS bearer in modem/imsmodem.c. A netdev that another connected bearer already uses is not touched either.
 *   4. IPv6 is switched off on the netdev when the bearer is IPv4-only, the netdev and the DNS servers are put into the guard (BEFORE it has
 *      an address), then the netdev is configured through rtnetlink as the IMS netdev is (address, a dedicated routing table with the
 *      prefix and a default route, a source rule; NOTHING in the main table; link up). Sockets are bound to the netdev and the address.
 * Teardown (linger over, shutdown, a new provider, the modem left, a failed step): netdev configuration removed (and IPv6 restored), bearer
 * disconnected and deleted, then the guard removed. Work that arrives while this runs waits and starts a new bring-up afterwards.
 * A failure is retried with backoff (5 s doubling up to 60 s); while a circuit switched voice call is up the retry stays at 5 s (on WCDMA
 * voice and packet data run together; if the modem refuses during the call it works again after it).
 * The bearer path is written to a marker (ops.marker_*, a tmpfs file) while it exists so that a crashed run's bearer is recognised and
 * cleaned up by the next one (the IMS bearer is "adopted" the same way); a bearer without the marker is never touched.
 */
struct mmsb_profile {
	char apn[64];
	char ip_type[16];
};

struct mmsb_cfg {
	unsigned linger_ms;		/* default 20000 */
	unsigned route_table;		/* default 1007 (rule priority = table) */
	unsigned call_timeout_ms;	/* uqmid get / create / disconnect / delete, default 15000 */
	unsigned connect_timeout_ms;	/* default 45000 */
	unsigned retry_min_ms, retry_max_ms;	/* default 5000 .. 60000 */
	unsigned blocked_retry_ms;	/* look again after "another bearer is connected", default 30000 */
	unsigned check_ms;		/* liveness check of the bearer while it is up, default 15000 */
};
void mmsb_cfg_defaults(struct mmsb_cfg *c);

struct mmsb_ops {
	struct uq_ops uq;
	struct netcfg_ops net;
	/* IPv6 on the netdev (disable_ipv6): optional */
	void (*ipv6_disable)(void *ctx, const char *ifname, bool disable);
	struct guard_exec_ops exec;
	/* object path of the modem to use, "" = none yet */
	const char *(*modem)(void *ctx);
	/* the carrier's MMS APN for the SIM in the modem; false (why filled) = no on-demand bearer for this line */
	bool (*profile)(void *ctx, struct mmsb_profile *out, char *why, size_t why_n);
	/* the link changed (up / down / reason): the MMS manager looks at it again. Never called from inside a call of this module. */
	void (*changed)(void *ctx);
	bool (*voice_call)(void *ctx);		/* a circuit switched call is active; NULL = no */
	void (*marker_load)(void *ctx, char *modem, size_t mn, char *bearer, size_t bn);	/* "" when none; may be NULL */
	void (*marker_save)(void *ctx, const char *modem, const char *bearer);
	void (*marker_clear)(void *ctx);
	void *ctx;
};

struct mmsb_link {
	bool up;
	char netdev[16];
	struct addr local;
	struct addr dns[4];
	int n_dns;
	unsigned seq;
	bool available;		/* it can come up when asked (provider active, modem present, not blocked) */
	char reason[160];	/* why not up ("" when up): "idle", "connecting", "retry in 10 s: ...", "another bearer ... not touched" */
};

struct mmsb_status {
	const char *state;
	char reason[160];
	char last_error[96];
	char netdev[16];
	char address[48];
	char apn[64];
	bool want;
	unsigned long connects, failures, scans_blocked;
	unsigned retry_n;
	struct guard_stats guard;
};

struct mmsb;
struct mmsb *mmsb_new(const struct mmsb_cfg *cfg, const struct mmsb_ops *ops);
/* immediate: no remote cleanup (mmsb_shutdown first when it matters) */
void mmsb_free(struct mmsb *b);
void mmsb_set_cfg(struct mmsb *b, const struct mmsb_cfg *cfg);
/* there is MMS work (true) / there is none (false: the linger starts) */
void mmsb_want(struct mmsb *b, bool want);
/* an input changed (modem path, carrier profile): look again */
void mmsb_poke(struct mmsb *b);
void mmsb_link(const struct mmsb *b, struct mmsb_link *out);
/* the traffic gate for the HTTP client (struct dns_bind.gate) */
int mmsb_gate(void *b, const struct addr *dst, void (*done)(void *arg, int err), void *arg);
void mmsb_gate_cancel(void *b, void *arg);
/* IMSI of the SIM in the modem, read through uqmid when needed ("" until known) */
const char *mmsb_imsi(const struct mmsb *b);
/* release everything (done once, from the loop or at once when idle; bounded by timeout_ms) */
void mmsb_shutdown(struct mmsb *b, void (*done)(void *arg), void *arg, unsigned timeout_ms);
void mmsb_get_status(const struct mmsb *b, struct mmsb_status *s);
#endif
