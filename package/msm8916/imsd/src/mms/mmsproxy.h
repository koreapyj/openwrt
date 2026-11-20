/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_MMSPROXY_H
#define IMSD_MMS_MMSPROXY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mms.h"
#include "../store/store.h"
#include "../ua/lan.h"
#include "../util/addr.h"

/*
 * The MMS proxy: imsd acts as an MMSC for the LAN. A device that is a standard MMS client builds M-Send.req and parses
 * M-Retrieve.conf itself and talks plain HTTP to imsd (httpd.c, no TLS, no authentication: the LAN is trusted, like the SIP
 * side), imsd relays to the operator's MMSC over the IMS PDN with the HTTP client of the MMS manager (same headers and
 * User-Agent as its own requests) and returns what the MMSC answered, unchanged. Base path /mms:
 *
 *   GET  /mms                         {"proxy":"imsd","mmsc_known":true,"mmsc":"http://mmsc/","max_size":1048576}
 *                                     (mmsc is null when unknown)
 *   POST /mms   M-Send.req            relayed to the MMSC; the MMSC's status, Content-Type and body come back (the M-Send.conf).
 *                                     A repeat of the same transaction id and body is answered from memory (10 min), the same
 *                                     id with another body is 409. 503: no IMS link / no MMSC known, 502 / 504: the MMSC did
 *                                     not answer, 413 too large, 400 not an MMS PDU, 415 wrong Content-Type.
 *   POST /mms   M-NotifyResp.ind / M-Acknowledge.ind   200, empty. imsd confirms to the MMSC itself, exactly once (mms.c).
 *   GET  /mms/fetch?url=<percent encoded Content-Location>
 *                                     the M-Retrieve.conf through the IMS PDN, for a URL announced in a notification that
 *                                     lives, or on the MMSC's host (403 otherwise). One upstream GET per URL: concurrent requests
 *                                     wait for it, later ones are served from the cache (cache_s seconds, tmpfs) while it lives.
 *   GET  /mms/sent/<id>               the M-Send.req another device sent through the proxy (carbon copy), 404 when gone.
 *
 * The same listener is also a standard HTTP forward proxy (the "MMS proxy" setting of a handset): a request line with an absolute URI is
 * the equivalent operation: GET http://host/path?query is GET /mms/fetch?url=<that URI> (store, allow-list and counters as there), POST
 * http://host/path with an M-Send.req is POST /mms (relayed to the line's MMSC whatever host the URI names; M-NotifyResp.ind and
 * M-Acknowledge.ind are 200 and not forwarded). Anything else is refused: CONNECT 501, other schemes 400, a POST that is not an MMS PDU
 * and any other method 403 (counted as denied). The sender of a proxied POST is identified by its source address, as for POST /mms.
 * Every response carries "X-MMS-Max-Size: <bytes>".
 *
 * Carbon copies: when a send was accepted by the operator (M-Send.conf Response-Status OK) the devices that registered with
 * +g.imsd.carbons, except the sender (the bindings whose source address is the client's), get a SIP MESSAGE announcing it like a received MMS
 * (the headers of a raw notification, body: an M-Notification.ind made here whose Content-Location is the gateway's /mms/sent/<id>, plus
 * X-IMSD-Carbon: sent and the carbon headers, X-MMS-Location the same URL). GET <that URL> also works as an absolute-URI request to the listener.
 *
 * Everything is on the event loop and never blocks. Memory is bounded: 8 connections (httpd.h), 4 relays at a time, 32 remembered
 * sends / cached messages, bodies up to mms_max_size.
 */
struct mmsproxy_cfg {
	unsigned port;			/* TCP port on the LAN address, 0 = the proxy is off */
	unsigned cache_s;		/* seconds a fetched message stays in the cache, 0 = no cache */
	bool carbons;			/* send carbon copies of MMS sent by a device */
	unsigned max_size;		/* mms_max_size */
	char ifname[32];		/* SO_BINDTODEVICE of the listener (lan_ifname); "" = none (tests) */
	char dir[96];			/* tmpfs directory of the cache and of the sent copies (NOT the attachment directory: not served by the web server) */
	unsigned keep_messages, keep_bytes, keep_days;
	unsigned store_keep_days;	/* store_keep_days: how long the copy lives in the message store (0 = unknown / no age limit: no expiration) */
};
void mmsproxy_cfg_defaults(struct mmsproxy_cfg *c);

struct mmsproxy_ops {
	int64_t (*wall)(void *ctx);			/* Unix time, NULL: time() */
	/* the line's own number (user part of the carbon copies' From), "" = unknown */
	void (*own_number)(void *ctx, char *out, size_t n);
	/* the message store, NULL = none. With one: the M-Send.req of an accepted send becomes an item (STORE_CARBON_MMS, delivered to the carbon
	 * devices, also to those that register later), GET /mms/sent/<id> is served from it, and GET /mms/fetch?url= from the STORE_MMS item
	 * whose Content-Location it is (the retrieve-conf the gateway fetched itself) for as long as the item is retained; the tmpfs cache and
	 * the tmpfs copies of sent messages are then used only for what is not in the store. The store must outlive the proxy. */
	struct store *store;
	void *ctx;
};

struct mmsproxy_status {
	bool listening;
	char address[64];		/* LAN address, "" while not listening */
	unsigned port;
	unsigned conns;
	unsigned long relayed_sends;	/* M-Send.req answered by the MMSC (any HTTP status) */
	unsigned long send_failures;	/* ... not answered (transport) or answered with an HTTP status other than 200 */
	unsigned long send_repeats;	/* answered from memory (same transaction id and body) */
	unsigned long fetches;		/* GETs to the MMSC (cache misses) */
	unsigned long fetch_failures;
	unsigned long cache_hits;	/* answered from the cache, or by waiting for a fetch already running */
	unsigned long denied;		/* fetch of a URL that is not allowed (403) */
	unsigned long carbons_sent;	/* carbon copies of MMS handed to at least one device */
	unsigned long carbons_failed;	/* ... taken by nobody / not sent */
	unsigned long store_hits;	/* fetches and sent copies answered from the store */
	unsigned long carbons_stored;	/* carbon copies of sent messages kept in the store */
	unsigned cache_entries;
	char error[96];			/* why not listening */
};

struct mmsproxy;
/* mms: the manager (not owned, must outlive the proxy). NULL on out of memory. */
struct mmsproxy *mmsproxy_new(const struct mmsproxy_cfg *cfg, const struct mmsproxy_ops *ops, struct mms *mms);
/* closes the listener and the connections, drops the relays (the manager's HTTP client is used: free the proxy BEFORE the manager) */
void mmsproxy_free(struct mmsproxy *p);
void mmsproxy_set_cfg(struct mmsproxy *p, const struct mmsproxy_cfg *cfg);
/* The LAN object and its address (the SIP endpoint's), NULL while the LAN side is down: the listener follows (re-bound to the new address) */
void mmsproxy_set_lan(struct mmsproxy *p, struct lan *l, const struct addr *a);
bool mmsproxy_listening(const struct mmsproxy *p);
/* "http://192.168.1.1:8090/mms", "" while not listening */
const char *mmsproxy_base_url(const struct mmsproxy *p);
void mmsproxy_get_status(const struct mmsproxy *p, struct mmsproxy_status *s);

/* percent-decoding of a query value ('+' stays '+'). 0 / -1 (bad escape, output too small) */
int mmsproxy_urldecode(const char *in, size_t n, char *out, size_t cap);
/* the value of a query parameter (decoded). 0 found / -1 */
int mmsproxy_query_get(const char *query, const char *name, char *out, size_t cap);
#endif
