/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_MMS_H
#define IMSD_MMS_MMS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "dns.h"
#include "http.h"
#include "mmspdu.h"
#include "mmsrender.h"
#include "netio.h"
#include "../store/store.h"
#include "../ua/registrar.h"
#include "../util/addr.h"

/*
 * MMS reception manager. An incoming MMS is announced by an m-notification-ind that the network pushes by SMS
 * (WAP Push, destination port 2948, see smsrelay/wappush.c); the SMS relay hands the reassembled WSP PDU to
 * mms_on_push(). From there, like a handset:
 *
 *   notification -> (duplicate? too big? expired?) -> queue (at most MMS_QUEUE jobs, one at a time)
 *   -> HTTP GET of X-Mms-Content-Location over the IMS PDN (DNS of the bearer, sockets bound to its address / netdev)
 *   -> m-retrieve-conf -> attachments to the web directory (mmsstore), text -> LAN devices as SIP MESSAGE
 *   -> M-NotifyResp.ind (Retrieved) and, when the retrieve-conf has a transaction id, M-Acknowledge.ind to the MMSC.
 *
 * The MMSC may notify the same message again under a new transaction id and Content-Location (when it believes the
 * confirmations did not arrive). After a retrieval the content identity (sender, Date, subject, parts: no id, no URL) is
 * looked up in a ring of the last 32 delivered messages (24 h, monotonic clock): a repeat is not delivered nor stored
 * again but is confirmed, so that the MMSC stops. A message lost for lack of a LAN client is in the ring too: it was
 * retrieved and confirmed, a later delivery would need a store (out of scope). mms_fetch() bypasses the ring.
 *
 * Devices that registered with +g.imsd.mms (ops->devices, only while the MMS proxy listens) get the ORIGINAL notification as SIP MESSAGE
 * (ops->deliver_raw) and fetch through the proxy (mmsproxy.h). With no other device imsd does not retrieve: it confirms once, after the
 * first proxied fetch of the Content-Location (mms_proxy_fetched: M-NotifyResp.ind Retrieved, then M-Acknowledge.ind with the id of the
 * fetched retrieve-conf; queued as a confirmation-only job). With devices of both kinds the text path above runs for the others (it
 * confirms) and the original goes to the tagged ones. A notification announcing, under a new transaction id, a message (sender, subject,
 * size) whose earlier notification was already fetched through the proxy is not passed on again, only confirmed; one that was not fetched
 * is passed on again. Notifications are remembered (32, their lifetime) for the proxy's fetch allow-list.
 *
 * Retrieval that fails transiently (DNS, connect, timeout, HTTP 5xx) is retried after 5 s, 30 s and 2 min while the
 * message has not expired; HTTP 4xx and unparseable answers are not retried. A message above mms_max_size is refused
 * with M-NotifyResp.ind(Rejected) without being fetched. While the IMS link is down the queue waits.
 *
 * STORE MODE (ops.store set and store_usable()): the gateway ALWAYS retrieves an incoming MMS itself as soon as it is notified (whatever kinds of
 * devices are registered), puts the m-retrieve-conf into the store together with the notification (item STORE_MMS: store/store.h,
 * mms/mmsitem.h), and confirms to the MMSC once after that retrieval (M-NotifyResp.ind + M-Acknowledge.ind, as in the text path above).
 * The item is created when the retrieval finished or failed for good (a transient failure follows the retry schedule above; until
 * then no device is told anything: the original notification is not sent early either). From the store each device gets what its
 * kind takes, at its own pace and in order: the text devices the rendered text with attachment links (the attachments are written from the
 * stored message into the tmpfs web directory at delivery time, again at every redelivery), the +g.imsd.mms devices the original
 * notification, and /mms/fetch is served from the store as long as the item is retained (mmsproxy.h). A retrieval that failed for good is still
 * an item: the +g.imsd.mms devices get the notification (they may try the fetch themselves), the text devices a short notice. A repeat
 * notification of a message in the store (same content) creates no second item (it is confirmed). Without a usable store everything
 * above is the live path described before.
 *
 * Everything runs on the event loop and never blocks (DNS and HTTP clients of this directory, fake sockets in tests).
 */
#define MMS_QUEUE	8

struct mms_cfg {
	bool enable;
	char mmsc[160];			/* explicit POST URL of the confirmations to the MMSC; "" = the operator table (ops->imsi, carrier.h),
					 * and when that has none either scheme://host:port/ of the Content-Location (logged once) */
	char uaprof[160];		/* x-wap-profile header, "" = none */
	char user_agent[96];		/* User-Agent of the HTTP requests when neither uci (mms_user_agent) nor the operator entry names one: the IMS user agent */
	/* uci overrides of the operator's MMS data connection (carrier.h: carrier_resolve_mms), "" = not set */
	char mms_apn[64], mms_ip_type[16], mms_proxy[140], mms_user_agent[96], mms_accept[200];
	unsigned max_size;		/* bytes, default 1 MiB */
	char dir[96];			/* attachment directory (tmpfs, served by the web server) */
	char url_base[160];		/* "" = http://<LAN address>/imsd-mms/ */
	unsigned keep_messages, keep_bytes, keep_days;
	unsigned text_split;		/* bytes per SIP MESSAGE, default 1000 */
};
void mms_cfg_defaults(struct mms_cfg *c);

/* the IMS bearer as far as the MMS client needs it */
struct mms_link {
	bool up;
	bool on_demand;			/* the on-demand bearer (mmsbearer.h): work asks for it (ops->want) and waits for it to come up */
	bool available;			/* on demand: it can come up when asked; false = blocked / no APN / no modem, see reason */
	char reason[160];		/* why it is not up ("" when up) */
	char netdev[16];
	struct addr local;
	struct addr dns[DNS_MAX_SERVERS];
	int n_dns;
	unsigned seq;			/* changes with the link */
};

/* what goes to the LAN devices: n pieces of text (each complete, with its "(i/n) " prefix) */
struct mms_out {
	char from[MMS_ADDR_MAX];	/* the sender's number / address */
	char subject[MMS_SUBJ_MAX];
	char message_id[MMS_ID_MAX];
	bool has_ts;
	int64_t ts;			/* Unix time of the message */
	bool exclude_mms;		/* not to the devices that get the original notification (+g.imsd.mms) */
	reg_id_t target;		/* REG_ID_NONE: all devices (but exclude_mms); else only this binding (the store's redelivery) */
	uint64_t seq;			/* store sequence number: X-IMSD-Seq header, 0 = none */
	unsigned n;
	const char *text[MMSR_MAX_CHUNKS];
};

/* the original m-notification-ind for the devices that fetch through the MMS proxy */
struct mms_raw {
	const uint8_t *pdu;		/* the MMS PDU as received, without the WSP push header */
	size_t len;
	char from[MMS_ADDR_MAX];
	char tid[MMS_ID_MAX];
	char proxy[200];		/* base URL of the MMS proxy: http://<LAN address>:<port>/mms */
	unsigned max_size;
	int64_t ts;			/* arrival, Unix time */
	reg_id_t target;		/* REG_ID_NONE: every device with +g.imsd.mms; else only this binding */
	uint64_t seq;			/* store sequence number: X-IMSD-Seq header, 0 = none */
};

struct mms_ops {
	void (*link)(void *ctx, struct mms_link *out);
	/* start delivering to the LAN devices. 0: started, done(arg, nok) follows once from the event loop (nok = devices
	 * that took the whole message); -ENOENT: nobody to deliver to; other -errno. */
	int (*deliver)(void *ctx, const struct mms_out *m, void (*done)(void *arg, int nok), void *arg);
	void (*deliver_abort)(void *ctx, void *arg);	/* done(arg) will not be called (for deliver and deliver_raw) */
	/* how many LAN devices take the original notification (the MMS proxy is listening and the device registered with
	 * +g.imsd.mms) and how many the rendered text (all the others; all of them while the proxy is down). NULL: n_mms 0. */
	void (*devices)(void *ctx, unsigned *n_mms, unsigned *n_text);
	/* the original notification as SIP MESSAGE to the devices counted in n_mms; same return value and done as deliver */
	int (*deliver_raw)(void *ctx, const struct mms_raw *r, void (*done)(void *arg, int nok), void *arg);
	/* base URL of the MMS proxy for the devices ("http://192.168.1.1:8090/mms"), "" = not listening. NULL: "" */
	const char *(*proxy_base)(void *ctx);
	const char *(*imsi)(void *ctx);			/* IMSI of the SIM, "" / NULL = unknown (selects the operator table) */
	const char *(*net_plmn)(void *ctx);		/* MCC+MNC of the registered network, "" / NULL = unknown (operator table fallback for MVNOs) */
	/* MMS work exists (true) / does not (false): the on-demand data connection is brought up / released after its linger. NULL: always up. */
	void (*want)(void *ctx, bool wanted);
	/* the traffic gate of the HTTP client (struct dns_bind.gate) for the on-demand link; NULL = none */
	int (*gate)(void *ctx, const struct addr *dst, void (*done)(void *arg, int err), void *arg);
	void (*gate_cancel)(void *ctx, void *arg);
	const char *(*lan_host)(void *ctx);		/* address text of the LAN side for URLs ("" = unknown) */
	int64_t (*wall)(void *ctx);			/* Unix time; NULL: time() */
	/* the message store, NULL = none (mms.h "STORE MODE" below). The manager registers its delivery handler (STORE_MMS) there and removes
	 * it in mms_free(); the store must outlive the manager. */
	struct store *store;
	const struct net_ops *net;			/* NULL: the real sockets */
	void *ctx;
};

/* what the MMS proxy (mmsproxy.c) needs to talk to the operator: the link, the MMSC and the headers of imsd's own requests */
struct mms_upstream {
	bool link_up;
	bool can_wait;			/* link down, but an on-demand bearer is being brought up: mms_link_wait() */
	char down_text[240];		/* what a refused request says when the link is down */
	struct dns_bind bind;
	char proxy_host[128];		/* the operator's MMS proxy ("" = none): http_opts.proxy_host / proxy_port */
	unsigned proxy_port;
	char mmsc[HTTP_MAX_URL];	/* POST URL of the MMSC, "" = unknown */
	char get_headers[512];		/* Accept, User-Agent, x-wap-profile (CRLF terminated lines) */
	char post_headers[640];		/* the same plus Content-Type: application/vnd.wap.mms-message */
	unsigned max_size;
};

struct mms_status {
	unsigned long notifications;	/* m-notification-ind received (duplicates not counted) */
	unsigned long duplicates;	/* repeats of a notification (same transaction id) or of a delivered message (same content) */
	unsigned long retrieved;	/* m-retrieve-conf received and decoded */
	unsigned long delivered;	/* handed to at least one LAN device */
	unsigned long lost_no_client;	/* retrieved, nobody on the LAN to take it */
	unsigned long failed;		/* gave up: permanent error, retries used up, expired, queue full */
	unsigned long rejected;		/* refused as too big (M-NotifyResp Rejected) */
	unsigned long acked;		/* confirmations (M-NotifyResp.ind / M-Acknowledge.ind) the MMSC answered 2xx */
	unsigned long ack_failed;	/* confirmations answered with another status (404 / 405: the URL is wrong) or not delivered */
	unsigned long raw_delivered;	/* original notifications handed to at least one device with +g.imsd.mms */
	unsigned long raw_lost;		/* ... and those that nobody took */
	unsigned long proxy_acks;	/* confirmations queued for messages that devices fetched through the proxy */
	unsigned long stored;		/* messages (and failed retrievals) durable in the store */
	unsigned long store_fallback;	/* ... the store did not take them: delivered live like without a store */
	unsigned long failed_stored;	/* retrievals that failed for good and were stored as such (devices get a notice / the notification) */
	unsigned pending;		/* jobs in the queue (including the one running) */
	char last_error[160];
	char mmsc[160];			/* POST URL in use (resolved, or derived from the last Content-Location) */
	char mmsc_source[12];		/* "config", "carrier", or "none" (then mmsc is the derived URL of the last confirmation, "" before one) */
	/* the operator entry in use (carrier.h) */
	char operator_name[48];		/* "" = none */
	char operator_match[8];		/* "sim" | "network" | "none" */
	char apn[64];			/* MMS APN, "" = the IMS PDN carries the MMS */
	char proxy[140];		/* "smart.nate.com:9093" or "" */
	char user_agent[96];		/* the one sent */
	bool entry_tested;
	bool on_demand;			/* the data connection is the on-demand bearer */
	char link_reason[160];		/* why the link is not up ("" when it is) */
	unsigned store_messages;
	size_t store_bytes;
};

struct mms;
struct mms *mms_new(const struct mms_cfg *cfg, const struct mms_ops *ops);
/* drops everything: running requests, queue, delivery callbacks */
void mms_free(struct mms *m);
void mms_set_cfg(struct mms *m, const struct mms_cfg *cfg);
/* the IMS link may have changed (ops->link is read again): a request in flight over a vanished link is repeated */
void mms_link_changed(struct mms *m);
/* For work that does not go through the queue (the MMS proxy's sends and fetches): is the data connection up (1), will it come up
 * when asked (0: cb(arg, up) follows once from the event loop, up false after 50 s or when it becomes unavailable; the work counts as
 * pending, so the on-demand bearer is brought up and kept for it) or not at all (-ENETDOWN: refuse). mms_link_wait_cancel(NULL) cancels all. */
int mms_link_wait(struct mms *m, void (*cb)(void *arg, bool up), void *arg);
void mms_link_wait_cancel(struct mms *m, void *arg);
/* a relay of the proxy started (+1) / ended (-1): MMS work that keeps the on-demand bearer */
void mms_work(struct mms *m, int delta);
/* A WAP Push (reassembled WDP payload = WSP PDU) that arrived on WDP port `port` from the originator `from`. Pushes that
 * are not MMS notifications are logged and dropped. */
void mms_on_push(struct mms *m, const char *from, unsigned port, const uint8_t *data, size_t n);
/* bench: retrieve url as if a notification had announced it (no NotifyResp / Acknowledge are sent for it).
 * 0, -EINVAL (bad URL), -ENOTSUP (https), -EBUSY (queue full) */
int mms_fetch(struct mms *m, const char *url, const char *from, const char *subject);
void mms_get_status(const struct mms *m, struct mms_status *s);

/* ---- for the MMS proxy: the same HTTP client, link, headers; the fetch allow-list; the first fetched message is confirmed ---- */
struct http *mms_http(struct mms *m);
void mms_upstream(struct mms *m, struct mms_upstream *u);
/* may a device fetch this URL through the proxy: the Content-Location of a notification that lives, or a URL on the MMSC's host */
bool mms_url_allowed(struct mms *m, const char *url);
/* a fetch of url completed with this body: when it is the first fetch of a message announced to the devices only, imsd sends
 * M-NotifyResp.ind (Retrieved) and M-Acknowledge.ind (transaction id of the retrieve-conf) to the MMSC, once */
void mms_proxy_fetched(struct mms *m, const char *url, const uint8_t *body, size_t len);
/* a device sent M-NotifyResp.ind for tid: with status Retrieved and no fetch through the proxy before, imsd confirms (once) */
void mms_proxy_notify_resp(struct mms *m, const char *tid, unsigned status);
#endif
