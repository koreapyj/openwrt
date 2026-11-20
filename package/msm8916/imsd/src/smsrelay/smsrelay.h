/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SMSRELAY_SMSRELAY_H
#define IMSD_SMSRELAY_SMSRELAY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../sip/msg.h"
#include "../sip/txn.h"
#include "../ua/lan.h"
#include "../store/store.h"
#include "../cs/cssms.h"

/*
 * SMS relay: plain SIP MESSAGE between the IMS network (SMS over IP, RP/TP in
 * application/vnd.3gpp.sms) and the SIP clients registered on the LAN
 * (text/plain). With the store (ops.store, store/store.h) an incoming SMS is kept (item type STORE_SMS) and acknowledged to the
 * network once it is durable; the LAN devices get it from the store, each at its own pace (redelivery after a lost
 * registration, X-IMSD-Seq). Without a store (store=0, or while it is unusable) an SMS that arrives while no LAN client takes it is
 * logged (full text, WARNING) and lost, as before.
 *
 *   MT: network MESSAGE (RP-DATA) -> 200 -> decode -> lan_fork_request MESSAGE to every
 *       binding -> RP-ACK (or RP-ERROR, see smsrelay_lost_policy) to the network.
 *   MO: LAN MESSAGE (hook) -> TP-SUBMIT segments -> RP-DATA MESSAGE to the SMS PSI, one segment at a
 *       time, each confirmed by the RP-ACK / RP-ERROR that the network sends back as a MESSAGE
 *       -> one answer to the LAN client.
 *
 * Carbon copies: when the network acknowledged an MO message (the moment its sender gets the 200) every other device that registered
 * with +g.imsd.carbons gets the text as SIP MESSAGE from the line's own identity: "X-IMSD-Carbon: sent", "X-IMSD-Carbon-ID", "X-IMSD-Peer"
 * (the number), "X-SMS-Timestamp", "X-SMS-Parts" (segments over the air); a text split for the SIP size limit carries "X-SMS-Part: i/n" and
 * the "(i/n) " markers (ua/lan_text.h). The sender is the binding the MESSAGE came from; an unregistered source has none, all get it.
 *
 * Wiring (integrator): smsrelay_new(lan, cfg, ops) (see also smsrelay_mod.c); lan_set_hooks with on_message =
 * smsrelay_on_lan_message and arg = the relay (or call it from your own hook); call
 * smsrelay_on_gm_request() first thing for every MESSAGE request arriving on the protected Gm
 * endpoint (when it returns false, answer as before: 415); forward Gm registration events to
 * smsrelay_on_reg_event(). The Gm side is reached only through struct smsrelay_ops, so the real gm/reg.c
 * is not needed in tests. Teardown order: smsrelay_free() BEFORE lan_free() / txn_layer_free(), and
 * after nothing can call back into it any more from the Gm side (reg_free).
 *
 * WAP Push (SMS-DELIVER, 8-bit data, application port addressing to port 2948 / 2949): the one place where segments are
 * reassembled (smsrelay/wappush.c, bounded and with a timeout). Each segment is acknowledged with RP-ACK at once, as a
 * handset does, without waiting for what is done with the message; the complete WDP payload goes to ops.push. Binary SMS
 * to other ports, or without port addressing, keep their notice to the LAN clients; text SMS are never reassembled.
 *
 * Circuit switched SMS (cs/cssms.h, SMS through the modem): messages arrive already decoded (smsrelay_cs_in) and enter at the same
 * points as the IMS ones after RP / TP decoding: the store item (STORE_SMS, own meta layout, same delivery handler and the same LAN
 * MESSAGE shape) or live delivery without a store; no RP-ACK (the modem acknowledged the network), duplicates by the store dedup
 * key (sender, SMSC timestamp, text hash). MO goes to ops.cs_submit while ops.cs_active says so, decided per message when it
 * arrives; the answers and X-SMS-Parts are the ones of the IMS path, carbons as well.
 *
 * Everything runs on the main loop and never blocks. Memory is bounded: MT jobs in flight
 * (mt_max_pending), MO queue (queue_max), segments per message (max_segments), the duplicate cache.
 */

struct smsrelay;

/* one out-of-dialog request on the registered Gm context (maps 1:1 onto gm/reg.h struct reg_req) */
struct smsrelay_gm_req {
	const char *ruri;
	const char *call_id;		/* always set by the relay */
	const char *extra;		/* complete header lines, CRLF each */
	const char *content_type;
	const uint8_t *body;
	size_t body_len;
};
/* identical in shape to reg_resp_cb. status 0: timeout / transport error. Must NOT be called synchronously from send(). */
typedef void (*smsrelay_gm_resp_cb)(void *arg, int status, const struct sip_msg *resp);

struct smsrelay_ops {
	bool (*registered)(void *ctx);	/* registered on the network right now (reg_is_registered) */
	/* send a MESSAGE with method "MESSAGE" via reg_send(): 0 or -errno (-ENOTCONN when not registered) */
	int (*send)(void *ctx, const struct smsrelay_gm_req *q, smsrelay_gm_resp_cb cb, void *arg);
	/* the SMSC from the card (USIM EF_SMSP, "+821080010585"), "" / NULL = unknown. Evaluated at every MO message. */
	const char *(*smsc)(void *ctx);
	/* the SMS gateway URI from the card (EF_PSISMSC), "" / NULL = none. Evaluated at every MO. The gateway is resolved as
	 * cfg sms_psi, else this, else the operator table of the IMSI (carrier.h); none: the MO is refused with 503. */
	const char *(*sms_psi)(void *ctx);
	/* the IMSI of the SIM (selects the operator table), "" / NULL = unknown */
	const char *(*imsi)(void *ctx);
	/* A WAP Push (binary SMS with application port addressing to WDP port 2948) was received completely: from = the
	 * originator's number, port = WDP destination port, data = the reassembled WDP payload (a WSP PDU; valid during the
	 * call only). NULL: such pushes are logged and dropped. */
	void (*push)(void *ctx, const char *from, unsigned port, const uint8_t *data, size_t len);
	/* the line's own number (user part of the public identity, "+82...") for the From of the carbon copies; "" / NULL = unknown */
	void (*own_number)(void *ctx, char *out, size_t n);
	/* circuit switched SMS (all NULL: no such path). cs_active: the circuit switched backend carries SMS now (asked for every MO
	 * message, the answer is fixed at that moment); cs_submit: cssms_submit(); push_active: the MMS manager is active for the
	 * current backend (an MMS notification received over CS is only handed to ops.push then); cs_in_done: the answer to
	 * CSSMS_PENDING of smsrelay_cs_in (cssms_in_done) */
	bool (*cs_active)(void *ctx);
	int (*cs_submit)(void *ctx, const struct cssms_submit *q, cssms_done_cb cb, void *arg);
	bool (*push_active)(void *ctx);
	void (*cs_in_done)(void *ctx, unsigned id, bool taken);
	/* cs_kick: ask cssms to offer the messages it kept (not taken) again now; called when the store becomes usable and by
	 * smsrelay_cs_kick() (a LAN device registered) */
	void (*cs_kick)(void *ctx);
	/* the message store, NULL = none: the relay registers its delivery handlers there (STORE_SMS, STORE_CARBON_SMS) and removes them in
	 * smsrelay_free(); the store must outlive the relay */
	struct store *store;
	void *ctx;
};

enum smsrelay_lost_policy {
	/*
	 * Nobody can take an incoming SMS: RP-ACK anyway (default). The network considers it delivered and
	 * stops retrying; the text is logged as lost. Chosen because with no store we could never deliver
	 * it later anyway.
	 */
	SMSRELAY_LOST_ACK = 0,
	/*
	 * RP-ERROR cause 22 (memory capacity exceeded) when no LAN client is registered at all. The network
	 * then keeps the message, sets the "messages waiting" flag and retries after its own schedule; it also
	 * expects an RP-SMMA from us when we can accept again, which is NOT implemented (retries depend on
	 * the operator's schedule and the message expires there). A registered client that fails to take the
	 * message still gets RP-ACK. Off by default.
	 */
	SMSRELAY_LOST_RPERROR22 = 1,
};

enum smsrelay_reg_ev {
	SMSRELAY_REG_UP,
	SMSRELAY_REG_DOWN,		/* registration lost: in-flight MO messages fail with 480 */
	SMSRELAY_REG_REPLACED,		/* re-authenticated onto a new endpoint: nothing to do, send() uses the current one */
};

struct smsrelay_cfg {
	/* ---- network -> LAN ---- */
	bool concat_prefix;		/* "(2/3) " in front of concatenated parts (default true) */
	bool delivery_reports;		/* MO sets TP-SRR; incoming SMS-STATUS-REPORT becomes a notice (default false) */
	enum smsrelay_lost_policy lost_policy;
	unsigned lan_wait_ms;		/* wait for LAN answers before the RP-ACK (default 5000) */
	unsigned mt_max_pending;	/* incoming SMS being delivered at once (default 16); more -> RP-ERROR 42 */
	/* ---- LAN -> network ---- */
	char smsc[32];			/* explicit SMSC "+821080010585"; wins over the SIM's (default "": use ops->smsc).
					 * Neither: MO is refused with 503 */
	char sms_psi[160];		/* explicit Request-URI of the MO MESSAGE; wins over the card's (ops->sms_psi) and the
					 * operator table (default "": none, so a MO is refused with 503 when neither knows one) */
	char p_preferred_identity[160];	/* optional P-Preferred-Identity value, default "" = omit (network accepted both) */
	unsigned max_segments;		/* 413 beyond this many SMS segments (default 10, max 32) */
	unsigned queue_max;		/* MO messages queued + in flight (default 8, max 64); more -> 503 Retry-After */
	unsigned report_timeout_ms;	/* RP-ACK / RP-ERROR per segment after the network's SIP answer (default 30000) */
	unsigned reply_deadline_ms;	/* answer 202 to the LAN client at the latest this long after its MESSAGE
					 * (default 28000: its Timer F is 64*T1 = 32 s, minus margin for transit and skew) */
	unsigned vp_minutes;		/* TP-VP relative, 0 = none (default, as the accepted capture) */
	bool mo_require_registered;	/* 403 for MESSAGE from LAN devices that are not registered (default false) */
	/* counters start values; -1 = random (default). Set to fixed values for byte-exact tests. */
	int rp_mr_start, tp_mr_start, concat_ref_start;
	/* ---- carbon copies ---- */
	bool carbons;			/* an SMS the network acknowledged goes as a copy to the devices with +g.imsd.carbons, except the sender (default true) */
	unsigned text_split;		/* bytes per SIP MESSAGE of a copy; a longer text is split losslessly (default 1000) */
	/* ---- store ---- */
	unsigned store_ack_wait_ms;	/* RP-ACK of an incoming SMS waits at most this long for the store's fsync, then the live path decides (default 3000) */
};
void smsrelay_cfg_defaults(struct smsrelay_cfg *c);

/* cfg and ops are copied. lan may be NULL (see smsrelay_set_lan). NULL on OOM / bad arguments. */
struct smsrelay *smsrelay_new(struct lan *lan, const struct smsrelay_cfg *cfg, const struct smsrelay_ops *ops);
/* Fails whatever is queued (503 to the LAN clients), detaches LAN forks, frees. */
void smsrelay_free(struct smsrelay *sr);
/*
 * The LAN object came up (lan != NULL) or is about to be freed (NULL, old object still valid): while NULL there is no
 * LAN client, so an incoming SMS is answered per the lost policy and logged as lost, and MO cannot arrive. Going down
 * ends the MT deliveries in progress (as lost) and fails queued MO messages with 503.
 */
void smsrelay_set_lan(struct smsrelay *sr, struct lan *lan);
/* new configuration for later messages (strings copied). */
void smsrelay_set_cfg(struct smsrelay *sr, const struct smsrelay_cfg *cfg);

/*
 * Gm entry point. Consumes MESSAGE requests whose Content-Type is application/vnd.3gpp.sms: answers 200
 * on st at once and handles RP-DATA (incoming SMS / status report), RP-ACK and RP-ERROR (answers to our MO).
 * Returns false (nothing sent) for anything else, so the caller answers it. ep / src are informational.
 */
bool smsrelay_on_gm_request(struct smsrelay *sr, struct txn_server *st, struct sip_endpoint *ep,
			    const struct addr *src, const struct sip_msg *req);

/* lan_hooks.on_message compatible; arg is the struct smsrelay. Owns the reply on st (see the answer table in the .c) */
void smsrelay_on_lan_message(struct lan *l, const struct lan_peer *peer, struct txn_server *st,
			     const struct sip_msg *req, void *arg);

void smsrelay_on_reg_event(struct smsrelay *sr, enum smsrelay_reg_ev ev);

/* A message from the circuit switched path (cssms_in_cb). Returns CSSMS_TAKEN / CSSMS_PENDING / < 0 (not taken, see cssms.h):
 * with the store the item is durable before the modem's copy is deleted (PENDING, ops.cs_in_done follows); without one the
 * message is taken when the LAN delivery was started or logged as lost. */
int smsrelay_cs_in(struct smsrelay *sr, const struct cssms_in *m);
/* a LAN device registered (or anything else that may make a kept CS message deliverable): ops.cs_kick */
void smsrelay_cs_kick(struct smsrelay *sr);

/* ---- status ---- */
struct smsrelay_status {
	unsigned long mt_received;	/* RP-DATA n->ms seen (retransmissions included) */
	unsigned long mt_delivered;	/* at least one LAN client answered 2xx */
	unsigned long mt_lost_no_client;/* nobody registered (logged as lost, see lost_policy) */
	unsigned long mt_lost_failed;	/* clients existed but none accepted within lan_wait_ms */
	unsigned long mt_duplicates;	/* retransmissions answered from the cache */
	unsigned long mt_reports;	/* SMS-STATUS-REPORTs received */
	unsigned long mt_errors;	/* undecodable / refused with RP-ERROR */
	unsigned long mt_push_segments;	/* WAP push segments received (acknowledged at once, retransmissions not counted) */
	unsigned long mt_push_messages;	/* complete WAP pushes handed to ops.push */
	unsigned long mo_submitted;	/* LAN messages accepted into the queue */
	unsigned long mo_acked;		/* fully acknowledged by the network */
	unsigned long mo_failed;
	unsigned long mo_segments_sent;
	unsigned long carbons_sent;	/* copies of sent SMS taken by at least one device */
	unsigned long carbons_failed;	/* ... taken by nobody */
	unsigned long mt_stored;	/* incoming SMS durable in the store (acknowledged to the network from there) */
	unsigned long mt_store_fallback;/* ... the store did not take / confirm in time: delivered live like without a store */
	unsigned long cs_rx_deferred;	/* CS messages answered "not taken" (store not ready / failed, or nobody to deliver to): they stay in the modem and are offered again */
	unsigned long carbons_stored;	/* carbon copies kept in the store */
	unsigned long cs_mms_unhandled;	/* MMS notifications received over the circuit switched path while the MMS manager is not active: only the notice went on */
	unsigned mo_queue_len;		/* queued + in flight */
	unsigned mt_pending;
	char last_error[160];		/* "" if none */
	char smsc[32];			/* SMSC in use now ("" if unknown) */
	char smsc_source[12];		/* "config", "sim" or "none" */
	char sms_psi[160];		/* SMS gateway URI in use ("" if unknown) */
	char sms_psi_source[12];	/* "config", "sim", "carrier" or "none" */
};
void smsrelay_get_status(const struct smsrelay *sr, struct smsrelay_status *s);
#endif
