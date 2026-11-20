/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_CSSMS_H
#define IMSD_CS_CSSMS_H
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "csline.h"

/*
 * SMS through uqmid messaging, for the line without SMS over IMS: the modem does RP / TP, SMSC and segmentation itself
 * (QMI WMS), uqmid hands over decoded messages. The contract towards the SMS relay is the one of the IMS path after the TPDU
 * is decoded: one message per callback, the text as UTF-8, binary user data, status reports; results of an MO message with
 * the same status codes smsrelay answers the LAN device with (200, 400, 403, 413, 480, 484, 502, 503, 504).
 *
 * ---- what uqmid delivers (sources in the report: uqmid/sms.c, messaging.c, common/sms_part.c) ------------------------
 *  - a message is one object uqmid.modem.N.sms.M ({state, pdu_type, number, text | data (hex), timestamp, class,
 *    multipart, max_parts, received_parts, message_reference, delivery_state, storage}); announced by the notification
 *    messaging.added {path, received}. A concatenated message is ONE object: it is announced with its first part in state
 *    "receiving" (only multipart / max_parts / received_parts are valid then) and turns "received" with
 *    messaging.state_changed {old receiving, new received} when the last part is there; text / data are the parts joined.
 *  - GSM 7 bit, 8 bit and UCS-2 are decoded to UTF-8 text; an 8 bit message (DCS 8 bit, e.g. WAP push) has "data" instead
 *    of "text": the TP-UD WITHOUT its user data header. The application port addressing IE (WDP port 2948 of an MMS
 *    notification) is DROPPED by uqmid's PDU parser (only the concatenation IEs are interpreted), so the port is not known;
 *    a WSP push PDU is recognised by its content (cssms_in.wsp_push, mms_hint). The raw PDU with the UDH is only in the
 *    modem storage (uqmid wms_get_raw_message, by storage index, not for transfer-route messages that are never stored).
 *  - class 0..3 is in "class" (-1 none). Status reports are objects with pdu_type "status-report" (message_reference,
 *    delivery_state = TP-Status, discharge_timestamp).
 *  - the modem stores messages in SIM / NV or hands them over unstored ("transfer-only" route, depends on the carrier
 *    configuration): either way the object lives in uqmid until messaging_delete (512 objects at most).
 *
 * ---- what this module does -------------------------------------------------------------------------------------------
 *  - every message is handed over ONCE (cssms_in_cb), then the uqmid object is deleted so storage never fills up. The
 *    object is deleted only after the taker confirmed it (CSSMS_TAKEN, or cssms_in_done after CSSMS_PENDING: the message store
 *    has it durable); a taker that logs a message as lost (nobody to deliver to, store off) answers TAKEN, like the IMS
 *    path RP-ACKs a message nobody can take. A negative answer keeps the object and offers it again: 20 passes 5 s apart, then
 *    one pass per slow_retry_ms (5 min); cssms_kick() and every new message notification restart the quick passes. The bound
 *    only limits the retrying, a kept object is never deleted because of it (only the incomplete_ms rule above deletes).
 *  - backlog: messages that are already there when the modem is first seen (the SIM / NV storage of a previous run, objects
 *    uqmid loaded while enabling) cannot be told from new ones; all of them are delivered once, with backlog = true, and
 *    deleted. After the first complete drain of a modem object new messages have backlog = false.
 *  - a concatenated message that stays incomplete for incomplete_ms is deleted (the parts leave the modem storage) and counted.
 *  - MO: messaging_create + send + delete, one message at a time in order; uqmid segments (GSM 7 bit / UCS-2, 153 / 67
 *    characters per part with a concatenation IE, up to 255 parts); max_segments (default 10, like smsrelay) is checked first
 *    with the same rule, 413 beyond it.
 */
enum cssms_kind { CSSMS_TEXT, CSSMS_DATA, CSSMS_REPORT };

struct cssms_in {
	enum cssms_kind kind;
	char from[48];			/* originator as uqmid gives it: a number ("+8210...") or the text of an alphanumeric sender */
	bool from_alnum;		/* not a number */
	char ts[32];			/* ISO 8601 service centre timestamp or "" */
	const char *text;		/* TEXT (UTF-8) */
	const uint8_t *data;		/* DATA: user data (valid during the callback) */
	size_t data_len;
	int sms_class;			/* -1 none, 0..3 */
	bool multipart;
	unsigned parts;			/* parts of a concatenated message, 1 otherwise */
	bool backlog;			/* found at start-up, not newly received */
	bool wsp_push;			/* DATA that is a WSP Push / ConfirmedPush PDU (WAP push) */
	bool mms_hint;			/* ... whose content type is application/vnd.wap.mms-message (an MMS notification) */
	unsigned message_reference;	/* REPORT: of the message the report is for */
	unsigned delivery_state;	/* REPORT: TP-Status (tp_status_is_success / _final in smscodec/tpdu.h) */
	char discharge_ts[32];		/* REPORT */
	bool truncated;			/* the text or data did not fit CSU_TEXT_MAX / CSU_DATA_MAX */
	unsigned id;			/* names this hand-over for cssms_in_done() */
};
/*
 * Return value: CSSMS_TAKEN (0) the message is taken, the uqmid object is deleted now. CSSMS_PENDING (> 0) it is being made
 * durable (the relay: the message store): the object stays and the queue waits until cssms_in_done(s, m->id, taken) is called
 * (once, from the event loop); taken false = give it back. < 0: not taken, the object stays in the modem and is offered again later.
 */
#define CSSMS_TAKEN 0
#define CSSMS_PENDING 1
typedef int (*cssms_in_cb)(void *arg, const struct cssms_in *m);
struct cssms;
void cssms_in_done(struct cssms *s, unsigned id, bool taken);
/* offer the objects that were not taken again now (the store is ready, a LAN device registered). Resets the retry bound. */
void cssms_kick(struct cssms *s);

struct cssms_cfg {
	unsigned max_segments;		/* MO: 413 beyond this many SMS parts, default 10 (max 32) */
	unsigned queue_max;		/* MO messages queued + in flight, default 8 (max 32) */
	unsigned send_timeout_ms;	/* one MO message, create + send + delete, default 120000 */
	unsigned incomplete_ms;		/* an incomplete concatenated message is deleted after this, default 600000 */
	unsigned retry_ms;		/* delete retry and the pause between the first passes over kept messages, default 5000 */
	unsigned slow_retry_ms;		/* after DRAIN_PASSES (20) passes in a row: one pass per this, default 300000 */
	cssms_in_cb on_message;
	void *arg;
};
void cssms_cfg_defaults(struct cssms_cfg *c);

struct cssms;
/* listens on the line; NULL on OOM */
struct cssms *cssms_new(struct csline *line, const struct cssms_cfg *cfg);
/* fails every queued MO message (503) and frees; no callback of the incoming path afterwards */
void cssms_free(struct cssms *s);
void cssms_set_cfg(struct cssms *s, const struct cssms_cfg *cfg);

struct cssms_submit {
	const char *dest;		/* "+821012345678" / "01012345678" / "114" */
	const char *text;		/* UTF-8 */
	bool delivery_report;		/* ask for a status report */
	unsigned vp_minutes;		/* relative validity, 0 = network default */
};
struct cssms_result {
	int status;			/* 200 sent; else the code smsrelay answers with: 400 403 413 480 484 502 503 504 */
	char text[128];
	unsigned parts;			/* SMS parts of the message (estimate by the same rule as max_segments) */
};
typedef void (*cssms_done_cb)(void *arg, const struct cssms_result *r);
/*
 * Queue one MO message. 0: cb runs exactly once later from the event loop. Otherwise -errno and no callback:
 * -EINVAL (empty / not valid UTF-8: 400), -EDESTADDRREQ (bad number: 484), -E2BIG (too many parts: 413), -ENOTCONN (line not
 * usable: 480), -ENOBUFS (queue full: 503), -ENOMEM (503). cssms_status_of_errno() gives the code.
 */
int cssms_submit(struct cssms *s, const struct cssms_submit *q, cssms_done_cb cb, void *arg);
static inline int cssms_status_of_errno(int err)
{
	switch (err) {
	case -EINVAL: return 400;
	case -EDESTADDRREQ: return 484;
	case -E2BIG: return 413;
	case -ENOTCONN: return 480;
	default: return 503;
	}
}
/* SMS parts of a text by the rule used for max_segments; -1 if it is not valid UTF-8 */
int cssms_count_parts(const char *utf8);

struct cssms_status {
	bool drained;			/* the first drain of the current modem object is complete */
	unsigned work_len;		/* incoming objects waiting to be processed */
	unsigned incomplete;		/* concatenated messages waiting for their parts */
	unsigned mo_queue;
	unsigned rx_kept;		/* objects not taken in the last pass: they stay in the modem (a warning is logged above 20) */
	unsigned long rx_text, rx_data, rx_reports, rx_backlog, rx_dropped_incomplete, rx_deleted, rx_delete_failed, rx_overflow;
	unsigned long mo_ok, mo_failed;
	char last_error[160];
};
void cssms_get_status(const struct cssms *s, struct cssms_status *st);
#endif
