/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_MMSPDU_H
#define IMSD_MMS_MMSPDU_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "wsp.h"

/*
 * MMS PDUs of OMA-TS-MMS_ENC-V1_2 (header field encoding of section 7, header values of 7.3): decoding of
 * M-Notification.ind and M-Retrieve.conf, encoding of M-NotifyResp.ind and M-Acknowledge.ind. All text results
 * are UTF-8, addresses lose their "/TYPE=PLMN" suffix. Pure functions, strict bounds checks, no allocation.
 */

#define MMS_ID_MAX	96
#define MMS_URL_MAX	512
#define MMS_ADDR_MAX	96
#define MMS_SUBJ_MAX	256
#define MMS_MAX_PARTS	32
#define MMS_MAX_RCPT	8
#define MMS_HEAD_RCPT	20

/* X-Mms-Message-Type */
enum {
	MMS_T_SEND_REQ = 0x80, MMS_T_SEND_CONF = 0x81, MMS_T_NOTIFICATION_IND = 0x82, MMS_T_NOTIFYRESP_IND = 0x83,
	MMS_T_RETRIEVE_CONF = 0x84, MMS_T_ACKNOWLEDGE_IND = 0x85, MMS_T_DELIVERY_IND = 0x86,
};
/* X-Mms-Status (M-NotifyResp.ind) */
enum {
	MMS_ST_EXPIRED = 0x80, MMS_ST_RETRIEVED = 0x81, MMS_ST_REJECTED = 0x82, MMS_ST_DEFERRED = 0x83,
	MMS_ST_UNRECOGNISED = 0x84, MMS_ST_INDETERMINATE = 0x85, MMS_ST_FORWARDED = 0x86, MMS_ST_UNREACHABLE = 0x87,
};
#define MMS_VERSION_1_0 0x90
#define MMS_VERSION_1_2 0x92

struct mms_notif {
	char tid[MMS_ID_MAX];
	uint8_t version;		/* wire value of the Short-integer (0x92 = 1.2), 0 when absent */
	char from[MMS_ADDR_MAX];	/* "" when absent / hidden */
	char subject[MMS_SUBJ_MAX];
	int msg_class;			/* 0 personal, 1 advertisement, 2 informational, 3 auto, -1 absent / other */
	bool has_size;
	uint32_t size;			/* X-Mms-Message-Size */
	bool has_expiry;
	bool expiry_relative;
	int64_t expiry;			/* seconds: relative to receipt, or absolute (Unix time) */
	char location[MMS_URL_MAX];	/* X-Mms-Content-Location */
	int delivery_report;		/* -1 absent, 0 no, 1 yes */
};
/* Decode a PDU (the body of the push, after the WSP headers). 0, or -1 when it is not a well formed m-notification-ind with a transaction id and a content location */
int mms_decode_notification(const uint8_t *d, size_t n, struct mms_notif *out);

struct mms_part {
	char type[96];			/* "text/plain" ... */
	int charset;			/* MIBenum, 0 absent */
	char content_id[WSP_NAME_MAX];	/* without the <> */
	char location[WSP_NAME_MAX];	/* Content-Location */
	char filename[WSP_NAME_MAX];	/* filename / name parameter of the type or of Content-Disposition, "" when none */
	int disposition;		/* -1 none, 0 form-data, 1 attachment, 2 inline */
	const uint8_t *data;		/* points into the input */
	size_t len;
};

struct mms_retrieve {
	char tid[MMS_ID_MAX];
	bool has_tid;
	uint8_t version;
	char message_id[MMS_ID_MAX];
	bool has_date;
	int64_t date;			/* Unix time */
	char from[MMS_ADDR_MAX];
	bool from_hidden;		/* Insert-address-token: the network hides the sender */
	char to[MMS_MAX_RCPT][MMS_ADDR_MAX];
	int n_to;
	char cc[MMS_MAX_RCPT][MMS_ADDR_MAX];
	int n_cc;
	char subject[MMS_SUBJ_MAX];
	int priority;			/* 0 low, 1 normal, 2 high, -1 absent */
	int msg_class;
	int delivery_report, read_report;	/* -1 absent, 0 no, 1 yes */
	int retrieve_status;		/* X-Mms-Retrieve-Status, -1 absent (0x80 = ok) */
	struct wsp_ctype ct;		/* content type of the message body with its parameters */
	bool multipart;
	struct mms_part part[MMS_MAX_PARTS];
	unsigned nparts;
	unsigned parts_dropped;		/* entries beyond MMS_MAX_PARTS */
};
/* Decode an m-retrieve-conf. The parts point into d. 0, or -1 (not an m-retrieve-conf, truncated, malformed) */
int mms_decode_retrieve(const uint8_t *d, size_t n, struct mms_retrieve *out);

/* The header part of any MMS PDU (what the proxy needs to know of what an app sends and what the MMSC answers): the type, the transaction id,
 * the recipients and the subject of an M-Send.req, the response status and message id of an M-Send.conf. Reading stops at the
 * Content-Type (M-Send.req) or the end of the headers. */
struct mms_head {
	uint8_t type;
	char tid[MMS_ID_MAX];
	bool has_tid;
	uint8_t version;
	char message_id[MMS_ID_MAX];
	char rcpt[3][MMS_HEAD_RCPT][MMS_ADDR_MAX];	/* To, Cc, Bcc addresses (in this order), "/TYPE=..." removed; at most MMS_HEAD_RCPT each */
	int n_rcpt[3];
	bool rcpt_more;			/* more recipients than fit */
	char subject[MMS_SUBJ_MAX];
	int response_status;		/* X-Mms-Response-Status as sent (0x80 = OK), -1 absent */
	int status;			/* X-Mms-Status of an M-NotifyResp.ind (0x81 = Retrieved), -1 absent */
	bool has_content_type;
};
/* 0, or -1 (empty, no leading X-Mms-Message-Type, a header that does not parse) */
int mms_decode_head(const uint8_t *d, size_t n, struct mms_head *out);

/* Seconds of Date-values into text; the "number" of an address: "+82.../TYPE=PLMN" -> "+82...", "a@b/TYPE=..." kept as an e-mail address */
void mms_clean_address(const char *in, char *out, size_t n);

/* M-NotifyResp.ind: type, transaction id, version, status. Returns the length, 0 if cap is too small */
size_t mms_encode_notifyresp(const char *tid, uint8_t version, unsigned status, uint8_t *out, size_t cap);
/* M-Acknowledge.ind: type, transaction id, version. Returns the length, 0 if cap is too small */
/* An M-Notification.ind (the gateway's own announcement of a message it keeps): Message-Type, Transaction-ID, MMS-Version, From (NULL: the
 * insert-address token), Subject (UTF-8, NULL = none), Message-Class personal, Message-Size, Expiry (absolute Unix time, 0 = none),
 * Content-Location. Returns the length, 0 when it does not fit cap. */
size_t mms_encode_notification(const char *tid, uint8_t version, const char *from, const char *subject_utf8, uint32_t size, int64_t expiry,
			       const char *location, uint8_t *out, size_t cap);
size_t mms_encode_acknowledge(const char *tid, uint8_t version, uint8_t *out, size_t cap);
#endif
