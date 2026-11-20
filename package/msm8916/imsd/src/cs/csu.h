/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_CSU_H
#define IMSD_CS_CSU_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Typed, asynchronous view of the part of the uqmid ubus API the circuit switched backend uses (voice calls,
 * messaging, modem state). Same contract as modem/uqmid.h (struct uq_ops): call() starts one request, the callback
 * runs exactly once, later, from the event loop (never from inside call()) unless the request is cancelled;
 * notifications arrive through the csline_ev_*() functions. cs/csubus.c implements it on libubus, tests use a
 * scripted fake (test/csu_fake.c). All request data is copied by call().
 *
 * Method / notification names and fields: uqmid/voice.c, messaging.c, sms.c, ubus.c, modem_3gpp.c (see cs/README in the
 * report; every use below carries its source line).
 */
#define CSU_PATH	64
#define CSU_MAX_MODEMS	4
#define CSU_MAX_PATHS	32	/* paths in one list result (call / sms objects); more are cut (a second list gets the rest) */
#define CSU_TEXT_MAX	2048	/* UTF-8 text of one received SMS; longer texts are cut and flagged */
#define CSU_DATA_MAX	1024	/* user data bytes of one received binary SMS */

enum csu_op {
	CSU_ENABLE,		/* obj: modem; flag: enable true; uqmid.modem.N enable (power on, 3gpp, messaging, voice; ubus.c:561, imsmodem does the same with manage_modem) */
	CSU_LIST,		/* uqmid.list                                        -> modems[]   (ubus.c:383) */
	CSU_MODEM_GET,		/* obj: modem; uqmid.modem.N get                      -> state, reg, operator ... (ubus.c:443) */
	CSU_CALL_CREATE,	/* obj: modem; str: number; voice_create_call        -> path       (voice.c:1231) */
	CSU_CALL_START,		/* obj: call; start (dials)                                    (voice.c:884) */
	CSU_CALL_ACCEPT,	/* obj: call; accept (answers a ringing-in call)               (voice.c:947) */
	CSU_CALL_HANGUP,	/* obj: call; hangup (ends / rejects / cancels)                (voice.c:1024) */
	CSU_CALL_GET,		/* obj: call; get                                    -> call_* fields (voice.c:392,411) */
	CSU_CALL_DTMF,		/* obj: call; str: digits; send_dtmf (500 ms per digit, only while active) (voice.c:1144) */
	CSU_CALL_DELETE,	/* obj: modem; str: call path; voice_delete_call (a running call is hung up first) (voice.c:1277) */
	CSU_CALL_LIST,		/* obj: modem; voice_list_calls                      -> paths[]    (voice.c:1206) */
	CSU_SMS_CREATE,		/* obj: modem; str: number, text | data; messaging_create -> path (messaging.c:861) */
	CSU_SMS_SEND,		/* obj: sms; send (completes when the network accepted every part) (sms.c:1063) */
	CSU_SMS_GET,		/* obj: sms; get                                     -> sms_* fields (sms.c:217,273) */
	CSU_SMS_DELETE,		/* obj: modem; str: sms path; messaging_delete     (messaging.c:965) */
	CSU_SMS_LIST,		/* obj: modem; messaging_list                        -> paths[]    (messaging.c:792) */
};

enum csu_err {
	CSU_OK = 0,
	CSU_E_TIMEOUT = -1,	/* no answer in time (ubus TIMEOUT, uqmid error "timeout") */
	CSU_E_GONE = -2,	/* object / method not found: the call object or the modem is gone (ubus NOT_FOUND; errname "not-found" or "aborted") */
	CSU_E_FAILED = -3,	/* uqmid says failed (errname "failed", errmsg has the QMI error text) */
	CSU_E_STATE = -4,	/* wrong state / not allowed (ubus PERMISSION_DENIED: errname "wrong-state", "unauthorized" ...) */
	CSU_E_CONN = -5,	/* no ubus connection / uqmid not running */
	CSU_E_BAD = -6,		/* unusable reply */
	CSU_E_ARGS = -7,	/* ubus INVALID_ARGUMENT (errname "invalid-args") */
	CSU_E_BUSY = -8,	/* errname "in-progress" */
};

struct csu_req {
	enum csu_op op;
	char obj[CSU_PATH];
	char str[CSU_PATH];		/* number / digits / path, see enum csu_op */
	const char *text;		/* CSU_SMS_CREATE: UTF-8 text (xor data) */
	const uint8_t *data;
	size_t data_len;
	int sms_class;			/* CSU_SMS_CREATE: -1 = none (class 0..3 otherwise) */
	bool flag;			/* CSU_ENABLE: enable (true) / disable */
	bool dra;			/* CSU_SMS_CREATE: delivery_report_request */
	unsigned validity_min;		/* CSU_SMS_CREATE: relative validity in minutes, 0 = network default */
};

struct csu_res {
	int err;			/* enum csu_err */
	char errname[32];		/* uqmid "error" ("wrong-state", "aborted", "timeout" ...) or "" */
	char errmsg[160];		/* uqmid "message" / ubus status text */
	/* CSU_LIST */
	struct { char path[CSU_PATH]; char device[96]; char state[16]; } modems[CSU_MAX_MODEMS];
	int n_modems;
	/* CSU_MODEM_GET */
	char state[16];			/* modem state: "enabled", "registered" ... (modem.c:78) */
	char power_state[8];
	char reg_state[28];		/* "home", "roaming", "home-sms-only" ... (modem_3gpp.c:130) */
	char operator_code[8];		/* "45006" */
	char operator_name[40];
	char act[40];			/* access technologies joined by ' ': "umts hspa" (modem_3gpp.c:176) */
	char own_number[24];		/* own_numbers[0] or "" */
	bool emergency_only;		/* voice.c:1603: the modem is not registered, only emergency calls */
	/* CSU_*_CREATE */
	char path[CSU_PATH];
	/* CSU_CALL_GET */
	char call_state[16];		/* unknown dialing ringing-out ringing-in active held waiting terminated (voice.c:112) */
	char call_reason[24];		/* state_reason (voice.c:120) */
	char call_dir[12];		/* incoming / outgoing / unknown */
	char call_number[48];		/* remote number as the network gave it, "" if none */
	int call_qmi_id;
	int end_cause;			/* uqmid "cc_cause" (TS 24.008 / Q.850 cause the network sent, 1..127), 0 when the modem gave none (uqmid r45) */
	int end_reason;			/* uqmid "end_reason".value: QMI call end reason (146 user-busy ...), 0 when absent */
	char end_reason_name[32];	/* "end_reason".name (libqmi nick, "unknown"), "" when absent */
	/* CSU_CALL_LIST / CSU_SMS_LIST */
	char paths[CSU_MAX_PATHS][CSU_PATH];
	int n_paths;
	/* CSU_SMS_GET */
	char sms_state[12];		/* unknown stored receiving received sending sent (sms.c:39) */
	char sms_pdu[16];		/* deliver submit status-report */
	char sms_number[48];
	char sms_timestamp[32];		/* ISO 8601 or "" */
	char sms_discharge[32];
	char sms_text[CSU_TEXT_MAX];
	bool sms_has_text;
	bool sms_text_cut;
	uint8_t sms_data[CSU_DATA_MAX];
	size_t sms_data_len;
	bool sms_has_data;
	int sms_class;			/* -1 none */
	bool sms_multipart;
	int sms_max_parts, sms_parts;
	unsigned sms_msgref;		/* message_reference */
	unsigned sms_delivery_state;	/* status report TP-Status */
};

typedef void (*csu_cb)(void *arg, const struct csu_res *res);

struct csu_ops {
	void *(*call)(void *ctx, const struct csu_req *rq, csu_cb cb, void *arg);
	void (*cancel)(void *ctx, void *handle);
	/* follow the notifications of one modem object (NULL path: none); the manager object is always followed */
	void (*watch_modem)(void *ctx, const char *path);
	void *ctx;
};

/* a notification of the modem object (uqmid names). Fields not used by a method are "". */
struct csu_notify {
	char method[32];	/* state_changed | registration_state_changed | voice.call_added | voice.call_state_changed | voice.call_deleted |
				 * messaging.added | messaging.state_changed | messaging.deleted | power_state_changed */
	char path[CSU_PATH];	/* call / sms object (voice.*, messaging.*) */
	char old_state[28];	/* "old" */
	char new_state[28];	/* "new" */
	char reason[24];	/* "reason" (state_changed, voice.call_state_changed) */
	bool received;		/* messaging.added: "received" */
	char operator_code[8], operator_name[40];	/* registration_state_changed */
	int cc_cause;		/* voice.call_state_changed with new == terminated: "cc_cause", 0 when absent (uqmid r45) */
	int end_reason;		/* ... "end_reason".value, 0 when absent */
	char end_reason_name[32];	/* ... "end_reason".name */
};
#endif
