/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_TEST_CSU_FAKE_H
#define IMSD_CS_TEST_CSU_FAKE_H
#include "../csline.h"

/*
 * Scripted uqmid for the tests: implements struct csu_ops with the semantics of uqmid/voice.c, messaging.c and sms.c as
 * far as the CS backend depends on them (object creation order of notifications and replies, error replies, ended objects
 * stay until deleted). Requests complete from the fake event loop (evfake_advance), never inside call().
 */
#define FK_CALLS 16
#define FK_SMS 160
#define FK_DIG 64

struct fk_call {
	bool used;
	char path[64], state[16], reason[24], dir[12], number[64];
	int qid, end_cause;
	int er_value;			/* end_reason.value / .name reported by get and by the terminated notification */
	char er_name[32];
};

struct fk_sms {
	bool used;
	char path[64], state[12], pdu[16], number[64], text[2048], ts[32], dts[32];
	bool has_text, has_data, multipart;
	uint8_t data[300];
	size_t dlen;
	int cls, maxp, parts;
	unsigned msgref, dstate;
	/* what happens when it is sent */
	int send_err;			/* enum csu_err */
	char send_name[32], send_msg[160];
};

struct fk_fail {			/* inject: the next `count` requests of an op fail */
	int count, err;
	char name[32], msg[160];
};

struct fk {
	struct csline *line;
	bool watch;
	char watched[64];
	char modem[64], device[96];
	char mstate[16], reg[28], act[40], opcode[8], opname[40], own[24];
	bool emerg, modem_listed, list_two;
	struct fk_call call[FK_CALLS];
	struct fk_sms sms[FK_SMS];
	unsigned next_call, next_sms;
	int n[24];			/* requests per csu_op */
	int n_inflight;
	struct fk_fail fail[24];
	unsigned delay_ms[24];		/* completion delay per op (0 = next loop iteration) */
	bool hold[24];			/* park the replies of this op until fk_release() */
	char dig[FK_DIG];
	int ndig;
	bool dtmf_busy_once;
	char last_create_num[64];
	char last_text[2048], last_dest[64];
	char order[512];		/* "C" create, "S" start, "A" accept, "H" hangup, "D" delete ... in order of arrival */
	int cancelled;
	bool notify_before_reply;
};
extern struct fk FK;

void fk_reset(struct csline *line);
const struct csu_ops *fk_ops(void);
/* the world */
struct fk_call *fk_find_call(const char *path);
struct fk_sms *fk_find_sms(const char *path);
int fk_live_calls(void);			/* objects that exist */
struct fk_call *fk_net_ring(const char *number);	/* a call arrives: object ringing-in, voice.call_added */
void fk_net_state(const char *path, const char *state, const char *reason);	/* the network changes a call: state + notification */
void fk_net_state_quiet(const char *path, const char *state);
void fk_set_end(const char *path, int cc_cause, int er_value, const char *er_name);	/* what the next terminated notification / get reports */	/* ... without a notification (lost) */
void fk_notify(const char *method, const char *path, const char *old, const char *nw, const char *reason, bool received);
struct fk_sms *fk_net_sms(const char *number, const char *text, bool notify);	/* received single message */
struct fk_sms *fk_net_sms_part(const char *number, int max_parts, int got);	/* first part of a concatenated message: state receiving */
void fk_net_sms_complete(struct fk_sms *s, const char *text);
void fk_release(int op);			/* complete the parked replies of an op */
void fk_fail_next(int op, int count, int err, const char *name, const char *msg);
void fk_modem_state(const char *state, const char *reg, const char *act, bool notify);
void fk_modem_add(void);			/* uqmid announces the modem (state as set) */
void fk_modem_remove(void);
#endif
