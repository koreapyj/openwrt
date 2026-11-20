/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UA_TEST_UA_H
#define IMSD_UA_TEST_UA_H
#include <stdlib.h>
#include <string.h>
#include "../test/test.h"
#include "../test/fakeep.h"
#include "../test/evloop_fake.h"
#include "../util/log.h"
#include "lan.h"

void test_registrar(void);
void test_lan(void);
void test_fork(void);
void test_regpersist(void);

/* ---- shared fixture: one LAN endpoint on a fake network, a txn layer, a lan, recorders ---- */

#define MAXLOG 128
struct binding_ev {
	enum registrar_event ev;
	reg_id_t id;
	enum reg_removal why;
	char contact[256];
};

struct hook_rec {
	int invite, in_dialog, message, ack;
	bool last_registered;
	reg_id_t last_id;
	char last_method[16];
	struct txn_server *st;
	bool autoreply;		/* hooks answer 200 themselves */
};

struct uaw {
	struct fakeep *f;
	struct txn_layer *tl;
	struct lan *lan;
	struct binding_ev bev[MAXLOG];
	int nbev;
	struct hook_rec hk;
};

struct addr ua_addr(const char *ip, int port);
/* new world; cfg_tweak may be NULL, otherwise called with the lan_cfg before lan_new (hooks installed when with_hooks) */
void uaw_init(struct uaw *w, void (*tweak)(struct lan_cfg *c), bool with_hooks);
void uaw_fini(struct uaw *w);
/* inject a datagram from ip:port */
void uaw_rx(struct uaw *w, const char *ip, int port, const char *msg);
/* status code / method of sent[i] (0 / "" if parse fails) */
int sent_status(const struct fakeep *f, int i);
const char *sent_method(const struct fakeep *f, int i, char *out);
/* header value of sent[i] into out ("" if absent) */
const char *sent_hdr(const struct fakeep *f, int i, const char *name, char *out, size_t n);
/* index of the nth (0-based) sent request with that method to ip:port, -1 */
int find_sent(const struct fakeep *f, const char *ip, int port, const char *method, int nth);
int count_sent(const struct fakeep *f, const char *method);
/* index of the last response sent (status > 0), -1 */
int last_resp(const struct fakeep *f);

/*
 * REGISTER text. contact: complete Contact header value ("<sip:a@1.2.3.4:5060>;expires=60"), NULL for none.
 * expires_hdr < 0: no Expires header. extra: more header lines (CRLF terminated) or NULL.
 */
const char *mk_register(const char *src_ip, const char *contact, int cseq, const char *call_id, int expires_hdr,
			const char *extra);
/* Register device k (1..): contact sip:u<k>@192.168.68.<10+k>:5060 expires 600; returns its binding id */
reg_id_t dev_register(struct uaw *w, int k);
/* device k's source address text */
const char *dev_ip(int k);
/* answer sent[idx] (a request we sent to a device) as that device would: status, to tag (may be NULL), 2xx get a Contact */
void dev_reply_idx(struct uaw *w, int idx, int k, int status, const char *to_tag, const char *extra);
/* answer the first request with that method sent to device k; returns false if none */
bool dev_reply(struct uaw *w, int k, const char *method, int status, const char *to_tag);

/* ---- fork event recorder ---- */
struct fork_rec {
	struct {
		enum lan_fork_ev_type type;
		reg_id_t id;
		int status;
		enum lan_branch_cause cause;
		bool is_winner;
		reg_id_t winner;
		int nok;
		int nresults;
		struct lan_branch_result res[8];
		bool had_dlg;
	} ev[MAXLOG];
	int n;
	int count[8];
	struct sip_dialog dlg[8];	/* dialogs taken (WINNER / EXTRA_2XX), in order */
	int ndlg;
	bool take;
};
void fork_cb(struct lan_fork *f, struct lan_fork_event *ev, void *arg);
/* index of the first event of a type from position `from`, -1 */
int fr_find(const struct fork_rec *r, enum lan_fork_ev_type t, int from);
void fr_release(struct fork_rec *r);

/* an INVITE request for lan_fork_request */
void mk_invite_req(struct lan_req *q, const char *body);
#endif
