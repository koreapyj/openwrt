/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_GM_REG_H
#define IMSD_GM_REG_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "xfrm.h"
#include "../aka.h"
#include "../modem/imsmodem.h"
#include "../sip/msg.h"
#include "../sip/transport.h"
#include "../sip/txn.h"

/*
 * Gm registration state machine (TS 24.229 / 33.203 as the LG U+ network
 * does it), on top of the transaction layer and the endpoints.
 *
 * Everything that touches the system goes through struct reg_ops, so the
 * host tests drive the whole machine with mock endpoints, a mock xfrm and a
 * scripted AKA over the fake event loop.
 */

enum reg_state {
	RS_IDLE,		/* not enabled (manual deregistration) */
	RS_WAIT_LINK,		/* no usable IMS link (modem / bearer / P-CSCF missing) */
	RS_UNPROT,		/* unprotected REGISTER sent, waiting for the 401 */
	RS_AKA,			/* challenge received, the card computes RES / CK / IK */
	RS_SA_INSTALL,		/* installing the four SAs and policies (transient) */
	RS_PROT,		/* protected REGISTER sent */
	RS_REGISTERED,
	RS_REFRESH,		/* re-REGISTER on the existing SAs */
	RS_REAUTH,		/* full re-authentication while still registered */
	RS_DEREG,		/* REGISTER Expires 0 sent */
	RS_BACKOFF,		/* every P-CSCF failed, waiting */
};

/* last resort P-Access-Network-Info (the cell of the first captured registration), also the test vector */
#define REG_PANI_LEGACY "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EB3161703"
enum reg_pani_src { PANI_CONFIG, PANI_LIVE, PANI_DEFAULT };

struct reg_cfg {
	int pcscf_port;			/* 5060 */
	int expires;			/* requested registration time, 8000 */
	char pani[160];			/* P-Access-Network-Info override, "" = the serving cell (reg_ops.pani), else REG_PANI_LEGACY */
	char user_agent[96];		/* User-Agent on every request and response we originate, "" = none */
	unsigned port_min, port_max;	/* range for protected / unprotected ports */
	unsigned backoff_min_ms;	/* 5000 */
	unsigned backoff_max_ms;	/* 900000 */
	unsigned step_timeout_ms;	/* no answer to a REGISTER: 8000 */
	unsigned aka_timeout_ms;	/* 20000 */
	unsigned drain_ms;		/* old SAs stay this long after a re-authentication: 5000 */
	unsigned dereg_timeout_ms;	/* 2000 */
	unsigned next_pcscf_ms;		/* delay before trying the next P-CSCF: 200 */
	int max_dup_retries;		/* 406 PORT-C/S DUPLICATED retries per P-CSCF: 3 */
};
void reg_cfg_defaults(struct reg_cfg *c);

struct reg_ops {
	/* queue an AKA computation; cb runs exactly once later unless aka_cancel(ctx, arg) ran. 0 or -errno */
	int (*aka)(void *ctx, const uint8_t rand[16], const uint8_t autn[16], imsmodem_aka_cb cb, void *arg);
	void (*aka_cancel)(void *ctx, void *arg);
	int (*xfrm_install)(void *ctx, const struct xfrm_sa_params *p);
	void (*xfrm_remove)(void *ctx, const struct xfrm_sa_params *p);
	/* optional: the live P-Access-Network-Info of the serving cell ("" / NULL: unknown); used when reg_cfg.pani is empty */
	const char *(*pani)(void *ctx);
	struct sip_endpoint *(*open_ep)(void *ctx, const struct sip_ep_cfg *cfg);
	/*
	 * Shared transaction layer (optional). The daemon has ONE layer (src/core.c owns it and dispatches incoming
	 * requests by endpoint: the Gm ones go to reg_on_request / reg_on_stray below); reg only starts client
	 * transactions on it and attaches its endpoints. NULL: reg makes, runs and frees a private layer
	 * (host tests).
	 */
	struct txn_layer *tl;
	void *ctx;
};

enum reg_event {
	REG_EV_UP,		/* registered (first registration of this link) */
	REG_EV_DOWN,		/* registration lost or removed; every dialog and binding on it is gone */
	REG_EV_REPLACED,	/* re-authenticated: a new protected endpoint / SA set replaced the old one */
};
typedef void (*reg_hook_cb)(void *arg, enum reg_event ev, const char *reason);

struct reg;
struct reg *reg_new(const struct reg_cfg *cfg, const struct reg_ops *ops);
/* immediate release of everything without a de-registration (SAs removed, endpoints retired) */
void reg_free(struct reg *r);
/* the configuration changed; re-registers only if something relevant did. Returns true if it did restart. */
bool reg_set_cfg(struct reg *r, const struct reg_cfg *cfg);
/* the link published by imsmodem */
void reg_set_link(struct reg *r, const struct ims_link *l);
/* manual control: false = de-register now and stay idle, true = register as soon as a link exists */
void reg_set_enabled(struct reg *r, bool enabled);
/* De-register (REGISTER Expires: 0 on the protected endpoint, bounded by dereg_timeout_ms), release everything, then done runs once. The machine stays stopped. */
void reg_shutdown(struct reg *r, void (*done)(void *arg), void *arg);

/* ---- registered context, for the call / SMS layers ---- */
#define REG_MAX_SROUTE 8
struct reg_ctx {
	struct sip_endpoint *ep;	/* current protected endpoint (not referenced: take sip_ep_ref to keep it) */
	struct addr pcscf_ps;		/* the P-CSCF's protected server port: where requests go */
	const char *security_verify;	/* value for Security-Verify on every protected request */
	const char *service_route[REG_MAX_SROUTE];
	int n_service_route;
	const char *impu;		/* public identity we registered (From of our requests) */
	const char *assoc_uri;		/* first P-Associated-URI (default public identity), "" if none */
	const char *pani;		/* effective value at the time of the call (see reg_cfg.pani) */
	uint16_t port_c, port_s;
	int64_t expires_in_ms;
};
/* NULL unless registered (also valid while REFRESH / REAUTH) */
const struct reg_ctx *reg_context(const struct reg *r);
bool reg_is_registered(const struct reg *r);
/* "sip:user@[addr]:port-s": the Contact URI of the current registration. 0 / -1 */
int reg_contact_uri(const struct reg *r, char *out, size_t n);
/*
 * Extension point for the modules that take over incoming requests on the protected Gm endpoint (call
 * control, SMS relay). The table is consulted BEFORE the built-in behaviour; a handler returns true when it
 * took the request (it then owns the reply on st: txn_server_reply, and st stays valid until its
 * TXN_SRV_TERMINATED callback, see txn_server_set_cb) and false to let the next step run. Slots left NULL
 * and requests nobody takes keep the built-in behaviour: INVITE 480, MESSAGE application/vnd.3gpp.sms
 * RP-ACKed + counted (other types 415), BYE / INFO / UPDATE / PRACK 481, OPTIONS / NOTIFY 200, REGISTER /
 * SUBSCRIBE / REFER / PUBLISH 405, anything else 501. Requests on the unprotected endpoint never reach the
 * table (403). req is valid only during the call. Not consulted for CANCEL (the transaction layer answers it
 * and raises TXN_SRV_CANCELLED on the INVITE's st).
 *   on_invite     INVITE without To tag
 *   on_message    MESSAGE without To tag (any content type, SMS included)
 *   on_in_dialog  requests with a To tag, and BYE / UPDATE / INFO / PRACK / NOTIFY / REFER without one
 *   on_ack        ACK for a 2xx (no transaction); the return value is ignored
 */
struct reg_handlers {
	bool (*on_invite)(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
			  const struct sip_msg *req, void *arg);
	bool (*on_message)(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
			   const struct sip_msg *req, void *arg);
	bool (*on_in_dialog)(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
			     const struct sip_msg *req, void *arg);
	bool (*on_ack)(struct reg *r, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
		       const struct sip_msg *req, void *arg);
	void *arg;
};
/* Install (copied; NULL clears). */
void reg_set_handlers(struct reg *r, const struct reg_handlers *h);
/*
 * txn_request_cb / txn_stray_cb of the Gm side, for the owner of a shared transaction layer
 * (pass the struct reg as arg).
 */
void reg_on_request(struct txn_layer *tl, struct txn_server *st, struct sip_endpoint *ep, const struct addr *src,
		    const struct sip_msg *req, void *arg);
void reg_on_stray(struct txn_layer *tl, struct sip_endpoint *ep, const struct addr *src, const struct sip_msg *resp,
		  void *arg);

/* hooks (up to 4). 0 / -1 */
int reg_add_hook(struct reg *r, reg_hook_cb cb, void *arg);
void reg_remove_hook(struct reg *r, reg_hook_cb cb, void *arg);

/* request inside the registration (SMS RP-ACK now, INVITE etc. later) */
struct reg_req {
	const char *method;
	const char *ruri;
	const char *to;			/* complete To value, NULL: "<ruri>" */
	const char *call_id;		/* NULL: generated */
	uint32_t cseq;			/* 0: random */
	const char *contact;		/* optional Contact value */
	const char *extra;		/* header lines (CRLF each) put after P-Access-Network-Info / Security-Verify */
	const char *content_type;
	const uint8_t *body;
	size_t body_len;
};
/* status: final response status, or 0 on timeout / transport error (resp NULL then). resp is valid only during the call. */
typedef void (*reg_resp_cb)(void *arg, int status, const struct sip_msg *resp);
/* Send a request on the protected endpoint to the P-CSCF (From = our IMPU, Route = P-CSCF + Service-Route, P-Access-Network-Info, Security-Verify). 0, or -errno (-ENOTCONN: not registered) */
int reg_send(struct reg *r, const struct reg_req *q, reg_resp_cb cb, void *arg);

/* ---- status ---- */
struct reg_status {
	enum reg_state state;
	const char *state_name;
	bool registered;
	char reason[96];		/* waiting / last failure reason */
	char last_error[160];
	char impu[160], impi[128], domain[96];
	char pcscf[64];			/* the P-CSCF in use (or being tried) */
	int pcscf_port_s;
	enum pcscf_source pcscf_source;
	int port_c, port_s;
	int64_t expires_in_s;		/* -1 when not registered */
	int64_t registered_since_s;	/* -1 when not registered */
	unsigned attempts, successes, auth_failures, failures, sms_received, reauths, refreshes;
	char assoc_uri[256];
	char pani[160];			/* P-Access-Network-Info in use now */
	enum reg_pani_src pani_source;	/* where it comes from: explicit config, live cell, legacy default */
};
void reg_get_status(const struct reg *r, struct reg_status *s);
const char *reg_state_name(enum reg_state s);
const char *reg_pani_source_name(enum reg_pani_src s);
/* the User-Agent value of the configuration ("" = none), for the modules that build their own requests */
const char *reg_user_agent(const struct reg *r);
#endif
