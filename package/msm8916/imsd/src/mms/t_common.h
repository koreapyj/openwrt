/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_T_COMMON_H
#define IMSD_MMS_T_COMMON_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../test/test.h"
#include "../test/evloop_fake.h"
#include "dns.h"
#include "http.h"
#include "mms.h"
#include "mmsbearer.h"
#include "netio.h"

void test_mms_codec(void);
void test_mms_net(void);
void test_mms_mgr(void);
void test_mms_flow(void);
void test_mms_proxy(void);
void test_mms_robust(void);
void test_mms_store(void);
void test_mms_bearer(void);
void test_mms_cs(void);

/* ---- the on-demand bearer rig (t_bearer.c): a real mmsb on a fake uqmid, fake rtnetlink, fake nft ---- */
struct brig {
	struct mmsb *b;
	/* behaviour */
	int connect_fail_n;		/* the first n connects fail */
	int create_fail_n;
	bool exec_fail_install, exec_fail_arm, exec_fail_gate, exec_fail_poll;
	int net_apply_rc;
	bool v6;			/* the bearer has an IPv6 address as well */
	bool prof_ok;
	char apn[64], ip_type[16];
	char modem[64];
	char imsi[24];
	char plmn[8];
	bool voice_call;
	unsigned disc_delay_ms, connect_delay_ms;
	char foreign_path[64];		/* "" = none: a bearer that someone else (netifd) connected */
	char foreign_apn[64], foreign_if[16];
	bool create_returns_foreign;	/* uqmid's find-matching: create_bearer answers with the foreign bearer */
	char marker_modem[64], marker_bearer[64];	/* the marker file */
	char leftover_path[64];		/* a bearer of an earlier run that still exists (connected) */
	/* observation */
	char log[4096];
	int created, max_live, live;
	bool foreign_touched;
	unsigned long acc, drp;		/* what the fake nft reports */
	int changed_n;
	struct netcfg_params last_net;
	void (*on_changed)(void *arg);
	void *on_changed_arg;
	void *priv;
};
struct brig *brig_new(void);
void brig_free(struct brig *r);
/* the link as the MMS manager reads it (struct mms_ops.link / want / gate) */
void brig_mms_link(struct brig *r, struct mms_link *out);


size_t hexv(const char *hex, uint8_t *out, size_t max);

/* run the fake loop: timers due now and readable / writable fds, until nothing happens (at most n rounds) */
void spin(int n);
/* called at the start of every spin round (the store tests drain the store's inline file backend here) */
extern void (*spin_hook)(void);
/* advance virtual time in steps, spinning after each */
void advance(unsigned ms);

/* ---- byte builder ---- */
struct pb {
	uint8_t d[16384];
	size_t n;
};
void pb_u8(struct pb *p, unsigned v);
void pb_add(struct pb *p, const void *d, size_t n);
void pb_text(struct pb *p, const char *s);		/* with the NUL */
void pb_uintvar(struct pb *p, uint32_t v);
void pb_long(struct pb *p, uint64_t v);			/* Long-integer */

/* Content-type-value encoders */
size_t ct_wk(uint8_t *out, unsigned code);						/* well-known media, constrained form */
size_t ct_wk_charset(uint8_t *out, unsigned code, unsigned mib);			/* value-length, media, charset parameter */
size_t ct_text(uint8_t *out, const char *type);					/* text media, constrained form */
/* append one multipart entry (HeadersLen DataLen ContentType Headers Data) to e */
void mp_entry(struct pb *e, const uint8_t *ct, size_t ctl, const uint8_t *hdrs, size_t hl, const void *data, size_t dl);
/* the part headers Content-ID "<id>" and Content-Location */
size_t ph_cid_loc(uint8_t *out, const char *cid, const char *loc);
/* a Content-Disposition attachment header with a filename */
size_t ph_disp_file(uint8_t *out, const char *fname);

/* m-retrieve-conf: headers, then Content-Type ct (ctl bytes) and body */
void build_retrieve(struct pb *p, const char *tid, unsigned version, const char *from, const char *subject_utf8,
		    int64_t date, const uint8_t *ct, size_t ctl, const void *body, size_t bl);
/* multipart: nEntries + entries */
void build_multipart(struct pb *out, unsigned n, const struct pb *entries);
/* a WSP push PDU carrying an MMS PDU */
void build_push(struct pb *p, const void *mms, size_t n);
/* m-notification-ind (as a bare MMS PDU) */
void build_notif(struct pb *p, const char *tid, unsigned version, const char *from, const char *subject_utf8, uint32_t size,
		 int expiry_rel_s, const char *url);

/* ---- mock sockets ---- */
#define MN_MAX_CONN	160
#define MN_MAX_UDP	32
struct mock_resp {
	const uint8_t *d;
	size_t n;
	bool eof;		/* close after the data */
	size_t step;		/* bytes per recv call, 0 = all */
	int connect_rc;		/* 0, -ECONNREFUSED ..., -EINPROGRESS (pending forever) */
	bool silent;		/* never answer */
};
struct mock_dns_rule {
	const char *name;
	int type;		/* 1 or 28 */
	int rcode;
	struct addr addr[4];
	int n;
	uint32_t ttl;
	int ignore;		/* silently drop the first `ignore` queries */
	const char *cname;	/* answer with name -> cname -> addresses */
	bool tc;
};
struct mocknet {
	struct net_ops ops;
	int fa[MN_MAX_CONN + MN_MAX_UDP], fb[MN_MAX_CONN + MN_MAX_UDP];
	int n_fd;
	/* udp */
	struct { struct addr dst; uint8_t d[1500]; size_t n; char netdev[16]; struct addr local; } usent[MN_MAX_UDP];
	int n_usent;
	struct { struct addr src; uint8_t d[1500]; size_t n; int fd; } uin[MN_MAX_UDP];
	int uin_head, uin_tail;
	struct mock_dns_rule dns[24];
	int n_dns;
	int udp_open_rc;	/* negative errno to fail udp_open with */
	struct addr udp_local;	/* what the last udp_open was asked to bind to */
	char udp_netdev[16];
	/* tcp */
	struct {
		int fd;
		struct addr dst, local;
		char netdev[16];
		uint8_t *sent;
		size_t sent_n;
		struct mock_resp resp;
		size_t rx_pos;
		bool armed, closed;
		bool has_resp;
	} conn[MN_MAX_CONN];
	int n_conn;
	struct mock_resp responses[MN_MAX_CONN];	/* the n-th connection gets responses[n] */
	int n_responses;
	int tcp_open_rc;
	int tcp_open_fail_n;	/* the first n tcp_connect calls fail with tcp_open_rc */
	int n_closed;
};
void mock_init(struct mocknet *m);
void mock_free(struct mocknet *m);
/* forget the connections and scripted responses (frees what was recorded) */
void mock_reset_conns(struct mocknet *m);
/* add a response for the next connection */
void mock_respond(struct mocknet *m, const struct mock_resp *r);
/* HTTP response text with Content-Length and the body */
size_t http_ok(uint8_t *out, size_t cap, int status, const char *ctype, const void *body, size_t bl);
/* the request bytes sent over connection i as text (NUL terminated) */
const char *mock_req(const struct mocknet *m, int i);
/* index of the first byte after the header block of connection i's request, 0 if none */
const uint8_t *mock_req_body(const struct mocknet *m, int i, size_t *n);
void mock_dns_add(struct mocknet *m, const struct mock_dns_rule *r);
/* DNS response builder for the tests */
struct dns_rr_spec {
	int type;
	uint32_t ttl;
	const uint8_t *rdata;
	size_t rdlen;
	const char *cname_target;	/* type 5: the target name, written in full (labels) */
	int owner_ref;			/* -1 the question name (pointer), >= 0 the target of the CNAME RR with that index (pointer) */
};
size_t dns_response(const uint8_t *q, size_t qn, int rcode, bool tc, const struct dns_rr_spec *rr, int nrr, uint8_t *out, size_t cap);
/* the qname (dotted, lower case) and type of a query packet; 0 / -1 */
int dns_qinfo(const uint8_t *q, size_t n, char *name, size_t nl, int *type, unsigned *id);
#endif
