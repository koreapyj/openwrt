/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SIP_MSG_H
#define IMSD_SIP_MSG_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../util/addr.h"
#include "../util/buf.h"

/*
 * SIP message parser and builder (RFC 3261 syntax), no SDP.
 *
 * Limits are explicit and reported with an error code, never truncated
 * silently: SIP_MAX_MSG bytes per message, SIP_MAX_HDRS header lines.
 */
#define SIP_MAX_MSG	65536
#define SIP_MAX_HDRS	96
#define SIP_BRANCH_LEN	40	/* buffer size for a generated branch */
#define SIP_MAGIC_COOKIE "z9hG4bK"

enum {
	SIP_E_NOMEM = -1,
	SIP_E_BAD = -2,		/* malformed start line */
	SIP_E_TOOBIG = -3,	/* larger than SIP_MAX_MSG or a field too long */
	SIP_E_TRUNC = -4,	/* Content-Length larger than the data we have */
	SIP_E_HDRS = -5,	/* more than SIP_MAX_HDRS header lines */
};

struct sip_hdr {
	const char *name;	/* as received (may be a compact form) */
	const char *val;	/* NUL terminated, trimmed, folded lines joined with one space */
};

struct sip_msg {
	bool is_resp;
	int status;		/* responses */
	char method[16];	/* requests */
	const char *ruri;	/* requests, NUL terminated */
	const char *reason;	/* responses ("" if absent) */
	struct sip_hdr hdr[SIP_MAX_HDRS];
	int nh;
	const uint8_t *body;	/* binary safe; always followed by a NUL byte */
	size_t body_len;
	char *buf;		/* owned copy; all pointers above point into it */
};

/*
 * Parse a datagram / framed message. The data is copied; the result owns it.
 * Body length follows Content-Length when present (excess bytes ignored,
 * shortage -> SIP_E_TRUNC), else the rest of the data. Returns 0 or SIP_E_*.
 */
int sip_parse(const uint8_t *data, size_t len, struct sip_msg *m);
void sip_msg_free(struct sip_msg *m);

/*
 * Stream framing (for a future TCP transport): length of the first complete
 * message in data (headers + Content-Length body), 0 if more data is needed,
 * -1 if the stream is broken or the message would exceed SIP_MAX_MSG.
 */
long sip_frame_len(const uint8_t *data, size_t len);

/* idx-th (0-based) header line called name (case-insensitive, compact forms i m e l c f s k t v accepted); NULL if absent */
const char *sip_hdr(const struct sip_msg *m, const char *name, int idx);
int sip_hdr_count(const struct sip_msg *m, const char *name);
bool sip_is_method(const struct sip_msg *m, const char *method);
/* default reason phrase for a status code ("Unknown" if not known) */
const char *sip_reason_phrase(int status);

/* ---- multi-value headers ---- */
struct sip_list {
	const struct sip_msg *m;
	const char *name;
	int hidx;
	const char *cur;
};
/* iterate over every comma separated element of every line called name (Via, Route, Record-Route, Contact ...) */
void sip_list_init(struct sip_list *it, const struct sip_msg *m, const char *name);
/* next element (trimmed, commas inside <> and quotes respected) copied to out. 1 = got one, 0 = end, -1 = does not fit (iteration stops) */
int sip_list_next(struct sip_list *it, char *out, size_t outsz);
/* same, over a single value string; *cursor starts at the value and advances */
int sip_split_next(const char **cursor, char *out, size_t outsz);

/* ---- generic ;name=value parameters ---- */
/* Look name up in a parameter string (";a=b;c=\"d\"" or " ; a=b"); value copied unquoted
 * ("" for a flag). 1 found, 0 not found, -1 value does not fit. */
int sip_params_get(const char *params, const char *name, char *out, size_t n);
/* same helper over a header value that is not a name-addr (Authorization, Security-*): parameters separated by ';' or ',' */
int sip_kv_get(const char *v, const char *name, char *out, size_t n);

/* ---- URIs ---- */
struct sip_uri {
	char scheme[8];		/* "sip" "sips" "tel" (lower case) */
	char user[128];		/* user part without parameters; the number for tel: */
	char host[128];		/* without brackets; "" for tel: */
	uint16_t port;		/* 0 if absent */
	char params[512];	/* raw, with leading ';' (e.g. ";transport=udp;lr" or ";phone-context=x") */
};
/* parse a bare URI (no <>) ; 0 or -1 (bad / field too long) */
int sip_uri_parse(const char *s, struct sip_uri *u);
/* "scheme:user@host:port;params"; IPv6 hosts bracketed. 0 or -1 if out too small */
int sip_uri_format(const struct sip_uri *u, char *out, size_t n);
/* ;name=value lookup in the URI parameters (same return as sip_params_get) */
int sip_uri_param(const struct sip_uri *u, const char *name, char *out, size_t n);

struct sip_nameaddr {
	char display[64];
	char uri[256];		/* without <> */
	char params[256];	/* header parameters after the URI, with leading ';' (tag, expires, +g.3gpp...) */
};
/* parse a From/To/Contact/Route-style value ("Name" <uri>;p=v  or  uri;p=v). 0 or -1 (bad / too long) */
int sip_nameaddr_parse(const char *v, struct sip_nameaddr *n);
/* the tag parameter of a From/To value; out = "" if none. 0, or -1 on parse error / overflow */
int sip_tag(const char *v, char *out, size_t n);
/* just the URI of a name-addr value, no <>. 0 / -1 */
int sip_uri_of(const char *v, char *out, size_t n);

/* ---- CSeq ---- */
int sip_cseq(const struct sip_msg *m, uint32_t *num, char *method, size_t msz);

/* ---- Via ---- */
#define SIP_VIA_BRANCH_MAX 256
struct sip_via {
	char transport[8];	/* "UDP" "TCP" (upper case) */
	char host[64];		/* sent-by host without brackets */
	uint16_t port;		/* 0 if absent */
	char branch[SIP_VIA_BRANCH_MAX];	/* networks use long branches (LG U+: ~90 chars) */
	char received[64];
	int rport;		/* -1 absent, 0 present without value, >0 value */
	char params[512];	/* all parameters, raw, leading ';' */
};
/* parse one Via element ("SIP/2.0/UDP host:port;branch=..;rport"). 0 / -1 */
int sip_via_parse(const char *v, struct sip_via *out);
/* topmost Via of m. 0 / -1 */
int sip_top_via(const struct sip_msg *m, struct sip_via *out);
/* Compose a Via value: sent-by is the advertised (addr,port). branch and rport(flag) as given; out like "SIP/2.0/UDP [::1]:5060;branch=...;rport" */
int sip_via_make(char *out, size_t n, const char *transport, const struct addr *sentby, const char *branch, bool rport);
/* new RFC 3261 branch ("z9hG4bK" + random) */
void sip_new_branch(char out[SIP_BRANCH_LEN]);

/* ---- builder ---- */
struct sip_req_parts {
	const char *method;
	const char *ruri;
	const char *via;	/* complete Via header value (see sip_via_make) */
	const char *from;	/* complete From value, tag included */
	const char *to;		/* complete To value */
	const char *call_id;
	uint32_t cseq;
	int max_forwards;	/* 0 -> 70 */
	const char *route;	/* optional: complete Route header lines ("Route: <..>\r\n" x N), may be NULL */
	const char *contact;	/* optional Contact value */
	const char *extra;	/* optional extra header lines, each ending in CRLF */
	const char *content_type; /* optional, only written when body_len > 0 */
	const uint8_t *body;
	size_t body_len;
};
/* Compose a request into out. Content-Length is computed. 0, or -1 if the buffer overflowed (see buf_ok). */
int sip_build_request(struct buf *out, const struct sip_req_parts *p);

struct sip_resp_parts {
	int status;
	const char *reason;	/* NULL -> sip_reason_phrase() */
	const char *to_tag;	/* added to To when the request's To has none (never for 100) */
	const char *contact;
	const char *extra;	/* extra header lines, each ending in CRLF */
	const char *content_type;
	const uint8_t *body;
	size_t body_len;
	const struct addr *src;	/* where the request came from: enables received=/rport= on the top Via (RFC 3261 18.2.1, RFC 3581); may be NULL */
};
/* Compose a response to req: Via (all, verbatim, top one patched), Record-Route (1xx/2xx), From, To, Call-ID, CSeq. 0 / -1 */
int sip_build_response(struct buf *out, const struct sip_msg *req, const struct sip_resp_parts *p);
#endif
