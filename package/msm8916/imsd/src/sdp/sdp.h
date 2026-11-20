/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SDP_SDP_H
#define IMSD_SDP_SDP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../util/addr.h"
#include "../util/buf.h"

/*
 * SDP (RFC 4566 / RFC 8866) parser and builder for the RTP audio subset
 * imsd needs. One structure serves both directions: sdp_parse() fills it,
 * the sdp_set_* / sdp_add_* calls build one, sdp_write() serialises it.
 *
 * Storage is fixed (no malloc): every string lives in the pool inside
 * struct sdp and is referred to by a 16-bit offset (sdp_str), so a struct
 * sdp may be copied with plain assignment. Explicit limits, reported as
 * SDP_E_LIMIT and never truncated:
 *   SDP_MAX_MEDIA media sections, SDP_MAX_FMT formats per section,
 *   SDP_MAX_ATTR uninterpreted attributes per section / session,
 *   SDP_MAX_LINE bytes per line, SDP_POOL_SIZE bytes of string data in total.
 * The struct is about 13 KiB: keep it off small thread stacks.
 */
#define SDP_MAX_MEDIA	4
#define SDP_MAX_FMT	32
#define SDP_MAX_ATTR	64
#define SDP_MAX_LINE	512
#define SDP_POOL_SIZE	8192

enum sdp_err {
	SDP_OK = 0,
	SDP_E_ARG = -1,		/* NULL / bad argument */
	SDP_E_SYNTAX = -2,	/* malformed line, missing v=, NUL byte ... (see sdp->err_line) */
	SDP_E_RANGE = -3,	/* number out of range (payload type, port, ptime ...) */
	SDP_E_LIMIT = -4,	/* more media / formats / attributes / bytes than the limits above */
	SDP_E_ADDR = -5,	/* connection address is not an IPv4/IPv6 literal */
	SDP_E_OVERFLOW = -6,	/* builder: output buffer overflowed */
};

const char *sdp_strerror(int err);

/* offset into sdp.pool; 0 is the empty string */
typedef uint16_t sdp_str;

enum sdp_dir {
	SDP_DIR_NONE = 0,	/* attribute absent (means sendrecv) */
	SDP_DIR_SENDRECV,
	SDP_DIR_SENDONLY,
	SDP_DIR_RECVONLY,
	SDP_DIR_INACTIVE,
};

struct sdp_conn {
	bool present;
	struct addr addr;	/* address only, port 0 */
};

/* bandwidth lines, -1 when absent (kbit/s for AS, bit/s for RS / RR) */
struct sdp_bw {
	int32_t as, rs, rr;
};

struct sdp_fmt {
	int pt;			/* 0..127 */
	sdp_str enc;		/* encoding name from a=rtpmap or the RFC 3551 static table; 0 if unknown */
	uint32_t clock;		/* Hz, 0 if unknown */
	uint8_t channels;	/* 0 = not stated (1 for audio) */
	bool has_rtpmap;	/* a=rtpmap was present (false: filled from the static table or unknown) */
	sdp_str fmtp;		/* raw a=fmtp parameter string, 0 if none */
};

/* an attribute kept as received: a=name[:value], order preserved (a=curr, a=des, a=conf, a=candidate ...) */
struct sdp_attr {
	sdp_str name;
	sdp_str value;		/* 0 when has_value is false */
	bool has_value;
};

struct sdp_media {
	sdp_str type;		/* "audio", "video", ... */
	sdp_str proto;		/* "RTP/AVP", ... */
	uint16_t port;		/* 0: the stream is rejected / disabled */
	uint16_t nports;	/* /n of the m= line, 0 when absent */
	bool rtp;		/* proto starts with "RTP/": fmt[] holds the payload types */
	sdp_str raw_fmts;	/* non-RTP protocols: the format list as one string */
	struct sdp_fmt fmt[SDP_MAX_FMT];
	int nfmt;
	struct sdp_conn conn;	/* media level c= (overrides the session one) */
	struct sdp_bw bw;
	int ptime, maxptime;	/* ms, 0 = absent */
	enum sdp_dir dir;	/* explicit media level direction, SDP_DIR_NONE if absent */
	int rtcp_port;		/* a=rtcp, 0 = absent */
	bool has_rtcp_addr;
	struct addr rtcp_addr;
	struct sdp_attr attr[SDP_MAX_ATTR];
	int nattr;
};

struct sdp_origin {
	char user[32];		/* "-" if unknown */
	uint64_t sess_id;
	uint64_t version;
};

struct sdp {
	struct sdp_origin o;
	bool o_addr_ok;		/* o= carried an IP literal (false for host names) */
	struct addr o_addr;
	sdp_str name;		/* s= */
	struct sdp_conn conn;	/* session level c= */
	struct sdp_bw bw;	/* session level b= */
	enum sdp_dir dir;	/* session level direction */
	struct sdp_attr attr[SDP_MAX_ATTR];
	int nattr;
	struct sdp_media media[SDP_MAX_MEDIA];
	int nmedia;
	int err_line;		/* after a failed sdp_parse: 1-based line number */
	uint16_t pool_len;
	char pool[SDP_POOL_SIZE];
};

/* ---- parsing ---------------------------------------------------------- */

/*
 * Parse an SDP body (not necessarily NUL terminated; CRLF, LF and trailing
 * blanks are accepted, blank lines ignored, unknown line types ignored).
 * v=0 must be the first line; o=, s=, t= and c= may be missing. Static
 * payload types without a=rtpmap (0 PCMU, 3 GSM, 4 G723, 8 PCMA, 9 G722, 13 CN,
 * 18 G729 ...) get their RFC 3551 name and clock; a=ptime / a=maxptime at session
 * level are inherited by media sections that have none. Attributes that are
 * not interpreted (everything but direction, rtpmap, fmtp, ptime, maxptime,
 * rtcp) are kept in order in attr[]; so are rtpmap / fmtp lines that name a
 * payload type not in the m= line.
 * Returns 0 or SDP_E_*; on failure the content of *s is unspecified except
 * s->err_line.
 */
int sdp_parse(struct sdp *s, const char *body, size_t len);

/* ---- accessors -------------------------------------------------------- */

const char *sdp_get(const struct sdp *s, sdp_str ref);		/* never NULL */
const char *sdp_media_type(const struct sdp *s, const struct sdp_media *m);
const char *sdp_media_proto(const struct sdp *s, const struct sdp_media *m);
const char *sdp_fmt_enc(const struct sdp *s, const struct sdp_fmt *f);
const char *sdp_fmt_fmtp(const struct sdp *s, const struct sdp_fmt *f);	/* "" if none */
const struct sdp_fmt *sdp_media_find_fmt(const struct sdp_media *m, int pt);
/* first uninterpreted attribute with this name (case sensitive) or NULL */
const struct sdp_attr *sdp_media_find_attr(const struct sdp *s, const struct sdp_media *m, const char *name);
const struct sdp_attr *sdp_find_attr(const struct sdp *s, const char *name);	/* session level */
/* media's own direction, else the session's, else SENDRECV */
enum sdp_dir sdp_media_dir(const struct sdp *s, const struct sdp_media *m);
/* connection of a media section (media c= overrides session c=), NULL if neither exists */
const struct sdp_conn *sdp_media_conn(const struct sdp *s, const struct sdp_media *m);
/* true for c=IN IP4 0.0.0.0 / IN IP6 :: (RFC 2543 style hold) */
bool sdp_conn_is_any(const struct sdp_conn *c);
const char *sdp_dir_name(enum sdp_dir d);

/* Direction helpers. dir NONE counts as sendrecv. */
bool sdp_dir_sends(enum sdp_dir d);
bool sdp_dir_recvs(enum sdp_dir d);
enum sdp_dir sdp_dir_make(bool sends, bool recvs);
/* the other party's view of a direction: sendonly <-> recvonly, others unchanged */
enum sdp_dir sdp_dir_flip(enum sdp_dir d);

/* ---- fmtp key/value access --------------------------------------------- */

/*
 * fmtp strings are ';' separated key=value lists ("octet-align=0; mode-set=7")
 * or a bare value ("0-15"). Keys compare case-insensitively, blanks around
 * keys and values are ignored.
 *
 * Copy the value of key into out (NUL terminated): 0 = found, -1 = not
 * found, -2 = out too small (nothing is truncated). A key without "=" yields
 * an empty value.
 */
int sdp_fmtp_get(const char *fmtp, const char *key, char *out, size_t outsz);
/* integer value of key: 0 = found, -1 = absent, -2 = not a (non-negative decimal) number */
int sdp_fmtp_get_int(const char *fmtp, const char *key, long *val);
/* true if fmtp is a bare value (no '=' at all), e.g. telephone-event "0-15" */
bool sdp_fmtp_is_bare(const char *fmtp);

/* ---- building --------------------------------------------------------- */

/* empty description: v=0, no origin address, no media. */
void sdp_init(struct sdp *s);
/* o= line. The address family of addr selects IP4 / IP6; user "" becomes "-". */
int sdp_set_origin(struct sdp *s, const char *user, uint64_t sess_id, uint64_t version, const struct addr *addr);
int sdp_set_name(struct sdp *s, const char *name);	/* s=, default "-" when written empty */
/* session level c= taken from addr (port ignored) */
void sdp_set_conn(struct sdp_conn *c, const struct addr *addr);
void sdp_set_conn_any(struct sdp_conn *c, bool v6);	/* 0.0.0.0 / :: */
/* add a media section; returns it or NULL (SDP_E_LIMIT / pool full) */
struct sdp_media *sdp_add_media(struct sdp *s, const char *type, uint16_t port, const char *proto);
/*
 * Append a payload type to a RTP media section. enc may be NULL (unknown),
 * clock 0 = unknown, channels 0 = not written, fmtp NULL = none.
 * Returns 0 or SDP_E_RANGE / SDP_E_LIMIT.
 */
int sdp_add_fmt(struct sdp *s, struct sdp_media *m, int pt, const char *enc, uint32_t clock, int channels,
		const char *fmtp);
/* non-RTP media section: set the raw format list (e.g. for a rejected section copied from an offer) */
int sdp_media_set_raw_fmts(struct sdp *s, struct sdp_media *m, const char *fmts);
/* append an uninterpreted attribute (value NULL: a=name) to a media section / the session */
int sdp_media_add_attr(struct sdp *s, struct sdp_media *m, const char *name, const char *value);
int sdp_add_attr(struct sdp *s, const char *name, const char *value);
/* set the direction attribute of a media section */
void sdp_media_set_dir(struct sdp_media *m, enum sdp_dir d);
/* replace a section's fmtp */
int sdp_fmt_set_fmtp(struct sdp *s, struct sdp_fmt *f, const char *fmtp);

/*
 * Serialise with CRLF line ends: v= o= s= [c=] [b=] t=0 0 [session attrs], then
 * per media m= [c=] [b=] a=rtpmap/fmtp per format, ptime, maxptime, rtcp, direction,
 * other attributes in their original order. The address family of every
 * c= / o= line follows its address. Returns 0 or SDP_E_OVERFLOW (the buf
 * overflow flag is set, nothing partial should be used).
 */
int sdp_write(const struct sdp *s, struct buf *out);

/*
 * Session version handling for a re-offer / re-answer. next is a description
 * about to be sent for the same session as prev (the last one we sent): copies
 * user and sess_id from prev and sets version = prev.version, plus one if the
 * content differs from prev (everything but o= is compared). Returns 0, or
 * SDP_E_OVERFLOW (cannot serialise).
 */
int sdp_origin_succeed(struct sdp *next, const struct sdp *prev);
#endif
