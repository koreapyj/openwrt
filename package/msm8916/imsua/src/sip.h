/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IMSUA_SIP_H
#define IMSUA_SIP_H
#include <stddef.h>
#include <stdint.h>

#define SIP_MAXH 48

struct sip_msg {
	int is_resp;
	int status;
	char method[16];
	char ruri[256];
	char reason[64];
	char *name[SIP_MAXH];
	char *val[SIP_MAXH];
	int nh;
	const char *body;
	size_t body_len;
	char *buf;	/* owned copy; names/values point into it */
};

int sip_parse(const char *data, size_t len, struct sip_msg *m);
void sip_free(struct sip_msg *m);
/* idx-th (0-based) header with this name, case-insensitive; NULL if absent */
const char *sip_hdr(const struct sip_msg *m, const char *name, int idx);
/* CSeq number and method */
int sip_cseq(const struct sip_msg *m, uint32_t *num, char *method, size_t msz);
/* value of ;tag= in a From/To value, "" if none */
void sip_tag(const char *v, char *out, size_t n);
/* generic param (";name=value" or ", name=value" style); returns 1 if found, value copied (unquoted) */
int sip_param(const char *v, const char *name, char *out, size_t n);
/* first URI in <...> or the bare token; copies without brackets */
int sip_uri_of(const char *v, char *out, size_t n);
/* split a comma list header value (Record-Route); ignores commas inside <> and quotes */
int sip_split_list(const char *v, char out[][256], int max);

/* ---- Security-Server / Security-Client (RFC 3329 / TS 33.203) ---- */
struct sec_ent {
	char prot[16];
	char alg[24];
	char ealg[16];
	char mod[16];
	int has_q;
	double q;
	uint32_t spi_c, spi_s;
	int port_c, port_s;
	int ok;		/* alg and ealg are supported */
	int sha1;	/* alg is hmac-sha-1-96 */
};
int sec_parse(const char *hdrval, struct sec_ent *out, int max);
/* highest q among supported entries (first one wins ties); -1 if none */
int sec_select(const struct sec_ent *e, int n);

/* ---- digest AKAv1-MD5 (RFC 3310 / 2617, no qop); res is the raw RES ---- */
void digest_response(const char *user, const char *realm, const uint8_t *res, size_t reslen,
		     const char *nonce, const char *method, const char *uri, char out[33]);

/* ---- SDP ---- */
struct sdp_media {
	char ip[64];
	int port;
	int pt;		/* chosen audio payload type, -1 if none */
	int wb;		/* AMR-WB */
	int octet_align;
	int dtmf_pt;
	char enc[24];
};
int sdp_parse(const char *body, size_t len, struct sdp_media *out);

/* ---- small string builder ---- */
struct sbuf { char *p; size_t n, cap; int ovf; };
void sb_init(struct sbuf *b, char *p, size_t cap);
void sb_add(struct sbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#endif
