/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * imsua - AP side IMS/VoLTE UE proof of concept (IMS AKA + sec-agree IPsec,
 * REGISTER, one short test call, RTP capture).
 *
 * HARD LIMIT: a call never lasts 20 s or longer, see dialog.h.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <poll.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "util.h"
#include "sip.h"
#include "aka.h"
#include "ipsec.h"
#include "dialog.h"
#include "rtp.h"

#define EXIT_REG 2
#define EXIT_CALL 3
#define EXIT_CAP 4
#define EXIT_USAGE 64

struct cfg {
	char local_ip[64], netdev[32];
	char pcscf[8][64]; int npcscf;
	char impi[128], impu[128], domain[64], imei[40], pani[160];
	char user[64];
	char contact_tags[512], invite_tags[512];
	int port_un, port_c, port_s, port_rtp, pcscf_port;
	char outdir[256];
	char mode[16], number[64], phone_ctx[64];
	int hold, dereg, expires, call_secs, reg_retries, slot;
	char aid[48], modem[64], ubus_sock[128], rand_hex[40], autn_hex[40];
	int p2, cla_ch;
};

#define MAXTXN 8
struct txn {
	int act, answered, timeout;
	char callid[128], method[16];
	uint32_t cseq;
	char buf[3072];
	size_t len;
	int fd;
	struct sockaddr_in6 to;
	uint64_t next, start;
	uint32_t iv;
};

struct ua {
	struct cfg c;
	int fd_un, fd_uc, fd_us;
	struct rtp rtp;
	struct aka_ubus *aka;
	struct aka_cfg akac;

	char pcscf[64];
	struct sockaddr_in6 pc_un;	/* P-CSCF:5060 */
	struct sockaddr_in6 pc_ps;	/* P-CSCF:port-s */
	struct ipsec_sa sa; int sa_up;
	char sec_server[600];
	struct sec_ent chosen;
	int ps_port;

	char reg_callid[128]; uint32_t reg_cseq;
	char realm[96], nonce[200], opaque[100], auth_last[1024];

	struct txn txn[MAXTXN];
	char await_callid[128]; uint32_t await_cseq; char await_method[16];
	char resp_raw[8192]; size_t resp_len; int resp_valid;

	/* call */
	int in_call;
	struct call call;
	struct cap cap;
	uint64_t inv_t0;
	char callid[128], from_tag[24], inv_branch[40], inv_ruri[128], inv_route[160];
	char inv_from[200], inv_to[200];
	uint32_t cseq;
	char cap_buf[3072]; size_t cap_len; int cap_dlg;
	char ack_buf[3072]; size_t ack_len;
	int call_end;		/* 1 = call finished */
	int call_rc;
	struct sdp_media ans;
	int remote_bye;
};

static volatile sig_atomic_t g_stop;
static struct ua U;

static void on_sig(int s) { (void)s; g_stop = 1; }

/* ---- helpers ---- */
static void mk_sa(struct sockaddr_in6 *sa, const char *ip, int port)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin6_family = AF_INET6;
	sa->sin6_port = htons(port);
	inet_pton(AF_INET6, ip, &sa->sin6_addr);
}

static void new_branch(char *o, size_t n) { snprintf(o, n, "z9hG4bK%u", rnd32()); }

static int udp_sock(const struct cfg *c, int port)
{
	struct sockaddr_in6 a;
	int fd = socket(AF_INET6, SOCK_DGRAM, 0), one = 1;

	if (fd < 0) return -1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (c->netdev[0]) setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, c->netdev, strlen(c->netdev) + 1);
	mk_sa(&a, c->local_ip, port);
	if (bind(fd, (struct sockaddr *)&a, sizeof(a))) {
		ilog("bind [%s]:%d failed: %s", c->local_ip, port, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static void peer_str(const struct sockaddr_in6 *a, char *o, size_t n)
{
	char ip[64];

	inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof(ip));
	snprintf(o, n, "[%s]:%d", ip, ntohs(a->sin6_port));
}

static int send_sip(int fd, const struct sockaddr_in6 *to, const char *buf, size_t len)
{
	char p[100];
	ssize_t r = sendto(fd, buf, len, 0, (const struct sockaddr *)to, sizeof(*to));

	peer_str(to, p, sizeof(p));
	ilog_msg("SEND to", p, buf, len);
	if (r < 0) ilog("sendto %s failed: %s", p, strerror(errno));
	return r < 0 ? -1 : 0;
}

/* ---- transactions ---- */
static struct txn *txn_add(struct ua *u, const char *method, uint32_t cseq, const char *callid,
			   const char *buf, size_t len, int fd, const struct sockaddr_in6 *to)
{
	int i;

	for (i = 0; i < MAXTXN; i++) if (!u->txn[i].act) break;
	if (i == MAXTXN) return NULL;
	{
		struct txn *t = &u->txn[i];
		memset(t, 0, sizeof(*t));
		t->act = 1;
		strlcpy_(t->method, method, sizeof(t->method));
		strlcpy_(t->callid, callid, sizeof(t->callid));
		t->cseq = cseq;
		memcpy(t->buf, buf, len); t->len = len;
		t->fd = fd; t->to = *to;
		t->start = now_ms(); t->iv = 500; t->next = t->start + 500;
		send_sip(fd, to, buf, len);
		return t;
	}
}

static struct txn *txn_find(struct ua *u, const char *callid, uint32_t cseq, const char *method)
{
	int i;

	for (i = 0; i < MAXTXN; i++) {
		struct txn *t = &u->txn[i];
		if (t->act && t->cseq == cseq && !strcasecmp(t->method, method) && !strcmp(t->callid, callid))
			return t;
	}
	return NULL;
}

static void txn_tick(struct ua *u, uint64_t now)
{
	int i;

	for (i = 0; i < MAXTXN; i++) {
		struct txn *t = &u->txn[i];
		if (!t->act || t->answered) continue;
		if (now - t->start >= 32000) { t->act = 0; t->timeout = 1; ilog("transaction %s %u timed out", t->method, t->cseq); continue; }
		if (now >= t->next) {
			ilog("retransmit %s %u", t->method, t->cseq);
			send_sip(t->fd, &t->to, t->buf, t->len);
			t->iv = t->iv * 2 > 4000 ? 4000 : t->iv * 2;
			t->next = now + t->iv;
		}
	}
}

/* ---- message building ---- */
static void std_via(struct ua *u, struct sbuf *b, int port, const char *branch)
{
	sb_add(b, "Via: SIP/2.0/UDP [%s]:%d;branch=%s\r\n", u->c.local_ip, port, branch);
}

static const char *ALLOW_REG = "INVITE,BYE,CANCEL,ACK,NOTIFY,UPDATE,PRACK,INFO,MESSAGE,OPTIONS";

static size_t build_register(struct ua *u, char *out, size_t cap, int protected_, int expires,
			     const char *response, const char *auts)
{
	struct sbuf b;
	char branch[40], tag[24], auth[1024], route[128];
	int port = protected_ ? u->c.port_s : u->c.port_un;

	sb_init(&b, out, cap);
	new_branch(branch, sizeof(branch));
	snprintf(tag, sizeof(tag), "%u", rnd32());
	snprintf(route, sizeof(route), "<sip:[%s]:%d;lr>", u->pcscf, protected_ ? u->ps_port : u->c.pcscf_port);
	if (response) {
		char opq[128] = "";
		if (u->opaque[0]) snprintf(opq, sizeof(opq), "opaque=\"%s\",", u->opaque);
		if (auts)	/* resync: empty response plus auts */
			snprintf(auth, sizeof(auth), "Digest username=\"%s\",realm=\"%s\",uri=\"sip:%s\",nonce=\"%s\",algorithm=AKAv1-MD5,%sauts=\"%s\",response=\"\"",
				 u->c.impi, u->realm, u->c.domain, u->nonce, opq, auts);
		else
			snprintf(auth, sizeof(auth), "Digest username=\"%s\",realm=\"%s\",uri=\"sip:%s\",nonce=\"%s\",algorithm=AKAv1-MD5,%sresponse=\"%s\"",
				 u->c.impi, u->realm, u->c.domain, u->nonce, opq, response);
	} else {
		snprintf(auth, sizeof(auth), "Digest uri=\"sip:%s\",username=\"%s\",response=\"\",realm=\"%s\",nonce=\"\"",
			 u->c.domain, u->c.impi, u->c.domain);
	}
	sb_add(&b, "REGISTER sip:%s SIP/2.0\r\n", u->c.domain);
	sb_add(&b, "From: <%s>;tag=%s\r\n", u->c.impu, tag);
	sb_add(&b, "To: <%s>\r\n", u->c.impu);
	sb_add(&b, "CSeq: %u REGISTER\r\n", ++u->reg_cseq);
	sb_add(&b, "Call-ID: %s\r\n", u->reg_callid);
	std_via(u, &b, port, branch);
	sb_add(&b, "Max-Forwards: 70\r\n");
	sb_add(&b, "Contact: <sip:%s@[%s]:%d>;%s\r\n", u->c.user, u->c.local_ip, port, u->c.contact_tags);
	sb_add(&b, "Route: %s\r\n", route);
	sb_add(&b, "P-Access-Network-Info: %s\r\n", u->c.pani);
	if (protected_) sb_add(&b, "Security-Verify: %s\r\n", u->sec_server);
	sb_add(&b, "Content-Length: 0\r\n");
	sb_add(&b, "Authorization: %s\r\n", auth);
	sb_add(&b, "Expires: %d\r\n", expires);
	sb_add(&b, "Require: sec-agree\r\nProxy-Require: sec-agree\r\nSupported: path,sec-agree\r\n");
	sb_add(&b, "Allow: %s\r\n", ALLOW_REG);
	sb_add(&b, "Security-Client: ipsec-3gpp; alg=hmac-md5-96; ealg=null; spi-c=%u; spi-s=%u; port-c=%d; port-s=%d,"
		   "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=%u; spi-s=%u; port-c=%d; port-s=%d\r\n",
		   u->sa.spi_uc, u->sa.spi_us, u->c.port_c, u->c.port_s,
		   u->sa.spi_uc, u->sa.spi_us, u->c.port_c, u->c.port_s);
	sb_add(&b, "\r\n");
	return b.ovf ? 0 : b.n;
}

/* ---- incoming requests ---- */
static void respond(struct ua *u, int fd, const struct sockaddr_in6 *to, const struct sip_msg *m, int code, const char *reason)
{
	char out[2048];
	struct sbuf b;
	const char *v;
	int i;
	char tag[24] = "";

	sb_init(&b, out, sizeof(out));
	sb_add(&b, "SIP/2.0 %d %s\r\n", code, reason);
	for (i = 0; (v = sip_hdr(m, "Via", i)); i++) sb_add(&b, "Via: %s\r\n", v);
	for (i = 0; (v = sip_hdr(m, "Record-Route", i)); i++) sb_add(&b, "Record-Route: %s\r\n", v);
	v = sip_hdr(m, "From", 0); if (v) sb_add(&b, "From: %s\r\n", v);
	v = sip_hdr(m, "To", 0);
	if (v) {
		char t[160];
		sip_tag(v, t, sizeof(t));
		if (!t[0] && code >= 200 && strcasecmp(m->method, "ACK")) { snprintf(tag, sizeof(tag), ";tag=%u", rnd32()); }
		sb_add(&b, "To: %s%s\r\n", v, tag);
	}
	v = sip_hdr(m, "Call-ID", 0); if (v) sb_add(&b, "Call-ID: %s\r\n", v);
	v = sip_hdr(m, "CSeq", 0); if (v) sb_add(&b, "CSeq: %s\r\n", v);
	if (!strcasecmp(m->method, "OPTIONS")) sb_add(&b, "Allow: %s\r\nAccept: application/sdp\r\n", ALLOW_REG);
	sb_add(&b, "Content-Length: 0\r\n\r\n");
	send_sip(fd, to, out, b.n);
}

static void handle_request(struct ua *u, int fd, const struct sockaddr_in6 *src, const struct sip_msg *m)
{
	const char *cid = sip_hdr(m, "Call-ID", 0);

	if (!strcasecmp(m->method, "ACK")) return;
	if (!strcasecmp(m->method, "OPTIONS") || !strcasecmp(m->method, "NOTIFY") || !strcasecmp(m->method, "INFO") ||
	    !strcasecmp(m->method, "UPDATE") || !strcasecmp(m->method, "MESSAGE")) {
		respond(u, fd, src, m, 200, "OK");
	} else if (!strcasecmp(m->method, "BYE")) {
		respond(u, fd, src, m, 200, "OK");
		if (u->in_call && cid && !strcmp(cid, u->callid)) {
			ilog("remote BYE, call ended");
			u->remote_bye = 1;
			u->call_end = 1;
			u->rtp.active = 0;
		}
	} else if (!strcasecmp(m->method, "INVITE")) {
		respond(u, fd, src, m, 486, "Busy Here");
	} else if (!strcasecmp(m->method, "CANCEL")) {
		respond(u, fd, src, m, 481, "Call/Transaction Does Not Exist");
	} else {
		respond(u, fd, src, m, 501, "Not Implemented");
	}
}

/* ---- call request building ---- */
static void dlg_route(struct ua *u, struct sbuf *b, const struct dlg *d)
{
	int i;

	/* all traffic leaves via the P-CSCF; keep its Route first unless the target is the P-CSCF itself */
	if (!strstr(d->contact, u->pcscf))
		sb_add(b, "Route: <sip:[%s]:%d;lr>\r\n", u->pcscf, u->ps_port);
	for (i = 0; i < d->nrr; i++) sb_add(b, "Route: %s\r\n", d->rr[i]);
}

static size_t build_in_dlg(struct ua *u, char *out, size_t cap, const char *method, int di, uint32_t cseq,
			   const char *extra)
{
	const struct dlg *d = &u->call.d[di];
	struct sbuf b;
	char br[40];

	sb_init(&b, out, cap);
	new_branch(br, sizeof(br));
	sb_add(&b, "%s %s SIP/2.0\r\n", method, d->contact[0] ? d->contact : u->inv_ruri);
	std_via(u, &b, u->c.port_s, br);
	dlg_route(u, &b, d);
	sb_add(&b, "Max-Forwards: 70\r\n");
	sb_add(&b, "From: <%s>;tag=%s\r\n", u->c.impu, u->from_tag);
	sb_add(&b, "To: %s;tag=%s\r\n", u->inv_to, d->tag);
	sb_add(&b, "Call-ID: %s\r\n", u->callid);
	sb_add(&b, "CSeq: %u %s\r\n", cseq, method);
	sb_add(&b, "P-Access-Network-Info: %s\r\n", u->c.pani);
	sb_add(&b, "Security-Verify: %s\r\n", u->sec_server);
	if (extra) sb_add(&b, "%s", extra);
	sb_add(&b, "Require: sec-agree\r\nProxy-Require: sec-agree\r\n");
	sb_add(&b, "Content-Length: 0\r\n\r\n");
	return b.ovf ? 0 : b.n;
}

static size_t build_cancel(struct ua *u, char *out, size_t cap)
{
	struct sbuf b;

	sb_init(&b, out, cap);
	sb_add(&b, "CANCEL %s SIP/2.0\r\n", u->inv_ruri);
	sb_add(&b, "Via: SIP/2.0/UDP [%s]:%d;branch=%s\r\n", u->c.local_ip, u->c.port_s, u->inv_branch);
	sb_add(&b, "Route: %s\r\n", u->inv_route);
	sb_add(&b, "Max-Forwards: 70\r\n");
	sb_add(&b, "From: %s\r\n", u->inv_from);
	sb_add(&b, "To: %s\r\n", u->inv_to);
	sb_add(&b, "Call-ID: %s\r\n", u->callid);
	sb_add(&b, "CSeq: 1 CANCEL\r\n");
	sb_add(&b, "Content-Length: 0\r\n\r\n");
	return b.ovf ? 0 : b.n;
}

/* ACK for a non-2xx final response: same transaction as the INVITE */
static size_t build_ack_non2xx(struct ua *u, char *out, size_t cap, const struct sip_msg *m)
{
	struct sbuf b;
	const char *to = sip_hdr(m, "To", 0);

	sb_init(&b, out, cap);
	sb_add(&b, "ACK %s SIP/2.0\r\n", u->inv_ruri);
	sb_add(&b, "Via: SIP/2.0/UDP [%s]:%d;branch=%s\r\n", u->c.local_ip, u->c.port_s, u->inv_branch);
	sb_add(&b, "Route: %s\r\n", u->inv_route);
	sb_add(&b, "Max-Forwards: 70\r\n");
	sb_add(&b, "From: %s\r\n", u->inv_from);
	sb_add(&b, "To: %s\r\n", to ? to : u->inv_to);
	sb_add(&b, "Call-ID: %s\r\n", u->callid);
	sb_add(&b, "CSeq: 1 ACK\r\n");
	sb_add(&b, "Content-Length: 0\r\n\r\n");
	return b.ovf ? 0 : b.n;
}

static void start_rtp_from(struct ua *u, const struct sip_msg *m)
{
	struct sdp_media s;

	if (sdp_parse(m->body, m->body_len, &s) || s.pt < 0) {
		ilog("SDP answer without usable AMR audio");
		return;
	}
	if (u->rtp.active && !strcmp(s.ip, u->ans.ip) && s.port == u->ans.port) return;
	u->ans = s;
	rtp_start(&u->rtp, s.ip, s.port, s.pt, s.wb, s.octet_align, u->c.outdir);
}

static void on_invite_response(struct ua *u, const struct sip_msg *m)
{
	struct call_ev ev[4];
	int n = call_on_response(&u->call, m, ev, 4), i;

	for (i = 0; i < n; i++) {
		char buf[3072];
		size_t l;
		switch (ev[i].type) {
		case EV_START_RTP:
			start_rtp_from(u, m);
			break;
		case EV_PRACK: {
			char extra[96], cid[8];
			struct txn *t;
			snprintf(extra, sizeof(extra), "RAck: %u %u INVITE\r\n", ev[i].rseq, u->call.invite_cseq);
			(void)cid;
			l = build_in_dlg(u, buf, sizeof(buf), "PRACK", ev[i].dlg, ++u->cseq, extra);
			if (l) {
				t = txn_add(u, "PRACK", u->cseq, u->callid, buf, l, u->fd_uc, &u->pc_ps);
				(void)t;
			}
			break;
		}
		case EV_ACK:
		case EV_DUP_2XX:
			if (ev[i].type == EV_ACK) {
				u->call_end = 0;
				ilog("call answered (dialog tag %s)", u->call.d[ev[i].dlg].tag);
				l = build_in_dlg(u, u->ack_buf, sizeof(u->ack_buf), "ACK", ev[i].dlg, u->call.invite_cseq, NULL);
				u->ack_len = l;
				/* 2xx SDP is authoritative for the media address */
				if (m->body_len) start_rtp_from(u, m);
				if (u->cap.started && u->cap.kind == CAP_SEND_CANCEL) u->cap.done = 0;
			}
			if (u->ack_len) send_sip(u->fd_uc, &u->pc_ps, u->ack_buf, u->ack_len);
			break;
		case EV_ACK_NON2XX:
			l = build_ack_non2xx(u, buf, sizeof(buf), m);
			if (l) send_sip(u->fd_uc, &u->pc_ps, buf, l);
			ilog("call failed: %d %s", m->status, m->reason);
			u->call_end = 1;
			u->call_rc = m->status == 487 ? 0 : EXIT_CALL;
			break;
		default: break;
		}
	}
}

static void on_response(struct ua *u, const struct sip_msg *m, const char *raw, size_t rawlen)
{
	uint32_t cs;
	char meth[16];
	const char *cid = sip_hdr(m, "Call-ID", 0);
	struct txn *t;

	if (!cid || sip_cseq(m, &cs, meth, sizeof(meth))) return;
	t = txn_find(u, cid, cs, meth);
	if (t && m->status >= 100) { t->answered = 1; if (m->status >= 200) t->act = 0; }
	if (u->await_callid[0] && !strcmp(cid, u->await_callid) && cs == u->await_cseq &&
	    !strcasecmp(meth, u->await_method) && m->status >= 200 && rawlen < sizeof(u->resp_raw)) {
		memcpy(u->resp_raw, raw, rawlen); u->resp_len = rawlen; u->resp_valid = 1;
	}
	if (u->in_call && !strcmp(cid, u->callid)) {
		if (!strcasecmp(meth, "INVITE")) on_invite_response(u, m);
		else if ((!strcasecmp(meth, "BYE") || !strcasecmp(meth, "CANCEL")) && m->status >= 200) {
			ilog("%s answered with %d", meth, m->status);
			cap_final_seen(&u->cap);
			if (!strcasecmp(meth, "BYE")) u->call_end = 1;
		} else if (!strcasecmp(meth, "PRACK") && m->status >= 300) {
			ilog("PRACK rejected: %d", m->status);
		}
	}
}

static void process_dgram(struct ua *u, int fd, const struct sockaddr_in6 *src, const char *buf, size_t n)
{
	struct sip_msg m;
	char p[100];

	peer_str(src, p, sizeof(p));
	ilog_msg("RECV from", p, buf, n);
	if (sip_parse(buf, n, &m)) { ilog("unparsable datagram"); return; }
	if (m.is_resp) on_response(u, &m, buf, n);
	else handle_request(u, fd, src, &m);
	sip_free(&m);
}

/* ---- call cap driver ---- */
static void cap_drive(struct ua *u)
{
	uint32_t t;
	enum cap_act a;
	char buf[3072];
	size_t l = 0;

	if (!u->in_call || !u->inv_t0) return;
	t = (uint32_t)(now_ms() - u->inv_t0);
	if (g_stop) u->cap.force = 1;
	if (u->call_end && u->cap.done) return;
	a = cap_poll(&u->cap, t, call_bye_target(&u->call) >= 0);
	switch (a) {
	case CAP_FATAL:
		ilog("FATAL: call cap exceeded: no final response to %s %u ms after INVITE; exiting (drop the PDN!)",
		     u->cap.kind == CAP_SEND_BYE ? "BYE" : "CANCEL", t);
		fprintf(stderr, "imsua: CALL CAP VIOLATION RISK - no response to hangup at %u ms\n", t);
		if (u->sa_up) ipsec_remove(&u->sa);
		exit(EXIT_CAP);
	case CAP_SEND_BYE:
		u->cap_dlg = call_bye_target(&u->call);
		ilog("call cap/hangup at %u ms: sending BYE", t);
		l = build_in_dlg(u, buf, sizeof(buf), "BYE", u->cap_dlg, ++u->cseq, NULL);
		break;
	case CAP_SEND_CANCEL:
		ilog("call cap/hangup at %u ms: not answered, sending CANCEL", t);
		l = build_cancel(u, buf, sizeof(buf));
		break;
	case CAP_RESEND:
		if (u->cap_len) { ilog("retransmit %s", u->cap.kind == CAP_SEND_BYE ? "BYE" : "CANCEL"); send_sip(u->fd_uc, &u->pc_ps, u->cap_buf, u->cap_len); }
		return;
	default:
		return;
	}
	if (l) {
		memcpy(u->cap_buf, buf, l); u->cap_len = l;
		send_sip(u->fd_uc, &u->pc_ps, buf, l);
	}
}

/* ---- main event pump ---- */
static void pump(struct ua *u, int timeout_ms)
{
	struct pollfd p[4];
	int n = 0, i, to = timeout_ms;
	uint64_t now = now_ms();
	int rt;
	char buf[8192];

	if (u->fd_un >= 0) { p[n].fd = u->fd_un; p[n++].events = POLLIN; }
	if (u->fd_uc >= 0) { p[n].fd = u->fd_uc; p[n++].events = POLLIN; }
	if (u->fd_us >= 0) { p[n].fd = u->fd_us; p[n++].events = POLLIN; }
	if (u->rtp.fd >= 0) { p[n].fd = u->rtp.fd; p[n++].events = POLLIN; }
	rt = rtp_poll_timeout(&u->rtp, now);
	if (rt >= 0 && rt < to) to = rt;
	if (u->in_call && to > 50) to = 50;	/* keep the cap timer responsive */
	if (to > 100) to = 100;
	if (to < 0) to = 0;
	if (poll(p, n, to) > 0) {
		for (i = 0; i < n; i++) {
			if (!(p[i].revents & POLLIN)) continue;
			if (p[i].fd == u->rtp.fd) { rtp_rx(&u->rtp); continue; }
			for (;;) {
				struct sockaddr_in6 src;
				socklen_t sl = sizeof(src);
				ssize_t r = recvfrom(p[i].fd, buf, sizeof(buf) - 1, MSG_DONTWAIT, (struct sockaddr *)&src, &sl);
				if (r < 0) break;
				process_dgram(u, p[i].fd, &src, buf, r);
			}
		}
	}
	now = now_ms();
	rtp_tx_tick(&u->rtp, now);
	txn_tick(u, now);
	cap_drive(u);
}

/* send a request and wait for its final response; returns 0 and fills u->resp_* */
static int req_wait(struct ua *u, const char *method, const char *callid, uint32_t cseq,
		    const char *buf, size_t len, int fd, const struct sockaddr_in6 *to, int max_ms)
{
	struct txn *t;
	uint64_t end = now_ms() + max_ms;

	strlcpy_(u->await_callid, callid, sizeof(u->await_callid));
	strlcpy_(u->await_method, method, sizeof(u->await_method));
	u->await_cseq = cseq;
	u->resp_valid = 0;
	t = txn_add(u, method, cseq, callid, buf, len, fd, to);
	if (!t) return -1;
	while (!u->resp_valid && !g_stop && now_ms() < end && !t->timeout && t->act)
		pump(u, 100);
	if (!u->resp_valid && t->act) t->act = 0;
	u->await_callid[0] = 0;
	return u->resp_valid ? 0 : -1;
}

/* ---- ISIM ---- */
static int do_aka(struct ua *u, const char *nonce_b64, struct aka_result *r)
{
	uint8_t n[64];
	int l = b64dec(nonce_b64, n, sizeof(n));

	if (l < 32) { ilog("nonce too short (%d bytes) for RAND||AUTN", l); return -1; }
	u->akac.channel = aka_ubus_channel(u->aka);
	return aka_authenticate(aka_ubus_apdu, u->aka, &u->akac, n, n + 16, r);
}

/* ---- registration ---- */
static void ipsec_cleanup(struct ua *u)
{
	if (u->sa_up) { ipsec_remove(&u->sa); u->sa_up = 0; }
	if (u->fd_uc >= 0) { close(u->fd_uc); u->fd_uc = -1; }
	if (u->fd_us >= 0) { close(u->fd_us); u->fd_us = -1; }
}

static int register_once(struct ua *u, const char *pcscf)
{
	char buf[4096], hexs[64];
	struct sip_msg m = {0};
	struct sec_ent se[4];
	struct aka_result ar;
	int ns, sel, attempts = 0, ok = -1;
	const char *v;
	size_t l;
	uint32_t cs;

	strlcpy_(u->pcscf, pcscf, sizeof(u->pcscf));
	mk_sa(&u->pc_un, pcscf, u->c.pcscf_port);
	snprintf(u->reg_callid, sizeof(u->reg_callid), "%u_%u@%s", rnd32(), rnd32(), u->c.local_ip);
	u->reg_cseq = rnd32() % 100000000;
	memset(&u->sa, 0, sizeof(u->sa));
	strlcpy_(u->sa.ue, u->c.local_ip, sizeof(u->sa.ue));
	strlcpy_(u->sa.pcscf, pcscf, sizeof(u->sa.pcscf));
	u->sa.spi_uc = rnd_range(256, 0x7fffffff);
	do { u->sa.spi_us = rnd_range(256, 0x7fffffff); } while (u->sa.spi_us == u->sa.spi_uc);
	u->sa.port_uc = u->c.port_c; u->sa.port_us = u->c.port_s;
	u->sa.reqid = rnd_range(1000, 100000) & ~3u;
	u->opaque[0] = 0;

	for (;;) {
		if (attempts == 0) l = build_register(u, buf, sizeof(buf), 0, u->c.expires, NULL, NULL);
		else l = build_register(u, buf, sizeof(buf), 0, u->c.expires, "", u->auth_last);
		cs = u->reg_cseq;
		if (!l || req_wait(u, "REGISTER", u->reg_callid, cs, buf, l, u->fd_un, &u->pc_un, 5000)) {
			ilog("no response from P-CSCF %s", pcscf);
			return -1;
		}
		sip_parse(u->resp_raw, u->resp_len, &m);
		if (m.status != 401) {
			ilog("unexpected response to unprotected REGISTER: %d %s", m.status, m.reason);
			sip_free(&m);
			return -1;
		}
		v = sip_hdr(&m, "WWW-Authenticate", 0);
		if (!v || !sip_param(v, "nonce", u->nonce, sizeof(u->nonce)) || !sip_param(v, "realm", u->realm, sizeof(u->realm))) {
			ilog("401 without nonce/realm"); sip_free(&m); return -1;
		}
		if (!sip_param(v, "opaque", u->opaque, sizeof(u->opaque))) u->opaque[0] = 0;
		v = sip_hdr(&m, "Security-Server", 0);
		if (!v) { ilog("401 without Security-Server"); sip_free(&m); return -1; }
		strlcpy_(u->sec_server, v, sizeof(u->sec_server));
		ns = sec_parse(v, se, 4);
		sel = sec_select(se, ns);
		if (sel < 0) { ilog("no usable Security-Server entry"); sip_free(&m); return -1; }
		u->chosen = se[sel];
		sip_free(&m);
		ilog("Security-Server: selected %s ealg=%s spi-c=%u spi-s=%u port-c=%d port-s=%d%s%s",
		     u->chosen.alg, u->chosen.ealg, u->chosen.spi_c, u->chosen.spi_s, u->chosen.port_c, u->chosen.port_s,
		     u->chosen.mod[0] ? " mod=" : "", u->chosen.mod);

		if (do_aka(u, u->nonce, &ar) || ar.status == AKA_ERR) {
			ilog("AKA failed (sw=%04x)", ar.sw < 0 ? 0 : ar.sw);
			return -1;
		}
		if (ar.status == AKA_SYNC_FAIL) {
			if (++attempts > 2) { ilog("AKA resync failed repeatedly"); return -1; }
			b64enc(ar.auts, ar.auts_len, u->auth_last, sizeof(u->auth_last));
			ilog("AKA sync failure, retrying REGISTER with AUTS");
			continue;
		}
		break;
	}
	/* IPsec */
	u->sa.spi_pc = u->chosen.spi_c; u->sa.spi_ps = u->chosen.spi_s;
	u->sa.port_pc = u->chosen.port_c; u->sa.port_ps = u->chosen.port_s;
	u->sa.sha1 = u->chosen.sha1;
	memcpy(u->sa.ik, ar.ik, 16);
	u->ps_port = u->chosen.port_s;
	mk_sa(&u->pc_ps, pcscf, u->ps_port);
	ipsec_remove(&u->sa);	/* stale leftovers with the same selectors */
	if (ipsec_install(&u->sa)) { ilog("IPsec SA install failed"); return -1; }
	u->sa_up = 1;
	u->fd_uc = udp_sock(&u->c, u->c.port_c);
	u->fd_us = udp_sock(&u->c, u->c.port_s);
	if (u->fd_uc < 0 || u->fd_us < 0) return -1;

	{
		char resp[33], uri[160];
		/* the digest uri is the one placed in the Authorization header */
		snprintf(uri, sizeof(uri), "sip:%s", u->c.domain);
		digest_response(u->c.impi, u->realm, ar.res, ar.res_len, u->nonce, "REGISTER", uri, resp);
		l = build_register(u, buf, sizeof(buf), 1, u->c.expires, resp, NULL);
		snprintf(u->auth_last, sizeof(u->auth_last), "%s", resp);
	}
	bin2hex(ar.res, ar.res_len, hexs);
	cs = u->reg_cseq;
	if (!l || req_wait(u, "REGISTER", u->reg_callid, cs, buf, l, u->fd_uc, &u->pc_ps, 8000)) {
		ilog("no response to protected REGISTER");
		return -1;
	}
	sip_parse(u->resp_raw, u->resp_len, &m);
	if (m.status == 200) {
		const char *pau = sip_hdr(&m, "P-Associated-URI", 0), *ct = sip_hdr(&m, "Contact", 0);
		char ex[32] = "";
		if (ct) sip_param(ct, "expires", ex, sizeof(ex));
		ilog("REGISTERED: P-Associated-URI=%s expires=%s", pau ? pau : "(none)", ex[0] ? ex : "?");
		printf("REGISTERED P-Associated-URI=%s expires=%s\n", pau ? pau : "(none)", ex);
		ok = 0;
	} else {
		ilog("protected REGISTER failed: %d %s", m.status, m.reason);
	}
	sip_free(&m);
	return ok;
}

static int do_register(struct ua *u)
{
	int a, i;

	for (a = 0; a <= u->c.reg_retries; a++) {
		for (i = 0; i < u->c.npcscf && !g_stop; i++) {
			ilog("REGISTER attempt %d via P-CSCF [%s]", a + 1, u->c.pcscf[i]);
			if (!register_once(u, u->c.pcscf[i])) return 0;
			ipsec_cleanup(u);	/* flush before retry */
		}
		if (g_stop) break;
	}
	return -1;
}

static void do_deregister(struct ua *u)
{
	char buf[4096];
	size_t l;

	if (!u->sa_up) return;
	/* reuse the last credentials (same nonce); UNVERIFIED whether the S-CSCF accepts that */
	l = build_register(u, buf, sizeof(buf), 1, 0, u->auth_last, NULL);
	if (l && !req_wait(u, "REGISTER", u->reg_callid, u->reg_cseq, buf, l, u->fd_uc, &u->pc_ps, 5000)) {
		struct sip_msg m;
		if (!sip_parse(u->resp_raw, u->resp_len, &m)) { ilog("de-REGISTER: %d %s", m.status, m.reason); sip_free(&m); }
	} else ilog("de-REGISTER: no response");
}

/* ---- call ---- */
static const char *SDP_FMT =
	"v=0\r\n"
	"o=root 1002 1000 IN IP6 %s\r\n"
	"s=QC VOIP\r\n"
	"c=IN IP6 %s\r\n"
	"t=0 0\r\n"
	"m=audio %d RTP/AVP 104 100 102 96 107 101\r\n"
	"b=AS:49\r\n"
	"b=RS:600\r\n"
	"b=RR:2000\r\n"
	"a=rtpmap:104 AMR-WB/16000/1\r\n"
	"a=fmtp:104 mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:100 AMR-WB/16000/1\r\n"
	"a=fmtp:100 octet-align=1;mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:102 AMR/8000/1\r\n"
	"a=fmtp:102 mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:96 AMR/8000/1\r\n"
	"a=fmtp:96 octet-align=1;mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:107 EVRCWB0/8000/1\r\n"
	"a=rtpmap:101 telephone-event/8000/1\r\n"
	"a=fmtp:101 0-15\r\n"
	"a=sendrecv\r\n"
	"a=maxptime:240\r\n"
	"a=ptime:20\r\n";

static size_t build_invite(struct ua *u, char *out, size_t cap)
{
	struct sbuf b;
	char sdp[1400];
	int sl = snprintf(sdp, sizeof(sdp), SDP_FMT, u->c.local_ip, u->c.local_ip, u->c.port_rtp);

	snprintf(u->inv_ruri, sizeof(u->inv_ruri), "tel:%s;phone-context=%s", u->c.number, u->c.phone_ctx);
	snprintf(u->inv_route, sizeof(u->inv_route), "<sip:[%s]:%d;lr>", u->pcscf, u->ps_port);
	snprintf(u->from_tag, sizeof(u->from_tag), "%u", rnd32());
	snprintf(u->inv_from, sizeof(u->inv_from), "<%s>;tag=%s", u->c.impu, u->from_tag);
	snprintf(u->inv_to, sizeof(u->inv_to), "<%s>", u->inv_ruri);
	snprintf(u->callid, sizeof(u->callid), "%u_%u@%s", rnd32(), rnd32(), u->c.local_ip);
	new_branch(u->inv_branch, sizeof(u->inv_branch));
	u->cseq = 1;

	sb_init(&b, out, cap);
	sb_add(&b, "INVITE %s SIP/2.0\r\n", u->inv_ruri);
	sb_add(&b, "From: %s\r\n", u->inv_from);
	sb_add(&b, "To: %s\r\n", u->inv_to);
	sb_add(&b, "CSeq: 1 INVITE\r\n");
	sb_add(&b, "Call-ID: %s\r\n", u->callid);
	sb_add(&b, "Via: SIP/2.0/UDP [%s]:%d;branch=%s\r\n", u->c.local_ip, u->c.port_s, u->inv_branch);
	sb_add(&b, "Max-Forwards: 70\r\n");
	sb_add(&b, "Contact: <sip:%s@[%s]:%d>;%s\r\n", u->c.user, u->c.local_ip, u->c.port_s, u->c.invite_tags);
	sb_add(&b, "Route: %s\r\n", u->inv_route);
	sb_add(&b, "P-Access-Network-Info: %s\r\n", u->c.pani);
	sb_add(&b, "Security-Verify: %s\r\n", u->sec_server);
	sb_add(&b, "Proxy-Require: sec-agree\r\nRequire: sec-agree\r\n");
	sb_add(&b, "P-Preferred-Identity: <%s>\r\n", u->c.impu);
	sb_add(&b, "Allow: INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO\r\n");
	sb_add(&b, "Content-Type: application/sdp\r\n");
	sb_add(&b, "Accept: application/sdp,application/3gpp-ims+xml\r\n");
	sb_add(&b, "P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel\r\n");
	sb_add(&b, "Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\";description=\"AT\"\r\n");
	sb_add(&b, "Supported: timer,100rel,replaces\r\n");
	sb_add(&b, "P-Early-Media: supported\r\n");
	sb_add(&b, "Content-Length: %d\r\n", sl);
	sb_add(&b, "Session-Expires: 3600;refresher=uac\r\n");
	sb_add(&b, "\r\n%s", sdp);
	return b.ovf ? 0 : b.n;
}

static int do_call(struct ua *u)
{
	char buf[4096];
	size_t l;
	struct txn *t;

	if (rtp_open(&u->rtp, u->c.local_ip, u->c.port_rtp, u->c.netdev, u->c.outdir)) return EXIT_CALL;
	l = build_invite(u, buf, sizeof(buf));
	if (!l) return EXIT_CALL;
	call_init(&u->call, 1);
	cap_init(&u->cap, u->c.call_secs > 0 ? (uint32_t)u->c.call_secs * 1000 : 0);
	u->in_call = 1;
	u->call_rc = 0;
	u->inv_t0 = now_ms();
	/* last-resort backstop independent of the event loop */
	alarm(22);
	ilog("INVITE %s (cap %u ms)", u->inv_ruri, u->cap.cap_ms);
	t = txn_add(u, "INVITE", 1, u->callid, buf, l, u->fd_uc, &u->pc_ps);
	if (!t) return EXIT_CALL;

	while (!u->call_end || !u->cap.done) {
		pump(u, 50);
		if (u->call_end && !u->cap.started) break;	/* remote hangup / failure */
		if (u->call_end && u->cap.started && u->cap.done) break;
		if (g_stop && !u->cap.started) u->cap.force = 1;
		if (now_ms() - u->inv_t0 >= IMSUA_CALL_ABORT_MS + 500) {	/* never hang around past the cap */
			ilog("call did not finish cleanly within the cap window");
			u->call_rc = EXIT_CAP;
			break;
		}
	}
	/* grace so the final 200 of BYE/CANCEL and trailing packets are absorbed */
	{
		uint64_t end = now_ms() + 500;
		while (now_ms() < end) pump(u, 50);
	}
	alarm(0);
	u->in_call = 0;
	printf("RTP rx_pkts=%u tx_pkts=%u rx_bytes=%u\n", u->rtp.rx_pkts, u->rtp.tx_pkts, u->rtp.rx_bytes);
	ilog("RTP counters: rx_pkts=%u tx_pkts=%u", u->rtp.rx_pkts, u->rtp.tx_pkts);
	rtp_close(&u->rtp);
	return u->call_rc;
}

/* ---- CLI ---- */
static void defaults(struct cfg *c)
{
	memset(c, 0, sizeof(*c));
	strcpy(c->pcscf[0], "2001:4430:5:405::43");
	strcpy(c->pcscf[1], "2001:4430:4:401::14");
	c->npcscf = 2;
	strcpy(c->impi, "450061039428657@lte-lguplus.co.kr");
	strcpy(c->impu, "sip:01039428657@lte-lguplus.co.kr");
	strcpy(c->domain, "lte-lguplus.co.kr");
	strcpy(c->imei, "86001804-613612-0");
	strcpy(c->pani, "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EB3161703");
	strcpy(c->phone_ctx, "lguplus.co.kr");
	strcpy(c->outdir, ".");
	strcpy(c->aid, ISIM_AID_DEFAULT);
	c->port_un = 28800; c->port_c = 8001; c->port_s = 8901; c->port_rtp = 50010;
	c->pcscf_port = 5060; c->expires = 8000; c->hold = 10; c->reg_retries = 1; c->p2 = 0x81; c->cla_ch = 1;
	strcpy(c->invite_tags, "+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";description=\"AT\";lgt-vt;+g.gsma.rcs.telephony=\"cs,volte\"");
}

static void usage(void)
{
	fprintf(stderr,
"usage: imsua [options] MODE [NUMBER]\n"
"  MODE: aka-test | register | call (NUMBER required)\n"
"  -l, --local-ip ADDR     IMS PDN IPv6 address (required for register/call)\n"
"  -d, --netdev IFACE      bind sockets to this device (SO_BINDTODEVICE)\n"
"  -p, --pcscf A[,B..]     P-CSCF IPv6 list, first reachable is used\n"
"      --pcscf-port N      unprotected P-CSCF port (5060)\n"
"      --impi X --impu sip:X --domain D --imei NNNNNNNN-NNNNNN-N\n"
"      --pani STR          P-Access-Network-Info value\n"
"      --port-un N (28800) --port-c N (8001) --port-s N (8901) --rtp-port N (50010)\n"
"  -o, --outdir DIR        logs and RTP capture (default .)\n"
"      --phone-context S   (lguplus.co.kr)\n"
"      --hold SECS         register mode: stay registered (10)\n"
"      --dereg             de-register before exit\n"
"      --expires N         (8000)\n"
"      --call-secs N       hang up earlier; can only LOWER the built-in %u s cap\n"
"      --contact-tags S    REGISTER Contact feature tags\n"
"      --invite-tags S     INVITE Contact feature tags\n"
"      --retries N         REGISTER retries over the P-CSCF list (1)\n"
"      --aid HEX (A0000000871004) --p2 N (0x81) --no-cla-channel --slot N\n"
"      --modem uqmid.modem.N --ubus-sock PATH\n"
"      --rand HEX32 --autn HEX32   aka-test inputs\n", IMSUA_CALL_HARD_CAP_MS / 1000);
}

enum { O_PCSCFPORT = 256, O_IMPI, O_IMPU, O_DOMAIN, O_IMEI, O_PANI, O_PUN, O_PC, O_PS, O_RTP, O_PCTX, O_HOLD,
       O_DEREG, O_EXP, O_CALLSECS, O_CTAGS, O_ITAGS, O_RETRIES, O_AID, O_P2, O_NOCLA, O_SLOT, O_MODEM, O_UBUS, O_RAND, O_AUTN };

static const struct option lo[] = {
	{ "local-ip", 1, 0, 'l' }, { "netdev", 1, 0, 'd' }, { "pcscf", 1, 0, 'p' }, { "outdir", 1, 0, 'o' },
	{ "pcscf-port", 1, 0, O_PCSCFPORT }, { "impi", 1, 0, O_IMPI }, { "impu", 1, 0, O_IMPU }, { "domain", 1, 0, O_DOMAIN },
	{ "imei", 1, 0, O_IMEI }, { "pani", 1, 0, O_PANI }, { "port-un", 1, 0, O_PUN }, { "port-c", 1, 0, O_PC },
	{ "port-s", 1, 0, O_PS }, { "rtp-port", 1, 0, O_RTP }, { "phone-context", 1, 0, O_PCTX }, { "hold", 1, 0, O_HOLD },
	{ "dereg", 0, 0, O_DEREG }, { "expires", 1, 0, O_EXP }, { "call-secs", 1, 0, O_CALLSECS },
	{ "contact-tags", 1, 0, O_CTAGS }, { "invite-tags", 1, 0, O_ITAGS }, { "retries", 1, 0, O_RETRIES },
	{ "aid", 1, 0, O_AID }, { "p2", 1, 0, O_P2 }, { "no-cla-channel", 0, 0, O_NOCLA }, { "slot", 1, 0, O_SLOT },
	{ "modem", 1, 0, O_MODEM }, { "ubus-sock", 1, 0, O_UBUS }, { "rand", 1, 0, O_RAND }, { "autn", 1, 0, O_AUTN },
	{ "help", 0, 0, 'h' }, { 0 }
};

static int parse_args(struct cfg *c, int argc, char **argv)
{
	int o;

	defaults(c);
	while ((o = getopt_long(argc, argv, "l:d:p:o:h", lo, NULL)) != -1) {
		switch (o) {
		case 'l': strlcpy_(c->local_ip, optarg, sizeof(c->local_ip)); break;
		case 'd': strlcpy_(c->netdev, optarg, sizeof(c->netdev)); break;
		case 'p': {
			char *s = strdup(optarg), *tok, *sv = NULL;
			c->npcscf = 0;
			for (tok = strtok_r(s, ", ", &sv); tok && c->npcscf < 8; tok = strtok_r(NULL, ", ", &sv))
				strlcpy_(c->pcscf[c->npcscf++], tok, 64);
			free(s);
			break;
		}
		case 'o': strlcpy_(c->outdir, optarg, sizeof(c->outdir)); break;
		case O_PCSCFPORT: c->pcscf_port = atoi(optarg); break;
		case O_IMPI: strlcpy_(c->impi, optarg, sizeof(c->impi)); break;
		case O_IMPU: strlcpy_(c->impu, optarg, sizeof(c->impu)); break;
		case O_DOMAIN: strlcpy_(c->domain, optarg, sizeof(c->domain)); break;
		case O_IMEI: strlcpy_(c->imei, optarg, sizeof(c->imei)); break;
		case O_PANI: strlcpy_(c->pani, optarg, sizeof(c->pani)); break;
		case O_PUN: c->port_un = atoi(optarg); break;
		case O_PC: c->port_c = atoi(optarg); break;
		case O_PS: c->port_s = atoi(optarg); break;
		case O_RTP: c->port_rtp = atoi(optarg); break;
		case O_PCTX: strlcpy_(c->phone_ctx, optarg, sizeof(c->phone_ctx)); break;
		case O_HOLD: c->hold = atoi(optarg); break;
		case O_DEREG: c->dereg = 1; break;
		case O_EXP: c->expires = atoi(optarg); break;
		case O_CALLSECS: c->call_secs = atoi(optarg); break;
		case O_CTAGS: strlcpy_(c->contact_tags, optarg, sizeof(c->contact_tags)); break;
		case O_ITAGS: strlcpy_(c->invite_tags, optarg, sizeof(c->invite_tags)); break;
		case O_RETRIES: c->reg_retries = atoi(optarg); break;
		case O_AID: strlcpy_(c->aid, optarg, sizeof(c->aid)); break;
		case O_P2: c->p2 = strtol(optarg, NULL, 0); break;
		case O_NOCLA: c->cla_ch = 0; break;
		case O_SLOT: c->slot = atoi(optarg); break;
		case O_MODEM: strlcpy_(c->modem, optarg, sizeof(c->modem)); break;
		case O_UBUS: strlcpy_(c->ubus_sock, optarg, sizeof(c->ubus_sock)); break;
		case O_RAND: strlcpy_(c->rand_hex, optarg, sizeof(c->rand_hex)); break;
		case O_AUTN: strlcpy_(c->autn_hex, optarg, sizeof(c->autn_hex)); break;
		default: usage(); return -1;
		}
	}
	if (optind >= argc) { usage(); return -1; }
	strlcpy_(c->mode, argv[optind++], sizeof(c->mode));
	if (optind < argc) strlcpy_(c->number, argv[optind], sizeof(c->number));
	if (!c->contact_tags[0])
		snprintf(c->contact_tags, sizeof(c->contact_tags),
			 "+sip.instance=\"<urn:gsma:imei:%s>\";+g.3gpp.icsi-ref=\"urn%%3Aurn-7%%3A3gpp-service.ims.icsi.mmtel\";+g.3gpp.smsip", c->imei);
	{
		const char *s = strncmp(c->impu, "sip:", 4) ? c->impu : c->impu + 4, *at = strchr(s, '@');
		size_t n = at ? (size_t)(at - s) : strlen(s);
		if (n >= sizeof(c->user)) n = sizeof(c->user) - 1;
		memcpy(c->user, s, n); c->user[n] = 0;
	}
	return 0;
}

static int mode_aka_test(struct ua *u)
{
	uint8_t rnd[16], autn[16];
	struct aka_result r;
	char h[80];
	int rc;

	if (u->c.rand_hex[0] ? hex2bin(u->c.rand_hex, rnd, 16) != 16 : (rnd32(), 0)) { fprintf(stderr, "--rand needs 32 hex digits\n"); return EXIT_USAGE; }
	if (!u->c.rand_hex[0]) { uint32_t i; for (i = 0; i < 16; i++) rnd[i] = rnd32(); }
	if (u->c.autn_hex[0] ? hex2bin(u->c.autn_hex, autn, 16) != 16 : 0) { fprintf(stderr, "--autn needs 32 hex digits\n"); return EXIT_USAGE; }
	if (!u->c.autn_hex[0]) { uint32_t i; for (i = 0; i < 16; i++) autn[i] = rnd32(); }
	u->aka = aka_ubus_open(u->c.ubus_sock[0] ? u->c.ubus_sock : NULL, u->c.modem, u->c.aid, u->c.slot);
	if (!u->aka) return EXIT_REG;
	u->akac.p2 = u->c.p2; u->akac.cla_from_channel = u->c.cla_ch; u->akac.channel = aka_ubus_channel(u->aka);
	rc = aka_authenticate(aka_ubus_apdu, u->aka, &u->akac, rnd, autn, &r);
	if (r.sw >= 0) printf("SW=%04x\n", r.sw);
	if (!rc && r.status == AKA_OK) {
		bin2hex(r.res, r.res_len, h); printf("RES=%s\n", h);
		bin2hex(r.ck, 16, h); printf("CK=%s\n", h);
		bin2hex(r.ik, 16, h); printf("IK=%s\n", h);
		if (r.has_kc) { bin2hex(r.kc, 8, h); printf("Kc=%s\n", h); }
		printf("RESULT=success\n");
	} else if (!rc && r.status == AKA_SYNC_FAIL) {
		bin2hex(r.auts, r.auts_len, h);
		printf("AUTS=%s\nRESULT=sync-failure\n", h);
	} else {
		printf("RESULT=error (sw=%04x%s)\n", r.sw < 0 ? 0 : r.sw, r.sw == 0x9862 ? ", MAC failure: card reached, AUTHENTICATE accepted" : "");
	}
	aka_ubus_close(u->aka); u->aka = NULL;
	return 0;
}

int main(int argc, char **argv)
{
	struct ua *u = &U;
	struct sigaction sa = { .sa_handler = on_sig };
	char p[300];
	int rc = 0;

	u->fd_un = u->fd_uc = u->fd_us = -1;
	u->rtp.fd = -1;
	if (parse_args(&u->c, argc, argv)) return EXIT_USAGE;
	mkdir(u->c.outdir, 0755);
	snprintf(p, sizeof(p), "%s/imsua.log", u->c.outdir);
	log_open(p);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	if (!strcmp(u->c.mode, "aka-test")) { rc = mode_aka_test(u); goto out; }
	if (strcmp(u->c.mode, "register") && strcmp(u->c.mode, "call")) { usage(); rc = EXIT_USAGE; goto out; }
	if (!u->c.local_ip[0]) { fprintf(stderr, "--local-ip is required\n"); rc = EXIT_USAGE; goto out; }
	if (!strcmp(u->c.mode, "call") && !u->c.number[0]) { fprintf(stderr, "call needs NUMBER\n"); rc = EXIT_USAGE; goto out; }

	u->aka = aka_ubus_open(u->c.ubus_sock[0] ? u->c.ubus_sock : NULL, u->c.modem, u->c.aid, u->c.slot);
	if (!u->aka) { rc = EXIT_REG; goto out; }
	u->akac.p2 = u->c.p2; u->akac.cla_from_channel = u->c.cla_ch;
	u->fd_un = udp_sock(&u->c, u->c.port_un);
	if (u->fd_un < 0) { rc = EXIT_REG; goto out; }

	if (do_register(u)) { ilog("registration failed"); rc = EXIT_REG; goto out; }
	if (!strcmp(u->c.mode, "register")) {
		uint64_t end = now_ms() + (uint64_t)u->c.hold * 1000;
		while (now_ms() < end && !g_stop) pump(u, 100);
	} else {
		rc = do_call(u);
	}
	if (u->c.dereg) do_deregister(u);
out:
	ipsec_cleanup(u);
	if (u->fd_un >= 0) close(u->fd_un);
	if (u->aka) aka_ubus_close(u->aka);
	rtp_close(&u->rtp);
	ilog("exit rc=%d", rc);
	log_close();
	return rc;
}
