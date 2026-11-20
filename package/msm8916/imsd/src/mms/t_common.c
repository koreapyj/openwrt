/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Shared helpers of the MMS host tests: byte builders, PDU encoders, mock sockets, DNS response builder. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include "t_common.h"
#include "../util/codec.h"

size_t hexv(const char *hex, uint8_t *out, size_t max)
{
	int n = hex_decode(hex, out, max);

	return n < 0 ? 0 : (size_t)n;
}

void (*spin_hook)(void);

void spin(int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (spin_hook)
			spin_hook();
		evfake_poll_fds();
		evfake_advance(0);
	}
}

void advance(unsigned ms)
{
	unsigned t;

	for (t = 0; t < ms; t += 100) {
		evfake_advance(100);
		spin(6);
	}
}

/* ------------------------------------------------------------------ */
/* builders                                                            */

void pb_u8(struct pb *p, unsigned v)
{
	if (p->n < sizeof(p->d))
		p->d[p->n++] = (uint8_t)v;
}

void pb_add(struct pb *p, const void *d, size_t n)
{
	if (n && p->n + n <= sizeof(p->d)) {
		memcpy(p->d + p->n, d, n);
		p->n += n;
	}
}

void pb_text(struct pb *p, const char *s)
{
	pb_add(p, s, strlen(s) + 1);
}

void pb_uintvar(struct pb *p, uint32_t v)
{
	uint8_t t[5];
	int k = 0;

	t[k++] = v & 0x7f;
	while ((v >>= 7))
		t[k++] = (uint8_t)(0x80 | (v & 0x7f));
	while (k--)
		pb_u8(p, t[k]);
}

void pb_long(struct pb *p, uint64_t v)
{
	uint8_t t[8];
	int k = 0, i;

	do {
		t[k++] = v & 0xff;
		v >>= 8;
	} while (v);
	pb_u8(p, (unsigned)k);
	for (i = k - 1; i >= 0; i--)
		pb_u8(p, t[i]);
}

size_t ct_wk(uint8_t *out, unsigned code)
{
	out[0] = (uint8_t)(0x80 | code);
	return 1;
}

size_t ct_wk_charset(uint8_t *out, unsigned code, unsigned mib)
{
	out[0] = 3;
	out[1] = (uint8_t)(0x80 | code);
	out[2] = 0x81;
	out[3] = (uint8_t)(0x80 | mib);
	return 4;
}

size_t ct_text(uint8_t *out, const char *type)
{
	size_t l = strlen(type) + 1;

	memcpy(out, type, l);
	return l;
}

void mp_entry(struct pb *e, const uint8_t *ct, size_t ctl, const uint8_t *hdrs, size_t hl, const void *data, size_t dl)
{
	pb_uintvar(e, (uint32_t)(ctl + hl));
	pb_uintvar(e, (uint32_t)dl);
	pb_add(e, ct, ctl);
	pb_add(e, hdrs, hl);
	pb_add(e, data, dl);
}

size_t ph_cid_loc(uint8_t *out, const char *cid, const char *loc)
{
	size_t k = 0;

	out[k++] = 0xc0;			/* Content-ID */
	out[k++] = 0x22;			/* quote */
	out[k++] = '<';
	memcpy(out + k, cid, strlen(cid));
	k += strlen(cid);
	out[k++] = '>';
	out[k++] = 0;
	out[k++] = 0x8e;			/* Content-Location */
	memcpy(out + k, loc, strlen(loc) + 1);
	k += strlen(loc) + 1;
	return k;
}

size_t ph_disp_file(uint8_t *out, const char *fname)
{
	size_t k = 0, l = strlen(fname) + 1;

	out[k++] = 0xae;			/* Content-Disposition */
	out[k++] = (uint8_t)(1 + 1 + l);	/* value-length: attachment token, filename token, text */
	out[k++] = 0x81;			/* attachment */
	out[k++] = 0x98;			/* filename (0x18) */
	memcpy(out + k, fname, l);
	k += l;
	return k;
}

void build_retrieve(struct pb *p, const char *tid, unsigned version, const char *from, const char *subject_utf8,
		    int64_t date, const uint8_t *ct, size_t ctl, const void *body, size_t bl)
{
	pb_u8(p, 0x8c);
	pb_u8(p, 0x84);
	if (tid) {
		pb_u8(p, 0x98);
		pb_text(p, tid);
	}
	pb_u8(p, 0x8d);
	pb_u8(p, version);
	if (date >= 0) {
		pb_u8(p, 0x85);
		pb_long(p, (uint64_t)date);
	}
	if (from) {
		pb_u8(p, 0x89);
		pb_u8(p, (unsigned)(2 + strlen(from)));
		pb_u8(p, 0x80);
		pb_text(p, from);
	}
	if (subject_utf8) {
		pb_u8(p, 0x96);
		pb_u8(p, (unsigned)(2 + strlen(subject_utf8)));
		pb_u8(p, 0xea);
		pb_text(p, subject_utf8);
	}
	pb_u8(p, 0x84);
	pb_add(p, ct, ctl);
	pb_add(p, body, bl);
}

void build_multipart(struct pb *out, unsigned n, const struct pb *entries)
{
	pb_uintvar(out, n);
	pb_add(out, entries->d, entries->n);
}

void build_push(struct pb *p, const void *mms, size_t n)
{
	static const char CT[] = "application/vnd.wap.mms-message";

	pb_u8(p, 0);
	pb_u8(p, 6);
	pb_uintvar(p, (uint32_t)(sizeof(CT) + 4));
	pb_add(p, CT, sizeof(CT));
	pb_u8(p, 0xaf);
	pb_u8(p, 0x84);
	pb_u8(p, 0xb4);
	pb_u8(p, 0x87);
	pb_add(p, mms, n);
}

void build_notif(struct pb *p, const char *tid, unsigned version, const char *from, const char *subject_utf8, uint32_t size,
		 int expiry_rel_s, const char *url)
{
	pb_u8(p, 0x8c);
	pb_u8(p, 0x82);
	pb_u8(p, 0x98);
	pb_text(p, tid);
	pb_u8(p, 0x8d);
	pb_u8(p, version);
	pb_u8(p, 0x8a);
	pb_u8(p, 0x80);
	pb_u8(p, 0x8e);
	pb_long(p, size);
	if (expiry_rel_s >= 0) {
		struct pb t = { .n = 0 };

		pb_u8(&t, 0x81);
		pb_long(&t, (uint64_t)expiry_rel_s);
		pb_u8(p, 0x88);
		pb_u8(p, (unsigned)t.n);
		pb_add(p, t.d, t.n);
	}
	pb_u8(p, 0x83);
	pb_text(p, url);
	if (from) {
		pb_u8(p, 0x89);
		pb_u8(p, (unsigned)(2 + strlen(from)));
		pb_u8(p, 0x80);
		pb_text(p, from);
	}
	if (subject_utf8) {
		pb_u8(p, 0x96);
		pb_u8(p, (unsigned)(2 + strlen(subject_utf8)));
		pb_u8(p, 0xea);
		pb_text(p, subject_utf8);
	}
}

/* ------------------------------------------------------------------ */
/* DNS responses                                                       */

int dns_qinfo(const uint8_t *q, size_t n, char *name, size_t nl, int *type, unsigned *id)
{
	size_t o = 12, k = 0;

	if (n < 17)
		return -1;
	*id = (unsigned)((q[0] << 8) | q[1]);
	while (o < n && q[o]) {
		size_t l = q[o];

		if (o + 1 + l > n || k + l + 2 > nl)
			return -1;
		if (k)
			name[k++] = '.';
		memcpy(name + k, q + o + 1, l);
		k += l;
		o += 1 + l;
	}
	name[k] = 0;
	if (o + 5 > n)
		return -1;
	*type = (q[o + 1] << 8) | q[o + 2];
	return 0;
}

size_t dns_response(const uint8_t *q, size_t qn, int rcode, bool tc, const struct dns_rr_spec *rr, int nrr, uint8_t *out, size_t cap)
{
	size_t qend = 12, k, i;
	size_t cname_off[16] = { 0 };

	while (qend < qn && q[qend])
		qend += 1 + (size_t)q[qend];
	qend += 5;
	if (qend > qn || qend + 400 > cap)
		return 0;
	memcpy(out, q, qend);
	out[2] = (uint8_t)(0x81 | (tc ? 0x02 : 0));
	out[3] = (uint8_t)(0x80 | rcode);
	out[6] = 0;
	out[7] = (uint8_t)nrr;
	out[8] = out[9] = out[10] = out[11] = 0;
	k = qend;
	for (i = 0; i < (size_t)nrr; i++) {
		size_t rdl_at;

		if (rr[i].owner_ref < 0) {
			out[k++] = 0xc0;
			out[k++] = 0x0c;
		} else {
			out[k++] = (uint8_t)(0xc0 | (cname_off[rr[i].owner_ref] >> 8));
			out[k++] = (uint8_t)(cname_off[rr[i].owner_ref] & 0xff);
		}
		out[k++] = (uint8_t)(rr[i].type >> 8);
		out[k++] = (uint8_t)rr[i].type;
		out[k++] = 0;
		out[k++] = 1;
		out[k++] = (uint8_t)(rr[i].ttl >> 24);
		out[k++] = (uint8_t)(rr[i].ttl >> 16);
		out[k++] = (uint8_t)(rr[i].ttl >> 8);
		out[k++] = (uint8_t)rr[i].ttl;
		rdl_at = k;
		k += 2;
		if (rr[i].type == 5) {
			const char *p = rr[i].cname_target;

			cname_off[i] = k;
			while (*p) {
				const char *e = strchr(p, '.');
				size_t l = e ? (size_t)(e - p) : strlen(p);

				out[k++] = (uint8_t)l;
				memcpy(out + k, p, l);
				k += l;
				if (!e)
					break;
				p = e + 1;
			}
			out[k++] = 0;
		} else {
			memcpy(out + k, rr[i].rdata, rr[i].rdlen);
			k += rr[i].rdlen;
		}
		out[rdl_at] = (uint8_t)((k - rdl_at - 2) >> 8);
		out[rdl_at + 1] = (uint8_t)(k - rdl_at - 2);
	}
	return k;
}

/* ------------------------------------------------------------------ */
/* mock sockets                                                        */

static int m_pair(struct mocknet *m)
{
	int sv[2];

	if (m->n_fd >= MN_MAX_CONN + MN_MAX_UDP || socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, sv))
		return -1;
	m->fa[m->n_fd] = sv[0];
	m->fb[m->n_fd] = sv[1];
	return m->n_fd++;
}

static int m_idx(const struct mocknet *m, int fd)
{
	int i;

	for (i = 0; i < m->n_fd; i++)
		if (m->fa[i] == fd)
			return i;
	return -1;
}

static void wake(struct mocknet *m, int idx)
{
	uint8_t b = 1;
	ssize_t r = write(m->fb[idx], &b, 1);

	(void)r;
}

static void drain(struct mocknet *m, int idx)
{
	uint8_t b[16];

	while (read(m->fa[idx], b, sizeof(b)) > 0)
		;
}

static int mk_udp_open(void *ctx, const struct addr *local, const char *netdev)
{
	struct mocknet *m = ctx;
	int i;

	m->udp_local = *local;
	snprintf(m->udp_netdev, sizeof(m->udp_netdev), "%s", netdev);
	if (m->udp_open_rc)
		return m->udp_open_rc;
	i = m_pair(m);
	return i < 0 ? -EMFILE : m->fa[i];
}

static void queue_udp(struct mocknet *m, int fd, const struct addr *src, const uint8_t *d, size_t n)
{
	int i;

	for (i = 0; i < MN_MAX_UDP; i++)
		if (!m->uin[i].n) {
			m->uin[i].src = *src;
			memcpy(m->uin[i].d, d, n);
			m->uin[i].n = n;
			m->uin[i].fd = fd;
			wake(m, m_idx(m, fd));
			return;
		}
}

static ssize_t mk_udp_send(void *ctx, int fd, const void *b, size_t n, const struct addr *dst)
{
	struct mocknet *m = ctx;
	char name[256];
	int type, i;
	unsigned id;

	if (m->n_usent < MN_MAX_UDP) {
		m->usent[m->n_usent].dst = *dst;
		memcpy(m->usent[m->n_usent].d, b, n);
		m->usent[m->n_usent].n = n;
		m->n_usent++;
	}
	if (dns_qinfo(b, n, name, sizeof(name), &type, &id))
		return (ssize_t)n;
	for (i = 0; i < m->n_dns; i++) {
		struct mock_dns_rule *r = &m->dns[i];
		struct dns_rr_spec rr[8];
		uint8_t raw[8][16], pkt[1400];
		size_t pl;
		int k, nrr = 0;

		if (strcasecmp(r->name, name) || r->type != type)
			continue;
		if (r->ignore > 0) {
			r->ignore--;
			return (ssize_t)n;
		}
		memset(rr, 0, sizeof(rr));
		if (r->cname) {
			rr[nrr].type = 5;
			rr[nrr].ttl = r->ttl;
			rr[nrr].cname_target = r->cname;
			rr[nrr].owner_ref = -1;
			nrr++;
		}
		for (k = 0; k < r->n && nrr < 8; k++) {
			int len = type == 28 ? 16 : 4;

			if (type == 28)
				memcpy(raw[k], r->addr[k].sa.sin6_addr.s6_addr, 16);
			else
				memcpy(raw[k], r->addr[k].sa.sin6_addr.s6_addr + 12, 4);
			rr[nrr].type = type;
			rr[nrr].ttl = r->ttl;
			rr[nrr].rdata = raw[k];
			rr[nrr].rdlen = (size_t)len;
			rr[nrr].owner_ref = r->cname ? 0 : -1;
			nrr++;
		}
		pl = dns_response(b, n, r->rcode, r->tc, rr, nrr, pkt, sizeof(pkt));
		queue_udp(m, fd, dst, pkt, pl);
		return (ssize_t)n;
	}
	return (ssize_t)n;
}

static ssize_t mk_udp_recv(void *ctx, int fd, void *b, size_t n, struct addr *src)
{
	struct mocknet *m = ctx;
	int idx = m_idx(m, fd), i;
	bool more = false;
	ssize_t r = -EAGAIN;

	drain(m, idx);
	for (i = 0; i < MN_MAX_UDP; i++) {
		if (m->uin[i].n && m->uin[i].fd == fd) {
			if (r == -EAGAIN) {
				size_t c = m->uin[i].n < n ? m->uin[i].n : n;

				memcpy(b, m->uin[i].d, c);
				*src = m->uin[i].src;
				r = (ssize_t)c;
				m->uin[i].n = 0;
			} else {
				more = true;
			}
		}
	}
	if (more)
		wake(m, idx);
	return r;
}

static int mk_tcp_connect(void *ctx, const struct addr *local, const char *netdev, const struct addr *dst)
{
	struct mocknet *m = ctx;
	int i, c;

	if (m->tcp_open_fail_n > 0) {
		m->tcp_open_fail_n--;
		return m->tcp_open_rc ? m->tcp_open_rc : -ENETUNREACH;
	}
	if (m->n_conn >= MN_MAX_CONN)
		return -EMFILE;
	i = m_pair(m);
	if (i < 0)
		return -EMFILE;
	c = m->n_conn++;
	memset(&m->conn[c], 0, sizeof(m->conn[c]));
	m->conn[c].fd = m->fa[i];
	m->conn[c].dst = *dst;
	m->conn[c].local = *local;
	snprintf(m->conn[c].netdev, sizeof(m->conn[c].netdev), "%s", netdev);
	if (c < m->n_responses) {
		m->conn[c].resp = m->responses[c];
		m->conn[c].has_resp = true;
	}
	return m->fa[i];
}

static int conn_of(const struct mocknet *m, int fd)
{
	int c;

	for (c = 0; c < m->n_conn; c++)
		if (m->conn[c].fd == fd)
			return c;
	return -1;
}

static int mk_tcp_status(void *ctx, int fd)
{
	struct mocknet *m = ctx;
	int c = conn_of(m, fd);

	return c >= 0 && m->conn[c].has_resp ? m->conn[c].resp.connect_rc : 0;
}

static bool request_complete(const uint8_t *d, size_t n)
{
	size_t i;

	for (i = 0; i + 3 < n; i++)
		if (!memcmp(d + i, "\r\n\r\n", 4)) {
			const char *cl = NULL;
			size_t k, bodyn = n - (i + 4), want = 0;

			for (k = 0; k + 16 < i; k++)
				if (!strncasecmp((const char *)d + k, "Content-Length:", 15)) {
					cl = (const char *)d + k + 15;
					break;
				}
			if (cl)
				want = (size_t)strtoul(cl, NULL, 10);
			return bodyn >= want;
		}
	return false;
}

static ssize_t mk_tcp_send(void *ctx, int fd, const void *b, size_t n)
{
	struct mocknet *m = ctx;
	int c = conn_of(m, fd);
	uint8_t *p;

	if (c < 0)
		return -EBADF;
	p = realloc(m->conn[c].sent, m->conn[c].sent_n + n + 1);
	if (!p)
		return -ENOMEM;
	m->conn[c].sent = p;
	memcpy(p + m->conn[c].sent_n, b, n);
	m->conn[c].sent_n += n;
	p[m->conn[c].sent_n] = 0;
	if (m->conn[c].has_resp && !m->conn[c].resp.silent && !m->conn[c].armed && request_complete(p, m->conn[c].sent_n)) {
		m->conn[c].armed = true;
		wake(m, m_idx(m, fd));
	}
	return (ssize_t)n;
}

static ssize_t mk_tcp_recv(void *ctx, int fd, void *b, size_t n)
{
	struct mocknet *m = ctx;
	int c = conn_of(m, fd), idx = m_idx(m, fd);
	size_t left, take;

	if (c < 0 || !m->conn[c].armed)
		return -EAGAIN;
	drain(m, idx);
	left = m->conn[c].resp.n - m->conn[c].rx_pos;
	if (!left)
		return m->conn[c].resp.eof ? 0 : -EAGAIN;
	take = left < n ? left : n;
	if (m->conn[c].resp.step && take > m->conn[c].resp.step)
		take = m->conn[c].resp.step;
	memcpy(b, m->conn[c].resp.d + m->conn[c].rx_pos, take);
	m->conn[c].rx_pos += take;
	if (m->conn[c].rx_pos < m->conn[c].resp.n || m->conn[c].resp.eof)
		wake(m, idx);
	return (ssize_t)take;
}

static void mk_close(void *ctx, int fd)
{
	struct mocknet *m = ctx;
	int c = conn_of(m, fd);

	if (c >= 0)
		m->conn[c].closed = true;
	m->n_closed++;
}

void mock_init(struct mocknet *m)
{
	memset(m, 0, sizeof(*m));
	m->ops.udp_open = mk_udp_open;
	m->ops.udp_send = mk_udp_send;
	m->ops.udp_recv = mk_udp_recv;
	m->ops.tcp_connect = mk_tcp_connect;
	m->ops.tcp_status = mk_tcp_status;
	m->ops.tcp_send = mk_tcp_send;
	m->ops.tcp_recv = mk_tcp_recv;
	m->ops.close = mk_close;
	m->ops.ctx = m;
}

void mock_free(struct mocknet *m)
{
	int i;

	for (i = 0; i < m->n_conn; i++)
		free(m->conn[i].sent);
	for (i = 0; i < m->n_fd; i++) {
		close(m->fa[i]);
		close(m->fb[i]);
	}
	memset(m, 0, sizeof(*m));
}

void mock_reset_conns(struct mocknet *m)
{
	int i;

	for (i = 0; i < m->n_conn; i++)
		free(m->conn[i].sent);
	m->n_conn = 0;
	m->n_responses = 0;
	memset(m->conn, 0, sizeof(m->conn));
	memset(m->responses, 0, sizeof(m->responses));
}

void mock_respond(struct mocknet *m, const struct mock_resp *r)
{
	if (m->n_responses < MN_MAX_CONN)
		m->responses[m->n_responses++] = *r;
}

void mock_dns_add(struct mocknet *m, const struct mock_dns_rule *r)
{
	if (m->n_dns < 24)
		m->dns[m->n_dns++] = *r;
}

size_t http_ok(uint8_t *out, size_t cap, int status, const char *ctype, const void *body, size_t bl)
{
	int h = snprintf((char *)out, cap, "HTTP/1.1 %d X\r\nServer: test\r\nConnection: close\r\nContent-Type: %s\r\nContent-Length: %zu\r\n\r\n",
			 status, ctype, bl);

	if ((size_t)h + bl > cap)
		return 0;
	memcpy(out + h, body, bl);
	return (size_t)h + bl;
}

const char *mock_req(const struct mocknet *m, int i)
{
	return i < m->n_conn && m->conn[i].sent ? (const char *)m->conn[i].sent : "";
}

const uint8_t *mock_req_body(const struct mocknet *m, int i, size_t *n)
{
	const char *s = mock_req(m, i), *e = strstr(s, "\r\n\r\n");

	if (!e) {
		*n = 0;
		return NULL;
	}
	*n = m->conn[i].sent_n - (size_t)(e + 4 - s);
	return (const uint8_t *)e + 4;
}
