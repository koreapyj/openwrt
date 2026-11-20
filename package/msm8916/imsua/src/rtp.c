/* SPDX-License-Identifier: GPL-2.0-only */
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include "rtp.h"
#include "util.h"

int rtp_nodata_payload(int oa, uint8_t *o)
{
	if (oa) { o[0] = 0xF0; o[1] = 0x7C; return 2; }	/* CMR=15 | F=0 FT=15 Q=1 pad */
	o[0] = 0xF7; o[1] = 0xC0;			/* CMR=15 F=0 FT=15 Q=1 + 6 pad bits */
	return 2;
}

int rtp_open(struct rtp *r, const char *ip, int port, const char *netdev, const char *outdir)
{
	struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_port = htons(port) };
	char p[512];
	int one = 1;

	memset(r, 0, sizeof(*r));
	r->fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (r->fd < 0) return -1;
	setsockopt(r->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (netdev && netdev[0]) setsockopt(r->fd, SOL_SOCKET, SO_BINDTODEVICE, netdev, strlen(netdev) + 1);
	if (inet_pton(AF_INET6, ip, &a.sin6_addr) != 1 || bind(r->fd, (struct sockaddr *)&a, sizeof(a))) {
		ilog("RTP bind [%s]:%d failed: %s", ip, port, strerror(errno));
		close(r->fd); r->fd = -1;
		return -1;
	}
	snprintf(p, sizeof(p), "%s/rtp_rx.bin", outdir);
	r->rxlog = fopen(p, "wb");
	r->ssrc = rnd32(); r->seq = rnd32() & 0x7fff; r->ts = rnd32();
	r->t0 = now_ms();
	return 0;
}

int rtp_start(struct rtp *r, const char *ip, int port, int pt, int wb, int oa, const char *outdir)
{
	char p[512];
	FILE *f;

	memset(&r->remote, 0, sizeof(r->remote));
	r->remote.sin6_family = AF_INET6;
	r->remote.sin6_port = htons(port);
	if (inet_pton(AF_INET6, ip, &r->remote.sin6_addr) != 1) { ilog("RTP: bad remote address %s", ip); return -1; }
	r->pt = pt; r->wb = wb; r->oa = oa;
	r->first = 1;
	r->next_tx = now_ms();
	r->active = 1;
	snprintf(p, sizeof(p), "%s/rtp_meta.txt", outdir);
	f = fopen(p, "w");
	if (f) {
		fprintf(f, "pt=%d codec=%s octet_align=%d remote=[%s]:%d\n", pt, wb ? "AMR-WB" : "AMR", oa, ip, port);
		fclose(f);
	}
	ilog("RTP start: remote [%s]:%d pt=%d %s octet-align=%d", ip, port, pt, wb ? "AMR-WB" : "AMR", oa);
	return 0;
}

void rtp_rx(struct rtp *r)
{
	uint8_t b[2048];

	if (r->fd < 0) return;
	for (;;) {
		ssize_t n = recv(r->fd, b, sizeof(b), MSG_DONTWAIT);
		size_t hl, plen;
		uint8_t pt;
		uint16_t seq, len16;
		uint32_t ts, ms;

		if (n < 0) break;
		if (n < 12 || (b[0] >> 6) != 2) continue;
		hl = 12 + 4 * (b[0] & 0x0f);
		if (b[0] & 0x10) {
			if ((size_t)n < hl + 4) continue;
			hl += 4 + 4 * (b[hl+2] << 8 | b[hl+3]);
		}
		if ((size_t)n < hl) continue;
		plen = n - hl;
		if (b[0] & 0x20 && plen) { plen -= b[n-1] <= plen ? b[n-1] : plen; }
		pt = b[1] & 0x7f;
		seq = b[2] << 8 | b[3];
		ts = (uint32_t)b[4] << 24 | b[5] << 16 | b[6] << 8 | b[7];
		ms = (uint32_t)(now_ms() - r->t0);
		len16 = plen;
		r->rx_pkts++; r->rx_bytes += plen;
		if (r->rxlog) {	/* little endian, packed: u32 ms, u16 seq, u32 ts, u8 pt, u16 len, payload */
			uint8_t h[13] = { ms, ms >> 8, ms >> 16, ms >> 24, seq, seq >> 8, ts, ts >> 8, ts >> 16, ts >> 24, pt, len16, len16 >> 8 };
			fwrite(h, 1, 13, r->rxlog);
			fwrite(b + hl, 1, plen, r->rxlog);
		}
	}
}

void rtp_tx_tick(struct rtp *r, uint64_t now)
{
	int guard = 0;

	if (!r->active) return;
	while (now >= r->next_tx && guard++ < 5) {
		uint8_t p[32];
		int pl = rtp_nodata_payload(r->oa, p + 12);
		p[0] = 0x80;
		p[1] = (r->first ? 0x80 : 0) | (r->pt & 0x7f);
		p[2] = r->seq >> 8; p[3] = r->seq;
		p[4] = r->ts >> 24; p[5] = r->ts >> 16; p[6] = r->ts >> 8; p[7] = r->ts;
		p[8] = r->ssrc >> 24; p[9] = r->ssrc >> 16; p[10] = r->ssrc >> 8; p[11] = r->ssrc;
		if (sendto(r->fd, p, 12 + pl, 0, (struct sockaddr *)&r->remote, sizeof(r->remote)) > 0)
			r->tx_pkts++;
		r->first = 0;
		r->seq++;
		r->ts += r->wb ? 320 : 160;
		r->next_tx += 20;
	}
	if (now >= r->next_tx + 200) r->next_tx = now + 20;	/* fell behind, resync */
}

int rtp_poll_timeout(const struct rtp *r, uint64_t now)
{
	if (!r->active) return -1;
	return r->next_tx > now ? (int)(r->next_tx - now) : 0;
}

void rtp_close(struct rtp *r)
{
	if (r->fd >= 0) close(r->fd);
	r->fd = -1;
	if (r->rxlog) fclose(r->rxlog);
	r->rxlog = NULL;
	r->active = 0;
}
