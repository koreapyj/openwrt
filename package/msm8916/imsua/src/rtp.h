/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IMSUA_RTP_H
#define IMSUA_RTP_H
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>

struct rtp {
	int fd;
	FILE *rxlog;
	int active;
	struct sockaddr_in6 remote;
	int pt, wb, oa;
	uint32_t ssrc, ts;
	uint16_t seq;
	uint64_t next_tx;	/* ms */
	uint64_t t0;
	unsigned rx_pkts, tx_pkts, rx_bytes;
	int first;
};

int rtp_open(struct rtp *r, const char *local_ip, int port, const char *netdev, const char *outdir);
/* remote answer; wb/oa/pt from SDP. writes rtp_meta.txt */
int rtp_start(struct rtp *r, const char *ip, int port, int pt, int wb, int oa, const char *outdir);
void rtp_rx(struct rtp *r);			/* drain the socket */
void rtp_tx_tick(struct rtp *r, uint64_t now);	/* send due frames */
int rtp_poll_timeout(const struct rtp *r, uint64_t now);
void rtp_close(struct rtp *r);

/* NO_DATA frame payload (CMR=15); returns length */
int rtp_nodata_payload(int oa, uint8_t *out);
#endif
