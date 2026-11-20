/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_NETIO_H
#define IMSD_MMS_NETIO_H
#include <stddef.h>
#include <sys/types.h>
#include "../util/addr.h"

/*
 * The sockets under the DNS and HTTP clients, behind one small ops struct so the host tests can substitute fakes.
 * Every call is non-blocking: fds are non-blocking, a call that cannot proceed returns -EAGAIN, nothing waits.
 * The real implementation (net_real_ops) uses dual-stack AF_INET6 sockets like the rest of the daemon (IPv4 is
 * v4-mapped), bound to the given local address and, when netdev is not empty, SO_BINDTODEVICE.
 */
struct net_ops {
	/* UDP socket bound to local (port 0) / netdev. fd >= 0, or -errno */
	int (*udp_open)(void *ctx, const struct addr *local, const char *netdev);
	/* >= 0 bytes sent, or -errno */
	ssize_t (*udp_send)(void *ctx, int fd, const void *b, size_t n, const struct addr *dst);
	/* bytes received (src filled), or -EAGAIN / -errno */
	ssize_t (*udp_recv)(void *ctx, int fd, void *b, size_t n, struct addr *src);
	/* TCP socket bound to local / netdev with a non-blocking connect to dst started. fd >= 0 (the connection may
	 * still be pending, see tcp_status), or -errno */
	int (*tcp_connect)(void *ctx, const struct addr *local, const char *netdev, const struct addr *dst);
	/* 0 connected, -EINPROGRESS still pending, -errno the connect failed */
	int (*tcp_status)(void *ctx, int fd);
	ssize_t (*tcp_send)(void *ctx, int fd, const void *b, size_t n);	/* >= 0, -EAGAIN, -errno */
	ssize_t (*tcp_recv)(void *ctx, int fd, void *b, size_t n);	/* > 0, 0 = end of stream, -EAGAIN, -errno */
	void (*close)(void *ctx, int fd);
	void *ctx;
};

const struct net_ops *net_real_ops(void);
#endif
