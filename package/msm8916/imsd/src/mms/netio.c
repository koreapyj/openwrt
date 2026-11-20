/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Real sockets for the MMS DNS and HTTP clients, see netio.h. */
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "netio.h"

static int sock_bound(int type, const struct addr *local, const char *netdev)
{
	int fd, off = 0, e;
	struct sockaddr_in6 sa = local->sa;

	fd = socket(AF_INET6, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
	if (netdev && netdev[0] && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, netdev, strlen(netdev) + 1))
		goto fail;
	sa.sin6_port = 0;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)))
		goto fail;
	return fd;
fail:
	e = errno;
	close(fd);
	return -e;
}

static int r_udp_open(void *ctx, const struct addr *local, const char *netdev)
{
	(void)ctx;
	return sock_bound(SOCK_DGRAM, local, netdev);
}

static ssize_t r_udp_send(void *ctx, int fd, const void *b, size_t n, const struct addr *dst)
{
	ssize_t r = sendto(fd, b, n, MSG_DONTWAIT | MSG_NOSIGNAL, (const struct sockaddr *)&dst->sa, sizeof(dst->sa));

	(void)ctx;
	return r < 0 ? -errno : r;
}

static ssize_t r_udp_recv(void *ctx, int fd, void *b, size_t n, struct addr *src)
{
	struct sockaddr_in6 from;
	socklen_t fl = sizeof(from);
	ssize_t r = recvfrom(fd, b, n, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);

	(void)ctx;
	if (r < 0)
		return -errno;
	addr_from_sa6(src, &from);
	return r;
}

static int r_tcp_connect(void *ctx, const struct addr *local, const char *netdev, const struct addr *dst)
{
	int fd = sock_bound(SOCK_STREAM, local, netdev);

	(void)ctx;
	if (fd < 0)
		return fd;
	if (connect(fd, (const struct sockaddr *)&dst->sa, sizeof(dst->sa)) && errno != EINPROGRESS) {
		int e = errno;

		close(fd);
		return -e;
	}
	return fd;
}

static int r_tcp_status(void *ctx, int fd)
{
	struct pollfd p = { .fd = fd, .events = POLLOUT };
	int err = 0;
	socklen_t l = sizeof(err);

	(void)ctx;
	if (poll(&p, 1, 0) <= 0)
		return -EINPROGRESS;
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l))
		return -errno;
	return -err;
}

static ssize_t r_tcp_send(void *ctx, int fd, const void *b, size_t n)
{
	ssize_t r = send(fd, b, n, MSG_DONTWAIT | MSG_NOSIGNAL);

	(void)ctx;
	return r < 0 ? -errno : r;
}

static ssize_t r_tcp_recv(void *ctx, int fd, void *b, size_t n)
{
	ssize_t r = recv(fd, b, n, MSG_DONTWAIT);

	(void)ctx;
	return r < 0 ? -errno : r;
}

static void r_close(void *ctx, int fd)
{
	(void)ctx;
	close(fd);
}

static const struct net_ops REAL = {
	.udp_open = r_udp_open, .udp_send = r_udp_send, .udp_recv = r_udp_recv, .tcp_connect = r_tcp_connect,
	.tcp_status = r_tcp_status, .tcp_send = r_tcp_send, .tcp_recv = r_tcp_recv, .close = r_close,
};

const struct net_ops *net_real_ops(void)
{
	return &REAL;
}
