/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UTIL_RTPSOCK_H
#define IMSD_UTIL_RTPSOCK_H
#include <stdint.h>
#include "addr.h"

/*
 * Allocate a bound, non-blocking UDP socket for one RTP stream from a port range.
 *
 * The socket is AF_INET6, dual-stack (IPV6_V6ONLY off) like every other socket of the daemon (util/addr.h:
 * IPv4 is v4-mapped), SOCK_NONBLOCK | SOCK_CLOEXEC, bound to `local` (its port is ignored) and, if netdev is
 * given, SO_BINDTODEVICE. Only EVEN ports of [port_min, port_max] are used (RTP on even, RTCP would be the
 * odd one above it). The search starts at a rotating position of the range so a port that was just released
 * is not the first one reused, and takes at most one pass over the range; no waiting.
 *
 * Returns the fd (>= 0) with *bound = local address + chosen port, or -errno: -EINVAL (bad range: no even
 * port in it, port_min < 1024), -EADDRINUSE (every port busy), or the error of socket() / SO_BINDTODEVICE /
 * bind() (e.g. -EADDRNOTAVAIL, -ENODEV).
 */
int rtpsock_open(const struct addr *local, const char *netdev, unsigned port_min, unsigned port_max,
		 struct addr *bound);
#endif
