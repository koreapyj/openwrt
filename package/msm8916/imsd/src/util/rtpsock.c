/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "rtpsock.h"
#include "sys.h"

static unsigned rotor;	/* next position inside the range; seeded at first use */
static bool rotor_set;

int rtpsock_open(const struct addr *local, const char *netdev, unsigned port_min, unsigned port_max,
		 struct addr *bound)
{
	unsigned first, last, n, i, pos;
	int err = EADDRINUSE;

	if (port_min < 1024 || port_max > 65535 || port_max < port_min)
		return -EINVAL;
	first = (port_min + 1) & ~1u;	/* first even port */
	last = port_max & ~1u;		/* last even port */
	if (last < first)
		return -EINVAL;
	n = (last - first) / 2 + 1;
	if (!rotor_set) {
		rotor = rnd32();
		rotor_set = true;
	}
	pos = rotor % n;
	for (i = 0; i < n; i++, pos = (pos + 1) % n) {
		struct sockaddr_in6 sa = local->sa;
		int fd, off = 0;
		unsigned port = first + 2 * pos;

		fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd < 0)
			return -errno;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
		if (netdev && netdev[0] && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, netdev, strlen(netdev) + 1)) {
			err = errno;
			close(fd);
			return -err;
		}
		sa.sin6_port = htons(port);
		if (!bind(fd, (struct sockaddr *)&sa, sizeof(sa))) {
			rotor = pos + 1;
			*bound = *local;
			addr_set_port(bound, port);
			return fd;
		}
		err = errno;
		close(fd);
		if (err != EADDRINUSE && err != EACCES)
			return -err;
	}
	return -err;
}
