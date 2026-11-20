/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include "ifaddr.h"

int ifaddr_first_v4(const char *ifname, const struct addr *prefer, struct addr *out)
{
	struct ifaddrs *all, *p;
	int rc = -1;
	bool have_first = false;

	if (!ifname || !ifname[0] || getifaddrs(&all))
		return -1;
	for (p = all; p; p = p->ifa_next) {
		struct addr a;

		if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET || strcmp(p->ifa_name, ifname))
			continue;
		addr_set_v4(&a, ((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr, 0);
		if (prefer && addr_equal_ip(&a, prefer)) {
			*out = a;
			rc = 0;
			break;
		}
		if (!have_first) {
			*out = a;
			have_first = true;
			rc = 0;
			if (!prefer)
				break;
		}
	}
	freeifaddrs(all);
	return rc;
}
