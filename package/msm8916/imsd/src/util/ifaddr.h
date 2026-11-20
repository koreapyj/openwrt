/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UTIL_IFADDR_H
#define IMSD_UTIL_IFADDR_H
#include <stdbool.h>
#include "addr.h"

/*
 * IPv4 address of a network interface (the LAN bridge) with a short getifaddrs() call
 * (one RTM_GETADDR netlink dump in the C library: no waiting on anything but the kernel).
 * Returns 0 and sets *out (port 0) to `prefer` when that address is still configured on the
 * interface, otherwise to the interface's first IPv4 address. -1 when the interface has none
 * (or does not exist, or is down without an address). prefer may be NULL.
 */
int ifaddr_first_v4(const char *ifname, const struct addr *prefer, struct addr *out);
#endif
