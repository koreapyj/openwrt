/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MODEM_NETCFG_H
#define IMSD_MODEM_NETCFG_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../util/addr.h"

/*
 * Configuration of the IMS netdev through rtnetlink: link up + MTU, the
 * address, and policy routing that only our own sockets use:
 *
 *   ip link set <if> up mtu <mtu>
 *   ip addr add <local>/<prefix> dev <if> [nodad]
 *   ip route replace <prefix> dev <if> table <table>
 *   ip route replace default dev <if> table <table>
 *   ip rule add from <local> lookup <table> pref <pref>
 *
 * The main routing table is never touched. The planning functions build the
 * netlink messages (pure, host testable); netcfg_io.c sends them with libmnl
 * (short synchronous requests to the local kernel, the only allowed blocking
 * kernel calls besides XFRM).
 */
struct netcfg_params {
	char ifname[16];
	struct addr local;	/* v4 or v6; the port is ignored */
	int prefix;		/* 0: 64 (v6) / 32 (v4) */
	int mtu;		/* 0: leave the MTU alone */
	unsigned table;		/* policy routing table id */
	unsigned rule_pref;	/* ip rule priority, 0: same as table */
};

struct netcfg_msg {
	uint8_t buf[256];
	int len;
	bool optional;		/* errors are not fatal (cleanup of leftovers, deletions) */
	const char *what;
};
#define NETCFG_MAX_MSGS 10

/* the messages for apply / remove, in order; ifindex 0 (device gone) omits the OIF. Returns the count, or -1 on a bad parameter set. seq numbers are assigned base+i */
int netcfg_plan_apply(const struct netcfg_params *p, int ifindex, uint32_t seq, struct netcfg_msg out[NETCFG_MAX_MSGS]);
int netcfg_plan_remove(const struct netcfg_params *p, int ifindex, uint32_t seq, struct netcfg_msg out[NETCFG_MAX_MSGS]);
/* effective prefix length */
int netcfg_prefix(const struct netcfg_params *p);

/* backend used by imsmodem (tests plug in a mock) */
struct netcfg_ops {
	/* 0 or -errno; on failure nothing stays configured */
	int (*apply)(void *ctx, const struct netcfg_params *p);
	/* best effort, always removes everything apply() may have added */
	void (*remove)(void *ctx, const struct netcfg_params *p);
	void *ctx;
};
/* the libmnl backend (netcfg_io.c, daemon only) */
const struct netcfg_ops *netcfg_io_ops(void);
#endif
