/* SPDX-License-Identifier: GPL-2.0-or-later */
/* rtnetlink request/ack through libmnl: short synchronous requests to the local kernel. */
#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include "netcfg.h"
#include "../util/log.h"

#define RTNL_RCV_TIMEOUT_S 2

static struct mnl_socket *rtnl_open(void)
{
	struct mnl_socket *nl = mnl_socket_open(NETLINK_ROUTE);
	struct timeval tv = { RTNL_RCV_TIMEOUT_S, 0 };

	if (!nl)
		return NULL;
	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		int e = errno;

		mnl_socket_close(nl);
		errno = e;
		return NULL;
	}
	setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return nl;
}

/* one request, wait for its ack. 0 or -errno */
static int rtnl_txn(struct mnl_socket *nl, const struct netcfg_msg *m)
{
	uint32_t seq = ((const struct nlmsghdr *)m->buf)->nlmsg_seq;

	if (mnl_socket_sendto(nl, m->buf, m->len) < 0)
		return -errno;
	for (;;) {
		char rb[MNL_SOCKET_BUFFER_SIZE];
		ssize_t n = mnl_socket_recvfrom(nl, rb, sizeof(rb));
		struct nlmsghdr *h = (struct nlmsghdr *)rb;
		int left;

		if (n < 0)
			return errno == EAGAIN || errno == EWOULDBLOCK ? -ETIMEDOUT : -errno;
		left = n;
		for (; mnl_nlmsg_ok(h, left); h = mnl_nlmsg_next(h, &left)) {
			if (h->nlmsg_seq != seq)
				continue;
			if (h->nlmsg_type == NLMSG_ERROR)
				return ((const struct nlmsgerr *)mnl_nlmsg_get_payload(h))->error;
		}
	}
}

/* strict: the first failing non-optional message aborts (its errno is returned); otherwise everything is best effort */
static int run_plan(struct mnl_socket *nl, struct netcfg_msg *msgs, int n, bool strict)
{
	int i;

	for (i = 0; i < n; i++) {
		int r = rtnl_txn(nl, &msgs[i]);

		if (r && strict && !msgs[i].optional) {
			LOGE("netcfg: %s failed: %s", msgs[i].what, strerror(-r));
			return r;
		}
	}
	return 0;
}

static int io_apply(void *ctx, const struct netcfg_params *p)
{
	struct netcfg_msg msgs[NETCFG_MAX_MSGS];
	struct mnl_socket *nl;
	int idx = if_nametoindex(p->ifname), n, r;

	(void)ctx;
	if (!idx)
		return -ENODEV;
	n = netcfg_plan_apply(p, idx, 100, msgs);
	if (n < 0)
		return -EINVAL;
	nl = rtnl_open();
	if (!nl)
		return -errno;
	r = run_plan(nl, msgs, n, true);
	if (r) {
		n = netcfg_plan_remove(p, idx, 200, msgs);
		if (n > 0)
			run_plan(nl, msgs, n, false);
	}
	mnl_socket_close(nl);
	return r;
}

static void io_remove(void *ctx, const struct netcfg_params *p)
{
	struct netcfg_msg msgs[NETCFG_MAX_MSGS];
	struct mnl_socket *nl;
	int idx = if_nametoindex(p->ifname), n;

	(void)ctx;
	n = netcfg_plan_remove(p, idx, 300, msgs);	/* idx 0: the device is gone, routes went with it */
	if (n < 0)
		return;
	nl = rtnl_open();
	if (!nl)
		return;
	run_plan(nl, msgs, n, false);
	mnl_socket_close(nl);
}

static const struct netcfg_ops io_ops = { .apply = io_apply, .remove = io_remove };

const struct netcfg_ops *netcfg_io_ops(void)
{
	return &io_ops;
}
