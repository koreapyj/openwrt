/* SPDX-License-Identifier: GPL-2.0-or-later */
/* NETLINK_XFRM request/ack through libmnl. The only synchronous kernel call in the daemon. */
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>	/* before the linux/ headers: musl needs it first */
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include "xfrm.h"
#include "../util/log.h"

#define XFRM_RCV_TIMEOUT_S 2

typedef int (*msg_fn)(uint8_t *, size_t, uint32_t, const struct xfrm_sa_params *, const struct xfrm_leg *);

static struct mnl_socket *xfrm_open(void)
{
	struct mnl_socket *nl = mnl_socket_open(NETLINK_XFRM);
	struct timeval tv = { XFRM_RCV_TIMEOUT_S, 0 };

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

/* one request, wait for its ack; returns 0 or -errno */
static int xfrm_txn(struct mnl_socket *nl, const uint8_t *msg, size_t len, uint32_t seq)
{
	if (mnl_socket_sendto(nl, msg, len) < 0)
		return -errno;
	for (;;) {
		char rb[MNL_SOCKET_BUFFER_SIZE];
		ssize_t n = mnl_socket_recvfrom(nl, rb, sizeof(rb));
		struct nlmsghdr *h = (struct nlmsghdr *)rb;

		if (n < 0)
			return errno == EAGAIN || errno == EWOULDBLOCK ? -ETIMEDOUT : -errno;
		int left = n;

		for (; mnl_nlmsg_ok(h, left); h = mnl_nlmsg_next(h, &left)) {
			if (h->nlmsg_seq != seq)
				continue;
			if (h->nlmsg_type == NLMSG_ERROR) {
				const struct nlmsgerr *e = mnl_nlmsg_get_payload(h);

				return e->error;	/* 0 for a plain ack, else -errno */
			}
		}
	}
}

static int run(struct mnl_socket *nl, msg_fn fn, const struct xfrm_sa_params *p, const struct xfrm_leg *l, uint32_t *seq)
{
	uint8_t buf[XFRM_MSG_BUFSZ];
	int n = fn(buf, sizeof(buf), ++*seq, p, l);

	if (n < 0)
		return -EINVAL;
	return xfrm_txn(nl, buf, n, *seq);
}

static int remove_all(struct mnl_socket *nl, const struct xfrm_sa_params *p, uint32_t *seq)
{
	struct xfrm_leg legs[XFRM_NLEGS];
	int i, failed = 0, r;

	xfrm_legs(p, legs);
	for (i = XFRM_NLEGS - 1; i >= 0; i--) {
		r = run(nl, xfrm_msg_delpolicy, p, &legs[i], seq);
		if (r && r != -ENOENT)
			failed++;
	}
	for (i = XFRM_NLEGS - 1; i >= 0; i--) {
		r = run(nl, xfrm_msg_delsa, p, &legs[i], seq);
		if (r && r != -ESRCH && r != -ENOENT)
			failed++;
	}
	return failed;
}

int xfrm_sa_install(const struct xfrm_sa_params *p)
{
	struct mnl_socket *nl = xfrm_open();
	struct xfrm_leg legs[XFRM_NLEGS];
	uint32_t seq = 1;
	int i, r = 0;

	if (!nl)
		return -errno;
	xfrm_legs(p, legs);
	for (i = 0; i < XFRM_NLEGS && !r; i++)
		r = run(nl, xfrm_msg_newsa, p, &legs[i], &seq);
	for (i = 0; i < XFRM_NLEGS && !r; i++)
		r = run(nl, xfrm_msg_newpolicy, p, &legs[i], &seq);
	if (r) {
		LOGE("xfrm: install failed: %s, rolling back", strerror(-r));
		remove_all(nl, p, &seq);
	}
	mnl_socket_close(nl);
	return r;
}

int xfrm_sa_remove(const struct xfrm_sa_params *p)
{
	struct mnl_socket *nl = xfrm_open();
	uint32_t seq = 1;
	int failed;

	if (!nl)
		return XFRM_NLEGS * 2;
	failed = remove_all(nl, p, &seq);
	mnl_socket_close(nl);
	return failed;
}
