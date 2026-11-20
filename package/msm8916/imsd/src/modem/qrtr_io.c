/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Non-blocking QRTR name service lookup on the event loop. */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/qrtr.h>
#include "qrtr.h"
#include "../util/evloop.h"
#include "../util/log.h"

#ifndef AF_QIPCRTR
#define AF_QIPCRTR 42
#endif

#define LOOKUP_TIMEOUT_MS 1500

struct qlookup {
	int fd;
	struct ev_fd *w;
	struct ev_timer *t;
	qrtr_done_cb done;
	void *arg;
	int ims;
	int err;		/* set for an immediate failure */
	bool ended;
};

static void ql_free(struct qlookup *q)
{
	ev_fd_del(q->w);
	ev_timer_free(q->t);
	if (q->fd >= 0)
		close(q->fd);
	free(q);
}

static void ql_finish(struct qlookup *q, int result)
{
	qrtr_done_cb cb = q->done;
	void *arg = q->arg;

	ql_free(q);
	cb(arg, result);
}

static void ql_timeout(void *arg)
{
	struct qlookup *q = arg;

	if (q->err)
		ql_finish(q, q->err);
	else
		ql_finish(q, q->ims > 0 ? q->ims : -ETIMEDOUT);	/* no end marker in time: use what we have */
}

static void ql_readable(void *arg, int fd)
{
	struct qlookup *q = arg;
	uint8_t pkt[256];

	for (;;) {
		struct sockaddr_qrtr from;
		socklen_t fl = sizeof(from);
		ssize_t n = recvfrom(fd, pkt, sizeof(pkt), MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
		uint32_t cmd;
		struct qrtr_server s;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				ql_finish(q, -errno);
			return;
		}
		if (from.sq_port != QRTR_PORT_CTRL || qrtr_parse_ctrl(pkt, n, &cmd, &s) || cmd != QRTR_CTRL_NEW_SERVER)
			continue;
		if (qrtr_is_end(&s)) {
			ql_finish(q, q->ims);
			return;
		}
		if (qrtr_is_ims_service(s.service)) {
			LOGI("qrtr: modem IMS service %u instance %u at node %u port %u", s.service, s.instance, s.node, s.port);
			q->ims++;
		}
	}
}

static void *io_start(void *ctx, qrtr_done_cb done, void *arg)
{
	struct qlookup *q = calloc(1, sizeof(*q));
	struct sockaddr_qrtr me, ns;
	socklen_t ml = sizeof(me);
	uint8_t req[QRTR_CTRL_PKT_LEN];

	(void)ctx;
	if (!q)
		return NULL;
	q->done = done;
	q->arg = arg;
	q->t = ev_timer_new(ql_timeout, q);
	q->fd = socket(AF_QIPCRTR, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (q->fd < 0) {
		q->err = -errno;
		LOGW("qrtr: socket: %s", strerror(errno));
	} else if (getsockname(q->fd, (struct sockaddr *)&me, &ml) < 0) {
		q->err = -errno;
	} else {
		ns.sq_family = AF_QIPCRTR;
		ns.sq_node = me.sq_node;
		ns.sq_port = QRTR_PORT_CTRL;
		qrtr_build_lookup(req, sizeof(req), 0);
		if (sendto(q->fd, req, sizeof(req), MSG_DONTWAIT, (struct sockaddr *)&ns, sizeof(ns)) < 0) {
			q->err = -errno;
			LOGW("qrtr: lookup request: %s", strerror(errno));
		} else if (!(q->w = ev_fd_add(q->fd, ql_readable, q))) {
			q->err = -ENOMEM;
		}
	}
	if (!q->t) {
		ql_free(q);
		return NULL;
	}
	ev_timer_set(q->t, q->err ? 0 : LOOKUP_TIMEOUT_MS);
	return q;
}

static void io_cancel(void *ctx, void *h)
{
	(void)ctx;
	if (h)
		ql_free(h);
}

static const struct qrtr_ops io_ops = { .start = io_start, .cancel = io_cancel };

const struct qrtr_ops *qrtr_io_ops(void)
{
	return &io_ops;
}
