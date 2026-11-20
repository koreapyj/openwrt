/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "transport.h"
#include "msg.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

struct udp_priv {
	int rx_fd, tx_fd;	/* equal when not split */
	struct ev_fd *w;
};

static int udp_socket(const struct sip_ep_cfg *c, const struct addr *bind_to, struct addr *local)
{
	int fd, off = 0, e;
	socklen_t sl = sizeof(local->sa);
	struct sockaddr_in6 sa = bind_to->sa;

	fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
	if (c->netdev && c->netdev[0] &&
	    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, c->netdev, strlen(c->netdev) + 1)) {
		e = errno;
		LOGE("%s: SO_BINDTODEVICE %s: %s", c->name, c->netdev, strerror(e));
		goto fail;
	}
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) {
		char as[INET6_ADDRSTRLEN + 8];

		e = errno;
		addr_str(bind_to, as, sizeof(as));
		LOGE("%s: bind %s: %s", c->name, as, strerror(e));
		goto fail;
	}
	if (getsockname(fd, (struct sockaddr *)&local->sa, &sl))
		local->sa = sa;
	return fd;
fail:
	close(fd);
	errno = e;
	return -1;
}

static void udp_rx(void *arg, int fd)
{
	struct sip_endpoint *ep = arg;
	uint8_t buf[SIP_MAX_MSG + 1];
	int i;

	sip_ep_ref(ep);		/* the callback may retire us */
	for (i = 0; i < 32; i++) {
		struct sockaddr_in6 from;
		socklen_t fl = sizeof(from);
		ssize_t n = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
		struct addr src;

		if (n < 0)
			break;
		if (n > SIP_MAX_MSG) {
			LOGW("%s: dropping oversized datagram", ep->name);
			continue;
		}
		addr_from_sa6(&src, &from);
		sip_ep_deliver(ep, &src, buf, n);
	}
	sip_ep_unref(ep);
}

static int udp_send(struct sip_endpoint *ep, const struct addr *dst, const void *data, size_t len)
{
	struct udp_priv *p = ep->priv;
	ssize_t n = sendto(p->tx_fd, data, len, MSG_DONTWAIT | MSG_NOSIGNAL,
			   (const struct sockaddr *)&dst->sa, sizeof(dst->sa));

	if (n < 0)
		return -errno;
	return (size_t)n == len ? 0 : -EMSGSIZE;
}

static void udp_close(struct sip_endpoint *ep)
{
	struct udp_priv *p = ep->priv;

	ev_fd_del(p->w);
	if (p->tx_fd != p->rx_fd)
		close(p->tx_fd);
	close(p->rx_fd);
	free(p);
}

static const struct sip_ep_ops udp_ops = { .send = udp_send, .close = udp_close };

struct sip_endpoint *sip_ep_create_custom(const struct sip_ep_cfg *cfg, const struct sip_ep_ops *ops, void *priv)
{
	struct sip_endpoint *ep = calloc(1, sizeof(*ep));

	if (!ep)
		return NULL;
	str_copy(ep->name, cfg->name ? cfg->name : "ep", sizeof(ep->name));
	ep->kind = cfg->kind;
	ep->reliable = cfg->reliable;
	ep->local_rx = cfg->rx_bind;
	ep->local_tx = cfg->split_tx ? cfg->tx_bind : cfg->rx_bind;
	ep->advertised = cfg->has_adv ? cfg->adv : cfg->rx_bind;
	ep->has_resp_override = cfg->has_resp_override;
	ep->resp_override = cfg->resp_override;
	ep->rx_cb = cfg->rx_cb;
	ep->rx_arg = cfg->rx_arg;
	ep->refs = 1;
	ep->ops = ops;
	ep->priv = priv;
	return ep;
}

struct sip_endpoint *sip_ep_open(const struct sip_ep_cfg *cfg)
{
	struct sip_ep_cfg c = *cfg;
	struct udp_priv *p;
	struct sip_endpoint *ep;
	struct addr lrx = cfg->rx_bind, ltx = cfg->rx_bind;
	int e;

	if (cfg->kind != SIP_TP_UDP) {
		LOGE("%s: stream transport not implemented", cfg->name ? cfg->name : "ep");
		errno = ENOTSUP;
		return NULL;
	}
	p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;
	p->rx_fd = udp_socket(cfg, &cfg->rx_bind, &lrx);
	if (p->rx_fd < 0)
		goto fail_p;
	p->tx_fd = p->rx_fd;
	if (cfg->split_tx) {
		p->tx_fd = udp_socket(cfg, &cfg->tx_bind, &ltx);
		if (p->tx_fd < 0)
			goto fail_rx;
		c.tx_bind = ltx;
	}
	c.rx_bind = lrx;
	c.reliable = false;
	ep = sip_ep_create_custom(&c, &udp_ops, p);
	if (!ep)
		goto fail_tx;
	ep->local_tx = cfg->split_tx ? ltx : lrx;
	p->w = ev_fd_add(p->rx_fd, udp_rx, ep);
	if (!p->w) {
		free(ep);
		goto fail_tx;
	}
	return ep;
fail_tx:
	if (p->tx_fd != p->rx_fd)
		close(p->tx_fd);
fail_rx:
	e = errno ? errno : ENOMEM;
	close(p->rx_fd);
	errno = e;
fail_p:
	e = errno;
	free(p);
	errno = e;
	return NULL;
}

struct sip_endpoint *sip_ep_ref(struct sip_endpoint *ep)
{
	ep->refs++;
	return ep;
}

void sip_ep_unref(struct sip_endpoint *ep)
{
	if (!ep || --ep->refs > 0)
		return;
	if (ep->ops && ep->ops->close)
		ep->ops->close(ep);
	free(ep);
}

void sip_ep_retire(struct sip_endpoint *ep)
{
	if (!ep->retired) {
		ep->retired = true;
		sip_ep_unref(ep);
	}
}

void sip_ep_set_rx(struct sip_endpoint *ep, sip_rx_cb cb, void *arg)
{
	ep->rx_cb = cb;
	ep->rx_arg = arg;
}

int sip_ep_send(struct sip_endpoint *ep, const struct addr *dst, const void *data, size_t len)
{
	int r = ep->ops->send(ep, dst, data, len);

	if (!r) {
		ep->tx_ok++;
		return 0;
	}
	if (r == -EAGAIN || r == -EWOULDBLOCK || r == -ENOBUFS) {
		ep->tx_dropped++;
		LOGW("%s: send queue full, datagram dropped (%zu bytes)", ep->name, len);
		return -EAGAIN;
	}
	ep->tx_err++;
	LOGW("%s: send failed: %s", ep->name, strerror(-r));
	return r;
}

void sip_ep_deliver(struct sip_endpoint *ep, const struct addr *src, const uint8_t *data, size_t len)
{
	ep->rx_msgs++;
	if (ep->rx_cb)
		ep->rx_cb(ep, src, data, len, ep->rx_arg);
}
