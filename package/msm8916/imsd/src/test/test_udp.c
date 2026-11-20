/* SPDX-License-Identifier: GPL-2.0-or-later */
/* real UDP endpoints over loopback, driven by the fake event loop (fd readiness polled) */
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "test.h"
#include "evloop_fake.h"
#include "../sip/transport.h"

struct got {
	int n;
	char data[256];
	struct addr src;
	struct sip_endpoint *ep;
};

static void on_rx(struct sip_endpoint *ep, const struct addr *src, const uint8_t *d, size_t n, void *arg)
{
	struct got *g = arg;

	g->n++;
	g->ep = ep;
	g->src = *src;
	memcpy(g->data, d, n < 255 ? n : 255);
	g->data[n < 255 ? n : 255] = 0;
}

void test_udp(void)
{
	struct sip_ep_cfg ca, cb;
	struct sip_endpoint *a, *b;
	struct got ga = {0}, gb = {0};
	struct addr dst;
	int probe = socket(AF_INET6, SOCK_DGRAM, 0);
	char s[64];

	if (probe < 0) {
		printf("(skipping udp tests: no IPv6 sockets)\n");
		return;
	}
	close(probe);
	evfake_reset();

	/* a: protected-style endpoint, receive on one socket, send from another; advertised address differs from the bind */
	memset(&ca, 0, sizeof(ca)); memset(&cb, 0, sizeof(cb));
	ca.name = "a"; ca.kind = SIP_TP_UDP; ca.split_tx = true;
	addr_set(&ca.rx_bind, "127.0.0.1", 0); addr_set(&ca.tx_bind, "127.0.0.1", 0);
	ca.has_adv = true; addr_set(&ca.adv, "192.0.2.77", 8901);
	ca.rx_cb = on_rx; ca.rx_arg = &ga;
	cb.name = "b"; cb.kind = SIP_TP_UDP;
	addr_set(&cb.rx_bind, "127.0.0.1", 0);
	cb.rx_cb = on_rx; cb.rx_arg = &gb;
	a = sip_ep_open(&ca); b = sip_ep_open(&cb);
	CHECK(a != NULL && b != NULL);
	if (!a || !b)
		return;
	CHECK_EQ(evfake_fd_watches(), 2);	/* only the rx sockets are watched */
	CHECK(addr_port(&a->local_rx) != 0 && addr_port(&a->local_tx) != 0 && addr_port(&a->local_rx) != addr_port(&a->local_tx));
	CHECK_EQ(addr_port(&b->local_rx) != 0, 1);
	CHECK_EQ(addr_port(&a->advertised), 8901);	/* advertised != bound */
	CHECK(!a->reliable && !b->reliable);
	addr_str(&b->local_rx, s, sizeof(s)); CHECK(!strncmp(s, "127.0.0.1:", 10));

	/* a -> b: arrives from a's TX port (port-c style), not from its rx port */
	CHECK_EQ(sip_ep_send(a, &b->local_rx, "hello", 5), 0);
	CHECK_EQ(evfake_poll_fds(), 1);
	CHECK_EQ(gb.n, 1); CHECK_STR(gb.data, "hello"); CHECK(gb.ep == b);
	CHECK_EQ(addr_port(&gb.src), addr_port(&a->local_tx));
	CHECK(addr_is_v4(&gb.src));
	/* b -> a's RX port is received by a's callback */
	CHECK_EQ(sip_ep_send(b, &a->local_rx, "world", 5), 0);
	CHECK_EQ(evfake_poll_fds(), 1);
	CHECK_EQ(ga.n, 1); CHECK_STR(ga.data, "world"); CHECK_EQ(addr_port(&ga.src), addr_port(&b->local_rx));
	/* a datagram sent to a's TX socket is not delivered (it is not watched) */
	CHECK_EQ(sip_ep_send(b, &a->local_tx, "nope", 4), 0);
	CHECK_EQ(evfake_poll_fds(), 0);
	CHECK_EQ(ga.n, 1);
	CHECK_EQ(a->tx_ok, 1); CHECK_EQ(a->rx_msgs, 1);

	/* refcounting: a retired endpoint keeps working while referenced, and goes away with the last reference */
	sip_ep_ref(a);
	sip_ep_retire(a);
	CHECK(a->retired);
	CHECK_EQ(sip_ep_send(a, &b->local_rx, "late", 4), 0);
	CHECK_EQ(evfake_poll_fds(), 1); CHECK_EQ(gb.n, 2);
	sip_ep_unref(a);
	CHECK_EQ(evfake_fd_watches(), 1);
	sip_ep_retire(b);
	CHECK_EQ(evfake_fd_watches(), 0);

	/* stream transport is a clearly refused stub */
	ca.kind = SIP_TP_TCP;
	errno = 0;
	CHECK(sip_ep_open(&ca) == NULL); CHECK_EQ(errno, ENOTSUP);

	/* bad bind address: error, no leak */
	ca.kind = SIP_TP_UDP; ca.split_tx = false;
	addr_set(&ca.rx_bind, "192.0.2.123", 5060);	/* not a local address */
	errno = 0;
	CHECK(sip_ep_open(&ca) == NULL); CHECK(errno != 0);
	(void)dst;
}
