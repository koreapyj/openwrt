/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/fib_rules.h>
#include "test.h"
#include "../modem/netcfg.h"
#include "../modem/qrtr.h"

static const struct nlattr *find_attr(const uint8_t *m, size_t off, size_t total, int type)
{
	while (off + NLA_HDRLEN <= total) {
		const struct nlattr *a = (const struct nlattr *)(m + off);

		if (a->nla_len < NLA_HDRLEN || off + a->nla_len > total)
			return NULL;
		if ((a->nla_type & NLA_TYPE_MASK) == type)
			return a;
		off += NLA_ALIGN(a->nla_len);
	}
	return NULL;
}

#define ATTR_U32(a) (*(const uint32_t *)((const uint8_t *)(a) + NLA_HDRLEN))

static struct netcfg_params P6(void)
{
	struct netcfg_params p;

	memset(&p, 0, sizeof(p));
	snprintf(p.ifname, sizeof(p.ifname), "wwan0");
	addr_set(&p.local, "2001:4430:141:990a:25b5:899e:232:cb69", 0);
	p.prefix = 64;
	p.mtu = 1400;
	p.table = 1006;
	return p;
}

void test_net(void)
{
	struct netcfg_params p = P6();
	struct netcfg_msg m[NETCFG_MAX_MSGS];
	const struct nlmsghdr *h;
	const struct nlattr *a;
	int n, i;
	uint8_t raw[16];

	/* ---- apply plan, IPv6 ---- */
	n = netcfg_plan_apply(&p, 7, 100, m);
	CHECK_EQ(n, 6);
	for (i = 0; i < n; i++) {
		h = (const struct nlmsghdr *)m[i].buf;
		CHECK_EQ(h->nlmsg_len, m[i].len); CHECK_EQ(NLMSG_ALIGN(m[i].len), m[i].len);
		CHECK_EQ(h->nlmsg_seq, 100 + i);
		CHECK((h->nlmsg_flags & (NLM_F_REQUEST | NLM_F_ACK)) == (NLM_F_REQUEST | NLM_F_ACK));
	}
	/* 0: stale rule removal (optional) */
	h = (const struct nlmsghdr *)m[0].buf;
	CHECK_EQ(h->nlmsg_type, RTM_DELRULE); CHECK(m[0].optional);
	/* 1: link up + mtu */
	h = (const struct nlmsghdr *)m[1].buf;
	CHECK_EQ(h->nlmsg_type, RTM_NEWLINK);
	{
		const struct ifinfomsg *ifi = NLMSG_DATA(h);

		CHECK_EQ(ifi->ifi_index, 7); CHECK(ifi->ifi_flags & IFF_UP); CHECK(ifi->ifi_change & IFF_UP);
		a = find_attr(m[1].buf, NLMSG_HDRLEN + sizeof(*ifi), m[1].len, IFLA_MTU);
		CHECK(a && ATTR_U32(a) == 1400);
	}
	/* 2: address with nodad */
	h = (const struct nlmsghdr *)m[2].buf;
	CHECK_EQ(h->nlmsg_type, RTM_NEWADDR); CHECK(!m[2].optional);
	{
		const struct ifaddrmsg *ifa = NLMSG_DATA(h);

		CHECK_EQ(ifa->ifa_family, AF_INET6); CHECK_EQ(ifa->ifa_prefixlen, 64); CHECK_EQ(ifa->ifa_index, 7);
		CHECK(ifa->ifa_flags & IFA_F_NODAD);
		a = find_attr(m[2].buf, NLMSG_HDRLEN + sizeof(*ifa), m[2].len, IFA_LOCAL);
		addr_raw(&p.local, raw);
		CHECK(a && a->nla_len == NLA_HDRLEN + 16 && !memcmp((const uint8_t *)a + NLA_HDRLEN, raw, 16));
		a = find_attr(m[2].buf, NLMSG_HDRLEN + sizeof(*ifa), m[2].len, IFA_FLAGS);
		CHECK(a && (ATTR_U32(a) & IFA_F_NODAD));
	}
	/* 3: on-link prefix route in the table (masked to /64) */
	h = (const struct nlmsghdr *)m[3].buf;
	CHECK_EQ(h->nlmsg_type, RTM_NEWROUTE);
	{
		const struct rtmsg *rt = NLMSG_DATA(h);
		uint8_t net[16];

		CHECK_EQ(rt->rtm_family, AF_INET6); CHECK_EQ(rt->rtm_dst_len, 64); CHECK_EQ(rt->rtm_scope, RT_SCOPE_LINK);
		CHECK_EQ(rt->rtm_type, RTN_UNICAST);
		a = find_attr(m[3].buf, NLMSG_HDRLEN + sizeof(*rt), m[3].len, RTA_TABLE);
		CHECK(a && ATTR_U32(a) == 1006);
		a = find_attr(m[3].buf, NLMSG_HDRLEN + sizeof(*rt), m[3].len, RTA_OIF);
		CHECK(a && ATTR_U32(a) == 7);
		a = find_attr(m[3].buf, NLMSG_HDRLEN + sizeof(*rt), m[3].len, RTA_DST);
		memcpy(net, raw, 16); memset(net + 8, 0, 8);
		CHECK(a && !memcmp((const uint8_t *)a + NLA_HDRLEN, net, 16));
	}
	/* 4: default route in the table, no gateway */
	h = (const struct nlmsghdr *)m[4].buf;
	{
		const struct rtmsg *rt = NLMSG_DATA(h);

		CHECK_EQ(h->nlmsg_type, RTM_NEWROUTE); CHECK_EQ(rt->rtm_dst_len, 0);
		CHECK(!find_attr(m[4].buf, NLMSG_HDRLEN + sizeof(*rt), m[4].len, RTA_DST));
		CHECK(!find_attr(m[4].buf, NLMSG_HDRLEN + sizeof(*rt), m[4].len, RTA_GATEWAY));
		a = find_attr(m[4].buf, NLMSG_HDRLEN + sizeof(*rt), m[4].len, RTA_TABLE);
		CHECK(a && ATTR_U32(a) == 1006);
	}
	/* 5: from <local>/128 lookup 1006 */
	h = (const struct nlmsghdr *)m[5].buf;
	CHECK_EQ(h->nlmsg_type, RTM_NEWRULE);
	{
		const struct fib_rule_hdr *fr = NLMSG_DATA(h);

		CHECK_EQ(fr->family, AF_INET6); CHECK_EQ(fr->src_len, 128); CHECK_EQ(fr->action, FR_ACT_TO_TBL);
		a = find_attr(m[5].buf, NLMSG_HDRLEN + sizeof(*fr), m[5].len, FRA_SRC);
		CHECK(a && !memcmp((const uint8_t *)a + NLA_HDRLEN, raw, 16));
		a = find_attr(m[5].buf, NLMSG_HDRLEN + sizeof(*fr), m[5].len, FRA_TABLE);
		CHECK(a && ATTR_U32(a) == 1006);
		a = find_attr(m[5].buf, NLMSG_HDRLEN + sizeof(*fr), m[5].len, FRA_PRIORITY);
		CHECK(a && ATTR_U32(a) == 1006);	/* default: the table id */
	}
	p.rule_pref = 500;
	n = netcfg_plan_apply(&p, 7, 1, m);
	a = find_attr(m[5].buf, NLMSG_HDRLEN + sizeof(struct fib_rule_hdr), m[5].len, FRA_PRIORITY);
	CHECK(n == 6 && a && ATTR_U32(a) == 500);

	/* ---- remove plan ---- */
	p = P6();
	n = netcfg_plan_remove(&p, 7, 10, m);
	CHECK_EQ(n, 5);
	CHECK_EQ(((const struct nlmsghdr *)m[0].buf)->nlmsg_type, RTM_DELRULE);
	CHECK_EQ(((const struct nlmsghdr *)m[1].buf)->nlmsg_type, RTM_DELROUTE);
	CHECK_EQ(((const struct nlmsghdr *)m[2].buf)->nlmsg_type, RTM_DELROUTE);
	CHECK_EQ(((const struct nlmsghdr *)m[3].buf)->nlmsg_type, RTM_DELADDR);
	CHECK_EQ(((const struct nlmsghdr *)m[4].buf)->nlmsg_type, RTM_NEWLINK);	/* the link goes down with the configuration */
	{
		const struct ifinfomsg *ifi = (const struct ifinfomsg *)(m[4].buf + NLMSG_HDRLEN);

		CHECK(ifi->ifi_index == 7 && !(ifi->ifi_flags & IFF_UP) && (ifi->ifi_change & IFF_UP));
	}
	for (i = 0; i < n; i++) CHECK(m[i].optional);
	n = netcfg_plan_remove(&p, 0, 10, m);	/* device gone: no address deletion, no OIF */
	CHECK_EQ(n, 3);
	CHECK(!find_attr(m[1].buf, NLMSG_HDRLEN + sizeof(struct rtmsg), m[1].len, RTA_OIF));

	/* ---- IPv4 ---- */
	memset(&p, 0, sizeof(p));
	snprintf(p.ifname, sizeof(p.ifname), "wwan0");
	addr_set(&p.local, "10.113.42.9", 0);
	p.prefix = 29; p.table = 1006;
	n = netcfg_plan_apply(&p, 3, 1, m);
	CHECK_EQ(n, 6);
	{
		const struct ifaddrmsg *ifa = NLMSG_DATA((const struct nlmsghdr *)m[2].buf);
		const struct rtmsg *rt = NLMSG_DATA((const struct nlmsghdr *)m[3].buf);
		const struct fib_rule_hdr *fr = NLMSG_DATA((const struct nlmsghdr *)m[5].buf);

		CHECK_EQ(ifa->ifa_family, AF_INET); CHECK_EQ(ifa->ifa_prefixlen, 29); CHECK(!(ifa->ifa_flags & IFA_F_NODAD));
		a = find_attr(m[2].buf, NLMSG_HDRLEN + sizeof(*ifa), m[2].len, IFA_LOCAL);
		CHECK(a && a->nla_len == NLA_HDRLEN + 4);
		a = find_attr(m[3].buf, NLMSG_HDRLEN + sizeof(*rt), m[3].len, RTA_DST);
		{
			const uint8_t *d = (const uint8_t *)a + NLA_HDRLEN;

			CHECK(a && d[0] == 10 && d[1] == 113 && d[2] == 42 && d[3] == 8);	/* 10.113.42.9/29 -> .8 */
		}
		CHECK_EQ(fr->src_len, 32); CHECK_EQ(fr->family, AF_INET);
	}
	/* no prefix: /32 for v4, /64 for v6 */
	p.prefix = 0;
	CHECK_EQ(netcfg_prefix(&p), 32);
	p = P6(); p.prefix = 0;
	CHECK_EQ(netcfg_prefix(&p), 64);
	/* bad parameter sets */
	p = P6(); p.table = 254;
	CHECK(netcfg_plan_apply(&p, 7, 1, m) < 0);
	p = P6(); p.table = 0;
	CHECK(netcfg_plan_apply(&p, 7, 1, m) < 0);
	p = P6(); p.ifname[0] = 0;
	CHECK(netcfg_plan_remove(&p, 7, 1, m) < 0);
	p = P6();
	CHECK(netcfg_plan_apply(&p, 0, 1, m) < 0);
}

void test_qrtr(void)
{
	uint8_t pkt[32];
	uint32_t cmd;
	struct qrtr_server s;

	CHECK_EQ(qrtr_build_lookup(pkt, sizeof(pkt), 0), 20);
	CHECK(pkt[0] == 10 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0);	/* QRTR_TYPE_NEW_LOOKUP, little endian */
	CHECK(!qrtr_parse_ctrl(pkt, 20, &cmd, &s));
	CHECK_EQ(cmd, QRTR_CTRL_NEW_LOOKUP); CHECK(qrtr_is_end(&s));
	CHECK_EQ(qrtr_build_lookup(pkt, sizeof(pkt), 33), 20);
	CHECK_EQ(pkt[4], 33);
	CHECK(qrtr_build_lookup(pkt, 19, 0) < 0);
	/* NEW_SERVER for service 18 instance 1 at node 0 port 0x1a */
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 4; pkt[4] = 18; pkt[8] = 1; pkt[12] = 0; pkt[16] = 0x1a;
	CHECK(!qrtr_parse_ctrl(pkt, 20, &cmd, &s));
	CHECK_EQ(cmd, QRTR_CTRL_NEW_SERVER);
	CHECK(s.service == 18 && s.instance == 1 && s.node == 0 && s.port == 0x1a);
	CHECK(!qrtr_is_end(&s)); CHECK(qrtr_is_ims_service(s.service));
	CHECK(qrtr_is_ims_service(33)); CHECK(!qrtr_is_ims_service(2)); CHECK(!qrtr_is_ims_service(0));
	CHECK(qrtr_parse_ctrl(pkt, 19, &cmd, &s) < 0);
	/* the end marker: a NEW_SERVER with everything zero */
	memset(pkt, 0, sizeof(pkt)); pkt[0] = 4;
	CHECK(!qrtr_parse_ctrl(pkt, 20, &cmd, &s));
	CHECK(cmd == QRTR_CTRL_NEW_SERVER && qrtr_is_end(&s));
}
