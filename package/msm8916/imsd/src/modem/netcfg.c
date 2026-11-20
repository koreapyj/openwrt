/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Pure rtnetlink message construction for the IMS netdev (host testable). */
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/fib_rules.h>
#include "netcfg.h"

struct nlw {
	uint8_t *b;
	size_t cap, len;
	bool bad;
};

static void *nlw_put(struct nlw *w, size_t n)
{
	size_t a = NLMSG_ALIGN(n);
	void *p;

	if (w->len + a > w->cap) {
		w->bad = true;
		return NULL;
	}
	p = w->b + w->len;
	memset(p, 0, a);
	w->len += a;
	return p;
}

static struct nlmsghdr *nlw_begin(struct nlw *w, uint8_t *buf, size_t cap, uint16_t type, uint16_t flags, uint32_t seq)
{
	struct nlmsghdr *h;

	w->b = buf;
	w->cap = cap;
	w->len = 0;
	w->bad = false;
	h = nlw_put(w, sizeof(*h));
	if (h) {
		h->nlmsg_type = type;
		h->nlmsg_flags = flags;
		h->nlmsg_seq = seq;
	}
	return h;
}

static void nlw_attr(struct nlw *w, uint16_t type, const void *data, size_t n)
{
	struct nlattr *a = nlw_put(w, NLA_HDRLEN + n);

	if (!a)
		return;
	a->nla_type = type;
	a->nla_len = NLA_HDRLEN + n;
	if (n)
		memcpy((uint8_t *)a + NLA_HDRLEN, data, n);
}

static void nlw_attr_u32(struct nlw *w, uint16_t type, uint32_t v)
{
	nlw_attr(w, type, &v, sizeof(v));
}

static int nlw_end(struct nlw *w)
{
	if (w->bad)
		return -1;
	((struct nlmsghdr *)w->b)->nlmsg_len = w->len;
	return w->len;
}

#define REQ (NLM_F_REQUEST | NLM_F_ACK)

int netcfg_prefix(const struct netcfg_params *p)
{
	if (p->prefix > 0)
		return p->prefix;
	return addr_family(&p->local) == AF_INET ? 32 : 64;
}

static void mask_addr(uint8_t *raw, int len, int prefix)
{
	int i;

	for (i = 0; i < len; i++) {
		int bits = prefix - i * 8;

		if (bits >= 8)
			continue;
		raw[i] &= bits <= 0 ? 0 : (uint8_t)(0xff << (8 - bits));
	}
}

static int msg_link(struct netcfg_msg *m, uint32_t seq, int ifindex, int mtu)
{
	struct nlw w;
	struct nlmsghdr *h = nlw_begin(&w, m->buf, sizeof(m->buf), RTM_NEWLINK, REQ, seq);
	struct ifinfomsg *ifi = h ? nlw_put(&w, sizeof(*ifi)) : NULL;

	if (!ifi)
		return -1;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;
	ifi->ifi_flags = IFF_UP;
	ifi->ifi_change = IFF_UP;
	if (mtu > 0)
		nlw_attr_u32(&w, IFLA_MTU, mtu);
	m->len = nlw_end(&w);
	m->what = "link up";
	return m->len < 0 ? -1 : 0;
}

/* The link goes down again with the configuration, as netifd does for its interfaces. A wwan netdev left up
 * would keep its channel "open" on our side only: after a modem restart the modem does not know about it. */
static int msg_link_down(struct netcfg_msg *m, uint32_t seq, int ifindex)
{
	struct nlw w;
	struct nlmsghdr *h = nlw_begin(&w, m->buf, sizeof(m->buf), RTM_NEWLINK, REQ, seq);
	struct ifinfomsg *ifi = h ? nlw_put(&w, sizeof(*ifi)) : NULL;

	if (!ifi)
		return -1;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;
	ifi->ifi_flags = 0;
	ifi->ifi_change = IFF_UP;
	m->len = nlw_end(&w);
	m->what = "link down";
	m->optional = true;
	return m->len < 0 ? -1 : 0;
}

static int msg_addr(struct netcfg_msg *m, uint32_t seq, bool add, int ifindex, const struct netcfg_params *p)
{
	struct nlw w;
	struct nlmsghdr *h = nlw_begin(&w, m->buf, sizeof(m->buf), add ? RTM_NEWADDR : RTM_DELADDR,
				       add ? REQ | NLM_F_CREATE | NLM_F_REPLACE : REQ, seq);
	struct ifaddrmsg *ifa = h ? nlw_put(&w, sizeof(*ifa)) : NULL;
	uint8_t raw[16];
	int fam = addr_family(&p->local), n = addr_raw(&p->local, raw);

	if (!ifa || n < 0)
		return -1;
	ifa->ifa_family = fam;
	ifa->ifa_prefixlen = netcfg_prefix(p);
	ifa->ifa_scope = RT_SCOPE_UNIVERSE;
	ifa->ifa_index = ifindex;
	if (add && fam == AF_INET6)
		ifa->ifa_flags = IFA_F_NODAD;	/* the network assigned the address, no DAD (also keeps it usable at once) */
	nlw_attr(&w, IFA_LOCAL, raw, n);
	nlw_attr(&w, IFA_ADDRESS, raw, n);
	if (add && fam == AF_INET6)
		nlw_attr_u32(&w, IFA_FLAGS, IFA_F_NODAD);
	m->len = nlw_end(&w);
	m->what = add ? "address add" : "address del";
	m->optional = !add;
	return m->len < 0 ? -1 : 0;
}

/* route in the policy table: dst_len 0 = default */
static int msg_route(struct netcfg_msg *m, uint32_t seq, bool add, int ifindex, const struct netcfg_params *p, bool dflt)
{
	struct nlw w;
	struct nlmsghdr *h = nlw_begin(&w, m->buf, sizeof(m->buf), add ? RTM_NEWROUTE : RTM_DELROUTE,
				       add ? REQ | NLM_F_CREATE | NLM_F_REPLACE : REQ, seq);
	struct rtmsg *rt = h ? nlw_put(&w, sizeof(*rt)) : NULL;
	uint8_t raw[16];
	int fam = addr_family(&p->local), n = addr_raw(&p->local, raw), plen = netcfg_prefix(p);

	if (!rt || n < 0)
		return -1;
	rt->rtm_family = fam;
	rt->rtm_dst_len = dflt ? 0 : plen;
	rt->rtm_table = RT_TABLE_UNSPEC;	/* the id goes into RTA_TABLE (ids above 255) */
	rt->rtm_protocol = RTPROT_STATIC;
	rt->rtm_scope = RT_SCOPE_LINK;
	rt->rtm_type = RTN_UNICAST;
	if (!dflt) {
		mask_addr(raw, n, plen);
		nlw_attr(&w, RTA_DST, raw, n);
	}
	if (ifindex > 0)
		nlw_attr_u32(&w, RTA_OIF, ifindex);
	nlw_attr_u32(&w, RTA_TABLE, p->table);
	m->len = nlw_end(&w);
	m->what = dflt ? (add ? "default route add" : "default route del") : (add ? "prefix route add" : "prefix route del");
	m->optional = !add;
	return m->len < 0 ? -1 : 0;
}

static int msg_rule(struct netcfg_msg *m, uint32_t seq, bool add, const struct netcfg_params *p)
{
	struct nlw w;
	struct nlmsghdr *h = nlw_begin(&w, m->buf, sizeof(m->buf), add ? RTM_NEWRULE : RTM_DELRULE,
				       add ? REQ | NLM_F_CREATE | NLM_F_EXCL : REQ, seq);
	struct fib_rule_hdr *fr = h ? nlw_put(&w, sizeof(*fr)) : NULL;
	uint8_t raw[16];
	int fam = addr_family(&p->local), n = addr_raw(&p->local, raw);

	if (!fr || n < 0)
		return -1;
	fr->family = fam;
	fr->src_len = n * 8;
	fr->action = FR_ACT_TO_TBL;
	fr->table = RT_TABLE_UNSPEC;
	nlw_attr(&w, FRA_SRC, raw, n);
	nlw_attr_u32(&w, FRA_PRIORITY, p->rule_pref ? p->rule_pref : p->table);
	nlw_attr_u32(&w, FRA_TABLE, p->table);
	m->len = nlw_end(&w);
	m->what = add ? "rule add" : "rule del";
	m->optional = !add;
	return m->len < 0 ? -1 : 0;
}

static bool params_ok(const struct netcfg_params *p)
{
	uint8_t raw[16];

	return p->ifname[0] && p->table && p->table != RT_TABLE_MAIN && p->table != RT_TABLE_LOCAL &&
	       p->table != RT_TABLE_DEFAULT && addr_raw(&p->local, raw) > 0 && netcfg_prefix(p) <= (addr_family(&p->local) == AF_INET ? 32 : 128);
}

int netcfg_plan_apply(const struct netcfg_params *p, int ifindex, uint32_t seq, struct netcfg_msg out[NETCFG_MAX_MSGS])
{
	int n = 0;

	if (!params_ok(p) || ifindex <= 0)
		return -1;
	memset(out, 0, sizeof(*out) * NETCFG_MAX_MSGS);
	/* a leftover rule of a previous run would make the add fail with EEXIST */
	if (msg_rule(&out[n], seq + n, false, p)) return -1;
	n++;
	if (msg_link(&out[n], seq + n, ifindex, p->mtu)) return -1;
	n++;
	if (msg_addr(&out[n], seq + n, true, ifindex, p)) return -1;
	n++;
	if (msg_route(&out[n], seq + n, true, ifindex, p, false)) return -1;
	n++;
	if (msg_route(&out[n], seq + n, true, ifindex, p, true)) return -1;
	n++;
	if (msg_rule(&out[n], seq + n, true, p)) return -1;
	n++;
	return n;
}

int netcfg_plan_remove(const struct netcfg_params *p, int ifindex, uint32_t seq, struct netcfg_msg out[NETCFG_MAX_MSGS])
{
	int n = 0;

	if (!params_ok(p))
		return -1;
	memset(out, 0, sizeof(*out) * NETCFG_MAX_MSGS);
	if (msg_rule(&out[n], seq + n, false, p)) return -1;
	n++;
	if (msg_route(&out[n], seq + n, false, ifindex, p, true)) return -1;
	n++;
	if (msg_route(&out[n], seq + n, false, ifindex, p, false)) return -1;
	n++;
	if (ifindex > 0) {
		if (msg_addr(&out[n], seq + n, false, ifindex, p)) return -1;
		n++;
		if (msg_link_down(&out[n], seq + n, ifindex)) return -1;
		n++;
	}
	return n;
}
