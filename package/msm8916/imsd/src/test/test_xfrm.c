/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include "test.h"
#include "../gm/xfrm.h"

static struct xfrm_sa_params params(bool v4, bool sha1)
{
	struct xfrm_sa_params p;
	int i;

	memset(&p, 0, sizeof(p));
	addr_set(&p.ue, v4 ? "192.0.2.10" : "2001:db8::1", 0);
	addr_set(&p.pcscf, v4 ? "198.51.100.7" : "2001:db8::2", 0);
	p.spi_uc = 1001; p.spi_us = 1002; p.spi_pc = 2001; p.spi_ps = 2002;
	p.port_uc = 8001; p.port_us = 8901; p.port_pc = 5073; p.port_ps = 5071;
	p.reqid = 4000; p.sha1 = sha1;
	for (i = 0; i < 16; i++) p.ik[i] = i + 1;
	return p;
}

/* find attribute type in the attribute area starting at off; NULL if absent */
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

static void check_sa(const struct xfrm_sa_params *p, int leg, bool v4, bool sha1, uint32_t spi, uint32_t sport, uint32_t dport,
		     const void *src, const void *dst, size_t alen)
{
	uint8_t buf[XFRM_MSG_BUFSZ];
	struct xfrm_leg legs[XFRM_NLEGS];
	int n;
	const struct nlmsghdr *h = (const struct nlmsghdr *)buf;
	const struct xfrm_usersa_info *si;
	const struct nlattr *a;
	const struct xfrm_algo_auth *aa;
	size_t off;
	uint8_t key[20] = {0};
	int i;

	xfrm_legs(p, legs);
	n = xfrm_msg_newsa(buf, sizeof(buf), 77 + leg, p, &legs[leg]);
	CHECK(n > 0);
	CHECK_EQ(h->nlmsg_len, n); CHECK_EQ(NLMSG_ALIGN(n), n);
	CHECK_EQ(h->nlmsg_type, XFRM_MSG_NEWSA); CHECK_EQ(h->nlmsg_seq, 77 + leg);
	CHECK((h->nlmsg_flags & (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)) == (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL));
	si = NLMSG_DATA(h);
	CHECK_EQ(si->id.proto, IPPROTO_ESP); CHECK_EQ(ntohl(si->id.spi), spi);
	CHECK_EQ(si->family, v4 ? AF_INET : AF_INET6); CHECK_EQ(si->mode, XFRM_MODE_TRANSPORT); CHECK_EQ(si->reqid, 4000 + leg);
	CHECK(!memcmp(&si->id.daddr, dst, alen)); CHECK(!memcmp(&si->saddr, src, alen));
	CHECK_EQ(si->sel.family, v4 ? AF_INET : AF_INET6); CHECK_EQ(si->sel.proto, IPPROTO_UDP);
	CHECK_EQ(ntohs(si->sel.sport), sport); CHECK_EQ(ntohs(si->sel.dport), dport);
	CHECK_EQ(si->sel.sport_mask, 0xffff); CHECK_EQ(si->sel.dport_mask, 0xffff);
	CHECK_EQ(si->sel.prefixlen_s, v4 ? 32 : 128); CHECK_EQ(si->sel.prefixlen_d, v4 ? 32 : 128);
	CHECK(!memcmp(&si->sel.saddr, src, alen)); CHECK(!memcmp(&si->sel.daddr, dst, alen));
	CHECK(si->lft.hard_byte_limit == XFRM_INF && si->lft.soft_packet_limit == XFRM_INF);
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*si));
	a = find_attr(buf, off, n, XFRMA_ALG_AUTH_TRUNC);
	CHECK(a != NULL);
	if (a) {
		aa = (const struct xfrm_algo_auth *)((const uint8_t *)a + NLA_HDRLEN);
		CHECK_STR(aa->alg_name, sha1 ? "hmac(sha1)" : "hmac(md5)");
		CHECK_EQ(aa->alg_key_len, sha1 ? 160 : 128); CHECK_EQ(aa->alg_trunc_len, 96);
		CHECK_EQ(a->nla_len, NLA_HDRLEN + sizeof(*aa) + (sha1 ? 20 : 16));
		for (i = 0; i < 16; i++) key[i] = i + 1;	/* IK, sha1 adds four zero bytes */
		CHECK(!memcmp(aa->alg_key, key, sha1 ? 20 : 16));
	}
	a = find_attr(buf, off, n, XFRMA_ALG_CRYPT);
	CHECK(a != NULL);
	if (a) {
		const struct xfrm_algo *ca = (const struct xfrm_algo *)((const uint8_t *)a + NLA_HDRLEN);

		CHECK_STR(ca->alg_name, "ecb(cipher_null)"); CHECK_EQ(ca->alg_key_len, 0);
	}
	CHECK(find_attr(buf, off, n, XFRMA_TMPL) == NULL);
	CHECK(xfrm_msg_newsa(buf, n - 1, 1, p, &legs[leg]) < 0);	/* does not fit: error */
}

static void t_family(bool v4)
{
	struct xfrm_sa_params p = params(v4, false);
	uint8_t ue[16], ps[16];
	size_t alen = v4 ? 4 : 16;
	uint8_t buf[XFRM_MSG_BUFSZ];
	struct xfrm_leg legs[XFRM_NLEGS];
	int i, n;

	addr_raw(&p.ue, ue); addr_raw(&p.pcscf, ps);
	xfrm_legs(&p, legs);
	/* leg table: out uc->ps (SPI ps), out us->pc (SPI pc), in ps->uc (SPI uc), in pc->us (SPI us) */
	CHECK(!legs[0].in && legs[0].spi == 2002 && legs[0].sport == 8001 && legs[0].dport == 5071);
	CHECK(!legs[1].in && legs[1].spi == 2001 && legs[1].sport == 8901 && legs[1].dport == 5073);
	CHECK(legs[2].in && legs[2].spi == 1001 && legs[2].sport == 5071 && legs[2].dport == 8001);
	CHECK(legs[3].in && legs[3].spi == 1002 && legs[3].sport == 5073 && legs[3].dport == 8901);
	CHECK(addr_equal_ip(&legs[0].src, &p.ue) && addr_equal_ip(&legs[2].src, &p.pcscf));

	check_sa(&p, 0, v4, false, 2002, 8001, 5071, ue, ps, alen);
	check_sa(&p, 1, v4, false, 2001, 8901, 5073, ue, ps, alen);
	check_sa(&p, 2, v4, false, 1001, 5071, 8001, ps, ue, alen);
	check_sa(&p, 3, v4, false, 1002, 5073, 8901, ps, ue, alen);
	{
		struct xfrm_sa_params q = params(v4, true);

		check_sa(&q, 0, v4, true, 2002, 8001, 5071, ue, ps, alen);	/* sha1: key = IK || 00000000 */
	}

	for (i = 0; i < XFRM_NLEGS; i++) {
		const struct nlmsghdr *h = (const struct nlmsghdr *)buf;
		const struct xfrm_userpolicy_info *pi;
		const struct nlattr *a;
		const struct xfrm_user_tmpl *t;
		const uint8_t *src = legs[i].in ? ps : ue, *dst = legs[i].in ? ue : ps;

		n = xfrm_msg_newpolicy(buf, sizeof(buf), 5, &p, &legs[i]);
		CHECK(n > 0); CHECK_EQ(h->nlmsg_len, n);
		CHECK_EQ(h->nlmsg_type, XFRM_MSG_UPDPOLICY);
		CHECK(h->nlmsg_flags & NLM_F_REPLACE);
		pi = NLMSG_DATA(h);
		CHECK_EQ(pi->dir, legs[i].in ? XFRM_POLICY_IN : XFRM_POLICY_OUT); CHECK_EQ(pi->action, XFRM_POLICY_ALLOW);
		CHECK_EQ(pi->sel.proto, IPPROTO_UDP); CHECK_EQ(ntohs(pi->sel.sport), legs[i].sport); CHECK_EQ(ntohs(pi->sel.dport), legs[i].dport);
		CHECK(!memcmp(&pi->sel.saddr, src, alen) && !memcmp(&pi->sel.daddr, dst, alen));
		a = find_attr(buf, NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*pi)), n, XFRMA_TMPL);
		CHECK(a != NULL);
		if (a) {
			CHECK_EQ(a->nla_len, NLA_HDRLEN + sizeof(*t));
			t = (const struct xfrm_user_tmpl *)((const uint8_t *)a + NLA_HDRLEN);
			CHECK_EQ(t->id.proto, IPPROTO_ESP); CHECK_EQ(t->mode, XFRM_MODE_TRANSPORT); CHECK_EQ(t->reqid, 4000 + i);
			CHECK(!memcmp(&t->saddr, src, alen) && !memcmp(&t->id.daddr, dst, alen));
			CHECK_EQ(t->family, v4 ? AF_INET : AF_INET6);
			CHECK_EQ(t->aalgos, 0xffffffffu);
		}
	}

	/* deletions: SA by (daddr, spi, proto) + source address; policy by selector + dir */
	{
		const struct nlmsghdr *h = (const struct nlmsghdr *)buf;
		const struct xfrm_usersa_id *id;
		const struct nlattr *a;

		n = xfrm_msg_delsa(buf, sizeof(buf), 9, &p, &legs[2]);
		CHECK(n > 0); CHECK_EQ(h->nlmsg_type, XFRM_MSG_DELSA); CHECK(!(h->nlmsg_flags & NLM_F_CREATE));
		id = NLMSG_DATA(h);
		CHECK_EQ(ntohl(id->spi), 1001); CHECK_EQ(id->proto, IPPROTO_ESP); CHECK(!memcmp(&id->daddr, ue, alen)); CHECK_EQ(id->family, v4 ? AF_INET : AF_INET6);
		a = find_attr(buf, NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*id)), n, XFRMA_SRCADDR);
		CHECK(a != NULL && !memcmp((const uint8_t *)a + NLA_HDRLEN, ps, alen));
	}
	{
		const struct nlmsghdr *h = (const struct nlmsghdr *)buf;
		const struct xfrm_userpolicy_id *id;

		n = xfrm_msg_delpolicy(buf, sizeof(buf), 10, &p, &legs[3]);
		CHECK(n > 0); CHECK_EQ(h->nlmsg_type, XFRM_MSG_DELPOLICY);
		id = NLMSG_DATA(h);
		CHECK_EQ(id->dir, XFRM_POLICY_IN); CHECK_EQ(ntohs(id->sel.sport), 5073); CHECK_EQ(ntohs(id->sel.dport), 8901);
		CHECK_EQ(id->sel.proto, IPPROTO_UDP);
		CHECK(xfrm_msg_delpolicy(buf, 20, 10, &p, &legs[3]) < 0);
	}
}

void test_xfrm(void)
{
	struct xfrm_sa_params p = params(false, false);
	struct xfrm_leg legs[XFRM_NLEGS];
	uint8_t buf[XFRM_MSG_BUFSZ];

	t_family(false);
	t_family(true);

	/* TCP selector for later: protocol parameter reaches the selector */
	p.proto = IPPROTO_TCP;
	xfrm_legs(&p, legs);
	CHECK(xfrm_msg_newpolicy(buf, sizeof(buf), 1, &p, &legs[0]) > 0);
	CHECK_EQ(((struct xfrm_userpolicy_info *)NLMSG_DATA((struct nlmsghdr *)buf))->sel.proto, IPPROTO_TCP);
	/* mixed families are refused instead of building a bogus message */
	addr_set(&p.pcscf, "198.51.100.7", 0);
	xfrm_legs(&p, legs);
	CHECK(xfrm_msg_newsa(buf, sizeof(buf), 1, &p, &legs[0]) < 0);
	CHECK(xfrm_msg_newpolicy(buf, sizeof(buf), 1, &p, &legs[0]) < 0);
	CHECK(xfrm_msg_delsa(buf, sizeof(buf), 1, &p, &legs[0]) < 0);
}
