/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Pure netlink/XFRM message construction (host testable). */
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include "xfrm.h"

void xfrm_legs(const struct xfrm_sa_params *p, struct xfrm_leg legs[XFRM_NLEGS])
{
	legs[0] = (struct xfrm_leg){ false, p->ue, p->pcscf, p->port_uc, p->port_ps, p->spi_ps, p->reqid };
	legs[1] = (struct xfrm_leg){ false, p->ue, p->pcscf, p->port_us, p->port_pc, p->spi_pc, p->reqid + 1 };
	legs[2] = (struct xfrm_leg){ true, p->pcscf, p->ue, p->port_ps, p->port_uc, p->spi_uc, p->reqid + 2 };
	legs[3] = (struct xfrm_leg){ true, p->pcscf, p->ue, p->port_pc, p->port_us, p->spi_us, p->reqid + 3 };
}

/* ---- tiny netlink writer ---- */
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
	if (!h)
		return NULL;
	h->nlmsg_type = type;
	h->nlmsg_flags = flags;
	h->nlmsg_seq = seq;
	return h;
}

static int nlw_end(struct nlw *w)
{
	struct nlmsghdr *h = (struct nlmsghdr *)w->b;

	if (w->bad)
		return -1;
	h->nlmsg_len = w->len;
	return w->len;
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

/* ---- field helpers ---- */
static void xaddr(xfrm_address_t *x, const struct addr *a)
{
	uint8_t raw[16];
	int n = addr_raw(a, raw);

	memset(x, 0, sizeof(*x));
	memcpy(x, raw, n);	/* a4 / a6 are at offset 0 */
}

static bool same_family(const struct xfrm_leg *l)
{
	return addr_family(&l->src) == addr_family(&l->dst);
}

static void fill_sel(struct xfrm_selector *s, const struct xfrm_sa_params *p, const struct xfrm_leg *l)
{
	int fam = addr_family(&l->src);

	memset(s, 0, sizeof(*s));
	xaddr(&s->daddr, &l->dst);
	xaddr(&s->saddr, &l->src);
	s->dport = htons(l->dport);
	s->dport_mask = 0xffff;
	s->sport = htons(l->sport);
	s->sport_mask = 0xffff;
	s->family = fam;
	s->prefixlen_d = s->prefixlen_s = fam == AF_INET ? 32 : 128;
	s->proto = p->proto ? p->proto : IPPROTO_UDP;
}

static void fill_lft(struct xfrm_lifetime_cfg *c)
{
	c->soft_byte_limit = c->hard_byte_limit = XFRM_INF;
	c->soft_packet_limit = c->hard_packet_limit = XFRM_INF;
}

int xfrm_msg_newsa(uint8_t *buf, size_t cap, uint32_t seq, const struct xfrm_sa_params *p, const struct xfrm_leg *l)
{
	struct nlw w;
	struct nlmsghdr *h = nlw_begin(&w, buf, cap, XFRM_MSG_NEWSA, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, seq);
	struct xfrm_usersa_info *si;
	size_t klen = p->sha1 ? 20 : 16;
	uint8_t abuf[sizeof(struct xfrm_algo_auth) + 20];
	struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)abuf;
	struct xfrm_algo ca;

	if (!h || !same_family(l))
		return -1;
	si = nlw_put(&w, sizeof(*si));
	if (!si)
		return -1;
	fill_sel(&si->sel, p, l);
	xaddr(&si->id.daddr, &l->dst);
	si->id.spi = htonl(l->spi);
	si->id.proto = IPPROTO_ESP;
	xaddr(&si->saddr, &l->src);
	fill_lft(&si->lft);
	si->reqid = l->reqid;
	si->family = addr_family(&l->src);
	si->mode = XFRM_MODE_TRANSPORT;

	memset(abuf, 0, sizeof(abuf));
	strcpy(aa->alg_name, p->sha1 ? "hmac(sha1)" : "hmac(md5)");
	aa->alg_key_len = klen * 8;
	aa->alg_trunc_len = 96;
	memcpy(aa->alg_key, p->ik, 16);	/* sha1: remaining 4 bytes stay 00 */
	nlw_attr(&w, XFRMA_ALG_AUTH_TRUNC, abuf, sizeof(struct xfrm_algo_auth) + klen);

	memset(&ca, 0, sizeof(ca));
	strcpy(ca.alg_name, "ecb(cipher_null)");
	nlw_attr(&w, XFRMA_ALG_CRYPT, &ca, sizeof(ca));
	return nlw_end(&w);
}

int xfrm_msg_delsa(uint8_t *buf, size_t cap, uint32_t seq, const struct xfrm_sa_params *p, const struct xfrm_leg *l)
{
	struct nlw w;
	struct nlmsghdr *h = nlw_begin(&w, buf, cap, XFRM_MSG_DELSA, NLM_F_REQUEST | NLM_F_ACK, seq);
	struct xfrm_usersa_id *id;
	xfrm_address_t src;

	(void)p;
	if (!h || !same_family(l))
		return -1;
	id = nlw_put(&w, sizeof(*id));
	if (!id)
		return -1;
	xaddr(&id->daddr, &l->dst);
	id->spi = htonl(l->spi);
	id->family = addr_family(&l->src);
	id->proto = IPPROTO_ESP;
	xaddr(&src, &l->src);
	nlw_attr(&w, XFRMA_SRCADDR, &src, sizeof(src));
	return nlw_end(&w);
}

int xfrm_msg_newpolicy(uint8_t *buf, size_t cap, uint32_t seq, const struct xfrm_sa_params *p, const struct xfrm_leg *l)
{
	struct nlw w;
	struct nlmsghdr *h = nlw_begin(&w, buf, cap, XFRM_MSG_UPDPOLICY, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, seq);
	struct xfrm_userpolicy_info *pi;
	struct xfrm_user_tmpl t;

	if (!h || !same_family(l))
		return -1;
	pi = nlw_put(&w, sizeof(*pi));
	if (!pi)
		return -1;
	fill_sel(&pi->sel, p, l);
	fill_lft(&pi->lft);
	pi->dir = l->in ? XFRM_POLICY_IN : XFRM_POLICY_OUT;
	pi->action = XFRM_POLICY_ALLOW;
	pi->share = XFRM_SHARE_ANY;

	memset(&t, 0, sizeof(t));
	xaddr(&t.id.daddr, &l->dst);
	t.id.proto = IPPROTO_ESP;
	t.family = addr_family(&l->src);
	xaddr(&t.saddr, &l->src);
	t.reqid = l->reqid;
	t.mode = XFRM_MODE_TRANSPORT;
	t.share = XFRM_SHARE_ANY;
	t.aalgos = t.ealgos = t.calgos = ~(uint32_t)0;
	nlw_attr(&w, XFRMA_TMPL, &t, sizeof(t));
	return nlw_end(&w);
}

int xfrm_msg_delpolicy(uint8_t *buf, size_t cap, uint32_t seq, const struct xfrm_sa_params *p, const struct xfrm_leg *l)
{
	struct nlw w;
	struct nlmsghdr *h = nlw_begin(&w, buf, cap, XFRM_MSG_DELPOLICY, NLM_F_REQUEST | NLM_F_ACK, seq);
	struct xfrm_userpolicy_id *id;

	if (!h || !same_family(l))
		return -1;
	id = nlw_put(&w, sizeof(*id));
	if (!id)
		return -1;
	fill_sel(&id->sel, p, l);
	id->dir = l->in ? XFRM_POLICY_IN : XFRM_POLICY_OUT;
	return nlw_end(&w);
}
