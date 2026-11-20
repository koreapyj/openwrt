/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_GM_XFRM_H
#define IMSD_GM_XFRM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../util/addr.h"

/*
 * TS 33.203 SA set through NETLINK_XFRM (no `ip` exec).
 *
 * UE: uc (client port/SPI we send from), us (server port/SPI we receive on).
 * P-CSCF: pc (its client), ps (its server). Four ESP transport-mode SAs and
 * four policies with port selectors:
 *   out  uc -> ps   SPI ps          in  ps -> uc   SPI uc
 *   out  us -> pc   SPI pc          in  pc -> us   SPI us
 * Auth: hmac(md5) key = IK, or hmac(sha1) key = IK || 00000000, ICV 96 bit;
 * encryption ecb(cipher_null). One reqid per leg (reqid + 0..3).
 *
 * The message-construction functions (xfrm_msg_*) are pure (no sockets) and
 * unit testable; xfrm_io.c does the synchronous netlink request + ack
 * (kernel-local, bounded by a receive timeout) and returns the kernel's errno.
 */

struct xfrm_sa_params {
	struct addr ue, pcscf;		/* addresses (ports in the addr are ignored; v4 or v6, same family) */
	uint32_t spi_uc, spi_us, spi_pc, spi_ps;
	uint16_t port_uc, port_us, port_pc, port_ps;
	bool sha1;
	uint8_t ik[16];
	uint32_t reqid;			/* base; reqid+0..3 are used */
	uint8_t proto;			/* selector protocol: IPPROTO_UDP (0 means UDP) or IPPROTO_TCP for later */
};

struct xfrm_leg {
	bool in;			/* policy direction */
	struct addr src, dst;		/* of the traffic itself */
	uint16_t sport, dport;
	uint32_t spi;
	uint32_t reqid;
};
#define XFRM_NLEGS 4
/* order: out uc->ps, out us->pc, in ps->uc, in pc->us */
void xfrm_legs(const struct xfrm_sa_params *p, struct xfrm_leg legs[XFRM_NLEGS]);

#define XFRM_MSG_BUFSZ 512	/* enough for any message below */
/*
 * Message builders: write one complete netlink message into buf (cap bytes) and
 * return its length, or -1 if it does not fit / the addresses mix families.
 * flags: NLM_F_REQUEST | NLM_F_ACK plus CREATE|EXCL (SA) or CREATE|REPLACE (policy).
 * The policy install uses XFRM_MSG_UPDPOLICY like `ip xfrm policy update` (the
 * kernel then replaces a stale identical policy instead of failing with EEXIST).
 */
int xfrm_msg_newsa(uint8_t *buf, size_t cap, uint32_t seq, const struct xfrm_sa_params *p, const struct xfrm_leg *l);
int xfrm_msg_delsa(uint8_t *buf, size_t cap, uint32_t seq, const struct xfrm_sa_params *p, const struct xfrm_leg *l);
int xfrm_msg_newpolicy(uint8_t *buf, size_t cap, uint32_t seq, const struct xfrm_sa_params *p, const struct xfrm_leg *l);
int xfrm_msg_delpolicy(uint8_t *buf, size_t cap, uint32_t seq, const struct xfrm_sa_params *p, const struct xfrm_leg *l);

/* Install 4 SAs + 4 policies; on any failure everything installed so far is removed again. 0, or -errno of the kernel / socket failure. Synchronous but bounded (netlink to the local kernel, 2 s receive timeout). */
int xfrm_sa_install(const struct xfrm_sa_params *p);
/* Remove all 8 objects, best effort (missing ones are not an error). Returns the number of deletions that failed for another reason. */
int xfrm_sa_remove(const struct xfrm_sa_params *p);
#endif
