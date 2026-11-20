/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IMSUA_IPSEC_H
#define IMSUA_IPSEC_H
#include <stdint.h>

/* TS 33.203 UE-side SA set. P-CSCF: pc (client) / ps (server); UE: uc / us. */
struct ipsec_sa {
	char ue[64], pcscf[64];
	uint32_t spi_uc, spi_us, spi_pc, spi_ps;
	int port_uc, port_us, port_pc, port_ps;
	int sha1;
	uint8_t ik[16];
	uint32_t reqid;		/* base; +0..3 used */
};

#define IPSEC_MAX_ARGS 48
struct ipsec_cmd {
	char a[IPSEC_MAX_ARGS][96];
	int n;
};
#define IPSEC_NCMD 8

/* fill 8 commands (4 states + 4 policies); add != 0 for install, 0 for removal */
int ipsec_build(const struct ipsec_sa *s, int add, struct ipsec_cmd *out);
/* install; on any failure removes what was installed. 0 on success */
int ipsec_install(const struct ipsec_sa *s);
void ipsec_remove(const struct ipsec_sa *s);
#endif
