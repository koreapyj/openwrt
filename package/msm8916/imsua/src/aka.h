/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IMSUA_AKA_H
#define IMSUA_AKA_H
#include <stddef.h>
#include <stdint.h>

#define ISIM_AID_DEFAULT "A0000000871004"

/* transport: send one APDU, get the card response bytes (data + SW1 SW2 expected,
 * but a bare data response without SW is tolerated). returns 0 or -1 */
typedef int (*apdu_fn)(void *ctx, const uint8_t *apdu, size_t n, uint8_t *resp, size_t *rn);

enum aka_status { AKA_OK, AKA_SYNC_FAIL, AKA_ERR };
struct aka_result {
	enum aka_status status;
	uint8_t res[16]; size_t res_len;
	uint8_t ck[16]; uint8_t ik[16];
	uint8_t kc[8]; int has_kc;
	uint8_t auts[14]; size_t auts_len;
	int sw;			/* last status word, -1 if none */
};

struct aka_cfg {
	int p2;			/* AUTHENTICATE P2, default 0x81 */
	int cla_from_channel;	/* put the logical channel number into CLA */
	int channel;
};

/* build the AUTHENTICATE command: CLA 88 00 P2 22 10 RAND 10 AUTN 00 */
size_t aka_build_apdu(const struct aka_cfg *c, const uint8_t rand[16], const uint8_t autn[16], uint8_t *out);
/* parse DB.. / DC.. card data (SW optional at the tail) */
int aka_parse(const uint8_t *d, size_t n, struct aka_result *r);
/* full run with GET RESPONSE handling */
int aka_authenticate(apdu_fn fn, void *ctx, const struct aka_cfg *c,
		     const uint8_t rand[16], const uint8_t autn[16], struct aka_result *r);
uint8_t aka_cla(int channel);

#ifndef IMSUA_NO_UBUS
/* ubus transport (uqmid.modem.N) */
struct aka_ubus;
struct aka_ubus *aka_ubus_open(const char *sock, const char *modem_path, const char *aid, int slot);
void aka_ubus_close(struct aka_ubus *u);
int aka_ubus_apdu(void *ctx, const uint8_t *apdu, size_t n, uint8_t *resp, size_t *rn);
int aka_ubus_channel(const struct aka_ubus *u);
#endif
#endif
