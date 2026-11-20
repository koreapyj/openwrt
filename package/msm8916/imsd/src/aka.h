/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_AKA_H
#define IMSD_AKA_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * ISIM AKA (UICC AUTHENTICATE, TS 31.102) as a non-blocking state machine.
 *
 * The caller owns the transport (an async ubus call to the modem daemon):
 *
 *   aka_sm_start(&sm, &cfg, rand, autn, apdu, &n);   // send apdu[0..n)
 *   ... response bytes arrive ...
 *   switch (aka_sm_feed(&sm, resp, rn, apdu, &n)) {
 *   case AKA_STEP_SEND: send apdu[0..n) (GET RESPONSE, or AUTHENTICATE with the corrected Le), repeat
 *   case AKA_STEP_DONE: aka_sm_result(&sm)->status is AKA_OK or AKA_SYNC_FAIL (AUTS)
 *   case AKA_STEP_FAIL: card / protocol error, ->sw has the status word if any
 *   }
 *   if the transport itself fails: aka_sm_abort(&sm).
 *
 * Key material (CK, IK, RES) lives in struct aka_result: never log it.
 */

#define ISIM_AID_DEFAULT "A0000000871004"
#define AKA_APDU_MAX 64		/* size of the buffer for outgoing APDUs */

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
	int p2;			/* AUTHENTICATE P2, default 0x81 (0 is replaced by 0x81) */
	int cla_from_channel;	/* put the logical channel number into CLA */
	int channel;
};

enum aka_step { AKA_STEP_SEND, AKA_STEP_DONE, AKA_STEP_FAIL };

struct aka_sm {
	struct aka_cfg cfg;
	uint8_t cmd[AKA_APDU_MAX];
	size_t cmd_len;
	int tries61;
	bool retried6c;
	bool done;
	struct aka_result res;
};

/* CLA for a logical channel (TS 102 221 11.1.1.1.1) */
uint8_t aka_cla(int channel);
/* AUTHENTICATE command: CLA 88 00 P2 22 10 RAND 10 AUTN 00; out needs AKA_APDU_MAX bytes; returns the length */
size_t aka_build_apdu(const struct aka_cfg *c, const uint8_t rand[16], const uint8_t autn[16], uint8_t *out);
/* Parse the card data (DB .. RES CK IK [Kc] / DC AUTS, trailing SW optional). 0 and r->status set, or -1 (r->sw set when the data is a bare status word). */
int aka_parse(const uint8_t *d, size_t n, struct aka_result *r);

/* begin: fills the first APDU */
void aka_sm_start(struct aka_sm *sm, const struct aka_cfg *cfg, const uint8_t rand[16], const uint8_t autn[16],
		  uint8_t apdu[AKA_APDU_MAX], size_t *apdu_len);
/* feed the card response (data + SW1 SW2; a bare data response without SW is tolerated) */
enum aka_step aka_sm_feed(struct aka_sm *sm, const uint8_t *resp, size_t rn, uint8_t apdu[AKA_APDU_MAX], size_t *apdu_len);
/* the transport failed: finish with AKA_ERR */
void aka_sm_abort(struct aka_sm *sm);
const struct aka_result *aka_sm_result(const struct aka_sm *sm);
#endif
