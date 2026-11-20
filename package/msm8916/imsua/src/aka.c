/* SPDX-License-Identifier: GPL-2.0-only */
#include <string.h>
#include <stdio.h>
#include "aka.h"
#include "util.h"

uint8_t aka_cla(int ch)
{
	/* TS 102.221 11.1.1.1.1: channels 1..3 -> bits b2b1; 4..19 -> 0x40 | (ch-4) */
	if (ch <= 0) return 0x00;
	if (ch <= 3) return 0x00 | ch;
	return 0x40 | (ch - 4);
}

size_t aka_build_apdu(const struct aka_cfg *c, const uint8_t rand[16], const uint8_t autn[16], uint8_t *o)
{
	size_t n = 0;

	o[n++] = c->cla_from_channel ? aka_cla(c->channel) : 0x00;
	o[n++] = 0x88;
	o[n++] = 0x00;
	o[n++] = c->p2;
	o[n++] = 0x22;
	o[n++] = 0x10; memcpy(o + n, rand, 16); n += 16;
	o[n++] = 0x10; memcpy(o + n, autn, 16); n += 16;
	o[n++] = 0x00;	/* Le */
	return n;
}

int aka_parse(const uint8_t *d, size_t n, struct aka_result *r)
{
	size_t i = 0, l;

	r->sw = -1;
	r->status = AKA_ERR;
	if (n >= 2 && d[0] != 0xDB && d[0] != 0xDC) {	/* bare status word */
		if (n == 2) { r->sw = d[0] << 8 | d[1]; return -1; }
		return -1;
	}
	if (n < 2) return -1;
	if (d[0] == 0xDC) {
		l = d[1];
		if (l > sizeof(r->auts) || 2 + l > n) return -1;
		memcpy(r->auts, d + 2, l); r->auts_len = l;
		if (n >= 2 + l + 2) r->sw = d[2 + l] << 8 | d[3 + l];
		r->status = AKA_SYNC_FAIL;
		return 0;
	}
	/* DB L RES L CK L IK [L Kc] */
	i = 1;
	l = d[i++];
	if (!l || l > 16 || i + l > n) return -1;
	memcpy(r->res, d + i, l); r->res_len = l; i += l;
	if (i >= n || d[i] != 16 || i + 1 + 16 > n) return -1;
	memcpy(r->ck, d + i + 1, 16); i += 17;
	if (i >= n || d[i] != 16 || i + 1 + 16 > n) return -1;
	memcpy(r->ik, d + i + 1, 16); i += 17;
	r->has_kc = 0;
	if (i < n && d[i] == 8 && i + 1 + 8 <= n && (n - (i + 9) == 0 || n - (i + 9) == 2)) {
		memcpy(r->kc, d + i + 1, 8); r->has_kc = 1; i += 9;
	}
	if (n - i == 2) r->sw = d[i] << 8 | d[i + 1];
	r->status = AKA_OK;
	return 0;
}

int aka_authenticate(apdu_fn fn, void *ctx, const struct aka_cfg *c,
		     const uint8_t rand[16], const uint8_t autn[16], struct aka_result *r)
{
	uint8_t cmd[64], resp[300];
	size_t cn, rn = sizeof(resp);
	int tries = 0;

	memset(r, 0, sizeof(*r));
	r->sw = -1;
	cn = aka_build_apdu(c, rand, autn, cmd);
	if (fn(ctx, cmd, cn, resp, &rn)) return -1;
	while (rn >= 2 && resp[rn-2] == 0x61 && tries++ < 3) {
		uint8_t gr[5] = { c->cla_from_channel ? aka_cla(c->channel) : 0x00, 0xC0, 0x00, 0x00, resp[rn-1] };
		rn = sizeof(resp);
		if (fn(ctx, gr, 5, resp, &rn)) return -1;
	}
	if (rn >= 2 && resp[rn-2] == 0x6C) {	/* wrong Le: retry once with the right one */
		cmd[cn-1] = resp[rn-1];
		rn = sizeof(resp);
		if (fn(ctx, cmd, cn, resp, &rn)) return -1;
	}
	if (aka_parse(resp, rn, r)) {
		if (r->sw < 0 && rn >= 2) r->sw = resp[rn-2] << 8 | resp[rn-1];
		return -1;
	}
	return 0;
}
