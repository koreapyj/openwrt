/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "aka.h"

uint8_t aka_cla(int ch)
{
	if (ch <= 0)
		return 0x00;
	if (ch <= 3)
		return ch;
	return 0x40 | (ch - 4);
}

size_t aka_build_apdu(const struct aka_cfg *c, const uint8_t rand[16], const uint8_t autn[16], uint8_t *o)
{
	size_t n = 0;

	o[n++] = c->cla_from_channel ? aka_cla(c->channel) : 0x00;
	o[n++] = 0x88;
	o[n++] = 0x00;
	o[n++] = c->p2 ? c->p2 : 0x81;
	o[n++] = 0x22;
	o[n++] = 0x10; memcpy(o + n, rand, 16); n += 16;
	o[n++] = 0x10; memcpy(o + n, autn, 16); n += 16;
	o[n++] = 0x00;	/* Le */
	return n;
}

int aka_parse(const uint8_t *d, size_t n, struct aka_result *r)
{
	size_t i, l;

	memset(r, 0, sizeof(*r));
	r->sw = -1;
	r->status = AKA_ERR;
	if (n >= 2 && d[0] != 0xDB && d[0] != 0xDC) {	/* bare status word */
		if (n == 2)
			r->sw = d[0] << 8 | d[1];
		return -1;
	}
	if (n < 2)
		return -1;
	if (d[0] == 0xDC) {
		l = d[1];
		if (l > sizeof(r->auts) || 2 + l > n)
			return -1;
		memcpy(r->auts, d + 2, l);
		r->auts_len = l;
		if (n >= 2 + l + 2)
			r->sw = d[2 + l] << 8 | d[3 + l];
		r->status = AKA_SYNC_FAIL;
		return 0;
	}
	/* DB L RES L CK L IK [L Kc] */
	i = 1;
	l = d[i++];
	if (!l || l > 16 || i + l > n)
		return -1;
	memcpy(r->res, d + i, l);
	r->res_len = l;
	i += l;
	if (i >= n || d[i] != 16 || i + 1 + 16 > n)
		return -1;
	memcpy(r->ck, d + i + 1, 16);
	i += 17;
	if (i >= n || d[i] != 16 || i + 1 + 16 > n)
		return -1;
	memcpy(r->ik, d + i + 1, 16);
	i += 17;
	if (i < n && d[i] == 8 && i + 1 + 8 <= n && (n - (i + 9) == 0 || n - (i + 9) == 2)) {
		memcpy(r->kc, d + i + 1, 8);
		r->has_kc = 1;
		i += 9;
	}
	if (n - i == 2)
		r->sw = d[i] << 8 | d[i + 1];
	r->status = AKA_OK;
	return 0;
}

void aka_sm_start(struct aka_sm *sm, const struct aka_cfg *cfg, const uint8_t rand[16], const uint8_t autn[16],
		  uint8_t apdu[AKA_APDU_MAX], size_t *apdu_len)
{
	memset(sm, 0, sizeof(*sm));
	sm->cfg = *cfg;
	sm->res.sw = -1;
	sm->res.status = AKA_ERR;
	sm->cmd_len = aka_build_apdu(cfg, rand, autn, sm->cmd);
	memcpy(apdu, sm->cmd, sm->cmd_len);
	*apdu_len = sm->cmd_len;
}

enum aka_step aka_sm_feed(struct aka_sm *sm, const uint8_t *resp, size_t rn, uint8_t apdu[AKA_APDU_MAX], size_t *apdu_len)
{
	if (sm->done)
		return AKA_STEP_FAIL;
	if (rn >= 2 && resp[rn - 2] == 0x61 && sm->tries61 < 3) {
		sm->tries61++;
		apdu[0] = sm->cfg.cla_from_channel ? aka_cla(sm->cfg.channel) : 0x00;
		apdu[1] = 0xC0;	/* GET RESPONSE */
		apdu[2] = 0x00;
		apdu[3] = 0x00;
		apdu[4] = resp[rn - 1];
		*apdu_len = 5;
		return AKA_STEP_SEND;
	}
	if (rn >= 2 && resp[rn - 2] == 0x6C && !sm->retried6c) {	/* wrong Le: repeat with the right one */
		sm->retried6c = true;
		sm->cmd[sm->cmd_len - 1] = resp[rn - 1];
		memcpy(apdu, sm->cmd, sm->cmd_len);
		*apdu_len = sm->cmd_len;
		return AKA_STEP_SEND;
	}
	sm->done = true;
	if (aka_parse(resp, rn, &sm->res)) {
		if (sm->res.sw < 0 && rn >= 2)
			sm->res.sw = resp[rn - 2] << 8 | resp[rn - 1];
		sm->res.status = AKA_ERR;
		return AKA_STEP_FAIL;
	}
	return AKA_STEP_DONE;
}

void aka_sm_abort(struct aka_sm *sm)
{
	sm->done = true;
	sm->res.status = AKA_ERR;
}

const struct aka_result *aka_sm_result(const struct aka_sm *sm)
{
	return &sm->res;
}
