/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "csmedia.h"
#include "../util/sys.h"

void cs_media_leg_cfg(struct br_leg_cfg *c, const char *spec, unsigned stall_ms)
{
	br_leg_cfg_default(c);
	c->kind = BR_LEG_PCMDEV;
	c->pcm_rate = PCMDEV_RATE;
	c->pdev_ops = &pcmdev_alsa_ops;
	str_copy(c->pdev_spec, spec ? spec : "", sizeof(c->pdev_spec));
	c->rx_timeout_ms = stall_ms;
}

bool cs_media_classify(const struct br_event *ev, struct cs_media_event *out)
{
	memset(out, 0, sizeof(*out));
	switch (ev->type) {
	case BR_EV_ERROR:
		if (ev->leg == BR_CARRIER && ev->err && strstr(ev->msg, "pcm device")) {
			out->type = CSM_OPEN_FAILED;
			out->err = ev->err;
			return true;
		}
		return false;
	case BR_EV_PCM_LOST:
		if (ev->leg != BR_CARRIER)
			return false;
		out->type = CSM_LOST;
		out->err = ev->err < 0 ? -ev->err : ev->err;
		return true;
	case BR_EV_RX_TIMEOUT:
		if (ev->leg != BR_CARRIER)
			return false;
		out->type = CSM_STALL;
		return true;
	case BR_EV_DTMF:
		if (ev->leg != BR_CLIENT || ev->end)
			return false;
		out->type = CSM_DIGIT;
		out->digit = ev->digit;
		return true;
	default:
		return false;
	}
}

void cs_media_apply(const struct carrier_call_ops *ops, struct carrier_call *c, const struct cs_media_event *m)
{
	switch (m->type) {
	case CSM_OPEN_FAILED:
	case CSM_LOST:
		ops->media_failed(c, m->err);
		break;
	case CSM_STALL:
		if (ops->state(c) == CC_ST_CONNECTED)
			ops->media_failed(c, 110 /* ETIMEDOUT */);
		break;
	case CSM_DIGIT:
		ops->send_dtmf(c, m->digit);
		break;
	default:
		break;
	}
}

void cs_media_stats(const struct bridge_stats *st, struct cs_pcm_stats *out)
{
	const struct bridge_leg_stats *l = &st->leg[BR_CARRIER];

	out->rx_periods = (unsigned long)l->rx_pkts;
	out->tx_periods = (unsigned long)l->tx_pkts;
	out->xrun_rx = l->pcm_xrun_rx;
	out->xrun_tx = l->pcm_xrun_tx;
	out->ul_drop = l->pcm_ul_drop;
	out->ul_fill = l->pcm_ul_fill;
	out->ul_idle = l->pcm_ul_idle;
	out->ul_full = l->pcm_ul_full;
	out->errors = l->pcm_err;
	out->ul_depth = l->pcm_ul_depth;
	out->lost = l->pcm_lost;
}
