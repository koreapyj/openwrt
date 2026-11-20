/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_CSMEDIA_H
#define IMSD_CS_CSMEDIA_H
#include <stdbool.h>
#include "carrier_call.h"
#include "../media/bridge.h"

/*
 * Glue between a CS call and the media bridge: the carrier leg of the bridge is the modem's PCM device
 * (BR_LEG_PCMDEV, media/pcmdev.h) instead of RTP towards the network.
 *
 *   b2b, MO:  on CC_EV_EARLY_MEDIA (or at answer() for an MT call):
 *               struct br_leg_cfg c; cs_media_leg_cfg(&c, cfg_spec, 1500);
 *               bridge_set_leg(br, BR_CARRIER, &c);   bridge_start(br);
 *   b2b, events: bridge_events_dispatch(cb) -> cs_media_classify(ev, &m) -> cs_media_apply(&cscall_carrier_ops, call, &m)
 *               m.type == CSM_DIGIT: a digit pressed on the LAN device (RFC 4733 key down): ops->send_dtmf(call, m.digit)
 *               CSM_OPEN_FAILED / CSM_LOST: ops->media_failed(call, err) ends the call with 503 and the B2BUA ends the LAN leg.
 *   hold from the LAN device: bridge_set_dir(br, BR_CLIENT, BR_INACTIVE) + ops->set_hold(call, true); silence goes to the modem.
 */
enum cs_media_ev { CSM_NONE = 0, CSM_OPEN_FAILED, CSM_LOST, CSM_STALL, CSM_DIGIT };

struct cs_media_event {
	enum cs_media_ev type;
	int err;		/* errno (positive) of CSM_OPEN_FAILED / CSM_LOST */
	char digit;		/* CSM_DIGIT */
};

/* the carrier leg: 8 kHz PCM device "spec" ("" / "auto" / "auto,<dev>" / "<card>,<dev>"), a stall of the capture stream longer than
 * stall_ms (0 off) is reported as CSM_STALL */
void cs_media_leg_cfg(struct br_leg_cfg *c, const char *spec, unsigned stall_ms);
/* what a bridge event means for the call; false when it is not about the carrier PCM leg / a digit */
bool cs_media_classify(const struct br_event *ev, struct cs_media_event *out);
/* hand it to the call; for CSM_STALL a call that has not been answered is left alone (a ringing line may deliver nothing) */
void cs_media_apply(const struct carrier_call_ops *ops, struct carrier_call *c, const struct cs_media_event *m);

struct cs_pcm_stats {
	unsigned long rx_periods, tx_periods;
	unsigned xrun_rx, xrun_tx, ul_drop, ul_fill, ul_idle, ul_full, errors, ul_depth;
	bool lost;
};
void cs_media_stats(const struct bridge_stats *st, struct cs_pcm_stats *out);
#endif
