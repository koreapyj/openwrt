/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_CARRIER_GM_H
#define IMSD_CS_CARRIER_GM_H
#include "carrier_call.h"
#include "../call/gmcall.h"

/*
 * struct gmcall (IMS carrier leg) behind struct carrier_call_ops: the B2BUA drives "gm" and "cs" through the same table.
 * A struct carrier_call * of this backend is a small heap object (struct ccgm) that holds the gmcall and the translated
 * callback; it lives until the terminal event has been delivered (or release()).
 * Event mapping: gm PROGRESS / RINGING / FAILED / CANCELLED / TERMINATED / ANSWERED -> the same cc event; gm MEDIA(early = true)
 * -> CC_EV_EARLY_MEDIA (media_kind RTP), MEDIA(early = false) -> CC_EV_MEDIA; REOFFER_FAILED -> CC_EV_REOFFER_FAILED (non terminal). hold = gmcall_set_direction(SENDONLY / SENDRECV).
 * send_dtmf is -ENOTSUP: digits towards the IMS network are RFC 4733 packets made by the media bridge.
 */
extern const struct carrier_call_ops carrier_gm_ops;
void carrier_gm_backend(struct gmcall_mgr *m, struct carrier_backend *out);
/* the gmcall behind a carrier_call of this backend (for the B2BUA's gm specific code: SDP, re-INVITE) */
struct gmcall *carrier_gm_call(struct carrier_call *c);
#endif
