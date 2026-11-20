/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_CSBACKEND_H
#define IMSD_CS_CSBACKEND_H
#include <stdbool.h>
#include <stdint.h>
#include "csline.h"

/*
 * Which carrier backend serves the line: IMS (imsd's own SIP / RTP stack towards the operator's IMS core) or CS (the modem's
 * circuit switched call control and SMS through uqmid). uci option "backend": auto | ims | cs (default auto).
 *
 * auto follows what a handset does:
 *   - on 2G / 3G the network has no IMS voice for us (the modem has no IMS PDN there): CS.
 *   - on LTE a handset registers to IMS when the SIM is provisioned for it and uses VoLTE / SMS over IP once that works; when
 *     IMS is not available (no ISIM, registration refused, IMS APN missing) it falls back to CSFB, i.e. circuit switched calls
 *     and SMS through the modem: CS.
 *   - right after the LTE attach IMS needs some seconds to register: IMS is waited for (ims_grace_ms) instead of flipping to
 *     CS and back; when IMS registration is lost later, IMS is kept for switch_delay_ms before CS takes over (a re-registration
 *     is not a reason to change the call path), and CS goes back to IMS only after IMS was up for cs_to_ims_ms.
 *   - never switch while a call is active (call_active): the audio path and the call control belong to the backend that
 *     started the call.
 * What uqmid exposes decides the inputs: access technologies (csline_status.rat), registration (csline voice_ok / sms_ok),
 * ISIM / IMS identity and bearer state come from imsmodem, the Gm registration from gm/reg.c.
 */
enum backend_mode { BACKEND_AUTO = 0, BACKEND_IMS, BACKEND_CS };
enum backend_id { BK_NONE = 0, BK_IMS, BK_CS };

const char *backend_mode_name(enum backend_mode m);	/* "auto" "ims" "cs" */
int backend_mode_parse(const char *s, enum backend_mode *out);	/* 0, or -1 (unknown text); case insensitive */
const char *backend_name(enum backend_id b);		/* "none" "ims" "cs" */

struct backend_cfg {
	enum backend_mode mode;
	unsigned ims_grace_ms;		/* wait this long after the LTE attach for IMS to register, default 45000 */
	unsigned switch_delay_ms;	/* IMS registration lost: keep IMS this long before CS takes over, default 20000 */
	unsigned cs_to_ims_ms;		/* IMS must have been registered this long before CS hands over to it, default 10000 */
};
void backend_cfg_defaults(struct backend_cfg *c);

struct backend_in {
	enum csline_rat rat;		/* csline_status.rat */
	bool cs_voice_ok, cs_sms_ok;	/* csline_status */
	bool ims_possible;		/* IMS can be attempted: ISIM / IMS identity present (or overridden) and not known to be refused */
	bool ims_registered;		/* Gm registration is up (reg_is_registered) */
	bool call_active;		/* a call is up on the current backend */
};

struct backend_state {			/* kept by the caller between calls; zero-initialise */
	enum backend_id cur;
	uint64_t lte_since, ims_up_since, ims_down_since;	/* 0 = not now */
	bool was_lte, was_ims;
};

struct backend_out {
	enum backend_id backend;	/* BK_NONE: nothing can be decided yet */
	bool voice_ok, sms_ok;		/* the chosen backend can take calls / SMS now */
	const char *reason;		/* static string: "forced-ims" "forced-cs" "umts" "gsm" "ims-registered" "ims-registering" "ims-lost"
				 * "ims-unavailable" "call-active" "no-service" "cs-fallback" ... */
};

/* pure apart from *st; now in ms of any monotonic clock */
void backend_decide(const struct backend_cfg *cfg, struct backend_state *st, const struct backend_in *in, uint64_t now, struct backend_out *out);
#endif
