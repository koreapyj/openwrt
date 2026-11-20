/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <strings.h>
#include "csbackend.h"

const char *backend_mode_name(enum backend_mode m)
{
	return m == BACKEND_IMS ? "ims" : m == BACKEND_CS ? "cs" : "auto";
}

int backend_mode_parse(const char *s, enum backend_mode *out)
{
	if (!s)
		return -1;
	if (!strcasecmp(s, "auto"))
		*out = BACKEND_AUTO;
	else if (!strcasecmp(s, "ims"))
		*out = BACKEND_IMS;
	else if (!strcasecmp(s, "cs"))
		*out = BACKEND_CS;
	else
		return -1;
	return 0;
}

const char *backend_name(enum backend_id b)
{
	return b == BK_IMS ? "ims" : b == BK_CS ? "cs" : "none";
}

void backend_cfg_defaults(struct backend_cfg *c)
{
	c->mode = BACKEND_AUTO;
	c->ims_grace_ms = 45000;
	c->switch_delay_ms = 20000;
	c->cs_to_ims_ms = 10000;
}

static void pick(struct backend_out *o, enum backend_id b, const struct backend_in *in, const char *reason)
{
	o->backend = b;
	o->reason = reason;
	o->voice_ok = b == BK_CS ? in->cs_voice_ok : b == BK_IMS ? in->ims_registered : false;
	o->sms_ok = b == BK_CS ? in->cs_sms_ok : b == BK_IMS ? in->ims_registered : false;
}

void backend_decide(const struct backend_cfg *cfg, struct backend_state *st, const struct backend_in *in, uint64_t now, struct backend_out *out)
{
	bool lte = in->rat == CSRAT_LTE;

	/* the clocks of the transitions */
	if (lte && !st->was_lte)
		st->lte_since = now;
	if (!lte)
		st->lte_since = 0;
	st->was_lte = lte;
	if (in->ims_registered && !st->was_ims) {
		st->ims_up_since = now;
		st->ims_down_since = 0;
	} else if (!in->ims_registered && st->was_ims) {
		st->ims_down_since = now;
		st->ims_up_since = 0;
	}
	st->was_ims = in->ims_registered;

	if (cfg->mode == BACKEND_IMS) {
		pick(out, BK_IMS, in, "forced-ims");
		st->cur = BK_IMS;
		return;
	}
	if (cfg->mode == BACKEND_CS) {
		pick(out, BK_CS, in, "forced-cs");
		st->cur = BK_CS;
		return;
	}
	/* a call in progress keeps its backend */
	if (in->call_active && st->cur != BK_NONE) {
		pick(out, st->cur, in, "call-active");
		return;
	}
	if (in->rat == CSRAT_NONE && st->cur == BK_NONE) {
		pick(out, BK_NONE, in, "no-service");
		return;
	}
	if (in->rat == CSRAT_GSM || in->rat == CSRAT_UMTS) {
		st->cur = BK_CS;
		pick(out, BK_CS, in, in->rat == CSRAT_UMTS ? "umts" : "gsm");
		return;
	}
	if (in->rat == CSRAT_NONE) {		/* the registration dropped for a moment: keep what we had */
		pick(out, st->cur, in, "no-service");
		return;
	}
	/* LTE */
	if (in->ims_registered) {
		if (st->cur == BK_CS && now - st->ims_up_since < cfg->cs_to_ims_ms) {
			pick(out, BK_CS, in, "ims-settling");	/* CS stays until IMS has proved stable */
			return;
		}
		st->cur = BK_IMS;
		pick(out, BK_IMS, in, "ims-registered");
		return;
	}
	if (!in->ims_possible) {
		st->cur = BK_CS;
		pick(out, BK_CS, in, "ims-unavailable");	/* CSFB */
		return;
	}
	if (st->cur == BK_IMS && st->ims_down_since) {	/* IMS was registered and is gone */
		if (now - st->ims_down_since < cfg->switch_delay_ms) {
			pick(out, BK_IMS, in, "ims-lost");
			return;
		}
		if (in->cs_voice_ok) {
			st->cur = BK_CS;
			pick(out, BK_CS, in, "cs-fallback");
			return;
		}
		pick(out, BK_IMS, in, "ims-lost");
		return;
	}
	if (st->cur == BK_CS) {
		pick(out, BK_CS, in, "cs-fallback");	/* already on CS while IMS is not up */
		return;
	}
	/* nothing chosen yet: IMS is attempted right after the attach, then CS */
	if (now - st->lte_since < cfg->ims_grace_ms || !in->cs_voice_ok) {
		st->cur = BK_IMS;
		pick(out, BK_IMS, in, "ims-registering");
		return;
	}
	st->cur = BK_CS;
	pick(out, BK_CS, in, "cs-fallback");
}
