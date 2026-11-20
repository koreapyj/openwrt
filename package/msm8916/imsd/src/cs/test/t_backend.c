/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "cstest.h"
#include "../csbackend.h"

static struct backend_cfg CFG;
static struct backend_state ST;
static struct backend_out O;

static struct backend_in in(enum csline_rat rat, bool cs_ok, bool possible, bool reg, bool call)
{
	struct backend_in i = { .rat = rat, .cs_voice_ok = cs_ok, .cs_sms_ok = cs_ok, .ims_possible = possible, .ims_registered = reg, .call_active = call };

	return i;
}

static void dec(struct backend_in i, uint64_t now)
{
	backend_decide(&CFG, &ST, &i, now, &O);
}

static void fresh(enum backend_mode m)
{
	backend_cfg_defaults(&CFG);
	CFG.mode = m;
	memset(&ST, 0, sizeof(ST));
}

void test_backend(void)
{
	enum backend_mode m;

	CHECK(backend_mode_parse("auto", &m) == 0 && m == BACKEND_AUTO);
	CHECK(backend_mode_parse("IMS", &m) == 0 && m == BACKEND_IMS);
	CHECK(backend_mode_parse("cs", &m) == 0 && m == BACKEND_CS);
	CHECK(backend_mode_parse("volte", &m) < 0 && backend_mode_parse("", &m) < 0 && backend_mode_parse(NULL, &m) < 0);
	CHECK_STR(backend_mode_name(BACKEND_CS), "cs");
	CHECK_STR(backend_name(BK_NONE), "none");

	/* forced */
	fresh(BACKEND_CS);
	dec(in(CSRAT_LTE, true, true, true, false), 1000);
	CHECK(O.backend == BK_CS && O.voice_ok && O.sms_ok);
	dec(in(CSRAT_LTE, false, true, true, false), 2000);
	CHECK(O.backend == BK_CS && !O.voice_ok);
	fresh(BACKEND_IMS);
	dec(in(CSRAT_UMTS, true, false, false, false), 1000);
	CHECK(O.backend == BK_IMS && !O.voice_ok);
	dec(in(CSRAT_LTE, true, true, true, false), 2000);
	CHECK(O.backend == BK_IMS && O.voice_ok && !strcmp(O.reason, "forced-ims"));

	/* auto: 2G / 3G is always CS */
	fresh(BACKEND_AUTO);
	dec(in(CSRAT_UMTS, true, true, false, false), 1000);
	CHECK(O.backend == BK_CS && O.voice_ok && !strcmp(O.reason, "umts"));
	dec(in(CSRAT_GSM, true, true, false, false), 2000);
	CHECK(O.backend == BK_CS && !strcmp(O.reason, "gsm"));
	dec(in(CSRAT_UMTS, false, true, false, false), 3000);
	CHECK(O.backend == BK_CS && !O.voice_ok);

	/* no service at all, nothing chosen yet */
	fresh(BACKEND_AUTO);
	dec(in(CSRAT_NONE, false, true, false, false), 1000);
	CHECK(O.backend == BK_NONE && !O.voice_ok && !strcmp(O.reason, "no-service"));

	/* LTE, SIM without IMS: CSFB at once */
	fresh(BACKEND_AUTO);
	dec(in(CSRAT_LTE, true, false, false, false), 1000);
	CHECK(O.backend == BK_CS && !strcmp(O.reason, "ims-unavailable") && O.voice_ok);

	/* LTE with an IMS capable SIM: IMS is waited for during the grace time, then CS */
	fresh(BACKEND_AUTO);
	dec(in(CSRAT_LTE, true, true, false, false), 1000);
	CHECK(O.backend == BK_IMS && !O.voice_ok && !strcmp(O.reason, "ims-registering"));
	dec(in(CSRAT_LTE, true, true, false, false), 40000);
	CHECK(O.backend == BK_IMS && !strcmp(O.reason, "ims-registering"));
	dec(in(CSRAT_LTE, true, true, true, false), 41000);	/* registered in time */
	CHECK(O.backend == BK_IMS && O.voice_ok && !strcmp(O.reason, "ims-registered"));
	/* IMS lost: kept for the switch delay (20 s), then CS (CSFB) */
	dec(in(CSRAT_LTE, true, true, false, false), 50000);
	CHECK(O.backend == BK_IMS && !O.voice_ok && !strcmp(O.reason, "ims-lost"));
	dec(in(CSRAT_LTE, true, true, false, false), 65000);
	CHECK(O.backend == BK_IMS && !strcmp(O.reason, "ims-lost"));
	dec(in(CSRAT_LTE, true, true, false, false), 71000);
	CHECK(O.backend == BK_CS && O.voice_ok && !strcmp(O.reason, "cs-fallback"));
	/* IMS comes back: CS stays until IMS was up for 10 s */
	dec(in(CSRAT_LTE, true, true, true, false), 80000);
	CHECK(O.backend == BK_CS && !strcmp(O.reason, "ims-settling"));
	dec(in(CSRAT_LTE, true, true, true, false), 85000);
	CHECK(O.backend == BK_CS);
	dec(in(CSRAT_LTE, true, true, true, false), 91000);
	CHECK(O.backend == BK_IMS && !strcmp(O.reason, "ims-registered"));

	/* grace over without IMS: CS */
	fresh(BACKEND_AUTO);
	dec(in(CSRAT_LTE, true, true, false, false), 1000);
	dec(in(CSRAT_LTE, true, true, false, false), 47000);
	CHECK(O.backend == BK_CS && !strcmp(O.reason, "cs-fallback"));
	/* ... but no CS to fall back to: IMS stays chosen */
	fresh(BACKEND_AUTO);
	dec(in(CSRAT_LTE, false, true, false, false), 1000);
	dec(in(CSRAT_LTE, false, true, false, false), 90000);
	CHECK(O.backend == BK_IMS && !O.voice_ok);

	/* never switch under an active call */
	fresh(BACKEND_AUTO);
	dec(in(CSRAT_UMTS, true, true, false, false), 1000);
	dec(in(CSRAT_LTE, true, true, true, true), 2000);	/* a CS call on 3G, the phone moves to LTE with IMS up */
	CHECK(O.backend == BK_CS && !strcmp(O.reason, "call-active"));
	dec(in(CSRAT_LTE, true, true, true, false), 3000);
	CHECK(O.backend == BK_CS && !strcmp(O.reason, "ims-settling"));
	dec(in(CSRAT_LTE, true, true, true, false), 14000);
	CHECK(O.backend == BK_IMS);
	dec(in(CSRAT_UMTS, true, true, false, true), 15000);	/* an IMS call is up while the modem drops to 3G */
	CHECK(O.backend == BK_IMS && !strcmp(O.reason, "call-active"));

	/* LTE -> 3G -> LTE: the LTE clock restarts */
	fresh(BACKEND_AUTO);
	dec(in(CSRAT_LTE, true, true, false, false), 1000);
	dec(in(CSRAT_UMTS, true, true, false, false), 5000);
	CHECK(O.backend == BK_CS);
	dec(in(CSRAT_LTE, true, true, false, false), 6000);
	CHECK(O.backend == BK_CS);	/* stays on CS: no flip-flop on a handover */
	/* a short dropout of the registration keeps the choice */
	dec(in(CSRAT_NONE, false, true, false, false), 7000);
	CHECK(O.backend == BK_CS && !O.voice_ok);
}
