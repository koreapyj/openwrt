/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "tcommon.h"

static int n_present, n_absent, n_status;
static unsigned last_gen;
static char last_path[64];

static void on_modem(void *arg, bool present, const char *path, unsigned gen)
{
	(void)arg;
	if (present)
		n_present++;
	else
		n_absent++;
	last_gen = gen;
	snprintf(last_path, sizeof(last_path), "%s", path);
}

static void on_status(void *arg, const struct csline_status *s)
{
	(void)arg;
	(void)s;
	n_status++;
}

static void hook(void)
{
	struct csline_listener l = { .on_modem = on_modem, .on_status = on_status };

	n_present = n_absent = n_status = 0;
	CHECK(csline_add_listener(LINE, &l) == 0);
}

void test_line(void)
{
	const struct csline_status *s;
	struct csline_cfg cfg;
	unsigned gen;

	/* ===== uqmid appears, modem found and read ===== */
	env_line(NULL);
	hook();
	s = csline_status(LINE);
	CHECK(!s->voice_ok && !s->sms_ok && !strcmp(s->reason, "waiting-for-uqmid"));
	adv(100);
	CHECK(FK.n[CSU_LIST] == 0);	/* nothing before uqmid is up */
	csline_ev_uqmid_up(LINE, true);
	adv(100);
	CHECK(FK.n[CSU_LIST] == 1 && FK.n[CSU_MODEM_GET] == 1);
	CHECK_STR(s->modem, "uqmid.modem.0");
	CHECK(s->voice_ok && s->sms_ok && s->enabled && !strcmp(s->reason, "ok"));
	CHECK_STR(s->modem_state, "registered");
	CHECK_STR(s->reg_state, "home");
	CHECK(s->rat == CSRAT_UMTS);
	CHECK_STR(s->operator_code, "45005");
	CHECK_STR(s->operator_name, "SKTelecom");
	CHECK_STR(s->own_number, "+821012345678");
	CHECK(FK.watch && !strcmp(FK.watched, "uqmid.modem.0"));
	CHECK(n_present == 1 && n_absent == 0 && n_status >= 1);
	gen = s->gen;
	CHECK(last_gen == gen && !strcmp(last_path, "uqmid.modem.0"));
	CHECK(FK.n[CSU_ENABLE] == 0);	/* manage_modem off: never enables */

	/* ===== notifications: state and registration; the modem is read again after the debounce ===== */
	{
		int gets = FK.n[CSU_MODEM_GET];

		strcpy(FK.act, "lte");
		fk_modem_state("registered", "roaming", "lte", true);
		CHECK(s->roaming && s->voice_ok);	/* the notification alone moved it */
		adv(500);
		CHECK(FK.n[CSU_MODEM_GET] == gets + 1);	/* one read for both notifications (debounced) */
		CHECK(s->rat == CSRAT_LTE && s->voice_ok);
	}

	/* ===== every reason ===== */
	fk_modem_state("searching", "searching", NULL, true);
	adv(500);
	CHECK(!s->voice_ok && !strcmp(s->reason, "searching"));
	fk_modem_state("enabled", "denied", NULL, true);
	adv(500);
	CHECK(!s->voice_ok && !strcmp(s->reason, "denied"));
	fk_modem_state("enabled", "idle", NULL, true);
	adv(500);
	CHECK(!s->voice_ok && !strcmp(s->reason, "not-registered"));
	fk_modem_state("enabled", "emergency-only", NULL, true);
	adv(500);
	CHECK(!s->voice_ok && !strcmp(s->reason, "emergency-only"));
	fk_modem_state("registered", "home-sms-only", NULL, true);
	adv(500);
	CHECK(!s->voice_ok && s->sms_ok && !strcmp(s->reason, "sms-only"));
	fk_modem_state("registered", "roaming-sms-only", NULL, true);
	adv(500);
	CHECK(!s->voice_ok && s->sms_ok && s->roaming);
	fk_modem_state("registered", "home-csfb-not-preferred", NULL, true);
	adv(500);
	CHECK(s->voice_ok && s->sms_ok);
	fk_modem_state("locked", "unknown", NULL, true);
	adv(500);
	CHECK(!s->voice_ok && !s->enabled && !strcmp(s->reason, "sim-locked"));
	fk_modem_state("failed", NULL, NULL, true);
	adv(500);
	CHECK(!strcmp(s->reason, "modem-failed"));
	fk_modem_state("disabled", NULL, NULL, true);
	adv(500);
	CHECK(!strcmp(s->reason, "modem-disabled") && FK.n[CSU_ENABLE] == 0);
	fk_modem_state("enabling", NULL, NULL, true);
	adv(500);
	CHECK(!strcmp(s->reason, "modem-enabling") && !s->enabled);
	fk_modem_state("connected", "home", NULL, true);
	adv(500);
	CHECK(s->voice_ok && s->enabled);

	/* ===== allow_roaming = false ===== */
	csline_cfg_defaults(&cfg);
	cfg.allow_roaming = false;
	csline_set_cfg(LINE, &cfg);
	fk_modem_state("registered", "roaming", NULL, true);
	adv(500);
	CHECK(!s->voice_ok && !s->sms_ok && !strcmp(s->reason, "roaming-not-allowed"));
	fk_modem_state("registered", "home", NULL, true);
	adv(500);
	CHECK(s->voice_ok);

	/* ===== the modem goes away (SIM swap / reset: uqmid renumbers it) ===== */
	n_present = n_absent = 0;
	FK.modem_listed = false;
	fk_modem_remove();
	CHECK(n_absent == 1 && !s->modem[0] && !s->voice_ok && !strcmp(s->reason, "no-modem"));
	CHECK(!FK.watch);
	CHECK(s->gen != gen);
	adv(100);
	CHECK(FK.n[CSU_LIST] >= 2);	/* it looks for a replacement at once */
	strcpy(FK.modem, "uqmid.modem.1");
	FK.modem_listed = true;
	fk_modem_add();
	adv(100);
	CHECK_STR(s->modem, "uqmid.modem.1");
	CHECK(s->voice_ok && n_present == 1 && !strcmp(FK.watched, "uqmid.modem.1"));
	/* an unrelated removal is ignored */
	fk_notify("state_changed", "uqmid.modem.1", "registered", "registered", NULL, false);
	csline_ev_modem_removed(LINE, "uqmid.modem.7");
	CHECK(s->voice_ok);

	/* ===== uqmid restarts ===== */
	n_absent = 0;
	csline_ev_uqmid_up(LINE, false);
	CHECK(!s->uqmid && !s->modem[0] && !s->voice_ok && !strcmp(s->reason, "waiting-for-uqmid") && n_absent == 1);
	{
		int lists = FK.n[CSU_LIST];

		adv(10000);
		CHECK(FK.n[CSU_LIST] == lists);		/* nothing is tried while uqmid is down */
	}
	strcpy(FK.modem, "uqmid.modem.0");
	csline_ev_uqmid_up(LINE, true);
	adv(100);
	CHECK(s->voice_ok && !strcmp(s->modem, "uqmid.modem.0"));
	env_down();

	/* ===== uqmid is up but has no modem yet: retries, modem.added wins ===== */
	env_line(NULL);
	FK.modem_listed = false;
	csline_ev_uqmid_up(LINE, true);
	adv(100);
	s = csline_status(LINE);
	CHECK(!s->modem[0] && !strcmp(s->reason, "no-modem"));
	adv(3100);
	CHECK(FK.n[CSU_LIST] >= 2);
	FK.modem_listed = true;
	fk_modem_add();
	adv(100);
	CHECK(s->voice_ok);
	env_down();

	/* ===== two modems: without a pin none is used; with a pin the right one ===== */
	env_line(NULL);
	FK.list_two = true;
	csline_ev_uqmid_up(LINE, true);
	adv(100);
	s = csline_status(LINE);
	CHECK(!s->modem[0]);
	csline_cfg_defaults(&cfg);
	snprintf(cfg.modem_pin, sizeof(cfg.modem_pin), "/dev/wwan0qmi0");
	csline_set_cfg(LINE, &cfg);
	adv(3100);
	CHECK_STR(s->modem, "uqmid.modem.0");
	env_down();

	/* ===== manage_modem: a disabled modem is enabled once ===== */
	csline_cfg_defaults(&cfg);
	cfg.manage_modem = true;
	env_line(&cfg);
	strcpy(FK.mstate, "disabled");
	csline_ev_uqmid_up(LINE, true);
	adv(200);
	s = csline_status(LINE);
	CHECK(FK.n[CSU_ENABLE] == 1);
	CHECK_STR(s->modem_state, "enabled");
	fk_modem_state("disabled", NULL, NULL, true);	/* it falls back (e.g. someone disables it): not enabled again */
	adv(500);
	CHECK(FK.n[CSU_ENABLE] == 1 && !strcmp(s->reason, "modem-disabled"));
	env_down();

	/* ===== failing reads: retried with a delay, no busy loop ===== */
	env_line(NULL);
	fk_fail_next(CSU_MODEM_GET, 2, CSU_E_TIMEOUT, "timeout", "Timed out");
	csline_ev_uqmid_up(LINE, true);
	adv(100);
	s = csline_status(LINE);
	CHECK(FK.n[CSU_MODEM_GET] == 1 && !s->voice_ok);
	adv(3100);
	CHECK(FK.n[CSU_MODEM_GET] == 2);
	adv(3100);
	CHECK(FK.n[CSU_MODEM_GET] == 3 && s->voice_ok);
	/* a vanished modem object during the read: dropped and looked up again */
	env_down();
	env_line(NULL);
	csline_ev_uqmid_up(LINE, true);
	adv(100);
	s = csline_status(LINE);
	fk_fail_next(CSU_MODEM_GET, 1, CSU_E_GONE, "not-found", "gone");
	csline_refresh(LINE);
	adv(100);
	CHECK(!s->modem[0] || s->voice_ok);	/* looked up again within the retry delay */
	adv(3100);
	CHECK(s->voice_ok);
	env_down();
}
