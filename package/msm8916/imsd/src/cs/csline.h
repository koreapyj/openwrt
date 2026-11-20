/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_CSLINE_H
#define IMSD_CS_CSLINE_H
#include <stdbool.h>
#include <stddef.h>
#include "csu.h"

/*
 * Line supervision of the circuit switched backend: follows uqmid (manager up / down), the one modem object
 * (added / removed, state, registration, access technology, operator, own number) and publishes "is this line usable
 * for calls / SMS, and if not why". Level triggered like modem/imsmodem.c, never blocks, creates no data bearer.
 *
 * manage_modem mirrors imsmodem_cfg.manage_modem: a modem found in state "disabled" is enabled once (uqmid does not
 * enable modems by itself, docs/uqmid.md); without it the line just reports "modem-disabled". modem_pin selects the
 * modem like imsmodem_cfg.modem_pin (device path or object path; "" = the only modem).
 *
 * The cscall and cssms modules sit on a line: they send their requests through csline_call() and receive the
 * modem-object notifications through listeners, so one subscription serves everything.
 */
enum csline_rat { CSRAT_NONE = 0, CSRAT_GSM, CSRAT_UMTS, CSRAT_LTE };
const char *csline_rat_name(enum csline_rat r);	/* "none" "gsm" "umts" "lte" */
/* highest technology in a space separated uqmid list ("umts hspa", "lte") */
enum csline_rat csline_rat_parse(const char *act);

struct csline_cfg {
	char modem_pin[96];
	bool manage_modem;		/* default false */
	bool allow_roaming;		/* default true: calls / SMS while registered as roaming */
	unsigned call_timeout_ms;	/* uqmid LIST / GET, default 15000 */
	unsigned enable_timeout_ms;	/* enable, default 60000 */
	unsigned retry_ms;		/* after a failed step, default 3000 */
	unsigned refresh_ms;		/* re-read the modem after a state notification (debounce), default 300 */
};
void csline_cfg_defaults(struct csline_cfg *c);

struct csline_status {
	bool uqmid;			/* the manager object is reachable */
	char modem[CSU_PATH];		/* "" when none */
	unsigned gen;			/* changes with every modem object (added / removed); stale answers are recognised by it */
	bool enabled;			/* modem state is enabled or better: messaging methods work */
	char modem_state[16];
	char reg_state[28];
	enum csline_rat rat;
	char act[40];
	char operator_code[8], operator_name[40];
	char own_number[24];
	bool roaming;
	bool voice_ok;			/* a call can be placed / answered */
	bool sms_ok;			/* SMS can be sent / received (also in "*-sms-only" registrations) */
	char reason[40];		/* why not: "waiting-for-uqmid" "no-modem" "modem-disabled" "modem-failed" "sim-locked" "searching" "denied"
					 * "not-registered" "sms-only" "roaming-not-allowed" "emergency-only" ...; "ok" when voice_ok */
	unsigned seq;			/* increments on every published change */
};

struct csline_listener {
	/* the modem object we use came / went (gen as in csline_status). present = false: every request in flight is void */
	void (*on_modem)(void *arg, bool present, const char *path, unsigned gen);
	/* a notification of the modem object (call / messaging / state) */
	void (*on_notify)(void *arg, const struct csu_notify *n);
	/* the published status changed */
	void (*on_status)(void *arg, const struct csline_status *s);
	void *arg;
};

struct csline;
/* ops is copied; NULL on OOM */
struct csline *csline_new(const struct csline_cfg *cfg, const struct csu_ops *ops);
void csline_free(struct csline *l);
bool csline_set_cfg(struct csline *l, const struct csline_cfg *cfg);
int csline_add_listener(struct csline *l, const struct csline_listener *lst);	/* 0 or -ENOBUFS (4 at most) */
void csline_remove_listener(struct csline *l, void *arg);

/* ---- events from the uqmid backend ---- */
void csline_ev_uqmid_up(struct csline *l, bool up);
void csline_ev_modem_added(struct csline *l, const char *path, const char *device);
void csline_ev_modem_removed(struct csline *l, const char *path);
void csline_ev_notify(struct csline *l, const struct csu_notify *n);

/* ---- for the modules ---- */
/* a request on the backend; the callback runs once from the loop. NULL on OOM */
void *csline_call(struct csline *l, const struct csu_req *rq, csu_cb cb, void *arg);
void csline_cancel(struct csline *l, void *handle);
const struct csline_status *csline_status(const struct csline *l);
/* the object path of the modem, "" if none */
const char *csline_modem(const struct csline *l);
/* ask for a fresh read of the modem (coalesced) */
void csline_refresh(struct csline *l);
#endif
