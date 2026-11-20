/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SMSRELAY_SMSRELAY_MOD_H
#define IMSD_SMSRELAY_SMSRELAY_MOD_H
#include <stdbool.h>
#include "smsrelay.h"
#include "../core.h"

/*
 * The SMS relay as a core module (core.h). main(): core_add_module(c, &smsrelay_module) before core_start().
 *   start()      creates the relay on the Gm registration (reg_send / reg_is_registered / registration hook);
 *                the LAN object arrives with lan_state() and is handed on with smsrelay_set_lan().
 *   MO from LAN  lan_hooks.on_message, MT from the network gm_handlers.on_message; everything the relay does not take
 *                (not application/vnd.3gpp.sms) falls through to the built-in handling of gm/reg.c.
 *   stop()       frees the relay and removes the registration hook before returning. reg_send() cannot be cancelled:
 *                late responses are dropped by a static slot table that outlives the relay.
 * SMSC rule for MO: imsd.main.smsc, else the USIM EF_SMSP (core_param_smsc), else 503. PSI: the card's EF_PSISMSC
 * (core_param_sms_psi), else imsd.main.sms_psi.
 */
extern const struct core_module smsrelay_module;

/* The consumer of complete WAP Push messages (binary SMS to WDP port 2948; see smsrelay.h): the MMS module installs it in
 * its start() and removes it (NULL) in its stop(). Without one a push is logged and dropped. */
typedef void (*smsrelay_mod_push_cb)(void *arg, const char *from, unsigned port, const uint8_t *data, size_t len);
void smsrelay_mod_set_push(smsrelay_mod_push_cb cb, void *arg);

/* Circuit switched SMS (cs/cssms.h): main() installs the hooks while the CS path exists (NULL: removed). The relay asks sms_active for
 * every LAN MESSAGE (the backend is fixed then), submit is cssms_submit, push_active tells whether an MMS notification may go to
 * the MMS module, in_done answers CSSMS_PENDING (cssms_in_done). */
struct smsrelay_mod_cs {
	bool (*sms_active)(void *ctx);
	int (*submit)(void *ctx, const struct cssms_submit *q, cssms_done_cb cb, void *arg);
	bool (*push_active)(void *ctx);
	void (*in_done)(void *ctx, unsigned id, bool taken);
	void (*kick)(void *ctx);	/* cssms_kick */
	void *ctx;
};
void smsrelay_mod_set_cs(const struct smsrelay_mod_cs *cs);
/* cssms_in_cb: a decoded message from the circuit switched line into the relay; -ENOTCONN (not taken) while the relay is not running */
int smsrelay_mod_cs_in(const struct cssms_in *m);
/* a LAN device registered: the CS messages kept in the modem are offered again */
void smsrelay_mod_cs_kick(void);

/* Fill *out; false when the module is not running. */
bool smsrelay_mod_status(struct smsrelay_status *out);
/* Re-read the options of core_cfg() (call after the configuration object changed). The module also compares them
 * before every message and on every status call, so forgetting this is harmless; it only makes the change immediate. */
void smsrelay_mod_reload(void);
#endif
