/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_MMS_MOD_H
#define IMSD_MMS_MMS_MOD_H
#include <stdbool.h>
#include "mms.h"
#include "mmsbearer.h"
#include "mmsproxy.h"
#include "../core.h"

/*
 * The MMS client as a core module (core.h). main(): core_add_module(c, &mms_module) after smsrelay_module.
 *   start()      creates the manager (mms.c) on the IMS link of core_param_ims_link() and the LAN delivery (mms_lan.c),
 *                and installs itself as the consumer of WAP pushes of the SMS relay (smsrelay_mod_set_push)
 *   lan_state()  hands the LAN object to the delivery and the proxy (the proxy listens on the LAN address, restarts with it)
 *   stop()       removes the push hook, frees everything (requests, queue, deliveries) before returning
 * main() calls mms_mod_link_changed() from the IMS link callback.
 */
extern const struct core_module mms_module;

/*
 * The MMS data connection has two providers (see mms.h struct mms_link):
 *   IMS PDN        the IMS bearer, always up while IMS is registered (the operator table has no MMS APN: LG U+). The default, and the only
 *                  one when no environment is set.
 *   on-demand      mmsbearer.h: a bearer with the carrier's MMS APN, brought up through uqmid when there is MMS work. Chosen when the
 *                  operator entry (SIM's MCC/MNC, else the registered network's) or uci gives an MMS APN, whatever backend is active.
 * The environment gives the module what only main() has (the modem, uqmid, the registered network, the voice call state); it is set before
 * core_start. mms_mod_set_env(NULL) = no on-demand provider.
 */
struct mms_mod_env {
	const struct uq_ops *uq;
	const struct netcfg_ops *net;
	void (*ipv6_disable)(void *ctx, const char *ifname, bool disable);
	const struct guard_exec_ops *exec;
	const char *(*modem)(void *ctx);	/* object path of the modem ("" = none): the CS line's, else the IMS side's */
	const char *(*net_plmn)(void *ctx);	/* MCC+MNC of the registered network, "" = unknown */
	bool (*voice_call)(void *ctx);
	void (*marker_load)(void *ctx, char *modem, size_t mn, char *bearer, size_t bn);
	void (*marker_save)(void *ctx, const char *modem, const char *bearer);
	void (*marker_clear)(void *ctx);
	void *ctx;
};
void mms_mod_set_env(const struct mms_mod_env *e);	/* copied; NULL clears */
/* the on-demand provider is in use (an MMS APN is known for the line) */
bool mms_mod_bearer_selected(void);
/* MMS notifications may be handed to the manager now: it runs, MMS is enabled and a data connection can exist for this operator
 * (the on-demand bearer is selected) */
bool mms_mod_push_ready(void);
/* the operator is not known yet (SIM identity not read): a notification should wait a little rather than be refused */
bool mms_mod_identity_pending(void);
/* inputs changed (modem object, backend): the bearer looks again */
void mms_mod_poke(void);
/* release the on-demand bearer and its guard (shutdown, service stop); done runs once, from the loop or at once */
void mms_mod_release(void (*done)(void *arg), void *arg, unsigned timeout_ms);
bool mms_mod_bearer_status(struct mmsb_status *out);

void mms_mod_link_changed(void);
/* false when the module is not running */
bool mms_mod_status(struct mms_status *out);
/* false when the module is not running */
bool mms_mod_proxy_status(struct mmsproxy_status *out);
/* bench: see mms_fetch(); -ESHUTDOWN when the module is not running */
int mms_mod_fetch(const char *url, const char *from, const char *subject);
/* re-read core_cfg() (also done before every push, fetch and status call) */
void mms_mod_reload(void);
#endif
