/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_STORE_STORE_MOD_H
#define IMSD_STORE_STORE_MOD_H
#include <stdbool.h>
#include "store.h"
#include "../core.h"

/*
 * The message store as a core module (core.h). main(): core_add_module(c, &store_module) FIRST, before the SMS relay and the MMS
 * module (they take the store in their start() and register their delivery handlers; modules are stopped in reverse order, so the
 * store goes last, after everything that uses it).
 *   start()      creates the store (uci store, store_dir, store_keep_*) and starts loading it in the writer thread; with store=0 no store
 *                exists and store_mod_get() is NULL: the daemon behaves as it did without one
 *   on_binding   every LAN registration event goes to the store (device identity, cursor, delivery of the backlog)
 *   lan_state    LAN down: all devices unregistered
 *   stop()       writes the cursors, stops the writer thread
 */
extern const struct core_module store_module;

/* the running store, NULL when disabled / not running */
struct store *store_mod_get(void);
bool store_mod_status(struct store_status *out);
/* re-read the limits of core_cfg() (also done before every status call) */
void store_mod_reload(void);
#endif
