/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MODEM_UQMID_UBUS_H
#define IMSD_MODEM_UQMID_UBUS_H
#include <libubus.h>
#include "imsmodem.h"
#include "uqmid.h"

/*
 * libubus backend of struct uq_ops (daemon only): typed asynchronous calls
 * to uqmid, the subscriptions to `uqmid` (modem.added / modem.removed) and
 * to the current modem object (state_changed, bearer.connected /
 * bearer.disconnected), re-established after every ubus reconnect.
 *
 * Calls use ubus_invoke_async + ubus_complete_request_async. The only
 * synchronous ubus operations are object id lookups, subscriptions and the
 * wildcard lookup of the sim / bearer objects: short round trips to ubusd
 * itself (never to uqmid), see the note in uqmid_ubus.c.
 */
/* target: where the events go (the pointer may still be NULL here and set later) */
void uqb_init(struct imsmodem **target);
/* from the ubus connect callback (first connection and every reconnect) */
void uqb_on_connect(struct ubus_context *ctx);
/* a new imsmodem was created while ubus is connected: tell it that uqmid is there (uqb_on_connect() when that never ran) */
void uqb_resync(struct ubus_context *ctx);
const struct uq_ops *uqb_ops(void);
void uqb_shutdown(void);
#endif
