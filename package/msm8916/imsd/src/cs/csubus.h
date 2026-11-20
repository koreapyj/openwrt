/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_CSUBUS_H
#define IMSD_CS_CSUBUS_H
#include <libubus.h>
#include "csline.h"
#include "csu.h"

/*
 * libubus backend of struct csu_ops (daemon only), the CS counterpart of modem/uqmid_ubus.[ch]: typed asynchronous calls to
 * uqmid (ubus_invoke_async), the subscription to `uqmid` (modem.added / modem.removed) and to the modem object (state_changed,
 * registration_state_changed, voice.call_*, messaging.*), re-established after every ubus reconnect. Its own subscribers, so
 * it can run next to uqmid_ubus.c (both may follow the same objects; libubus delivers a notification to every subscriber).
 *
 * Like uqmid_ubus.c it uses three short synchronous round trips to ubusd itself (object id lookup, subscribe), never to uqmid.
 */
/* target: the line the events go to (the pointer may still be NULL here and set later) */
void csub_init(struct csline **target);
/* from the ubus connect callback (first connection and every reconnect) */
void csub_on_connect(struct ubus_context *ctx);
/* a new line was created while ubus is connected: tell it whether uqmid is there */
void csub_resync(struct ubus_context *ctx);
const struct csu_ops *csub_ops(void);
void csub_shutdown(void);
#endif
