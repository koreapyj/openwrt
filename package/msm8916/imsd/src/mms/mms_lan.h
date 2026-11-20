/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_MMS_LAN_H
#define IMSD_MMS_MMS_LAN_H
#include "mms.h"
#include "../ua/lan.h"

/*
 * Delivery of a retrieved MMS to the LAN devices: its text pieces go out in order as SIP MESSAGE (text/plain;
 * charset=utf-8, ua/lan_text.c) from the MMS sender, each after the previous one was answered by at least one device:
 *     X-MMS: 1
 *     X-MMS-Subject: <subject, one line>           (when the message has one)
 *     X-MMS-Message-ID: <id>
 *     X-SMS-Timestamp: 2026-11-20T00:42:55+00:00   (the MMS Date, UTC)
 *     X-MMS-Part: <i>/<n>                          (only when the text is split in n > 1 pieces)
 * The sender is rendered like an SMS sender (smsrelay/smsfmt.c): a number is the user part of From, anything else
 * becomes "alnum.<text>" with the original as display name. Devices with +g.imsd.mms are left out when m->exclude_mms.
 *
 * The original notification (mms_lan_deliver_raw) goes to the devices with +g.imsd.mms only, as one SIP MESSAGE
 * "application/vnd.wap.mms-message" whose body is the m-notification-ind (binary, byte exact), with
 *     X-MMS: 1, X-MMS-Transaction-ID, X-MMS-Proxy, X-MMS-Max-Size, X-SMS-Timestamp (arrival)
 * and X-IMSD-Seq when the message comes from the store (mms_out.seq / mms_raw.seq). mms_out.target / mms_raw.target address ONE binding.
 */
struct mms_lan;
struct mms_lan *mms_lan_new(void);
/* aborts every delivery in progress */
void mms_lan_free(struct mms_lan *d);
/* the LAN object (NULL while the LAN side is down; deliveries in progress are aborted then) */
void mms_lan_set(struct mms_lan *d, struct lan *l);
/* mms_ops.deliver / deliver_abort compatible (ctx = the struct mms_lan). m->text is copied. */
int mms_lan_deliver(void *ctx, const struct mms_out *m, void (*done)(void *arg, int nok), void *arg);
int mms_lan_deliver_raw(void *ctx, const struct mms_raw *r, void (*done)(void *arg, int nok), void *arg);
void mms_lan_abort(void *ctx, void *arg);
/* the header lines (CRLF each) of a raw notification MESSAGE: X-MMS, X-MMS-Transaction-ID, X-MMS-Proxy, X-MMS-Max-Size, X-SMS-Timestamp, X-IMSD-Seq,
 * X-MMS-Content-Location / X-MMS-Expiry / X-MMS-Size from the PDU. Used by mms_lan_deliver_raw and by the carbon copy of a sent MMS. Returns the length. */
size_t mms_lan_raw_headers(const struct mms_raw *r, char *extra, size_t cap);
/* mms_ops.devices compatible for the host tests and the module: counts of bindings with / without +g.imsd.mms (MESSAGE capable) */
void mms_lan_devices(void *ctx, unsigned *n_mms, unsigned *n_text);
/* the sender of a message as From user / display name of a SIP request (number: user part; else "alnum.<text>") */
void mms_lan_sender(const char *from, char *user, size_t un, char *disp, size_t dn);
#endif
