/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MODEM_QRTR_H
#define IMSD_MODEM_QRTR_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Detection of the modem's built-in IMS stack through the QRTR name service
 * (AF_QIPCRTR control port). A running modem IMS registers the QMI services
 * IMS settings (18) and IMS application (33); when one of them is present the
 * modem owns the IMS PDN and imsd must not touch it.
 *
 * The lookup is non-blocking: one NEW_LOOKUP request for all services, the
 * name service answers with one NEW_SERVER packet per registered server and
 * ends the list with an all-zero NEW_SERVER.
 */
#define QRTR_SVC_IMS_SETTINGS	18
#define QRTR_SVC_IMS_APP	33

#define QRTR_CTRL_NEW_SERVER	4
#define QRTR_CTRL_NEW_LOOKUP	10
#define QRTR_CTRL_PKT_LEN	20	/* cmd + service, instance, node, port (little endian u32) */

struct qrtr_server {
	uint32_t service, instance, node, port;
};

/* NEW_LOOKUP for service (0 = all services). Returns the length (20) or -1 */
int qrtr_build_lookup(uint8_t *out, size_t cap, uint32_t service);
/* parse a control packet: 0 and *cmd / *s set, -1 if too short */
int qrtr_parse_ctrl(const uint8_t *d, size_t n, uint32_t *cmd, struct qrtr_server *s);
/* the all-zero server entry that ends a lookup list */
bool qrtr_is_end(const struct qrtr_server *s);
bool qrtr_is_ims_service(uint32_t service);

/* result of a lookup: >0 modem IMS present (value = the number of IMS servers seen), 0 absent, <0 error (-errno) */
typedef void (*qrtr_done_cb)(void *arg, int present);

struct qrtr_ops {
	/* start a lookup; done is called exactly once (never from inside start) unless cancelled. Returns a handle or NULL. */
	void *(*start)(void *ctx, qrtr_done_cb done, void *arg);
	/* the callback will not be called any more; the handle is invalid afterwards (not after done ran) */
	void (*cancel)(void *ctx, void *handle);
	void *ctx;
};
/* the AF_QIPCRTR backend (qrtr_io.c, daemon only) */
const struct qrtr_ops *qrtr_io_ops(void);
#endif
