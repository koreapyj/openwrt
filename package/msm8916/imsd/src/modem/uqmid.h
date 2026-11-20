/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MODEM_UQMID_H
#define IMSD_MODEM_UQMID_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Typed, asynchronous view of the uqmid ubus API. imsmodem.c only talks to
 * this interface; modem/uqmid_ubus.c implements it on libubus (blobmsg
 * translation, subscriptions) and the host tests implement a scripted mock.
 *
 * Contract: uq_ops.call() starts one request and the callback is invoked
 * exactly once, later, from the event loop (never from inside call()),
 * unless the request is cancelled. After the callback ran the handle is
 * invalid. Notifications (modem added/removed, state, bearer events) are
 * delivered through the imsmodem_ev_* functions.
 */

enum uq_op {
	UQ_LIST,		/* uqmid.list */
	UQ_MODEM_GET,		/* obj: modem object path */
	UQ_SIM_GET,		/* obj: modem path; the sim object below it is located by the backend */
	UQ_ENABLE,		/* obj: modem; flag */
	UQ_CREATE_BEARER,	/* obj: modem; str apn, str2 ip_type, num profile_id */
	UQ_BEARER_CONNECT,	/* obj: bearer path */
	UQ_BEARER_GET,		/* obj: bearer path */
	UQ_BEARER_DISCONNECT,	/* obj: bearer path */
	UQ_DELETE_BEARER,	/* obj: modem; str bearer path */
	UQ_CHAN_OPEN,		/* obj: modem; str aid (hex) */
	UQ_APDU,		/* obj: modem; num channel_id; data */
	UQ_CHAN_CLOSE,		/* obj: modem; num channel_id */
	UQ_CELL_INFO,		/* obj: modem path; uqmid.modem.N get_cell_info */
};

enum uq_err {
	UQ_OK = 0,
	UQ_E_TIMEOUT = -1,	/* no answer in time */
	UQ_E_GONE = -2,		/* object not found / modem went away */
	UQ_E_FAILED = -3,	/* the call failed, errmsg has the text */
	UQ_E_STATE = -4,	/* wrong state (uqmid: PERMISSION_DENIED / wrong-state) */
	UQ_E_CONN = -5,		/* ubus connection problem */
	UQ_E_BAD = -6,		/* unusable reply */
};

#define UQ_MAX_MODEMS	4
#define UQ_MAX_PCSCF	8
#define UQ_MAX_BEARERS	8
#define UQ_PATH		64
#define UQ_DATA_MAX	300

struct uq_req {
	enum uq_op op;
	char obj[UQ_PATH];
	char str[UQ_PATH];
	char str2[24];
	int num;
	bool flag;
	uint8_t data[UQ_DATA_MAX];
	size_t n;
};

struct uq_ipcfg {
	bool present;
	char address[48];
	int prefix;
	char gateway[48];
	char dns1[48], dns2[48];
	int mtu;
};

struct uq_res {
	int err;			/* enum uq_err */
	char errmsg[120];
	/* UQ_LIST */
	struct { char path[UQ_PATH]; char device[96]; char state[16]; } modems[UQ_MAX_MODEMS];
	int n_modems;
	/* UQ_MODEM_GET */
	char state[16];
	char imei[24];
	char bearer_paths[UQ_MAX_BEARERS][UQ_PATH];
	int n_bearer_paths;
	/* UQ_SIM_GET */
	char imsi[24];
	char iccid[32];
	/* UQ_CREATE_BEARER: the new bearer path */
	char path[UQ_PATH];
	/* UQ_BEARER_GET */
	char status[16];		/* disconnected / connecting / connected / disconnecting */
	bool connected;
	char ifname[16];
	struct uq_ipcfg ip4, ip6;
	char pcscf[UQ_MAX_PCSCF][48];
	int n_pcscf;
	char apn[64];
	char ip_type[16];
	/* UQ_CHAN_OPEN */
	int channel, sw1, sw2;
	/* UQ_CELL_INFO: the serving LTE cell (first cell with serving=true and a cell id) */
	bool cell_valid;
	char cell_plmn[8];		/* operator_id "45006" (MCC + MNC as the network reports it, 5 or 6 digits) */
	unsigned cell_tac, cell_ci;	/* tracking area code, 28 bit E-UTRAN cell identity */
	bool cell_has_earfcn;
	unsigned cell_earfcn;
	/* UQ_APDU: card response including the status word */
	uint8_t data[UQ_DATA_MAX];
	size_t n;
};

typedef void (*uq_cb)(void *arg, const struct uq_res *res);

struct uq_ops {
	void *(*call)(void *ctx, const struct uq_req *rq, uq_cb cb, void *arg);
	void (*cancel)(void *ctx, void *handle);
	/* follow the notifications of one modem object (NULL path: none); the manager is always followed */
	void (*watch_modem)(void *ctx, const char *path);
	void *ctx;
};
#endif
