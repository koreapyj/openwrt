/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MODEM_IMSMODEM_H
#define IMSD_MODEM_IMSMODEM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../aka.h"
#include "../util/addr.h"
#include "netcfg.h"
#include "qrtr.h"
#include "uqmid.h"

/*
 * imsmodem: everything imsd needs from the modem, as one level-triggered
 * state machine ("what is missing for a usable IMS link? do the next step").
 *
 *   uqmid reachable -> modem object -> modem state registered+ -> identity
 *   (SIM key, ISIM IMPI/IMPU/domain, or config overrides) -> modem IMS not
 *   running (QRTR) -> IMS bearer (adopt / create, connect, get) -> netdev
 *   configuration -> P-CSCF list -> link READY.
 *
 * Whenever the link (identity, bearer, P-CSCF list, readiness) changes the
 * on_link callback runs with the new struct ims_link; ready == false means
 * everything the registration holds on the link has to be dropped.
 *
 * Also provides the AKA service (imsmodem_aka) on the ISIM logical channel.
 * Never blocks: all uqmid calls are asynchronous through struct uq_ops, the
 * only synchronous calls are the short rtnetlink requests of netcfg_ops.
 */
#define IMS_MAX_PCSCF 8

enum pcscf_source { PCSCF_NONE, PCSCF_NETWORK, PCSCF_STATIC };

struct ims_identity {
	char impi[128];
	char impu[160];		/* public identity, "sip:user@domain" */
	char domain[96];
	char user[64];		/* user part of the IMPU (MSISDN) */
	char imei[24];		/* 8-6-1 formatted, "" if unknown */
};

struct ims_bearer {
	char path[64];
	char ifname[16];
	struct addr local;	/* port 0 */
	int prefix;
	int mtu;
	char dns[2][48];
	int n_dns;
	bool ours;		/* created (or adopted) by imsd: deleted on teardown */
};

struct ims_link {
	bool ready;
	struct ims_identity id;
	struct ims_bearer br;
	char pcscf[IMS_MAX_PCSCF][64];	/* effective list: network, else static (family matches the local address) */
	int n_pcscf;
	enum pcscf_source pcscf_src;
	char reason[64];	/* why it is not ready ("" when ready) */
	unsigned seq;		/* increments on every published change */
};

struct imsmodem_cfg {
	char apn[64];
	char ip_type[16];
	int profile_id;
	char static_pcscf[IMS_MAX_PCSCF][64];
	int n_static;
	bool manage_modem;	/* enable a disabled modem (bench use) */
	char modem_pin[96];	/* device path or object path to pin; "" = the only modem */
	char o_impi[128], o_impu[160], o_domain[96];	/* overrides, "" = read the ISIM */
	unsigned route_table;
	unsigned rule_pref;
	/* timing (0 = default) */
	unsigned call_timeout_ms;	/* uqmid call, default 15000 */
	unsigned connect_timeout_ms;	/* bearer connect, default 45000 */
	unsigned ims_recheck_ms;	/* modem IMS re-check, default 30000 */
	unsigned retry_min_ms, retry_max_ms;	/* bearer / identity retry backoff, default 5000 .. 60000 */
	unsigned chan_idle_ms;		/* close the ISIM channel after this idle time, default 20000 */
};
void imsmodem_cfg_defaults(struct imsmodem_cfg *c);

struct imsmodem_ops {
	struct uq_ops uq;
	struct netcfg_ops net;
	struct qrtr_ops qrtr;
	void (*on_link)(void *arg, const struct ims_link *l);
	void *arg;
};

struct imsmodem;
struct imsmodem *imsmodem_new(const struct imsmodem_cfg *cfg, const struct imsmodem_ops *ops);
/* drop everything immediately (no remote cleanup) */
void imsmodem_free(struct imsmodem *m);
/* update the configuration (static P-CSCF list, apn, overrides ...); returns true if the link had to be restarted */
bool imsmodem_set_cfg(struct imsmodem *m, const struct imsmodem_cfg *cfg);

/* ---- events from the uqmid backend ---- */
void imsmodem_uqmid_up(struct imsmodem *m, bool up);
void imsmodem_ev_modem_added(struct imsmodem *m, const char *path, const char *device);
void imsmodem_ev_modem_removed(struct imsmodem *m, const char *path);
void imsmodem_ev_state(struct imsmodem *m, const char *modem_path, const char *new_state);
void imsmodem_ev_bearer(struct imsmodem *m, const char *modem_path, const char *bearer_path, bool connected);

/* ---- AKA service ---- */
typedef void (*imsmodem_aka_cb)(void *arg, const struct aka_result *res);
/* Queue one AUTHENTICATE (serialised on the ISIM channel, at most 4 queued). 0, or -errno (-ENOMEM: queue full, -ESHUTDOWN: stopping). cb runs exactly once from the event loop unless cancelled; res holds key material, it is wiped after the callback. */
int imsmodem_aka(struct imsmodem *m, const uint8_t rand[16], const uint8_t autn[16], imsmodem_aka_cb cb, void *arg);
/* no callback will run for the queued / running requests of this caller any more */
void imsmodem_aka_cancel(struct imsmodem *m, void *arg);

/* ---- teardown ---- */
/* Release the link (on_link with ready=false), remove the netdev configuration, disconnect + delete our bearer, close the channel. done runs once (bounded by timeout_ms, then anyway). */
void imsmodem_shutdown(struct imsmodem *m, void (*done)(void *arg), void *arg, unsigned timeout_ms);

/* ---- status ---- */
const struct ims_link *imsmodem_link(const struct imsmodem *m);
const char *imsmodem_state_name(const struct imsmodem *m);
const char *imsmodem_reason(const struct imsmodem *m);
const char *imsmodem_last_error(const struct imsmodem *m);
const char *imsmodem_modem_path(const struct imsmodem *m);
const char *imsmodem_modem_state(const struct imsmodem *m);
bool imsmodem_ims_active(const struct imsmodem *m);

/* ---- what a handset takes from the SIM and the serving cell ---- */
/* SMSC of the USIM (EF_SMSP record 1, "+821080010585"), "" when unknown. Read in the background after the identity, cached per SIM. */
const char *imsmodem_smsc(const struct imsmodem *m);
/* SMS over IP gateway URI of EF_PSISMSC (ISIM, else USIM), "" when the SIM has none */
const char *imsmodem_sms_psi(const struct imsmodem *m);
/* IMSI of the SIM ("" until read): selects the built-in operator table (carrier.h). Not for logs or status output. */
const char *imsmodem_imsi(const struct imsmodem *m);
/* P-Access-Network-Info value of the last known serving cell ("3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EB3161703"), "" when unknown */
const char *imsmodem_pani(const struct imsmodem *m);
/* the serving cell as text for status output ("lte 45006 tac 20EB ci 3161703 earfcn 1300"), "" when unknown */
const char *imsmodem_cell_info(const struct imsmodem *m);
/* Start an asynchronous refresh of the serving cell (call or SMS initiation). Coalesced: nothing happens while one is in flight or when there is no usable modem. Never blocks; the result shows in imsmodem_pani() later. */
void imsmodem_pani_refresh(struct imsmodem *m);

/* "3GPP-E-UTRAN-FDD|TDD; utran-cell-id-3gpp=<plmn><tac 4 hex><eci 7 hex>" (TS 24.229 7.2A.4); plmn = MCC + MNC (5 or 6 digits). 0, or -1 for bad input / overflow */
int imsmodem_pani_format(const char *plmn, unsigned tac, unsigned eci, bool tdd, char *out, size_t n);
/* EARFCN (downlink) of an LTE TDD band (33..53, TS 36.101 table 5.7.3-1) */
bool imsmodem_earfcn_is_tdd(unsigned earfcn);
#endif
