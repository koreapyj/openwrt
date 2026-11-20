/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CARRIER_H
#define IMSD_CARRIER_H
#include <stdbool.h>
#include <stddef.h>

/*
 * Built-in operator configuration: what a handset carries per operator (Android: the carrier / APN database keyed by
 * MCC+MNC), for the parameters that neither the SIM nor the network deliver. The table is deliberately small: an
 * operator is added only with values that were verified on its network. For every other operator the values are empty
 * ("unknown operator") and the parameters must come from the SIM or from uci.
 *
 * Resolution order of one parameter, implemented only here (the callers pass the candidates):
 *     explicit uci option ("config")  ->  SIM file where a handset really reads one ("sim")
 *     ->  this table ("carrier")  ->  nothing ("none", value "").
 *   mmsc     config, carrier. The SIM is NOT consulted, as on Android: USIM EF_MMSICP (6FD0) is not read by handsets and
 *            cards carry leftover templates of other operators (the LG U+ SIM holds Verizon's "http://mms.vtext.com/servlets/mms").
 *   sms_psi  config, sim (EF_PSISMSC of the ISIM / USIM), carrier.
 *   smsc     config, sim (EF_SMSP); the table has no SMSC.
 */
struct carrier {
	const char *plmn;	/* MCC + MNC, 5 digits ("45006"); matched as a prefix of the IMSI (the SIM's own operator),
				 * and, as the fallback of carrier_match(), against the registered network's PLMN */
	const char *name;
	const char *mmsc;	/* "" = not known */
	const char *sms_psi;	/* "" = not known */
	/* MMS data connection (Android: the APN table entry of type "mms" with its MMSC / MMS proxy) */
	const char *mms_apn;	/* "" = no MMS APN: the MMS rides the IMS PDN (LG U+), nothing is brought up on demand */
	const char *mms_ip_type;	/* "ipv4" | "ipv6" | "ipv4v6" requested from the modem; "" = ipv4v6 */
	const char *mms_proxy;	/* host name of the MMS proxy, "" = none (HTTP straight to the MMSC / Content-Location) */
	unsigned mms_proxy_port;	/* 0 = 80 */
	const char *mms_user_agent;	/* "" = imsd's IMS User-Agent (ims_user_agent) */
	const char *mms_accept;	/* "" = the default Accept: any type, application/vnd.wap.mms-message, application/vnd.wap.sic */
	bool tested;		/* the values were verified on a live network */
};

/* How the entry of the MMS data connection is chosen, in this order (a handset keys its APN table by the SIM's operator and falls
 * back to the registered network for MVNO SIMs that have no APN entry of their own):
 *   1. the SIM's MCC/MNC (first 5 digits of the IMSI) against the table  -> source "sim"
 *   2. else the MCC/MNC of the registered network (the plmn csline / uqmid report) against the table -> source "network"
 *   3. else no entry (the values then come from uci only, or are empty).
 * An MVNO that is known (45011) has an explicit entry so that its match does not depend on the fallback. */
struct carrier_match {
	const struct carrier *c;
	const char *how;	/* "sim" | "network" | "none" (static string) */
};
void carrier_match(const char *imsi, const char *net_plmn, struct carrier_match *out);

/* the table entry for an IMSI ("450061234567890"), NULL for an unknown operator or an IMSI that is empty / too short.
 * The MNC length of the SIM (EF_AD) is not read: a 6-digit-MNC operator would need an entry whose plmn has 6 digits and
 * is listed before any 5-digit entry it shares a prefix with. */
const struct carrier *carrier_find(const char *imsi);

#define CARRIER_VAL_MAX	160
struct carrier_val {
	char value[CARRIER_VAL_MAX];	/* "" when none */
	const char *source;		/* "config" | "sim" | "carrier" | "none" (static string) */
};
void carrier_resolve_mmsc(const char *cfg, const char *imsi, const char *net_plmn, struct carrier_val *out);
void carrier_resolve_sms_psi(const char *cfg, const char *sim, const char *imsi, struct carrier_val *out);
void carrier_resolve_smsc(const char *cfg, const char *sim, struct carrier_val *out);

/* The MMS data connection: every value is "uci override, else the matched table entry, else empty". via_ims = no MMS APN known: the MMS client
 * uses the IMS PDN as before. */
struct carrier_mms_cfg {		/* the uci overrides, "" = not set */
	const char *mmsc, *apn, *ip_type, *proxy /* host[:port] */, *user_agent, *accept;
};
struct carrier_mms {
	char apn[64];
	char ip_type[16];
	char mmsc[CARRIER_VAL_MAX];
	char proxy_host[128];
	unsigned proxy_port;		/* 80 when a proxy host is set without a port */
	char user_agent[96];		/* "" = the caller's default */
	char accept[200];		/* "" = the caller's default */
	bool via_ims;			/* apn is empty */
	bool tested;
	const char *name;		/* operator of the entry, "" if none */
	const char *how;		/* carrier_match().how */
	const char *mmsc_source;	/* "config" | "carrier" | "none" */
};
void carrier_resolve_mms(const struct carrier_mms_cfg *cfg, const char *imsi, const char *net_plmn, struct carrier_mms *out);
#endif
