/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Built-in operator table and the resolution order of the operator dependent parameters, see carrier.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "carrier.h"

static const struct carrier TABLE[] = {
	/* LG U+ (Korea): the MMSC is the value of the operator's APN entry in Android's carrier database (a POST of
	 * M-NotifyResp.ind there answered HTTP 200 on the live network; the server of the Content-Location answers 405);
	 * the SMS-over-IP gateway is the one the network accepts MESSAGEs on. The MMS rides the IMS PDN (no MMS APN here). */
	{ "45006", "LG U+", "http://omammsc.uplus.co.kr:9084", "sip:ipsmgw.lte-lguplus.co.kr", "", "", "", 0, "", "", true },
	/* SK Telecom: AOSP apns-full-conf (450/05, APN lte.sktelecom.com of type default,...,mms). MMSC, proxy, APN, and the
	 * Accept / User-Agent headers (the proxy answered 500 without them) were verified on the live network (WCDMA, a line with
	 * general data blocked: MMS still worked through the proxy). Android's own user agent. */
	{ "45005", "SK Telecom", "http://omms.nate.com:9082/oma_mms", "", "lte.sktelecom.com", "ipv4v6", "smart.nate.com", 9093,
	  "Android-Mms/2.0", "*/*, application/vnd.wap.mms-message, application/vnd.wap.sic", true },
	/* Korea Cable Telecom (MVNO on the SK Telecom network, SIM IMSI prefix 45011): uses the SKT APN / MMSC / proxy (verified with a
	 * live SIM: registered on 45005). Explicit entry, the registered-network fallback is not needed for it. */
	{ "45011", "Korea Cable Telecom (SKT MVNO)", "http://omms.nate.com:9082/oma_mms", "", "lte.sktelecom.com", "ipv4v6", "smart.nate.com", 9093,
	  "Android-Mms/2.0", "*/*, application/vnd.wap.mms-message, application/vnd.wap.sic", true },
	/* KT: AOSP apns-full-conf (450/08): APN lte.ktfwing.com, MMSC http://mmsc.ktfwing.com:9082, no proxy. NOT tested on a live network. */
	{ "45008", "KT", "http://mmsc.ktfwing.com:9082", "", "lte.ktfwing.com", "ipv4v6", "", 0, "", "", false },
};

#define NTABLE (sizeof(TABLE) / sizeof(TABLE[0]))

const struct carrier *carrier_find(const char *imsi)
{
	size_t i;

	if (!imsi)
		return NULL;
	for (i = 0; i < NTABLE; i++)
		if (!strncmp(imsi, TABLE[i].plmn, strlen(TABLE[i].plmn)))
			return &TABLE[i];
	return NULL;
}

void carrier_match(const char *imsi, const char *net_plmn, struct carrier_match *out)
{
	size_t i;

	out->c = carrier_find(imsi);
	out->how = out->c ? "sim" : "none";
	if (out->c || !net_plmn || !net_plmn[0])
		return;
	for (i = 0; i < NTABLE; i++)
		if (!strcmp(net_plmn, TABLE[i].plmn)) {
			out->c = &TABLE[i];
			out->how = "network";
			return;
		}
}

static void pick(struct carrier_val *o, const char *v, const char *src)
{
	snprintf(o->value, sizeof(o->value), "%s", v);
	o->source = src;
}

static bool has(const char *s)
{
	return s && s[0];
}

void carrier_resolve_mmsc(const char *cfg, const char *imsi, const char *net_plmn, struct carrier_val *out)
{
	struct carrier_match m;

	carrier_match(imsi, net_plmn, &m);
	if (has(cfg))
		pick(out, cfg, "config");
	else if (m.c && has(m.c->mmsc))
		pick(out, m.c->mmsc, "carrier");
	else
		pick(out, "", "none");
}

static void set_proxy(struct carrier_mms *o, const char *s)
{
	const char *colon = strrchr(s, ':');

	o->proxy_port = 80;
	if (colon && colon[1] >= '0' && colon[1] <= '9') {
		snprintf(o->proxy_host, sizeof(o->proxy_host), "%.*s", (int)(colon - s), s);
		o->proxy_port = (unsigned)strtoul(colon + 1, NULL, 10);
	} else {
		snprintf(o->proxy_host, sizeof(o->proxy_host), "%s", s);
	}
}

void carrier_resolve_mms(const struct carrier_mms_cfg *cfg, const char *imsi, const char *net_plmn, struct carrier_mms *o)
{
	struct carrier_match m;
	const struct carrier *c;
	struct carrier_mms_cfg z;

	memset(o, 0, sizeof(*o));
	memset(&z, 0, sizeof(z));
	if (!cfg)
		cfg = &z;
	carrier_match(imsi, net_plmn, &m);
	c = m.c;
	o->how = m.how;
	o->name = c ? c->name : "";
	o->tested = c ? c->tested : false;
	snprintf(o->mmsc, sizeof(o->mmsc), "%s", has(cfg->mmsc) ? cfg->mmsc : c ? c->mmsc : "");
	o->mmsc_source = has(cfg->mmsc) ? "config" : (c && has(c->mmsc)) ? "carrier" : "none";
	snprintf(o->apn, sizeof(o->apn), "%s", has(cfg->apn) ? cfg->apn : c ? c->mms_apn : "");
	snprintf(o->ip_type, sizeof(o->ip_type), "%s", has(cfg->ip_type) ? cfg->ip_type : (c && has(c->mms_ip_type)) ? c->mms_ip_type : "ipv4v6");
	if (has(cfg->proxy))
		set_proxy(o, cfg->proxy);
	else if (c && has(c->mms_proxy)) {
		snprintf(o->proxy_host, sizeof(o->proxy_host), "%s", c->mms_proxy);
		o->proxy_port = c->mms_proxy_port ? c->mms_proxy_port : 80;
	}
	snprintf(o->user_agent, sizeof(o->user_agent), "%s", has(cfg->user_agent) ? cfg->user_agent : c ? c->mms_user_agent : "");
	snprintf(o->accept, sizeof(o->accept), "%s", has(cfg->accept) ? cfg->accept : c ? c->mms_accept : "");
	o->via_ims = !o->apn[0];
}

void carrier_resolve_sms_psi(const char *cfg, const char *sim, const char *imsi, struct carrier_val *out)
{
	const struct carrier *c = carrier_find(imsi);

	if (has(cfg))
		pick(out, cfg, "config");
	else if (has(sim))
		pick(out, sim, "sim");
	else if (c && has(c->sms_psi))
		pick(out, c->sms_psi, "carrier");
	else
		pick(out, "", "none");
}

void carrier_resolve_smsc(const char *cfg, const char *sim, struct carrier_val *out)
{
	if (has(cfg))
		pick(out, cfg, "config");
	else if (has(sim))
		pick(out, sim, "sim");
	else
		pick(out, "", "none");
}
