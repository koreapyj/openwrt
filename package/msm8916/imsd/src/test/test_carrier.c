/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The built-in operator table and the resolution order of mmsc / sms_psi / smsc (carrier.h) */
#include <string.h>
#include "test.h"
#include "../carrier.h"

#define LGU_IMSI "450061051226862"

static void t_find(void)
{
	const struct carrier *c = carrier_find(LGU_IMSI);

	CHECK(c != NULL);
	if (c) {
		CHECK_STR(c->plmn, "45006"); CHECK_STR(c->name, "LG U+");
		CHECK_STR(c->mmsc, "http://omammsc.uplus.co.kr:9084"); CHECK_STR(c->sms_psi, "sip:ipsmgw.lte-lguplus.co.kr");
	}
	CHECK(carrier_find("45006") == c);			/* the 5-digit prefix itself */
	CHECK(carrier_find("450080020509251") != NULL);		/* KT (45008): in the table, from AOSP, untested */
	CHECK(carrier_find("450051234567890") != NULL);		/* SKT (45005) */
	CHECK(carrier_find("310260123456789") == NULL);		/* a 3-digit-MNC operator */
	CHECK(carrier_find("311480123456789") == NULL);
	CHECK(carrier_find("4506") == NULL);			/* too short */
	CHECK(carrier_find("") == NULL);
	CHECK(carrier_find(NULL) == NULL);
	CHECK(carrier_find("x45006") == NULL);			/* a prefix match, nothing else */
}

static void t_resolve(void)
{
	struct carrier_val v;
	const char *card = "sip:card.example.net";

	/* mmsc: config, carrier; the SIM is not an input at all */
	carrier_resolve_mmsc("http://cfg/", LGU_IMSI, NULL, &v); CHECK_STR(v.value, "http://cfg/"); CHECK_STR(v.source, "config");
	carrier_resolve_mmsc("", LGU_IMSI, NULL, &v); CHECK_STR(v.value, "http://omammsc.uplus.co.kr:9084"); CHECK_STR(v.source, "carrier");
	carrier_resolve_mmsc(NULL, LGU_IMSI, NULL, &v); CHECK_STR(v.source, "carrier");
	carrier_resolve_mmsc("http://cfg/", "310260123456789", NULL, &v); CHECK_STR(v.value, "http://cfg/"); CHECK_STR(v.source, "config");
	carrier_resolve_mmsc("", "310260123456789", NULL, &v); CHECK_STR(v.value, ""); CHECK_STR(v.source, "none");
	carrier_resolve_mmsc("", "", NULL, &v); CHECK_STR(v.value, ""); CHECK_STR(v.source, "none");
	carrier_resolve_mmsc(NULL, NULL, NULL, &v); CHECK_STR(v.value, ""); CHECK_STR(v.source, "none");

	/* sms_psi: config, sim, carrier */
	carrier_resolve_sms_psi("sip:cfg.example.net", card, LGU_IMSI, &v); CHECK_STR(v.value, "sip:cfg.example.net"); CHECK_STR(v.source, "config");
	carrier_resolve_sms_psi("sip:cfg.example.net", "", LGU_IMSI, &v); CHECK_STR(v.source, "config");
	carrier_resolve_sms_psi("sip:cfg.example.net", card, "", &v); CHECK_STR(v.source, "config");
	carrier_resolve_sms_psi("", card, LGU_IMSI, &v); CHECK_STR(v.value, card); CHECK_STR(v.source, "sim");
	carrier_resolve_sms_psi("", card, "310260123456789", &v); CHECK_STR(v.value, card); CHECK_STR(v.source, "sim");
	carrier_resolve_sms_psi("", "", LGU_IMSI, &v); CHECK_STR(v.value, "sip:ipsmgw.lte-lguplus.co.kr"); CHECK_STR(v.source, "carrier");
	carrier_resolve_sms_psi(NULL, NULL, LGU_IMSI, &v); CHECK_STR(v.source, "carrier");
	carrier_resolve_sms_psi("", "", "310260123456789", &v); CHECK_STR(v.value, ""); CHECK_STR(v.source, "none");
	carrier_resolve_sms_psi("", "", "", &v); CHECK_STR(v.value, ""); CHECK_STR(v.source, "none");

	/* smsc: config, sim (the table has none) */
	carrier_resolve_smsc("+821099999999", "+821080010585", &v); CHECK_STR(v.value, "+821099999999"); CHECK_STR(v.source, "config");
	carrier_resolve_smsc("", "+821080010585", &v); CHECK_STR(v.value, "+821080010585"); CHECK_STR(v.source, "sim");
	carrier_resolve_smsc("+821099999999", "", &v); CHECK_STR(v.source, "config");
	carrier_resolve_smsc("", "", &v); CHECK_STR(v.value, ""); CHECK_STR(v.source, "none");
	carrier_resolve_smsc(NULL, NULL, &v); CHECK_STR(v.source, "none");
}

#define SKT_IMSI "450051234567890"
#define KCT_IMSI "450119876543210"	/* Korea Cable Telecom, an MVNO on the SKT network */
#define SKT_MMSC "http://omms.nate.com:9082/oma_mms"

static void t_mms_entries(void)
{
	struct carrier_mms m;
	struct carrier_mms_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));
	/* LG U+: no MMS APN, the IMS PDN carries the MMS, no proxy, the IMS user agent (unchanged) */
	carrier_resolve_mms(&cfg, LGU_IMSI, "", &m);
	CHECK(m.via_ims); CHECK_STR(m.apn, ""); CHECK_STR(m.proxy_host, ""); CHECK_STR(m.mmsc, "http://omammsc.uplus.co.kr:9084");
	CHECK_STR(m.how, "sim"); CHECK_STR(m.user_agent, ""); CHECK_STR(m.accept, ""); CHECK(m.tested);
	/* SKT */
	carrier_resolve_mms(&cfg, SKT_IMSI, "", &m);
	CHECK(!m.via_ims); CHECK_STR(m.apn, "lte.sktelecom.com"); CHECK_STR(m.ip_type, "ipv4v6"); CHECK_STR(m.mmsc, SKT_MMSC);
	CHECK_STR(m.proxy_host, "smart.nate.com"); CHECK_EQ(m.proxy_port, 9093); CHECK_STR(m.user_agent, "Android-Mms/2.0");
	CHECK_STR(m.accept, "*/*, application/vnd.wap.mms-message, application/vnd.wap.sic"); CHECK_STR(m.how, "sim"); CHECK(m.tested);
	/* the MVNO 45011 has its own entry: it matches by the SIM, with the SKT values, whatever the network says */
	carrier_resolve_mms(&cfg, KCT_IMSI, "", &m);
	CHECK_STR(m.how, "sim"); CHECK_STR(m.apn, "lte.sktelecom.com"); CHECK_STR(m.proxy_host, "smart.nate.com"); CHECK_STR(m.mmsc, SKT_MMSC);
	carrier_resolve_mms(&cfg, KCT_IMSI, "45005", &m);
	CHECK_STR(m.how, "sim");
	carrier_resolve_mms(&cfg, KCT_IMSI, "45008", &m);		/* the SIM wins over the network */
	CHECK_STR(m.how, "sim"); CHECK_STR(m.apn, "lte.sktelecom.com");
	/* KT: from AOSP, no proxy, not tested */
	carrier_resolve_mms(&cfg, "450080020509251", "", &m);
	CHECK_STR(m.apn, "lte.ktfwing.com"); CHECK_STR(m.mmsc, "http://mmsc.ktfwing.com:9082"); CHECK_STR(m.proxy_host, ""); CHECK(!m.tested);
	/* an MVNO without an entry: the registered network decides */
	carrier_resolve_mms(&cfg, "450129999999999", "45005", &m);
	CHECK_STR(m.how, "network"); CHECK_STR(m.apn, "lte.sktelecom.com"); CHECK_STR(m.proxy_host, "smart.nate.com");
	carrier_resolve_mms(&cfg, "", "45005", &m);			/* the IMSI is not known yet: the network alone */
	CHECK_STR(m.how, "network"); CHECK(!m.via_ims);
	carrier_resolve_mms(&cfg, "450129999999999", "45099", &m);	/* neither */
	CHECK_STR(m.how, "none"); CHECK(m.via_ims); CHECK_STR(m.mmsc, ""); CHECK_STR(m.mmsc_source, "none"); CHECK_STR(m.name, "");
	carrier_resolve_mms(&cfg, "310260123456789", NULL, &m);
	CHECK_STR(m.how, "none");
	{
		struct carrier_val v;

		carrier_resolve_mmsc("", "450129999999999", "45005", &v);	/* the MMSC follows the same match */
		CHECK_STR(v.value, SKT_MMSC); CHECK_STR(v.source, "carrier");
		carrier_resolve_mmsc("", "450129999999999", "45099", &v);
		CHECK_STR(v.source, "none");
	}
	/* uci overrides, value by value */
	cfg.apn = "mms.example"; cfg.proxy = "proxy.example:8080"; cfg.mmsc = "http://mmsc.example/x"; cfg.user_agent = "UA/9"; cfg.accept = "a/b"; cfg.ip_type = "ipv4";
	carrier_resolve_mms(&cfg, SKT_IMSI, "", &m);
	CHECK_STR(m.apn, "mms.example"); CHECK_STR(m.ip_type, "ipv4"); CHECK_STR(m.proxy_host, "proxy.example"); CHECK_EQ(m.proxy_port, 8080);
	CHECK_STR(m.mmsc, "http://mmsc.example/x"); CHECK_STR(m.mmsc_source, "config"); CHECK_STR(m.user_agent, "UA/9"); CHECK_STR(m.accept, "a/b");
	cfg.proxy = "proxy.example";
	carrier_resolve_mms(&cfg, SKT_IMSI, "", &m);
	CHECK_EQ(m.proxy_port, 80);
	/* uci alone makes an entry for an unknown operator (a bearer with an APN, no table) */
	memset(&cfg, 0, sizeof(cfg));
	cfg.apn = "internet.example";
	carrier_resolve_mms(&cfg, "310260123456789", "", &m);
	CHECK(!m.via_ims); CHECK_STR(m.apn, "internet.example"); CHECK_STR(m.how, "none"); CHECK_STR(m.proxy_host, "");
	/* uci can also switch a table entry's proxy off: an explicit apn with the LG U+ entry moves it to a bearer */
	cfg.apn = "mms.lguplus.example";
	carrier_resolve_mms(&cfg, LGU_IMSI, "", &m);
	CHECK(!m.via_ims);
}

void test_carrier(void)
{
	t_find();
	t_resolve();
	t_mms_entries();
}
