/* SPDX-License-Identifier: GPL-2.0-or-later */
/* configuration defaults and validation of the LAN / media options */
#include <string.h>
#include "test.h"
#include "../config.h"

static char err[160];

static int val(struct imsd_config *c)
{
	err[0] = 0;
	return config_validate(c, err, sizeof(err));
}

void test_config(void)
{
	struct imsd_config c, d;

	config_defaults(&c);
	CHECK_EQ(val(&c), 0);
	CHECK_STR(c.lan_ifname, "br-lan"); CHECK_STR(c.lan_addr, ""); CHECK_EQ(c.lan_sip_port, 5060);
	CHECK_EQ(c.reg_min_expires, 60); CHECK_EQ(c.reg_max_expires, 3600); CHECK_EQ(c.reg_default_expires, 3600);
	CHECK_EQ(c.max_bindings, 16); CHECK_EQ(c.keepalive, 0); CHECK_STR(c.user_agent, "imsd");
	CHECK_EQ(c.rtp_port_min, 16384); CHECK_EQ(c.rtp_port_max, 16482);
	CHECK_EQ(c.carrier_rtp_port_min, 50000); CHECK_EQ(c.carrier_rtp_port_max, 50098);
	CHECK_EQ(c.opus_bitrate, 24000); CHECK_EQ(c.opus_complexity, 5); CHECK(c.g722);
	CHECK_STR(c.lan_codecs, "opus g722 pcma");
	CHECK_EQ(c.n_lan_codec_pref, 3);
	CHECK_EQ(c.lan_codec_pref[0], CODEC_OPUS); CHECK_EQ(c.lan_codec_pref[1], CODEC_G722); CHECK_EQ(c.lan_codec_pref[2], CODEC_PCMA);

#define BAD(stmt, frag) do { d = c; stmt; CHECK_EQ(val(&d), -1); CHECK(strstr(err, frag) != NULL); } while (0)
	BAD(d.lan_ifname[0] = 0, "lan_ifname");
	BAD(strcpy(d.lan_ifname, "a-very-long-interface-name"), "lan_ifname");
	BAD(strcpy(d.lan_ifname, "br lan"), "lan_ifname");
	BAD(strcpy(d.lan_addr, "lan.example"), "lan_addr");
	BAD(strcpy(d.lan_addr, "2001:db8::1"), "lan_addr");
	BAD(strcpy(d.lan_addr, "300.1.1.1"), "lan_addr");
	BAD(d.lan_sip_port = 0, "lan_sip_port");
	BAD(d.lan_sip_port = 70000, "lan_sip_port");
	BAD(d.user_agent[0] = 0, "user_agent");
	BAD(strcpy(d.user_agent, "x\r\nVia: y"), "user_agent");
	BAD(d.reg_min_expires = 5, "reg_min_expires");
	BAD(d.reg_max_expires = 30, "reg_max_expires");
	BAD(d.reg_max_expires = 90000, "reg_max_expires");
	BAD(d.reg_default_expires = 30, "reg_default_expires");
	BAD(d.reg_default_expires = 4000, "reg_default_expires");
	BAD(d.max_bindings = 0, "max_bindings");
	BAD(d.max_bindings = 1000, "max_bindings");
	BAD(d.keepalive = 3, "keepalive");
	BAD(d.keepalive = 100000, "keepalive");
	BAD(d.rtp_port_min = 500, "rtp_port");
	BAD(d.rtp_port_max = 16385, "rtp_port");
	BAD(d.rtp_port_max = 70000, "rtp_port");
	BAD(d.carrier_rtp_port_max = d.carrier_rtp_port_min + 4, "carrier_rtp_port");
	BAD(d.carrier_rtp_port_min = 16400; d.carrier_rtp_port_max = 16500, "overlap");	/* with the LAN range */
	BAD(d.carrier_rtp_port_min = 8500; d.carrier_rtp_port_max = 8600, "Gm port range");
	BAD(d.lan_sip_port = 16400, "lan_sip_port");
	BAD(d.opus_bitrate = 1000, "opus_bitrate");
	BAD(d.opus_bitrate = 600000, "opus_bitrate");
	BAD(d.opus_complexity = 11, "opus_complexity");
	BAD(d.opus_complexity = -1, "opus_complexity");
	BAD(strcpy(d.lan_codecs, "opus speex"), "speex");
	BAD(strcpy(d.lan_codecs, "amr"), "amr");
	BAD(strcpy(d.lan_codecs, "  "), "empty");
	BAD(strcpy(d.lan_codecs, "g722"); d.g722 = false, "g722");

	/* calls and SMS options */
	CHECK_EQ(c.ring_timeout_s, 60); CHECK_EQ(c.rtp_timeout_s, 30); CHECK_EQ(c.session_expires, 1800);
	CHECK(!c.bench_incoming); CHECK_STR(c.sms_psi, ""); CHECK(c.sms_concat_prefix);
	CHECK(!c.sms_delivery_reports); CHECK_STR(c.sms_lost_policy, "ack"); CHECK_STR(c.smsc, "");
	{
		char ua[128];

		config_ims_user_agent(&c, ua, sizeof(ua));
		CHECK_STR(ua, "TTA-VoLTE/3.0 imsd/0.1 Device_Type/Android_Phone OMD");
		d = c; strcpy(d.ims_user_agent, "X/1"); config_ims_user_agent(&d, ua, sizeof(ua)); CHECK_STR(ua, "X/1");
	}
	BAD(d.ring_timeout_s = 601, "ring_timeout");
	BAD(d.rtp_timeout_s = 4000, "rtp_timeout");
	BAD(d.session_expires = 60, "session_expires");
	BAD(strcpy(d.phone_context, "a b"), "phone_context");
	BAD(strcpy(d.contact_params, "x"), "contact_params");
	BAD(strcpy(d.ims_user_agent, "a\r\nb"), "ims_user_agent");
	BAD(strcpy(d.smsc, "+82abc"), "smsc");
	BAD(strcpy(d.sms_psi, "tel:123"), "sms_psi");
	BAD(strcpy(d.sms_lost_policy, "drop"), "sms_lost_policy");
	d = c; strcpy(d.smsc, "+821080010585"); strcpy(d.phone_context, "lte-lguplus.co.kr"); d.ring_timeout_s = 0; CHECK_EQ(val(&d), 0);

	/* backend options */
	CHECK_STR(c.backend, "auto"); CHECK_STR(c.cs_pcm_device, ""); CHECK(c.cs_early_media); CHECK_EQ(c.cs_ring_timeout_s, 120);
	CHECK_EQ(c.cs_short_ring_ms, 4000); CHECK(c.cs_allow_roaming); CHECK_EQ(c.cs_media_stall_ms, 1500); CHECK_EQ(c.cs_sms_incomplete_s, 600);
	CHECK_EQ(c.ims_grace_s, 45); CHECK_EQ(c.backend_switch_delay_s, 20); CHECK_EQ(c.backend_ims_settle_s, 10);
	BAD(strcpy(d.backend, "volte"), "backend");
	BAD(strcpy(d.backend, "CS"), "backend");		/* the uci reader lower-cases, the validator is exact */
	BAD(strcpy(d.cs_pcm_device, "hw:0 1"), "cs_pcm_device");
	BAD(strcpy(d.cs_pcm_device, "../x"), "cs_pcm_device");
	BAD(d.cs_ring_timeout_s = 3601, "cs_ring_timeout");
	BAD(d.cs_short_ring_ms = 70000, "cs_short_ring_ms");
	BAD(d.cs_media_stall_ms = 50, "cs_media_stall_ms");
	BAD(d.cs_sms_incomplete_s = 5, "cs_sms_incomplete");
	BAD(d.ims_grace_s = 601, "ims_grace");
	BAD(d.backend_switch_delay_s = 601, "backend_switch_delay");
	d = c; strcpy(d.backend, "cs"); strcpy(d.cs_pcm_device, "auto,1"); d.cs_ring_timeout_s = 0; d.cs_media_stall_ms = 0; CHECK_EQ(val(&d), 0);
	d = c; strcpy(d.backend, "ims"); strcpy(d.cs_pcm_device, "0,1"); CHECK_EQ(val(&d), 0);

	/* MMS options */
	CHECK(c.mms); CHECK_STR(c.mmsc, ""); CHECK_STR(c.mms_uaprof, ""); CHECK_EQ(c.mms_max_size, 1048576);
	CHECK_STR(c.mms_dir, "/tmp/imsd-mms"); CHECK_STR(c.mms_url_base, ""); CHECK_EQ(c.mms_keep_messages, 50);
	CHECK_EQ(c.mms_keep_bytes, 16 * 1024 * 1024); CHECK_EQ(c.mms_keep_days, 7); CHECK_EQ(c.mms_text_split, 1000);
	CHECK_STR(c.mms_apn, ""); CHECK_STR(c.mms_ip_type, ""); CHECK_STR(c.mms_proxy, ""); CHECK_STR(c.mms_user_agent, ""); CHECK_STR(c.mms_accept, "");
	CHECK_EQ(c.mms_bearer_linger_s, 20); CHECK_EQ(c.mms_route_table, 1007);
	BAD(strcpy(d.mms_apn, "a b"), "mms_apn");
	BAD(strcpy(d.mms_ip_type, "ipv5"), "mms_ip_type");
	BAD(strcpy(d.mms_proxy, "http://p:80"), "mms_proxy");
	BAD(strcpy(d.mms_proxy, "p.example:0"), "mms_proxy");
	BAD(strcpy(d.mms_proxy, "p.example:70000"), "mms_proxy");
	BAD(strcpy(d.mms_user_agent, "a\r\nX: y"), "mms_user_agent");
	BAD(d.mms_bearer_linger_s = 4000, "mms_bearer_linger");
	BAD(d.mms_route_table = 0, "mms_route_table");
	BAD(d.mms_route_table = 254, "mms_route_table");
	BAD(d.mms_route_table = d.modem.route_table, "mms_route_table");
	d = c; strcpy(d.mms_apn, "mms.example"); strcpy(d.mms_ip_type, "ipv4"); strcpy(d.mms_proxy, "p.example:8080"); strcpy(d.mms_user_agent, "UA/1");
	d.mms_bearer_linger_s = 0;
	CHECK_EQ(val(&d), 0);
	BAD(strcpy(d.mmsc, "https://mmsc.example/"), "mmsc");
	BAD(strcpy(d.mmsc, "mmsc.example"), "mmsc");
	BAD(strcpy(d.mmsc, "http://a b/"), "mmsc");
	BAD(strcpy(d.mms_uaprof, "ftp://x/y.xml"), "mms_uaprof");
	BAD(d.mms_max_size = 100, "mms_max_size");
	BAD(d.mms_max_size = 100u * 1024 * 1024, "mms_max_size");
	BAD(strcpy(d.mms_dir, "tmp/x"), "mms_dir");
	BAD(strcpy(d.mms_dir, "/"), "mms_dir");
	BAD(strcpy(d.mms_dir, "/tmp/../etc"), "mms_dir");
	BAD(strcpy(d.mms_dir, "/tmp/imsd-mms/"), "mms_dir");
	BAD(strcpy(d.mms_url_base, "http://192.168.1.1/imsd-mms"), "mms_url_base");
	BAD(strcpy(d.mms_url_base, "192.168.1.1/imsd-mms/"), "mms_url_base");
	BAD(d.mms_keep_messages = 0, "mms_keep_messages");
	BAD(d.mms_keep_messages = 5000, "mms_keep_messages");
	BAD(d.mms_keep_bytes = 100, "mms_keep_bytes");
	BAD(d.mms_keep_days = 400, "mms_keep_days");
	/* the store */
	CHECK(c.store); CHECK_STR(c.store_dir, "/srv/imsd"); CHECK_EQ(c.store_keep_messages, 500); CHECK_EQ(c.store_keep_days, 0);	/* no age limit by default: it would depend on the system clock */
	CHECK_EQ(c.store_keep_bytes, 32 * 1024 * 1024);
	BAD(strcpy(d.store_dir, "srv/imsd"), "store_dir");
	BAD(strcpy(d.store_dir, "/srv/imsd/"), "store_dir");
	BAD(strcpy(d.store_dir, "/srv/../etc"), "store_dir");
	BAD(strcpy(d.store_dir, "/a"), "store_dir");
	BAD(d.store_keep_messages = 0, "store_keep_messages");
	BAD(d.store_keep_messages = 5001, "store_keep_messages");
	BAD(d.store_keep_days = 4000, "store_keep_days");
	BAD(d.store_keep_bytes = 1000, "store_keep_bytes");
	d = c; d.store = false; d.store_keep_days = 0; CHECK_EQ(val(&d), 0);
	BAD(d.mms_text_split = 100, "mms_text_split");
	BAD(d.mms_text_split = 5000, "mms_text_split");
	/* MMS proxy and carbon copies */
	CHECK_EQ(c.mms_proxy_port, 8090); CHECK_EQ(c.mms_proxy_cache, 600); CHECK(c.carbons);
	BAD(d.mms_proxy_port = 80, "mms_proxy_port");
	BAD(d.mms_proxy_port = 70000, "mms_proxy_port");
	BAD(d.mms_proxy_cache = 100000, "mms_proxy_cache");
	d = c; memset(d.mms_dir, 'a', 81); d.mms_dir[0] = '/'; d.mms_dir[81] = 0; CHECK_EQ(val(&d), -1); CHECK(strstr(err, "too long") != NULL);
	d = c; d.mms_proxy_port = 0; d.mms_proxy_cache = 0; d.carbons = false; CHECK_EQ(val(&d), 0);
	d = c; d.mms_proxy_port = 1024; d.mms_proxy_cache = 86400; CHECK_EQ(val(&d), 0);
	d = c; strcpy(d.mmsc, "http://omammsc.uplus.co.kr:9084"); strcpy(d.mms_url_base, "http://192.168.1.1/imsd-mms/");
	d.mms_keep_days = 0; d.mms = false; d.mms_text_split = 200; CHECK_EQ(val(&d), 0);

	/* the good edges */
	d = c; d.keepalive = 10; CHECK_EQ(val(&d), 0);
	d = c; d.keepalive = 3600; CHECK_EQ(val(&d), 0);
	d = c; d.reg_min_expires = d.reg_max_expires = d.reg_default_expires = 300; CHECK_EQ(val(&d), 0);
	d = c; strcpy(d.lan_addr, "192.168.1.1"); CHECK_EQ(val(&d), 0);
	d = c; d.rtp_port_min = 20000; d.rtp_port_max = 20008; CHECK_EQ(val(&d), 0);
	d = c; d.opus_bitrate = 6000; d.opus_complexity = 0; CHECK_EQ(val(&d), 0);

	/* codec list: any order, separators, case, duplicates; normalised; g722 switch */
	d = c; strcpy(d.lan_codecs, "PCMA,Opus  g722 pcma"); CHECK_EQ(val(&d), 0);
	CHECK_STR(d.lan_codecs, "pcma opus g722"); CHECK_EQ(d.n_lan_codec_pref, 3);
	CHECK_EQ(d.lan_codec_pref[0], CODEC_PCMA); CHECK_EQ(d.lan_codec_pref[1], CODEC_OPUS); CHECK_EQ(d.lan_codec_pref[2], CODEC_G722);
	d.g722 = false; CHECK_EQ(val(&d), 0);	/* validating again is idempotent; g722 leaves the effective list */
	CHECK_EQ(d.n_lan_codec_pref, 2); CHECK_EQ(d.lan_codec_pref[0], CODEC_PCMA); CHECK_EQ(d.lan_codec_pref[1], CODEC_OPUS);
	d = c; strcpy(d.lan_codecs, "pcma"); CHECK_EQ(val(&d), 0); CHECK_EQ(d.n_lan_codec_pref, 1);

	/* the existing options still validate as before */
	d = c; d.reg.port_min = 16400; d.reg.port_max = 16500; CHECK_EQ(val(&d), 0);	/* Gm ports live on the IMS netdev: only the carrier range matters */
	d = c; d.reg.port_min = 50010; d.reg.port_max = 50100; CHECK_EQ(val(&d), -1); CHECK(strstr(err, "Gm port range") != NULL);

	/* config_lan_changed: only the LAN socket / registrar options count */
	d = c; CHECK(!config_lan_changed(&c, &d));
	d.opus_bitrate = 32000; d.rtp_port_min = 17000; d.keepalive = 0; strcpy(d.lan_codecs, "pcma"); CHECK(!config_lan_changed(&c, &d));
	d = c; d.lan_sip_port = 5061; CHECK(config_lan_changed(&c, &d));
	d = c; strcpy(d.lan_ifname, "br-guest"); CHECK(config_lan_changed(&c, &d));
	d = c; strcpy(d.lan_addr, "192.168.1.1"); CHECK(config_lan_changed(&c, &d));
	d = c; strcpy(d.user_agent, "x"); CHECK(config_lan_changed(&c, &d));
	d = c; d.max_bindings = 4; CHECK(config_lan_changed(&c, &d));
	d = c; d.keepalive = 30; CHECK(config_lan_changed(&c, &d));
	d = c; d.reg_min_expires = 120; CHECK(config_lan_changed(&c, &d));
	d = c; d.reg_max_expires = 7200; CHECK(config_lan_changed(&c, &d));
	d = c; d.reg_default_expires = 1800; CHECK(config_lan_changed(&c, &d));
}
