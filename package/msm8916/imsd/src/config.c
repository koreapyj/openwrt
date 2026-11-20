/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <ctype.h>
#include "config.h"
#include "util/addr.h"

#ifndef IMSD_VERSION
#define IMSD_VERSION "0.1"
#endif

void config_defaults(struct imsd_config *c)
{
	memset(c, 0, sizeof(*c));
	c->log_level = LOG_INFO;
	snprintf(c->lan_ifname, sizeof(c->lan_ifname), "br-lan");
	c->lan_sip_port = 5060;
	snprintf(c->user_agent, sizeof(c->user_agent), "imsd");
	c->reg_min_expires = 60;
	c->reg_max_expires = 3600;
	c->reg_default_expires = 3600;
	c->max_bindings = 16;
	c->rtp_port_min = 16384;
	c->rtp_port_max = 16482;
	c->carrier_rtp_port_min = 50000;
	c->carrier_rtp_port_max = 50098;
	c->opus_bitrate = 24000;
	c->opus_complexity = 5;
	c->g722 = true;
	snprintf(c->lan_codecs, sizeof(c->lan_codecs), "opus g722 pcma");
	c->ring_timeout_s = 60;
	c->rtp_timeout_s = 30;
	c->session_expires = 1800;
	snprintf(c->backend, sizeof(c->backend), "auto");
	c->cs_early_media = true;
	c->cs_ring_timeout_s = 120;
	c->cs_short_ring_ms = 4000;
	c->cs_allow_roaming = true;
	c->cs_media_stall_ms = 1500;
	c->cs_sms_incomplete_s = 600;
	c->ims_grace_s = 45;
	c->backend_switch_delay_s = 20;
	c->backend_ims_settle_s = 10;
	c->sms_concat_prefix = true;
	snprintf(c->sms_lost_policy, sizeof(c->sms_lost_policy), "ack");
	c->mms = true;
	c->mms_max_size = 1024 * 1024;
	c->mms_bearer_linger_s = 20;
	c->mms_route_table = 1007;
	snprintf(c->mms_dir, sizeof(c->mms_dir), "/tmp/imsd-mms");
	c->mms_keep_messages = 50;
	c->mms_keep_bytes = 16 * 1024 * 1024;
	c->mms_keep_days = 7;
	c->mms_text_split = 1000;
	c->mms_proxy_port = 8090;
	c->mms_proxy_cache = 600;
	c->carbons = true;
	c->store = true;
	c->lan_persist = true;
	snprintf(c->store_dir, sizeof(c->store_dir), "/srv/imsd");
	c->store_keep_messages = 500;
	c->store_keep_days = 0;
	c->store_keep_bytes = 32u * 1024 * 1024;
	imsmodem_cfg_defaults(&c->modem);
	reg_cfg_defaults(&c->reg);
}

void config_ims_user_agent(const struct imsd_config *c, char *out, size_t n)
{
	char ver[24];
	size_t l = strcspn(IMSD_VERSION, "-");

	if (c->ims_user_agent[0]) {
		snprintf(out, n, "%s", c->ims_user_agent);
		return;
	}
	if (l >= sizeof(ver))
		l = sizeof(ver) - 1;
	memcpy(ver, IMSD_VERSION, l);
	ver[l] = 0;
	snprintf(out, n, "TTA-VoLTE/3.0 imsd/%s Device_Type/Android_Phone OMD", ver);
}

/* Parse and normalise lan_codecs (opus, g722, pcma in any order, no duplicates; separators: blanks / commas). 0 / -1 */
static int parse_codecs(struct imsd_config *c, char *err, size_t n)
{
	char norm[sizeof(c->lan_codecs)] = "", tok[16];
	const char *p = c->lan_codecs;
	size_t o = 0;
	int i;

	c->n_lan_codec_pref = 0;
	while (*p) {
		enum codec_id id;
		size_t l = 0;

		while (*p == ' ' || *p == ',' || *p == '\t')
			p++;
		if (!*p)
			break;
		while (*p && *p != ' ' && *p != ',' && *p != '\t') {
			if (l + 1 >= sizeof(tok)) {
				snprintf(err, n, "lan_codecs: token too long");
				return -1;
			}
			tok[l++] = tolower((unsigned char)*p++);
		}
		tok[l] = 0;
		if (!strcmp(tok, "opus"))
			id = CODEC_OPUS;
		else if (!strcmp(tok, "g722"))
			id = CODEC_G722;
		else if (!strcmp(tok, "pcma"))
			id = CODEC_PCMA;
		else {
			snprintf(err, n, "lan_codecs: '%s' is not one of opus, g722, pcma", tok);
			return -1;
		}
		for (i = 0; i < c->n_lan_codec_pref; i++)
			if (c->lan_codec_pref[i] == id)
				break;
		if (i < c->n_lan_codec_pref)
			continue;	/* duplicate: first one wins */
		c->lan_codec_pref[c->n_lan_codec_pref++] = id;
		o += snprintf(norm + o, sizeof(norm) - o, "%s%s", o ? " " : "", tok);
	}
	if (!c->n_lan_codec_pref) {
		snprintf(err, n, "lan_codecs is empty");
		return -1;
	}
	snprintf(c->lan_codecs, sizeof(c->lan_codecs), "%s", norm);
	if (!c->g722) {
		int k = 0;

		for (i = 0; i < c->n_lan_codec_pref; i++)
			if (c->lan_codec_pref[i] != CODEC_G722)
				c->lan_codec_pref[k++] = c->lan_codec_pref[i];
		c->n_lan_codec_pref = k;
		if (!k) {
			snprintf(err, n, "lan_codecs lists only g722 but g722 is switched off");
			return -1;
		}
	}
	return 0;
}

bool config_lan_changed(const struct imsd_config *a, const struct imsd_config *b)
{
	return strcmp(a->lan_ifname, b->lan_ifname) || a->lan_sip_port != b->lan_sip_port || strcmp(a->lan_addr, b->lan_addr) ||
	       strcmp(a->user_agent, b->user_agent) || a->reg_min_expires != b->reg_min_expires ||
	       a->reg_max_expires != b->reg_max_expires || a->reg_default_expires != b->reg_default_expires ||
	       a->max_bindings != b->max_bindings || a->keepalive != b->keepalive;
}

static bool ranges_overlap(unsigned a0, unsigned a1, unsigned b0, unsigned b1)
{
	return a0 <= b1 && b0 <= a1;
}

#define FAIL(...) do { snprintf(err, n, __VA_ARGS__); return -1; } while (0)

int config_validate(struct imsd_config *c, char *err, size_t n)
{
	struct imsmodem_cfg *m = &c->modem;
	struct reg_cfg *r = &c->reg;
	int i;
	struct addr a;

	if (!m->apn[0])
		FAIL("apn must not be empty");
	if (strcasecmp(m->ip_type, "ipv4") && strcasecmp(m->ip_type, "ipv6") && strcasecmp(m->ip_type, "ipv4v6"))
		FAIL("ip_type '%s' is not ipv4, ipv6 or ipv4v6", m->ip_type);
	if (m->profile_id < 0 || m->profile_id > 255)
		FAIL("profile_id %d out of range", m->profile_id);
	if (m->route_table < 1 || m->route_table > 0x7fffffffu || (m->route_table >= 253 && m->route_table <= 255))
		FAIL("route_table %u is not usable (0, 253..255 are reserved)", m->route_table);
	for (i = 0; i < m->n_static; i++)
		if (addr_set(&a, m->static_pcscf[i], 5060))
			FAIL("pcscf '%s' is not an IP address", m->static_pcscf[i]);
	if (r->pcscf_port < 1 || r->pcscf_port > 65535)
		FAIL("pcscf_port %d out of range", r->pcscf_port);
	if (r->expires < 60 || r->expires > 1000000)
		FAIL("expires %d out of range (60..1000000)", r->expires);
	if (r->port_min < 1024 || r->port_max > 65535 || r->port_max < r->port_min + 16)
		FAIL("port range %u..%u is not usable (1024..65535, at least 16 ports)", r->port_min, r->port_max);
	if (r->backoff_min_ms < 1000 || r->backoff_max_ms < r->backoff_min_ms)
		FAIL("backoff %u..%u ms is not usable", r->backoff_min_ms, r->backoff_max_ms);
	if (c->lan_sip_port < 1 || c->lan_sip_port > 65535)
		FAIL("lan_sip_port %d out of range", c->lan_sip_port);
	if (m->o_impu[0] && strncasecmp(m->o_impu, "sip:", 4))
		FAIL("impu '%s' must be a sip: URI", m->o_impu);

	/* LAN side */
	if (!c->lan_ifname[0] || strlen(c->lan_ifname) > 15 || strchr(c->lan_ifname, '/') || strchr(c->lan_ifname, ' '))
		FAIL("lan_ifname '%s' is not an interface name", c->lan_ifname);
	if (c->lan_addr[0] && (addr_set(&a, c->lan_addr, 0) || !addr_is_v4(&a)))
		FAIL("lan_addr '%s' is not an IPv4 address", c->lan_addr);
	if (!c->user_agent[0] || strpbrk(c->user_agent, "\r\n"))
		FAIL("user_agent must be a single non-empty line");
	if (c->reg_min_expires < 10 || c->reg_min_expires > 86400)
		FAIL("reg_min_expires %u out of range (10..86400)", c->reg_min_expires);
	if (c->reg_max_expires < c->reg_min_expires || c->reg_max_expires > 86400)
		FAIL("reg_max_expires %u out of range (reg_min_expires..86400)", c->reg_max_expires);
	if (c->reg_default_expires < c->reg_min_expires || c->reg_default_expires > c->reg_max_expires)
		FAIL("reg_default_expires %u must lie between reg_min_expires and reg_max_expires", c->reg_default_expires);
	if (c->max_bindings < 1 || c->max_bindings > 256)
		FAIL("max_bindings %u out of range (1..256)", c->max_bindings);
	if (c->keepalive && (c->keepalive < 10 || c->keepalive > 3600))
		FAIL("keepalive %u out of range (0 = off, or 10..3600)", c->keepalive);

	/* media */
	if (c->rtp_port_min < 1024 || c->rtp_port_max > 65535 || c->rtp_port_max < c->rtp_port_min + 8)
		FAIL("rtp_port range %u..%u is not usable (1024..65535, at least 8 ports)", c->rtp_port_min, c->rtp_port_max);
	if (c->carrier_rtp_port_min < 1024 || c->carrier_rtp_port_max > 65535 ||
	    c->carrier_rtp_port_max < c->carrier_rtp_port_min + 8)
		FAIL("carrier_rtp_port range %u..%u is not usable (1024..65535, at least 8 ports)", c->carrier_rtp_port_min,
		     c->carrier_rtp_port_max);
	if (ranges_overlap(c->rtp_port_min, c->rtp_port_max, c->carrier_rtp_port_min, c->carrier_rtp_port_max))
		FAIL("rtp_port and carrier_rtp_port ranges overlap");
	if (ranges_overlap(c->carrier_rtp_port_min, c->carrier_rtp_port_max, r->port_min, r->port_max))
		FAIL("carrier_rtp_port range overlaps the Gm port range %u..%u", r->port_min, r->port_max);
	if (c->lan_sip_port >= (int)c->rtp_port_min && c->lan_sip_port <= (int)c->rtp_port_max)
		FAIL("lan_sip_port %d lies inside the rtp_port range", c->lan_sip_port);
	if (c->opus_bitrate < 6000 || c->opus_bitrate > 510000)
		FAIL("opus_bitrate %d out of range (6000..510000)", c->opus_bitrate);
	if (c->opus_complexity < 0 || c->opus_complexity > 10)
		FAIL("opus_complexity %d out of range (0..10)", c->opus_complexity);
	if (parse_codecs(c, err, n))
		return -1;

	/* calls and SMS */
	if (c->ring_timeout_s > 600)
		FAIL("ring_timeout %u out of range (0 = none, or 1..600)", c->ring_timeout_s);
	if (c->rtp_timeout_s > 3600)
		FAIL("rtp_timeout %u out of range (0 = off, or 1..3600)", c->rtp_timeout_s);
	if (strcmp(c->backend, "auto") && strcmp(c->backend, "ims") && strcmp(c->backend, "cs"))
		FAIL("backend '%s' is not auto, ims or cs", c->backend);
	if (strspn(c->cs_pcm_device, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,_-") != strlen(c->cs_pcm_device))
		FAIL("cs_pcm_device '%s' must be empty, auto, auto,<device> or <card>,<device>", c->cs_pcm_device);
	if (c->cs_ring_timeout_s > 3600)
		FAIL("cs_ring_timeout %u out of range (0 = off, or 1..3600)", c->cs_ring_timeout_s);
	if (c->cs_short_ring_ms > 60000)
		FAIL("cs_short_ring_ms %u out of range (0..60000)", c->cs_short_ring_ms);
	if (c->cs_sms_incomplete_s < 30 || c->cs_sms_incomplete_s > 86400)
		FAIL("cs_sms_incomplete %u out of range (30..86400)", c->cs_sms_incomplete_s);
	if (c->cs_media_stall_ms && (c->cs_media_stall_ms < 200 || c->cs_media_stall_ms > 60000))
		FAIL("cs_media_stall_ms %u out of range (0 = off, or 200..60000)", c->cs_media_stall_ms);
	if (c->ims_grace_s > 600 || c->backend_switch_delay_s > 600 || c->backend_ims_settle_s > 600)
		FAIL("ims_grace / backend_switch_delay / backend_ims_settle out of range (0..600 s)");
	if (c->session_expires < 90 || c->session_expires > 86400)
		FAIL("session_expires %u out of range (90..86400)", c->session_expires);
	if (strpbrk(c->phone_context, " \r\n;<>\"") != NULL)
		FAIL("phone_context '%s' is not a domain", c->phone_context);
	if (c->contact_params[0] && (c->contact_params[0] != ';' || strpbrk(c->contact_params, "\r\n")))
		FAIL("contact_params must start with ';' and be a single line");
	if (strpbrk(c->ims_user_agent, "\r\n"))
		FAIL("ims_user_agent must be a single line");
	config_ims_user_agent(c, r->user_agent, sizeof(r->user_agent));	/* the registration layer sends the same one */
	if (c->smsc[0]) {
		const char *p = c->smsc + (c->smsc[0] == '+');
		size_t k = strspn(p, "0123456789");

		if (!k || p[k] || k > 20)
			FAIL("smsc '%s' is not a phone number (+821012345678 or 01012345678)", c->smsc);
	}
	if (c->sms_psi[0] && (strncasecmp(c->sms_psi, "sip:", 4) || strpbrk(c->sms_psi, " \r\n<>")))
		FAIL("sms_psi '%s' must be a sip: URI", c->sms_psi);
	if (strcmp(c->sms_lost_policy, "ack") && strcmp(c->sms_lost_policy, "rperror22"))
		FAIL("sms_lost_policy '%s' is not ack or rperror22", c->sms_lost_policy);

	/* MMS */
	if (c->mmsc[0] && (strncasecmp(c->mmsc, "http://", 7) || c->mmsc[7] == 0 || strpbrk(c->mmsc, " \r\n\t<>\"")))
		FAIL("mmsc '%s' must be an http:// URL (https is not supported)", c->mmsc);
	if (c->mms_apn[0] && (strlen(c->mms_apn) > 60 || strpbrk(c->mms_apn, " \r\n\t\"'\\")))
		FAIL("mms_apn '%s' is not an APN", c->mms_apn);
	if (c->mms_ip_type[0] && strcmp(c->mms_ip_type, "ipv4") && strcmp(c->mms_ip_type, "ipv6") && strcmp(c->mms_ip_type, "ipv4v6"))
		FAIL("mms_ip_type '%s' is not ipv4, ipv6 or ipv4v6", c->mms_ip_type);
	if (c->mms_proxy[0]) {
		const char *colon = strrchr(c->mms_proxy, ':');
		unsigned long port = colon ? strtoul(colon + 1, NULL, 10) : 80;

		if (strpbrk(c->mms_proxy, " \r\n\t/\"<>") || (colon && (port < 1 || port > 65535 || colon == c->mms_proxy)))
			FAIL("mms_proxy '%s' must be host or host:port", c->mms_proxy);
	}
	if (strpbrk(c->mms_user_agent, "\r\n") || strpbrk(c->mms_accept, "\r\n"))
		FAIL("mms_user_agent / mms_accept must be one line");
	if (c->mms_bearer_linger_s > 3600)
		FAIL("mms_bearer_linger %u out of range (0..3600 seconds)", c->mms_bearer_linger_s);
	if (c->mms_route_table < 1 || c->mms_route_table > 0x7fffffffu || (c->mms_route_table >= 253 && c->mms_route_table <= 255) ||
	    c->mms_route_table == c->modem.route_table)
		FAIL("mms_route_table %u is not usable (0, 253..255 are reserved, it must differ from route_table)", c->mms_route_table);
	if (c->mms_uaprof[0] && (strncasecmp(c->mms_uaprof, "http://", 7) && strncasecmp(c->mms_uaprof, "https://", 8)))
		FAIL("mms_uaprof '%s' must be an http(s):// URL", c->mms_uaprof);
	if (strpbrk(c->mms_uaprof, " \r\n\t"))
		FAIL("mms_uaprof must be a single URL");
	if (c->mms_max_size < 4096 || c->mms_max_size > 16u * 1024 * 1024)
		FAIL("mms_max_size %u out of range (4096..16777216)", c->mms_max_size);
	if (c->mms_dir[0] != '/' || strlen(c->mms_dir) < 6 || c->mms_dir[strlen(c->mms_dir) - 1] == '/' ||
	    strstr(c->mms_dir, "..") || strstr(c->mms_dir, "//") || strpbrk(c->mms_dir, " \r\n\t\"'\\"))
		FAIL("mms_dir '%s' must be an absolute directory path (a tmpfs, e.g. /tmp/imsd-mms)", c->mms_dir);
	if (c->mms_url_base[0] && ((strncasecmp(c->mms_url_base, "http://", 7) && strncasecmp(c->mms_url_base, "https://", 8)) ||
				   c->mms_url_base[strlen(c->mms_url_base) - 1] != '/' || strpbrk(c->mms_url_base, " \r\n\t<>\"")))
		FAIL("mms_url_base '%s' must be an http(s):// URL ending in '/'", c->mms_url_base);
	if (c->mms_keep_messages < 1 || c->mms_keep_messages > 1000)
		FAIL("mms_keep_messages %u out of range (1..1000)", c->mms_keep_messages);
	if (c->mms_keep_bytes < 65536 || c->mms_keep_bytes > 256u * 1024 * 1024)
		FAIL("mms_keep_bytes %u out of range (65536..268435456)", c->mms_keep_bytes);
	if (c->mms_keep_days > 365)
		FAIL("mms_keep_days %u out of range (0 = no age limit, or 1..365)", c->mms_keep_days);
	if (c->mms_text_split < 200 || c->mms_text_split > 1400)
		FAIL("mms_text_split %u out of range (200..1400: a SIP MESSAGE over UDP must fit one datagram)", c->mms_text_split);
	if (strlen(c->mms_dir) > 80)
		FAIL("mms_dir is too long (80 characters at most: the proxy keeps its files in <mms_dir>-proxy)");
	if (c->mms_proxy_port && (c->mms_proxy_port < 1024 || c->mms_proxy_port > 65535))
		FAIL("mms_proxy_port %u out of range (0 = off, or 1024..65535)", c->mms_proxy_port);
	if (c->store_dir[0] != '/' || strlen(c->store_dir) < 5 || strlen(c->store_dir) > 80 || c->store_dir[strlen(c->store_dir) - 1] == '/' ||
	    strstr(c->store_dir, "..") || strstr(c->store_dir, "//") || strpbrk(c->store_dir, " \r\n\t\"'\\"))
		FAIL("store_dir '%s' must be an absolute directory path on persistent storage (e.g. /srv/imsd)", c->store_dir);
	if (c->store_keep_messages < 1 || c->store_keep_messages > 5000)
		FAIL("store_keep_messages %u out of range (1..5000)", c->store_keep_messages);
	if (c->store_keep_days > 3650)
		FAIL("store_keep_days %u out of range (0 = no age limit, or 1..3650)", c->store_keep_days);
	if (c->store_keep_bytes < 65536 || c->store_keep_bytes > 1024u * 1024 * 1024)
		FAIL("store_keep_bytes %u out of range (65536..1073741824)", c->store_keep_bytes);
	if (c->mms_proxy_cache > 86400)
		FAIL("mms_proxy_cache %u out of range (0 = no cache, or 1..86400 seconds)", c->mms_proxy_cache);
	return 0;
}
