/* SPDX-License-Identifier: GPL-2.0-or-later */
/* /etc/config/imsd through libuci (daemon only). */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <uci.h>
#include "config.h"
#include "util/log.h"

static const char *opt(struct uci_context *ctx, struct uci_section *s, const char *name)
{
	const char *v = uci_lookup_option_string(ctx, s, name);

	return v && v[0] ? v : NULL;
}

static void str_opt(struct uci_context *ctx, struct uci_section *s, const char *name, char *dst, size_t n)
{
	const char *v = opt(ctx, s, name);

	if (v)
		snprintf(dst, n, "%s", v);
}

static void int_opt(struct uci_context *ctx, struct uci_section *s, const char *name, int *dst)
{
	const char *v = opt(ctx, s, name);

	if (v)
		*dst = atoi(v);
}

static void uint_opt(struct uci_context *ctx, struct uci_section *s, const char *name, unsigned *dst, unsigned mult)
{
	const char *v = opt(ctx, s, name);

	if (v)
		*dst = (unsigned)atoi(v) * mult;
}

static void bool_opt(struct uci_context *ctx, struct uci_section *s, const char *name, bool *dst)
{
	const char *v = opt(ctx, s, name);

	if (v)
		*dst = !strcmp(v, "1") || !strcasecmp(v, "true") || !strcasecmp(v, "on") || !strcasecmp(v, "yes") || !strcasecmp(v, "enabled");
}

int config_load_uci(struct imsd_config *c, const char *confdir, char *err, size_t n)
{
	struct uci_context *ctx = uci_alloc_context();
	struct uci_package *pkg = NULL;
	struct uci_section *s = NULL;
	struct uci_element *e;
	struct imsmodem_cfg *m = &c->modem;
	struct reg_cfg *r = &c->reg;
	const char *v;
	int rc = -1;
	size_t k;

	config_defaults(c);
	if (!ctx) {
		snprintf(err, n, "out of memory");
		return -1;
	}
	if (confdir)
		uci_set_confdir(ctx, confdir);
	if (uci_load(ctx, "imsd", &pkg) || !pkg) {
		snprintf(err, n, "cannot load /etc/config/imsd");
		goto out;
	}
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *sec = uci_to_section(e);

		if (!strcmp(sec->type, "imsd") && (!s || !strcmp(sec->e.name, "main")))
			s = sec;
	}
	if (!s) {
		snprintf(err, n, "no 'config imsd main' section");
		goto out;
	}
	bool_opt(ctx, s, "enabled", &c->enabled);
	if ((v = opt(ctx, s, "log_level"))) {
		int l = imsd_log_parse_level(v);

		if (l < 0) {
			snprintf(err, n, "bad log_level '%s'", v);
			goto out;
		}
		c->log_level = l;
	}
	str_opt(ctx, s, "lan_ifname", c->lan_ifname, sizeof(c->lan_ifname));
	int_opt(ctx, s, "lan_sip_port", &c->lan_sip_port);
	str_opt(ctx, s, "lan_addr", c->lan_addr, sizeof(c->lan_addr));
	str_opt(ctx, s, "user_agent", c->user_agent, sizeof(c->user_agent));
	uint_opt(ctx, s, "reg_min_expires", &c->reg_min_expires, 1);
	uint_opt(ctx, s, "reg_max_expires", &c->reg_max_expires, 1);
	uint_opt(ctx, s, "reg_default_expires", &c->reg_default_expires, 1);
	uint_opt(ctx, s, "max_bindings", &c->max_bindings, 1);
	uint_opt(ctx, s, "keepalive", &c->keepalive, 1);
	uint_opt(ctx, s, "rtp_port_min", &c->rtp_port_min, 1);
	uint_opt(ctx, s, "rtp_port_max", &c->rtp_port_max, 1);
	uint_opt(ctx, s, "carrier_rtp_port_min", &c->carrier_rtp_port_min, 1);
	uint_opt(ctx, s, "carrier_rtp_port_max", &c->carrier_rtp_port_max, 1);
	int_opt(ctx, s, "opus_bitrate", &c->opus_bitrate);
	int_opt(ctx, s, "opus_complexity", &c->opus_complexity);
	bool_opt(ctx, s, "g722", &c->g722);
	{
		struct uci_option *o = uci_lookup_option(ctx, s, "lan_codecs");

		if (o && o->type == UCI_TYPE_LIST) {
			size_t k = 0;

			c->lan_codecs[0] = 0;
			uci_foreach_element(&o->v.list, e)
				if (k < sizeof(c->lan_codecs))
					k += snprintf(c->lan_codecs + k, sizeof(c->lan_codecs) - k, "%s%s", k ? " " : "", e->name);
		} else if (o && o->type == UCI_TYPE_STRING && o->v.string[0]) {
			snprintf(c->lan_codecs, sizeof(c->lan_codecs), "%s", o->v.string);
		}
	}
	uint_opt(ctx, s, "ring_timeout", &c->ring_timeout_s, 1);
	uint_opt(ctx, s, "rtp_timeout", &c->rtp_timeout_s, 1);
	uint_opt(ctx, s, "session_expires", &c->session_expires, 1);
	str_opt(ctx, s, "phone_context", c->phone_context, sizeof(c->phone_context));
	str_opt(ctx, s, "contact_params", c->contact_params, sizeof(c->contact_params));
	str_opt(ctx, s, "ims_user_agent", c->ims_user_agent, sizeof(c->ims_user_agent));
	bool_opt(ctx, s, "bench_incoming", &c->bench_incoming);
	str_opt(ctx, s, "backend", c->backend, sizeof(c->backend));
	for (k = 0; c->backend[k]; k++)
		c->backend[k] = (char)tolower((unsigned char)c->backend[k]);
	str_opt(ctx, s, "cs_pcm_device", c->cs_pcm_device, sizeof(c->cs_pcm_device));
	bool_opt(ctx, s, "cs_early_media", &c->cs_early_media);
	uint_opt(ctx, s, "cs_ring_timeout", &c->cs_ring_timeout_s, 1);
	uint_opt(ctx, s, "cs_short_ring_ms", &c->cs_short_ring_ms, 1);
	bool_opt(ctx, s, "cs_allow_roaming", &c->cs_allow_roaming);
	uint_opt(ctx, s, "cs_media_stall_ms", &c->cs_media_stall_ms, 1);
	uint_opt(ctx, s, "cs_sms_incomplete", &c->cs_sms_incomplete_s, 1);
	uint_opt(ctx, s, "ims_grace", &c->ims_grace_s, 1);
	uint_opt(ctx, s, "backend_switch_delay", &c->backend_switch_delay_s, 1);
	uint_opt(ctx, s, "backend_ims_settle", &c->backend_ims_settle_s, 1);
	str_opt(ctx, s, "smsc", c->smsc, sizeof(c->smsc));
	str_opt(ctx, s, "sms_psi", c->sms_psi, sizeof(c->sms_psi));
	bool_opt(ctx, s, "sms_concat_prefix", &c->sms_concat_prefix);
	bool_opt(ctx, s, "sms_delivery_reports", &c->sms_delivery_reports);
	str_opt(ctx, s, "sms_lost_policy", c->sms_lost_policy, sizeof(c->sms_lost_policy));
	bool_opt(ctx, s, "mms", &c->mms);
	str_opt(ctx, s, "mmsc", c->mmsc, sizeof(c->mmsc));
	str_opt(ctx, s, "mms_uaprof", c->mms_uaprof, sizeof(c->mms_uaprof));
	str_opt(ctx, s, "mms_apn", c->mms_apn, sizeof(c->mms_apn));
	str_opt(ctx, s, "mms_ip_type", c->mms_ip_type, sizeof(c->mms_ip_type));
	str_opt(ctx, s, "mms_proxy", c->mms_proxy, sizeof(c->mms_proxy));
	str_opt(ctx, s, "mms_user_agent", c->mms_user_agent, sizeof(c->mms_user_agent));
	str_opt(ctx, s, "mms_accept", c->mms_accept, sizeof(c->mms_accept));
	uint_opt(ctx, s, "mms_bearer_linger", &c->mms_bearer_linger_s, 1);
	uint_opt(ctx, s, "mms_route_table", &c->mms_route_table, 1);
	uint_opt(ctx, s, "mms_max_size", &c->mms_max_size, 1);
	str_opt(ctx, s, "mms_dir", c->mms_dir, sizeof(c->mms_dir));
	str_opt(ctx, s, "mms_url_base", c->mms_url_base, sizeof(c->mms_url_base));
	uint_opt(ctx, s, "mms_keep_messages", &c->mms_keep_messages, 1);
	uint_opt(ctx, s, "mms_keep_bytes", &c->mms_keep_bytes, 1);
	uint_opt(ctx, s, "mms_keep_days", &c->mms_keep_days, 1);
	uint_opt(ctx, s, "mms_text_split", &c->mms_text_split, 1);
	uint_opt(ctx, s, "mms_proxy_port", &c->mms_proxy_port, 1);
	uint_opt(ctx, s, "mms_proxy_cache", &c->mms_proxy_cache, 1);
	bool_opt(ctx, s, "carbons", &c->carbons);
	bool_opt(ctx, s, "store", &c->store);
	bool_opt(ctx, s, "lan_persist", &c->lan_persist);
	str_opt(ctx, s, "store_dir", c->store_dir, sizeof(c->store_dir));
	uint_opt(ctx, s, "store_keep_messages", &c->store_keep_messages, 1);
	uint_opt(ctx, s, "store_keep_days", &c->store_keep_days, 1);
	uint_opt(ctx, s, "store_keep_bytes", &c->store_keep_bytes, 1);
	str_opt(ctx, s, "apn", m->apn, sizeof(m->apn));
	str_opt(ctx, s, "ip_type", m->ip_type, sizeof(m->ip_type));
	int_opt(ctx, s, "profile_id", &m->profile_id);
	bool_opt(ctx, s, "manage_modem", &m->manage_modem);
	str_opt(ctx, s, "modem", m->modem_pin, sizeof(m->modem_pin));
	str_opt(ctx, s, "impi", m->o_impi, sizeof(m->o_impi));
	str_opt(ctx, s, "impu", m->o_impu, sizeof(m->o_impu));
	str_opt(ctx, s, "domain", m->o_domain, sizeof(m->o_domain));
	uint_opt(ctx, s, "route_table", &m->route_table, 1);
	m->rule_pref = 0;
	{
		struct uci_option *o = uci_lookup_option(ctx, s, "pcscf");

		if (o && o->type == UCI_TYPE_LIST) {
			uci_foreach_element(&o->v.list, e)
				if (m->n_static < IMS_MAX_PCSCF && e->name[0])
					snprintf(m->static_pcscf[m->n_static++], sizeof(m->static_pcscf[0]), "%s", e->name);
		} else if (o && o->type == UCI_TYPE_STRING && o->v.string[0]) {
			snprintf(m->static_pcscf[m->n_static++], sizeof(m->static_pcscf[0]), "%s", o->v.string);
		}
	}
	int_opt(ctx, s, "pcscf_port", &r->pcscf_port);
	int_opt(ctx, s, "expires", &r->expires);
	str_opt(ctx, s, "pani", r->pani, sizeof(r->pani));
	uint_opt(ctx, s, "port_min", &r->port_min, 1);
	uint_opt(ctx, s, "port_max", &r->port_max, 1);
	uint_opt(ctx, s, "backoff_min", &r->backoff_min_ms, 1000);
	uint_opt(ctx, s, "backoff_max", &r->backoff_max_ms, 1000);
	rc = config_validate(c, err, n);
out:
	if (pkg)
		uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return rc;
}
