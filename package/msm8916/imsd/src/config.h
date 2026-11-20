/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CONFIG_H
#define IMSD_CONFIG_H
#include <stdbool.h>
#include <stddef.h>
#include "gm/reg.h"
#include "media/codec.h"
#include "modem/imsmodem.h"

/*
 * The daemon configuration (uci package imsd, section main). config.c holds
 * the defaults and the validation (host testable); config_uci.c reads uci.
 *
 *   option enabled        0|1                  (default 0)
 *   option log_level      error|warn|notice|info|debug  (info)
 *   option apn            IMS
 *   option ip_type        ipv6 | ipv4 | ipv4v6 (ipv6)
 *   option profile_id     6
 *   list   pcscf          static P-CSCF fallback (used only when the bearer has none)
 *   option pcscf_port     5060
 *   option expires        8000
 *   option pani           P-Access-Network-Info value
 *   option port_min/port_max   range for the protected and unprotected ports (8000..8999)
 *   option route_table    1006   routing table + rule priority for the IMS netdev
 *   option manage_modem   0      enable a disabled modem (bench use)
 *   option modem          pin the modem by device or object path
 *   option impi/impu/domain    identity overrides (bench use)
 *   option backoff_min / backoff_max   seconds, 5 / 900
 *
 * LAN side (SIP registrar for the softphones / ATAs on the LAN):
 *   option lan_ifname     br-lan   the SIP socket is bound to this interface (SO_BINDTODEVICE)
 *   option lan_addr       ""       explicit IPv4 bind / advertised address; default: first IPv4 address of lan_ifname
 *   option lan_sip_port   5060
 *   option reg_min_expires / reg_max_expires / reg_default_expires   60 / 3600 / 3600 s (REGISTER lifetime limits)
 *   option max_bindings   16       registered devices
 *   option keepalive      0        seconds between OPTIONS pings of the bindings, 0 = off
 *   option user_agent     imsd
 * Media:
 *   option rtp_port_min / rtp_port_max                 LAN leg RTP ports (even ports used): 16384..16482
 *   option carrier_rtp_port_min / carrier_rtp_port_max carrier leg (IMS netdev) RTP ports: 50000..50098
 *   option opus_bitrate   24000 (bit/s)   option opus_complexity 5 (0..10)
 *   option g722           1       0 drops G.722 from the offer on the LAN side
 *   option lan_codecs     "opus g722 pcma"  codec preference order on the LAN side (also accepted as a list)
 * Calls:
 *   option ring_timeout   60     s an incoming call rings the LAN devices (0 = none, the network decides)
 *   option rtp_timeout    30     s without carrier RTP before a call is hung up (0 = off; not while on hold)
 *   option session_expires 1800  Session-Expires we ask the network for (its answer wins)
 *   option phone_context  ""     phone-context for dialled local numbers; default: the ISIM home domain
 *   option contact_params ""     Contact feature tags of INVITE / 200; default: the mmtel icsi tag
 *   option ims_user_agent ""     User-Agent toward the network; default "TTA-VoLTE/3.0 imsd/<version> Device_Type/Android_Phone OMD"
 *   option bench_incoming 0      incoming calls may be answered over ubus (call_answer) when no LAN device is registered
 * Backend (circuit switched calls through the modem, cs/csbackend.h; the CS call path needs the voice sound card kmods):
 *   option backend        auto   auto | ims | cs. auto: 2G / 3G and LTE without usable IMS -> CS, LTE with IMS registered -> IMS
 *                                ims never starts the CS call path, cs never touches IMS (no bearer, no registration)
 *   option cs_pcm_device  ""     the modem's PCM device: "" / auto = first rtproxy card, "auto,1", or "<card>,<dev>"
 *   option cs_early_media 1      MO: open the audio at the alerting state (network ringback / announcements reach the phone)
 *   option cs_ring_timeout 120   s an outgoing CS call may alert before it is hung up (0 = off; the network decides)
 *   option cs_short_ring_ms 4000 alerting shorter than this and then ended by the far end = rejected (603)
 *   option cs_allow_roaming 1    CS calls while registered as roaming
 *   option cs_media_stall_ms 1500 a stall of the modem's capture stream this long ends a connected CS call (0 = off)
 *   option cs_sms_incomplete 600 s after which a concatenated CS SMS that is still missing parts is deleted from the modem
 *   option ims_grace      45     s the LTE attach waits for IMS to register before CS takes over (auto)
 *   option backend_switch_delay 20  s IMS is kept after its registration was lost before CS takes over (auto)
 *   option backend_ims_settle 10    s IMS must have been registered before CS hands over to it (auto)
 * SMS:
 *   option smsc           ""     SMSC override; default: USIM EF_SMSP
 *   option sms_psi        ""     SMS-over-IP gateway override (sip: URI); default: the SIM's EF_PSISMSC, else the built-in operator table (carrier.h)
 *   option sms_concat_prefix 1   "(1/2) " in front of the parts of a concatenated SMS
 *   option sms_delivery_reports 0  ask for delivery reports of outgoing SMS
 *   option sms_lost_policy ack   ack | rperror22: incoming SMS while no LAN device is registered
 * MMS (receiving only; a WAP Push in a binary SMS announces the message, it is fetched by HTTP over the IMS bearer):
 *   option mms            1      0 switches MMS reception off (the push is then logged and dropped)
 *   option mmsc           ""     URL the M-NotifyResp.ind / M-Acknowledge.ind are POSTed to; default: the built-in operator table (carrier.h, the SIM is
 *                                not consulted); for an unknown operator scheme://host:port/ of the notification's Content-Location
 *   option mms_uaprof     ""     URL sent as x-wap-profile header; default: none
 *   option mms_apn / mms_ip_type / mms_proxy (host[:port]) / mms_user_agent / mms_accept   ""   overrides of the operator's MMS data connection
 *                                (carrier.h): the on-demand bearer's APN and IP type, the HTTP proxy, the User-Agent / Accept headers of the requests
 *   option mms_bearer_linger 20  seconds the on-demand MMS bearer is kept after the last MMS work
 *   option mms_route_table 1007  routing table (and rule priority) of the MMS bearer's netdev
 *   option mms_max_size   1048576  largest message fetched, bytes (a bigger one is refused with M-NotifyResp.ind Rejected)
 *   option mms_dir        /tmp/imsd-mms        attachments (tmpfs) served by the web server at /imsd-mms/
 *   option mms_url_base   ""     URL prefix of the attachment links; default: http://<LAN address>/imsd-mms/
 *   option mms_keep_messages 50 / mms_keep_bytes 16777216 / mms_keep_days 7   retention of the attachments (days 0 = no age limit)
 *   option mms_text_split 1000   bytes of text per SIP MESSAGE; a longer text is sent in several, marked "(1/3) "
 *   option mms_proxy_port 8090   TCP port of the MMS proxy on the LAN address (0 = off), see mms/mmsproxy.h
 *   option mms_proxy_cache 600   seconds a message fetched through the proxy is kept for the other devices (0 = no cache)
 * Carbon copies:
 *   option carbons       1      0 switches the copies of sent SMS / MMS to the devices with +g.imsd.carbons off
 */
/* Message store (store/store.h): persistent, with per-device redelivery
 *   option store               1     0 switches the store off: nothing is kept, a message nobody takes is lost as before
 *   option store_dir           /srv/imsd   (flash!) created by the init script, mode 0700
 *   option lan_persist         1     0: the LAN registrar's bindings are not saved to <store_dir>/bindings (ua/regpersist.h); read at start
 *   option store_keep_messages 500   option store_keep_days 30   option store_keep_bytes 33554432   (oldest goes first)
 */
struct imsd_config {
	bool enabled;
	int log_level;
	char lan_ifname[32];
	int lan_sip_port;
	char lan_addr[64];		/* "" = first IPv4 address of lan_ifname */
	char user_agent[48];
	unsigned reg_min_expires, reg_max_expires, reg_default_expires;
	unsigned max_bindings;
	unsigned keepalive;		/* s, 0 = off */
	unsigned rtp_port_min, rtp_port_max;			/* LAN leg */
	unsigned carrier_rtp_port_min, carrier_rtp_port_max;	/* carrier leg */
	int opus_bitrate, opus_complexity;
	bool g722;
	char lan_codecs[64];		/* as configured (lower case, single spaces after validation) */
	enum codec_id lan_codec_pref[3];	/* parsed from lan_codecs, g722 removed when !g722 */
	int n_lan_codec_pref;
	/* calls */
	unsigned ring_timeout_s;	/* 0 = none */
	unsigned rtp_timeout_s;		/* 0 = off */
	unsigned session_expires;
	char phone_context[64];		/* "" = ISIM domain */
	char contact_params[160];	/* "" = default */
	char ims_user_agent[96];	/* "" = default, see config_ims_user_agent() */
	bool bench_incoming;
	/* backend (cs/csbackend.h) */
	char backend[8];		/* "auto" | "ims" | "cs" */
	char cs_pcm_device[32];		/* "" = auto */
	bool cs_early_media;
	unsigned cs_ring_timeout_s;	/* 0 = off */
	unsigned cs_short_ring_ms;
	bool cs_allow_roaming;
	unsigned cs_media_stall_ms;	/* 0 = off */
	unsigned cs_sms_incomplete_s;	/* incomplete concatenated CS SMS are deleted after this */
	unsigned ims_grace_s, backend_switch_delay_s, backend_ims_settle_s;
	/* SMS */
	char smsc[32];			/* "" = EF_SMSP of the USIM */
	char sms_psi[160];		/* "" = SIM (EF_PSISMSC), else the operator table */
	bool sms_concat_prefix, sms_delivery_reports;
	char sms_lost_policy[12];	/* "ack" | "rperror22" */
	/* MMS */
	bool mms;
	char mmsc[160];			/* "" = operator table, else derive from the Content-Location */
	/* the operator's MMS data connection, overrides of the built-in table (carrier.h), "" = the table's value */
	char mms_apn[64], mms_ip_type[16], mms_proxy[140], mms_user_agent[96], mms_accept[200];
	unsigned mms_bearer_linger_s;	/* the on-demand MMS bearer is kept this long after the last MMS work (default 20) */
	unsigned mms_route_table;	/* routing table + rule priority of the MMS bearer's netdev (default 1007) */
	char mms_uaprof[160];		/* "" = no x-wap-profile */
	unsigned mms_max_size;
	char mms_dir[96];
	char mms_url_base[160];		/* "" = http://<LAN address>/imsd-mms/ */
	unsigned mms_keep_messages, mms_keep_bytes, mms_keep_days;
	unsigned mms_text_split;
	unsigned mms_proxy_port, mms_proxy_cache;
	bool carbons;
	bool store;
	bool lan_persist;
	char store_dir[96];
	unsigned store_keep_messages, store_keep_days, store_keep_bytes;
	struct imsmodem_cfg modem;
	struct reg_cfg reg;
};

void config_defaults(struct imsd_config *c);
/* The User-Agent toward the network: ims_user_agent, or the default "TTA-VoLTE/3.0 imsd/<version> Device_Type/Android_Phone OMD" (version = IMSD_VERSION without the "-rN" suffix). */
void config_ims_user_agent(const struct imsd_config *c, char *out, size_t n);
/* Check and normalise. 0 ok; -1 with a message in err (the caller keeps its old configuration) */
/* true when a LAN socket / registrar relevant option differs (reload then restarts the LAN side) */
bool config_lan_changed(const struct imsd_config *a, const struct imsd_config *b);
int config_validate(struct imsd_config *c, char *err, size_t n);
/* read /etc/config/imsd (or another uci dir); the previous contents of c are replaced. 0 / -1 */
int config_load_uci(struct imsd_config *c, const char *confdir, char *err, size_t n);
#endif
