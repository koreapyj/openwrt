/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "sdp_neg.h"

const char *sdpn_codec_name(enum sdpn_codec c)
{
	switch (c) {
	case SDPN_C_AMRWB: return "AMR-WB";
	case SDPN_C_AMRNB: return "AMR";
	case SDPN_C_OPUS: return "opus";
	case SDPN_C_G722: return "G722";
	case SDPN_C_PCMA: return "PCMA";
	default: return "none";
	}
}

uint32_t sdpn_codec_rtp_clock(enum sdpn_codec c)
{
	switch (c) {
	case SDPN_C_AMRWB: return 16000;
	case SDPN_C_OPUS: return 48000;
	case SDPN_C_AMRNB:
	case SDPN_C_G722:
	case SDPN_C_PCMA: return 8000;
	default: return 0;
	}
}

uint32_t sdpn_codec_audio_rate(enum sdpn_codec c)
{
	return c == SDPN_C_G722 ? 16000 : sdpn_codec_rtp_clock(c);
}

const char *sdpn_strerror(int err)
{
	switch (err) {
	case SDPN_OK: return "ok";
	case SDPN_E_ARG: return "bad argument";
	case SDPN_E_NOMEDIA: return "no usable audio media";
	case SDPN_E_NOCODEC: return "no common codec";
	case SDPN_E_NOADDR: return "no connection address";
	case SDPN_E_REJECTED: return "media rejected";
	case SDPN_E_BADANSWER: return "answer does not match the offer";
	case SDPN_E_BUILD: return "cannot build SDP";
	}
	return "unknown error";
}

int sdpn_sip_status(int err)
{
	switch (err) {
	case SDPN_E_NOMEDIA:
	case SDPN_E_NOCODEC:
	case SDPN_E_NOADDR:
	case SDPN_E_REJECTED:
	case SDPN_E_BADANSWER:
		return 488;
	default:
		return 500;
	}
}

/* ------------------------------------------------------------------ */
/* mode-set                                                           */
/* ------------------------------------------------------------------ */

int sdpn_parse_mode_set(const char *s, unsigned max_mode, uint32_t *mask)
{
	uint32_t m = 0;

	if (!s || !*s)
		return -1;
	for (;;) {
		unsigned v = 0, nd = 0;

		while (*s == ' ')
			s++;
		while (*s >= '0' && *s <= '9') {
			v = v * 10 + (unsigned)(*s - '0');
			if (++nd > 2)
				return -1;
			s++;
		}
		while (*s == ' ')
			s++;
		if (!nd || v > max_mode || v > 31)
			return -1;
		m |= 1u << v;
		if (!*s)
			break;
		if (*s != ',')
			return -1;
		s++;
	}
	*mask = m;
	return 0;
}

int sdpn_format_mode_set(uint32_t mask, char *out, size_t outsz)
{
	size_t n = 0;
	unsigned i;

	if (outsz == 0)
		return -1;
	out[0] = 0;
	for (i = 0; i < 32; i++) {
		int k;

		if (!(mask & (1u << i)))
			continue;
		k = snprintf(out + n, outsz - n, "%s%u", n ? "," : "", i);
		if (k < 0 || (size_t)k >= outsz - n)
			return -1;
		n += (size_t)k;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* format classification                                              */
/* ------------------------------------------------------------------ */

struct cpar {
	bool oa, oa_present;
	uint32_t mode_set;
	int opus_rate;
	bool opus_stereo, opus_fec;
};

static enum sdpn_codec fmt_codec(const struct sdp *s, const struct sdp_fmt *f)
{
	const char *e = sdp_fmt_enc(s, f);
	int ch = f->channels ? f->channels : 1;

	if (!*e)
		return SDPN_C_NONE;
	if (!strcasecmp(e, "AMR-WB") && f->clock == 16000 && ch == 1)
		return SDPN_C_AMRWB;
	if (!strcasecmp(e, "AMR") && f->clock == 8000 && ch == 1)
		return SDPN_C_AMRNB;
	if (!strcasecmp(e, "opus") && f->clock == 48000 && (ch == 1 || ch == 2))
		return SDPN_C_OPUS;
	if (!strcasecmp(e, "G722") && f->clock == 8000 && ch == 1)
		return SDPN_C_G722;
	if (!strcasecmp(e, "PCMA") && f->clock == 8000 && ch == 1)
		return SDPN_C_PCMA;
	return SDPN_C_NONE;
}

static bool fmt_is_te(const struct sdp *s, const struct sdp_fmt *f)
{
	return !strcasecmp(sdp_fmt_enc(s, f), "telephone-event") && f->clock > 0;
}

/* 0, or -1 if this format cannot be used by us as described */
static int params_parse(const struct sdp *s, const struct sdp_fmt *f, enum sdpn_codec c, struct cpar *p)
{
	const char *fp = sdp_fmt_fmtp(s, f);
	char t[64];
	long v;
	int r;

	memset(p, 0, sizeof(*p));
	p->opus_rate = 48000;
	switch (c) {
	case SDPN_C_AMRWB:
	case SDPN_C_AMRNB:
		r = sdp_fmtp_get(fp, "octet-align", t, sizeof(t));
		if (r == -2)
			return -1;
		if (r == 0) {
			if (!strcmp(t, "1"))
				p->oa = true;
			else if (strcmp(t, "0"))
				return -1;
			p->oa_present = true;
		}
		r = sdp_fmtp_get(fp, "crc", t, sizeof(t));
		if (r == -2 || (r == 0 && strcmp(t, "0")))
			return -1;
		r = sdp_fmtp_get(fp, "robust-sorting", t, sizeof(t));
		if (r == -2 || (r == 0 && strcmp(t, "0")))
			return -1;
		r = sdp_fmtp_get(fp, "interleaving", t, sizeof(t));
		if (r != -1)
			return -1;
		r = sdp_fmtp_get(fp, "mode-set", t, sizeof(t));
		if (r == -2)
			return -1;
		if (r == 0 && sdpn_parse_mode_set(t, c == SDPN_C_AMRWB ? 8 : 7, &p->mode_set) < 0)
			return -1;
		break;
	case SDPN_C_OPUS:
		if (sdp_fmtp_get_int(fp, "maxplaybackrate", &v) == 0 && v >= 8000 && v <= 48000)
			p->opus_rate = (int)v;
		if (sdp_fmtp_get(fp, "stereo", t, sizeof(t)) == 0)
			p->opus_stereo = !strcmp(t, "1");
		if (sdp_fmtp_get(fp, "useinbandfec", t, sizeof(t)) == 0)
			p->opus_fec = !strcmp(t, "1");
		break;
	default:
		break;
	}
	return 0;
}

static const struct sdp_media *first_audio(const struct sdp *s, int *idx, bool need_port)
{
	int i;

	for (i = 0; i < s->nmedia; i++) {
		const struct sdp_media *m = &s->media[i];
		const char *proto = sdp_media_proto(s, m);

		if (strcmp(sdp_media_type(s, m), "audio") || !m->rtp)
			continue;
		if (strcmp(proto, "RTP/AVP") && strcmp(proto, "RTP/AVPF"))
			continue;
		if (need_port && m->port == 0)
			continue;
		if (m->nfmt == 0)
			continue;
		*idx = i;
		return m;
	}
	return NULL;
}

static bool in_pref(const enum sdpn_codec *pref, int npref, enum sdpn_codec c)
{
	int i;

	for (i = 0; i < npref; i++)
		if (pref[i] == c)
			return true;
	return false;
}

/* pick the format to answer with: by our preference, or (honour) by the offerer's order */
static int select_codec(const struct sdp *s, const struct sdp_media *m, const enum sdpn_codec *pref, int npref,
			bool honour, struct cpar *par)
{
	int i, k;

	if (honour) {
		for (i = 0; i < m->nfmt; i++) {
			enum sdpn_codec c = fmt_codec(s, &m->fmt[i]);

			if (c != SDPN_C_NONE && in_pref(pref, npref, c) && params_parse(s, &m->fmt[i], c, par) == 0)
				return i;
		}
		return -1;
	}
	for (k = 0; k < npref; k++)
		for (i = 0; i < m->nfmt; i++)
			if (fmt_codec(s, &m->fmt[i]) == pref[k] &&
			    params_parse(s, &m->fmt[i], pref[k], par) == 0)
				return i;
	return -1;
}

/* telephone-event: exact clock, else 8000, else the first one */
static int select_te(const struct sdp *s, const struct sdp_media *m, uint32_t want)
{
	int i, any = -1, c8 = -1;

	for (i = 0; i < m->nfmt; i++) {
		if (!fmt_is_te(s, &m->fmt[i]))
			continue;
		if (m->fmt[i].clock == want)
			return i;
		if (m->fmt[i].clock == 8000 && c8 < 0)
			c8 = i;
		if (any < 0)
			any = i;
	}
	return c8 >= 0 ? c8 : any;
}

enum sdp_dir sdpn_remote_dir(const struct sdp *s, const struct sdp_media *m, bool *legacy)
{
	enum sdp_dir d = sdp_media_dir(s, m);
	const struct sdp_conn *c = sdp_media_conn(s, m);
	bool lh = c && sdp_conn_is_any(c);

	if (legacy)
		*legacy = lh;
	if (lh)
		d = sdp_dir_make(sdp_dir_sends(d), false);
	return d;
}

bool sdpn_dir_is_hold(enum sdp_dir remote_dir)
{
	return !sdp_dir_recvs(remote_dir);
}

enum sdp_dir sdpn_forward_dir(enum sdp_dir remote_dir)
{
	return remote_dir == SDP_DIR_NONE ? SDP_DIR_SENDRECV : remote_dir;
}

enum sdp_dir sdpn_answer_dir(enum sdp_dir offered, enum sdp_dir ours_max)
{
	/* we may send if the offerer receives, and receive if the offerer sends */
	return sdp_dir_make(sdp_dir_recvs(offered) && sdp_dir_sends(ours_max),
			    sdp_dir_sends(offered) && sdp_dir_recvs(ours_max));
}

void sdpn_apply_dir(struct sdp *s, struct sdp_media *m, enum sdp_dir d, bool legacy)
{
	sdp_media_set_dir(m, d);
	if (legacy) {
		const struct sdp_conn *c = m->conn.present ? &m->conn : (s->conn.present ? &s->conn : NULL);
		bool v6 = c && addr_family(&c->addr) == AF_INET6;

		sdp_set_conn_any(&m->conn, v6);
	}
}

/* ------------------------------------------------------------------ */
/* shared pieces of answers                                           */
/* ------------------------------------------------------------------ */

static int fill_remote(const struct sdp *s, const struct sdp_media *m, struct sdpn_media *n)
{
	const struct sdp_conn *c = sdp_media_conn(s, m);

	if (!c)
		return SDPN_E_NOADDR;
	n->remote = c->addr;
	addr_set_port(&n->remote, m->port);
	if (m->rtcp_port) {
		n->remote_rtcp = m->has_rtcp_addr ? m->rtcp_addr : c->addr;
		addr_set_port(&n->remote_rtcp, (uint16_t)m->rtcp_port);
	} else {
		n->remote_rtcp = c->addr;
		addr_set_port(&n->remote_rtcp, (uint16_t)(m->port + 1));
	}
	return 0;
}

/* session header + one section per offered section (all rejected except idx, returned in *mp) */
static int answer_skeleton(struct sdp *ans, const struct sdp *offer, int idx, const struct sdp_origin *org,
			   const struct addr *rtp, const char *sname, struct sdp_media **mp)
{
	int i, j;

	sdp_init(ans);
	if (sdp_set_origin(ans, org->user, org->sess_id, org->version, rtp) < 0 || sdp_set_name(ans, sname) < 0)
		return SDPN_E_BUILD;
	sdp_set_conn(&ans->conn, rtp);
	for (i = 0; i < offer->nmedia; i++) {
		const struct sdp_media *om = &offer->media[i];
		struct sdp_media *m = sdp_add_media(ans, sdp_media_type(offer, om), i == idx ? addr_port(rtp) : 0,
						    sdp_media_proto(offer, om));

		if (!m)
			return SDPN_E_BUILD;
		if (i == idx) {
			*mp = m;
		} else if (om->rtp) {
			for (j = 0; j < om->nfmt; j++)
				if (sdp_add_fmt(ans, m, om->fmt[j].pt, NULL, 0, 0, NULL) < 0)
					return SDPN_E_BUILD;
		} else if (sdp_media_set_raw_fmts(ans, m, sdp_get(offer, om->raw_fmts)) < 0) {
			return SDPN_E_BUILD;
		}
	}
	return 0;
}

static int check_args(const struct sdp *offer, const struct sdp_origin *org, const struct addr *rtp,
		      struct sdp *answer)
{
	return (!offer || !org || !rtp || !answer || addr_port(rtp) == 0) ? SDPN_E_ARG : 0;
}

/* ------------------------------------------------------------------ */
/* carrier leg                                                        */
/* ------------------------------------------------------------------ */

void sdpn_carrier_cfg_default(struct sdpn_carrier_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->pt_amrwb_be = 104;
	c->pt_amrwb_oa = 100;
	c->pt_amrnb_be = 102;
	c->pt_amrnb_oa = 96;
	c->pt_dtmf16 = 107;
	c->pt_dtmf8 = 101;
	c->offer_amrwb = c->offer_amrnb = true;
	c->offer_be = c->offer_oa = true;
	c->bw_as = 49;
	c->bw_rs = 600;
	c->bw_rr = 2000;
	c->ptime = 20;
	c->maxptime = 240;
	c->session_name = "QC VOIP";
}

static void carrier_pref(const struct sdpn_carrier_cfg *cfg, enum sdpn_codec out[4], int *n)
{
	if (cfg->npref > 0 && cfg->npref <= 4) {
		memcpy(out, cfg->pref, sizeof(out[0]) * (size_t)cfg->npref);
		*n = cfg->npref;
	} else {
		out[0] = SDPN_C_AMRWB;
		out[1] = SDPN_C_AMRNB;
		*n = 2;
	}
}

static bool pts_distinct(const int *pt, int n)
{
	int i, j;

	for (i = 0; i < n; i++) {
		if (pt[i] < 0 || pt[i] > 127)
			return false;
		for (j = i + 1; j < n; j++)
			if (pt[i] == pt[j])
				return false;
	}
	return true;
}

static void set_bw(struct sdp_bw *bw, int as, int rs, int rr)
{
	bw->as = as >= 0 ? as : -1;
	bw->rs = rs >= 0 ? rs : -1;
	bw->rr = rr >= 0 ? rr : -1;
}

static int amr_fmtp(char *out, size_t n, const struct cpar *p)
{
	char ms[80];
	int k;

	if (sdpn_format_mode_set(p->mode_set, ms, sizeof(ms)) < 0)
		return -1;
	k = snprintf(out, n, "%s%s;max-red=0%s%s", p->oa_present ? (p->oa ? "octet-align=1;" : "octet-align=0;") : "",
		     "mode-change-capability=2", p->mode_set ? ";mode-set=" : "", ms);
	return (k < 0 || (size_t)k >= n) ? -1 : 0;
}

int sdpn_carrier_offer(const struct sdpn_carrier_cfg *cfg, const struct sdp_origin *org, const struct addr *rtp,
		       struct sdp *out)
{
	static const char *const cc = "mode-change-capability=2;max-red=0";
	struct sdp_media *m;
	char fp[96];
	int pts[6], np = 0, r = 0;

	if (!cfg || !org || !rtp || !out || addr_port(rtp) == 0)
		return SDPN_E_ARG;
	if (!(cfg->offer_amrwb || cfg->offer_amrnb) || !(cfg->offer_be || cfg->offer_oa))
		return SDPN_E_BUILD;
	if (cfg->offer_amrwb && cfg->offer_be)
		pts[np++] = cfg->pt_amrwb_be;
	if (cfg->offer_amrwb && cfg->offer_oa)
		pts[np++] = cfg->pt_amrwb_oa;
	if (cfg->offer_amrnb && cfg->offer_be)
		pts[np++] = cfg->pt_amrnb_be;
	if (cfg->offer_amrnb && cfg->offer_oa)
		pts[np++] = cfg->pt_amrnb_oa;
	if (cfg->offer_amrwb)
		pts[np++] = cfg->pt_dtmf16;
	pts[np++] = cfg->pt_dtmf8;
	if (!pts_distinct(pts, np))
		return SDPN_E_BUILD;

	sdp_init(out);
	if (sdp_set_origin(out, org->user, org->sess_id, org->version, rtp) < 0 ||
	    sdp_set_name(out, cfg->session_name ? cfg->session_name : "QC VOIP") < 0)
		return SDPN_E_BUILD;
	sdp_set_conn(&out->conn, rtp);
	m = sdp_add_media(out, "audio", addr_port(rtp), "RTP/AVP");
	if (!m)
		return SDPN_E_BUILD;
	set_bw(&m->bw, cfg->bw_as, cfg->bw_rs, cfg->bw_rr);

	snprintf(fp, sizeof(fp), "octet-align=1;%s", cc);
	if (cfg->offer_amrwb && cfg->offer_be)
		r |= sdp_add_fmt(out, m, cfg->pt_amrwb_be, "AMR-WB", 16000, 1, cc);
	if (cfg->offer_amrwb && cfg->offer_oa)
		r |= sdp_add_fmt(out, m, cfg->pt_amrwb_oa, "AMR-WB", 16000, 1, fp);
	if (cfg->offer_amrnb && cfg->offer_be)
		r |= sdp_add_fmt(out, m, cfg->pt_amrnb_be, "AMR", 8000, 1, cc);
	if (cfg->offer_amrnb && cfg->offer_oa)
		r |= sdp_add_fmt(out, m, cfg->pt_amrnb_oa, "AMR", 8000, 1, fp);
	if (cfg->offer_amrwb)
		r |= sdp_add_fmt(out, m, cfg->pt_dtmf16, "telephone-event", 16000, 1, "0-15");
	r |= sdp_add_fmt(out, m, cfg->pt_dtmf8, "telephone-event", 8000, 1, "0-15");
	m->ptime = cfg->ptime;
	m->maxptime = cfg->maxptime;
	sdp_media_set_dir(m, SDP_DIR_SENDRECV);
	return r < 0 ? SDPN_E_BUILD : 0;
}

/* shared tail of the two answer functions: build the section and fill *neg */
struct answer_ctx {
	const struct sdp *offer;
	const struct sdp_media *om;
	int idx;
	const struct addr *rtp;
	const struct sdp_origin *org;
	const char *sname;
	int bw_as, bw_rs, bw_rr;
	int ptime, maxptime;
	enum sdpn_codec codec;
	const struct sdp_fmt *cf;	/* chosen codec format in the offer */
	const struct cpar *par;
	const char *codec_enc;
	int codec_ch;
	const char *codec_fmtp;
};

static int finish_answer(const struct answer_ctx *x, struct sdp *ans, struct sdpn_media *neg)
{
	struct sdp_media *m = NULL;
	struct sdpn_media tmp;
	const struct sdp_media *om = x->om;
	int ti, r;
	bool legacy;
	enum sdp_dir od = sdpn_remote_dir(x->offer, om, &legacy);

	if (!neg)
		neg = &tmp;
	memset(neg, 0, sizeof(*neg));
	r = fill_remote(x->offer, om, neg);
	if (r < 0)
		return r;
	r = answer_skeleton(ans, x->offer, x->idx, x->org, x->rtp, x->sname, &m);
	if (r < 0)
		return r;
	if (sdp_add_fmt(ans, m, x->cf->pt, x->codec_enc, sdpn_codec_rtp_clock(x->codec), x->codec_ch, x->codec_fmtp) < 0)
		return SDPN_E_BUILD;
	ti = select_te(x->offer, om, sdpn_codec_rtp_clock(x->codec));
	neg->dtmf_pt = neg->dtmf_pt_recv = -1;
	if (ti >= 0) {
		const struct sdp_fmt *tf = &om->fmt[ti];
		const char *ev = sdp_fmt_fmtp(x->offer, tf);

		if (sdp_add_fmt(ans, m, tf->pt, "telephone-event", tf->clock, 1, *ev ? ev : NULL) < 0)
			return SDPN_E_BUILD;
		neg->dtmf_pt = neg->dtmf_pt_recv = tf->pt;
		neg->dtmf_clock = tf->clock;
	}
	set_bw(&m->bw, x->bw_as, x->bw_rs, x->bw_rr);
	m->ptime = om->ptime ? om->ptime : x->ptime;
	m->maxptime = x->maxptime;
	if (om->maxptime && om->maxptime < m->maxptime)
		m->maxptime = om->maxptime;
	neg->dir = sdpn_answer_dir(od, SDP_DIR_SENDRECV);
	sdp_media_set_dir(m, neg->dir);

	neg->valid = true;
	neg->media_index = x->idx;
	neg->codec = x->codec;
	neg->pt_send = neg->pt_recv = x->cf->pt;
	neg->clock = sdpn_codec_rtp_clock(x->codec);
	neg->audio_rate = sdpn_codec_audio_rate(x->codec);
	neg->octet_align = x->par->oa;
	neg->mode_set = x->par->mode_set;
	neg->ptime = m->ptime;
	neg->maxptime = m->maxptime;
	neg->bw_as = m->bw.as;
	neg->opus_maxplaybackrate = x->par->opus_rate;
	neg->opus_stereo = x->par->opus_stereo;
	neg->opus_fec = x->par->opus_fec;
	neg->legacy_hold = legacy;
	return 0;
}

int sdpn_carrier_answer(const struct sdpn_carrier_cfg *cfg, const struct sdp *offer, const struct sdp_origin *org,
			const struct addr *rtp, struct sdp *answer, struct sdpn_media *neg)
{
	enum sdpn_codec pref[4];
	int npref, fi, idx = 0;
	const struct sdp_media *om;
	struct cpar par;
	char fp[160];
	struct answer_ctx x;

	if (!cfg || check_args(offer, org, rtp, answer))
		return SDPN_E_ARG;
	om = first_audio(offer, &idx, true);
	if (!om)
		return SDPN_E_NOMEDIA;
	carrier_pref(cfg, pref, &npref);
	fi = select_codec(offer, om, pref, npref, false, &par);
	if (fi < 0)
		return SDPN_E_NOCODEC;
	if (amr_fmtp(fp, sizeof(fp), &par) < 0)
		return SDPN_E_BUILD;
	memset(&x, 0, sizeof(x));
	x.offer = offer;
	x.om = om;
	x.idx = idx;
	x.rtp = rtp;
	x.org = org;
	x.sname = cfg->session_name ? cfg->session_name : "QC VOIP";
	x.bw_as = cfg->bw_as;
	x.bw_rs = cfg->bw_rs;
	x.bw_rr = cfg->bw_rr;
	x.ptime = cfg->ptime;
	x.maxptime = cfg->maxptime;
	x.cf = &om->fmt[fi];
	x.codec = fmt_codec(offer, x.cf);
	x.par = &par;
	x.codec_enc = sdpn_codec_name(x.codec);
	x.codec_ch = 1;
	x.codec_fmtp = fp;
	return finish_answer(&x, answer, neg);
}

/* ------------------------------------------------------------------ */
/* client leg                                                         */
/* ------------------------------------------------------------------ */

void sdpn_lan_cfg_default(struct sdpn_lan_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->carrier_wideband = true;
	c->pt_opus = 111;
	c->pt_g722 = 9;
	c->pt_pcma = 8;
	c->pt_dtmf8 = 101;
	c->pt_dtmf48 = 102;
	c->dtmf48 = true;
	c->ptime = 20;
	c->session_name = "imsd";
}

static void lan_pref(const struct sdpn_lan_cfg *cfg, enum sdpn_codec out[4], int *n)
{
	if (cfg->npref > 0 && cfg->npref <= 4) {
		memcpy(out, cfg->pref, sizeof(out[0]) * (size_t)cfg->npref);
		*n = cfg->npref;
		return;
	}
	if (cfg->carrier_wideband) {
		out[0] = SDPN_C_OPUS;
		out[1] = SDPN_C_G722;
		out[2] = SDPN_C_PCMA;
	} else {
		out[0] = SDPN_C_PCMA;
		out[1] = SDPN_C_OPUS;
		out[2] = SDPN_C_G722;
	}
	*n = 3;
}

static int lan_opus_rate(const struct sdpn_lan_cfg *cfg)
{
	return cfg->opus_rate ? cfg->opus_rate : (cfg->carrier_wideband ? 16000 : 8000);
}

static int opus_fmtp(char *out, size_t n, int rate)
{
	int k = snprintf(out, n, "maxplaybackrate=%d;sprop-maxcapturerate=%d;stereo=0;useinbandfec=0", rate, rate);

	return (k < 0 || (size_t)k >= n) ? -1 : 0;
}

int sdpn_lan_offer(const struct sdpn_lan_cfg *cfg, const struct sdp_origin *org, const struct addr *rtp,
		   struct sdp *out)
{
	enum sdpn_codec pref[4];
	int npref, i, r = 0, pts[6], np = 0;
	struct sdp_media *m;
	char fp[128];
	bool opus = false;

	if (!cfg || !org || !rtp || !out || addr_port(rtp) == 0)
		return SDPN_E_ARG;
	lan_pref(cfg, pref, &npref);
	for (i = 0; i < npref; i++) {
		if (pref[i] == SDPN_C_OPUS) {
			opus = true;
			pts[np++] = cfg->pt_opus;
		} else if (pref[i] == SDPN_C_G722) {
			pts[np++] = cfg->pt_g722;
		} else if (pref[i] == SDPN_C_PCMA) {
			pts[np++] = cfg->pt_pcma;
		} else {
			return SDPN_E_BUILD;	/* AMR is not offered to LAN phones */
		}
	}
	pts[np++] = cfg->pt_dtmf8;
	if (opus && cfg->dtmf48)
		pts[np++] = cfg->pt_dtmf48;
	if (np == 0 || !pts_distinct(pts, np))
		return SDPN_E_BUILD;

	sdp_init(out);
	if (sdp_set_origin(out, org->user, org->sess_id, org->version, rtp) < 0 ||
	    sdp_set_name(out, cfg->session_name ? cfg->session_name : "imsd") < 0)
		return SDPN_E_BUILD;
	sdp_set_conn(&out->conn, rtp);
	m = sdp_add_media(out, "audio", addr_port(rtp), "RTP/AVP");
	if (!m)
		return SDPN_E_BUILD;
	for (i = 0; i < npref; i++) {
		switch (pref[i]) {
		case SDPN_C_OPUS:
			if (opus_fmtp(fp, sizeof(fp), lan_opus_rate(cfg)) < 0)
				return SDPN_E_BUILD;
			r |= sdp_add_fmt(out, m, cfg->pt_opus, "opus", 48000, 2, fp);
			break;
		case SDPN_C_G722:
			r |= sdp_add_fmt(out, m, cfg->pt_g722, "G722", 8000, 1, NULL);
			break;
		default:
			r |= sdp_add_fmt(out, m, cfg->pt_pcma, "PCMA", 8000, 1, NULL);
		}
	}
	r |= sdp_add_fmt(out, m, cfg->pt_dtmf8, "telephone-event", 8000, 1, "0-15");
	if (opus && cfg->dtmf48)
		r |= sdp_add_fmt(out, m, cfg->pt_dtmf48, "telephone-event", 48000, 1, "0-15");
	m->ptime = cfg->ptime;
	sdp_media_set_dir(m, SDP_DIR_SENDRECV);
	return r < 0 ? SDPN_E_BUILD : 0;
}

int sdpn_lan_answer(const struct sdpn_lan_cfg *cfg, const struct sdp *offer, const struct sdp_origin *org,
		    const struct addr *rtp, struct sdp *answer, struct sdpn_media *neg)
{
	enum sdpn_codec pref[4];
	int npref, fi, idx = 0;
	const struct sdp_media *om;
	struct cpar par;
	char fp[128];
	struct answer_ctx x;

	if (!cfg || check_args(offer, org, rtp, answer))
		return SDPN_E_ARG;
	om = first_audio(offer, &idx, true);
	if (!om)
		return SDPN_E_NOMEDIA;
	lan_pref(cfg, pref, &npref);
	fi = select_codec(offer, om, pref, npref, cfg->honour_client_order, &par);
	if (fi < 0)
		return SDPN_E_NOCODEC;
	memset(&x, 0, sizeof(x));
	x.cf = &om->fmt[fi];
	x.codec = fmt_codec(offer, x.cf);
	x.codec_ch = x.codec == SDPN_C_OPUS ? 2 : 1;
	if (x.codec == SDPN_C_OPUS) {
		if (opus_fmtp(fp, sizeof(fp), lan_opus_rate(cfg)) < 0)
			return SDPN_E_BUILD;
		x.codec_fmtp = fp;
	}
	x.offer = offer;
	x.om = om;
	x.idx = idx;
	x.rtp = rtp;
	x.org = org;
	x.sname = cfg->session_name ? cfg->session_name : "imsd";
	x.bw_as = x.bw_rs = x.bw_rr = -1;
	x.ptime = cfg->ptime;
	x.maxptime = 0;
	x.par = &par;
	x.codec_enc = sdpn_codec_name(x.codec);
	return finish_answer(&x, answer, neg);
}

/* ------------------------------------------------------------------ */
/* interpreting an answer                                             */
/* ------------------------------------------------------------------ */

int sdpn_from_answer(const struct sdp *offer, const struct sdp *answer, struct sdpn_media *out)
{
	const struct sdp_media *om, *am;
	const struct sdp_fmt *of = NULL, *af = NULL;
	struct cpar par;
	enum sdpn_codec codec = SDPN_C_NONE;
	int idx = 0, i, j, r;
	bool legacy;
	enum sdp_dir od, ad;

	if (!offer || !answer || !out)
		return SDPN_E_ARG;
	memset(out, 0, sizeof(*out));
	out->dtmf_pt = out->dtmf_pt_recv = -1;
	om = first_audio(offer, &idx, false);
	if (!om)
		return SDPN_E_NOMEDIA;
	if (idx >= answer->nmedia)
		return SDPN_E_BADANSWER;
	am = &answer->media[idx];
	if (strcmp(sdp_media_type(answer, am), "audio") || !am->rtp)
		return SDPN_E_BADANSWER;
	if (am->port == 0)
		return SDPN_E_REJECTED;

	/* pass 1: the first answered format that we offered under that PT */
	for (i = 0; i < am->nfmt && !af; i++) {
		const struct sdp_fmt *a = &am->fmt[i], *o;
		enum sdpn_codec oc, ac;

		if (fmt_is_te(answer, a))
			continue;
		o = sdp_media_find_fmt(om, a->pt);
		oc = o ? fmt_codec(offer, o) : SDPN_C_NONE;
		if (oc == SDPN_C_NONE)
			continue;
		ac = fmt_codec(answer, a);
		if (a->has_rtpmap && ac != oc)
			continue;
		if (params_parse(answer, a, oc, &par) < 0)
			continue;
		af = a;
		of = o;
		codec = oc;
	}
	/* pass 2: same encoding under a different PT */
	for (i = 0; i < am->nfmt && !af; i++) {
		const struct sdp_fmt *a = &am->fmt[i];
		enum sdpn_codec ac = fmt_codec(answer, a);
		const struct sdp_fmt *best = NULL;

		if (ac == SDPN_C_NONE || params_parse(answer, a, ac, &par) < 0)
			continue;
		for (j = 0; j < om->nfmt; j++) {
			const struct sdp_fmt *o = &om->fmt[j];
			struct cpar op;

			if (fmt_codec(offer, o) != ac || params_parse(offer, o, ac, &op) < 0)
				continue;
			if (op.oa == par.oa) {
				best = o;
				break;
			}
			if (!best)
				best = o;
		}
		if (best) {
			af = a;
			of = best;
			codec = ac;
		}
	}
	if (!af)
		return SDPN_E_BADANSWER;

	r = fill_remote(answer, am, out);
	if (r < 0)
		return r;
	out->valid = true;
	out->media_index = idx;
	out->codec = codec;
	out->pt_send = af->pt;
	out->pt_recv = of->pt;
	out->clock = sdpn_codec_rtp_clock(codec);
	out->audio_rate = sdpn_codec_audio_rate(codec);
	out->octet_align = par.oa;
	out->mode_set = par.mode_set;
	out->opus_maxplaybackrate = par.opus_rate;
	out->opus_stereo = par.opus_stereo;
	out->opus_fec = par.opus_fec;
	out->ptime = am->ptime ? am->ptime : om->ptime;
	out->maxptime = am->maxptime;
	out->bw_as = am->bw.as >= 0 ? am->bw.as : answer->bw.as;

	/* telephone-event: first answered one that we offered (same PT, else same clock) */
	for (i = 0; i < am->nfmt && out->dtmf_pt < 0; i++) {
		const struct sdp_fmt *a = &am->fmt[i], *o;

		if (!fmt_is_te(answer, a))
			continue;
		o = sdp_media_find_fmt(om, a->pt);
		if (o && fmt_is_te(offer, o) && o->clock == a->clock) {
			out->dtmf_pt = a->pt;
			out->dtmf_pt_recv = o->pt;
			out->dtmf_clock = a->clock;
			break;
		}
		for (j = 0; j < om->nfmt; j++) {
			if (fmt_is_te(offer, &om->fmt[j]) && om->fmt[j].clock == a->clock) {
				out->dtmf_pt = a->pt;
				out->dtmf_pt_recv = om->fmt[j].pt;
				out->dtmf_clock = a->clock;
				break;
			}
		}
	}

	od = sdp_media_dir(offer, om);
	ad = sdpn_remote_dir(answer, am, &legacy);
	out->legacy_hold = legacy;
	out->dir = sdp_dir_make(sdp_dir_sends(od) && sdp_dir_recvs(ad), sdp_dir_recvs(od) && sdp_dir_sends(ad));
	return 0;
}
