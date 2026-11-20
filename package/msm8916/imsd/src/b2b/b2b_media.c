/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Bridge glue: the two negotiated legs -> bridge configuration, updates, events, listing. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "b2b_int.h"

enum br_dir b2b_br_dir(enum sdp_dir d)
{
	switch (d) {
	case SDP_DIR_SENDONLY: return BR_SENDONLY;
	case SDP_DIR_RECVONLY: return BR_RECVONLY;
	case SDP_DIR_INACTIVE: return BR_INACTIVE;
	default: return BR_SENDRECV;
	}
}

static enum codec_id to_codec(enum sdpn_codec c)
{
	switch (c) {
	case SDPN_C_AMRWB: return CODEC_AMRWB;
	case SDPN_C_AMRNB: return CODEC_AMRNB;
	case SDPN_C_OPUS: return CODEC_OPUS;
	case SDPN_C_G722: return CODEC_G722;
	default: return CODEC_PCMA;
	}
}

bool b2b_media_same(const struct sdpn_media *a, const struct sdpn_media *b)
{
	return a->codec == b->codec && a->pt_send == b->pt_send && a->pt_recv == b->pt_recv &&
	       a->octet_align == b->octet_align && a->mode_set == b->mode_set && a->dtmf_pt == b->dtmf_pt &&
	       a->dtmf_clock == b->dtmf_clock && a->clock == b->clock;
}

static bool usable_remote(const struct sdpn_media *m)
{
	return addr_port(&m->remote) && !m->legacy_hold;
}

static void carrier_cfg(const struct b2b_call *c, struct br_leg_cfg *cfg)
{
	const struct sdpn_media *m = &c->cm;
	const struct imsd_config *g = b2b_cfg();

	br_leg_cfg_default(cfg);
	cfg->kind = BR_LEG_UDP;
	cfg->dir = c->cdir;
	cfg->fd = c->cfd;
	cfg->own_fd = true;
	cfg->remote = m->remote;
	cfg->has_remote = usable_remote(m);
	cfg->learn = false;			/* the carrier leg only talks to the address it negotiated */
	cfg->codec = to_codec(m->codec);
	cfg->cp.mode = -1;
	cfg->cp.modeset = (uint16_t)m->mode_set;
	cfg->amr_oa = m->octet_align;
	cfg->pt = (uint8_t)m->pt_send;
	cfg->te_pt = m->dtmf_pt;
	cfg->te_clock = m->dtmf_clock;
	cfg->keepalive = true;			/* send first and keep the conntrack entry of the IMS netdev alive */
	cfg->rx_timeout_ms = g->rtp_timeout_s * 1000u;
	if (m->pt_recv != m->pt_send)
		LOGW("call#%u: carrier uses payload type %d for sending and %d for receiving, the bridge handles %d", c->id,
		     m->pt_recv, m->pt_send, m->pt_send);
}

static void client_cfg(const struct b2b_call *c, struct br_leg_cfg *cfg)
{
	const struct sdpn_media *m = &c->lm;
	const struct imsd_config *g = b2b_cfg();

	br_leg_cfg_default(cfg);
	cfg->kind = BR_LEG_UDP;
	cfg->dir = c->ldir;
	cfg->fd = c->lfd;
	cfg->own_fd = true;
	cfg->remote = m->remote;
	cfg->has_remote = usable_remote(m);
	cfg->learn = true;			/* the phone may sit behind a NAT / change its port */
	cfg->codec = to_codec(m->codec);
	cfg->cp.bitrate = g->opus_bitrate;
	cfg->cp.complexity = g->opus_complexity;
	cfg->cp.pcm_rate = 0;
	cfg->pt = (uint8_t)m->pt_send;
	cfg->te_pt = m->dtmf_pt;
	cfg->te_clock = m->dtmf_clock == 48000 ? 0 : m->dtmf_clock;
}

int b2b_bridge_up(struct b2b_call *c)
{
	struct br_leg_cfg cc, lc;
	struct bridge *br;

	if (c->br)
		return 0;
	if ((!c->pcm && !c->cm_ok) || (!c->bench && !c->lm_ok))
		return -EINVAL;
	c->cdir = c->pcm ? BR_SENDRECV : b2b_br_dir(c->cm.dir);
	c->ldir = c->bench ? (c->bench_play_started ? BR_SENDRECV : BR_SENDONLY) : b2b_br_dir(c->lm.dir);
	br = bridge_create((void *)(uintptr_t)c->id);
	if (!br)
		return -ENOMEM;
	if (c->pcm) {
		/* the carrier leg is the modem's sound card: no socket, no SDP */
		cs_media_leg_cfg(&cc, b2b_cfg()->cs_pcm_device, b2b_cfg()->cs_media_stall_ms);
		cc.dir = c->cdir;
		if (B.ops.pcm_ops)
			cc.pdev_ops = B.ops.pcm_ops;
		if (bridge_set_leg(br, BR_CARRIER, &cc))
			goto fail;
	} else {
		carrier_cfg(c, &cc);
		if (bridge_set_leg(br, BR_CARRIER, &cc))
			goto fail;
		c->cfd_br = true;
	}
	if (c->bench) {
		if (b2b_bench_pcm_cfg(c, &lc) || bridge_set_leg(br, BR_CLIENT, &lc))
			goto fail;
	} else {
		client_cfg(c, &lc);
		if (bridge_set_leg(br, BR_CLIENT, &lc))
			goto fail;
		c->lfd_br = true;
	}
	if (bridge_start(br))
		goto fail;
	c->br = br;
	c->br_started = true;
	return 0;
fail:
	bridge_destroy(br);
	return -EIO;
}

void b2b_bridge_destroy(struct b2b_call *c)
{
	if (!c->br)
		return;
	bridge_destroy(c->br);
	c->br = NULL;
	if (c->cfd_br)
		c->cfd = -1;
	if (c->lfd_br)
		c->lfd = -1;
}

void b2b_close_socks(struct b2b_call *c)
{
	if (c->cfd >= 0 && !c->cfd_br)
		close(c->cfd);
	if (c->lfd >= 0 && !c->lfd_br)
		close(c->lfd);
	c->cfd = c->lfd = -1;
}

static void hold_note(struct b2b_call *c, bool *flag, bool now)
{
	if (*flag == now)
		return;
	*flag = now;
	b2b_notify(c, now ? "hold" : "resume", 0, flag == &c->hold_c ? "network" : "client");
}

void b2b_carrier_media(struct b2b_call *c, const struct sdpn_media *m)
{
	struct sdpn_media old = c->cm;
	bool had = c->cm_ok;
	struct br_leg_cfg cc;

	c->cm = *m;
	c->cm_ok = true;
	if (!c->br) {
		if (c->bench || c->lm_ok)
			b2b_bridge_up(c);
		return;
	}
	if (!had)
		return;
	c->cdir = b2b_br_dir(m->dir);
	if (!b2b_media_same(&old, m)) {
		/* another codec / payload type / AMR mode set: the carrier leg restarts, the client leg is only
		 * re-created inside the bridge when its decoder depends on the carrier rate (Opus follows its peer) */
		LOGI("call#%u: carrier media changed codec/parameters (%s -> %s), restarting the bridge", c->id,
		     sdpn_codec_name(old.codec), sdpn_codec_name(m->codec));
		carrier_cfg(c, &cc);
		bridge_stop(c->br);
		bridge_set_leg(c->br, BR_CARRIER, &cc);
		bridge_start(c->br);
	} else {
		if (usable_remote(m) && !addr_equal(&old.remote, &m->remote))
			bridge_set_remote(c->br, BR_CARRIER, &m->remote);
		if (old.dir != m->dir || old.legacy_hold != m->legacy_hold)
			bridge_set_dir(c->br, BR_CARRIER, c->cdir);
	}
	hold_note(c, &c->hold_c, m->dir == SDP_DIR_RECVONLY || m->dir == SDP_DIR_INACTIVE || m->legacy_hold);
}

void b2b_client_media(struct b2b_call *c, const struct sdpn_media *m)
{
	struct sdpn_media old = c->lm;
	struct br_leg_cfg lc;

	c->lm = *m;
	c->lm_ok = true;
	c->ldir = b2b_br_dir(m->dir);
	if (!c->br)
		return;
	if (!b2b_media_same(&old, m)) {
		LOGI("call#%u: client changed codec (%s -> %s), restarting the bridge", c->id, sdpn_codec_name(old.codec),
		     sdpn_codec_name(m->codec));
		client_cfg(c, &lc);
		bridge_stop(c->br);
		bridge_set_leg(c->br, BR_CLIENT, &lc);
		bridge_start(c->br);
	} else {
		if (usable_remote(m) && !addr_equal(&old.remote, &m->remote))
			bridge_set_remote(c->br, BR_CLIENT, &m->remote);
		if (old.dir != m->dir)
			bridge_set_dir(c->br, BR_CLIENT, c->ldir);
	}
	hold_note(c, &c->hold_l, m->dir == SDP_DIR_RECVONLY || m->dir == SDP_DIR_INACTIVE ? true : false);
}

/* a problem of the PCM device / a digit of the LAN device for a CS call; true when the call is over */
static bool pcm_event(struct b2b_call *c, const struct br_event *ev)
{
	struct cs_media_event m;
	bool fatal;

	if (!c->cc || !cs_media_classify(ev, &m))
		return false;
	fatal = m.type == CSM_OPEN_FAILED || m.type == CSM_LOST ||
		(m.type == CSM_STALL && c->ops->state(c->cc) == CC_ST_CONNECTED);
	if (m.type == CSM_DIGIT)
		LOGD("call#%u: DTMF %c from the LAN device sent with the call control", c->id, m.digit);
	else if (m.type != CSM_STALL || fatal)
		LOGW("call#%u: PCM %s%s%s", c->id, m.type == CSM_OPEN_FAILED ? "device cannot be opened" :
		     m.type == CSM_LOST ? "device lost" : "capture stalled", m.err ? ": " : "", m.err ? strerror(m.err) : "");
	cs_media_apply(c->ops, c->cc, &m);
	if (fatal) {
		c->end_status = 503;
		b2b_teardown(c, m.type == CSM_OPEN_FAILED ? "the PCM device cannot be opened" : "the PCM device failed", true);
		return true;
	}
	return m.type != CSM_DIGIT;	/* a stall before the answer is nothing to act on */
}

void b2b_bridge_event(void *arg, const struct br_event *ev)
{
	struct b2b_call *c = b2b_find((unsigned)(uintptr_t)ev->user);
	char d[2] = { 0, 0 };

	(void)arg;
	if (!c)
		return;		/* stale event of a call that is gone */
	if (c->pcm && pcm_event(c, ev))
		return;
	switch (ev->type) {
	case BR_EV_RX_TIMEOUT:
		if (ev->leg != BR_CARRIER || c->bench || c->pcm)
			break;
		B.cnt.rtp_timeouts++;
		LOGW("call#%u: no RTP from the network for %u s, hanging up", c->id, b2b_cfg()->rtp_timeout_s);
		c->end_status = 408;
		b2b_teardown(c, "no media from the network", true);
		break;
	case BR_EV_ERROR:
		LOGW("call#%u: media error: %s", c->id, ev->msg);
		if (c->bench && c->st != CS_ENDED) {
			b2b_notify(c, "media-error", 0, ev->msg);
		}
		c->end_status = 500;
		b2b_teardown(c, ev->msg[0] ? ev->msg : "media error", true);
		break;
	case BR_EV_DTMF:
		if (!ev->end) {
			d[0] = ev->digit;
			b2b_notify(c, "dtmf", 0, d);
		}
		break;
	case BR_EV_PLAY_DONE:
		b2b_notify(c, "play-done", 0, "");
		break;
	case BR_EV_FIRST_RX:
		LOGD("call#%u: first RTP on the %s leg", c->id, ev->leg == BR_CARRIER ? "carrier" : "client");
		break;
	default:
		break;
	}
}

void b2b_fill_info(const struct b2b_call *c, struct b2b_info *i)
{
	memset(i, 0, sizeof(*i));
	i->id = c->id;
	i->dir = c->out ? "out" : "in";
	i->state = b2b_state_name(c);
	i->bench = c->bench;
	snprintf(i->number, sizeof(i->number), "%s", c->number);
	snprintf(i->carrier_name, sizeof(i->carrier_name), "%s", c->ops ? c->ops->name : "");
	if (c->pcm)
		snprintf(i->carrier_codec, sizeof(i->carrier_codec), "pcm");
	else if (c->cm_ok)
		snprintf(i->carrier_codec, sizeof(i->carrier_codec), "%s", sdpn_codec_name(c->cm.codec));
	if (c->bench)
		snprintf(i->client_codec, sizeof(i->client_codec), "pcm");
	else if (c->lm_ok)
		snprintf(i->client_codec, sizeof(i->client_codec), "%s", sdpn_codec_name(c->lm.codec));
	i->age_ms = ev_now_ms() - c->t_start;
	i->talk_ms = c->t_up ? ev_now_ms() - c->t_up : 0;
	if (c->br) {
		i->bridge = true;
		bridge_get_stats(c->br, &i->stats);
	}
}
