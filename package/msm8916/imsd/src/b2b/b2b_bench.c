/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Bench calls: the LAN leg is a PCM file leg of the bridge (ubus call_dial / call_answer), plus the call controls. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "b2b_int.h"

int b2b_bench_pcm_cfg(struct b2b_call *c, struct br_leg_cfg *cfg)
{
	br_leg_cfg_default(cfg);
	cfg->kind = BR_LEG_PCM;
	cfg->dir = c->ldir;
	cfg->pcm_rate = (int)c->rate;
	snprintf(cfg->play_path, sizeof(cfg->play_path), "%s", c->play);
	snprintf(cfg->rec_path, sizeof(cfg->rec_path), "%s", c->rec);
	return 0;
}

static int set_files(struct b2b_call *c, const char *play, const char *rec, unsigned rate)
{
	if (rate && rate != 8000 && rate != 16000)
		return -EINVAL;
	if ((play && strlen(play) >= sizeof(c->play)) || (rec && strlen(rec) >= sizeof(c->rec)))
		return -ENAMETOOLONG;
	snprintf(c->play, sizeof(c->play), "%s", play ? play : "");
	snprintf(c->rec, sizeof(c->rec), "%s", rec ? rec : "");
	c->rate = rate ? rate : 16000;
	return 0;
}

int b2b_bench_dial(const char *number, const char *play, const char *record, unsigned rate, unsigned *id)
{
	const struct imsd_config *cfg = b2b_cfg();
	const struct carrier_backend *be = b2b_cur_backend();
	struct b2b_call *c;
	struct cc_dial d;
	char ctx[96], ua[128];
	bool pcm;
	int rc;

	if (!B.running)
		return -ENODEV;
	if (!number || !number[0])
		return -EINVAL;
	if (!be)
		return -ENOTCONN;
	pcm = be->ops->media_kind == CC_MEDIA_PCM;
	if (!pcm && !reg_is_registered(core_reg(B.core)))
		return -ENOTCONN;
	c = b2b_call_new(true);
	if (!c)
		return -ENOMEM;
	c->bench = true;
	c->ops = be->ops;
	c->pcm = pcm;
	rc = set_files(c, play, record, rate);
	if (rc)
		goto fail;
	snprintf(c->number, sizeof(c->number), "%s", number);
	memset(&d, 0, sizeof(d));
	d.target = number;
	if (!pcm) {
		c->cfd = b2b_rtp_carrier(&c->cbound);
		if (c->cfd < 0) {
			rc = c->cfd;
			c->cfd = -1;
			goto fail;
		}
		snprintf(ctx, sizeof(ctx), "%s", cfg->phone_context[0] ? cfg->phone_context : core_param_domain(B.core));
		config_ims_user_agent(cfg, ua, sizeof(ua));
		gmcall_mgr_set_strings(B.gm, ctx, cfg->contact_params, ua);
		gmcall_mgr_set_session_expires(B.gm, cfg->session_expires);
		core_pani_refresh(B.core);
		d.local_rtp = c->cbound;
	}
	rc = be->ops->dial(be->be, &d, b2b_cc_event, c, &c->cc);
	if (rc)
		goto fail;
	B.cnt.out_total++;
	B.cnt.bench_total++;
	*id = c->id;
	LOGI("call#%u: bench call to %s (%s)", c->id, number, be->ops->name);
	b2b_notify(c, "new", 0, "");
	return 0;
fail:
	c->st = CS_SETUP;
	b2b_teardown(c, strerror(-rc), false);
	return rc;
}

int b2b_bench_answer(unsigned id, const char *play, const char *record, unsigned rate)
{
	struct b2b_call *c = b2b_find(id);
	int rc;

	if (!c || c->out || !c->bench || c->st != CS_SETUP || !c->cc)
		return c ? -EINVAL : -ENOENT;
	rc = set_files(c, play, record, rate);
	if (rc)
		return rc;
	if (c->pcm) {
		rc = c->ops->answer(c->cc, NULL);
		if (rc)
			return rc;
	} else {
		c->cfd = b2b_rtp_carrier(&c->cbound);
		if (c->cfd < 0) {
			rc = c->cfd;
			c->cfd = -1;
			return rc;
		}
		rc = c->ops->answer(c->cc, &c->cbound);
		if (rc) {
			b2b_close_socks(c);
			return rc;
		}
		if (!c->ops->get_media(c->cc, &c->cm)) {
			c->end_status = 500;
			b2b_teardown(c, "no carrier media", true);
			return -EPROTO;
		}
		c->cm_ok = true;
	}
	c->st = CS_UP;
	c->t_up = ev_now_ms();
	B.cnt.answered++;
	c->bench_play_started = true;
	if (b2b_bridge_up(c)) {
		c->end_status = 500;
		b2b_teardown(c, "media bridge failed", true);
		return -EIO;
	}
	b2b_notify(c, "answered", 0, "");
	return 0;
}

int b2b_call_reject(unsigned id, int status)
{
	struct b2b_call *c = b2b_find(id);

	if (!c || c->out || !c->bench || c->st != CS_SETUP || !c->cc)
		return c ? -EINVAL : -ENOENT;
	if (status < 400 || status > 699)
		status = 486;
	c->end_status = status;
	b2b_cc_reject_release(c, status);
	b2b_teardown(c, "rejected over ubus", false);
	return 0;
}

int b2b_call_hangup(unsigned id)
{
	struct b2b_call *c = b2b_find(id);

	if (!c)
		return -ENOENT;
	if (c->out && (c->st == CS_SETUP || c->st == CS_EARLY))
		c->end_status = 487;
	if (!c->out && c->st == CS_SETUP && c->bench) {
		c->end_status = 480;
		b2b_cc_reject_release(c, 480);
	}
	if (c->st == CS_SETUP && !c->out)
		b2b_in_end(c);
	b2b_teardown(c, "hangup over ubus", true);
	return 0;
}
