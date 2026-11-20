/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "carrier_gm.h"
#include "../util/sys.h"

struct ccgm {
	struct gmcall *g;
	cc_event_cb cb;
	void *arg;
	struct cc_identity remote;
};

static cc_incoming_cb IN_CB;
static void *IN_ARG;

static void identity_from(struct cc_identity *dst, const struct gmcall_identity *src)
{
	str_copy(dst->uri, src->uri, sizeof(dst->uri));
	str_copy(dst->number, src->number, sizeof(dst->number));
	str_copy(dst->display, src->display, sizeof(dst->display));
	dst->anonymous = src->anonymous;
}

static void gm_event(struct gmcall *g, const struct gmcall_event *ev, void *arg)
{
	struct ccgm *w = arg;
	struct cc_event e;
	bool terminal = false;

	(void)g;
	memset(&e, 0, sizeof(e));
	e.status = ev->status;
	e.by_remote = ev->by_remote;
	str_copy(e.reason, ev->reason, sizeof(e.reason));
	switch (ev->type) {
	case GMCALL_EV_PROGRESS: e.type = CC_EV_PROGRESS; break;
	case GMCALL_EV_RINGING: e.type = CC_EV_RINGING; break;
	case GMCALL_EV_MEDIA:
		e.type = ev->early ? CC_EV_EARLY_MEDIA : CC_EV_MEDIA;
		e.early = ev->early;
		e.media_kind = CC_MEDIA_RTP;
		e.media = ev->media;
		break;
	case GMCALL_EV_ANSWERED: e.type = CC_EV_ANSWERED; break;
	case GMCALL_EV_FAILED:
		e.type = CC_EV_FAILED;
		terminal = true;
		if (!e.reason[0])
			str_copy(e.reason, ev->warning, sizeof(e.reason));	/* the text of a failure: the reason, else the Warning header */
		break;
	case GMCALL_EV_CANCELLED: e.type = CC_EV_CANCELLED; terminal = true; break;
	case GMCALL_EV_TERMINATED: e.type = CC_EV_TERMINATED; terminal = true; break;
	case GMCALL_EV_REOFFER_FAILED: e.type = CC_EV_REOFFER_FAILED; break;
	default:
		return;
	}
	if (w->cb)
		w->cb((struct carrier_call *)w, &e, w->arg);
	if (terminal)
		free(w);			/* the gmcall is reclaimed by gmcall itself after this callback */
}

static int gm_incoming(struct gmcall *g, const struct gmcall_incoming *in, void *arg)
{
	struct ccgm *w;
	struct cc_incoming ci;
	int rc;

	(void)arg;
	if (!IN_CB)
		return -1;
	w = calloc(1, sizeof(*w));
	if (!w)
		return -1;
	w->g = g;
	identity_from(&w->remote, &in->caller);
	memset(&ci, 0, sizeof(ci));
	ci.caller = w->remote;
	str_copy(ci.called, in->called, sizeof(ci.called));
	ci.media_kind = CC_MEDIA_RTP;
	ci.offered = in->offered;
	rc = IN_CB((struct carrier_call *)w, &ci, IN_ARG);
	if (rc) {
		free(w);
		return rc;
	}
	gmcall_set_handler(g, gm_event, w);	/* the user installed its handler on w with set_handler: cb / arg are w's */
	return 0;
}

static void op_set_incoming(void *be, cc_incoming_cb cb, void *arg)
{
	IN_CB = cb;
	IN_ARG = arg;
	gmcall_set_incoming(be, cb ? gm_incoming : NULL, NULL);
}

static int op_dial(void *be, const struct cc_dial *d, cc_event_cb cb, void *arg, struct carrier_call **out)
{
	struct ccgm *w = calloc(1, sizeof(*w));
	struct gmcall_dial gd;
	int rc;

	if (!w)
		return -ENOMEM;
	w->cb = cb;
	w->arg = arg;
	memset(&gd, 0, sizeof(gd));
	gd.target = d->target;
	gd.local_rtp = d->local_rtp;
	gd.extra_headers = d->extra_headers;
	rc = gmcall_dial(be, &gd, gm_event, w, &w->g);
	if (rc) {
		free(w);
		return rc;
	}
	identity_from(&w->remote, gmcall_remote(w->g));
	*out = (struct carrier_call *)w;
	return 0;
}

static unsigned op_count(const void *be)
{
	return gmcall_count(be);
}

static int op_list(const void *be, struct cc_info *out, int max)
{
	struct gmcall_info gi[8];
	int n = gmcall_list(be, gi, 8), i;

	for (i = 0; i < n && i < max && i < 8; i++) {
		memset(&out[i], 0, sizeof(out[i]));
		out[i].id = gi[i].id;
		out[i].dir = gi[i].dir == GMCALL_MO ? CC_MO : CC_MT;
		out[i].state_name = gi[i].state_name;
		identity_from(&out[i].remote, &gi[i].remote);
		out[i].age_ms = gi[i].age_ms;
		out[i].talk_ms = gi[i].talk_ms;
		out[i].media_kind = CC_MEDIA_RTP;
		out[i].hold = gi[i].local_dir != SDP_DIR_SENDRECV;
	}
	return n;
}

static struct gmcall *G(struct carrier_call *c)
{
	return ((struct ccgm *)c)->g;
}

static const struct gmcall *GC(const struct carrier_call *c)
{
	return ((const struct ccgm *)c)->g;
}

static void op_set_handler(struct carrier_call *c, cc_event_cb cb, void *arg)
{
	struct ccgm *w = (struct ccgm *)c;

	w->cb = cb;
	w->arg = arg;
}

static int op_ring(struct carrier_call *c) { return gmcall_ring(G(c)); }
static int op_answer(struct carrier_call *c, const struct addr *rtp) { return rtp ? gmcall_answer(G(c), rtp) : -EINVAL; }
static int op_reject(struct carrier_call *c, int status) { return gmcall_reject(G(c), status); }
static int op_hangup(struct carrier_call *c) { return gmcall_hangup(G(c)); }

static void op_release(struct carrier_call *c)
{
	struct ccgm *w = (struct ccgm *)c;

	gmcall_release(w->g);
	free(w);
}

static int op_set_hold(struct carrier_call *c, bool hold)
{
	return gmcall_set_direction(G(c), hold ? SDP_DIR_SENDONLY : SDP_DIR_SENDRECV);
}

static int op_send_dtmf(struct carrier_call *c, char digit)
{
	(void)c;
	(void)digit;
	return -ENOTSUP;
}

static void op_media_failed(struct carrier_call *c, int err)
{
	(void)err;
	gmcall_hangup(G(c));
}

static bool op_get_media(const struct carrier_call *c, struct sdpn_media *out)
{
	return gmcall_get_media(GC(c), out);
}

static enum cc_state op_state(const struct carrier_call *c)
{
	switch (gmcall_get_state(GC(c))) {
	case GMCALL_ST_DIALING: return CC_ST_DIALING;
	case GMCALL_ST_EARLY: return CC_ST_EARLY;
	case GMCALL_ST_CANCELLING: return CC_ST_CANCELLING;
	case GMCALL_ST_INCOMING: return CC_ST_INCOMING;
	case GMCALL_ST_ANSWERING: return CC_ST_ANSWERING;
	case GMCALL_ST_CONNECTED: return CC_ST_CONNECTED;
	default: return CC_ST_ENDED;
	}
}

static enum cc_dir op_direction(const struct carrier_call *c)
{
	return gmcall_direction(GC(c)) == GMCALL_MO ? CC_MO : CC_MT;
}

static const struct cc_identity *op_remote(const struct carrier_call *c)
{
	return &((const struct ccgm *)c)->remote;
}

static unsigned op_id(const struct carrier_call *c) { return gmcall_id(GC(c)); }
static uint64_t op_talk_ms(const struct carrier_call *c) { return gmcall_talk_ms(GC(c)); }

const struct carrier_call_ops carrier_gm_ops = {
	.name = "gm",
	.media_kind = CC_MEDIA_RTP,
	.set_incoming = op_set_incoming,
	.dial = op_dial,
	.count = op_count,
	.list = op_list,
	.set_handler = op_set_handler,
	.ring = op_ring,
	.answer = op_answer,
	.reject = op_reject,
	.hangup = op_hangup,
	.release = op_release,
	.set_hold = op_set_hold,
	.send_dtmf = op_send_dtmf,
	.media_failed = op_media_failed,
	.get_media = op_get_media,
	.state = op_state,
	.direction = op_direction,
	.remote = op_remote,
	.id = op_id,
	.talk_ms = op_talk_ms,
};

void carrier_gm_backend(struct gmcall_mgr *m, struct carrier_backend *out)
{
	out->ops = &carrier_gm_ops;
	out->be = m;
}

struct gmcall *carrier_gm_call(struct carrier_call *c)
{
	return G(c);
}
