/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "lan.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define ALLOW_LIST "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER, MESSAGE, UPDATE, INFO, NOTIFY"
#define ACCEPT_LIST "application/sdp, text/plain"
#define ABANDON_MS 33000	/* just over 64*T1: a cancelled / finished branch that is still silent is given up */
#define REASON_ELSEWHERE "Reason: SIP;cause=200;text=\"Call completed elsewhere\"\r\n"

struct lan_xact {
	struct lan *lan;
	struct lan_xact *next;
	reg_id_t id;
	struct txn_client *c;
	lan_xact_cb cb;
	void *arg;
	char method[16];
	char ruri[256], via[160], from[560], to[200], call_id[128];
	uint32_t cseq;
};

struct lan_branch {
	struct lan_fork *f;
	struct lan_xact *x;
	reg_id_t id;
	int status;
	enum lan_branch_cause cause;
	bool final;		/* outcome known (or branch abandoned) */
	bool lost;		/* we cancelled it: late 2xx are extras, outcome is not reported */
	bool got2xx;
	char tag2xx[64];
};

struct lan_fork {
	struct lan *lan;
	struct lan_fork *next;
	lan_fork_cb cb;
	void *arg;
	bool invite, completed, cancelled, detached;
	struct lan_branch *br;
	int nb, live;
	reg_id_t winner;
	uint32_t cseq;
	struct ev_timer *abandon;	/* after completion / cancel: stop waiting for dead branches */
	char call_id[128], from_tag[64], from_uri[256];
};

struct lan {
	struct lan_cfg cfg;
	char ua[48], contact_user[48];
	struct txn_layer *tl;
	struct sip_endpoint *ep;
	struct registrar *reg;
	struct lan_xact *xacts;
	struct lan_fork *forks;
	struct lan_stats st;
};

/* ------------------------------------------------------------------ */
/* registrar glue                                                      */

static void fork_binding_gone(struct lan_fork *f, reg_id_t id);

static void on_reg_event(struct registrar *r, enum registrar_event ev, const struct reg_binding *b,
			 enum reg_removal why, void *arg)
{
	struct lan *l = arg;

	(void)r;
	if (ev == REG_EV_REMOVED) {
		struct lan_fork *f, *nx;

		for (f = l->forks; f; f = nx) {
			nx = f->next;
			fork_binding_gone(f, b->id);
		}
	}
	if (l->cfg.on_binding)
		l->cfg.on_binding(l, ev, b, why, l->cfg.arg);
}

static void on_reg_ping(struct registrar *r, reg_id_t id, void *arg)
{
	struct lan *l = arg;
	struct lan_req q;

	(void)r;
	memset(&q, 0, sizeof(q));
	q.method = "OPTIONS";
	q.from_user = l->contact_user;
	lan_send_request(l, id, &q, NULL, NULL, NULL);	/* the xact layer marks reachable / unreachable */
}

struct lan *lan_new(const struct lan_cfg *cfg)
{
	struct lan *l = calloc(1, sizeof(*l));
	struct registrar_cfg rc;

	if (!l)
		return NULL;
	l->cfg = *cfg;
	str_copy(l->ua, cfg->user_agent ? cfg->user_agent : "imsd", sizeof(l->ua));
	str_copy(l->contact_user, cfg->contact_user ? cfg->contact_user : "imsd", sizeof(l->contact_user));
	l->cfg.user_agent = l->ua;
	l->cfg.contact_user = l->contact_user;
	rc = cfg->reg;
	rc.on_event = on_reg_event;
	rc.ping = on_reg_ping;
	rc.arg = l;
	l->reg = registrar_new(&rc);
	if (!l->reg) {
		free(l);
		return NULL;
	}
	lan_attach(l, cfg->tl, cfg->ep);
	return l;
}

void lan_attach(struct lan *l, struct txn_layer *tl, struct sip_endpoint *ep)
{
	l->tl = tl;
	if (ep && ep != l->ep) {
		if (l->ep)
			sip_ep_unref(l->ep);
		l->ep = sip_ep_ref(ep);
	}
}

void lan_set_hooks(struct lan *l, const struct lan_hooks *h)
{
	l->cfg.hooks = *h;
}

struct registrar *lan_registrar(struct lan *l)
{
	return l->reg;
}

struct sip_endpoint *lan_endpoint(struct lan *l)
{
	return l->ep;
}

void lan_free(struct lan *l)
{
	struct lan_xact *x;
	struct lan_fork *f;

	if (!l)
		return;
	while ((x = l->xacts)) {
		l->xacts = x->next;
		if (x->c)
			txn_client_detach(x->c);
		free(x);
	}
	while ((f = l->forks)) {
		l->forks = f->next;
		ev_timer_free(f->abandon);
		free(f->br);
		free(f);
	}
	registrar_free(l->reg);
	if (l->ep)
		sip_ep_unref(l->ep);
	free(l);
}

/* ------------------------------------------------------------------ */
/* identification and router                                           */

void lan_identify(struct lan *l, const struct addr *src, const struct sip_msg *req, struct lan_peer *peer)
{
	const char *ct = sip_hdr(req, "Contact", 0);
	char uri[256];

	memset(peer, 0, sizeof(*peer));
	peer->src = *src;
	if (ct && sip_uri_of(ct, uri, sizeof(uri)))
		ct = NULL;
	peer->id = reg_identify(l->reg, src, ct ? uri : NULL);
	peer->b = reg_find(l->reg, peer->id);
	peer->registered = peer->b != NULL;
}

static void reply(struct lan *l, struct txn_server *st, int status, const char *extra)
{
	struct sip_resp_parts p;
	char hdr[512];

	snprintf(hdr, sizeof(hdr), "Server: %s\r\n%s", l->ua, extra ? extra : "");
	memset(&p, 0, sizeof(p));
	p.status = status;
	p.extra = hdr;
	txn_server_reply(st, &p);
}

static bool has_to_tag(const struct sip_msg *req)
{
	const char *to = sip_hdr(req, "To", 0);
	char tag[96];

	return to && !sip_tag(to, tag, sizeof(tag)) && tag[0];
}

static void note_unreg(struct lan *l, const struct lan_peer *peer, const struct sip_msg *req)
{
	char a[64];

	if (peer->registered)
		return;
	l->st.rx_unregistered++;
	addr_str(&peer->src, a, sizeof(a));
	LOGD("lan: %s from unregistered source %s", req->method, a);
}

void lan_on_request(struct txn_layer *tl, struct txn_server *st, struct sip_endpoint *ep,
		    const struct addr *src, const struct sip_msg *req, void *arg)
{
	struct lan *l = arg;
	const struct lan_hooks *h = &l->cfg.hooks;
	struct lan_peer peer;
	const char *m = req->method;

	(void)tl;
	l->st.rx_requests++;
	if (!st) {		/* ACK without transaction */
		l->st.rx_ack++;
		lan_identify(l, src, req, &peer);
		if (peer.registered)
			reg_note_rx(l->reg, peer.id);
		if (h->on_ack)
			h->on_ack(l, &peer, req, h->arg);
		return;
	}
	if (!strcmp(m, "REGISTER")) {
		l->st.rx_register++;
		reg_handle_register(l->reg, st, ep, src, req);
		/* a REGISTER proves the device is alive: reg_handle_register() created / refreshed it */
		return;
	}
	lan_identify(l, src, req, &peer);
	if (peer.registered)
		reg_note_rx(l->reg, peer.id);
	note_unreg(l, &peer, req);

	if (!strcmp(m, "OPTIONS")) {
		l->st.rx_options++;
		reply(l, st, 200, "Allow: " ALLOW_LIST "\r\nAccept: " ACCEPT_LIST "\r\n");
	} else if (!strcmp(m, "SUBSCRIBE")) {
		l->st.rx_subscribe++;
		LOGD("lan: SUBSCRIBE (%s) refused with 489", sip_hdr(req, "Event", 0) ? sip_hdr(req, "Event", 0) : "no Event");
		reply(l, st, 489, NULL);	/* no Allow-Events: we support no event package */
	} else if (!strcmp(m, "PUBLISH")) {
		l->st.rx_other++;
		reply(l, st, 405, "Allow: " ALLOW_LIST "\r\n");
	} else if (!strcmp(m, "REFER")) {
		l->st.rx_other++;
		LOGI("lan: REFER (call transfer) is not supported, answering 501");
		reply(l, st, 501, NULL);
	} else if (!strcmp(m, "INVITE")) {
		l->st.rx_invite++;
		if (has_to_tag(req)) {
			if (h->on_in_dialog)
				h->on_in_dialog(l, &peer, st, req, h->arg);
			else
				reply(l, st, 481, NULL);
		} else if (h->on_invite)
			h->on_invite(l, &peer, st, req, h->arg);
		else
			reply(l, st, 480, NULL);
	} else if (!strcmp(m, "MESSAGE")) {
		l->st.rx_message++;
		if (h->on_message)
			h->on_message(l, &peer, st, req, h->arg);
		else
			reply(l, st, 503, "Retry-After: 30\r\n");
	} else if (!strcmp(m, "NOTIFY") && !has_to_tag(req)) {
		const char *ev = sip_hdr(req, "Event", 0);

		l->st.rx_other++;
		if (ev && !strncasecmp(ev, "keep-alive", 10))
			reply(l, st, 200, NULL);
		else
			reply(l, st, 481, NULL);
	} else if (!strcmp(m, "INFO")) {
		l->st.rx_other++;
		if (h->on_in_dialog && has_to_tag(req))
			h->on_in_dialog(l, &peer, st, req, h->arg);
		else
			reply(l, st, 200, NULL);
	} else if (!strcmp(m, "BYE") || !strcmp(m, "UPDATE") || !strcmp(m, "PRACK") || !strcmp(m, "NOTIFY")) {
		l->st.rx_other++;
		if (h->on_in_dialog && has_to_tag(req))
			h->on_in_dialog(l, &peer, st, req, h->arg);
		else
			reply(l, st, 481, NULL);
	} else {
		l->st.rx_other++;
		LOGD("lan: unsupported method %s -> 501", m);
		reply(l, st, 501, NULL);
	}
}

/* ------------------------------------------------------------------ */
/* outbound request                                                    */

static void xact_unlink(struct lan_xact *x)
{
	struct lan_xact **pp;

	for (pp = &x->lan->xacts; *pp; pp = &(*pp)->next)
		if (*pp == x) {
			*pp = x->next;
			return;
		}
}

static void xact_cb(struct txn_client *c, enum txn_cli_event ev, const struct sip_msg *resp,
		    struct sip_endpoint *rx_ep, const struct addr *src, void *arg)
{
	struct lan_xact *x = arg;
	struct lan *l = x->lan;

	(void)c; (void)rx_ep;
	switch (ev) {
	case TXN_CLI_RESPONSE:
		reg_note_response(l->reg, x->id, resp);
		break;
	case TXN_CLI_TIMEOUT:
		LOGI("lan: %s to binding %u timed out", x->method, x->id);
		reg_note_timeout(l->reg, x->id);
		break;
	case TXN_CLI_TRANSPORT_ERROR:
		LOGW("lan: %s to binding %u failed to send", x->method, x->id);
		break;
	case TXN_CLI_TERMINATED:
		x->c = NULL;
		break;
	}
	if (x->cb)
		x->cb(x, ev, resp, src, x->arg);
	if (ev == TXN_CLI_TERMINATED) {
		xact_unlink(x);
		free(x);
	}
}

static void quote_display(char *out, size_t n, const char *s)
{
	size_t o = 0;

	for (; *s && o + 3 < n; s++) {
		if (*s == '"' || *s == '\\')
			out[o++] = '\\';
		if ((unsigned char)*s >= 0x20)
			out[o++] = *s;
	}
	out[o] = 0;
}

static void our_contact(struct lan *l, char *out, size_t n)
{
	char h[96];

	addr_uri_host(&l->ep->advertised, h, sizeof(h));
	snprintf(out, n, "<sip:%s@%s:%u%s>", l->contact_user, h, addr_port(&l->ep->advertised),
		 l->ep->kind == SIP_TP_TCP ? ";transport=tcp" : "");
}

/* identifiers that all branches of a fork share */
struct req_ids {
	char call_id[128], from_tag[64], from_uri[256], from[560];
	uint32_t cseq;
};

static int make_ids(struct lan *l, const struct lan_req *r, struct req_ids *ids)
{
	char host[96], disp[128];
	char uri[256];

	if (!r->method || (!r->from_uri && !r->from_user))
		return -1;
	addr_uri_host(&l->ep->advertised, host, sizeof(host));
	if (r->call_id)
		str_copy(ids->call_id, r->call_id, sizeof(ids->call_id));
	else {
		char tok[25];

		rnd_token(tok, 24);
		snprintf(ids->call_id, sizeof(ids->call_id), "%s@%s", tok, host);
	}
	if (r->from_tag)
		str_copy(ids->from_tag, r->from_tag, sizeof(ids->from_tag));
	else
		rnd_token(ids->from_tag, 12);
	if (r->from_uri)
		str_copy(uri, r->from_uri, sizeof(uri));
	else
		snprintf(uri, sizeof(uri), "sip:%s@%s", r->from_user, host);
	str_copy(ids->from_uri, uri, sizeof(ids->from_uri));
	disp[0] = 0;
	if (r->from_display && r->from_display[0]) {
		quote_display(disp, sizeof(disp), r->from_display);
		snprintf(ids->from, sizeof(ids->from), "\"%s\" <%s>;tag=%s", disp, uri, ids->from_tag);
	} else
		snprintf(ids->from, sizeof(ids->from), "<%s>;tag=%s", uri, ids->from_tag);
	ids->cseq = r->cseq ? r->cseq : 1;
	return 0;
}

static struct lan_xact *xact_start(struct lan *l, const struct reg_binding *b, const struct lan_req *r,
				   const struct req_ids *ids, lan_xact_cb cb, void *arg, char *branch_out)
{
	struct lan_xact *x;
	struct sip_req_parts p;
	struct txn_client_req cr;
	struct buf buf, ex;
	char contact[256];
	struct sip_endpoint *ep = b->ep ? b->ep : l->ep;
	bool invite = !strcmp(r->method, "INVITE");
	char branch[SIP_BRANCH_LEN];

	if (!ep || !l->tl) {
		errno = EINVAL;
		return NULL;
	}
	x = calloc(1, sizeof(*x));
	if (!x) {
		errno = ENOMEM;
		return NULL;
	}
	x->lan = l;
	x->id = b->id;
	x->cb = cb;
	x->arg = arg;
	x->cseq = ids->cseq;
	str_copy(x->method, r->method, sizeof(x->method));
	str_copy(x->ruri, b->contact, sizeof(x->ruri));
	str_copy(x->from, ids->from, sizeof(x->from));
	snprintf(x->to, sizeof(x->to), "<%s>", b->aor);
	str_copy(x->call_id, ids->call_id, sizeof(x->call_id));
	sip_new_branch(branch);
	sip_via_make(x->via, sizeof(x->via), ep->kind == SIP_TP_TCP ? "TCP" : "UDP", &ep->advertised, branch, false);
	our_contact(l, contact, sizeof(contact));

	buf_init(&ex, 2048);
	buf_printf(&ex, "User-Agent: %s\r\n", l->ua);
	if (invite)
		buf_puts(&ex, "Allow: " ALLOW_LIST "\r\n");
	if (r->extra)
		buf_puts(&ex, r->extra);
	buf_init(&buf, 0);
	memset(&p, 0, sizeof(p));
	p.method = x->method;
	p.ruri = x->ruri;
	p.via = x->via;
	p.from = x->from;
	p.to = x->to;
	p.call_id = x->call_id;
	p.cseq = x->cseq;
	p.contact = contact;
	p.extra = buf_cstr(&ex);
	p.content_type = r->content_type;
	p.body = r->body;
	p.body_len = r->body_len;
	if (sip_build_request(&buf, &p) || !buf_ok(&ex)) {
		buf_free(&buf);
		buf_free(&ex);
		free(x);
		errno = EINVAL;
		return NULL;
	}
	memset(&cr, 0, sizeof(cr));
	cr.ep = ep;
	cr.dst = b->target;
	cr.data = buf.p;
	cr.len = buf.len;
	cr.cb = xact_cb;
	cr.arg = x;
	x->c = txn_client_start(l->tl, &cr);
	buf_free(&buf);
	buf_free(&ex);
	if (!x->c) {
		free(x);
		errno = EAGAIN;
		return NULL;
	}
	x->next = l->xacts;
	l->xacts = x;
	reg_note_tx(l->reg, x->id);
	if (branch_out)
		str_copy(branch_out, branch, SIP_BRANCH_LEN);
	return x;
}

static void fill_sent(struct lan_sent *s, const struct req_ids *ids, const char *aor, const char *branch)
{
	if (!s)
		return;
	memset(s, 0, sizeof(*s));
	str_copy(s->call_id, ids->call_id, sizeof(s->call_id));
	str_copy(s->from_tag, ids->from_tag, sizeof(s->from_tag));
	str_copy(s->from_uri, ids->from_uri, sizeof(s->from_uri));
	str_copy(s->to_uri, aor, sizeof(s->to_uri));
	s->cseq = ids->cseq;
	if (branch)
		str_copy(s->branch, branch, sizeof(s->branch));
}

struct lan_xact *lan_send_request(struct lan *l, reg_id_t id, const struct lan_req *req, lan_xact_cb cb, void *arg,
				  struct lan_sent *sent)
{
	const struct reg_binding *b = reg_find(l->reg, id);
	struct req_ids ids;
	struct lan_xact *x;
	char branch[SIP_BRANCH_LEN];

	if (!b) {
		errno = ENOENT;
		return NULL;
	}
	if (make_ids(l, req, &ids)) {
		errno = EINVAL;
		return NULL;
	}
	x = xact_start(l, b, req, &ids, cb, arg, branch);
	if (x)
		fill_sent(sent, &ids, b->aor, branch);
	return x;
}

int lan_xact_cancel(struct lan_xact *x, const char *extra)
{
	/* the transaction layer sends the CANCEL once a provisional was seen (pending until then, dropped if a final
	 * arrives first) and bounds the INVITE to 64*T1 afterwards (RFC 3261 9.1) */
	if (!x->c || strcmp(x->method, "INVITE"))
		return -1;
	return txn_client_cancel_ex(x->c, extra, NULL, NULL);
}

void lan_xact_detach(struct lan_xact *x)
{
	x->cb = NULL;
}

reg_id_t lan_xact_binding(const struct lan_xact *x)
{
	return x->id;
}

/* ------------------------------------------------------------------ */
/* fork                                                                */

static void fork_emit(struct lan_fork *f, struct lan_fork_event *ev)
{
	if (f->cb && !f->detached)
		f->cb(f, ev, f->arg);
}

static int rank_of(const struct lan_branch *b, int *status)
{
	int s = b->status;

	*status = s;
	if (b->cause == LAN_BR_TIMEOUT || b->cause == LAN_BR_TRANSPORT || b->cause == LAN_BR_REMOVED)
		return 5;
	if (s >= 600)
		return 0;
	if (s == 486)
		return 1;
	if (s >= 300 && s < 400) {
		*status = 480;
		return 4;
	}
	if (s == 408 || s == 487)
		return 4;
	if (s >= 500)
		return 3;
	return 2;
}

static int aggregate(const struct lan_fork *f)
{
	int best_rank = 99, best = 480, i;

	for (i = 0; i < f->nb; i++) {
		const struct lan_branch *b = &f->br[i];
		int st, rk;

		if (!b->status)
			continue;
		rk = rank_of(b, &st);
		if (rk < best_rank || (rk == best_rank && st < best)) {
			best_rank = rk;
			best = st;
		}
	}
	return best;
}

static void fork_free(struct lan_fork *f);

static void fork_abandon_fire(void *arg)
{
	struct lan_fork *f = arg;
	struct lan_fork_event ev;
	int i;

	for (i = 0; i < f->nb; i++)
		if (f->br[i].x) {
			LOGD("lan: giving up on binding %u of a finished fork", f->br[i].id);
			lan_xact_detach(f->br[i].x);	/* the transaction runs to its end on its own */
			f->br[i].x = NULL;
		}
	f->live = 0;
	memset(&ev, 0, sizeof(ev));
	ev.type = LAN_FORK_DONE;
	fork_emit(f, &ev);
	fork_free(f);
}

static void fork_arm_abandon(struct lan_fork *f)
{
	if (!f->abandon)
		f->abandon = ev_timer_new(fork_abandon_fire, f);
	if (f->abandon)
		ev_timer_set(f->abandon, ABANDON_MS);
}

static void fork_complete(struct lan_fork *f, int status, int nok)
{
	struct lan_fork_event ev;
	struct lan_branch_result *res;
	int i;

	f->completed = true;
	fork_arm_abandon(f);
	res = calloc(f->nb, sizeof(*res));
	memset(&ev, 0, sizeof(ev));
	ev.type = LAN_FORK_COMPLETE;
	ev.status = status;
	ev.winner = f->winner;
	ev.nok = nok;
	ev.invite_cseq = f->cseq;
	for (i = 0; res && i < f->nb; i++) {
		res[i].id = f->br[i].id;
		res[i].status = f->br[i].status;
		res[i].cause = f->br[i].cause;
	}
	ev.results = res;
	ev.nresults = res ? f->nb : 0;
	fork_emit(f, &ev);
	free(res);
}

/* all branches have an outcome: report (non-INVITE: also on partial success; INVITE: only failure) */
static void fork_check_complete(struct lan_fork *f)
{
	int i, nok = 0;

	if (f->completed || f->cancelled)
		return;
	for (i = 0; i < f->nb; i++) {
		if (!f->br[i].final)
			return;
		if (f->br[i].status >= 200 && f->br[i].status < 300)
			nok++;
	}
	fork_complete(f, nok ? 200 : aggregate(f), nok);
}

static void fork_cancel_others(struct lan_fork *f, int except, const char *reason)
{
	int i;

	for (i = 0; i < f->nb; i++) {
		struct lan_branch *b = &f->br[i];

		if (i == except || b->final || b->lost)
			continue;
		b->lost = true;
		if (b->x)
			lan_xact_cancel(b->x, reason);
	}
}

static void fork_binding_gone(struct lan_fork *f, reg_id_t id)
{
	int i;

	if (!f->invite)
		return;
	for (i = 0; i < f->nb; i++) {
		struct lan_branch *b = &f->br[i];

		if (b->id != id || b->final)
			continue;
		b->final = true;
		b->status = 480;
		b->cause = LAN_BR_REMOVED;
		b->lost = true;
		if (b->x)
			lan_xact_cancel(b->x, NULL);
		if (!f->completed && !f->cancelled) {
			struct lan_fork_event ev;

			memset(&ev, 0, sizeof(ev));
			ev.type = LAN_FORK_BRANCH_FINAL;
			ev.id = id;
			ev.status = 480;
			ev.cause = LAN_BR_REMOVED;
			fork_emit(f, &ev);
			fork_check_complete(f);
		}
	}
}

/* UAC dialog from a 2xx. 0 / -1 */
static int dlg_from_2xx(struct lan_fork *f, const struct lan_branch *b, const struct sip_msg *resp, struct sip_dialog *out)
{
	struct dlgset s;
	struct dlg_ev ev[4];
	const struct reg_binding *rb = reg_find(f->lan->reg, b->id);
	char to_uri[160];
	int rc = -1;

	str_copy(to_uri, rb ? rb->aor : "sip:unknown@invalid", sizeof(to_uri));
	if (dlgset_init(&s, b->x && b->x->c ? txn_client_endpoint(b->x->c) : f->lan->ep, f->call_id, f->from_tag, f->from_uri,
			to_uri, f->cseq))
		return -1;
	dlgset_on_response(&s, resp, ev, 4);
	if (s.answered >= 0) {
		*out = s.d[s.answered];
		sip_ep_ref(out->ep);
		rc = 0;
	}
	dlgset_release(&s);
	return rc;
}

static void fork_2xx(struct lan_fork *f, struct lan_branch *b, const struct sip_msg *resp, const struct addr *src)
{
	struct lan_fork_event ev;
	struct sip_dialog d;
	char tag[64] = "";
	bool first_on_branch, extra;
	int idx = (int)(b - f->br);

	sip_tag(sip_hdr(resp, "To", 0), tag, sizeof(tag));
	memset(&ev, 0, sizeof(ev));
	ev.id = b->id;
	ev.status = resp->status;
	ev.resp = resp;
	ev.src = src;
	ev.invite_cseq = f->cseq;
	first_on_branch = !b->got2xx || strcmp(tag, b->tag2xx);
	if (!first_on_branch) {
		ev.type = LAN_FORK_2XX_RETRANS;
		ev.is_winner = f->winner == b->id;
		fork_emit(f, &ev);
		return;
	}
	extra = f->winner || f->cancelled || b->lost || b->final;
	b->got2xx = true;
	str_copy(b->tag2xx, tag, sizeof(b->tag2xx));
	if (!extra) {
		b->final = true;
		b->status = resp->status;
		b->cause = LAN_BR_RESPONSE;
		f->winner = b->id;
	} else
		LOGI("lan: extra 2xx for INVITE from binding %u (call completed elsewhere or cancelled)", b->id);
	ev.type = extra ? LAN_FORK_EXTRA_2XX : LAN_FORK_WINNER;
	ev.dlg = NULL;
	if (!dlg_from_2xx(f, b, resp, &d))
		ev.dlg = &d;
	fork_emit(f, &ev);
	if (ev.dlg && !ev.take_dlg)
		dlg_release(&d);
	if (!extra) {
		fork_cancel_others(f, idx, REASON_ELSEWHERE);
		fork_complete(f, resp->status, 1);
	}
}

static void fork_free(struct lan_fork *f)
{
	struct lan_fork **pp;
	int i;

	for (i = 0; i < f->nb; i++)
		if (f->br[i].x)
			lan_xact_detach(f->br[i].x);
	ev_timer_free(f->abandon);

	for (pp = &f->lan->forks; *pp; pp = &(*pp)->next)
		if (*pp == f) {
			*pp = f->next;
			break;
		}
	if (f->lan->st.forks_active)
		f->lan->st.forks_active--;
	free(f->br);
	free(f);
}

static void branch_cb(struct lan_xact *x, enum txn_cli_event ev, const struct sip_msg *resp, const struct addr *src, void *arg)
{
	struct lan_branch *b = arg;
	struct lan_fork *f = b->f;
	struct lan_fork_event fe;

	memset(&fe, 0, sizeof(fe));
	fe.id = b->id;
	switch (ev) {
	case TXN_CLI_RESPONSE:
		if (resp->status < 200) {
			if (b->final || b->lost || f->cancelled || f->winner)
				break;
			fe.type = LAN_FORK_PROVISIONAL;
			fe.status = resp->status;
			fe.resp = resp;
			fe.src = src;
			fe.invite_cseq = f->cseq;
			fork_emit(f, &fe);
		} else if (resp->status < 300) {
			if (f->invite) {
				fork_2xx(f, b, resp, src);
				break;
			}
			if (b->final)
				break;
			b->final = true;
			b->status = resp->status;
			b->cause = LAN_BR_RESPONSE;
			fe.type = LAN_FORK_BRANCH_FINAL;
			fe.status = resp->status;
			fe.cause = LAN_BR_RESPONSE;
			fe.resp = resp;
			fe.src = src;
			fork_emit(f, &fe);
			fork_check_complete(f);
		} else {
			bool quiet = b->final || b->lost || f->cancelled;

			if (b->final)
				break;
			b->final = true;
			b->status = resp->status;
			b->cause = LAN_BR_RESPONSE;
			if (quiet)
				break;
			fe.type = LAN_FORK_BRANCH_FINAL;
			fe.status = resp->status;
			fe.cause = LAN_BR_RESPONSE;
			fe.resp = resp;
			fe.src = src;
			fork_emit(f, &fe);
			fork_check_complete(f);
		}
		break;
	case TXN_CLI_TIMEOUT:
	case TXN_CLI_TRANSPORT_ERROR:
		if (b->final)
			break;
		b->final = true;
		b->status = ev == TXN_CLI_TIMEOUT ? 408 : 503;
		b->cause = ev == TXN_CLI_TIMEOUT ? LAN_BR_TIMEOUT : LAN_BR_TRANSPORT;
		if (b->lost || f->cancelled)
			break;
		fe.type = LAN_FORK_BRANCH_FINAL;
		fe.status = b->status;
		fe.cause = b->cause;
		fork_emit(f, &fe);
		fork_check_complete(f);
		break;
	case TXN_CLI_TERMINATED:
		b->x = NULL;
		b->final = true;
		if (--f->live == 0) {
			memset(&fe, 0, sizeof(fe));
			fe.type = LAN_FORK_DONE;
			fork_emit(f, &fe);
			fork_free(f);
		}
		break;
	}
	(void)x;
}

struct lan_fork *lan_fork_request(struct lan *l, const struct lan_req *req, const struct lan_fork_opts *opts,
				  lan_fork_cb cb, void *arg, struct lan_sent *sent)
{
	const struct reg_binding *b;
	reg_id_t cand[64], id = REG_ID_NONE;
	int ncand = 0, nreach = 0, i, j;
	struct req_ids ids;
	struct lan_fork *f;
	bool incl_unreach = opts && opts->include_unreachable;
	char first_branch[SIP_BRANCH_LEN] = "";

	if (make_ids(l, req, &ids)) {
		errno = EINVAL;
		return NULL;
	}
	/* candidates: not excluded, method allowed, one per distinct Contact */
	while ((b = reg_next(l->reg, id)) && ncand < 64) {
		const struct reg_binding *o;
		bool skip = false;

		id = b->id;
		for (j = 0; opts && j < (int)opts->nexclude; j++)
			if (opts->exclude[j] == b->id)
				skip = true;
		if (opts && opts->include_set) {
			bool in = false;

			for (j = 0; j < (int)opts->ninclude; j++)
				if (opts->include[j] == b->id)
					in = true;
			if (!in)
				skip = true;
		}
		if (!reg_allows(b, req->method))
			skip = true;
		for (j = 0; !skip && j < ncand; j++) {
			o = reg_find(l->reg, cand[j]);
			if (o && !strcmp(o->key, b->key))
				skip = true;
		}
		if (skip)
			continue;
		cand[ncand++] = b->id;
		if (b->reachable)
			nreach++;
	}
	f = calloc(1, sizeof(*f));
	if (!f) {
		errno = ENOMEM;
		return NULL;
	}
	f->br = calloc(ncand ? ncand : 1, sizeof(*f->br));
	if (!f->br) {
		free(f);
		errno = ENOMEM;
		return NULL;
	}
	f->lan = l;
	f->cb = cb;
	f->arg = arg;
	f->invite = !strcmp(req->method, "INVITE");
	f->cseq = ids.cseq;
	str_copy(f->call_id, ids.call_id, sizeof(f->call_id));
	str_copy(f->from_tag, ids.from_tag, sizeof(f->from_tag));
	str_copy(f->from_uri, ids.from_uri, sizeof(f->from_uri));
	f->next = l->forks;
	l->forks = f;
	for (i = 0; i < ncand; i++) {
		char branch[SIP_BRANCH_LEN];
		struct lan_branch *br = &f->br[f->nb];

		b = reg_find(l->reg, cand[i]);
		if (!b || (!b->reachable && nreach && !incl_unreach))
			continue;
		br->f = f;
		br->id = b->id;
		br->x = xact_start(l, b, req, &ids, branch_cb, br, branch);
		if (!br->x)
			continue;
		if (!first_branch[0])
			str_copy(first_branch, branch, sizeof(first_branch));
		f->nb++;
		f->live++;
	}
	if (!f->nb) {
		struct lan_fork **pp;

		for (pp = &l->forks; *pp; pp = &(*pp)->next)
			if (*pp == f) {
				*pp = f->next;
				break;
			}
		free(f->br);
		free(f);
		errno = ncand ? EAGAIN : ENOENT;
		return NULL;
	}
	/* branch pointers stay valid: f->br never reallocates */
	l->st.forks_started++;
	l->st.forks_active++;
	fill_sent(sent, &ids, "", first_branch);
	return f;
}

void lan_fork_cancel(struct lan_fork *f)
{
	if (f->cancelled || f->winner)
		return;
	f->cancelled = true;
	f->completed = true;
	fork_cancel_others(f, -1, NULL);
	fork_arm_abandon(f);
}

void lan_fork_detach(struct lan_fork *f)
{
	f->detached = true;
}

int lan_fork_branches(const struct lan_fork *f)
{
	return f->nb;
}

const char *lan_fork_call_id(const struct lan_fork *f)
{
	return f->call_id;
}

/* ------------------------------------------------------------------ */
/* status                                                              */

void lan_status(struct lan *l, struct lan_stats *st, lan_status_cb cb, void *arg)
{
	const struct reg_binding *b;
	reg_id_t id = REG_ID_NONE;
	uint64_t now = ev_now_ms();

	if (st) {
		*st = l->st;
		st->bindings = reg_count(l->reg);
		st->reg = *reg_get_stats(l->reg);
	}
	while (cb && (b = reg_next(l->reg, id))) {
		struct lan_binding_status s;

		id = b->id;
		memset(&s, 0, sizeof(s));
		s.id = b->id;
		s.aor = b->aor;
		s.contact = b->contact;
		s.instance = b->instance;
		s.user_agent = b->ua;
		addr_str(&b->src, s.source, sizeof(s.source));
		addr_str(&b->target, s.target, sizeof(s.target));
		s.target_from_src = b->target_from_src;
		s.expires_in = b->expires_at_ms > now ? (unsigned)((b->expires_at_ms - now + 999) / 1000) : 0;
		s.age = (unsigned)((now - b->registered_ms) / 1000);
		s.reachable = b->reachable;
		s.answered = b->answered;
		s.restored = b->restored;
		s.allow_known = b->allow_known;
		s.allow = b->allow;
		s.features = b->features;
		s.q = b->q;
		s.n_register = b->n_register;
		s.n_rx = b->n_rx;
		s.n_tx = b->n_tx;
		s.n_answered = b->n_answered;
		s.n_timeouts = b->n_timeouts;
		cb(&s, arg);
	}
}
