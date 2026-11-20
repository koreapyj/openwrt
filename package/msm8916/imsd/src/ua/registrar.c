/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "registrar.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define MAX_CONTACTS	16	/* Contact elements accepted in one REGISTER */
#define SIP_DEFAULT_PORT 5060

struct bnode {
	struct reg_binding b;
	struct bnode *next;
};

struct registrar {
	struct registrar_cfg cfg;
	struct bnode *head, *tail;
	unsigned count;
	reg_id_t next_id;
	struct ev_timer *exp_timer;
	struct ev_timer *ka_timer;
	struct reg_stats st;
};

static const struct {
	const char *name;
	uint32_t bit;
} methods[] = {
	{ "INVITE", REG_M_INVITE }, { "ACK", REG_M_ACK }, { "CANCEL", REG_M_CANCEL }, { "BYE", REG_M_BYE },
	{ "OPTIONS", REG_M_OPTIONS }, { "MESSAGE", REG_M_MESSAGE }, { "UPDATE", REG_M_UPDATE },
	{ "INFO", REG_M_INFO }, { "NOTIFY", REG_M_NOTIFY }, { "PRACK", REG_M_PRACK }, { "REFER", REG_M_REFER },
};

/* ------------------------------------------------------------------ */
/* helpers                                                             */

static void lower(char *s)
{
	for (; *s; s++)
		*s = tolower((unsigned char)*s);
}

int reg_normalize_aor(const char *uri, char *out, size_t n)
{
	struct sip_uri u;
	int r;

	if (sip_uri_parse(uri, &u))
		return -1;
	lower(u.host);
	if (u.host[0] && strchr(u.host, ':'))
		r = snprintf(out, n, "%s:%s@[%s]", u.scheme, u.user, u.host);
	else if (u.user[0])
		r = snprintf(out, n, "%s:%s@%s", u.scheme, u.user, u.host);
	else
		r = snprintf(out, n, "%s:%s", u.scheme, u.host);
	return (r < 0 || (size_t)r >= n) ? -1 : 0;
}

/* scheme:user@host:port with default port, IPv6 hosts bracketed */
static int contact_key(const char *uri, char *out, size_t n)
{
	struct sip_uri u;
	int r;

	if (sip_uri_parse(uri, &u) || !u.host[0])
		return -1;
	lower(u.host);
	r = snprintf(out, n, u.host[0] && strchr(u.host, ':') ? "%s:%s@[%s]:%u" : "%s:%s@%s:%u", u.scheme, u.user, u.host,
		     u.port ? u.port : SIP_DEFAULT_PORT);
	return (r < 0 || (size_t)r >= n) ? -1 : 0;
}

/* collect all lines of a list header, joined with ", ", into out (truncated at the last full element) */
static void join_hdr(const struct sip_msg *m, const char *name, char *out, size_t n)
{
	struct sip_list it;
	char el[128];
	size_t len = 0;

	out[0] = 0;
	sip_list_init(&it, m, name);
	while (sip_list_next(&it, el, sizeof(el)) > 0) {
		size_t l = strlen(el);

		if (len + l + 3 > n)
			break;
		if (len) {
			memcpy(out + len, ", ", 2);
			len += 2;
		}
		memcpy(out + len, el, l + 1);
		len += l;
	}
}

/* parse Allow lines of m into a mask; false if there is no Allow header */
static bool parse_allow(const struct sip_msg *m, uint32_t *mask)
{
	struct sip_list it;
	char el[32];
	size_t i;
	bool any = sip_hdr_count(m, "Allow") > 0;

	*mask = 0;
	sip_list_init(&it, m, "Allow");
	while (sip_list_next(&it, el, sizeof(el)) > 0)
		for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
			if (!strcasecmp(el, methods[i].name))
				*mask |= methods[i].bit;
	return any;
}

bool reg_allows(const struct reg_binding *b, const char *method)
{
	size_t i;

	if (!b->allow_known)
		return true;
	for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
		if (!strcasecmp(method, methods[i].name))
			return b->allow & methods[i].bit;
	return false;
}

bool reg_accepts(const struct reg_binding *b, const char *ct)
{
	const char *cur = b->accept;
	char el[64], type[64], *semi;
	size_t tl;

	if (!b->accept[0])
		return true;
	while (sip_split_next(&cur, el, sizeof(el)) > 0) {
		semi = strchr(el, ';');
		if (semi)
			*semi = 0;
		str_copy(type, el, sizeof(type));
		tl = strlen(type);
		while (tl && (type[tl - 1] == ' ' || type[tl - 1] == '\t'))
			type[--tl] = 0;
		if (!strcmp(type, "*/*") || !strcasecmp(type, ct))
			return true;
		if (tl > 2 && !strcmp(type + tl - 2, "/*") && !strncasecmp(type, ct, tl - 1))
			return true;
	}
	return false;
}

static struct bnode *find_node(const struct registrar *r, reg_id_t id)
{
	struct bnode *n;

	for (n = r->head; id && n; n = n->next)
		if (n->b.id == id)
			return n;
	return NULL;
}

static void unlink_node(struct registrar *r, struct bnode *n)
{
	struct bnode *prev = NULL, *it;

	for (it = r->head; it && it != n; it = it->next)
		prev = it;
	if (!it)
		return;
	if (prev)
		prev->next = n->next;
	else
		r->head = n->next;
	if (r->tail == n)
		r->tail = prev;
	r->count--;
}

static void emit(struct registrar *r, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why)
{
	if (r->cfg.on_event)
		r->cfg.on_event(r, ev, b, why, r->cfg.arg);
}

/* unlink and count; the node stays allocated until finish_node() */
static void detach_node(struct registrar *r, struct bnode *n, enum reg_removal why)
{
	unlink_node(r, n);
	n->next = NULL;
	r->st.removed++;
	if (why == REG_RM_EXPIRED)
		r->st.expired++;
	LOGI("registrar: binding %u removed (%s) %s", n->b.id,
	     why == REG_RM_EXPIRED ? "expired" : why == REG_RM_UNREGISTERED ? "unregistered" : "flushed", n->b.contact);
}

/* notify and free a detached node */
static void finish_node(struct registrar *r, struct bnode *n, enum reg_removal why)
{
	emit(r, REG_EV_REMOVED, &n->b, why);
	if (n->b.ep)
		sip_ep_unref(n->b.ep);
	free(n);
}

static void drop_node(struct registrar *r, struct bnode *n, enum reg_removal why)
{
	detach_node(r, n, why);
	finish_node(r, n, why);
}

/* ------------------------------------------------------------------ */
/* timers                                                              */

static void exp_rearm(struct registrar *r)
{
	struct bnode *n;
	uint64_t now = ev_now_ms(), best = 0;
	bool have = false;

	for (n = r->head; n; n = n->next)
		if (!have || n->b.expires_at_ms < best) {
			best = n->b.expires_at_ms;
			have = true;
		}
	if (!have) {
		ev_timer_cancel(r->exp_timer);
		return;
	}
	ev_timer_set(r->exp_timer, best > now ? best - now : 0);
}

static void exp_fire(void *arg)
{
	struct registrar *r = arg;
	uint64_t now = ev_now_ms();
	reg_id_t id = REG_ID_NONE;
	const struct reg_binding *b;

	/* ids are re-resolved every round: callbacks may remove other bindings */
	while ((b = reg_next(r, id))) {
		id = b->id;
		if (b->expires_at_ms <= now)
			drop_node(r, find_node(r, id), REG_RM_EXPIRED);
	}
	exp_rearm(r);
}

static void ka_fire(void *arg)
{
	struct registrar *r = arg;
	reg_id_t id = REG_ID_NONE;
	const struct reg_binding *b;

	while ((b = reg_next(r, id))) {
		id = b->id;
		if (r->cfg.ping)
			r->cfg.ping(r, id, r->cfg.arg);
	}
	if (r->cfg.keepalive_s)
		ev_timer_set(r->ka_timer, r->cfg.keepalive_s * 1000ull);
}

/* ------------------------------------------------------------------ */
/* public: lifecycle and lookup                                        */

struct registrar *registrar_new(const struct registrar_cfg *cfg)
{
	struct registrar *r = calloc(1, sizeof(*r));

	if (!r)
		return NULL;
	if (cfg)
		r->cfg = *cfg;
	if (!r->cfg.min_expires)
		r->cfg.min_expires = 60;
	if (!r->cfg.max_expires)
		r->cfg.max_expires = 3600;
	if (r->cfg.max_expires < r->cfg.min_expires)
		r->cfg.max_expires = r->cfg.min_expires;
	if (!r->cfg.default_expires)
		r->cfg.default_expires = 3600;
	if (r->cfg.default_expires > r->cfg.max_expires)
		r->cfg.default_expires = r->cfg.max_expires;
	if (r->cfg.default_expires < r->cfg.min_expires)
		r->cfg.default_expires = r->cfg.min_expires;
	if (!r->cfg.max_bindings)
		r->cfg.max_bindings = 16;
	r->next_id = 1;
	r->exp_timer = ev_timer_new(exp_fire, r);
	r->ka_timer = ev_timer_new(ka_fire, r);
	if (!r->exp_timer || !r->ka_timer) {
		ev_timer_free(r->exp_timer);
		ev_timer_free(r->ka_timer);
		free(r);
		return NULL;
	}
	if (r->cfg.keepalive_s)
		ev_timer_set(r->ka_timer, r->cfg.keepalive_s * 1000ull);
	return r;
}

void registrar_free(struct registrar *r)
{
	struct bnode *n;

	if (!r)
		return;
	while ((n = r->head)) {
		r->head = n->next;
		if (n->b.ep)
			sip_ep_unref(n->b.ep);
		free(n);
	}
	ev_timer_free(r->exp_timer);
	ev_timer_free(r->ka_timer);
	free(r);
}

unsigned reg_count(const struct registrar *r)
{
	return r->count;
}

const struct reg_binding *reg_find(const struct registrar *r, reg_id_t id)
{
	struct bnode *n = find_node(r, id);

	return n ? &n->b : NULL;
}

const struct reg_binding *reg_next(const struct registrar *r, reg_id_t after)
{
	struct bnode *n;

	for (n = r->head; n; n = n->next)
		if (n->b.id > after)
			return &n->b;
	return NULL;
}

reg_id_t reg_identify(const struct registrar *r, const struct addr *src, const char *contact_uri)
{
	const struct bnode *n, *hit = NULL;
	char key[200];
	int ipmatches = 0;

	for (n = r->head; n; n = n->next)
		if (addr_equal(&n->b.src, src) || addr_equal(&n->b.target, src))
			return n->b.id;
	if (contact_uri && !contact_key(contact_uri, key, sizeof(key)))
		for (n = r->head; n; n = n->next)
			if (!strcmp(n->b.key, key))
				return n->b.id;
	for (n = r->head; n; n = n->next)
		if (addr_equal_ip(&n->b.src, src) || addr_equal_ip(&n->b.target, src)) {
			hit = n;
			ipmatches++;
		}
	return ipmatches == 1 ? hit->b.id : REG_ID_NONE;
}

int reg_remove(struct registrar *r, reg_id_t id)
{
	struct bnode *n = find_node(r, id);

	if (!n)
		return -1;
	drop_node(r, n, REG_RM_FLUSHED);
	exp_rearm(r);
	return 0;
}

void reg_flush(struct registrar *r)
{
	while (r->head)
		drop_node(r, r->head, REG_RM_FLUSHED);
	exp_rearm(r);
}

const struct reg_stats *reg_get_stats(const struct registrar *r)
{
	return &r->st;
}

unsigned reg_min_expires(const struct registrar *r)
{
	return r->cfg.min_expires;
}

/* ------------------------------------------------------------------ */
/* bookkeeping                                                         */

void reg_set_reachable(struct registrar *r, reg_id_t id, bool ok)
{
	struct bnode *n = find_node(r, id);

	if (!n || n->b.reachable == ok)
		return;
	n->b.reachable = ok;
	LOGI("registrar: binding %u is now %s", id, ok ? "reachable" : "unreachable");
	emit(r, ok ? REG_EV_REACHABLE : REG_EV_UNREACHABLE, &n->b, REG_RM_NONE);
}

void reg_note_rx(struct registrar *r, reg_id_t id)
{
	struct bnode *n = find_node(r, id);

	if (!n)
		return;
	n->b.n_rx++;
	n->b.last_rx_ms = ev_now_ms();
	reg_set_reachable(r, id, true);
}

void reg_note_tx(struct registrar *r, reg_id_t id)
{
	struct bnode *n = find_node(r, id);

	if (n)
		n->b.n_tx++;
}

void reg_note_response(struct registrar *r, reg_id_t id, const struct sip_msg *resp)
{
	struct bnode *n = find_node(r, id);
	uint32_t mask;

	if (!n)
		return;
	n->b.answered = true;
	n->b.n_answered++;
	n->b.last_rx_ms = ev_now_ms();
	if (resp && parse_allow(resp, &mask)) {
		n->b.allow = mask;
		n->b.allow_known = true;
	}
	reg_set_reachable(r, id, true);
}

void reg_note_timeout(struct registrar *r, reg_id_t id)
{
	struct bnode *n = find_node(r, id);

	if (!n)
		return;
	n->b.n_timeouts++;
	reg_set_reachable(r, id, false);
}

/* ------------------------------------------------------------------ */
/* REGISTER                                                            */

struct pcontact {
	char uri[256];
	char key[200];
	char instance[96];
	uint32_t features;
	unsigned expires;
	bool remove;
	int q;
	struct bnode *match;
};

enum { EVQ_ADD, EVQ_REFRESH };
struct evq {
	int kind;
	reg_id_t id;
};

static void fmt_date(char *out, size_t n)
{
	static const char *const wd[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	static const char *const mo[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	time_t t = time(NULL);
	struct tm tm;

	out[0] = 0;
	if (t < 1500000000)	/* clock not set (no NTP yet): do not lie */
		return;
	gmtime_r(&t, &tm);
	snprintf(out, n, "Date: %s, %02d %s %04d %02d:%02d:%02d GMT\r\n", wd[tm.tm_wday], tm.tm_mday, mo[tm.tm_mon],
		 tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int reply_simple(struct registrar *r, struct txn_server *st, int status, const char *extra)
{
	struct sip_resp_parts p;

	(void)r;
	memset(&p, 0, sizeof(p));
	p.status = status;
	p.extra = extra;
	txn_server_reply(st, &p);
	return status;
}

static int q_parse(const char *s)
{
	double d = strtod(s, NULL);

	if (d < 0)
		d = 0;
	if (d > 1)
		d = 1;
	return (int)(d * 1000.0 + 0.5);
}

/* where requests go; see header */
static void pick_target(struct reg_binding *b, const struct addr *src)
{
	struct sip_uri u;
	struct addr ca;

	b->target = *src;
	b->target_from_src = true;
	if (sip_uri_parse(b->contact, &u) || !u.host[0])
		return;
	if (addr_set(&ca, u.host, u.port ? u.port : SIP_DEFAULT_PORT))
		return;		/* a host name: we never resolve, use the source */
	if (addr_equal_ip(&ca, src)) {
		b->target = ca;
		b->target_from_src = false;
	} else {
		char a[64], c[64];

		addr_str(src, a, sizeof(a));
		addr_str(&ca, c, sizeof(c));
		LOGI("registrar: Contact host %s differs from source %s, using the source address", c, a);
	}
}

static bool feature_tag(const char *params, const char *name)
{
	char v[16];
	int r = sip_params_get(params, name, v, sizeof(v));

	if (r <= 0)
		return r < 0;		/* a value that does not fit is not "0" */
	return strcmp(v, "0") && strcasecmp(v, "false");
}

static int body_contacts(struct registrar *r, const struct sip_msg *req, struct pcontact *pc, int *n, bool *star,
			 long hdr_exp, unsigned *min_exp_out)
{
	struct sip_list it;
	char el[512], v[64];
	int rc;

	*n = 0;
	*star = false;
	sip_list_init(&it, req, "Contact");
	while ((rc = sip_list_next(&it, el, sizeof(el))) > 0) {
		struct sip_nameaddr na;
		struct pcontact *c;
		long ex;

		if (!strcmp(el, "*")) {
			*star = true;
			continue;
		}
		if (*n >= MAX_CONTACTS || sip_nameaddr_parse(el, &na) || contact_key(na.uri, el, sizeof(pc->key)))
			return 400;
		c = &pc[(*n)++];
		memset(c, 0, sizeof(*c));
		str_copy(c->uri, na.uri, sizeof(c->uri));
		contact_key(na.uri, c->key, sizeof(c->key));
		c->q = 1000;
		if (sip_params_get(na.params, "q", v, sizeof(v)) > 0)
			c->q = q_parse(v);
		if (sip_params_get(na.params, "+sip.instance", c->instance, sizeof(c->instance)) < 0)
			c->instance[0] = 0;
		if (feature_tag(na.params, "+g.imsd.mms"))
			c->features |= REG_F_MMS;
		if (feature_tag(na.params, "+g.imsd.carbons"))
			c->features |= REG_F_CARBONS;
		ex = hdr_exp >= 0 ? hdr_exp : (long)r->cfg.default_expires;
		if (sip_params_get(na.params, "expires", v, sizeof(v)) > 0) {
			char *end;

			ex = strtol(v, &end, 10);
			if (end == v || ex < 0)
				return 400;
		}
		if (ex == 0)
			c->remove = true;
		else if (ex < (long)r->cfg.min_expires) {
			*min_exp_out = r->cfg.min_expires;
			return 423;
		} else if (ex > (long)r->cfg.max_expires)
			ex = r->cfg.max_expires;
		c->expires = c->remove ? 0 : (unsigned)ex;
	}
	return rc < 0 ? 400 : 0;
}

static struct bnode *match_binding(struct registrar *r, const char *aor, const struct pcontact *c)
{
	struct bnode *n, *inst = NULL;

	for (n = r->head; n; n = n->next) {
		if (strcmp(n->b.aor, aor))
			continue;
		if (!strcmp(n->b.key, c->key))
			return n;
		if (c->instance[0] && !strcmp(n->b.instance, c->instance) && !inst)
			inst = n;
	}
	return inst;
}

static int reply_bindings(struct registrar *r, struct txn_server *st, const char *aor)
{
	struct bnode *n;
	struct buf b;
	char date[64];
	struct sip_resp_parts p;
	uint64_t now = ev_now_ms();
	int rc;

	buf_init(&b, 8192);
	for (n = r->head; n; n = n->next) {
		unsigned left;

		if (strcmp(n->b.aor, aor))
			continue;
		left = n->b.expires_at_ms > now ? (unsigned)((n->b.expires_at_ms - now + 999) / 1000) : 0;
		buf_printf(&b, "Contact: <%s>;expires=%u", n->b.contact, left);
		if (n->b.q != 1000)
			buf_printf(&b, ";q=%d.%03d", n->b.q / 1000, n->b.q % 1000);
		if (n->b.instance[0])
			buf_printf(&b, ";+sip.instance=\"%s\"", n->b.instance);
		if (n->b.features & REG_F_MMS)
			buf_puts(&b, ";+g.imsd.mms");
		if (n->b.features & REG_F_CARBONS)
			buf_puts(&b, ";+g.imsd.carbons");
		buf_puts(&b, "\r\n");
	}
	fmt_date(date, sizeof(date));
	buf_puts(&b, date);
	memset(&p, 0, sizeof(p));
	p.status = 200;
	p.extra = buf_cstr(&b);
	if (!buf_ok(&b)) {
		buf_free(&b);
		return reply_simple(r, st, 500, NULL);
	}
	rc = txn_server_reply(st, &p);
	(void)rc;
	buf_free(&b);
	return 200;
}

/* X-IMSD-Ack-Seq: a plain decimal number (surrounding blanks allowed) */
static uint8_t parse_ack_seq(const struct sip_msg *req, uint64_t *out)
{
	const char *h = sip_hdr(req, "X-IMSD-Ack-Seq", 0);
	uint64_t v = 0;
	size_t n;

	*out = 0;
	if (!h)
		return REG_ACK_NONE;
	while (*h == ' ' || *h == '\t')
		h++;
	for (n = 0; h[n] >= '0' && h[n] <= '9'; n++) {
		unsigned d = (unsigned)(h[n] - '0');

		if (n >= 20 || v > (UINT64_MAX - d) / 10)
			return REG_ACK_BAD;
		v = v * 10 + d;
	}
	if (!n)
		return REG_ACK_BAD;
	while (h[n] == ' ' || h[n] == '\t')
		n++;
	if (h[n])
		return REG_ACK_BAD;
	*out = v;
	return REG_ACK_OK;
}

int reg_handle_register(struct registrar *r, struct txn_server *st, struct sip_endpoint *ep,
			const struct addr *src, const struct sip_msg *req)
{
	const char *to = sip_hdr(req, "To", 0), *cid = sip_hdr(req, "Call-ID", 0), *h;
	char aor[160], uri[256], ua[96], accept[96], supported[96];
	char cseq_m[16];
	struct pcontact pc[MAX_CONTACTS];
	struct evq evq[MAX_CONTACTS];
	struct bnode *gone[MAX_CONTACTS * 2];
	int ngone = 0;
	int nc = 0, nq = 0, rc, i, adds = 0, rms = 0;
	bool star = false, allow_known;
	uint32_t cseq, allow;
	uint8_t ack_state;
	uint64_t ack_seq;
	long hdr_exp = -1;
	unsigned min_exp = 0;
	uint64_t now = ev_now_ms();
	char extra[48];

	r->st.registers++;
	if (!to || !cid || sip_uri_of(to, uri, sizeof(uri)) || reg_normalize_aor(uri, aor, sizeof(aor)) ||
	    sip_cseq(req, &cseq, cseq_m, sizeof(cseq_m)) || strcasecmp(cseq_m, "REGISTER") || strlen(cid) >= sizeof(((struct reg_binding *)0)->call_id)) {
		r->st.rejected_400++;
		return reply_simple(r, st, 400, NULL);
	}
	/* Require: only tokens we can honour; outbound is accepted (instance handling) without its flow semantics */
	{
		struct sip_list it;
		char tok[48];

		sip_list_init(&it, req, "Require");
		while (sip_list_next(&it, tok, sizeof(tok)) > 0) {
			char unsup[96];

			if (!strcasecmp(tok, "outbound") || !strcasecmp(tok, "path"))
				continue;
			snprintf(unsup, sizeof(unsup), "Unsupported: %s\r\n", tok);
			r->st.rejected_400++;
			return reply_simple(r, st, 420, unsup);
		}
	}
	h = sip_hdr(req, "Expires", 0);
	if (h) {
		char *end;

		hdr_exp = strtol(h, &end, 10);
		if (end == h || hdr_exp < 0)
			hdr_exp = -1;	/* SIP-date or junk: treat as absent */
	}
	rc = body_contacts(r, req, pc, &nc, &star, hdr_exp, &min_exp);
	if (rc == 423) {
		snprintf(extra, sizeof(extra), "Min-Expires: %u\r\n", min_exp);
		r->st.rejected_423++;
		LOGI("registrar: REGISTER from device rejected: interval too brief (min %u)", min_exp);
		return reply_simple(r, st, 423, extra);
	}
	if (rc || (star && (nc || hdr_exp != 0 || sip_hdr_count(req, "Contact") != 1))) {
		r->st.rejected_400++;
		return reply_simple(r, st, 400, NULL);
	}
	if (!star && !nc) {
		r->st.queries++;
		return reply_bindings(r, st, aor);
	}

	/* ---- validate everything before changing anything ---- */
	if (star) {
		struct bnode *n;

		for (n = r->head; n; n = n->next)
			if (!strcmp(n->b.aor, aor) && !strcmp(n->b.call_id, cid) && cseq < n->b.cseq) {
				r->st.rejected_500++;
				return reply_simple(r, st, 500, NULL);
			}
	}
	for (i = 0; i < nc; i++) {
		pc[i].match = match_binding(r, aor, &pc[i]);
		if (pc[i].match && !strcmp(pc[i].match->b.call_id, cid) && cseq < pc[i].match->b.cseq) {
			LOGI("registrar: REGISTER CSeq %u older than %u for binding %u", cseq, pc[i].match->b.cseq,
			     pc[i].match->b.id);
			r->st.rejected_500++;
			return reply_simple(r, st, 500, NULL);
		}
		if (pc[i].remove) {
			if (pc[i].match)
				rms++;
		} else if (!pc[i].match) {
			int j, dup = 0;

			for (j = 0; j < i; j++)
				if (!strcmp(pc[j].key, pc[i].key) && !pc[j].remove)
					dup = 1;
			if (!dup)
				adds++;
		}
	}
	if (star) {
		struct bnode *n;

		for (n = r->head; n; n = n->next)
			if (!strcmp(n->b.aor, aor))
				rms++;
	}
	if (r->count + adds > r->cfg.max_bindings + (unsigned)rms) {
		LOGW("registrar: binding table full (%u), rejecting REGISTER for %s with 503", r->cfg.max_bindings, aor);
		r->st.rejected_503++;
		return reply_simple(r, st, 503, "Retry-After: 300\r\n");
	}

	/* ---- apply ---- */
	h = sip_hdr(req, "User-Agent", 0);
	str_copy(ua, h ? h : "", sizeof(ua));
	join_hdr(req, "Accept", accept, sizeof(accept));
	join_hdr(req, "Supported", supported, sizeof(supported));
	allow_known = parse_allow(req, &allow);
	ack_state = parse_ack_seq(req, &ack_seq);

	if (star) {
		struct bnode *n, *nx;

		for (n = r->head; n; n = nx) {
			nx = n->next;
			if (!strcmp(n->b.aor, aor) && ngone < MAX_CONTACTS * 2) {
				detach_node(r, n, REG_RM_UNREGISTERED);
				gone[ngone++] = n;
			}
		}
	}
	for (i = 0; i < nc && nq < MAX_CONTACTS; i++) {
		struct bnode *n = pc[i].match;
		struct reg_binding *b;
		bool is_new = false;

		if (pc[i].remove) {
			if (n && find_node(r, n->b.id) && ngone < MAX_CONTACTS * 2) {
				detach_node(r, n, REG_RM_UNREGISTERED);
				gone[ngone++] = n;
			}
			continue;
		}
		if (n && !find_node(r, n->b.id))
			n = NULL;	/* removed earlier in this very request */
		if (!n) {
			/* a second contact of this request may already have created it */
			n = match_binding(r, aor, &pc[i]);
		}
		if (!n) {
			n = calloc(1, sizeof(*n));
			if (!n) {
				r->st.rejected_503++;
				return reply_simple(r, st, 503, NULL);
			}
			n->b.id = r->next_id++;
			if (r->tail)
				r->tail->next = n;
			else
				r->head = n;
			r->tail = n;
			r->count++;
			is_new = true;
			n->b.registered_ms = now;
			n->b.reachable = true;
			str_copy(n->b.aor, aor, sizeof(n->b.aor));
		}
		b = &n->b;
		str_copy(b->contact, pc[i].uri, sizeof(b->contact));
		str_copy(b->key, pc[i].key, sizeof(b->key));
		str_copy(b->instance, pc[i].instance, sizeof(b->instance));
		b->features = pc[i].features;
		b->ack_state = ack_state;
		b->ack_seq = ack_seq;
		str_copy(b->ua, ua, sizeof(b->ua));
		str_copy(b->accept, accept, sizeof(b->accept));
		str_copy(b->supported, supported, sizeof(b->supported));
		str_copy(b->call_id, cid, sizeof(b->call_id));
		b->cseq = cseq;
		b->src = *src;
		pick_target(b, src);
		if (b->ep != ep) {
			if (b->ep)
				sip_ep_unref(b->ep);
			b->ep = sip_ep_ref(ep);
		}
		b->refreshed_ms = now;
		b->expires_s = pc[i].expires;
		b->expires_at_ms = now + pc[i].expires * 1000ull;
		b->q = pc[i].q;
		b->n_register++;
		b->restored = false;
		b->last_rx_ms = now;
		if (allow_known) {
			b->allow = allow;
			b->allow_known = true;
		}
		evq[nq].kind = is_new ? EVQ_ADD : EVQ_REFRESH;
		evq[nq++].id = b->id;
		if (is_new)
			LOGI("registrar: new binding %u %s (%s) expires %us", b->id, b->contact, ua[0] ? ua : "?", b->expires_s);
		pc[i].match = n;
	}
	r->st.ok++;
	/* reply first (it reflects the table after the update), then tell the others */
	rc = reply_bindings(r, st, aor);
	for (i = 0; i < nq; i++) {
		struct bnode *n = find_node(r, evq[i].id);

		if (!n)
			continue;
		if (evq[i].kind == EVQ_ADD) {
			r->st.added++;
			emit(r, REG_EV_ADDED, &n->b, REG_RM_NONE);
		} else {
			r->st.refreshed++;
			emit(r, REG_EV_REFRESHED, &n->b, REG_RM_NONE);
		}
	}
	for (i = 0; i < ngone; i++)
		finish_node(r, gone[i], REG_RM_UNREGISTERED);
	exp_rearm(r);
	return rc;
}

int reg_restore(struct registrar *r, const struct reg_binding *in, struct sip_endpoint *ep, unsigned remain_s)
{
	struct pcontact pc;
	struct bnode *n;
	struct reg_binding *b;
	uint64_t now = ev_now_ms();

	memset(&pc, 0, sizeof(pc));
	if (!in || !ep || !remain_s || !in->aor[0] || contact_key(in->contact, pc.key, sizeof(pc.key)))
		return -EINVAL;
	str_copy(pc.instance, in->instance, sizeof(pc.instance));
	if (match_binding(r, in->aor, &pc))
		return -EEXIST;
	if (r->count >= r->cfg.max_bindings)
		return -ENOSPC;
	n = calloc(1, sizeof(*n));
	if (!n)
		return -ENOMEM;
	b = &n->b;
	*b = *in;
	b->id = r->next_id++;
	b->ep = sip_ep_ref(ep);
	str_copy(b->key, pc.key, sizeof(b->key));
	b->restored = true;
	b->reachable = true;
	b->refreshed_ms = now;
	b->expires_at_ms = now + remain_s * 1000ull;
	b->n_register = b->n_rx = b->n_tx = b->n_answered = b->n_timeouts = 0;
	b->last_rx_ms = now;
	if (b->registered_ms > now)
		b->registered_ms = now;
	if (r->tail)
		r->tail->next = n;
	else
		r->head = n;
	r->tail = n;
	r->count++;
	r->st.added++;
	LOGI("registrar: restored binding %u %s (%s) expires in %us", b->id, b->contact, b->ua[0] ? b->ua : "?", remain_s);
	emit(r, REG_EV_ADDED, &n->b, REG_RM_NONE);
	exp_rearm(r);
	return 0;
}
