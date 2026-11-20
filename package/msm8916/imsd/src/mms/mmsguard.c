/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The nftables traffic guard of the MMS bearer, see mmsguard.h. */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mmsguard.h"
#include "../util/evloop.h"
#include "../util/log.h"

#define POLL_MS		5000
#define MAX_ALLOWED	32
#define MAX_JOBS	8

enum jk { JK_INSTALL, JK_ARM, JK_GATE, JK_LIST_FINAL, JK_DELETE };

struct job {
	enum jk kind;
	char *script;
	void (*done)(void *arg, int err);
	void *arg;
};

struct gwait {
	struct gwait *next;
	struct addr dst;
	void (*done)(void *arg, int err);
	void *arg;
};

struct mmsguard {
	struct guard_exec_ops x;
	void (*lost)(void *arg);
	void *arg;
	void *run;		/* handle of the child in flight */
	struct job cur;		/* the job it runs */
	bool busy;		/* a child is in flight (or a start failure is being delivered) */
	bool polling;		/* the child in flight is a counter poll */
	int fail_status;	/* start failure to deliver from t_defer */
	struct ev_timer *t_defer;
	struct job q[MAX_JOBS];
	unsigned nq;
	struct gwait *gw;	/* waiting for their destination to be allowed */
	struct gwait *gcur;	/* ... being allowed by the job in flight */
	struct addr allowed[MAX_ALLOWED];
	unsigned nallowed;
	bool installed, armed, lost_sent;
	bool dirty;			/* an install was started and the table has not been deleted since: remove must really delete */
	struct ev_timer *t_poll;
	struct guard_stats st;
	unsigned long base_acc, base_drp;	/* of earlier sessions */
	unsigned long cur_acc, cur_drp;		/* of the table now */
};

size_t mmsguard_script_install(char *out, size_t n)
{
	int l = snprintf(out, n,
		"add table inet " GUARD_TABLE "\n"
		"delete table inet " GUARD_TABLE "\n"
		"table inet " GUARD_TABLE " {\n"
		"\tcounter acc { packets 0 bytes 0 }\n"
		"\tcounter drp { packets 0 bytes 0 }\n"
		"\tset ifs { type ifname; }\n"
		"\tset dns4 { type ipv4_addr; }\n"
		"\tset dns6 { type ipv6_addr; }\n"
		"\tset tcp4 { type ipv4_addr . inet_service; }\n"
		"\tset tcp6 { type ipv6_addr . inet_service; }\n"
		"\tchain mmsoutput {\n"
		"\t\ttype filter hook output priority -10; policy accept;\n"
		"\t\toifname @ifs jump mmsout\n"
		"\t}\n"
		"\tchain mmsout {\n"
		"\t\tip daddr @dns4 udp dport 53 counter name \"acc\" accept\n"
		"\t\tip daddr @dns4 tcp dport 53 counter name \"acc\" accept\n"
		"\t\tip6 daddr @dns6 udp dport 53 counter name \"acc\" accept\n"
		"\t\tip6 daddr @dns6 tcp dport 53 counter name \"acc\" accept\n"
		"\t\tip daddr . tcp dport @tcp4 counter name \"acc\" accept\n"
		"\t\tip6 daddr . tcp dport @tcp6 counter name \"acc\" accept\n"
		"\t\tcounter name \"drp\" drop\n"
		"\t}\n"
		"\tchain mmsfwd {\n"
		"\t\ttype filter hook forward priority -10; policy accept;\n"
		"\t\tiifname @ifs counter name \"drp\" drop\n"
		"\t\toifname @ifs counter name \"drp\" drop\n"
		"\t}\n"
		"}\n");
	return l > 0 && (size_t)l < n ? (size_t)l : 0;
}

static void set_err(struct mmsguard *g, const char *what, int status)
{
	if (status < 0)
		snprintf(g->st.last_error, sizeof(g->st.last_error), "%s: %s", what, strerror(-status));
	else
		snprintf(g->st.last_error, sizeof(g->st.last_error), "%s: nft exit status %d", what, status);
}

static void pump(struct mmsguard *g);

static void tell_lost(struct mmsguard *g)
{
	if (g->lost_sent || !g->installed)
		return;
	g->lost_sent = true;
	g->installed = g->armed = false;
	g->st.installed = g->st.armed = false;
	LOGW("mms: traffic guard lost (%s)", g->st.last_error);
	if (g->lost)
		g->lost(g->arg);
}

/* "counter acc {\n\t\tpackets N bytes M" -> N */
static bool parse_counter(const char *out, const char *name, unsigned long *pk)
{
	char key[32];
	const char *p;

	snprintf(key, sizeof(key), "counter %s ", name);
	p = strstr(out, key);
	if (!p)
		return false;
	p = strstr(p, "packets ");
	if (!p)
		return false;
	*pk = strtoul(p + 8, NULL, 10);
	return true;
}

static void job_free(struct job *j)
{
	free(j->script);
	memset(j, 0, sizeof(*j));
}

static void on_exit_cb(void *arg, int status, const char *out)
{
	struct mmsguard *g = arg;
	struct job j = g->cur;
	struct gwait *w = g->gcur;
	bool polling = g->polling;
	int err = status == 0 ? 0 : status < 0 ? status : -EPROTO;
	unsigned long a, d;

	g->run = NULL;
	g->busy = false;
	g->polling = false;
	memset(&g->cur, 0, sizeof(g->cur));
	g->gcur = NULL;
	if (polling) {
		if (!status && out && parse_counter(out, "acc", &a) && parse_counter(out, "drp", &d)) {
			g->cur_acc = a;
			g->cur_drp = d;
			g->st.accepted = g->base_acc + a;
			g->st.dropped = g->base_drp + d;
		} else if (g->installed) {
			set_err(g, "counter poll", status ? status : -ENOENT);
			g->st.failures++;
			tell_lost(g);
		}
		pump(g);
		return;
	}
	if (j.kind == JK_LIST_FINAL) {
		if (!status && out && parse_counter(out, "acc", &a) && parse_counter(out, "drp", &d)) {
			g->base_acc += a;
			g->base_drp += d;
			g->st.accepted = g->base_acc;
			g->st.dropped = g->base_drp;
		}
		g->cur_acc = g->cur_drp = 0;
		job_free(&j);		/* a failed read does not matter: the delete follows */
		pump(g);
		return;
	}
	if (err) {
		if (j.kind == JK_DELETE)
			g->dirty = false;	/* said at once, the table could not be deleted (or was not there): nothing more to try */
		set_err(g, j.kind == JK_INSTALL ? "install" : j.kind == JK_ARM ? "arm" : j.kind == JK_GATE ? "allow" : "delete", status);
		g->st.failures++;
		LOGW("mms: traffic guard: %s", g->st.last_error);
	} else if (j.kind == JK_INSTALL) {
		g->installed = true;
		g->armed = false;
		g->lost_sent = false;
		g->nallowed = 0;
		g->cur_acc = g->cur_drp = 0;
		g->st.installed = true;
		g->st.armed = false;
		g->st.installs++;
		ev_timer_set(g->t_poll, POLL_MS);
	} else if (j.kind == JK_ARM) {
		g->armed = true;
		g->st.armed = true;
	} else if (j.kind == JK_DELETE) {
		g->dirty = false;
		g->installed = g->armed = false;
		g->st.installed = g->st.armed = false;
		g->nallowed = 0;
		ev_timer_cancel(g->t_poll);
	}
	while (w) {
		struct gwait *n = w->next;

		if (!err && g->nallowed < MAX_ALLOWED)
			g->allowed[g->nallowed++] = w->dst;
		if (w->done)
			w->done(w->arg, err);
		free(w);
		w = n;
	}
	if (j.done)
		j.done(j.arg, err);
	job_free(&j);
	pump(g);
}

static const char *const ARGV_STDIN[] = { "nft", "-f", "-", NULL };
static const char *const ARGV_LIST[] = { "nft", "list", "table", "inet", GUARD_TABLE, NULL };

static void start(struct mmsguard *g, const char *const *argv, const char *script)
{
	g->busy = true;
	g->run = g->x.run(g->x.ctx, argv, script, on_exit_cb, g);
	if (!g->run) {		/* nothing started: the failure is reported from the loop like a failed child */
		g->fail_status = errno ? -errno : -EIO;
		ev_timer_set(g->t_defer, 0);
	}
}

static void on_defer(void *arg)
{
	struct mmsguard *g = arg;

	if (g->busy && !g->run)
		on_exit_cb(g, g->fail_status, "");
}

static void on_poll(void *arg)
{
	struct mmsguard *g = arg;

	if (!g->installed)
		return;
	ev_timer_set(g->t_poll, POLL_MS);
	if (g->busy || g->nq || g->gw)
		return;
	g->polling = true;
	start(g, ARGV_LIST, NULL);
}

static char *build_gate_script(struct gwait *w)
{
	char v4[512] = "", v6[512] = "", h[64], *out;
	size_t l4 = 0, l6 = 0;

	for (; w; w = w->next) {
		bool is4 = addr_family(&w->dst) == AF_INET;
		char *b = is4 ? v4 : v6;
		size_t *l = is4 ? &l4 : &l6;
		int n;

		if (addr_host(&w->dst, h, sizeof(h)))
			continue;
		n = snprintf(b + *l, 512 - *l, "%s%s . %u", *l ? ", " : "", h, (unsigned)addr_port(&w->dst));
		if (n < 0 || (size_t)n >= 512 - *l)
			continue;
		*l += (size_t)n;
	}
	out = malloc(1200);
	if (!out)
		return NULL;
	out[0] = 0;
	if (l4)
		snprintf(out + strlen(out), 1200 - strlen(out), "add element inet " GUARD_TABLE " tcp4 { %s }\n", v4);
	if (l6)
		snprintf(out + strlen(out), 1200 - strlen(out), "add element inet " GUARD_TABLE " tcp6 { %s }\n", v6);
	return out;
}

static void pump(struct mmsguard *g)
{
	if (g->busy)
		return;
	if (g->nq) {
		struct job j = g->q[0];

		memmove(&g->q[0], &g->q[1], sizeof(g->q[0]) * (g->nq - 1));
		g->nq--;
		g->cur = j;
		if (j.kind == JK_LIST_FINAL)
			start(g, ARGV_LIST, NULL);
		else
			start(g, ARGV_STDIN, j.script);
		return;
	}
	if (g->gw) {
		char *sc = build_gate_script(g->gw);

		g->gcur = g->gw;
		g->gw = NULL;
		memset(&g->cur, 0, sizeof(g->cur));
		g->cur.kind = JK_GATE;
		g->cur.script = sc;
		if (!sc) {
			g->busy = true;
			g->fail_status = -ENOMEM;
			g->run = NULL;
			ev_timer_set(g->t_defer, 0);
			return;
		}
		start(g, ARGV_STDIN, sc);
	}
}

static int enqueue(struct mmsguard *g, enum jk kind, char *script, void (*done)(void *, int), void *arg)
{
	if (!script)
		return -ENOMEM;
	if (g->nq >= MAX_JOBS) {
		free(script);
		return -EBUSY;
	}
	g->q[g->nq].kind = kind;
	g->q[g->nq].script = script;
	g->q[g->nq].done = done;
	g->q[g->nq].arg = arg;
	g->nq++;
	pump(g);
	return 0;
}

struct mmsguard *mmsguard_new(const struct guard_exec_ops *x, void (*lost)(void *arg), void *arg)
{
	struct mmsguard *g = calloc(1, sizeof(*g));

	if (!g)
		return NULL;
	g->x = *x;
	g->lost = lost;
	g->arg = arg;
	g->t_poll = ev_timer_new(on_poll, g);
	g->t_defer = ev_timer_new(on_defer, g);
	if (!g->t_poll || !g->t_defer) {
		mmsguard_free(g);
		return NULL;
	}
	return g;
}

void mmsguard_free(struct mmsguard *g)
{
	unsigned i;

	if (!g)
		return;
	if (g->run && g->x.cancel)
		g->x.cancel(g->x.ctx, g->run);
	ev_timer_free(g->t_poll);
	ev_timer_free(g->t_defer);
	for (i = 0; i < g->nq; i++)
		free(g->q[i].script);
	free(g->cur.script);
	while (g->gw) {
		struct gwait *n = g->gw->next;

		free(g->gw);
		g->gw = n;
	}
	while (g->gcur) {
		struct gwait *n = g->gcur->next;

		free(g->gcur);
		g->gcur = n;
	}
	free(g);
}

int mmsguard_install(struct mmsguard *g, void (*done)(void *arg, int err), void *arg)
{
	char *s = malloc(2048);

	if (s && !mmsguard_script_install(s, 2048)) {
		free(s);
		s = NULL;
	}
	g->dirty = true;
	return enqueue(g, JK_INSTALL, s, done, arg);
}

static bool ifname_ok(const char *s)
{
	size_t i;

	if (!s[0] || strlen(s) > 15)
		return false;
	for (i = 0; s[i]; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '.' && s[i] != '-')
			return false;
	return true;
}

int mmsguard_arm(struct mmsguard *g, const char *ifname, const struct addr *dns, int n_dns, void (*done)(void *arg, int err), void *arg)
{
	char *s;
	char v4[256] = "", v6[256] = "", h[64];
	int i;

	if (!g->installed || !ifname_ok(ifname))
		return -EINVAL;
	for (i = 0; i < n_dns && i < 4; i++) {
		char *b = addr_family(&dns[i]) == AF_INET ? v4 : v6;

		if (addr_host(&dns[i], h, sizeof(h)))
			continue;
		snprintf(b + strlen(b), 256 - strlen(b), "%s%s", b[0] ? ", " : "", h);
	}
	s = malloc(1024);
	if (!s)
		return -ENOMEM;
	snprintf(s, 1024, "add element inet " GUARD_TABLE " ifs { \"%s\" }\n", ifname);
	if (v4[0])
		snprintf(s + strlen(s), 1024 - strlen(s), "add element inet " GUARD_TABLE " dns4 { %s }\n", v4);
	if (v6[0])
		snprintf(s + strlen(s), 1024 - strlen(s), "add element inet " GUARD_TABLE " dns6 { %s }\n", v6);
	return enqueue(g, JK_ARM, s, done, arg);
}

int mmsguard_gate(struct mmsguard *g, const struct addr *dst, void (*done)(void *arg, int err), void *arg)
{
	struct gwait *w;
	unsigned i;

	if (!g->installed || !g->armed)
		return -ENETDOWN;
	for (i = 0; i < g->nallowed; i++)
		if (addr_equal(&g->allowed[i], dst))
			return 0;
	w = calloc(1, sizeof(*w));
	if (!w)
		return -ENOMEM;
	w->dst = *dst;
	w->done = done;
	w->arg = arg;
	w->next = g->gw;
	g->gw = w;
	pump(g);
	return 1;
}

void mmsguard_gate_cancel(struct mmsguard *g, void *arg)
{
	struct gwait **pp, *w;

	for (pp = &g->gw; (w = *pp);) {
		if (w->arg == arg) {
			*pp = w->next;
			free(w);
		} else {
			pp = &w->next;
		}
	}
	for (w = g->gcur; w; w = w->next)
		if (w->arg == arg)
			w->done = NULL;
}

void mmsguard_remove(struct mmsguard *g, void (*done)(void *arg, int err), void *arg)
{
	char *s;
	int rc;

	if (!g->installed && !g->dirty && !g->busy && !g->nq) {
		if (done)
			done(arg, 0);
		return;
	}
	ev_timer_cancel(g->t_poll);
	if (g->installed) {
		s = strdup("");
		enqueue(g, JK_LIST_FINAL, s, NULL, NULL);	/* a failure only costs the last counters */
	}
	s = strdup("destroy table inet " GUARD_TABLE "\n");
	rc = enqueue(g, JK_DELETE, s, done, arg);
	if (rc && done)
		done(arg, rc);
}

void mmsguard_stats(const struct mmsguard *g, struct guard_stats *out)
{
	*out = g->st;
}

bool mmsguard_installed(const struct mmsguard *g)
{
	return g->installed;
}
