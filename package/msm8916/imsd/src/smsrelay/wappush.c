/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WAP Push reassembly, see wappush.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wappush.h"
#include "../smscodec/tpdu.h"
#include "../util/evloop.h"
#include "../util/log.h"

struct msg {
	bool used;
	char from[TP_ADDR_MAX];
	uint16_t ref;
	unsigned total, got, port;
	uint64_t t0;
	uint16_t mask;
	uint8_t len[WAPPUSH_MAX_SEG];
	uint8_t data[WAPPUSH_MAX_SEG][WAPPUSH_SEG_MAX];
};

struct wappush {
	struct msg m[WAPPUSH_MAX_MSG];
	wappush_cb cb;
	void *arg;
	struct ev_timer *timer;
};

static void arm(struct wappush *w);

static void on_timer(void *arg)
{
	struct wappush *w = arg;
	uint64_t now = ev_now_ms();
	int i;

	for (i = 0; i < WAPPUSH_MAX_MSG; i++) {
		struct msg *m = &w->m[i];

		if (m->used && now - m->t0 >= WAPPUSH_TIMEOUT_MS) {
			LOGI("sms: WAP push from %s (ref %u): %u of %u segments after %u s, dropped", m->from, m->ref, m->got, m->total,
			     WAPPUSH_TIMEOUT_MS / 1000);
			m->used = false;
		}
	}
	arm(w);
}

static void arm(struct wappush *w)
{
	uint64_t now = ev_now_ms(), first = 0;
	int i;

	for (i = 0; i < WAPPUSH_MAX_MSG; i++)
		if (w->m[i].used && (!first || w->m[i].t0 < first))
			first = w->m[i].t0;
	if (!first) {
		ev_timer_cancel(w->timer);
		return;
	}
	ev_timer_set(w->timer, first + WAPPUSH_TIMEOUT_MS > now ? first + WAPPUSH_TIMEOUT_MS - now : 0);
}

struct wappush *wappush_new(wappush_cb cb, void *arg)
{
	struct wappush *w = calloc(1, sizeof(*w));

	if (!w)
		return NULL;
	w->cb = cb;
	w->arg = arg;
	w->timer = ev_timer_new(on_timer, w);
	if (!w->timer) {
		free(w);
		return NULL;
	}
	return w;
}

void wappush_free(struct wappush *w)
{
	if (!w)
		return;
	ev_timer_free(w->timer);
	free(w);
}

static struct msg *find(const struct wappush *w, const char *from, uint16_t ref, unsigned total)
{
	int i;

	for (i = 0; i < WAPPUSH_MAX_MSG; i++) {
		const struct msg *m = &w->m[i];

		if (m->used && m->ref == ref && m->total == total && !strcmp(m->from, from))
			return (struct msg *)m;
	}
	return NULL;
}

bool wappush_pending(const struct wappush *w, const char *from, uint16_t ref, unsigned total)
{
	return find(w, from, ref, total) != NULL;
}

unsigned wappush_count(const struct wappush *w)
{
	unsigned i, n = 0;

	for (i = 0; i < WAPPUSH_MAX_MSG; i++)
		n += w->m[i].used;
	return n;
}

int wappush_segment(struct wappush *w, const char *from, unsigned port, uint16_t ref, unsigned total, unsigned seq,
		    const uint8_t *data, size_t len)
{
	struct msg *m;
	uint8_t *buf, *o;
	size_t n = 0;
	unsigned i;

	if (len > WAPPUSH_SEG_MAX) {
		LOGI("sms: WAP push segment of %zu bytes refused", len);
		return -1;
	}
	if (total <= 1) {
		w->cb(w->arg, from, port, data, len);
		return 0;
	}
	if (total > WAPPUSH_MAX_SEG || seq < 1 || seq > total) {
		LOGI("sms: WAP push from %s with %u segments (segment %u) refused, at most %d are kept", from, total, seq,
		     WAPPUSH_MAX_SEG);
		return -1;
	}
	m = find(w, from, ref, total);
	if (!m) {
		struct msg *old = NULL;

		for (i = 0; i < WAPPUSH_MAX_MSG; i++) {
			if (!w->m[i].used) {
				old = &w->m[i];
				break;
			}
			if (!old || w->m[i].t0 < old->t0)
				old = &w->m[i];
		}
		if (old->used)
			LOGI("sms: WAP push table full, dropping the oldest incomplete message (from %s)", old->from);
		m = old;
		memset(m, 0, sizeof(*m) - sizeof(m->data));
		m->used = true;
		snprintf(m->from, sizeof(m->from), "%s", from);
		m->ref = ref;
		m->total = total;
		m->t0 = ev_now_ms();
		arm(w);
	}
	if (port && !m->port)
		m->port = port;
	if (m->mask & (1u << (seq - 1)))
		return 0;		/* a repeat of a segment we have */
	memcpy(m->data[seq - 1], data, len);
	m->len[seq - 1] = (uint8_t)len;
	m->mask |= (uint16_t)(1u << (seq - 1));
	m->got++;
	if (m->got < m->total)
		return 0;
	for (i = 0; i < m->total; i++)
		n += m->len[i];
	buf = malloc(n ? n : 1);
	if (!buf) {
		m->used = false;
		arm(w);
		return -1;
	}
	for (i = 0, o = buf; i < m->total; i++) {
		memcpy(o, m->data[i], m->len[i]);
		o += m->len[i];
	}
	{
		char from_c[TP_ADDR_MAX];
		unsigned p = m->port;

		snprintf(from_c, sizeof(from_c), "%s", m->from);
		m->used = false;
		arm(w);
		w->cb(w->arg, from_c, p, buf, n);
	}
	free(buf);
	return 0;
}
