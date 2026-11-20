/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "dtmf.h"

int dtmf_parse(const uint8_t *p, size_t len, struct dtmf_event *ev)
{
	if (len < 4)
		return -1;
	ev->event = p[0];
	ev->end = p[1] & 0x80;
	ev->volume = p[1] & 0x3f;
	ev->duration = (uint16_t)(p[2] << 8 | p[3]);
	return 0;
}

void dtmf_build(uint8_t out[4], const struct dtmf_event *ev)
{
	out[0] = ev->event;
	out[1] = (uint8_t)((ev->end ? 0x80 : 0) | (ev->volume & 0x3f));
	out[2] = (uint8_t)(ev->duration >> 8);
	out[3] = (uint8_t)ev->duration;
}

char dtmf_event_char(uint8_t e)
{
	if (e <= 9)
		return (char)('0' + e);
	if (e == 10)
		return '*';
	if (e == 11)
		return '#';
	if (e <= 15)
		return (char)('A' + e - 12);
	if (e == 16)
		return 'F';
	return '?';
}

static uint32_t units_to_ms(uint32_t clock, uint32_t units)
{
	return (uint32_t)((uint64_t)units * 1000 / clock);
}

static uint32_t ms_to_units(uint32_t clock, uint32_t ms)
{
	return (uint32_t)((uint64_t)ms * clock / 1000);
}

/* ------------------------------------------------------------------ decoder */

void dtmf_dec_init(struct dtmf_dec *d, uint32_t clock)
{
	memset(d, 0, sizeof(*d));
	d->clock = clock ? clock : 8000;
}

unsigned dtmf_dec_feed(struct dtmf_dec *d, uint32_t src_ts, const struct dtmf_event *ev, uint64_t now_ms, struct dtmf_in *in)
{
	unsigned fl = DTMF_F_UPDATE;
	bool same = (d->active || d->ended) && d->event == ev->event && d->src_ts == src_ts;

	if (same && d->ended)
		return 0;	/* retransmitted end (or late continuation) of an event already closed */
	if (!same) {
		d->event = ev->event;
		d->src_ts = src_ts;
		fl |= DTMF_F_START;
	}
	d->active = true;
	d->ended = false;
	d->volume = ev->volume;
	d->last_ms = now_ms;
	d->last_ms_dur = units_to_ms(d->clock, ev->duration);
	if (ev->end) {
		fl |= DTMF_F_END;
		d->active = false;
		d->ended = true;
	}
	in->event = ev->event;
	in->volume = ev->volume;
	in->dur_ms = d->last_ms_dur;
	return fl;
}

unsigned dtmf_dec_idle(struct dtmf_dec *d, uint64_t now_ms, uint64_t idle_ms, struct dtmf_in *in)
{
	if (!d->active || now_ms - d->last_ms < idle_ms)
		return 0;
	d->active = false;
	d->ended = true;
	in->event = d->event;
	in->volume = d->volume;
	in->dur_ms = d->last_ms_dur;
	return DTMF_F_END;
}

/* ------------------------------------------------------------------ generator */

void dtmf_gen_init(struct dtmf_gen *g, uint32_t clock, uint32_t min_ms, uint32_t pause_ms, uint32_t max_ms)
{
	uint32_t lim;

	memset(g, 0, sizeof(*g));
	g->clock = clock ? clock : 8000;
	g->step = g->clock / 50;
	lim = (uint32_t)((uint64_t)0xffff * 1000 / g->clock);	/* the duration field is 16 bits */
	if (!max_ms)
		max_ms = 2000;
	if (max_ms > lim)
		max_ms = lim;
	if (max_ms < DTMF_STEP_MS)
		max_ms = DTMF_STEP_MS;
	if (min_ms < DTMF_STEP_MS)
		min_ms = DTMF_STEP_MS;
	if (min_ms > max_ms)
		min_ms = max_ms;
	g->min_ms = min_ms;
	g->pause_ms = pause_ms;
	g->max_ms = max_ms;
}

static struct dtmf_q *q_at(struct dtmf_gen *g, unsigned i)
{
	return &g->q[(g->head + i) % DTMF_Q_MAX];
}

/* newest digit of this source with this code that has not been released */
static struct dtmf_q *q_find_open(struct dtmf_gen *g, int src, uint8_t event)
{
	unsigned i;

	for (i = g->cnt; i-- > 0;) {
		struct dtmf_q *q = q_at(g, i);

		if (q->src == src && q->event == event && !q->closed)
			return q;
	}
	return NULL;
}

void dtmf_gen_down(struct dtmf_gen *g, int src, uint8_t event, uint8_t volume, uint32_t dur_ms, uint64_t now_ms)
{
	struct dtmf_q *q;
	unsigned i;

	for (i = 0; i < g->cnt; i++) {	/* a new key of the same source implies the previous one was released */
		q = q_at(g, i);
		if (q->src == src)
			q->closed = true;
	}
	if (g->cnt >= DTMF_Q_MAX) {
		unsigned first = g->state ? 1 : 0;	/* the event on the wire is never dropped */

		for (i = first; i + 1 < g->cnt; i++)
			*q_at(g, i) = *q_at(g, i + 1);
		g->cnt--;
		g->dropped++;
	}
	q = q_at(g, g->cnt++);
	q->event = event;
	q->volume = volume;
	q->src = (uint8_t)src;
	q->closed = false;
	q->ann_ms = dur_ms;
	q->last_ms = now_ms;
}

void dtmf_gen_hold(struct dtmf_gen *g, int src, uint8_t event, uint32_t dur_ms, uint64_t now_ms)
{
	struct dtmf_q *q = q_find_open(g, src, event);

	if (!q)
		return;
	if (dur_ms > q->ann_ms)
		q->ann_ms = dur_ms;
	q->last_ms = now_ms;
}

void dtmf_gen_up(struct dtmf_gen *g, int src, uint8_t event, uint32_t dur_ms, uint64_t now_ms)
{
	struct dtmf_q *q = q_find_open(g, src, event);

	if (!q)
		return;
	if (dur_ms > q->ann_ms)
		q->ann_ms = dur_ms;
	q->last_ms = now_ms;
	q->closed = true;
}

unsigned dtmf_gen_flush(struct dtmf_gen *g)
{
	unsigned n = g->cnt;

	g->dropped += n;
	g->cnt = 0;
	g->state = 0;
	return n;
}

bool dtmf_gen_active(const struct dtmf_gen *g)
{
	return g->state != 0;
}

bool dtmf_gen_busy(const struct dtmf_gen *g)
{
	return g->state != 0 || g->cnt != 0;
}

uint64_t dtmf_gen_due(const struct dtmf_gen *g)
{
	if (g->state)
		return g->next_ms;
	return g->cnt ? g->gate : 0;
}

static void fill(struct dtmf_gen *g, struct dtmf_pkt *out, bool end, bool marker)
{
	const struct dtmf_q *q = &g->q[g->head];

	out->ev.event = q->event;
	out->ev.end = end;
	out->ev.volume = q->volume;
	out->ev.duration = (uint16_t)g->dur;
	out->ts = g->ts;
	out->marker = marker;
}

/* next packet slot; a tick that is more than 100 ms late re-anchors instead of bursting */
static void advance(struct dtmf_gen *g, uint64_t now)
{
	g->next_ms = now > g->next_ms + 100 ? now + DTMF_STEP_MS : g->next_ms + DTMF_STEP_MS;
}

int dtmf_gen_tick(struct dtmf_gen *g, uint64_t now, uint32_t ts_now, struct dtmf_pkt *out, unsigned *flags)
{
	struct dtmf_q *q;

	*flags = 0;
	if (g->state == 0) {
		if (!g->cnt || now < g->gate)
			return 0;
		g->state = 1;
		g->ts = ts_now;
		g->k = 0;
		g->dur = g->step;
		g->next_ms = now + DTMF_STEP_MS;
		fill(g, out, false, true);
		*flags = DTMF_G_START;
		return 1;
	}
	if (now < g->next_ms)
		return 0;
	q = &g->q[g->head];
	if (g->state == 1) {
		uint32_t tgt = q->ann_ms > g->min_ms ? q->ann_ms : g->min_ms, elapsed;
		bool cont;

		if (tgt > g->max_ms)
			tgt = g->max_ms;
		g->k++;
		elapsed = g->k * DTMF_STEP_MS;
		cont = elapsed < tgt;
		if (!cont && !q->closed && elapsed < g->max_ms && now - q->last_ms <= DTMF_HOLD_STALE_MS)
			cont = true;	/* key still held: keep the event going */
		if (cont) {
			uint32_t cap = q->closed ? ms_to_units(g->clock, tgt) : ms_to_units(g->clock, g->max_ms);
			uint32_t nd = (g->k + 1) * g->step;

			g->dur = nd < cap ? nd : cap;
			fill(g, out, false, false);
			advance(g, now);
			return 1;
		}
		g->state = 2;
		g->end_sent = 1;
		g->nominal_end = g->next_ms;
		fill(g, out, true, false);
		advance(g, now);
		*flags = DTMF_G_END1;
		return 1;
	}
	fill(g, out, true, false);
	g->end_sent++;
	if (g->end_sent >= DTMF_END_REPEAT) {
		uint64_t a = g->nominal_end + g->pause_ms, b = g->next_ms + DTMF_STEP_MS;

		g->state = 0;
		g->head = (g->head + 1) % DTMF_Q_MAX;
		g->cnt--;
		g->played++;
		g->gate = a > b ? a : b;
		*flags = DTMF_G_DONE;
		return 1;
	}
	advance(g, now);
	return 1;
}
