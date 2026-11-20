/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "../dtmf.h"
#include "test.h"

static void gen_tests(void);

void test_dtmf(void)
{
	struct dtmf_event e, e2;
	uint8_t b[4];
	struct dtmf_dec d;
	struct dtmf_in in;
	unsigned fl;

	/* parse / build */
	e = (struct dtmf_event){ .event = 11, .end = true, .volume = 10, .duration = 1600 };
	dtmf_build(b, &e);
	CHECK(b[0] == 11 && b[1] == (0x80 | 10) && b[2] == 0x06 && b[3] == 0x40);
	CHECK(dtmf_parse(b, 4, &e2) == 0 && e2.event == 11 && e2.end && e2.volume == 10 && e2.duration == 1600);
	CHECK(dtmf_parse(b, 3, &e2) < 0);
	b[1] = 0x7f;	/* reserved R bit is ignored, volume masked */
	CHECK(dtmf_parse(b, 4, &e2) == 0 && !e2.end && e2.volume == 0x3f);
	CHECK(dtmf_event_char(5) == '5' && dtmf_event_char(10) == '*' && dtmf_event_char(11) == '#' &&
	      dtmf_event_char(12) == 'A' && dtmf_event_char(15) == 'D' && dtmf_event_char(16) == 'F' && dtmf_event_char(99) == '?');

	/* decoder 8000: start, continuation, end, swallowed retransmissions, new event */
	dtmf_dec_init(&d, 8000);
	e = (struct dtmf_event){ .event = 5, .volume = 10, .duration = 160 };
	fl = dtmf_dec_feed(&d, 1000, &e, 100, &in);
	CHECK(fl == (DTMF_F_START | DTMF_F_UPDATE) && in.event == 5 && in.dur_ms == 20 && in.volume == 10);
	e.duration = 320;
	fl = dtmf_dec_feed(&d, 1000, &e, 120, &in);
	CHECK(fl == DTMF_F_UPDATE && in.dur_ms == 40);
	e.duration = 480;
	e.end = true;
	fl = dtmf_dec_feed(&d, 1000, &e, 140, &in);
	CHECK(fl == (DTMF_F_UPDATE | DTMF_F_END) && in.dur_ms == 60);
	CHECK(dtmf_dec_feed(&d, 1000, &e, 150, &in) == 0 && dtmf_dec_feed(&d, 1000, &e, 160, &in) == 0);
	e.end = false;
	e.duration = 160;
	fl = dtmf_dec_feed(&d, 3000, &e, 400, &in);	/* same key again: new timestamp */
	CHECK(fl == (DTMF_F_START | DTMF_F_UPDATE));
	CHECK(dtmf_dec_idle(&d, 500, 400, &in) == 0);
	CHECK(dtmf_dec_idle(&d, 900, 400, &in) == DTMF_F_END && in.event == 5 && in.dur_ms == 20);
	CHECK(dtmf_dec_idle(&d, 5000, 400, &in) == 0);
	CHECK(dtmf_dec_feed(&d, 3000, &e, 5000, &in) == 0);	/* late packet of the idle-closed event */
	/* 16000 clock, lost start; 48000 clock; a single end packet is start and end at once */
	dtmf_dec_init(&d, 16000);
	e = (struct dtmf_event){ .event = 0, .volume = 7, .duration = 960 };
	fl = dtmf_dec_feed(&d, 777, &e, 10, &in);
	CHECK((fl & DTMF_F_START) && in.dur_ms == 60 && in.volume == 7);
	dtmf_dec_init(&d, 48000);
	e = (struct dtmf_event){ .event = 9, .end = true, .duration = 1920 };
	fl = dtmf_dec_feed(&d, 1, &e, 0, &in);
	CHECK(fl == (DTMF_F_START | DTMF_F_UPDATE | DTMF_F_END) && in.dur_ms == 40);

	gen_tests();
}

/* ------------------------------------------------------------ generator in virtual time */

struct rec {
	uint64_t t;
	struct dtmf_pkt p;
	unsigned fl;
};

/* ts timeline = wall clock in te units; packets are recorded; the callback may inject input at ms t */
static int vrun(struct dtmf_gen *g, uint64_t from, uint64_t to, struct rec *r, int n, int max,
		void (*in)(struct dtmf_gen *, uint64_t))
{
	uint64_t t;

	for (t = from; t <= to; t++) {
		struct dtmf_pkt p;
		unsigned fl;

		if (in)
			in(g, t);
		while (n < max && dtmf_gen_tick(g, t, (uint32_t)(t * g->clock / 1000), &p, &fl)) {
			r[n].t = t;
			r[n].p = p;
			r[n].fl = fl;
			n++;
		}
	}
	return n;
}

static struct rec R[2000];

/* splits R into events: start index of each event (marker) */
static int events(int n, int *start)
{
	int i, ne = 0;

	for (i = 0; i < n; i++)
		if (R[i].p.marker)
			start[ne++] = i;
	return ne;
}

/* checks one event starting at R[s] up to (excluding) R[e]: returns the final duration; verifies shape */
static uint32_t check_event(int s, int e, uint32_t step, uint8_t digit, uint32_t *final_dur)
{
	int i, ends = 0;
	uint32_t last = 0;

	CHECK(R[s].p.marker && !R[s].p.ev.end && R[s].p.ev.duration == step);
	for (i = s; i < e; i++) {
		CHECK(R[i].p.ev.event == digit && R[i].p.ts == R[s].p.ts);
		CHECK(R[i].p.marker == (i == s));
		if (!R[i].p.ev.end) {
			CHECK(ends == 0 && R[i].p.ev.duration >= last);
			if (i > s)
				CHECKF(R[i].t - R[i - 1].t == 20, "update spacing %llu", (unsigned long long)(R[i].t - R[i - 1].t));
			last = R[i].p.ev.duration;
		} else {
			ends++;
			CHECK(R[i].p.ev.duration == last);
			CHECK(ends == 1 || R[i].t - R[i - 1].t == 20);
		}
	}
	CHECK(ends == 3 && (R[e - 1].fl & DTMF_G_DONE));
	*final_dur = last;
	return last;
}

static void in_burst10(struct dtmf_gen *g, uint64_t t)
{
	if (t < 200 && t % 20 == 0) {
		dtmf_gen_down(g, DTMF_SRC_PEER, (uint8_t)(t / 20), 10, 240, t);
		dtmf_gen_up(g, DTMF_SRC_PEER, (uint8_t)(t / 20), 240, t);
	}
}

static void in_burst10_short(struct dtmf_gen *g, uint64_t t)
{
	if (t < 200 && t % 20 == 0) {
		dtmf_gen_down(g, DTMF_SRC_PEER, (uint8_t)(t / 20), 10, 20, t);
		dtmf_gen_up(g, DTMF_SRC_PEER, (uint8_t)(t / 20), 20, t);
	}
}

static void in_held(struct dtmf_gen *g, uint64_t t)	/* key down at 0, packets every 20 ms until 1500, end packet at 1500 */
{
	if (t == 0)
		dtmf_gen_down(g, DTMF_SRC_PEER, 4, 10, 20, t);
	else if (t < 1500 && t % 20 == 0)
		dtmf_gen_hold(g, DTMF_SRC_PEER, 4, t + 20, t);
	else if (t == 1500)
		dtmf_gen_up(g, DTMF_SRC_PEER, 4, 1520, t);
}

static void in_held_lost_end(struct dtmf_gen *g, uint64_t t)	/* packets until 500, then silence */
{
	if (t == 0)
		dtmf_gen_down(g, DTMF_SRC_PEER, 4, 10, 20, t);
	else if (t <= 500 && t % 20 == 0)
		dtmf_gen_hold(g, DTMF_SRC_PEER, 4, t + 20, t);
}

static void in_held_forever(struct dtmf_gen *g, uint64_t t)
{
	if (t == 0)
		dtmf_gen_down(g, DTMF_SRC_PEER, 4, 10, 20, t);
	else if (t % 20 == 0)
		dtmf_gen_hold(g, DTMF_SRC_PEER, 4, t + 20, t);
}

static void gen_tests(void)
{
	struct dtmf_gen g;
	int n, ne, st[64], i;
	uint32_t fd;
	uint32_t clk;

	/* the Bria case: one 240 ms event announced at once, 8000 -> 8000 */
	dtmf_gen_init(&g, 8000, 100, 60, 2000);
	dtmf_gen_down(&g, DTMF_SRC_PEER, 1, 10, 240, 0);
	dtmf_gen_up(&g, DTMF_SRC_PEER, 1, 240, 0);
	n = vrun(&g, 0, 1000, R, 0, 2000, NULL);
	ne = events(n, st);
	CHECKF(n == 12 + 3 && ne == 1, "n=%d ne=%d", n, ne);
	check_event(0, n, 160, 1, &fd);
	CHECK(fd == 1920 && R[0].t == 0 && R[11].p.ev.duration == 1920 && R[12].t == 240 && R[12].p.ev.end && R[14].t == 280);
	CHECK(!dtmf_gen_busy(&g) && dtmf_gen_due(&g) == 0 && g.played == 1 && g.dropped == 0);
	/* the gate for the next digit: nominal end 240 + 60 */
	dtmf_gen_down(&g, DTMF_SRC_PEER, 2, 10, 240, 1000);
	dtmf_gen_up(&g, DTMF_SRC_PEER, 2, 240, 1000);
	n = vrun(&g, 1000, 1100, R, 0, 2000, NULL);
	CHECK(n >= 1 && R[0].t == 1000);	/* idle: starts at once */

	/* a short announcement is stretched to the minimum: 20 ms announced -> 100 ms, 5 updates */
	dtmf_gen_init(&g, 8000, 100, 60, 2000);
	dtmf_gen_down(&g, DTMF_SRC_PEER, 7, 10, 20, 0);
	dtmf_gen_up(&g, DTMF_SRC_PEER, 7, 20, 0);
	n = vrun(&g, 0, 500, R, 0, 2000, NULL);
	CHECKF(n == 5 + 3, "n=%d", n);
	check_event(0, n, 160, 7, &fd);
	CHECK(fd == 800 && R[5].t == 100 && R[5].p.ev.end);

	/* two events 201 ms apart (announced 240 ms) are serialised: start 2 >= nominal end of 1 + pause */
	dtmf_gen_init(&g, 8000, 100, 60, 2000);
	dtmf_gen_down(&g, DTMF_SRC_PEER, 1, 10, 240, 0);
	dtmf_gen_up(&g, DTMF_SRC_PEER, 1, 240, 0);
	dtmf_gen_down(&g, DTMF_SRC_PEER, 3, 10, 240, 201);
	dtmf_gen_up(&g, DTMF_SRC_PEER, 3, 240, 201);
	n = vrun(&g, 0, 1000, R, 0, 2000, NULL);
	ne = events(n, st);
	CHECKF(ne == 2 && n == 30, "ne=%d n=%d", ne, n);
	if (ne == 2) {
		check_event(st[0], st[1], 160, 1, &fd);
		check_event(st[1], n, 160, 3, &fd);
		CHECK(R[st[1]].t >= R[st[0] + 12].t + 60);	/* nominal end + pause */
		CHECK(R[st[1]].t >= R[st[0] + 14].t + 20);	/* and after the last end packet */
		CHECK(R[st[1]].p.ts - R[st[0]].p.ts >= 1920);	/* timestamps do not overlap either (timeline = wall clock) */
	}

	/* ten digits within 200 ms: all played, in order, ~160 ms apart (min 100 + pause 60), none lost */
	dtmf_gen_init(&g, 8000, 100, 60, 2000);
	n = vrun(&g, 0, 3000, R, 0, 2000, in_burst10_short);
	ne = events(n, st);
	CHECKF(ne == 10 && n == 10 * 8, "ne=%d n=%d", ne, n);
	for (i = 0; i < ne && i < 10; i++) {
		CHECK(R[st[i]].p.ev.event == i);
		if (i)
			CHECKF(R[st[i]].t - R[st[i - 1]].t == 160, "gap %llu", (unsigned long long)(R[st[i]].t - R[st[i - 1]].t));
	}
	CHECK(g.dropped == 0 && g.played == 10);
	dtmf_gen_init(&g, 8000, 100, 60, 2000);	/* the same with the 240 ms announcement: 300 ms apart */
	n = vrun(&g, 0, 6000, R, 0, 2000, in_burst10);
	ne = events(n, st);
	CHECKF(ne == 10, "ne=%d", ne);
	for (i = 1; i < ne && i < 10; i++)
		CHECK(R[st[i]].t - R[st[i - 1]].t == 300 && R[st[i]].p.ev.event == i);

	/* pause 0: the next digit still waits for the last end packet + 20 ms (nominal end 100, end packets 100/120/140) */
	dtmf_gen_init(&g, 8000, 100, 0, 2000);
	n = vrun(&g, 0, 3000, R, 0, 2000, in_burst10_short);
	ne = events(n, st);
	CHECK(ne == 10 && R[st[1]].t - R[st[0]].t == 160);

	/* long key press: packets for 1.5 s -> one event of about 1.5 s */
	dtmf_gen_init(&g, 8000, 100, 60, 2000);
	n = vrun(&g, 0, 4000, R, 0, 2000, in_held);
	ne = events(n, st);
	CHECKF(ne == 1, "ne=%d", ne);
	check_event(0, n, 160, 4, &fd);
	CHECKF(fd >= 1500 * 8 && fd <= 1560 * 8, "long press dur %u", fd);
	/* end packets lost: released 100 ms after the last packet, proper end triplet, key held longer than the minimum */
	dtmf_gen_init(&g, 8000, 100, 60, 2000);
	n = vrun(&g, 0, 4000, R, 0, 2000, in_held_lost_end);
	ne = events(n, st);
	CHECKF(ne == 1, "ne=%d", ne);
	check_event(0, n, 160, 4, &fd);
	CHECKF(fd >= 500 * 8 && fd <= 640 * 8, "lost end dur %u", fd);
	/* a key held forever stops at max_ms (2000) */
	n = (dtmf_gen_init(&g, 8000, 100, 60, 2000), vrun(&g, 0, 3000, R, 0, 2000, in_held_forever));
	CHECK(n >= 100 && R[n - 1].p.ev.end);
	CHECKF(R[n - 1].p.ev.duration == 16000, "max dur %u", R[n - 1].p.ev.duration);

	/* other te clocks: 16000 and 48000 destinations, 240 ms */
	for (i = 0; i < 2; i++) {
		clk = i ? 48000 : 16000;
		dtmf_gen_init(&g, clk, 100, 60, 2000);
		dtmf_gen_down(&g, DTMF_SRC_PEER, 6, 10, 240, 0);
		dtmf_gen_up(&g, DTMF_SRC_PEER, 6, 240, 0);
		n = vrun(&g, 0, 1000, R, 0, 2000, NULL);
		CHECK(n == 15);
		check_event(0, n, clk / 50, 6, &fd);
		CHECKF(fd == clk * 240 / 1000, "dur %u", fd);
		CHECK(R[0].p.ts == (uint32_t)0);
	}
	/* 48 kHz: the 16 bit duration field limits an event to 1365 ms */
	dtmf_gen_init(&g, 48000, 100, 60, 2000);
	CHECK(g.max_ms == 1365);
	n = vrun(&g, 0, 4000, R, 0, 2000, in_held_forever);
	CHECKF(R[n - 1].p.ev.end && R[n - 1].p.ev.duration > 65000, "48k max dur %u", R[n - 1].p.ev.duration);

	/* queue overflow: idle generator, 40 digits at once: the 8 oldest are dropped */
	dtmf_gen_init(&g, 8000, 100, 60, 2000);
	for (i = 0; i < 40; i++) {
		dtmf_gen_down(&g, DTMF_SRC_PEER, (uint8_t)(i % 16), 10, 20, 0);
		dtmf_gen_up(&g, DTMF_SRC_PEER, (uint8_t)(i % 16), 20, 0);
	}
	CHECK(g.cnt == DTMF_Q_MAX && g.dropped == 8);
	n = vrun(&g, 0, 20000, R, 0, 2000, NULL);
	ne = events(n, st);
	CHECKF(ne == 32, "ne=%d", ne);
	for (i = 0; ne == 32 && i < 32; i++)
		CHECK(R[st[i]].p.ev.event == (8 + i) % 16);
	/* overflow while one is playing: the playing one is kept, the oldest waiting ones go */
	dtmf_gen_init(&g, 8000, 100, 60, 2000);
	dtmf_gen_down(&g, DTMF_SRC_PEER, 0, 10, 20, 0);
	dtmf_gen_up(&g, DTMF_SRC_PEER, 0, 20, 0);
	n = vrun(&g, 0, 40, R, 0, 2000, NULL);
	for (i = 1; i <= 33; i++) {
		dtmf_gen_down(&g, DTMF_SRC_PEER, (uint8_t)(i % 16), 10, 20, 40);
		dtmf_gen_up(&g, DTMF_SRC_PEER, (uint8_t)(i % 16), 20, 40);
	}
	CHECK(g.dropped == 2 && g.cnt == 32);
	n = vrun(&g, 41, 20000, R, n, 2000, NULL);
	ne = events(n, st);
	CHECKF(ne == 1 + 31 - 0, "ne=%d", ne);	/* the playing one + 31 waiting */
	CHECK(R[st[0]].p.ev.event == 0 && R[st[1]].p.ev.event == 3);

	/* API digits and peer digits interleave in arrival order; a held peer key is not closed by an API digit */
	dtmf_gen_init(&g, 8000, 100, 60, 2000);
	dtmf_gen_down(&g, DTMF_SRC_PEER, 1, 10, 20, 0);
	dtmf_gen_down(&g, DTMF_SRC_API, 2, 10, 100, 0);
	dtmf_gen_up(&g, DTMF_SRC_API, 2, 100, 0);
	dtmf_gen_up(&g, DTMF_SRC_PEER, 1, 20, 0);
	dtmf_gen_down(&g, DTMF_SRC_PEER, 3, 10, 20, 0);
	dtmf_gen_up(&g, DTMF_SRC_PEER, 3, 20, 0);
	n = vrun(&g, 0, 2000, R, 0, 2000, NULL);
	ne = events(n, st);
	CHECK(ne == 3 && R[st[0]].p.ev.event == 1 && R[st[1]].p.ev.event == 2 && R[st[2]].p.ev.event == 3);

	/* flush counts the queued and the running digit, and the generator is usable afterwards */
	dtmf_gen_init(&g, 8000, 100, 60, 2000);
	for (i = 0; i < 5; i++) {
		dtmf_gen_down(&g, DTMF_SRC_PEER, (uint8_t)i, 10, 20, 0);
		dtmf_gen_up(&g, DTMF_SRC_PEER, (uint8_t)i, 20, 0);
	}
	n = vrun(&g, 0, 30, R, 0, 2000, NULL);
	CHECK(dtmf_gen_active(&g) && dtmf_gen_flush(&g) == 5 && g.dropped == 5 && !dtmf_gen_busy(&g));
	CHECK(dtmf_gen_due(&g) == 0);
	dtmf_gen_down(&g, DTMF_SRC_PEER, 9, 10, 20, 100);
	dtmf_gen_up(&g, DTMF_SRC_PEER, 9, 20, 100);
	n = vrun(&g, 100, 400, R, 0, 2000, NULL);
	CHECK(n == 8 && R[0].p.ev.event == 9);

	/* a tick that is very late does not burst out more than a few packets and keeps spacing sane */
	dtmf_gen_init(&g, 8000, 100, 60, 2000);
	dtmf_gen_down(&g, DTMF_SRC_PEER, 1, 10, 240, 0);
	dtmf_gen_up(&g, DTMF_SRC_PEER, 1, 240, 0);
	n = 0;
	{
		struct dtmf_pkt p;
		unsigned fl;

		CHECK(dtmf_gen_tick(&g, 0, 0, &p, &fl) == 1 && (fl & DTMF_G_START));
		CHECK(dtmf_gen_tick(&g, 500, 0, &p, &fl) == 1 && p.ev.duration == 320);	/* one packet, then re-anchored */
		CHECK(dtmf_gen_tick(&g, 500, 0, &p, &fl) == 0);
		CHECK(dtmf_gen_due(&g) == 520);
	}
}
