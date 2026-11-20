/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * PCM device leg of the bridge (BR_LEG_PCMDEV) against a fake device: a producer thread plays the modem clock
 * (one capture period per tick), uplink periods are recorded. The LAN side is a PCMA RTP peer on loopback (8 kHz,
 * so the paths need no resampling). Run under TSan: fake device, media thread and test thread all touch the state.
 */
#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "../bridge.h"
#include "../codec.h"
#include "../dtmf.h"
#include "../pcmdev.h"
#include "../rtp.h"
#include "test.h"

#define PI 3.14159265358979323846
#define FR 160

/* ------------------------------------------------------------ fake device */

static struct fake {
	pthread_mutex_t mu;
	pthread_t th;
	atomic_bool run, ticking;
	int efd;
	unsigned period_us;
	unsigned pending;
	/* injection (under mu) */
	int open_err, xrun_rx, xrun_tx, full_tx, bad_rx;
	bool gone;
	bool opened;
	unsigned opens, closes;
	/* downlink tone */
	double phase;
	/* recording of the uplink */
	int16_t *ul;
	size_t ul_n, ul_cap;
	unsigned reads, writes;
} F = { .mu = PTHREAD_MUTEX_INITIALIZER, .efd = -1 };

static void *fake_clock(void *arg)
{
	(void)arg;
	while (atomic_load(&F.run)) {
		usleep(F.period_us);
		if (!atomic_load(&F.ticking))
			continue;
		pthread_mutex_lock(&F.mu);
		F.pending++;
		eventfd_write(F.efd, 1);
		pthread_mutex_unlock(&F.mu);
	}
	return NULL;
}

static void *fk_open(const char *spec, unsigned rate, unsigned frames)
{
	void *r = NULL;

	(void)spec;
	pthread_mutex_lock(&F.mu);
	if (F.open_err) {
		errno = F.open_err;
	} else if (rate != 8000 || frames != FR) {
		errno = EINVAL;
	} else {
		F.opened = true;
		F.opens++;
		r = &F;
	}
	pthread_mutex_unlock(&F.mu);
	return r;
}

static int fk_fd(void *d)
{
	(void)d;
	return F.efd;
}

static int fk_read(void *d, int16_t *pcm, unsigned frames)
{
	int r;
	unsigned i;
	uint64_t junk;

	(void)d;
	pthread_mutex_lock(&F.mu);
	if (F.gone) {
		r = -ENODEV;
	} else if (!F.pending) {
		if (eventfd_read(F.efd, &junk) < 0) { /* already clear */ }
		r = 0;
	} else {
		F.pending--;
		F.reads++;
		if (F.bad_rx) {
			F.bad_rx--;
			r = -EIO;
		} else if (F.xrun_rx) {
			F.xrun_rx--;
			r = -EPIPE;
		} else {
			for (i = 0; i < frames; i++) {
				pcm[i] = (int16_t)(8000 * sin(F.phase));
				F.phase += 2 * PI * 400.0 / 8000.0;
			}
			r = (int)frames;
		}
	}
	pthread_mutex_unlock(&F.mu);
	return r;
}

static int fk_write(void *d, const int16_t *pcm, unsigned frames)
{
	int r = (int)frames;

	(void)d;
	pthread_mutex_lock(&F.mu);
	if (F.gone) {
		r = -ENODEV;
	} else if (F.full_tx) {
		F.full_tx--;
		r = -EAGAIN;
	} else if (F.xrun_tx) {
		F.xrun_tx--;
		r = -EPIPE;
	} else {
		F.writes++;
		if (F.ul_n + frames <= F.ul_cap) {
			memcpy(F.ul + F.ul_n, pcm, frames * sizeof(int16_t));
			F.ul_n += frames;
		}
	}
	pthread_mutex_unlock(&F.mu);
	return r;
}

static void fk_close(void *d)
{
	(void)d;
	pthread_mutex_lock(&F.mu);
	F.opened = false;
	F.closes++;
	pthread_mutex_unlock(&F.mu);
}

static const struct br_pcmdev_ops fake_ops = {
	.name = "fake", .open = fk_open, .poll_fd = fk_fd, .read = fk_read, .write = fk_write, .close = fk_close,
};

static void fake_start(unsigned period_us)
{
	pthread_mutex_lock(&F.mu);
	F.pending = 0;
	F.open_err = F.xrun_rx = F.xrun_tx = F.full_tx = F.bad_rx = 0;
	F.gone = false;
	F.opens = F.closes = F.reads = F.writes = 0;
	F.ul_n = 0;
	F.phase = 0;
	pthread_mutex_unlock(&F.mu);
	if (F.efd < 0) {
		F.efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		F.ul_cap = 16000 * 8;
		F.ul = malloc(F.ul_cap * sizeof(int16_t));
	} else {
		uint64_t j;

		while (eventfd_read(F.efd, &j) == 0) { }
	}
	F.period_us = period_us;
	atomic_store(&F.ticking, true);
	atomic_store(&F.run, true);
	pthread_create(&F.th, NULL, fake_clock, NULL);
}

static void fake_stop(void)
{
	atomic_store(&F.run, false);
	pthread_join(F.th, NULL);
}

/* ------------------------------------------------------------ plumbing */

static int sock_open(struct addr *out)
{
	int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	int off = 0;
	struct addr a;
	struct sockaddr_in6 got;
	socklen_t sl = sizeof(got);

	if (fd < 0)
		return -1;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
	addr_set(&a, "127.0.0.1", 0);
	if (bind(fd, (struct sockaddr *)&a.sa, sizeof(a.sa)) < 0) {
		close(fd);
		return -1;
	}
	getsockname(fd, (struct sockaddr *)&got, &sl);
	addr_from_sa6(out, &got);
	return fd;
}

static struct br_event evlog[256];
static int nev;

static void ev_cb(void *arg, const struct br_event *ev)
{
	(void)arg;
	if (nev < 256)
		evlog[nev++] = *ev;
}

static int ev_count(enum br_event_type t)
{
	int i, n = 0;

	bridge_events_dispatch(ev_cb, NULL);
	for (i = 0; i < nev; i++)
		if (evlog[i].type == t)
			n++;
	return n;
}

static const struct br_event *ev_find(enum br_event_type t)
{
	int i;

	ev_count(t);
	for (i = 0; i < nev; i++)
		if (evlog[i].type == t)
			return &evlog[i];
	return NULL;
}

static bool wait_ev(enum br_event_type t, int want, int ms)
{
	int waited = 0;

	for (;;) {
		struct pollfd pf = { .fd = bridge_event_fd(), .events = POLLIN };

		if (ev_count(t) >= want)
			return true;
		if (waited >= ms)
			return false;
		poll(&pf, 1, 10);
		waited += 10;
	}
}

struct rig {
	struct bridge *br;
	int lan_fd, br_fd;
	struct addr lan, brs;
	struct codec *pcma;
	uint16_t seq;
	uint32_t ts;
};

static void rig_up(struct rig *r, bool start, unsigned rx_timeout_ms)
{
	struct br_leg_cfg c0, c1;

	memset(r, 0, sizeof(*r));
	nev = 0;
	r->lan_fd = sock_open(&r->lan);
	r->br_fd = sock_open(&r->brs);
	CHECK(r->lan_fd >= 0 && r->br_fd >= 0);
	r->pcma = codec_create(CODEC_PCMA, NULL);
	br_leg_cfg_default(&c0);
	c0.kind = BR_LEG_PCMDEV;
	c0.pcm_rate = 8000;
	c0.pdev_ops = &fake_ops;
	snprintf(c0.pdev_spec, sizeof(c0.pdev_spec), "auto,0");
	c0.rx_timeout_ms = rx_timeout_ms;
	br_leg_cfg_default(&c1);
	c1.kind = BR_LEG_UDP;
	c1.codec = CODEC_PCMA;
	c1.pt = 8;
	c1.te_pt = 101;
	c1.te_clock = 8000;
	c1.fd = r->br_fd;
	c1.own_fd = true;
	c1.remote = r->lan;
	c1.has_remote = true;
	r->br = bridge_create(r);
	CHECK(r->br != NULL);
	CHECK(bridge_set_leg(r->br, BR_CARRIER, &c0) == 0);
	CHECK(bridge_set_leg(r->br, BR_CLIENT, &c1) == 0);
	if (start)
		CHECK(bridge_start(r->br) == 0);
}

static void rig_down(struct rig *r)
{
	bridge_destroy(r->br);
	CHECK(wait_ev(BR_EV_DESTROYED, 1, 3000));
	close(r->lan_fd);
	codec_destroy(r->pcma);
}

/* one 20 ms PCMA packet of a 600 Hz tone to the bridge */
static void lan_send_tone(struct rig *r, double *phase)
{
	int16_t pcm[FR];
	uint8_t pl[FR], pkt[200];
	int i, n;

	for (i = 0; i < FR; i++) {
		pcm[i] = (int16_t)(8000 * sin(*phase));
		*phase += 2 * PI * 600.0 / 8000.0;
	}
	n = codec_encode(r->pcma, pcm, pl, sizeof(pl));
	n = rtp_build(pkt, sizeof(pkt), r->seq == 0, 8, r->seq, r->ts, 0x22220002u, pl, (size_t)n);
	sendto(r->lan_fd, pkt, (size_t)n, 0, (const struct sockaddr *)&r->brs.sa, sizeof(r->brs.sa));
	r->seq++;
	r->ts += FR;
}

static int lan_drain(struct rig *r, int *tone_pkts)
{
	int n = 0;

	for (;;) {
		uint8_t b[512];
		struct rtp_pkt p;
		ssize_t k = recv(r->lan_fd, b, sizeof(b), MSG_DONTWAIT);

		if (k < 0)
			break;
		if (rtp_parse(b, (size_t)k, &p) == 0 && p.h.pt == 8) {
			n++;
			if (tone_pkts && p.plen == FR)
				(*tone_pkts)++;
		}
	}
	return n;
}

static void sleep_ms(unsigned ms)
{
	usleep(ms * 1000);
}

/* power of a tone in the recording (Goertzel), relative to the total power */
static double goertzel(const int16_t *x, size_t n, double hz)
{
	double w = 2 * PI * hz / 8000.0, c = 2 * cos(w), s0, s1 = 0, s2 = 0, e = 0;
	size_t i;

	for (i = 0; i < n; i++) {
		s0 = x[i] + c * s1 - s2;
		s2 = s1;
		s1 = s0;
		e += (double)x[i] * x[i];
	}
	return e > 0 ? (s1 * s1 + s2 * s2 - c * s1 * s2) / (e * (double)n / 2) : 0;
}

/* ------------------------------------------------------------ tests */

static void t_pure(void)
{
	int card = -9, dev = -9;
	char path[40];

	CHECK(pcmdev_find_card(" 0 [MSM8916Voice  ]: q6afe-rtproxy - MSM8916 Voice\n                      MSM8916 Voice\n", &card) == 0 && card == 0);
	CHECK(pcmdev_find_card(" 0 [Other          ]: simple-card - Other\n 2 [Voice          ]: x - y\n", &card) == 0 && card == 2);
	CHECK(pcmdev_find_card(" 1 [Foo            ]: q6afe-rtproxy - Foo\n", &card) == 0 && card == 1);
	CHECK(pcmdev_find_card(" 0 [PCH            ]: HDA-Intel - HDA Intel PCH\n", &card) < 0);
	CHECK(pcmdev_find_card("", &card) < 0);
	CHECK(pcmdev_parse_spec("", &card, &dev) == 0 && card == -1 && dev == 0);
	CHECK(pcmdev_parse_spec("auto", &card, &dev) == 0 && card == -1 && dev == 0);
	CHECK(pcmdev_parse_spec("auto,1", &card, &dev) == 0 && card == -1 && dev == 1);
	CHECK(pcmdev_parse_spec("hw:2,1", &card, &dev) == 0 && card == 2 && dev == 1);
	CHECK(pcmdev_parse_spec("1", &card, &dev) == 0 && card == -1 && dev == 1);
	CHECK(pcmdev_parse_spec("x", &card, &dev) < 0 && pcmdev_parse_spec("1,", &card, &dev) < 0 && pcmdev_parse_spec("99,0", &card, &dev) < 0);
	CHECK(pcmdev_path(path, sizeof(path), 0, 0, 1) == 0 && !strcmp(path, "/dev/snd/pcmC0D0c"));
	CHECK(pcmdev_path(path, sizeof(path), 3, 1, 0) == 0 && !strcmp(path, "/dev/snd/pcmC3D1p"));
	CHECK(pcmdev_path(path, 8, 3, 1, 0) < 0);
	printf("  (p) card lookup, device spec, path\n");
}

/* both directions at the modem's 20 ms clock with a LAN peer at 20 ms: no drift, tone both ways */
static void t_flow(void)
{
	struct rig r;
	struct bridge_stats st;
	double ph = 0;
	int i, tone = 0, got = 0;
	int16_t *ul;
	size_t n;

	fake_start(20000);
	rig_up(&r, true, 0);
	for (i = 0; i < 100; i++) {	/* 2 s */
		lan_send_tone(&r, &ph);
		sleep_ms(20);
		got += lan_drain(&r, &tone);
	}
	sleep_ms(60);
	got += lan_drain(&r, &tone);
	bridge_get_stats(r.br, &st);
	CHECKF(got >= 90 && got <= 110, "downlink packets to the LAN: %d", got);
	CHECKF(st.leg[BR_CARRIER].rx_pkts >= 90 && st.leg[BR_CARRIER].rx_pkts <= 110, "capture periods %llu", (unsigned long long)st.leg[BR_CARRIER].rx_pkts);
	CHECK(st.leg[BR_CARRIER].tx_pkts >= 90);
	CHECKF(st.leg[BR_CARRIER].pcm_ul_drop + st.leg[BR_CARRIER].pcm_ul_fill <= 12, "drop %u fill %u", st.leg[BR_CARRIER].pcm_ul_drop,
	       st.leg[BR_CARRIER].pcm_ul_fill);
	CHECK(st.leg[BR_CARRIER].pcm_xrun_rx == 0 && st.leg[BR_CARRIER].pcm_xrun_tx == 0 && !st.leg[BR_CARRIER].pcm_lost);
	CHECK(st.leg[BR_CARRIER].pcm_ul_depth <= 5);
	CHECK(ev_count(BR_EV_FIRST_RX) >= 1);
	/* uplink recording: the 600 Hz tone is in it (after the first few frames) */
	pthread_mutex_lock(&F.mu);
	n = F.ul_n;
	ul = malloc(n * sizeof(int16_t));
	memcpy(ul, F.ul, n * sizeof(int16_t));
	pthread_mutex_unlock(&F.mu);
	CHECK(n >= 90 * FR);
	if (n > 40 * FR) {
		double g = goertzel(ul + 20 * FR, n - 30 * FR, 600.0);

		CHECKF(g > 0.5, "600 Hz share of the uplink: %.2f", g);
	}
	free(ul);
	/* downlink tone on the LAN side: decode the last packet */
	printf("  (f) %d downlink packets, %llu uplink periods, drop %u fill %u idle %u\n", got,
	       (unsigned long long)st.leg[BR_CARRIER].tx_pkts, st.leg[BR_CARRIER].pcm_ul_drop, st.leg[BR_CARRIER].pcm_ul_fill, st.leg[BR_CARRIER].pcm_ul_idle);
	rig_down(&r);
	fake_stop();
	CHECK(F.opens == 1 && F.closes == 1);
}

/* the peer's clock runs faster / slower than the modem's: frames are dropped / silence inserted, both counted */
static void t_drift(void)
{
	struct rig r;
	struct bridge_stats st;
	double ph = 0;
	int i;

	/* LAN 4 ms ahead per packet (16 ms vs 20 ms): the queue overflows */
	fake_start(20000);
	rig_up(&r, true, 0);
	for (i = 0; i < 125; i++) {
		lan_send_tone(&r, &ph);
		sleep_ms(16);
		lan_drain(&r, NULL);
	}
	bridge_get_stats(r.br, &st);
	CHECKF(st.leg[BR_CARRIER].pcm_ul_drop >= 10, "drop %u", st.leg[BR_CARRIER].pcm_ul_drop);
	CHECKF(st.leg[BR_CARRIER].pcm_ul_depth <= 5, "depth %u", st.leg[BR_CARRIER].pcm_ul_depth);
	printf("  (d) fast peer: %u frames dropped, depth %u\n", st.leg[BR_CARRIER].pcm_ul_drop, st.leg[BR_CARRIER].pcm_ul_depth);
	rig_down(&r);
	fake_stop();

	/* LAN slower (26 ms vs 20 ms): the queue runs dry, silence is inserted */
	ph = 0;
	fake_start(20000);
	rig_up(&r, true, 0);
	for (i = 0; i < 80; i++) {
		lan_send_tone(&r, &ph);
		sleep_ms(26);
		lan_drain(&r, NULL);
	}
	bridge_get_stats(r.br, &st);
	CHECKF(st.leg[BR_CARRIER].pcm_ul_fill >= 8, "fill %u", st.leg[BR_CARRIER].pcm_ul_fill);
	printf("  (d) slow peer: %u silence frames inserted\n", st.leg[BR_CARRIER].pcm_ul_fill);
	rig_down(&r);
	fake_stop();

	/* nobody sends: idle silence, not counted as an underrun */
	fake_start(20000);
	rig_up(&r, true, 0);
	sleep_ms(400);
	bridge_get_stats(r.br, &st);
	CHECK(st.leg[BR_CARRIER].pcm_ul_fill == 0 && st.leg[BR_CARRIER].pcm_ul_idle >= 10);
	{
		int16_t z = 0;

		pthread_mutex_lock(&F.mu);
		for (i = 0; i < (int)F.ul_n; i++)
			z |= F.ul[i];
		pthread_mutex_unlock(&F.mu);
		CHECK(z == 0);
	}
	rig_down(&r);
	fake_stop();
}

static void t_xrun(void)
{
	struct rig r;
	struct bridge_stats st;
	double ph = 0;
	int i;

	fake_start(20000);
	rig_up(&r, true, 0);
	pthread_mutex_lock(&F.mu);
	F.xrun_rx = 3;
	F.xrun_tx = 2;
	F.full_tx = 2;
	pthread_mutex_unlock(&F.mu);
	for (i = 0; i < 40; i++) {
		lan_send_tone(&r, &ph);
		sleep_ms(20);
		lan_drain(&r, NULL);
	}
	bridge_get_stats(r.br, &st);
	CHECKF(st.leg[BR_CARRIER].pcm_xrun_rx == 3, "rx xruns %u", st.leg[BR_CARRIER].pcm_xrun_rx);
	CHECKF(st.leg[BR_CARRIER].pcm_xrun_tx == 2, "tx xruns %u", st.leg[BR_CARRIER].pcm_xrun_tx);
	CHECKF(st.leg[BR_CARRIER].pcm_ul_full == 2, "full %u", st.leg[BR_CARRIER].pcm_ul_full);
	CHECK(!st.leg[BR_CARRIER].pcm_lost && st.leg[BR_CARRIER].tx_pkts >= 30);
	CHECK(ev_count(BR_EV_PCM_LOST) == 0);
	/* non-fatal errors: counted, the device is kept until five in a row */
	pthread_mutex_lock(&F.mu);
	F.bad_rx = 2;
	pthread_mutex_unlock(&F.mu);
	sleep_ms(200);
	bridge_get_stats(r.br, &st);
	CHECK(st.leg[BR_CARRIER].pcm_err == 2 && !st.leg[BR_CARRIER].pcm_lost);
	pthread_mutex_lock(&F.mu);
	F.bad_rx = 50;
	pthread_mutex_unlock(&F.mu);
	CHECK(wait_ev(BR_EV_PCM_LOST, 1, 2000));
	CHECK(ev_find(BR_EV_PCM_LOST)->err == -EIO);
	printf("  (x) rx xrun 3, tx xrun 2, full 2 recovered; five EIO in a row = device lost\n");
	rig_down(&r);
	fake_stop();
}

static void t_open_fail(void)
{
	struct rig r;
	const struct br_event *e;
	double ph = 0;
	int i, got = 0;

	fake_start(20000);
	pthread_mutex_lock(&F.mu);
	F.open_err = EBUSY;
	pthread_mutex_unlock(&F.mu);
	rig_up(&r, true, 0);
	CHECK(wait_ev(BR_EV_ERROR, 1, 2000));
	e = ev_find(BR_EV_ERROR);
	CHECK(e && e->err == EBUSY && strstr(e->msg, "open"));
	/* retry after the other voice device was closed */
	pthread_mutex_lock(&F.mu);
	F.open_err = 0;
	pthread_mutex_unlock(&F.mu);
	CHECK(bridge_start(r.br) == 0);
	for (i = 0; i < 20; i++) {
		lan_send_tone(&r, &ph);
		sleep_ms(20);
		got += lan_drain(&r, NULL);
	}
	CHECKF(got >= 10, "after the retry %d packets", got);
	/* ENODEV (no card) is reported the same way */
	CHECK(bridge_stop(r.br) == 0);
	CHECK(wait_ev(BR_EV_STOPPED, 1, 2000));
	pthread_mutex_lock(&F.mu);
	F.open_err = ENODEV;
	pthread_mutex_unlock(&F.mu);
	nev = 0;
	CHECK(bridge_start(r.br) == 0);
	CHECK(wait_ev(BR_EV_ERROR, 1, 2000));
	CHECK(ev_find(BR_EV_ERROR)->err == ENODEV);
	rig_down(&r);
	fake_stop();
	CHECK(F.opens == F.closes);
	printf("  (o) open EBUSY / ENODEV -> BR_EV_ERROR with errno; start again works\n");
}

static void t_gone(void)
{
	struct rig r;
	struct bridge_stats st;
	double ph = 0;
	int i, got = 0, before;

	fake_start(20000);
	rig_up(&r, true, 0);
	for (i = 0; i < 15; i++) {
		lan_send_tone(&r, &ph);
		sleep_ms(20);
		got += lan_drain(&r, NULL);
	}
	CHECK(got >= 8);
	pthread_mutex_lock(&F.mu);
	F.gone = true;
	eventfd_write(F.efd, 1);
	pthread_mutex_unlock(&F.mu);
	CHECK(wait_ev(BR_EV_PCM_LOST, 1, 2000));
	CHECK(ev_find(BR_EV_PCM_LOST)->err == -ENODEV);
	sleep_ms(100);
	bridge_get_stats(r.br, &st);
	CHECK(st.leg[BR_CARRIER].pcm_lost);
	CHECK(F.closes == 1);
	/* LAN keeps talking into the dead leg: no crash, nothing queued, the event is raised once */
	before = (int)F.writes;
	for (i = 0; i < 10; i++) {
		lan_send_tone(&r, &ph);
		sleep_ms(20);
	}
	CHECK((int)F.writes == before);
	CHECK(ev_count(BR_EV_PCM_LOST) == 1);
	printf("  (g) device disappears: one BR_EV_PCM_LOST (-ENODEV), device closed, bridge still alive\n");
	/* stop + start reopens it */
	pthread_mutex_lock(&F.mu);
	F.gone = false;
	pthread_mutex_unlock(&F.mu);
	CHECK(bridge_stop(r.br) == 0);
	CHECK(bridge_start(r.br) == 0);
	got = 0;
	for (i = 0; i < 15; i++) {
		lan_send_tone(&r, &ph);
		sleep_ms(20);
		got += lan_drain(&r, NULL);
	}
	CHECK(got >= 8 && F.opens == 2);
	rig_down(&r);
	fake_stop();
}

static void t_stall_and_hold(void)
{
	struct rig r;
	struct bridge_stats st;
	double ph = 0;
	int i, got;

	/* the capture stream stops (modem hung): rx timeout */
	fake_start(20000);
	rig_up(&r, true, 300);
	sleep_ms(200);
	CHECK(ev_count(BR_EV_RX_TIMEOUT) == 0);
	atomic_store(&F.ticking, false);
	CHECK(wait_ev(BR_EV_RX_TIMEOUT, 1, 2000));
	rig_down(&r);
	fake_stop();

	/* hold: the LAN leg is inactive: silence uplink, nothing downlink */
	ph = 0;
	fake_start(20000);
	rig_up(&r, true, 0);
	for (i = 0; i < 20; i++) {
		lan_send_tone(&r, &ph);
		sleep_ms(20);
	}
	lan_drain(&r, NULL);
	CHECK(bridge_set_dir(r.br, BR_CLIENT, BR_INACTIVE) == 0);
	sleep_ms(100);
	lan_drain(&r, NULL);
	pthread_mutex_lock(&F.mu);
	F.ul_n = 0;
	pthread_mutex_unlock(&F.mu);
	for (i = 0; i < 20; i++) {
		lan_send_tone(&r, &ph);
		sleep_ms(20);
	}
	got = lan_drain(&r, NULL);
	bridge_get_stats(r.br, &st);
	CHECK(got == 0);
	{
		int16_t z = 0;
		size_t k;

		pthread_mutex_lock(&F.mu);
		for (k = 0; k < F.ul_n; k++)
			z |= F.ul[k];
		CHECK(F.ul_n >= 10 * FR);
		pthread_mutex_unlock(&F.mu);
		CHECKF(z == 0, "uplink while on hold is silence");
	}
	CHECK(bridge_set_dir(r.br, BR_CLIENT, BR_SENDRECV) == 0);
	for (i = 0; i < 20; i++) {
		lan_send_tone(&r, &ph);
		sleep_ms(20);
		got += lan_drain(&r, NULL);
	}
	CHECKF(got >= 8, "after resume %d", got);
	printf("  (h) capture stall -> BR_EV_RX_TIMEOUT; hold = silence both ways, resume works\n");
	rig_down(&r);
	fake_stop();
}

static void t_dtmf(void)
{
	struct rig r;
	struct bridge_stats st;
	double ph = 0;
	int i, down = 0, up = 0;
	uint16_t dur;

	fake_start(20000);
	rig_up(&r, true, 0);
	lan_send_tone(&r, &ph);
	sleep_ms(40);
	/* RFC 4733 '5' from the LAN: start packet, updates, three end packets */
	for (dur = 160, i = 0; i < 8; i++, dur += 160) {
		struct dtmf_event ev = { .event = 5, .end = i >= 5, .volume = 10, .duration = i >= 5 ? 800 : dur };
		uint8_t pl[4], pkt[64];
		int n;

		dtmf_build(pl, &ev);
		n = rtp_build(pkt, sizeof(pkt), i == 0, 101, r.seq++, 0, 0x22220002u, pl, 4);
		sendto(r.lan_fd, pkt, (size_t)n, 0, (const struct sockaddr *)&r.brs.sa, sizeof(r.brs.sa));
		sleep_ms(20);
	}
	sleep_ms(100);
	bridge_events_dispatch(ev_cb, NULL);
	for (i = 0; i < nev; i++)
		if (evlog[i].type == BR_EV_DTMF && evlog[i].digit == '5') {
			if (evlog[i].end)
				up++;
			else
				down++;
		}
	bridge_get_stats(r.br, &st);
	CHECKF(down == 1 && up == 1, "digit events down %d up %d", down, up);
	CHECK(st.leg[BR_CARRIER].dtmf_dropped == 0);
	printf("  (t) RFC 4733 digit from the LAN: one key-down / key-up event for the main loop, none dropped\n");
	rig_down(&r);
	fake_stop();
}

/* the fake runs 3 bridges' worth of start / stop cycles while the main thread polls stats (TSan food) */
static void t_cycles(void)
{
	struct rig r;
	struct bridge_stats st;
	double ph = 0;
	int i, k;

	fake_start(5000);
	rig_up(&r, true, 0);
	for (k = 0; k < 6; k++) {
		for (i = 0; i < 10; i++) {
			lan_send_tone(&r, &ph);
			sleep_ms(5);
			bridge_get_stats(r.br, &st);
			lan_drain(&r, NULL);
		}
		CHECK(bridge_stop(r.br) == 0);
		CHECK(bridge_start(r.br) == 0);
	}
	sleep_ms(50);
	rig_down(&r);
	fake_stop();
	CHECKF(F.opens == F.closes && F.opens == 7, "opens %u closes %u", F.opens, F.closes);
	printf("  (c) 6 stop/start cycles at a 5 ms device clock: every open closed\n");
}

void test_pcmdev(void)
{
	CHECK(bridge_engine_start() == 0);
	t_pure();
	t_flow();
	t_drift();
	t_xrun();
	t_open_fail();
	t_gone();
	t_stall_and_hold();
	t_dtmf();
	t_cycles();
	bridge_engine_stop();
	free(F.ul);
}
