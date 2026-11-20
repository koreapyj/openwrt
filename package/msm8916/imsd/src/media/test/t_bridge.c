/* SPDX-License-Identifier: GPL-2.0-or-later */
/* End to end tests of the bridge over real UDP sockets on loopback. */
#include <errno.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "../amr.h"
#include "../bridge.h"
#include "../codec.h"
#include "../dtmf.h"
#include "../resample.h"
#include "../rtp.h"
#include "test.h"

#define PI 3.14159265358979323846
#define CAR_SSRC 0x11110001u
#define CLI_SSRC 0x22220002u

/* ------------------------------------------------------------ plumbing */

struct peer {
	int fd;
	struct addr addr;
};

static int sock_open(struct addr *out)
{
	int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	int off = 0;
	struct addr a;
	socklen_t sl = sizeof(a.sa);
	struct sockaddr_in6 got;

	if (fd < 0)
		return -1;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
	addr_set(&a, "127.0.0.1", 0);
	if (bind(fd, (struct sockaddr *)&a.sa, sizeof(a.sa)) < 0) {
		close(fd);
		return -1;
	}
	sl = sizeof(got);
	getsockname(fd, (struct sockaddr *)&got, &sl);
	addr_from_sa6(out, &got);
	return fd;
}

static void peer_open(struct peer *p)
{
	p->fd = sock_open(&p->addr);
	CHECK(p->fd >= 0);
}

static void psend(struct peer *p, const struct addr *to, bool m, uint8_t pt, uint16_t seq, uint32_t ts, uint32_t ssrc,
		  const void *pl, size_t len)
{
	uint8_t b[1500];
	int n = rtp_build(b, sizeof(b), m, pt, seq, ts, ssrc, pl, len);

	if (n > 0)
		sendto(p->fd, b, (size_t)n, 0, (const struct sockaddr *)&to->sa, sizeof(to->sa));
}

struct got {
	uint8_t b[512];
	size_t len;
	struct rtp_pkt p;
};

/* read until the socket has been idle for idle_ms; returns count (max max) */
static int collect(struct peer *p, struct got *g, int max, int idle_ms)
{
	int n = 0;

	for (;;) {
		struct pollfd pf = { .fd = p->fd, .events = POLLIN };
		ssize_t r;

		if (poll(&pf, 1, idle_ms) <= 0)
			break;
		if (n >= max) {
			uint8_t sink[2048];

			if (recv(p->fd, sink, sizeof(sink), 0) < 0)
				break;
			continue;
		}
		r = recv(p->fd, g[n].b, sizeof(g[n].b), 0);
		if (r < 0)
			break;
		g[n].len = (size_t)r;
		if (rtp_parse(g[n].b, (size_t)r, &g[n].p) < 0)
			continue;
		n++;
	}
	return n;
}

static struct br_event evlog[512];
static int nev;

static void ev_cb(void *arg, const struct br_event *ev)
{
	(void)arg;
	if (nev < 512)
		evlog[nev++] = *ev;
}

static void pump(void)
{
	bridge_events_dispatch(ev_cb, NULL);
}

static int ev_count(enum br_event_type t, int leg)
{
	int i, n = 0;

	pump();
	for (i = 0; i < nev; i++)
		if (evlog[i].type == t && (leg < 0 || evlog[i].leg == leg))
			n++;
	return n;
}

static bool wait_ev(enum br_event_type t, int leg, int want, int ms)
{
	int waited = 0;

	for (;;) {
		struct pollfd pf = { .fd = bridge_event_fd(), .events = POLLIN };

		if (ev_count(t, leg) >= want)
			return true;
		if (waited >= ms)
			return false;
		poll(&pf, 1, 10);
		waited += 10;
	}
}

struct tb {
	struct bridge *br;
	struct peer car, cli;
	struct addr car_b, cli_b;	/* bridge side addresses */
};

static void leg_udp(struct br_leg_cfg *c, enum codec_id id, int pt)
{
	br_leg_cfg_default(c);
	c->kind = BR_LEG_UDP;
	c->codec = id;
	c->pt = (uint8_t)pt;
}

static void tb_setup(struct tb *t, struct br_leg_cfg *c0, struct br_leg_cfg *c1, bool start)
{
	nev = 0;
	peer_open(&t->car);
	peer_open(&t->cli);
	c0->fd = sock_open(&t->car_b);
	c1->fd = sock_open(&t->cli_b);
	c0->own_fd = c1->own_fd = true;
	c0->remote = t->car.addr;
	c0->has_remote = true;
	if (!c1->learn) {
		c1->remote = t->cli.addr;
		c1->has_remote = true;
	}
	t->br = bridge_create(t);
	CHECK(t->br != NULL);
	CHECK(bridge_set_leg(t->br, BR_CARRIER, c0) == 0);
	CHECK(bridge_set_leg(t->br, BR_CLIENT, c1) == 0);
	if (start)
		CHECK(bridge_start(t->br) == 0);
}

static void tb_end(struct tb *t)
{
	bridge_destroy(t->br);
	CHECK(wait_ev(BR_EV_DESTROYED, -1, 1, 3000));
	close(t->car.fd);
	close(t->cli.fd);
}

static void send_cap(struct peer *from, const struct addr *to, const struct cap *c, size_t first, size_t last, int us,
		     uint32_t ssrc, struct peer *rx, struct got *g, int *n, int max)
{
	size_t i;

	for (i = first; i < last && i < c->n; i++) {
		psend(from, to, i == first, c->r[i].pt, c->r[i].seq, c->r[i].ts, ssrc, c->r[i].p, c->r[i].len);
		if (us)
			usleep((useconds_t)us);
		if (rx)	/* drain while sending: a loopback socket buffer holds only ~250 small datagrams */
			*n += collect(rx, g + *n, max - *n, 0);
	}
}

static void sine16(int16_t *x, size_t n, double hz, double rate, double amp, size_t off)
{
	size_t i;

	for (i = 0; i < n; i++)
		x[i] = (int16_t)(amp * sin(2 * PI * hz * (double)(i + off) / rate));
}

/* checks of the output stream of a leg: ssrc constant, pt, seq +1, ts + step, marker only first; returns packets */
static void check_stream(const char *what, const struct got *g, int n, uint8_t pt, uint32_t step, bool strict_ts)
{
	int i, bad_seq = 0, bad_ts = 0, bad_m = 0, bad_ssrc = 0, bad_pt = 0;

	for (i = 0; i < n; i++) {
		if (g[i].p.h.ssrc != g[0].p.h.ssrc)
			bad_ssrc++;
		if (g[i].p.h.pt != pt)
			bad_pt++;
		if (i) {
			if (rtp_seq_diff(g[i].p.h.seq, g[i - 1].p.h.seq) != 1)
				bad_seq++;
			if (strict_ts && rtp_ts_diff(g[i].p.h.ts, g[i - 1].p.h.ts) != (int32_t)step)
				bad_ts++;
			if (g[i].p.h.marker && strict_ts)
				bad_m++;
		}
	}
	CHECKF(n > 0 && g[0].p.h.marker, "%s: first packet marker", what);
	CHECKF(!bad_seq && !bad_ts && !bad_m && !bad_ssrc && !bad_pt, "%s: bad seq %d ts %d marker %d ssrc %d pt %d of %d",
	       what, bad_seq, bad_ts, bad_m, bad_ssrc, bad_pt, n);
}

/* ------------------------------------------------------------ (a) AMR-WB capture -> Opus */

static void t_wb_to_opus(void)
{
	struct cap c;
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[800];
	int n, i;
	struct codec *od, *ad;
	static int16_t out[800 * 320 + 4000], ref[800 * 320 + 4000];
	size_t no = 0, nr = 0;
	struct bridge_stats st;

	if (cap_load(&c, "l1/mt/rtp_rx.bin") < 0)
		return;
	leg_udp(&c0, CODEC_AMRWB, 100);
	c0.amr_oa = true;
	c0.te_pt = 107;
	leg_udp(&c1, CODEC_OPUS, 111);
	c1.cp.bitrate = 24000;
	tb_setup(&t, &c0, &c1, true);
	n = 0;
	send_cap(&t.car, &t.car_b, &c, 0, c.n, 400, CAR_SSRC, &t.cli, g, &n, 800);
	n += collect(&t.cli, g + n, 800 - n, 400);
	printf("  (a) %zu AMR-WB packets in, %d Opus packets out\n", c.n, n);
	{
		size_t tl = (size_t)(rtp_ts_diff(c.r[c.n - 1].ts, c.r[0].ts) / 320) + 1;

		printf("  (a) capture timeline %zu frames (%zu packets; the rest is DTX silence)\n", tl, c.n);
		CHECKF(n >= (int)c.n && n <= (int)tl, "got %d want %zu..%zu", n, c.n, tl);
		/* the output timeline is the input timeline: 960 ticks per 320 */
		CHECK(rtp_ts_diff(g[n - 1].p.h.ts, g[0].p.h.ts) == 3 * rtp_ts_diff(c.r[c.n - 1].ts, c.r[0].ts));
	}
	check_stream("a", g, n, 111, 960, false);
	od = codec_create(CODEC_OPUS, NULL);
	ad = codec_create(CODEC_AMRWB, NULL);
	for (i = 0; i < n; i++) {
		int d = codec_decode(od, g[i].p.payload, g[i].p.plen, out + no, 320);

		CHECK(d == 320);
		if (d > 0)
			no += (size_t)d;
	}
	{
		bool prev_dtx = false;

		/* reference: the same decoder run on the capture, with the comfort-noise fill the bridge does */
		for (i = 0; i < (int)c.n; i++) {
			struct amr_pdu pdu;
			int gap = i ? (int)(rtp_ts_diff(c.r[i].ts, c.r[i - 1].ts) / 320) - 1 : 0, k;

			if (gap > 0 && gap <= 16 && prev_dtx)
				for (k = 0; k < gap; k++)
					nr += (size_t)codec_decode(ad, NULL, 0, ref + nr, 320);
			if (amr_parse(AMR_WB, true, c.r[i].p, c.r[i].len, &pdu) == 0) {
				int d2 = codec_decode(ad, pdu.f[0].data, 1u + pdu.f[0].nbytes, ref + nr, 320);

				if (d2 > 0)
					nr += (size_t)d2;
				prev_dtx = amr_ft_is_dtx(AMR_WB, pdu.f[0].ft);
			}
		}
	}
	printf("  (a) %d output frames decoded, %zu reference frames\n", n, nr / 320);
	CHECK(nr == no);
	{
		int lag;
		size_t skip = 16000;
		double corr = best_corr(ref + skip, out + skip, nr - skip - 2000, 700, &lag);
		double ratio = rms16(out + skip, no - skip) / rms16(ref + skip, nr - skip);

		printf("  (a) opus vs direct AMR-WB decode: corr %.3f at lag %d, rms ratio %.2f\n", corr, lag,
		       ratio);
		CHECK(corr > 0.7 && ratio > 0.6 && ratio < 1.4);
	}
	bridge_get_stats(t.br, &st);
	CHECK(st.leg[BR_CARRIER].rx_pkts == c.n && st.leg[BR_CLIENT].tx_pkts == (uint64_t)n);
	CHECK(st.leg[BR_CARRIER].rx_lost == 0 && st.leg[BR_CARRIER].rx_bad == 0);
	CHECK(ev_count(BR_EV_FIRST_RX, BR_CARRIER) == 1 && ev_count(BR_EV_FIRST_RX, BR_CLIENT) == 0);
	codec_destroy(od);
	codec_destroy(ad);
	tb_end(&t);
	cap_free(&c);
}

/* ------------------------------------------------------------ (b) PCMA -> AMR-WB with CMR */

static void send_amr_cmr(struct tb *t, bool oa, unsigned cmr, uint16_t *seq, uint32_t *ts)
{
	struct amr_frame f;
	uint8_t pl[16];
	int n;

	memset(&f, 0, sizeof(f));
	f.ft = 15;
	amr_frame_finish(&f);
	n = amr_build(AMR_WB, oa, cmr, &f, 1, pl, sizeof(pl));
	psend(&t->car, &t->car_b, false, 104, (*seq)++, *ts, CAR_SSRC, pl, (size_t)n);
	*ts += 320;
	usleep(30000);
}

static void send_pcma(struct tb *t, int nfr, uint16_t *seq, uint32_t *ts, int *phase)
{
	int i;
	struct codec *pc = codec_create(CODEC_PCMA, NULL);
	int16_t pcm[160];
	uint8_t b[160];

	for (i = 0; i < nfr; i++) {
		bool first = i == 0 && *seq == 0;

		sine16(pcm, 160, 1000, 8000, 8000, (size_t)(*phase) * 160);
		(*phase)++;
		codec_encode(pc, pcm, b, sizeof(b));
		psend(&t->cli, &t->cli_b, first, 8, *seq, *ts, CLI_SSRC, b, 160);
		(*seq)++;
		*ts += 160;
		usleep(600);
	}
	codec_destroy(pc);
}

static void t_pcma_to_wb_cmr(void)
{
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[200];
	uint16_t cseq = 100, sseq = 0;
	uint32_t cts = 5000, sts = 9000;
	int phase = 0, n, i, ph;
	static const struct { unsigned cmr; int ft; } steps[] = { { 4, 3 }, { 1, 0 }, { 15, 0 }, { 8, 8 } };
	static int16_t dec[200 * 320], refsine[200 * 320];
	size_t nd = 0;
	struct codec *wd = codec_create(CODEC_AMRWB, NULL);
	int total = 0;

	leg_udp(&c0, CODEC_AMRWB, 104);
	c0.amr_oa = false;
	c0.cp.modeset = amr_modeset_parse(AMR_WB, "0,2,3,8");
	leg_udp(&c1, CODEC_PCMA, 8);
	tb_setup(&t, &c0, &c1, true);
	for (ph = 0; ph < 4; ph++) {
		struct got *gp = g + total;

		send_amr_cmr(&t, false, steps[ph].cmr, &cseq, &cts);
		/* the NO_DATA packet makes the bridge answer the client with comfort noise: drain it */
		(void)collect(&t.cli, (struct got[4]){ 0 } , 0, 60);
		send_pcma(&t, 20, &sseq, &sts, &phase);
		n = collect(&t.car, gp, 200 - total, 150);
		CHECKF(n == 20, "phase %d: %d packets", ph, n);
		for (i = 0; i < n; i++) {
			struct amr_pdu pdu;

			if (amr_parse(AMR_WB, false, gp[i].p.payload, gp[i].p.plen, &pdu) < 0 || pdu.n != 1) {
				CHECK(0);
				continue;
			}
			CHECKF(pdu.f[0].ft == steps[ph].ft && pdu.cmr == 15, "phase %d pkt %d ft %d cmr %u", ph, i, pdu.f[0].ft, pdu.cmr);
			if (ph == 3 && i >= 5) {
				int d = codec_decode(wd, pdu.f[0].data, 1u + pdu.f[0].nbytes, dec + nd, 320);

				if (d > 0)
					nd += (size_t)d;
			}
		}
		total += n;
	}
	check_stream("b", g, total, 104, 320, true);
	{
		int lag;
		double corr;

		sine16(refsine, nd + 600, 1000, 16000, 8000, 0);
		corr = best_corr(refsine + 640, dec, nd - 100, 600, &lag);
		printf("  (b) PCMA -> AMR-WB: modes followed CMR 4->3, 1->0, 15->0, 8->8; mode 8 tone corr %.3f\n", corr);
		CHECK(corr > 0.9);
	}
	codec_destroy(wd);
	tb_end(&t);
}

/* ------------------------------------------------------------ (c) AMR-NB capture <-> G.722 */

#ifdef IMSD_WITH_G722
static void t_nb_g722(void)
{
	struct cap c;
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[1200];
	int n, i;
	static int16_t out[1200 * 320], ref[1200 * 160], o8[1200 * 160];
	size_t no = 0, nr = 0, gaps = 0, dtx = 0;
	struct codec *gd = codec_create(CODEC_G722, NULL), *ad = codec_create(CODEC_AMRNB, NULL);
	struct resamp rs;

	if (cap_load(&c, "run1/rtp_rx.bin") < 0)
		return;
	leg_udp(&c0, CODEC_AMRNB, 102);
	c0.amr_oa = false;
	leg_udp(&c1, CODEC_G722, 9);
	tb_setup(&t, &c0, &c1, true);
	n = 0;
	send_cap(&t.car, &t.car_b, &c, 0, c.n, 400, CAR_SSRC, &t.cli, g, &n, 1200);
	n += collect(&t.cli, g + n, 1200 - n, 400);
	{
		bool prev_dtx = false;

		/* reference: AMR-NB decode of the capture with the comfort-noise fill the bridge performs */
		for (i = 0; i < (int)c.n; i++) {
			struct amr_pdu pdu;
			int gap = i ? (int)(rtp_ts_diff(c.r[i].ts, c.r[i - 1].ts) / 160) - 1 : 0, k;

			if (i && rtp_seq_diff(c.r[i].seq, c.r[i - 1].seq) != 1)
				gaps++;
			if (gap > 0 && gap <= 16 && prev_dtx)
				for (k = 0; k < gap; k++)
					nr += (size_t)codec_decode(ad, NULL, 0, ref + nr, 160);
			if (amr_parse(AMR_NB, false, c.r[i].p, c.r[i].len, &pdu) == 0) {
				int d = codec_decode(ad, pdu.f[0].data, 1u + pdu.f[0].nbytes, ref + nr, 160);

				dtx += amr_ft_is_dtx(AMR_NB, pdu.f[0].ft);
				if (d > 0)
					nr += (size_t)d;
				prev_dtx = amr_ft_is_dtx(AMR_NB, pdu.f[0].ft);
			}
		}
	}
	printf("  (c) %zu AMR-NB packets in (%zu seq gaps, %zu SID/NO_DATA), %d G.722 packets out, %zu reference frames\n", c.n,
	       gaps, dtx, n, nr / 160);
	CHECK(n > 0 && (size_t)n * 160 == nr);
	/* timeline: output duration == input duration (both RTP clocks are 8000) */
	CHECK(n > 0 && rtp_ts_diff(g[n - 1].p.h.ts, g[0].p.h.ts) == rtp_ts_diff(c.r[c.n - 1].ts, c.r[0].ts));
	check_stream("c", g, n, 9, 160, false);
	for (i = 0; i < n; i++) {
		int d = codec_decode(gd, g[i].p.payload, g[i].p.plen, out + no, 320);

		CHECK(g[i].p.plen == 160 && d == 320);
		if (d > 0)
			no += (size_t)d;
	}
	{
		size_t k, m = 0;

		resamp_init(&rs);
		for (k = 0; k + 320 <= no; k += 320)
			m += (size_t)resamp_down2(&rs, out + k, 320, o8 + m);
		{
			int lag;
			double corr = best_corr(ref + 8000, o8 + 8000, m - 8000 - 1000, 200, &lag);
			double ratio = rms16(o8 + 8000, m - 8000) / rms16(ref + 8000, nr - 8000);

			printf("  (c) G.722 output vs direct AMR-NB decode (8 kHz): corr %.3f lag %d rms ratio %.2f\n", corr, lag, ratio);
			CHECK(corr > 0.9 && ratio > 0.7 && ratio < 1.3);
		}
	}
	codec_destroy(gd);
	codec_destroy(ad);
	tb_end(&t);
	cap_free(&c);
}

static void t_g722_to_nb(void)
{
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[100];
	struct codec *gc = codec_create(CODEC_G722, NULL), *ad = codec_create(CODEC_AMRNB, NULL);
	int i, n;
	static int16_t dec[100 * 160], sn[100 * 160 + 400];
	size_t nd = 0;

	leg_udp(&c0, CODEC_AMRNB, 102);
	c0.amr_oa = true;
	c0.cp.modeset = amr_modeset_parse(AMR_NB, "7");
	leg_udp(&c1, CODEC_G722, 9);
	tb_setup(&t, &c0, &c1, true);
	for (i = 0; i < 60; i++) {
		int16_t pcm[320];
		uint8_t b[160];

		sine16(pcm, 320, 800, 16000, 8000, (size_t)i * 320);
		codec_encode(gc, pcm, b, sizeof(b));
		psend(&t.cli, &t.cli_b, i == 0, 9, (uint16_t)(40 + i), (uint32_t)(i * 160), CLI_SSRC, b, 160);
		usleep(600);
	}
	n = collect(&t.car, g, 100, 300);
	printf("  (c) 60 G.722 packets in -> %d AMR-NB packets out\n", n);
	CHECK(n == 60);
	check_stream("c2", g, n, 102, 160, true);
	for (i = 0; i < n; i++) {
		struct amr_pdu pdu;

		if (amr_parse(AMR_NB, true, g[i].p.payload, g[i].p.plen, &pdu) == 0 && pdu.n == 1) {
			CHECK(pdu.f[0].ft == 7);
			if (i >= 10) {
				int d = codec_decode(ad, pdu.f[0].data, 1u + pdu.f[0].nbytes, dec + nd, 160);

				if (d > 0)
					nd += (size_t)d;
			}
		} else {
			CHECK(0);
		}
	}
	{
		int lag;
		double corr;

		sine16(sn, 100 * 160, 800, 8000, 8000, 0);
		corr = best_corr(sn + 1600, dec, nd - 400, 300, &lag);
		printf("  (c) 800 Hz tone through G.722 -> AMR-NB 12.2k: corr %.3f\n", corr);
		CHECK(corr > 0.85);
	}
	codec_destroy(gc);
	codec_destroy(ad);
	tb_end(&t);
}
#endif

/* ------------------------------------------------------------ (d) hold */

static int pcma_burst(struct peer *from, const struct addr *to, uint32_t ssrc, uint16_t *seq, uint32_t *ts, int n)
{
	uint8_t b[160];
	int i;

	memset(b, 0xd5, sizeof(b));
	for (i = 0; i < n; i++) {
		psend(from, to, false, 8, (*seq)++, *ts, ssrc, b, 160);
		*ts += 160;
		usleep(500);
	}
	return n;
}

static void t_hold(void)
{
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[64];
	uint16_t cs = 1, ss = 1;
	uint32_t ct = 1000, st = 2000;
	int n;

	leg_udp(&c0, CODEC_PCMA, 8);
	leg_udp(&c1, CODEC_PCMA, 8);
	tb_setup(&t, &c0, &c1, true);
	/* baseline both ways */
	pcma_burst(&t.car, &t.car_b, CAR_SSRC, &cs, &ct, 10);
	n = collect(&t.cli, g, 64, 100);
	CHECK(n == 10);
	pcma_burst(&t.cli, &t.cli_b, CLI_SSRC, &ss, &st, 10);
	n = collect(&t.car, g, 64, 100);
	CHECK(n == 10);
	/* carrier inactive: nothing either way */
	bridge_set_dir(t.br, BR_CARRIER, BR_INACTIVE);
	usleep(40000);
	pcma_burst(&t.car, &t.car_b, CAR_SSRC, &cs, &ct, 10);
	pcma_burst(&t.cli, &t.cli_b, CLI_SSRC, &ss, &st, 10);
	CHECK(collect(&t.cli, g, 64, 100) == 0);
	CHECK(collect(&t.car, g, 64, 100) == 0);
	/* resume; client sendonly (we only send to it): carrier->client flows, client->carrier does not */
	bridge_set_dir(t.br, BR_CARRIER, BR_SENDRECV);
	bridge_set_dir(t.br, BR_CLIENT, BR_SENDONLY);
	usleep(40000);
	pcma_burst(&t.car, &t.car_b, CAR_SSRC, &cs, &ct, 10);
	pcma_burst(&t.cli, &t.cli_b, CLI_SSRC, &ss, &st, 10);
	n = collect(&t.cli, g, 64, 100);
	CHECK(n == 10);
	if (n > 0)
		CHECK(g[0].p.h.marker);	/* talkspurt restarts after hold */
	CHECK(collect(&t.car, g, 64, 100) == 0);
	/* client recvonly (we never send to it): client->carrier flows only */
	bridge_set_dir(t.br, BR_CLIENT, BR_RECVONLY);
	usleep(40000);
	pcma_burst(&t.car, &t.car_b, CAR_SSRC, &cs, &ct, 10);
	pcma_burst(&t.cli, &t.cli_b, CLI_SSRC, &ss, &st, 10);
	CHECK(collect(&t.cli, g, 64, 100) == 0);
	n = collect(&t.car, g, 64, 100);
	CHECK(n == 10);
	/* back to sendrecv: the carrier-bound stream continues without a timestamp hole */
	bridge_set_dir(t.br, BR_CLIENT, BR_SENDRECV);
	usleep(40000);
	pcma_burst(&t.cli, &t.cli_b, CLI_SSRC, &ss, &st, 10);
	n = collect(&t.car, g, 64, 100);
	CHECK(n == 10);
	tb_end(&t);
	printf("  (d) hold: inactive / sendonly / recvonly / resume behave as specified\n");
}

/* ------------------------------------------------------------ (e) DTMF */

static void dtmf_pkt(struct peer *from, const struct addr *to, uint32_t ssrc, bool m, uint8_t pt, uint16_t seq, uint32_t ts,
		     uint8_t ev, bool end, uint16_t dur)
{
	uint8_t pl[4];
	struct dtmf_event e = { .event = ev, .end = end, .volume = 10, .duration = dur };

	dtmf_build(pl, &e);
	psend(from, to, m, pt, seq, ts, ssrc, pl, 4);
	usleep(2000);
}

static void check_dtmf_out(const char *what, const struct got *g, int n, bool up)
{
	int i;
	unsigned step = up ? 320 : 160;	/* 20 ms in the destination te clock */

	/* the event is regenerated: 80 ms announced -> min 100 ms: 5 updates every 20 ms, then the end packet x3 */
	CHECKF(n == 8, "%s: %d event packets", what, n);
	if (n != 8)
		return;
	for (i = 0; i < 8; i++) {
		struct dtmf_event e;

		CHECK(dtmf_parse(g[i].p.payload, g[i].p.plen, &e) == 0);
		CHECK(e.event == 5 && e.volume == 10);
		CHECK(g[i].p.h.ts == g[0].p.h.ts);
		CHECK(g[i].p.h.marker == (i == 0));
		if (i)
			CHECK(rtp_seq_diff(g[i].p.h.seq, g[i - 1].p.h.seq) == 1);
		if (i < 5)
			CHECK(!e.end && e.duration == step * (unsigned)(i + 1));
		else
			CHECK(e.end && e.duration == step * 5);
	}
}

static void t_dtmf(void)
{
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[64];
	int n, i;
	uint32_t T = 777000;

	leg_udp(&c0, CODEC_AMRWB, 104);
	c0.te_pt = 107;
	c0.te_clock = 16000;
	leg_udp(&c1, CODEC_PCMA, 8);
	c1.te_pt = 101;
	c1.te_clock = 8000;
	tb_setup(&t, &c0, &c1, true);
	/* client (8 kHz events) -> carrier (16 kHz) */
	dtmf_pkt(&t.cli, &t.cli_b, CLI_SSRC, true, 101, 1, T, 5, false, 160);
	dtmf_pkt(&t.cli, &t.cli_b, CLI_SSRC, false, 101, 2, T, 5, false, 320);
	dtmf_pkt(&t.cli, &t.cli_b, CLI_SSRC, false, 101, 3, T, 5, false, 480);
	for (i = 0; i < 3; i++)
		dtmf_pkt(&t.cli, &t.cli_b, CLI_SSRC, false, 101, (uint16_t)(4 + i), T, 5, true, 640);
	n = collect(&t.car, g, 64, 150);
	check_dtmf_out("client->carrier", g, n, true);
	/* carrier (16 kHz) -> client (8 kHz); the source sends only ONE end packet this time */
	T = 5000;
	dtmf_pkt(&t.car, &t.car_b, CAR_SSRC, true, 107, 10, T, 5, false, 320);
	dtmf_pkt(&t.car, &t.car_b, CAR_SSRC, false, 107, 11, T, 5, false, 640);
	dtmf_pkt(&t.car, &t.car_b, CAR_SSRC, false, 107, 12, T, 5, false, 960);
	dtmf_pkt(&t.car, &t.car_b, CAR_SSRC, false, 107, 13, T, 5, true, 1280);
	n = collect(&t.cli, g, 64, 150);
	check_dtmf_out("carrier->client", g, n, false);
	/* main thread saw start+end on each leg */
	CHECK(wait_ev(BR_EV_DTMF, BR_CLIENT, 2, 500) && wait_ev(BR_EV_DTMF, BR_CARRIER, 2, 500));
	{
		int k, ends = 0, starts = 0;

		for (k = 0; k < nev; k++)
			if (evlog[k].type == BR_EV_DTMF) {
				CHECK(evlog[k].digit == '5');
				if (evlog[k].end) {
					ends++;
					CHECK(evlog[k].duration_ms == 80);
				} else {
					starts++;
				}
			}
		CHECK(starts == 2 && ends == 2);
	}
	/* a never terminated event is closed by the idle timer */
	dtmf_pkt(&t.cli, &t.cli_b, CLI_SSRC, true, 101, 20, 99000, 7, false, 160);
	n = collect(&t.car, g, 64, 900);
	/* regenerated: 100 ms minimum, the key counts as released 100 ms after the last packet (5..6 updates) + end x3 */
	CHECKF(n >= 8 && n <= 9, "idle close: %d packets", n);
	if (n >= 8)
		CHECK(g[n - 1].p.h.pt == 107 && (g[n - 1].p.payload[1] & 0x80) && (g[n - 3].p.payload[1] & 0x80) &&
		      !(g[n - 4].p.payload[1] & 0x80));
	/* unknown payload type is dropped and counted */
	{
		struct bridge_stats st;
		uint8_t b[10] = { 0 };

		psend(&t.cli, &t.cli_b, false, 77, 30, 0, CLI_SSRC, b, 10);
		usleep(50000);
		bridge_get_stats(t.br, &st);
		CHECK(st.leg[BR_CLIENT].rx_dropped >= 1 && st.leg[BR_CLIENT].dtmf_events == 2);
	}
	tb_end(&t);
	printf("  (e) DTMF relayed both ways with clock scaling, end triplet, idle close\n");
}

/* ------------------------------------------------------------ loss, DTX, sources, learn, timeout */

/* indexes of capture packets that carry exactly one WB speech frame (octet aligned) */
static size_t speech_idx(const struct cap *c, size_t *idx, size_t max)
{
	size_t i, n = 0;

	for (i = 0; i < c->n && n < max; i++) {
		struct amr_pdu pdu;

		if (amr_parse(AMR_WB, true, c->r[i].p, c->r[i].len, &pdu) == 0 && pdu.n == 1 && pdu.f[0].ft <= 8 && pdu.f[0].nbytes > 20)
			idx[n++] = i;
	}
	return n;
}

static void t_loss_dtx(void)
{
	struct cap c;
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[300];
	size_t sp[200], nsp, i;
	int n;
	struct bridge_stats st;
	uint16_t seq = 1000;
	uint32_t ts = 50000;

	if (cap_load(&c, "n1/rtp_rx.bin") < 0)
		return;
	nsp = speech_idx(&c, sp, 200);
	CHECK(nsp == 200);
	leg_udp(&c0, CODEC_AMRWB, 104);
	c0.amr_oa = true;
	leg_udp(&c1, CODEC_OPUS, 111);
	tb_setup(&t, &c0, &c1, true);
#define SP(k) c.r[sp[(k)]].p, c.r[sp[(k)]].len
	/* 40 packets, 3 lost, 40 more */
	for (i = 0; i < 40; i++, seq++, ts += 320) {
		psend(&t.car, &t.car_b, i == 0, 104, seq, ts, CAR_SSRC, SP(i));
		usleep(400);
	}
	seq += 3;
	ts += 3 * 320;
	for (i = 40; i < 80; i++, seq++, ts += 320) {
		psend(&t.car, &t.car_b, false, 104, seq, ts, CAR_SSRC, SP(i));
		usleep(400);
	}
	n = collect(&t.cli, g, 300, 300);
	CHECKF(n == 80, "loss: %d out", n);
	if (n == 80) {
		CHECK(rtp_seq_diff(g[40].p.h.seq, g[39].p.h.seq) == 4);	/* the gap is passed on */
		CHECK(rtp_ts_diff(g[40].p.h.ts, g[39].p.h.ts) == 4 * 960);
		CHECK(!g[40].p.h.marker);
		CHECK(rtp_seq_diff(g[41].p.h.seq, g[40].p.h.seq) == 1 && rtp_ts_diff(g[41].p.h.ts, g[40].p.h.ts) == 960);
	}
	bridge_get_stats(t.br, &st);
	CHECK(st.leg[BR_CARRIER].rx_lost == 3 && st.leg[BR_CARRIER].plc_frames == 3);
	/* duplicates and late packets are dropped */
	psend(&t.car, &t.car_b, false, 104, (uint16_t)(seq - 1), ts - 320, CAR_SSRC, SP(79));
	psend(&t.car, &t.car_b, false, 104, (uint16_t)(seq - 5), ts - 5 * 320, CAR_SSRC, SP(75));
	CHECK(collect(&t.cli, g, 300, 150) == 0);
	bridge_get_stats(t.br, &st);
	CHECK(st.leg[BR_CARRIER].rx_dropped >= 2);
	/* DTX: speech, SID, (7 silent frames), SID, speech: continuous output, no marker */
	{
		struct amr_frame sid;
		uint8_t pl[16];
		int len;
		uint32_t ssrc = CAR_SSRC + 1;

		seq = 200;
		ts = 100000;
		memset(&sid, 0, sizeof(sid));
		sid.ft = 9;
		sid.q = 1;
		sid.nbytes = 5;
		sid.data[1] = 0x12;
		amr_frame_finish(&sid);
		len = amr_build(AMR_WB, true, 15, &sid, 1, pl, sizeof(pl));
		for (i = 0; i < 10; i++) {
			psend(&t.car, &t.car_b, i == 0, 104, seq++, ts, ssrc, SP(100 + i));
			ts += 320;
			usleep(400);
		}
		psend(&t.car, &t.car_b, false, 104, seq++, ts, ssrc, pl, (size_t)len);
		ts += 320 * 8;	/* next SID 160 ms later */
		usleep(400);
		psend(&t.car, &t.car_b, false, 104, seq++, ts, ssrc, pl, (size_t)len);
		ts += 320;
		usleep(400);
		psend(&t.car, &t.car_b, true, 104, seq++, ts, ssrc, SP(120));
		n = collect(&t.cli, g, 300, 300);
		printf("  (j) DTX: 10 speech + SID + 7 silent + SID + speech -> %d packets\n", n);
		CHECKF(n == 10 + 1 + 7 + 1 + 1, "dtx fill: %d", n);
		if (n >= 2)
			for (i = 1; i < (size_t)n; i++)
				CHECK(!g[i].p.h.marker && rtp_ts_diff(g[i].p.h.ts, g[i - 1].p.h.ts) == 960);
	}
	/* a long pause without SID (> fill limit) is not filled: marker on resume, timestamps jump */
	{
		seq = 400;
		ts = 500000;
		psend(&t.car, &t.car_b, false, 104, seq++, ts, CAR_SSRC + 2, SP(130));
		usleep(2000);
		psend(&t.car, &t.car_b, true, 104, seq++, ts + 320 * 50, CAR_SSRC + 2, SP(131));
		n = collect(&t.cli, g, 300, 200);
		CHECK(n == 2);
		if (n == 2)
			CHECK(g[1].p.h.marker && rtp_ts_diff(g[1].p.h.ts, g[0].p.h.ts) == 960 * 50);
	}
#undef SP
	tb_end(&t);
	cap_free(&c);
}

static void t_sources(void)
{
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[64];
	struct peer other, cli2;
	uint16_t s = 1;
	uint32_t ts = 0;
	struct bridge_stats st;

	/* carrier leg validates the source; client leg learns */
	leg_udp(&c0, CODEC_PCMA, 8);
	leg_udp(&c1, CODEC_PCMA, 8);
	c1.learn = true;
	c0.rx_timeout_ms = 250;
	tb_setup(&t, &c0, &c1, true);
	peer_open(&other);
	peer_open(&cli2);
	/* nothing known about the client yet: carrier audio has nowhere to go */
	pcma_burst(&t.car, &t.car_b, CAR_SSRC, &s, &ts, 3);
	usleep(30000);
	bridge_get_stats(t.br, &st);
	CHECK(st.leg[BR_CLIENT].tx_err >= 3);
	/* the client announces itself from cli2 (not the socket tests normally use) */
	{
		uint16_t s2 = 1;
		uint32_t t2 = 0;

		pcma_burst(&cli2, &t.cli_b, CLI_SSRC, &s2, &t2, 5);
		CHECK(collect(&t.car, g, 64, 100) == 5);
		pcma_burst(&t.car, &t.car_b, CAR_SSRC, &s, &ts, 5);
		CHECK(collect(&cli2, g, 64, 100) == 5);	/* learned */
		CHECK(collect(&t.cli, g, 64, 50) == 0);
	}
	/* a stranger sending to the carrier leg is ignored */
	pcma_burst(&other, &t.car_b, 0x99, &s, &ts, 5);
	CHECK(collect(&t.cli, g, 64, 50) == 0 && collect(&cli2, g, 64, 100) == 0);
	bridge_get_stats(t.br, &st);
	CHECK(st.leg[BR_CARRIER].rx_dropped >= 5);
	/* RTP garbage */
	{
		uint8_t junk[20] = { 0x45, 0x00 };

		sendto(t.car.fd, junk, sizeof(junk), 0, (struct sockaddr *)&t.car_b.sa, sizeof(t.car_b.sa));
		usleep(30000);
		bridge_get_stats(t.br, &st);
		CHECK(st.leg[BR_CARRIER].rx_bad == 1);
	}
	/* rx timeout event on the carrier leg after 250 ms of silence */
	CHECK(wait_ev(BR_EV_RX_TIMEOUT, BR_CARRIER, 1, 1500));
	CHECK(ev_count(BR_EV_RX_TIMEOUT, BR_CLIENT) == 0);
	/* remote change by command */
	bridge_set_remote(t.br, BR_CLIENT, &t.cli.addr);
	usleep(30000);
	pcma_burst(&t.car, &t.car_b, CAR_SSRC, &s, &ts, 3);
	CHECK(collect(&t.cli, g, 64, 100) == 3);
	close(other.fd);
	close(cli2.fd);
	tb_end(&t);
	printf("  (src) source validation, learn-from-source, rx timeout, set_remote ok\n");
}

/* ------------------------------------------------------------ (g) PCM leg: file and callbacks */

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static int16_t cb_buf[200000];
static size_t cb_n, cb_src_calls;

static size_t cb_src(void *arg, int16_t *pcm, size_t n)
{
	(void)arg;
	if (cb_src_calls++ >= 25)
		return 0;
	sine16(pcm, n, 600, 8000, 6000, (cb_src_calls - 1) * n);
	return n;
}

static void cb_sink(void *arg, const int16_t *pcm, size_t n)
{
	(void)arg;
	if (cb_n + n <= sizeof(cb_buf) / 2) {
		memcpy(cb_buf + cb_n, pcm, n * 2);
		cb_n += n;
	}
}

static void t_pcm_leg(void)
{
	char play[190], rec[190];
	FILE *f;
	uint8_t h[44];
	static int16_t pcm[16000];
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[100];
	struct cap c;
	int n;

	snprintf(play, sizeof(play), "%s/play.wav", test_tmp());
	snprintf(rec, sizeof(rec), "%s/rec.wav", test_tmp());
	sine16(pcm, 16000, 1000, 16000, 8000, 0);
	f = fopen(play, "wb");
	CHECK(f != NULL);
	if (!f)
		return;
	memset(h, 0, sizeof(h));
	memcpy(h, "RIFF", 4);
	put32(h + 4, 36 + 32000);
	memcpy(h + 8, "WAVEfmt ", 8);
	put32(h + 16, 16);
	h[20] = 1; h[22] = 1;
	put32(h + 24, 16000);
	put32(h + 28, 32000);
	h[32] = 2; h[34] = 16;
	memcpy(h + 36, "data", 4);
	put32(h + 40, 32000);
	fwrite(h, 1, 44, f);
	fwrite(pcm, 2, 16000, f);
	fclose(f);
	if (cap_load(&c, "n1/rtp_rx.bin") < 0)
		return;
	/* leg 0: the "carrier" side is a PCM file leg; leg 1: UDP AMR-WB (BE) toward a test peer */
	br_leg_cfg_default(&c0);
	c0.kind = BR_LEG_PCM;
	c0.pcm_rate = 16000;
	snprintf(c0.play_path, sizeof(c0.play_path), "%s", play);
	snprintf(c0.rec_path, sizeof(c0.rec_path), "%s", rec);
	leg_udp(&c1, CODEC_AMRWB, 104);
	c1.amr_oa = false;
	nev = 0;
	peer_open(&t.car);
	c1.fd = sock_open(&t.car_b);
	c1.own_fd = true;
	c1.remote = t.car.addr;
	c1.has_remote = true;
	t.br = bridge_create(&t);
	bridge_set_leg(t.br, 0, &c0);
	bridge_set_leg(t.br, 1, &c1);
	bridge_start(t.br);
	/* record direction: 100 captured AMR-WB packets arrive quickly */
	usleep(50000);
	send_cap(&t.car, &t.car_b, &c, 0, 100, 500, CAR_SSRC, NULL, NULL, NULL, 0);
	/* play direction: 1 s of file at real time -> ~50 packets */
	n = collect(&t.car, g, 100, 400);
	CHECK(wait_ev(BR_EV_PLAY_DONE, 0, 1, 1000));
	printf("  (g) file play: %d AMR-WB packets for 1.0 s of audio\n", n);
	CHECK(n >= 48 && n <= 52);
	check_stream("g", g, n, 104, 320, true);
	{
		struct codec *d = codec_create(CODEC_AMRWB, NULL);
		static int16_t dec[60 * 320], sn[60 * 320 + 800];
		size_t nd = 0;
		int i, lag;

		for (i = 0; i < n; i++) {
			struct amr_pdu pdu;

			if (amr_parse(AMR_WB, false, g[i].p.payload, g[i].p.plen, &pdu) == 0 && pdu.n == 1 && i >= 5) {
				int dd = codec_decode(d, pdu.f[0].data, 1u + pdu.f[0].nbytes, dec + nd, 320);

				if (dd > 0)
					nd += (size_t)dd;
			}
		}
		sine16(sn, sizeof(sn) / 2, 1000, 16000, 8000, 0);
		CHECK(best_corr(sn + 1600, dec, nd - 700, 400, &lag) > 0.9);
		codec_destroy(d);
	}
	bridge_stop(t.br);
	CHECK(wait_ev(BR_EV_STOPPED, -1, 1, 2000));
	{
		long sz = 0;
		static int16_t r[100 * 320];
		size_t got;

		f = fopen(rec, "rb");
		CHECK(f != NULL);
		if (f) {
			fseek(f, 0, SEEK_END);
			sz = ftell(f);
			fseek(f, 0, SEEK_SET);
			CHECK(fread(h, 1, 44, f) == 44 && !memcmp(h, "RIFF", 4) && !memcmp(h + 36, "data", 4));
			got = fread(r, 2, 100 * 320, f);
			printf("  (g) file record: %ld bytes (%zu samples), wav data size field %u\n", sz, got,
			       (unsigned)(h[40] | h[41] << 8 | h[42] << 16 | (unsigned)h[43] << 24));
			/* 100 packets plus comfort-noise fill frames of the capture's DTX gaps */
			CHECK(sz >= 44 + 100 * 640 && (unsigned)(h[40] | h[41] << 8 | h[42] << 16) == (unsigned)(sz - 44));
			CHECK(rms16(r + 320 * 20, 320 * 60) > 100);
			fclose(f);
		}
	}
	tb_end(&t);
	cap_free(&c);

	/* callback legs: PCM 8 kHz source/sink against a PCMA UDP leg */
	br_leg_cfg_default(&c0);
	c0.kind = BR_LEG_PCM;
	c0.pcm_rate = 8000;
	c0.pcm_src = cb_src;
	c0.pcm_sink = cb_sink;
	leg_udp(&c1, CODEC_PCMA, 8);
	cb_n = 0;
	cb_src_calls = 0;
	nev = 0;
	peer_open(&t.car);
	c1.fd = sock_open(&t.car_b);
	c1.own_fd = true;
	c1.remote = t.car.addr;
	c1.has_remote = true;
	t.br = bridge_create(&t);
	bridge_set_leg(t.br, 0, &c0);
	bridge_set_leg(t.br, 1, &c1);
	bridge_start(t.br);
	{
		uint16_t s = 1;
		uint32_t ts = 0;

		pcma_burst(&t.car, &t.car_b, CAR_SSRC, &s, &ts, 10);
	}
	n = collect(&t.car, g, 100, 300);
	printf("  (g) callback leg: %d PCMA packets from pcm_src (25 frames offered), sink got %zu samples\n", n, cb_n);
	CHECK(n == 25 && cb_n == 1600);
	bridge_stop(t.br);
	wait_ev(BR_EV_STOPPED, -1, 1, 1000);
	tb_end(&t);
}

/* ------------------------------------------------------------ (h) keep-alive, DTMF generation, WAV files, rx timer */

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* everything that arrives within ms */
static int collect_for(struct peer *p, struct got *g, int max, int ms)
{
	uint64_t end = now_ms() + (uint64_t)ms;
	int n = 0;

	for (;;) {
		uint64_t t = now_ms();
		struct pollfd pf = { .fd = p->fd, .events = POLLIN };
		ssize_t r;

		if (t >= end)
			break;
		if (poll(&pf, 1, (int)(end - t)) <= 0)
			break;
		if (n >= max) {
			uint8_t sink[2048];

			if (recv(p->fd, sink, sizeof(sink), 0) < 0)
				break;
			continue;
		}
		r = recv(p->fd, g[n].b, sizeof(g[n].b), 0);
		if (r < 0)
			break;
		g[n].len = (size_t)r;
		if (rtp_parse(g[n].b, (size_t)r, &g[n].p) == 0)
			n++;
	}
	return n;
}

static bool is_no_data(const struct got *g, bool wb, bool oa)
{
	struct amr_pdu pdu;

	return amr_parse(wb ? AMR_WB : AMR_NB, oa, g->p.payload, g->p.plen, &pdu) == 0 && pdu.n == 1 &&
	       pdu.f[0].ft == AMR_FT_NO_DATA;
}

/* all NO_DATA, one ssrc, seq +1, ts always a whole number of frames ahead; returns the largest ts step in frames */
static int check_ka(const char *what, const struct got *g, int n, uint8_t pt, uint32_t inc, bool wb, bool oa)
{
	int i, worst = 0, bad = 0;

	for (i = 0; i < n; i++) {
		CHECKF(g[i].p.h.pt == pt && g[i].p.h.ssrc == g[0].p.h.ssrc && !g[i].p.h.marker && is_no_data(&g[i], wb, oa),
		       "%s: packet %d is not a clean NO_DATA keep-alive", what, i);
		if (i) {
			int32_t d = rtp_ts_diff(g[i].p.h.ts, g[i - 1].p.h.ts);

			if (rtp_seq_diff(g[i].p.h.seq, g[i - 1].p.h.seq) != 1 || d < (int32_t)inc || d % (int32_t)inc)
				bad++;
			if (d / (int32_t)inc > worst)
				worst = d / (int32_t)inc;
		}
	}
	CHECKF(!bad, "%s: %d seq/timestamp irregularities in %d packets", what, bad, n);
	return worst;
}

static void t_keepalive(void)
{
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[200];
	uint16_t ss = 1;
	uint32_t st = 5000;
	int n, i, worst;
	uint32_t last_ts, last_seq;

	/* carrier AMR-WB (octet aligned) with keep-alive, client silent: NO_DATA at 20 ms from the very start */
	leg_udp(&c0, CODEC_AMRWB, 104);
	c0.amr_oa = true;
	c0.keepalive = true;
	leg_udp(&c1, CODEC_PCMA, 8);
	tb_setup(&t, &c0, &c1, true);
	n = collect_for(&t.car, g, 200, 1000);
	printf("  (h) keep-alive: %d NO_DATA frames in the first second\n", n);
	CHECK(n >= 42 && n <= 51);
	worst = check_ka("ka fast", g, n, 104, 320, true, true);
	CHECK(worst <= 2);
	CHECK(rtp_ts_diff(g[n - 1].p.h.ts, g[0].p.h.ts) >= (int32_t)(320 * (n - 1)));
	/* after 2 s the pace drops to ~160 ms, timestamps follow the wall clock */
	(void)collect_for(&t.car, g, 200, 1300);
	n = collect_for(&t.car, g, 200, 1280);
	printf("  (h) keep-alive: %d frames in 1.28 s of slow phase\n", n);
	CHECK(n >= 6 && n <= 10);
	worst = check_ka("ka slow", g, n, 104, 320, true, true);
	CHECK(worst >= 6 && worst <= 10);
	last_ts = g[n - 1].p.h.ts;
	last_seq = g[n - 1].p.h.seq;
	/* the other leg starts talking: real audio continues the same stream (seq +1, no timestamp going back) */
	pcma_burst(&t.cli, &t.cli_b, CLI_SSRC, &ss, &st, 10);
	n = collect_for(&t.car, g, 200, 100);
	CHECKF(n >= 10, "audio toward the carrier: %d packets", n);
	{
		int real = 0;

		for (i = 0; i < n; i++)
			if (!is_no_data(&g[i], true, true))
				real++;
		CHECK(real >= 9);
		/* first packet may still be a late keep-alive, but the first real one carries the marker */
		for (i = 0; i < n && is_no_data(&g[i], true, true); i++) { }
		if (i < n)
			CHECK(g[i].p.h.marker);
		for (i = 0; i < n; i++) {
			uint16_t prev = i ? g[i - 1].p.h.seq : (uint16_t)last_seq;
			uint32_t pts = i ? g[i - 1].p.h.ts : last_ts;
			int32_t d = rtp_ts_diff(g[i].p.h.ts, pts);

			CHECKF(rtp_seq_diff(g[i].p.h.seq, prev) == 1 && d >= 320 && d <= 320 * 12, "audio join %d: seq/ts", i);
		}
	}
	/* after real audio: 200 ms of grace, then the fast pace again */
	n = collect_for(&t.car, g, 200, 70);
	CHECKF(n == 0, "no keep-alive during the grace time (%d)", n);
	n = collect_for(&t.car, g, 200, 700);
	CHECKF(n >= 28 && n <= 40, "fast pace resumes (%d)", n);
	check_ka("ka after audio", g, n, 104, 320, true, true);
	/* direction: RECVONLY / INACTIVE = nothing is sent to the carrier; SENDONLY and SENDRECV keep-alive */
	bridge_set_dir(t.br, BR_CARRIER, BR_RECVONLY);
	usleep(50000);
	(void)collect_for(&t.car, g, 200, 10);
	n = collect_for(&t.car, g, 200, 500);
	CHECKF(n == 0, "recvonly: %d", n);
	bridge_set_dir(t.br, BR_CARRIER, BR_INACTIVE);
	n = collect_for(&t.car, g, 200, 400);
	CHECKF(n == 0, "inactive: %d", n);
	bridge_set_dir(t.br, BR_CARRIER, BR_SENDONLY);
	n = collect_for(&t.car, g, 200, 500);
	CHECKF(n >= 20, "sendonly keeps the leg alive (%d)", n);
	check_ka("ka sendonly", g, n, 104, 320, true, true);
	bridge_set_dir(t.br, BR_CARRIER, BR_SENDRECV);
	n = collect_for(&t.car, g, 200, 300);
	CHECKF(n >= 10, "sendrecv again (%d)", n);
	{
		struct bridge_stats bs;

		bridge_get_stats(t.br, &bs);
		CHECK(bs.leg[BR_CARRIER].ka_pkts > 100 && bs.leg[BR_CLIENT].ka_pkts == 0);
	}
	tb_end(&t);

	/* bandwidth-efficient AMR-NB */
	leg_udp(&c0, CODEC_AMRNB, 97);
	c0.amr_oa = false;
	c0.keepalive = true;
	leg_udp(&c1, CODEC_PCMA, 8);
	tb_setup(&t, &c0, &c1, true);
	n = collect_for(&t.car, g, 200, 400);
	CHECK(n >= 15 && n <= 21);
	check_ka("ka nb", g, n, 97, 160, false, false);
	tb_end(&t);

	/* off by default; never on a non-AMR leg */
	leg_udp(&c0, CODEC_AMRWB, 104);
	leg_udp(&c1, CODEC_PCMA, 8);
	tb_setup(&t, &c0, &c1, true);
	CHECK(collect_for(&t.car, g, 200, 500) == 0);
	tb_end(&t);
	leg_udp(&c0, CODEC_PCMA, 8);
	c0.keepalive = true;
	leg_udp(&c1, CODEC_AMRWB, 104);
	tb_setup(&t, &c0, &c1, true);
	CHECK(collect_for(&t.car, g, 200, 500) == 0);
	tb_end(&t);

	/* a leg without a remote yet starts when the remote is set */
	leg_udp(&c0, CODEC_AMRWB, 104);
	c0.keepalive = true;
	leg_udp(&c1, CODEC_PCMA, 8);
	tb_setup(&t, &c0, &c1, false);
	c0.has_remote = false;
	bridge_set_leg(t.br, BR_CARRIER, &c0);
	bridge_start(t.br);
	CHECK(collect_for(&t.car, g, 200, 300) == 0);
	bridge_set_remote(t.br, BR_CARRIER, &t.car.addr);
	n = collect_for(&t.car, g, 200, 300);
	CHECK(n >= 10);
	tb_end(&t);
	printf("  (h) keep-alive: fast/slow pace, join with audio, directions, off cases\n");
}

static void t_dtmf_tx(void)
{
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[100];
	uint16_t ss = 1;
	uint32_t st = 9000;
	int n, i;
	int32_t d;

	leg_udp(&c0, CODEC_AMRWB, 104);
	c0.te_pt = 107;
	c0.te_clock = 16000;
	leg_udp(&c1, CODEC_PCMA, 8);
	tb_setup(&t, &c0, &c1, true);
	CHECK(bridge_send_dtmf(t.br, BR_CARRIER, 'x', 100) < 0);
	CHECK(bridge_send_dtmf(t.br, 7, '5', 100) < 0);
	/* audio from the client at the same time must not be interleaved with the event */
	pcma_burst(&t.cli, &t.cli_b, CLI_SSRC, &ss, &st, 3);
	n = collect_for(&t.car, g, 100, 100);
	CHECK(n == 3);
	CHECK(bridge_send_dtmf(t.br, BR_CARRIER, '5', 100) == 0);
	pcma_burst(&t.cli, &t.cli_b, CLI_SSRC, &ss, &st, 3);
	n = collect_for(&t.car, g, 100, 400);
	{	/* the audio burst races with the command: an audio packet may slip out before the event starts; keep the events */
		int m = 0;

		for (i = 0; i < n; i++)
			if (g[i].p.h.pt == 107) {
				g[m] = g[i];
				rtp_parse(g[m].b, g[m].len, &g[m].p);	/* payload points into the copy's own buffer */
				m++;
			}
		n = m;
	}
	CHECKF(n == 8, "event packets: %d", n);
	if (n == 8) {
		for (i = 0; i < 8; i++) {
			struct dtmf_event e;

			CHECK(g[i].p.h.pt == 107 && g[i].p.h.ts == g[0].p.h.ts && g[i].p.h.marker == (i == 0));
			CHECK(dtmf_parse(g[i].p.payload, g[i].p.plen, &e) == 0 && e.event == 5);
			CHECK(e.end == (i >= 5));
			CHECKF(e.duration == (i < 5 ? 320u * (unsigned)(i + 1) : 1600u), "pkt %d end %d dur %u", i, e.end, e.duration);
			if (i)
				CHECK(rtp_seq_diff(g[i].p.h.seq, g[i - 1].p.h.seq) == 1);
		}
	}
	/* audio after the event: marker, timestamp past the end of the event, seq continues */
	{
		uint32_t ev_ts = n > 0 ? g[0].p.h.ts : 0;
		uint16_t ev_seq = n > 0 ? g[n - 1].p.h.seq : 0;

		pcma_burst(&t.cli, &t.cli_b, CLI_SSRC, &ss, &st, 3);
		n = collect_for(&t.car, g, 100, 100);
		CHECK(n == 3);
		if (n == 3) {
			d = rtp_ts_diff(g[0].p.h.ts, ev_ts);
			CHECK(g[0].p.h.pt == 104 && g[0].p.h.marker && d >= 1600);
			CHECK(rtp_seq_diff(g[0].p.h.seq, ev_seq) == 1);
		}
	}
	/* '#', toward a leg with no telephone-event, and while we must not send */
	CHECK(bridge_send_dtmf(t.br, BR_CARRIER, '#', 40) == 0);
	n = collect_for(&t.car, g, 100, 300);
	CHECKF(n == 8, "40 ms event: %d", n);	/* raised to the 100 ms minimum: 5 updates, then end x3 */
	CHECK(bridge_send_dtmf(t.br, BR_CLIENT, '1', 100) == 0);
	CHECK(collect_for(&t.cli, g, 100, 300) == 0);
	bridge_set_dir(t.br, BR_CARRIER, BR_RECVONLY);
	CHECK(bridge_send_dtmf(t.br, BR_CARRIER, '1', 100) == 0);
	CHECK(collect_for(&t.car, g, 100, 300) == 0);
	tb_end(&t);
	printf("  (h) bridge_send_dtmf: start/updates/end x3, audio suppressed meanwhile, timestamps continue\n");
}

static void write_wav(const char *path, unsigned tag, unsigned ch, uint32_t rate, unsigned bits, const void *data, uint32_t bytes,
		      bool trailer)
{
	FILE *f = fopen(path, "wb");
	uint8_t h[44];
	uint32_t blk = ch * bits / 8;

	CHECK(f != NULL);
	if (!f)
		return;
	memset(h, 0, sizeof(h));
	memcpy(h, "RIFF", 4);
	put32(h + 4, 36 + bytes);
	memcpy(h + 8, "WAVEfmt ", 8);
	put32(h + 16, 16);
	h[20] = (uint8_t)tag; h[22] = (uint8_t)ch;
	put32(h + 24, rate);
	put32(h + 28, rate * blk);
	h[32] = (uint8_t)blk; h[34] = (uint8_t)bits;
	memcpy(h + 36, "data", 4);
	put32(h + 40, bytes);
	fwrite(h, 1, 44, f);
	fwrite(data, 1, bytes, f);
	if (trailer) {	/* a LIST chunk after the samples must not be played */
		static uint8_t junk[4008];

		memset(junk, 0x55, sizeof(junk));
		memcpy(junk, "LIST", 4);
		put32(junk + 4, 4000);
		fwrite(junk, 1, sizeof(junk), f);
	}
	fclose(f);
}

static void pcm_bad_file(const char *name, const char *path, int pcm_rate, const char *want)
{
	struct br_leg_cfg c0, c1;
	struct tb t;
	int i;
	bool found = false;

	br_leg_cfg_default(&c0);
	c0.kind = BR_LEG_PCM;
	c0.pcm_rate = pcm_rate;
	snprintf(c0.play_path, sizeof(c0.play_path), "%s", path);
	leg_udp(&c1, CODEC_AMRWB, 104);
	nev = 0;
	peer_open(&t.car);
	c1.fd = sock_open(&t.car_b);
	c1.own_fd = true;
	c1.remote = t.car.addr;
	c1.has_remote = true;
	t.br = bridge_create(&t);
	bridge_set_leg(t.br, 0, &c0);
	bridge_set_leg(t.br, 1, &c1);
	bridge_start(t.br);
	CHECKF(wait_ev(BR_EV_ERROR, -1, 1, 1000), "%s: no error event", name);
	for (i = 0; i < nev; i++)
		if (evlog[i].type == BR_EV_ERROR && strstr(evlog[i].msg, want))
			found = true;
	CHECKF(found, "%s: error text does not contain '%s' (%s)", name, want, nev ? evlog[nev - 1].msg : "-");
	tb_end(&t);
}

static void t_wav(void)
{
	char play[190], rec[190], bad[190];
	static int16_t pcm[8000];
	static int16_t st2[16000];
	static uint8_t b8[8000];
	struct tb t;
	struct br_leg_cfg c0, c1;
	static struct got g[100];
	int n, i;
	FILE *f;
	uint8_t h[44];

	snprintf(play, sizeof(play), "%s/play8.wav", test_tmp());
	snprintf(rec, sizeof(rec), "%s/rec8.wav", test_tmp());
	snprintf(bad, sizeof(bad), "%s/bad.wav", test_tmp());
	sine16(pcm, 8000, 700, 8000, 8000, 0);
	write_wav(play, 1, 1, 8000, 16, pcm, 16000, true);
	/* 8 kHz file -> 8 kHz PCM leg -> AMR-NB (octet aligned) leg, and back into a WAV recording */
	br_leg_cfg_default(&c0);
	c0.kind = BR_LEG_PCM;
	c0.pcm_rate = 8000;
	snprintf(c0.play_path, sizeof(c0.play_path), "%s", play);
	snprintf(c0.rec_path, sizeof(c0.rec_path), "%s", rec);
	leg_udp(&c1, CODEC_AMRNB, 97);
	c1.amr_oa = true;
	nev = 0;
	peer_open(&t.car);
	c1.fd = sock_open(&t.car_b);
	c1.own_fd = true;
	c1.remote = t.car.addr;
	c1.has_remote = true;
	t.br = bridge_create(&t);
	bridge_set_leg(t.br, 0, &c0);
	bridge_set_leg(t.br, 1, &c1);
	bridge_start(t.br);
	n = collect(&t.car, g, 100, 500);
	CHECK(wait_ev(BR_EV_PLAY_DONE, 0, 1, 500));
	printf("  (wav) 1.0 s 8 kHz file (+ trailing LIST chunk) -> %d AMR-NB packets\n", n);
	CHECK(n >= 48 && n <= 52);	/* the trailing chunk is not played */
	check_stream("wav nb", g, n, 97, 160, true);
	{
		struct codec *d = codec_create(CODEC_AMRNB, NULL);
		static int16_t dec[60 * 160], sn[60 * 160 + 800];
		size_t nd = 0;
		int lag;

		for (i = 0; i < n; i++) {
			struct amr_pdu pdu;

			if (amr_parse(AMR_NB, true, g[i].p.payload, g[i].p.plen, &pdu) == 0 && pdu.n == 1 && i >= 5) {
				int dd = codec_decode(d, pdu.f[0].data, 1u + pdu.f[0].nbytes, dec + nd, 160);

				if (dd > 0)
					nd += (size_t)dd;
			}
		}
		sine16(sn, sizeof(sn) / 2, 700, 8000, 8000, 0);
		CHECK(best_corr(sn + 800, dec, nd - 400, 200, &lag) > 0.9);
		codec_destroy(d);
	}
	/* loop the received packets back: UDP -> bridge -> WAV */
	for (i = 0; i < n; i++) {
		psend(&t.car, &t.car_b, i == 0, 97, (uint16_t)(1 + i), (uint32_t)(1000 + 160 * i), CAR_SSRC, g[i].p.payload, g[i].p.plen);
		usleep(300);
	}
	usleep(50000);
	bridge_stop(t.br);
	CHECK(wait_ev(BR_EV_STOPPED, -1, 1, 2000));
	f = fopen(rec, "rb");
	CHECK(f != NULL);
	if (f) {
		long sz;
		static int16_t r[8000];
		size_t got;

		fseek(f, 0, SEEK_END);
		sz = ftell(f);
		fseek(f, 0, SEEK_SET);
		CHECK(fread(h, 1, 44, f) == 44 && !memcmp(h, "RIFF", 4) && !memcmp(h + 8, "WAVEfmt ", 8) && !memcmp(h + 36, "data", 4));
		CHECK(h[20] == 1 && h[22] == 1 && (h[24] | h[25] << 8) == 8000 && h[34] == 16);
		CHECK((unsigned)(h[40] | h[41] << 8 | h[42] << 16) == (unsigned)(sz - 44));
		CHECK(sz - 44 >= 2 * 160 * (n - 2));
		got = fread(r, 2, 8000, f);
		CHECK(got >= (size_t)(160 * (n - 2)));
		CHECK(rms16(r + 800, 160 * 20) > 1000);
		fclose(f);
		printf("  (wav) UDP -> WAV recording: %ld bytes, header rate/ch/bits ok\n", sz);
	}
	tb_end(&t);

	/* looping play on a UDP leg: keeps going, no end event */
	br_leg_cfg_default(&c0);
	c0.kind = BR_LEG_PCM;
	c0.pcm_rate = 8000;
	c0.play_loop = true;
	snprintf(c0.play_path, sizeof(c0.play_path), "%s", play);
	leg_udp(&c1, CODEC_AMRNB, 97);
	nev = 0;
	peer_open(&t.car);
	c1.fd = sock_open(&t.car_b);
	c1.own_fd = true;
	c1.remote = t.car.addr;
	c1.has_remote = true;
	t.br = bridge_create(&t);
	bridge_set_leg(t.br, 0, &c0);
	bridge_set_leg(t.br, 1, &c1);
	bridge_start(t.br);
	n = collect_for(&t.car, g, 100, 1300);
	CHECK(n >= 60 && ev_count(BR_EV_PLAY_DONE, -1) == 0);	/* more than the 50 frames of one pass */
	tb_end(&t);

	/* unsupported files fail loudly */
	for (i = 0; i < 8000; i++)
		b8[i] = 128;
	write_wav(bad, 1, 2, 8000, 16, st2, 32000, false);
	pcm_bad_file("stereo", bad, 8000, "not mono");
	write_wav(bad, 1, 1, 8000, 8, b8, 8000, false);
	pcm_bad_file("8-bit", bad, 8000, "not 16-bit");
	write_wav(bad, 1, 1, 44100, 16, st2, 32000, false);
	pcm_bad_file("44.1k", bad, 16000, "rate != pcm_rate");
	write_wav(bad, 1, 1, 8000, 16, pcm, 16000, false);
	pcm_bad_file("8k file on a 16k leg", bad, 16000, "rate != pcm_rate");
	write_wav(bad, 3, 1, 8000, 32, st2, 16000, false);	/* IEEE float */
	pcm_bad_file("float", bad, 8000, "not PCM");
	f = fopen(bad, "wb");
	if (f) {
		fwrite("RIFF\x10\0\0\0WAVX", 1, 12, f);
		fclose(f);
	}
	pcm_bad_file("riff not wave", bad, 8000, "not WAVE");
	snprintf(bad, sizeof(bad), "%s/does-not-exist.wav", test_tmp());
	pcm_bad_file("missing", bad, 8000, "cannot open");
	printf("  (wav) stereo / 8-bit / wrong rate / float / not-wave / missing file raise BR_EV_ERROR\n");
}

static void t_rx_timer_hold(void)
{
	struct tb t;
	struct br_leg_cfg c0, c1;
	uint16_t cs = 1;
	uint32_t ct = 100;

	leg_udp(&c0, CODEC_PCMA, 8);
	c0.rx_timeout_ms = 300;
	leg_udp(&c1, CODEC_PCMA, 8);
	tb_setup(&t, &c0, &c1, true);
	pcma_burst(&t.car, &t.car_b, CAR_SSRC, &cs, &ct, 3);
	/* on hold (cannot receive) the timer does not run ... */
	bridge_set_dir(t.br, BR_CARRIER, BR_INACTIVE);
	usleep(700000);
	CHECK(ev_count(BR_EV_RX_TIMEOUT, -1) == 0);
	/* ... and resuming restarts it instead of firing at once */
	bridge_set_dir(t.br, BR_CARRIER, BR_SENDRECV);
	usleep(150000);
	CHECK(ev_count(BR_EV_RX_TIMEOUT, -1) == 0);
	CHECK(wait_ev(BR_EV_RX_TIMEOUT, BR_CARRIER, 1, 600));
	usleep(400000);
	CHECK(ev_count(BR_EV_RX_TIMEOUT, -1) == 1);	/* once per silence */
	/* sendonly (we do not listen) then recvonly: same rules */
	bridge_set_dir(t.br, BR_CARRIER, BR_SENDONLY);
	usleep(500000);
	bridge_set_dir(t.br, BR_CARRIER, BR_RECVONLY);
	usleep(150000);
	CHECK(ev_count(BR_EV_RX_TIMEOUT, -1) == 1);
	CHECK(wait_ev(BR_EV_RX_TIMEOUT, BR_CARRIER, 2, 600));
	tb_end(&t);
	printf("  (h) rx timeout: not counted on hold, restarted on resume\n");
}

/* ------------------------------------------------------------ start failures */

static void t_errors(void)
{
	struct br_leg_cfg c0, c1;
	struct tb t;

	/* 8k <-> 48k is not supported: the bridge refuses to start and reports it */
	leg_udp(&c0, CODEC_OPUS, 111);
	c0.cp.pcm_rate = 48000;
	leg_udp(&c1, CODEC_PCMA, 8);
	tb_setup(&t, &c0, &c1, true);
	CHECK(wait_ev(BR_EV_ERROR, -1, 1, 1000));
	tb_end(&t);
	/* unconfigured leg */
	nev = 0;
	t.br = bridge_create(&t);
	bridge_start(t.br);
	CHECK(wait_ev(BR_EV_ERROR, -1, 1, 1000));
	bridge_destroy(t.br);
	CHECK(wait_ev(BR_EV_DESTROYED, -1, 1, 1000));
	CHECK(bridge_set_leg(NULL, 0, &c0) < 0 && bridge_set_dir(t.br, 5, BR_SENDRECV) < 0);
}

/* ------------------------------------------------------------ (i) DTMF regeneration: queue, pacing, audio replacement */

/* telephone-event packets of the real Bria Mobile capture (lan.pcap, 9 key presses 1 3 4 3 1 3 4 3 1): arrival time in ms
   since the first packet (silent stretches longer than 1 s shortened to 250 ms), marker, RTP timestamp, event, E bit, duration */
static const struct bria_pkt { uint32_t ms; uint8_t m; uint32_t ts; uint8_t ev, e; uint16_t dur; } bria[] = {
	{ 0, 1, 2416904246u, 1, 0, 960 },
	{ 0, 0, 2416904246u, 1, 0, 960 },
	{ 0, 0, 2416904246u, 1, 0, 960 },
	{ 21, 0, 2416904246u, 1, 1, 1920 },
	{ 21, 0, 2416904246u, 1, 1, 1920 },
	{ 21, 0, 2416904246u, 1, 1, 1920 },
	{ 271, 1, 2416926326u, 3, 0, 960 },
	{ 271, 0, 2416926326u, 3, 0, 960 },
	{ 271, 0, 2416926326u, 3, 0, 960 },
	{ 292, 0, 2416926326u, 3, 1, 1920 },
	{ 292, 0, 2416926326u, 3, 1, 1920 },
	{ 292, 0, 2416926326u, 3, 1, 1920 },
	{ 471, 1, 2416935926u, 4, 0, 960 },
	{ 471, 0, 2416935926u, 4, 0, 960 },
	{ 471, 0, 2416935926u, 4, 0, 960 },
	{ 490, 0, 2416935926u, 4, 1, 1920 },
	{ 490, 0, 2416935926u, 4, 1, 1920 },
	{ 491, 0, 2416935926u, 4, 1, 1920 },
	{ 741, 1, 2416958006u, 3, 0, 960 },
	{ 741, 0, 2416958006u, 3, 0, 960 },
	{ 741, 0, 2416958006u, 3, 0, 960 },
	{ 759, 0, 2416958006u, 3, 1, 1920 },
	{ 759, 0, 2416958006u, 3, 1, 1920 },
	{ 759, 0, 2416958006u, 3, 1, 1920 },
	{ 1009, 1, 2417509046u, 1, 0, 960 },
	{ 1009, 0, 2417509046u, 1, 0, 960 },
	{ 1009, 0, 2417509046u, 1, 0, 960 },
	{ 1027, 0, 2417509046u, 1, 1, 1920 },
	{ 1028, 0, 2417509046u, 1, 1, 1920 },
	{ 1028, 0, 2417509046u, 1, 1, 1920 },
	{ 1278, 1, 2417582006u, 3, 0, 960 },
	{ 1278, 0, 2417582006u, 3, 0, 960 },
	{ 1278, 0, 2417582006u, 3, 0, 960 },
	{ 1301, 0, 2417582006u, 3, 1, 1920 },
	{ 1301, 0, 2417582006u, 3, 1, 1920 },
	{ 1301, 0, 2417582006u, 3, 1, 1920 },
	{ 1551, 1, 2417654006u, 4, 0, 960 },
	{ 1551, 0, 2417654006u, 4, 0, 960 },
	{ 1551, 0, 2417654006u, 4, 0, 960 },
	{ 1571, 0, 2417654006u, 4, 1, 1920 },
	{ 1571, 0, 2417654006u, 4, 1, 1920 },
	{ 1571, 0, 2417654006u, 4, 1, 1920 },
	{ 1821, 1, 2417731766u, 3, 0, 960 },
	{ 1821, 0, 2417731766u, 3, 0, 960 },
	{ 1822, 0, 2417731766u, 3, 0, 960 },
	{ 1841, 0, 2417731766u, 3, 1, 1920 },
	{ 1842, 0, 2417731766u, 3, 1, 1920 },
	{ 1842, 0, 2417731766u, 3, 1, 1920 },
	{ 2092, 1, 2418068726u, 1, 0, 960 },
	{ 2092, 0, 2418068726u, 1, 0, 960 },
	{ 2092, 0, 2418068726u, 1, 0, 960 },
	{ 2110, 0, 2418068726u, 1, 1, 1920 },
	{ 2110, 0, 2418068726u, 1, 1, 1920 },
	{ 2110, 0, 2418068726u, 1, 1, 1920 },
};

#define BRIA_N ((int)(sizeof(bria) / sizeof(bria[0])))

struct orec {			/* one packet seen on the destination leg */
	uint32_t ms;		/* arrival, ms since the start of the run */
	uint8_t pt;
	bool m;
	uint16_t seq;
	uint32_t ts, ssrc;
	uint8_t pl[4];
};

#define OREC_MAX 4000

struct run {
	struct tb t;
	struct peer *src, *dst;	/* the peer that sends the events / the one that receives the regenerated ones */
	const struct addr *src_to;
	int src_leg, dst_leg;
	uint8_t src_pt, src_te, dst_pt, dst_te;
	uint32_t src_ssrc;
	uint16_t seq;
	uint32_t audio_ts;
	int audio;		/* 0 none, 1 PCMA silence, 2 Opus silence frame */
	struct orec *rec;
	int n;
	uint64_t t0;
};

static uint64_t run_now(const struct run *r)
{
	return now_ms() - r->t0;
}

static void run_poll(struct run *r, int wait_ms)
{
	struct pollfd pf = { .fd = r->dst->fd, .events = POLLIN };

	if (poll(&pf, 1, wait_ms) <= 0)
		return;
	for (;;) {
		uint8_t b[1500];
		struct rtp_pkt p;
		ssize_t n = recv(r->dst->fd, b, sizeof(b), MSG_DONTWAIT);

		if (n < 0)
			break;
		if (rtp_parse(b, (size_t)n, &p) < 0 || r->n >= OREC_MAX)
			continue;
		r->rec[r->n] = (struct orec){ .ms = (uint32_t)run_now(r), .pt = p.h.pt, .m = p.h.marker, .seq = p.h.seq,
					      .ts = p.h.ts, .ssrc = p.h.ssrc };
		if (p.plen >= 4 && p.h.pt == r->dst_te)
			memcpy(r->rec[r->n].pl, p.payload, 4);
		r->n++;
	}
}

static void run_event(struct run *r, bool m, uint32_t ts, uint8_t ev, bool end, uint16_t dur)
{
	uint8_t pl[4];
	struct dtmf_event e = { .event = ev, .end = end, .volume = 10, .duration = dur };

	dtmf_build(pl, &e);
	psend(r->src, r->src_to, m, r->src_te, r->seq++, ts, r->src_ssrc, pl, 4);
}

static void run_audio(struct run *r)
{
	static const uint8_t opus_silence[3] = { 0xf8, 0xff, 0xfe };
	uint8_t pcma[160];

	if (r->audio == 1) {
		memset(pcma, 0xd5, sizeof(pcma));
		psend(r->src, r->src_to, false, r->src_pt, r->seq++, r->audio_ts, r->src_ssrc, pcma, sizeof(pcma));
		r->audio_ts += 160;
	} else if (r->audio == 2) {
		psend(r->src, r->src_to, false, r->src_pt, r->seq++, r->audio_ts, r->src_ssrc, opus_silence, 3);
		r->audio_ts += 960;
	}
}

/* what to send: the capture, or a generated list */
struct act {
	uint32_t ms;
	uint8_t kind;		/* 0 event packet, 1 bridge_send_dtmf */
	bool m, end;
	uint32_t ts;
	uint8_t ev;
	uint16_t dur;
};

/* send the actions (sorted by ms) with 20 ms audio frames in between, recording the destination, until total_ms */
static void run_play(struct run *r, const struct act *a, int na, uint32_t total_ms)
{
	uint32_t next_audio = 0;
	int i = 0;

	r->t0 = now_ms();
	for (;;) {
		uint64_t t = run_now(r);

		if (t >= total_ms)
			break;
		while (i < na && a[i].ms <= t) {
			if (a[i].kind == 1)
				CHECK(bridge_send_dtmf(r->t.br, r->dst_leg, dtmf_event_char(a[i].ev), a[i].dur) == 0);
			else
				run_event(r, a[i].m, a[i].ts, a[i].ev, a[i].end, a[i].dur);
			i++;
		}
		while (r->audio && next_audio <= t) {
			run_audio(r);
			next_audio += 20;
		}
		run_poll(r, 2);
	}
}

static void run_open(struct run *r, struct br_leg_cfg *c0, struct br_leg_cfg *c1, int src_leg, int audio)
{
	memset(r, 0, sizeof(*r));
	r->rec = calloc(OREC_MAX, sizeof(*r->rec));
	tb_setup(&r->t, c0, c1, true);
	r->src_leg = src_leg;
	r->dst_leg = 1 - src_leg;
	r->src = src_leg == BR_CLIENT ? &r->t.cli : &r->t.car;
	r->dst = src_leg == BR_CLIENT ? &r->t.car : &r->t.cli;
	r->src_to = src_leg == BR_CLIENT ? &r->t.cli_b : &r->t.car_b;
	r->src_ssrc = src_leg == BR_CLIENT ? CLI_SSRC : CAR_SSRC;
	r->src_pt = src_leg == BR_CLIENT ? c1->pt : c0->pt;
	r->src_te = (uint8_t)(src_leg == BR_CLIENT ? c1->te_pt : c0->te_pt);
	r->dst_pt = src_leg == BR_CLIENT ? c0->pt : c1->pt;
	r->dst_te = (uint8_t)(src_leg == BR_CLIENT ? c0->te_pt : c1->te_pt);
	r->audio = audio;
	r->seq = 100;
	r->audio_ts = 5000;
}

static void run_close(struct run *r)
{
	tb_end(&r->t);
	free(r->rec);
}

struct oev {
	uint8_t digit;
	int first, end1, last;	/* indexes in rec */
	int nupd, nend;
	uint32_t ts, dur;	/* start timestamp, final duration in te units */
};

#define OEV_MAX 64

/*
 * Checks every regenerated event on the destination and returns their number: structure (marker only on the first,
 * growing durations every ~20 ms, exactly three equal end packets), length (>= want_ms[i], wall clock), non
 * overlap / pause, sequence continuity, no audio inside an event span and audio resuming with the marker.  The te
 * clock of the destination equals its audio clock in every test using this.
 */
static int run_check(const char *what, const struct run *r, struct oev *ev, const uint8_t *digits, const uint32_t *want_ms,
		     int ndig, uint32_t clk, uint32_t pause_ms, bool audio_on_dst, bool strict_len)
{
	int i, ne = 0, k;
	uint32_t step = clk / 50;

	for (i = 0; i < r->n; i++) {
		const struct orec *o = &r->rec[i];
		struct dtmf_event e;
		struct oev *c = ne ? &ev[ne - 1] : NULL;

		if (i && rtp_seq_diff(o->seq, r->rec[i - 1].seq) != 1)
			CHECKF(0, "%s: seq %u after %u", what, o->seq, r->rec[i - 1].seq);
		if (o->ssrc != r->rec[0].ssrc)
			CHECKF(0, "%s: ssrc changed", what);
		if (o->pt != r->dst_te)
			continue;
		dtmf_parse(o->pl, 4, &e);
		if (o->m) {
			if (ne >= OEV_MAX)
				break;
			c = &ev[ne++];
			memset(c, 0, sizeof(*c));
			c->digit = e.event;
			c->first = c->end1 = c->last = i;
			c->ts = o->ts;
			c->nupd = 1;
			CHECKF(!e.end && e.duration == step, "%s: first packet dur %u", what, e.duration);
			continue;
		}
		if (!c) {
			CHECKF(0, "%s: event packet without a start", what);
			continue;
		}
		CHECKF(o->ts == c->ts && e.event == c->digit, "%s: ts / digit change inside an event", what);
		if (!e.end) {
			CHECKF(c->nend == 0, "%s: update after the end", what);
			CHECKF(e.duration > c->dur || c->nupd == 1, "%s: duration not growing", what);
			c->nupd++;
		} else {
			if (!c->nend) {
				c->end1 = i;
				c->dur = e.duration;
			}
			CHECKF(e.duration == c->dur, "%s: end packets differ", what);
			c->nend++;
		}
		if (!e.end)
			c->dur = e.duration;
		c->last = i;
	}
	CHECKF(ne == ndig, "%s: %d events, want %d", what, ne, ndig);
	for (k = 0; k < ne && k < ndig; k++) {
		const struct oev *c = &ev[k];
		uint32_t span = r->rec[c->end1].ms - r->rec[c->first].ms;
		uint32_t want = want_ms[k];

		CHECKF(c->digit == digits[k], "%s: event %d digit %d want %d", what, k, c->digit, digits[k]);
		CHECKF(c->nend == 3, "%s: event %d has %d end packets", what, k, c->nend);
		CHECKF(c->dur == (uint32_t)((uint64_t)want * clk / 1000) || (!strict_len && c->dur >= (uint32_t)((uint64_t)want * clk / 1000)),
		       "%s: event %d final duration %u (want %u ms)", what, k, c->dur, want);
		CHECKF(span + 15 >= want && (!strict_len || span <= want + 100), "%s: event %d lasted %u ms, announced %u", what, k, span, want);
		CHECKF(c->nupd >= 2 && (uint32_t)c->nupd * 20 + 20 >= want, "%s: event %d: %d updates", what, k, c->nupd);
		if (c->nupd >= 4) {	/* mean pacing of the updates */
			uint32_t m = (r->rec[c->first + c->nupd - 1].ms - r->rec[c->first].ms) / (uint32_t)(c->nupd - 1);

			CHECKF(m >= 15 && m <= 26, "%s: event %d: mean update spacing %u ms", what, k, m);
		}
		if (k) {
			const struct oev *p = &ev[k - 1];

			CHECKF(r->rec[c->first].ms >= r->rec[p->last].ms, "%s: events %d/%d overlap on the wire", what, k - 1, k);
			CHECKF(r->rec[c->first].ms + 15 >= r->rec[p->end1].ms + pause_ms, "%s: pause %d->%d only %u ms", what, k - 1, k,
			       r->rec[c->first].ms - r->rec[p->end1].ms);
			CHECKF(rtp_ts_diff(c->ts, p->ts) >= (int32_t)p->dur, "%s: timestamps of events %d/%d overlap", what, k - 1, k);
		}
		/* audio: none inside the span, and the first one after the event has the marker */
		if (audio_on_dst) {
			bool seen = false;

			for (i = 0; i < r->n; i++) {
				const struct orec *o = &r->rec[i];
				int32_t d;

				if (o->pt != r->dst_pt)
					continue;
				d = rtp_ts_diff(o->ts, c->ts);
				CHECKF(d < 0 || (uint32_t)d >= c->dur, "%s: audio ts %d inside event %d (dur %u)", what, d, k, c->dur);
				if (!seen && i > c->last) {
					seen = true;
					CHECKF(o->m, "%s: first audio after event %d lacks the marker", what, k);
					CHECKF(rtp_ts_diff(o->ts, c->ts) >= (int32_t)c->dur, "%s: audio after event %d starts inside it", what, k);
				}
			}
			if (k == ne - 1)
				CHECKF(seen, "%s: audio did not resume", what);
		}
	}
	return ne;
}

static const char *const mm = "";

static void bria_acts(struct act *a, int *na, int upto_ev, bool le20)
{
	int i, events = 0;

	(void)le20;
	for (i = 0; i < BRIA_N; i++) {
		if (bria[i].m && ++events > upto_ev)
			break;
		a[i] = (struct act){ .ms = bria[i].ms + 100, .m = bria[i].m, .end = bria[i].e, .ts = bria[i].ts, .ev = bria[i].ev,
				     .dur = bria[i].dur };
	}
	*na = i;
}

static void dtmf_events_seen(int starts, int ends, uint32_t end_ms, int want_starts)
{
	int k, s = 0, e = 0;

	pump();
	for (k = 0; k < nev; k++) {
		if (evlog[k].type != BR_EV_DTMF)
			continue;
		if (evlog[k].end) {
			e++;
			CHECKF(end_ms == 0 || evlog[k].duration_ms == end_ms, "BR_EV_DTMF end duration %u", evlog[k].duration_ms);
		} else {
			s++;
		}
	}
	CHECKF(s == starts && e == ends, "BR_EV_DTMF %d starts %d ends (want %d/%d)", s, e, starts, ends);
	(void)want_starts;
}

/* the real Bria burst pattern, read with an 8 kHz te clock: every key press is announced as 240 ms in one burst */
static void t_dtmf_bria(void)
{
	static struct act a[64];
	static struct oev ev[OEV_MAX];
	static const uint8_t dig[9] = { 1, 3, 4, 3, 1, 3, 4, 3, 1 };
	uint32_t want[9];
	struct br_leg_cfg c0, c1;
	struct bridge_stats st;
	struct run r;
	int na, i;

	for (i = 0; i < 9; i++)
		want[i] = 240;
	leg_udp(&c0, CODEC_AMRNB, 104);
	c0.te_pt = 107;
	c0.te_clock = 8000;
	leg_udp(&c1, CODEC_PCMA, 8);
	c1.te_pt = 101;
	c1.te_clock = 8000;
	run_open(&r, &c0, &c1, BR_CLIENT, 1);
	bria_acts(a, &na, 9, false);
	CHECK(na == 54);
	run_play(&r, a, na, a[na - 1].ms + 800);
	CHECK(run_check("bria 8k", &r, ev, dig, want, 9, 8000, 60, true, true) == 9);
	/* the 201 ms pair (events 2 and 3): the second starts after the first one's 240 ms + pause */
	if (r.n)
		CHECK(ev[2].first > ev[1].first);
	bridge_get_stats(r.t.br, &st);
	CHECK(st.leg[BR_CLIENT].dtmf_events == 9 && st.leg[BR_CARRIER].dtmf_dropped == 0);
	dtmf_events_seen(9, 9, 240, 9);
	run_close(&r);
	printf("  (i) Bria burst replay (9 key presses, 54 packets in) -> 9 serialised 240 ms events, audio replaced and resumed\n");
	(void)mm;
}

/* the same capture read with its real 48 kHz telephone-event clock: 40 ms announced -> stretched to the 100 ms minimum;
 * AMR-NB carrier at 8 kHz; Opus audio meanwhile */
static void t_dtmf_bria_48k(void)
{
	static struct act a[64];
	static struct oev ev[OEV_MAX];
	static const uint8_t dig[4] = { 1, 3, 4, 3 };
	static const uint32_t want[4] = { 100, 100, 100, 100 };
	struct br_leg_cfg c0, c1;
	struct run r;
	int na;

	leg_udp(&c0, CODEC_AMRNB, 104);
	c0.te_pt = 107;
	c0.te_clock = 8000;
	leg_udp(&c1, CODEC_OPUS, 111);
	c1.te_pt = 101;
	c1.te_clock = 48000;
	run_open(&r, &c0, &c1, BR_CLIENT, 2);
	bria_acts(a, &na, 4, false);
	run_play(&r, a, na, a[na - 1].ms + 600);
	CHECK(run_check("bria 48k", &r, ev, dig, want, 4, 8000, 60, true, true) == 4);
	run_close(&r);
	printf("  (i) Bria burst with the real 48 kHz te clock -> 8 kHz carrier: 100 ms minimum\n");
}

/* ten keys within 200 ms, 8 kHz in, 16 kHz out; carrier -> client direction is covered in t_dtmf_queue_dir */
static void t_dtmf_burst10(void)
{
	static struct act a[64];
	static struct oev ev[OEV_MAX];
	uint8_t dig[10];
	uint32_t want[10];
	struct br_leg_cfg c0, c1;
	struct run r;
	int i, na = 0;

	leg_udp(&c0, CODEC_AMRWB, 104);
	c0.te_pt = 107;
	c0.te_clock = 16000;
	leg_udp(&c1, CODEC_PCMA, 8);
	c1.te_pt = 101;
	c1.te_clock = 8000;
	run_open(&r, &c0, &c1, BR_CLIENT, 1);
	for (i = 0; i < 10; i++) {
		dig[i] = (uint8_t)i;
		want[i] = 100;
		a[na++] = (struct act){ .ms = 100 + 20 * (uint32_t)i, .m = true, .ts = 1000 + 100 * (uint32_t)i, .ev = (uint8_t)i, .dur = 160 };
		a[na++] = (struct act){ .ms = 100 + 20 * (uint32_t)i, .end = true, .ts = 1000 + 100 * (uint32_t)i, .ev = (uint8_t)i, .dur = 160 };
		a[na++] = (struct act){ .ms = 100 + 20 * (uint32_t)i, .end = true, .ts = 1000 + 100 * (uint32_t)i, .ev = (uint8_t)i, .dur = 160 };
		a[na++] = (struct act){ .ms = 100 + 20 * (uint32_t)i, .end = true, .ts = 1000 + 100 * (uint32_t)i, .ev = (uint8_t)i, .dur = 160 };
	}
	run_play(&r, a, na, 100 + 10 * 160 + 400);
	CHECK(run_check("burst10", &r, ev, dig, want, 10, 16000, 60, true, true) == 10);
	if (r.n && ev[9].digit == 9)	/* ~10 * (100 + 60) ms of playout */
		CHECK(r.rec[ev[9].end1].ms - r.rec[ev[0].first].ms >= 9 * 160 + 100 - 20);
	run_close(&r);
	printf("  (i) 10 digits within 200 ms: all played in order, ~160 ms each, 8 kHz -> 16 kHz\n");
}

/* a key held 1.5 s (continuation packets every 20 ms) is one event of ~1.5 s; carrier (16 kHz) -> client (8 kHz) */
static void t_dtmf_long(void)
{
	static struct act a[200];
	static struct oev ev[OEV_MAX];
	static const uint8_t dig[1] = { 11 };
	static const uint32_t want[1] = { 1500 };
	struct br_leg_cfg c0, c1;
	struct run r;
	int i, na = 0;

	leg_udp(&c0, CODEC_AMRWB, 104);
	c0.te_pt = 107;
	c0.te_clock = 16000;
	leg_udp(&c1, CODEC_PCMA, 8);
	c1.te_pt = 101;
	c1.te_clock = 8000;
	run_open(&r, &c0, &c1, BR_CARRIER, 0);
	for (i = 0; i < 75; i++)
		a[na++] = (struct act){ .ms = 100 + 20 * (uint32_t)i, .m = i == 0, .ts = 7000, .ev = 11, .dur = (uint16_t)(320 * (i + 1)) };
	for (i = 0; i < 3; i++)
		a[na++] = (struct act){ .ms = 100 + 1500, .end = true, .ts = 7000, .ev = 11, .dur = 24000 };
	run_play(&r, a, na, 100 + 1500 + 400);
	CHECK(run_check("long", &r, ev, dig, want, 1, 8000, 60, false, false) == 1);
	if (r.n && ev[0].digit == 11)
		CHECKF(ev[0].dur >= 12000 && ev[0].dur <= 12000 + 8 * 60, "long press duration %u", ev[0].dur);
	dtmf_events_seen(1, 1, 1500, 1);
	run_close(&r);
	printf("  (i) key held 1.5 s -> one event of ~1.5 s (16 kHz -> 8 kHz, carrier -> client)\n");
}

/* end packets lost: closed after the packets stop, proper end triplet; the main thread gets the idle-timeout end */
static void t_dtmf_lost_end(void)
{
	static struct act a[40];
	static struct oev ev[OEV_MAX];
	static const uint8_t dig[1] = { 5 };
	static const uint32_t want[1] = { 200 };
	struct br_leg_cfg c0, c1;
	struct run r;
	int i, na = 0;

	leg_udp(&c0, CODEC_AMRNB, 104);
	c0.te_pt = 107;
	c0.te_clock = 8000;
	leg_udp(&c1, CODEC_PCMA, 8);
	c1.te_pt = 101;
	c1.te_clock = 8000;
	run_open(&r, &c0, &c1, BR_CLIENT, 1);
	for (i = 0; i < 10; i++)
		a[na++] = (struct act){ .ms = 100 + 20 * (uint32_t)i, .m = i == 0, .ts = 7000, .ev = 5, .dur = (uint16_t)(160 * (i + 1)) };
	run_play(&r, a, na, 100 + 200 + 700);
	CHECK(run_check("lost end", &r, ev, dig, want, 1, 8000, 60, true, false) == 1);
	if (r.n && ev[0].digit == 5)	/* last packet announced 200 ms; released 100 ms after it, at most ~one packet of slack */
		CHECKF(ev[0].dur >= 1600 && ev[0].dur <= 2800, "lost end duration %u", ev[0].dur);
	CHECK(wait_ev(BR_EV_DTMF, BR_CLIENT, 2, 1000));
	dtmf_events_seen(1, 1, 200, 1);
	run_close(&r);
	printf("  (i) end packets lost: event closed after the packets stop, end triplet, idle-timeout notification\n");
}

/* queue overflow: 40 digits at once, queue of 32 -> the oldest waiting ones are dropped and counted */
static void t_dtmf_overflow(void)
{
	static struct act a[200];
	static struct oev ev[OEV_MAX];
	uint8_t dig[40];
	uint32_t want[40];
	struct br_leg_cfg c0, c1;
	struct bridge_stats st;
	struct run r;
	int i, na = 0, ne, drop, k;

	leg_udp(&c0, CODEC_AMRNB, 104);
	c0.te_pt = 107;
	c0.te_clock = 8000;
	c0.dtmf_min_ms = 20;	/* fast playout keeps the test short: 80 ms per digit (end packets 20 ms apart) */
	c0.dtmf_pause_ms = 0;
	leg_udp(&c1, CODEC_PCMA, 8);
	c1.te_pt = 101;
	c1.te_clock = 8000;
	run_open(&r, &c0, &c1, BR_CLIENT, 1);
	for (i = 0; i < 36; i++) {
		a[na++] = (struct act){ .ms = 100 + 2 * (uint32_t)i, .m = true, .ts = 1000 + 100 * (uint32_t)i, .ev = (uint8_t)(i % 16), .dur = 160 };
		a[na++] = (struct act){ .ms = 100 + 2 * (uint32_t)i, .end = true, .ts = 1000 + 100 * (uint32_t)i, .ev = (uint8_t)(i % 16), .dur = 160 };
	}
	run_play(&r, a, na, 100 + 72 + 33 * 80 + 250);
	bridge_get_stats(r.t.br, &st);
	drop = (int)st.leg[BR_CARRIER].dtmf_dropped;
	CHECKF(drop >= 3 && drop <= 4, "dropped %d", drop);
	/* expected: digits 0..39 minus the dropped ones just after the first; check the tail: the last 30 digits arrive in order */
	for (i = 0; i < 36; i++) {
		dig[i] = (uint8_t)(i % 16);
		want[i] = 20;
	}
	ne = 0;
	{
		int j;

		for (j = 0; j < r.n; j++)
			if (r.rec[j].pt == 107 && r.rec[j].m)
				ne++;
	}
	CHECKF(ne == 36 - drop, "played %d of 36, dropped %d", ne, drop);
	{
		static uint8_t got[64];
		int j, m = 0;

		for (j = 0; j < r.n; j++)
			if (r.rec[j].pt == 107 && r.rec[j].m && m < 64)
				got[m++] = r.rec[j].pl[0];
		for (k = 0; k < 30 && m >= 30; k++)
			CHECKF(got[m - 1 - k] == (uint8_t)((35 - k) % 16), "tail digit %d", k);
		CHECK(m == 0 || got[0] == 0);
	}
	run_close(&r);
	printf("  (i) queue overflow: oldest waiting digits dropped and counted, the rest in order\n");
	(void)ev;
	(void)want;
	(void)dig;
}

/* bridge_send_dtmf digits interleaved with RTP-borne ones keep their order */
static void t_dtmf_interleave(void)
{
	static struct act a[40];
	static struct oev ev[OEV_MAX];
	static const uint8_t dig[4] = { 1, 2, 3, 4 };
	static const uint32_t want[4] = { 160, 100, 160, 100 };
	struct br_leg_cfg c0, c1;
	struct run r;
	int na = 0;

	leg_udp(&c0, CODEC_AMRNB, 104);
	c0.te_pt = 107;
	c0.te_clock = 8000;
	leg_udp(&c1, CODEC_PCMA, 8);
	c1.te_pt = 101;
	c1.te_clock = 8000;
	run_open(&r, &c0, &c1, BR_CLIENT, 1);
	a[na++] = (struct act){ .ms = 100, .kind = 1, .ev = 1, .dur = 160 };
	a[na++] = (struct act){ .ms = 110, .m = true, .ts = 900, .ev = 2, .dur = 160 };
	a[na++] = (struct act){ .ms = 110, .end = true, .ts = 900, .ev = 2, .dur = 800 };
	a[na++] = (struct act){ .ms = 120, .kind = 1, .ev = 3, .dur = 160 };
	a[na++] = (struct act){ .ms = 130, .m = true, .ts = 1900, .ev = 4, .dur = 160 };
	a[na++] = (struct act){ .ms = 130, .end = true, .ts = 1900, .ev = 4, .dur = 800 };
	r.dst_leg = BR_CARRIER;
	run_play(&r, a, na, 100 + 4 * 160 + 300);
	CHECK(run_check("interleave", &r, ev, dig, want, 4, 8000, 60, true, true) == 4);
	run_close(&r);
	printf("  (i) bridge_send_dtmf and RTP-borne digits interleaved keep their order\n");
}

/* direction: a leg we may not send to drops digits silently and counts them */
static void t_dtmf_dir(void)
{
	static struct act a[40];
	struct br_leg_cfg c0, c1;
	struct bridge_stats st;
	struct run r;
	int na = 0, i;
	int n_te = 0;

	leg_udp(&c0, CODEC_AMRNB, 104);
	c0.te_pt = 107;
	c0.te_clock = 8000;
	leg_udp(&c1, CODEC_PCMA, 8);
	c1.te_pt = 101;
	c1.te_clock = 8000;
	run_open(&r, &c0, &c1, BR_CLIENT, 0);
	bridge_set_dir(r.t.br, BR_CARRIER, BR_RECVONLY);	/* we only receive from the carrier */
	for (i = 0; i < 3; i++) {
		a[na++] = (struct act){ .ms = 50 + 100 * (uint32_t)i, .m = true, .ts = 900 + 1000 * (uint32_t)i, .ev = (uint8_t)i, .dur = 160 };
		a[na++] = (struct act){ .ms = 50 + 100 * (uint32_t)i, .end = true, .ts = 900 + 1000 * (uint32_t)i, .ev = (uint8_t)i, .dur = 160 };
	}
	run_play(&r, a, na, 400);
	for (i = 0; i < r.n; i++)
		n_te += r.rec[i].pt == 107;
	CHECK(n_te == 0);
	bridge_get_stats(r.t.br, &st);
	CHECKF(st.leg[BR_CARRIER].dtmf_dropped == 3, "dropped %u", st.leg[BR_CARRIER].dtmf_dropped);
	/* digits already queued when the direction changes are dropped, the one on the wire stops */
	bridge_set_dir(r.t.br, BR_CARRIER, BR_SENDRECV);
	usleep(50000);
	na = 0;
	for (i = 0; i < 6; i++) {
		a[na++] = (struct act){ .ms = 10, .m = true, .ts = 90000 + 1000 * (uint32_t)i, .ev = (uint8_t)i, .dur = 160 };
		a[na++] = (struct act){ .ms = 10, .end = true, .ts = 90000 + 1000 * (uint32_t)i, .ev = (uint8_t)i, .dur = 160 };
	}
	r.n = 0;
	{
		uint32_t t_off = 0;

		run_play(&r, a, na, 60);
		bridge_set_dir(r.t.br, BR_CARRIER, BR_RECVONLY);
		t_off = (uint32_t)run_now(&r);
		(void)t_off;
		run_poll(&r, 50);
		n_te = r.n;
		run_poll(&r, 300);
		CHECK(r.n == n_te);	/* nothing more once the direction is gone */
	}
	bridge_get_stats(r.t.br, &st);
	CHECKF(st.leg[BR_CARRIER].dtmf_dropped >= 3 + 4, "dropped after dir change %u", st.leg[BR_CARRIER].dtmf_dropped);
	run_close(&r);
	printf("  (i) direction recvonly: digits dropped silently and counted; queue flushed on a direction change\n");
}

static void t_dtmf_regen(void)
{
	uint64_t t0 = now_ms();

	t_dtmf_bria();
	t_dtmf_bria_48k();
	t_dtmf_burst10();
	t_dtmf_long();
	t_dtmf_lost_end();
	t_dtmf_overflow();
	t_dtmf_interleave();
	t_dtmf_dir();
	printf("  (i) DTMF regeneration group took %.1f s\n", (double)(now_ms() - t0) / 1000.0);
}

void test_bridge(void)
{
	CHECK(bridge_engine_start() == 0);
	CHECK(bridge_engine_start() == 0);	/* idempotent */
	CHECK(bridge_engine_running() && bridge_event_fd() >= 0 && bridge_count() == 0);
	{
		struct bridge *b1 = bridge_create(NULL), *b2 = bridge_create(NULL);

		CHECK(b1 && b2 && bridge_count() == 2);
		bridge_destroy(b1);
		CHECK(bridge_count() == 1);
		bridge_destroy(b2);
		CHECK(bridge_count() == 0);
		CHECK(wait_ev(BR_EV_DESTROYED, -1, 2, 1000));
	}
	t_wb_to_opus();
	t_pcma_to_wb_cmr();
#ifdef IMSD_WITH_G722
	t_nb_g722();
	t_g722_to_nb();
#endif
	t_hold();
	t_dtmf();
	t_loss_dtx();
	t_sources();
	t_pcm_leg();
	t_keepalive();
	t_dtmf_tx();
	t_dtmf_regen();
	t_wav();
	t_rx_timer_hold();
	t_errors();
	bridge_engine_stop();
	CHECK(!bridge_engine_running() && bridge_count() == 0);
}

/* ------------------------------------------------------------ (f) command API stress */

#define NB_STRESS 100

struct stress {
	struct bridge *br;
	struct peer peer;
	struct addr a0, a1;
};

static volatile int flood_run;
static struct stress S[NB_STRESS];

static void *flooder(void *arg)
{
	uint8_t b[160];
	uint16_t seq = 0;
	int i;

	(void)arg;
	memset(b, 0xd5, sizeof(b));
	while (flood_run) {
		for (i = 0; i < NB_STRESS; i++) {
			struct sockaddr_in6 *sa = &S[i].a0.sa;

			if (S[i].peer.fd < 0)
				continue;
			(void)sa;
			psend(&S[i].peer, &S[i].a0, false, 8, seq, (uint32_t)seq * 160, 5, b, 160);
			psend(&S[i].peer, &S[i].a1, false, 8, seq, (uint32_t)seq * 160, 5, b, 160);
		}
		seq++;
		usleep(2000);
	}
	return NULL;
}

static void cmd_retry(int rc_fn(struct bridge *), struct bridge *b)
{
	while (rc_fn(b) < 0 && errno == EAGAIN)
		usleep(500);
}

void test_stress(void)
{
	pthread_t th;
	int i, round;
	struct br_leg_cfg c0, c1;
	static const enum codec_id ca[] = { CODEC_PCMA, CODEC_AMRWB, CODEC_AMRNB };
	static const enum codec_id cb[] = { CODEC_PCMA, CODEC_OPUS, CODEC_PCMA };

	CHECK(bridge_engine_start() == 0);
	nev = 0;
	for (i = 0; i < NB_STRESS; i++) {
		struct br_leg_cfg *c[2] = { &c0, &c1 };
		int fd0, fd1;

		leg_udp(&c0, ca[i % 3], i % 3 == 0 ? 8 : 100);
		leg_udp(&c1, cb[i % 3], i % 3 == 1 ? 111 : 8);
		if (i % 3 == 2)
			c0.amr_oa = true;
		fd0 = sock_open(&S[i].a0);
		fd1 = sock_open(&S[i].a1);
		c0.fd = fd0;
		c1.fd = fd1;
		c0.own_fd = c1.own_fd = true;
		peer_open(&S[i].peer);
		c0.remote = c1.remote = S[i].peer.addr;
		c0.has_remote = c1.has_remote = true;
		for (round = 0; round < 1; round++) {
			S[i].br = bridge_create(&S[i]);
			CHECK(S[i].br != NULL);
		}
		(void)c;
		while (bridge_set_leg(S[i].br, 0, &c0) < 0)
			usleep(500);
		while (bridge_set_leg(S[i].br, 1, &c1) < 0)
			usleep(500);
	}
	flood_run = 1;
	pthread_create(&th, NULL, flooder, NULL);
	for (round = 0; round < 3; round++) {
		for (i = 0; i < NB_STRESS; i++)
			cmd_retry(bridge_start, S[i].br);
		usleep(60000);
		for (i = 0; i < NB_STRESS; i++) {
			bridge_set_dir(S[i].br, i % 2, (enum br_dir)(round % 4));
			if (i % 2)
				cmd_retry(bridge_stop, S[i].br);
		}
		usleep(30000);
		pump();
	}
	/* drain what the peers received, then destroy everything while packets still flow */
	for (i = 0; i < NB_STRESS; i++)
		cmd_retry(bridge_destroy, S[i].br);
	CHECK(wait_ev(BR_EV_DESTROYED, -1, NB_STRESS, 10000));
	flood_run = 0;
	pthread_join(th, NULL);
	for (i = 0; i < NB_STRESS; i++) {
		static struct got g[4];
		(void)collect(&S[i].peer, g, 4, 0);
		close(S[i].peer.fd);
		S[i].peer.fd = -1;
	}
	printf("  (f) %d bridges created/started/stopped/restarted/destroyed under traffic; %d destroyed events, %d errors\n",
	       NB_STRESS, ev_count(BR_EV_DESTROYED, -1), ev_count(BR_EV_ERROR, -1));
	CHECK(ev_count(BR_EV_ERROR, -1) == 0);
	bridge_engine_stop();
}
