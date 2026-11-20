/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Smoke test of the modem's voice sound card with the same device code the daemon uses (media/pcmdev.c: kernel PCM ioctls
 * on /dev/snd/pcmC<card>D<dev>{c,p}, 8 kHz S16_LE mono, 20 ms periods, paced by the capture stream).
 *
 *   pcmsmoke [-d spec] [-s seconds] [-o downlink.wav] [-m tone|silence|echo] [-f hz]
 *
 *   -d  device: "" / "auto" (locate the voice card in /proc/asound/cards, device 0), "auto,1", "0,0"   (default auto)
 *   -s  how long to run, seconds                                                                      (default 10, max 300)
 *   -o  write the downlink (what the network sends) to this WAV file; every second is also summarised on stdout
 *   -m  uplink: tone (default, sine of -f Hz, so the far end hears it), silence, or echo (downlink looped back, delayed 40 ms)
 *   -f  tone frequency                                                                                 (default 440)
 *
 * Use it during a call: start a call (ubus call uqmid.modem.0 voice_create_call '{"number":"114"}' then start on the call
 * object), run `pcmsmoke -s 15 -o /tmp/dl.wav`, hang up. 114 plays an announcement: /tmp/dl.wav must contain it (the rms column is
 * not 0), the capture periods must arrive every 20 ms (50 per second, small gap_max), xruns must stay 0. Without a call the
 * downlink is silence (rms 0): that only proves that the device opens and is clocked. Opening starts the voice session of the
 * modem, closing ends it (the call itself stays up).
 */
#include <errno.h>
#include <math.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../../media/pcmdev.h"

#define PI 3.14159265358979323846
#define FR 160
#define MAX_S 300

static uint64_t now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static int write_wav(const char *path, const int16_t *pcm, size_t n)
{
	static const uint8_t tmpl[44] = { 'R', 'I', 'F', 'F', 0, 0, 0, 0, 'W', 'A', 'V', 'E', 'f', 'm', 't', ' ', 16, 0, 0, 0, 1, 0, 1, 0,
					  0x40, 0x1f, 0, 0, 0x80, 0x3e, 0, 0, 2, 0, 16, 0, 'd', 'a', 't', 'a', 0, 0, 0, 0 };
	uint8_t h[44];
	FILE *f = fopen(path, "wb");

	if (!f)
		return -1;
	memcpy(h, tmpl, sizeof(h));
	put32(h + 4, (uint32_t)(36 + n * 2));
	put32(h + 40, (uint32_t)(n * 2));
	if (fwrite(h, 1, 44, f) != 44 || fwrite(pcm, 2, n, f) != n) {
		fclose(f);
		return -1;
	}
	return fclose(f);
}

static double rms(const int16_t *x, size_t n)
{
	double s = 0;
	size_t i;

	for (i = 0; i < n; i++)
		s += (double)x[i] * x[i];
	return n ? sqrt(s / (double)n) : 0;
}

int main(int argc, char **argv)
{
	const struct br_pcmdev_ops *op = &pcmdev_alsa_ops;
	const char *spec = "", *out = NULL, *mode = "tone";
	unsigned secs = 10, freq = 440;
	int opt, pfd, sec_no = 0;
	void *dev;
	int16_t *dl;
	size_t cap, nd = 0;
	int16_t ring[16][FR], fr[FR], ul[FR];
	unsigned rp = 0, wp = 0;
	double ph = 0, sec_sq = 0;
	uint64_t start, last_rx, next_report, gap_max = 0, sec_gap_max = 0;
	unsigned long periods = 0, xr_rx = 0, xr_tx = 0, full = 0, errs = 0, sec_n = 0, zero_periods = 0;

	while ((opt = getopt(argc, argv, "d:s:o:m:f:h")) != -1) {
		switch (opt) {
		case 'd': spec = optarg; break;
		case 's': secs = (unsigned)atoi(optarg); break;
		case 'o': out = optarg; break;
		case 'm': mode = optarg; break;
		case 'f': freq = (unsigned)atoi(optarg); break;
		default:
			fprintf(stderr, "usage: %s [-d spec] [-s seconds] [-o downlink.wav] [-m tone|silence|echo] [-f hz]\n", argv[0]);
			return 2;
		}
	}
	if (!secs || secs > MAX_S || (strcmp(mode, "tone") && strcmp(mode, "silence") && strcmp(mode, "echo"))) {
		fprintf(stderr, "bad -s / -m\n");
		return 2;
	}
	cap = (size_t)(secs + 2) * 8000;
	dl = calloc(cap, sizeof(*dl));
	if (!dl)
		return 1;
	dev = op->open(spec, PCMDEV_RATE, FR);
	if (!dev) {
		fprintf(stderr, "open failed: %s (EBUSY = the other voice device is open, ENODEV = no voice card)\n", strerror(errno));
		free(dl);
		return 1;
	}
	pfd = op->poll_fd(dev);
	printf("device open (%s), %u s, uplink %s\n", spec[0] ? spec : "auto", secs, mode);
	printf("%4s %8s %8s %10s %8s %8s\n", "sec", "periods", "rms", "gap_max", "xrun_rx", "xrun_tx");
	start = last_rx = now_ms();
	next_report = start + 1000;
	memset(ring, 0, sizeof(ring));
	while (now_ms() - start < (uint64_t)secs * 1000) {
		struct pollfd p = { .fd = pfd, .events = POLLIN };
		uint64_t t;

		if (poll(&p, 1, 200) < 0 && errno != EINTR)
			break;
		for (;;) {
			int r, i;

			r = op->read(dev, fr, FR);
			if (r == 0)
				break;
			if (r == -EPIPE) {
				xr_rx++;
				continue;
			}
			if (r < 0) {
				fprintf(stderr, "read: %s\n", strerror(-r));
				errs++;
				goto done;
			}
			t = now_ms();
			if (t - last_rx > gap_max)
				gap_max = t - last_rx;
			if (t - last_rx > sec_gap_max)
				sec_gap_max = t - last_rx;
			last_rx = t;
			periods++;
			sec_n++;
			{
				double e = rms(fr, FR);

				sec_sq += e * e;
				if (e == 0)
					zero_periods++;
			}
			if (nd + FR <= cap) {
				memcpy(dl + nd, fr, sizeof(fr));
				nd += FR;
			}
			/* the uplink period */
			if (!strcmp(mode, "tone")) {
				for (i = 0; i < FR; i++) {
					ul[i] = (int16_t)(6000 * sin(ph));
					ph += 2 * PI * freq / 8000.0;
				}
			} else if (!strcmp(mode, "echo")) {
				memcpy(ring[wp % 16], fr, sizeof(fr));
				wp++;
				if (wp - rp > 2) {
					memcpy(ul, ring[rp % 16], sizeof(ul));
					rp++;
				} else {
					memset(ul, 0, sizeof(ul));
				}
			} else {
				memset(ul, 0, sizeof(ul));
			}
			r = op->write(dev, ul, FR);
			if (r == -EPIPE) {
				xr_tx++;
				r = op->write(dev, ul, FR);
			}
			if (r == -EAGAIN) {
				full++;
			} else if (r < 0 && r != -EPIPE) {
				fprintf(stderr, "write: %s\n", strerror(-r));
				errs++;
				goto done;
			}
		}
		t = now_ms();
		if (t >= next_report) {
			printf("%4d %8lu %8.0f %7lu ms %8lu %8lu\n", ++sec_no, sec_n, sec_n ? sqrt(sec_sq / (double)sec_n) : 0.0,
			       (unsigned long)sec_gap_max, xr_rx, xr_tx);
			fflush(stdout);
			sec_n = 0;
			sec_sq = 0;
			sec_gap_max = 0;
			next_report += 1000;
		}
	}
done:
	op->close(dev);
	printf("done: %lu capture periods in %u s (50 per second expected), %lu all-zero, worst gap %lu ms, capture xruns %lu, playback xruns %lu, "
	       "playback full %lu, errors %lu\n", periods, secs, zero_periods, (unsigned long)gap_max, xr_rx, xr_tx, full, errs);
	if (out) {
		if (write_wav(out, dl, nd) < 0)
			fprintf(stderr, "cannot write %s\n", out);
		else
			printf("downlink: %s (%zu samples, %.1f s, overall rms %.0f)\n", out, nd, (double)nd / 8000.0, rms(dl, nd));
	}
	free(dl);
	return errs ? 1 : 0;
}
