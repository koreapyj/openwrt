/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Kernel PCM interface (sound/asound.h) without alsa-lib: hw_params / sw_params by ioctl, interleaved
 * S16_LE mono transfers with SNDRV_PCM_IOCTL_READI_FRAMES / WRITEI_FRAMES on non-blocking fds. See pcmdev.h.
 *
 * Driver facts (target/linux/msm89xx/patches-6.12/922-...rtproxy-pcm): S16_LE only, 8000 / 16000 Hz, 1 channel,
 * period >= 320 bytes (20 ms at 8 kHz), 2..128 periods, buffer <= 64 KiB; the downlink / uplink commands are
 * paced by an hrtimer of 20 ms in the kernel, so the capture stream produces a period every 20 ms.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sound/asound.h>
#include "pcmdev.h"
#include "../util/log.h"

#define NPERIODS 4	/* buffer = 4 periods = 80 ms in each direction */

struct alsadev {
	int cfd, pfd;
	unsigned rate, period;
	int16_t part[PCMDEV_MAX_FRAMES];	/* a capture period that arrived in pieces */
	unsigned part_n;
};

/* ------------------------------------------------------------------ pure helpers */

int pcmdev_path(char *out, size_t n, int card, int dev, int capture)
{
	int r = snprintf(out, n, "/dev/snd/pcmC%dD%d%c", card, dev, capture ? 'c' : 'p');

	return r > 0 && (size_t)r < n ? 0 : -1;
}

int pcmdev_find_card(const char *text, int *card)
{
	const char *p = text;

	while (p && *p) {
		const char *eol = strchr(p, '\n');
		size_t len = eol ? (size_t)(eol - p) : strlen(p);
		char line[160];
		char *lb, *rb, *colon, *dash;
		int nr;

		if (len >= sizeof(line))
			len = sizeof(line) - 1;
		memcpy(line, p, len);
		line[len] = 0;
		p = eol ? eol + 1 : NULL;
		/* " 0 [MSM8916Voice  ]: q6afe-rtproxy - MSM8916 Voice"; continuation lines have no '[' before the text */
		lb = strchr(line, '[');
		rb = lb ? strchr(lb, ']') : NULL;
		colon = rb ? strchr(rb, ':') : NULL;
		if (!lb || !rb || !colon || sscanf(line, " %d", &nr) != 1)
			continue;
		*rb = 0;
		dash = strstr(colon + 1, " - ");
		if (strstr(lb + 1, "Voice") || (dash && strstr(dash, "Voice")) || strstr(colon + 1, "q6afe-rtproxy")) {
			*card = nr;
			return 0;
		}
	}
	return -1;
}

int pcmdev_parse_spec(const char *spec, int *card, int *dev)
{
	const char *s = spec ? spec : "";
	char *end;
	long v;

	*card = -1;
	*dev = 0;
	if (!strncmp(s, "hw:", 3))
		s += 3;
	if (!*s || !strcmp(s, "auto"))
		return 0;
	if (!strncmp(s, "auto,", 5)) {
		s += 5;
	} else {
		v = strtol(s, &end, 10);
		if (end == s || v < 0 || v > 31)
			return -1;
		if (*end == ',') {
			*card = (int)v;
			s = end + 1;
		} else if (!*end) {
			*dev = (int)v;
			return 0;
		} else {
			return -1;
		}
	}
	v = strtol(s, &end, 10);
	if (end == s || *end || v < 0 || v > 31)
		return -1;
	*dev = (int)v;
	return 0;
}

/* ------------------------------------------------------------------ ioctl layer */

static struct snd_mask *hw_mask(struct snd_pcm_hw_params *p, int v)
{
	return &p->masks[v - SNDRV_PCM_HW_PARAM_FIRST_MASK];
}

static struct snd_interval *hw_int(struct snd_pcm_hw_params *p, int v)
{
	return &p->intervals[v - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL];
}

static void hw_any(struct snd_pcm_hw_params *p)
{
	int i;

	memset(p, 0, sizeof(*p));
	for (i = 0; i <= SNDRV_PCM_HW_PARAM_LAST_MASK - SNDRV_PCM_HW_PARAM_FIRST_MASK; i++)
		memset(&p->masks[i], 0xff, sizeof(p->masks[i]));
	for (i = 0; i <= SNDRV_PCM_HW_PARAM_LAST_INTERVAL - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL; i++) {
		p->intervals[i].min = 0;
		p->intervals[i].max = ~0u;
	}
	p->rmask = ~0u;
	p->info = ~0u;
}

static void hw_set_mask(struct snd_pcm_hw_params *p, int v, unsigned bit)
{
	struct snd_mask *m = hw_mask(p, v);

	memset(m, 0, sizeof(*m));
	m->bits[bit >> 5] = 1u << (bit & 31);
}

static void hw_set_int(struct snd_pcm_hw_params *p, int v, unsigned val)
{
	struct snd_interval *i = hw_int(p, v);

	i->min = i->max = val;
	i->openmin = i->openmax = 0;
	i->integer = 1;
	i->empty = 0;
}

/* hw + sw parameters, PREPARE. 0 or -errno */
static int stream_setup(int fd, unsigned rate, unsigned period, bool capture)
{
	struct snd_pcm_hw_params hw;
	struct snd_pcm_sw_params sw;

	hw_any(&hw);
	hw_set_mask(&hw, SNDRV_PCM_HW_PARAM_ACCESS, SNDRV_PCM_ACCESS_RW_INTERLEAVED);
	hw_set_mask(&hw, SNDRV_PCM_HW_PARAM_FORMAT, SNDRV_PCM_FORMAT_S16_LE);
	hw_set_mask(&hw, SNDRV_PCM_HW_PARAM_SUBFORMAT, SNDRV_PCM_SUBFORMAT_STD);
	hw_set_int(&hw, SNDRV_PCM_HW_PARAM_CHANNELS, 1);
	hw_set_int(&hw, SNDRV_PCM_HW_PARAM_RATE, rate);
	hw_set_int(&hw, SNDRV_PCM_HW_PARAM_PERIOD_SIZE, period);
	hw_set_int(&hw, SNDRV_PCM_HW_PARAM_PERIODS, NPERIODS);
	if (ioctl(fd, SNDRV_PCM_IOCTL_HW_PARAMS, &hw) < 0)
		return -errno;
	memset(&sw, 0, sizeof(sw));
	sw.tstamp_mode = SNDRV_PCM_TSTAMP_NONE;
	sw.period_step = 1;
	sw.avail_min = period;			/* poll wakes up when a whole period is there / free */
	sw.xfer_align = 1;
	sw.start_threshold = capture ? 1 : 2 * period;	/* playback starts once two periods are queued */
	sw.stop_threshold = period * NPERIODS;	/* underrun / overrun when the buffer runs empty / full */
	sw.proto = SNDRV_PCM_VERSION;
	if (ioctl(fd, SNDRV_PCM_IOCTL_SW_PARAMS, &sw) < 0)
		return -errno;
	if (ioctl(fd, SNDRV_PCM_IOCTL_PREPARE) < 0)
		return -errno;
	return 0;
}

static int xfer_errno(int e)
{
	/* a disconnected card: -ENODEV, or -EBADFD (state DISCONNECTED) on the data path */
	if (e == EBADFD || e == ENODEV || e == ENOTTY || e == ESTRPIPE)
		return -ENODEV;
	return -e;
}

static int write_silence(struct alsadev *d, unsigned periods)
{
	int16_t z[PCMDEV_MAX_FRAMES];
	struct snd_xferi x;
	unsigned i;

	memset(z, 0, sizeof(z));
	for (i = 0; i < periods; i++) {
		memset(&x, 0, sizeof(x));
		x.buf = z;
		x.frames = d->period;
		if (ioctl(d->pfd, SNDRV_PCM_IOCTL_WRITEI_FRAMES, &x) < 0)
			return xfer_errno(errno);
	}
	return 0;
}

/* ------------------------------------------------------------------ ops */

static void *alsa_open(const char *spec, unsigned rate, unsigned period)
{
	struct alsadev *d;
	int card, dev, e;
	char path[40];

	if ((rate != 8000 && rate != 16000) || !period || period > PCMDEV_MAX_FRAMES || pcmdev_parse_spec(spec, &card, &dev) < 0) {
		errno = EINVAL;
		return NULL;
	}
	if (card < 0) {
		char buf[2048];
		FILE *f = fopen("/proc/asound/cards", "r");
		size_t n = 0;

		if (f) {
			n = fread(buf, 1, sizeof(buf) - 1, f);
			fclose(f);
		}
		buf[n] = 0;
		if (!n || pcmdev_find_card(buf, &card) < 0) {
			LOGW("pcm: no voice sound card found in /proc/asound/cards");
			errno = ENODEV;
			return NULL;
		}
	}
	d = calloc(1, sizeof(*d));
	if (!d)
		return NULL;
	d->cfd = d->pfd = -1;
	d->rate = rate;
	d->period = period;
	if (pcmdev_path(path, sizeof(path), card, dev, 1) < 0) {
		e = ENAMETOOLONG;
		goto fail;
	}
	d->cfd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (d->cfd < 0) {
		e = errno;
		LOGW("pcm: open %s: %s", path, strerror(e));
		goto fail;
	}
	pcmdev_path(path, sizeof(path), card, dev, 0);
	d->pfd = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
	if (d->pfd < 0) {
		e = errno;
		LOGW("pcm: open %s: %s", path, strerror(e));
		goto fail;
	}
	e = -stream_setup(d->cfd, rate, period, true);
	if (e) {
		LOGW("pcm: capture setup: %s", strerror(e));
		goto fail;
	}
	e = -stream_setup(d->pfd, rate, period, false);
	if (e) {
		LOGW("pcm: playback setup: %s", strerror(e));
		goto fail;
	}
	/* two periods of silence start the playback stream; the capture stream is started explicitly */
	e = -write_silence(d, 2);
	if (e) {
		LOGW("pcm: playback prime: %s", strerror(e));
		goto fail;
	}
	if (ioctl(d->cfd, SNDRV_PCM_IOCTL_START) < 0) {
		e = errno;
		LOGW("pcm: capture start: %s", strerror(e));
		goto fail;
	}
	LOGI("pcm: card %d device %d open, %u Hz, %u frames per period", card, dev, rate, period);
	return d;
fail:
	if (d->cfd >= 0)
		close(d->cfd);
	if (d->pfd >= 0)
		close(d->pfd);
	free(d);
	errno = e ? e : EIO;
	return NULL;
}

static int alsa_poll_fd(void *dev)
{
	return ((struct alsadev *)dev)->cfd;
}

static int alsa_read(void *dev, int16_t *pcm, unsigned frames)
{
	struct alsadev *d = dev;
	struct snd_xferi x;

	if (frames != d->period)
		return -EINVAL;
	memset(&x, 0, sizeof(x));
	x.buf = d->part + d->part_n;
	x.frames = frames - d->part_n;
	if (ioctl(d->cfd, SNDRV_PCM_IOCTL_READI_FRAMES, &x) < 0) {
		int e = errno;

		if (e == EAGAIN)
			return 0;
		if (e == EPIPE) {		/* overrun: start over */
			d->part_n = 0;
			if (ioctl(d->cfd, SNDRV_PCM_IOCTL_PREPARE) < 0 || ioctl(d->cfd, SNDRV_PCM_IOCTL_START) < 0)
				return xfer_errno(errno);
			return -EPIPE;
		}
		return xfer_errno(e);
	}
	d->part_n += (unsigned)x.result;
	if (d->part_n < frames)
		return 0;
	memcpy(pcm, d->part, frames * sizeof(int16_t));
	d->part_n = 0;
	return (int)frames;
}

static int alsa_write(void *dev, const int16_t *pcm, unsigned frames)
{
	struct alsadev *d = dev;
	struct snd_xferi x;

	memset(&x, 0, sizeof(x));
	x.buf = (void *)pcm;
	x.frames = frames;
	if (ioctl(d->pfd, SNDRV_PCM_IOCTL_WRITEI_FRAMES, &x) < 0) {
		int e = errno;

		if (e == EAGAIN)
			return -EAGAIN;
		if (e == EPIPE) {		/* underrun: restart, one period of silence in the buffer */
			if (ioctl(d->pfd, SNDRV_PCM_IOCTL_PREPARE) < 0)
				return xfer_errno(errno);
			if (write_silence(d, 1) < 0)
				return -ENODEV;
			return -EPIPE;
		}
		return xfer_errno(e);
	}
	return (int)x.result;
}

static void alsa_close(void *dev)
{
	struct alsadev *d = dev;

	if (!d)
		return;
	ioctl(d->cfd, SNDRV_PCM_IOCTL_DROP);
	ioctl(d->pfd, SNDRV_PCM_IOCTL_DROP);
	close(d->cfd);
	close(d->pfd);
	free(d);
}

const struct br_pcmdev_ops pcmdev_alsa_ops = {
	.name = "alsa-ioctl",
	.open = alsa_open,
	.poll_fd = alsa_poll_fd,
	.read = alsa_read,
	.write = alsa_write,
	.close = alsa_close,
};
