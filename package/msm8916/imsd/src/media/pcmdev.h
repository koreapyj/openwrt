/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MEDIA_PCMDEV_H
#define IMSD_MEDIA_PCMDEV_H
#include <stddef.h>
#include <stdint.h>

/*
 * Local PCM device as a carrier endpoint of the media bridge (circuit switched voice: the modem does the
 * codec and the air interface, the AP only moves 8 kHz S16_LE PCM). The bridge (BR_LEG_PCMDEV, bridge.h)
 * only talks to this small ops struct, so tests plug in a fake device; the real one (pcmdev_alsa_ops) uses
 * the kernel PCM character device /dev/snd/pcmC<card>D<dev>{c,p} through its ioctl interface, with no
 * alsa-lib.
 *
 * The device is the CLOCK MASTER: the capture stream (call downlink) delivers one period every 20 ms; the
 * bridge reads it when poll_fd() becomes readable and writes exactly one uplink period per downlink period.
 * All functions are called from the media thread only and must not block (the fds are non-blocking).
 */
#define PCMDEV_RATE 8000
#define PCMDEV_PERIOD_MS 20
#define PCMDEV_MAX_FRAMES 320	/* largest period the bridge handles: 20 ms at 16 kHz */

struct br_pcmdev_ops {
	const char *name;
	/*
	 * Open capture and playback of the device named by spec ("" / "auto" = locate the voice card, device 0;
	 * "<card>,<dev>" or "auto,<dev>"), S16_LE mono at rate (8000 / 16000), one period = period_frames frames.
	 * Opening the first stream starts the voice session of the modem. NULL with errno set on failure (EBUSY: the
	 * other voice device is open, ENODEV / ENOENT: no such card).
	 */
	void *(*open)(const char *spec, unsigned rate, unsigned period_frames);
	/* a pollable fd that becomes readable when a capture period is ready (owned by the device) */
	int (*poll_fd)(void *dev);
	/*
	 * Read exactly one period. Returns period_frames; 0 = not ready; -EPIPE = overrun (already recovered, no
	 * data this time); -ENODEV (or any other negative errno) = the device is gone / broken.
	 */
	int (*read)(void *dev, int16_t *pcm, unsigned frames);
	/*
	 * Write one period. Returns the frames accepted (< frames: the buffer was nearly full, the rest is
	 * dropped); -EAGAIN = buffer full, nothing accepted; -EPIPE = underrun (already recovered, nothing written,
	 * the caller may write again); other negative errno = gone.
	 */
	int (*write)(void *dev, const int16_t *pcm, unsigned frames);
	void (*close)(void *dev);
};

extern const struct br_pcmdev_ops pcmdev_alsa_ops;

/*
 * Find the voice card in the text of /proc/asound/cards: a line " 0 [MSM8916Voice  ]: q6afe-rtproxy - MSM8916 Voice"
 * matches when the driver is q6afe-rtproxy, or the id or the name contains "Voice". 0 and *card, or -1.
 * Pure function (tests).
 */
int pcmdev_find_card(const char *cards_text, int *card);
/* "" / "auto" / "auto,1" / "0,0" / "1" (device only) -> card (-1 = auto), dev. 0, or -1 for garbage. Pure. */
int pcmdev_parse_spec(const char *spec, int *card, int *dev);
/* "/dev/snd/pcmC0D0c" (capture) / "...p" (playback). 0, or -1 if it does not fit */
int pcmdev_path(char *out, size_t n, int card, int dev, int capture);
#endif
