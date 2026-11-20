// SPDX-License-Identifier: GPL-2.0-only
/*
 * msm-diag-bridge: bridge the modem DIAG SMD channel (rpmsg) to the USB ACM
 * gadget tty so QPST/QXDM on the host can talk DIAG.
 *
 * usage: msm-diag-bridge [tty]   (env DIAG_TTY / DIAG_CHAN also honoured)
 * Exits non-zero on any error so procd respawns it.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <linux/types.h>

/* local definition of <linux/rpmsg.h> uapi, avoids header dependency */
struct msm_rpmsg_ept_info {
	char name[32];
	__u32 src;
	__u32 dst;
};
#define MSM_RPMSG_CREATE_EPT_IOCTL _IOW(0xb5, 0x1, struct msm_rpmsg_ept_info)

#define MODEM_EDGE "remoteproc0:smd-edge"

static const char *chan = "DIAG";

static int fail(const char *what)
{
	fprintf(stderr, "msm-diag-bridge: %s: %s\n", what, strerror(errno));
	return 1;
}

static const char *base(const char *p)
{
	const char *s = strrchr(p, '/');
	return s ? s + 1 : p;
}

/* returns 0 and fills dev with /dev/rpmsgN if channel endpoint exists */
static int find_ept(char *dev, size_t len)
{
	glob_t g;
	size_t i;
	int found = 0;

	if (glob("/sys/class/rpmsg/rpmsg[0-9]*", 0, NULL, &g))
		return -1;
	for (i = 0; i < g.gl_pathc && !found; i++) {
		char path[PATH_MAX], name[64];
		FILE *f;

		snprintf(path, sizeof(path), "%s/name", g.gl_pathv[i]);
		f = fopen(path, "r");
		if (!f)
			continue;
		if (fgets(name, sizeof(name), f)) {
			name[strcspn(name, "\r\n")] = 0;
			if (!strcmp(name, chan)) {
				snprintf(dev, len, "/dev/%s", base(g.gl_pathv[i]));
				found = 1;
			}
		}
		fclose(f);
	}
	globfree(&g);
	return found ? 0 : -1;
}

static int find_ctrl(char *dev, size_t len)
{
	glob_t g;
	size_t i;
	int found = 0;

	if (glob("/sys/class/rpmsg/rpmsg_ctrl*", 0, NULL, &g))
		return -1;
	for (i = 0; i < g.gl_pathc && !found; i++) {
		char path[PATH_MAX], target[PATH_MAX];
		ssize_t n;

		snprintf(path, sizeof(path), "%s/device", g.gl_pathv[i]);
		n = readlink(path, target, sizeof(target) - 1);
		if (n < 0)
			continue;
		target[n] = 0;
		if (strstr(target, MODEM_EDGE)) {
			snprintf(dev, len, "/dev/%s", base(g.gl_pathv[i]));
			found = 1;
		}
	}
	globfree(&g);
	return found ? 0 : -1;
}

static int write_full(int fd, const char *buf, size_t len)
{
	while (len) {
		ssize_t w = write(fd, buf, len);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				struct pollfd p = { .fd = fd, .events = POLLOUT };

				poll(&p, 1, -1);
				continue;
			}
			return -1;
		}
		buf += w;
		len -= w;
	}
	return 0;
}

static int pump(int from, int to, const char *fname, const char *tname)
{
	static char buf[65536];
	ssize_t r;
	char msg[64];

	do
		r = read(from, buf, sizeof(buf));
	while (r < 0 && (errno == EINTR || errno == EAGAIN));
	if (r <= 0) {
		if (r == 0)
			errno = EPIPE;
		snprintf(msg, sizeof(msg), "%s read", fname);
		return fail(msg);
	}
	if (write_full(to, buf, r)) {
		snprintf(msg, sizeof(msg), "%s write", tname);
		return fail(msg);
	}
	return 0;
}

/*
 * host -> modem: the modem DIAG SMD channel takes one raw (un-framed) request per
 * rpmsg packet, while QPST/QXDM send HDLC frames (escaped payload + CRC16 + 0x7e).
 * Forwarding frames verbatim only works for commands that tolerate trailing bytes
 * (version, NV); strict-length ones (EFS2, log/event masks) get rejected. So decode
 * each frame and write its payload as a single packet. Non-HDLC frames
 * (0x7e 0x01 <len16> <payload> 0x7e) are passed as their payload too.
 */
static unsigned short crc16(const unsigned char *d, size_t n)
{
	unsigned short c = 0xffff;
	int i;

	while (n--) {
		c ^= *d++;
		for (i = 0; i < 8; i++)
			c = (c & 1) ? (c >> 1) ^ 0x8408 : c >> 1;
	}
	return c ^ 0xffff;
}

static int host_to_modem(int from, int to)
{
	static unsigned char in[65536], frame[65536];
	static size_t flen;
	static int esc;
	ssize_t r, i;

	do
		r = read(from, in, sizeof(in));
	while (r < 0 && (errno == EINTR || errno == EAGAIN));
	if (r <= 0) {
		if (r == 0)
			errno = EPIPE;
		return fail("tty read");
	}
	for (i = 0; i < r; i++) {
		unsigned char b = in[i];

		if (b != 0x7e) {
			if (flen >= sizeof(frame)) {	/* runaway: resync */
				flen = 0;
				esc = 0;
			}
			if (esc) {
				frame[flen++] = b ^ 0x20;
				esc = 0;
			} else if (b == 0x7d) {
				esc = 1;
			} else {
				frame[flen++] = b;
			}
			continue;
		}
		/* end of frame */
		if (flen >= 3 && crc16(frame, flen - 2) ==
		    (frame[flen - 2] | frame[flen - 1] << 8)) {
			if (write_full(to, (char *)frame, flen - 2))
				return fail("rpmsg write");
		} else if (flen >= 3 && frame[0] == 0x01 &&
			   (size_t)(frame[1] | frame[2] << 8) == flen - 3) {
			if (write_full(to, (char *)frame + 3, flen - 3))
				return fail("rpmsg write");
		}
		flen = 0;
		esc = 0;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *tty = getenv("DIAG_TTY");
	char ept[64] = "", ctrl[64];
	struct msm_rpmsg_ept_info info;
	struct termios t;
	struct pollfd pfd[2];
	int ttyfd, rpfd, cfd, i;

	if (getenv("DIAG_CHAN"))
		chan = getenv("DIAG_CHAN");
	if (argc > 1)
		tty = argv[1];
	if (!tty || !*tty)
		tty = "/dev/ttyGS0";

	if (find_ept(ept, sizeof(ept))) {
		if (find_ctrl(ctrl, sizeof(ctrl))) {
			fprintf(stderr, "msm-diag-bridge: no modem rpmsg_ctrl found\n");
			return 1;
		}
		cfd = open(ctrl, O_RDWR);
		if (cfd < 0)
			return fail(ctrl);
		memset(&info, 0, sizeof(info));
		strncpy(info.name, chan, sizeof(info.name) - 1);
		info.src = 0xffffffff;
		info.dst = 0xffffffff;
		if (ioctl(cfd, MSM_RPMSG_CREATE_EPT_IOCTL, &info) < 0) {
			fail("RPMSG_CREATE_EPT_IOCTL");
			close(cfd);
			return 1;
		}
		close(cfd);
		for (i = 0; i < 50 && find_ept(ept, sizeof(ept)); i++)
			usleep(100000);
		if (!ept[0]) {
			fprintf(stderr, "msm-diag-bridge: endpoint for %s did not appear\n", chan);
			return 1;
		}
	}
	fprintf(stderr, "msm-diag-bridge: %s endpoint %s <-> %s\n", chan, ept, tty);

	/* wait for the /dev node (devtmpfs/hotplug) */
	for (i = 0; i < 100 && access(ept, F_OK); i++)
		usleep(100000);
	for (i = 0; i < 100 && access(tty, F_OK); i++)
		usleep(100000);

	ttyfd = open(tty, O_RDWR | O_NOCTTY);
	if (ttyfd < 0)
		return fail(tty);
	if (tcgetattr(ttyfd, &t) < 0)
		return fail("tcgetattr");
	cfmakeraw(&t);
	t.c_cflag |= CREAD | CLOCAL;
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;
	if (tcsetattr(ttyfd, TCSANOW, &t) < 0)
		return fail("tcsetattr");

	rpfd = open(ept, O_RDWR);
	if (rpfd < 0)
		return fail(ept);

	pfd[0].fd = rpfd;
	pfd[0].events = POLLIN;
	pfd[1].fd = ttyfd;
	pfd[1].events = POLLIN;
	for (;;) {
		if (poll(pfd, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			return fail("poll");
		}
		/* modem -> host */
		if (pfd[0].revents & POLLIN) {
			if (pump(rpfd, ttyfd, "rpmsg", "tty"))
				return 1;
		} else if (pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
			fprintf(stderr, "msm-diag-bridge: rpmsg hangup\n");
			return 1;
		}
		/* host -> modem */
		if (pfd[1].revents & POLLIN) {
			if (host_to_modem(ttyfd, rpfd))
				return 1;
		} else if (pfd[1].revents & (POLLHUP | POLLERR | POLLNVAL)) {
			fprintf(stderr, "msm-diag-bridge: tty hangup\n");
			return 1;
		}
	}
}
