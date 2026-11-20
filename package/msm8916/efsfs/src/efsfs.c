// SPDX-License-Identifier: GPL-2.0-only
/*
 * efsfs: READ-ONLY FUSE view of the MSM8916 modem EFS2 (and NV items),
 * reached over the modem DIAG rpmsg channel.
 *
 *  - EFS paths map 1:1 (/nv/item_files/..., /policyman/..., ...).
 *  - /nv/<decimal> that is not a real EFS entry is NV item <decimal>
 *    (DIAG NV_READ_F 0x26), exposed as a 128 byte file.
 *
 * Only getattr/readdir/open/read/readlink are implemented. The DIAG channel
 * is opened per FUSE operation and released afterwards so that the modem_nv
 * hotplug script and msm-diag-bridge can use it between operations.
 * Requests sent: EFS2 OPEN(O_RDONLY)/READ/CLOSE/OPENDIR/READDIR/CLOSEDIR/
 * STAT/READLINK and NV_READ_F only.
 */
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <linux/types.h>

struct ept_info { char name[32]; __u32 src; __u32 dst; };
#define RPMSG_CREATE_EPT_IOCTL _IOW(0xb5, 0x1, struct ept_info)
#define MODEM_EDGE "remoteproc0:smd-edge"
#define CHAN "DIAG"

#define EFS_OPEN 2
#define EFS_CLOSE 3
#define EFS_READ 4
#define EFS_READLINK 7
#define EFS_OPENDIR 11
#define EFS_READDIR 12
#define EFS_CLOSEDIR 13
#define EFS_STAT 15

#define EFS_CHUNK 512
#define NV_SIZE 128
#define XFER_TIMEOUT_MS 5000
#define IDLE_CLOSE_S 2
#define PACE_US 10000
#define COOLDOWN_S 3
#define RSP_MAX 4096

static int dfd = -1;

/* modem (EFS2) errno -> Linux errno; EFS uses the common POSIX values */
static int efs_err(int e)
{
	switch (e) {
	case 2: return ENOENT;
	case 20: return ENOTDIR;
	case 1: case 13: return e == 1 ? EPERM : EACCES;
	}
	return e > 0 && e < 200 ? e : EIO;
}
static pthread_mutex_t diag_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---------------- HDLC ---------------- */

static uint16_t crc16(const uint8_t *d, size_t n)
{
	uint16_t crc = 0xffff;
	while (n--) {
		crc ^= *d++;
		for (int i = 0; i < 8; i++)
			crc = (crc & 1) ? (crc >> 1) ^ 0x8408 : crc >> 1;
	}
	return crc ^ 0xffff;
}

/* in-place unescape of one frame (without the 0x7e); returns payload len or -1 */
static int unhdlc(uint8_t *f, size_t n)
{
	size_t o = 0;
	int esc = 0;
	for (size_t i = 0; i < n; i++) {
		if (esc) { f[o++] = f[i] ^ 0x20; esc = 0; }
		else if (f[i] == 0x7d) esc = 1;
		else f[o++] = f[i];
	}
	if (o < 3)
		return -1;
	o -= 2;
	if (crc16(f, o) != (uint16_t)(f[o] | f[o + 1] << 8))
		return -1;
	return (int)o;
}

/* ---------------- DIAG channel ---------------- */

static const char *base(const char *p)
{
	const char *s = strrchr(p, '/');
	return s ? s + 1 : p;
}

static int find_ept(char *dev, size_t len)
{
	glob_t g;
	int found = 0;

	if (glob("/sys/class/rpmsg/rpmsg[0-9]*", 0, NULL, &g))
		return -1;
	for (size_t i = 0; i < g.gl_pathc && !found; i++) {
		char path[PATH_MAX], name[64];
		FILE *f;

		snprintf(path, sizeof(path), "%s/name", g.gl_pathv[i]);
		if (!(f = fopen(path, "r")))
			continue;
		if (fgets(name, sizeof(name), f)) {
			name[strcspn(name, "\r\n")] = 0;
			if (!strcmp(name, CHAN)) {
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
	int found = 0;

	if (glob("/sys/class/rpmsg/rpmsg_ctrl*", 0, NULL, &g))
		return -1;
	for (size_t i = 0; i < g.gl_pathc && !found; i++) {
		char path[PATH_MAX], target[PATH_MAX];
		ssize_t n;

		snprintf(path, sizeof(path), "%s/device", g.gl_pathv[i]);
		if ((n = readlink(path, target, sizeof(target) - 1)) < 0)
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

/* open the DIAG endpoint; -EBUSY if someone else holds it, -ENODEV if no modem */
static int diag_open(void)
{
	char ept[64] = "", ctrl[64];
	struct ept_info info;
	int fd = -1, tries, i;

	if (find_ept(ept, sizeof(ept))) {
		int cfd;

		if (find_ctrl(ctrl, sizeof(ctrl)))
			return -ENODEV;
		if ((cfd = open(ctrl, O_RDWR)) < 0)
			return -errno;
		memset(&info, 0, sizeof(info));
		strncpy(info.name, CHAN, sizeof(info.name) - 1);
		info.src = info.dst = 0xffffffff;
		if (ioctl(cfd, RPMSG_CREATE_EPT_IOCTL, &info) < 0) {
			int e = errno;
			close(cfd);
			return -e;
		}
		close(cfd);
		for (i = 0; i < 30 && find_ept(ept, sizeof(ept)); i++)
			usleep(100000);
		if (!ept[0])
			return -ENODEV;
	}
	for (i = 0; i < 30 && access(ept, F_OK); i++)
		usleep(100000);
	for (tries = 0; tries < 5; tries++) {
		fd = open(ept, O_RDWR | O_NONBLOCK);
		if (fd >= 0)
			break;
		if (errno != EBUSY)
			return -errno;
		usleep(300000);
	}
	if (fd < 0)
		return -EBUSY;
	/* drop stale messages */
	{
		static uint8_t junk[RSP_MAX * 4];
		while (read(fd, junk, sizeof(junk)) > 0)
			;
	}
	dfd = fd;
	return 0;
}

static long now_s(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec;
}

static long long now_us(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long long)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}

static long long last_send_us;
static long cooldown_until;	/* after a DIAG failure leave the modem alone for a while */

static void diag_close(void)
{
	if (dfd >= 0)
		close(dfd);
	dfd = -1;
}

/* a failed/unanswered exchange: drop the endpoint and back off, never resend */
static void diag_poison(void)
{
	diag_close();
	cooldown_until = now_s() + COOLDOWN_S;
}

/*
 * Send ONE request (never resent) and wait for the response whose first
 * `echo` bytes match the request. Returns the whole response length or
 * -errno. The caller holds diag_lock, so exchanges never overlap.
 */
static int xfer(const uint8_t *req, size_t rlen, size_t echo, uint8_t *rsp, size_t cap)
{
	static uint8_t buf[RSP_MAX * 4];
	struct pollfd p = { .fd = dfd, .events = POLLIN };
	int waited = 0;
	long long d;

	if (rlen > 1100)
		return -EINVAL;
	/* drop anything left over from an earlier exchange */
	while (read(dfd, buf, sizeof(buf)) > 0)
		;
	/* pace requests */
	if ((d = now_us() - last_send_us) < PACE_US && d >= 0)
		usleep(PACE_US - d);
	if (write(dfd, req, rlen) < 0) {
		int e = errno;
		diag_poison();
		return e == ENOTCONN || e == EPIPE ? -ENODEV : -EIO;
	}
	last_send_us = now_us();

	while (waited < XFER_TIMEOUT_MS) {
		ssize_t n;
		size_t pos = 0;
		int r = poll(&p, 1, 100);

		if (r < 0 && errno != EINTR) {
			diag_poison();
			return -EIO;
		}
		if (r <= 0) { waited += 100; continue; }
		if (p.revents & (POLLHUP | POLLERR | POLLNVAL)) {
			diag_poison();
			return -ENODEV;
		}
		n = read(dfd, buf, sizeof(buf));
		if (n <= 0)
			continue;
		/* a read may hold several 0x7e terminated frames */
		while (pos < (size_t)n) {
			size_t e = pos;
			int l;

			while (e < (size_t)n && buf[e] != 0x7e)
				e++;
			if (e > pos && (l = unhdlc(buf + pos, e - pos)) > 0) {
				uint8_t *m = buf + pos;

				if ((size_t)l >= echo && !memcmp(m, req, echo)) {
					if ((size_t)l > cap)
						return -EIO;
					memcpy(rsp, m, l);
					return l;
				}
				/* 0x13 bad cmd, 0x14/0x15/0x16/0x18/0x47 rejects: final answer */
				if (m[0] == 0x13 || m[0] == 0x14 || m[0] == 0x15 ||
				    m[0] == 0x16 || m[0] == 0x18 || m[0] == 0x47) {
					fprintf(stderr, "efsfs: DIAG rejected request %02x %02x %02x %02x with 0x%02x\n",
						req[0], rlen > 1 ? req[1] : 0, rlen > 2 ? req[2] : 0,
						rlen > 3 ? req[3] : 0, m[0]);
					return -EACCES;
				}
			}
			pos = e + 1;
		}
	}
	/* no answer: it may still arrive, so do not send anything else for a while */
	fprintf(stderr, "efsfs: DIAG timeout\n");
	diag_poison();
	return -EIO;
}

static int efs(uint16_t cmd, const void *pl, size_t plen, uint8_t *rsp, size_t cap)
{
	uint8_t req[1024 + 8];
	int r;

	if (plen > 1024)
		return -ENAMETOOLONG;
	req[0] = 0x4b; req[1] = 0x13; req[2] = cmd & 0xff; req[3] = cmd >> 8;
	memcpy(req + 4, pl, plen);
	r = xfer(req, 4 + plen, 4, rsp, cap);
	if (r < 0)
		return r;
	return r - 4;	/* payload after subsys header */
}

#define RD32(p, o) ((int32_t)((p)[o] | (p)[(o)+1] << 8 | (p)[(o)+2] << 16 | (uint32_t)(p)[(o)+3] << 24))
#define WR32(p, o, v) do { uint32_t _v = (v); (p)[o] = _v; (p)[(o)+1] = _v >> 8; \
	(p)[(o)+2] = _v >> 16; (p)[(o)+3] = _v >> 24; } while (0)

/* ---------------- EFS / NV ops ---------------- */

static int path_ok(const char *path)
{
	return strlen(path) < 512 ? 0 : -ENAMETOOLONG;
}

static void fill_stat(struct stat *st, int32_t mode, int32_t size, int32_t nlink,
		      int32_t mtime, int32_t atime, int32_t ctime)
{
	memset(st, 0, sizeof(*st));
	switch (mode & S_IFMT) {
	case S_IFDIR: st->st_mode = S_IFDIR; break;
	case S_IFLNK: st->st_mode = S_IFLNK; break;
	default: st->st_mode = S_IFREG; break;	/* regular and EFS item files */
	}
	/* read-only mount: dirs r-x, files r-- (EFS mode bits are not meaningful here) */
	st->st_mode |= S_ISDIR(st->st_mode) ? 0555 : 0444;
	st->st_size = size < 0 ? 0 : size;
	st->st_nlink = nlink > 0 ? nlink : 1;
	st->st_mtime = mtime; st->st_atime = atime; st->st_ctime = ctime;
}

/* returns 0 / -errno (ENOENT from the modem errno field) */
static int efs_stat(const char *path, struct stat *st)
{
	uint8_t rsp[RSP_MAX], pl[520];
	size_t pn = strlen(path) + 1;
	int r, e;

	memcpy(pl, path, pn);
	r = efs(EFS_STAT, pl, pn, rsp, sizeof(rsp));
	if (r < 4)
		return r < 0 ? r : -EIO;
	e = RD32(rsp + 4, 0);
	if (e)
		return -efs_err(e);
	if (r < 28)
		return -EIO;
	/* diag_errno, mode, size, nlink, atime, mtime, ctime */
	fill_stat(st, RD32(rsp + 4, 4), RD32(rsp + 4, 8), RD32(rsp + 4, 12),
		  RD32(rsp + 4, 20), RD32(rsp + 4, 16), RD32(rsp + 4, 24));
	return 0;
}

static int nv_item(const char *path)
{
	char *end;
	long v;

	if (strncmp(path, "/nv/", 4) || !path[4] || strchr(path + 4, '/'))
		return -1;
	v = strtol(path + 4, &end, 10);
	if (*end || v < 0 || v > 65535 || path[4] == '+' || path[4] == '-')
		return -1;
	return (int)v;
}

static int nv_read(int item, uint8_t *data)
{
	uint8_t req[133] = { 0x26 }, rsp[RSP_MAX];
	int r;
	unsigned st;

	req[1] = item & 0xff; req[2] = item >> 8;
	r = xfer(req, sizeof(req), 3, rsp, sizeof(rsp));
	if (r < 0)
		return r;
	if (r < 133)
		return -EIO;
	st = rsp[131] | rsp[132] << 8;
	if (st == 5 || st == 6)		/* NV_NOTACTIVE_S / NV_BADPARM_S */
		return -ENOENT;
	if (st)
		return -EIO;
	memcpy(data, rsp + 3, NV_SIZE);
	return NV_SIZE;
}

/*
 * Entries of the most recently listed directory (name, mode, size, times from
 * READDIR). getattr for them is answered from here, which saves one STAT
 * round trip per entry on `ls` and works for entries STAT rejects.
 */
#define CACHE_MAX 512
#define CACHE_TTL_S 3
struct cent { char name[128]; struct stat st; };
static struct { char dir[512]; long t; int n; struct cent *e; } cache;

static void cache_begin(const char *dir)
{
	if (!cache.e)
		cache.e = malloc(CACHE_MAX * sizeof(*cache.e));
	cache.n = 0;
	cache.t = 0;
	snprintf(cache.dir, sizeof(cache.dir), "%s", dir);
}

static void cache_add(const char *name, const struct stat *st)
{
	if (cache.e && cache.n < CACHE_MAX && strlen(name) < sizeof(cache.e[0].name)) {
		strcpy(cache.e[cache.n].name, name);
		cache.e[cache.n++].st = *st;
	}
}

static int cache_lookup(const char *path, struct stat *st)
{
	const char *name = strrchr(path, '/');
	char parent[512];

	if (!cache.e || !cache.t || !name || !name[1] || now_s() - cache.t > CACHE_TTL_S)
		return -1;
	snprintf(parent, sizeof(parent), "%.*s", name == path ? 1 : (int)(name - path), path);
	if (strcmp(parent, cache.dir))
		return -1;
	for (int i = 0; i < cache.n; i++)
		if (!strcmp(cache.e[i].name, name + 1)) {
			*st = cache.e[i].st;
			return 0;
		}
	return -1;
}

static int resolve(const char *path, struct stat *st)
{
	int r, nv;
	uint8_t d[NV_SIZE];

	if ((r = path_ok(path)))
		return r;
	if (!strcmp(path, "/")) {
		r = efs_stat("/", st);
		if (r == -ENOENT) {	/* be lenient: synthesize root */
			memset(st, 0, sizeof(*st));
			st->st_mode = S_IFDIR | 0500;
			st->st_nlink = 2;
			return 0;
		}
		return r;
	}
	if (cache_lookup(path, st) == 0)
		return 0;
	r = efs_stat(path, st);
	if (r == -EIO || r == -EACCES || r == -EPERM)
		fprintf(stderr, "efsfs: stat %s failed (%d)\n", path, r);
	if (r != -ENOENT || (nv = nv_item(path)) < 0)
		return r;
	if ((r = nv_read(nv, d)) < 0)
		return r;
	memset(st, 0, sizeof(*st));
	st->st_mode = S_IFREG | 0400;
	st->st_nlink = 1;
	st->st_size = NV_SIZE;
	return 0;
}

static long last_use;
static int idle_started;

/* release the DIAG endpoint when idle so modem_nv / msm-diag-bridge can use it */
static void *idle_thread(void *arg)
{
	(void)arg;
	for (;;) {
		sleep(1);
		pthread_mutex_lock(&diag_lock);
		if (dfd >= 0 && now_s() - last_use >= IDLE_CLOSE_S)
			diag_close();
		pthread_mutex_unlock(&diag_lock);
	}
	return NULL;
}

/* caller holds diag_lock */
static int diag_get(void)
{
	int r;

	if (now_s() < cooldown_until)
		return -EIO;
	if (dfd < 0) {
		if ((r = diag_open()))
			return r;
		if (!idle_started) {
			pthread_t t;

			if (!pthread_create(&t, NULL, idle_thread, NULL)) {
				pthread_detach(t);
				idle_started = 1;
			}
		}
	}
	return 0;
}

/* one exchange at a time across all FUSE threads; endpoint kept for IDLE_CLOSE_S */
#define WITH_DIAG(expr) ({ int _r; pthread_mutex_lock(&diag_lock); \
	if ((_r = diag_get()) == 0) { _r = (expr); last_use = now_s(); } \
	pthread_mutex_unlock(&diag_lock); _r; })

static int do_getattr(const char *p, struct stat *st) { return resolve(p, st); }

static int fs_getattr(const char *path, struct stat *st, struct fuse_file_info *fi)
{
	(void)fi;
	return WITH_DIAG(do_getattr(path, st));
}

struct rd { const char *path; void *buf; fuse_fill_dir_t fill; };

static int do_readdir(struct rd *a)
{
	uint8_t rsp[RSP_MAX], pl[520];
	size_t pn;
	uint32_t dirp;
	int r, e, seq;
	struct stat chk;

	if ((r = path_ok(a->path)))
		return r;
	if ((r = resolve(a->path, &chk)))
		return r;
	if (!S_ISDIR(chk.st_mode))
		return -ENOTDIR;
	pn = strlen(a->path) + 1;
	memcpy(pl, a->path, pn);
	r = efs(EFS_OPENDIR, pl, pn, rsp, sizeof(rsp));
	if (r < 8)
		return r < 0 ? r : -EIO;
	dirp = (uint32_t)RD32(rsp + 4, 0);
	e = RD32(rsp + 4, 4);
	if (!dirp)
		return -efs_err(e);
	cache_begin(a->path);
	a->fill(a->buf, ".", NULL, 0, 0);
	a->fill(a->buf, "..", NULL, 0, 0);
	r = 0;
	for (seq = 1; seq < 100000; seq++) {
		uint8_t q[8];
		struct stat st;
		char name[256];
		int n;

		WR32(q, 0, dirp); WR32(q, 4, seq);
		n = efs(EFS_READDIR, q, 8, rsp, sizeof(rsp));
		if (n < 36 + 1) { if (n < 0) r = n; break; }
		if (RD32(rsp + 4, 8) != 0)	/* errno set: end of dir */
			break;
		snprintf(name, sizeof(name), "%.*s", (int)(n - 36 > 255 ? 255 : n - 36),
			 (char *)rsp + 4 + 36);
		if (!name[0])
			break;
		if (!strcmp(name, ".") || !strcmp(name, ".."))
			continue;
		memset(&st, 0, sizeof(st));
		{
			/* entry_type: 0 file, 1 dir, 2 symlink (NOT an end marker) */
			int32_t m = RD32(rsp + 4, 16) & S_IFMT, t = RD32(rsp + 4, 12);

			if (m == S_IFDIR || (!m && t == 1))
				st.st_mode = S_IFDIR;
			else if (m == S_IFLNK || (!m && t == 2))
				st.st_mode = S_IFLNK;
			else
				st.st_mode = S_IFREG;
		}
		{
			struct stat cs;
			int32_t m = RD32(rsp + 4, 16);

			if (!(m & S_IFMT))
				m |= st.st_mode;
			fill_stat(&cs, m, RD32(rsp + 4, 20), 1, RD32(rsp + 4, 28),
				  RD32(rsp + 4, 24), RD32(rsp + 4, 32));
			cache_add(name, &cs);
		}
		if (a->fill(a->buf, name, &st, 0, 0))
			break;
	}
	if (!r && seq < 100000)
		cache.t = now_s();
	{
		uint8_t q[4];
		WR32(q, 0, dirp);
		efs(EFS_CLOSEDIR, q, 4, rsp, sizeof(rsp));
	}
	return r;
}

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t fill, off_t off,
		      struct fuse_file_info *fi, enum fuse_readdir_flags fl)
{
	struct rd a = { path, buf, fill };
	(void)off; (void)fi; (void)fl;
	return WITH_DIAG(do_readdir(&a));
}

static int fs_open(const char *path, struct fuse_file_info *fi)
{
	struct stat st;
	int r;

	if ((fi->flags & O_ACCMODE) != O_RDONLY || (fi->flags & (O_TRUNC | O_CREAT)))
		return -EROFS;
	if ((r = WITH_DIAG(do_getattr(path, &st))))
		return r;
	if (S_ISDIR(st.st_mode))
		return -EISDIR;
	fi->direct_io = 1;	/* sizes can be stale/unknown */
	return 0;
}

struct rb { const char *path; char *buf; size_t size; off_t off; };

static int do_read(struct rb *a)
{
	uint8_t rsp[RSP_MAX], pl[528];
	size_t pn = strlen(a->path) + 1, got = 0;
	int r, fd, e, nv;
	struct stat st;

	if ((r = path_ok(a->path)))
		return r;
	if ((r = efs_stat(a->path, &st)) == -ENOENT && (nv = nv_item(a->path)) >= 0) {
		uint8_t d[NV_SIZE];

		if ((r = nv_read(nv, d)) < 0)
			return r;
		if (a->off >= NV_SIZE)
			return 0;
		got = (size_t)(NV_SIZE - a->off) < a->size ? (size_t)(NV_SIZE - a->off) : a->size;
		memcpy(a->buf, d + a->off, got);
		return (int)got;
	}
	if (r < 0)
		return r;
	if (S_ISDIR(st.st_mode))
		return -EISDIR;
	WR32(pl, 0, 0); WR32(pl, 4, 0);		/* O_RDONLY, mode 0 */
	memcpy(pl + 8, a->path, pn);
	r = efs(EFS_OPEN, pl, 8 + pn, rsp, sizeof(rsp));
	if (r < 8)
		return r < 0 ? r : -EIO;
	fd = RD32(rsp + 4, 0);
	e = RD32(rsp + 4, 4);
	if (fd < 0)
		return -efs_err(e);
	r = 0;
	while (got < a->size) {
		uint8_t q[12];
		size_t want = a->size - got < EFS_CHUNK ? a->size - got : EFS_CHUNK;
		int n;

		WR32(q, 0, fd); WR32(q, 4, want); WR32(q, 8, (uint32_t)a->off + (uint32_t)got);
		n = efs(EFS_READ, q, 12, rsp, sizeof(rsp));
		if (n < 16) { r = n < 0 ? n : -EIO; break; }
		{
			int32_t cnt = RD32(rsp + 4, 8), er = RD32(rsp + 4, 12);

			if (cnt < 0) { r = -efs_err(er); break; }
			if (cnt == 0)
				break;
			if (cnt > n - 16 || (size_t)cnt > want)
				{ r = -EIO; break; }
			memcpy(a->buf + got, rsp + 4 + 16, cnt);
			got += cnt;
			if ((size_t)cnt < want)
				break;
		}
	}
	{
		uint8_t q[4];
		WR32(q, 0, fd);
		efs(EFS_CLOSE, q, 4, rsp, sizeof(rsp));
	}
	return r < 0 && !got ? r : (int)got;
}

static int fs_read(const char *path, char *buf, size_t size, off_t off,
		   struct fuse_file_info *fi)
{
	struct rb a = { path, buf, size, off };
	(void)fi;
	return WITH_DIAG(do_read(&a));
}

static int do_readlink(struct rb *a)
{
	uint8_t rsp[RSP_MAX], pl[520];
	size_t pn = strlen(a->path) + 1;
	int r, e;

	memcpy(pl, a->path, pn);
	r = efs(EFS_READLINK, pl, pn, rsp, sizeof(rsp));
	if (r < 4)
		return r < 0 ? r : -EIO;
	e = RD32(rsp + 4, 0);
	if (e)
		return -efs_err(e);
	snprintf(a->buf, a->size, "%.*s", r - 4, (char *)rsp + 8);
	return 0;
}

static int fs_readlink(const char *path, char *buf, size_t size)
{
	struct rb a = { path, buf, size, 0 };
	if (path_ok(path))
		return -ENAMETOOLONG;
	return WITH_DIAG(do_readlink(&a));
}

static const struct fuse_operations ops = {
	.getattr = fs_getattr,
	.readdir = fs_readdir,
	.open = fs_open,
	.read = fs_read,
	.readlink = fs_readlink,
};

enum { KEY_IGN, KEY_RW };

static const struct fuse_opt opts[] = {
	/* mount(8)/fstab leftovers that make no sense here */
	FUSE_OPT_KEY("-n", KEY_IGN),
	FUSE_OPT_KEY("-v", KEY_IGN),
	FUSE_OPT_KEY("nofail", KEY_IGN),
	FUSE_OPT_KEY("_netdev", KEY_IGN),
	FUSE_OPT_KEY("user", KEY_IGN),
	FUSE_OPT_KEY("nouser", KEY_IGN),
	FUSE_OPT_KEY("users", KEY_IGN),
	FUSE_OPT_KEY("rw", KEY_RW),
	FUSE_OPT_END
};

static char *nonopt[2];
static int nnonopt;

static int opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
	(void)data; (void)outargs;
	switch (key) {
	case KEY_IGN:
		return 0;
	case KEY_RW:
		fprintf(stderr, "efsfs: read-only filesystem, 'rw' is not supported\n");
		return -1;
	case FUSE_OPT_KEY_NONOPT:
		/* [source] mountpoint; the source (as in fstab/mount.fuse) is ignored */
		if (nnonopt >= 2) {
			fprintf(stderr, "efsfs: too many arguments\n");
			return -1;
		}
		nonopt[nnonopt++] = strdup(arg);
		return 0;
	}
	return 1;	/* keep for libfuse */
}

/*
 * Accepted forms:
 *   efsfs [fuse opts] <mountpoint>
 *   efsfs <source> <mountpoint> [-o opts]     (fstab / mount -t fuse.efsfs,
 *   mount.fuse.efsfs <source> <mountpoint> [-n] [-o opts]   via mount.fuse.efsfs)
 */
int main(int argc, char **argv)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_args out = FUSE_ARGS_INIT(0, NULL);
	int i, ret;

	if (fuse_opt_parse(&args, NULL, opts, opt_proc))
		return 1;
	/* argv[0] and user args kept by libfuse first, our forced options after so they win */
	for (i = 0; i < args.argc; i++)
		fuse_opt_add_arg(&out, i == 0 ? "efsfs" : args.argv[i]);
	/* read-only, single threaded (one DIAG request at a time) */
	fuse_opt_add_arg(&out, "-oro,fsname=efsfs,subtype=efsfs");
	fuse_opt_add_arg(&out, "-s");
	if (nnonopt)
		fuse_opt_add_arg(&out, nonopt[nnonopt - 1]);
	fuse_opt_free_args(&args);
	ret = fuse_main(out.argc, out.argv, &ops, NULL);
	fuse_opt_free_args(&out);
	return ret;
}
