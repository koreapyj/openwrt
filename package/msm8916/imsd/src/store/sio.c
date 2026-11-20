/* SPDX-License-Identifier: GPL-2.0-or-later */
/* File layer of the message store, see sio.h for the formats and the threading model. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sio.h"
#include "../util/log.h"

#define LOG_MAGIC	"IMSDLOG1"
#define STATE_MAGIC	"IMSDST01"
#define FILE_VERSION	1u
#define LOG_HDR		16u
#define REC_HDR		8u
#define REC_MAX		(256u * 1024)
#define ITEM_FIXED	50u
#define RT_ITEM		1
#define RT_PURGE	2
#define RT_DROP		3
#define STATE_DEV	128u
#define STATE_MAXDEV	64u
#define COMPACT_MIN	64u

struct sio_fault sio_fault;

struct wrec {
	uint64_t seq, off;
	uint32_t len;		/* record bytes including the 8 byte header */
	uint32_t body_len, body_crc;
};

struct sio {
	char dir[256], p_log[300], p_logn[300], p_state[300], p_statet[300], p_b[300];
	bool threaded, stop, started;
	pthread_t th;
	pthread_mutex_t mu;
	pthread_cond_t cv;
	struct sio_req *qh, *qt;
	unsigned qn, qmax;
	struct sio_req *ch, *ct;
	unsigned outstanding;
	int efd;
	struct sio_stats st;
	/* owned by the writer */
	int logfd;
	uint64_t log_end;
	unsigned nrec_log;
	struct wrec *map;
	unsigned nmap, capmap;
	uint64_t reserved;
	struct sio_dev *devs;
	unsigned ndev;
	bool poisoned;
};

/* ------------------------------------------------------------------ */
/* small helpers                                                       */

static pthread_once_t crc_once = PTHREAD_ONCE_INIT;
static uint32_t crc_tab[256];

static void crc_init(void)
{
	uint32_t i, k, c;

	for (i = 0; i < 256; i++) {
		c = i;
		for (k = 0; k < 8; k++)
			c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
		crc_tab[i] = c;
	}
}

uint32_t sio_crc32(const void *p, size_t n)
{
	const uint8_t *b = p;
	uint32_t c = 0xffffffffu;
	size_t i;

	pthread_once(&crc_once, crc_init);
	for (i = 0; i < n; i++)
		c = crc_tab[(c ^ b[i]) & 0xff] ^ (c >> 8);
	return c ^ 0xffffffffu;
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
	int i;

	for (i = 0; i < 4; i++)
		p[i] = (uint8_t)(v >> (8 * i));
}

static void put64(uint8_t *p, uint64_t v)
{
	int i;

	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (8 * i));
}

static uint16_t get16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t get32(const uint8_t *p)
{
	uint32_t v = 0;
	int i;

	for (i = 3; i >= 0; i--)
		v = (v << 8) | p[i];
	return v;
}

static uint64_t get64(const uint8_t *p)
{
	uint64_t v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = (v << 8) | p[i];
	return v;
}

/* test hook: errno to fail with at this point, 0 for none */
static int fault_at(unsigned point)
{
	int e = 0;

	if (!(sio_fault.points & point) || !sio_fault.count)
		return 0;
	e = sio_fault.err ? sio_fault.err : EIO;
	if (sio_fault.count > 0)
		sio_fault.count--;
	return e;
}

static int write_full(int fd, const void *b, size_t n, uint64_t off)
{
	const uint8_t *p = b;

	while (n) {
		ssize_t w = pwrite(fd, p, n, (off_t)off);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (w == 0)
			return -EIO;
		p += w;
		off += (uint64_t)w;
		n -= (size_t)w;
	}
	return 0;
}

static int read_full(int fd, void *b, size_t n, uint64_t off)
{
	uint8_t *p = b;

	while (n) {
		ssize_t r = pread(fd, p, n, (off_t)off);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (r == 0)
			return -EIO;
		p += r;
		off += (uint64_t)r;
		n -= (size_t)r;
	}
	return 0;
}

static int fsync_dir(const char *path)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	int rc = 0;

	if (fd < 0)
		return -errno;
	if (fsync(fd))
		rc = -errno;
	close(fd);
	return rc;
}

static void body_path(const struct sio *s, uint64_t seq, char *out, size_t n)
{
	snprintf(out, n, "%s/%016llx", s->p_b, (unsigned long long)seq);
}

/* ------------------------------------------------------------------ */
/* map of the live records (writer thread)                             */

static struct wrec *map_find(struct sio *s, uint64_t seq)
{
	unsigned lo = 0, hi = s->nmap;

	while (lo < hi) {
		unsigned mid = (lo + hi) / 2;

		if (s->map[mid].seq < seq)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo < s->nmap && s->map[lo].seq == seq ? &s->map[lo] : NULL;
}

static int map_add(struct sio *s, const struct wrec *w)
{
	if (s->nmap == s->capmap) {
		unsigned nc = s->capmap ? s->capmap * 2 : 256;
		struct wrec *nm = realloc(s->map, nc * sizeof(*nm));

		if (!nm)
			return -ENOMEM;
		s->map = nm;
		s->capmap = nc;
	}
	s->map[s->nmap++] = *w;
	return 0;
}

static void map_del_at(struct sio *s, unsigned i)
{
	memmove(&s->map[i], &s->map[i + 1], (s->nmap - i - 1) * sizeof(s->map[0]));
	s->nmap--;
}

/* ------------------------------------------------------------------ */
/* records                                                             */

static size_t item_encode(const struct sio_entry *e, const uint8_t *meta, uint8_t *out)
{
	size_t pl = strlen(e->peer), o = ITEM_FIXED, i;

	if (pl > SIO_PEER_MAX - 1)
		pl = SIO_PEER_MAX - 1;
	out[0] = RT_ITEM;
	out[1] = e->type;
	out[2] = e->flags;
	out[3] = e->nexcl;
	put64(out + 4, e->seq);
	put64(out + 12, (uint64_t)e->time);
	put64(out + 20, e->dedup);
	put64(out + 28, e->lookup);
	put32(out + 36, e->meta_len);
	put32(out + 40, e->body_len);
	put32(out + 44, e->body_crc);
	put16(out + 48, (uint16_t)pl);
	for (i = 0; i < e->nexcl; i++, o += 8)
		put64(out + o, e->excl[i]);
	memcpy(out + o, e->peer, pl);
	o += pl;
	if (e->meta_len)
		memcpy(out + o, meta, e->meta_len);
	return o + e->meta_len;
}

/* parse an ITEM payload; *meta points into p. 0 / -EBADMSG */
static int item_parse(const uint8_t *p, size_t n, struct sio_entry *e, const uint8_t **meta)
{
	size_t pl, o, i;

	if (n < ITEM_FIXED || p[0] != RT_ITEM)
		return -EBADMSG;
	memset(e, 0, sizeof(*e));
	e->type = p[1];
	e->flags = p[2];
	e->nexcl = p[3];
	e->seq = get64(p + 4);
	e->time = (int64_t)get64(p + 12);
	e->dedup = get64(p + 20);
	e->lookup = get64(p + 28);
	e->meta_len = get32(p + 36);
	e->body_len = get32(p + 40);
	e->body_crc = get32(p + 44);
	pl = get16(p + 48);
	if (e->nexcl > SIO_EXCL_MAX || pl >= SIO_PEER_MAX || e->meta_len > SIO_META_MAX || e->body_len > SIO_BODY_MAX)
		return -EBADMSG;
	o = ITEM_FIXED + (size_t)e->nexcl * 8;
	if (o + pl + e->meta_len != n)
		return -EBADMSG;
	for (i = 0; i < e->nexcl; i++)
		e->excl[i] = get64(p + ITEM_FIXED + i * 8);
	memcpy(e->peer, p + o, pl);
	e->peer[pl] = 0;
	*meta = p + o + pl;
	return 0;
}

/* append one record (header + payload) at log_end, fdatasync. On failure the file is cut back to log_end. */
static int log_append(struct sio *s, const uint8_t *payload, size_t n, uint32_t *total)
{
	uint8_t *b = malloc(REC_HDR + n);
	int rc, e;

	if (!b)
		return -ENOMEM;
	put32(b, (uint32_t)n);
	put32(b + 4, sio_crc32(payload, n));
	memcpy(b + REC_HDR, payload, n);
	if (s->poisoned) {
		if (ftruncate(s->logfd, (off_t)s->log_end)) {
			free(b);
			return -errno;
		}
		s->poisoned = false;
	}
	e = fault_at(SIO_FP_LOGWRITE);
	if (e) {
		write_full(s->logfd, b, (REC_HDR + n) / 2, s->log_end);	/* a half record, as a full disk leaves it */
		rc = -e;
	} else {
		rc = write_full(s->logfd, b, REC_HDR + n, s->log_end);
	}
	free(b);
	if (!rc) {
		e = fault_at(SIO_FP_LOGSYNC);
		if (e)
			rc = -e;
		else if (fdatasync(s->logfd))
			rc = -errno;
	}
	if (rc) {
		if (ftruncate(s->logfd, (off_t)s->log_end))
			s->poisoned = true;
		return rc;
	}
	s->log_end += REC_HDR + n;
	s->nrec_log++;
	if (total)
		*total = (uint32_t)(REC_HDR + n);
	return 0;
}

/* ------------------------------------------------------------------ */
/* state file                                                          */

static int state_write(struct sio *s, uint64_t reserved, const struct sio_dev *devs, unsigned ndev)
{
	size_t n, o = 24, i;
	uint8_t *b;
	int fd, rc = 0, e;

	if (ndev > STATE_MAXDEV)
		ndev = STATE_MAXDEV;
	n = 24 + (size_t)ndev * STATE_DEV + 4;
	b = calloc(1, n);
	if (!b)
		return -ENOMEM;
	memcpy(b, STATE_MAGIC, 8);
	put32(b + 8, FILE_VERSION);
	put32(b + 12, ndev);
	put64(b + 16, reserved);
	for (i = 0; i < ndev; i++, o += STATE_DEV) {
		memcpy(b + o, devs[i].id, SIO_DEVID_MAX);
		b[o + SIO_DEVID_MAX - 1] = 0;
		put64(b + o + 96, devs[i].cursor);
		put64(b + o + 104, devs[i].reported);
		put32(b + o + 112, devs[i].flags);
		put64(b + o + 120, (uint64_t)devs[i].last_seen);
	}
	put32(b + o, sio_crc32(b, o));
	e = fault_at(SIO_FP_STATE);
	if (e) {
		free(b);
		return -e;
	}
	fd = open(s->p_statet, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		free(b);
		return -errno;
	}
	rc = write_full(fd, b, n, 0);
	if (!rc && fsync(fd))
		rc = -errno;
	close(fd);
	free(b);
	if (!rc && rename(s->p_statet, s->p_state))
		rc = -errno;
	if (!rc)
		rc = fsync_dir(s->dir);
	if (rc) {
		unlink(s->p_statet);
		return rc;
	}
	s->reserved = reserved;
	return 0;
}

/* 0, -ENOENT, -EBADMSG */
static int state_read(struct sio *s, uint64_t *reserved, struct sio_dev **devs, unsigned *ndev)
{
	struct stat st;
	uint8_t *b;
	int fd, rc;
	unsigned i, nd;
	size_t o;

	*devs = NULL;
	*ndev = 0;
	*reserved = 0;
	fd = open(s->p_state, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? -ENOENT : -errno;
	if (fstat(fd, &st) || st.st_size < 28 || st.st_size > (off_t)(28 + STATE_MAXDEV * STATE_DEV)) {
		close(fd);
		return -EBADMSG;
	}
	b = malloc((size_t)st.st_size);
	if (!b) {
		close(fd);
		return -ENOMEM;
	}
	rc = read_full(fd, b, (size_t)st.st_size, 0);
	close(fd);
	if (rc)
		goto bad;
	rc = -EBADMSG;
	if (memcmp(b, STATE_MAGIC, 8) || get32(b + 8) != FILE_VERSION)
		goto bad;
	nd = get32(b + 12);
	if (nd > STATE_MAXDEV || (size_t)st.st_size != 24 + (size_t)nd * STATE_DEV + 4)
		goto bad;
	o = 24 + (size_t)nd * STATE_DEV;
	if (get32(b + o) != sio_crc32(b, o))
		goto bad;
	*reserved = get64(b + 16);
	if (nd) {
		*devs = calloc(nd, sizeof(**devs));
		if (!*devs) {
			rc = -ENOMEM;
			goto bad;
		}
	}
	for (i = 0; i < nd; i++) {
		const uint8_t *p = b + 24 + (size_t)i * STATE_DEV;

		memcpy((*devs)[i].id, p, SIO_DEVID_MAX);
		(*devs)[i].id[SIO_DEVID_MAX - 1] = 0;
		(*devs)[i].cursor = get64(p + 96);
		(*devs)[i].reported = get64(p + 104);
		(*devs)[i].flags = get32(p + 112);
		(*devs)[i].last_seen = (int64_t)get64(p + 120);
	}
	*ndev = nd;
	free(b);
	return 0;
bad:
	free(b);
	return rc;
}

/* ------------------------------------------------------------------ */
/* compaction                                                          */

/* Copy the live records to log.new, fsync, rename over log, fsync the directory. Steps 1..5, see sio_fault.kill_step. */
static int compact(struct sio *s)
{
	struct wrec *nm = NULL;
	uint8_t hdr[LOG_HDR];
	uint8_t *buf = NULL;
	size_t bcap = 0;
	uint64_t pos = LOG_HDR;
	unsigned i;
	int fd, rc = 0, e;
	const int kill = sio_fault.kill_step;

	nm = calloc(s->nmap ? s->nmap : 1, sizeof(*nm));
	if (!nm)
		return -ENOMEM;
	fd = open(s->p_logn, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		free(nm);
		return -errno;
	}
	memcpy(hdr, LOG_MAGIC, 8);
	put32(hdr + 8, FILE_VERSION);
	put32(hdr + 12, 0);
	rc = write_full(fd, hdr, LOG_HDR, 0);
	if (rc)
		goto fail;
	if (kill == 1) {
		close(fd);
		free(nm);
		return -ECANCELED;
	}
	for (i = 0; i < s->nmap; i++) {
		const struct wrec *w = &s->map[i];

		if (w->len > bcap) {
			uint8_t *nb = realloc(buf, w->len);

			if (!nb) {
				rc = -ENOMEM;
				goto fail;
			}
			buf = nb;
			bcap = w->len;
		}
		e = fault_at(SIO_FP_COMPACT);
		if (e) {
			rc = -e;
			goto fail;
		}
		rc = read_full(s->logfd, buf, w->len, w->off);
		if (!rc)
			rc = write_full(fd, buf, w->len, pos);
		if (rc)
			goto fail;
		nm[i] = *w;
		nm[i].off = pos;
		pos += w->len;
	}
	if (kill == 2) {
		close(fd);
		free(nm);
		free(buf);
		return -ECANCELED;
	}
	if (fsync(fd)) {
		rc = -errno;
		goto fail;
	}
	if (kill == 3) {
		close(fd);
		free(nm);
		free(buf);
		return -ECANCELED;
	}
	if (rename(s->p_logn, s->p_log)) {
		rc = -errno;
		goto fail;
	}
	if (kill == 4) {
		close(fd);
		free(nm);
		free(buf);
		return -ECANCELED;
	}
	fsync_dir(s->dir);		/* the rename is already atomic; this only makes it durable */
	if (kill == 5) {
		close(fd);
		free(nm);
		free(buf);
		return -ECANCELED;
	}
	close(s->logfd);
	s->logfd = fd;
	free(s->map);
	s->map = nm;
	s->capmap = s->nmap ? s->nmap : 1;
	s->log_end = pos;
	s->nrec_log = s->nmap;
	s->poisoned = false;
	free(buf);
	s->st.compactions++;
	return 0;
fail:
	close(fd);
	unlink(s->p_logn);
	free(nm);
	free(buf);
	return rc;
}

static void maybe_compact(struct sio *s)
{
	unsigned dead = s->nrec_log > s->nmap ? s->nrec_log - s->nmap : 0;

	if (dead >= COMPACT_MIN && dead >= s->nmap) {
		int rc = compact(s);

		if (rc && rc != -ECANCELED)
			LOGW("store: compaction failed (%s), the old log stays in use", strerror(-rc));
	}
}

/* ------------------------------------------------------------------ */
/* the operations                                                      */

struct u64v {
	uint64_t *v;
	unsigned n, cap;
};

static int u64v_add(struct u64v *a, uint64_t x)
{
	if (a->n == a->cap) {
		unsigned nc = a->cap ? a->cap * 2 : 16;
		uint64_t *nv = realloc(a->v, nc * sizeof(*nv));

		if (!nv)
			return -ENOMEM;
		a->v = nv;
		a->cap = nc;
	}
	a->v[a->n++] = x;
	return 0;
}

static void remove_orphans(struct sio *s, struct sio_load *L)
{
	DIR *d = opendir(s->p_b);
	struct dirent *de;

	if (!d)
		return;
	while ((de = readdir(d))) {
		char *end;
		unsigned long long v;
		char p[400];

		if (de->d_name[0] == '.')
			continue;
		v = strtoull(de->d_name, &end, 16);
		if (*end || strlen(de->d_name) != 16 || map_find(s, v))
			continue;
		snprintf(p, sizeof(p), "%s/%.16s", s->p_b, de->d_name);
		if (!unlink(p))
			L->orphans++;
	}
	closedir(d);
}

static int do_load(struct sio *s, struct sio_load *L)
{
	struct stat st;
	uint8_t hdr[LOG_HDR];
	uint8_t *rec = NULL;
	size_t rcap = 0;
	uint64_t off, maxseq = 0, last = 0, keep_from = 0, st_reserved = 0;
	struct u64v drops = { 0 };
	struct sio_dev *devs = NULL;
	unsigned nd = 0, i, j;
	int rc, srcrc;
	bool fresh = false;

	/* a repeated load (the directory was not there the first time): start from nothing */
	if (s->logfd >= 0) {
		close(s->logfd);
		s->logfd = -1;
	}
	s->nmap = 0;
	s->nrec_log = 0;
	s->log_end = 0;
	free(s->devs);
	s->devs = NULL;
	s->ndev = 0;
	mkdir(s->dir, 0700);
	mkdir(s->p_b, 0700);
	unlink(s->p_logn);
	unlink(s->p_statet);

	srcrc = state_read(s, &st_reserved, &devs, &nd);
	if (srcrc == -EBADMSG) {
		LOGE("store: the state file is damaged: the device cursors are lost");
		L->state_bad = true;
	}
	s->logfd = open(s->p_log, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (s->logfd < 0) {
		rc = -errno;
		goto out;
	}
	if (fstat(s->logfd, &st)) {
		rc = -errno;
		goto out;
	}
	if (st.st_size < (off_t)LOG_HDR) {
		fresh = true;
		if (st.st_size)
			L->torn++;
	} else if (read_full(s->logfd, hdr, LOG_HDR, 0) || memcmp(hdr, LOG_MAGIC, 8) || get32(hdr + 8) != FILE_VERSION) {
		char bad[320];

		LOGE("store: %s has a bad header, set aside as log.bad", s->p_log);
		snprintf(bad, sizeof(bad), "%s.bad", s->p_log);
		close(s->logfd);
		rename(s->p_log, bad);
		s->logfd = open(s->p_log, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		if (s->logfd < 0) {
			rc = -errno;
			goto out;
		}
		L->log_reset = true;
		fresh = true;
	}
	if (fresh) {
		memcpy(hdr, LOG_MAGIC, 8);
		put32(hdr + 8, FILE_VERSION);
		put32(hdr + 12, 0);
		if (ftruncate(s->logfd, 0)) {
			rc = -errno;
			goto out;
		}
		rc = write_full(s->logfd, hdr, LOG_HDR, 0);
		if (!rc && fsync(s->logfd))
			rc = -errno;
		if (rc)
			goto out;
		st.st_size = LOG_HDR;
	}
	/* scan */
	off = LOG_HDR;
	for (;;) {
		uint8_t rh[REC_HDR];
		uint32_t len;
		struct sio_entry e;
		const uint8_t *meta;
		struct wrec w;

		if ((uint64_t)st.st_size < off + REC_HDR)
			break;
		if (read_full(s->logfd, rh, REC_HDR, off))
			break;
		len = get32(rh);
		if (len < 1 || len > REC_MAX || (uint64_t)st.st_size < off + REC_HDR + len)
			break;
		if (len + REC_HDR > rcap) {
			uint8_t *nb = realloc(rec, len + REC_HDR);

			if (!nb) {
				rc = -ENOMEM;
				goto out;
			}
			rec = nb;
			rcap = len + REC_HDR;
		}
		if (read_full(s->logfd, rec, len + REC_HDR, off))
			break;
		if (sio_crc32(rec + REC_HDR, len) != get32(rec + 4))
			break;
		if (rec[REC_HDR] == RT_ITEM) {
			if (item_parse(rec + REC_HDR, len, &e, &meta) || e.seq <= last)
				break;
			last = e.seq;
			if (e.seq > maxseq)
				maxseq = e.seq;
			w.seq = e.seq;
			w.off = off;
			w.len = len + REC_HDR;
			w.body_len = e.body_len;
			w.body_crc = e.body_crc;
			if ((rc = map_add(s, &w)))
				goto out;
		} else if (rec[REC_HDR] == RT_PURGE && len == 9) {
			uint64_t k = get64(rec + REC_HDR + 1);

			if (k > keep_from)
				keep_from = k;
		} else if (rec[REC_HDR] == RT_DROP && len == 9) {
			if ((rc = u64v_add(&drops, get64(rec + REC_HDR + 1))))
				goto out;
		} else {
			break;
		}
		s->nrec_log++;
		off += REC_HDR + len;
	}
	if (off < (uint64_t)st.st_size) {
		LOGW("store: torn or damaged record at offset %llu: the log is cut there (%llu bytes dropped)", (unsigned long long)off,
		     (unsigned long long)((uint64_t)st.st_size - off));
		L->torn++;
		if (ftruncate(s->logfd, (off_t)off) || fsync(s->logfd)) {
			rc = -errno;
			goto out;
		}
	}
	s->log_end = off;
	/* purge and drop marks */
	for (i = 0, j = 0; i < s->nmap; i++) {
		bool gone = s->map[i].seq < keep_from;
		unsigned k;

		for (k = 0; k < drops.n && !gone; k++)
			gone = drops.v[k] == s->map[i].seq;
		if (!gone)
			s->map[j++] = s->map[i];
	}
	s->nmap = j;
	/* bodies: the file must be there and as long as the record says */
	for (i = 0, j = 0; i < s->nmap; i++) {
		char p[400];

		if (s->map[i].body_len) {
			body_path(s, s->map[i].seq, p, sizeof(p));
			if (stat(p, &st) || (uint64_t)st.st_size != s->map[i].body_len) {
				LOGW("store: item %llu lost its body file, dropped", (unsigned long long)s->map[i].seq);
				L->bodies_missing++;
				continue;
			}
		}
		s->map[j++] = s->map[i];
	}
	s->nmap = j;
	remove_orphans(s, L);
	/* the entries for the index, read once more from the log (the map has no payload) */
	L->ent = calloc(s->nmap ? s->nmap : 1, sizeof(*L->ent));
	if (!L->ent) {
		rc = -ENOMEM;
		goto out;
	}
	for (i = 0; i < s->nmap; i++) {
		const uint8_t *meta;
		const struct wrec *w = &s->map[i];

		if (w->len > rcap) {
			uint8_t *nb = realloc(rec, w->len);

			if (!nb) {
				rc = -ENOMEM;
				goto out;
			}
			rec = nb;
			rcap = w->len;
		}
		if (read_full(s->logfd, rec, w->len, w->off) || item_parse(rec + REC_HDR, w->len - REC_HDR, &L->ent[L->n], &meta)) {
			rc = -EIO;
			goto out;
		}
		L->n++;
	}
	/* the counter: never reuse a number */
	L->next_seq = st_reserved > maxseq + 1 ? st_reserved : maxseq + 1;
	if (L->next_seq < 1)
		L->next_seq = 1;
	s->devs = devs;
	s->ndev = nd;
	devs = NULL;
	L->dev = s->devs ? calloc(s->ndev, sizeof(*L->dev)) : NULL;
	if (L->dev)
		memcpy(L->dev, s->devs, s->ndev * sizeof(*L->dev));
	L->ndev = L->dev ? s->ndev : 0;
	L->log_bytes = s->log_end;
	s->reserved = L->next_seq;
	rc = state_write(s, L->next_seq + SIO_RESERVE, s->devs, s->ndev);
	maybe_compact(s);
	L->log_bytes = s->log_end;
	free(drops.v);
	free(rec);
	return rc;
out:
	free(drops.v);
	free(rec);
	free(devs);
	return rc;
}

static int do_append(struct sio *s, struct sio_req *r)
{
	uint8_t *pl;
	struct sio_entry *e = &r->ent;
	struct wrec w;
	char p[400];
	size_t n;
	uint32_t total = 0;
	int rc;

	if (s->logfd < 0)
		return -EIO;
	if (e->nexcl > SIO_EXCL_MAX)
		e->nexcl = SIO_EXCL_MAX;
	if (r->meta_len > SIO_META_MAX || r->body_len > SIO_BODY_MAX)
		return -EFBIG;
	if (e->seq >= s->reserved) {
		rc = state_write(s, e->seq + SIO_RESERVE, s->devs, s->ndev);
		if (rc)
			return rc;
	}
	e->meta_len = (uint32_t)r->meta_len;
	e->body_len = (uint32_t)r->body_len;
	e->body_crc = r->body_len ? sio_crc32(r->body, r->body_len) : 0;
	if (r->body_len) {
		int fd, fe;

		body_path(s, e->seq, p, sizeof(p));
		unlink(p);
		fe = fault_at(SIO_FP_BODY);
		if (fe)
			return -fe;
		fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
		if (fd < 0)
			return -errno;
		rc = write_full(fd, r->body, r->body_len, 0);
		if (!rc && fsync(fd))
			rc = -errno;
		close(fd);
		if (!rc)
			rc = fsync_dir(s->p_b);
		if (rc) {
			unlink(p);
			return rc;
		}
	}
	pl = malloc(ITEM_FIXED + SIO_EXCL_MAX * 8 + SIO_PEER_MAX + r->meta_len);
	if (!pl) {
		rc = -ENOMEM;
		goto undo;
	}
	n = item_encode(e, r->meta, pl);
	w.off = s->log_end;
	rc = log_append(s, pl, n, &total);
	free(pl);
	if (rc)
		goto undo;
	w.seq = e->seq;
	w.len = total;
	w.body_len = e->body_len;
	w.body_crc = e->body_crc;
	if (map_add(s, &w)) {		/* out of memory: the record is on disk and will be there at the next load */
		return -ENOMEM;
	}
	s->st.appends++;
	return 0;
undo:
	if (r->body_len) {
		body_path(s, e->seq, p, sizeof(p));
		unlink(p);
	}
	return rc;
}

static int do_read(struct sio *s, struct sio_req *r)
{
	struct wrec *w = map_find(s, r->ent.seq);
	uint8_t *buf;
	struct sio_entry e;
	const uint8_t *meta;
	int rc, fe;

	if (!w)
		return -ENOENT;
	fe = fault_at(SIO_FP_READ);
	if (fe)
		return -fe;
	buf = malloc(w->len);
	if (!buf)
		return -ENOMEM;
	rc = read_full(s->logfd, buf, w->len, w->off);
	if (rc) {
		free(buf);
		return rc;
	}
	if (get32(buf) + REC_HDR != w->len || sio_crc32(buf + REC_HDR, w->len - REC_HDR) != get32(buf + 4) ||
	    item_parse(buf + REC_HDR, w->len - REC_HDR, &e, &meta)) {
		free(buf);
		return -EBADMSG;
	}
	r->ent = e;
	r->meta = malloc(e.meta_len ? e.meta_len : 1);
	if (!r->meta) {
		free(buf);
		return -ENOMEM;
	}
	memcpy(r->meta, meta, e.meta_len);
	r->meta_len = e.meta_len;
	free(buf);
	if (r->want_body && w->body_len) {
		char p[400];
		int fd;

		body_path(s, r->ent.seq, p, sizeof(p));
		fd = open(p, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			return -errno;
		r->body = malloc(w->body_len);
		if (!r->body) {
			close(fd);
			return -ENOMEM;
		}
		rc = read_full(fd, r->body, w->body_len, 0);
		close(fd);
		if (rc)
			return rc;
		if (sio_crc32(r->body, w->body_len) != w->body_crc)
			return -EBADMSG;
		r->body_len = w->body_len;
	}
	return 0;
}

static int do_evict(struct sio *s, struct sio_req *r)
{
	uint64_t keep = r->ent.seq;
	unsigned n = 0, i;
	int rc = 0;

	while (n < s->nmap && s->map[n].seq < keep)
		n++;
	for (i = 0; i < n; i++)
		if (s->map[i].body_len) {
			char p[400];

			body_path(s, s->map[i].seq, p, sizeof(p));
			unlink(p);
		}
	if (n) {
		memmove(s->map, s->map + n, (s->nmap - n) * sizeof(s->map[0]));
		s->nmap -= n;
	}
	if (r->persist && s->logfd >= 0) {
		uint8_t pl[9];

		pl[0] = RT_PURGE;
		put64(pl + 1, keep);
		rc = log_append(s, pl, sizeof(pl), NULL);
	}
	if (s->logfd >= 0)
		maybe_compact(s);
	return rc;
}

static int do_drop(struct sio *s, struct sio_req *r)
{
	struct wrec *w = map_find(s, r->ent.seq);
	uint8_t pl[9];
	int rc;

	if (!w)
		return 0;
	if (w->body_len) {
		char p[400];

		body_path(s, w->seq, p, sizeof(p));
		unlink(p);
	}
	map_del_at(s, (unsigned)(w - s->map));
	pl[0] = RT_DROP;
	put64(pl + 1, r->ent.seq);
	rc = log_append(s, pl, sizeof(pl), NULL);
	maybe_compact(s);
	return rc;
}

static int do_state(struct sio *s, struct sio_req *r)
{
	free(s->devs);
	s->devs = r->devs;
	s->ndev = r->ndev;
	r->devs = NULL;
	r->ndev = 0;
	return state_write(s, s->reserved, s->devs, s->ndev);
}

static int do_probe(struct sio *s)
{
	if (s->logfd < 0)
		return -EIO;
	if (ftruncate(s->logfd, (off_t)s->log_end))
		return -errno;
	s->poisoned = false;
	return state_write(s, s->reserved, s->devs, s->ndev);
}

static int blob_path(const struct sio_req *r, const char *dir, const char *suffix, char *out, size_t n)
{
	size_t i, l = strnlen(r->name, sizeof(r->name));

	if (!l || l >= sizeof(r->name) - 5)
		return -EINVAL;
	for (i = 0; i < l; i++) {
		char ch = r->name[i];

		if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-'))
			return -EINVAL;
	}
	if (r->name[0] == '.')
		return -EINVAL;
	return snprintf(out, n, "%s/%.*s%s", dir, (int)l, r->name, suffix) >= (int)n ? -ENAMETOOLONG : 0;
}

static int do_blob_put(struct sio *s, struct sio_req *r)
{
	char p[320], pt[330];
	int fd, rc = blob_path(r, s->dir, "", p, sizeof(p));

	if (rc)
		return rc;
	if (!r->body || r->body_len > SIO_BLOB_MAX)
		return -EINVAL;
	if (blob_path(r, s->dir, ".tmp", pt, sizeof(pt)))
		return -ENAMETOOLONG;
	rc = fault_at(SIO_FP_STATE);
	if (rc)
		return -rc;
	fd = open(pt, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	rc = write_full(fd, r->body, r->body_len, 0);
	if (!rc && fsync(fd))
		rc = -errno;
	close(fd);
	if (!rc && rename(pt, p))
		rc = -errno;
	if (!rc)
		rc = fsync_dir(s->dir);
	if (rc)
		unlink(pt);
	return rc;
}

static int do_blob_get(struct sio *s, struct sio_req *r)
{
	char p[320];
	struct stat st;
	int fd, rc = blob_path(r, s->dir, "", p, sizeof(p));

	if (rc)
		return rc;
	fd = open(p, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) || st.st_size < 0 || (uint64_t)st.st_size > SIO_BLOB_MAX) {
		close(fd);
		return -EBADMSG;
	}
	r->body = malloc(st.st_size ? (size_t)st.st_size : 1);
	if (!r->body) {
		close(fd);
		return -ENOMEM;
	}
	r->body_len = (size_t)st.st_size;
	rc = read_full(fd, r->body, r->body_len, 0);
	close(fd);
	if (rc) {
		free(r->body);
		r->body = NULL;
		r->body_len = 0;
	}
	return rc;
}

static void exec_req(struct sio *s, struct sio_req *r)
{
	if (sio_fault.stall_ms)
		usleep(sio_fault.stall_ms * 1000u);
	switch (r->op) {
	case SIO_LOAD:
		r->load = calloc(1, sizeof(*r->load));
		r->err = r->load ? do_load(s, r->load) : -ENOMEM;
		break;
	case SIO_APPEND:
		r->err = do_append(s, r);
		break;
	case SIO_STATE:
		r->err = do_state(s, r);
		break;
	case SIO_READ:
		r->err = do_read(s, r);
		break;
	case SIO_EVICT:
		r->err = do_evict(s, r);
		break;
	case SIO_DROP:
		r->err = do_drop(s, r);
		break;
	case SIO_PROBE:
		r->err = do_probe(s);
		break;
	case SIO_BLOB_PUT:
		r->err = do_blob_put(s, r);
		break;
	case SIO_BLOB_GET:
		r->err = do_blob_get(s, r);
		break;
	default:
		r->err = -EINVAL;
	}
	pthread_mutex_lock(&s->mu);
	if (r->err && r->err != -ENOENT)
		s->st.errors++;
	s->st.log_bytes = s->log_end;
	s->st.live = s->nmap;
	s->st.dead = s->nrec_log > s->nmap ? s->nrec_log - s->nmap : 0;
	pthread_mutex_unlock(&s->mu);
}

/* ------------------------------------------------------------------ */
/* requests, queue, thread                                             */

struct sio_req *sio_req_new(enum sio_op op)
{
	struct sio_req *r = calloc(1, sizeof(*r));

	if (r)
		r->op = op;
	return r;
}

void sio_req_free(struct sio_req *r)
{
	if (!r)
		return;
	free(r->meta);
	free(r->body);
	free(r->devs);
	if (r->load) {
		free(r->load->ent);
		free(r->load->dev);
		free(r->load);
	}
	free(r);
}

static void complete(struct sio *s, struct sio_req *r)
{
	r->next = NULL;
	pthread_mutex_lock(&s->mu);
	if (s->ct)
		s->ct->next = r;
	else
		s->ch = r;
	s->ct = r;
	pthread_mutex_unlock(&s->mu);
	if (s->efd >= 0) {
		uint64_t one = 1;

		if (write(s->efd, &one, sizeof(one)) < 0) { /* counter full: the reader wakes anyway */ }
	}
}

static void *writer_main(void *arg)
{
	struct sio *s = arg;

	pthread_mutex_lock(&s->mu);
	for (;;) {
		struct sio_req *r;

		while (!s->qh && !s->stop)
			pthread_cond_wait(&s->cv, &s->mu);
		if (!s->qh)
			break;			/* stop requested and everything queued is done */
		r = s->qh;
		s->qh = r->next;
		if (!s->qh)
			s->qt = NULL;
		s->qn--;
		pthread_mutex_unlock(&s->mu);
		exec_req(s, r);
		complete(s, r);
		pthread_mutex_lock(&s->mu);
	}
	pthread_mutex_unlock(&s->mu);
	return NULL;
}

struct sio *sio_open(const char *dir, bool threaded, unsigned qmax)
{
	struct sio *s;

	if (!dir || strlen(dir) > 200)
		return NULL;
	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;
	snprintf(s->dir, sizeof(s->dir), "%s", dir);
	snprintf(s->p_log, sizeof(s->p_log), "%s/log", dir);
	snprintf(s->p_logn, sizeof(s->p_logn), "%s/log.new", dir);
	snprintf(s->p_state, sizeof(s->p_state), "%s/state", dir);
	snprintf(s->p_statet, sizeof(s->p_statet), "%s/state.tmp", dir);
	snprintf(s->p_b, sizeof(s->p_b), "%s/b", dir);
	s->qmax = qmax ? qmax : 32;
	s->logfd = -1;
	s->efd = -1;
	s->threaded = threaded;
	pthread_mutex_init(&s->mu, NULL);
	pthread_cond_init(&s->cv, NULL);
	if (threaded) {
		sigset_t all, old;

		s->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (s->efd < 0) {
			free(s);
			return NULL;
		}
		sigfillset(&all);
		pthread_sigmask(SIG_BLOCK, &all, &old);		/* the thread must never take the daemon's signals */
		if (pthread_create(&s->th, NULL, writer_main, s)) {
			pthread_sigmask(SIG_SETMASK, &old, NULL);
			close(s->efd);
			free(s);
			return NULL;
		}
		pthread_sigmask(SIG_SETMASK, &old, NULL);
		s->started = true;
	}
	return s;
}

void sio_close(struct sio *s)
{
	struct sio_req *r;

	if (!s)
		return;
	if (s->started) {
		pthread_mutex_lock(&s->mu);
		s->stop = true;
		pthread_cond_signal(&s->cv);
		pthread_mutex_unlock(&s->mu);
		pthread_join(s->th, NULL);
	}
	while ((r = s->qh)) {		/* inline backend never queues; a stopped thread has drained */
		s->qh = r->next;
		sio_req_free(r);
	}
	while ((r = s->ch)) {
		s->ch = r->next;
		sio_req_free(r);
	}
	if (s->logfd >= 0)
		close(s->logfd);
	if (s->efd >= 0)
		close(s->efd);
	free(s->map);
	free(s->devs);
	pthread_cond_destroy(&s->cv);
	pthread_mutex_destroy(&s->mu);
	free(s);
}

int sio_submit(struct sio *s, struct sio_req *r)
{
	r->next = NULL;
	if (!s->threaded) {
		exec_req(s, r);
		pthread_mutex_lock(&s->mu);
		s->outstanding++;
		pthread_mutex_unlock(&s->mu);
		complete(s, r);
		return 0;
	}
	pthread_mutex_lock(&s->mu);
	if (r->op != SIO_LOAD && s->qn >= s->qmax) {
		pthread_mutex_unlock(&s->mu);
		return -EBUSY;
	}
	if (s->qt)
		s->qt->next = r;
	else
		s->qh = r;
	s->qt = r;
	s->qn++;
	s->outstanding++;
	pthread_cond_signal(&s->cv);
	pthread_mutex_unlock(&s->mu);
	return 0;
}

struct sio_req *sio_next(struct sio *s)
{
	struct sio_req *r;

	pthread_mutex_lock(&s->mu);
	r = s->ch;
	if (r) {
		s->ch = r->next;
		if (!s->ch)
			s->ct = NULL;
		s->outstanding--;
	}
	pthread_mutex_unlock(&s->mu);
	return r;
}

void sio_ack(struct sio *s)
{
	uint64_t cnt;

	if (s->efd >= 0 && read(s->efd, &cnt, sizeof(cnt)) < 0) { /* EAGAIN */ }
}

struct sio_req *sio_wait(struct sio *s, unsigned ms)
{
	struct sio_req *r;
	struct pollfd p;

	r = sio_next(s);
	if (r || s->efd < 0)
		return r;
	p.fd = s->efd;
	p.events = POLLIN;
	while (!(r = sio_next(s))) {
		sio_ack(s);
		if ((r = sio_next(s)))
			break;
		if (poll(&p, 1, (int)ms) <= 0)
			return sio_next(s);
	}
	return r;
}

int sio_event_fd(const struct sio *s)
{
	return s->efd;
}

unsigned sio_outstanding(const struct sio *s)
{
	struct sio *w = (struct sio *)s;
	unsigned n;

	pthread_mutex_lock(&w->mu);
	n = w->outstanding;
	pthread_mutex_unlock(&w->mu);
	return n;
}

void sio_get_stats(struct sio *s, struct sio_stats *st)
{
	pthread_mutex_lock(&s->mu);
	*st = s->st;
	pthread_mutex_unlock(&s->mu);
}
