/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Attachment directory, see mmsstore.h. */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include "mmsstore.h"
#include "../util/evloop.h"
#include "../util/log.h"
#include "../util/sys.h"

#define CHUNK		(32 * 1024)
#define NAME_MAX_LEN	64
#define SWEEP_MS	(30u * 60 * 1000)
#define MAX_KEEP	1000
#define WALL_PLAUSIBLE	1600000000	/* a clock earlier than Sep 2020 was not set yet: no age based eviction */

struct entry {
	char dir[33];
	size_t bytes;
	int64_t t;
};

struct mmsstore {
	struct mmsstore_cfg cfg;
	int64_t (*wall)(void *);
	void *wctx;
	struct entry *e;	/* oldest first */
	unsigned n, cap;
	size_t bytes;
	bool scanned;
	struct ev_timer *timer;
};

static int64_t wall_now(const struct mmsstore *s)
{
	return s->wall ? s->wall(s->wctx) : (int64_t)time(NULL);
}

static const struct { const char *type, *ext; } EXTS[] = {
	{ "image/jpeg", ".jpg" }, { "image/jpg", ".jpg" }, { "image/gif", ".gif" }, { "image/png", ".png" },
	{ "image/bmp", ".bmp" }, { "image/vnd.wap.wbmp", ".wbmp" }, { "image/tiff", ".tif" }, { "image/webp", ".webp" },
	{ "image/heic", ".heic" }, { "audio/amr", ".amr" }, { "audio/amr-wb", ".awb" }, { "audio/mpeg", ".mp3" },
	{ "audio/mp3", ".mp3" }, { "audio/aac", ".aac" }, { "audio/mid", ".mid" }, { "audio/midi", ".mid" },
	{ "audio/x-wav", ".wav" }, { "audio/wav", ".wav" }, { "audio/ogg", ".ogg" }, { "video/3gpp", ".3gp" },
	{ "video/3gpp2", ".3g2" }, { "video/mp4", ".mp4" }, { "text/x-vcard", ".vcf" }, { "text/vcard", ".vcf" },
	{ "text/x-vcalendar", ".vcs" }, { "text/plain", ".txt" }, { "text/html", ".html" }, { "application/pdf", ".pdf" },
	{ "application/smil", ".smil" }, { "application/vnd.oma.drm.message", ".dm" },
};

static const char *ext_of(const char *type)
{
	size_t i;

	for (i = 0; i < sizeof(EXTS) / sizeof(EXTS[0]); i++)
		if (!strcasecmp(EXTS[i].type, type))
			return EXTS[i].ext;
	return ".bin";
}

void mmsstore_clean_name(const char *hint, const char *type, unsigned idx, char *out, size_t n)
{
	const char *b, *p, *dot;
	char t[256];
	size_t k = 0, l;

	if (!n)
		return;
	b = hint ? hint : "";
	for (p = b; *p; p++)
		if (*p == '/' || *p == '\\')
			b = p + 1;
	for (p = b; *p && k < sizeof(t) - 1; p++) {
		unsigned char c = (unsigned char)*p;

		t[k++] = (isalnum(c) && c < 0x80) || c == '.' || c == '-' || c == '_' ? (char)c : '_';
	}
	t[k] = 0;
	/* leading dots would hide the file or make "..": drop them */
	for (p = t; *p == '.'; p++)
		;
	memmove(t, p, strlen(p) + 1);
	l = strlen(t);
	if (l > NAME_MAX_LEN) {		/* keep the extension */
		dot = strrchr(t, '.');
		if (dot && strlen(dot) <= 8) {
			size_t el = strlen(dot);

			memmove(t + NAME_MAX_LEN - el, dot, el + 1);
		} else {
			t[NAME_MAX_LEN] = 0;
		}
	}
	if (!t[0] || !strcmp(t, "_") ) {
		snprintf(out, n, "part%u%s", idx, ext_of(type ? type : ""));
		return;
	}
	snprintf(out, n, "%s", t);
}

/* ------------------------------------------------------------------ */

static bool is_dirname(const char *s)
{
	size_t i;

	for (i = 0; i < 32; i++)
		if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i]))
			return false;
	return s[32] == 0;
}

static void entry_path(const struct mmsstore *s, const char *dir, const char *file, char *out, size_t n)
{
	if (file)
		snprintf(out, n, "%s/%.32s/%s", s->cfg.dir, dir, file);
	else
		snprintf(out, n, "%s/%.32s", s->cfg.dir, dir);
}

static void remove_dir(const struct mmsstore *s, const char *dir)
{
	char p[256];
	DIR *d;
	struct dirent *de;

	if (!is_dirname(dir))
		return;
	entry_path(s, dir, NULL, p, sizeof(p));
	d = opendir(p);
	if (d) {
		while ((de = readdir(d))) {
			char f[520];

			if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
				continue;
			snprintf(f, sizeof(f), "%s/%s", p, de->d_name);
			unlink(f);
		}
		closedir(d);
	}
	rmdir(p);
}

static void evict_oldest(struct mmsstore *s)
{
	if (!s->n)
		return;
	LOGD("mms: store: evicting %s (%zu bytes)", s->e[0].dir, s->e[0].bytes);
	remove_dir(s, s->e[0].dir);
	s->bytes -= s->e[0].bytes;
	memmove(&s->e[0], &s->e[1], sizeof(s->e[0]) * (s->n - 1));
	s->n--;
}

/* evict by age, then oldest first until the limits hold; need > 0 / room: leave space for one more message of need bytes */
static void trim(struct mmsstore *s, size_t need, bool room)
{
	int64_t now = wall_now(s);
	unsigned limit = s->cfg.keep_messages - (room ? 1 : 0);

	if (s->cfg.keep_days && now >= WALL_PLAUSIBLE) {
		int64_t limit = (int64_t)s->cfg.keep_days * 86400;

		while (s->n && s->e[0].t >= WALL_PLAUSIBLE && now - s->e[0].t > limit)
			evict_oldest(s);
	}
	while (s->n && (s->n > limit || s->bytes + need > s->cfg.keep_bytes))
		evict_oldest(s);
}

static int cmp_entry(const void *a, const void *b)
{
	const struct entry *x = a, *y = b;

	return x->t < y->t ? -1 : x->t > y->t;
}

static void scan(struct mmsstore *s)
{
	DIR *d = opendir(s->cfg.dir);
	struct dirent *de;

	s->scanned = true;
	if (!d)
		return;
	while ((de = readdir(d))) {
		char p[256];
		struct stat st;
		DIR *dd;
		struct dirent *fe;
		struct entry *e;

		if (!is_dirname(de->d_name))
			continue;
		entry_path(s, de->d_name, NULL, p, sizeof(p));
		if (stat(p, &st) || !S_ISDIR(st.st_mode))
			continue;
		if (s->n >= s->cap) {
			unsigned nc = s->cap ? s->cap * 2 : 16;
			struct entry *ne;

			if (nc > MAX_KEEP + 1)
				break;
			ne = realloc(s->e, sizeof(*ne) * nc);
			if (!ne)
				break;
			s->e = ne;
			s->cap = nc;
		}
		e = &s->e[s->n];
		memcpy(e->dir, de->d_name, 32);
		e->dir[32] = 0;
		e->t = st.st_mtime;
		e->bytes = 0;
		dd = opendir(p);
		if (dd) {
			while ((fe = readdir(dd))) {
				char f[520];

				snprintf(f, sizeof(f), "%s/%s", p, fe->d_name);
				if (!stat(f, &st) && S_ISREG(st.st_mode))
					e->bytes += (size_t)st.st_size;
			}
			closedir(dd);
		}
		s->bytes += e->bytes;
		s->n++;
	}
	closedir(d);
	if (s->n)
		qsort(s->e, s->n, sizeof(s->e[0]), cmp_entry);
	trim(s, 0, false);
	if (s->n)
		LOGI("mms: store: took over %u message(s), %zu bytes in %s", s->n, s->bytes, s->cfg.dir);
}

static void on_sweep(void *arg)
{
	struct mmsstore *s = arg;

	mmsstore_sweep(s);
	ev_timer_set(s->timer, SWEEP_MS);
}

static void clamp_cfg(struct mmsstore_cfg *c)
{
	if (!c->keep_messages)
		c->keep_messages = 1;
	if (c->keep_messages > MAX_KEEP)
		c->keep_messages = MAX_KEEP;
	if (!c->keep_bytes)
		c->keep_bytes = 1;
}

struct mmsstore *mmsstore_new(const struct mmsstore_cfg *cfg, int64_t (*wall)(void *), void *ctx)
{
	struct mmsstore *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;
	s->cfg = *cfg;
	clamp_cfg(&s->cfg);
	s->wall = wall;
	s->wctx = ctx;
	s->timer = ev_timer_new(on_sweep, s);
	if (s->timer)
		ev_timer_set(s->timer, SWEEP_MS);
	return s;
}

void mmsstore_free(struct mmsstore *s)
{
	if (!s)
		return;
	ev_timer_free(s->timer);
	free(s->e);
	free(s);
}

void mmsstore_set_cfg(struct mmsstore *s, const struct mmsstore_cfg *cfg)
{
	bool newdir = strcmp(s->cfg.dir, cfg->dir) != 0;

	s->cfg = *cfg;
	clamp_cfg(&s->cfg);
	if (newdir) {		/* forget the old directory (its files stay), take over the new one at the next save */
		s->n = 0;
		s->bytes = 0;
		s->scanned = false;
	} else if (s->scanned) {
		trim(s, 0, false);
	}
}

void mmsstore_sweep(struct mmsstore *s)
{
	if (s->scanned)
		trim(s, 0, false);
}

void mmsstore_stats(const struct mmsstore *s, unsigned *messages, size_t *bytes)
{
	if (messages)
		*messages = s->n;
	if (bytes)
		*bytes = s->bytes;
}

static int write_file(const char *path, const uint8_t *d, size_t n)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	size_t off = 0;

	if (fd < 0)
		return -errno;
	while (off < n) {
		size_t c = n - off > CHUNK ? CHUNK : n - off;
		ssize_t w = write(fd, d + off, c);

		if (w < 0 && errno == EINTR)
			continue;
		if (w <= 0) {
			int e = w < 0 ? errno : EIO;

			close(fd);
			unlink(path);
			return -e;
		}
		off += (size_t)w;
	}
	if (close(fd)) {
		unlink(path);
		return -errno;
	}
	return 0;
}

/* an unused name within this message: "a.jpg", "a-2.jpg", ... */
static void unique_name(char *name, size_t n, struct mmsstore_file *f, unsigned upto)
{
	char base[72], ext[16] = "";
	char *dot;
	unsigned k, i;

	for (k = 1;; k++) {
		bool clash = false;

		for (i = 0; i < upto; i++)
			if (f[i].ok && !strcasecmp(f[i].saved, name))
				clash = true;
		if (!clash)
			return;
		if (k == 1) {
			snprintf(base, sizeof(base), "%s", name);
			dot = strrchr(base, '.');
			if (dot && dot != base && strlen(dot) <= 8) {
				snprintf(ext, sizeof(ext), "%s", dot);
				*dot = 0;
			}
		}
		snprintf(name, n, "%.40s-%u%s", base, k + 1, ext);
	}
}

int mmsstore_save(struct mmsstore *s, struct mmsstore_file *f, unsigned n, char dir[33])
{
	char tok[33], p[256];
	size_t need = 0;
	unsigned i, nok = 0;
	struct entry *e;

	if (mkdir(s->cfg.dir, 0755) && errno != EEXIST)
		return -errno;
	if (!s->scanned)
		scan(s);
	{	/* an empty index.html keeps uhttpd from listing the directory (and so the names of the messages) */
		char ix[256];
		int fd;

		snprintf(ix, sizeof(ix), "%s/index.html", s->cfg.dir);
		fd = open(ix, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
		if (fd >= 0)
			close(fd);
	}
	for (i = 0; i < n; i++) {
		f[i].ok = false;
		f[i].saved[0] = 0;
		if (f[i].len <= s->cfg.keep_bytes)
			need += f[i].len;
	}
	trim(s, need, true);
	rnd_token(tok, 32);
	snprintf(dir, 33, "%s", tok);
	entry_path(s, dir, NULL, p, sizeof(p));
	if (mkdir(p, 0755))
		return -errno;
	for (i = 0; i < n; i++) {
		char name[72], path[400];

		if (f[i].len > s->cfg.keep_bytes)
			continue;
		mmsstore_clean_name(f[i].name, f[i].type, f[i].idx ? f[i].idx : i + 1, name, sizeof(name));
		unique_name(name, sizeof(name), f, i);
		snprintf(path, sizeof(path), "%s/%s", p, name);
		if (write_file(path, f[i].data, f[i].len)) {
			LOGW("mms: store: cannot write %s", path);
			continue;
		}
		snprintf(f[i].saved, sizeof(f[i].saved), "%s", name);
		f[i].ok = true;
		nok++;
	}
	if (!nok) {		/* nothing worth a directory */
		rmdir(p);
		return n ? -ENOSPC : 0;
	}
	if (s->n >= s->cap) {
		unsigned nc = s->cap ? s->cap * 2 : 16;
		struct entry *ne = realloc(s->e, sizeof(*ne) * nc);

		if (!ne) {
			remove_dir(s, dir);
			return -ENOMEM;
		}
		s->e = ne;
		s->cap = nc;
	}
	e = &s->e[s->n++];
	snprintf(e->dir, sizeof(e->dir), "%s", dir);
	e->t = wall_now(s);
	e->bytes = 0;
	for (i = 0; i < n; i++)
		if (f[i].ok)
			e->bytes += f[i].len;
	s->bytes += e->bytes;
	return 0;
}

int mmsstore_read(const struct mmsstore *s, const char *dir, const char *name, size_t max, uint8_t **out, size_t *len)
{
	char p[400];
	struct stat st;
	uint8_t *b;
	size_t off = 0;
	int fd;

	*out = NULL;
	*len = 0;
	if (!is_dirname(dir) || !name[0] || strchr(name, '/') || !strcmp(name, ".."))
		return -EINVAL;
	snprintf(p, sizeof(p), "%s/%.32s/%s", s->cfg.dir, dir, name);
	fd = open(p, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
		close(fd);
		return -ENOENT;
	}
	if ((uint64_t)st.st_size > max) {
		close(fd);
		return -EFBIG;
	}
	b = malloc((size_t)st.st_size + 1);
	if (!b) {
		close(fd);
		return -ENOMEM;
	}
	while (off < (size_t)st.st_size) {
		size_t c = (size_t)st.st_size - off > CHUNK ? CHUNK : (size_t)st.st_size - off;
		ssize_t r = read(fd, b + off, c);

		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0) {
			int e = r < 0 ? errno : EIO;

			close(fd);
			free(b);
			return -e;
		}
		off += (size_t)r;
	}
	close(fd);
	b[off] = 0;
	*out = b;
	*len = off;
	return 0;
}

void mmsstore_remove(struct mmsstore *s, const char *dir)
{
	unsigned i;

	for (i = 0; i < s->n; i++)
		if (!strncmp(s->e[i].dir, dir, 32)) {
			remove_dir(s, s->e[i].dir);
			s->bytes -= s->e[i].bytes;
			memmove(&s->e[i], &s->e[i + 1], sizeof(s->e[0]) * (s->n - i - 1));
			s->n--;
			return;
		}
}
