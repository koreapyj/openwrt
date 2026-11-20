/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_MMSSTORE_H
#define IMSD_MMS_MMSSTORE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Attachments of received MMS under a tmpfs directory that the device's web server serves (uhttpd, document
 * root /www, symlink /www/imsd-mms -> mms_dir made by the init script). This is not a message store: there is no
 * index a client could ask, no way back from the file to the message; the only handle is the link in the text
 * of the delivered message. Every message gets a random directory name of 128 bits (32 hex digits), the files in
 * it carry sanitised names. Retention is bounded by message count, total size and age; the oldest message goes
 * first. After a restart of the daemon the directories found on disk are taken over (and trimmed).
 *
 * File I/O is plain blocking open / write / close on a tmpfs (RAM: no storage to wait for, no fsync, never),
 * in chunks of 32 KiB; a full file system makes a write fail at once with ENOSPC. The walk over mms_dir at start
 * and the removal of a message (a handful of unlink calls) are equally short. Nothing here sleeps.
 */
struct mmsstore_cfg {
	char dir[96];			/* absolute path of the directory, e.g. /tmp/imsd-mms */
	unsigned keep_messages;		/* default 50 */
	unsigned keep_bytes;		/* default 16 MiB */
	unsigned keep_days;		/* default 7, 0 = no age limit */
};

struct mmsstore;
/* wall: Unix time source (NULL: time()); ctx handed to it. NULL on out of memory. Does not touch the file system. */
struct mmsstore *mmsstore_new(const struct mmsstore_cfg *cfg, int64_t (*wall)(void *ctx), void *ctx);
void mmsstore_free(struct mmsstore *s);
/* new limits / directory; trims */
void mmsstore_set_cfg(struct mmsstore *s, const struct mmsstore_cfg *cfg);

struct mmsstore_file {
	/* in */
	const char *name;		/* name hint (Content-Location / filename), may be NULL or "" */
	const char *type;		/* content type, for the extension of a name made up */
	unsigned idx;			/* number of the part in the message, for a name made up ("part3.jpg"); 0: position in this list + 1 */
	const uint8_t *data;
	size_t len;
	/* out */
	bool ok;			/* written */
	char saved[72];			/* the file name inside the message directory */
};
/*
 * Save n files as one message. dir (33 bytes) receives the directory name. Files bigger than keep_bytes are not
 * written (ok false). Older messages are evicted to make room. 0 when at least the directory was created, or
 * -errno (mms_dir cannot be created / no space: nothing saved).
 */
int mmsstore_save(struct mmsstore *s, struct mmsstore_file *f, unsigned n, char dir[33]);
/* Read file `name` of message `dir` whole into a malloc'd buffer (*out, *len; at most max bytes, chunks of 32 KiB, tmpfs).
 * 0, -ENOENT (evicted / unknown), -EFBIG (larger than max), other -errno */
int mmsstore_read(const struct mmsstore *s, const char *dir, const char *name, size_t max, uint8_t **out, size_t *len);
/* remove one message now (no error when it is gone already) */
void mmsstore_remove(struct mmsstore *s, const char *dir);
/* drop messages older than keep_days (also done by every save) */
void mmsstore_sweep(struct mmsstore *s);
void mmsstore_stats(const struct mmsstore *s, unsigned *messages, size_t *bytes);

/* file name for a part: the hint reduced to [A-Za-z0-9._-] (path components removed, no leading dot, at most 64
 * characters keeping the extension), or "part<idx>" + the extension of the content type */
void mmsstore_clean_name(const char *hint, const char *type, unsigned idx, char *out, size_t n);
#endif
