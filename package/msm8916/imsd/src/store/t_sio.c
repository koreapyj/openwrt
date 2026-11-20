/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Tests of the file layer (sio.c): formats, load, torn writes, corruption, compaction kill points, injected I/O errors, threads. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "t_store.h"
#include "sio.h"

void t_tmpdir(const char *tag, char *out, size_t n)
{
	const char *base = getenv("IMSD_TEST_TMP");
	static int k;

	snprintf(out, n, "%s/store-%s-%d-%d", base ? base : "/tmp", tag, (int)getpid(), ++k);
	t_rmtree(out);
	if (mkdir(out, 0700)) {
		perror("mkdir");
		exit(2);
	}
}

void t_rmtree(const char *dir)
{
	char cmd[400];

	if (strlen(dir) < 10 || strstr(dir, "..") || strpbrk(dir, "'\"\\;$`"))
		return;
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd)) { /* nothing to remove */ }
}

static void copy_dir(const char *src, const char *dst)
{
	char cmd[700];

	t_rmtree(dst);
	snprintf(cmd, sizeof(cmd), "cp -a '%s' '%s'", src, dst);
	if (system(cmd))
		printf("cp failed\n");
}

static off_t fsize(const char *dir, const char *name)
{
	char p[400];
	struct stat st;

	snprintf(p, sizeof(p), "%s/%s", dir, name);
	return stat(p, &st) ? -1 : st.st_size;
}

static bool exists(const char *dir, const char *name)
{
	return fsize(dir, name) >= 0;
}

static struct sio_req *run(struct sio *s, struct sio_req *r, bool threaded)
{
	struct sio_req *c;

	if (sio_submit(s, r)) {
		sio_req_free(r);
		return NULL;
	}
	c = threaded ? sio_wait(s, 10000) : sio_next(s);
	return c;
}

static struct sio_load *load(struct sio *s, bool threaded, struct sio_req **keep, int *err)
{
	struct sio_req *c = run(s, sio_req_new(SIO_LOAD), threaded);

	CHECK(c != NULL);
	if (!c) {
		*keep = NULL;
		return NULL;
	}
	if (err)
		*err = c->err;
	*keep = c;
	return c->load;
}

static int append(struct sio *s, bool threaded, uint64_t seq, uint8_t type, const char *peer, const void *meta, size_t ml,
		  const void *body, size_t bl, uint64_t dedup, uint64_t lookup)
{
	struct sio_req *r = sio_req_new(SIO_APPEND), *c;
	int err;

	r->ent.seq = seq;
	r->ent.time = 1700000000 + (int64_t)seq;
	r->ent.type = type;
	r->ent.flags = type >= 3;
	r->ent.dedup = dedup;
	r->ent.lookup = lookup;
	if (type >= 3) {
		r->ent.nexcl = 2;
		r->ent.excl[0] = 0x1111 + seq;
		r->ent.excl[1] = 0x2222;
	}
	snprintf(r->ent.peer, sizeof(r->ent.peer), "%s", peer);
	r->meta = malloc(ml ? ml : 1);
	r->body = malloc(bl ? bl : 1);
	memcpy(r->meta, meta, ml);
	if (bl)
		memcpy(r->body, body, bl);
	r->meta_len = ml;
	r->body_len = bl;
	c = run(s, r, threaded);
	CHECK(c != NULL);
	if (!c)
		return -EIO;
	err = c->err;
	sio_req_free(c);
	return err;
}

static int read_item(struct sio *s, bool threaded, uint64_t seq, bool want_body, struct sio_req **out)
{
	struct sio_req *r = sio_req_new(SIO_READ), *c;
	int err;

	r->ent.seq = seq;
	r->want_body = want_body;
	c = run(s, r, threaded);
	CHECK(c != NULL);
	if (!c)
		return -EIO;
	err = c->err;
	if (out)
		*out = c;
	else
		sio_req_free(c);
	return err;
}

static int simple(struct sio *s, bool threaded, enum sio_op op, uint64_t seq, bool persist)
{
	struct sio_req *r = sio_req_new(op), *c;
	int err;

	r->ent.seq = seq;
	r->persist = persist;
	c = run(s, r, threaded);
	CHECK(c != NULL);
	if (!c)
		return -EIO;
	err = c->err;
	sio_req_free(c);
	return err;
}

static void fill(uint8_t *p, size_t n, unsigned salt)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(i * 7 + salt);
}

/* ------------------------------------------------------------------ */

void test_sio_basic(void)
{
	char dir[256];
	struct sio *s;
	struct sio_req *c, *rd;
	struct sio_load *L;
	uint8_t meta[200], *body;
	struct sio_dev dv[2];
	unsigned i;
	int err;

	CHECK_EQ(sio_crc32("123456789", 9), 0xcbf43926u);
	t_tmpdir("basic", dir, sizeof(dir));
	body = malloc(100000);
	fill(body, 100000, 3);
	fill(meta, sizeof(meta), 9);
	s = sio_open(dir, true, 0);
	CHECK(s != NULL);
	L = load(s, true, &c, &err);
	CHECK_EQ(err, 0);
	CHECK(L && L->n == 0);
	CHECK(L && L->next_seq == 1);
	sio_req_free(c);
	CHECK(exists(dir, "log"));
	CHECK(exists(dir, "state"));
	CHECK_EQ(fsize(dir, "log"), 16);

	CHECK_EQ(append(s, true, 1, 1, "+821011112222", "hello", 5, NULL, 0, 0xaa, 0), 0);
	CHECK_EQ(append(s, true, 2, 2, "0107777", meta, 200, body, 5000, 0xbb, 0xcc), 0);
	CHECK_EQ(append(s, true, 3, 3, "+8210333", "carbon", 6, NULL, 0, 0, 0), 0);
	CHECK_EQ(append(s, true, 4, 4, "a@b.c", meta, 100, body, 100000, 0, 0xdd), 0);
	CHECK(exists(dir, "b/0000000000000002"));
	CHECK(exists(dir, "b/0000000000000004"));
	CHECK(!exists(dir, "b/0000000000000001"));

	/* read back: meta only, with body, missing */
	CHECK_EQ(read_item(s, true, 2, false, &rd), 0);
	CHECK(rd->meta_len == 200 && !memcmp(rd->meta, meta, 200) && rd->body == NULL);
	CHECK_STR(rd->ent.peer, "0107777");
	CHECK(rd->ent.dedup == 0xbb && rd->ent.lookup == 0xcc && rd->ent.type == 2);
	sio_req_free(rd);
	CHECK_EQ(read_item(s, true, 4, true, &rd), 0);
	CHECK(rd->body_len == 100000 && !memcmp(rd->body, body, 100000));
	CHECK(rd->ent.nexcl == 2 && rd->ent.excl[0] == 0x1115 && rd->ent.excl[1] == 0x2222 && rd->ent.flags == 1);
	sio_req_free(rd);
	CHECK_EQ(read_item(s, true, 3, false, &rd), 0);
	CHECK(rd->meta_len == 6 && !memcmp(rd->meta, "carbon", 6));
	sio_req_free(rd);
	CHECK_EQ(read_item(s, true, 99, false, NULL), -ENOENT);

	memset(dv, 0, sizeof(dv));
	snprintf(dv[0].id, sizeof(dv[0].id), "i:urn:uuid:1234");
	dv[0].cursor = 3;
	dv[0].reported = 2;
	dv[0].flags = SIO_DEV_ACK;
	dv[0].last_seen = 1700000100;
	snprintf(dv[1].id, sizeof(dv[1].id), "u:alice");
	dv[1].cursor = 4;
	c = sio_req_new(SIO_STATE);
	c->devs = calloc(2, sizeof(*c->devs));
	memcpy(c->devs, dv, sizeof(dv));
	c->ndev = 2;
	rd = run(s, c, true);
	CHECK(rd && rd->err == 0);
	sio_req_free(rd);
	{
		struct sio_stats st;

		sio_get_stats(s, &st);
		CHECK_EQ(st.appends, 4);
		CHECK_EQ(st.live, 4);
	}
	sio_close(s);

	/* restart: everything is back, the counter continues past the reserved block */
	s = sio_open(dir, true, 0);
	L = load(s, true, &c, &err);
	CHECK_EQ(err, 0);
	CHECK(L && L->n == 4);
	if (L && L->n == 4) {
		for (i = 0; i < 4; i++)
			CHECK_EQ(L->ent[i].seq, i + 1);
		CHECK_STR(L->ent[1].peer, "0107777");
		CHECK(L->ent[1].meta_len == 200 && L->ent[1].body_len == 5000);
		CHECK(L->ent[3].body_len == 100000 && L->ent[3].body_crc == sio_crc32(body, 100000));
		CHECK_EQ(L->ent[0].time, 1700000001);
		CHECK_EQ(L->ent[2].type, 3);
		CHECK_EQ(L->ent[3].excl[0], 0x1115);
	}
	CHECK(L && L->ndev == 2);
	if (L && L->ndev == 2) {
		CHECK_STR(L->dev[0].id, "i:urn:uuid:1234");
		CHECK(L->dev[0].cursor == 3 && L->dev[0].reported == 2 && (L->dev[0].flags & SIO_DEV_ACK));
		CHECK_EQ(L->dev[0].last_seen, 1700000100);
		CHECK(L->dev[1].cursor == 4 && !L->dev[1].flags);
	}
	CHECK(L && L->next_seq >= 1 + SIO_RESERVE);	/* never below what could have been assigned */
	CHECK(L && L->next_seq > 4);
	{
		uint64_t n1 = L ? L->next_seq : 0;

		sio_req_free(c);
		CHECK_EQ(append(s, true, n1, 1, "+82", "new", 3, NULL, 0, 0, 0), 0);
		sio_close(s);
		s = sio_open(dir, true, 0);
		L = load(s, true, &c, &err);
		CHECK(L && L->n == 5 && L->ent[4].seq == n1);
		CHECK(L && L->next_seq > n1);		/* monotonic across restarts */
		sio_req_free(c);
	}
	sio_close(s);
	free(body);
	t_rmtree(dir);
}

void test_sio_torn(void)
{
	char dir[256], d2[300];
	struct sio *s;
	struct sio_req *c;
	struct sio_load *L;
	off_t sz[6];
	unsigned i;
	int err;
	uint8_t body[300], meta[120];
	long cut, fails = 0;

	fill(body, sizeof(body), 1);
	fill(meta, sizeof(meta), 2);
	t_tmpdir("torn", dir, sizeof(dir));
	snprintf(d2, sizeof(d2), "%s-copy", dir);
	s = sio_open(dir, false, 0);
	L = load(s, false, &c, &err);
	sio_req_free(c);
	(void)L;
	sz[0] = fsize(dir, "log");
	for (i = 1; i <= 5; i++) {
		CHECK_EQ(append(s, false, i, i == 5 ? 2 : 1, "+82101234", meta, 20 + i * 10, i == 5 ? body : NULL, i == 5 ? 300 : 0, i, 0), 0);
		sz[i] = fsize(dir, "log");
		CHECK(sz[i] > sz[i - 1]);
	}
	sio_close(s);

	/* truncate the file at every byte offset inside the last record (and at its start and end) */
	for (cut = sz[4]; cut <= sz[5]; cut++) {
		char p[400];

		copy_dir(dir, d2);
		snprintf(p, sizeof(p), "%s/log", d2);
		if (truncate(p, cut)) {
			printf("truncate failed\n");
			break;
		}
		s = sio_open(d2, false, 0);
		L = load(s, false, &c, &err);
		if (!L) {
			fails++;
			sio_close(s);
			continue;
		}
		if (cut == sz[5]) {
			if (L->n != 5 || L->torn != 0)
				fails++;
		} else {
			if (L->n != 4 || L->torn != (cut > sz[4] ? 1u : 0u))
				fails++;
			if (L->next_seq <= 5)			/* the counter never goes back to the number of the torn item */
				fails++;
			if (exists(d2, "b/0000000000000005"))	/* the body of the cut record is an orphan, removed */
				fails++;
			if (fsize(d2, "log") != sz[4])
				fails++;
		}
		for (i = 0; i < L->n && i < 4; i++)
			if (L->ent[i].seq != i + 1 || L->ent[i].dedup != i + 1)
				fails++;
		sio_req_free(c);
		/* the repaired log takes new records and reads the old ones */
		if (cut < sz[5] && cut % 37 == 0) {
			uint64_t nx = 200 + (uint64_t)cut;

			if (append(s, false, nx, 1, "+82", "x", 1, NULL, 0, 0, 0) || read_item(s, false, 3, false, NULL))
				fails++;
		}
		sio_close(s);
	}
	CHECK_EQ(fails, 0);

	/* a flipped byte in the middle of record 3: records 1 and 2 survive, the rest is cut and counted */
	{
		char p[400];
		int fd;
		uint8_t b;
		off_t at = sz[2] + (sz[3] - sz[2]) / 2;

		copy_dir(dir, d2);
		snprintf(p, sizeof(p), "%s/log", d2);
		fd = open(p, O_RDWR);
		CHECK(fd >= 0);
		CHECK(pread(fd, &b, 1, at) == 1);
		b ^= 0x40;
		CHECK(pwrite(fd, &b, 1, at) == 1);
		close(fd);
		s = sio_open(d2, false, 0);
		L = load(s, false, &c, &err);
		CHECK(L && L->n == 2 && L->torn == 1);
		CHECK(L && L->next_seq > 5);
		CHECK_EQ(fsize(d2, "log"), sz[2]);
		sio_req_free(c);
		sio_close(s);
	}
	/* a header that is cut (creation torn): treated as new */
	{
		char p[400];

		copy_dir(dir, d2);
		snprintf(p, sizeof(p), "%s/log", d2);
		CHECK(!truncate(p, 7));
		s = sio_open(d2, false, 0);
		L = load(s, false, &c, &err);
		CHECK(L && L->n == 0 && L->torn == 1);
		sio_req_free(c);
		sio_close(s);
	}
	/* a log with a wrong magic is set aside, not overwritten */
	{
		char p[400];
		FILE *f;

		copy_dir(dir, d2);
		snprintf(p, sizeof(p), "%s/log", d2);
		f = fopen(p, "r+");
		CHECK(f != NULL);
		fputs("NOTALOG!", f);
		fclose(f);
		s = sio_open(d2, false, 0);
		L = load(s, false, &c, &err);
		CHECK(L && L->n == 0 && L->log_reset);
		CHECK(exists(d2, "log.bad"));
		sio_req_free(c);
		sio_close(s);
	}
	t_rmtree(dir);
	t_rmtree(d2);
}

void test_sio_compact(void)
{
	char dir[256];
	int kill;

	for (kill = 0; kill <= 5; kill++) {
		struct sio *s;
		struct sio_req *c, *rd;
		struct sio_load *L;
		uint8_t body[64], meta[40];
		uint64_t i;
		int err;
		off_t before;
		struct sio_stats st;

		fill(body, sizeof(body), 5);
		fill(meta, sizeof(meta), 6);
		t_tmpdir("compact", dir, sizeof(dir));
		s = sio_open(dir, false, 0);
		L = load(s, false, &c, &err);
		sio_req_free(c);
		(void)L;
		for (i = 1; i <= 100; i++)
			CHECK_EQ(append(s, false, i, 2, "+82", meta, sizeof(meta), body, sizeof(body), 0, 0), 0);
		before = fsize(dir, "log");
		sio_fault.kill_step = kill;
		CHECK_EQ(simple(s, false, SIO_EVICT, 71, false), 0);	/* 70 dead records >= 64 and >= the 30 live ones: compaction */
		sio_fault.kill_step = 0;
		sio_get_stats(s, &st);
		CHECK_EQ(st.compactions, kill ? 0 : 1);
		CHECK_EQ(st.live, 30);
		if (!kill) {
			CHECK(fsize(dir, "log") < before / 2);
			CHECK(!exists(dir, "log.new"));
			/* the open store goes on with the new file */
			CHECK_EQ(read_item(s, false, 100, true, &rd), 0);
			CHECK(rd->body_len == 64 && !memcmp(rd->body, body, 64));
			sio_req_free(rd);
			CHECK_EQ(append(s, false, 101, 2, "+82", meta, sizeof(meta), body, sizeof(body), 0, 0), 0);
		}
		sio_close(s);

		/* "crash": whatever step it stopped at, a valid store loads, with every live item */
		s = sio_open(dir, false, 0);
		L = load(s, false, &c, &err);
		CHECK_EQ(err, 0);
		CHECK(L != NULL);
		if (L) {
			unsigned want = kill ? 30 : 31, k;

			CHECK_EQ(L->n, want);
			CHECK_EQ(L->torn, 0);
			CHECK(!exists(dir, "log.new"));
			for (k = 0; k < L->n; k++)
				CHECK(L->ent[k].seq >= 71);
			for (i = 71; i <= 100; i++) {
				if (read_item(s, false, i, true, &rd)) {
					CHECK(0);
					continue;
				}
				CHECK(rd->body_len == 64 && !memcmp(rd->body, body, 64));
				sio_req_free(rd);
			}
		}
		sio_req_free(c);
		sio_close(s);
		t_rmtree(dir);
	}
}

void test_sio_faults(void)
{
	char dir[256];
	struct sio *s;
	struct sio_req *c, *rd;
	struct sio_load *L;
	uint8_t body[300], meta[30];
	off_t good;
	int err;
	unsigned i;

	fill(body, sizeof(body), 1);
	fill(meta, sizeof(meta), 2);
	t_tmpdir("faults", dir, sizeof(dir));
	s = sio_open(dir, false, 0);
	L = load(s, false, &c, &err);
	sio_req_free(c);
	(void)L;
	CHECK_EQ(append(s, false, 1, 1, "+82", meta, 30, NULL, 0, 0, 0), 0);
	good = fsize(dir, "log");

	/* a full disk in the middle of a record: the half record is cut away again, the next one lands after the good ones */
	sio_fault.points = SIO_FP_LOGWRITE;
	sio_fault.err = ENOSPC;
	sio_fault.count = 1;
	CHECK_EQ(append(s, false, 2, 1, "+82", meta, 30, NULL, 0, 0, 0), -ENOSPC);
	CHECK_EQ(fsize(dir, "log"), good);
	CHECK_EQ(append(s, false, 3, 1, "+82", meta, 30, NULL, 0, 0, 0), 0);
	/* fsync failing */
	sio_fault.points = SIO_FP_LOGSYNC;
	sio_fault.err = EIO;
	sio_fault.count = 1;
	CHECK_EQ(append(s, false, 4, 1, "+82", meta, 30, NULL, 0, 0, 0), -EIO);
	/* the body file */
	sio_fault.points = SIO_FP_BODY;
	sio_fault.err = ENOSPC;
	sio_fault.count = -1;
	CHECK_EQ(append(s, false, 5, 2, "+82", meta, 30, body, 300, 0, 0), -ENOSPC);
	CHECK(!exists(dir, "b/0000000000000005"));
	sio_fault.points = 0;
	/* the state file */
	sio_fault.points = SIO_FP_STATE;
	sio_fault.err = ENOSPC;
	sio_fault.count = -1;
	{
		struct sio_req *r = sio_req_new(SIO_STATE);

		r->devs = calloc(1, sizeof(*r->devs));
		r->ndev = 1;
		snprintf(r->devs[0].id, sizeof(r->devs[0].id), "u:x");
		c = run(s, r, false);
		CHECK(c && c->err == -ENOSPC);
		sio_req_free(c);
	}
	/* an append beyond the reserved block needs the state file: it fails with it, and writes nothing */
	CHECK_EQ(append(s, false, 1000, 1, "+82", meta, 30, NULL, 0, 0, 0), -ENOSPC);
	sio_fault.points = 0;
	CHECK_EQ(simple(s, false, SIO_PROBE, 0, false), 0);
	CHECK_EQ(append(s, false, 1000, 1, "+82", meta, 30, NULL, 0, 0, 0), 0);
	/* reads */
	sio_fault.points = SIO_FP_READ;
	sio_fault.err = EIO;
	sio_fault.count = 1;
	CHECK_EQ(read_item(s, false, 1, false, NULL), -EIO);
	CHECK_EQ(read_item(s, false, 1, false, NULL), 0);
	sio_fault.points = 0;
	CHECK_EQ(append(s, false, 1001, 2, "+82", meta, 30, body, 300, 0, 0), 0);
	sio_close(s);

	/* nothing of the failed appends is in the log; the good ones are */
	s = sio_open(dir, false, 0);
	L = load(s, false, &c, &err);
	CHECK(L && L->n == 4 && L->torn == 0);
	if (L && L->n == 4) {
		CHECK_EQ(L->ent[0].seq, 1);
		CHECK_EQ(L->ent[1].seq, 3);
		CHECK_EQ(L->ent[2].seq, 1000);
		CHECK_EQ(L->ent[3].seq, 1001);
		CHECK(L->next_seq > 1001);
	}
	sio_req_free(c);

	/* a flipped byte in a body file is noticed when it is read */
	{
		char p[400];
		int fd;
		uint8_t b;

		snprintf(p, sizeof(p), "%s/b/00000000000003e9", dir);
		fd = open(p, O_RDWR);
		CHECK(fd >= 0);
		CHECK(pread(fd, &b, 1, 100) == 1);
		b ^= 1;
		CHECK(pwrite(fd, &b, 1, 100) == 1);
		close(fd);
		CHECK_EQ(read_item(s, false, 1001, true, NULL), -EBADMSG);
		CHECK_EQ(read_item(s, false, 1001, false, NULL), 0);
	}
	/* drop and purge are durable */
	CHECK_EQ(simple(s, false, SIO_DROP, 3, false), 0);
	CHECK_EQ(simple(s, false, SIO_EVICT, 1000, true), 0);
	sio_close(s);
	s = sio_open(dir, false, 0);
	L = load(s, false, &c, &err);
	CHECK(L && L->n == 2);
	if (L && L->n == 2) {
		CHECK_EQ(L->ent[0].seq, 1000);
		CHECK_EQ(L->ent[1].seq, 1001);
	}
	sio_req_free(c);
	sio_close(s);

	/* a body file that is gone: the item is dropped at load; one that has no item is removed */
	{
		char p[400];
		FILE *f;

		snprintf(p, sizeof(p), "%s/b/00000000000003e9", dir);
		CHECK(!unlink(p));
		snprintf(p, sizeof(p), "%s/b/00000000000009ff", dir);
		f = fopen(p, "w");
		fputs("orphan", f);
		fclose(f);
		s = sio_open(dir, false, 0);
		L = load(s, false, &c, &err);
		CHECK(L && L->n == 1 && L->bodies_missing == 1 && L->orphans == 1);
		CHECK(!exists(dir, "b/00000000000009ff"));
		sio_req_free(c);
		sio_close(s);
	}
	/* a state file that is damaged: the cursors are lost but the counter stays above the records */
	{
		char p[400];
		FILE *f;

		snprintf(p, sizeof(p), "%s/state", dir);
		f = fopen(p, "r+");
		fseek(f, 20, SEEK_SET);
		fputc(0x7f, f);
		fclose(f);
		s = sio_open(dir, false, 0);
		L = load(s, false, &c, &err);
		CHECK(L && L->state_bad && L->ndev == 0 && L->next_seq > 1000);
		sio_req_free(c);
		sio_close(s);
	}
	/* the bounded queue (threaded backend): a stalled writer makes sio_submit answer -EBUSY, a LOAD always fits */
	s = sio_open(dir, true, 2);
	sio_fault.stall_ms = 50;
	{
		int busy = 0, ok = 0;

		for (i = 0; i < 6; i++) {
			struct sio_req *r = sio_req_new(SIO_READ);

			r->ent.seq = 1000;
			if (sio_submit(s, r)) {
				sio_req_free(r);
				busy++;
			} else {
				ok++;
			}
		}
		CHECK(busy >= 1 && ok >= 2);
		while (ok--) {
			rd = sio_wait(s, 5000);
			CHECK(rd != NULL);
			sio_req_free(rd);
		}
	}
	sio_fault.stall_ms = 0;
	sio_close(s);
	t_rmtree(dir);
}

void test_sio_threads(void)
{
	char dir[256];
	struct sio *s;
	struct sio_req *c;
	struct sio_load *L;
	uint8_t meta[50], body[2000];
	uint64_t next = 1, got = 0, sent = 0, reads = 0;
	int err, bad = 0;

	fill(meta, sizeof(meta), 4);
	fill(body, sizeof(body), 8);
	t_tmpdir("threads", dir, sizeof(dir));
	s = sio_open(dir, true, 8);
	L = load(s, true, &c, &err);
	CHECK(L != NULL);
	sio_req_free(c);
	/* appends and reads of earlier items, all queued from this thread, completions taken as they come */
	while (got < 300) {
		while (sent < 300 && sent - got < 40) {
			struct sio_req *r;

			if (sent % 3 == 2 && next > 2) {
				r = sio_req_new(SIO_READ);
				r->ent.seq = next - 2;
				r->want_body = true;
				r->token = 1;
			} else {
				r = sio_req_new(SIO_APPEND);
				r->ent.seq = next++;
				r->ent.type = 2;
				snprintf(r->ent.peer, sizeof(r->ent.peer), "+82");
				r->meta = malloc(50);
				memcpy(r->meta, meta, 50);
				r->meta_len = 50;
				r->body = malloc(2000);
				memcpy(r->body, body, 2000);
				r->body_len = 2000;
			}
			if (sio_submit(s, r)) {
				bool app = r->op == SIO_APPEND;

				sio_req_free(r);
				if (app)
					next--;
				break;
			}
			sent++;
		}
		c = sio_wait(s, 10000);
		if (!c) {
			bad++;
			break;
		}
		if (c->err)
			bad++;
		if (c->op == SIO_READ) {
			reads++;
			if (c->body_len != 2000 || memcmp(c->body, body, 2000))
				bad++;
		}
		sio_req_free(c);
		got++;
	}
	CHECK_EQ(bad, 0);
	CHECK(reads > 50);
	sio_close(s);
	s = sio_open(dir, true, 0);
	L = load(s, true, &c, &err);
	CHECK(L && L->n == next - 1);
	sio_req_free(c);
	sio_close(s);
	t_rmtree(dir);
}
