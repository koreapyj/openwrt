/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A retrieved MMS delivered through the real LAN side (registrar, fork, SIP MESSAGE to a fake device), attachments in the
 * store, text rendering variants; and the robustness tests (truncation and mutation of PDUs and answers). */
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../ua/test_ua.h"
#include "t_common.h"
#include "t_vectors.h"
#include "mms_lan.h"
#include "mmsstore.h"
#include "mmsrender.h"
#include "wsp.h"
#include "../util/codec.h"

#define UA "TTA-VoLTE/3.0 imsd/0.1 Device_Type/Android_Phone OMD"

struct ffix {
	struct uaw w;
	struct mms_lan *ml;
	struct mocknet mn;
	struct mms *m;
	struct mms_cfg cfg;
	struct mms_link link;
	uint8_t ok_empty[256];
	size_t ok_empty_n;
	char dir[64];
	uint8_t httpbuf[8][20000];
	int nbuf;
};

static struct ffix *FF;

static void ff_link(void *ctx, struct mms_link *out)
{
	(void)ctx;
	*out = FF->link;
}

static const char *ff_host(void *ctx)
{
	(void)ctx;
	return "192.168.68.1";
}

static int64_t ff_wall(void *ctx)
{
	(void)ctx;
	return 1795134300;
}

static void ff_init(struct ffix *f, void (*tweak)(struct mms_cfg *))
{
	struct mms_ops ops;
	struct mock_dns_rule rule;
	struct addr a;

	memset(f, 0, sizeof(*f));
	FF = f;
	uaw_init(&f->w, NULL, false);
	f->ml = mms_lan_new();
	mms_lan_set(f->ml, f->w.lan);
	mock_init(&f->mn);
	mms_cfg_defaults(&f->cfg);
	snprintf(f->cfg.user_agent, sizeof(f->cfg.user_agent), "%s", UA);
	snprintf(f->dir, sizeof(f->dir), "/tmp/imsd-mms-flow-XXXXXX");
	CHECK(mkdtemp(f->dir) != NULL);
	snprintf(f->cfg.dir, sizeof(f->cfg.dir), "%s/m", f->dir);
	if (tweak)
		tweak(&f->cfg);
	f->link.up = true;
	snprintf(f->link.netdev, sizeof(f->link.netdev), "wwan0");
	addr_set(&f->link.local, "2001:4430:141:990a::cb69", 0);
	addr_set(&a, "2001:4430:8000:20:0:1:0:1", 0);
	f->link.dns[0] = a;
	f->link.n_dns = 1;
	f->link.seq = 1;
	memset(&ops, 0, sizeof(ops));
	ops.link = ff_link;
	ops.deliver = mms_lan_deliver;
	ops.deliver_abort = mms_lan_abort;
	ops.lan_host = ff_host;
	ops.wall = ff_wall;
	ops.net = &f->mn.ops;
	ops.ctx = f->ml;
	f->m = mms_new(&f->cfg, &ops);
	CHECK(f->m != NULL);
	memset(&rule, 0, sizeof(rule));
	rule.name = "mmsc.test"; rule.type = 28; rule.ttl = 3600; rule.n = 1; addr_set(&rule.addr[0], "2001:db8::10", 0);
	mock_dns_add(&f->mn, &rule);
	f->ok_empty_n = http_ok(f->ok_empty, sizeof(f->ok_empty), 200, "text/plain", "", 0);
}

static void ff_fini(struct ffix *f)
{
	char cmd[128];

	mms_free(f->m);
	mms_lan_free(f->ml);
	mock_free(&f->mn);
	uaw_fini(&f->w);
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", f->dir);
	if (system(cmd) < 0)
		CHECK(0);
}

static void ff_respond(struct ffix *f, const void *pdu, size_t n)
{
	struct mock_resp r;
	uint8_t *b = f->httpbuf[f->nbuf++ & 7];

	memset(&r, 0, sizeof(r));
	r.n = http_ok(b, sizeof(f->httpbuf[0]), 200, "application/vnd.wap.mms-message", pdu, n);
	r.d = b;
	CHECK(r.n > 0);
	mock_respond(&f->mn, &r);
}

static void ff_fetch(struct ffix *f, const char *tid)
{
	char url[100];
	struct pb n = { .n = 0 }, p = { .n = 0 };

	snprintf(url, sizeof(url), "http://mmsc.test/?%s", tid);
	build_notif(&n, tid, 0x92, "01012345678/TYPE=PLMN", NULL, 100, -1, url);
	build_push(&p, n.d, n.n);
	mms_on_push(f->m, "0100000004", 2948, p.d, p.n);
}

/* ---- LAN side observation ---- */

static int dev_count(struct ffix *f, int k)
{
	int n = 0;

	while (find_sent(f->w.f, dev_ip(k), 5060, "MESSAGE", n) >= 0)
		n++;
	return n;
}

static void dev_answer_last(struct ffix *f, int k, int status)
{
	int n = dev_count(f, k);

	if (n > 0)
		dev_reply_idx(&f->w, find_sent(f->w.f, dev_ip(k), 5060, "MESSAGE", n - 1), k, status, "tg", NULL);
}

static bool dev_parse(struct ffix *f, int k, int nth, struct sip_msg *m)
{
	int i = find_sent(f->w.f, dev_ip(k), 5060, "MESSAGE", nth);

	return i >= 0 && !fakeep_parse(f->w.f, i, m);
}

static bool utf8_ok(const char *s, size_t n)
{
	size_t i = 0;

	while (i < n) {
		unsigned char c = (unsigned char)s[i];
		size_t l = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
		size_t k;

		if (!l || i + l > n)
			return false;
		for (k = 1; k < l; k++)
			if (((unsigned char)s[i + k] & 0xc0) != 0x80)
				return false;
		i += l;
	}
	return true;
}

/* the whole path: a stored retrieve-conf as an HTTP answer, every device answers 200 to each MESSAGE until `pieces` were sent */
static void ff_run(struct ffix *f, int pieces)
{
	int i;

	spin(150);
	for (i = 0; i < pieces; i++) {
		dev_answer_last(f, 1, 200);
		spin(50);
	}
}

/* ------------------------------------------------------------------ */

static void t_captured_lan(void)
{
	struct ffix f;
	uint8_t conf[1024], resp[2048];
	size_t cn = hexv(V_RETRIEVE_CONF, conf, sizeof(conf));
	struct sip_msg m;
	struct mms_status st;
	struct mock_resp r;
	char h[400];
	struct mms_retrieve *rv = malloc(sizeof(*rv));
	size_t rn;

	ff_init(&f, NULL);
	dev_register(&f.w, 1);
	fakeep_clear(f.w.f);
	memset(&r, 0, sizeof(r));
	rn = http_ok(resp, sizeof(resp), 200, "application/vnd.wap.mms-message", conf, cn);
	r.d = resp; r.n = rn;
	mock_respond(&f.mn, &r);
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	ff_fetch(&f, "AvBt6f7q");
	ff_run(&f, 1);
	CHECK_EQ(dev_count(&f, 1), 1);
	CHECK(dev_parse(&f, 1, 0, &m));
	CHECK_EQ(mms_decode_retrieve(conf, cn, rv), 0);
	/* From: the sender's number; the headers; the body (the subject line, then the text part byte for byte) */
	CHECK(sip_hdr(&m, "From", 0) && strstr(sip_hdr(&m, "From", 0), "sip:114@") != NULL);
	CHECK_STR(sip_hdr(&m, "Content-Type", 0), "text/plain; charset=utf-8");
	CHECK_STR(sip_hdr(&m, "X-MMS", 0), "1");
	CHECK_STR(sip_hdr(&m, "X-MMS-Subject", 0), "[LG U+]");
	CHECK_STR(sip_hdr(&m, "X-MMS-Message-ID", 0), "AvBt6f7q");
	CHECK_STR(sip_hdr(&m, "X-SMS-Timestamp", 0), "2026-11-20T00:23:39+00:00");
	CHECK(!sip_hdr(&m, "X-MMS-Part", 0));		/* one MESSAGE: no part header, no marker */
	CHECK_EQ(m.body_len, 8 + rv->part[0].len);
	CHECK(!memcmp(m.body, "[LG U+]\n", 8)); CHECK(!memcmp(m.body + 8, rv->part[0].data, rv->part[0].len));
	CHECK_STR(sip_hdr(&m, "Request-Line", 0) ? "x" : "x", "x");
	if (getenv("T_PRINT")) {
		int i = find_sent(f.w.f, dev_ip(1), 5060, "MESSAGE", 0);

		printf("---- SIP MESSAGE to the LAN device ----\n%.*s\n----\n", (int)f.w.f->sent[i].len, (const char *)f.w.f->sent[i].data);
	}
	(void)h;
	sip_msg_free(&m);
	mms_get_status(f.m, &st);
	CHECK_EQ(st.delivered, 1); CHECK_EQ(st.retrieved, 1); CHECK_EQ(st.pending, 0); CHECK_EQ(f.mn.n_conn, 3);
	free(rv);
	ff_fini(&f);
}

static void tw_split(struct mms_cfg *c)
{
	c->text_split = 400;
}

static void t_split_lan(void)
{
	struct ffix f;
	struct pb p = { .n = 0 }, body = { .n = 0 }, e = { .n = 0 };
	uint8_t ct[8];
	size_t cl, total = 0;
	char text[4000];
	struct sip_msg m;
	int i, n;
	struct mms_status st;

	ff_init(&f, tw_split);
	dev_register(&f.w, 1);
	fakeep_clear(f.w.f);
	/* about 1900 bytes of text: lines of Korean and ASCII */
	text[0] = 0;
	for (i = 0; i < 80; i++) {
		char l[80];

		snprintf(l, sizeof(l), "줄 %02d: 한글 text line number %d\n", i, i);
		strcat(text, l);
	}
	cl = ct_wk_charset(ct, 0x03, 106);
	mp_entry(&e, ct, cl, NULL, 0, text, strlen(text));
	build_multipart(&body, 1, &e);
	cl = ct_wk(ct, 0x23);
	build_retrieve(&p, "SPL", 0x90, "01012345678/TYPE=PLMN", "long", 1795134000, ct, cl, body.d, body.n);
	ff_respond(&f, p.d, p.n);
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	ff_fetch(&f, "SPL");
	spin(150);
	/* one MESSAGE at a time, in order: the next goes out after the devices answered the previous one */
	CHECK_EQ(dev_count(&f, 1), 1);
	n = 1;
	for (;;) {
		char pre[16];
		size_t before = total;

		CHECK(dev_parse(&f, 1, n - 1, &m));
		snprintf(pre, sizeof(pre), "(%d/", n);
		CHECK(!strncmp((const char *)m.body, pre, strlen(pre)));
		CHECK(m.body_len <= 400);
		CHECK(utf8_ok((const char *)m.body, m.body_len));
		CHECK_STR(sip_hdr(&m, "X-MMS-Subject", 0), "long");
		{
			char want[24];

			snprintf(want, sizeof(want), "%d/", n);
			CHECK(sip_hdr(&m, "X-MMS-Part", 0) && !strncmp(sip_hdr(&m, "X-MMS-Part", 0), want, strlen(want)));
			CHECK_STR(sip_hdr(&m, "X-MMS", 0), "1");
			CHECK_STR(sip_hdr(&m, "X-MMS-Message-ID", 0), "SPL");
			CHECK(sip_hdr(&m, "X-SMS-Timestamp", 0) != NULL);
		}
		total += m.body_len;
		(void)before;
		sip_msg_free(&m);
		dev_answer_last(&f, 1, 200);
		spin(50);
		if (dev_count(&f, 1) == n)
			break;
		n++;
		CHECK(n < 20);
	}
	CHECK(n >= 5);
	CHECK(dev_parse(&f, 1, 0, &m));
	{
		char want[40];

		snprintf(want, sizeof(want), "(1/%d) [long]\n", n);
		CHECK(!strncmp((const char *)m.body, want, strlen(want)));
	}
	sip_msg_free(&m);
	CHECK(dev_parse(&f, 1, n - 1, &m));
	{
		char want[40];

		snprintf(want, sizeof(want), "(%d/%d) ", n, n);
		CHECK(!strncmp((const char *)m.body, want, strlen(want)));
		CHECK(strstr((const char *)m.body, "line number 79") != NULL);
	}
	sip_msg_free(&m);
	CHECK(total > 2500);
	mms_get_status(f.m, &st);
	CHECK_EQ(st.delivered, 1);
	ff_fini(&f);

	/* a device that refuses the first piece: the rest is not sent, the message counts as lost */
	ff_init(&f, tw_split);
	dev_register(&f.w, 1);
	fakeep_clear(f.w.f);
	ff_respond(&f, p.d, p.n);
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	ff_fetch(&f, "SPL");
	spin(150);
	dev_answer_last(&f, 1, 500);
	spin(50);
	CHECK_EQ(dev_count(&f, 1), 1);
	mms_get_status(f.m, &st);
	CHECK_EQ(st.delivered, 0); CHECK_EQ(st.lost_no_client, 1); CHECK_EQ(f.mn.n_conn, 3);
	ff_fini(&f);
}

static const char *find_dir(const char *root, char *out, size_t n)
{
	DIR *d = opendir(root);
	struct dirent *e;

	out[0] = 0;
	if (!d)
		return out;
	while ((e = readdir(d)))
		if (strlen(e->d_name) == 32) {
			snprintf(out, n, "%.32s", e->d_name);
			break;
		}
	closedir(d);
	return out;
}

static bool file_is(const char *path, const void *data, size_t n)
{
	FILE *fp = fopen(path, "r");
	uint8_t buf[4096];
	size_t k;

	if (!fp)
		return false;
	k = fread(buf, 1, sizeof(buf), fp);
	fclose(fp);
	return k == n && !memcmp(buf, data, n);
}

static void tw_url(struct mms_cfg *c)
{
	snprintf(c->url_base, sizeof(c->url_base), "http://router.lan/imsd-mms/");
}

static void t_attachments(void)
{
	static const char SMIL[] = "<smil><body><par><img src=\"cid:img1\"/><text src=\"t.txt\"/></par></body></smil>";
	static const uint8_t JPG[] = { 0xff, 0xd8, 0xff, 0xe0, 0, 16, 'J', 'F', 'I', 'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0xff, 0xd9 };
	struct ffix f;
	struct pb e = { .n = 0 }, body = { .n = 0 }, pdu = { .n = 0 };
	uint8_t ct[128], h[128];
	size_t cl, hl;
	struct sip_msg m;
	char dir[40], root[100], path[300], want[300];
	struct stat st;
	struct mms_status ms;

	/* multipart.related: SMIL + text + JPEG; the image is a link, the SMIL never shown */
	ff_init(&f, tw_url);
	dev_register(&f.w, 1);
	fakeep_clear(f.w.f);
	cl = ct_text(ct, "application/smil"); hl = ph_cid_loc(h, "smil", "smil.xml");
	mp_entry(&e, ct, cl, h, hl, SMIL, strlen(SMIL));
	cl = ct_wk_charset(ct, 0x03, 106); hl = ph_cid_loc(h, "txt", "t.txt");
	mp_entry(&e, ct, cl, h, hl, "Look at this", 12);
	cl = ct_wk(ct, 0x1e); hl = ph_cid_loc(h, "img1", "My Photo?.jpg");
	mp_entry(&e, ct, cl, h, hl, JPG, sizeof(JPG));
	build_multipart(&body, 3, &e);
	{
		uint8_t c[64];
		size_t k = 0;

		c[k++] = 2; c[k++] = 0xb3; c[k++] = 0x80;	/* multipart.related with a parameter we skip (q = 0) */
		build_retrieve(&pdu, "ATT1", 0x92, "+821012345678/TYPE=PLMN", "pic", 1795134000, c, 3, body.d, body.n);
	}
	ff_respond(&f, pdu.d, pdu.n);
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	ff_fetch(&f, "ATT1");
	ff_run(&f, 1);
	CHECK_EQ(dev_count(&f, 1), 1);
	snprintf(root, sizeof(root), "%s/m", f.dir);
	find_dir(root, dir, sizeof(dir));
	CHECK_EQ(strlen(dir), 32);
	snprintf(path, sizeof(path), "%s/%s/My_Photo_.jpg", root, dir);
	CHECK(file_is(path, JPG, sizeof(JPG)));
	snprintf(path, sizeof(path), "%s/index.html", root);
	CHECK(!stat(path, &st));
	CHECK(dev_parse(&f, 1, 0, &m));
	snprintf(want, sizeof(want), "[pic]\nLook at this\n\nMy_Photo_.jpg (image/jpeg, 22 B) http://router.lan/imsd-mms/%s/My_Photo_.jpg", dir);
	CHECK_EQ(m.body_len, strlen(want)); CHECK(m.body && !memcmp(m.body, want, strlen(want)));
	if (getenv("T_DEBUG")) {
		FILE *fp;
		uint8_t bb[64];
		size_t k;

		snprintf(path, sizeof(path), "%s/%s/My_Photo_.jpg", root, dir);
		fp = fopen(path, "r");
		k = fp ? fread(bb, 1, sizeof(bb), fp) : 0;
		printf("path=%s k=%zu\n want=<%s>\n got=<%.*s>\n", path, k, want, (int)m.body_len, (const char *)m.body);
		if (fp) fclose(fp);
	}
	CHECK(strstr((const char *)m.body, "smil") == NULL);
	CHECK_STR(sip_hdr(&m, "From", 0) ? "from" : "", "from");
	CHECK(strstr(sip_hdr(&m, "From", 0), "sip:+821012345678@") != NULL);
	sip_msg_free(&m);
	mms_get_status(f.m, &ms); CHECK_EQ(ms.store_messages, 1); CHECK_EQ(ms.store_bytes, sizeof(JPG));
	ff_fini(&f);

	/* multipart.mixed with two attachments, one named by a hostile Content-Disposition, the default URL base from the LAN address */
	ff_init(&f, NULL);
	dev_register(&f.w, 1);
	fakeep_clear(f.w.f);
	memset(&e, 0, sizeof(e)); memset(&body, 0, sizeof(body)); memset(&pdu, 0, sizeof(pdu));
	cl = ct_wk_charset(ct, 0x03, 106);
	mp_entry(&e, ct, cl, NULL, 0, "see files", 9);
	cl = ct_wk(ct, 0x1d); hl = ph_disp_file(h, "../../a b/c.gif");
	mp_entry(&e, ct, cl, h, hl, "GIF89a", 6);
	cl = ct_wk(ct, 0x1e);
	mp_entry(&e, ct, cl, NULL, 0, JPG, sizeof(JPG));
	build_multipart(&body, 3, &e);
	cl = ct_wk(ct, 0x23);
	build_retrieve(&pdu, "ATT2", 0x90, "01099998888", NULL, 1795134000, ct, cl, body.d, body.n);
	ff_respond(&f, pdu.d, pdu.n);
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	ff_fetch(&f, "ATT2");
	ff_run(&f, 1);
	snprintf(root, sizeof(root), "%s/m", f.dir);
	find_dir(root, dir, sizeof(dir));
	snprintf(path, sizeof(path), "%s/%s/c.gif", root, dir);
	CHECK(file_is(path, "GIF89a", 6));
	snprintf(path, sizeof(path), "%s/%s/part3.jpg", root, dir);
	CHECK(file_is(path, JPG, sizeof(JPG)));
	CHECK(dev_parse(&f, 1, 0, &m));
	snprintf(want, sizeof(want), "see files\n\nc.gif (image/gif, 6 B) http://192.168.68.1/imsd-mms/%s/c.gif\n"
		 "part3.jpg (image/jpeg, 22 B) http://192.168.68.1/imsd-mms/%s/part3.jpg", dir, dir);
	CHECK_EQ(m.body_len, strlen(want)); CHECK(m.body && !memcmp(m.body, want, strlen(want)));
	CHECK(sip_hdr(&m, "X-MMS-Subject", 0) == NULL);
	sip_msg_free(&m);
	ff_fini(&f);

	/* retention: two messages kept, the third evicts the first */
	{
		char first[40], second[40], third[40], d[40];
		int i;

		ff_init(&f, NULL);
		{
			struct mms_cfg c = f.cfg;

			c.keep_messages = 2;
			mms_set_cfg(f.m, &c);
		}
		dev_register(&f.w, 1);
		for (i = 0; i < 3; i++) {
			char tid[8];

			snprintf(tid, sizeof(tid), "R%d", i);
			memset(&e, 0, sizeof(e)); memset(&body, 0, sizeof(body)); memset(&pdu, 0, sizeof(pdu));
			cl = ct_wk(ct, 0x1e);
			mp_entry(&e, ct, cl, NULL, 0, JPG, sizeof(JPG));
			build_multipart(&body, 1, &e);
			cl = ct_wk(ct, 0x23);
			build_retrieve(&pdu, tid, 0x90, "1", NULL, 1795134000 + i, ct, cl, body.d, body.n);
			ff_respond(&f, pdu.d, pdu.n);
			mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
			mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
			ff_fetch(&f, tid);
			ff_run(&f, 1);
			snprintf(root, sizeof(root), "%s/m", f.dir);
			if (i == 0) {
				find_dir(root, first, sizeof(first));
			} else if (i == 1) {
				DIR *dd = opendir(root);
				struct dirent *de;

				second[0] = 0;
				while ((de = readdir(dd)))
					if (strlen(de->d_name) == 32 && strcmp(de->d_name, first))
						snprintf(second, sizeof(second), "%.32s", de->d_name);
				closedir(dd);
			}
		}
		{
			DIR *dd = opendir(root);
			struct dirent *de;
			int n = 0;

			third[0] = 0;
			while ((de = readdir(dd)))
				if (strlen(de->d_name) == 32) {
					n++;
					if (strcmp(de->d_name, first) && strcmp(de->d_name, second))
						snprintf(third, sizeof(third), "%.32s", de->d_name);
				}
			closedir(dd);
			CHECK_EQ(n, 2); CHECK_EQ(strlen(third), 32);
		}
		snprintf(d, sizeof(d), "%s", first);
		snprintf(path, sizeof(path), "%s/%s", root, d);
		CHECK(stat(path, &st) != 0);
		snprintf(path, sizeof(path), "%s/%s/part1.jpg", root, second);
		CHECK(!stat(path, &st));
		mms_get_status(f.m, &ms); CHECK_EQ(ms.store_messages, 2); CHECK_EQ(dev_count(&f, 1), 3);
		ff_fini(&f);
	}
}

static void t_text_variants(void)
{
	struct ffix f;
	struct pb e, body, pdu;
	uint8_t ct[64];
	size_t cl;
	struct sip_msg m;
	static const struct {
		const char *name;
		uint8_t ctype[8];
		size_t ctn;
		const char *data;
		size_t dn;
		const char *subject;
		const char *want;
		const char *from_user;
	} T[] = {
		/* EUC-KR text, subject not repeated */
		{ "EUCKR", { 3, 0x83, 0x81, 0xa6 }, 4, "\xc7\xd1\xb1\xdb \xc5\xd7\xbd\xba\xc6\xae", 11, "S", "[S]\n한글 테스트", "01011112222" },
		/* UTF-16BE text */
		{ "U16", { 3, 0x83, 0x81, 0x80 | 0x7f }, 4, "\xd5\x5c\xae\x00\x00\x20\x00\x41", 8, NULL, NULL, "01011112222" },
		/* HTML */
		{ "HTML", { 3, 0x82, 0x81, 0xea }, 4, "<p>Hi&nbsp;<b>there</b></p><p>2nd</p>", 37, NULL, "Hi there\n2nd", "01011112222" },
		/* the subject is the first line of the text: not repeated; an unwrapped subject is put in brackets when it differs */
		{ "SUB1", { 3, 0x83, 0x81, 0xea }, 4, "[Hi]\nbody", 9, "[Hi]", "[Hi]\nbody", "01011112222" },
		{ "SUB2", { 3, 0x83, 0x81, 0xea }, 4, "Hello\nbody", 10, "Hello", "Hello\nbody", "01011112222" },
		{ "SUB3", { 3, 0x83, 0x81, 0xea }, 4, "Other", 5, "Hello", "[Hello]\nOther", "01011112222" },
		/* a Korean subject: raw UTF-8 in X-MMS-Subject */
		{ "SUBK", { 3, 0x83, 0x81, 0xea }, 4, "\xeb\xb3\xb8\xeb\xac\xb8", 6, "한글 제목", "[한글 제목]\n본문", "01011112222" },
		/* a subject and no text at all */
		{ "SUB4", { 1, 0x80 | 0x1e }, 2, "\xff\xd8", 2, "Only subject", "[Only subject]\n\nattachment", "01011112222" },
	};
	size_t i;

	for (i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
		ff_init(&f, tw_url);
		dev_register(&f.w, 1);
		fakeep_clear(f.w.f);
		memset(&e, 0, sizeof(e)); memset(&body, 0, sizeof(body)); memset(&pdu, 0, sizeof(pdu));
		if (!strcmp(T[i].name, "U16")) {
			uint8_t c[8] = { 5, 0x83, 0x82, 0x08, 0x07, 0xf7 };	/* charset as long integer 1015 = 0x03f7 */

			c[0] = 5; c[1] = 0x83; c[2] = 0x81; c[3] = 0x02; c[4] = 0x03; c[5] = 0xf7;
			mp_entry(&e, c, 6, NULL, 0, T[i].data, T[i].dn);
		} else {
			mp_entry(&e, T[i].ctype, T[i].ctn, NULL, 0, T[i].data, T[i].dn);
		}
		build_multipart(&body, 1, &e);
		cl = ct_wk(ct, 0x23);
		build_retrieve(&pdu, T[i].name, 0x90, T[i].from_user, T[i].subject, 1795134000, ct, cl, body.d, body.n);
		ff_respond(&f, pdu.d, pdu.n);
		mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
		mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
		ff_fetch(&f, T[i].name);
		ff_run(&f, 1);
		CHECK_EQ(dev_count(&f, 1), 1);
		if (dev_parse(&f, 1, 0, &m)) {
			if (!strcmp(T[i].name, "U16")) {
				CHECK_EQ(m.body_len, strlen("한글 A")); CHECK(!memcmp(m.body, "한글 A", m.body_len));
			} else if (!strcmp(T[i].name, "SUB4")) {
				CHECK(!strncmp((const char *)m.body, "[Only subject]\n\npart1.jpg (image/jpeg, 2 B) http://router.lan/imsd-mms/", 62));
			} else {
				CHECK_EQ(m.body_len, strlen(T[i].want));
				CHECK(m.body && !memcmp(m.body, T[i].want, strlen(T[i].want)));
			}
			if (T[i].subject && strcmp(T[i].name, "SUB4")) {
				CHECK(sip_hdr(&m, "X-MMS-Subject", 0) != NULL);
				if (sip_hdr(&m, "X-MMS-Subject", 0))
					CHECK_STR(sip_hdr(&m, "X-MMS-Subject", 0), T[i].subject);
			}
			sip_msg_free(&m);
		} else {
			CHECK(0);
		}
		ff_fini(&f);
	}
}

static void t_senders(void)
{
	static const struct { const char *from; const char *user; const char *disp; } T[] = {
		{ "01012345678", "01012345678", NULL },
		{ "+821012345678", "+821012345678", NULL },
		{ "KT-Info", "alnum.KT-Info", "KT-Info" },
		{ "a@example.com", "alnum.a-example.com", "a@example.com" },
		{ "", "alnum.unknown", "unknown" },
	};
	size_t i;

	for (i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
		struct ffix f;
		struct pb e = { .n = 0 }, body = { .n = 0 }, pdu = { .n = 0 };
		uint8_t ct[8];
		size_t cl;
		struct sip_msg m;

		ff_init(&f, NULL);
		dev_register(&f.w, 1);
		fakeep_clear(f.w.f);
		cl = ct_wk_charset(ct, 0x03, 106);
		mp_entry(&e, ct, cl, NULL, 0, "x", 1);
		build_multipart(&body, 1, &e);
		cl = ct_wk(ct, 0x23);
		build_retrieve(&pdu, "S", 0x90, T[i].from[0] ? T[i].from : NULL, NULL, -1, ct, cl, body.d, body.n);
		ff_respond(&f, pdu.d, pdu.n);
		mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
		mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
		{
			char url[64];
			struct pb n = { .n = 0 }, p = { .n = 0 };

			snprintf(url, sizeof(url), "http://mmsc.test/?S");
			build_notif(&n, "S", 0x92, NULL, NULL, 10, -1, url);
			build_push(&p, n.d, n.n);
			mms_on_push(f.m, "x", 2948, p.d, p.n);
		}
		ff_run(&f, 1);
		CHECK(dev_parse(&f, 1, 0, &m));
		{
			char want[100];
			const char *from = sip_hdr(&m, "From", 0);

			snprintf(want, sizeof(want), "sip:%s@", T[i].user);
			CHECK(from && strstr(from, want) != NULL);
			if (T[i].disp)
				CHECK(from && strstr(from, T[i].disp) != NULL);
			CHECK(sip_hdr(&m, "X-SMS-Timestamp", 0) == NULL);	/* no Date in the PDU */
		}
		sip_msg_free(&m);
		ff_fini(&f);
	}
}

static void t_no_client(void)
{
	struct ffix f;
	uint8_t conf[1024], resp[2048];
	size_t cn = hexv(V_RETRIEVE_CONF, conf, sizeof(conf));
	struct mms_status st;

	/* nobody registered: lost (counted), the MMSC still gets NotifyResp and Acknowledge */
	ff_init(&f, NULL);
	ff_respond(&f, conf, cn);
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	ff_fetch(&f, "AvBt6f7q");
	spin(200);
	mms_get_status(f.m, &st);
	CHECK_EQ(st.retrieved, 1); CHECK_EQ(st.lost_no_client, 1); CHECK_EQ(st.delivered, 0); CHECK_EQ(f.mn.n_conn, 3);
	ff_fini(&f);

	/* the LAN side goes down while a delivery is in flight: aborted without a callback, no crash */
	ff_init(&f, tw_split);
	dev_register(&f.w, 1);
	ff_respond(&f, conf, cn);
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	ff_fetch(&f, "AvBt6f7q");
	spin(200);
	CHECK_EQ(dev_count(&f, 1), 1);		/* 441 bytes of text > 400: two pieces; the first is out, the device has not answered */
	mms_lan_set(f.ml, NULL);
	dev_answer_last(&f, 1, 200);
	spin(100);
	CHECK_EQ(dev_count(&f, 1), 1);		/* the second never goes out */
	(void)resp;
	ff_fini(&f);

	/* stop with everything in flight */
	ff_init(&f, NULL);
	dev_register(&f.w, 1);
	ff_respond(&f, conf, cn);
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	mock_respond(&f.mn, &(struct mock_resp){ .d = f.ok_empty, .n = f.ok_empty_n });
	ff_fetch(&f, "AvBt6f7q");
	spin(200);
	ff_fini(&f);
}

void test_mms_flow(void)
{
	t_captured_lan();
	t_split_lan();
	t_attachments();
	t_text_variants();
	t_senders();
	t_no_client();
}

/* ------------------------------------------------------------------ */
/* robustness                                                          */

static uint64_t rs = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(void)
{
	rs ^= rs << 13;
	rs ^= rs >> 7;
	rs ^= rs << 17;
	return (uint32_t)(rs >> 11);
}

static void decode_all(const uint8_t *d, size_t n)
{
	struct wsp_push p;
	struct mms_notif nf;
	static struct mms_retrieve rv;
	struct buf b;
	unsigned order[MMS_MAX_PARTS], i, k;

	if (!wsp_parse_push(d, n, &p) && p.body_len)
		(void)mms_decode_notification(p.body, p.body_len, &nf);
	(void)mms_decode_notification(d, n, &nf);
	if (!mms_decode_retrieve(d, n, &rv)) {
		k = mmsr_order(rv.part, rv.nparts, order);
		for (i = 0; i < k; i++) {
			const struct mms_part *pt = &rv.part[order[i]];

			CHECK(pt->data >= d && pt->data + pt->len <= d + n);	/* parts never point outside the PDU */
			if (mmsr_is_text(pt)) {
				buf_init(&b, 64 * 1024);
				mmsr_part_text(pt, &b);
				buf_free(&b);
			}
		}
	}
}

void test_mms_robust(void)
{
	uint8_t notif[200], conf[1024], syn[4096];
	size_t nn = hexv(V_NOTIF_PUSH, notif, sizeof(notif)), cn = hexv(V_RETRIEVE_CONF, conf, sizeof(conf)), sn, i, it;
	struct pb e = { .n = 0 }, body = { .n = 0 }, pdu = { .n = 0 };
	uint8_t ct[64], h[64];
	size_t cl, hl;
	static const uint8_t *vec[3];
	size_t vlen[3];
	uint8_t m[4096];

	cl = ct_text(ct, "application/smil"); hl = ph_cid_loc(h, "smil", "smil.xml");
	mp_entry(&e, ct, cl, h, hl, "<smil><par><img src=\"cid:i\"/></par></smil>", 43);
	cl = ct_wk(ct, 0x1e); hl = ph_cid_loc(h, "i", "i.jpg");
	mp_entry(&e, ct, cl, h, hl, "\xff\xd8\xff\xd9", 4);
	cl = ct_wk_charset(ct, 0x02, 106);
	mp_entry(&e, ct, cl, NULL, 0, "<b>x&amp;&#65;</b>", 18);
	build_multipart(&body, 3, &e);
	{
		uint8_t c[64];

		c[0] = 2; c[1] = 0xb3; c[2] = 0x80;
		build_retrieve(&pdu, "T", 0x92, "123/TYPE=PLMN", "subj", 1700000000, c, 3, body.d, body.n);
	}
	memcpy(syn, pdu.d, pdu.n);
	sn = pdu.n;
	vec[0] = notif; vlen[0] = nn;
	vec[1] = conf; vlen[1] = cn;
	vec[2] = syn; vlen[2] = sn;
	/* the three vectors decode cleanly */
	CHECK_EQ(nn, 127); CHECK_EQ(cn, 553); CHECK(sn > 50);
	decode_all(notif, nn); decode_all(conf, cn); decode_all(syn, sn);
	/* every truncation */
	for (it = 0; it < 3; it++)
		for (i = 0; i <= vlen[it]; i++)
			decode_all(vec[it], i);
	/* every single byte set to a few special values */
	for (it = 0; it < 3; it++) {
		for (i = 0; i < vlen[it]; i++) {
			static const uint8_t V[] = { 0x00, 0x1f, 0x7f, 0x80, 0xff, 0x22 };
			size_t k;

			for (k = 0; k < sizeof(V); k++) {
				memcpy(m, vec[it], vlen[it]);
				m[i] = V[k];
				decode_all(m, vlen[it]);
			}
		}
	}
	/* random mutations: 1..4 byte changes, insertions, truncations */
	for (i = 0; i < 40000; i++) {
		size_t n, k, nm;

		it = rnd() % 3;
		n = vlen[it];
		memcpy(m, vec[it], n);
		nm = 1 + rnd() % 4;
		for (k = 0; k < nm; k++)
			m[rnd() % n] = (uint8_t)rnd();
		if (rnd() % 4 == 0)
			n = rnd() % (n + 1);
		decode_all(m, n);
	}
	/* random garbage */
	for (i = 0; i < 5000; i++) {
		size_t n = rnd() % 300, k;

		for (k = 0; k < n; k++)
			m[k] = (uint8_t)rnd();
		if (n > 2 && (rnd() & 1)) {
			m[0] = 0x8c;
			m[1] = (rnd() & 1) ? 0x82 : 0x84;
		}
		decode_all(m, n);
	}
	/* HTML stripping on random tag soup */
	for (i = 0; i < 3000; i++) {
		static const char A[] = "<>&#;x/ !-abp1Xscript style\"'=\n";
		char s[200];
		struct buf b;
		size_t n = rnd() % 150, k;

		for (k = 0; k < n; k++)
			s[k] = A[rnd() % (sizeof(A) - 1)];
		s[n] = 0;
		buf_init(&b, 4096);
		mmsr_html_to_text(s, &b);
		buf_free(&b);
	}
	/* the manager given every truncation of a real push: nothing queued from a broken one, never a crash */
	{
		struct mms_ops ops;
		struct mms_cfg cfg;
		struct mms_link link;
		struct mocknet mn;
		struct mms *mgr;
		struct mms_status st;

		evfake_reset();
		mock_init(&mn);
		memset(&link, 0, sizeof(link));
		mms_cfg_defaults(&cfg);
		memset(&ops, 0, sizeof(ops));
		ops.net = &mn.ops;
		mgr = mms_new(&cfg, &ops);
		for (i = 0; i < nn; i++)
			mms_on_push(mgr, "x", 2948, notif, i);
		mms_get_status(mgr, &st);
		CHECK(st.notifications <= 8);
		for (i = 0; i < 3000; i++) {
			size_t n = nn, k;

			memcpy(m, notif, n);
			for (k = 0; k < 1 + rnd() % 3; k++)
				m[rnd() % n] = (uint8_t)rnd();
			mms_on_push(mgr, "x", 2948, m, n);
		}
		mms_free(mgr);
		mock_free(&mn);
		CHECK_EQ(evfake_armed_timers(), 0);
	}
	/* the DNS parser on mutated answers */
	{
		uint8_t q[100], r[500];
		size_t ql = dns_build_query("a.test", 28, 9, q, sizeof(q)), rl;
		uint8_t a6[16] = { 0x20, 1 };
		struct dns_rr_spec rr[2] = { { .type = 5, .ttl = 5, .cname_target = "b.test", .owner_ref = -1 },
					     { .type = 28, .ttl = 5, .rdata = a6, .rdlen = 16, .owner_ref = 0 } };
		struct dns_answer a;

		rl = dns_response(q, ql, 0, false, rr, 2, r, sizeof(r));
		for (i = 0; i <= rl; i++)
			(void)dns_parse_answer(r, i, 9, "a.test", 28, &a);
		for (i = 0; i < 20000; i++) {
			size_t k;

			memcpy(m, r, rl);
			for (k = 0; k < 1 + rnd() % 4; k++)
				m[rnd() % rl] = (uint8_t)rnd();
			(void)dns_parse_answer(m, rl, 9, "a.test", 28, &a);
		}
	}
}
