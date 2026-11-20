/* SPDX-License-Identifier: GPL-2.0-or-later */
/* WSP / MMS PDU decoding of the captured vectors and synthetic PDUs, text rendering, the attachment store. */
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "t_common.h"
#include "t_vectors.h"
#include "mmspdu.h"
#include "mmsrender.h"
#include "mmsstore.h"
#include "wsp.h"

/* ------------------------------------------------------------------ */

static void t_primitives(void)
{
	struct wsp_rd r;
	uint32_t v;
	uint64_t x;
	size_t l;
	char t[16];
	bool tr;
	const uint8_t uv1[] = { 0x7f }, uv2[] = { 0x81, 0x00 }, uv3[] = { 0xc0, 0x80, 0x00 }, uv_bad[] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 };
	const uint8_t uv_big[] = { 0x8f, 0xff, 0xff, 0xff, 0x7f }, uv_big2[] = { 0x90, 0x80, 0x80, 0x80, 0x00 }, uv_trunc[] = { 0x81 };

	wsp_rd_init(&r, uv1, sizeof(uv1)); CHECK_EQ(wsp_uintvar(&r, &v), 0); CHECK_EQ(v, 127);
	wsp_rd_init(&r, uv2, sizeof(uv2)); CHECK_EQ(wsp_uintvar(&r, &v), 0); CHECK_EQ(v, 128);
	wsp_rd_init(&r, uv3, sizeof(uv3)); CHECK_EQ(wsp_uintvar(&r, &v), 0); CHECK_EQ(v, 0x100000);
	wsp_rd_init(&r, uv_bad, sizeof(uv_bad)); CHECK_EQ(wsp_uintvar(&r, &v), -1);
	wsp_rd_init(&r, uv_big, sizeof(uv_big)); CHECK_EQ(wsp_uintvar(&r, &v), 0); CHECK_EQ(v, 0xffffffffu);
	wsp_rd_init(&r, uv_big2, sizeof(uv_big2)); CHECK_EQ(wsp_uintvar(&r, &v), -1);
	wsp_rd_init(&r, uv_trunc, sizeof(uv_trunc)); CHECK_EQ(wsp_uintvar(&r, &v), -1);
	wsp_rd_init(&r, NULL, 0); CHECK_EQ(wsp_uintvar(&r, &v), -1);

	{
		const uint8_t vl1[] = { 3, 'a', 'b', 'c' }, vl2[] = { 31, 2, 'a', 'b' }, vl3[] = { 5, 'a' }, vl4[] = { 0x80 };

		wsp_rd_init(&r, vl1, sizeof(vl1)); CHECK_EQ(wsp_value_length(&r, &l), 0); CHECK_EQ(l, 3);
		wsp_rd_init(&r, vl2, sizeof(vl2)); CHECK_EQ(wsp_value_length(&r, &l), 0); CHECK_EQ(l, 2);
		wsp_rd_init(&r, vl3, sizeof(vl3)); CHECK_EQ(wsp_value_length(&r, &l), -1);	/* longer than what is left */
		wsp_rd_init(&r, vl4, sizeof(vl4)); CHECK_EQ(wsp_value_length(&r, &l), -1);
	}
	{
		const uint8_t i1[] = { 0x85 }, i2[] = { 2, 0x01, 0xf0 }, i3[] = { 0 }, i4[] = { 9, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, i5[] = { 3, 1 };

		wsp_rd_init(&r, i1, sizeof(i1)); CHECK_EQ(wsp_integer(&r, &x), 0); CHECK_EQ(x, 5);
		wsp_rd_init(&r, i2, sizeof(i2)); CHECK_EQ(wsp_integer(&r, &x), 0); CHECK_EQ(x, 496);
		wsp_rd_init(&r, i3, sizeof(i3)); CHECK_EQ(wsp_integer(&r, &x), -1);
		wsp_rd_init(&r, i4, sizeof(i4)); CHECK_EQ(wsp_integer(&r, &x), -1);
		wsp_rd_init(&r, i5, sizeof(i5)); CHECK_EQ(wsp_integer(&r, &x), -1);
	}
	{
		const uint8_t t1[] = { 'h', 'i', 0, 'x' }, t2[] = { 0x7f, 0xc3, 0xa9, 0 }, t3[] = { 'a', 'b' }, t4[] = { '"', 'q', 0 },
			      t5[] = { 'a', 'b', 'c', 'd', 'e', 'f', 0 };

		wsp_rd_init(&r, t1, sizeof(t1)); CHECK_EQ(wsp_text(&r, t, sizeof(t), &tr), 0); CHECK_STR(t, "hi"); CHECK_EQ(r.pos, 3); CHECK(!tr);
		wsp_rd_init(&r, t2, sizeof(t2)); CHECK_EQ(wsp_text(&r, t, sizeof(t), &tr), 0); CHECK_STR(t, "\xc3\xa9");
		wsp_rd_init(&r, t3, sizeof(t3)); CHECK_EQ(wsp_text(&r, t, sizeof(t), &tr), -1);
		wsp_rd_init(&r, t4, sizeof(t4)); CHECK_EQ(wsp_text(&r, t, sizeof(t), &tr), 0); CHECK_STR(t, "q");
		wsp_rd_init(&r, t5, sizeof(t5)); CHECK_EQ(wsp_text(&r, t, 4, &tr), 0); CHECK_STR(t, "abc"); CHECK(tr); CHECK_EQ(r.pos, 7);
	}
	{	/* Field-value skipping: short-length, length-quote, text, short integer */
		const uint8_t s1[] = { 2, 9, 9, 0xaa }, s2[] = { 31, 3, 1, 2, 3, 0xaa }, s3[] = { 'a', 'b', 0, 0xaa }, s4[] = { 0x83, 0xaa },
			      s5[] = { 5, 1 };

		wsp_rd_init(&r, s1, sizeof(s1)); CHECK_EQ(wsp_skip_value(&r), 0); CHECK_EQ(r.pos, 3);
		wsp_rd_init(&r, s2, sizeof(s2)); CHECK_EQ(wsp_skip_value(&r), 0); CHECK_EQ(r.pos, 5);
		wsp_rd_init(&r, s3, sizeof(s3)); CHECK_EQ(wsp_skip_value(&r), 0); CHECK_EQ(r.pos, 3);
		wsp_rd_init(&r, s4, sizeof(s4)); CHECK_EQ(wsp_skip_value(&r), 0); CHECK_EQ(r.pos, 1);
		wsp_rd_init(&r, s5, sizeof(s5)); CHECK_EQ(wsp_skip_value(&r), -1);
	}
	{
		char b[40];

		CHECK_STR(wsp_media_name(0x03, b, sizeof(b)), "text/plain");
		CHECK_STR(wsp_media_name(0x1e, b, sizeof(b)), "image/jpeg");
		CHECK_STR(wsp_media_name(0x1d, b, sizeof(b)), "image/gif");
		CHECK_STR(wsp_media_name(0x20, b, sizeof(b)), "image/png");
		CHECK_STR(wsp_media_name(0x23, b, sizeof(b)), "application/vnd.wap.multipart.mixed");
		CHECK_STR(wsp_media_name(0x33, b, sizeof(b)), "application/vnd.wap.multipart.related");
		CHECK_STR(wsp_media_name(0x26, b, sizeof(b)), "application/vnd.wap.multipart.alternative");
		CHECK_STR(wsp_media_name(0x3e, b, sizeof(b)), "application/vnd.wap.mms-message");
		CHECK_STR(wsp_media_name(0x02, b, sizeof(b)), "text/html");
		CHECK_STR(wsp_media_name(0x7e, b, sizeof(b)), "application/x-wap-7e");
		CHECK_STR(wsp_charset_name(106), "utf-8");
		CHECK(wsp_charset_name(9999) == NULL);
	}
}

static void t_charsets(void)
{
	char o[64];
	size_t n;

	/* EUC-KR "한글 OK" */
	n = wsp_to_utf8(38, (const uint8_t *)"\xc7\xd1\xb1\xdb OK", 7, o, sizeof(o)); CHECK_STR(o, "한글 OK"); CHECK_EQ(n, strlen("한글 OK"));
	n = wsp_to_utf8(36, (const uint8_t *)"\xb0\xa1", 2, o, sizeof(o)); CHECK_STR(o, "가"); (void)n;
	/* UCS-2 / UTF-16 big endian, little endian with a BOM, surrogate pair */
	n = wsp_to_utf8(1000, (const uint8_t *)"\xd5\x5c\xae\x00\x00\x41", 6, o, sizeof(o)); CHECK_STR(o, "한글A");
	n = wsp_to_utf8(1015, (const uint8_t *)"\xff\xfe\x41\x00\x00\xac", 6, o, sizeof(o)); CHECK_STR(o, "A가");
	n = wsp_to_utf8(1015, (const uint8_t *)"\xfe\xff\x00\x41\xd8\x3d\xde\x00", 8, o, sizeof(o)); CHECK_STR(o, "A\xf0\x9f\x98\x80");
	n = wsp_to_utf8(1013, (const uint8_t *)"\x00\x42\xd8\x3d", 4, o, sizeof(o)); CHECK_STR(o, "B\xef\xbf\xbd");	/* lone surrogate */
	n = wsp_to_utf8(1014, (const uint8_t *)"\x43\x00", 2, o, sizeof(o)); CHECK_STR(o, "C");
	/* Latin-1, ASCII, invalid UTF-8, no charset, NUL dropped, unknown charset treated as UTF-8 */
	n = wsp_to_utf8(4, (const uint8_t *)"caf\xe9", 4, o, sizeof(o)); CHECK_STR(o, "caf\xc3\xa9");
	n = wsp_to_utf8(3, (const uint8_t *)"a\xe9z", 3, o, sizeof(o)); CHECK_STR(o, "a\xef\xbf\xbdz");
	n = wsp_to_utf8(106, (const uint8_t *)"a\xffz", 3, o, sizeof(o)); CHECK_STR(o, "a\xef\xbf\xbdz");
	n = wsp_to_utf8(0, (const uint8_t *)"a\0b", 3, o, sizeof(o)); CHECK_STR(o, "ab");
	n = wsp_to_utf8(4242, (const uint8_t *)"hi", 2, o, sizeof(o)); CHECK_STR(o, "hi");
	/* capacity: cut on a character boundary */
	n = wsp_to_utf8(106, (const uint8_t *)"가나다", 9, o, 8); CHECK_STR(o, "가나"); CHECK_EQ(n, 6);
	n = wsp_to_utf8(38, (const uint8_t *)"\xb0\xa1\xb0\xa2\xb0\xa3", 6, o, 8); CHECK(strlen(o) <= 7);
	CHECK_EQ(wsp_to_utf8(106, (const uint8_t *)"x", 1, o, 0), 0);
	(void)n;
}

static void t_real_notification(void)
{
	uint8_t d[256];
	size_t n = hexv(V_NOTIF_PUSH, d, sizeof(d));
	struct wsp_push p;
	struct mms_notif nf;

	CHECK_EQ(n, 127);
	CHECK_EQ(wsp_parse_push(d, n, &p), 0);
	CHECK_EQ(p.tid, 0); CHECK_EQ(p.pdu_type, 6);
	CHECK_STR(p.ct.type, "application/vnd.wap.mms-message");
	CHECK(p.has_app_id); CHECK_STR(p.app_id, "x-wap-application:mms.ua");
	CHECK_EQ(p.body_len, 127 - 3 - 36);
	CHECK_EQ(mms_decode_notification(p.body, p.body_len, &nf), 0);
	CHECK_STR(nf.tid, "AvBt6f7q");
	CHECK_EQ(nf.version, MMS_VERSION_1_2);
	CHECK_EQ(nf.msg_class, 0);
	CHECK(nf.has_size); CHECK_EQ(nf.size, 496);
	CHECK(nf.has_expiry); CHECK(nf.expiry_relative); CHECK_EQ(nf.expiry, 0x03f1f4);
	CHECK_STR(nf.location, "http://omammsc.uplus.co.kr:9095/?AvBt6f7q");
	CHECK_STR(nf.from, "114");
	CHECK_STR(nf.subject, "[LG U+]");
	CHECK_EQ(nf.delivery_report, -1);
	/* the same PDU without the WSP header and as a bare body */
	CHECK_EQ(mms_decode_notification(d + 39, n - 39, &nf), 0);
}

static void t_real_retrieve(void)
{
	static uint8_t d[1024];
	size_t n = hexv(V_RETRIEVE_CONF, d, sizeof(d));
	struct mms_retrieve *r = malloc(sizeof(*r));

	CHECK_EQ(n, 553);
	CHECK_EQ(mms_decode_retrieve(d, n, r), 0);
	CHECK_STR(r->tid, "AvBt6f7q"); CHECK(r->has_tid);
	CHECK_EQ(r->version, MMS_VERSION_1_0);
	CHECK_STR(r->message_id, "AvBt6f7q");
	CHECK(r->has_date); CHECK_EQ(r->date, 1795134219);
	CHECK_STR(r->from, "114"); CHECK(!r->from_hidden);
	CHECK_EQ(r->n_to, 1); CHECK_STR(r->to[0], "01051226862"); CHECK_EQ(r->n_cc, 0);
	CHECK_STR(r->subject, "[LG U+]");
	CHECK_EQ(r->delivery_report, 0); CHECK_EQ(r->read_report, 0); CHECK_EQ(r->priority, -1); CHECK_EQ(r->retrieve_status, -1);
	CHECK_STR(r->ct.type, "application/vnd.wap.multipart.mixed");
	CHECK(r->multipart);
	CHECK_EQ(r->nparts, 1); CHECK_EQ(r->parts_dropped, 0);
	CHECK_STR(r->part[0].type, "text/plain"); CHECK_EQ(r->part[0].charset, 106);
	CHECK_STR(r->part[0].content_id, "LGTSMS123"); CHECK_STR(r->part[0].location, "LGTSMS123");
	CHECK_EQ(r->part[0].len, 433); CHECK_EQ(r->part[0].disposition, -1);
	{
		static const char PRE[] = "[Web\xeb\xb0\x9c\xec\x8b\xa0]\n[LG U+] \xeb\xb3\xb4\xec\x9d\xb4\xeb\x8a\x94 ARS";

		CHECK(!memcmp(r->part[0].data, PRE, sizeof(PRE) - 1));
	}
	CHECK(!memcmp(r->part[0].data + 433 - 4, "\xeb\x8b\xa4.", 4));
	CHECK_EQ(r->part[0].data + r->part[0].len, d + n);
	{
		struct buf b;

		buf_init(&b, 0);
		mmsr_part_text(&r->part[0], &b);
		CHECK(!strncmp(buf_cstr(&b), "[Web발신]\n[LG U+] 보이는 ARS 연결 안내", strlen("[Web발신]\n[LG U+] 보이는 ARS 연결 안내")));
		CHECK(!strcmp(buf_cstr(&b) + b.len - strlen("감사합니다."), "감사합니다."));
		buf_free(&b);
	}
	/* a truncated body: one byte short of the data is a decode error (the part claims 433 bytes) */
	CHECK_EQ(mms_decode_retrieve(d, n - 1, r), -1);
	free(r);
}

static void t_encoders(void)
{
	uint8_t o[64];
	size_t l = mms_encode_notifyresp("AvBt6f7q", MMS_VERSION_1_2, MMS_ST_RETRIEVED, o, sizeof(o));
	static const uint8_t EXP[] = { 0x8c, 0x83, 0x98, 'A', 'v', 'B', 't', '6', 'f', '7', 'q', 0, 0x8d, 0x92, 0x95, 0x81 };
	static const uint8_t EXP_ACK[] = { 0x8c, 0x85, 0x98, 'A', 'v', 'B', 't', '6', 'f', '7', 'q', 0, 0x8d, 0x90 };

	CHECK_EQ(l, sizeof(EXP)); CHECK(!memcmp(o, EXP, sizeof(EXP)));
	l = mms_encode_acknowledge("AvBt6f7q", MMS_VERSION_1_0, o, sizeof(o));
	CHECK_EQ(l, sizeof(EXP_ACK)); CHECK(!memcmp(o, EXP_ACK, sizeof(EXP_ACK)));
	CHECK_EQ(mms_encode_notifyresp("AvBt6f7q", 0, MMS_ST_REJECTED, o, sizeof(o)), 16); CHECK_EQ(o[13], 0x92); CHECK_EQ(o[15], 0x82);
	CHECK_EQ(mms_encode_notifyresp("AvBt6f7q", 0, MMS_ST_REJECTED, o, 10), 0);
	CHECK_EQ(mms_encode_acknowledge("AvBt6f7q", 0, o, 10), 0);
}

static void t_addresses(void)
{
	char o[64];

	mms_clean_address("+821012345678/TYPE=PLMN", o, sizeof(o)); CHECK_STR(o, "+821012345678");
	mms_clean_address("01012345678/type=plmn", o, sizeof(o)); CHECK_STR(o, "01012345678");
	mms_clean_address("someone@example.com", o, sizeof(o)); CHECK_STR(o, "someone@example.com");
	mms_clean_address("1.2.3.4/TYPE=IPV4", o, sizeof(o)); CHECK_STR(o, "1.2.3.4");
	mms_clean_address("0123456789", o, 5); CHECK_STR(o, "0123");
}

/* ---- synthetic multipart: related with SMIL + text + JPEG; mixed with attachments ---- */

static void t_synthetic(void)
{
	static const char SMIL[] = "<smil><head><layout/></head><body><par><img src=\"cid:img1\"/><text src=\"t.txt\"/></par></body></smil>";
	static const uint8_t JPG[] = { 0xff, 0xd8, 0xff, 0xe0, 0, 16, 'J', 'F', 'I', 'F', 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0xff, 0xd9 };
	struct pb e = { .n = 0 }, body = { .n = 0 }, pdu = { .n = 0 };
	uint8_t ct[64], h[128];
	size_t cl, hl;
	struct mms_retrieve *r = malloc(sizeof(*r));
	unsigned order[8], k;
	/* the root part is SMIL (text form), then the text (text/plain, UTF-8 via token form), then the JPEG */

	cl = ct_text(ct, "application/smil");
	hl = ph_cid_loc(h, "smil", "smil.xml");
	mp_entry(&e, ct, cl, h, hl, SMIL, strlen(SMIL));
	cl = ct_wk_charset(ct, 0x03, 106);
	hl = ph_cid_loc(h, "txt", "t.txt");
	mp_entry(&e, ct, cl, h, hl, "hello", 5);
	cl = ct_wk(ct, 0x1e);
	hl = ph_cid_loc(h, "img1", "photo.jpg");
	mp_entry(&e, ct, cl, h, hl, JPG, sizeof(JPG));
	build_multipart(&body, 3, &e);
	{	/* Content-Type multipart/related with start and type parameters (typed: start 0x19? use 0x0A text, type 0x09 text) */
		uint8_t c[128];
		size_t k2 = 0;
		const char *start = "<smil>";

		c[k2++] = (uint8_t)(1 + 1 + strlen(start) + 1 + 1 + 17);
		c[k2++] = 0xb3;			/* application/vnd.wap.multipart.related */
		c[k2++] = 0x8a;			/* start (0x0A, Text-string) */
		memcpy(c + k2, start, strlen(start) + 1);
		k2 += strlen(start) + 1;
		c[k2++] = 0x89;			/* type (0x09, constrained media) */
		memcpy(c + k2, "application/smil", 17);
		k2 += 17;
		build_retrieve(&pdu, "T1", 0x92, "+821012345678/TYPE=PLMN", "pic", 1700000000, c, k2, body.d, body.n);
	}
	CHECK_EQ(mms_decode_retrieve(pdu.d, pdu.n, r), 0);
	CHECK_STR(r->ct.type, "application/vnd.wap.multipart.related"); CHECK_STR(r->ct.start, "<smil>"); CHECK_STR(r->ct.type_param, "application/smil");
	CHECK_STR(r->from, "+821012345678"); CHECK_STR(r->subject, "pic"); CHECK_EQ(r->date, 1700000000); CHECK_EQ(r->nparts, 3);
	CHECK_STR(r->part[0].type, "application/smil"); CHECK_STR(r->part[0].content_id, "smil");
	CHECK_STR(r->part[1].type, "text/plain"); CHECK_EQ(r->part[1].charset, 106);
	CHECK_STR(r->part[2].type, "image/jpeg"); CHECK_STR(r->part[2].location, "photo.jpg"); CHECK_EQ(r->part[2].len, sizeof(JPG));
	CHECK(!memcmp(r->part[2].data, JPG, sizeof(JPG)));
	/* SMIL order: the image (cid:img1) before the text (t.txt); the SMIL part itself left out */
	k = mmsr_order(r->part, r->nparts, order);
	CHECK_EQ(k, 2); CHECK_EQ(order[0], 2); CHECK_EQ(order[1], 1);

	/* multipart.mixed (0x23), two attachments with Content-Disposition filenames, one with a name parameter */
	memset(&e, 0, sizeof(e)); memset(&body, 0, sizeof(body)); memset(&pdu, 0, sizeof(pdu));
	cl = ct_wk_charset(ct, 0x03, 106);
	mp_entry(&e, ct, cl, NULL, 0, "text part", 9);
	cl = ct_wk(ct, 0x1d);				/* image/gif */
	hl = ph_disp_file(h, "a b/../c.gif");
	mp_entry(&e, ct, cl, h, hl, "GIF89a", 6);
	{
		static const uint8_t c[] = { 8, 0xc4, 0x97, 'n', '.', 'b', 'i', 'n', 0 };	/* any well-known type + name parameter (0x17) */

		mp_entry(&e, c, sizeof(c), NULL, 0, "\x01\x02\x03", 3);
	}
	build_multipart(&body, 3, &e);
	cl = ct_wk(ct, 0x23);
	build_retrieve(&pdu, NULL, 0x90, "alice@example.com", NULL, -1, ct, cl, body.d, body.n);
	CHECK_EQ(mms_decode_retrieve(pdu.d, pdu.n, r), 0);
	CHECK(!r->has_tid); CHECK(!r->has_date); CHECK_STR(r->from, "alice@example.com"); CHECK_EQ(r->nparts, 3);
	CHECK_STR(r->ct.type, "application/vnd.wap.multipart.mixed");
	CHECK_STR(r->part[1].type, "image/gif"); CHECK_EQ(r->part[1].disposition, 1); CHECK_STR(r->part[1].filename, "a b/../c.gif");
	CHECK_STR(r->part[2].type, "application/vnd.syncml.notification"); CHECK_STR(r->part[2].filename, "n.bin");
	k = mmsr_order(r->part, r->nparts, order);
	CHECK_EQ(k, 3); CHECK_EQ(order[0], 0); CHECK_EQ(order[1], 1); CHECK_EQ(order[2], 2);

	/* a single body without multipart (text/plain; charset=EUC-KR as a token-text media with a text charset parameter) */
	memset(&pdu, 0, sizeof(pdu));
	{
		static const uint8_t c[] = { 5, 0x83, 0x81, 0x80 | 38, 0x97, 0x00 };	/* text/plain; charset=EUC-KR; name (no value) */

		build_retrieve(&pdu, "T2", 0x92, "123", NULL, 1700000001, c, sizeof(c), "\xc7\xd1\xb1\xdb", 4);
	}
	CHECK_EQ(mms_decode_retrieve(pdu.d, pdu.n, r), 0);
	CHECK(!r->multipart); CHECK_EQ(r->nparts, 1); CHECK_STR(r->part[0].type, "text/plain"); CHECK_EQ(r->part[0].charset, 38);
	CHECK_EQ(r->part[0].len, 4);
	{
		struct buf b;

		buf_init(&b, 0);
		mmsr_part_text(&r->part[0], &b);
		CHECK_STR(buf_cstr(&b), "한글");
		buf_free(&b);
	}
	/* untyped parameters in the text form: text/plain;charset=utf-16;name=x.txt */
	memset(&pdu, 0, sizeof(pdu));
	{
		uint8_t c[128];
		size_t k2 = 0;
		const char *s = "text/plain";

		c[k2++] = 0;
		memcpy(c + k2, s, strlen(s) + 1); k2 += strlen(s) + 1;
		memcpy(c + k2, "charset", 8); k2 += 8;
		memcpy(c + k2, "utf-16", 7); k2 += 7;
		memcpy(c + k2, "name", 5); k2 += 5;
		memcpy(c + k2, "x.txt", 6); k2 += 6;
		{	/* the value is longer than 30 bytes: Length-quote + uintvar */
			uint8_t c2[130];

			c2[0] = 31;
			c2[1] = (uint8_t)(k2 - 1);
			memcpy(c2 + 2, c + 1, k2 - 1);
			build_retrieve(&pdu, "T3", 0x92, "123", NULL, 1700000001, c2, k2 + 1, "\x00\x41", 2);
		}
	}
	CHECK_EQ(mms_decode_retrieve(pdu.d, pdu.n, r), 0);
	CHECK_STR(r->part[0].type, "text/plain"); CHECK_EQ(r->part[0].charset, 1015); CHECK_STR(r->part[0].filename, "x.txt");
	free(r);
}

static void t_notif_variants(void)
{
	struct pb p = { .n = 0 };
	struct mms_notif nf;
	uint8_t d[512];

	build_notif(&p, "TID", MMS_VERSION_1_2, "+821012345678/TYPE=PLMN", "제목", 70000, 3600, "http://mmsc.example:8080/m?id=1");
	CHECK_EQ(mms_decode_notification(p.d, p.n, &nf), 0);
	CHECK_STR(nf.from, "+821012345678"); CHECK_STR(nf.subject, "제목"); CHECK_EQ(nf.size, 70000); CHECK_EQ(nf.expiry, 3600);
	/* absolute expiry */
	{
		uint8_t pdu[] = { 0x8c, 0x82, 0x98, 'A', 0, 0x83, 'h', 't', 't', 'p', ':', '/', '/', 'x', 0, 0x88, 6, 0x80, 4, 0x6a, 0xff, 0x93, 0x0b };

		CHECK_EQ(mms_decode_notification(pdu, sizeof(pdu), &nf), 0);
		CHECK(nf.has_expiry); CHECK(!nf.expiry_relative); CHECK_EQ(nf.expiry, 0x6aff930b);
		CHECK_EQ(nf.version, 0); CHECK(!nf.has_size); CHECK_STR(nf.from, "");
	}
	/* the encoder of the gateway's own announcements: long / non-ASCII subject, odd sizes, no From, cap checks */
	{
		uint8_t out[600];
		char sub[121];
		size_t n, i;

		for (i = 0; i < 40; i++)
			memcpy(sub + i * 3, "한", 3);
		sub[120] = 0;
		n = mms_encode_notification("T1", MMS_VERSION_1_2, "+821012345678/TYPE=PLMN", sub, 0x1234567, 1795134300, "http://192.168.68.1:8090/mms/sent/abc", out, sizeof(out));
		CHECK(n > 0);
		CHECK_EQ(mms_decode_notification(out, n, &nf), 0);
		CHECK_STR(nf.tid, "T1"); CHECK_STR(nf.from, "+821012345678"); CHECK_STR(nf.subject, sub); CHECK_EQ(nf.size, 0x1234567);
		CHECK(nf.has_expiry && !nf.expiry_relative && nf.expiry == 1795134300); CHECK_EQ(nf.msg_class, 0);
		CHECK_STR(nf.location, "http://192.168.68.1:8090/mms/sent/abc");
		CHECK_EQ(mms_encode_notification("T1", 0, NULL, NULL, 0, 0, "http://x", out, sizeof(out)) > 0, 1);
		CHECK_EQ(mms_decode_notification(out, mms_encode_notification("T1", 0, NULL, NULL, 0, 0, "http://x", out, sizeof(out)), &nf), 0);
		CHECK_EQ(nf.version, MMS_VERSION_1_2); CHECK(!nf.has_expiry); CHECK_STR(nf.from, ""); CHECK_EQ(nf.size, 0);
		CHECK_EQ(mms_encode_notification("T1", 0, NULL, sub, 1, 1, "http://x", out, 60), 0);	/* does not fit */
		CHECK_EQ(mms_encode_notification("", 0, NULL, NULL, 1, 0, "http://x", out, sizeof(out)), 0);
	}
	/* not a notification / missing fields */
	{
		uint8_t no_tid[] = { 0x8c, 0x82, 0x83, 'h', 0 }, no_loc[] = { 0x8c, 0x82, 0x98, 'A', 0 }, wrong[] = { 0x8c, 0x86, 0x98, 'A', 0 },
			not_first[] = { 0x98, 'A', 0, 0x8c, 0x82 };

		CHECK_EQ(mms_decode_notification(no_tid, sizeof(no_tid), &nf), -1);
		CHECK_EQ(mms_decode_notification(no_loc, sizeof(no_loc), &nf), -1);
		CHECK_EQ(mms_decode_notification(wrong, sizeof(wrong), &nf), -1);
		CHECK_EQ(mms_decode_notification(not_first, sizeof(not_first), &nf), -1);
		CHECK_EQ(mms_decode_notification(d, 0, &nf), -1);
	}
	/* unknown headers are skipped by the WSP rules: well-known with short length / length-quote / text, application header */
	{
		struct pb q = { .n = 0 };

		pb_u8(&q, 0x8c); pb_u8(&q, 0x82);
		pb_u8(&q, 0xb7); pb_u8(&q, 0x85);			/* short integer value */
		pb_u8(&q, 0xa9); pb_u8(&q, 2); pb_u8(&q, 1); pb_u8(&q, 2);	/* short length */
		pb_u8(&q, 0xaa); pb_u8(&q, 31); pb_u8(&q, 2); pb_u8(&q, 9); pb_u8(&q, 9);	/* length quote */
		pb_u8(&q, 0xab); pb_text(&q, "text value");
		pb_text(&q, "X-Custom"); pb_text(&q, "v");		/* application header */
		pb_u8(&q, 0x98); pb_text(&q, "ID");
		pb_u8(&q, 0x83); pb_text(&q, "http://h/p");
		CHECK_EQ(mms_decode_notification(q.d, q.n, &nf), 0);
		CHECK_STR(nf.tid, "ID"); CHECK_STR(nf.location, "http://h/p");
	}
}

/* ---- rendering ---- */

static void t_render(void)
{
	struct buf b;
	char o[40];
	size_t off[MMSR_MAX_CHUNKS], len[MMSR_MAX_CHUNKS];
	bool tr;
	unsigned n;
	const char *s;

	buf_init(&b, 0);
	mmsr_html_to_text("<html><head><title>T</title><style>p{x:y}</style></head><body><p>Hello&nbsp;&amp;&lt;world&gt;</p>"
			  "<div>a  b\n c</div><script>alert(1)</script><!-- c -->x<br/>y&#65;&#x42;&bogus; &#0;</body></html>", &b);
	CHECK_STR(buf_cstr(&b), "T\nHello &<world>\na b c\nx\nyAB&bogus; &#0;");
	buf_free(&b);
	mmsr_oneline("a\r\nb\tc", o, sizeof(o)); CHECK_STR(o, "a  b c");
	mmsr_oneline("가나다라", o, 8); CHECK_STR(o, "가나");	/* cut inside a character: back to the boundary */
	mmsr_oneline("가나다라", o, 10); CHECK_STR(o, "가나다");
	mmsr_human_size(512, o, sizeof(o)); CHECK_STR(o, "512 B");
	mmsr_human_size(2048, o, sizeof(o)); CHECK_STR(o, "2 KB");
	mmsr_human_size(1536 * 1024, o, sizeof(o)); CHECK_STR(o, "1.5 MB");
	/* splitting: lossless, character boundaries, a cut right after a line break preferred */
	s = "aaaa bbbb\ncccc dddd\neeee ffff";
	n = mmsr_split(s, strlen(s), 24, off, len, 8, &tr);
	CHECK_EQ(n, 2); CHECK(!tr); CHECK_EQ(off[0], 0); CHECK_EQ(len[0], 20); CHECK_EQ(off[1], 20);
	s = "한한한한한한한한한한";		/* 30 bytes */
	n = mmsr_split(s, strlen(s), 16, off, len, 8, &tr);
	CHECK_EQ(n, 2); CHECK_EQ(len[0], 15); CHECK_EQ(len[1], 15);
	n = mmsr_split("", 0, 100, off, len, 8, &tr); CHECK_EQ(n, 0);
	n = mmsr_split("\r\n\r\n", 4, 100, off, len, 8, &tr); CHECK_EQ(n, 1); CHECK_EQ(len[0], 4);
	{
		char big[400];

		memset(big, 'x', sizeof(big) - 1);
		big[sizeof(big) - 1] = 0;
		n = mmsr_split(big, strlen(big), 16, off, len, 4, &tr);
		CHECK_EQ(n, 4); CHECK(tr);
		n = mmsr_split(big, strlen(big), 100, off, len, 8, &tr);
		CHECK_EQ(n, 4); CHECK(!tr); CHECK_EQ(len[0] + len[1] + len[2] + len[3], 399);
	}
}

/* ---- attachment store ---- */

static const char *tmpdir(char *out, size_t n)
{
	const char *t = getenv("IMSD_TEST_TMP");

	(void)t;
	snprintf(out, n, "/tmp/imsd-mms-test-XXXXXX");
	return mkdtemp(out);
}

static int64_t g_wall = 1700000000;
static int64_t wall_cb(void *ctx)
{
	(void)ctx;
	return g_wall;
}

static unsigned count_dirs(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	unsigned n = 0;

	if (!d)
		return 0;
	while ((e = readdir(d)))
		if (strlen(e->d_name) == 32)
			n++;
	closedir(d);
	return n;
}

static void rm_rf(const char *dir)
{
	char cmd[400];

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) < 0)
		CHECK(0);
}

static void t_store(void)
{
	char root[64], dir[33], p[512];
	struct mmsstore_cfg c;
	struct mmsstore *s;
	struct mmsstore_file f[3];
	unsigned n;
	size_t bytes;
	struct stat st;
	char nm[80];
	int i;

	CHECK(tmpdir(root, sizeof(root)) != NULL);
	memset(&c, 0, sizeof(c));
	snprintf(c.dir, sizeof(c.dir), "%s/m", root);
	c.keep_messages = 3; c.keep_bytes = 1000; c.keep_days = 2;
	g_wall = 1700000000;
	s = mmsstore_new(&c, wall_cb, NULL);
	/* names */
	mmsstore_clean_name("../../etc/passwd", "text/plain", 1, nm, sizeof(nm)); CHECK_STR(nm, "passwd");
	mmsstore_clean_name("a b?*.jpg", "image/jpeg", 1, nm, sizeof(nm)); CHECK_STR(nm, "a_b__.jpg");
	mmsstore_clean_name("", "image/jpeg", 2, nm, sizeof(nm)); CHECK_STR(nm, "part2.jpg");
	mmsstore_clean_name(NULL, "audio/amr", 3, nm, sizeof(nm)); CHECK_STR(nm, "part3.amr");
	mmsstore_clean_name("...", "video/3gpp", 4, nm, sizeof(nm)); CHECK_STR(nm, "part4.3gp");
	mmsstore_clean_name(".hidden", "x/y", 5, nm, sizeof(nm)); CHECK_STR(nm, "hidden");
	mmsstore_clean_name("사진.jpg", "image/jpeg", 6, nm, sizeof(nm)); CHECK(strstr(nm, ".jpg") != NULL); CHECK(strchr(nm, '/') == NULL);
	mmsstore_clean_name("한글", "image/png", 7, nm, sizeof(nm)); CHECK(nm[0] != 0);
	{
		char longn[200];

		memset(longn, 'a', sizeof(longn));
		strcpy(longn + 150, ".jpeg");
		mmsstore_clean_name(longn, "image/jpeg", 1, nm, sizeof(nm)); CHECK_EQ(strlen(nm), 64); CHECK_STR(nm + 59, ".jpeg");
	}
	/* save: two files with the same name, one empty name */
	memset(f, 0, sizeof(f));
	f[0].name = "pic.jpg"; f[0].type = "image/jpeg"; f[0].data = (const uint8_t *)"AAAA"; f[0].len = 4;
	f[1].name = "pic.jpg"; f[1].type = "image/jpeg"; f[1].data = (const uint8_t *)"BBBBBB"; f[1].len = 6;
	f[2].name = ""; f[2].type = "audio/amr"; f[2].data = (const uint8_t *)"C"; f[2].len = 1;
	CHECK_EQ(mmsstore_save(s, f, 3, dir), 0);
	CHECK_EQ(strlen(dir), 32);
	CHECK(f[0].ok && f[1].ok && f[2].ok);
	CHECK_STR(f[0].saved, "pic.jpg"); CHECK_STR(f[1].saved, "pic-2.jpg"); CHECK_STR(f[2].saved, "part3.amr");
	snprintf(p, sizeof(p), "%s/m/%s/pic-2.jpg", root, dir);
	{
		char buf[16] = "";
		FILE *fp = fopen(p, "r");

		CHECK(fp != NULL);
		if (fp) {
			CHECK(fgets(buf, sizeof(buf), fp) != NULL);
			fclose(fp);
		}
		CHECK_STR(buf, "BBBBBB");
		CHECK(!stat(p, &st) && (st.st_mode & 0777) == 0644);
	}
	snprintf(p, sizeof(p), "%s/m/%s", root, dir);
	CHECK(!stat(p, &st) && S_ISDIR(st.st_mode));
	snprintf(p, sizeof(p), "%s/m/index.html", root);
	CHECK(!stat(p, &st) && st.st_size == 0);
	mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 1); CHECK_EQ(bytes, 11);
	/* the directory names are random */
	{
		char d2[33];

		f[0].len = 4;
		CHECK_EQ(mmsstore_save(s, f, 1, d2), 0);
		CHECK(strcmp(dir, d2) != 0);
	}
	/* retention by count (3 kept): a third and a fourth message evict the oldest */
	{
		char d3[33], d4[33];

		CHECK_EQ(mmsstore_save(s, f, 1, d3), 0);
		mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 3);
		snprintf(p, sizeof(p), "%s/m", root);
		CHECK_EQ(count_dirs(p), 3);
		CHECK_EQ(mmsstore_save(s, f, 1, d4), 0);
		CHECK_EQ(count_dirs(p), 3);
		snprintf(p, sizeof(p), "%s/m/%s", root, dir);
		CHECK(stat(p, &st) != 0);			/* the oldest is gone, with its files */
		snprintf(p, sizeof(p), "%s/m/%s", root, d4);
		CHECK(!stat(p, &st));
	}
	/* retention by bytes (1000): a 900 byte message pushes the others out */
	{
		static uint8_t big[900];
		char db[33];

		memset(big, 'z', sizeof(big));
		memset(f, 0, sizeof(f));
		f[0].name = "big.bin"; f[0].type = "x/y"; f[0].data = big; f[0].len = sizeof(big);
		CHECK_EQ(mmsstore_save(s, f, 1, db), 0);
		mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 3); CHECK_EQ(bytes, 908);	/* the count limit made room for one */
		CHECK_EQ(mmsstore_save(s, f, 1, db), 0);
		mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 1); CHECK_EQ(bytes, 900);	/* the byte limit pushed the rest out */
		/* a file above keep_bytes alone is not stored */
		{
			static uint8_t huge[1200];

			f[0].data = huge; f[0].len = sizeof(huge);
			CHECK_EQ(mmsstore_save(s, f, 1, db), -ENOSPC);
			CHECK(!f[0].ok);
			mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 1);	/* too big to keep: nothing evicted for it, nothing added */
		}
	}
	/* retention by age (2 days) */
	{
		char da[33], db[33];

		g_wall += 100 * 86400;
		mmsstore_sweep(s);
		mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 0);

		memset(f, 0, sizeof(f));
		f[0].name = "a"; f[0].type = "x/y"; f[0].data = (const uint8_t *)"1"; f[0].len = 1;
		CHECK_EQ(mmsstore_save(s, f, 1, da), 0);
		g_wall += 86400;
		CHECK_EQ(mmsstore_save(s, f, 1, db), 0);
		mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 2);
		g_wall += 86400 + 100;			/* da is now older than 2 days */
		mmsstore_sweep(s);
		mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 1);
		snprintf(p, sizeof(p), "%s/m/%s", root, da);
		CHECK(stat(p, &st) != 0);
		g_wall += 3 * 86400;
		mmsstore_sweep(s);
		mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 0);
	}
	/* an unset clock (before 2020) does not evict by age */
	{
		char da[33];

		g_wall = 100;
		CHECK_EQ(mmsstore_save(s, f, 1, da), 0);
		g_wall = 100 + 10 * 86400;
		mmsstore_sweep(s);
		mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 1);
	}
	mmsstore_free(s);
	/* a new store over the same directory takes the old messages over and trims them to its limits */
	g_wall = 1700000000;
	c.keep_messages = 50; c.keep_bytes = 1000000;
	s = mmsstore_new(&c, wall_cb, NULL);
	for (i = 0; i < 4; i++) {
		char d[33];

		memset(f, 0, sizeof(f));
		f[0].name = "x"; f[0].type = "x/y"; f[0].data = (const uint8_t *)"12345"; f[0].len = 5;
		CHECK_EQ(mmsstore_save(s, f, 1, d), 0);
	}
	mmsstore_free(s);
	c.keep_messages = 2;
	s = mmsstore_new(&c, wall_cb, NULL);
	f[0].len = 5;
	{
		char d[33];

		CHECK_EQ(mmsstore_save(s, f, 1, d), 0);		/* scan: took over the old ones, trimmed to make room */
		mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 2);
		snprintf(p, sizeof(p), "%s/m", root);
		CHECK_EQ(count_dirs(p), 2);
	}
	/* the limits can change at run time */
	c.keep_messages = 1;
	mmsstore_set_cfg(s, &c);
	mmsstore_stats(s, &n, &bytes); CHECK_EQ(n, 1);
	mmsstore_free(s);
	/* an impossible directory */
	snprintf(c.dir, sizeof(c.dir), "/proc/imsd-no-such/x");
	s = mmsstore_new(&c, wall_cb, NULL);
	{
		char d[33];

		CHECK(mmsstore_save(s, f, 1, d) < 0);
	}
	mmsstore_free(s);
	rm_rf(root);
}

void test_mms_codec(void)
{
	t_primitives();
	t_charsets();
	t_real_notification();
	t_real_retrieve();
	t_encoders();
	t_addresses();
	t_synthetic();
	t_notif_variants();
	t_render();
	t_store();
}
