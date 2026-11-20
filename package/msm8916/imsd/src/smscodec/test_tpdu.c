/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host tests for the TP layer: real captured TPDUs, boundaries, round trips, fuzz. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tpdu.h"
#include "gsm7.h"
#include "utf8.h"
#include "euckr.h"
#include "../util/codec.h"

static int n_checks, n_fail;

#define CHECK(c) do { n_checks++; if (!(c)) { n_fail++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_STR(a, b) do { n_checks++; if (strcmp((a), (b))) { n_fail++; \
	printf("FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); } } while (0)

static size_t unhex(const char *h, uint8_t *o, size_t max)
{
	int n = hex_decode(h, o, max);

	if (n < 0) {
		printf("bad hex in test: %s\n", h);
		exit(2);
	}
	return (size_t)n;
}

static uint32_t rng_state = 0x12345678;
static uint32_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

/* ---- independent reference: bit-by-bit septet packer ---- */
static size_t ref_pack(const uint8_t *sept, size_t n, unsigned fill, uint8_t *out)
{
	size_t nbits = fill + n * 7, i, b;

	memset(out, 0, (nbits + 7) / 8);
	for (i = 0; i < n; i++)
		for (b = 0; b < 7; b++)
			if (sept[i] & (1u << b)) {
				size_t bit = fill + i * 7 + b;

				out[bit / 8] |= (uint8_t)(1u << (bit % 8));
			}
	return (nbits + 7) / 8;
}

/* ---- real captures ---- */

/* strip the RP-DATA (network to MS) header: 01 MR OA(len,..) DA(len,..) UDL TPDU */
static size_t rp_data_tpdu(const uint8_t *rp, size_t n, const uint8_t **tpdu)
{
	size_t pos = 2;

	CHECK(n > 4 && (rp[0] & 7) == 1);
	pos += 1 + rp[pos];	/* RP-OA */
	pos += 1 + rp[pos];	/* RP-DA */
	CHECK(rp[pos] == n - pos - 1);
	*tpdu = rp + pos + 1;
	return n - pos - 1;
}

static void test_real_deliver(void)
{
	uint8_t rp[200];
	const uint8_t *t;
	size_t n, tl;
	struct tp_sms s;

	/* MT SMS, UCS2 Korean */
	n = unhex("013e07912801022981120019040b811050216268f200086211025061646306d14cc2a4d2b8", rp, sizeof(rp));
	tl = rp_data_tpdu(rp, n, &t);
	CHECK(tl == 25);
	CHECK(tp_decode_deliver(t, tl, &s) == 0);
	CHECK(s.mti == 0 && !s.more_messages && !s.udhi);
	CHECK_STR(s.addr.str, "01051226862");
	CHECK(s.addr.ton == 0 && s.addr.npi == 1 && !s.addr.alnum);
	CHECK(s.pid == 0 && s.dcs == 0x08 && s.charset == TP_CS_UCS2 && s.msg_class == -1);
	CHECK(s.scts.valid && s.scts.year == 2026 && s.scts.mon == 11 && s.scts.day == 20);
	CHECK(s.scts.hour == 5 && s.scts.min == 16 && s.scts.sec == 46 && s.scts.tz_quarters == 36);
	CHECK(s.scts.epoch == 1795119406);
	CHECK(s.has_text && !s.flags);
	CHECK_STR(s.text, "\xed\x85\x8c\xec\x8a\xa4\xed\x8a\xb8");	/* 테스트 */

	/* MT SMS, GSM 7-bit */
	n = unhex("016807912801022981720026040b811050216268f200006211025073146315e9f6bc1e0685e1ad747b0e9ab7e7207a794e07",
		  rp, sizeof(rp));
	tl = rp_data_tpdu(rp, n, &t);
	CHECK(tp_decode_deliver(t, tl, &s) == 0);
	CHECK_STR(s.text, "imsua ap-ims sms test");
	CHECK(s.charset == TP_CS_GSM7 && s.text_len == 21 && s.scts.epoch == 1795120661);
	CHECK(s.scts.hour == 5 && s.scts.min == 37 && s.scts.sec == 41);
}

static void test_real_submit_and_report(void)
{
	uint8_t exp[64], rp[64];
	size_t en, n;
	struct tp_submit_req rq;
	struct tp_pdu pdu[4];
	struct tp_sms s;
	struct tp_submit_report r;
	const uint8_t *t;
	size_t tl;

	/* the SMS-SUBMIT the network accepted (from the RP-DATA 00ae00..., TPDU part), MR 0x14 */
	en = unhex("01140b811050216268f2000015e9f6bc1e0685e1ad747b0e9ab7e7207a794e07", exp, sizeof(exp));
	memset(&rq, 0, sizeof(rq));
	rq.dest = "01051226862";
	rq.text = "imsua ap-ims sms test";
	rq.text_len = strlen(rq.text);
	rq.mr = 0x14;
	CHECK(tp_encode_submit(&rq, pdu, 4) == 1);
	CHECK(pdu[0].len == en && !memcmp(pdu[0].data, exp, en));
	CHECK(!pdu[0].ucs2 && pdu[0].seq == 1 && pdu[0].total == 1);
	CHECK(tp_decode_submit(exp, en, &s) == 0);
	CHECK_STR(s.text, "imsua ap-ims sms test");
	CHECK_STR(s.addr.str, "01051226862");
	CHECK(s.mr == 0x14 && s.mti == 1 && !s.srr && !s.vp_relative);

	/* SUBMIT-REPORT inside the RP-ACK: 03 ae 41 09 01 00 <SCTS> */
	n = unhex("03ae4109010062110250731463", rp, sizeof(rp));
	CHECK((rp[0] & 7) == 3 && rp[1] == 0xae);
	CHECK(tp_rp_user_data(rp + 2, n - 2, &t, &tl) == 0 && tl == 9);
	CHECK(tp_decode_submit_report(t, tl, false, &r) == 0);
	CHECK(r.pi == 0 && !r.has_pid && !r.has_dcs && r.scts.valid);
	CHECK(r.scts.epoch == 1795120661 && r.scts.tz_quarters == 36);
	CHECK(tp_rp_user_data(rp + 2, 5, &t, &tl) == TP_E_TRUNC);
	rp[2] = 0x42;
	CHECK(tp_rp_user_data(rp + 2, n - 2, &t, &tl) == TP_E_MTI);
	CHECK(tp_decode_submit_report(t, 1, false, &r) == TP_E_TRUNC);
}

/* ---- GSM 7-bit packing at every offset ---- */
static void test_gsm7_pack(void)
{
	unsigned fill;
	size_t n;

	for (fill = 0; fill <= 6; fill++) {
		for (n = 0; n <= 40; n++) {
			uint8_t sept[40], ref[64], got[64], back[40];
			size_t i, rl;

			for (i = 0; i < n; i++)
				sept[i] = (uint8_t)(rnd() & 0x7F);
			rl = ref_pack(sept, n, fill, ref);
			CHECK(gsm7_packed_len(n, fill) == rl);
			CHECK(gsm7_pack(sept, n, fill, got, sizeof(got)) == (int)rl);
			CHECK(!memcmp(ref, got, rl));
			CHECK(gsm7_unpack(got, rl, fill, n, back) == 0);
			CHECK(!memcmp(sept, back, n));
			if (rl)
				CHECK(gsm7_unpack(got, rl - 1, fill, n, back) == -1 || gsm7_packed_len(n, fill) <= rl - 1);
		}
	}
	{
		uint8_t s[3] = { 1, 2, 3 }, o[2];

		CHECK(gsm7_pack(s, 3, 0, o, 2) == -1);
		CHECK(gsm7_pack(s, 3, 7, o, 2) == -1);
	}
}

/* ---- deliver with UDH of different lengths (7-bit alignment) ---- */
static size_t build_deliver_gsm7(uint8_t *o, const uint8_t *udh, size_t udhl_octets /* incl. UDHL */,
				 const uint8_t *sept, size_t ns, uint8_t dcs)
{
	uint8_t *w = o;
	size_t hdr_sept = (udhl_octets * 8 + 6) / 7, fill = hdr_sept * 7 - udhl_octets * 8, total;
	uint8_t pk[200];
	size_t pl;

	*w++ = udhl_octets ? 0x44 : 0x04;
	*w++ = 0x03;
	*w++ = 0x81;
	*w++ = 0x21;
	*w++ = 0x43;
	*w++ = 0x00;
	*w++ = dcs;
	memcpy(w, "\x62\x11\x02\x50\x61\x64\x63", 7);
	w += 7;
	total = hdr_sept + ns;
	*w++ = (uint8_t)total;
	if (udhl_octets) {
		pl = ref_pack(sept, ns, fill, pk);
		memcpy(w, udh, udhl_octets);
		w += udhl_octets;
		memcpy(w, pk, pl);
		w += pl;
	} else {
		pl = ref_pack(sept, ns, 0, pk);
		memcpy(w, pk, pl);
		w += pl;
	}
	return (size_t)(w - o);
}

static void test_udh_alignment(void)
{
	size_t hdr;
	const char *txt = "Hello, wide world! ~[]{}|^\\ \xe2\x82\xac end";

	for (hdr = 1; hdr <= 12; hdr++) {
		uint8_t udh[16], sept[64], pdu[200];
		uint8_t sv[2];
		size_t ns = 0, n, i;
		struct tp_sms s;
		const char *p;

		if (hdr == 2)
			continue;	/* a 1 octet header cannot hold an information element */
		memset(udh, 0, sizeof(udh));
		udh[0] = (uint8_t)(hdr - 1);
		if (hdr >= 3) {
			udh[1] = 0x70;			/* unknown IEI */
			udh[2] = (uint8_t)(hdr - 3);
			for (i = 0; i < hdr - 3; i++)
				udh[3 + i] = (uint8_t)(0xA0 + i);
		}
		for (p = txt; *p;) {
			uint32_t cp;
			int k = utf8_decode(p, strlen(p), &cp), c = gsm7_from_cp(cp, sv);

			CHECK(c > 0);
			for (i = 0; i < (size_t)c; i++)
				sept[ns++] = sv[i];
			p += k;
		}
		n = build_deliver_gsm7(pdu, udh, hdr, sept, ns, 0x00);
		CHECK(tp_decode_deliver(pdu, n, &s) == 0);
		CHECK_STR(s.text, txt);
		CHECK(s.udh_len == hdr - 1 && !s.flags);
	}
	/* hdr == 1 case: UDHL 0, no information elements */
	{
		uint8_t udh[1] = { 0 }, sept[3] = { 'a', 'b', 'c' }, pdu[64];
		size_t n = build_deliver_gsm7(pdu, udh, 1, sept, 3, 0x00);
		struct tp_sms s;

		CHECK(tp_decode_deliver(pdu, n, &s) == 0);
		CHECK_STR(s.text, "abc");
	}
}

static void test_udh_concat_and_nls(void)
{
	uint8_t pdu[200], sept[4] = { 'h', 'i', '!', 'x' };
	uint8_t udh8[6] = { 5, 0x00, 3, 0xAB, 3, 2 };
	uint8_t udh16[7] = { 6, 0x08, 4, 0x12, 0x34, 5, 5 };
	uint8_t udhbad[6] = { 5, 0x00, 3, 1, 2, 3 };
	uint8_t udhnls[9] = { 8, 0x24, 1, 1, 0x25, 1, 2, 0x70, 0 };
	struct tp_sms s;
	size_t n;

	n = build_deliver_gsm7(pdu, udh8, 6, sept, 4, 0);
	CHECK(tp_decode_deliver(pdu, n, &s) == 0);
	CHECK(s.concat.present && !s.concat.ref16 && s.concat.ref == 0xAB && s.concat.total == 3 && s.concat.seq == 2);
	CHECK_STR(s.text, "hi!x");

	n = build_deliver_gsm7(pdu, udh16, 7, sept, 4, 0);
	CHECK(tp_decode_deliver(pdu, n, &s) == 0);
	CHECK(s.concat.present && s.concat.ref16 && s.concat.ref == 0x1234 && s.concat.total == 5 && s.concat.seq == 5);

	n = build_deliver_gsm7(pdu, udhbad, 6, sept, 4, 0);
	CHECK(tp_decode_deliver(pdu, n, &s) == 0);
	CHECK(!s.concat.present && (s.flags & TP_F_BAD_CONCAT));

	n = build_deliver_gsm7(pdu, udhnls, 9, sept, 4, 0);
	CHECK(tp_decode_deliver(pdu, n, &s) == 0);
	CHECK((s.flags & TP_F_NLS) && s.nls_single == 1 && s.nls_locking == 2);

	/* UDH longer than the data */
	{
		uint8_t bad[6] = { 9, 0x70, 0, 0, 0, 0 };

		n = build_deliver_gsm7(pdu, bad, 6, sept, 4, 0);
		CHECK(tp_decode_deliver(pdu, n, &s) == TP_E_UDH);
	}
	/* IE running past the UDH */
	{
		uint8_t bad[6] = { 5, 0x70, 9, 0, 0, 0 };

		n = build_deliver_gsm7(pdu, bad, 6, sept, 4, 0);
		CHECK(tp_decode_deliver(pdu, n, &s) == TP_E_UDH);
	}
}

/* ---- DCS handling ---- */
static size_t mk_deliver(uint8_t *o, uint8_t dcs, const uint8_t *ud, size_t udl, size_t ud_octets)
{
	uint8_t *w = o;

	*w++ = 0x00;
	*w++ = 0x03;
	*w++ = 0x81;
	*w++ = 0x21;
	*w++ = 0x43;
	*w++ = 0x00;
	*w++ = dcs;
	memcpy(w, "\x62\x11\x02\x50\x61\x64\x63", 7);
	w += 7;
	*w++ = (uint8_t)udl;
	memcpy(w, ud, ud_octets);
	return (size_t)(w - o) + ud_octets;
}

static void test_dcs(void)
{
	uint8_t pdu[200], ud[8];
	struct tp_sms s;
	size_t n;

	/* compressed rejected */
	ud[0] = 'a';
	n = mk_deliver(pdu, 0x20, ud, 1, 1);
	CHECK(tp_decode_deliver(pdu, n, &s) == TP_E_COMPRESSED);
	n = mk_deliver(pdu, 0x70, ud, 1, 1);
	CHECK(tp_decode_deliver(pdu, n, &s) == TP_E_COMPRESSED);

	/* class 2, GSM7 */
	n = mk_deliver(pdu, 0x12, ud, 1, 1);
	CHECK(tp_decode_deliver(pdu, n, &s) == 0 && s.msg_class == 2 && s.charset == TP_CS_GSM7);
	/* 8-bit data with class 1 */
	memcpy(ud, "\x01\x02\xff", 3);
	n = mk_deliver(pdu, 0x15, ud, 3, 3);
	CHECK(tp_decode_deliver(pdu, n, &s) == 0 && s.charset == TP_CS_8BIT && s.msg_class == 1);
	CHECK(!s.has_text && s.data_len == 3 && !memcmp(s.data, ud, 3));
	/* 0xF4: class 0 8-bit */
	n = mk_deliver(pdu, 0xF4, ud, 3, 3);
	CHECK(tp_decode_deliver(pdu, n, &s) == 0 && s.charset == TP_CS_8BIT && s.msg_class == 0);
	/* MWI store UCS2, active voicemail */
	memcpy(ud, "\x00\x41", 2);
	n = mk_deliver(pdu, 0xE8, ud, 2, 2);
	CHECK(tp_decode_deliver(pdu, n, &s) == 0 && s.mwi && s.mwi_active && s.mwi_type == 0 && s.charset == TP_CS_UCS2);
	CHECK_STR(s.text, "A");
	/* reserved alphabet bits: assumed GSM7 with flag */
	n = mk_deliver(pdu, 0x0C, ud, 1, 1);
	CHECK(tp_decode_deliver(pdu, n, &s) == 0 && (s.flags & TP_F_RESERVED_ALPHABET) && s.charset == TP_CS_GSM7);
	/* reserved coding group: raw */
	n = mk_deliver(pdu, 0x94, ud, 2, 2);
	CHECK(tp_decode_deliver(pdu, n, &s) == 0 && s.charset == TP_CS_UNKNOWN && (s.flags & TP_F_UNKNOWN_CHARSET));
	CHECK(!s.has_text && s.data_len == 2);

	/* DCS 0x84: EUC-KR "Hangul" + ASCII + a CP949-only pair */
	{
		const uint8_t k[] = { 0xC7, 0xD1, 0xB1, 0xDB, 'a', 'b', 0xB0, 0xA1, 0xA1, 0xA1 };	/* 한글ab가(ideographic space) */

		n = mk_deliver(pdu, 0x84, k, sizeof(k), sizeof(k));
		CHECK(tp_decode_deliver(pdu, n, &s) == 0 && s.charset == TP_CS_KSC5601 && s.has_text);
		CHECK_STR(s.text, "\xed\x95\x9c\xea\xb8\x80" "ab\xea\xb0\x80\xe3\x80\x80");
		CHECK(s.data_len == sizeof(k) && !s.flags);
	}
	{
		const uint8_t k[] = { 0x81, 0x41, 'x', 0xB0 };	/* CP949 extension pair, then a dangling lead */

		n = mk_deliver(pdu, 0x84, k, sizeof(k), sizeof(k));
		CHECK(tp_decode_deliver(pdu, n, &s) == 0);
		CHECK_STR(s.text, "\xef\xbf\xbdx\xef\xbf\xbd");
		CHECK(s.flags & TP_F_LOSSY_TEXT);
	}
	/* hanja and symbols from the table */
	{
		const uint8_t k[] = { 0xD7, 0xCF /* hanja */, 0xA1, 0xA2 /* symbol */ };
		struct buf b;
		bool lossy = false;

		buf_init(&b, 64);
		CHECK(euckr_to_utf8(k, sizeof(k), &b, &lossy) == 0 && !lossy);
		CHECK(b.len == 6);
		buf_free(&b);
	}

	/* UCS2 with surrogate pair (U+1F600) and a lone high surrogate */
	{
		const uint8_t u[] = { 0x00, 'A', 0xD8, 0x3D, 0xDE, 0x00, 0xD8, 0x3D, 0x00, 'B' };

		n = mk_deliver(pdu, 0x08, u, sizeof(u), sizeof(u));
		CHECK(tp_decode_deliver(pdu, n, &s) == 0);
		CHECK_STR(s.text, "A\xf0\x9f\x98\x80\xef\xbf\xbd" "B");
		CHECK(s.flags & TP_F_LOSSY_TEXT);
	}
	/* odd UCS2 length: dangling byte dropped, flagged */
	{
		const uint8_t u[] = { 0x00, 'A', 0x00 };

		n = mk_deliver(pdu, 0x08, u, 3, 3);
		CHECK(tp_decode_deliver(pdu, n, &s) == 0 && (s.flags & TP_F_LOSSY_TEXT));
		CHECK_STR(s.text, "A");
	}
	/* UDL beyond limits */
	{
		uint8_t big[200];

		memset(big, 0x41, sizeof(big));
		n = mk_deliver(pdu, 0x00, big, 161, 141);
		CHECK(tp_decode_deliver(pdu, n, &s) == TP_E_UDL);
		n = mk_deliver(pdu, 0x08, big, 141, 141);
		CHECK(tp_decode_deliver(pdu, n, &s) == TP_E_UDL);
		n = mk_deliver(pdu, 0x08, big, 20, 10);
		CHECK(tp_decode_deliver(pdu, n, &s) == TP_E_TRUNC);
	}
}

static void test_addr_and_scts(void)
{
	uint8_t pdu[100], ud[2] = { 'a', 0 };
	struct tp_sms s;
	size_t n, i;
	struct tp_scts t;
	uint8_t scts[7];

	/* international, odd digit count with filler: +8210123456789 (13 digits) */
	memcpy(pdu, "\x00\x0d\x91\x28\x01\x21\x43\x65\x87\xf9\x00\x00\x62\x11\x02\x50\x61\x64\x63\x01\x61", 21);
	CHECK(tp_decode_deliver(pdu, 21, &s) == 0);
	CHECK_STR(s.addr.str, "+8210123456789");
	CHECK(s.addr.ton == 1 && s.addr.npi == 1);

	/* alphanumeric sender "Google" (6 chars, 11 useful semi-octets) and 7 chars "Example" (13) */
	{
		const char *names[] = { "Google", "Example", "A", "INFO-SMS", "Telekom" };
		for (i = 0; i < 5; i++) {
			uint8_t sept[20], pk[20];
			size_t ns = strlen(names[i]), nb, k;
			uint8_t *w = pdu;

			for (k = 0; k < ns; k++) {
				uint8_t g[2];

				CHECK(gsm7_from_cp((uint8_t)names[i][k], g) == 1);
				sept[k] = g[0];
			}
			nb = ref_pack(sept, ns, 0, pk);
			*w++ = 0x00;
			*w++ = (uint8_t)((ns * 7 + 3) / 4);
			*w++ = 0xD0;
			memcpy(w, pk, nb);
			w += nb;
			*w++ = 0;
			*w++ = 0;
			memcpy(w, "\x62\x11\x02\x50\x61\x64\x63", 7);
			w += 7;
			*w++ = 1;
			*w++ = 'a';
			CHECK(tp_decode_deliver(pdu, (size_t)(w - pdu), &s) == 0);
			CHECK(s.addr.alnum && s.addr.ton == 5);
			CHECK_STR(s.addr.str, names[i]);
		}
	}
	/* address length > 20 */
	memcpy(pdu, "\x00\x15\x81", 3);
	CHECK(tp_decode_deliver(pdu, 40, &s) == TP_E_ADDR);
	/* empty address */
	memcpy(pdu, "\x00\x00\x81\x00\x00\x62\x11\x02\x50\x61\x64\x63\x01\x61", 14);
	CHECK(tp_decode_deliver(pdu, 14, &s) == 0 && s.addr.str[0] == 0);
	(void)ud;
	(void)n;

	/* timezones: +09:00 (0x63), -08:00 (0x2B), +05:30 (22 quarters = 0x22), 0 */
	memcpy(scts, "\x62\x03\x01\x80\x00\x00\x63", 7);	/* 2026-30-10? invalid month: 30 */
	tp_scts_decode(scts, &t);
	CHECK(!t.valid);
	memcpy(scts, "\x62\x30\x10\x80\x00\x00\x63", 7);	/* 2026-03-01 08:00:00 +09:00 */
	tp_scts_decode(scts, &t);
	CHECK(t.valid && t.mon == 3 && t.day == 1 && t.tz_quarters == 36);
	CHECK(t.epoch == 1772352000 - 9 * 3600);
	scts[6] = 0x2B;		/* -08:00 */
	tp_scts_decode(scts, &t);
	CHECK(t.valid && t.tz_quarters == -32 && t.epoch == 1772352000 + 8 * 3600);
	scts[6] = 0x22;		/* +05:30 */
	tp_scts_decode(scts, &t);
	CHECK(t.tz_quarters == 22 && t.epoch == 1772352000 - 5 * 3600 - 1800);
	scts[6] = 0x00;
	tp_scts_decode(scts, &t);
	CHECK(t.tz_quarters == 0 && t.epoch == 1772352000);
	scts[6] = 0x0A;		/* sign set, digit nibble 2 / bad? 0x0A: tens=2? lo=0xA bit3 set -> -(2*10+0) */
	tp_scts_decode(scts, &t);
	CHECK(t.tz_quarters == -20 || !t.valid);
	/* leap day and invalid dates */
	memcpy(scts, "\x42\x20\x92\x12\x30\x45\x00", 7);	/* 2024-02-29 21:03:54 */
	tp_scts_decode(scts, &t);
	CHECK(t.valid && t.mon == 2 && t.day == 29 && t.epoch == 1709240634);
	memcpy(scts, "\x52\x20\x92\x12\x30\x45\x00", 7);	/* 2025-02-29 */
	tp_scts_decode(scts, &t);
	CHECK(!t.valid);
	memcpy(scts, "\x6a\x20\x92\x12\x30\x45\x00", 7);	/* BCD nibble 0xA */
	tp_scts_decode(scts, &t);
	CHECK(!t.valid);
}

static void test_status_report(void)
{
	uint8_t t[] = { 0x06, 0x05, 0x0b, 0x81, 0x10, 0x50, 0x21, 0x62, 0x68, 0xf2,
			0x62, 0x11, 0x02, 0x50, 0x73, 0x14, 0x63, 0x62, 0x11, 0x02, 0x50, 0x73, 0x15, 0x63, 0x00 };
	struct tp_status_report r;

	CHECK(tp_decode_status_report(t, sizeof(t), &r) == 0);
	CHECK(r.mr == 5 && r.st == 0 && !strcmp(r.ra.str, "01051226862"));
	CHECK(r.scts.valid && r.dt.valid && r.dt.sec == 51 && r.dt.epoch == r.scts.epoch + 10);
	CHECK(tp_status_is_success(0) && tp_status_is_final(0x40) && !tp_status_is_final(0x20));
	CHECK(!tp_status_is_success(0x40) && tp_status_is_final(0x62));
	CHECK(tp_decode_status_report(t, sizeof(t) - 1, &r) == TP_E_TRUNC);
	t[0] = 0x04;
	CHECK(tp_decode_status_report(t, sizeof(t), &r) == TP_E_MTI);
}

static void test_vp(void)
{
	uint32_t m;
	struct tp_submit_req rq;
	struct tp_pdu pdu[2];
	struct tp_sms s;

	CHECK(tp_vp_encode(0) == TP_E_VP && tp_vp_encode(63 * 10080 + 1) == TP_E_VP);
	CHECK(tp_vp_encode(5) == 0 && tp_vp_encode(1) == 0 && tp_vp_encode(720) == 143 && tp_vp_encode(1440) == 167);
	CHECK(tp_vp_encode(2880) == 168 && tp_vp_encode(43200) == 196 && tp_vp_encode(63 * 10080) == 255);
	for (m = 1; m <= 63u * 10080u; m += (m < 5000 ? 1 : 997)) {
		int v = tp_vp_encode(m);

		CHECK(v >= 0 && v <= 255);
		if (v < 0)
			break;
		CHECK(tp_vp_decode((uint8_t)v) >= m);
	}
	memset(&rq, 0, sizeof(rq));
	rq.dest = "+821012345678";
	rq.text = "vp";
	rq.text_len = 2;
	rq.vp_minutes = 1440;
	rq.status_report = true;
	rq.mr = 7;
	CHECK(tp_encode_submit(&rq, pdu, 2) == 1);
	CHECK(pdu[0].data[0] == 0x31 && pdu[0].data[1] == 7);
	CHECK(tp_decode_submit(pdu[0].data, pdu[0].len, &s) == 0);
	CHECK(s.srr && s.vp_relative && s.vp_minutes == 1440 && s.addr.ton == 1);
	CHECK_STR(s.addr.str, "+821012345678");
	rq.vp_minutes = 63u * 10080u + 1;
	CHECK(tp_encode_submit(&rq, pdu, 2) == TP_E_VP);
}

/* ---- encoder: boundaries, alphabets, segmentation ---- */

/* decode all segments, check consistency, return concatenated text */
static int roundtrip(const char *dest, const char *text, size_t tl, size_t expect_segs, bool expect_ucs2, char *out,
		     size_t outmax)
{
	static struct tp_pdu pdu[TP_MAX_SEGMENTS];
	struct tp_submit_req rq;
	int ns, i;
	size_t pos = 0;

	memset(&rq, 0, sizeof(rq));
	rq.dest = dest;
	rq.text = text;
	rq.text_len = tl;
	rq.mr = 250;
	rq.concat_ref = 0x5A;
	ns = tp_encode_submit(&rq, pdu, TP_MAX_SEGMENTS);
	if (ns < 0)
		return ns;
	CHECK((size_t)ns == expect_segs || expect_segs == 0);
	for (i = 0; i < ns; i++) {
		static struct tp_sms s;
		int r = tp_decode_submit(pdu[i].data, pdu[i].len, &s);

		CHECK(r == 0);
		if (r < 0)
			return r;
		CHECK(pdu[i].len <= TP_MAX_TPDU && pdu[i].len - 0 <= 7 + 12 + 140 + 4);
		CHECK(s.mr == (uint8_t)(250 + i));
		CHECK(s.dcs == (expect_ucs2 ? 0x08 : 0x00) || expect_segs == 0);
		CHECK(!s.flags);
		if (ns > 1) {
			CHECK(s.udhi && s.concat.present && !s.concat.ref16 && s.concat.ref == 0x5A);
			CHECK(s.concat.total == ns && s.concat.seq == i + 1);
			CHECK(pdu[i].seq == i + 1 && pdu[i].total == ns);
			CHECK(s.udh_len == 5);
		} else {
			CHECK(!s.udhi && !s.concat.present);
		}
		if (pos + s.text_len + 1 > outmax)
			return -100;
		memcpy(out + pos, s.text, s.text_len);
		pos += s.text_len;
	}
	out[pos] = 0;
	return ns;
}

static void gen(char *o, const char *unit, size_t n)
{
	size_t i, l = strlen(unit);

	for (i = 0; i < n; i++)
		memcpy(o + i * l, unit, l);
	o[n * l] = 0;
}

static void test_encode_boundaries(void)
{
	static char t[70000], back[70000];
	static struct tp_pdu pdu[TP_MAX_SEGMENTS];
	struct tp_submit_req rq;
	size_t k;

	memset(&rq, 0, sizeof(rq));
	rq.dest = "01012345678";
	rq.mr = 1;
	rq.text = t;

	/* 160 / 161 septets */
	gen(t, "a", 160);
	CHECK(roundtrip("01012345678", t, 160, 1, false, back, sizeof(back)) == 1 && !strcmp(t, back));
	gen(t, "a", 161);
	CHECK(roundtrip("01012345678", t, 161, 2, false, back, sizeof(back)) == 2 && !strcmp(t, back));
	rq.text_len = 161;
	CHECK(tp_encode_submit(&rq, pdu, 4) == 2);
	CHECK(pdu[0].data[0] == 0x41);
	/* UDL of segment 1 = 7 + 153, segment 2 = 7 + 8; header at known offset */
	k = 1 + 1 + 2 + 6 + 2;	/* b0 mr da(len toa 6 octets=hmm) */
	(void)k;
	{
		struct tp_sms s;

		CHECK(tp_decode_submit(pdu[0].data, pdu[0].len, &s) == 0 && s.text_len == 153);
		CHECK(tp_decode_submit(pdu[1].data, pdu[1].len, &s) == 0 && s.text_len == 8);
	}
	CHECK(tp_encode_submit(&rq, pdu, 1) == TP_E_TOOLONG);

	/* 70 / 71 UCS2 */
	gen(t, "\xea\xb0\x80", 70);
	CHECK(roundtrip("01012345678", t, strlen(t), 1, true, back, sizeof(back)) == 1 && !strcmp(t, back));
	gen(t, "\xea\xb0\x80", 71);
	CHECK(roundtrip("01012345678", t, strlen(t), 2, true, back, sizeof(back)) == 2 && !strcmp(t, back));

	/* 160 septets with one extension char (158 + euro = 160): still single */
	gen(t, "a", 158);
	strcat(t, "\xe2\x82\xac");
	CHECK(roundtrip("01012345678", t, strlen(t), 1, false, back, sizeof(back)) == 1 && !strcmp(t, back));
	/* 159 + euro = 161 septets: two segments, escape pair intact */
	gen(t, "a", 159);
	strcat(t, "\xe2\x82\xac");
	CHECK(roundtrip("01012345678", t, strlen(t), 2, false, back, sizeof(back)) == 2 && !strcmp(t, back));
	/* extension at the segment boundary: 152 a + euro + b -> seg1 = 152 septets, seg2 starts with euro */
	gen(t, "a", 152);
	strcat(t, "\xe2\x82\xac" "bcccccccccc");
	rq.text_len = strlen(t);
	CHECK(tp_encode_submit(&rq, pdu, 4) == 2);
	{
		struct tp_sms s;

		CHECK(tp_decode_submit(pdu[0].data, pdu[0].len, &s) == 0 && s.text_len == 152);
		CHECK(tp_decode_submit(pdu[1].data, pdu[1].len, &s) == 0);
		CHECK_STR(s.text, "\xe2\x82\xac" "bcccccccccc");
	}
	/* extension char ending exactly at 153 */
	gen(t, "a", 151);
	strcat(t, "\xe2\x82\xac" "bcdefghijklmnop");
	rq.text_len = strlen(t);
	CHECK(tp_encode_submit(&rq, pdu, 4) == 2);
	{
		struct tp_sms s;

		CHECK(tp_decode_submit(pdu[0].data, pdu[0].len, &s) == 0 && s.text_len == 151 + 3);
		CHECK(tp_decode_submit(pdu[1].data, pdu[1].len, &s) == 0 && s.text_len == 15);
	}

	/* 200 Hangul syllables: 3 UCS2 segments 67 + 67 + 66 */
	gen(t, "\xed\x95\x9c", 200);
	rq.text_len = strlen(t);
	CHECK(tp_encode_submit(&rq, pdu, 8) == 3);
	CHECK(roundtrip("01012345678", t, strlen(t), 3, true, back, sizeof(back)) == 3 && !strcmp(t, back));
	{
		struct tp_sms s;

		CHECK(tp_decode_submit(pdu[2].data, pdu[2].len, &s) == 0 && s.text_len == 66 * 3);
		CHECK(pdu[0].len <= 140 + 20);
	}

	/* emoji at a segment boundary: 66 hangul + U+1F600 + 10 hangul -> the pair moves to segment 2 */
	gen(t, "\xed\x95\x9c", 66);
	strcat(t, "\xf0\x9f\x98\x80");
	gen(t + strlen(t), "\xea\xb0\x80", 10);
	rq.text_len = strlen(t);
	CHECK(tp_encode_submit(&rq, pdu, 8) == 2);
	{
		struct tp_sms s;

		CHECK(tp_decode_submit(pdu[0].data, pdu[0].len, &s) == 0 && s.text_len == 66 * 3 && !s.flags);
		CHECK(tp_decode_submit(pdu[1].data, pdu[1].len, &s) == 0 && !s.flags);
		CHECK(!strncmp(s.text, "\xf0\x9f\x98\x80", 4));
	}
	CHECK(roundtrip("01012345678", t, strlen(t), 2, true, back, sizeof(back)) == 2 && !strcmp(t, back));
	/* emoji that exactly fits at 66+1 */
	gen(t, "\xed\x95\x9c", 65);
	strcat(t, "\xf0\x9f\x98\x80");
	gen(t + strlen(t), "\xea\xb0\x80", 10);
	CHECK(roundtrip("01012345678", t, strlen(t), 2, true, back, sizeof(back)) == 2 && !strcmp(t, back));
	/* single emoji message: 2 units */
	CHECK(roundtrip("01012345678", "hi \xf0\x9f\x98\x80", 7, 1, true, back, sizeof(back)) == 1);
	CHECK_STR(back, "hi \xf0\x9f\x98\x80");

	/* too many segments: 255 * 153 fits, +1 does not */
	gen(t, "a", 255 * 153);
	CHECK(roundtrip("01012345678", t, strlen(t), 255, false, back, sizeof(back)) == 255 && !strcmp(t, back));
	gen(t, "a", 255 * 153 + 1);
	rq.text_len = strlen(t);
	CHECK(tp_encode_submit(&rq, pdu, TP_MAX_SEGMENTS) == TP_E_TOOLONG);

	/* forced UCS2 for pure ASCII */
	rq.text = "abc";
	rq.text_len = 3;
	rq.force_ucs2 = true;
	CHECK(tp_encode_submit(&rq, pdu, 1) == 1 && pdu[0].ucs2 && pdu[0].data[pdu[0].len - 7] == 6);
	rq.force_ucs2 = false;
	/* empty text */
	rq.text = "";
	rq.text_len = 0;
	CHECK(tp_encode_submit(&rq, pdu, 1) == 1);
	{
		struct tp_sms s;

		CHECK(tp_decode_submit(pdu[0].data, pdu[0].len, &s) == 0 && s.text_len == 0);
	}
}

static void test_encode_errors(void)
{
	struct tp_submit_req rq;
	struct tp_pdu pdu[2];
	static const char *bad[] = {
		"\xc0\x80", "\xed\xa0\x80", "\xe2\x82", "\xf4\x90\x80\x80", "\x80", "ab\xff", "a\0b", "\xf0\x80\x80\x80",
		"\xe0\x80\x80",
	};
	size_t i;

	memset(&rq, 0, sizeof(rq));
	rq.dest = "01012345678";
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		rq.text = bad[i];
		rq.text_len = (i == 6) ? 3 : strlen(bad[i]);
		CHECK(tp_encode_submit(&rq, pdu, 2) == TP_E_UTF8);
	}
	rq.text = "x";
	rq.text_len = 1;
	rq.dest = "";
	CHECK(tp_encode_submit(&rq, pdu, 2) == TP_E_ADDR);
	rq.dest = "+";
	CHECK(tp_encode_submit(&rq, pdu, 2) == TP_E_ADDR);
	rq.dest = "010-1234";
	CHECK(tp_encode_submit(&rq, pdu, 2) == TP_E_ADDR);
	rq.dest = "123456789012345678901";
	CHECK(tp_encode_submit(&rq, pdu, 2) == TP_E_ADDR);
	rq.dest = "12345678901234567890";
	CHECK(tp_encode_submit(&rq, pdu, 2) == 1);
	rq.dest = "*123#";
	CHECK(tp_encode_submit(&rq, pdu, 2) == 1);
	CHECK(pdu[0].data[2] == 5 && pdu[0].data[3] == 0x81 && pdu[0].data[4] == 0x1A && pdu[0].data[5] == 0x32 &&
	      pdu[0].data[6] == 0xFB);
	CHECK(tp_encode_submit(NULL, pdu, 2) == TP_E_ARG);
	rq.dest = NULL;
	CHECK(tp_encode_submit(&rq, pdu, 2) == TP_E_ARG);
	/* all of GSM 7-bit incl. every extension char is encodable as GSM7 (DCS 0) */
	rq.dest = "0101";
	rq.text = "@\xc2\xa3$\xc2\xa5\xc3\xa8\xc3\xa9\xc3\xb9\xc3\xac\xc3\xb2\xc3\x87\n\xc3\x98\xc3\xb8\r\xc3\x85\xc3\xa5"
		  "\xce\x94_\xce\xa6\xce\x93\xce\x9b\xce\xa9\xce\xa0\xce\xa8\xce\xa3\xce\x98\xce\x9e\xc3\x86\xc3\xa6\xc3\x9f\xc3\x89"
		  " !\"#\xc2\xa4%&'()*+,-./0123456789:;<=>?\xc2\xa1" "ABCDEFGHIJKLMNOPQRSTUVWXYZ\xc3\x84\xc3\x96\xc3\x91\xc3\x9c\xc2\xa7"
		  "\xc2\xbf" "abcdefghijklmnopqrstuvwxyz\xc3\xa4\xc3\xb6\xc3\xb1\xc3\xbc\xc3\xa0\x0c^{}\\[~]|\xe2\x82\xac";
	{
		static char back[2000];
		const char *t = rq.text;
		size_t tl = strlen(t) + 0;

		/* the string above contains a raw 0x0c byte -> NUL-safe because strlen stops at no NUL */
		CHECK(roundtrip("0101", t, tl, 0, false, back, sizeof(back)) >= 1);
		CHECK(!strcmp(t, back));
	}
}

static void test_roundtrip_table(void)
{
	static const char *tab[] = {
		"", "a", "hello world", "Hello, \xec\x84\xb8\xea\xb3\x84!", "\xed\x85\x8c\xec\x8a\xa4\xed\x8a\xb8",
		"price: 5\xe2\x82\xac [ok] {x} ~ | ^ \\", "line1\nline2\r\nline3", "\xf0\x9f\x98\x80\xf0\x9f\x91\x8d",
		"mixed \xed\x95\x9c\xea\xb8\x80 and emoji \xf0\x9f\x8e\x89 and \xc3\xa9", "@@@@", "\xc3\xa9\xc3\xa8\xc3\xa0",
		"\xe4\xb8\xad\xe6\x96\x87", "\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82", "\xc2\xa0nbsp",
	};
	static char back[20000], big[12000];
	size_t i;

	for (i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
		CHECK(roundtrip("+821012345678", tab[i], strlen(tab[i]), 0, false, back, sizeof(back)) >= 1);
		CHECK_STR(back, tab[i]);
	}
	/* long variations of each */
	for (i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
		size_t k, l = strlen(tab[i]);

		if (!l)
			continue;
		big[0] = 0;
		for (k = 0; k < 11000 / l && k < 150; k++)
			strcat(big, tab[i]);
		CHECK(roundtrip("01012345678", big, strlen(big), 0, false, back, sizeof(back)) >= 1);
		CHECK_STR(back, big);
	}
	/* random strings from a mixed alphabet */
	{
		static const char *pieces[] = { "a", "Z", " ", "\xe2\x82\xac", "{", "\xea\xb0\x80", "\xed\x9e\xa3", "\xf0\x9f\x98\x80",
						"\n", "~", "\xc3\xa9", "9", "\xce\x94" };
		int it;

		for (it = 0; it < 300; it++) {
			size_t cnt = rnd() % 400, k;

			big[0] = 0;
			/* half of the cases stay inside GSM 7-bit */
			for (k = 0; k < cnt; k++) {
				size_t pi = rnd() % (it & 1 ? 13 : 7);

				if (!(it & 1) && (pi == 5 || pi == 6))
					pi = 0;
				strcat(big, pieces[pi]);
			}
			CHECK(roundtrip("01099998888", big, strlen(big), 0, false, back, sizeof(back)) >= 1);
			CHECK_STR(back, big);
		}
	}
}

/* ---- robustness ---- */
static void test_fuzz(void)
{
	static const char *seeds[] = {
		"040b811050216268f200086211025061646306d14cc2a4d2b8",
		"040b811050216268f2000062110250731463" "15e9f6bc1e0685e1ad747b0e9ab7e7207a794e07",
		"44038121430008621102506164630d" "0500034002010041004200430044",
		"640b811050216268f2008462110250616463" "04c7d1b1db",
		"01140b811050216268f2000015e9f6bc1e0685e1ad747b0e9ab7e7207a794e07",
		"3120" "0b811050216268f2000008" "06d14cc2a4d2b8",
	};
	uint8_t buf[300];
	size_t si, n, i;
	int iter;
	struct tp_sms s;
	struct tp_status_report sr;
	struct tp_submit_report rep;

	for (si = 0; si < sizeof(seeds) / sizeof(seeds[0]); si++) {
		n = unhex(seeds[si], buf, sizeof(buf));
		for (i = 0; i <= n; i++) {
			uint8_t *tmp = malloc(i ? i : 1);	/* exact size: ASan catches any over-read */

			memcpy(tmp, buf, i);
			tp_decode_deliver(tmp, i, &s);
			tp_decode_submit(tmp, i, &s);
			tp_decode_status_report(tmp, i, &sr);
			tp_decode_submit_report(tmp, i, false, &rep);
			tp_decode_submit_report(tmp, i, true, &rep);
			free(tmp);
		}
		for (iter = 0; iter < 20000; iter++) {
			size_t len = n;
			uint8_t *tmp;
			int m = 1 + (int)(rnd() % 4);

			tmp = malloc(len + 8);
			memcpy(tmp, buf, n);
			while (m--)
				tmp[rnd() % n] = (uint8_t)rnd();
			if (iter % 3 == 0)
				len = rnd() % (n + 1);
			{
				uint8_t *ex = malloc(len ? len : 1);

				memcpy(ex, tmp, len);
				tp_decode_deliver(ex, len, &s);
				tp_decode_submit(ex, len, &s);
				tp_decode_status_report(ex, len, &sr);
				tp_decode_submit_report(ex, len, iter & 1, &rep);
				free(ex);
			}
			free(tmp);
		}
	}
	/* fully random buffers */
	for (iter = 0; iter < 100000; iter++) {
		size_t len = rnd() % 180;
		uint8_t *ex = malloc(len ? len : 1);

		for (i = 0; i < len; i++)
			ex[i] = (uint8_t)rnd();
		tp_decode_deliver(ex, len, &s);
		tp_decode_submit(ex, len, &s);
		free(ex);
	}
	CHECK(1);
	/* random UTF-8-ish input to the encoder */
	for (iter = 0; iter < 20000; iter++) {
		size_t len = rnd() % 60;
		char *ex = malloc(len ? len : 1);
		struct tp_submit_req rq;
		static struct tp_pdu pdu[TP_MAX_SEGMENTS];
		int r;

		for (i = 0; i < len; i++)
			ex[i] = (char)(rnd() % 4 ? 0x80 + rnd() % 0x80 : rnd() & 0xFF);
		memset(&rq, 0, sizeof(rq));
		rq.dest = "01012345678";
		rq.text = ex;
		rq.text_len = len;
		r = tp_encode_submit(&rq, pdu, 4);
		CHECK(r > 0 || r == TP_E_UTF8 || r == TP_E_TOOLONG);
		free(ex);
	}
	/* strict UTF-8: round trip every scalar value class */
	{
		uint32_t cp;
		char t[4];

		for (cp = 0; cp < 0x110000; cp += (cp < 0x3000 ? 1 : 13)) {
			uint32_t back = 0;
			int k = utf8_encode(cp, t);

			if (cp >= 0xD800 && cp <= 0xDFFF) {
				CHECK(k == 0);
				continue;
			}
			CHECK(k > 0 && utf8_decode(t, (size_t)k, &back) == k && back == cp);
			if (k > 1)
				CHECK(utf8_decode(t, (size_t)k - 1, &back) == -1);
		}
	}
}

int main(void)
{
	test_real_deliver();
	test_real_submit_and_report();
	test_gsm7_pack();
	test_udh_alignment();
	test_udh_concat_and_nls();
	test_dcs();
	test_addr_and_scts();
	test_status_report();
	test_vp();
	test_encode_boundaries();
	test_encode_errors();
	test_roundtrip_table();
	test_fuzz();
	printf("test_tpdu: %d checks, %d failed\n", n_checks, n_fail);
	return n_fail ? 1 : 0;
}
