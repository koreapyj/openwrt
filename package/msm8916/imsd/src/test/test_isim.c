/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "test.h"
#include "../modem/isim.h"
#include "../sms/rp.h"
#include "../util/codec.h"

/* "80 <len> <text>" padded with FF to total bytes, like an EF record */
static size_t rec80(const char *s, size_t total, uint8_t *out)
{
	size_t l = strlen(s);

	memset(out, 0xFF, total);
	out[0] = 0x80;
	out[1] = l;
	memcpy(out + 2, s, l);
	return total;
}

void test_isim(void)
{
	uint8_t rec[96], apdu[8];
	char out[200], user[64], host[64];
	int sw, n;
	size_t l;

	/* ---- APDUs ---- */
	l = isim_apdu_select(3, ISIM_FID_IMPU, apdu);
	CHECK(l == 7 && apdu[0] == 0x03 && apdu[1] == 0xA4 && apdu[2] == 0 && apdu[3] == 4 && apdu[4] == 2 && apdu[5] == 0x6F && apdu[6] == 0x04);
	l = isim_apdu_read_binary(1, 0, apdu);
	CHECK(l == 5 && apdu[0] == 0x01 && apdu[1] == 0xB0 && apdu[2] == 0 && apdu[3] == 0 && apdu[4] == 0);
	l = isim_apdu_read_record(2, 3, 0x40, apdu);
	CHECK(l == 5 && apdu[0] == 0x02 && apdu[1] == 0xB2 && apdu[2] == 3 && apdu[3] == 0x04 && apdu[4] == 0x40);
	isim_apdu_select(0, ISIM_FID_IMPI, apdu);
	CHECK_EQ(apdu[0], 0x00);
	isim_apdu_select(5, ISIM_FID_DOMAIN, apdu);
	CHECK_EQ(apdu[0], 0x41);

	/* ---- data objects ---- */
	rec80("450061051226862@lte-lguplus.co.kr", 64, rec);
	rec[64] = 0x90; rec[65] = 0x00;
	n = isim_split_sw(rec, 66, &sw);
	CHECK_EQ(n, 64); CHECK_EQ(sw, 0x9000);
	CHECK_EQ(isim_tlv80(rec, n, out, sizeof(out)), 33);
	CHECK_STR(out, "450061051226862@lte-lguplus.co.kr");
	CHECK(isim_split_sw(rec, 1, &sw) < 0);
	/* from a hex dump, as the card returns it ("80 11 lte-lguplus.co.kr" + FF) */
	{
		uint8_t h[40];
		int hn = hex_decode("8011 6c74652d6c6775706c75732e636f2e6b72 ffffff 9000", h, sizeof(h));

		CHECK_EQ(hn, 2 + 17 + 3 + 2);
		n = isim_split_sw(h, hn, &sw);
		CHECK_EQ(isim_tlv80(h, n, out, sizeof(out)), 17);
		CHECK_STR(out, "lte-lguplus.co.kr");
	}
	memset(rec, 0xFF, sizeof(rec));	/* empty record */
	CHECK(isim_tlv80(rec, 32, out, sizeof(out)) < 0);
	rec80("sip:x@y", 20, rec); rec[1] = 30;	/* length beyond the data */
	CHECK(isim_tlv80(rec, 20, out, sizeof(out)) < 0);
	rec80("0123456789", 20, rec);
	CHECK(isim_tlv80(rec, 20, out, 5) < 0);	/* does not fit */
	rec[0] = 0x81;
	CHECK(isim_tlv80(rec, 20, out, sizeof(out)) < 0);

	/* ---- EF_SMSP (TS 31.102): the record of the test SIM ---- */
	{
		uint8_t sm[64];
		int sn = hex_decode("534d532043656e747265ffffffffffff e9 ffffffffffffffffffffffff 0791280108105058ffffffff 00 ff ff", sm, sizeof(sm));

		CHECK_EQ(sn, 44);
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), 13);
		CHECK_STR(out, "+821080010585");
		/* alpha identifier of any length: the layout is anchored at the end of the record */
		memmove(sm + 3, sm, sn);
		memcpy(sm, "\xff\xff\xff", 3);
		CHECK_EQ(isim_smsp_parse(sm, sn + 3, out, sizeof(out)), 13);
		CHECK_STR(out, "+821080010585");
		memmove(sm, sm + 3 + 16, sn - 16);	/* no alpha identifier at all: 28 bytes */
		CHECK_EQ(isim_smsp_parse(sm, 28, out, sizeof(out)), 13);
		CHECK_STR(out, "+821080010585");
		CHECK_EQ(isim_smsp_parse(sm, 27, out, sizeof(out)), -1);	/* too short */
		/* TON variants */
		sn = hex_decode("ffffffffffff e9 ffffffffffffffffffffffff 0781280108105058ffffffff 00 ff ff", sm, sizeof(sm));
		CHECK_EQ(sn, 34);
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), 12);	/* TON 0 (unknown): digits as is */
		CHECK_STR(out, "821080010585");
		sm[sn - 14] = 0xA1;	/* national */
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), 12);
		CHECK_STR(out, "821080010585");
		sm[sn - 14] = 0x91;	/* international */
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), 13);
		CHECK_STR(out, "+821080010585");
		/* odd number of digits: filler nibble F */
		sm[sn - 8] = 0xF8;
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), 12);
		CHECK_STR(out, "+82108001058");
		sm[sn - 8] = 0x58;
		/* absent: parameter indicator bit 2 set, or length byte 0 / FF */
		sm[6] = 0xEB;
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), 0); CHECK_STR(out, "");
		sm[6] = 0xE9;
		sm[sn - 15] = 0x00;
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), 0);
		sm[sn - 15] = 0xFF;
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), 0);
		memset(sm, 0xFF, sn); sm[6] = 0xE9;	/* an erased record that claims the SCA is valid */
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), 0);
		/* garbage lengths and digits */
		sn = hex_decode("ffffffffffff e9 ffffffffffffffffffffffff 0c91280108105058ffffffff 00 ff ff", sm, sizeof(sm));
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), -1);	/* longer than the 10 BCD bytes of a TS-SCA */
		sm[sn - 15] = 0x01;
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), -1);	/* no digit bytes after TON/NPI */
		sn = hex_decode("ffffffffffff e9 ffffffffffffffffffffffff 07912c01081050d8ffffffff 00 ff ff", sm, sizeof(sm));
		CHECK_EQ(isim_smsp_parse(sm, sn, out, sizeof(out)), -1);	/* nibble C / D is no digit */
		CHECK_STR(out, "");
		CHECK_EQ(isim_smsp_parse(sm, sn, out, 8), -1);	/* output too small */
	}
	/* ---- EF_PSISMSC ---- */
	{
		uint8_t pd[64];
		int pn = hex_decode("80 1c 7369703a6970736d67772e6c74652d6c6775706c75732e636f2e6b72 ffffffff", pd, sizeof(pd));

		CHECK_EQ(pn, 2 + 28 + 4);
		CHECK_EQ(isim_psismsc_parse(pd, pn, out, sizeof(out)), 28);
		CHECK_STR(out, "sip:ipsmgw.lte-lguplus.co.kr");
		memmove(pd + 2, pd, pn);	/* leading FF padding */
		pd[0] = pd[1] = 0xFF;
		CHECK_EQ(isim_psismsc_parse(pd, pn + 2, out, sizeof(out)), 28);
		memset(pd, 0xFF, sizeof(pd));	/* empty file */
		CHECK_EQ(isim_psismsc_parse(pd, sizeof(pd), out, sizeof(out)), -1); CHECK_STR(out, "");
		pn = hex_decode("80 0a 74656c3a2b3832313031 ff", pd, sizeof(pd));
		CHECK_EQ(isim_psismsc_parse(pd, pn, out, sizeof(out)), 10); CHECK_STR(out, "tel:+82101");
		pd[1] = 0x40;	/* length beyond the data */
		CHECK_EQ(isim_psismsc_parse(pd, pn, out, sizeof(out)), -1);
		pd[1] = 0;	/* empty URI */
		CHECK_EQ(isim_psismsc_parse(pd, pn, out, sizeof(out)), -1);
		pd[0] = 0x81; pd[1] = 10;	/* wrong tag */
		CHECK_EQ(isim_psismsc_parse(pd, pn, out, sizeof(out)), -1);
		pd[0] = 0x80; pd[1] = 10; pd[4] = 0x01;	/* control character: not a URI */
		CHECK_EQ(isim_psismsc_parse(pd, pn, out, sizeof(out)), -1);
		pn = hex_decode("80 81 0a 74656c3a2b3832313031", pd, sizeof(pd));	/* long form length */
		CHECK_EQ(isim_psismsc_parse(pd, pn, out, sizeof(out)), 10);
		CHECK_EQ(isim_psismsc_parse(pd, pn, out, 5), -1);
	}
	l = isim_apdu_get_response(2, 0x2c, apdu);
	CHECK(l == 5 && apdu[0] == 0x02 && apdu[1] == 0xC0 && apdu[2] == 0 && apdu[3] == 0 && apdu[4] == 0x2c);
	l = isim_apdu_select(1, USIM_FID_SMSP, apdu);
	CHECK(l == 7 && apdu[0] == 0x01 && apdu[1] == 0xA4 && apdu[5] == 0x6F && apdu[6] == 0x42);
	CHECK_STR(USIM_AID, "A0000000871002");

	/* ---- IMPU selection: the emergency record is skipped ---- */
	CHECK_EQ(isim_impu_usable("sip:01051226862@sos.lte-lguplus.co.kr"), 0);
	CHECK_EQ(isim_impu_usable("sip:01051226862@SOS.lte-lguplus.co.kr"), 0);
	CHECK_EQ(isim_impu_usable("sip:01051226862@lte-lguplus.co.kr"), 1);
	CHECK_EQ(isim_impu_usable("tel:+821051226862"), 0);
	CHECK_EQ(isim_impu_usable("garbage"), 0);
	CHECK_EQ(isim_impu_usable("sip:01058512207@ims.mnc008.mcc450.3gppnetwork.org"), 1);
	CHECK(!isim_impu_split("sip:01051226862@lte-lguplus.co.kr", user, sizeof(user), host, sizeof(host)));
	CHECK_STR(user, "01051226862"); CHECK_STR(host, "lte-lguplus.co.kr");
	CHECK(!isim_impu_split("sip:+821051226862@lte-lguplus.co.kr;user=phone", user, sizeof(user), host, sizeof(host)));
	CHECK_STR(user, "+821051226862"); CHECK_STR(host, "lte-lguplus.co.kr");
	CHECK(isim_impu_split("tel:+8210", user, sizeof(user), host, sizeof(host)) < 0);
	CHECK(isim_impu_split("sip:01051226862@lte-lguplus.co.kr", user, 5, host, sizeof(host)) < 0);

	/* ---- IMEI ---- */
	CHECK(!ims_format_imei("868837083662185", out, sizeof(out)));
	CHECK_STR(out, "86883708-366218-5");
	CHECK(!ims_format_imei("86883708366218", out, sizeof(out)));	/* 14 digits: check digit computed */
	CHECK_STR(out, "86883708-366218-5");
	CHECK(!ims_format_imei("8688370836621801", out, sizeof(out)));	/* IMEISV: version dropped */
	CHECK_STR(out, "86883708-366218-5");
	CHECK(ims_format_imei("86883708", out, sizeof(out)) < 0);
	CHECK(ims_format_imei("86883708366218x", out, sizeof(out)) < 0);
	CHECK(ims_format_imei("", out, sizeof(out)) < 0);
	CHECK(ims_format_imei("868837083662185", out, 10) < 0);
}

void test_rp(void)
{
	/* real RP PDUs from the network (apims_research.md, l1/n2 logs) */
	static const char *const RPDATA_MT = "013e07912801022981120019040b811050216268f200086211025061646306d14cc2a4d2b8";
	static const char *const RPACK_N = "03ae4109010062110250731463";
	static const char *const RPDATA_MT2 = "016807912801022981720026040b811050216268f200006211025073146315e9f6bc1e0685e1ad747b0e9ab7e7207a794e07";
	uint8_t d[64], ack[2];
	struct rp_info ri;
	int n;

	n = hex_decode(RPDATA_MT, d, sizeof(d));
	CHECK_EQ(n, 37);
	CHECK(!rp_parse(d, n, &ri));
	CHECK_EQ(ri.mti, RP_DATA_N_MS); CHECK_EQ(ri.mr, 0x3e); CHECK_EQ(ri.cause, -1);
	rp_build_ack(ri.mr, ack);
	CHECK(ack[0] == 0x02 && ack[1] == 0x3e);
	n = hex_decode(RPDATA_MT2, d, sizeof(d));
	CHECK_EQ(n, 50);
	CHECK(!rp_parse(d, n, &ri));
	CHECK_EQ(ri.mti, RP_DATA_N_MS); CHECK_EQ(ri.mr, 0x68);
	n = hex_decode(RPACK_N, d, sizeof(d));
	CHECK_EQ(n, 13);
	CHECK(!rp_parse(d, n, &ri));
	CHECK_EQ(ri.mti, RP_ACK_N_MS); CHECK_EQ(ri.mr, 0xae);
	/* RP-ERROR n->ms: 05 MR len cause */
	d[0] = 0x05; d[1] = 0x11; d[2] = 0x01; d[3] = 0x16;
	CHECK(!rp_parse(d, 4, &ri));
	CHECK_EQ(ri.mti, RP_ERROR_N_MS); CHECK_EQ(ri.mr, 0x11); CHECK_EQ(ri.cause, 0x16);
	CHECK(rp_parse(d, 1, &ri) < 0);
	CHECK_STR(rp_mti_name(RP_DATA_N_MS), "RP-DATA(n->ms)");
	CHECK_STR(rp_mti_name(RP_ACK_N_MS), "RP-ACK(n->ms)");
}
