/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "test.h"
#include "../aka.h"

static size_t db_resp(uint8_t *db, int with_kc, int with_sw)
{
	size_t n = 0;
	int i;

	db[n++] = 0xDB; db[n++] = 8;
	for (i = 0; i < 8; i++) db[n++] = 0x10 + i;
	db[n++] = 16; for (i = 0; i < 16; i++) db[n++] = 0x20 + i;
	db[n++] = 16; for (i = 0; i < 16; i++) db[n++] = 0x40 + i;
	if (with_kc) { db[n++] = 8; for (i = 0; i < 8; i++) db[n++] = 0x60 + i; }
	if (with_sw) { db[n++] = 0x90; db[n++] = 0x00; }
	return n;
}

void test_aka(void)
{
	struct aka_result r;
	uint8_t db[64], a[AKA_APDU_MAX], rnd[16] = { 1 }, autn[16] = { 2 };
	size_t n, l;
	int i;
	struct aka_cfg c = { .p2 = 0x81, .cla_from_channel = 1, .channel = 3 };
	struct aka_sm sm;

	/* DB 08 RES(8) 10 CK 10 IK [08 Kc] [90 00] */
	n = db_resp(db, 0, 0);
	CHECK(!aka_parse(db, n, &r) && r.status == AKA_OK && r.res_len == 8 && r.res[0] == 0x10 && r.ck[0] == 0x20 && r.ik[15] == 0x4f && !r.has_kc);
	n = db_resp(db, 0, 1);
	CHECK(!aka_parse(db, n, &r) && r.status == AKA_OK && r.sw == 0x9000);
	n = db_resp(db, 1, 1);
	CHECK(!aka_parse(db, n, &r) && r.has_kc && r.kc[7] == 0x67 && r.sw == 0x9000);
	/* DC 0E AUTS(14) */
	n = 0; db[n++] = 0xDC; db[n++] = 14; for (i = 0; i < 14; i++) db[n++] = 0xA0 + i; db[n++] = 0x90; db[n++] = 0;
	CHECK(!aka_parse(db, n, &r) && r.status == AKA_SYNC_FAIL && r.auts_len == 14 && r.auts[13] == 0xAD);
	/* bare MAC failure SW, truncated data */
	db[0] = 0x98; db[1] = 0x62;
	CHECK(aka_parse(db, 2, &r) < 0 && r.sw == 0x9862);
	n = db_resp(db, 0, 0);
	CHECK(aka_parse(db, n - 3, &r) < 0);
	/* apdu layout */
	l = aka_build_apdu(&c, rnd, autn, a);
	CHECK(l == 40 && a[0] == 0x03 && a[1] == 0x88 && a[2] == 0 && a[3] == 0x81 && a[4] == 0x22 && a[5] == 0x10 && a[6] == 1 && a[22] == 0x10 && a[23] == 2 && a[39] == 0);
	c.cla_from_channel = 0; l = aka_build_apdu(&c, rnd, autn, a); CHECK_EQ(a[0], 0x00);
	CHECK_EQ(aka_cla(0), 0); CHECK_EQ(aka_cla(2), 2); CHECK_EQ(aka_cla(4), 0x40); CHECK_EQ(aka_cla(19), 0x4f);

	/* state machine: 61 2D -> GET RESPONSE -> DB.. 9000 */
	c.cla_from_channel = 1; c.channel = 3;
	aka_sm_start(&sm, &c, rnd, autn, a, &l);
	CHECK(l == 40 && a[1] == 0x88);
	db[0] = 0x61; db[1] = 0x2d;
	CHECK_EQ(aka_sm_feed(&sm, db, 2, a, &l), AKA_STEP_SEND);
	CHECK(l == 5 && a[0] == 0x03 && a[1] == 0xC0 && a[4] == 0x2d);
	n = db_resp(db, 0, 1);
	CHECK_EQ(aka_sm_feed(&sm, db, n, a, &l), AKA_STEP_DONE);
	CHECK(aka_sm_result(&sm)->status == AKA_OK && aka_sm_result(&sm)->res_len == 8 && aka_sm_result(&sm)->sw == 0x9000);
	CHECK_EQ(aka_sm_feed(&sm, db, n, a, &l), AKA_STEP_FAIL);	/* finished machines refuse more input */

	/* 6C xx: repeat AUTHENTICATE with the corrected Le, once */
	aka_sm_start(&sm, &c, rnd, autn, a, &l);
	db[0] = 0x6c; db[1] = 0x2c;
	CHECK_EQ(aka_sm_feed(&sm, db, 2, a, &l), AKA_STEP_SEND);
	CHECK(l == 40 && a[1] == 0x88 && a[39] == 0x2c);
	CHECK_EQ(aka_sm_feed(&sm, db, 2, a, &l), AKA_STEP_FAIL);
	CHECK_EQ(aka_sm_result(&sm)->sw, 0x6c2c);

	/* resynchronisation */
	aka_sm_start(&sm, &c, rnd, autn, a, &l);
	n = 0; db[n++] = 0xDC; db[n++] = 14; for (i = 0; i < 14; i++) db[n++] = i; db[n++] = 0x90; db[n++] = 0;
	CHECK_EQ(aka_sm_feed(&sm, db, n, a, &l), AKA_STEP_DONE);
	CHECK(aka_sm_result(&sm)->status == AKA_SYNC_FAIL && aka_sm_result(&sm)->auts_len == 14);

	/* MAC failure: FAIL with the status word */
	aka_sm_start(&sm, &c, rnd, autn, a, &l);
	db[0] = 0x98; db[1] = 0x62;
	CHECK_EQ(aka_sm_feed(&sm, db, 2, a, &l), AKA_STEP_FAIL); CHECK_EQ(aka_sm_result(&sm)->sw, 0x9862);
	CHECK(aka_sm_result(&sm)->status == AKA_ERR);

	/* endless 61xx loops end after 3 GET RESPONSEs; transport failure aborts */
	aka_sm_start(&sm, &c, rnd, autn, a, &l);
	db[0] = 0x61; db[1] = 0x10;
	for (i = 0; i < 3; i++) CHECK_EQ(aka_sm_feed(&sm, db, 2, a, &l), AKA_STEP_SEND);
	CHECK_EQ(aka_sm_feed(&sm, db, 2, a, &l), AKA_STEP_FAIL);
	aka_sm_start(&sm, &c, rnd, autn, a, &l);
	aka_sm_abort(&sm); CHECK(aka_sm_result(&sm)->status == AKA_ERR);
}
