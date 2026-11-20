/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include "cstest.h"
#include "../cscall.h"
#include "../cssms.h"
#include "../csmedia.h"
#include "../../call/gmcall_util.h"

static void t_cause(void)
{
	static const struct { int q; int sip; } T[] = {
		{ 1, 404 }, { 2, 404 }, { 3, 404 }, { 16, 480 }, { 17, 486 }, { 18, 408 }, { 19, 480 }, { 20, 480 }, { 21, 603 }, { 22, 410 },
		{ 25, 483 }, { 27, 502 }, { 28, 484 }, { 29, 501 }, { 31, 480 }, { 34, 503 }, { 38, 503 }, { 41, 503 }, { 42, 503 }, { 44, 503 },
		{ 47, 503 }, { 55, 403 }, { 57, 403 }, { 58, 503 }, { 65, 488 }, { 69, 501 }, { 79, 501 }, { 87, 403 }, { 88, 503 }, { 102, 504 },
		{ 111, 500 }, { 127, 500 },
		/* not in the table: by class */
		{ 5, 480 }, { 30, 480 }, { 35, 503 }, { 63, 503 }, { 70, 501 }, { 95, 501 }, { 96, 500 }, { 126, 500 },
		{ 0, 500 }, { 128, 500 }, { -3, 500 },
	};
	size_t i;
	const char *t = NULL;

	for (i = 0; i < sizeof(T) / sizeof(T[0]); i++)
		CHECK_EQ(cs_cause_to_sip(T[i].q, NULL), T[i].sip);
	CHECK_EQ(cs_cause_to_sip(17, &t), 486);
	CHECK_STR(t, "user busy");
	CHECK_EQ(cs_cause_to_sip(99, &t), 500);
	CHECK_STR(t, "cause not in the table");

	/* inferred without a cause: MT = 487, MO by how far it got */
	CHECK_EQ(cs_infer_status(CC_MT, true, false, 0, 4000, "unknown"), 487);
	CHECK_EQ(cs_infer_status(CC_MO, false, false, 0, 4000, "unknown"), 503);
	CHECK_EQ(cs_infer_status(CC_MO, true, false, 1500, 4000, "unknown"), 603);
	CHECK_EQ(cs_infer_status(CC_MO, true, false, 4000, 4000, "unknown"), 480);
	CHECK_EQ(cs_infer_status(CC_MO, true, false, 20000, 4000, "unknown"), 480);
	CHECK_EQ(cs_infer_status(CC_MO, true, true, 20000, 4000, "unknown"), 0);
	CHECK_EQ(cs_infer_status(CC_MO, true, false, 20000, 4000, "error"), 503);
	CHECK_EQ(cs_infer_status(CC_MO, false, false, 0, 4000, NULL), 503);
}

static void t_numbers(void)
{
	static const char *const V[] = {
		"sip:01051226862@lte-lguplus.co.kr", "<sip:+821051226862@lte-lguplus.co.kr;user=phone>", "tel:010-5122-6862;phone-context=lguplus.co.kr",
		"tel:+82-10-5122-6862", "sip:%2B821051226862@d", "01012345678", "+82 10 1234 5678", "sip:anonymous@anonymous.invalid", "sip:example.com", "",
		"tel:*23#", "114", "sip:+82@h", "(010) 1234.5678",
	};
	char a[48], b[48];
	size_t i;

	/* the same answer as the IMS path gives the LAN clients */
	for (i = 0; i < sizeof(V) / sizeof(V[0]); i++) {
		int ra = cs_number_normalize(V[i], a, sizeof(a));
		int rb = gmcall_number_normalize(V[i], b, sizeof(b));

		if (ra != rb || (!ra && strcmp(a, b))) {
			t_fails++;
			printf("FAIL normalize(%s): cs %d '%s' gm %d '%s'\n", V[i], ra, ra ? "" : a, rb, rb ? "" : b);
		}
		t_checks++;
	}
	CHECK(cs_number_normalize("+8210123456789012345678901234567890123456789012345", a, 5) < 0);
	CHECK(cs_number_normalize(NULL, a, sizeof(a)) < 0);

	CHECK(cs_dial_string("+82 10-1234 5678", a, sizeof(a)) == 0 && !strcmp(a, "+821012345678"));
	CHECK(cs_dial_string("114", a, sizeof(a)) == 0 && !strcmp(a, "114"));
	CHECK(cs_dial_string("*23#", a, sizeof(a)) == 0 && !strcmp(a, "*23#"));
	CHECK(cs_dial_string("(010) 1234.5678", a, sizeof(a)) == 0 && !strcmp(a, "01012345678"));
	CHECK(cs_dial_string("", a, sizeof(a)) < 0 && cs_dial_string("+", a, sizeof(a)) < 0);
	CHECK(cs_dial_string("01a", a, sizeof(a)) < 0 && cs_dial_string("010+1", a, sizeof(a)) < 0);
	CHECK(cs_dial_string("sip:114@x", a, sizeof(a)) < 0);
	CHECK(cs_dial_string("123456789012345678901234567890123", a, sizeof(a)) < 0);
}

static void t_rat(void)
{
	CHECK(csline_rat_parse("lte") == CSRAT_LTE);
	CHECK(csline_rat_parse("umts hspa") == CSRAT_UMTS);
	CHECK(csline_rat_parse("hspa-plus") == CSRAT_UMTS);
	CHECK(csline_rat_parse("gsm gprs edge") == CSRAT_GSM);
	CHECK(csline_rat_parse("gsm lte") == CSRAT_LTE);
	CHECK(csline_rat_parse("lte-cat-m") == CSRAT_LTE);
	CHECK(csline_rat_parse("unknown") == CSRAT_NONE && csline_rat_parse("") == CSRAT_NONE && csline_rat_parse(NULL) == CSRAT_NONE);
	CHECK_STR(csline_rat_name(CSRAT_UMTS), "umts");
}

static void t_parts(void)
{
	char big[2000];
	int i;

	CHECK_EQ(cssms_count_parts("hello"), 1);
	memset(big, 'a', 160);
	big[160] = 0;
	CHECK_EQ(cssms_count_parts(big), 1);
	big[160] = 'a';
	big[161] = 0;
	CHECK_EQ(cssms_count_parts(big), 2);
	memset(big, 'a', 306);
	big[306] = 0;
	CHECK_EQ(cssms_count_parts(big), 2);
	big[306] = 'a';
	big[307] = 0;
	CHECK_EQ(cssms_count_parts(big), 3);
	/* extension characters take two septets: 80 euro signs are 160 septets, 81 do not fit one part */
	big[0] = 0;
	for (i = 0; i < 80; i++)
		strcat(big, "\xE2\x82\xAC");
	CHECK_EQ(cssms_count_parts(big), 1);
	strcat(big, "\xE2\x82\xAC");
	CHECK_EQ(cssms_count_parts(big), 2);
	/* Hangul is UCS-2: 70 / 67 */
	big[0] = 0;
	for (i = 0; i < 70; i++)
		strcat(big, "\xEA\xB0\x80");
	CHECK_EQ(cssms_count_parts(big), 1);
	strcat(big, "\xEA\xB0\x80");
	CHECK_EQ(cssms_count_parts(big), 2);
	big[0] = 0;
	for (i = 0; i < 134; i++)
		strcat(big, "\xEA\xB0\x80");
	CHECK_EQ(cssms_count_parts(big), 2);
	strcat(big, "\xEA\xB0\x80");
	CHECK_EQ(cssms_count_parts(big), 3);
	/* an emoji is two UTF-16 units */
	CHECK_EQ(cssms_count_parts("\xF0\x9F\x98\x80"), 1);
	CHECK(cssms_count_parts("\xFF") < 0 && cssms_count_parts("\xC0\x80") < 0);
	CHECK_EQ(cssms_count_parts(""), 0);
	CHECK_EQ(cssms_status_of_errno(-EINVAL), 400);
	CHECK_EQ(cssms_status_of_errno(-EDESTADDRREQ), 484);
	CHECK_EQ(cssms_status_of_errno(-E2BIG), 413);
	CHECK_EQ(cssms_status_of_errno(-ENOTCONN), 480);
	CHECK_EQ(cssms_status_of_errno(-ENOBUFS), 503);
}

/* ---- csmedia: bridge events -> call actions ---- */
static int n_fail, last_err, n_dtmf;
static char last_digit;
static enum cc_state ST = CC_ST_CONNECTED;

static void m_failed(struct carrier_call *c, int err) { (void)c; n_fail++; last_err = err; }
static int m_dtmf(struct carrier_call *c, char d) { (void)c; n_dtmf++; last_digit = d; return 0; }
static enum cc_state m_state(const struct carrier_call *c) { (void)c; return ST; }

static void t_media(void)
{
	struct carrier_call_ops ops = { .media_failed = m_failed, .send_dtmf = m_dtmf, .state = m_state };
	struct cs_media_event m;
	struct br_event ev;
	struct br_leg_cfg c;
	struct bridge_stats st;
	struct cs_pcm_stats ps;

	cs_media_leg_cfg(&c, "auto,0", 1500);
	CHECK(c.kind == BR_LEG_PCMDEV && c.pcm_rate == 8000 && c.pdev_ops == &pcmdev_alsa_ops && c.rx_timeout_ms == 1500 && !strcmp(c.pdev_spec, "auto,0"));

	memset(&ev, 0, sizeof(ev));
	ev.type = BR_EV_ERROR;
	ev.leg = BR_CARRIER;
	ev.err = EBUSY;
	strcpy(ev.msg, "pcm device open failed");
	CHECK(cs_media_classify(&ev, &m) && m.type == CSM_OPEN_FAILED && m.err == EBUSY);
	cs_media_apply(&ops, NULL, &m);
	CHECK(n_fail == 1 && last_err == EBUSY);
	ev.err = 0;
	strcpy(ev.msg, "codec create failed");
	CHECK(!cs_media_classify(&ev, &m));
	ev.type = BR_EV_PCM_LOST;
	ev.err = -ENODEV;
	CHECK(cs_media_classify(&ev, &m) && m.type == CSM_LOST && m.err == ENODEV);
	cs_media_apply(&ops, NULL, &m);
	CHECK(n_fail == 2 && last_err == ENODEV);
	ev.leg = BR_CLIENT;
	CHECK(!cs_media_classify(&ev, &m));
	memset(&ev, 0, sizeof(ev));
	ev.type = BR_EV_RX_TIMEOUT;
	ev.leg = BR_CARRIER;
	CHECK(cs_media_classify(&ev, &m) && m.type == CSM_STALL);
	ST = CC_ST_EARLY;
	cs_media_apply(&ops, NULL, &m);
	CHECK(n_fail == 2);	/* a ringing line may carry nothing */
	ST = CC_ST_CONNECTED;
	cs_media_apply(&ops, NULL, &m);
	CHECK(n_fail == 3);
	memset(&ev, 0, sizeof(ev));
	ev.type = BR_EV_DTMF;
	ev.leg = BR_CLIENT;
	ev.digit = '7';
	CHECK(cs_media_classify(&ev, &m) && m.type == CSM_DIGIT && m.digit == '7');
	cs_media_apply(&ops, NULL, &m);
	CHECK(n_dtmf == 1 && last_digit == '7');
	ev.end = true;
	CHECK(!cs_media_classify(&ev, &m));	/* key up */
	ev.end = false;
	ev.leg = BR_CARRIER;
	CHECK(!cs_media_classify(&ev, &m));

	memset(&st, 0, sizeof(st));
	st.leg[BR_CARRIER].rx_pkts = 100;
	st.leg[BR_CARRIER].tx_pkts = 99;
	st.leg[BR_CARRIER].pcm_xrun_rx = 2;
	st.leg[BR_CARRIER].pcm_ul_drop = 3;
	st.leg[BR_CARRIER].pcm_lost = true;
	cs_media_stats(&st, &ps);
	CHECK(ps.rx_periods == 100 && ps.tx_periods == 99 && ps.xrun_rx == 2 && ps.ul_drop == 3 && ps.lost);
}

void test_misc(void)
{
	t_cause();
	t_numbers();
	t_rat();
	t_parts();
	t_media();
}
