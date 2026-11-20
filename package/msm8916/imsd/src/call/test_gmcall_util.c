/* SPDX-License-Identifier: GPL-2.0-or-later */
/* host tests of the pure helpers (make -C src/call test) */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../test/test.h"
#include "gmcall_util.h"

int t_checks, t_fails;

static void t_normalize(void)
{
	char o[48];

	CHECK_EQ(gmcall_number_normalize("sip:01051226862@lte-lguplus.co.kr", o, sizeof(o)), 0);
	CHECK_STR(o, "01051226862");
	CHECK_EQ(gmcall_number_normalize("<sip:+821051226862@lte-lguplus.co.kr;user=phone>", o, sizeof(o)), 0);
	CHECK_STR(o, "+821051226862");
	CHECK_EQ(gmcall_number_normalize("tel:010-5122-6862;phone-context=lguplus.co.kr", o, sizeof(o)), 0);
	CHECK_STR(o, "01051226862");
	CHECK_EQ(gmcall_number_normalize("tel:+82-10-5122-6862", o, sizeof(o)), 0);
	CHECK_STR(o, "+821051226862");
	CHECK_EQ(gmcall_number_normalize("sip:%2B821051226862@d", o, sizeof(o)), 0);
	CHECK_STR(o, "+821051226862");
	CHECK_EQ(gmcall_number_normalize("01012345678", o, sizeof(o)), 0);
	CHECK_STR(o, "01012345678");
	CHECK_EQ(gmcall_number_normalize("sip:anonymous@anonymous.invalid", o, sizeof(o)), -1);
	CHECK_EQ(gmcall_number_normalize("sip:example.com", o, sizeof(o)), -1);
	CHECK_EQ(gmcall_number_normalize("", o, sizeof(o)), -1);
	CHECK_EQ(gmcall_number_normalize("tel:+1234567890123", o, 5), -1);	/* too small: no truncation */
	CHECK_EQ(gmcall_number_normalize(NULL, o, sizeof(o)), -1);
}

static void t_target(void)
{
	char u[128];

	CHECK_EQ(gmcall_make_target("114", "lguplus.co.kr", u, sizeof(u)), 0);
	CHECK_STR(u, "tel:114;phone-context=lguplus.co.kr");
	CHECK_EQ(gmcall_make_target(" 010-1234 5678 ", "lguplus.co.kr", u, sizeof(u)), 0);
	CHECK_STR(u, "tel:01012345678;phone-context=lguplus.co.kr");
	CHECK_EQ(gmcall_make_target("+82 10 1234 5678", "lguplus.co.kr", u, sizeof(u)), 0);
	CHECK_STR(u, "tel:+821012345678");	/* global number: no phone-context */
	CHECK_EQ(gmcall_make_target("*23#", "lguplus.co.kr", u, sizeof(u)), 0);
	CHECK_STR(u, "tel:*23%23;phone-context=lguplus.co.kr");
	CHECK_EQ(gmcall_make_target("sip:01012345678@lte-lguplus.co.kr;user=phone", "x", u, sizeof(u)), 0);
	CHECK_STR(u, "sip:01012345678@lte-lguplus.co.kr;user=phone");
	CHECK_EQ(gmcall_make_target("tel:+8210;x=y", "x", u, sizeof(u)), 0);
	CHECK_STR(u, "tel:+8210;x=y");
	CHECK_EQ(gmcall_make_target("", "x", u, sizeof(u)), -EINVAL);
	CHECK_EQ(gmcall_make_target("abc", "x", u, sizeof(u)), -EINVAL);
	CHECK_EQ(gmcall_make_target("01a2", "x", u, sizeof(u)), -EINVAL);
	CHECK_EQ(gmcall_make_target("12+34", "x", u, sizeof(u)), -EINVAL);
	CHECK_EQ(gmcall_make_target("+12*3", "x", u, sizeof(u)), -EINVAL);
	CHECK_EQ(gmcall_make_target("sip:", "x", u, sizeof(u)), -EINVAL);
	CHECK_EQ(gmcall_make_target("123456789012345678901234567890123", "x", u, sizeof(u)), -EINVAL);
	CHECK_EQ(gmcall_make_target("114", "lguplus.co.kr", u, 10), -EMSGSIZE);
	CHECK_EQ(gmcall_make_target("114", "", u, sizeof(u)), 0);
	CHECK_STR(u, "tel:114");
}

static void t_se(void)
{
	unsigned iv = 0;
	int ref = -1;

	CHECK_EQ(gmcall_parse_session_expires("600;refresher=uac", &iv, &ref), 0);
	CHECK_EQ(iv, 600);
	CHECK_EQ(ref, GMCALL_REFRESHER_UAC);
	CHECK_EQ(gmcall_parse_session_expires(" 1800 ; refresher=UAS", &iv, &ref), 0);
	CHECK_EQ(iv, 1800);
	CHECK_EQ(ref, GMCALL_REFRESHER_UAS);
	CHECK_EQ(gmcall_parse_session_expires("90", &iv, &ref), 0);
	CHECK_EQ(ref, GMCALL_REFRESHER_NONE);
	CHECK_EQ(gmcall_parse_session_expires("0", &iv, &ref), -1);
	CHECK_EQ(gmcall_parse_session_expires("abc", &iv, &ref), -1);
	CHECK_EQ(gmcall_parse_session_expires("600x", &iv, &ref), -1);
	CHECK_EQ(gmcall_parse_session_expires(NULL, &iv, &ref), -1);
	CHECK_EQ(gmcall_parse_min_se("1200", &iv), 0);
	CHECK_EQ(iv, 1200);
	CHECK_EQ(gmcall_parse_min_se("", &iv), -1);
}

static void t_text(void)
{
	char o[64];

	CHECK_EQ(gmcall_reason_text("SIP ;cause=200 ;text=\"Call completed elsewhere\"", o, sizeof(o)), 0);
	CHECK_STR(o, "Call completed elsewhere");
	CHECK_EQ(gmcall_reason_text("Q.850;cause=16", o, sizeof(o)), 0);
	CHECK_STR(o, "cause 16");
	CHECK_EQ(gmcall_reason_text("garbage", o, sizeof(o)), 0);
	CHECK_STR(o, "");
	CHECK_EQ(gmcall_reason_text(NULL, o, sizeof(o)), 0);
	CHECK_EQ(gmcall_reason_text("SIP;text=\"0123456789012345678901234567890123456789\"", o, 8), -1);
	CHECK_EQ(gmcall_warning_text("399 isc.example.com \"Barred call\"", o, sizeof(o)), 0);
	CHECK_STR(o, "Barred call");
	CHECK_EQ(gmcall_warning_text("399 nothing", o, sizeof(o)), 0);
	CHECK_STR(o, "");
}

static void t_tokens(void)
{
	char o[64];

	CHECK(gmcall_has_token("timer, 100rel", "100rel"));
	CHECK(gmcall_has_token("Timer", "timer"));
	CHECK(!gmcall_has_token("timers", "timer"));
	CHECK(!gmcall_has_token(NULL, "timer"));
	CHECK(gmcall_has_token("a;x=y, b", "b"));
	CHECK_EQ(gmcall_unsupported_options("timer", o, sizeof(o)), 0);
	CHECK_EQ(gmcall_unsupported_options("100rel, precondition,timer", o, sizeof(o)), 2);
	CHECK_STR(o, "100rel,precondition");
	CHECK_EQ(gmcall_unsupported_options("sec-agree", o, sizeof(o)), 0);
	CHECK_EQ(gmcall_unsupported_options(NULL, o, sizeof(o)), 0);
}

static void t_identity(void)
{
	static const char *inv =
		"INVITE sip:01039428657@[2001:db8::1]:8931 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP [2001:db8::2]:5071;branch=z9hG4bKx\r\n"
		"From: \"Kim\" <sip:01051226862@lte-lguplus.co.kr>;tag=a\r\n"
		"To: <tel:01039428657;phone-context=lte-lguplus.co.kr>\r\n"
		"Call-ID: c\r\nCSeq: 1 INVITE\r\n"
		"P-Asserted-Identity: <sip:+821051226862@lte-lguplus.co.kr>\r\n"
		"Privacy: header;id\r\n\r\n";
	static const char *inv2 =
		"INVITE sip:u@h SIP/2.0\r\nVia: SIP/2.0/UDP h:1;branch=z9hG4bKy\r\n"
		"From: <sip:anonymous@anonymous.invalid>;tag=a\r\nTo: <sip:u@h>\r\nCall-ID: c\r\nCSeq: 1 INVITE\r\n\r\n";
	struct sip_msg m;
	struct gmcall_identity id;

	CHECK_EQ(sip_parse((const uint8_t *)inv, strlen(inv), &m), 0);
	gmcall_identity_from_request(&m, &id);
	CHECK_STR(id.number, "+821051226862");
	CHECK_STR(id.display, "Kim");	/* display name of From when the PAI has none */
	CHECK(id.anonymous);
	sip_msg_free(&m);
	CHECK_EQ(sip_parse((const uint8_t *)inv2, strlen(inv2), &m), 0);
	gmcall_identity_from_request(&m, &id);
	CHECK_STR(id.number, "");
	CHECK(id.anonymous);
	sip_msg_free(&m);
}

int main(void)
{
	t_normalize();
	t_target();
	t_se();
	t_text();
	t_tokens();
	t_identity();
	printf("test_gmcall_util: %d checks, %d failures\n", t_checks, t_fails);
	return t_fails ? 1 : 0;
}
