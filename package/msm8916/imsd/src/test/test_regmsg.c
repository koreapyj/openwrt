/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "test.h"
#include "../gm/regmsg.h"
#include "../gm/secagree.h"

/* header values of the REGISTERs the network accepted in the proof of concept (run1 / l1 logs) */
static const char *POC_PANI = "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=4500620EB3161703";
static const char *POC_CONTACT_TAGS = ";+sip.instance=\"<urn:gsma:imei:86883708-366218-5>\";+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";+g.3gpp.smsip";
static const char *POC_SECVERIFY = "ipsec-3gpp; mod=trans; alg=hmac-md5-96; ealg=null; spi-c=3417264; spi-s=3417263; port-c=5073; port-s=5071";

static struct regmsg_params base(struct addr *adv, struct addr *pc, struct sec_client *sc)
{
	struct regmsg_params p;

	memset(&p, 0, sizeof(p));
	addr_set(adv, "2001:4430:1094:d1c6:b9d6:b61:344:9645", 28811);
	addr_set(pc, "2001:4430:4:405::43", 5060);
	sc->spi_c = 665077002; sc->spi_s = 1104518164; sc->port_c = 8031; sc->port_s = 8931;
	p.domain = "lte-lguplus.co.kr";
	p.impu = "sip:01039428657@lte-lguplus.co.kr";
	p.user = "01039428657";
	p.imei = "86883708-366218-5";
	p.adv = adv; p.pcscf = pc; p.sc = sc;
	p.call_id = "1689536197_1983692051@2001:4430:1094:d1c6:b9d6:b61:344:9645";
	p.cseq = 35286014;
	p.expires = 8000;
	p.pani = POC_PANI;
	return p;
}

static void hdr_is(const struct sip_msg *m, const char *name, const char *val)
{
	const char *v = sip_hdr(m, name, 0);

	t_checks++;
	if (!v || strcmp(v, val)) {
		t_fails++;
		printf("FAIL %s:%d: header %s = \"%s\", expected \"%s\"\n", __FILE__, __LINE__, name, v ? v : "(none)", val);
	}
}

static void hdr_absent(const struct sip_msg *m, const char *name)
{
	CHECK(!sip_hdr(m, name, 0));
}

void test_regmsg(void)
{
	struct addr adv, pc, adv2;
	struct sec_client sc;
	struct regmsg_params p = base(&adv, &pc, &sc);
	char auth[1300], br[SIP_BRANCH_LEN];
	struct buf b;
	struct sip_msg m;
	struct sip_via v;
	uint8_t res[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	char resp[33];

	/* ---- the initial (unprotected) REGISTER ---- */
	CHECK(!regmsg_authorization(auth, sizeof(auth), "450061039428657@lte-lguplus.co.kr", "lte-lguplus.co.kr", "lte-lguplus.co.kr", "", "", NULL, NULL));
	CHECK_STR(auth, "Digest uri=\"sip:lte-lguplus.co.kr\",username=\"450061039428657@lte-lguplus.co.kr\",response=\"\",realm=\"lte-lguplus.co.kr\",nonce=\"\"");
	p.authorization = auth;
	buf_init(&b, SIP_MAX_MSG);
	CHECK(!regmsg_build_register(&b, &p, br));
	CHECK(!strncmp(buf_cstr(&b), "REGISTER sip:lte-lguplus.co.kr SIP/2.0\r\n", 40));
	CHECK(!sip_parse(b.p, b.len, &m));
	CHECK(!m.is_resp); CHECK_STR(m.method, "REGISTER"); CHECK_STR(m.ruri, "sip:lte-lguplus.co.kr");
	CHECK(!sip_top_via(&m, &v));
	CHECK_STR(v.transport, "UDP"); CHECK_STR(v.host, "2001:4430:1094:d1c6:b9d6:b61:344:9645"); CHECK_EQ(v.port, 28811);
	CHECK_STR(v.branch, br); CHECK(!strncmp(br, "z9hG4bK", 7)); CHECK_EQ(v.rport, -1);
	hdr_is(&m, "Max-Forwards", "70");
	CHECK(!strncmp(sip_hdr(&m, "From", 0), "<sip:01039428657@lte-lguplus.co.kr>;tag=", 40));
	hdr_is(&m, "To", "<sip:01039428657@lte-lguplus.co.kr>");
	hdr_is(&m, "Call-ID", "1689536197_1983692051@2001:4430:1094:d1c6:b9d6:b61:344:9645");
	hdr_is(&m, "CSeq", "35286014 REGISTER");
	{
		char c[400];

		snprintf(c, sizeof(c), "<sip:01039428657@[2001:4430:1094:d1c6:b9d6:b61:344:9645]:28811>%s", POC_CONTACT_TAGS);
		hdr_is(&m, "Contact", c);
	}
	hdr_is(&m, "Route", "<sip:[2001:4430:4:405::43]:5060;lr>");
	hdr_is(&m, "P-Access-Network-Info", POC_PANI);
	hdr_is(&m, "Content-Length", "0");
	hdr_is(&m, "Authorization", auth);
	hdr_is(&m, "Expires", "8000");
	hdr_is(&m, "Require", "sec-agree");
	hdr_is(&m, "Proxy-Require", "sec-agree");
	hdr_is(&m, "Supported", "path,sec-agree");
	hdr_is(&m, "Allow", "INVITE,BYE,CANCEL,ACK,NOTIFY,UPDATE,PRACK,INFO,MESSAGE,OPTIONS");
	hdr_is(&m, "Security-Client", "ipsec-3gpp; alg=hmac-md5-96; ealg=null; spi-c=665077002; spi-s=1104518164; port-c=8031; port-s=8931,"
	       "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=665077002; spi-s=1104518164; port-c=8031; port-s=8931");
	hdr_absent(&m, "Security-Verify");
	/* the Security-Client we send parses back to both algorithms */
	{
		struct sec_ent e[4];

		CHECK_EQ(sec_parse(sip_hdr(&m, "Security-Client", 0), e, 4), 2);
		CHECK(e[0].ok && !e[0].sha1 && e[1].ok && e[1].sha1 && e[0].port_c == 8031 && e[1].port_s == 8931);
	}
	sip_msg_free(&m);

	/* ---- protected REGISTER: digest response, Security-Verify, port-s as sent-by ---- */
	{
		struct sip_msg m2;

		addr_set(&adv2, "2001:4430:1094:d1c6:b9d6:b61:344:9645", 8931);
		digest_response("450061039428657@lte-lguplus.co.kr", "lte-lguplus.co.kr", res, 8, "miz0NWVBDyX5cW4hv0pZUkecgFgpR4AAqVvrEyfG2Eo=", "REGISTER", "sip:lte-lguplus.co.kr", resp);
		CHECK(!regmsg_authorization(auth, sizeof(auth), "450061039428657@lte-lguplus.co.kr", "lte-lguplus.co.kr", "lte-lguplus.co.kr",
					    "miz0NWVBDyX5cW4hv0pZUkecgFgpR4AAqVvrEyfG2Eo=", "", resp, NULL));
		{
			char exp[600];

			snprintf(exp, sizeof(exp), "Digest username=\"450061039428657@lte-lguplus.co.kr\",realm=\"lte-lguplus.co.kr\",uri=\"sip:lte-lguplus.co.kr\","
				 "nonce=\"miz0NWVBDyX5cW4hv0pZUkecgFgpR4AAqVvrEyfG2Eo=\",algorithm=AKAv1-MD5,response=\"%s\"", resp);
			CHECK_STR(auth, exp);
		}
		addr_set(&pc, "2001:4430:4:405::43", 5071);
		p.adv = &adv2; p.pcscf = &pc; p.is_protected = true; p.security_verify = POC_SECVERIFY; p.authorization = auth;
		p.cseq = 35286015;
		buf_reset(&b);
		CHECK(!regmsg_build_register(&b, &p, NULL));
		CHECK(!sip_parse(b.p, b.len, &m2));
		CHECK(!sip_top_via(&m2, &v));
		CHECK_EQ(v.port, 8931);
		hdr_is(&m2, "Route", "<sip:[2001:4430:4:405::43]:5071;lr>");
		hdr_is(&m2, "Security-Verify", POC_SECVERIFY);
		hdr_is(&m2, "Authorization", auth);
		hdr_is(&m2, "CSeq", "35286015 REGISTER");
		{
			char c[400];

			snprintf(c, sizeof(c), "<sip:01039428657@[2001:4430:1094:d1c6:b9d6:b61:344:9645]:8931>%s", POC_CONTACT_TAGS);
			hdr_is(&m2, "Contact", c);
		}
		sip_msg_free(&m2);
	}

	/* ---- de-registration: Expires 0 ---- */
	p.expires = 0;
	buf_reset(&b);
	CHECK(!regmsg_build_register(&b, &p, NULL));
	CHECK(!sip_parse(b.p, b.len, &m));
	hdr_is(&m, "Expires", "0");
	sip_msg_free(&m);

	/* ---- resync form and opaque ---- */
	CHECK(!regmsg_authorization(auth, sizeof(auth), "u@d", "d", "d", "NONCE=", "OPQ", NULL, "AUTSB64"));
	CHECK_STR(auth, "Digest username=\"u@d\",realm=\"d\",uri=\"sip:d\",nonce=\"NONCE=\",algorithm=AKAv1-MD5,opaque=\"OPQ\",auts=\"AUTSB64\",response=\"\"");
	CHECK(!regmsg_authorization(auth, sizeof(auth), "u@d", "d", "d", "NONCE=", "OPQ", "abc", NULL));
	CHECK_STR(auth, "Digest username=\"u@d\",realm=\"d\",uri=\"sip:d\",nonce=\"NONCE=\",algorithm=AKAv1-MD5,opaque=\"OPQ\",response=\"abc\"");
	CHECK(regmsg_authorization(auth, 20, "u@d", "d", "d", "NONCE=", "", "abc", NULL) < 0);

	/* ---- IPv4 and no IMEI ---- */
	{
		struct addr a4, p4;

		addr_set(&a4, "10.113.42.9", 8931);
		addr_set(&p4, "10.113.2.5", 5071);
		p.adv = &a4; p.pcscf = &p4; p.imei = ""; p.expires = 8000;
		buf_reset(&b);
		CHECK(!regmsg_build_register(&b, &p, NULL));
		CHECK(!sip_parse(b.p, b.len, &m));
		hdr_is(&m, "Contact", "<sip:01039428657@10.113.42.9:8931>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";+g.3gpp.smsip");
		hdr_is(&m, "Route", "<sip:10.113.2.5:5071;lr>");
		CHECK(!sip_top_via(&m, &v));
		CHECK_STR(v.host, "10.113.42.9");
		sip_msg_free(&m);
	}
	/* ---- User-Agent: present on every REGISTER variant when set, absent otherwise ---- */
	{
		static const char *UA = "TTA-VoLTE/3.0 imsd/0.1 Device_Type/Android_Phone OMD";
		struct addr a6, p6;
		struct sip_msg m3;

		addr_set(&a6, "2001:4430:1094:d1c6:b9d6:b61:344:9645", 8931);
		addr_set(&p6, "2001:4430:4:405::43", 5071);
		p.adv = &a6; p.pcscf = &p6; p.imei = "86883708-366218-5"; p.expires = 8000;
		buf_reset(&b);
		CHECK(!regmsg_build_register(&b, &p, NULL));	/* user_agent not set */
		CHECK(!sip_parse(b.p, b.len, &m3));
		hdr_absent(&m3, "User-Agent");
		sip_msg_free(&m3);
		p.user_agent = UA;
		buf_reset(&b);
		CHECK(!regmsg_build_register(&b, &p, NULL));	/* unprotected */
		CHECK(!sip_parse(b.p, b.len, &m3));
		hdr_is(&m3, "User-Agent", UA);
		sip_msg_free(&m3);
		p.is_protected = true; p.security_verify = POC_SECVERIFY; p.expires = 0;	/* protected de-registration */
		buf_reset(&b);
		CHECK(!regmsg_build_register(&b, &p, NULL));
		CHECK(!sip_parse(b.p, b.len, &m3));
		hdr_is(&m3, "User-Agent", UA); hdr_is(&m3, "Expires", "0");
		sip_msg_free(&m3);
		p.user_agent = "";
		buf_reset(&b);
		CHECK(!regmsg_build_register(&b, &p, NULL));
		CHECK(!sip_parse(b.p, b.len, &m3));
		hdr_absent(&m3, "User-Agent");
		sip_msg_free(&m3);
	}
	/* missing mandatory input */
	p.call_id = NULL;
	buf_reset(&b);
	CHECK(regmsg_build_register(&b, &p, NULL) < 0);
	buf_free(&b);
}
