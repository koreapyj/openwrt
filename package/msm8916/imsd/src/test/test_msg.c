/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdlib.h>
#include "test.h"
#include "../sip/msg.h"
#include "../util/codec.h"

/* captured on the carrier */
static const char *R401 =
	"SIP/2.0 401 UNAUTHORIZED\r\n"
	"Via: SIP/2.0/UDP [2001:4430:135:e395::1e7:4a91]:28800;received=2001:4430:135:e395::1e7:4a91;rport=28800;branch=z9hG4bK1455467046\r\n"
	"To: <sip:01039428657@lte-lguplus.co.kr>;tag=4cf63dca72efd\r\n"
	"From: <sip:01039428657@lte-lguplus.co.kr>;tag=1664737061\r\n"
	"Call-ID: 1664737052_2334231496@2001:4430:135:e395::1e7:4a91\r\n"
	"CSeq: 590995228 REGISTER\r\n"
	"WWW-Authenticate: Digest realm=\"lte-lguplus.co.kr\", nonce=\"MRTdOIZ7hwcN/iIcq7/KRmcd8nPtUoAA4+bwhST7kMM=\", algorithm=AKAv1-MD5\r\n"
	"P-LGUplus-Specific-Control: ipsec=yes\r\n"
	"Security-Server: ipsec-3gpp; mod=trans; alg=hmac-md5-96; ealg=null; spi-c=1612738; spi-s=1612737; port-c=5073; port-s=5071\r\n"
	"\r\n";

static const char *MT_INVITE =
	"INVITE sip:01039428657@[2001:4430:1094:d1c6:b9d6:b61:344:9645]:8931 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP [2001:4430:4:405::43]:5071;branch=z9hG4bK7eff6c368a1049bd41e3_6bf2a\r\n"
	"Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";require;explicit\r\n"
	"Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REGISTER,REFER,SUBSCRIBE,UPDATE\r\n"
	"Call-ID: abc-dGhoc2RjeWItMC0yLWE4MmhrSzltRkxVeWcwTVhmeGFAZ2hnbGhpaW1vbWk-LGU+IBCF\r\n"
	"Content-Length: 564\r\n"
	"Content-Type: application/sdp\r\n"
	"CSeq: 9203 INVITE\r\n"
	"From: <sip:01051226862@lte-lguplus.co.kr>;tag=kmnham7485C9417df6d25733432\r\n"
	"Max-Forwards: 57\r\n"
	"P-Asserted-Identity: <sip:01051226862@lte-lguplus.co.kr>\r\n"
	"P-Called-Party-Id: <sip:01039428657@lte-lguplus.co.kr>\r\n"
	"Privacy: none\r\n"
	"Session-Expires: 600;refresher=uac\r\n"
	"Supported: timer, sec-agree\r\n"
	"To: <tel:01039428657;phone-context=lte-lguplus.co.kr>\r\n"
	"User-Agent: TTA-VoLTE/3.0 SM-S918N/ZI1_ZF1 Device_Type/Android_Phone OMD\r\n"
	"P-Early-Media: supported\r\n"
	"Contact: <sip:[2001:4430:4:405::43]:5071>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";video\r\n"
	"\r\n";
static const char *MT_SDP =
	"v=0\r\no=vIBCF 1356104123 1795119376 IN IP6 2001:4430:4:315::8\r\ns=-\r\ni=A VOIP Session\r\n"
	"c=IN IP6 2001:4430:4:315::8\r\nt=0 0\r\nm=audio 44218 RTP/AVP 110 100 96 107 101\r\nb=AS:50\r\nb=RS:0\r\nb=RR:2500\r\n"
	"a=rtpmap:110 EVS/16000\r\na=fmtp:110 br=9.6-24.4;bw=nb-swb\r\na=rtpmap:100 AMR-WB/16000/1\r\na=fmtp:100 octet-align=1\r\n"
	"a=rtpmap:96 AMR/8000/1\r\na=fmtp:96 octet-align=1\r\na=rtpmap:107 telephone-event/16000\r\na=fmtp:107 0-15\r\n"
	"a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=candidate:1 1 UDP 2130706431 2001:4430:4:315::8 44218 typ host\r\n"
	"a=sendrecv\r\na=ptime:20\r\na=maxptime:120\r\n";

static const char *R183 =
	"SIP/2.0 183 Session Progress\r\n"
	"Via: SIP/2.0/UDP [2001:4430:1094:d1c6:b9d6:b61:344:9645]:8921;branch=z9hG4bK3704757540\r\n"
	"Require: 100rel\r\n"
	"Contact: <sip:[2001:4430:5:401::53]:1357;transport=UDP>\r\n"
	"To: <tel:01039428657;phone-context=lguplus.co.kr>;tag=az004c351a470f150fc0c49d8d40c21d_kmnham35CE3B543fb662707299\r\n"
	"From: <sip:01039428657@lte-lguplus.co.kr>;tag=1069810415\r\n"
	"Call-ID: 32960760_2724848206@2001:4430:1094:d1c6:b9d6:b61:344:9645\r\n"
	"CSeq: 1 INVITE\r\n"
	"Content-Type: application/sdp\r\n"
	"RSeq: 80904\r\n"
	"Content-Length: 309\r\n"
	"\r\n"
	"v=0\r\no=vIBCF 1347224678 1795119320 IN IP6 2001:4430:5:323::5\r\ns=MRF\r\nc=IN IP6 2001:4430:5:323::5\r\nt=0 0\r\n"
	"m=audio 38470 RTP/AVP 104 101\r\nb=AS:49\r\nb=RS:600\r\nb=RR:2000\r\na=maxptime:60\r\na=fmtp:104 octet-align=0;mode-set=8\r\n"
	"a=fmtp:101 0-11\r\na=ptime:20\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:101 telephone-event/8000\r\n";

/* the incoming SMS MESSAGE: odd spacing in Content-Length, lower-case header names, binary body with NULs */
static const char *MT_MSG_HDR =
	"MESSAGE sip:01039428657@[2001:4430:1094:d1c6:b9d6:b61:344:9645]:8931 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP [2001:4430:4:405::43]:5071;branch=z9hG4bK7eff525e28b03ed187_4d57b\r\n"
	"Accept-contact: *;+g.3gpp.smsip;require;explicit\r\n"
	"Call-ID: Mjg2NzIxNTk4LTE3MDEwLWEwdGh5Y2psQDEwLjEyMC4xNjYuNTI-LGU+IBCF\r\n"
	"Content-Length:    37\r\n"
	"Content-Type: application/vnd.3gpp.sms\r\n"
	"CSeq: 286721598 MESSAGE\r\n"
	"From: <sip:ipsmgw.lte-lguplus.co.kr>;tag=4j8gcj2n\r\n"
	"Max-Forwards: 66\r\n"
	"P-Asserted-Identity: <sip:ipsmgw.lte-lguplus.co.kr>\r\n"
	"P-Called-Party-Id: <sip:01039428657@lte-lguplus.co.kr>\r\n"
	"To: <sip:01039428657@lte-lguplus.co.kr>\r\n"
	"User-agent: TTA-VoLTE/3.0 SM-S918N/ZI1_ZF1 Device_Type/Android_Phone OMD\r\n"
	"\r\n";
static const char *RPDU_MT = "013e07912801022981120019040b811050216268f200086211025061646306d14cc2a4d2b8";
static const char *RPDU_MO = "00ae0007912801022981122001140b811050216268f2000015e9f6bc1e0685e1ad747b0e9ab7e7207a794e07";

static uint8_t *cat(const char *hdr, const uint8_t *body, size_t bl, size_t *tot)
{
	size_t hl = strlen(hdr);
	uint8_t *p = malloc(hl + bl + 1);

	memcpy(p, hdr, hl);
	memcpy(p + hl, body, bl);
	*tot = hl + bl;
	return p;
}

static int parse_str(const char *s, struct sip_msg *m)
{
	return sip_parse((const uint8_t *)s, strlen(s), m);
}

static void t_responses(void)
{
	struct sip_msg m;
	struct sip_via v;
	char tag[64], meth[16];
	uint32_t cs;

	CHECK_EQ(parse_str(R401, &m), 0);
	CHECK(m.is_resp && m.status == 401); CHECK_STR(m.reason, "UNAUTHORIZED");
	CHECK_STR(sip_hdr(&m, "call-id", 0), "1664737052_2334231496@2001:4430:135:e395::1e7:4a91");
	CHECK_STR(sip_hdr(&m, "i", 0), "1664737052_2334231496@2001:4430:135:e395::1e7:4a91");	/* compact form of the lookup name */
	CHECK(!sip_hdr(&m, "Call-ID", 1));
	CHECK(!sip_cseq(&m, &cs, meth, sizeof(meth)) && cs == 590995228 && !strcmp(meth, "REGISTER"));
	CHECK(!sip_tag(sip_hdr(&m, "To", 0), tag, sizeof(tag))); CHECK_STR(tag, "4cf63dca72efd");
	CHECK(!sip_top_via(&m, &v));
	CHECK_STR(v.transport, "UDP"); CHECK_STR(v.host, "2001:4430:135:e395::1e7:4a91"); CHECK_EQ(v.port, 28800);
	CHECK_STR(v.branch, "z9hG4bK1455467046"); CHECK_STR(v.received, "2001:4430:135:e395::1e7:4a91"); CHECK_EQ(v.rport, 28800);
	CHECK_EQ(m.body_len, 0);
	sip_msg_free(&m);

	/* 183 with 100rel and SDP: Content-Length bound body */
	CHECK_EQ(parse_str(R183, &m), 0);
	CHECK(m.status == 183); CHECK_STR(sip_hdr(&m, "Require", 0), "100rel"); CHECK_STR(sip_hdr(&m, "RSeq", 0), "80904");
	CHECK_EQ(m.body_len, 309); CHECK(!memcmp(m.body, "v=0\r\no=vIBCF", 12));
	CHECK(m.body[m.body_len] == 0);
	CHECK(sip_tag(sip_hdr(&m, "To", 0), tag, 16) < 0);	/* long tag does not fit: error, not truncation */
	{
		char big[160];

		CHECK(!sip_tag(sip_hdr(&m, "To", 0), big, sizeof(big)));
		CHECK_STR(big, "az004c351a470f150fc0c49d8d40c21d_kmnham35CE3B543fb662707299");
	}
	sip_msg_free(&m);
}

static void t_requests(void)
{
	struct sip_msg m;
	struct sip_uri u;
	struct sip_nameaddr na;
	char out[256];
	uint8_t body[64];
	uint8_t *raw;
	size_t tot;
	struct sip_list it;
	int n;
	char buf[512];

	/* MT INVITE with SDP: the SDP bytes are the body, Content-Length 564 */
	{
		size_t sl = strlen(MT_SDP);
		char hdr[2048];

		snprintf(hdr, sizeof(hdr), "%s", MT_INVITE);
		raw = cat(hdr, (const uint8_t *)MT_SDP, sl, &tot);
		CHECK_EQ(sl, 564);
		CHECK_EQ(sip_parse(raw, tot, &m), 0);
		free(raw);
	}
	CHECK(!m.is_resp); CHECK_STR(m.method, "INVITE");
	CHECK_STR(m.ruri, "sip:01039428657@[2001:4430:1094:d1c6:b9d6:b61:344:9645]:8931");
	CHECK_EQ(m.body_len, 564);
	CHECK_STR(sip_hdr(&m, "Supported", 0), "timer, sec-agree");
	CHECK_STR(sip_hdr(&m, "SUPPORTED", 0), "timer, sec-agree");
	CHECK_STR(sip_hdr(&m, "k", 0), "timer, sec-agree");
	CHECK(sip_is_method(&m, "INVITE") && !sip_is_method(&m, "BYE"));
	/* To is a tel URI with phone-context */
	CHECK(!sip_nameaddr_parse(sip_hdr(&m, "To", 0), &na));
	CHECK_STR(na.uri, "tel:01039428657;phone-context=lte-lguplus.co.kr"); CHECK_STR(na.params, "");
	CHECK(!sip_uri_parse(na.uri, &u));
	CHECK_STR(u.scheme, "tel"); CHECK_STR(u.user, "01039428657"); CHECK_STR(u.host, "");
	CHECK_EQ(sip_uri_param(&u, "phone-context", out, sizeof(out)), 1); CHECK_STR(out, "lte-lguplus.co.kr");
	CHECK_EQ(sip_uri_param(&u, "other", out, sizeof(out)), 0);
	CHECK(!sip_uri_format(&u, out, sizeof(out))); CHECK_STR(out, "tel:01039428657;phone-context=lte-lguplus.co.kr");
	/* Request-URI with a bracketed IPv6 host and port */
	CHECK(!sip_uri_parse(m.ruri, &u));
	CHECK_STR(u.scheme, "sip"); CHECK_STR(u.user, "01039428657"); CHECK_STR(u.host, "2001:4430:1094:d1c6:b9d6:b61:344:9645");
	CHECK_EQ(u.port, 8931);
	CHECK(!sip_uri_format(&u, out, sizeof(out))); CHECK_STR(out, m.ruri);
	/* Contact name-addr with header params that contain quotes and ';' */
	CHECK(!sip_nameaddr_parse(sip_hdr(&m, "Contact", 0), &na));
	CHECK_STR(na.uri, "sip:[2001:4430:4:405::43]:5071");
	CHECK_EQ(sip_params_get(na.params, "+g.3gpp.icsi-ref", out, sizeof(out)), 1);
	CHECK_STR(out, "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel");
	CHECK_EQ(sip_params_get(na.params, "video", out, sizeof(out)), 1); CHECK_STR(out, "");
	/* Session-Expires params */
	CHECK_EQ(sip_params_get(strchr(sip_hdr(&m, "Session-Expires", 0), ';'), "refresher", out, sizeof(out)), 1);
	CHECK_STR(out, "uac");
	sip_msg_free(&m);

	/* MT SMS MESSAGE: binary body with NUL bytes, odd Content-Length spacing, lower-case names */
	CHECK_EQ(hex_decode(RPDU_MT, body, sizeof(body)), 37);
	raw = cat(MT_MSG_HDR, body, 37, &tot);
	CHECK_EQ(sip_parse(raw, tot, &m), 0);
	CHECK_STR(m.method, "MESSAGE");
	CHECK_EQ(m.body_len, 37); CHECK(!memcmp(m.body, body, 37));
	CHECK(memchr(m.body, 0, m.body_len) != NULL);	/* the point: NULs survive */
	CHECK_STR(sip_hdr(&m, "Accept-Contact", 0), "*;+g.3gpp.smsip;require;explicit");
	CHECK_STR(sip_hdr(&m, "user-agent", 0), "TTA-VoLTE/3.0 SM-S918N/ZI1_ZF1 Device_Type/Android_Phone OMD");
	CHECK_STR(sip_hdr(&m, "Content-Length", 0), "37");
	sip_msg_free(&m);
	/* trailing garbage after Content-Length is ignored, shortage is an error */
	{
		uint8_t *r2 = realloc(raw, tot + 5);

		memcpy(r2 + tot, "extra", 5);
		CHECK_EQ(sip_parse(r2, tot + 5, &m), 0); CHECK_EQ(m.body_len, 37); sip_msg_free(&m);
		CHECK_EQ(sip_parse(r2, tot - 1, &m), SIP_E_TRUNC);
		raw = r2;
	}
	free(raw);

	/* builder: MO RP-DATA as MESSAGE round trip, binary body kept */
	{
		struct buf b;
		struct sip_req_parts p;
		uint8_t mo[64];

		CHECK_EQ(hex_decode(RPDU_MO, mo, sizeof(mo)), 44);
		memset(&p, 0, sizeof(p));
		p.method = "MESSAGE";
		p.ruri = "sip:ipsmgw.lte-lguplus.co.kr";
		p.via = "SIP/2.0/UDP [2001:4430:a102::1]:8962;branch=z9hG4bK913583043";
		p.from = "<sip:01051226862@lte-lguplus.co.kr>;tag=2212537505";
		p.to = "<sip:ipsmgw.lte-lguplus.co.kr>";
		p.call_id = "1406660416_2096928453@2001:4430:a102::1";
		p.cseq = 858036387;
		p.route = "Route: <sip:[2001:4430:5:401::53]:1357;lr>\r\n";
		p.extra = "Request-Disposition: no-fork\r\nAccept-Contact: *;+g.3gpp.smsip\r\n";
		p.content_type = "application/vnd.3gpp.sms";
		p.body = mo;
		p.body_len = 44;
		buf_init(&b, 0);
		CHECK_EQ(sip_build_request(&b, &p), 0);
		CHECK(strstr(buf_cstr(&b), "MESSAGE sip:ipsmgw.lte-lguplus.co.kr SIP/2.0\r\nVia: SIP/2.0/UDP [2001:4430:a102::1]:8962;branch=z9hG4bK913583043\r\nMax-Forwards: 70\r\n"));
		CHECK(strstr(buf_cstr(&b), "CSeq: 858036387 MESSAGE\r\n"));
		CHECK(strstr(buf_cstr(&b), "Content-Length: 44\r\n\r\n"));
		CHECK_EQ(sip_parse(b.p, b.len, &m), 0);
		CHECK_EQ(m.body_len, 44); CHECK(!memcmp(m.body, mo, 44));
		CHECK_STR(sip_hdr(&m, "Route", 0), "<sip:[2001:4430:5:401::53]:1357;lr>");
		CHECK_STR(sip_hdr(&m, "Content-Type", 0), "application/vnd.3gpp.sms");
		sip_msg_free(&m);
		buf_free(&b);

		/* header injection is refused */
		p.call_id = "x\r\nEvil: 1";
		buf_init(&b, 0);
		CHECK(sip_build_request(&b, &p) < 0);
		buf_free(&b);
		/* no space for the body: error, not truncation */
		p.call_id = "x";
		buf_init(&b, 300);
		CHECK(sip_build_request(&b, &p) < 0); CHECK(!buf_ok(&b));
		buf_free(&b);
	}

	/* folded header lines, compact forms, multi value headers */
	{
		static const char *msg =
			"INVITE sip:bob@example.com SIP/2.0\r\n"
			"v: SIP/2.0/UDP a.example.com:5060;branch=z9hG4bK1,\r\n"
			" SIP/2.0/UDP b.example.com;branch=z9hG4bK2\r\n"
			"Via: SIP/2.0/TCP c.example.com;branch=z9hG4bK3\r\n"
			"f: \"Alice A\" <sip:alice@example.com>;tag=abc\r\n"
			"t: <sip:bob@example.com>\r\n"
			"i: callid@example.com\r\n"
			"CSeq: 7 INVITE\r\n"
			"Record-Route: <sip:p1.example.com;lr>, <sip:p2.example.com;lr>\r\n"
			"Record-Route: <sip:p3.example.com;lr>\r\n"
			"Subject: line one\r\n"
			"\tline two\r\n"
			"l: 0\r\n\r\n";
		struct sip_via v;

		CHECK_EQ(parse_str(msg, &m), 0);
		CHECK_STR(sip_hdr(&m, "From", 0), "\"Alice A\" <sip:alice@example.com>;tag=abc");
		CHECK_STR(sip_hdr(&m, "Call-ID", 0), "callid@example.com");
		CHECK_STR(sip_hdr(&m, "Subject", 0), "line one line two");
		CHECK_EQ(sip_hdr_count(&m, "Via"), 2);
		sip_list_init(&it, &m, "Via"); n = 0;
		while (sip_list_next(&it, buf, sizeof(buf)) > 0) n++;
		CHECK_EQ(n, 3);
		CHECK(!sip_top_via(&m, &v)); CHECK_STR(v.host, "a.example.com"); CHECK_EQ(v.port, 5060); CHECK_STR(v.branch, "z9hG4bK1");
		sip_list_init(&it, &m, "Record-Route"); n = 0;
		while (sip_list_next(&it, buf, sizeof(buf)) > 0) { n++; if (n == 3) CHECK_STR(buf, "<sip:p3.example.com;lr>"); }
		CHECK_EQ(n, 3);
		sip_list_init(&it, &m, "Record-Route");
		CHECK_EQ(sip_list_next(&it, buf, 8), -1);	/* too small: reported, not truncated */
		CHECK(!sip_nameaddr_parse(sip_hdr(&m, "f", 0), &na)); CHECK_STR(na.display, "Alice A"); CHECK_STR(na.uri, "sip:alice@example.com");
		CHECK_STR(na.params, ";tag=abc");
		sip_msg_free(&m);
	}

	/* strictness and limits */
	CHECK_EQ(parse_str("garbage\r\n\r\n", &m), SIP_E_BAD);
	CHECK_EQ(parse_str("INVITE sip:a@b SIP/3.0\r\n\r\n", &m), SIP_E_BAD);
	CHECK_EQ(parse_str("SIP/2.0 20 OK\r\n\r\n", &m), SIP_E_BAD);
	CHECK_EQ(sip_parse((const uint8_t *)"", 0, &m), SIP_E_BAD);
	CHECK_EQ(parse_str("SIP/2.0 200 OK\r\nContent-Length: 5\r\n\r\nabc", &m), SIP_E_TRUNC);
	CHECK_EQ(parse_str("SIP/2.0 200 OK\r\nContent-Length: x\r\n\r\n", &m), SIP_E_BAD);
	{
		char *big = malloc(SIP_MAX_MSG + 10);

		memset(big, 'a', SIP_MAX_MSG + 10);
		CHECK_EQ(sip_parse((uint8_t *)big, SIP_MAX_MSG + 1, &m), SIP_E_TOOBIG);
		free(big);
	}
	{
		struct buf b;
		int i;

		buf_init(&b, 0);
		buf_puts(&b, "SIP/2.0 200 OK\r\n");
		for (i = 0; i < SIP_MAX_HDRS + 1; i++)
			buf_printf(&b, "X-H%d: v\r\n", i);
		buf_puts(&b, "\r\n");
		CHECK_EQ(sip_parse(b.p, b.len, &m), SIP_E_HDRS);	/* explicit error, not a silent drop */
		buf_free(&b);
	}
	/* "\n" only line endings and a missing final blank line still parse */
	CHECK_EQ(parse_str("OPTIONS sip:x@y SIP/2.0\nVia: SIP/2.0/UDP h;branch=z9hG4bKq\nCSeq: 1 OPTIONS\n\n", &m), 0);
	CHECK_STR(m.method, "OPTIONS"); sip_msg_free(&m);
	CHECK_EQ(parse_str("SIP/2.0 180\r\nCSeq: 1 INVITE", &m), 0); CHECK_STR(m.reason, ""); CHECK_EQ(m.status, 180); sip_msg_free(&m);
}

static void t_misc(void)
{
	struct sip_uri u;
	struct sip_via v;
	char out[128], br[SIP_BRANCH_LEN], br2[SIP_BRANCH_LEN];
	struct addr a;
	char via[128];
	long n;

	/* URIs */
	CHECK(!sip_uri_parse("sip:+8210123@host.example.com:5080;transport=tcp;lr", &u));
	CHECK_STR(u.user, "+8210123"); CHECK_STR(u.host, "host.example.com"); CHECK_EQ(u.port, 5080); CHECK_STR(u.params, ";transport=tcp;lr");
	CHECK_EQ(sip_uri_param(&u, "lr", out, sizeof(out)), 1);
	CHECK_EQ(sip_uri_param(&u, "transport", out, sizeof(out)), 1); CHECK_STR(out, "tcp");
	CHECK(!sip_uri_parse("sip:10.1.2.3:5060", &u)); CHECK_STR(u.host, "10.1.2.3"); CHECK_STR(u.user, "");
	CHECK(!sip_uri_parse("sip:alice:secret@example.com;user=phone?h=v", &u)); CHECK_STR(u.user, "alice"); CHECK_STR(u.params, ";user=phone");
	CHECK(!sip_uri_parse("SIP:u@[::1]", &u)); CHECK_STR(u.host, "::1"); CHECK_STR(u.scheme, "sip");
	CHECK(!sip_uri_parse("tel:114;phone-context=lguplus.co.kr", &u)); CHECK_STR(u.user, "114");
	CHECK(!sip_uri_parse("tel:+821012345678", &u)); CHECK_STR(u.user, "+821012345678"); CHECK_STR(u.params, "");
	CHECK(sip_uri_parse("http://x", &u) < 0);
	CHECK(sip_uri_parse("sip:", &u) < 0);
	CHECK(sip_uri_parse("sip:u@[::1", &u) < 0);
	CHECK(sip_uri_parse("sip:u@h:99999", &u) < 0);
	{
		char longuri[400] = "sip:";

		memset(longuri + 4, 'a', 300); longuri[304] = 0;
		CHECK(sip_uri_parse(longuri, &u) < 0);	/* host does not fit: error, not truncation */
	}

	/* params */
	CHECK_EQ(sip_params_get(";a=1;b=\"x;y\";c", "b", out, sizeof(out)), 1); CHECK_STR(out, "x;y");
	CHECK_EQ(sip_params_get(";a=1;b=2", "B", out, sizeof(out)), 1); CHECK_STR(out, "2");
	CHECK_EQ(sip_params_get(";abc=1", "a", out, sizeof(out)), 0);	/* whole-name match only */
	CHECK_EQ(sip_params_get(";a=0123456789", "a", out, 4), -1);
	CHECK_EQ(sip_kv_get("Digest realm=\"r\", nonce=\"n=n\", algorithm=AKAv1-MD5", "nonce", out, sizeof(out)), 1); CHECK_STR(out, "n=n");
	CHECK_EQ(sip_kv_get("Digest realm=\"r\", nonce=\"n\"", "realm", out, sizeof(out)), 1); CHECK_STR(out, "r");

	/* Via helpers */
	CHECK(!sip_via_parse("SIP / 2.0 / udp 192.0.2.1:5070 ;branch=z9hG4bKx;rport;received=1.2.3.4", &v));
	{	/* real LG U+ P-CSCF Via (node 2001:4430:5:401::38): an 88-character branch must not be rejected */
		struct sip_via lv;
		CHECK_EQ(sip_via_parse("SIP/2.0/UDP [2001:4430:5:401::38]:1357;branch=z9hG4bK-ag905z-b7997538b679ff39-1-az004a6772141d07048a7e4b8d0d8e67-aWZjMl92Ng..--ag905z-;rport", &lv), 0);
		CHECK_STR(lv.branch, "z9hG4bK-ag905z-b7997538b679ff39-1-az004a6772141d07048a7e4b8d0d8e67-aWZjMl92Ng..--ag905z-");
		CHECK_EQ(lv.port, 1357);
		CHECK_EQ(lv.rport, 0);
	}
	CHECK_STR(v.transport, "UDP"); CHECK_STR(v.host, "192.0.2.1"); CHECK_EQ(v.port, 5070); CHECK_EQ(v.rport, 0); CHECK_STR(v.received, "1.2.3.4");
	CHECK(!sip_via_parse("SIP/2.0/UDP host", &v)); CHECK_EQ(v.port, 0); CHECK_EQ(v.rport, -1); CHECK_STR(v.branch, "");
	CHECK(sip_via_parse("SIP/2.0", &v) < 0);
	addr_set(&a, "2001:db8::5", 8901);
	CHECK(!sip_via_make(via, sizeof(via), "udp", &a, "z9hG4bKabc", true));
	CHECK_STR(via, "SIP/2.0/UDP [2001:db8::5]:8901;branch=z9hG4bKabc;rport");
	addr_set(&a, "192.0.2.9", 5060);
	CHECK(!sip_via_make(via, sizeof(via), "TCP", &a, "z9hG4bKabc", false));
	CHECK_STR(via, "SIP/2.0/TCP 192.0.2.9:5060;branch=z9hG4bKabc");
	sip_new_branch(br); sip_new_branch(br2);
	CHECK(!strncmp(br, "z9hG4bK", 7) && strlen(br) < SIP_BRANCH_LEN && strcmp(br, br2));

	/* stream framing */
	{
		const char *m1 = "OPTIONS sip:a SIP/2.0\r\nl: 5\r\n\r\nhello";
		char two[256];

		CHECK_EQ(sip_frame_len((const uint8_t *)m1, strlen(m1)), (long)strlen(m1));
		CHECK_EQ(sip_frame_len((const uint8_t *)m1, strlen(m1) - 1), 0);
		CHECK_EQ(sip_frame_len((const uint8_t *)m1, 10), 0);
		snprintf(two, sizeof(two), "%s%s", m1, m1);
		CHECK_EQ(sip_frame_len((const uint8_t *)two, strlen(two)), (long)strlen(m1));
		n = sip_frame_len((const uint8_t *)"X sip:a SIP/2.0\r\nContent-Length: 99999999\r\n\r\n", 48);
		CHECK_EQ(n, -1);
		CHECK_EQ(sip_frame_len((const uint8_t *)"X sip:a SIP/2.0\r\nContent-Length: \r\n\r\n", 38), -1);
		CHECK_EQ(sip_frame_len((const uint8_t *)"X sip:a SIP/2.0\r\nVia: x\r\n\r\n", 27), 27);	/* no Content-Length: no body */
	}
}

static void t_response_builder(void)
{
	struct sip_msg req, rsp;
	struct buf b;
	struct sip_resp_parts p;
	struct addr src;
	struct sip_via v;
	static const char *inv =
		"INVITE sip:bob@example.com SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKaaa;rport\r\n"
		"Via: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bKbbb\r\n"
		"From: <sip:alice@example.com>;tag=abc\r\n"
		"To: <sip:bob@example.com>\r\n"
		"Call-ID: cid1\r\nCSeq: 5 INVITE\r\n"
		"Record-Route: <sip:p1;lr>\r\nRecord-Route: <sip:p2;lr>\r\n"
		"Contact: <sip:alice@10.0.0.9>\r\nContent-Length: 0\r\n\r\n";

	CHECK_EQ(parse_str(inv, &req), 0);
	addr_set(&src, "10.0.0.77", 49152);
	memset(&p, 0, sizeof(p));
	p.status = 180; p.to_tag = "t123"; p.src = &src; p.contact = "<sip:bob@10.0.0.2:5060>";
	buf_init(&b, 0);
	CHECK_EQ(sip_build_response(&b, &req, &p), 0);
	CHECK_EQ(sip_parse(b.p, b.len, &rsp), 0);
	CHECK(rsp.is_resp && rsp.status == 180); CHECK_STR(rsp.reason, "Ringing");
	CHECK_EQ(sip_hdr_count(&rsp, "Via"), 2);
	CHECK(!sip_top_via(&rsp, &v));
	CHECK_EQ(v.rport, 49152); CHECK_STR(v.received, "10.0.0.77"); CHECK_STR(v.branch, "z9hG4bKaaa");	/* rport filled, received added */
	CHECK_STR(sip_hdr(&rsp, "Via", 1), "SIP/2.0/UDP 10.0.0.1;branch=z9hG4bKbbb");	/* the rest verbatim */
	CHECK_STR(sip_hdr(&rsp, "To", 0), "<sip:bob@example.com>;tag=t123");
	CHECK_EQ(sip_hdr_count(&rsp, "Record-Route"), 2); CHECK_STR(sip_hdr(&rsp, "Record-Route", 0), "<sip:p1;lr>");
	CHECK_STR(sip_hdr(&rsp, "Contact", 0), "<sip:bob@10.0.0.2:5060>");
	CHECK_STR(sip_hdr(&rsp, "CSeq", 0), "5 INVITE");
	sip_msg_free(&rsp); buf_free(&b);

	/* 100 gets no tag; a To that already has a tag is left alone; 4xx carries no Record-Route */
	p.status = 100; buf_init(&b, 0);
	CHECK_EQ(sip_build_response(&b, &req, &p), 0); CHECK_EQ(sip_parse(b.p, b.len, &rsp), 0);
	CHECK_STR(sip_hdr(&rsp, "To", 0), "<sip:bob@example.com>"); sip_msg_free(&rsp); buf_free(&b);
	p.status = 486; buf_init(&b, 0);
	CHECK_EQ(sip_build_response(&b, &req, &p), 0); CHECK_EQ(sip_parse(b.p, b.len, &rsp), 0);
	CHECK_EQ(sip_hdr_count(&rsp, "Record-Route"), 0); CHECK_STR(rsp.reason, "Busy Here"); sip_msg_free(&rsp); buf_free(&b);
	sip_msg_free(&req);
	{
		static const char *tagged = "BYE sip:b SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKz\r\nFrom: <sip:a>;tag=1\r\nTo: <sip:b>;tag=2\r\nCall-ID: c\r\nCSeq: 2 BYE\r\n\r\n";

		CHECK_EQ(parse_str(tagged, &req), 0);
		p.status = 200; p.src = NULL; p.to_tag = "new"; buf_init(&b, 0);
		CHECK_EQ(sip_build_response(&b, &req, &p), 0); CHECK_EQ(sip_parse(b.p, b.len, &rsp), 0);
		CHECK_STR(sip_hdr(&rsp, "To", 0), "<sip:b>;tag=2");
		CHECK_STR(sip_hdr(&rsp, "Via", 0), "SIP/2.0/UDP h;branch=z9hG4bKz");
		sip_msg_free(&rsp); buf_free(&b); sip_msg_free(&req);
	}

	/* response with a body (binary) */
	{
		static const uint8_t bin[] = { 0, 1, 0, 2 };

		CHECK_EQ(parse_str(inv, &req), 0);
		memset(&p, 0, sizeof(p));
		p.status = 200; p.content_type = "application/octet-stream"; p.body = bin; p.body_len = 4;
		buf_init(&b, 0);
		CHECK_EQ(sip_build_response(&b, &req, &p), 0); CHECK_EQ(sip_parse(b.p, b.len, &rsp), 0);
		CHECK_EQ(rsp.body_len, 4); CHECK(!memcmp(rsp.body, bin, 4));
		sip_msg_free(&rsp); buf_free(&b); sip_msg_free(&req);
	}
}

void test_msg(void)
{
	t_responses();
	t_requests();
	t_misc();
	t_response_builder();
}
