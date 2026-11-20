/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "test.h"
#include "../gm/secagree.h"
#include "../util/codec.h"

static const char *R401_TRANS =
	"SIP/2.0 401 UNAUTHORIZED\r\n"
	"Via: SIP/2.0/UDP [2001:4430:135:e395::1e7:4a91]:28800;branch=z9hG4bK1455467046\r\n"
	"To: <sip:01039428657@lte-lguplus.co.kr>;tag=4cf63dca72efd\r\n"
	"From: <sip:01039428657@lte-lguplus.co.kr>;tag=1664737061\r\n"
	"Call-ID: c\r\nCSeq: 590995228 REGISTER\r\n"
	"WWW-Authenticate: Digest realm=\"lte-lguplus.co.kr\", nonce=\"MRTdOIZ7hwcN/iIcq7/KRmcd8nPtUoAA4+bwhST7kMM=\", algorithm=AKAv1-MD5\r\n"
	"Security-Server: ipsec-3gpp; mod=trans; alg=hmac-md5-96; ealg=null; spi-c=1612738; spi-s=1612737; port-c=5073; port-s=5071\r\n\r\n";
static const char *SECQ = "ipsec-3gpp;q=0.1;alg=hmac-md5-96;ealg=null;spi-c=10341389;spi-s=10341388;port-c=7537;port-s=1357";

void test_secagree(void)
{
	struct sip_msg m;
	struct sec_ent e[SEC_MAX_ENT];
	struct digest_challenge ch;
	char out[600], v[600];
	uint8_t auts[14];
	int n;

	CHECK_EQ(sip_parse((const uint8_t *)R401_TRANS, strlen(R401_TRANS), &m), 0);
	n = sec_parse(sip_hdr(&m, "Security-Server", 0), e, SEC_MAX_ENT);
	CHECK_EQ(n, 1);
	CHECK_STR(e[0].prot, "ipsec-3gpp"); CHECK_STR(e[0].mod, "trans"); CHECK_STR(e[0].alg, "hmac-md5-96"); CHECK_STR(e[0].ealg, "null");
	CHECK(e[0].spi_c == 1612738 && e[0].spi_s == 1612737 && e[0].port_c == 5073 && e[0].port_s == 5071);
	CHECK(e[0].ok && !e[0].sha1 && !e[0].has_q);
	CHECK_EQ(sec_select(e, n), 0);
	/* Security-Verify echoes the server value untouched */
	CHECK(!sec_server_value(&m, v, sizeof(v)));
	CHECK_STR(v, "ipsec-3gpp; mod=trans; alg=hmac-md5-96; ealg=null; spi-c=1612738; spi-s=1612737; port-c=5073; port-s=5071");
	CHECK(!sec_build_verify(out, sizeof(out), v)); CHECK_STR(out, v);
	CHECK(sec_build_verify(out, 10, v) < 0);
	/* challenge: nonce decodes to RAND || AUTN */
	CHECK(!digest_parse_challenge(sip_hdr(&m, "WWW-Authenticate", 0), &ch));
	CHECK_STR(ch.realm, "lte-lguplus.co.kr"); CHECK_STR(ch.nonce, "MRTdOIZ7hwcN/iIcq7/KRmcd8nPtUoAA4+bwhST7kMM="); CHECK_STR(ch.algorithm, "AKAv1-MD5");
	CHECK(ch.aka && ch.rand[0] == 0x31 && ch.rand[1] == 0x14 && ch.autn[15] == 0xc3);
	CHECK(digest_parse_challenge("Digest realm=\"x\"", &ch) < 0);
	CHECK(digest_parse_challenge("Digest nonce=\"abc\", realm=\"x\", algorithm=MD5", &ch) == 0 && !ch.aka);
	sip_msg_free(&m);

	/* q= format without spaces */
	n = sec_parse(SECQ, e, SEC_MAX_ENT);
	CHECK(n == 1 && e[0].has_q && e[0].q > 0.09 && e[0].q < 0.11);
	CHECK(e[0].spi_c == 10341389 && e[0].spi_s == 10341388 && e[0].port_c == 7537 && e[0].port_s == 1357);
	CHECK(e[0].ok && !e[0].mod[0]);

	/* several mechanisms: highest q among the supported ones wins, unsupported alg skipped */
	n = sec_parse("ipsec-3gpp; q=0.9; alg=hmac-sha-256; ealg=null; spi-c=1; spi-s=2; port-c=3; port-s=4,"
		      "ipsec-3gpp; q=0.2; alg=hmac-md5-96; ealg=null; spi-c=11; spi-s=12; port-c=13; port-s=14,"
		      "ipsec-3gpp; q=0.5; alg=hmac-sha-1-96; ealg=null; spi-c=21; spi-s=22; port-c=23; port-s=24", e, SEC_MAX_ENT);
	CHECK(n == 3 && !e[0].ok);
	CHECK_EQ(sec_select(e, n), 2); CHECK(e[2].sha1 && e[2].spi_c == 21);
	/* tie: first wins; ealg other than null is not supported; tls entry skipped; missing port is not ok */
	n = sec_parse("ipsec-3gpp;alg=hmac-md5-96;ealg=aes-cbc;spi-c=1;spi-s=2;port-c=3;port-s=4,tls;q=0.9,"
		      "ipsec-3gpp;alg=hmac-md5-96;spi-c=1;spi-s=2;port-c=3,"
		      "ipsec-3gpp;alg=hmac-md5-96;spi-c=5;spi-s=6;port-c=7;port-s=8,ipsec-3gpp;alg=hmac-sha-1-96;spi-c=9;spi-s=10;port-c=11;port-s=12", e, SEC_MAX_ENT);
	CHECK_EQ(n, 5); CHECK(!e[0].ok && !e[1].ok && !e[2].ok && e[3].ok && e[4].ok);
	CHECK_EQ(sec_select(e, n), 3);
	CHECK_EQ(sec_select(e, 3), -1);
	CHECK_EQ(sec_parse("", e, SEC_MAX_ENT), 0);
	CHECK_EQ(sec_parse("ipsec-3gpp;alg=hmac-md5-96;spi-c=99999999999;spi-s=2;port-c=3;port-s=4", e, 2), 1); CHECK(!e[0].ok);	/* spi overflow */

	/* Security-Client */
	{
		struct sec_client c = { 112566253, 1427139618, 8062, 8962 };

		CHECK(!sec_build_client(out, sizeof(out), &c));
		CHECK_STR(out, "ipsec-3gpp; alg=hmac-md5-96; ealg=null; spi-c=112566253; spi-s=1427139618; port-c=8062; port-s=8962,"
			       "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=112566253; spi-s=1427139618; port-c=8062; port-s=8962");
		CHECK(sec_build_client(out, 50, &c) < 0);
		/* our own offer parses back */
		sec_build_client(out, sizeof(out), &c);
		n = sec_parse(out, e, SEC_MAX_ENT);
		CHECK(n == 2 && e[0].ok && !e[0].sha1 && e[1].ok && e[1].sha1 && e[1].port_s == 8962);
	}

	/* digest: vector constructed with python hashlib: MD5(MD5(IMPI:realm:RES_raw):nonce:MD5("REGISTER:uri")) */
	{
		uint8_t res[8] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18 };
		char r[33];
		struct digest_auth a = { .user = "450061039428657@lte-lguplus.co.kr", .realm = "lte-lguplus.co.kr",
			.nonce = "MRTdOIZ7hwcN/iIcq7/KRmcd8nPtUoAA4+bwhST7kMM=", .uri = "sip:lte-lguplus.co.kr", .method = "REGISTER",
			.res = res, .res_len = 8 };

		digest_response(a.user, a.realm, res, 8, a.nonce, "REGISTER", a.uri, r);
		CHECK_STR(r, "504a0c183df601a5ac7b973cd2ded539");
		CHECK(!digest_build_authorization(out, sizeof(out), &a));
		CHECK_STR(out, "Digest username=\"450061039428657@lte-lguplus.co.kr\",realm=\"lte-lguplus.co.kr\",uri=\"sip:lte-lguplus.co.kr\","
			       "nonce=\"MRTdOIZ7hwcN/iIcq7/KRmcd8nPtUoAA4+bwhST7kMM=\",algorithm=AKAv1-MD5,response=\"504a0c183df601a5ac7b973cd2ded539\"");
		/* the response embeds a RES with NUL bytes correctly (binary-safe) */
		{
			uint8_t res0[4] = { 0x00, 0x11, 0x00, 0x22 };

			digest_response("u", "r", res0, 4, "n", "REGISTER", "sip:r", r);
			CHECK_STR(r, "8ff4c65353d9f15bdd2d6ee2a9fbbd05");
		}
		/* initial unauthenticated REGISTER form */
		a.nonce = "";
		CHECK(!digest_build_authorization(out, sizeof(out), &a));
		CHECK_STR(out, "Digest uri=\"sip:lte-lguplus.co.kr\",username=\"450061039428657@lte-lguplus.co.kr\",response=\"\",realm=\"lte-lguplus.co.kr\",nonce=\"\"");
		/* resync: response empty, auts base64 */
		for (n = 0; n < 14; n++) auts[n] = n;
		a.nonce = "abc="; a.auts = auts; a.auts_len = 14;
		CHECK(!digest_build_authorization(out, sizeof(out), &a));
		CHECK(strstr(out, "response=\"\",auts=\"AAECAwQFBgcICQoLDA0=\""));
		CHECK(digest_build_authorization(out, 20, &a) < 0);
	}
}
