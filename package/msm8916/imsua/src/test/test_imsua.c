/* SPDX-License-Identifier: GPL-2.0-only */
/* host unit tests: make -C src test */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../util.h"
#include "../sip.h"
#include "../dialog.h"
#include "../aka.h"
#include "../ipsec.h"
#include "../rtp.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_STR(a, b) do { checks++; if (strcmp((a), (b))) { fails++; printf("FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); } } while (0)

static const char *R401_TRANS =
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

static const char *SECQ = "ipsec-3gpp;q=0.1;alg=hmac-md5-96;ealg=null;spi-c=10341389;spi-s=10341388;port-c=7537;port-s=1357";

static void test_util(void)
{
	char h[33];
	uint8_t b[64];
	char e[64];

	md5_hex("", 0, h); CHECK_STR(h, "d41d8cd98f00b204e9800998ecf8427e");
	md5_hex("abc", 3, h); CHECK_STR(h, "900150983cd24fb0d6963f7d28e17f72");
	md5_hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, h);
	CHECK_STR(h, "57edf4a22be3c955ac49da2e2107b67a");
	CHECK(b64enc((const uint8_t *)"foobar", 6, e, sizeof(e)) == 8); CHECK_STR(e, "Zm9vYmFy");
	CHECK(b64enc((const uint8_t *)"fo", 2, e, sizeof(e)) == 4); CHECK_STR(e, "Zm8=");
	CHECK(b64dec("MRTdOIZ7hwcN/iIcq7/KRmcd8nPtUoAA4+bwhST7kMM=", b, sizeof(b)) == 32);
	CHECK(b[0] == 0x31 && b[1] == 0x14 && b[31] == 0xc3);
	CHECK(hex2bin("00ff10", b, 8) == 3 && b[1] == 0xff);
}

static void test_parse(void)
{
	struct sip_msg m;
	struct sec_ent e[4];
	char v[128], tag[64];
	uint32_t cs;
	char meth[16];
	int n, s;

	CHECK(!sip_parse(R401_TRANS, strlen(R401_TRANS), &m));
	CHECK(m.is_resp && m.status == 401);
	CHECK_STR(sip_hdr(&m, "call-id", 0), "1664737052_2334231496@2001:4430:135:e395::1e7:4a91");
	CHECK(!sip_cseq(&m, &cs, meth, sizeof(meth)) && cs == 590995228 && !strcmp(meth, "REGISTER"));
	CHECK(sip_param(sip_hdr(&m, "WWW-Authenticate", 0), "nonce", v, sizeof(v)));
	CHECK_STR(v, "MRTdOIZ7hwcN/iIcq7/KRmcd8nPtUoAA4+bwhST7kMM=");
	CHECK(sip_param(sip_hdr(&m, "WWW-Authenticate", 0), "realm", v, sizeof(v)));
	CHECK_STR(v, "lte-lguplus.co.kr");
	CHECK(sip_param(sip_hdr(&m, "WWW-Authenticate", 0), "algorithm", v, sizeof(v)));
	CHECK_STR(v, "AKAv1-MD5");
	sip_tag(sip_hdr(&m, "To", 0), tag, sizeof(tag)); CHECK_STR(tag, "4cf63dca72efd");
	n = sec_parse(sip_hdr(&m, "Security-Server", 0), e, 4);
	CHECK(n == 1);
	CHECK_STR(e[0].prot, "ipsec-3gpp"); CHECK_STR(e[0].mod, "trans"); CHECK_STR(e[0].alg, "hmac-md5-96");
	CHECK_STR(e[0].ealg, "null");
	CHECK(e[0].spi_c == 1612738 && e[0].spi_s == 1612737 && e[0].port_c == 5073 && e[0].port_s == 5071);
	CHECK(e[0].ok && !e[0].sha1 && !e[0].has_q);
	s = sec_select(e, n); CHECK(s == 0);
	sip_free(&m);

	/* q= format, no spaces */
	n = sec_parse(SECQ, e, 4);
	CHECK(n == 1 && e[0].has_q && e[0].q > 0.09 && e[0].q < 0.11);
	CHECK(e[0].spi_c == 10341389 && e[0].spi_s == 10341388 && e[0].port_c == 7537 && e[0].port_s == 1357);
	CHECK(e[0].ok && !e[0].mod[0]);

	/* multiple entries: higher q and supported wins; unsupported alg skipped */
	n = sec_parse("ipsec-3gpp; q=0.9; alg=hmac-sha-256; ealg=null; spi-c=1; spi-s=2; port-c=3; port-s=4,"
		      "ipsec-3gpp; q=0.2; alg=hmac-md5-96; ealg=null; spi-c=11; spi-s=12; port-c=13; port-s=14,"
		      "ipsec-3gpp; q=0.5; alg=hmac-sha-1-96; ealg=null; spi-c=21; spi-s=22; port-c=23; port-s=24", e, 4);
	CHECK(n == 3 && !e[0].ok);
	s = sec_select(e, n); CHECK(s == 2 && e[2].sha1 && e[2].spi_c == 21);
}

static void test_digest(void)
{
	uint8_t res[8] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18 };
	char out[33];

	/* constructed with python hashlib: MD5(MD5(IMPI:realm:RES_raw):nonce:MD5("REGISTER:uri")) */
	digest_response("450061039428657@lte-lguplus.co.kr", "lte-lguplus.co.kr", res, 8,
			"MRTdOIZ7hwcN/iIcq7/KRmcd8nPtUoAA4+bwhST7kMM=", "REGISTER", "sip:lte-lguplus.co.kr", out);
	CHECK_STR(out, "504a0c183df601a5ac7b973cd2ded539");
}

static void test_aka(void)
{
	struct aka_result r;
	uint8_t db[64], k;
	size_t n = 0;
	int i;

	/* DB 08 RES(8) 10 CK 10 IK 90 00 */
	db[n++] = 0xDB; db[n++] = 8;
	for (i = 0; i < 8; i++) db[n++] = 0x10 + i;
	db[n++] = 16; for (i = 0; i < 16; i++) db[n++] = 0x20 + i;
	db[n++] = 16; for (i = 0; i < 16; i++) db[n++] = 0x40 + i;
	k = n;
	CHECK(!aka_parse(db, n, &r) && r.status == AKA_OK && r.res_len == 8 && r.res[0] == 0x10 && r.ck[0] == 0x20 && r.ik[15] == 0x4f && !r.has_kc);
	db[n++] = 0x90; db[n++] = 0x00;
	CHECK(!aka_parse(db, n, &r) && r.status == AKA_OK && r.sw == 0x9000);
	n = k; db[n++] = 8; for (i = 0; i < 8; i++) db[n++] = 0x60 + i; db[n++] = 0x90; db[n++] = 0;
	CHECK(!aka_parse(db, n, &r) && r.has_kc && r.kc[7] == 0x67 && r.sw == 0x9000);
	/* DC 0E AUTS(14) */
	n = 0; db[n++] = 0xDC; db[n++] = 14; for (i = 0; i < 14; i++) db[n++] = 0xA0 + i; db[n++] = 0x90; db[n++] = 0;
	CHECK(!aka_parse(db, n, &r) && r.status == AKA_SYNC_FAIL && r.auts_len == 14 && r.auts[13] == 0xAD);
	/* bare MAC failure SW */
	db[0] = 0x98; db[1] = 0x62;
	CHECK(aka_parse(db, 2, &r) < 0 && r.sw == 0x9862);
	/* apdu layout */
	{
		struct aka_cfg c = { .p2 = 0x81, .cla_from_channel = 1, .channel = 3 };
		uint8_t rnd[16] = {1}, autn[16] = {2}, a[64];
		size_t l = aka_build_apdu(&c, rnd, autn, a);
		CHECK(l == 40 && a[0] == 0x03 && a[1] == 0x88 && a[2] == 0 && a[3] == 0x81 && a[4] == 0x22 && a[5] == 0x10 && a[6] == 1 && a[22] == 0x10 && a[23] == 2 && a[39] == 0);
		c.cla_from_channel = 0; l = aka_build_apdu(&c, rnd, autn, a); CHECK(a[0] == 0x00);
	}
}

/* mock card: first reply 61 2D, GET RESPONSE reply DB... 90 00 */
static int mock_calls;
static int mock_fn(void *ctx, const uint8_t *apdu, size_t n, uint8_t *resp, size_t *rn)
{
	int i; size_t o = 0;

	mock_calls++;
	if (apdu[1] == 0x88) { resp[0] = 0x61; resp[1] = 0x2d; *rn = 2; return 0; }
	if (apdu[1] == 0xC0 && apdu[4] == 0x2d) {
		resp[o++] = 0xDB; resp[o++] = 8; for (i = 0; i < 8; i++) resp[o++] = i;
		resp[o++] = 16; for (i = 0; i < 16; i++) resp[o++] = 0x20 + i;
		resp[o++] = 16; for (i = 0; i < 16; i++) resp[o++] = 0x40 + i;
		resp[o++] = 0x90; resp[o++] = 0; *rn = o; return 0;
	}
	return -1;
}

static void test_aka_flow(void)
{
	struct aka_cfg c = { .p2 = 0x81, .cla_from_channel = 0 };
	uint8_t rnd[16] = {0}, autn[16] = {0};
	struct aka_result r;

	CHECK(!aka_authenticate(mock_fn, NULL, &c, rnd, autn, &r) && r.status == AKA_OK && mock_calls == 2 && r.res_len == 8);
}

/* ---- dialog logic ---- */
static const char *R183 =
	"SIP/2.0 183 Session Progress\r\nVia: SIP/2.0/UDP [2001:db8::1]:8901;branch=z9hG4bKx\r\n"
	"Contact: <sip:[2001:4430:4:401::14]:1357;transport=UDP>\r\n"
	"To: <tel:114;phone-context=lguplus.co.kr>;tag=az00_early_A\r\nFrom: <sip:01039428657@lte-lguplus.co.kr>;tag=1663314068\r\n"
	"Call-ID: c1\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: 98\r\n\r\n"
	"v=0\r\no=vIBCF 1 1 IN IP6 2001:4430:4:319::6\r\ns=-\r\nc=IN IP6 2001:4430:4:319::6\r\nt=0 0\r\nm=audio 50344 RTP/AVP 102 101\r\n"
	"a=rtpmap:102 AMR/8000/1\r\na=fmtp:102 octet-align=0; mode-set=7\r\na=rtpmap:101 telephone-event/8000/1\r\n";
static const char *R200 =
	"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP [2001:db8::1]:8901;branch=z9hG4bKx\r\nRequire: timer\r\n"
	"Contact: <sip:[2001:4430:4:401::14]:1357;transport=UDP>\r\n"
	"To: <tel:114;phone-context=lguplus.co.kr>;tag=az00_final_B\r\nFrom: <sip:01039428657@lte-lguplus.co.kr>;tag=1663314068\r\n"
	"Call-ID: c1\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: 98\r\n\r\n"
	"v=0\r\no=vIBCF 2 1 IN IP6 2001:4430:4:319::6\r\ns=-\r\nc=IN IP6 2001:4430:4:319::6\r\nt=0 0\r\nm=audio 50344 RTP/AVP 102 101\r\n"
	"a=rtpmap:102 AMR/8000/1\r\na=fmtp:102 octet-align=0; mode-set=7\r\na=rtpmap:101 telephone-event/8000/1\r\n";

static int feed(struct call *c, const char *raw, struct call_ev *ev)
{
	struct sip_msg m;
	int n;

	sip_parse(raw, strlen(raw), &m);
	n = call_on_response(c, &m, ev, 4);
	sip_free(&m);
	return n;
}

static void test_dialog(void)
{
	struct call c;
	struct call_ev ev[4];
	struct sip_msg m;
	struct sdp_media s;
	int n, i, ea = -1, eb = -1;

	call_init(&c, 1);
	n = feed(&c, R183, ev);
	/* the 183 (no Require: 100rel) yields only media start, never a request */
	CHECK(n == 1 && ev[0].type == EV_START_RTP);
	CHECK(call_bye_target(&c) < 0);	/* before the 2xx: CANCEL, never BYE on the early dialog */
	n = feed(&c, R200, ev);
	for (i = 0; i < n; i++) if (ev[i].type == EV_ACK) eb = ev[i].dlg;
	CHECK(eb >= 0 && !strcmp(c.d[eb].tag, "az00_final_B"));
	for (i = 0; i < n; i++) CHECK(ev[i].type != EV_PRACK);
	for (i = 0; i < n; i++) if (ev[i].dlg >= 0 && !strcmp(c.d[ev[i].dlg].tag, "az00_early_A")) ea = i;
	CHECK(ea < 0);	/* nothing at all for the early dialog */
	CHECK(call_bye_target(&c) == eb && !strcmp(c.d[call_bye_target(&c)].tag, "az00_final_B"));
	CHECK(!c.d[0].confirmed && c.d[1].confirmed);
	CHECK_STR(c.d[eb].contact, "sip:[2001:4430:4:401::14]:1357;transport=UDP");
	/* retransmitted 200: ACK again, same dialog */
	n = feed(&c, R200, ev);
	CHECK(n == 1 && ev[0].type == EV_DUP_2XX && ev[0].dlg == eb);

	sip_parse(R200, strlen(R200), &m);
	CHECK(!sdp_parse(m.body, m.body_len, &s));
	CHECK_STR(s.ip, "2001:4430:4:319::6"); CHECK(s.port == 50344 && s.pt == 102 && !s.wb && !s.octet_align && s.dtmf_pt == 101);
	sip_free(&m);

	/* 100rel provisional: PRACK on that dialog, once per RSeq */
	{
		static const char *P =
			"SIP/2.0 180 Ringing\r\nTo: <tel:1>;tag=T1\r\nFrom: <sip:a@b>;tag=f\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n"
			"Require: 100rel\r\nRSeq: 7\r\nContact: <sip:x@y>\r\n\r\n";
		call_init(&c, 1);
		n = feed(&c, P, ev); CHECK(n == 1 && ev[0].type == EV_PRACK && ev[0].rseq == 7);
		n = feed(&c, P, ev); CHECK(n == 0);
		CHECK(call_bye_target(&c) < 0);
	}
	/* 486: transaction-level ACK only, no dialog */
	{
		static const char *F = "SIP/2.0 486 Busy Here\r\nTo: <tel:1>;tag=T9\r\nFrom: <sip:a@b>;tag=f\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n\r\n";
		call_init(&c, 1);
		n = feed(&c, F, ev); CHECK(n == 1 && ev[0].type == EV_ACK_NON2XX && c.final_nonok == 486 && call_bye_target(&c) < 0);
	}
}

static void test_cap(void)
{
	struct cap c;
	uint32_t t;
	int bye = 0, cancel = 0, resend = 0, fatal = 0;
	enum cap_act a;

	/* the constants themselves */
	CHECK(IMSUA_CALL_HARD_CAP_MS == 18000 && IMSUA_CALL_ABORT_MS == 19000 && IMSUA_CALL_ABORT_MS < 20000);
	/* options cannot raise the cap */
	cap_init(&c, 60000); CHECK(c.cap_ms == 18000);
	cap_init(&c, 18000); CHECK(c.cap_ms == 18000);
	cap_init(&c, 5000); CHECK(c.cap_ms == 5000);
	cap_init(&c, 0); CHECK(c.cap_ms == 18000);

	/* answered call: BYE at 18000, never earlier */
	cap_init(&c, 0);
	for (t = 0; t < 17999; t += 10) { if (cap_poll(&c, t, 1) != CAP_NONE) { bye = -1000; break; } }
	CHECK(bye == 0);
	a = cap_poll(&c, 18000, 1); CHECK(a == CAP_SEND_BYE);
	/* no response: resend at 18500, FATAL at 19000 */
	for (t = 18001; t < 19000; t++) { a = cap_poll(&c, t, 1); if (a == CAP_RESEND) resend++; if (a == CAP_FATAL) fatal++; }
	CHECK(resend == 1 && fatal == 0);
	CHECK(cap_poll(&c, 19000, 1) == CAP_FATAL);

	/* unanswered: CANCEL at 18000 */
	cap_init(&c, 0);
	CHECK(cap_poll(&c, 17999, 0) == CAP_NONE);
	CHECK(cap_poll(&c, 18000, 0) == CAP_SEND_CANCEL);
	/* 2xx races in after the CANCEL: switch to BYE */
	CHECK(cap_poll(&c, 18100, 1) == CAP_SEND_BYE);
	cap_final_seen(&c);
	CHECK(cap_poll(&c, 19500, 1) == CAP_NONE);	/* answered in time: no fatal */

	/* answered quickly: BYE at 18000 gets 200 at 18040, simulated clock to 25 s: no fatal */
	cap_init(&c, 0); cancel = 0;
	CHECK(cap_poll(&c, 18000, 1) == CAP_SEND_BYE);
	cap_final_seen(&c);
	for (t = 18001; t < 25000; t++) if (cap_poll(&c, t, 1) != CAP_NONE) cancel++;
	CHECK(cancel == 0);

	/* user lowered cap and forced shutdown */
	cap_init(&c, 3000); CHECK(cap_poll(&c, 2999, 1) == CAP_NONE); CHECK(cap_poll(&c, 3000, 1) == CAP_SEND_BYE);
	cap_init(&c, 0); c.force = 1; CHECK(cap_poll(&c, 100, 0) == CAP_SEND_CANCEL);
}

static void test_ipsec(void)
{
	struct ipsec_sa s;
	struct ipsec_cmd c[IPSEC_NCMD];
	char line[512];
	int i, j;

	memset(&s, 0, sizeof(s));
	strcpy(s.ue, "2001:db8::1"); strcpy(s.pcscf, "2001:db8::2");
	s.spi_uc = 1001; s.spi_us = 1002; s.spi_pc = 2001; s.spi_ps = 2002;
	s.port_uc = 8001; s.port_us = 8901; s.port_pc = 5073; s.port_ps = 5071; s.reqid = 4000;
	for (i = 0; i < 16; i++) s.ik[i] = i;
	CHECK(ipsec_build(&s, 1, c) == 8);
	line[0] = 0; for (j = 0; j < c[0].n; j++) { strcat(line, c[0].a[j]); strcat(line, " "); }
	/* out uc -> ps with SPI = Ps (2002 = 0x7d2) */
	CHECK(strstr(line, "state add src 2001:db8::1 dst 2001:db8::2 proto esp spi 0x000007d2 reqid 4000 mode transport auth-trunc hmac(md5) 0x000102030405060708090a0b0c0d0e0f 96 enc ecb(cipher_null)  sel src 2001:db8::1/128 dst 2001:db8::2/128 proto udp sport 8001 dport 5071"));
	line[0] = 0; for (j = 0; j < c[1].n; j++) { strcat(line, c[1].a[j]); strcat(line, " "); }
	CHECK(strstr(line, "spi 0x000007d1 ") && strstr(line, "sport 8901 dport 5073"));	/* out us -> pc, SPI = Pc */
	line[0] = 0; for (j = 0; j < c[2].n; j++) { strcat(line, c[2].a[j]); strcat(line, " "); }
	CHECK(strstr(line, "src 2001:db8::2 dst 2001:db8::1 proto esp spi 0x000003e9 ") && strstr(line, "sport 5071 dport 8001"));	/* in ps -> uc, SPI = Uc */
	line[0] = 0; for (j = 0; j < c[3].n; j++) { strcat(line, c[3].a[j]); strcat(line, " "); }
	CHECK(strstr(line, "spi 0x000003ea ") && strstr(line, "sport 5073 dport 8901"));	/* in pc -> us, SPI = Us */
	line[0] = 0; for (j = 0; j < c[4].n; j++) { strcat(line, c[4].a[j]); strcat(line, " "); }
	CHECK(strstr(line, "policy update src 2001:db8::1/128 dst 2001:db8::2/128 proto udp sport 8001 dport 5071 dir out tmpl src 2001:db8::1 dst 2001:db8::2 proto esp reqid 4000 mode transport"));
	line[0] = 0; for (j = 0; j < c[6].n; j++) { strcat(line, c[6].a[j]); strcat(line, " "); }
	CHECK(strstr(line, "dir in tmpl"));
	s.sha1 = 1;
	ipsec_build(&s, 1, c);
	line[0] = 0; for (j = 0; j < c[0].n; j++) { strcat(line, c[0].a[j]); strcat(line, " "); }
	CHECK(strstr(line, "hmac(sha1) 0x000102030405060708090a0b0c0d0e0f00000000 96"));
	ipsec_build(&s, 0, c);
	line[0] = 0; for (j = 0; j < c[4].n; j++) { strcat(line, c[4].a[j]); strcat(line, " "); }
	CHECK(strstr(line, "policy delete ") && !strstr(line, "tmpl"));
	line[0] = 0; for (j = 0; j < c[0].n; j++) { strcat(line, c[0].a[j]); strcat(line, " "); }
	CHECK(strstr(line, "state delete src 2001:db8::1 dst 2001:db8::2 proto esp spi 0x000007d2") && !strstr(line, "auth"));
}

static void test_rtp(void)
{
	uint8_t p[4];

	CHECK(rtp_nodata_payload(0, p) == 2 && p[0] == 0xF7 && p[1] == 0xC0);
	CHECK(rtp_nodata_payload(1, p) == 2 && p[0] == 0xF0 && p[1] == 0x7C);
}

int main(void)
{
	test_util(); test_parse(); test_digest(); test_aka(); test_aka_flow(); test_dialog(); test_cap(); test_ipsec(); test_rtp();
	printf("%d checks, %d failures\n", checks, fails);
	return fails ? 1 : 0;
}
