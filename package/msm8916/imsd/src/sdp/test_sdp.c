/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host tests for the SDP parser / builder: real captures, syntax variants, limits, fuzz. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sdp.h"
#include "sdp_vectors.h"

static int n_checks, n_fail;

#define CHECK(c) do { n_checks++; if (!(c)) { n_fail++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_STR(a, b) do { n_checks++; if (strcmp((a), (b))) { n_fail++; \
	printf("FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); } } while (0)

static struct sdp S;	/* 20 KiB: keep off the stack */

static int parse(const char *t)
{
	return sdp_parse(&S, t, strlen(t));
}

static uint32_t rng_state = 0xdeadbeef;
static uint32_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

static void test_poc_offer(void)
{
	const struct sdp_media *m;
	char t[64];

	CHECK(parse(VEC_POC_OFFER) == 0);
	CHECK_STR(S.o.user, "root");
	CHECK(S.o.sess_id == 1002 && S.o.version == 1000 && S.o_addr_ok);
	CHECK(addr_family(&S.o_addr) == AF_INET6);
	CHECK_STR(sdp_get(&S, S.name), "QC VOIP");
	CHECK(S.conn.present && addr_family(&S.conn.addr) == AF_INET6);
	CHECK(S.nmedia == 1);
	m = &S.media[0];
	CHECK_STR(sdp_media_type(&S, m), "audio");
	CHECK_STR(sdp_media_proto(&S, m), "RTP/AVP");
	CHECK(m->port == 50010 && m->rtp && m->nfmt == 6);
	CHECK(m->bw.as == 49 && m->bw.rs == 600 && m->bw.rr == 2000 && S.bw.as == -1);
	CHECK(m->ptime == 20 && m->maxptime == 240 && sdp_media_dir(&S, m) == SDP_DIR_SENDRECV);
	CHECK(m->fmt[0].pt == 104 && !strcmp(sdp_fmt_enc(&S, &m->fmt[0]), "AMR-WB") && m->fmt[0].clock == 16000 &&
	      m->fmt[0].channels == 1);
	CHECK_STR(sdp_fmt_fmtp(&S, &m->fmt[1]), "octet-align=1;mode-change-capability=2;max-red=0");
	CHECK(sdp_fmtp_get(sdp_fmt_fmtp(&S, &m->fmt[1]), "octet-align", t, sizeof(t)) == 0 && !strcmp(t, "1"));
	CHECK(sdp_fmtp_get(sdp_fmt_fmtp(&S, &m->fmt[0]), "octet-align", t, sizeof(t)) == -1);
	CHECK(!strcmp(sdp_fmt_enc(&S, sdp_media_find_fmt(m, 107)), "EVRCWB0"));
	CHECK(!strcmp(sdp_fmt_fmtp(&S, sdp_media_find_fmt(m, 101)), "0-15"));
	CHECK(sdp_fmtp_is_bare("0-15") && !sdp_fmtp_is_bare("a=b") && !sdp_fmtp_is_bare(""));
	CHECK(S.nattr == 0 && m->nattr == 0);
}

static void test_other_vectors(void)
{
	const struct sdp_media *m;
	char t[64];
	long v;

	CHECK(parse(VEC_A114_183) == 0);
	m = &S.media[0];
	CHECK(S.o_addr_ok && !strcmp(S.o.user, "vIBCF") && S.o.sess_id == 1351675568ull && S.o.version == 1795104518ull);
	CHECK(m->port == 48814 && m->nfmt == 2 && m->bw.as == 38 && m->bw.rs == 0 && m->bw.rr == 700);
	/* "octet-align=0; mode-set=7" (blank after the semicolon) */
	CHECK(sdp_fmtp_get(sdp_fmt_fmtp(&S, &m->fmt[0]), "mode-set", t, sizeof(t)) == 0 && !strcmp(t, "7"));
	CHECK(sdp_fmtp_get_int(sdp_fmt_fmtp(&S, &m->fmt[0]), "octet-align", &v) == 0 && v == 0);
	CHECK(sdp_fmtp_get_int(sdp_fmt_fmtp(&S, &m->fmt[0]), "mode-set", &v) == 0 && v == 7);
	CHECK(m->fmt[1].clock == 8000 && !strcmp(sdp_fmt_enc(&S, &m->fmt[1]), "telephone-event"));
	CHECK(parse(VEC_A114_200) == 0 && S.media[0].port == 48814);

	CHECK(parse(VEC_MRF_ANSWER) == 0);
	m = &S.media[0];
	CHECK(m->port == 38470 && m->maxptime == 60 && m->ptime == 20 && m->nfmt == 2);
	CHECK(m->fmt[0].clock == 16000 && m->fmt[0].channels == 0);	/* "AMR-WB/16000" without channels */
	CHECK_STR(sdp_fmt_fmtp(&S, &m->fmt[1]), "0-11");

	CHECK(parse(VEC_VM_ANSWER) == 0);
	m = &S.media[0];
	CHECK(sdp_fmtp_get(sdp_fmt_fmtp(&S, &m->fmt[0]), "octet-align", t, sizeof(t)) == 0 && !strcmp(t, "1"));

	CHECK(parse(VEC_MT_OFFER) == 0);
	m = &S.media[0];
	CHECK(m->nfmt == 5 && m->port == 44218 && m->bw.as == 50 && m->maxptime == 120);
	CHECK_STR(sdp_get(&S, S.name), "-");
	CHECK_STR(sdp_fmt_enc(&S, &m->fmt[0]), "EVS");
	CHECK(m->fmt[0].channels == 0 && m->fmt[0].clock == 16000);
	CHECK(m->nattr == 1);	/* a=candidate preserved */
	CHECK(!strcmp(sdp_get(&S, m->attr[0].name), "candidate") && m->attr[0].has_value);
	CHECK(sdp_media_find_attr(&S, m, "candidate") == &m->attr[0] && !sdp_media_find_attr(&S, m, "nope"));
	CHECK(!strncmp(sdp_get(&S, m->attr[0].value), "1 1 UDP 2130706431", 18));
	CHECK(parse(VEC_MT_ANSWER_OURS) == 0 && S.media[0].nfmt == 2);
	CHECK(parse(VEC_VM_OFFER) == 0 && parse(VEC_MRF_OFFER) == 0);
}

static void test_syntax_variants(void)
{
	const struct sdp_media *m;
	const struct sdp_fmt *f;

	/* bare LF, trailing blanks, no o= s= t=, session level c=, static payloads without rtpmap */
	CHECK(parse("v=0\nc=IN IP4 192.0.2.7   \nm=audio 4000 RTP/AVP 0 8 9 18 101  \na=rtpmap:101 telephone-event/8000\n"
		    "a=fmtp:101 0-16  \na=sendonly\n") == 0);
	m = &S.media[0];
	CHECK(S.conn.present && addr_is_v4(&S.conn.addr) && S.nmedia == 1 && m->nfmt == 5);
	f = sdp_media_find_fmt(m, 0);
	CHECK(f && !strcmp(sdp_fmt_enc(&S, f), "PCMU") && f->clock == 8000 && !f->has_rtpmap);
	f = sdp_media_find_fmt(m, 8);
	CHECK(f && !strcmp(sdp_fmt_enc(&S, f), "PCMA") && f->clock == 8000);
	f = sdp_media_find_fmt(m, 9);
	CHECK(f && !strcmp(sdp_fmt_enc(&S, f), "G722") && f->clock == 8000);
	f = sdp_media_find_fmt(m, 18);
	CHECK(f && !strcmp(sdp_fmt_enc(&S, f), "G729"));
	f = sdp_media_find_fmt(m, 101);
	CHECK(f && f->has_rtpmap && !strcmp(sdp_fmt_fmtp(&S, f), "0-16") && f->channels == 0);
	CHECK(sdp_media_dir(&S, m) == SDP_DIR_SENDONLY && m->dir == SDP_DIR_SENDONLY && S.dir == SDP_DIR_NONE);
	CHECK(sdp_media_conn(&S, m) == &S.conn);

	/* media level direction overrides session level; media c= overrides session c= */
	CHECK(parse("v=0\r\no=- 1 2 IN IP4 10.0.0.1\r\ns=x\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\na=recvonly\r\n"
		    "m=audio 5000 RTP/AVP 8\r\nc=IN IP6 2001:db8::5\r\na=inactive\r\n"
		    "m=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n") == 0);
	CHECK(S.nmedia == 2 && sdp_media_dir(&S, &S.media[0]) == SDP_DIR_INACTIVE && sdp_media_dir(&S, &S.media[1]) == SDP_DIR_RECVONLY);
	CHECK(sdp_media_conn(&S, &S.media[0]) == &S.media[0].conn && addr_family(&S.media[0].conn.addr) == AF_INET6);
	CHECK(S.media[1].port == 0 && S.media[1].fmt[0].clock == 90000);
	CHECK(sdp_media_conn(&S, &S.media[1]) == &S.conn);

	/* session ptime inherited, rtcp, bandwidth at session level, unknown attributes in order */
	CHECK(parse("v=0\no=a 1 1 IN IP4 1.2.3.4\ns=-\nb=AS:64\nc=IN IP4 1.2.3.4\nt=0 0\na=ptime:30\na=x-session\na=group:foo\n"
		    "m=audio 6000 RTP/AVP 8\na=rtcp:6011 IN IP4 1.2.3.5\na=curr:qos local sendrecv\na=des:qos mandatory local sendrecv\n"
		    "a=conf:qos remote sendrecv\na=rtcp-mux\na=fmtp:99 foo\na=rtpmap:98 foo/8000\n") == 0);
	m = &S.media[0];
	CHECK(S.bw.as == 64 && m->ptime == 30 && m->rtcp_port == 6011 && m->has_rtcp_addr && S.nattr == 2);
	CHECK(!strcmp(sdp_get(&S, S.attr[0].name), "x-session") && !S.attr[0].has_value);
	CHECK(m->nattr == 6);
	CHECK(!strcmp(sdp_get(&S, m->attr[0].name), "curr") && !strcmp(sdp_get(&S, m->attr[1].name), "des") &&
	      !strcmp(sdp_get(&S, m->attr[2].name), "conf") && !strcmp(sdp_get(&S, m->attr[3].name), "rtcp-mux"));
	CHECK(!strcmp(sdp_get(&S, m->attr[4].name), "fmtp") && !strcmp(sdp_get(&S, m->attr[5].name), "rtpmap"));
	CHECK_STR(sdp_get(&S, m->attr[1].value), "qos mandatory local sendrecv");
	CHECK(sdp_find_attr(&S, "group") != NULL);

	/* IPv6 origin / connection, hostname origin tolerated, c= with TTL */
	CHECK(parse("v=0\no=- 5 6 IN IP6 2001:db8::1\ns=-\nc=IN IP6 ::\nt=0 0\nm=audio 9 RTP/AVP 8\n") == 0);
	CHECK(S.o_addr_ok && sdp_conn_is_any(&S.conn));
	CHECK(parse("v=0\no=- 5 6 IN IP4 host.example.com\ns=-\nc=IN IP4 224.2.1.1/127\nt=0 0\nm=audio 9 RTP/AVP 8\n") == 0);
	CHECK(!S.o_addr_ok && S.conn.present && !sdp_conn_is_any(&S.conn));
	CHECK(parse("v=0\nc=IN IP4 0.0.0.0\nm=audio 9 RTP/AVP 8\n") == 0 && sdp_conn_is_any(&S.conn));

	/* non-RTP media keeps its raw format list */
	CHECK(parse("v=0\nm=image 7000 udptl t38\nm=application 9 TCP/MSRP *\n") == 0);
	CHECK(!S.media[0].rtp && !strcmp(sdp_get(&S, S.media[0].raw_fmts), "t38") && S.media[1].nfmt == 0);

	/* empty body with v only, blank lines, m= port/n */
	CHECK(parse("v=0\n\n\n") == 0 && S.nmedia == 0);
	CHECK(parse("v=0\nm=audio 4000/2 RTP/AVP 8\n") == 0 && S.media[0].nports == 2);
	/* i= u= e= p= k= z= r= ignored */
	CHECK(parse("v=0\ni=info\nu=http://x\ne=a@b\np=+1\nk=clear:x\nz=0 0\nr=1 2 3\nm=audio 4000 RTP/AVP 8\n") == 0);
	/* case: attribute names are matched exactly; bandwidth types other than AS/RS/RR ignored */
	CHECK(parse("v=0\nb=CT:128\nb=TIAS:64000\nm=audio 4000 RTP/AVP 8\nb=AS:12\n") == 0 && S.bw.as == -1 && S.media[0].bw.as == 12);
}

static void test_errors(void)
{
	char big[40000];
	size_t i, n;

	CHECK(parse("") == SDP_E_SYNTAX);
	CHECK(parse("o=- 1 1 IN IP4 1.1.1.1\n") == SDP_E_SYNTAX);	/* v= must come first */
	CHECK(parse("v=1\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nv=0\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\ngarbage\n") == SDP_E_SYNTAX && S.err_line == 2);
	CHECK(parse("v=0\n=x\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\n1=x\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio 4000\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio x RTP/AVP 8\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio 70000 RTP/AVP 8\n") == SDP_E_RANGE);
	CHECK(parse("v=0\nm=audio -1 RTP/AVP 8\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 128\n") == SDP_E_RANGE);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 99999999999999999999\n") == SDP_E_RANGE);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8x\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\no=a b c IN IP4 1.1.1.1\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\no=a 99999999999999999999 1 IN IP4 1.1.1.1\n") == SDP_E_RANGE);
	CHECK(parse("v=0\no=a 1 1 IN IP4\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nc=IN IP4 not-an-ip\n") == SDP_E_ADDR);
	CHECK(parse("v=0\nc=IN IP4 2001:db8::1\n") == SDP_E_ADDR);
	CHECK(parse("v=0\nc=IN IP6 1.2.3.4\n") == SDP_E_ADDR);
	CHECK(parse("v=0\nc=ATM IP4 1.2.3.4\n") == SDP_E_ADDR);
	CHECK(parse("v=0\nc=IN IP4\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nb=AS\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nb=AS:x\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nb=AS:99999999999\n") == SDP_E_RANGE);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=rtpmap:8\n") != 0);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=rtpmap:8 PCMA\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=rtpmap:8 PCMA/0\n") == SDP_E_RANGE);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=rtpmap:8 PCMA/8000/x\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=rtpmap:x PCMA/8000\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=rtpmap:8 /8000\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=fmtp:8\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=fmtp:8 \n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=ptime:0\n") == SDP_E_RANGE);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=ptime:20.5\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=maxptime:999999\n") == SDP_E_RANGE);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=rtcp:0\n") == SDP_E_RANGE);
	CHECK(parse("v=0\nm=audio 4000 RTP/AVP 8\na=rtcp:5001 IN IP4\n") == SDP_E_SYNTAX);
	CHECK(parse("v=0\na=\n") == SDP_E_SYNTAX);
	CHECK(sdp_parse(&S, "v=0\n\0x=y\n", 9) == SDP_E_SYNTAX);
	CHECK(sdp_parse(NULL, "v=0", 3) == SDP_E_ARG && sdp_parse(&S, NULL, 3) == SDP_E_ARG);

	/* limits */
	{
		char t[4096];
		int k;

		strcpy(t, "v=0\n");
		for (k = 0; k < 5; k++)
			strcat(t, "m=audio 4000 RTP/AVP 8\n");
		CHECK(parse(t) == SDP_E_LIMIT);
		strcpy(t, "v=0\n");
		for (k = 0; k < 4; k++)
			strcat(t, "m=audio 4000 RTP/AVP 8\n");
		CHECK(parse(t) == 0 && S.nmedia == 4);

		strcpy(t, "v=0\nm=audio 4000 RTP/AVP");
		for (k = 0; k < 32; k++)
			strcat(t, " 8");
		strcat(t, "\n");
		CHECK(parse(t) == 0 && S.media[0].nfmt == 32);
		strcpy(t, "v=0\nm=audio 4000 RTP/AVP");
		for (k = 0; k < 33; k++)
			strcat(t, " 8");
		strcat(t, "\n");
		CHECK(parse(t) == SDP_E_LIMIT);

		strcpy(t, "v=0\nm=audio 4000 RTP/AVP 8\n");
		for (k = 0; k < 64; k++)
			strcat(t, "a=x-attr:1\n");
		CHECK(parse(t) == 0 && S.media[0].nattr == 64);
		strcat(t, "a=x-attr:1\n");
		CHECK(parse(t) == SDP_E_LIMIT);
		strcpy(t, "v=0\n");
		for (k = 0; k < 65; k++)
			strcat(t, "a=y\n");
		CHECK(parse(t) == SDP_E_LIMIT);
	}
	/* a line over SDP_MAX_LINE, and a pool that runs full */
	n = 0;
	memcpy(big, "v=0\na=x:", 8);
	n = 8;
	for (i = 0; i < SDP_MAX_LINE; i++)
		big[n++] = 'y';
	big[n++] = '\n';
	CHECK(sdp_parse(&S, big, n) == SDP_E_LIMIT);
	n = 0;
	memcpy(big, "v=0\nm=audio 4000 RTP/AVP 8\n", 27);
	n = 27;
	for (i = 0; i < 64; i++)
		n += (size_t)sprintf(big + n, "a=a%zu:%0400d\n", i, 7);
	CHECK(sdp_parse(&S, big, n) == SDP_E_LIMIT);	/* 64 * ~410 bytes of strings overrun the 8 KiB pool */
}

static void test_fmtp(void)
{
	char t[16];
	long v;

	CHECK(sdp_fmtp_get("a=1; B = 2 ;c", "b", t, sizeof(t)) == 0 && !strcmp(t, "2"));
	CHECK(sdp_fmtp_get("a=1; B = 2 ;c", "c", t, sizeof(t)) == 0 && !strcmp(t, ""));
	CHECK(sdp_fmtp_get("a=1;;;b=2;", "b", t, sizeof(t)) == 0 && !strcmp(t, "2"));
	CHECK(sdp_fmtp_get("a=1", "A", t, sizeof(t)) == 0);
	CHECK(sdp_fmtp_get("a=1", "a=", t, sizeof(t)) == -1);
	CHECK(sdp_fmtp_get("ab=1", "a", t, sizeof(t)) == -1);
	CHECK(sdp_fmtp_get("a=0123456789abcdefghij", "a", t, sizeof(t)) == -2);
	CHECK(sdp_fmtp_get("a=0123456789abcde", "a", t, sizeof(t)) == 0 && strlen(t) == 15);
	CHECK(sdp_fmtp_get("", "a", t, sizeof(t)) == -1 && sdp_fmtp_get(NULL, "a", t, sizeof(t)) == -1);
	CHECK(sdp_fmtp_get_int("a=12;b=x;c=-3", "a", &v) == 0 && v == 12);
	CHECK(sdp_fmtp_get_int("a=12;b=x;c=-3", "b", &v) == -2 && sdp_fmtp_get_int("c=-3", "c", &v) == -2);
	CHECK(sdp_fmtp_get_int("a=12", "z", &v) == -1);
	CHECK(sdp_fmtp_get("0-15", "0-15", t, sizeof(t)) == 0);
}

static void test_dirs(void)
{
	CHECK(sdp_dir_sends(SDP_DIR_SENDRECV) && sdp_dir_recvs(SDP_DIR_SENDRECV) && sdp_dir_sends(SDP_DIR_NONE));
	CHECK(sdp_dir_sends(SDP_DIR_SENDONLY) && !sdp_dir_recvs(SDP_DIR_SENDONLY));
	CHECK(!sdp_dir_sends(SDP_DIR_RECVONLY) && sdp_dir_recvs(SDP_DIR_RECVONLY));
	CHECK(!sdp_dir_sends(SDP_DIR_INACTIVE) && !sdp_dir_recvs(SDP_DIR_INACTIVE));
	CHECK(sdp_dir_make(true, true) == SDP_DIR_SENDRECV && sdp_dir_make(true, false) == SDP_DIR_SENDONLY);
	CHECK(sdp_dir_make(false, true) == SDP_DIR_RECVONLY && sdp_dir_make(false, false) == SDP_DIR_INACTIVE);
	CHECK(sdp_dir_flip(SDP_DIR_SENDONLY) == SDP_DIR_RECVONLY && sdp_dir_flip(SDP_DIR_RECVONLY) == SDP_DIR_SENDONLY);
	CHECK(sdp_dir_flip(SDP_DIR_INACTIVE) == SDP_DIR_INACTIVE && sdp_dir_flip(SDP_DIR_SENDRECV) == SDP_DIR_SENDRECV);
	CHECK_STR(sdp_dir_name(SDP_DIR_INACTIVE), "inactive");
}

/* ---- builder ---- */
static struct sdp A, B;

static int write_str(const struct sdp *s, char *out, size_t n)
{
	struct buf b;
	int r;

	buf_init_fixed(&b, out, n);
	r = sdp_write(s, &b);
	return r;
}

static void test_builder(void)
{
	struct addr a4, a6;
	char t1[4096], t2[4096];
	struct sdp_media *m;
	struct buf b;

	CHECK(addr_set(&a4, "192.0.2.10", 4000) == 0 && addr_set(&a6, "2001:db8::10", 5000) == 0);

	/* IPv4 */
	sdp_init(&A);
	CHECK(sdp_set_origin(&A, "imsd", 77, 1, &a4) == 0 && sdp_set_name(&A, "call") == 0);
	sdp_set_conn(&A.conn, &a4);
	m = sdp_add_media(&A, "audio", 4000, "RTP/AVP");
	CHECK(m != NULL);
	CHECK(sdp_add_fmt(&A, m, 8, "PCMA", 8000, 1, NULL) == 0);
	CHECK(sdp_add_fmt(&A, m, 111, "opus", 48000, 2, "maxplaybackrate=16000;stereo=0") == 0);
	CHECK(sdp_add_fmt(&A, m, 101, "telephone-event", 8000, 0, "0-15") == 0);
	CHECK(sdp_media_add_attr(&A, m, "curr", "qos local none") == 0 && sdp_media_add_attr(&A, m, "rtcp-mux", NULL) == 0);
	m->ptime = 20;
	m->bw.as = 40;
	sdp_media_set_dir(m, SDP_DIR_SENDONLY);
	CHECK(write_str(&A, t1, sizeof(t1)) == 0);
	CHECK(strstr(t1, "o=imsd 77 1 IN IP4 192.0.2.10\r\n") && strstr(t1, "c=IN IP4 192.0.2.10\r\n"));
	CHECK(strstr(t1, "m=audio 4000 RTP/AVP 8 111 101\r\n") && strstr(t1, "a=rtpmap:111 opus/48000/2\r\n"));
	CHECK(strstr(t1, "a=rtpmap:101 telephone-event/8000\r\n") && strstr(t1, "a=fmtp:101 0-15\r\n"));
	CHECK(strstr(t1, "a=sendonly\r\n") && strstr(t1, "b=AS:40\r\n") && strstr(t1, "a=curr:qos local none\r\n"));
	CHECK(strstr(t1, "t=0 0\r\n") && !strstr(t1, "b=RS"));
	/* parse it back and write again: identical */
	CHECK(sdp_parse(&B, t1, strlen(t1)) == 0 && write_str(&B, t2, sizeof(t2)) == 0 && !strcmp(t1, t2));
	CHECK(B.media[0].nfmt == 3 && B.media[0].bw.as == 40 && B.media[0].dir == SDP_DIR_SENDONLY && B.media[0].nattr == 2);

	/* IPv6 */
	sdp_init(&A);
	sdp_set_origin(&A, "", 1, 1, &a6);
	sdp_set_conn(&A.conn, &a6);
	m = sdp_add_media(&A, "audio", 5000, "RTP/AVP");
	sdp_add_fmt(&A, m, 9, "G722", 8000, 1, NULL);
	CHECK(write_str(&A, t1, sizeof(t1)) == 0);
	CHECK(strstr(t1, "o=- 1 1 IN IP6 2001:db8::10\r\n") && strstr(t1, "c=IN IP6 2001:db8::10\r\n") && strstr(t1, "s=-\r\n"));
	CHECK(sdp_parse(&B, t1, strlen(t1)) == 0 && write_str(&B, t2, sizeof(t2)) == 0 && !strcmp(t1, t2));
	CHECK(addr_family(&B.conn.addr) == AF_INET6 && addr_is_v4(&B.conn.addr) == false);

	/* every captured vector survives parse -> write -> parse -> write */
	{
		const char *v[] = { VEC_POC_OFFER, VEC_A114_183, VEC_A114_200, VEC_VM_OFFER, VEC_VM_ANSWER, VEC_MT_OFFER,
				    VEC_MT_ANSWER_OURS, VEC_MRF_OFFER, VEC_MRF_ANSWER };
		size_t i;

		for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
			CHECK(parse(v[i]) == 0);
			CHECK(write_str(&S, t1, sizeof(t1)) == 0);
			CHECK(sdp_parse(&B, t1, strlen(t1)) == 0 && write_str(&B, t2, sizeof(t2)) == 0 && !strcmp(t1, t2));
			CHECK(B.nmedia == S.nmedia && B.media[0].port == S.media[0].port && B.media[0].nfmt == S.media[0].nfmt);
		}
	}

	/* overflow is reported, never silent */
	buf_init_fixed(&b, t2, 20);
	CHECK(sdp_write(&A, &b) == SDP_E_OVERFLOW);

	/* limits in the builder */
	sdp_init(&A);
	{
		int i;

		for (i = 0; i < SDP_MAX_MEDIA; i++)
			CHECK(sdp_add_media(&A, "audio", 1, "RTP/AVP") != NULL);
		CHECK(sdp_add_media(&A, "audio", 1, "RTP/AVP") == NULL);
		m = &A.media[0];
		for (i = 0; i < SDP_MAX_FMT; i++)
			CHECK(sdp_add_fmt(&A, m, i, NULL, 0, 0, NULL) == 0);
		CHECK(sdp_add_fmt(&A, m, 1, NULL, 0, 0, NULL) == SDP_E_LIMIT);
		CHECK(sdp_add_fmt(&A, &A.media[1], 128, NULL, 0, 0, NULL) == SDP_E_RANGE);
		CHECK(sdp_add_fmt(&A, &A.media[1], -1, NULL, 0, 0, NULL) == SDP_E_RANGE);
		for (i = 0; i < SDP_MAX_ATTR; i++)
			CHECK(sdp_add_attr(&A, "x", "1") == 0);
		CHECK(sdp_add_attr(&A, "x", "1") == SDP_E_LIMIT);
		CHECK(sdp_set_origin(&A, "0123456789012345678901234567890123", 1, 1, NULL) == SDP_E_LIMIT);
	}
	/* a media section without formats cannot be serialised */
	sdp_init(&A);
	sdp_add_media(&A, "audio", 1, "RTP/AVP");
	CHECK(write_str(&A, t1, sizeof(t1)) == SDP_E_ARG);
}

static void test_version_handling(void)
{
	struct addr a4;
	struct sdp *p = malloc(sizeof(*p)), *n = malloc(sizeof(*n));
	struct sdp_media *m;

	addr_set(&a4, "192.0.2.10", 4000);
	sdp_init(p);
	sdp_set_origin(p, "imsd", 500, 7, &a4);
	sdp_set_conn(&p->conn, &a4);
	m = sdp_add_media(p, "audio", 4000, "RTP/AVP");
	sdp_add_fmt(p, m, 8, "PCMA", 8000, 1, NULL);
	sdp_media_set_dir(m, SDP_DIR_SENDRECV);

	/* identical content: version unchanged, session id and user copied */
	*n = *p;
	n->o.version = 0;
	n->o.sess_id = 0;
	strcpy(n->o.user, "other");
	CHECK(sdp_origin_succeed(n, p) == 0);
	CHECK(n->o.version == 7 && n->o.sess_id == 500 && !strcmp(n->o.user, "imsd"));

	/* direction change: version + 1 */
	sdp_media_set_dir(&n->media[0], SDP_DIR_SENDONLY);
	CHECK(sdp_origin_succeed(n, p) == 0 && n->o.version == 8);
	/* new media address: version + 1 */
	*n = *p;
	addr_set(&a4, "192.0.2.11", 4000);
	sdp_set_conn(&n->conn, &a4);
	CHECK(sdp_origin_succeed(n, p) == 0 && n->o.version == 8);
	/* new port */
	*n = *p;
	n->media[0].port = 4002;
	CHECK(sdp_origin_succeed(n, p) == 0 && n->o.version == 8);
	/* added attribute */
	*n = *p;
	sdp_media_add_attr(n, &n->media[0], "x", "y");
	CHECK(sdp_origin_succeed(n, p) == 0 && n->o.version == 8);
	/* chained: each re-offer builds on the last one sent */
	*p = *n;
	p->o.version = 8;
	*n = *p;
	CHECK(sdp_origin_succeed(n, p) == 0 && n->o.version == 8);
	/* plain struct copies stay valid (offsets, not pointers) */
	{
		char t1[2048], t2[2048];

		CHECK(write_str(n, t1, sizeof(t1)) == 0 && write_str(p, t2, sizeof(t2)) == 0 && !strcmp(t1, t2));
	}
	free(p);
	free(n);
}

/* ---- robustness ---- */
static void test_fuzz(void)
{
	const char *vecs[] = { VEC_POC_OFFER, VEC_A114_183, VEC_VM_ANSWER, VEC_MT_OFFER, VEC_MRF_ANSWER,
			       "v=0\no=- 1 1 IN IP4 1.2.3.4\nc=IN IP4 1.2.3.4\nm=audio 4000 RTP/AVP 0 8 9\na=rtcp:4001 IN IP4 1.2.3.5\n" };
	static const char alpha[] = "v=oscmbta:/ \r\n0123456789ABCIPN-;,.";
	size_t vi, i;
	int it, ok = 0, bad = 0;
	char *buf = malloc(8192);

	for (vi = 0; vi < sizeof(vecs) / sizeof(vecs[0]); vi++) {
		size_t n = strlen(vecs[vi]);

		/* every prefix, with an exactly sized heap copy so ASan sees any over-read */
		for (i = 0; i <= n; i++) {
			char *tmp = malloc(i ? i : 1);

			memcpy(tmp, vecs[vi], i);
			(sdp_parse(&S, tmp, i) == 0 ? ok++ : bad++);
			free(tmp);
		}
		for (it = 0; it < 6000; it++) {
			int m = 1 + (int)(rnd() % 5);
			size_t len = n;
			char *tmp;

			memcpy(buf, vecs[vi], n);
			while (m--) {
				size_t pos = rnd() % len;

				switch (rnd() % 4) {
				case 0: buf[pos] = (char)rnd(); break;
				case 1: buf[pos] = alpha[rnd() % (sizeof(alpha) - 1)]; break;
				case 2:
					if (len > pos + 1) {
						memmove(buf + pos, buf + pos + 1, len - pos - 1);
						len--;
					}
					break;
				default:
					if (len < 8000) {
						memmove(buf + pos + 1, buf + pos, len - pos);
						buf[pos] = alpha[rnd() % (sizeof(alpha) - 1)];
						len++;
					}
				}
			}
			tmp = malloc(len ? len : 1);
			memcpy(tmp, buf, len);
			if (sdp_parse(&S, tmp, len) == 0) {
				char out[8192];
				struct buf b;

				ok++;
				buf_init_fixed(&b, out, sizeof(out));
				sdp_write(&S, &b);	/* any parsed result must be writable without faults */
			} else {
				bad++;
			}
			free(tmp);
		}
	}
	/* random garbage */
	for (it = 0; it < 30000; it++) {
		size_t len = rnd() % 300;
		char *tmp = malloc(len ? len : 1);

		for (i = 0; i < len; i++)
			tmp[i] = rnd() % 3 ? alpha[rnd() % (sizeof(alpha) - 1)] : (char)rnd();
		sdp_parse(&S, tmp, len);
		free(tmp);
	}
	/* huge lists / absurd values in otherwise valid documents */
	{
		size_t n = 0;
		char *h = malloc(300000);

		n += (size_t)sprintf(h + n, "v=0\nm=audio 4000 RTP/AVP");
		for (i = 0; i < 20000; i++)
			n += (size_t)sprintf(h + n, " %zu", i);
		n += (size_t)sprintf(h + n, "\n");
		CHECK(sdp_parse(&S, h, n) == SDP_E_LIMIT || sdp_parse(&S, h, n) == SDP_E_LIMIT);
		n = 0;
		for (i = 0; i < 20000; i++)
			n += (size_t)sprintf(h + n, "a=a:b\n");
		CHECK(sdp_parse(&S, h, n) == SDP_E_SYNTAX);	/* no v= first */
		memcpy(h, "v=0\n", 4);
		n = 4;
		for (i = 0; i < 20000; i++)
			n += (size_t)sprintf(h + n, "a=a:b\n");
		CHECK(sdp_parse(&S, h, n) == SDP_E_LIMIT);
		free(h);
	}
	free(buf);
	CHECK(ok > 0 && bad > 0);
}

int main(void)
{
	test_poc_offer();
	test_other_vectors();
	test_syntax_variants();
	test_errors();
	test_fmtp();
	test_dirs();
	test_builder();
	test_version_handling();
	test_fuzz();
	printf("test_sdp: %d checks, %d failed\n", n_checks, n_fail);
	return n_fail ? 1 : 0;
}
