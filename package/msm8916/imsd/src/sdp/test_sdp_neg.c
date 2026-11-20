/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host tests for codec negotiation: results must match what worked on LG U+ (captured SDP). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sdp.h"
#include "sdp_neg.h"
#include "sdp_vectors.h"

static int n_checks, n_fail;

#define CHECK(c) do { n_checks++; if (!(c)) { n_fail++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_STR(a, b) do { n_checks++; if (strcmp((a), (b))) { n_fail++; \
	printf("FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); } } while (0)

static struct sdp OFF, ANS, MINE, TMP;	/* big structs, keep off the stack */
static struct sdpn_media N;

static bool remote_is(const struct sdpn_media *n, const char *host, uint16_t port)
{
	struct addr a;

	return addr_set(&a, host, port) == 0 && addr_equal(&n->remote, &a);
}

static int parse_into(struct sdp *s, const char *t)
{
	return sdp_parse(s, t, strlen(t));
}

static char text[4096];
static const char *dump(const struct sdp *s)
{
	struct buf b;

	buf_init_fixed(&b, text, sizeof(text));
	if (sdp_write(s, &b) < 0)
		strcpy(text, "<overflow>");
	return text;
}

static struct sdp_origin org = { "imsd", 4242, 1 };

static struct addr rtp6, rtp4;

/* m= line of an SDP body as "port: pts" */
static void mline(const struct sdp *s, int i, char *out, size_t n)
{
	const struct sdp_media *m = &s->media[i];
	int k, w = snprintf(out, n, "%s %u %s", sdp_media_type(s, m), (unsigned)m->port, sdp_media_proto(s, m));

	for (k = 0; k < m->nfmt && (size_t)w < n; k++)
		w += snprintf(out + w, n - (size_t)w, " %d", m->fmt[k].pt);
}

/* ---- carrier: offer ---- */
static void test_carrier_offer(void)
{
	struct sdpn_carrier_cfg cfg;
	const struct sdp_media *m;
	char ml[128];

	sdpn_carrier_cfg_default(&cfg);
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp6, &MINE) == 0);
	m = &MINE.media[0];
	mline(&MINE, 0, ml, sizeof(ml));
	CHECK_STR(ml, "audio 50010 RTP/AVP 104 100 102 96 107 101");
	CHECK(m->bw.as == 49 && m->bw.rs == 600 && m->bw.rr == 2000 && m->ptime == 20 && m->maxptime == 240);
	CHECK(sdp_media_dir(&MINE, m) == SDP_DIR_SENDRECV);
	CHECK_STR(sdp_fmt_fmtp(&MINE, &m->fmt[0]), "mode-change-capability=2;max-red=0");
	CHECK_STR(sdp_fmt_fmtp(&MINE, &m->fmt[1]), "octet-align=1;mode-change-capability=2;max-red=0");
	CHECK_STR(sdp_fmt_fmtp(&MINE, &m->fmt[2]), "mode-change-capability=2;max-red=0");
	CHECK_STR(sdp_fmt_fmtp(&MINE, &m->fmt[3]), "octet-align=1;mode-change-capability=2;max-red=0");
	CHECK(!strcmp(sdp_fmt_enc(&MINE, &m->fmt[4]), "telephone-event") && m->fmt[4].clock == 16000);
	CHECK(!strcmp(sdp_fmt_enc(&MINE, &m->fmt[5]), "telephone-event") && m->fmt[5].clock == 8000);
	CHECK(!strstr(dump(&MINE), "EVRC"));
	CHECK(strstr(text, "o=imsd 4242 1 IN IP6 2001:4430:141:990a:25b5:899e:232:cb69\r\n"));
	CHECK(strstr(text, "c=IN IP6 2001:4430:141:990a:25b5:899e:232:cb69\r\n"));
	CHECK(strstr(text, "a=rtpmap:104 AMR-WB/16000/1\r\n") && strstr(text, "a=rtpmap:96 AMR/8000/1\r\n"));
	CHECK(strstr(text, "a=rtpmap:107 telephone-event/16000/1\r\n") && strstr(text, "a=fmtp:101 0-15\r\n"));
	CHECK(strstr(text, "b=AS:49\r\nb=RS:600\r\nb=RR:2000\r\n"));
	CHECK(parse_into(&TMP, text) == 0 && TMP.media[0].nfmt == 6);

	/* IPv4 local address */
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp4, &MINE) == 0);
	CHECK(strstr(dump(&MINE), "c=IN IP4 192.0.2.10\r\n") && strstr(text, "o=imsd 4242 1 IN IP4 192.0.2.10\r\n"));

	/* configurable payload types and codec subsets */
	cfg.pt_amrwb_be = 97;
	cfg.pt_dtmf8 = 110;
	cfg.offer_amrnb = false;
	cfg.offer_oa = false;
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp6, &MINE) == 0);
	mline(&MINE, 0, ml, sizeof(ml));
	CHECK_STR(ml, "audio 50010 RTP/AVP 97 107 110");
	cfg.offer_amrwb = false;
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp6, &MINE) == SDPN_E_BUILD);
	sdpn_carrier_cfg_default(&cfg);
	cfg.pt_amrnb_oa = 104;	/* duplicate PT */
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp6, &MINE) == SDPN_E_BUILD);
	sdpn_carrier_cfg_default(&cfg);
	cfg.pt_dtmf8 = 200;
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp6, &MINE) == SDPN_E_BUILD);
	sdpn_carrier_cfg_default(&cfg);
	cfg.bw_as = -1;
	cfg.bw_rs = -1;
	cfg.bw_rr = -1;
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp6, &MINE) == 0 && !strstr(dump(&MINE), "b="));
	{
		struct addr noport;

		addr_set(&noport, "192.0.2.1", 0);
		CHECK(sdpn_carrier_offer(&cfg, &org, &noport, &MINE) == SDPN_E_ARG);
		CHECK(sdpn_carrier_offer(NULL, &org, &rtp6, &MINE) == SDPN_E_ARG);
	}
}

/* ---- carrier: what the network answered to our offers ---- */
static void check_answer(const char *offer_txt, const char *answer_txt, enum sdpn_codec codec, int pt, bool oa,
			 uint32_t mode_set, int dtmf_pt, uint32_t dtmf_clock, const char *host, uint16_t port, int line)
{
	int r;

	CHECK(parse_into(&OFF, offer_txt) == 0);
	CHECK(parse_into(&ANS, answer_txt) == 0);
	r = sdpn_from_answer(&OFF, &ANS, &N);
	n_checks++;
	if (r != 0 || N.codec != codec || N.pt_send != pt || N.pt_recv != pt || N.octet_align != oa ||
	    N.mode_set != mode_set || N.dtmf_pt != dtmf_pt || N.dtmf_pt_recv != dtmf_pt || N.dtmf_clock != dtmf_clock ||
	    !remote_is(&N, host, port) || N.dir != SDP_DIR_SENDRECV || !N.valid) {
		n_fail++;
		printf("FAIL line %d: r=%d codec=%d pt=%d/%d oa=%d ms=%x dtmf=%d/%d@%u\n", line, r, N.codec, N.pt_send,
		       N.pt_recv, N.octet_align, N.mode_set, N.dtmf_pt, N.dtmf_pt_recv, N.dtmf_clock);
	}
}

static void test_carrier_answers(void)
{
	struct sdpn_carrier_cfg cfg;

	sdpn_carrier_cfg_default(&cfg);
	/* 114: AMR-NB PT 102, octet-align=0; mode-set=7, telephone-event/8000 as PT 101 */
	check_answer(VEC_POC_OFFER, VEC_A114_183, SDPN_C_AMRNB, 102, false, 1u << 7, 101, 8000, "2001:4430:4:313::7", 48814,
		     __LINE__);
	CHECK(N.ptime == 20 && N.bw_as == 38 && N.clock == 8000 && N.audio_rate == 8000 && N.maxptime == 0);
	CHECK(N.media_index == 0 && N.remote_rtcp.sa.sin6_port != 0);
	check_answer(VEC_POC_OFFER, VEC_A114_200, SDPN_C_AMRNB, 102, false, 1u << 7, 101, 8000, "2001:4430:4:313::7", 48814,
		     __LINE__);
	/* the same answer against the new offer built by sdpn_carrier_offer() */
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp6, &MINE) == 0);
	check_answer(dump(&MINE), VEC_A114_183, SDPN_C_AMRNB, 102, false, 1u << 7, 101, 8000, "2001:4430:4:313::7", 48814,
		     __LINE__);
	/* MRF early media: AMR-WB BE, mode-set=8, te/8000 with events 0-11 */
	check_answer(VEC_MRF_OFFER, VEC_MRF_ANSWER, SDPN_C_AMRWB, 104, false, 1u << 8, 101, 8000, "2001:4430:5:323::5", 38470,
		     __LINE__);
	CHECK(N.maxptime == 60 && N.ptime == 20 && N.clock == 16000 && N.audio_rate == 16000);
	check_answer(dump(&MINE), VEC_MRF_ANSWER, SDPN_C_AMRWB, 104, false, 1u << 8, 101, 8000, "2001:4430:5:323::5", 38470,
		     __LINE__);
	/* voicemail: PT 104 was offered bandwidth-efficient but the answer says octet-align=1: the answer wins */
	check_answer(VEC_VM_OFFER, VEC_VM_ANSWER, SDPN_C_AMRWB, 104, true, 0, 101, 8000, "2001:4430:5:325::8", 42746,
		     __LINE__);
	check_answer(dump(&MINE), VEC_VM_ANSWER, SDPN_C_AMRWB, 104, true, 0, 101, 8000, "2001:4430:5:325::8", 42746, __LINE__);
	CHECK(N.bw_as == 49);
}

/* ---- carrier: answering the network's offer (MT) ---- */
static void test_mt_answer(void)
{
	struct sdpn_carrier_cfg cfg;
	const struct sdp_media *m, *c;
	char ml[128];

	sdpn_carrier_cfg_default(&cfg);
	CHECK(parse_into(&OFF, VEC_MT_OFFER) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0);
	/* the network accepted: pt 100 AMR-WB octet-align=1 + telephone-event 107 (16 kHz), remote [..315::8]:44218 */
	CHECK(N.valid && N.codec == SDPN_C_AMRWB && N.pt_send == 100 && N.pt_recv == 100 && N.octet_align);
	CHECK(N.mode_set == 0 && N.dtmf_pt == 107 && N.dtmf_clock == 16000 && N.dir == SDP_DIR_SENDRECV);
	CHECK(remote_is(&N, "2001:4430:4:315::8", 44218));
	CHECK(N.maxptime == 120 && N.ptime == 20 && N.bw_as == 49);

	mline(&ANS, 0, ml, sizeof(ml));
	CHECK_STR(ml, "audio 50010 RTP/AVP 100 107");
	CHECK(parse_into(&MINE, VEC_MT_ANSWER_OURS) == 0);
	m = &ANS.media[0];
	c = &MINE.media[0];
	/* same formats, rtpmaps and fmtps as the answer that worked */
	CHECK(m->nfmt == c->nfmt && m->fmt[0].pt == c->fmt[0].pt && m->fmt[1].pt == c->fmt[1].pt);
	CHECK_STR(sdp_fmt_fmtp(&ANS, &m->fmt[0]), sdp_fmt_fmtp(&MINE, &c->fmt[0]));
	CHECK_STR(sdp_fmt_fmtp(&ANS, &m->fmt[1]), sdp_fmt_fmtp(&MINE, &c->fmt[1]));
	CHECK_STR(sdp_fmt_enc(&ANS, &m->fmt[0]), sdp_fmt_enc(&MINE, &c->fmt[0]));
	CHECK_STR(sdp_fmt_enc(&ANS, &m->fmt[1]), sdp_fmt_enc(&MINE, &c->fmt[1]));
	CHECK(m->fmt[0].clock == c->fmt[0].clock && m->fmt[1].clock == c->fmt[1].clock);
	CHECK(m->fmt[0].channels == c->fmt[0].channels && m->fmt[1].channels == c->fmt[1].channels);
	CHECK(m->bw.as == c->bw.as && m->bw.rs == c->bw.rs && m->bw.rr == c->bw.rr && m->ptime == c->ptime);
	CHECK(sdp_media_dir(&ANS, m) == sdp_media_dir(&MINE, c));
	CHECK(!strstr(dump(&ANS), "EVS") && !strstr(text, "110") && !strstr(text, " 96"));
	CHECK_STR(sdp_get(&ANS, ANS.name), "QC VOIP");
	CHECK(strstr(text, "o=imsd 4242 1 IN IP6 2001:4430:141:990a:25b5:899e:232:cb69\r\n"));
	/* the answer round-trips as an answer-to-our-offer view too */
	{
		struct sdpn_media back;

		CHECK(sdpn_from_answer(&OFF, &ANS, &back) == 0 && back.codec == SDPN_C_AMRWB && back.pt_send == 100 &&
		      back.octet_align && back.dtmf_pt == 107);
	}
}

/* build a network style offer */
static const char *net_offer(const char *media_and_attrs)
{
	static char t[2048];

	snprintf(t, sizeof(t),
		 "v=0\r\no=vIBCF 1 1 IN IP6 2001:4430:4:315::8\r\ns=-\r\nc=IN IP6 2001:4430:4:315::8\r\nt=0 0\r\n%s",
		 media_and_attrs);
	return t;
}

static void test_mt_variants(void)
{
	struct sdpn_carrier_cfg cfg;
	int r;

	sdpn_carrier_cfg_default(&cfg);

	/* bandwidth-efficient AMR-WB (no octet-align) mirrored exactly: no octet-align in the answer */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 97 98 99\r\na=rtpmap:97 AMR-WB/16000/1\r\na=rtpmap:98 AMR/8000/1\r\n"
					 "a=fmtp:98 octet-align=1\r\na=rtpmap:99 telephone-event/16000\r\na=fmtp:99 0-15\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0);
	CHECK(N.codec == SDPN_C_AMRWB && N.pt_send == 97 && !N.octet_align && N.dtmf_pt == 99 && N.dtmf_clock == 16000);
	CHECK_STR(sdp_fmt_fmtp(&ANS, &ANS.media[0].fmt[0]), "mode-change-capability=2;max-red=0");
	/* explicit octet-align=0 mirrored */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 97\r\na=rtpmap:97 AMR-WB/16000\r\na=fmtp:97 octet-align=0\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && !N.octet_align);
	CHECK_STR(sdp_fmt_fmtp(&ANS, &ANS.media[0].fmt[0]), "octet-align=0;mode-change-capability=2;max-red=0");
	CHECK(N.dtmf_pt == -1 && N.dtmf_clock == 0 && ANS.media[0].nfmt == 1);

	/* mode-set restriction echoed and exposed as a mask */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 97\r\na=rtpmap:97 AMR-WB/16000\r\na=fmtp:97 octet-align=1; mode-set=0,2,8\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && N.mode_set == (1u | 4u | 256u));
	CHECK_STR(sdp_fmt_fmtp(&ANS, &ANS.media[0].fmt[0]), "octet-align=1;mode-change-capability=2;max-red=0;mode-set=0,2,8");

	/* AMR-NB only, te/8000 */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 96 101\r\na=rtpmap:96 AMR/8000/1\r\na=fmtp:96 octet-align=1\r\n"
					 "a=rtpmap:101 telephone-event/8000\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0);
	CHECK(N.codec == SDPN_C_AMRNB && N.pt_send == 96 && N.octet_align && N.dtmf_pt == 101 && N.dtmf_clock == 8000);
	CHECK(N.clock == 8000 && N.audio_rate == 8000);
	/* AMR-WB with only te/8000 offered: falls back to it */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 100 101\r\na=rtpmap:100 AMR-WB/16000\r\na=fmtp:100 octet-align=1\r\n"
					 "a=rtpmap:101 telephone-event/8000\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && N.dtmf_pt == 101 && N.dtmf_clock == 8000);
	/* our preference beats the offerer's order: NB listed first, WB wins */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 96 100 107 101\r\na=rtpmap:96 AMR/8000\r\na=rtpmap:100 AMR-WB/16000\r\n"
					 "a=rtpmap:107 telephone-event/16000\r\na=rtpmap:101 telephone-event/8000\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && N.codec == SDPN_C_AMRWB && N.pt_send == 100 && N.dtmf_pt == 107);
	/* ... unless configured otherwise; NB then takes the 8 kHz te */
	cfg.pref[0] = SDPN_C_AMRNB;
	cfg.pref[1] = SDPN_C_AMRWB;
	cfg.npref = 2;
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && N.codec == SDPN_C_AMRNB && N.dtmf_pt == 101);
	sdpn_carrier_cfg_default(&cfg);
	/* two AMR-WB variants: the first offered one is taken (offer order among equals) */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 104 100\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:100 AMR-WB/16000\r\n"
					 "a=fmtp:100 octet-align=1\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && N.pt_send == 104 && !N.octet_align);
	/* unusable parameters are skipped: crc=1 / interleaving / robust-sorting / bad mode-set */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 97 98 99 100\r\na=rtpmap:97 AMR-WB/16000\r\na=fmtp:97 crc=1\r\n"
					 "a=rtpmap:98 AMR-WB/16000\r\na=fmtp:98 interleaving=3\r\na=rtpmap:99 AMR-WB/16000\r\n"
					 "a=fmtp:99 mode-set=9\r\na=rtpmap:100 AMR/8000\r\na=fmtp:100 robust-sorting=0;crc=0\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && N.codec == SDPN_C_AMRNB && N.pt_send == 100);
	/* EVS only (or nothing we know): 488 material */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 110\r\na=rtpmap:110 EVS/16000\r\na=fmtp:110 br=9.6-24.4;bw=nb-swb\r\n")) == 0);
	r = sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N);
	CHECK(r == SDPN_E_NOCODEC && sdpn_sip_status(r) == 488);
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 0 8\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == SDPN_E_NOCODEC);
	/* AMR-WB announced with the wrong clock / channels is not AMR-WB */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 97\r\na=rtpmap:97 AMR-WB/8000\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == SDPN_E_NOCODEC);
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 97\r\na=rtpmap:97 AMR-WB/16000/2\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == SDPN_E_NOCODEC);

	/* no audio / rejected audio / no address */
	CHECK(parse_into(&OFF, net_offer("m=video 4000 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == SDPN_E_NOMEDIA);
	CHECK(parse_into(&OFF, net_offer("m=audio 0 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == SDPN_E_NOMEDIA);
	CHECK(parse_into(&OFF, "v=0\r\nm=audio 4000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\n") == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == SDPN_E_NOADDR);
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/SAVP 100\r\na=rtpmap:100 AMR-WB/16000\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == SDPN_E_NOMEDIA);

	/* audio + video offer: video is answered with port 0 and the same formats, audio keeps its index */
	CHECK(parse_into(&OFF, net_offer("m=video 5000 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\nm=audio 4000 RTP/AVP 100\r\n"
					 "a=rtpmap:100 AMR-WB/16000\r\nm=application 9 TCP/MSRP *\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && ANS.nmedia == 3 && N.media_index == 1);
	CHECK(ANS.media[0].port == 0 && ANS.media[0].nfmt == 1 && ANS.media[0].fmt[0].pt == 96);
	CHECK(ANS.media[1].port == 50010 && ANS.media[2].port == 0);
	CHECK(strstr(dump(&ANS), "m=video 0 RTP/AVP 96\r\n") && strstr(text, "m=application 0 TCP/MSRP *\r\n"));
	CHECK(parse_into(&TMP, text) == 0 && TMP.nmedia == 3);

	/* IPv4 offer and answer */
	CHECK(parse_into(&OFF, "v=0\r\no=- 1 1 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\nt=0 0\r\n"
				"m=audio 30000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\n") == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == 0 && remote_is(&N, "203.0.113.9", 30000));
	CHECK(strstr(dump(&ANS), "c=IN IP4 192.0.2.10\r\n") && strstr(text, "m=audio 50010 RTP/AVP 100\r\n"));
	CHECK(N.remote_rtcp.sa.sin6_port == htons(30001));
	/* a=rtcp given */
	CHECK(parse_into(&OFF, "v=0\r\nc=IN IP4 203.0.113.9\r\nm=audio 30000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\n"
				"a=rtcp:30011 IN IP4 203.0.113.10\r\n") == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == 0 && N.remote_rtcp.sa.sin6_port == htons(30011));
	/* media level c= wins */
	CHECK(parse_into(&OFF, "v=0\r\nc=IN IP4 203.0.113.9\r\nm=audio 30000 RTP/AVP 100\r\nc=IN IP4 198.51.100.2\r\n"
				"a=rtpmap:100 AMR-WB/16000\r\n") == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == 0 && remote_is(&N, "198.51.100.2", 30000));
}

/* ---- hold / resume ---- */
static void test_hold(void)
{
	struct sdpn_carrier_cfg cfg;
	bool legacy;

	sdpn_carrier_cfg_default(&cfg);
	CHECK(sdpn_answer_dir(SDP_DIR_SENDRECV, SDP_DIR_SENDRECV) == SDP_DIR_SENDRECV);
	CHECK(sdpn_answer_dir(SDP_DIR_NONE, SDP_DIR_SENDRECV) == SDP_DIR_SENDRECV);
	CHECK(sdpn_answer_dir(SDP_DIR_SENDONLY, SDP_DIR_SENDRECV) == SDP_DIR_RECVONLY);
	CHECK(sdpn_answer_dir(SDP_DIR_RECVONLY, SDP_DIR_SENDRECV) == SDP_DIR_SENDONLY);
	CHECK(sdpn_answer_dir(SDP_DIR_INACTIVE, SDP_DIR_SENDRECV) == SDP_DIR_INACTIVE);
	CHECK(sdpn_answer_dir(SDP_DIR_SENDRECV, SDP_DIR_SENDONLY) == SDP_DIR_SENDONLY);
	CHECK(sdpn_answer_dir(SDP_DIR_SENDRECV, SDP_DIR_RECVONLY) == SDP_DIR_RECVONLY);
	CHECK(sdpn_answer_dir(SDP_DIR_SENDONLY, SDP_DIR_RECVONLY) == SDP_DIR_RECVONLY);
	CHECK(sdpn_answer_dir(SDP_DIR_SENDONLY, SDP_DIR_SENDONLY) == SDP_DIR_INACTIVE);
	CHECK(sdpn_dir_is_hold(SDP_DIR_SENDONLY) && sdpn_dir_is_hold(SDP_DIR_INACTIVE));
	CHECK(!sdpn_dir_is_hold(SDP_DIR_SENDRECV) && !sdpn_dir_is_hold(SDP_DIR_RECVONLY) && !sdpn_dir_is_hold(SDP_DIR_NONE));
	CHECK(sdpn_forward_dir(SDP_DIR_SENDONLY) == SDP_DIR_SENDONLY && sdpn_forward_dir(SDP_DIR_NONE) == SDP_DIR_SENDRECV);
	CHECK(sdpn_forward_dir(SDP_DIR_INACTIVE) == SDP_DIR_INACTIVE && sdpn_forward_dir(SDP_DIR_RECVONLY) == SDP_DIR_RECVONLY);

	/* re-INVITE with sendonly */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\na=sendonly\r\n")) == 0);
	CHECK(sdpn_remote_dir(&OFF, &OFF.media[0], &legacy) == SDP_DIR_SENDONLY && !legacy);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0);
	CHECK(N.dir == SDP_DIR_RECVONLY && ANS.media[0].dir == SDP_DIR_RECVONLY && strstr(dump(&ANS), "a=recvonly\r\n"));
	/* inactive */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\na=inactive\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && N.dir == SDP_DIR_INACTIVE);
	/* session level direction */
	CHECK(parse_into(&OFF, net_offer("a=sendonly\r\nm=audio 4000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && N.dir == SDP_DIR_RECVONLY);
	/* legacy hold: c=0.0.0.0 with sendrecv, c=:: and recvonly */
	CHECK(parse_into(&OFF, "v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 4000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\n") == 0);
	CHECK(sdpn_remote_dir(&OFF, &OFF.media[0], &legacy) == SDP_DIR_SENDONLY && legacy);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == 0 && N.legacy_hold && N.dir == SDP_DIR_RECVONLY);
	CHECK(parse_into(&OFF, "v=0\r\nc=IN IP6 ::\r\nm=audio 4000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\na=recvonly\r\n") == 0);
	CHECK(sdpn_remote_dir(&OFF, &OFF.media[0], &legacy) == SDP_DIR_INACTIVE && legacy);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == 0 && N.dir == SDP_DIR_INACTIVE);
	/* resume: back to sendrecv */
	CHECK(parse_into(&OFF, net_offer("m=audio 4000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\na=sendrecv\r\n")) == 0);
	CHECK(sdpn_carrier_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && N.dir == SDP_DIR_SENDRECV && !N.legacy_hold);

	/* applying hold to something we send */
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp6, &MINE) == 0);
	sdpn_apply_dir(&MINE, &MINE.media[0], SDP_DIR_SENDONLY, false);
	CHECK(strstr(dump(&MINE), "a=sendonly\r\n") && !strstr(text, "a=sendrecv"));
	sdpn_apply_dir(&MINE, &MINE.media[0], SDP_DIR_INACTIVE, true);
	CHECK(strstr(dump(&MINE), "a=inactive\r\n"));
	CHECK(parse_into(&TMP, text) == 0 && sdpn_remote_dir(&TMP, &TMP.media[0], &legacy) == SDP_DIR_INACTIVE && legacy);

	/* answer to our hold offer: peer answers recvonly -> we may only send */
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp6, &MINE) == 0);
	sdpn_apply_dir(&MINE, &MINE.media[0], SDP_DIR_SENDONLY, false);
	CHECK(parse_into(&OFF, dump(&MINE)) == 0);
	CHECK(parse_into(&ANS, "v=0\r\nc=IN IP6 2001:db8::9\r\nm=audio 7000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\n"
			       "a=fmtp:100 octet-align=1\r\na=recvonly\r\n") == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == 0 && N.dir == SDP_DIR_SENDONLY);
	/* peer ignores our sendonly and answers sendrecv: we still only send */
	CHECK(parse_into(&ANS, "v=0\r\nc=IN IP6 2001:db8::9\r\nm=audio 7000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\n") == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == 0 && N.dir == SDP_DIR_SENDONLY);
	/* answer inactive */
	CHECK(parse_into(&ANS, "v=0\r\nc=IN IP6 2001:db8::9\r\nm=audio 7000 RTP/AVP 100\r\na=rtpmap:100 AMR-WB/16000\r\na=inactive\r\n") == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == 0 && N.dir == SDP_DIR_INACTIVE);
}

/* ---- client (LAN) leg ---- */
static const char *lan_sdp(const char *media_and_attrs)
{
	static char t[2048];

	snprintf(t, sizeof(t), "v=0\r\no=- 11 11 IN IP4 192.168.1.20\r\ns=-\r\nc=IN IP4 192.168.1.20\r\nt=0 0\r\n%s", media_and_attrs);
	return t;
}

static void test_lan_offer(void)
{
	struct sdpn_lan_cfg cfg;
	char ml[128];
	const struct sdp_media *m;

	sdpn_lan_cfg_default(&cfg);
	CHECK(sdpn_lan_offer(&cfg, &org, &rtp4, &MINE) == 0);
	m = &MINE.media[0];
	mline(&MINE, 0, ml, sizeof(ml));
	CHECK_STR(ml, "audio 50010 RTP/AVP 111 9 8 101 102");
	CHECK(strstr(dump(&MINE), "a=rtpmap:111 opus/48000/2\r\n"));
	CHECK(strstr(text, "a=fmtp:111 maxplaybackrate=16000;sprop-maxcapturerate=16000;stereo=0;useinbandfec=0\r\n"));
	CHECK(strstr(text, "a=rtpmap:9 G722/8000/1\r\n") && strstr(text, "a=rtpmap:8 PCMA/8000/1\r\n"));
	CHECK(strstr(text, "a=rtpmap:101 telephone-event/8000/1\r\n") && strstr(text, "a=rtpmap:102 telephone-event/48000/1\r\n"));
	CHECK(strstr(text, "a=fmtp:101 0-15\r\n") && strstr(text, "a=ptime:20\r\n") && strstr(text, "a=sendrecv\r\n"));
	CHECK(strstr(text, "c=IN IP4 192.0.2.10\r\n") && m->ptime == 20);
	CHECK(parse_into(&TMP, text) == 0 && TMP.media[0].nfmt == 5);

	/* narrowband carrier: PCMA first and 8 kHz Opus */
	cfg.carrier_wideband = false;
	CHECK(sdpn_lan_offer(&cfg, &org, &rtp4, &MINE) == 0);
	mline(&MINE, 0, ml, sizeof(ml));
	CHECK_STR(ml, "audio 50010 RTP/AVP 8 111 9 101 102");
	CHECK(strstr(dump(&MINE), "maxplaybackrate=8000;sprop-maxcapturerate=8000;"));
	/* configured order without Opus: no 48 kHz telephone-event */
	cfg.pref[0] = SDPN_C_G722;
	cfg.pref[1] = SDPN_C_PCMA;
	cfg.npref = 2;
	CHECK(sdpn_lan_offer(&cfg, &org, &rtp6, &MINE) == 0);
	mline(&MINE, 0, ml, sizeof(ml));
	CHECK_STR(ml, "audio 50010 RTP/AVP 9 8 101");
	CHECK(strstr(dump(&MINE), "c=IN IP6 ") && !strstr(text, "opus"));
	/* Opus with an explicit rate and without te/48000 */
	sdpn_lan_cfg_default(&cfg);
	cfg.opus_rate = 24000;
	cfg.dtmf48 = false;
	cfg.pt_opus = 96;
	CHECK(sdpn_lan_offer(&cfg, &org, &rtp4, &MINE) == 0);
	mline(&MINE, 0, ml, sizeof(ml));
	CHECK_STR(ml, "audio 50010 RTP/AVP 96 9 8 101");
	CHECK(strstr(dump(&MINE), "maxplaybackrate=24000;"));
	/* AMR cannot be offered to LAN phones; duplicates are refused */
	sdpn_lan_cfg_default(&cfg);
	cfg.pref[0] = SDPN_C_AMRWB;
	cfg.npref = 1;
	CHECK(sdpn_lan_offer(&cfg, &org, &rtp4, &MINE) == SDPN_E_BUILD);
	sdpn_lan_cfg_default(&cfg);
	cfg.pt_pcma = 9;
	CHECK(sdpn_lan_offer(&cfg, &org, &rtp4, &MINE) == SDPN_E_BUILD);
}

static void lan_case(const struct sdpn_lan_cfg *cfg, const char *offer, int expect_err, enum sdpn_codec codec, int pt,
		     int dtmf_pt, uint32_t dtmf_clock, int line)
{
	int r;

	CHECK(parse_into(&OFF, offer) == 0);
	r = sdpn_lan_answer(cfg, &OFF, &org, &rtp4, &ANS, &N);
	n_checks++;
	if (r != expect_err || (r == 0 && (N.codec != codec || N.pt_send != pt || N.pt_recv != pt || N.dtmf_pt != dtmf_pt ||
					   N.dtmf_clock != dtmf_clock))) {
		n_fail++;
		printf("FAIL line %d: r=%d (want %d) codec=%d pt=%d dtmf=%d@%u\n", line, r, expect_err, N.codec, N.pt_send,
		       N.dtmf_pt, N.dtmf_clock);
	}
}

static void test_lan_answers(void)
{
	struct sdpn_lan_cfg cfg;
	char ml[128];

	sdpn_lan_cfg_default(&cfg);

	/* only PCMA (static PT, no rtpmap), with and without telephone-event */
	lan_case(&cfg, lan_sdp("m=audio 4000 RTP/AVP 8\r\n"), 0, SDPN_C_PCMA, 8, -1, 0, __LINE__);
	CHECK(N.remote.sa.sin6_port == htons(4000) && remote_is(&N, "192.168.1.20", 4000) && N.dtmf_pt == -1);
	lan_case(&cfg, lan_sdp("m=audio 4000 RTP/AVP 8 101\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\n"), 0,
		 SDPN_C_PCMA, 8, 101, 8000, __LINE__);
	mline(&ANS, 0, ml, sizeof(ml));
	CHECK_STR(ml, "audio 50010 RTP/AVP 8 101");
	CHECK(strstr(dump(&ANS), "c=IN IP4 192.0.2.10\r\n") && strstr(text, "a=fmtp:101 0-15\r\n") && strstr(text, "a=sendrecv"));
	/* G722 + PCMA: our order picks G722 whichever the client lists first */
	lan_case(&cfg, lan_sdp("m=audio 4000 RTP/AVP 8 9 101\r\na=rtpmap:101 telephone-event/8000\r\n"), 0, SDPN_C_G722, 9, 101, 8000,
		 __LINE__);
	CHECK(N.clock == 8000 && N.audio_rate == 16000);
	lan_case(&cfg, lan_sdp("m=audio 4000 RTP/AVP 9 8\r\n"), 0, SDPN_C_G722, 9, -1, 0, __LINE__);
	/* ... honouring the client's order instead */
	cfg.honour_client_order = true;
	lan_case(&cfg, lan_sdp("m=audio 4000 RTP/AVP 8 9\r\n"), 0, SDPN_C_PCMA, 8, -1, 0, __LINE__);
	cfg.honour_client_order = false;

	/* Opus + G722 + PCMA in all orders: Opus first in our order, PT echoed, te matching the 48 kHz clock */
	{
		static const char *orders[] = { "111 9 8", "111 8 9", "9 111 8", "9 8 111", "8 111 9", "8 9 111" };
		size_t i;
		char m[512];

		for (i = 0; i < 6; i++) {
			snprintf(m, sizeof(m),
				 "m=audio 4000 RTP/AVP %s 110 126\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 minptime=10;useinbandfec=1;stereo=1;"
				 "maxplaybackrate=24000\r\na=rtpmap:110 telephone-event/48000\r\na=rtpmap:126 telephone-event/8000\r\n",
				 orders[i]);
			lan_case(&cfg, lan_sdp(m), 0, SDPN_C_OPUS, 111, 110, 48000, __LINE__);
			CHECK(N.opus_maxplaybackrate == 24000 && N.opus_stereo && N.opus_fec && N.clock == 48000);
		}
		cfg.honour_client_order = true;
		snprintf(m, sizeof(m), "m=audio 4000 RTP/AVP 9 111 8 126\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:126 telephone-event/8000\r\n");
		lan_case(&cfg, lan_sdp(m), 0, SDPN_C_G722, 9, 126, 8000, __LINE__);
		cfg.honour_client_order = false;
		/* client PT numbers are echoed, even when different from ours */
		snprintf(m, sizeof(m), "m=audio 4000 RTP/AVP 96 97\r\na=rtpmap:96 OPUS/48000/2\r\na=rtpmap:97 telephone-event/48000\r\n");
		lan_case(&cfg, lan_sdp(m), 0, SDPN_C_OPUS, 96, 97, 48000, __LINE__);
		CHECK(N.opus_maxplaybackrate == 48000 && !N.opus_stereo && !N.opus_fec);
		CHECK(strstr(dump(&ANS), "a=rtpmap:96 opus/48000/2\r\n") && strstr(text, "a=fmtp:96 maxplaybackrate=16000;sprop-maxcapturerate=16000;stereo=0;useinbandfec=0\r\n"));
		CHECK(strstr(text, "a=rtpmap:97 telephone-event/48000/1\r\n"));
		/* Opus with only te/8000 offered: falls back to the 8 kHz event clock */
		snprintf(m, sizeof(m), "m=audio 4000 RTP/AVP 111 101\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:101 telephone-event/8000\r\n");
		lan_case(&cfg, lan_sdp(m), 0, SDPN_C_OPUS, 111, 101, 8000, __LINE__);
	}
	/* narrowband carrier prefers PCMA over Opus */
	cfg.carrier_wideband = false;
	lan_case(&cfg, lan_sdp("m=audio 4000 RTP/AVP 111 9 8\r\na=rtpmap:111 opus/48000/2\r\n"), 0, SDPN_C_PCMA, 8, -1, 0, __LINE__);
	cfg.carrier_wideband = true;

	/* unknown codecs only: 488 */
	lan_case(&cfg, lan_sdp("m=audio 4000 RTP/AVP 0 18 3 97\r\na=rtpmap:97 iLBC/8000\r\na=fmtp:97 mode=20\r\n"), SDPN_E_NOCODEC, 0, 0, 0, 0,
		 __LINE__);
	CHECK(sdpn_sip_status(SDPN_E_NOCODEC) == 488 && sdpn_sip_status(SDPN_E_BUILD) == 500);
	/* AMR-WB from a LAN client is not something we serve either */
	lan_case(&cfg, lan_sdp("m=audio 4000 RTP/AVP 98\r\na=rtpmap:98 AMR-WB/16000\r\n"), SDPN_E_NOCODEC, 0, 0, 0, 0, __LINE__);
	/* a client mislabelling PT 8 as another codec: rtpmap wins, PCMA not found */
	lan_case(&cfg, lan_sdp("m=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMU/8000\r\n"), SDPN_E_NOCODEC, 0, 0, 0, 0, __LINE__);
	/* dynamic PT carrying PCMA / G722 via rtpmap */
	lan_case(&cfg, lan_sdp("m=audio 4000 RTP/AVP 100\r\na=rtpmap:100 PCMA/8000\r\n"), 0, SDPN_C_PCMA, 100, -1, 0, __LINE__);
	/* video + audio: video rejected; audio at index 1 */
	CHECK(parse_into(&OFF, lan_sdp("m=video 5000 RTP/AVP 96\r\na=rtpmap:96 VP8/90000\r\nm=audio 4000 RTP/AVP 8\r\n")) == 0);
	CHECK(sdpn_lan_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == 0 && N.media_index == 1 && ANS.media[0].port == 0);
	/* all media rejected / video only */
	CHECK(parse_into(&OFF, lan_sdp("m=video 5000 RTP/AVP 96\r\na=rtpmap:96 VP8/90000\r\n")) == 0);
	CHECK(sdpn_lan_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == SDPN_E_NOMEDIA);
	CHECK(parse_into(&OFF, lan_sdp("m=audio 0 RTP/AVP 8\r\n")) == 0);
	CHECK(sdpn_lan_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == SDPN_E_NOMEDIA);

	/* ptime echo: the client's value, else ours */
	CHECK(parse_into(&OFF, lan_sdp("m=audio 4000 RTP/AVP 8\r\na=ptime:30\r\n")) == 0);
	CHECK(sdpn_lan_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == 0 && N.ptime == 30 && ANS.media[0].ptime == 30);
	CHECK(parse_into(&OFF, lan_sdp("m=audio 4000 RTP/AVP 8\r\n")) == 0);
	CHECK(sdpn_lan_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == 0 && N.ptime == 20);
	/* client on IPv6 with an IPv4 answer address is the caller's concern: families follow the addresses given */
	CHECK(parse_into(&OFF, "v=0\r\no=- 1 1 IN IP6 fd00::20\r\ns=-\r\nc=IN IP6 fd00::20\r\nt=0 0\r\nm=audio 4000 RTP/AVP 8\r\n") == 0);
	CHECK(sdpn_lan_answer(&cfg, &OFF, &org, &rtp6, &ANS, &N) == 0 && remote_is(&N, "fd00::20", 4000));
	CHECK(strstr(dump(&ANS), "c=IN IP6 2001:4430:141:990a:25b5:899e:232:cb69\r\n"));
	/* hold from a phone */
	CHECK(parse_into(&OFF, lan_sdp("m=audio 4000 RTP/AVP 8\r\na=sendonly\r\n")) == 0);
	CHECK(sdpn_lan_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == 0 && N.dir == SDP_DIR_RECVONLY);
	CHECK(parse_into(&OFF, "v=0\r\nc=IN IP4 0.0.0.0\r\nm=audio 4000 RTP/AVP 8\r\n") == 0);
	CHECK(sdpn_lan_answer(&cfg, &OFF, &org, &rtp4, &ANS, &N) == 0 && N.legacy_hold && N.dir == SDP_DIR_RECVONLY);
}

static void test_lan_client_answer(void)
{
	struct sdpn_lan_cfg cfg;

	sdpn_lan_cfg_default(&cfg);
	CHECK(sdpn_lan_offer(&cfg, &org, &rtp4, &MINE) == 0);
	CHECK(parse_into(&OFF, dump(&MINE)) == 0);

	/* the phone picks G722 + te/8000 */
	CHECK(parse_into(&ANS, lan_sdp("m=audio 4002 RTP/AVP 9 101\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\n")) == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == 0);
	CHECK(N.codec == SDPN_C_G722 && N.pt_send == 9 && N.pt_recv == 9 && N.dtmf_pt == 101 && N.dtmf_clock == 8000);
	CHECK(remote_is(&N, "192.168.1.20", 4002) && N.dir == SDP_DIR_SENDRECV && N.audio_rate == 16000);
	/* Opus with 48 kHz events and its own parameters from the answer */
	CHECK(parse_into(&ANS, lan_sdp("m=audio 4002 RTP/AVP 111 102\r\na=rtpmap:111 opus/48000/2\r\na=fmtp:111 maxplaybackrate=12000;stereo=1;useinbandfec=1\r\n"
				       "a=rtpmap:102 telephone-event/48000\r\n")) == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == 0 && N.codec == SDPN_C_OPUS && N.pt_send == 111 && N.dtmf_pt == 102 &&
	      N.dtmf_clock == 48000 && N.opus_maxplaybackrate == 12000 && N.opus_stereo && N.opus_fec);
	/* answer lists a format we never offered first: the first one we offered wins */
	CHECK(parse_into(&ANS, lan_sdp("m=audio 4002 RTP/AVP 0 8 101\r\na=rtpmap:101 telephone-event/8000\r\n")) == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == 0 && N.codec == SDPN_C_PCMA && N.pt_send == 8);
	/* answer without rtpmap for a static PT */
	CHECK(parse_into(&ANS, lan_sdp("m=audio 4002 RTP/AVP 8\r\n")) == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == 0 && N.codec == SDPN_C_PCMA && N.dtmf_pt == -1 && N.dtmf_pt_recv == -1);
	/* the phone renumbers Opus: answer PT 109 for what we offered as 111 -> send 109, receive 111 */
	CHECK(parse_into(&ANS, lan_sdp("m=audio 4002 RTP/AVP 109\r\na=rtpmap:109 opus/48000/2\r\n")) == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == 0 && N.codec == SDPN_C_OPUS && N.pt_send == 109 && N.pt_recv == 111);
	/* answer's rtpmap contradicts what we offered under that PT: not accepted */
	CHECK(parse_into(&ANS, lan_sdp("m=audio 4002 RTP/AVP 111\r\na=rtpmap:111 PCMU/8000\r\n")) == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == SDPN_E_BADANSWER);
	/* nothing in common */
	CHECK(parse_into(&ANS, lan_sdp("m=audio 4002 RTP/AVP 0 18\r\n")) == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == SDPN_E_BADANSWER && sdpn_sip_status(SDPN_E_BADANSWER) == 488);
	/* rejected stream, missing stream, no address */
	CHECK(parse_into(&ANS, lan_sdp("m=audio 0 RTP/AVP 8\r\n")) == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == SDPN_E_REJECTED);
	CHECK(parse_into(&ANS, "v=0\r\nc=IN IP4 1.2.3.4\r\n") == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == SDPN_E_BADANSWER);
	CHECK(parse_into(&ANS, "v=0\r\nm=audio 4002 RTP/AVP 8\r\n") == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == SDPN_E_NOADDR);
	CHECK(parse_into(&ANS, lan_sdp("m=video 4002 RTP/AVP 8\r\n")) == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == SDPN_E_BADANSWER);
	CHECK(sdpn_from_answer(NULL, &ANS, &N) == SDPN_E_ARG);
	/* te in the answer with the clock of one we offered but another PT */
	CHECK(parse_into(&ANS, lan_sdp("m=audio 4002 RTP/AVP 8 96\r\na=rtpmap:96 telephone-event/8000\r\n")) == 0);
	CHECK(sdpn_from_answer(&OFF, &ANS, &N) == 0 && N.dtmf_pt == 96 && N.dtmf_pt_recv == 101);
}

static void test_mode_set(void)
{
	uint32_t m = 0;
	char t[40];

	CHECK(sdpn_parse_mode_set("7", 7, &m) == 0 && m == 0x80);
	CHECK(sdpn_parse_mode_set("0,2, 4 ,8", 8, &m) == 0 && m == (1u | 4u | 16u | 256u));
	CHECK(sdpn_parse_mode_set("8", 7, &m) == -1 && sdpn_parse_mode_set("", 7, &m) == -1);
	CHECK(sdpn_parse_mode_set("1,", 7, &m) == -1 && sdpn_parse_mode_set(",1", 7, &m) == -1 && sdpn_parse_mode_set("a", 7, &m) == -1);
	CHECK(sdpn_parse_mode_set("100", 255, &m) == -1 && sdpn_parse_mode_set("1;2", 7, &m) == -1 && sdpn_parse_mode_set("32", 255, &m) == -1);
	CHECK(sdpn_format_mode_set(0x115, t, sizeof(t)) == 0 && !strcmp(t, "0,2,4,8"));
	CHECK(sdpn_format_mode_set(0, t, sizeof(t)) == 0 && !strcmp(t, ""));
	CHECK(sdpn_format_mode_set(0x115, t, 5) == -1 && sdpn_format_mode_set(1, t, 0) == -1);
	CHECK_STR(sdpn_codec_name(SDPN_C_AMRWB), "AMR-WB");
	CHECK(sdpn_codec_rtp_clock(SDPN_C_OPUS) == 48000 && sdpn_codec_audio_rate(SDPN_C_G722) == 16000 && sdpn_codec_rtp_clock(SDPN_C_NONE) == 0);
}

/* re-offer session version bookkeeping through the negotiation layer */
static void test_reoffer(void)
{
	struct sdpn_carrier_cfg cfg;
	static struct sdp prev;

	sdpn_carrier_cfg_default(&cfg);
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp6, &prev) == 0);
	CHECK(sdpn_carrier_offer(&cfg, &org, &rtp6, &MINE) == 0 && sdp_origin_succeed(&MINE, &prev) == 0 && MINE.o.version == 1);
	sdpn_apply_dir(&MINE, &MINE.media[0], SDP_DIR_SENDONLY, false);
	CHECK(sdp_origin_succeed(&MINE, &prev) == 0 && MINE.o.version == 2 && MINE.o.sess_id == 4242);
}

/* garbage SDP never crashes the negotiation functions */
static void test_neg_fuzz(void)
{
	static const char *v[] = { VEC_POC_OFFER, VEC_MT_OFFER, VEC_VM_ANSWER, VEC_MRF_ANSWER };
	struct sdpn_carrier_cfg cc;
	struct sdpn_lan_cfg lc;
	uint32_t s = 0x9e3779b9;
	size_t vi;
	int it;

	sdpn_carrier_cfg_default(&cc);
	sdpn_lan_cfg_default(&lc);
	for (vi = 0; vi < sizeof(v) / sizeof(v[0]); vi++) {
		size_t n = strlen(v[vi]);

		for (it = 0; it < 4000; it++) {
			char *t = malloc(n);
			int m = 1 + it % 4;

			memcpy(t, v[vi], n);
			while (m--) {
				s ^= s << 13;
				s ^= s >> 17;
				s ^= s << 5;
				t[s % n] = (char)(s >> 8);
			}
			if (sdp_parse(&TMP, t, n) == 0) {
				sdpn_carrier_answer(&cc, &TMP, &org, &rtp6, &ANS, &N);
				sdpn_lan_answer(&lc, &TMP, &org, &rtp4, &ANS, &N);
				sdpn_from_answer(&TMP, &OFF, &N);
				sdpn_from_answer(&MINE, &TMP, &N);
			}
			free(t);
		}
	}
	CHECK(1);
}

int main(void)
{
	addr_set(&rtp6, "2001:4430:141:990a:25b5:899e:232:cb69", 50010);
	addr_set(&rtp4, "192.0.2.10", 50010);
	test_carrier_offer();
	test_carrier_answers();
	test_mt_answer();
	test_mt_variants();
	test_hold();
	test_lan_offer();
	test_lan_answers();
	test_lan_client_answer();
	test_mode_set();
	test_reoffer();
	test_neg_fuzz();
	printf("test_sdp_neg: %d checks, %d failed\n", n_checks, n_fail);
	return n_fail ? 1 : 0;
}
