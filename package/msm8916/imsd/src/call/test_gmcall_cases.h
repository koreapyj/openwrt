/* SPDX-License-Identifier: GPL-2.0-or-later */
/* scenarios (included by test_gmcall.c) */

#define ICSI "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
#define CONTACT_EXPECT "<sip:01039428657@[" UE_IP "]:8901>;+g.3gpp.icsi-ref=\"" ICSI "\""
#define L1_FROM_TAG "kmnham7485C9417df6d25733432"

static char pstr[16];
static const char *itoa_(int v)
{
	snprintf(pstr, sizeof(pstr), "%d", v);
	return pstr;
}

static bool addr_is(const struct addr *a, const char *ip, int port)
{
	struct addr x = A(ip, port);

	return addr_equal(a, &x);
}

/* every request we sent: none may carry To tag tag */
static int count_to_tag(const char *tag)
{
	int i, n = 0;

	for (i = 0; i < W.f->nsent; i++) {
		struct pm p;

		if (parse_sent(W.f, i, &p)) {
			if (!p.m.is_resp && strstr(H(&p, "To"), tag))
				n++;
			pm_free(&p);
		}
	}
	return n;
}

/* ------------------------------------------------------------------ */
/* MO: 114 (run1): 183 on one To tag, 200 on another                    */

static void case_mo_114(bool adapt_port)
{
	struct gmcall *c;
	struct pm p;
	struct sip_msg *m;
	static struct sdp sd;
	int inv, ack, bye, finalp = adapt_port ? 48816 : 48814;
	const struct gmcall_event *e;
	struct addr dst;

	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	CHECK(c != NULL);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_DIALING);
	CHECK_EQ(W.f->nsent, 1);
	inv = find_req("INVITE", 0);
	CHECK_EQ(inv, 0);
	parse_sent(W.f, 0, &p);
	m = &p.m;
	/* the headers the network accepted (PoC build_invite), minus the modem's artefacts */
	CHECK_STR(m->ruri, "tel:114;phone-context=lguplus.co.kr");
	CHECK_STR(H(&p, "To"), "<tel:114;phone-context=lguplus.co.kr>");
	CHECK(has_prefix(H(&p, "From"), "<sip:01039428657@lte-lguplus.co.kr>;tag="));
	CHECK_STR(H(&p, "CSeq"), "1 INVITE");
	CHECK_STR(sip_hdr(m, "Route", 0), "<sip:[" PCSCF_A "]:1357;lr>");
	CHECK_STR(sip_hdr(m, "Route", 1), "<sip:orig@scscf.lte-lguplus.co.kr:5060;lr>");
	CHECK_EQ(sip_hdr_count(m, "Route"), 2);
	CHECK_STR(H(&p, "Contact"), CONTACT_EXPECT);
	CHECK(!strstr(H(&p, "Contact"), "description"));
	CHECK(!strstr(H(&p, "Contact"), "lgt-vt"));
	CHECK_STR(H(&p, "Security-Verify"), W.sv);
	CHECK_STR(H(&p, "Require"), "sec-agree");
	CHECK_STR(H(&p, "Proxy-Require"), "sec-agree");
	CHECK_STR(H(&p, "P-Preferred-Identity"), "<sip:01039428657@lte-lguplus.co.kr>");
	CHECK_STR(H(&p, "P-Preferred-Service"), "urn:urn-7:3gpp-service.ims.icsi.mmtel");
	CHECK_STR(H(&p, "Accept-Contact"), "*;+g.3gpp.icsi-ref=\"" ICSI "\"");
	CHECK_STR(H(&p, "Supported"), "100rel,timer");
	CHECK(!strstr(H(&p, "Supported"), "replaces"));
	CHECK_STR(H(&p, "P-Early-Media"), "supported");
	CHECK_STR(H(&p, "Session-Expires"), "1800;refresher=uac");
	CHECK_STR(H(&p, "Accept"), "application/sdp");
	CHECK(strstr(H(&p, "Allow"), "UPDATE") && strstr(H(&p, "Allow"), "PRACK"));
	CHECK(has_prefix(H(&p, "P-Access-Network-Info"), "3GPP-E-UTRAN-FDD"));
	CHECK_STR(H(&p, "Content-Type"), "application/sdp");
	CHECK_EQ(sdp_parse(&sd, (const char *)m->body, m->body_len), 0);
	CHECK_EQ(sd.nmedia, 1);
	CHECK_EQ(sd.media[0].port, 50010);
	CHECK(addr_is(&W.f->sent[0].dst, PCSCF_A, 1357));
	printf("  INVITE with the full SDP offer: %zu bytes (UDP over the 1400 byte path MTU: %s)\n", W.f->sent[0].len,
	       W.f->sent[0].len > 1400 ? "FRAGMENTS" : "fits");
	pm_free(&p);

	respond_tpl(inv, V_100, (char *)NULL);
	CHECK_EQ(rec_count(&R, GMCALL_EV_PROGRESS), 0);
	respond_tpl(inv, V_183_114, "$PORT", "48814", (char *)NULL);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_EARLY);
	e = rec_nth(&R, GMCALL_EV_PROGRESS, 0);
	CHECK(e && e->status == 183 && e->has_sdp);
	e = rec_nth(&R, GMCALL_EV_MEDIA, 0);
	CHECK(e && e->early && e->media);
	if (e && e->media) {
		CHECK(addr_is(&e->media->remote, "2001:4430:4:313::7", 48814));
		CHECK_EQ(e->media->codec, SDPN_C_AMRNB);
		CHECK_EQ(e->media->pt_send, 102);
		CHECK(!e->media->octet_align);
		CHECK_EQ(e->media->mode_set, 1u << 7);
		CHECK_EQ(e->media->dtmf_pt, 101);
		CHECK_EQ(e->media->dir, SDP_DIR_SENDRECV);
	}
	CHECK_EQ(rec_count(&R, GMCALL_EV_RINGING), 0);	/* a 183 with SDP: the network sends audio itself */
	CHECK_EQ(W.f->nsent, 1);	/* nothing at all is sent to an early dialog without 100rel */
	respond_tpl(inv, V_183_114, "$PORT", "48814", (char *)NULL);	/* retransmitted 183 */
	CHECK_EQ(rec_count(&R, GMCALL_EV_PROGRESS), 1);
	CHECK_EQ(rec_count(&R, GMCALL_EV_MEDIA), 1);

	respond_tpl(inv, V_200_114, "$PORT", itoa_(finalp), (char *)NULL);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	e = rec_nth(&R, GMCALL_EV_MEDIA, 1);
	CHECK(e && !e->early);
	if (e && e->media)
		CHECK(addr_is(&e->media->remote, "2001:4430:4:313::7", finalp));
	CHECK_EQ(rec_count(&R, GMCALL_EV_MEDIA), 2);
	CHECK_EQ(rec_count(&R, GMCALL_EV_ANSWERED), 1);
	ack = find_req("ACK", 0);
	CHECK(ack > 0);
	parse_sent(W.f, ack, &p);
	CHECK_STR(dialog_tag(&p), TAG_FINAL);
	CHECK_STR(p.m.ruri, "sip:[" PCSCF_A "]:1357;transport=UDP");
	CHECK_STR(H(&p, "CSeq"), "1 ACK");
	CHECK_EQ(sip_hdr_count(&p.m, "Route"), 0);	/* the remote target is the P-CSCF itself */
	CHECK_STR(H(&p, "Security-Verify"), W.sv);
	CHECK_STR(H(&p, "Require"), "sec-agree");
	CHECK(has_prefix(H(&p, "From"), "<sip:01039428657@lte-lguplus.co.kr>;tag="));
	CHECK(addr_is(&W.f->sent[ack].dst, PCSCF_A, 1357));
	pm_free(&p);
	/* retransmitted 200 is ACKed again */
	respond_tpl(inv, V_200_114, "$PORT", itoa_(finalp), (char *)NULL);
	CHECK_EQ(count_req("ACK"), 2);
	CHECK_EQ(rec_count(&R, GMCALL_EV_MEDIA), 2);
	CHECK_EQ(rec_count(&R, GMCALL_EV_ANSWERED), 1);
	{
		struct gmcall_info info[2];

		CHECK_EQ(gmcall_list(W.m, info, 2), 1);
		CHECK_STR(info[0].state_name, "connected");
		CHECK_EQ(info[0].session_interval, 600);	/* the 2xx wins over our 1800 */
		CHECK(info[0].session_refresher_local);
		CHECK_STR(info[0].codec, "AMR");
		CHECK_STR(info[0].remote.number, "114");
	}

	R.in_api = true;
	CHECK_EQ(gmcall_hangup(c), 0);
	R.in_api = false;
	CHECK_EQ(R.reentrant, 0);	/* no callback from inside the API call */
	bye = find_req("BYE", 0);
	CHECK(bye > 0);
	parse_sent(W.f, bye, &p);
	CHECK_STR(dialog_tag(&p), TAG_FINAL);
	CHECK_STR(H(&p, "CSeq"), "2 BYE");	/* no PRACK was ever sent: CSeq 2 */
	CHECK_STR(p.m.ruri, "sip:[" PCSCF_A "]:1357;transport=UDP");
	CHECK_EQ(sip_hdr_count(&p.m, "Route"), 0);
	dst = W.f->sent[bye].dst;
	CHECK(addr_is(&dst, PCSCF_A, 1357));
	pm_free(&p);
	CHECK_EQ(count_to_tag(TAG_EARLY), 0);	/* nothing was ever sent to the early dialog */
	respond_simple(bye, 200, NULL, NULL, NULL);
	evfake_advance(10);
	CHECK_EQ(R.term, 1);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_TERMINATED && !e->by_remote);
	CHECK_EQ(gmcall_count(W.m), 0);
	world_fini();
}

/* ------------------------------------------------------------------ */
/* MO: 100rel / PRACK, then 603 (c1)                                    */

static void case_mo_100rel_603(void)
{
	struct gmcall *c;
	struct pm p;
	int inv, prack;
	const struct gmcall_event *e;

	world_init(PCSCF_A, 1357, 7531, NULL);
	c = dial("01039428657", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_tpl(inv, V_100, (char *)NULL);
	respond_tpl(inv, V_183_100REL, (char *)NULL);
	prack = find_req("PRACK", 0);
	CHECK(prack > 0);
	parse_sent(W.f, prack, &p);
	CHECK_STR(H(&p, "CSeq"), "2 PRACK");
	CHECK_STR(H(&p, "RAck"), "80904 1 INVITE");
	CHECK_STR(p.m.ruri, "sip:[" PCSCF_A "]:1357;transport=UDP");
	CHECK(strstr(H(&p, "To"), "az004c351a470f150fc0c49d8d40c21d"));
	CHECK_EQ(sip_hdr_count(&p.m, "Route"), 0);
	CHECK_STR(H(&p, "Security-Verify"), W.sv);
	pm_free(&p);
	e = rec_nth(&R, GMCALL_EV_MEDIA, 0);
	CHECK(e && e->early && e->media);
	if (e && e->media) {
		CHECK(addr_is(&e->media->remote, "2001:4430:5:323::5", 38470));
		CHECK_EQ(e->media->codec, SDPN_C_AMRWB);
		CHECK_EQ(e->media->pt_send, 104);
		CHECK(!e->media->octet_align);
		CHECK_EQ(e->media->mode_set, 1u << 8);
	}
	respond_tpl(prack, V_200_PRACK, (char *)NULL);
	respond_tpl(inv, V_183_100REL, (char *)NULL);	/* the same reliable 183 again: no second PRACK */
	CHECK_EQ(count_req("PRACK"), 1);
	CHECK_EQ(rec_count(&R, GMCALL_EV_PROGRESS), 1);
	CHECK_EQ(rec_count(&R, GMCALL_EV_MEDIA), 1);
	respond_tpl(inv, V_603, (char *)NULL);
	CHECK_EQ(R.term, 1);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_FAILED && e->status == 603);
	if (e)
		CHECK_STR(e->reason, "Decline");
	CHECK_EQ(count_req("ACK"), 1);	/* the transaction layer ACKs the 603 */
	CHECK_EQ(count_req("CANCEL"), 0);
	CHECK_EQ(count_req("BYE"), 0);
	(void)c;
	world_fini();
}

/* ------------------------------------------------------------------ */
/* MO to a mobile (n1): 180, 200 with Require: timer, session refresh   */

static struct gmcall *establish_mo_n1(const char *allow)
{
	struct gmcall *c;
	int inv;

	world_init(PCSCF_B, 5071, 5073, NULL);
	c = dial("01051226862", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_tpl(inv, V_100, (char *)NULL);
	respond_tpl(inv, V_180_N1, (char *)NULL);
	respond_tpl(inv, V_200_N1, "$ALLOW", allow, (char *)NULL);
	return c;
}

static void case_mo_n1(void)
{
	struct gmcall *c = establish_mo_n1(ALLOW_UPD);
	struct pm p;
	const struct gmcall_event *e;
	int u, ack;

	CHECK_EQ(rec_count(&R, GMCALL_EV_RINGING), 1);
	e = rec_nth(&R, GMCALL_EV_PROGRESS, 0);
	CHECK(e && e->status == 180 && !e->has_sdp);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	e = rec_nth(&R, GMCALL_EV_MEDIA, 0);
	CHECK(e && !e->early && e->media);
	if (e && e->media) {
		CHECK_EQ(e->media->codec, SDPN_C_AMRWB);
		CHECK(e->media->octet_align);
		CHECK_EQ(e->media->pt_send, 104);
		CHECK(addr_is(&e->media->remote, "2001:4430:5:325::8", 42746));
	}
	ack = find_req("ACK", 0);
	parse_sent(W.f, ack, &p);
	CHECK_STR(p.m.ruri, "sip:[" PCSCF_B "]:5071");
	CHECK_EQ(sip_hdr_count(&p.m, "Route"), 0);
	pm_free(&p);
	/* UAC refresher, interval 600: a refresh at 300 s */
	evfake_advance(299000);
	CHECK_EQ(count_req("UPDATE"), 0);
	evfake_advance(1500);
	u = find_req("UPDATE", 0);
	CHECK(u > 0);
	parse_sent(W.f, u, &p);
	CHECK_STR(H(&p, "CSeq"), "2 UPDATE");
	CHECK_STR(H(&p, "Session-Expires"), "600;refresher=uac");
	CHECK_STR(H(&p, "Supported"), "timer");
	CHECK_EQ((int)p.m.body_len, 0);
	CHECK(strstr(H(&p, "Contact"), "8901"));
	CHECK_STR(H(&p, "Security-Verify"), W.sv);
	pm_free(&p);
	respond_simple(u, 200, NULL, "Session-Expires: 600;refresher=uac\nRequire: timer\n", NULL);
	CHECK_EQ(count_req("BYE"), 0);
	evfake_advance(299000);
	CHECK_EQ(count_req("UPDATE"), 1);
	evfake_advance(2000);
	CHECK_EQ(count_req("UPDATE"), 2);
	u = find_req("UPDATE", u + 1);
	parse_sent(W.f, u, &p);
	CHECK_STR(H(&p, "CSeq"), "3 UPDATE");
	pm_free(&p);
	/* the refresh fails with 408: BYE */
	respond_simple(u, 408, NULL, NULL, NULL);
	CHECK_EQ(count_req("BYE"), 1);
	evfake_advance(10);
	CHECK_EQ(R.term, 1);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_TERMINATED && !e->by_remote);
	world_fini();
}

static void case_mo_n1_refresh_481(void)
{
	struct gmcall *c = establish_mo_n1(ALLOW_UPD);
	int u;

	(void)c;
	evfake_advance(301000);
	u = find_req("UPDATE", 0);
	CHECK(u > 0);
	respond_simple(u, 481, NULL, NULL, NULL);
	CHECK_EQ(count_req("BYE"), 1);
	evfake_advance(10);
	CHECK_EQ(R.term, 1);
	world_fini();
}

static void case_mo_n1_refresh_reinvite(void)
{
	struct gmcall *c = establish_mo_n1(ALLOW_NOUPD);
	struct pm p;
	int r, ack;
	static struct sdp sd;

	(void)c;
	evfake_advance(301000);
	CHECK_EQ(count_req("UPDATE"), 0);	/* the peer does not list UPDATE: a re-INVITE with the current SDP */
	r = find_req("INVITE", 1);
	CHECK(r > 0);
	parse_sent(W.f, r, &p);
	CHECK_STR(H(&p, "CSeq"), "2 INVITE");
	CHECK_STR(H(&p, "Session-Expires"), "600;refresher=uac");
	CHECK_EQ(sdp_parse(&sd, (const char *)p.m.body, p.m.body_len), 0);
	CHECK_EQ(sd.o.version, sd.o.sess_id);	/* unchanged content: same version */
	pm_free(&p);
	respond_tpl(r, V_200_N1, "$ALLOW", ALLOW_NOUPD, (char *)NULL);
	ack = find_req("ACK", r + 1);
	CHECK(ack > 0);
	parse_sent(W.f, ack, &p);
	CHECK_STR(H(&p, "CSeq"), "2 ACK");
	pm_free(&p);
	CHECK_EQ(count_req("BYE"), 0);
	CHECK_EQ(rec_count(&R, GMCALL_EV_MEDIA), 1);	/* the media did not change: nothing new */
	evfake_advance(301000);
	CHECK_EQ(count_req("INVITE"), 3);	/* refreshed again */
	world_fini();
}

static void case_mo_n1_refresh_422(void)
{
	struct gmcall *c = establish_mo_n1(ALLOW_UPD);
	struct pm p;
	int u;

	(void)c;
	evfake_advance(301000);
	u = find_req("UPDATE", 0);
	respond_simple(u, 422, NULL, "Min-SE: 1200\n", NULL);
	CHECK_EQ(count_req("UPDATE"), 2);
	u = find_req("UPDATE", u + 1);
	parse_sent(W.f, u, &p);
	CHECK_STR(H(&p, "Session-Expires"), "1200;refresher=uac");
	CHECK_STR(H(&p, "CSeq"), "3 UPDATE");
	pm_free(&p);
	respond_simple(u, 200, NULL, "Session-Expires: 1200;refresher=uac\n", NULL);
	{
		struct gmcall_info info[1];

		gmcall_list(W.m, info, 1);
		CHECK_EQ(info[0].session_interval, 1200);
	}
	evfake_advance(599000);
	CHECK_EQ(count_req("UPDATE"), 2);
	evfake_advance(2000);
	CHECK_EQ(count_req("UPDATE"), 3);
	world_fini();
}

/* ------------------------------------------------------------------ */
/* MT (l1)                                                              */

static void l1_invite(void)
{
	inject_wire(wire(V_INVITE_L1, (char *)NULL));
}

static const char *mt_tag(void)
{
	static char tag[160];
	int i = find_resp(180, "INVITE", 0);
	struct pm p;

	tag[0] = 0;
	if (i < 0)
		i = find_resp(200, "INVITE", 0);
	if (i >= 0 && parse_sent(W.f, i, &p)) {
		sip_tag(H(&p, "To"), tag, sizeof(tag));
		pm_free(&p);
	}
	return tag;
}

static void inject_ack_l1(void)
{
	inject_wire(wire(V_ACK_L1, "$TAG", mt_tag(), (char *)NULL));
}

/* in-dialog request of the network towards the established MT call */
static void net_req(const char *method, unsigned cseq, const char *hdrs, const char *body)
{
	static unsigned br;
	char buf[4096];

	snprintf(buf, sizeof(buf),
		 "%s sip:01039428657@[2001:4430:1094:d1c6:b9d6:b61:344:9645]:8931 SIP/2.0\n"
		 "Via: SIP/2.0/UDP [" PCSCF_B "]:5071;branch=z9hG4bKnet%u\n"
		 "Call-ID: abc-dGhoc2RjeWItMC0yLWE4MmhrSzltRkxVeWcwTVhmeGFAZ2hnbGhpaW1vbWk-LGU+IBCF\n"
		 "CSeq: %u %s\n"
		 "From: <sip:01051226862@lte-lguplus.co.kr>;tag=" L1_FROM_TAG "\n"
		 "Max-Forwards: 66\n"
		 "To: <tel:01039428657;phone-context=lte-lguplus.co.kr>;tag=%s\n"
		 "Contact: <sip:[" PCSCF_B "]:5071>\n"
		 "%sContent-Length: 0\n\n%s",
		 method, ++br, cseq, method, mt_tag(), hdrs ? hdrs : "", body ? body : "");
	inject_wire(wire(buf, (char *)NULL));
}

static void mk_offer(char *out, size_t n, int port, const char *dir, unsigned ver)
{
	snprintf(out, n,
		 "v=0\no=vIBCF 1356104123 %u IN IP6 2001:4430:4:315::8\ns=-\nc=IN IP6 2001:4430:4:315::8\nt=0 0\n"
		 "m=audio %d RTP/AVP 100 107\nb=AS:50\na=rtpmap:100 AMR-WB/16000/1\na=fmtp:100 octet-align=1\n"
		 "a=rtpmap:107 telephone-event/16000\na=fmtp:107 0-15\na=%s\na=ptime:20\n", ver, port, dir);
}

static struct gmcall *mt_connected(void)
{
	struct gmcall *c;
	struct addr rtp = A(UE_IP, 50012);

	world_init(PCSCF_B, 5071, 5073, NULL);
	l1_invite();
	c = W.in_call;
	CHECK(c != NULL);
	if (!c)
		return NULL;
	CHECK_EQ(gmcall_answer(c, &rtp), 0);
	inject_ack_l1();
	return c;
}

static void case_mt_l1(void)
{
	struct gmcall *c;
	struct pm p;
	static struct sdp sd;
	const struct gmcall_event *e;
	int i, r100, r180, r200, n200;
	struct addr rtp = A(UE_IP, 50012);
	char tag[160];

	world_init(PCSCF_B, 5071, 5073, NULL);
	l1_invite();
	CHECK_EQ(W.n_incoming, 1);
	c = W.in_call;
	CHECK(c != NULL);
	CHECK_STR(W.last_in.caller.number, "01051226862");
	CHECK_STR(W.last_in.called, "01039428657");
	CHECK(!W.last_in.caller.anonymous);
	CHECK(W.last_in.session_timer);
	CHECK_EQ(W.last_in_media.codec, SDPN_C_AMRWB);
	CHECK_EQ(W.last_in_media.pt_send, 100);
	CHECK(W.last_in_media.octet_align);
	CHECK_EQ(W.last_in_media.dtmf_pt, 107);
	CHECK(addr_is(&W.last_in_media.remote, "2001:4430:4:315::8", 44218));
	CHECK_EQ(gmcall_direction(c), GMCALL_MT);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_INCOMING);
	r100 = find_resp(100, "INVITE", 0);
	r180 = find_resp(180, "INVITE", 0);
	CHECK(r100 >= 0 && r180 > r100);
	parse_sent(W.f, r180, &p);
	snprintf(tag, sizeof(tag), "%s", dialog_tag(&p));
	CHECK(tag[0] != 0);
	CHECK_STR(H(&p, "Contact"), CONTACT_EXPECT);
	CHECK(strstr(H(&p, "Allow"), "INVITE"));
	CHECK(has_prefix(H(&p, "P-Access-Network-Info"), "3GPP-E-UTRAN-FDD"));
	CHECK_EQ((int)p.m.body_len, 0);
	CHECK_STR(H(&p, "Require"), "");
	CHECK(addr_is(&W.f->sent[r180].dst, PCSCF_B, 5071) || addr_is(&W.f->sent[r180].dst, PCSCF_B, 5073));
	pm_free(&p);

	CHECK_EQ(gmcall_answer(c, &rtp), 0);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_ANSWERING);
	r200 = find_resp(200, "INVITE", 0);
	CHECK(r200 > r180);
	parse_sent(W.f, r200, &p);
	CHECK_STR(dialog_tag(&p), tag);
	CHECK_STR(H(&p, "Content-Type"), "application/sdp");
	CHECK_STR(H(&p, "Session-Expires"), "600;refresher=uac");
	CHECK_STR(H(&p, "Require"), "timer");
	CHECK_STR(H(&p, "Supported"), "timer");
	CHECK_STR(H(&p, "Contact"), CONTACT_EXPECT);
	CHECK_EQ(sdp_parse(&sd, (const char *)p.m.body, p.m.body_len), 0);
	CHECK_EQ(sd.nmedia, 1);
	CHECK_EQ(sd.media[0].port, 50012);
	CHECK_EQ(sd.media[0].nfmt, 2);
	CHECK_EQ(sd.media[0].fmt[0].pt, 100);	/* the codec PT of the offer, echoed */
	CHECK_STR(sdp_fmt_enc(&sd, &sd.media[0].fmt[0]), "AMR-WB");
	CHECK(strstr(sdp_fmt_fmtp(&sd, &sd.media[0].fmt[0]), "octet-align=1"));	/* mirrored */
	CHECK_EQ(sd.media[0].fmt[1].pt, 107);
	CHECK_EQ(sdp_media_dir(&sd, &sd.media[0]), SDP_DIR_SENDRECV);
	pm_free(&p);
	/* the 200 is retransmitted (T1 500 ms, doubling) until the ACK */
	evfake_advance(499);
	CHECK_EQ(find_resp(200, "INVITE", r200 + 1), -1);
	evfake_advance(2);
	n200 = 0;
	for (i = 0; (i = find_resp(200, "INVITE", i)) >= 0; i++)
		n200++;
	CHECK_EQ(n200, 2);
	evfake_advance(1000);
	n200 = 0;
	for (i = 0; (i = find_resp(200, "INVITE", i)) >= 0; i++)
		n200++;
	CHECK_EQ(n200, 3);
	CHECK_EQ(rec_count(&W.mt, GMCALL_EV_ANSWERED), 0);
	inject_ack_l1();
	CHECK_EQ(rec_count(&W.mt, GMCALL_EV_ANSWERED), 1);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	evfake_advance(20000);
	n200 = 0;
	for (i = 0; (i = find_resp(200, "INVITE", i)) >= 0; i++)
		n200++;
	CHECK_EQ(n200, 3);	/* stopped */
	CHECK_EQ(count_req("BYE"), 0);

	CHECK_EQ(gmcall_hangup(c), 0);
	i = find_req("BYE", 0);
	CHECK(i >= 0);
	parse_sent(W.f, i, &p);
	CHECK_STR(p.m.ruri, "sip:[" PCSCF_B "]:5071");	/* the remote target = the P-CSCF */
	CHECK_EQ(sip_hdr_count(&p.m, "Route"), 0);
	CHECK(has_prefix(H(&p, "From"), "<tel:01039428657;phone-context=lte-lguplus.co.kr>;tag="));
	CHECK(strstr(H(&p, "From"), tag));
	CHECK_STR(H(&p, "To"), "<sip:01051226862@lte-lguplus.co.kr>;tag=" L1_FROM_TAG);
	CHECK_STR(H(&p, "Call-ID"), "abc-dGhoc2RjeWItMC0yLWE4MmhrSzltRkxVeWcwTVhmeGFAZ2hnbGhpaW1vbWk-LGU+IBCF");
	CHECK_STR(H(&p, "Security-Verify"), W.sv);
	CHECK_STR(H(&p, "Require"), "sec-agree");
	CHECK(addr_is(&W.f->sent[i].dst, PCSCF_B, 5071));
	pm_free(&p);
	respond_simple(i, 200, NULL, NULL, NULL);
	evfake_advance(10);
	CHECK_EQ(W.mt.term, 1);
	e = rec_last(&W.mt);
	CHECK(e && e->type == GMCALL_EV_TERMINATED && !e->by_remote);
	world_fini();
}

static void case_mt_remote_bye(void)
{
	struct gmcall *c = mt_connected();
	const struct gmcall_event *e;

	(void)c;
	net_req("BYE", 9204, "Reason: SIP ;cause=200 ;text=\"Call completed elsewhere\"\n", NULL);
	CHECK(find_resp(200, "BYE", 0) >= 0);
	CHECK_EQ(W.mt.term, 1);
	e = rec_last(&W.mt);
	CHECK(e && e->type == GMCALL_EV_TERMINATED && e->by_remote);
	if (e)
		CHECK_STR(e->reason, "Call completed elsewhere");
	CHECK_EQ(count_req("BYE"), 0);
	/* a retransmitted BYE is absorbed by the transaction; an unknown dialog falls through to the default */
	net_req("BYE", 9205, NULL, NULL);
	evfake_advance(10);
	CHECK_EQ(W.unhandled, 1);
	world_fini();
}

static void case_mt_session_expiry(void)
{
	struct gmcall *c = mt_connected();
	const struct gmcall_event *e;
	struct gmcall_info info[1];

	(void)c;
	gmcall_list(W.m, info, 1);
	CHECK_EQ(info[0].session_interval, 600);
	CHECK(!info[0].session_refresher_local);
	/* non-refresher: BYE at expiry minus min(32 s, interval/3) = 568 s */
	evfake_advance(567000);
	CHECK_EQ(count_req("BYE"), 0);
	evfake_advance(2000);
	CHECK_EQ(count_req("BYE"), 1);
	evfake_advance(10);
	CHECK_EQ(W.mt.term, 1);
	e = rec_last(&W.mt);
	CHECK(e && e->type == GMCALL_EV_TERMINATED && !e->by_remote && strstr(e->reason, "session"));
	world_fini();
}

static void case_mt_remote_refresh(void)
{
	struct gmcall *c = mt_connected();
	int i;
	struct pm p;

	(void)c;
	evfake_advance(300000);
	net_req("UPDATE", 9204, "Session-Expires: 600;refresher=uac\nSupported: timer\n", NULL);
	i = find_resp(200, "UPDATE", 0);
	CHECK(i >= 0);
	parse_sent(W.f, i, &p);
	CHECK_STR(H(&p, "Session-Expires"), "600;refresher=uac");
	CHECK_STR(H(&p, "Require"), "timer");
	CHECK_EQ((int)p.m.body_len, 0);	/* UPDATE without SDP: 200 without SDP */
	pm_free(&p);
	evfake_advance(560000);	/* 860 s: past the original expiry, before the new one */
	CHECK_EQ(count_req("BYE"), 0);
	evfake_advance(20000);
	CHECK_EQ(count_req("BYE"), 1);
	/* a refresh with a too small interval is refused with 422 */
	world_fini();
}

static void case_mt_cancel(void)
{
	struct gmcall *c;
	const struct gmcall_event *e;

	world_init(PCSCF_B, 5071, 5073, NULL);
	l1_invite();
	c = W.in_call;
	CHECK(c != NULL);
	inject_wire(wire(V_CANCEL_L1, (char *)NULL));
	CHECK(find_resp(200, "CANCEL", 0) >= 0);	/* the transaction layer answers the CANCEL */
	CHECK(find_resp(487, "INVITE", 0) >= 0);
	CHECK_EQ(W.mt.term, 1);
	e = rec_last(&W.mt);
	CHECK(e && e->type == GMCALL_EV_CANCELLED && e->by_remote);
	CHECK_EQ(gmcall_count(W.m), 0);
	evfake_advance(100);
	world_fini();
}

static void case_mt_reject(void)
{
	const struct gmcall_event *e;

	world_init(PCSCF_B, 5071, 5073, NULL);
	l1_invite();
	W.mt.in_api = true;
	CHECK_EQ(gmcall_reject(W.in_call, 486), 0);
	W.mt.in_api = false;
	CHECK_EQ(W.mt.reentrant, 0);
	CHECK(find_resp(486, "INVITE", 0) >= 0);
	evfake_advance(10);
	CHECK_EQ(W.mt.term, 1);
	e = rec_last(&W.mt);
	CHECK(e && e->type == GMCALL_EV_CANCELLED && !e->by_remote);
	/* the 486 is retransmitted until the network ACKs (txn layer); we do not care */
	world_fini();
}

static void case_mt_no_ack(void)
{
	struct gmcall *c;
	struct addr rtp = A(UE_IP, 50012);
	const struct gmcall_event *e;

	world_init(PCSCF_B, 5071, 5073, NULL);
	l1_invite();
	c = W.in_call;
	CHECK_EQ(gmcall_answer(c, &rtp), 0);
	evfake_advance(31000);
	CHECK_EQ(count_req("BYE"), 0);
	evfake_advance(2000);	/* 64 * T1 = 32 s */
	CHECK_EQ(count_req("BYE"), 1);
	evfake_advance(10);
	CHECK_EQ(W.mt.term, 1);
	e = rec_last(&W.mt);
	CHECK(e && e->type == GMCALL_EV_TERMINATED && !e->by_remote && strstr(e->reason, "ACK"));
	world_fini();
}

static void tune_noincoming(struct gmcall_cfg *c)
{
	c->on_incoming = NULL;
}

static void tune_max2(struct gmcall_cfg *c)
{
	c->max_calls = 2;
}

static void case_mt_refusals(void)
{
	/* no incoming handler: 480 */
	world_init(PCSCF_B, 5071, 5073, tune_noincoming);
	l1_invite();
	CHECK(find_resp(480, "INVITE", 0) >= 0);
	CHECK_EQ(W.n_incoming, 0);
	world_fini();

	/* the handler refuses */
	world_init(PCSCF_B, 5071, 5073, NULL);
	W.in_ret = -1;
	l1_invite();
	CHECK(find_resp(480, "INVITE", 0) >= 0);
	evfake_advance(10);
	CHECK_EQ(W.mt.term, 1);
	world_fini();

	/* Require: 100rel -> 420 with Unsupported */
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire("INVITE sip:01039428657@[" UE_IP "]:8931 SIP/2.0\n"
			 "Via: SIP/2.0/UDP [" PCSCF_B "]:5071;branch=z9hG4bKr1\nFrom: <sip:a@b>;tag=1\nTo: <sip:01039428657@lte-lguplus.co.kr>\n"
			 "Call-ID: r1\nCSeq: 1 INVITE\nRequire: 100rel, precondition\nContact: <sip:[" PCSCF_B "]:5071>\n"
			 "Content-Length: 0\n\n", (char *)NULL));
	{
		int i = find_resp(420, "INVITE", 0);
		struct pm p;

		CHECK(i >= 0);
		if (i >= 0) {
			parse_sent(W.f, i, &p);
			CHECK_STR(H(&p, "Unsupported"), "100rel,precondition");
			pm_free(&p);
		}
	}
	CHECK_EQ(W.n_incoming, 0);
	world_fini();

	/* a request URI that is not ours */
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire(V_INVITE_L1, "sip:01039428657@[2001:4430:1094:d1c6:b9d6:b61:344:9645]:8931",
			 "sip:someoneelse@elsewhere.example", (char *)NULL));
	CHECK(find_resp(404, "INVITE", 0) >= 0);
	world_fini();

	/* offer without audio codec we know: 488 before ringing */
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire(V_INVITE_L1, "m=audio 44218 RTP/AVP 110 100 96 107 101", "m=audio 44218 RTP/AVP 110",
			 "a=rtpmap:100 AMR-WB/16000/1\n", "", "a=rtpmap:96 AMR/8000/1\n", "", (char *)NULL));
	CHECK(find_resp(488, "INVITE", 0) >= 0);
	CHECK_EQ(W.n_incoming, 0);
	world_fini();

	/* INVITE without SDP: 488 (late offer not supported) */
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire("INVITE sip:01039428657@[" UE_IP "]:8931 SIP/2.0\n"
			 "Via: SIP/2.0/UDP [" PCSCF_B "]:5071;branch=z9hG4bKr2\nFrom: <sip:a@b>;tag=1\nTo: <sip:01039428657@lte-lguplus.co.kr>\n"
			 "Call-ID: r2\nCSeq: 1 INVITE\nContact: <sip:[" PCSCF_B "]:5071>\nContent-Length: 0\n\n", (char *)NULL));
	CHECK(find_resp(488, "INVITE", 0) >= 0);
	world_fini();

	/* call limit */
	world_init(PCSCF_B, 5071, 5073, tune_max2);
	{
		struct gmcall_dial d;
		struct gmcall *a = NULL, *b = NULL, *x = NULL;

		memset(&d, 0, sizeof(d));
		d.target = "114";
		d.local_rtp = A(UE_IP, 50010);
		CHECK_EQ(gmcall_dial(W.m, &d, NULL, NULL, &a), 0);
		CHECK_EQ(gmcall_dial(W.m, &d, NULL, NULL, &b), 0);
		CHECK_EQ(gmcall_dial(W.m, &d, NULL, NULL, &x), -ENOBUFS);
		l1_invite();
		CHECK(find_resp(486, "INVITE", 0) >= 0);
	}
	world_fini();
}

#include "test_gmcall_cases2.h"

static void run_cases(void)
{
#define RUN(f) do { int c0 = t_checks, f0 = t_fails; f; printf("%-34s %4d checks, %d failures\n", #f, t_checks - c0, t_fails - f0); } while (0)
	RUN(case_mo_114(false));
	RUN(case_mo_114(true));
	RUN(case_mo_100rel_603());
	RUN(case_mo_n1());
	RUN(case_mo_n1_refresh_481());
	RUN(case_mo_n1_refresh_reinvite());
	RUN(case_mo_n1_refresh_422());
	RUN(case_mt_l1());
	RUN(case_mt_remote_bye());
	RUN(case_mt_session_expiry());
	RUN(case_mt_remote_refresh());
	RUN(case_mt_cancel());
	RUN(case_mt_reject());
	RUN(case_mt_no_ack());
	RUN(case_mt_refusals());
	run_cases2();
#undef RUN
}
