/* SPDX-License-Identifier: GPL-2.0-or-later */
/* more scenarios (included by test_gmcall_cases.h) */

#define N1_TAG "73677a2f29f4e"

static int count_resp(int status, const char *method)
{
	int n = 0, i = -1;

	while ((i = find_resp(status, method, i + 1)) >= 0)
		n++;
	return n;
}

/* a request of the network inside the dialog of the MO call established by establish_mo_n1() */
static void net_req_mo(const char *method, unsigned cseq, const char *hdrs, const char *body)
{
	static unsigned br;
	char buf[4096], ft[64];
	struct pm p;
	int inv = find_req("INVITE", 0);

	parse_sent(W.f, inv, &p);
	sip_tag(H(&p, "From"), ft, sizeof(ft));
	snprintf(buf, sizeof(buf),
		 "%s sip:01039428657@[" UE_IP "]:8901 SIP/2.0\n"
		 "Via: SIP/2.0/UDP [" PCSCF_B "]:5071;branch=z9hG4bKmo%u\n"
		 "Call-ID: %s\n"
		 "CSeq: %u %s\n"
		 "From: <tel:01051226862;phone-context=lguplus.co.kr>;tag=" N1_TAG "\n"
		 "Max-Forwards: 66\n"
		 "To: <sip:01039428657@lte-lguplus.co.kr>;tag=%s\n"
		 "Contact: <sip:[" PCSCF_B "]:5071>\n"
		 "%sContent-Length: 0\n\n%s",
		 method, ++br, H(&p, "Call-ID"), cseq, method, ft, hdrs ? hdrs : "", body ? body : "");
	pm_free(&p);
	inject_wire(wire(buf, (char *)NULL));
}

static void mk_offer_mo(char *out, size_t n, int port, const char *dir, unsigned ver)
{
	snprintf(out, n,
		 "v=0\no=vIBCF 1342570928 %u IN IP6 2001:4430:5:325::8\ns=QC VOIP\nc=IN IP6 2001:4430:5:325::8\nt=0 0\n"
		 "m=audio %d RTP/AVP 104 101\nb=AS:49\na=rtpmap:104 AMR-WB/16000/1\n"
		 "a=fmtp:104 octet-align=1;mode-change-capability=2;max-red=0\n"
		 "a=rtpmap:101 telephone-event/8000/1\na=fmtp:101 0-15\na=%s\na=ptime:20\n", ver, port, dir);
}

static void parse_body(const struct pm *p, struct sdp *sd)
{
	CHECK_EQ(sdp_parse(sd, (const char *)p->m.body, p->m.body_len), 0);
}

/* ------------------------------------------------------------------ */
/* cancel                                                               */

static void case_mo_cancel_pending(void)
{
	struct gmcall *c;
	struct pm p, q;
	int inv, can;
	const struct gmcall_event *e;

	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	CHECK_EQ(gmcall_hangup(c), 0);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CANCELLING);
	CHECK_EQ(count_req("CANCEL"), 0);	/* no provisional response yet: pending */
	respond_tpl(inv, V_100, (char *)NULL);	/* the first 1xx releases it */
	can = find_req("CANCEL", 0);
	CHECK(can > 0);
	parse_sent(W.f, inv, &p);
	parse_sent(W.f, can, &q);
	CHECK_STR(H(&q, "CSeq"), "1 CANCEL");
	CHECK_STR(H(&q, "Call-ID"), H(&p, "Call-ID"));
	CHECK_STR(H(&q, "Via"), H(&p, "Via"));	/* same branch as the INVITE */
	CHECK_STR(sip_hdr(&q.m, "Route", 0), "<sip:[" PCSCF_A "]:1357;lr>");
	pm_free(&p);
	pm_free(&q);
	respond_simple(can, 200, NULL, NULL, NULL);
	CHECK_EQ(R.term, 0);
	respond_simple(inv, 487, "t487", NULL, NULL);
	CHECK_EQ(R.term, 1);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_CANCELLED && !e->by_remote);
	CHECK_EQ(count_req("ACK"), 1);	/* the 487 is ACKed by the transaction layer */
	world_fini();
}

static void case_mo_cancel_race(void)
{
	struct gmcall *c;
	int inv;
	const struct gmcall_event *e;
	struct pm p;

	world_init(PCSCF_B, 5071, 5073, NULL);
	c = dial("01051226862", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_tpl(inv, V_180_N1, (char *)NULL);
	CHECK_EQ(gmcall_hangup(c), 0);
	CHECK_EQ(count_req("CANCEL"), 1);
	/* the callee answers just before the CANCEL arrives: a 2xx instead of the 487 */
	respond_tpl(inv, V_200_N1, "$ALLOW", ALLOW_UPD, (char *)NULL);
	CHECK_EQ(count_req("ACK"), 1);
	CHECK_EQ(count_req("BYE"), 1);
	parse_sent(W.f, find_req("BYE", 0), &p);
	CHECK_STR(dialog_tag(&p), N1_TAG);
	pm_free(&p);
	CHECK_EQ(R.term, 1);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_CANCELLED && !e->by_remote);
	CHECK_EQ(rec_count(&R, GMCALL_EV_ANSWERED), 0);
	CHECK_EQ(rec_count(&R, GMCALL_EV_MEDIA), 0);
	world_fini();
}

static void case_mo_cancel_guard(void)
{
	struct gmcall *c;
	int inv;
	const struct gmcall_event *e;

	world_init(PCSCF_B, 5071, 5073, NULL);
	c = dial("01051226862", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_tpl(inv, V_180_N1, (char *)NULL);
	CHECK_EQ(gmcall_hangup(c), 0);
	evfake_advance(31000);
	CHECK_EQ(R.term, 0);
	evfake_advance(2000);	/* nothing answers the CANCEL: give up after 64*T1 */
	CHECK_EQ(R.term, 1);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_CANCELLED);
	world_fini();
}

static void case_mo_ring_timeout(void)
{
	struct gmcall *c;
	int inv;
	const struct gmcall_event *e;

	world_init(PCSCF_B, 5071, 5073, NULL);
	c = dial("01051226862", UE_IP, 50010);
	(void)c;
	inv = find_req("INVITE", 0);
	respond_tpl(inv, V_180_N1, (char *)NULL);
	evfake_advance(179000);
	CHECK_EQ(count_req("CANCEL"), 0);
	evfake_advance(2000);
	CHECK_EQ(count_req("CANCEL"), 1);
	respond_simple(inv, 487, NULL, NULL, NULL);
	CHECK_EQ(R.term, 1);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_FAILED && e->status == 408);
	world_fini();
}

/* ------------------------------------------------------------------ */
/* forked 2xx                                                           */

static void case_mo_forked_2xx(void)
{
	struct gmcall *c = establish_mo_n1(ALLOW_UPD);
	struct pm p;
	int inv = find_req("INVITE", 0), i, bye;

	CHECK_EQ(count_req("ACK"), 1);
	respond_tpl(inv, V_200_N1, "$ALLOW", ALLOW_UPD, "tag=" N1_TAG, "tag=otherfork99", (char *)NULL);
	CHECK_EQ(count_req("ACK"), 2);
	i = find_req("ACK", find_req("ACK", 0) + 1);
	parse_sent(W.f, i, &p);
	CHECK_STR(dialog_tag(&p), "otherfork99");
	pm_free(&p);
	bye = find_req("BYE", 0);
	CHECK(bye > 0);
	parse_sent(W.f, bye, &p);
	CHECK_STR(dialog_tag(&p), "otherfork99");	/* only the extra dialog is torn down */
	pm_free(&p);
	CHECK_EQ(count_req("BYE"), 1);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	CHECK_EQ(rec_count(&R, GMCALL_EV_ANSWERED), 1);
	respond_tpl(inv, V_200_N1, "$ALLOW", ALLOW_UPD, "tag=" N1_TAG, "tag=otherfork99", (char *)NULL);
	CHECK_EQ(count_req("BYE"), 1);
	CHECK_EQ(gmcall_hangup(c), 0);
	CHECK_EQ(count_req("BYE"), 2);
	i = find_req("BYE", bye + 1);
	parse_sent(W.f, i, &p);
	CHECK_STR(dialog_tag(&p), N1_TAG);
	pm_free(&p);
	world_fini();
}

static void case_mo_stray_2xx(void)
{
	struct gmcall *c = establish_mo_n1(ALLOW_UPD);
	int inv = find_req("INVITE", 0), acks;

	(void)c;
	evfake_advance(40000);	/* the client transaction is gone (Timer M) */
	acks = count_req("ACK");
	/* the network did not get our ACK and retransmits the 2xx: it reaches the stray callback; ACKed again */
	respond_tpl(inv, V_200_N1, "$ALLOW", ALLOW_UPD, (char *)NULL);
	CHECK_EQ(count_req("ACK"), acks + 1);
	CHECK_EQ(rec_count(&R, GMCALL_EV_ANSWERED), 1);
	/* a 2xx of a different dialog after the transaction is gone: ACK + BYE */
	respond_tpl(inv, V_200_N1, "$ALLOW", ALLOW_UPD, "tag=" N1_TAG, "tag=latefork77", (char *)NULL);
	CHECK_EQ(count_req("BYE"), 1);
	world_fini();
}

/* ------------------------------------------------------------------ */
/* 422, failures with Reason / Warning, timeouts                        */

static void case_mo_422_retry(void)
{
	struct gmcall *c;
	struct pm p, q;
	int inv, inv2;
	const struct gmcall_event *e;

	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	(void)c;
	inv = find_req("INVITE", 0);
	respond_simple(inv, 422, "t422", "Min-SE: 2400\n", NULL);
	CHECK_EQ(count_req("ACK"), 1);	/* the 422 is ACKed by the transaction layer */
	inv2 = find_req("INVITE", inv + 1);
	CHECK(inv2 > 0);
	parse_sent(W.f, inv, &p);
	parse_sent(W.f, inv2, &q);
	CHECK_STR(H(&q, "CSeq"), "2 INVITE");
	CHECK_STR(H(&q, "Call-ID"), H(&p, "Call-ID"));
	CHECK_STR(H(&q, "From"), H(&p, "From"));	/* same dialog identifiers, same From tag */
	CHECK_STR(H(&q, "To"), "<tel:114;phone-context=lguplus.co.kr>");
	CHECK_STR(H(&q, "Session-Expires"), "2400;refresher=uac");
	CHECK_STR(H(&q, "Min-SE"), "2400");
	CHECK(strcmp(H(&q, "Via"), H(&p, "Via")));	/* a new branch */
	pm_free(&p);
	pm_free(&q);
	/* only once */
	respond_simple(inv2, 422, "t422", "Min-SE: 3000\n", NULL);
	CHECK_EQ(count_req("INVITE"), 2);
	CHECK_EQ(R.term, 1);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_FAILED && e->status == 422);
	world_fini();

	/* a retry that is then answered normally */
	world_init(PCSCF_B, 5071, 5073, NULL);
	c = dial("01051226862", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_simple(inv, 422, "t422", "Min-SE: 600\n", NULL);
	inv2 = find_req("INVITE", inv + 1);
	respond_tpl(inv2, V_200_N1, "$ALLOW", ALLOW_UPD, (char *)NULL);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	CHECK_EQ(count_req("ACK"), 2);
	{
		struct pm a;
		int ack = find_req("ACK", inv2 + 1);

		parse_sent(W.f, ack, &a);
		CHECK_STR(H(&a, "CSeq"), "2 ACK");	/* the ACK carries the retried INVITE's CSeq */
		pm_free(&a);
	}
	world_fini();
}

static void case_mo_failures(void)
{
	struct gmcall *c;
	int inv;
	const struct gmcall_event *e;

	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	(void)c;
	inv = find_req("INVITE", 0);
	respond_simple(inv, 603, "t1", "Reason: SIP ;cause=603 ;text=\"Barred by policy\"\nWarning: 399 pcscf \"Call barred\"\n", NULL);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_FAILED && e->status == 603);
	if (e) {
		CHECK_STR(e->reason, "Barred by policy");
		CHECK_STR(e->warning, "Call barred");
	}
	world_fini();

	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_simple(inv, 486, "t1", "Warning: 399 x \"Busy now\"\n", NULL);
	e = rec_last(&R);
	CHECK(e && e->status == 486);
	if (e)
		CHECK_STR(e->reason, "Busy now");
	world_fini();

	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_simple(inv, 404, NULL, NULL, NULL);
	e = rec_last(&R);
	CHECK(e && e->status == 404);
	if (e)
		CHECK_STR(e->reason, "Not Found");
	world_fini();

	/* a challenge: reported as a plain failure (re-authentication is the registration module's business) */
	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_simple(inv, 401, "t1", NULL, NULL);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_FAILED && e->status == 401);
	CHECK_EQ(count_req("INVITE"), 1);
	world_fini();

	/* nothing answers: Timer B, 408 */
	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	evfake_advance(33000);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_FAILED && e->status == 408);
	CHECK_EQ(R.term, 1);
	CHECK(count_req("INVITE") == 1);
	world_fini();

	/* the transport refuses the send */
	world_init(PCSCF_A, 1357, 7535, NULL);
	W.f->fail_errno = ENETUNREACH;
	c = dial("114", UE_IP, 50010);
	evfake_advance(10);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_FAILED && e->status == 503);
	W.f->fail_errno = 0;
	world_fini();
}

/* ------------------------------------------------------------------ */
/* hold / resume, glare                                                 */

static void case_mo_hold_resume(void)
{
	struct gmcall *c = establish_mo_n1(ALLOW_UPD);
	struct pm p;
	static struct sdp sd, sd2;
	int r, r2, ack;
	const struct gmcall_event *e;
	uint64_t v1;

	CHECK_EQ(gmcall_set_direction(c, SDP_DIR_SENDONLY), 0);
	r = find_req("INVITE", 1);
	CHECK(r > 0);
	parse_sent(W.f, r, &p);
	CHECK_STR(H(&p, "CSeq"), "2 INVITE");
	CHECK_STR(dialog_tag(&p), N1_TAG);
	CHECK_EQ(sip_hdr_count(&p.m, "Route"), 0);
	CHECK(H(&p, "Contact")[0] != 0);
	parse_body(&p, &sd);
	CHECK_EQ(sdp_media_dir(&sd, &sd.media[0]), SDP_DIR_SENDONLY);
	pm_free(&p);
	parse_sent(W.f, 0, &p);
	parse_body(&p, &sd2);
	pm_free(&p);
	CHECK_EQ(sd.o.sess_id, sd2.o.sess_id);
	CHECK_EQ(sd.o.version, sd2.o.version + 1);	/* the origin version is incremented */
	v1 = sd.o.version;
	respond_tpl(r, V_200_N1, "$ALLOW", ALLOW_UPD, "a=sendrecv", "a=recvonly", (char *)NULL);
	ack = find_req("ACK", r + 1);
	CHECK(ack > 0);
	parse_sent(W.f, ack, &p);
	CHECK_STR(H(&p, "CSeq"), "2 ACK");
	pm_free(&p);
	e = rec_nth(&R, GMCALL_EV_MEDIA, 1);
	CHECK(e && !e->early && e->media && e->media->dir == SDP_DIR_SENDONLY);
	CHECK_EQ(gmcall_local_dir(c), SDP_DIR_SENDONLY);
	{
		int nack = count_req("ACK");

		/* the 200 of our re-INVITE arrives again (our ACK was lost): ACKed again, nothing re-reported */
		respond_tpl(r, V_200_N1, "$ALLOW", ALLOW_UPD, "a=sendrecv", "a=recvonly", (char *)NULL);
		CHECK_EQ(count_req("ACK"), nack + 1);
		CHECK_EQ(rec_count(&R, GMCALL_EV_MEDIA), 2);
	}
	/* resume */
	CHECK_EQ(gmcall_set_direction(c, SDP_DIR_SENDRECV), 0);
	r2 = find_req("INVITE", r + 1);
	CHECK(r2 > 0);
	parse_sent(W.f, r2, &p);
	CHECK_STR(H(&p, "CSeq"), "3 INVITE");
	parse_body(&p, &sd);
	CHECK_EQ(sdp_media_dir(&sd, &sd.media[0]), SDP_DIR_SENDRECV);
	CHECK_EQ(sd.o.version, v1 + 1);
	pm_free(&p);
	respond_tpl(r2, V_200_N1, "$ALLOW", ALLOW_UPD, (char *)NULL);
	e = rec_nth(&R, GMCALL_EV_MEDIA, 2);
	CHECK(e && e->media && e->media->dir == SDP_DIR_SENDRECV);
	CHECK_EQ(gmcall_local_dir(c), SDP_DIR_SENDRECV);
	/* asking for what we already have sends nothing */
	CHECK_EQ(gmcall_set_direction(c, SDP_DIR_SENDRECV), 0);
	CHECK_EQ(count_req("INVITE"), 3);
	/* a rejected re-INVITE leaves the call as it was and says so */
	CHECK_EQ(gmcall_set_direction(c, SDP_DIR_INACTIVE), 0);
	r = find_req("INVITE", r2 + 1);
	respond_simple(r, 488, "x", NULL, NULL);
	e = rec_nth(&R, GMCALL_EV_REOFFER_FAILED, 0);
	CHECK(e && e->status == 488);
	CHECK_EQ(gmcall_local_dir(c), SDP_DIR_SENDRECV);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	world_fini();
}

static void case_mo_glare(void)
{
	struct gmcall *c = establish_mo_n1(ALLOW_UPD);
	struct pm p;
	int r, r2, i;
	char off[800];
	uint64_t t0;

	CHECK_EQ(gmcall_set_direction(c, SDP_DIR_SENDONLY), 0);
	r = find_req("INVITE", 1);
	/* the network's own re-INVITE crosses ours: 491 Request Pending */
	mk_offer_mo(off, sizeof(off), 42746, "sendrecv", 1795120621);
	net_req_mo("INVITE", 700, "Content-Type: application/sdp\n", off);
	CHECK(find_resp(491, "INVITE", 0) >= 0);
	/* the network answers ours with 491: we own the Call-ID, so we wait 2.1 - 4 s, then try again */
	respond_simple(r, 491, "x", NULL, NULL);
	CHECK_EQ(count_req("INVITE"), 2);
	t0 = 0;
	for (i = 0; i < 20 && count_req("INVITE") < 3; i++) {
		evfake_advance(250);
		t0 += 250;
	}
	CHECK(count_req("INVITE") == 3);
	CHECK(t0 >= 2000 && t0 <= 4250);
	r2 = find_req("INVITE", r + 1);
	parse_sent(W.f, r2, &p);
	CHECK_STR(H(&p, "CSeq"), "3 INVITE");
	pm_free(&p);
	respond_tpl(r2, V_200_N1, "$ALLOW", ALLOW_UPD, "a=sendrecv", "a=recvonly", (char *)NULL);
	CHECK_EQ(gmcall_local_dir(c), SDP_DIR_SENDONLY);
	world_fini();
}

static void case_mo_remote_reinvite(void)
{
	struct gmcall *c = establish_mo_n1(ALLOW_UPD);
	char off[800];
	struct pm p;
	static struct sdp sd, sd0;
	int r, n;
	const struct gmcall_event *e;
	uint64_t v0;

	(void)c;
	parse_sent(W.f, 0, &p);
	parse_body(&p, &sd0);
	pm_free(&p);
	v0 = sd0.o.version;
	/* the network puts us on hold */
	mk_offer_mo(off, sizeof(off), 42746, "sendonly", 1795120621);
	net_req_mo("INVITE", 701, "Content-Type: application/sdp\nSupported: timer\n", off);
	r = find_resp(200, "INVITE", 1);
	CHECK(r > 0);
	parse_sent(W.f, r, &p);
	parse_body(&p, &sd);
	CHECK_EQ(sdp_media_dir(&sd, &sd.media[0]), SDP_DIR_RECVONLY);	/* RFC 3264: sendonly -> recvonly */
	CHECK_EQ(sd.o.version, v0 + 1);
	CHECK_EQ(sd.media[0].port, 50010);
	CHECK(H(&p, "Contact")[0] != 0);
	pm_free(&p);
	e = rec_nth(&R, GMCALL_EV_MEDIA, 1);
	CHECK(e && e->media && e->media->dir == SDP_DIR_RECVONLY && !e->early);
	n = rec_count(&R, GMCALL_EV_MEDIA);
	/* the 200 is retransmitted until the ACK */
	evfake_advance(600);
	CHECK(count_resp(200, "INVITE") >= 2);	/* the first transmission and a retransmission after T1 */
	net_req_mo("ACK", 701, NULL, NULL);
	{
		int c200 = count_resp(200, "INVITE");

		evfake_advance(10000);
		CHECK_EQ(count_resp(200, "INVITE"), c200);
	}
	/* a refresh with unchanged SDP: no MEDIA event */
	net_req_mo("INVITE", 702, "Content-Type: application/sdp\n", off);
	net_req_mo("ACK", 702, NULL, NULL);
	CHECK_EQ(rec_count(&R, GMCALL_EV_MEDIA), n);
	/* resume, with a different RTP port */
	mk_offer_mo(off, sizeof(off), 42800, "sendrecv", 1795120622);
	net_req_mo("INVITE", 703, "Content-Type: application/sdp\n", off);
	net_req_mo("ACK", 703, NULL, NULL);
	e = rec_nth(&R, GMCALL_EV_MEDIA, n);
	CHECK(e && e->media && e->media->dir == SDP_DIR_SENDRECV);
	if (e && e->media)
		CHECK(addr_is(&e->media->remote, "2001:4430:5:325::8", 42800));
	/* a re-INVITE that cannot be answered keeps the old session */
	net_req_mo("INVITE", 704, "Content-Type: application/sdp\n", "v=0\no=- 1 1 IN IP4 1.2.3.4\ns=-\nc=IN IP4 1.2.3.4\nt=0 0\nm=audio 9 RTP/AVP 0\n");
	CHECK(find_resp(488, "INVITE", 0) >= 0);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	/* an old CSeq is refused */
	net_req_mo("INFO", 600, NULL, NULL);
	CHECK(find_resp(500, "INFO", 0) >= 0);
	world_fini();
}

static void case_mt_hold_and_late_offer(void)
{
	struct gmcall *c = mt_connected();
	char off[800];
	struct pm p;
	static struct sdp sd;
	int r;
	const struct gmcall_event *e;
	struct addr rtp = A(UE_IP, 50012);

	(void)rtp;
	mk_offer(off, sizeof(off), 44218, "sendonly", 1356104124);
	net_req("INVITE", 9204, "Content-Type: application/sdp\n", off);
	r = find_resp(200, "INVITE", find_resp(200, "INVITE", 0) + 1);
	CHECK(r > 0);
	parse_sent(W.f, r, &p);
	parse_body(&p, &sd);
	CHECK_EQ(sdp_media_dir(&sd, &sd.media[0]), SDP_DIR_RECVONLY);
	pm_free(&p);
	e = rec_nth(&W.mt, GMCALL_EV_MEDIA, 0);
	CHECK(e && e->media && e->media->dir == SDP_DIR_RECVONLY);
	/* another re-INVITE before the ACK of the first: 500 + Retry-After (RFC 3261 14.2) */
	net_req("INVITE", 9205, "Content-Type: application/sdp\n", off);
	r = find_resp(500, "INVITE", 0);
	CHECK(r >= 0);
	if (r >= 0) {
		parse_sent(W.f, r, &p);
		CHECK(H(&p, "Retry-After")[0] != 0);
		pm_free(&p);
	}
	net_req("ACK", 9204, NULL, NULL);
	/* late offer: INVITE without SDP; our offer goes into the 200, the answer comes in the ACK */
	net_req("INVITE", 9206, NULL, NULL);
	r = find_resp(200, "INVITE", r + 1);
	r = -1;
	{
		int i = -1, last = -1;

		while ((i = find_resp(200, "INVITE", i + 1)) >= 0)
			last = i;
		r = last;
	}
	parse_sent(W.f, r, &p);
	CHECK(p.m.body_len > 0);
	parse_body(&p, &sd);
	pm_free(&p);
	mk_offer(off, sizeof(off), 44300, "sendrecv", 1356104125);
	net_req("ACK", 9206, "Content-Type: application/sdp\n", off);
	e = rec_nth(&W.mt, GMCALL_EV_MEDIA, 1);
	CHECK(e && e->media);
	if (e && e->media)
		CHECK(addr_is(&e->media->remote, "2001:4430:4:315::8", 44300));
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	/* UPDATE carrying an offer: answered in the 200 and reported like a re-INVITE */
	mk_offer(off, sizeof(off), 44400, "sendrecv", 1356104126);
	net_req("UPDATE", 9207, "Content-Type: application/sdp\n", off);
	r = find_resp(200, "UPDATE", 0);
	CHECK(r > 0);
	parse_sent(W.f, r, &p);
	CHECK(p.m.body_len > 0);
	pm_free(&p);
	e = rec_nth(&W.mt, GMCALL_EV_MEDIA, 2);
	CHECK(e && e->media);
	if (e && e->media)
		CHECK(addr_is(&e->media->remote, "2001:4430:4:315::8", 44400));
	world_fini();
}

static void case_mt_local_hold_queued(void)
{
	struct gmcall *c;
	struct addr rtp = A(UE_IP, 50012);
	struct pm p;
	static struct sdp sd;
	int r;

	world_init(PCSCF_B, 5071, 5073, NULL);
	l1_invite();
	c = W.in_call;
	CHECK_EQ(gmcall_answer(c, &rtp), 0);
	CHECK_EQ(gmcall_set_direction(c, SDP_DIR_INACTIVE), 0);	/* before the ACK: queued */
	CHECK_EQ(count_req("INVITE"), 0);
	inject_ack_l1();
	r = find_req("INVITE", 0);
	CHECK(r >= 0);
	if (r >= 0) {
		parse_sent(W.f, r, &p);
		parse_body(&p, &sd);
		CHECK_EQ(sdp_media_dir(&sd, &sd.media[0]), SDP_DIR_INACTIVE);
		CHECK_EQ(sip_hdr_count(&p.m, "Route"), 0);
		pm_free(&p);
	}
	/* glare timer of the non-owner of the Call-ID: 0 - 2 s */
	respond_simple(r, 491, "x", NULL, NULL);
	evfake_advance(2100);
	CHECK_EQ(count_req("INVITE"), 2);
	/* a new local RTP port (media moved) */
	{
		struct addr np = A(UE_IP, 50100);

		r = find_req("INVITE", r + 1);
		respond_simple(r, 200, "x", NULL, NULL);	/* no SDP in the answer: unusable */
		CHECK_EQ(rec_count(&W.mt, GMCALL_EV_REOFFER_FAILED), 1);
		CHECK_EQ(gmcall_set_media(c, &np, SDP_DIR_SENDRECV), 0);
		r = find_req("INVITE", r + 1);
		CHECK(r >= 0);
		if (r >= 0) {
			parse_sent(W.f, r, &p);
			parse_body(&p, &sd);
			CHECK_EQ(sd.media[0].port, 50100);
			pm_free(&p);
		}
	}
	world_fini();
}

static void case_mt_dialog_requests(void)
{
	struct gmcall *c = mt_connected();
	int i;
	struct pm p;

	(void)c;
	net_req("INFO", 9204, "Content-Type: application/dtmf-relay\n", NULL);
	CHECK(find_resp(200, "INFO", 0) >= 0);
	net_req("OPTIONS", 9205, NULL, NULL);
	i = find_resp(200, "OPTIONS", 0);
	CHECK(i >= 0);
	parse_sent(W.f, i, &p);
	CHECK(strstr(H(&p, "Allow"), "INVITE"));
	pm_free(&p);
	net_req("REFER", 9206, "Refer-To: <sip:x@y>\n", NULL);
	CHECK(find_resp(501, "REFER", 0) >= 0);
	net_req("NOTIFY", 9207, "Event: refer\n", NULL);
	CHECK(find_resp(501, "NOTIFY", 0) >= 0);
	net_req("MESSAGE", 9208, "Content-Type: text/plain\n", NULL);
	CHECK(find_resp(405, "MESSAGE", 0) >= 0);
	net_req("PRACK", 9209, "RAck: 1 1 INVITE\n", NULL);
	CHECK(find_resp(481, "PRACK", 0) >= 0);
	net_req("UPDATE", 9210, NULL, NULL);	/* no SDP, no Session-Expires: plain 200 */
	i = find_resp(200, "UPDATE", 0);
	CHECK(i >= 0);
	/* UPDATE with an interval below our minimum: 422 Min-SE */
	net_req("UPDATE", 9211, "Session-Expires: 30;refresher=uac\n", NULL);
	i = find_resp(422, "UPDATE", 0);
	CHECK(i >= 0);
	if (i >= 0) {
		parse_sent(W.f, i, &p);
		CHECK_STR(H(&p, "Min-SE"), "90");
		pm_free(&p);
	}
	/* nothing of this was a call event */
	CHECK_EQ(W.mt.term, 0);
	/* requests that belong to no dialog fall through to the caller's default handler */
	W.unhandled = 0;
	inject_wire(wire("BYE sip:x@y SIP/2.0\nVia: SIP/2.0/UDP [" PCSCF_B "]:5071;branch=z9hG4bKzz1\nFrom: <sip:a@b>;tag=1\n"
			 "To: <sip:c@d>;tag=nosuch\nCall-ID: nosuchcall\nCSeq: 5 BYE\nContent-Length: 0\n\n", (char *)NULL));
	CHECK_EQ(W.unhandled, 1);
	CHECK(find_resp(481, "BYE", 0) >= 0);
	inject_wire(wire("OPTIONS sip:x@y SIP/2.0\nVia: SIP/2.0/UDP [" PCSCF_B "]:5071;branch=z9hG4bKzz2\nFrom: <sip:a@b>;tag=1\n"
			 "To: <sip:c@d>\nCall-ID: nosuchcall2\nCSeq: 5 OPTIONS\nContent-Length: 0\n\n", (char *)NULL));
	CHECK_EQ(W.unhandled, 2);
	world_fini();
}

static void case_mt_anonymous(void)
{
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire(V_INVITE_L1, "Privacy: none", "Privacy: id", (char *)NULL));
	CHECK_EQ(W.n_incoming, 1);
	CHECK(W.last_in.caller.anonymous);
	CHECK_STR(W.last_in.caller.number, "01051226862");
	world_fini();
}

/* ------------------------------------------------------------------ */
/* registration events                                                  */

static void case_reg_replaced(void)
{
	struct gmcall *c = establish_mo_n1(ALLOW_UPD);
	struct sip_ep_cfg cfg;
	struct pm p;
	int bye;
	char newsv[400];

	memset(&cfg, 0, sizeof(cfg));
	cfg.name = "gm#2";
	cfg.kind = SIP_TP_UDP;
	cfg.rx_bind = A(UE_IP, 8002);
	cfg.has_adv = true;
	cfg.adv = A(UE_IP, 8911);
	W.f2 = fakeep_open(&cfg);
	txn_layer_attach(W.tl, W.f2->ep);
	snprintf(newsv, sizeof(newsv), "ipsec-3gpp;q=0.1;alg=hmac-md5-96;ealg=null;spi-c=777;spi-s=778;port-c=5075;port-s=5071");
	snprintf(W.sv, sizeof(W.sv), "%s", newsv);
	W.ctx.ep = W.f2->ep;
	gmcall_reg_hook(W.m, REG_EV_REPLACED, NULL);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	CHECK_EQ(gmcall_hangup(c), 0);
	CHECK_EQ(find_req("BYE", 0), -1);	/* nothing more through the old endpoint */
	bye = find_req_on(W.f2, "BYE", 0);
	CHECK(bye >= 0);
	if (bye >= 0) {
		parse_sent(W.f2, bye, &p);
		CHECK_STR(H(&p, "Security-Verify"), newsv);
		CHECK(strstr(H(&p, "Via"), ":8911"));
		pm_free(&p);
	}
	evfake_advance(10);
	CHECK_EQ(R.term, 1);
	world_fini();
}

static void case_reg_down(bool retired)
{
	struct gmcall *early;
	struct rec r2, *saved;
	struct gmcall_dial d;
	const struct gmcall_event *e;
	struct rec first;
	int nbye;

	establish_mo_n1(ALLOW_UPD);
	/* establish_mo_n1 recorded the connected call in R: keep it, use r2 for the others */
	first = R;
	saved = &R;
	(void)saved;
	memset(&r2, 0, sizeof(r2));
	memset(&d, 0, sizeof(d));
	d.target = "114";
	d.local_rtp = A(UE_IP, 50020);
	CHECK_EQ(gmcall_dial(W.m, &d, rec_cb, &r2, &early), 0);
	l1_invite();
	CHECK(W.in_call != NULL);
	if (retired)
		W.f->ep->retired = true;
	W.registered = false;
	nbye = count_req("BYE");
	gmcall_reg_hook(W.m, REG_EV_DOWN, "lost");
	/* every call ended, each with exactly one terminal event, delivered right here */
	CHECK_EQ(R.term, 1);
	CHECK_EQ(r2.term, 1);
	CHECK_EQ(W.mt.term, 1);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_TERMINATED && !e->by_remote && strstr(e->reason, "registration"));
	e = rec_last(&r2);
	CHECK(e && e->type == GMCALL_EV_FAILED);
	e = rec_last(&W.mt);
	CHECK(e && e->type == GMCALL_EV_CANCELLED);
	CHECK_EQ(gmcall_count(W.m), 0);
	/* a BYE is tried only while an endpoint still exists */
	CHECK_EQ(count_req("BYE") - nbye, retired ? 0 : 1);
	CHECK(find_resp(480, "INVITE", 0) >= 0);	/* the MT INVITE was refused */
	(void)first;
	{
		struct gmcall_dial d2;
		struct gmcall *x = NULL;

		memset(&d2, 0, sizeof(d2));
		d2.target = "114";
		d2.local_rtp = A(UE_IP, 50020);
		CHECK_EQ(gmcall_dial(W.m, &d2, NULL, NULL, &x), -ENOTCONN);
	}
	evfake_advance(100);
	if (retired)
		W.f->ep->retired = false;
	world_fini();
}

static void case_two_calls(void)
{
	struct gmcall *a, *b;
	struct rec ra, rb;
	struct gmcall_dial d;
	int inva, invb;
	struct pm p;

	world_init(PCSCF_B, 5071, 5073, NULL);
	memset(&ra, 0, sizeof(ra));
	memset(&rb, 0, sizeof(rb));
	memset(&d, 0, sizeof(d));
	d.target = "01051226862";
	d.local_rtp = A(UE_IP, 50010);
	CHECK_EQ(gmcall_dial(W.m, &d, rec_cb, &ra, &a), 0);
	d.target = "01077778888";
	d.local_rtp = A(UE_IP, 50012);
	CHECK_EQ(gmcall_dial(W.m, &d, rec_cb, &rb, &b), 0);
	CHECK_EQ(gmcall_count(W.m), 2);
	inva = find_req("INVITE", 0);
	invb = find_req("INVITE", inva + 1);
	CHECK(invb > inva);
	parse_sent(W.f, inva, &p);
	CHECK(strcmp(gmcall_call_id(a), gmcall_call_id(b)));
	CHECK_STR(H(&p, "Call-ID"), gmcall_call_id(a));
	pm_free(&p);
	/* b gets answered, a keeps ringing */
	respond_tpl(invb, V_200_N1, "$ALLOW", ALLOW_UPD, "tel:01051226862", "tel:01077778888", (char *)NULL);
	CHECK_EQ(gmcall_get_state(b), GMCALL_ST_CONNECTED);
	CHECK_EQ(gmcall_get_state(a), GMCALL_ST_DIALING);
	CHECK_EQ(rec_count(&rb, GMCALL_EV_ANSWERED), 1);
	CHECK_EQ(ra.n, 0);
	/* a is cancelled, b untouched */
	CHECK_EQ(gmcall_hangup(a), 0);
	respond_tpl(inva, V_180_N1, (char *)NULL);
	CHECK_EQ(count_req("CANCEL"), 1);
	CHECK_EQ(gmcall_get_state(b), GMCALL_ST_CONNECTED);
	respond_simple(inva, 487, "q", NULL, NULL);
	CHECK_EQ(ra.term, 1);
	CHECK_EQ(rb.term, 0);
	CHECK_EQ(gmcall_hangup(b), 0);
	evfake_advance(10);
	CHECK_EQ(rb.term, 1);
	CHECK_EQ(gmcall_count(W.m), 0);
	world_fini();
}

/* ------------------------------------------------------------------ */
/* dial arguments                                                       */

static void tune_ctx(struct gmcall_cfg *c)
{
	c->phone_context = "example.org";
	c->user_agent = "imsd-test/1";
	c->session_expires = 900;
}

static void case_dial_args(void)
{
	struct gmcall_dial d;
	struct gmcall *c = NULL;
	struct pm p;
	int i;

	world_init(PCSCF_A, 1357, 7535, tune_ctx);
	memset(&d, 0, sizeof(d));
	d.local_rtp = A(UE_IP, 50010);
	d.target = "abc";
	CHECK_EQ(gmcall_dial(W.m, &d, NULL, NULL, &c), -EINVAL);
	d.target = "";
	CHECK_EQ(gmcall_dial(W.m, &d, NULL, NULL, &c), -EINVAL);
	d.target = NULL;
	CHECK_EQ(gmcall_dial(W.m, &d, NULL, NULL, &c), -EINVAL);
	d.target = "114";
	d.local_rtp = A(UE_IP, 0);
	CHECK_EQ(gmcall_dial(W.m, &d, NULL, NULL, &c), -EINVAL);
	CHECK_EQ(gmcall_count(W.m), 0);
	CHECK_EQ(W.f->nsent, 0);
	d.local_rtp = A(UE_IP, 50010);
	d.target = "+82 10-1234-5678";
	d.extra_headers = "Privacy: id\r\n";
	CHECK_EQ(gmcall_dial(W.m, &d, NULL, NULL, &c), 0);
	parse_sent(W.f, 0, &p);
	CHECK_STR(p.m.ruri, "tel:+821012345678");
	CHECK_STR(H(&p, "To"), "<tel:+821012345678>");
	CHECK_STR(H(&p, "Privacy"), "id");
	CHECK_STR(H(&p, "User-Agent"), "imsd-test/1");
	CHECK_STR(H(&p, "Session-Expires"), "900;refresher=uac");
	pm_free(&p);
	d.target = "0212345678";
	d.extra_headers = NULL;
	CHECK_EQ(gmcall_dial(W.m, &d, NULL, NULL, &c), 0);
	i = find_req("INVITE", 1);
	parse_sent(W.f, i, &p);
	CHECK_STR(p.m.ruri, "tel:0212345678;phone-context=example.org");
	pm_free(&p);
	d.target = "sip:01012345678@lte-lguplus.co.kr;user=phone";
	CHECK_EQ(gmcall_dial(W.m, &d, NULL, NULL, &c), 0);
	i = find_req("INVITE", i + 1);
	parse_sent(W.f, i, &p);
	CHECK_STR(p.m.ruri, "sip:01012345678@lte-lguplus.co.kr;user=phone");
	pm_free(&p);
	world_fini();

	world_init(PCSCF_A, 1357, 7535, NULL);
	W.registered = false;
	d.target = "114";
	CHECK_EQ(gmcall_dial(W.m, &d, NULL, NULL, &c), -ENOTCONN);
	W.registered = true;
	world_fini();
}

/* ------------------------------------------------------------------ */
/* malformed input                                                      */

static void case_malformed(void)
{
	struct gmcall *c;
	int inv, i;
	const struct gmcall_event *e;
	char *junk;
	static const char *const garbage[] = {
		"", "\r\n", "SIP/2.0", "SIP/2.0 200", "INVITE\r\n\r\n", "\x01\x02\x03\xff\xfe", "SIP/2.0 999 Weird\r\n\r\n",
		"BYE sip:x SIP/2.0\r\nCSeq: x\r\n\r\n", "SIP/2.0 200 OK\r\nCall-ID: nothing\r\nCSeq: 1 INVITE\r\n\r\n",
	};

	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	for (i = 0; i < (int)(sizeof(garbage) / sizeof(garbage[0])); i++)
		fakeep_rx(W.f, &W.src, garbage[i]);
	/* a response for another call */
	junk = wire(V_183_114, "$VIA", "SIP/2.0/UDP [::1]:1;branch=z9hG4bKunknown", "$FROM", "<sip:a@b>;tag=1", "$CID", "other", "$PORT", "1", (char *)NULL);
	fakeep_rx(W.f, &W.src, junk);
	free(junk);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_DIALING);
	/* a 183 whose SDP is garbage: progress is reported, no media, the call lives on */
	respond_simple(inv, 183, "t183", "Contact: <sip:[" PCSCF_A "]:1357>\nP-Early-Media: sendrecv\n", "v=0\no=bad\nm=audio x RTP/AVP\n");
	CHECK_EQ(rec_count(&R, GMCALL_EV_PROGRESS), 1);
	e = rec_nth(&R, GMCALL_EV_PROGRESS, 0);
	CHECK(e && e->has_sdp);
	if (e)
		CHECK_STR(e->early_media, "sendrecv");
	CHECK_EQ(rec_count(&R, GMCALL_EV_MEDIA), 0);
	/* a 200 whose SDP cannot be used: ACK, BYE, FAILED(488) */
	respond_tpl(inv, V_200_114, "$PORT", "0", (char *)NULL);
	CHECK_EQ(count_req("ACK"), 1);
	CHECK_EQ(count_req("BYE"), 1);
	CHECK_EQ(R.term, 1);
	e = rec_last(&R);
	CHECK(e && e->type == GMCALL_EV_FAILED && e->status == 488);
	CHECK_EQ(rec_count(&R, GMCALL_EV_ANSWERED), 0);
	world_fini();

	/* a 200 without a To tag cannot create a dialog: the call times out by itself */
	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_simple(inv, 200, NULL, "Contact: <sip:[" PCSCF_A "]:1357>\n", NULL);
	CHECK_EQ(R.term, 0);
	evfake_advance(200000);
	CHECK_EQ(R.term, 1);
	world_fini();

	/* MT: an INVITE with an SDP content type but a broken body */
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire(V_INVITE_L1, "m=audio 44218 RTP/AVP 110 100 96 107 101", "m=audio abc RTP/AVP 110 100", (char *)NULL));
	CHECK(find_resp(488, "INVITE", 0) >= 0);
	CHECK_EQ(W.n_incoming, 0);
	world_fini();
}

/* deterministic mutation fuzzing of everything the module parses */
static uint32_t lcg = 12345;
static uint32_t rnd_next(void)
{
	lcg = lcg * 1664525u + 1013904223u;
	return lcg >> 8;
}

static void mutate(char *s, size_t n)
{
	int k = 1 + (int)(rnd_next() % 6), i;

	for (i = 0; i < k && n; i++) {
		size_t p = rnd_next() % n;

		switch (rnd_next() % 4) {
		case 0: s[p] = (char)rnd_next(); break;
		case 1: s[p] = ' '; break;
		case 2: s[p] = '\n'; break;
		default: if (p + 1 < n) s[p] = s[p + 1]; break;
		}
	}
}

static void case_fuzz(void)
{
	int it;

	for (it = 0; it < 60; it++) {
		struct gmcall *c;
		int inv, k;
		char *w;
		size_t n;
		struct addr rtp = A(UE_IP, 50012);

		world_init(PCSCF_B, 5071, 5073, NULL);
		c = dial("01051226862", UE_IP, 50010);
		inv = find_req("INVITE", 0);
		for (k = 0; k < 24; k++) {
			const char *tpl = k % 3 == 0 ? V_180_N1 : V_200_N1;
			struct pm p;
			const char *vals[3];

			parse_sent(W.f, inv, &p);
			vals[0] = H(&p, "Via");
			vals[1] = H(&p, "From");
			vals[2] = H(&p, "Call-ID");
			w = wire(tpl, "$VIA", vals[0], "$FROM", vals[1], "$CID", vals[2], "$ALLOW", ALLOW_UPD, (char *)NULL);
			pm_free(&p);
			n = strlen(w);
			mutate(w, n);
			fakeep_rx_n(W.f, &W.src, w, n);
			free(w);
			if (k % 5 == 4)
				evfake_advance(700);
		}
		w = wire(V_INVITE_L1, (char *)NULL);
		n = strlen(w);
		mutate(w, n);
		fakeep_rx_n(W.f, &W.src, w, n);
		free(w);
		if (W.in_call && gmcall_get_state(W.in_call) == GMCALL_ST_INCOMING)
			gmcall_answer(W.in_call, &rtp);
		for (k = 0; k < 6; k++) {
			static const char *const meth[] = { "UPDATE", "INVITE", "BYE", "INFO", "OPTIONS", "ACK" };
			char off[800];
			const char *m = meth[rnd_next() % 6];

			mk_offer(off, sizeof(off), 44000 + (int)(rnd_next() % 100), k % 2 ? "sendonly" : "sendrecv", 1356104124 + k);
			net_req(m, 9300 + (unsigned)k, "Content-Type: application/sdp\nSession-Expires: 600;refresher=uac\n", off);
			(void)c;
		}
		evfake_advance(2000);
		world_fini();
	}
}

/* ------------------------------------------------------------------ */
/* more MT behaviour, lifetime, session timer variants                  */

static void tune_noring(struct gmcall_cfg *c)
{
	c->auto_ring = false;
}

static void case_mt_misc(void)
{
	struct gmcall *c;
	const struct gmcall_event *e;
	struct addr rtp = A(UE_IP, 50012);
	int n;

	/* rejecting from inside the incoming callback: no 180, final status goes out, event comes later */
	world_init(PCSCF_B, 5071, 5073, NULL);
	W.in_reject = 486;
	l1_invite();
	CHECK(find_resp(486, "INVITE", 0) >= 0);
	CHECK_EQ(find_resp(180, "INVITE", 0), -1);
	CHECK_EQ(W.mt.term, 0);
	evfake_advance(1);
	CHECK_EQ(W.mt.term, 1);
	world_fini();

	/* manual ringing: auto_ring off, the handler rings when it wants; a retransmitted INVITE is absorbed */
	world_init(PCSCF_B, 5071, 5073, tune_noring);
	l1_invite();
	c = W.in_call;
	CHECK_EQ(find_resp(180, "INVITE", 0), -1);
	CHECK(find_resp(100, "INVITE", 0) >= 0);
	CHECK_EQ(gmcall_ring(c), 0);
	CHECK(find_resp(180, "INVITE", 0) >= 0);
	n = W.f->nsent;
	CHECK_EQ(gmcall_ring(c), 0);	/* only once */
	CHECK_EQ(W.f->nsent, n);
	l1_invite();	/* the INVITE again: the transaction repeats the last response, the TU sees nothing */
	CHECK_EQ(W.n_incoming, 1);
	CHECK_EQ(gmcall_count(W.m), 1);
	/* nobody answers: 480 after the ring timeout */
	evfake_advance(179000);
	CHECK_EQ(W.mt.term, 0);
	evfake_advance(2000);
	CHECK_EQ(W.mt.term, 1);
	CHECK(find_resp(480, "INVITE", 0) >= 0);
	e = rec_last(&W.mt);
	CHECK(e && e->type == GMCALL_EV_CANCELLED && !e->by_remote);
	world_fini();

	/* hangup of an unanswered call = 480 */
	world_init(PCSCF_B, 5071, 5073, NULL);
	l1_invite();
	CHECK_EQ(gmcall_hangup(W.in_call), 0);
	CHECK(find_resp(480, "INVITE", 0) >= 0);
	/* the pointer is still there until the loop turns: API calls say so */
	CHECK_EQ(gmcall_hangup(W.in_call), -ESTALE);
	CHECK_EQ(gmcall_answer(W.in_call, &rtp), -ESTALE);
	world_fini();

	/* release: the user lets go of a connected call; BYE goes out, no callback of any kind */
	c = mt_connected();
	n = W.mt.n;
	gmcall_release(c);
	CHECK_EQ(count_req("BYE"), 1);
	evfake_advance(100);
	CHECK_EQ(W.mt.n, n);
	CHECK_EQ(gmcall_count(W.m), 0);
	world_fini();

	/* an answer on a call that was not accepted for answering twice / wrong state */
	c = mt_connected();
	CHECK_EQ(gmcall_answer(c, &rtp), -EINVAL);
	CHECK_EQ(gmcall_reject(c, 486), -EINVAL);
	CHECK_EQ(gmcall_ring(c), -EINVAL);
	world_fini();

	/* offer without octet-align: the answer mirrors "absent" */
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire(V_INVITE_L1, "a=fmtp:100 octet-align=1\n", "", (char *)NULL));
	CHECK_EQ(W.n_incoming, 1);
	CHECK(!W.last_in_media.octet_align);
	CHECK_EQ(gmcall_answer(W.in_call, &rtp), 0);
	{
		struct pm p;
		static struct sdp sd;
		int i = find_resp(200, "INVITE", 0);

		parse_sent(W.f, i, &p);
		parse_body(&p, &sd);
		CHECK(!strstr(sdp_fmt_fmtp(&sd, &sd.media[0].fmt[0]), "octet-align"));
		pm_free(&p);
	}
	world_fini();
}

static void case_mt_record_route(void)
{
	struct gmcall *c;
	struct pm p;
	int b;
	struct addr rtp = A(UE_IP, 50012);
	const char *hdr = "Max-Forwards: 57\nRecord-Route: <sip:[" PCSCF_B "]:5071;lr>\nRecord-Route: <sip:mid.example.org;lr>\n";

	/* the first Record-Route is the P-CSCF: no extra Route; the target is a far host */
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire(V_INVITE_L1, "Max-Forwards: 57\n", hdr,
			 "Contact: <sip:[" PCSCF_B "]:5071>;+g", "Contact: <sip:far@far.example.org>;+g", (char *)NULL));
	c = W.in_call;
	CHECK(c != NULL);
	{
		int i = find_resp(180, "INVITE", 0);

		parse_sent(W.f, i, &p);
		CHECK_EQ(sip_hdr_count(&p.m, "Record-Route"), 2);	/* echoed in the provisional response */
		pm_free(&p);
	}
	CHECK_EQ(gmcall_answer(c, &rtp), 0);
	inject_ack_l1();
	CHECK_EQ(gmcall_hangup(c), 0);
	b = find_req("BYE", 0);
	parse_sent(W.f, b, &p);
	CHECK_STR(p.m.ruri, "sip:far@far.example.org");
	CHECK_EQ(sip_hdr_count(&p.m, "Route"), 2);
	CHECK_STR(sip_hdr(&p.m, "Route", 0), "<sip:[" PCSCF_B "]:5071;lr>");
	CHECK_STR(sip_hdr(&p.m, "Route", 1), "<sip:mid.example.org;lr>");
	CHECK(addr_is(&W.f->sent[b].dst, PCSCF_B, 5071));
	pm_free(&p);
	world_fini();

	/* the first Record-Route is somebody else: our Route to the P-CSCF goes first */
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire(V_INVITE_L1, "Max-Forwards: 57\n",
			 "Max-Forwards: 57\nRecord-Route: <sip:mid.example.org;lr>\n", (char *)NULL));
	c = W.in_call;
	CHECK_EQ(gmcall_answer(c, &rtp), 0);
	inject_ack_l1();
	CHECK_EQ(gmcall_hangup(c), 0);
	b = find_req("BYE", 0);
	parse_sent(W.f, b, &p);
	CHECK_EQ(sip_hdr_count(&p.m, "Route"), 1);
	CHECK_STR(sip_hdr(&p.m, "Route", 0), "<sip:mid.example.org;lr>");
	pm_free(&p);
	world_fini();
}

static void case_mt_timer_variants(void)
{
	struct gmcall *c;
	struct addr rtp = A(UE_IP, 50012);
	struct pm p;
	int i;
	struct gmcall_info info[1];

	/* the caller does not support timer and gives no refresher: we choose to refresh ourselves */
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire(V_INVITE_L1, "Supported: timer, sec-agree", "Supported: sec-agree",
			 "Session-Expires: 600;refresher=uac", "Session-Expires: 600", (char *)NULL));
	c = W.in_call;
	CHECK_EQ(gmcall_answer(c, &rtp), 0);
	i = find_resp(200, "INVITE", 0);
	parse_sent(W.f, i, &p);
	CHECK_STR(H(&p, "Session-Expires"), "600;refresher=uas");
	CHECK_STR(H(&p, "Require"), "");	/* nobody asked for timer, so it is not required */
	pm_free(&p);
	inject_ack_l1();
	gmcall_list(W.m, info, 1);
	CHECK(info[0].session_refresher_local);
	evfake_advance(301000);
	i = find_req("UPDATE", 0);
	CHECK(i >= 0);
	if (i >= 0) {
		parse_sent(W.f, i, &p);
		CHECK_STR(H(&p, "Session-Expires"), "600;refresher=uac");	/* "uac" = the sender of this request: us */
		pm_free(&p);
	}
	world_fini();

	/* no Session-Expires at all: no session timer, the call is never cut */
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire(V_INVITE_L1, "Session-Expires: 600;refresher=uac\n", "", (char *)NULL));
	c = W.in_call;
	CHECK_EQ(gmcall_answer(c, &rtp), 0);
	i = find_resp(200, "INVITE", 0);
	parse_sent(W.f, i, &p);
	CHECK_STR(H(&p, "Session-Expires"), "");
	pm_free(&p);
	inject_ack_l1();
	gmcall_list(W.m, info, 1);
	CHECK_EQ(info[0].session_interval, 0);
	evfake_advance(3600000);
	CHECK_EQ(count_req("BYE"), 0);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	world_fini();

	/* an interval below our minimum: 422 with Min-SE before anything rings */
	world_init(PCSCF_B, 5071, 5073, NULL);
	inject_wire(wire(V_INVITE_L1, "Session-Expires: 600;refresher=uac", "Session-Expires: 30;refresher=uac", (char *)NULL));
	i = find_resp(422, "INVITE", 0);
	CHECK(i >= 0);
	CHECK_EQ(W.n_incoming, 0);
	world_fini();
}

static void case_mo_refresher_uas(void)
{
	struct gmcall *c;
	int inv;

	world_init(PCSCF_B, 5071, 5073, NULL);
	c = dial("01051226862", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_tpl(inv, V_200_N1, "$ALLOW", ALLOW_UPD, "refresher=uac", "refresher=uas", (char *)NULL);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	evfake_advance(400000);
	CHECK_EQ(count_req("UPDATE"), 0);	/* the network refreshes */
	/* it does: UPDATE from the network re-arms the timer and is answered with the echo */
	net_req_mo("UPDATE", 710, "Session-Expires: 600;refresher=uac\nSupported: timer\n", NULL);
	{
		int i = find_resp(200, "UPDATE", 0);
		struct pm p;

		CHECK(i >= 0);
		parse_sent(W.f, i, &p);
		CHECK_STR(H(&p, "Session-Expires"), "600;refresher=uac");
		pm_free(&p);
	}
	evfake_advance(520000);
	CHECK_EQ(count_req("BYE"), 0);
	evfake_advance(60000);	/* the network stopped refreshing: BYE at 568 s */
	CHECK_EQ(count_req("BYE"), 1);
	world_fini();

	/* a 2xx without Session-Expires: no timer */
	world_init(PCSCF_B, 5071, 5073, NULL);
	c = dial("01051226862", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_tpl(inv, V_200_N1, "$ALLOW", ALLOW_UPD, "Session-Expires: 600;refresher=uac", "X-Dropped: 1", (char *)NULL);
	CHECK_EQ(gmcall_get_state(c), GMCALL_ST_CONNECTED);
	evfake_advance(3600000);
	CHECK_EQ(count_req("UPDATE") + count_req("BYE"), 0);
	world_fini();
}

static void case_api_lifetime(void)
{
	struct gmcall *c;
	int inv;
	struct gmcall_event *dummy = NULL;

	(void)dummy;
	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_simple(inv, 486, "t1", NULL, NULL);
	CHECK_EQ(R.term, 1);
	/* the terminal event was delivered: the pointer is about to go; API calls on it fail cleanly until it does */
	CHECK_EQ(gmcall_hangup(c), -ESTALE);
	CHECK_EQ(gmcall_set_direction(c, SDP_DIR_SENDONLY), -ESTALE);
	CHECK_EQ(gmcall_count(W.m), 0);
	evfake_advance(1);	/* the reaper runs: memory is released (ASan would flag any later use) */
	world_fini();

	/* release of a dialling call: cancelled silently */
	world_init(PCSCF_A, 1357, 7535, NULL);
	c = dial("114", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_tpl(inv, V_100, (char *)NULL);
	gmcall_release(c);
	CHECK_EQ(count_req("CANCEL"), 1);
	respond_simple(inv, 487, "t1", NULL, NULL);
	evfake_advance(10);
	CHECK_EQ(R.n, 0);	/* released: not even the terminal event is delivered */
	CHECK_EQ(gmcall_count(W.m), 0);
	world_fini();

	/* the manager can be destroyed with calls in every state: silently, no leaks */
	world_init(PCSCF_B, 5071, 5073, NULL);
	c = dial("01051226862", UE_IP, 50010);
	inv = find_req("INVITE", 0);
	respond_tpl(inv, V_180_N1, (char *)NULL);
	dial("114", UE_IP, 50012);
	l1_invite();
	CHECK_EQ(gmcall_count(W.m), 3);
	world_fini();
}

static void case_auto100(void)
{
	g_auto100 = true;
	world_init(PCSCF_B, 5071, 5073, NULL);
	l1_invite();
	CHECK_EQ(count_resp(100, "INVITE"), 1);
	CHECK(find_resp(180, "INVITE", 0) > find_resp(100, "INVITE", 0));
	world_fini();
	g_auto100 = false;
	world_init(PCSCF_B, 5071, 5073, NULL);
	l1_invite();
	CHECK_EQ(count_resp(100, "INVITE"), 1);
	world_fini();
}

static void tune_cp(struct gmcall_cfg *c)
{
	c->contact_params = ";+g.3gpp.icsi-ref=\"" ICSI "\";video";
}

static void case_contact_params(void)
{
	struct pm p;

	world_init(PCSCF_A, 1357, 7535, tune_cp);
	dial("114", UE_IP, 50010);
	parse_sent(W.f, 0, &p);
	CHECK_STR(H(&p, "Contact"), "<sip:01039428657@[" UE_IP "]:8901>;+g.3gpp.icsi-ref=\"" ICSI "\";video");
	pm_free(&p);
	world_fini();
}

static void run_cases2(void)
{
#define RUN2(f) do { int c0 = t_checks, f0 = t_fails; f; printf("%-34s %4d checks, %d failures\n", #f, t_checks - c0, t_fails - f0); } while (0)
	RUN2(case_mo_cancel_pending());
	RUN2(case_mo_cancel_race());
	RUN2(case_mo_cancel_guard());
	RUN2(case_mo_ring_timeout());
	RUN2(case_mo_forked_2xx());
	RUN2(case_mo_stray_2xx());
	RUN2(case_mo_422_retry());
	RUN2(case_mo_failures());
	RUN2(case_mo_hold_resume());
	RUN2(case_mo_glare());
	RUN2(case_mo_remote_reinvite());
	RUN2(case_mt_hold_and_late_offer());
	RUN2(case_mt_local_hold_queued());
	RUN2(case_mt_dialog_requests());
	RUN2(case_mt_anonymous());
	RUN2(case_reg_replaced());
	RUN2(case_reg_down(false));
	RUN2(case_reg_down(true));
	RUN2(case_two_calls());
	RUN2(case_dial_args());
	RUN2(case_mt_misc());
	RUN2(case_mt_record_route());
	RUN2(case_mt_timer_variants());
	RUN2(case_mo_refresher_uas());
	RUN2(case_api_lifetime());
	RUN2(case_contact_params());
	RUN2(case_auto100());
	RUN2(case_malformed());
	RUN2(case_fuzz());
#undef RUN2
}
