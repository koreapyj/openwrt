/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdlib.h>
#include "test.h"
#include "fakeep.h"
#include "../sip/dialog.h"

static const char *R183 =
	"SIP/2.0 183 Session Progress\r\nVia: SIP/2.0/UDP [2001:db8::1]:8901;branch=z9hG4bKx\r\n"
	"Contact: <sip:[2001:4430:4:401::14]:1357;transport=UDP>\r\n"
	"To: <tel:114;phone-context=lguplus.co.kr>;tag=az00_early_A\r\nFrom: <sip:01039428657@lte-lguplus.co.kr>;tag=1663314068\r\n"
	"Call-ID: c1\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: 98\r\n\r\n"
	"v=0\r\no=vIBCF 1 1 IN IP6 2001:4430:4:319::6\r\ns=-\r\nc=IN IP6 2001:4430:4:319::6\r\nt=0 0\r\nm=audio 50344 RTP/AVP 102 101\r\n"
	"a=rtpmap:102 AMR/8000/1\r\na=fmtp:102 octet-align=0; mode-set=7\r\na=rtpmap:101 telephone-event/8000/1\r\n";
static const char *R200 =
	"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP [2001:db8::1]:8901;branch=z9hG4bKx\r\nRequire: timer\r\n"
	"Record-Route: <sip:[2001:4430:4:401::14]:1357;lr>\r\nRecord-Route: <sip:pcscf2.example.com;lr>\r\n"
	"Contact: <sip:[2001:4430:4:401::14]:1357;transport=UDP>\r\n"
	"To: <tel:114;phone-context=lguplus.co.kr>;tag=az00_final_B\r\nFrom: <sip:01039428657@lte-lguplus.co.kr>;tag=1663314068\r\n"
	"Call-ID: c1\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: 98\r\n\r\n"
	"v=0\r\no=vIBCF 2 1 IN IP6 2001:4430:4:319::6\r\ns=-\r\nc=IN IP6 2001:4430:4:319::6\r\nt=0 0\r\nm=audio 50344 RTP/AVP 102 101\r\n"
	"a=rtpmap:102 AMR/8000/1\r\na=fmtp:102 octet-align=0; mode-set=7\r\na=rtpmap:101 telephone-event/8000/1\r\n";

static int feed(struct dlgset *s, const char *raw, struct dlg_ev *ev)
{
	struct sip_msg m;
	int n;

	sip_parse((const uint8_t *)raw, strlen(raw), &m);
	n = dlgset_on_response(s, &m, ev, 4);
	sip_msg_free(&m);
	return n;
}

static int has(const struct dlg_ev *ev, int n, enum dlg_ev_type t)
{
	int i;

	for (i = 0; i < n; i++)
		if (ev[i].type == t)
			return 1;
	return 0;
}

void test_dialog(void)
{
	struct fakeep *f = fakeep_new("d", false, NULL);
	struct dlgset s;
	struct dlg_ev ev[4];
	int n, i, ea = -1, eb = -1;

	CHECK(!dlgset_init(&s, f->ep, "c1", "1663314068", "sip:01039428657@lte-lguplus.co.kr", "tel:114;phone-context=lguplus.co.kr", 1));
	/* the 183 (no Require: 100rel) yields only the SDP notice, never a request */
	n = feed(&s, R183, ev);
	CHECK(n == 1 && ev[0].type == DLG_EV_SDP);
	CHECK(dlgset_bye_target(&s) == NULL);	/* before the 2xx: CANCEL, never BYE on the early dialog */
	n = feed(&s, R200, ev);
	for (i = 0; i < n; i++) if (ev[i].type == DLG_EV_ACK) eb = ev[i].dlg;
	CHECK(eb >= 0 && !strcmp(s.d[eb].remote_tag, "az00_final_B"));
	CHECK(!has(ev, n, DLG_EV_PRACK) && has(ev, n, DLG_EV_SDP));
	for (i = 0; i < n; i++) if (ev[i].dlg >= 0 && !strcmp(s.d[ev[i].dlg].remote_tag, "az00_early_A")) ea = i;
	CHECK(ea < 0);	/* nothing at all for the early dialog */
	CHECK(dlgset_bye_target(&s) == &s.d[eb]);
	CHECK(s.d[0].state == DLG_EARLY && s.d[1].state == DLG_CONFIRMED);
	CHECK_STR(s.d[eb].remote_target, "sip:[2001:4430:4:401::14]:1357;transport=UDP");
	/* UAC route set is the Record-Route list reversed */
	CHECK_EQ(s.d[eb].nroute, 2); CHECK_STR(s.d[eb].route[0], "<sip:pcscf2.example.com;lr>"); CHECK_STR(s.d[eb].route[1], "<sip:[2001:4430:4:401::14]:1357;lr>");
	/* retransmitted 200: ACK again, same dialog, no second SDP notice */
	n = feed(&s, R200, ev);
	CHECK(n == 1 && ev[0].type == DLG_EV_DUP_2XX && ev[0].dlg == eb);
	CHECK_EQ(dlgset_find(&s, "az00_early_A"), 0); CHECK_EQ(dlgset_find(&s, "nope"), -1);

	/* in-dialog request for the confirmed dialog: loose routing, Route lines, tags, CSeq */
	{
		struct buf b;
		struct dlg_req_opts o = { .method = "BYE", .via = "SIP/2.0/UDP [2001:db8::1]:8901;branch=z9hG4bKbye" };
		struct sip_msg m;
		uint32_t cs;

		buf_init(&b, 0);
		CHECK(!dlg_build_request(dlgset_bye_target(&s), &b, &o, &cs));
		CHECK_EQ(cs, 2);
		CHECK(!sip_parse(b.p, b.len, &m));
		CHECK_STR(m.ruri, "sip:[2001:4430:4:401::14]:1357;transport=UDP");
		CHECK_EQ(sip_hdr_count(&m, "Route"), 2); CHECK_STR(sip_hdr(&m, "Route", 0), "<sip:pcscf2.example.com;lr>");
		CHECK_STR(sip_hdr(&m, "To", 0), "<tel:114;phone-context=lguplus.co.kr>;tag=az00_final_B");
		CHECK_STR(sip_hdr(&m, "From", 0), "<sip:01039428657@lte-lguplus.co.kr>;tag=1663314068");
		CHECK_STR(sip_hdr(&m, "CSeq", 0), "2 BYE");
		sip_msg_free(&m); buf_free(&b);
		/* ACK for the 2xx reuses the INVITE's CSeq without consuming one */
		o.method = "ACK"; o.cseq = 1; buf_init(&b, 0);
		CHECK(!dlg_build_request(dlgset_bye_target(&s), &b, &o, &cs)); CHECK_EQ(cs, 1);
		CHECK(strstr(buf_cstr(&b), "CSeq: 1 ACK\r\n"));
		buf_free(&b);
		CHECK_EQ(dlg_next_cseq(dlgset_bye_target(&s)), 3);
	}
	/* response matching */
	{
		struct sip_msg m;

		sip_parse((const uint8_t *)R200, strlen(R200), &m);
		CHECK(dlg_match_response(&s.d[eb], &m)); CHECK(!dlg_match_response(&s.d[ea < 0 ? 0 : 0], &m));
		sip_msg_free(&m);
	}
	dlgset_release(&s);

	/* 100rel provisional: PRACK on that dialog, once per RSeq */
	{
		static const char *P =
			"SIP/2.0 180 Ringing\r\nTo: <tel:1>;tag=T1\r\nFrom: <sip:a@b>;tag=f\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n"
			"Require: 100rel\r\nRSeq: 7\r\nContact: <sip:x@y>\r\n\r\n";
		dlgset_init(&s, f->ep, "c1", "f", "sip:a@b", "tel:1", 1);
		n = feed(&s, P, ev); CHECK(n == 1 && ev[0].type == DLG_EV_PRACK && ev[0].rseq == 7 && ev[0].dlg == 0);
		n = feed(&s, P, ev); CHECK_EQ(n, 0);
		CHECK(dlgset_bye_target(&s) == NULL);
		/* a different To tag is a different early dialog, with its own PRACK */
		{
			static const char *P2 =
				"SIP/2.0 183 Progress\r\nTo: <tel:1>;tag=T2\r\nFrom: <sip:a@b>;tag=f\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n"
				"Require: 100rel\r\nRSeq: 7\r\nContact: <sip:x@y>\r\n\r\n";

			n = feed(&s, P2, ev); CHECK(n == 1 && ev[0].type == DLG_EV_PRACK && ev[0].dlg == 1);
		}
		/* responses to other transactions are ignored */
		{
			static const char *PR = "SIP/2.0 200 OK\r\nTo: <tel:1>;tag=T3\r\nFrom: <sip:a@b>;tag=f\r\nCall-ID: c1\r\nCSeq: 2 PRACK\r\n\r\n";
			static const char *NT = "SIP/2.0 180 Ringing\r\nTo: <tel:1>\r\nFrom: <sip:a@b>;tag=f\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n\r\n";

			CHECK_EQ(feed(&s, PR, ev), 0); CHECK_EQ(feed(&s, NT, ev), 0); CHECK_EQ(dlgset_find(&s, "T3"), -1);
		}
		dlgset_release(&s);
	}
	/* 486: no dialog, ACK is the transaction's */
	{
		static const char *F = "SIP/2.0 486 Busy Here\r\nTo: <tel:1>;tag=T9\r\nFrom: <sip:a@b>;tag=f\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n\r\n";

		dlgset_init(&s, f->ep, "c1", "f", "sip:a@b", "tel:1", 1);
		CHECK_EQ(feed(&s, F, ev), 0); CHECK_EQ(s.final_status, 486); CHECK(dlgset_bye_target(&s) == NULL); CHECK_EQ(dlgset_find(&s, "T9"), -1);
		dlgset_release(&s);
	}
	/* too many forks: bounded, no overflow */
	{
		char raw[400];

		dlgset_init(&s, f->ep, "c1", "f", "sip:a@b", "tel:1", 1);
		for (i = 0; i < DLG_MAX_DIALOGS + 2; i++) {
			snprintf(raw, sizeof(raw), "SIP/2.0 180 R\r\nTo: <tel:1>;tag=F%d\r\nFrom: <sip:a@b>;tag=f\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\n\r\n", i);
			feed(&s, raw, ev);
		}
		CHECK_EQ(dlgset_find(&s, "F7"), 7); CHECK_EQ(dlgset_find(&s, "F8"), -1);
		dlgset_release(&s);
	}

	/* ---- UAS dialog from an incoming INVITE ---- */
	{
		static const char *INV =
			"INVITE sip:01039428657@[2001:db8::9]:8931 SIP/2.0\r\nVia: SIP/2.0/UDP [2001:4430:4:405::43]:5071;branch=z9hG4bKaa\r\n"
			"Record-Route: <sip:rr1;lr>, <sip:rr2;lr>\r\n"
			"Contact: <sip:[2001:4430:4:405::43]:5071>\r\nTo: <tel:01039428657;phone-context=lte-lguplus.co.kr>\r\n"
			"From: <sip:01051226862@lte-lguplus.co.kr>;tag=kmnham74\r\nCall-ID: abc\r\nCSeq: 9203 INVITE\r\n\r\n";
		struct sip_dialog d;
		struct sip_msg m, bye;
		char ruri[256];
		struct buf rh;

		sip_parse((const uint8_t *)INV, strlen(INV), &m);
		CHECK(!dlg_init_uas(&d, f->ep, &m, "ourtag"));
		CHECK_STR(d.remote_tag, "kmnham74"); CHECK_STR(d.local_tag, "ourtag"); CHECK_STR(d.remote_uri, "sip:01051226862@lte-lguplus.co.kr");
		CHECK_STR(d.local_uri, "tel:01039428657;phone-context=lte-lguplus.co.kr"); CHECK_STR(d.remote_target, "sip:[2001:4430:4:405::43]:5071");
		CHECK_EQ(d.nroute, 2); CHECK_STR(d.route[0], "<sip:rr1;lr>"); CHECK_STR(d.route[1], "<sip:rr2;lr>");	/* UAS: in order */
		CHECK_EQ(d.remote_cseq, 9203); CHECK(d.state == DLG_EARLY);
		dlg_confirm(&d); CHECK(d.state == DLG_CONFIRMED);
		CHECK_EQ(f->ep->refs, 2);	/* the dialog pins the endpoint */
		/* incoming BYE matches with swapped tags, CSeq must grow */
		{
			static const char *BYE = "BYE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKb\r\nFrom: <sip:01051226862@lte-lguplus.co.kr>;tag=kmnham74\r\n"
				"To: <tel:01039428657;phone-context=lte-lguplus.co.kr>;tag=ourtag\r\nCall-ID: abc\r\nCSeq: 9204 BYE\r\n\r\n";
			static const char *OTHER = "BYE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bKb\r\nFrom: <sip:01051226862@lte-lguplus.co.kr>;tag=zzz\r\n"
				"To: <tel:01039428657;phone-context=lte-lguplus.co.kr>;tag=ourtag\r\nCall-ID: abc\r\nCSeq: 9205 BYE\r\n\r\n";

			sip_parse((const uint8_t *)BYE, strlen(BYE), &bye);
			CHECK(dlg_match_request(&d, &bye)); CHECK(!dlg_check_remote_cseq(&d, &bye)); CHECK_EQ(d.remote_cseq, 9204);
			CHECK(dlg_check_remote_cseq(&d, &bye) < 0);	/* replayed */
			sip_msg_free(&bye);
			sip_parse((const uint8_t *)OTHER, strlen(OTHER), &bye);
			CHECK(!dlg_match_request(&d, &bye)); sip_msg_free(&bye);
		}
		/* our BYE goes through the route set in order, R-URI is the remote target */
		buf_init(&rh, 1024);
		CHECK(!dlg_route(&d, ruri, sizeof(ruri), &rh)); CHECK_STR(ruri, "sip:[2001:4430:4:405::43]:5071");
		CHECK_STR(buf_cstr(&rh), "Route: <sip:rr1;lr>\r\nRoute: <sip:rr2;lr>\r\n");
		buf_free(&rh);
		/* strict router first in the route set: R-URI = that router, target appended last */
		strcpy(d.route[0], "<sip:strict.example.com>");
		buf_init(&rh, 1024);
		CHECK(!dlg_route(&d, ruri, sizeof(ruri), &rh)); CHECK_STR(ruri, "sip:strict.example.com");
		CHECK_STR(buf_cstr(&rh), "Route: <sip:rr2;lr>\r\nRoute: <sip:[2001:4430:4:405::43]:5071>\r\n");
		buf_free(&rh);
		/* target refresh from a re-INVITE Contact */
		{
			static const char *RE = "INVITE sip:x SIP/2.0\r\nContact: <sip:newtarget@192.0.2.1>\r\nCSeq: 9300 INVITE\r\n\r\n";

			sip_parse((const uint8_t *)RE, strlen(RE), &bye);
			CHECK(!dlg_refresh_target(&d, &bye)); CHECK_STR(d.remote_target, "sip:newtarget@192.0.2.1");
			sip_msg_free(&bye);
		}
		dlg_release(&d);
		CHECK_EQ(f->ep->refs, 1);
		sip_msg_free(&m);
	}
	fakeep_free(f);
}
