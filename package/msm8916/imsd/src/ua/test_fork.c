/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include "test_ua.h"

#define REASON "SIP;cause=200;text=\"Call completed elsewhere\""
#define SDP "v=0\r\no=- 1 1 IN IP4 192.168.68.1\r\ns=-\r\nc=IN IP4 192.168.68.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 8\r\n"

static void setup5(struct uaw *w, reg_id_t id[6])
{
	int k;

	uaw_init(w, NULL, false);
	for (k = 1; k <= 5; k++)
		id[k] = dev_register(w, k);
	fakeep_clear(w->f);
}

static struct lan_fork *start(struct uaw *w, struct fork_rec *fr, const struct lan_fork_opts *o, const char *method)
{
	struct lan_req q;

	mk_invite_req(&q, SDP);
	q.method = method;
	if (strcmp(method, "INVITE")) {
		q.content_type = "text/plain; charset=utf-8";
		q.body = (const uint8_t *)"hi";
		q.body_len = 2;
	}
	return lan_fork_request(w->lan, &q, o, fork_cb, fr, NULL);
}

/* device k answers its first request of that method */
static void rep(struct uaw *w, int k, const char *method, int status)
{
	char tag[16];

	snprintf(tag, sizeof(tag), "tag%d", k);
	CHECK(dev_reply(w, k, method, status, tag));
}

static int cancels_to(struct uaw *w, int k)
{
	int n = 0, i;

	while ((i = find_sent(w->f, dev_ip(k), 5060, "CANCEL", n)) >= 0)
		n++;
	return n;
}

static int count_ev(const struct fork_rec *r, enum lan_fork_ev_type t)
{
	return r->count[t];
}

/* ---- A: all ring, one answers ---- */
static void t_winner(void)
{
	struct uaw w;
	struct fork_rec fr = {0};
	reg_id_t id[6];
	struct lan_fork *f;
	int k, iw, ic, i;
	char v[300], b1[80], b2[80];
	struct sip_msg inv, can;

	setup5(&w, id);
	f = start(&w, &fr, NULL, "INVITE");
	CHECK(f != NULL);
	CHECK_EQ(lan_fork_branches(f), 5);
	CHECK_EQ(count_sent(w.f, "INVITE"), 5);
	for (k = 1; k <= 5; k++)
		rep(&w, k, "INVITE", 180);
	CHECK_EQ(count_ev(&fr, LAN_FORK_PROVISIONAL), 5);
	CHECK_EQ(fr.n, 5);
	rep(&w, 3, "INVITE", 200);
	iw = fr_find(&fr, LAN_FORK_WINNER, 0);
	ic = fr_find(&fr, LAN_FORK_COMPLETE, 0);
	CHECK(iw == 5 && ic == 6);
	CHECK_EQ(fr.ev[iw].id, id[3]); CHECK_EQ(fr.ev[iw].status, 200); CHECK(fr.ev[iw].had_dlg);
	CHECK_EQ(fr.ev[ic].status, 200); CHECK_EQ(fr.ev[ic].winner, id[3]); CHECK_EQ(fr.ev[ic].nok, 1);
	CHECK_EQ(fr.ev[ic].nresults, 5);
	/* the dialog of the winner, ready for ACK/BYE */
	CHECK_EQ(fr.ndlg, 1);
	CHECK_STR(fr.dlg[0].remote_tag, "tag3");
	CHECK_STR(fr.dlg[0].remote_target, "sip:u3@192.168.68.13:5060");
	CHECK_STR(fr.dlg[0].call_id, lan_fork_call_id(f));
	CHECK(fr.dlg[0].is_uac); CHECK_EQ(fr.dlg[0].state, DLG_CONFIRMED);
	CHECK_EQ(fr.dlg[0].local_cseq, 1);
	CHECK(strstr(fr.dlg[0].local_uri, "sip:+821012345678@") == fr.dlg[0].local_uri);
	/* 4 CANCELs with Reason, none to the winner; same branch / Call-ID / R-URI as their INVITE */
	CHECK_EQ(cancels_to(&w, 3), 0);
	for (k = 1; k <= 5; k++) {
		int ii, cc;

		if (k == 3)
			continue;
		CHECK_EQ(cancels_to(&w, k), 1);
		cc = find_sent(w.f, dev_ip(k), 5060, "CANCEL", 0);
		ii = find_sent(w.f, dev_ip(k), 5060, "INVITE", 0);
		CHECK_STR(sent_hdr(w.f, cc, "Reason", v, sizeof(v)), REASON);
		CHECK(!fakeep_parse(w.f, ii, &inv) && !fakeep_parse(w.f, cc, &can));
		CHECK_STR(can.ruri, inv.ruri);
		CHECK_STR(sip_hdr(&can, "Call-ID", 0), sip_hdr(&inv, "Call-ID", 0));
		CHECK_STR(sip_hdr(&can, "CSeq", 0), "1 CANCEL");
		sip_top_via(&inv, &(struct sip_via){0});
		{
			struct sip_via v1, v2;

			sip_top_via(&inv, &v1);
			sip_top_via(&can, &v2);
			snprintf(b1, sizeof(b1), "%s", v1.branch);
			snprintf(b2, sizeof(b2), "%s", v2.branch);
		}
		CHECK_STR(b1, b2);
		sip_msg_free(&inv); sip_msg_free(&can);
	}
	/* the losers answer: 200 to CANCEL, 487 to INVITE: absorbed, ACKed by the transaction layer */
	for (k = 1; k <= 5; k++) {
		if (k == 3)
			continue;
		CHECK(dev_reply(&w, k, "CANCEL", 200, NULL));
		rep(&w, k, "INVITE", 487);
	}
	CHECK_EQ(count_ev(&fr, LAN_FORK_WINNER), 1);
	CHECK_EQ(count_ev(&fr, LAN_FORK_COMPLETE), 1);
	CHECK_EQ(count_ev(&fr, LAN_FORK_BRANCH_FINAL), 0);
	CHECK_EQ(fr.n, 7);
	for (k = 1; k <= 5; k++)
		if (k != 3) {
			i = 0;
			while (find_sent(w.f, dev_ip(k), 5060, "ACK", i) >= 0)
				i++;
			CHECK_EQ(i, 1);
		}
	/* retransmitted 2xx of the winner: reported so the caller can ACK again */
	rep(&w, 3, "INVITE", 200);
	i = fr_find(&fr, LAN_FORK_2XX_RETRANS, 0);
	CHECK(i >= 0 && fr.ev[i].is_winner);
	CHECK_EQ(count_ev(&fr, LAN_FORK_WINNER), 1);
	/* cancelling after the call was won is a no-op */
	lan_fork_cancel(f);
	CHECK_EQ(cancels_to(&w, 1), 1);
	CHECK_EQ(count_ev(&fr, LAN_FORK_DONE), 0);
	evfake_advance(60000);
	CHECK_EQ(count_ev(&fr, LAN_FORK_DONE), 1);
	CHECK_EQ(fr.ev[fr.n - 1].type, LAN_FORK_DONE);
	/* the registrar learned who answers */
	CHECK(reg_find(lan_registrar(w.lan), id[3])->answered);
	fr_release(&fr);
	uaw_fini(&w);
}

/* ---- B: CANCEL-pending path ---- */
static void t_cancel_pending(void)
{
	struct uaw w;
	struct fork_rec fr = {0};
	reg_id_t id[6];
	struct lan_fork *f;
	char v[200];
	int k;

	setup5(&w, id);
	f = start(&w, &fr, NULL, "INVITE");
	CHECK(f != NULL);
	/* dev 1 answers with a bare 200 before anyone else sent anything */
	rep(&w, 1, "INVITE", 200);
	CHECK_EQ(count_ev(&fr, LAN_FORK_WINNER), 1);
	CHECK_EQ(fr.n, 2);
	for (k = 2; k <= 5; k++)
		CHECK_EQ(cancels_to(&w, k), 0);	/* nothing sent yet: RFC 3261 9.1 forbids CANCEL before a provisional */
	/* dev 2 finally shows life with a 100: the pending CANCEL goes out, with Reason */
	rep(&w, 2, "INVITE", 100);
	CHECK_EQ(cancels_to(&w, 2), 1);
	CHECK_STR(sent_hdr(w.f, find_sent(w.f, dev_ip(2), 5060, "CANCEL", 0), "Reason", v, sizeof(v)), REASON);
	/* dev 3 sends a final before any provisional: the pending CANCEL is dropped */
	rep(&w, 3, "INVITE", 486);
	CHECK_EQ(cancels_to(&w, 3), 0);
	/* dev 4 / 5: nothing at all. They time out; no event, no CANCEL */
	evfake_advance(32000);
	CHECK_EQ(cancels_to(&w, 4), 0);
	CHECK_EQ(cancels_to(&w, 5), 0);
	/* dev 2 never answered its CANCEL: its INVITE transaction timed out 64*T1 after the CANCEL (RFC 3261 9.1,
	 * txn layer) and the fork ended silently: the winner was reported once, then only DONE */
	CHECK_EQ(fr.n, 3);
	CHECK_EQ(count_ev(&fr, LAN_FORK_DONE), 1);
	CHECK_EQ(txn_layer_count(w.tl), 0);	/* no transaction slot left behind */
	evfake_advance(60000);
	CHECK_EQ(count_ev(&fr, LAN_FORK_DONE), 1);
	CHECK(!reg_find(lan_registrar(w.lan), id[4])->reachable);	/* silent device flagged by its Timer B */
	fr_release(&fr);
	uaw_fini(&w);
}

/* ---- C: 486 does not stop the others ---- */
static void t_busy_keeps_ringing(void)
{
	struct uaw w;
	struct fork_rec fr = {0};
	reg_id_t id[6];
	struct lan_fork *f;
	int k, i;

	setup5(&w, id);
	f = start(&w, &fr, NULL, "INVITE");
	CHECK(f != NULL);
	for (k = 1; k <= 5; k++)
		rep(&w, k, "INVITE", 180);
	rep(&w, 1, "INVITE", 486);
	i = fr_find(&fr, LAN_FORK_BRANCH_FINAL, 0);
	CHECK(i >= 0); CHECK_EQ(fr.ev[i].id, id[1]); CHECK_EQ(fr.ev[i].status, 486); CHECK_EQ(fr.ev[i].cause, LAN_BR_RESPONSE);
	CHECK_EQ(count_ev(&fr, LAN_FORK_COMPLETE), 0);
	CHECK_EQ(count_sent(w.f, "CANCEL"), 0);
	rep(&w, 4, "INVITE", 603);		/* even a 6xx from one phone does not kill the others (documented deviation) */
	CHECK_EQ(count_ev(&fr, LAN_FORK_COMPLETE), 0);
	CHECK_EQ(count_sent(w.f, "CANCEL"), 0);
	rep(&w, 5, "INVITE", 200);
	CHECK_EQ(count_ev(&fr, LAN_FORK_WINNER), 1);
	CHECK_EQ(count_sent(w.f, "CANCEL"), 2);	/* 2 and 3 only: 1 and 4 are finished */
	CHECK_EQ(cancels_to(&w, 2), 1); CHECK_EQ(cancels_to(&w, 3), 1);
	i = fr_find(&fr, LAN_FORK_COMPLETE, 0);
	CHECK_EQ(fr.ev[i].status, 200);
	CHECK_EQ(fr.ev[i].res[0].status, 486);	/* results are ordered by binding id */
	evfake_advance(60000);
	CHECK_EQ(count_ev(&fr, LAN_FORK_DONE), 1);
	fr_release(&fr);
	uaw_fini(&w);
}

/* ---- D: aggregation ---- */
static void agg_case(const int st[5], int expect, enum lan_branch_cause only_cause)
{
	struct uaw w;
	struct fork_rec fr = {0};
	reg_id_t id[6];
	struct lan_fork *f;
	int k, i;

	setup5(&w, id);
	f = start(&w, &fr, NULL, "INVITE");
	CHECK(f != NULL);
	for (k = 1; k <= 5; k++)
		if (st[k - 1])
			rep(&w, k, "INVITE", st[k - 1]);
	evfake_advance(33000);		/* silent ones hit Timer B */
	i = fr_find(&fr, LAN_FORK_COMPLETE, 0);
	if (i < 0) {
		CHECK(i >= 0);
	} else {
		if (fr.ev[i].status != expect)
			printf("  aggregate of %d %d %d %d %d: got %d\n", st[0], st[1], st[2], st[3], st[4], fr.ev[i].status);
		CHECK_EQ(fr.ev[i].status, expect);
		CHECK_EQ(fr.ev[i].nok, 0);
		CHECK_EQ(fr.ev[i].nresults, 5);
		CHECK_EQ(count_ev(&fr, LAN_FORK_COMPLETE), 1);
		CHECK_EQ(count_ev(&fr, LAN_FORK_WINNER), 0);
		CHECK_EQ(count_ev(&fr, LAN_FORK_BRANCH_FINAL), 5);
		if (only_cause != LAN_BR_NONE)
			for (k = 0; k < 5; k++)
				CHECK_EQ(fr.ev[i].res[k].cause, only_cause);
	}
	evfake_advance(40000);
	CHECK_EQ(count_ev(&fr, LAN_FORK_DONE), 1);
	fr_release(&fr);
	uaw_fini(&w);
}

static void t_aggregate(void)
{
	static const int all486[5] = { 486, 486, 486, 486, 486 };
	static const int mixed1[5] = { 486, 404, 480, 503, 408 };
	static const int has6xx[5] = { 603, 486, 404, 500, 480 };
	static const int fourxx[5] = { 500, 503, 404, 480, 480 };
	static const int fivexx[5] = { 503, 500, 502, 503, 500 };
	static const int silent[5] = { 0, 0, 0, 0, 0 };
	static const int one500[5] = { 0, 0, 500, 0, 0 };
	static const int redirect[5] = { 0, 0, 302, 0, 0 };
	static const int busy_timeouts[5] = { 0, 486, 0, 0, 0 };
	static const int e408[5] = { 408, 0, 0, 0, 0 };

	agg_case(all486, 486, LAN_BR_RESPONSE);
	agg_case(mixed1, 486, LAN_BR_NONE);	/* someone is there and busy: say so */
	agg_case(has6xx, 603, LAN_BR_NONE);	/* 6xx first */
	agg_case(fourxx, 404, LAN_BR_NONE);	/* otherwise the lowest 4xx before any 5xx */
	agg_case(fivexx, 500, LAN_BR_NONE);
	agg_case(silent, 408, LAN_BR_TIMEOUT);	/* nobody answered at all */
	agg_case(one500, 500, LAN_BR_NONE);	/* a real answer beats four timeouts */
	agg_case(redirect, 480, LAN_BR_NONE);	/* 3xx are not followed: reported as 480 */
	agg_case(busy_timeouts, 486, LAN_BR_NONE);
	agg_case(e408, 408, LAN_BR_NONE);
}

/* ---- E: the caller cancels mid-ring ---- */
static void t_caller_cancel(void)
{
	struct uaw w;
	struct fork_rec fr = {0};
	reg_id_t id[6];
	struct lan_fork *f;
	int k, i;
	char v[100];

	setup5(&w, id);
	f = start(&w, &fr, NULL, "INVITE");
	for (k = 1; k <= 5; k++)
		rep(&w, k, "INVITE", 180);
	CHECK_EQ(fr.n, 5);
	lan_fork_cancel(f);
	lan_fork_cancel(f);		/* idempotent */
	CHECK_EQ(count_sent(w.f, "CANCEL"), 5);
	for (k = 1; k <= 5; k++)
		CHECK_EQ(cancels_to(&w, k), 1);
	CHECK_STR(sent_hdr(w.f, find_sent(w.f, dev_ip(1), 5060, "CANCEL", 0), "Reason", v, sizeof(v)), "");
	/* dev 2's 200 crosses our CANCEL: extra, must be ACKed + BYEd by the call module */
	rep(&w, 2, "INVITE", 200);
	i = fr_find(&fr, LAN_FORK_EXTRA_2XX, 0);
	CHECK(i >= 0); CHECK_EQ(fr.ev[i].id, id[2]); CHECK(fr.ev[i].had_dlg);
	CHECK_EQ(count_ev(&fr, LAN_FORK_WINNER), 0);
	for (k = 1; k <= 5; k++) {
		if (k == 2)
			continue;
		CHECK(dev_reply(&w, k, "CANCEL", 200, NULL));
		rep(&w, k, "INVITE", 487);
	}
	CHECK_EQ(count_ev(&fr, LAN_FORK_COMPLETE), 0);
	CHECK_EQ(count_ev(&fr, LAN_FORK_BRANCH_FINAL), 0);	/* the caller knows: nothing more than the extra */
	CHECK_EQ(count_ev(&fr, LAN_FORK_PROVISIONAL), 5);
	evfake_advance(60000);
	CHECK_EQ(count_ev(&fr, LAN_FORK_DONE), 1);
	fr_release(&fr);
	uaw_fini(&w);
}

/* ---- F: binding removed / expired mid-fork ---- */
static void t_binding_gone(void)
{
	struct uaw w;
	struct fork_rec fr = {0};
	reg_id_t id[6];
	struct lan_fork *f;
	int k, i;
	char ct[128];

	setup5(&w, id);
	f = start(&w, &fr, NULL, "INVITE");
	for (k = 1; k <= 5; k++)
		rep(&w, k, "INVITE", 180);
	/* device 2 un-registers while ringing */
	snprintf(ct, sizeof(ct), "<sip:u2@%s:5060>;expires=0", dev_ip(2));
	uaw_rx(&w, dev_ip(2), 5060, mk_register(dev_ip(2), ct, 2, "dev2-reg", -1, NULL));
	i = fr_find(&fr, LAN_FORK_BRANCH_FINAL, 0);
	CHECK(i >= 0); CHECK_EQ(fr.ev[i].id, id[2]); CHECK_EQ(fr.ev[i].status, 480); CHECK_EQ(fr.ev[i].cause, LAN_BR_REMOVED);
	CHECK_EQ(cancels_to(&w, 2), 1);		/* its phone stops ringing */
	CHECK_EQ(count_ev(&fr, LAN_FORK_COMPLETE), 0);
	rep(&w, 2, "INVITE", 487);		/* its answer is absorbed */
	CHECK_EQ(count_ev(&fr, LAN_FORK_BRANCH_FINAL), 1);
	for (k = 1; k <= 5; k++)
		if (k != 2)
			rep(&w, k, "INVITE", k == 4 ? 603 : 486);
	i = fr_find(&fr, LAN_FORK_COMPLETE, 0);
	CHECK(i >= 0); CHECK_EQ(fr.ev[i].status, 603); CHECK_EQ(fr.ev[i].nresults, 5);
	evfake_advance(60000);
	CHECK_EQ(count_ev(&fr, LAN_FORK_DONE), 1);
	fr_release(&fr);
	uaw_fini(&w);

	/* expiry; the removed device's late 200 is an extra */
	memset(&fr, 0, sizeof(fr));
	uaw_init(&w, NULL, false);
	for (k = 1; k <= 5; k++) {
		char cid[32];

		snprintf(ct, sizeof(ct), "<sip:u%d@%s:5060>;expires=%d", k, dev_ip(k), k == 2 ? 60 : 600);
		snprintf(cid, sizeof(cid), "dev%d-reg", k);
		uaw_rx(&w, dev_ip(k), 5060, mk_register(dev_ip(k), ct, 1, cid, -1, NULL));
	}
	fakeep_clear(w.f);
	f = start(&w, &fr, NULL, "INVITE");
	CHECK(f != NULL);
	for (k = 1; k <= 5; k++)
		rep(&w, k, "INVITE", 180);
	evfake_advance(60000);
	CHECK_EQ(reg_count(lan_registrar(w.lan)), 4);
	CHECK_EQ(w.bev[w.nbev - 1].why, REG_RM_EXPIRED);
	i = fr_find(&fr, LAN_FORK_BRANCH_FINAL, 0);
	CHECK(i >= 0 && fr.ev[i].cause == LAN_BR_REMOVED);
	CHECK_EQ(cancels_to(&w, 2), 1);
	rep(&w, 2, "INVITE", 200);		/* crossed */
	CHECK_EQ(count_ev(&fr, LAN_FORK_EXTRA_2XX), 1);
	CHECK_EQ(count_ev(&fr, LAN_FORK_WINNER), 0);
	rep(&w, 3, "INVITE", 200);		/* a real winner afterwards still wins */
	CHECK_EQ(count_ev(&fr, LAN_FORK_WINNER), 1);
	evfake_advance(60000);
	fr_release(&fr);
	uaw_fini(&w);
}

/* ---- G: two 2xx race ---- */
static void t_extra_2xx(void)
{
	struct uaw w;
	struct fork_rec fr = {0};
	reg_id_t id[6];
	int k, i, iw, ie;
	struct buf b;
	struct dlg_req_opts o;
	struct sip_msg m;
	char via[160], br[SIP_BRANCH_LEN];

	fr.take = true;				/* exercise the take_dlg ownership path here */
	setup5(&w, id);
	CHECK(start(&w, &fr, NULL, "INVITE") != NULL);
	for (k = 1; k <= 5; k++)
		rep(&w, k, "INVITE", 180);
	rep(&w, 1, "INVITE", 200);
	rep(&w, 2, "INVITE", 200);		/* both answered before the CANCEL got there */
	iw = fr_find(&fr, LAN_FORK_WINNER, 0);
	ie = fr_find(&fr, LAN_FORK_EXTRA_2XX, 0);
	CHECK(iw >= 0 && ie > iw);
	CHECK_EQ(fr.ev[iw].id, id[1]); CHECK_EQ(fr.ev[ie].id, id[2]);
	CHECK_EQ(count_ev(&fr, LAN_FORK_EXTRA_2XX), 1);
	CHECK_EQ(count_ev(&fr, LAN_FORK_WINNER), 1);
	CHECK_EQ(count_ev(&fr, LAN_FORK_COMPLETE), 1);
	CHECK_EQ(fr.ndlg, 2);
	CHECK_STR(fr.dlg[1].remote_tag, "tag2");
	CHECK_STR(fr.dlg[0].call_id, fr.dlg[1].call_id);	/* same Call-ID, different dialog */
	/* the call module can build the ACK and the BYE for it from the dialog alone */
	sip_new_branch(br);
	sip_via_make(via, sizeof(via), "UDP", &w.f->ep->advertised, br, false);
	memset(&o, 0, sizeof(o));
	o.method = "ACK";
	o.cseq = fr.dlg[1].local_cseq;
	o.via = via;
	buf_init(&b, 0);
	CHECK(!dlg_build_request(&fr.dlg[1], &b, &o, NULL));
	CHECK(!sip_parse(b.p, b.len, &m));
	CHECK_STR(m.method, "ACK"); CHECK_STR(m.ruri, "sip:u2@192.168.68.12:5060");
	CHECK(strstr(sip_hdr(&m, "To", 0), "tag=tag2") != NULL);
	CHECK_STR(sip_hdr(&m, "CSeq", 0), "1 ACK");
	sip_msg_free(&m); buf_free(&b);
	o.method = "BYE"; o.cseq = 0;
	buf_init(&b, 0);
	CHECK(!dlg_build_request(&fr.dlg[1], &b, &o, NULL));
	CHECK(!sip_parse(b.p, b.len, &m));
	CHECK_STR(m.method, "BYE");
	CHECK_STR(sip_hdr(&m, "CSeq", 0), "2 BYE");
	sip_msg_free(&m); buf_free(&b);
	/* a retransmission of the extra 2xx is told apart */
	rep(&w, 2, "INVITE", 200);
	i = fr_find(&fr, LAN_FORK_2XX_RETRANS, 0);
	CHECK(i >= 0 && !fr.ev[i].is_winner && fr.ev[i].id == id[2]);
	CHECK_EQ(count_ev(&fr, LAN_FORK_EXTRA_2XX), 1);
	/* a 2xx with another To tag from the same branch is another dialog */
	CHECK(dev_reply(&w, 2, "INVITE", 200, "other-tag"));
	CHECK_EQ(count_ev(&fr, LAN_FORK_EXTRA_2XX), 2);
	/* the winner is not cancelled, the third ringing device is */
	CHECK_EQ(cancels_to(&w, 1), 0);
	CHECK_EQ(cancels_to(&w, 3), 1);
	evfake_advance(60000);
	CHECK_EQ(count_ev(&fr, LAN_FORK_DONE), 1);
	fr_release(&fr);
	uaw_fini(&w);
}

/* ---- H: MESSAGE fan-out ---- */
static void t_message(void)
{
	struct uaw w;
	struct fork_rec fr = {0};
	reg_id_t id[6];
	struct lan_fork *f;
	int i;
	struct lan_fork_opts o;
	reg_id_t ex[1];
	struct sip_msg m;
	static const int st[5] = { 200, 405, 0, 415, 200 };
	int k;

	setup5(&w, id);
	f = start(&w, &fr, NULL, "MESSAGE");
	CHECK(f != NULL);
	CHECK_EQ(count_sent(w.f, "MESSAGE"), 5);
	CHECK(!fakeep_parse(w.f, 0, &m));
	CHECK_STR(sip_hdr(&m, "Content-Type", 0), "text/plain; charset=utf-8");
	CHECK_STR(sip_hdr(&m, "CSeq", 0), "1 MESSAGE");
	sip_msg_free(&m);
	for (k = 1; k <= 5; k++)
		if (st[k - 1])
			rep(&w, k, "MESSAGE", st[k - 1]);
	CHECK_EQ(count_ev(&fr, LAN_FORK_BRANCH_FINAL), 4);
	CHECK_EQ(count_ev(&fr, LAN_FORK_COMPLETE), 0);	/* waits for the silent one */
	CHECK_EQ(count_sent(w.f, "CANCEL"), 0);
	evfake_advance(33000);
	i = fr_find(&fr, LAN_FORK_COMPLETE, 0);
	CHECK(i >= 0);
	CHECK_EQ(fr.ev[i].status, 200); CHECK_EQ(fr.ev[i].nok, 2); CHECK_EQ(fr.ev[i].nresults, 5);
	CHECK_EQ(fr.ev[i].res[0].status, 200); CHECK_EQ(fr.ev[i].res[1].status, 405);
	CHECK_EQ(fr.ev[i].res[2].status, 408); CHECK_EQ(fr.ev[i].res[2].cause, LAN_BR_TIMEOUT);
	CHECK_EQ(fr.ev[i].res[3].status, 415); CHECK_EQ(fr.ev[i].res[4].status, 200);
	CHECK_EQ(count_ev(&fr, LAN_FORK_WINNER), 0);
	CHECK_EQ(count_ev(&fr, LAN_FORK_DONE), 1);
	uaw_fini(&w);

	/* nobody accepts */
	memset(&fr, 0, sizeof(fr));
	setup5(&w, id);
	f = start(&w, &fr, NULL, "MESSAGE");
	rep(&w, 1, "MESSAGE", 404); rep(&w, 2, "MESSAGE", 405); rep(&w, 3, "MESSAGE", 415);
	rep(&w, 4, "MESSAGE", 500); rep(&w, 5, "MESSAGE", 486);
	i = fr_find(&fr, LAN_FORK_COMPLETE, 0);
	CHECK(i >= 0); CHECK_EQ(fr.ev[i].status, 486); CHECK_EQ(fr.ev[i].nok, 0);
	evfake_advance(40000);
	CHECK_EQ(count_ev(&fr, LAN_FORK_DONE), 1);
	uaw_fini(&w);

	/* exclusion and Allow filter */
	memset(&fr, 0, sizeof(fr));
	setup5(&w, id);
	ex[0] = id[1];
	memset(&o, 0, sizeof(o));
	o.exclude = ex;
	o.nexclude = 1;
	f = start(&w, &fr, &o, "MESSAGE");
	CHECK_EQ(lan_fork_branches(f), 4);
	CHECK_EQ(find_sent(w.f, dev_ip(1), 5060, "MESSAGE", 0), -1);
	lan_fork_detach(f);			/* no further events, no crash at the end */
	for (k = 2; k <= 5; k++)
		rep(&w, k, "MESSAGE", 200);
	CHECK_EQ(fr.n, 0);
	evfake_advance(40000);
	uaw_fini(&w);

	memset(&fr, 0, sizeof(fr));
	setup5(&w, id);
	{
		char ct[128];

		snprintf(ct, sizeof(ct), "<sip:u2@%s:5060>;expires=600", dev_ip(2));
		uaw_rx(&w, dev_ip(2), 5060, mk_register(dev_ip(2), ct, 2, "dev2-reg", -1,
			"Allow: INVITE, ACK, CANCEL, BYE, OPTIONS\r\n"));
		fakeep_clear(w.f);
	}
	f = start(&w, &fr, NULL, "MESSAGE");
	CHECK_EQ(lan_fork_branches(f), 4);	/* dev 2 said it does not do MESSAGE */
	CHECK_EQ(find_sent(w.f, dev_ip(2), 5060, "MESSAGE", 0), -1);
	lan_fork_detach(f);
	{
		struct fork_rec fr2 = {0};
		struct lan_fork *g = start(&w, &fr2, NULL, "INVITE");

		CHECK_EQ(lan_fork_branches(g), 5);	/* but it rings for calls */
		lan_fork_cancel(g);
		lan_fork_detach(g);
	}
	evfake_advance(60000);
	uaw_fini(&w);
}

/* ---- I: selection ---- */
static void t_selection(void)
{
	struct uaw w;
	struct fork_rec fr = {0};
	reg_id_t id[6];
	struct lan_fork *f;
	struct lan_fork_opts o;
	struct lan_req q;
	int k;

	uaw_init(&w, NULL, false);
	mk_invite_req(&q, SDP);
	errno = 0;
	CHECK(lan_fork_request(w.lan, &q, NULL, fork_cb, &fr, NULL) == NULL);
	CHECK_EQ(errno, ENOENT);
	for (k = 1; k <= 5; k++)
		id[k] = dev_register(&w, k);
	fakeep_clear(w.f);
	/* an unreachable device is skipped while others are reachable */
	reg_set_reachable(lan_registrar(w.lan), id[3], false);
	f = start(&w, &fr, NULL, "INVITE");
	CHECK_EQ(lan_fork_branches(f), 4);
	CHECK_EQ(find_sent(w.f, dev_ip(3), 5060, "INVITE", 0), -1);
	lan_fork_cancel(f); lan_fork_detach(f);
	evfake_advance(60000);
	/* ... unless asked otherwise */
	fakeep_clear(w.f);
	memset(&o, 0, sizeof(o));
	o.include_unreachable = true;
	f = start(&w, &fr, &o, "INVITE");
	CHECK_EQ(lan_fork_branches(f), 5);
	lan_fork_cancel(f); lan_fork_detach(f);
	evfake_advance(60000);
	/* all unreachable: try them all (the flag may be stale) */
	for (k = 1; k <= 5; k++)
		reg_set_reachable(lan_registrar(w.lan), id[k], false);
	fakeep_clear(w.f);
	f = start(&w, &fr, NULL, "INVITE");
	CHECK_EQ(lan_fork_branches(f), 5);
	lan_fork_cancel(f); lan_fork_detach(f);
	evfake_advance(60000);
	/* everything excluded: nothing to do */
	{
		reg_id_t all[5] = { id[1], id[2], id[3], id[4], id[5] };

		memset(&o, 0, sizeof(o));
		o.exclude = all;
		o.nexclude = 5;
		errno = 0;
		CHECK(lan_fork_request(w.lan, &q, &o, fork_cb, &fr, NULL) == NULL);
		CHECK_EQ(errno, ENOENT);
	}
	/* one device, two AORs: it rings once */
	uaw_rx(&w, dev_ip(1), 5060, "REGISTER sip:192.168.68.1 SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.68.11:5060;branch=z9hG4bKbob1\r\n"
	       "From: <sip:bob@192.168.68.1>;tag=bb\r\nTo: <sip:bob@192.168.68.1>\r\nCall-ID: bob1\r\nCSeq: 1 REGISTER\r\n"
	       "Contact: <sip:u1@192.168.68.11:5060>;expires=600\r\nContent-Length: 0\r\n\r\n");
	CHECK_EQ(reg_count(lan_registrar(w.lan)), 6);
	fakeep_clear(w.f);
	f = start(&w, &fr, NULL, "INVITE");
	CHECK_EQ(lan_fork_branches(f), 5);
	CHECK_EQ(count_sent(w.f, "INVITE"), 5);
	/* lan_free with a live fork: silent teardown (sanitizers watch for leaks / use after free) */
	uaw_fini(&w);
}

void test_fork(void)
{
	t_winner();
	t_cancel_pending();
	t_busy_keeps_ringing();
	t_aggregate();
	t_caller_cancel();
	t_binding_gone();
	t_extra_2xx();
	t_message();
	t_selection();
}
