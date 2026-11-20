/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Messages captured on the live LG U+ network (apims P1 logs: run1 = MO call
 * to 114, c1 = 100rel/PRACK then 603, n1 = MO to a mobile, l1 = MT call).
 * $VIA $FROM $CID are replaced by the values of our request, LF becomes CRLF
 * and Content-Length is recomputed; everything else is verbatim.
 */
#ifndef IMSD_CALL_TEST_GMCALL_VEC_H
#define IMSD_CALL_TEST_GMCALL_VEC_H

#define TAG_EARLY "az00a69dad4e0f150fc08a749e6b46b9_kmnham67BBB7C859cbb47042615"
#define TAG_FINAL "az00a69dad4e0f150fc08a749e6b46b9_kmnham67BBB7C859cbb47042608"

static const char V_100[] =
	"SIP/2.0 100 Trying\n"
	"Via: $VIA\n"
	"To: $TO\n"
	"From: $FROM\n"
	"Call-ID: $CID\n"
	"CSeq: $CSEQ\n"
	"Content-Length: 0\n\n";

/* run1: 183 with early media on one To tag ... */
static const char V_183_114[] =
	"SIP/2.0 183 Session Progress\n"
	"Via: $VIA\n"
	"Contact: <sip:[2001:4430:5:401::53]:1357;transport=UDP>\n"
	"To: <tel:114;phone-context=lguplus.co.kr>;tag=" TAG_EARLY "\n"
	"From: $FROM\n"
	"Call-ID: $CID\n"
	"CSeq: $CSEQ\n"
	"Allow: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, REGISTER, REFER, SUBSCRIBE, UPDATE\n"
	"Content-Type: application/sdp\n"
	"Content-Length: 308\n\n"
	"v=0\n"
	"o=vIBCF 1351675568 1795104518 IN IP6 2001:4430:4:313::7\n"
	"s=MGCF-HS\n"
	"c=IN IP6 2001:4430:4:313::7\n"
	"t=0 0\n"
	"m=audio $PORT RTP/AVP 102 101\n"
	"b=AS:38\n"
	"b=RS:0\n"
	"b=RR:700\n"
	"a=fmtp:102 octet-align=0; mode-set=7\n"
	"a=fmtp:101 0-15\n"
	"a=ptime:20\n"
	"a=rtpmap:102 AMR/8000/1\n"
	"a=rtpmap:101 telephone-event/8000/1\n"
	"a=sendrecv\n";

/* ... and the 200 on a DIFFERENT To tag */
static const char V_200_114[] =
	"SIP/2.0 200 OK\n"
	"Via: $VIA\n"
	"Require: timer\n"
	"Contact: <sip:[2001:4430:5:401::53]:1357;transport=UDP>\n"
	"To: <tel:114;phone-context=lguplus.co.kr>;tag=" TAG_FINAL "\n"
	"From: $FROM\n"
	"Call-ID: $CID\n"
	"CSeq: $CSEQ\n"
	"Session-Expires: 600;refresher=uac\n"
	"Allow: ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, REGISTER, REFER, SUBSCRIBE, UPDATE\n"
	"Content-Type: application/sdp\n"
	"Supported: timer\n"
	"Content-Length: 308\n\n"
	"v=0\n"
	"o=vIBCF 1345002320 1795104518 IN IP6 2001:4430:4:313::7\n"
	"s=MGCF-HS\n"
	"c=IN IP6 2001:4430:4:313::7\n"
	"t=0 0\n"
	"m=audio $PORT RTP/AVP 102 101\n"
	"b=AS:38\n"
	"b=RS:0\n"
	"b=RR:700\n"
	"a=fmtp:102 octet-align=0; mode-set=7\n"
	"a=fmtp:101 0-15\n"
	"a=ptime:20\n"
	"a=rtpmap:102 AMR/8000/1\n"
	"a=rtpmap:101 telephone-event/8000/1\n"
	"a=sendrecv\n";

/* c1: reliable 183 (Require: 100rel + RSeq) with the SDP answer of an announcement server */
static const char V_183_100REL[] =
	"SIP/2.0 183 Session Progress\n"
	"Via: $VIA\n"
	"Require: 100rel\n"
	"Contact: <sip:[2001:4430:5:401::53]:1357;transport=UDP>\n"
	"To: <tel:01039428657;phone-context=lguplus.co.kr>;tag=az004c351a470f150fc0c49d8d40c21d_kmnham35CE3B543fb662707299\n"
	"From: $FROM\n"
	"Call-ID: $CID\n"
	"CSeq: $CSEQ\n"
	"Content-Type: application/sdp\n"
	"RSeq: 80904\n"
	"Content-Length: 309\n\n"
	"v=0\n"
	"o=vIBCF 1347224678 1795119320 IN IP6 2001:4430:5:323::5\n"
	"s=MRF\n"
	"c=IN IP6 2001:4430:5:323::5\n"
	"t=0 0\n"
	"m=audio 38470 RTP/AVP 104 101\n"
	"b=AS:49\n"
	"b=RS:600\n"
	"b=RR:2000\n"
	"a=maxptime:60\n"
	"a=fmtp:104 octet-align=0;mode-set=8\n"
	"a=fmtp:101 0-11\n"
	"a=ptime:20\n"
	"a=rtpmap:104 AMR-WB/16000\n"
	"a=rtpmap:101 telephone-event/8000\n";

static const char V_200_PRACK[] =
	"SIP/2.0 200 OK\n"
	"Via: $VIA\n"
	"To: $TO\n"
	"From: $FROM\n"
	"Call-ID: $CID\n"
	"CSeq: $CSEQ\n"
	"Content-Length: 0\n\n";

static const char V_603[] =
	"SIP/2.0 603 Decline\n"
	"Via: $VIA\n"
	"Contact: <sip:[2001:4430:5:401::53]:1357;transport=UDP>\n"
	"To: <tel:01039428657;phone-context=lguplus.co.kr>;tag=az004c351a470f150fc0c49d8d40c21d_kmnham35CE3B543fb662707299\n"
	"From: $FROM\n"
	"Call-ID: $CID\n"
	"CSeq: $CSEQ\n"
	"Content-Length: 0\n\n";

/* n1: MO to a mobile: 180 without SDP, 200 with Require: timer and Session-Expires: 600;refresher=uac */
static const char V_180_N1[] =
	"SIP/2.0 180 Ringing\n"
	"Via: $VIA;received=2001:4430:a102:2ee6:4c13:4bd7:fafd:12d7;rport=8061\n"
	"Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REGISTER,REFER,SUBSCRIBE,UPDATE\n"
	"Call-ID: $CID\n"
	"Content-Length: 0\n"
	"CSeq: $CSEQ\n"
	"From: $FROM\n"
	"To: <tel:01051226862;phone-context=lguplus.co.kr>;tag=73677a2f29f4e\n"
	"Contact: <sip:[2001:4430:4:405::43]:5071>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";video\n\n";

static const char V_200_N1[] =
	"SIP/2.0 200 OK\n"
	"Via: $VIA;received=2001:4430:a102:2ee6:4c13:4bd7:fafd:12d7;rport=8061\n"
	"Allow: $ALLOW\n"
	"Call-ID: $CID\n"
	"Content-Length: 354\n"
	"Content-Type: application/sdp\n"
	"CSeq: $CSEQ\n"
	"From: $FROM\n"
	"Require: timer\n"
	"Session-Expires: 600;refresher=uac\n"
	"Supported: timer\n"
	"To: <tel:01051226862;phone-context=lguplus.co.kr>;tag=73677a2f29f4e\n"
	"Contact: <sip:[2001:4430:4:405::43]:5071>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";video\n\n"
	"v=0\n"
	"o=vIBCF 1342570928 1795120620 IN IP6 2001:4430:5:325::8\n"
	"s=QC VOIP\n"
	"c=IN IP6 2001:4430:5:325::8\n"
	"t=0 0\n"
	"m=audio 42746 RTP/AVP 104 101\n"
	"b=AS:49\n"
	"b=RS:600\n"
	"b=RR:2000\n"
	"a=ptime:20\n"
	"a=maxptime:240\n"
	"a=rtpmap:104 AMR-WB/16000/1\n"
	"a=rtpmap:101 telephone-event/8000/1\n"
	"a=sendrecv\n"
	"a=fmtp:104 octet-align=1;mode-change-capability=2;max-red=0\n"
	"a=fmtp:101 0-15\n";

#define ALLOW_UPD "ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REGISTER,REFER,SUBSCRIBE,UPDATE"
#define ALLOW_NOUPD "ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REGISTER,REFER,SUBSCRIBE"

/* l1: the MT INVITE, verbatim (no Require, Supported: timer, sec-agree, no Record-Route, Contact = the P-CSCF) */
static const char V_INVITE_L1[] =
	"INVITE sip:01039428657@[2001:4430:1094:d1c6:b9d6:b61:344:9645]:8931 SIP/2.0\n"
	"Via: SIP/2.0/UDP [2001:4430:4:405::43]:5071;branch=z9hG4bK7eff6c368a1049bd41e3_6bf2a\n"
	"Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";require;explicit\n"
	"Allow: ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REGISTER,REFER,SUBSCRIBE,UPDATE\n"
	"Call-ID: abc-dGhoc2RjeWItMC0yLWE4MmhrSzltRkxVeWcwTVhmeGFAZ2hnbGhpaW1vbWk-LGU+IBCF\n"
	"Content-Length: 564\n"
	"Content-Type: application/sdp\n"
	"CSeq: 9203 INVITE\n"
	"From: <sip:01051226862@lte-lguplus.co.kr>;tag=kmnham7485C9417df6d25733432\n"
	"Max-Forwards: 57\n"
	"P-Asserted-Identity: <sip:01051226862@lte-lguplus.co.kr>\n"
	"P-Called-Party-Id: <sip:01039428657@lte-lguplus.co.kr>\n"
	"Privacy: none\n"
	"Session-Expires: 600;refresher=uac\n"
	"Supported: timer, sec-agree\n"
	"To: <tel:01039428657;phone-context=lte-lguplus.co.kr>\n"
	"User-Agent: TTA-VoLTE/3.0 SM-S918N/ZI1_ZF1 Device_Type/Android_Phone OMD\n"
	"P-Early-Media: supported\n"
	"P-TTA-VoLTE-Info: avchange\n"
	"P-VRBT-info: ver=1.0\n"
	"Contact: <sip:[2001:4430:4:405::43]:5071>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";video\n\n"
	"v=0\n"
	"o=vIBCF 1356104123 1795119376 IN IP6 2001:4430:4:315::8\n"
	"s=-\n"
	"i=A VOIP Session\n"
	"c=IN IP6 2001:4430:4:315::8\n"
	"t=0 0\n"
	"m=audio 44218 RTP/AVP 110 100 96 107 101\n"
	"b=AS:50\n"
	"b=RS:0\n"
	"b=RR:2500\n"
	"a=rtpmap:110 EVS/16000\n"
	"a=fmtp:110 br=9.6-24.4;bw=nb-swb\n"
	"a=rtpmap:100 AMR-WB/16000/1\n"
	"a=fmtp:100 octet-align=1\n"
	"a=rtpmap:96 AMR/8000/1\n"
	"a=fmtp:96 octet-align=1\n"
	"a=rtpmap:107 telephone-event/16000\n"
	"a=fmtp:107 0-15\n"
	"a=rtpmap:101 telephone-event/8000\n"
	"a=fmtp:101 0-15\n"
	"a=candidate:1 1 UDP 2130706431 2001:4430:4:315::8 44218 typ host\n"
	"a=sendrecv\n"
	"a=ptime:20\n"
	"a=maxptime:120\n";

static const char V_ACK_L1[] =
	"ACK sip:01039428657@[2001:4430:1094:d1c6:b9d6:b61:344:9645]:8931 SIP/2.0\n"
	"Via: SIP/2.0/UDP [2001:4430:4:405::43]:5071;branch=z9hG4bK7eff6c3ebbd01822bee3_788b7\n"
	"Call-ID: abc-dGhoc2RjeWItMC0yLWE4MmhrSzltRkxVeWcwTVhmeGFAZ2hnbGhpaW1vbWk-LGU+IBCF\n"
	"Content-Length: 0\n"
	"CSeq: 9203 ACK\n"
	"From: <sip:01051226862@lte-lguplus.co.kr>;tag=kmnham7485C9417df6d25733432\n"
	"Max-Forwards: 66\n"
	"To: <tel:01039428657;phone-context=lte-lguplus.co.kr>;tag=$TAG\n\n";

static const char V_CANCEL_L1[] =
	"CANCEL sip:01039428657@[2001:4430:1094:d1c6:b9d6:b61:344:9645]:8931 SIP/2.0\n"
	"Via: SIP/2.0/UDP [2001:4430:4:405::43]:5071;branch=z9hG4bK7eff6c368a1049bd41e3_6bf2a\n"
	"Call-ID: abc-dGhoc2RjeWItMC0yLWE4MmhrSzltRkxVeWcwTVhmeGFAZ2hnbGhpaW1vbWk-LGU+IBCF\n"
	"Content-Length: 0\n"
	"CSeq: 9203 CANCEL\n"
	"From: <sip:01051226862@lte-lguplus.co.kr>;tag=kmnham7485C9417df6d25733432\n"
	"Max-Forwards: 66\n"
	"To: <tel:01039428657;phone-context=lte-lguplus.co.kr>\n\n";

#endif
