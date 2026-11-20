/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Real SDP bodies captured on LG U+ with the imsua PoC (apims/{run1,n1,l1,c1}/imsua.log). Do not edit. */
#ifndef IMSD_SDP_VECTORS_H
#define IMSD_SDP_VECTORS_H

/* our PoC offer (run1, call to 114), CRLF */
static const char VEC_POC_OFFER[] =
	"v=0\r\n"
	"o=root 1002 1000 IN IP6 2001:4430:141:990a:25b5:899e:232:cb69\r\n"
	"s=QC VOIP\r\n"
	"c=IN IP6 2001:4430:141:990a:25b5:899e:232:cb69\r\n"
	"t=0 0\r\n"
	"m=audio 50010 RTP/AVP 104 100 102 96 107 101\r\n"
	"b=AS:49\r\n"
	"b=RS:600\r\n"
	"b=RR:2000\r\n"
	"a=rtpmap:104 AMR-WB/16000/1\r\n"
	"a=fmtp:104 mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:100 AMR-WB/16000/1\r\n"
	"a=fmtp:100 octet-align=1;mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:102 AMR/8000/1\r\n"
	"a=fmtp:102 mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:96 AMR/8000/1\r\n"
	"a=fmtp:96 octet-align=1;mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:107 EVRCWB0/8000/1\r\n"
	"a=rtpmap:101 telephone-event/8000/1\r\n"
	"a=fmtp:101 0-15\r\n"
	"a=sendrecv\r\n"
	"a=maxptime:240\r\n"
	"a=ptime:20\r\n"
;

/* 114 provisional answer: AMR-NB PT 102 octet-align=0; mode-set=7 (note the blank after ';') */
static const char VEC_A114_183[] =
	"v=0\r\n"
	"o=vIBCF 1351675568 1795104518 IN IP6 2001:4430:4:313::7\r\n"
	"s=MGCF-HS\r\n"
	"c=IN IP6 2001:4430:4:313::7\r\n"
	"t=0 0\r\n"
	"m=audio 48814 RTP/AVP 102 101\r\n"
	"b=AS:38\r\n"
	"b=RS:0\r\n"
	"b=RR:700\r\n"
	"a=fmtp:102 octet-align=0; mode-set=7\r\n"
	"a=fmtp:101 0-15\r\n"
	"a=ptime:20\r\n"
	"a=rtpmap:102 AMR/8000/1\r\n"
	"a=rtpmap:101 telephone-event/8000/1\r\n"
	"a=sendrecv\r\n"
;

/* 114 final 200 answer (same media) */
static const char VEC_A114_200[] =
	"v=0\r\n"
	"o=vIBCF 1345002320 1795104518 IN IP6 2001:4430:4:313::7\r\n"
	"s=MGCF-HS\r\n"
	"c=IN IP6 2001:4430:4:313::7\r\n"
	"t=0 0\r\n"
	"m=audio 48814 RTP/AVP 102 101\r\n"
	"b=AS:38\r\n"
	"b=RS:0\r\n"
	"b=RR:700\r\n"
	"a=fmtp:102 octet-align=0; mode-set=7\r\n"
	"a=fmtp:101 0-15\r\n"
	"a=ptime:20\r\n"
	"a=rtpmap:102 AMR/8000/1\r\n"
	"a=rtpmap:101 telephone-event/8000/1\r\n"
	"a=sendrecv\r\n"
;

/* voicemail call: our offer */
static const char VEC_VM_OFFER[] =
	"v=0\r\n"
	"o=root 1002 1000 IN IP6 2001:4430:a102:2ee6:4c13:4bd7:fafd:12d7\r\n"
	"s=QC VOIP\r\n"
	"c=IN IP6 2001:4430:a102:2ee6:4c13:4bd7:fafd:12d7\r\n"
	"t=0 0\r\n"
	"m=audio 50010 RTP/AVP 104 100 102 96 107 101\r\n"
	"b=AS:49\r\n"
	"b=RS:600\r\n"
	"b=RR:2000\r\n"
	"a=rtpmap:104 AMR-WB/16000/1\r\n"
	"a=fmtp:104 mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:100 AMR-WB/16000/1\r\n"
	"a=fmtp:100 octet-align=1;mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:102 AMR/8000/1\r\n"
	"a=fmtp:102 mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:96 AMR/8000/1\r\n"
	"a=fmtp:96 octet-align=1;mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:107 EVRCWB0/8000/1\r\n"
	"a=rtpmap:101 telephone-event/8000/1\r\n"
	"a=fmtp:101 0-15\r\n"
	"a=sendrecv\r\n"
	"a=maxptime:240\r\n"
	"a=ptime:20\r\n"
;

/* voicemail answer: PT 104 offered as BE comes back with octet-align=1 */
static const char VEC_VM_ANSWER[] =
	"v=0\r\n"
	"o=vIBCF 1342570928 1795120620 IN IP6 2001:4430:5:325::8\r\n"
	"s=QC VOIP\r\n"
	"c=IN IP6 2001:4430:5:325::8\r\n"
	"t=0 0\r\n"
	"m=audio 42746 RTP/AVP 104 101\r\n"
	"b=AS:49\r\n"
	"b=RS:600\r\n"
	"b=RR:2000\r\n"
	"a=ptime:20\r\n"
	"a=maxptime:240\r\n"
	"a=rtpmap:104 AMR-WB/16000/1\r\n"
	"a=rtpmap:101 telephone-event/8000/1\r\n"
	"a=sendrecv\r\n"
	"a=fmtp:104 octet-align=1;mode-change-capability=2;max-red=0\r\n"
	"a=fmtp:101 0-15\r\n"
;

/* MT call offer from the network, with EVS */
static const char VEC_MT_OFFER[] =
	"v=0\r\n"
	"o=vIBCF 1356104123 1795119376 IN IP6 2001:4430:4:315::8\r\n"
	"s=-\r\n"
	"i=A VOIP Session\r\n"
	"c=IN IP6 2001:4430:4:315::8\r\n"
	"t=0 0\r\n"
	"m=audio 44218 RTP/AVP 110 100 96 107 101\r\n"
	"b=AS:50\r\n"
	"b=RS:0\r\n"
	"b=RR:2500\r\n"
	"a=rtpmap:110 EVS/16000\r\n"
	"a=fmtp:110 br=9.6-24.4;bw=nb-swb\r\n"
	"a=rtpmap:100 AMR-WB/16000/1\r\n"
	"a=fmtp:100 octet-align=1\r\n"
	"a=rtpmap:96 AMR/8000/1\r\n"
	"a=fmtp:96 octet-align=1\r\n"
	"a=rtpmap:107 telephone-event/16000\r\n"
	"a=fmtp:107 0-15\r\n"
	"a=rtpmap:101 telephone-event/8000\r\n"
	"a=fmtp:101 0-15\r\n"
	"a=candidate:1 1 UDP 2130706431 2001:4430:4:315::8 44218 typ host\r\n"
	"a=sendrecv\r\n"
	"a=ptime:20\r\n"
	"a=maxptime:120\r\n"
;

/* our MT answer that the network accepted */
static const char VEC_MT_ANSWER_OURS[] =
	"v=0\r\n"
	"o=root 1002 1000 IN IP6 2001:4430:1094:d1c6:b9d6:b61:344:9645\r\n"
	"s=QC VOIP\r\n"
	"c=IN IP6 2001:4430:1094:d1c6:b9d6:b61:344:9645\r\n"
	"t=0 0\r\n"
	"m=audio 50012 RTP/AVP 100 107\r\n"
	"b=AS:49\r\n"
	"b=RS:600\r\n"
	"b=RR:2000\r\n"
	"a=rtpmap:100 AMR-WB/16000/1\r\n"
	"a=fmtp:100 octet-align=1;mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:107 telephone-event/16000/1\r\n"
	"a=fmtp:107 0-15\r\n"
	"a=sendrecv\r\n"
	"a=maxptime:240\r\n"
	"a=ptime:20\r\n"
;

/* call to a barred line: our offer */
static const char VEC_MRF_OFFER[] =
	"v=0\r\n"
	"o=root 1002 1000 IN IP6 2001:4430:1094:d1c6:b9d6:b61:344:9645\r\n"
	"s=QC VOIP\r\n"
	"c=IN IP6 2001:4430:1094:d1c6:b9d6:b61:344:9645\r\n"
	"t=0 0\r\n"
	"m=audio 50010 RTP/AVP 104 100 102 96 107 101\r\n"
	"b=AS:49\r\n"
	"b=RS:600\r\n"
	"b=RR:2000\r\n"
	"a=rtpmap:104 AMR-WB/16000/1\r\n"
	"a=fmtp:104 mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:100 AMR-WB/16000/1\r\n"
	"a=fmtp:100 octet-align=1;mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:102 AMR/8000/1\r\n"
	"a=fmtp:102 mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:96 AMR/8000/1\r\n"
	"a=fmtp:96 octet-align=1;mode-change-capability=2;max-red=0\r\n"
	"a=rtpmap:107 EVRCWB0/8000/1\r\n"
	"a=rtpmap:101 telephone-event/8000/1\r\n"
	"a=fmtp:101 0-15\r\n"
	"a=sendrecv\r\n"
	"a=maxptime:240\r\n"
	"a=ptime:20\r\n"
;

/* MRF early-media answer: AMR-WB BE mode-set=8, te fmtp 0-11 */
static const char VEC_MRF_ANSWER[] =
	"v=0\r\n"
	"o=vIBCF 1347224678 1795119320 IN IP6 2001:4430:5:323::5\r\n"
	"s=MRF\r\n"
	"c=IN IP6 2001:4430:5:323::5\r\n"
	"t=0 0\r\n"
	"m=audio 38470 RTP/AVP 104 101\r\n"
	"b=AS:49\r\n"
	"b=RS:600\r\n"
	"b=RR:2000\r\n"
	"a=maxptime:60\r\n"
	"a=fmtp:104 octet-align=0;mode-set=8\r\n"
	"a=fmtp:101 0-11\r\n"
	"a=ptime:20\r\n"
	"a=rtpmap:104 AMR-WB/16000\r\n"
	"a=rtpmap:101 telephone-event/8000\r\n"
;

#endif
