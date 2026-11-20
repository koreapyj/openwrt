/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_SDP_SDP_NEG_H
#define IMSD_SDP_SDP_NEG_H
#include <stdbool.h>
#include <stdint.h>
#include "sdp.h"

/*
 * Codec model and offer / answer handling for the two legs of imsd:
 *   carrier leg (LG U+ IMS):  AMR-WB / AMR-NB (RFC 4867) + telephone-event (RFC 4733)
 *   client leg (LAN phones):  Opus (RFC 7587), G.722, PCMA + telephone-event
 * Nothing here decides about transcoding: both legs yield a struct
 * sdpn_media and the call controller pairs them.
 *
 * Offers and answers are produced as struct sdp (serialise with sdp_write(),
 * use sdp_origin_succeed() before sending a re-offer / re-answer).
 * struct sdp / struct sdpn_media are big or plain data: allocate struct sdp
 * statically or on the heap.
 *
 * Only one audio stream is negotiated (the first RTP/AVP audio media section
 * with a non-zero port). Other sections of an offer are answered with port 0.
 */

enum sdpn_codec {
	SDPN_C_NONE = 0,
	SDPN_C_AMRWB,	/* AMR-WB/16000 */
	SDPN_C_AMRNB,	/* AMR/8000 */
	SDPN_C_OPUS,	/* opus/48000/2 */
	SDPN_C_G722,	/* G722/8000 (RTP clock 8000, 16 kHz audio) */
	SDPN_C_PCMA,	/* PCMA/8000 */
};

const char *sdpn_codec_name(enum sdpn_codec c);
/* RTP timestamp clock of the codec in Hz (AMR-WB 16000, AMR 8000, Opus 48000, G722 8000, PCMA 8000) */
uint32_t sdpn_codec_rtp_clock(enum sdpn_codec c);
/* audio sampling rate (G722: 16000) */
uint32_t sdpn_codec_audio_rate(enum sdpn_codec c);

enum sdpn_err {
	SDPN_OK = 0,
	SDPN_E_ARG = -1,
	SDPN_E_NOMEDIA = -2,	/* no usable RTP/AVP audio section (488 material) */
	SDPN_E_NOCODEC = -3,	/* no mutually supported codec (488 Not Acceptable Here) */
	SDPN_E_NOADDR = -4,	/* no connection address */
	SDPN_E_REJECTED = -5,	/* answer: the stream was rejected (port 0) */
	SDPN_E_BADANSWER = -6,	/* answer: nothing in it matches our offer */
	SDPN_E_BUILD = -7,	/* could not build the SDP (limits, bad configuration) */
};
const char *sdpn_strerror(int err);
/* SIP status for a negotiation failure: 488 for NOMEDIA / NOCODEC / NOADDR / REJECTED / BADANSWER, 500 otherwise */
int sdpn_sip_status(int err);

/* AMR mode-set bit i = mode i allowed; 0 = no restriction */
#define SDPN_MODESET_ALL 0u

/*
 * What one audio leg ended up with. Filled by sdpn_from_answer() and by the
 * answer functions, from the point of view of imsd (local = imsd).
 */
struct sdpn_media {
	bool valid;
	int media_index;	/* index of the audio section in the SDP */
	struct addr remote;	/* where to send RTP: connection address + media port */
	struct addr remote_rtcp;/* a=rtcp if given, else RTP port + 1 */
	enum sdpn_codec codec;
	int pt_send;		/* payload type to put into RTP we send */
	int pt_recv;		/* payload type we expect in RTP we receive */
	uint32_t clock;		/* RTP clock of the codec in Hz */
	uint32_t audio_rate;	/* sampling rate in Hz */
	bool octet_align;	/* AMR: octet-aligned (true) or bandwidth-efficient mode; the ANSWER wins */
	uint32_t mode_set;	/* AMR: bit i = mode i permitted, 0 = unrestricted */
	int ptime;		/* ms, 0 = none stated */
	int maxptime;		/* ms, 0 = none stated */
	int bw_as;		/* b=AS of the answer, -1 absent */
	int dtmf_pt;		/* telephone-event PT to send, -1 none */
	int dtmf_pt_recv;	/* telephone-event PT we receive, -1 none */
	uint32_t dtmf_clock;	/* telephone-event clock rate (0 if none) */
	/* Opus (RFC 7587) parameters announced by the remote for what it receives */
	int opus_maxplaybackrate;	/* default 48000 */
	bool opus_stereo;
	bool opus_fec;
	enum sdp_dir dir;	/* what imsd may do: SENDRECV / SENDONLY / RECVONLY / INACTIVE */
	bool legacy_hold;	/* remote connection address is 0.0.0.0 / :: (RFC 2543 hold) */
};

/* ---- carrier leg ---------------------------------------------------------- */

struct sdpn_carrier_cfg {
	/* payload types in our offers; defaults are the ones the PoC used and LG U+ accepted */
	int pt_amrwb_be, pt_amrwb_oa, pt_amrnb_be, pt_amrnb_oa;	/* 104 100 102 96 */
	int pt_dtmf16, pt_dtmf8;				/* 107 101 */
	bool offer_amrwb, offer_amrnb;				/* true true */
	bool offer_be, offer_oa;				/* bandwidth-efficient and octet-aligned variants: true true */
	enum sdpn_codec pref[4];	/* preference when answering; npref == 0: AMR-WB, AMR-NB */
	int npref;
	int bw_as, bw_rs, bw_rr;	/* b= lines, -1 omits: 49 600 2000 */
	int ptime, maxptime;		/* 20, 240 */
	const char *session_name;	/* s=, default "QC VOIP" (as in the accepted traffic) */
};
void sdpn_carrier_cfg_default(struct sdpn_carrier_cfg *c);

/*
 * Offer to the carrier: AMR-WB BE/OA, AMR BE/OA (each with
 * mode-change-capability=2;max-red=0), telephone-event/16000 and /8000
 * (fmtp 0-15), b=AS:49 RS:600 RR:2000, ptime 20, maxptime 240, sendrecv.
 * rtp: local RTP address and port (the family of the address selects
 * IP4 / IP6 in o= and c=). org: origin user / session id / version.
 */
int sdpn_carrier_offer(const struct sdpn_carrier_cfg *cfg, const struct sdp_origin *org, const struct addr *rtp,
		       struct sdp *out);

/*
 * Answer a network offer (MT call or re-INVITE): the best supported codec in
 * our preference order (the first offered PT of that codec that we can
 * handle: crc=1, robust-sorting=1, interleaving, invalid mode-set are not),
 * its PT echoed, octet-align mirrored exactly as offered (present/absent,
 * 0/1), mode-set echoed when offered, one telephone-event PT with a clock
 * matching the codec (falls back to the other clock, then to any), answer
 * direction per RFC 3264. neg (may be NULL) describes the resulting leg.
 */
int sdpn_carrier_answer(const struct sdpn_carrier_cfg *cfg, const struct sdp *offer, const struct sdp_origin *org,
			const struct addr *rtp, struct sdp *answer, struct sdpn_media *neg);

/* ---- client (LAN) leg ------------------------------------------------------ */

struct sdpn_lan_cfg {
	enum sdpn_codec pref[4];	/* offer order and answer preference; npref == 0: see carrier_wideband */
	int npref;
	bool carrier_wideband;		/* default order Opus, G722, PCMA (true) or PCMA, Opus, G722 (false) */
	bool honour_client_order;	/* answer with the client's first acceptable codec instead of ours */
	int pt_opus, pt_g722, pt_pcma;	/* 111, 9, 8 */
	int pt_dtmf8, pt_dtmf48;	/* 101, 102 */
	bool dtmf48;			/* offer telephone-event/48000 next to Opus (default true) */
	int opus_rate;			/* maxplaybackrate / sprop-maxcapturerate we announce; 0: 16000 wideband else 8000 */
	int ptime;			/* 20 */
	const char *session_name;	/* default "imsd" */
};
void sdpn_lan_cfg_default(struct sdpn_lan_cfg *c);

/*
 * Offer to a LAN phone: Opus/48000/2 (fmtp maxplaybackrate=R;sprop-maxcapturerate=R;stereo=0;
 * useinbandfec=0), G722/8000, PCMA/8000, telephone-event/8000 (and /48000 with Opus), ptime, sendrecv.
 */
int sdpn_lan_offer(const struct sdpn_lan_cfg *cfg, const struct sdp_origin *org, const struct addr *rtp,
		   struct sdp *out);
/* Answer a LAN client's offer: one supported codec + one telephone-event, client PTs echoed. */
int sdpn_lan_answer(const struct sdpn_lan_cfg *cfg, const struct sdp *offer, const struct sdp_origin *org,
		    const struct addr *rtp, struct sdp *answer, struct sdpn_media *neg);

/* ---- interpreting an answer (either leg) -------------------------------------- */

/*
 * Interpret the ANSWER to an offer we sent (offer is what we sent, in the
 * same struct form). The selected codec is the first format of the answer's
 * m= line that we offered (same PT with a compatible rtpmap, else a format
 * with a matching encoding: then pt_send is the answer's PT and pt_recv ours).
 * Parameters (octet-align, mode-set, Opus) are taken from the ANSWER's fmtp:
 * the answer wins over what we offered. dtmf PT / clock from the answer's
 * telephone-event. Direction = our offered direction restricted by the answer's.
 * Returns 0 or SDPN_E_*.
 */
int sdpn_from_answer(const struct sdp *offer, const struct sdp *answer, struct sdpn_media *out);

/* ---- hold / resume ----------------------------------------------------------- */

/*
 * Direction an offer / answer section means for the sender (the remote's view),
 * with legacy hold folded in: c=0.0.0.0 turns sendrecv into sendonly and
 * recvonly into inactive (the sender no longer receives). *legacy (may be NULL)
 * tells whether the legacy form was used.
 */
enum sdp_dir sdpn_remote_dir(const struct sdp *s, const struct sdp_media *m, bool *legacy);
/* true if the remote does not want to receive media: sendonly or inactive (the hold states) */
bool sdpn_dir_is_hold(enum sdp_dir remote_dir);
/*
 * Direction to put into the offer we send on the OTHER leg of a call when the
 * remote on this leg re-offers with remote_dir (sendonly = put us on hold):
 * the same direction, since our offer speaks for that remote.
 */
enum sdp_dir sdpn_forward_dir(enum sdp_dir remote_dir);
/*
 * Direction of our answer to an offer with direction offered (remote's view)
 * when we would like to do ours_max (our view, normally SENDRECV): sendonly ->
 * recvonly, recvonly -> sendonly (we can only send), sendrecv -> ours_max,
 * inactive -> inactive (RFC 3264 section 6.1).
 */
enum sdp_dir sdpn_answer_dir(enum sdp_dir offered, enum sdp_dir ours_max);
/* set the direction on a section we are about to send; legacy also sets c= to 0.0.0.0 / :: */
void sdpn_apply_dir(struct sdp *s, struct sdp_media *m, enum sdp_dir d, bool legacy);

/* ---- codec parameter helpers --------------------------------------------------- */

/* "0,2,4,7" -> bit mask; 0 on success, -1 if malformed or a mode above max_mode */
int sdpn_parse_mode_set(const char *s, unsigned max_mode, uint32_t *mask);
/* bit mask -> "0,2,4,7" (nothing is truncated); 0 or -1 */
int sdpn_format_mode_set(uint32_t mask, char *out, size_t outsz);
#endif
