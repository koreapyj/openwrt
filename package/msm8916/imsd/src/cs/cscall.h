/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_CSCALL_H
#define IMSD_CS_CSCALL_H
#include "carrier_call.h"
#include "csline.h"

/*
 * Circuit switched carrier call leg: struct cscall is one call placed / received by the modem through uqmid
 * (docs/uqmid.md): voice_create_call + start for MO, the voice.call_added notification + accept for MT. It carries no
 * media; the call audio is the modem's sound card (media/pcmdev.h) and the B2BUA joins it with the LAN leg through a
 * BR_LEG_PCMDEV bridge leg (cs/csmedia.h). It implements struct carrier_call_ops (carrier_call.h), so the B2BUA drives it
 * like a gmcall: see there for the event contract (events only from the loop, exactly one terminal event, never from
 * inside a cscall_*() call).
 *
 * ---- uqmid state -> events (MO) ----------------------------------------------------------------------------------
 *   create + start ok              (DIALING)
 *   dialing                        -
 *   ringing-out (alerting)         RINGING, PROGRESS(180); with cfg.early_media also PROGRESS(183) + EARLY_MEDIA (the PCM path
 *                                  is opened by the B2BUA now: network ringback / announcements reach the LAN device)
 *   active                         (EARLY_MEDIA if it has not been sent yet), ANSWERED
 *   terminated by the network      before alerting: FAILED(503) | alerting: FAILED(603 if it ended within short_ring_ms, else
 *                                  480) | after the answer: TERMINATED(by_remote); the status comes from the Q.850 cause when
 *                                  uqmid reports one (it does not today), see cs_cause_to_sip()
 * ---- MT ------------------------------------------------------------------------------------------------------------
 *   voice.call_added, state ringing-in    incoming callback (the B2BUA forks the call to the LAN devices) -> answer() = accept
 *   terminated while ringing              CANCELLED(by_remote)
 * ---- one call at a time (the PCM path is single) --------------------------------------------------------------------
 *   a second MO attempt            dial() = -EBUSY (answer the LAN device 486)
 *   a second incoming call         left ringing / waiting at the network untouched (no accept, no hangup), counted and
 *                                  reported in cscall_status(); when the active call ends the line is rescanned and a call that
 *                                  still rings is offered as a normal incoming call
 * Finished uqmid call objects are always deleted (voice_delete_call), also foreign ones that show up as terminated.
 */
struct cscall;
struct cscall_mgr;

struct cscall_cfg {
	bool early_media;		/* MO: EARLY_MEDIA at the alerting state (default true); false: only RINGING, EARLY_MEDIA right before ANSWERED */
	unsigned ring_timeout_s;	/* MO: not answered after this: hang up, CANCELLED("no answer"); MT: not answered by the LAN side after this: rejected. 0 off, default 120 */
	unsigned dial_timeout_ms;	/* create + start must be done within this, default 20000 */
	unsigned hangup_wait_ms;	/* after a hangup request: report the end at the latest after this, default 3000 */
	unsigned reconcile_ms;		/* a live call is read back this often to catch a lost notification, default 5000 (0 off) */
	unsigned short_ring_ms;		/* alerting shorter than this and then ended by the far end = "rejected" (603), default 4000 */
	unsigned max_calls;		/* objects of this manager (live + being reaped), 1..4, default 4 */
	cc_incoming_cb on_incoming;
	void *incoming_arg;
};
void cscall_cfg_defaults(struct cscall_cfg *c);

/* the manager registers itself as a listener of the line. NULL on OOM */
struct cscall_mgr *cscall_mgr_new(struct csline *line, const struct cscall_cfg *cfg);
/* destroy every call silently (no callbacks) and free */
void cscall_mgr_free(struct cscall_mgr *m);
void cscall_mgr_set_cfg(struct cscall_mgr *m, const struct cscall_cfg *cfg);

struct cscall_status {
	unsigned live;			/* calls not ended */
	unsigned active_id;		/* id of the live call, 0 = none */
	unsigned waiting;		/* incoming calls left at the network because a call is active (current) */
	char waiting_number[48];	/* of the first one */
	unsigned foreign;		/* uqmid calls not ours that are not terminated (other ubus users, before a restart) */
	unsigned long mo, mt, answered, failed, busy_refused, waiting_total, dtmf_sent, dtmf_dropped, lost_modem, glare;
	char last_end[128];		/* "" or "mo failed 486: user busy (cause 17, end reason user-busy 146)" of the last ended call */
};
void cscall_mgr_status(const struct cscall_mgr *m, struct cscall_status *s);

/* Q.850 cause (0..127) -> SIP status; the text for the Reason line. Unknown values: by class (see the table in cscall.c). */
int cs_cause_to_sip(int q850, const char **text);
/* QMI call end reason (uqmid end_reason value / libqmi name) -> SIP status for a call that never connected; 0 for an unknown reason.
 * *normal is set for the plain ends (normal-call-clearing 145, network-end 104, client-end 29: no failure; 480 when it never connected). */
int cs_end_reason_to_sip(int value, const char *name, const char **text, bool *normal);
/* the status of a call that ended without a reported cause: from direction, how far it got and how long it alerted */
int cs_infer_status(enum cc_dir dir, bool alerting, bool active, unsigned alert_ms, unsigned short_ring_ms, const char *uq_reason);
/* "+82 10-1234 5678" / "tel:010..." / "sip:+8210...@h" -> "+821012345678"; identical to gmcall_number_normalize. 0, or -1 (nothing left / too small) */
int cs_number_normalize(const char *in, char *out, size_t n);
/* a dial string for uqmid ("+821012345678", "114", "*23#"): separators dropped, only 0-9 * # and a leading + remain. 0, or -1 */
int cs_dial_string(const char *in, char *out, size_t n);

/* ---- the operations (struct carrier_call_ops "cs"); manager = struct cscall_mgr ---- */
extern const struct carrier_call_ops cscall_carrier_ops;
/* the backend handle for the B2BUA: { &cscall_carrier_ops, m } */
void cscall_carrier_backend(struct cscall_mgr *m, struct carrier_backend *out);

int cscall_dial(struct cscall_mgr *m, const struct cc_dial *d, cc_event_cb cb, void *arg, struct carrier_call **out);
#endif
