/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_B2B_B2B_H
#define IMSD_B2B_B2B_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../core.h"
#include "../cs/carrier_call.h"
#include "../media/bridge.h"

/*
 * The call module (struct core_module "call"): joins the LAN clients' call legs with the carrier call legs
 * (call/gmcall.[ch]) through the media bridge (media/bridge.h). One mobile line, shared by every registered LAN
 * device, no authentication, no call-count limit (each call gets its own bridge and its own pair of RTP
 * sockets); what the network or a device refuses is passed on.
 *
 *   LAN -> network   LAN INVITE: 100, carrier INVITE; 180 on carrier ringing; 183 + our SDP answer on early
 *                    media (the bridge is already up then, the carrier leg sends first); 200 with the SAME answer
 *                    when the network answers; carrier failure -> the status mapped to the client (the early media
 *                    has been played before).
 *   network -> LAN   gmcall incoming: no LAN device -> 480 (or the bench, see below); else 180 to the network and
 *                    an INVITE forked to every binding; first 2xx wins, the carrier is answered, the rest is
 *                    cancelled; extra 2xx get ACK + BYE.
 *   established      BYE both ways; re-INVITE / UPDATE from the client: hold / resume / media change answered per
 *                    RFC 3264 and mirrored to the carrier (gmcall_set_direction); INFO DTMF -> RFC 4733; carrier
 *                    hold or media changes only adjust the bridge (no unsolicited re-INVITE towards the client).
 *   bench            ubus calls without a LAN device: the LAN leg is a PCM file leg of the bridge.
 *
 * Everything runs on the main loop and never blocks; media work stays in the media thread.
 */
extern const struct core_module b2b_module;

/* system dependencies of the module, injectable for the host tests (NULL entries: core_rtp_open_*) */
struct b2b_ops {
	int (*rtp_lan)(void *ctx, struct addr *bound);
	int (*rtp_carrier)(void *ctx, const struct addr *local, const char *netdev, struct addr *bound);
	const struct br_pcmdev_ops *pcm_ops;	/* the modem's PCM device of a CS call (NULL: the real one, media/pcmdev.h) */
	void *ctx;
};
void b2b_set_ops(const struct b2b_ops *ops);	/* before core_start; NULL = defaults */

bool b2b_running(void);

/*
 * Carrier backends. The gm (IMS) backend is created by the module itself and serves new outgoing calls by default. A circuit
 * switched backend (cs/cscall.h) is plugged in by the daemon: b2b_set_cs_backend() hooks its incoming calls (they are forked to
 * the LAN devices like the IMS ones, whichever backend is selected) and NULL removes it, ending its calls first (before the
 * manager is freed). b2b_select_backend() says which backend a new outgoing call (LAN INVITE, ubus call_dial) uses; B2B_BE_NONE:
 * they are refused with 503. A call keeps the backend it started on. Both before / after core_start of the module.
 */
enum b2b_backend { B2B_BE_NONE = 0, B2B_BE_GM, B2B_BE_CS };
void b2b_set_cs_backend(const struct carrier_backend *be);
void b2b_select_backend(enum b2b_backend b);
enum b2b_backend b2b_selected_backend(void);
unsigned b2b_active_calls(void);	/* calls not ended, either backend */

struct b2b_counters {
	unsigned active;
	unsigned long out_total, in_total, answered, failed, missed, no_device, bench_total, rtp_timeouts;
};
void b2b_get_counters(struct b2b_counters *c);

struct b2b_info {
	unsigned id;
	const char *dir;		/* "out" (LAN -> network) or "in" */
	const char *state;		/* "dialing" "ringing" "early-media" "answering" "up" "hold" "ended" */
	char carrier_name[4];		/* "gm" (IMS) or "cs" (circuit switched) */
	bool bench;
	char number[48];		/* the remote party's number */
	char carrier_codec[16];		/* "" until known */
	char client_codec[16];		/* "pcm" for a bench call */
	uint64_t age_ms, talk_ms;
	bool bridge;
	struct bridge_stats stats;	/* valid with bridge */
};
/* fills up to max rows, returns how many calls exist */
int b2b_list(struct b2b_info *out, int max);

/* state change notice for ubus subscribers; strings are valid during the callback */
struct b2b_notice {
	unsigned id;
	const char *event;	/* "new" "ringing" "early-media" "answered" "hold" "resume" "ended" "dtmf" "play-done" */
	const char *dir;
	const char *number;
	int status;		/* final SIP status for "ended" when there is one, else 0 */
	const char *reason;	/* "" when none */
};
typedef void (*b2b_notify_cb)(void *arg, const struct b2b_notice *n);
void b2b_set_notify(b2b_notify_cb cb, void *arg);

/* ---- bench (ubus without a LAN phone) ---- */
/* rate: PCM rate of the files, 8000 or 16000 (0: 16000). play / record: "" for none. 0 and *id, or -errno */
int b2b_bench_dial(const char *number, const char *play, const char *record, unsigned rate, unsigned *id);
int b2b_bench_answer(unsigned id, const char *play, const char *record, unsigned rate);
int b2b_call_reject(unsigned id, int status);	/* incoming call not answered yet */
int b2b_call_hangup(unsigned id);		/* any call */

/* End every call with BYE / CANCEL / final responses to both sides, best effort (shutdown, registration loss) */
void b2b_end_all(const char *reason);
#endif
