/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_MMSGUARD_H
#define IMSD_MMS_MMSGUARD_H
#include <stdbool.h>
#include <stddef.h>
#include "../util/addr.h"

/*
 * Traffic guard of the on-demand MMS bearer (mmsbearer.h). On this line NOTHING but MMS traffic may leave through the cellular data
 * bearer: DNS queries to the bearer's own servers (to resolve the MMS proxy / MMSC names) and TCP to the resolved addresses of the
 * MMS proxy (or, without a proxy, of the MMSC / Content-Location host). The sockets of the MMS client are bound to the netdev and the
 * bearer has no route in the main table, so nothing else normally goes there; the guard is defence in depth that keeps the promise even
 * if a route or a socket appears by mistake, and the daemon fails closed: no guard, no bearer.
 *
 * One small nftables table owned by imsd (family inet, name imsd_mms, never shared with fw4):
 *
 *   table inet imsd_mms {
 *       counter acc, drp                                   (what status reports)
 *       set ifs   { type ifname }                          (the bearer netdev; empty until the bearer exists)
 *       set dns4  { type ipv4_addr }       dns6  { type ipv6_addr }      (the bearer's DNS servers)
 *       set tcp4  { type ipv4_addr . inet_service }   tcp6 { type ipv6_addr . inet_service }   (resolved proxy / MMSC addresses)
 *       chain out { type filter hook output priority -10; oifname @ifs jump mmsout }
 *       chain mmsout { ip daddr @dns4 udp dport 53 counter "acc" accept; same for tcp 53 and for dns6;
 *                      ip daddr . tcp dport @tcp4 counter "acc" accept; same for tcp6;  counter "drp" drop }
 *       chain fwd { type filter hook forward priority -10; iifname @ifs counter "drp" drop; oifname @ifs counter "drp" drop }
 *   }
 *
 * Mechanism: `nft -f -` run as a child process WITHOUT waiting (posix_spawn, the script on its stdin, the exit status collected on the
 * event loop): the tree has no libnftnl / nf_tables netlink helper (only the XFRM and rtnetlink ones), and the main loop must never
 * wait for an external command. The commands are serialised, one child at a time. Steps, in the order the bearer needs them:
 *   mmsguard_install   the table with empty sets (nothing is bound to it yet): before the bearer is created. Failure: no bearer.
 *   mmsguard_arm       the netdev and the DNS servers go into the sets: after `get`, BEFORE the netdev gets an address.
 *   mmsguard_gate      one destination address:port is allowed (TCP) before the HTTP client connects (the client waits for the answer).
 *   mmsguard_remove    the counters are read one last time and the table is deleted: after the address / the bearer are gone.
 * The table is polled every few seconds for its counters while it is installed; if the table is gone or nft fails the guard reports
 * `lost` and the owner tears the bearer down. A table left behind by a crash keeps dropping (fail closed) and is replaced by the next
 * install (`add table; delete table; table {...}` in one transaction).
 */
#define GUARD_TABLE "imsd_mms"

/* the process runner, a seam for the host tests. run() starts `nft` with argv (NULL terminated, argv[0] = "nft"), feeds stdin_text to it
 * (NULL: nothing) and calls cb(arg, status, out) exactly once from the event loop (never from inside run): status 0 = exit status 0,
 * else the exit status (> 0), or -errno (spawn failure, timeout -ETIMEDOUT); out = what it printed on stdout (NUL terminated, valid during
 * the callback). Returns a handle, or NULL (errno) when nothing could be started (no callback then). */
struct guard_exec_ops {
	void *(*run)(void *ctx, const char *const *argv, const char *stdin_text, void (*cb)(void *arg, int status, const char *out), void *arg);
	void (*cancel)(void *ctx, void *handle);	/* no callback any more, the child is killed and reaped later */
	void *ctx;
};
const struct guard_exec_ops *guard_exec_real(void);	/* mmsguard_io.c, daemon and the host tests that spawn a fake nft */

struct guard_stats {
	bool installed;		/* the table exists and has been seen to exist */
	bool armed;		/* a netdev is in the set */
	unsigned long accepted, dropped;	/* packets, summed over every bearer session since the daemon started */
	unsigned long installs, failures;
	char last_error[96];
};

struct mmsguard;
/* lost(arg): the table disappeared / nft failed while it was in use (the owner tears down) */
struct mmsguard *mmsguard_new(const struct guard_exec_ops *x, void (*lost)(void *arg), void *arg);
/* cancels the child, leaves the table alone (use mmsguard_remove first when it matters) */
void mmsguard_free(struct mmsguard *g);
/* done(arg, err): 0 or -errno. Exactly once from the event loop unless the guard is freed. */
int mmsguard_install(struct mmsguard *g, void (*done)(void *arg, int err), void *arg);
/* the netdev name and the DNS servers (at most 4, ports ignored) */
int mmsguard_arm(struct mmsguard *g, const char *ifname, const struct addr *dns, int n_dns, void (*done)(void *arg, int err), void *arg);
/* rc 0: the destination is allowed already; 1: wait for done(arg, err); -errno: refused (not armed, bad address) */
int mmsguard_gate(struct mmsguard *g, const struct addr *dst, void (*done)(void *arg, int err), void *arg);
void mmsguard_gate_cancel(struct mmsguard *g, void *arg);
/* read the counters, delete the table. done runs once (also when nothing was installed). */
void mmsguard_remove(struct mmsguard *g, void (*done)(void *arg, int err), void *arg);
void mmsguard_stats(const struct mmsguard *g, struct guard_stats *out);
bool mmsguard_installed(const struct mmsguard *g);
/* script builders, exposed for the tests */
size_t mmsguard_script_install(char *out, size_t n);
#endif
