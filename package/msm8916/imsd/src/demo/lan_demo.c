/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LAN-side demo for the host: the real core (shared transaction layer, LAN endpoint, registrar, request routing)
 * on real UDP sockets and the real libubox event loop, without modem, Gm registration or ubus.
 *
 *   lan_demo [-a ip] [-p port] [-i ifname] [-t seconds]
 *
 * Prints the LAN status (like `ubus call imsd status` would) when a binding changes and every 5 s.
 * make -C src lan-demo TESTOUT=<dir>  ->  <dir>/lan_demo
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/uloop.h>
#include "../core.h"
#include "../util/log.h"

static struct imsd_config cfg;
static struct core *core;
static struct uloop_timeout tick, quit;

static void show_binding(const struct lan_binding_status *s, void *arg)
{
	(void)arg;
	printf("  binding %u: contact %s source %s ua '%s' expires_in %us reachable %d\n", s->id, s->contact, s->source,
	       s->user_agent, s->expires_in, s->reachable);
}

static void show(void)
{
	struct core_lan_info li;
	struct lan_stats st;
	char as[64] = "-";

	core_lan_info(core, &li);
	if (li.up)
		addr_str(&li.addr, as, sizeof(as));
	printf("lan: state=%s listening=%s %s%s\n", li.state, as, li.reason[0] ? "reason=" : "", li.reason);
	if (core_lan(core)) {
		lan_status(core_lan(core), &st, show_binding, NULL);
		printf("  bindings=%u requests=%lu registers=%lu\n", st.bindings, st.rx_requests, st.rx_register);
	}
	fflush(stdout);
}

static void tick_cb(struct uloop_timeout *t)
{
	show();
	uloop_timeout_set(t, 5000);
}

static void quit_cb(struct uloop_timeout *t)
{
	(void)t;
	uloop_end();
}

static void binding(void *ctx, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why)
{
	(void)ctx; (void)why;
	printf("lan.binding event=%d contact=%s user_agent='%s'\n", ev, b->contact, b->ua);
	show();
}

int main(int argc, char **argv)
{
	struct core_ops ops = { .on_binding = binding };
	struct reg_ops ro;
	char err[160];
	int opt, secs = 0;

	config_defaults(&cfg);
	while ((opt = getopt(argc, argv, "a:p:i:t:")) != -1) {
		switch (opt) {
		case 'a': snprintf(cfg.lan_addr, sizeof(cfg.lan_addr), "%s", optarg); break;
		case 'p': cfg.lan_sip_port = atoi(optarg); break;
		case 'i': snprintf(cfg.lan_ifname, sizeof(cfg.lan_ifname), "%s", optarg); break;
		case 't': secs = atoi(optarg); break;
		default:
			fprintf(stderr, "usage: %s [-a ip] [-p port] [-i ifname] [-t seconds]\n", argv[0]);
			return 2;
		}
	}
	if (config_validate(&cfg, err, sizeof(err))) {
		fprintf(stderr, "config: %s\n", err);
		return 1;
	}
	imsd_log_open("lan_demo", 1);
	imsd_log_level(LOG_INFO);
	uloop_init();
	core = core_new(&cfg, &ops);
	memset(&ro, 0, sizeof(ro));
	if (!core || core_start(core, &ro)) {
		fprintf(stderr, "cannot start the core\n");
		return 1;
	}
	tick.cb = tick_cb;
	uloop_timeout_set(&tick, 1000);
	if (secs) {
		quit.cb = quit_cb;
		uloop_timeout_set(&quit, secs * 1000);
	}
	uloop_run();
	show();
	core_free(core);
	uloop_done();
	return 0;
}
