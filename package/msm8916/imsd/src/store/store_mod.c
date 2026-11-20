/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The message store as a core module, see store_mod.h. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "store_mod.h"
#include "../util/log.h"

static struct {
	struct store *s;
	struct core *c;
} G;

static void build_cfg(struct store_cfg *o)
{
	const struct imsd_config *c = core_cfg(G.c);

	store_cfg_defaults(o);
	snprintf(o->dir, sizeof(o->dir), "%s", c->store_dir);
	o->keep_messages = c->store_keep_messages;
	o->keep_days = c->store_keep_days;
	o->keep_bytes = c->store_keep_bytes;
}

static int mod_start(struct core *c, void *arg)
{
	struct store_cfg sc;
	struct store_ops ops;

	(void)arg;
	if (G.s)
		return -EBUSY;
	memset(&G, 0, sizeof(G));
	G.c = c;
	if (!core_cfg(c)->store) {
		LOGI("store: switched off (uci store=0): messages nobody takes are lost");
		return 0;
	}
	build_cfg(&sc);
	memset(&ops, 0, sizeof(ops));
	G.s = store_new(&sc, &ops);
	if (!G.s) {
		LOGE("store: cannot start (out of memory or no thread): running without a store");
		return 0;
	}
	return 0;
}

static void mod_stop(struct core *c, void *arg)
{
	(void)c;
	(void)arg;
	store_free(G.s);
	memset(&G, 0, sizeof(G));
}

static void mod_lan_state(struct core *c, struct lan *l, void *arg)
{
	(void)c;
	(void)arg;
	if (G.s && !l)
		store_lan_down(G.s);
}

static void mod_binding(struct core *c, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why, void *arg)
{
	(void)c;
	(void)arg;
	if (G.s)
		store_on_binding(G.s, ev, b, why);
}

const struct core_module store_module = {
	.name = "store",
	.start = mod_start,
	.stop = mod_stop,
	.lan_state = mod_lan_state,
	.on_binding = mod_binding,
};

struct store *store_mod_get(void)
{
	return G.s;
}

void store_mod_reload(void)
{
	struct store_cfg sc;

	if (!G.s)
		return;
	build_cfg(&sc);
	store_set_cfg(G.s, &sc);
}

bool store_mod_status(struct store_status *out)
{
	if (!G.s)
		return false;
	store_mod_reload();
	store_get_status(G.s, out);
	return true;
}
