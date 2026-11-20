/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The LAN registrar's persistence as a core module, see regpersist.h. */
#include <string.h>
#include "regpersist.h"
#include "regpersist_mod.h"
#include "../util/log.h"

static struct regpersist *P;

static int mod_start(struct core *c, void *arg)
{
	struct regpersist_cfg rc;
	const struct imsd_config *cfg = core_cfg(c);

	(void)arg;
	if (P)
		return -1;
	if (!cfg->lan_persist) {
		LOGI("registrar: bindings are not persisted (uci lan_persist=0)");
		return 0;
	}
	memset(&rc, 0, sizeof(rc));
	rc.dir = cfg->store_dir;
	P = regpersist_new(&rc);
	if (!P)
		LOGE("registrar: cannot start the persistence of the bindings: running without it");
	return 0;
}

static void mod_stop(struct core *c, void *arg)
{
	(void)c;
	(void)arg;
	regpersist_free(P);
	P = NULL;
}

static void mod_lan_state(struct core *c, struct lan *l, void *arg)
{
	(void)arg;
	if (!P)
		return;
	if (!l)
		regpersist_detach(P);
	else
		regpersist_attach(P, lan_registrar(l), lan_endpoint(l));
	(void)c;
}

static void mod_binding(struct core *c, enum registrar_event ev, const struct reg_binding *b, enum reg_removal why, void *arg)
{
	(void)c;
	(void)arg;
	regpersist_on_binding(P, ev, b, why);
}

const struct core_module regpersist_module = {
	.name = "regpersist",
	.start = mod_start,
	.stop = mod_stop,
	.lan_state = mod_lan_state,
	.on_binding = mod_binding,
};
