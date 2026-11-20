/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_TEST_TCOMMON_H
#define IMSD_CS_TEST_TCOMMON_H
#include <stdlib.h>
#include "cstest.h"
#include "csu_fake.h"
#include "../cscall.h"
#include "../cssms.h"
#include "../../test/evloop_fake.h"

static struct csline *LINE;

/* line + fake uqmid, uqmid up, modem found and read: the line is usable */
static inline struct csline *env_line(const struct csline_cfg *cfg)
{
	struct csline_cfg c;

	evfake_reset();
	if (cfg)
		c = *cfg;
	else
		csline_cfg_defaults(&c);
	LINE = csline_new(&c, fk_ops());
	fk_reset(LINE);
	return LINE;
}

static inline void env_up(void)
{
	csline_ev_uqmid_up(LINE, true);
	evfake_advance(100);
}

static inline void env_down(void)
{
	csline_free(LINE);
	LINE = NULL;
	fk_reset(NULL);
	evfake_reset();
}

static inline void adv(unsigned ms)
{
	evfake_advance(ms);
}
#endif
