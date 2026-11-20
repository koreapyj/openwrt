/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "carrier_call.h"

const char *cc_state_name(enum cc_state s)
{
	static const char *const n[] = { "dialing", "early", "cancelling", "incoming", "answering", "connected", "ended" };

	return (unsigned)s < sizeof(n) / sizeof(n[0]) ? n[s] : "?";
}
