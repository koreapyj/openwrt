/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Adapter that lets gmcall read the registered context from a struct reg.
 * Kept in its own file so host tests (which fake the context) do not link gm/reg.c.
 */
#include "gmcall.h"

static const struct reg_ctx *ctx_of(void *arg)
{
	return reg_context(arg);
}

static int contact_of(void *arg, char *out, size_t n)
{
	return reg_contact_uri(arg, out, n);
}

const struct gmcall_reg_ops gmcall_reg_adapter = {
	.context = ctx_of,
	.contact_uri = contact_of,
};
