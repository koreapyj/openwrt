# SPDX-License-Identifier: GPL-2.0-or-later
# Fragment for the integrator: paths relative to src/.
# Needs (already in the other modules): util/{buf,addr,log,sys}.c, sip/{msg,transport,txn,dialog}.c,
# sdp/{sdp,sdp_neg}.c. gmcall_reg.c needs gm/reg.c (only the daemon links it; host tests fake the context).
GMCALL_SRC = call/gmcall.c call/gmcall_mo.c call/gmcall_mt.c call/gmcall_dlg.c call/gmcall_util.c call/gmcall_reg.c
# sources the host tests compile (everything but the reg adapter)
GMCALL_HOST_SRC = call/gmcall.c call/gmcall_mo.c call/gmcall_mt.c call/gmcall_dlg.c call/gmcall_util.c
# each test file has its own main(): separate binaries (see src/Makefile)
GMCALL_TEST_SRC = call/test_gmcall_util.c call/test_gmcall.c
GMCALL_TEST_SUPPORT = test/evloop_fake.c test/fakeep.c
