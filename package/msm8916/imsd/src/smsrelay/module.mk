# SPDX-License-Identifier: GPL-2.0-or-later
# Fragment for the integrator: paths relative to src/. The relay proper needs util/{buf,codec,log,sys}.c, sip/, ua/{lan,registrar}.c,
# smscodec/ and sms/rp.c in the same program; the core module glue (smsrelay_mod.c) also needs core.c and gm/reg.c.
SMSRELAY_SOURCES = smsrelay/smsrelay.c smsrelay/smsfmt.c smsrelay/wappush.c
SMSRELAY_MOD_SOURCES = smsrelay/smsrelay_mod.c
SMSRELAY_TEST_SOURCES = smsrelay/test_smsrelay.c
