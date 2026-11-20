# SPDX-License-Identifier: GPL-2.0-or-later
# Objects / tests of the LAN-side SIP module, for the integrator's src/Makefile
# (paths relative to src/ua; prefix with ua/ when included from src/).
UA_SOURCES := registrar.c regpersist.c lan.c lan_text.c
UA_TEST_SOURCES := test_main.c test_common.c test_registrar.c test_lan.c test_fork.c test_regpersist.c
