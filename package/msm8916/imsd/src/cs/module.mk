# SPDX-License-Identifier: GPL-2.0-or-later
#
# Make fragment of the circuit switched backend (cs/), for inclusion by src/Makefile.
#   CS_DIR        directory of this file as seen from the including make (override before including if needed)
# Provided variables
#   CS_SRCS       .c files of the module that run in the daemon (relative to the including make's cwd)
#   CS_TEST_SRCS  host test sources (cs/test, own main in test/test_main.c)
#   CS_PKG_DEPENDS  OpenWrt package DEPENDS to add (the voice sound card kernel modules)
CS_DIR ?= $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
CS_SRCS := $(addprefix $(CS_DIR)/,csline.c cscall.c cc_util.c cssms.c csbackend.c csmedia.c csubus.c carrier_gm.c)
CS_TEST_SRCS := $(addprefix $(CS_DIR)/test/,test_main.c csu_fake.c t_line.c t_call.c t_sms.c t_backend.c t_misc.c)
CS_PKG_DEPENDS := +kmod-sound-soc-qdsp6-rtproxy
# the part the B2BUA links (gmcall wrapper, PCM media glue, state names); the daemon links all of CS_SRCS
CS_B2B_SRC := $(addprefix $(CS_DIR)/,carrier_gm.c csmedia.c cc_util.c)
