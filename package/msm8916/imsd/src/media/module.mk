# SPDX-License-Identifier: GPL-2.0-or-later
#
# Make fragment describing the media/ module, for inclusion by the package
# Makefile (src/Makefile).
#
#   MEDIA_DIR      directory of this file, relative to the including make's cwd
#                  (computed below, override before including if needed)
#   IMSD_WITH_G722 1 (default): build the vendored G.722 codec (g722/); set to 0
#                  to drop it (the licence status of the CMU-derived parts is
#                  under review).  The switch becomes -DIMSD_WITH_G722.
#   IMSD_WITH_OPUS 1 (default): build the libopus wrapper
#
# Provided variables
#   MEDIA_SRCS         .c files of the module (relative to the including make's cwd)
#   MEDIA_UTIL_SRCS    util/ files the module needs on top of it (relative to src/)
#   MEDIA_CPPFLAGS     preprocessor flags (feature switches)
#   MEDIA_LIBS         libraries to link
#   MEDIA_TEST_SRCS    host unit/integration test sources (own main in test/test_main.c)
#   MEDIA_PKG_DEPENDS  OpenWrt package DEPENDS to add
MEDIA_DIR ?= $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
IMSD_WITH_G722 ?= 1
IMSD_WITH_OPUS ?= 1

MEDIA_SRCS := $(addprefix $(MEDIA_DIR)/,rtp.c amr.c resample.c dtmf.c codec.c codec_amr.c codec_pcma.c pcmdev.c bridge.c)
MEDIA_UTIL_SRCS := util/log.c util/sys.c util/addr.c util/codec.c
MEDIA_CPPFLAGS :=
MEDIA_LIBS := -lopencore-amrnb -lopencore-amrwb -lvo-amrwbenc -lpthread -lm
MEDIA_PKG_DEPENDS := +libopencore-amrnb +libopencore-amrwb +libvo-amrwbenc +libpthread
ifeq ($(IMSD_WITH_OPUS),1)
MEDIA_SRCS += $(MEDIA_DIR)/codec_opus.c
MEDIA_CPPFLAGS += -DIMSD_WITH_OPUS
MEDIA_LIBS += -lopus
MEDIA_PKG_DEPENDS += +libopus
endif
ifeq ($(IMSD_WITH_G722),1)
MEDIA_SRCS += $(MEDIA_DIR)/codec_g722.c $(MEDIA_DIR)/g722/g722_encode.c $(MEDIA_DIR)/g722/g722_decode.c
MEDIA_CPPFLAGS += -DIMSD_WITH_G722
endif
MEDIA_TEST_SRCS := $(addprefix $(MEDIA_DIR)/test/,test_main.c t_rtp.c t_amr.c t_codec.c t_dtmf.c t_bridge.c t_pcmdev.c)
