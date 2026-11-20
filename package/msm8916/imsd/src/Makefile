# SPDX-License-Identifier: GPL-2.0-or-later
#
# One daemon (core + LAN UA + SDP + SMS codec + media) and the one host test runner.
#
#   make imsd [OUT=dir]            the daemon (objects in $(OUT)/obj/<dir>/*.o, binary $(OUT)/imsd)
#   make test                      host unit tests of everything, one combined summary
#   make test-asan                 the same under ASan + UBSan (objects in $(TESTOUT)/asan)
#   make test-tsan                 the threaded suites (store, media pcmdev/bridge threads) under ThreadSanitizer
#   make bench                     CPU cost of one media bridge direction pair (needs IMSD_TEST_CAPDIR)
#   make pcmsmoke                  host build of the PCM device smoke tool (cs/tools/pcmsmoke.c)
#   make lan-demo                  host build of a LAN-only daemon for the REGISTER walk-through (demo/lan_demo.c)
#   make cross-check               every daemon .c (+ module tests) with the OpenWrt cross compiler, -Os -Werror;
#                                  needs a built toolchain in $(STAGING_DIR), exits non-zero without it
#   make clean
#
# Variables (see also test/README)
#   TESTOUT=dir         output of the test targets, default src/.testout (git ignored)
#   SUITES="a b"        run only these test binaries (default: all, see ALL_SUITES below)
#   IMSD_TEST_CAPDIR=d  directory with RTP recordings of a live line (never in the tree); unset -> those checks are skipped
#   HOSTINST=prefix     optional private prefix with include/ and lib/ of the AMR / Opus libraries; empty -> the system's
#                       (pkg-config when available, else the default compiler paths)
#   IMSD_WITH_OPUS=1|0  Opus wrapper; for the test targets it defaults to "whatever the host has"
#   IMSD_WITH_G722=1|0  vendored G.722
#   TOPDIR=dir          the OpenWrt tree this package sits in (default: four levels up); STAGING_DIR=$(TOPDIR)/staging_dir
#   XCC / XINC          cross compiler and target include dir for cross-check (default: found in $(STAGING_DIR))
# Includes are relative to src/ ("util/x.h", "../util/x.h"); never add -Iutil or -Imedia: src/util/codec.[ch] and
# src/media/codec.[ch] are different files. The modules' module.mk fragments are the single list of their sources.
CC ?= cc
HOSTCC ?= cc
CFLAGS ?= -O2
VERSION ?= 0.1
WARN = -Wall -Wextra
override CFLAGS += $(WARN) -D_GNU_SOURCE -std=gnu11
OUT ?= build
TESTOUT ?= $(CURDIR)/.testout
HOSTINST ?=
TOPDIR ?= $(abspath $(CURDIR)/../../../..)
STAGING_DIR ?= $(TOPDIR)/staging_dir

# ---- host codec libraries (test targets only; the daemon build gets them from the OpenWrt toolchain) ----
TESTGOALS := test test-asan test-tsan run-tests run-tsan bench pcmsmoke
ifneq ($(filter $(TESTGOALS),$(MAKECMDGOALS)),)
HASH := \#
HOSTPC := $(shell command -v pkg-config 2>/dev/null)
ifneq ($(HOSTINST),)
HINC := -I$(HOSTINST)/include
HLIBDIR := -L$(HOSTINST)/lib -Wl,-rpath,$(HOSTINST)/lib
else ifneq ($(HOSTPC),)
HINC := $(shell pkg-config --cflags opencore-amrnb opencore-amrwb vo-amrwbenc opus 2>/dev/null || pkg-config --cflags opencore-amrnb opencore-amrwb vo-amrwbenc 2>/dev/null)
HLIBDIR := $(shell pkg-config --libs-only-L opencore-amrnb opencore-amrwb vo-amrwbenc opus 2>/dev/null || pkg-config --libs-only-L opencore-amrnb opencore-amrwb vo-amrwbenc 2>/dev/null)
endif
# probe(header, lib): 1 if a program including the header links with -llib
probe = $(shell printf '$(HASH)include <%s>\nint main(void){return 0;}\n' $(1) | $(HOSTCC) -x c - -o /dev/null $(HINC) $(HLIBDIR) -l$(2) >/dev/null 2>&1 && echo 1)
HAVE_AMR := $(and $(call probe,opencore-amrnb/interf_dec.h,opencore-amrnb),$(call probe,opencore-amrwb/dec_if.h,opencore-amrwb),$(call probe,vo-amrwbenc/enc_if.h,vo-amrwbenc))
ifeq ($(origin IMSD_WITH_OPUS),undefined)
IMSD_WITH_OPUS := $(if $(call probe,opus/opus.h,opus),1,0)
endif
endif

# ---- module fragments ----
MEDIA_DIR := media
include ua/module.mk
include sdp/module.mk
include smscodec/module.mk
include smsrelay/module.mk
include mms/module.mk
include store/module.mk
include call/module.mk
include b2b/module.mk
include media/module.mk
CS_DIR := cs
include cs/module.mk

UA_SRC := $(addprefix ua/,$(UA_SOURCES))
UA_TEST := $(addprefix ua/,$(UA_TEST_SOURCES))

# modules shared by the daemon and the host tests (no libubox/libubus/libmnl)
CORE = util/buf.c util/log.c util/codec.c util/md5.c util/sys.c util/addr.c util/ifaddr.c util/rtpsock.c \
       sip/msg.c sip/transport.c sip/txn.c sip/dialog.c \
       gm/secagree.c gm/xfrm.c gm/regmsg.c gm/reg.c aka.c carrier.c config.c core.c \
       modem/isim.c modem/netcfg.c modem/qrtr.c modem/imsmodem.c sms/rp.c $(UA_SRC) ua/regpersist_mod.c
# daemon only
DAEMON = main.c config_uci.c util/evloop_uloop.c gm/xfrm_io.c modem/netcfg_io.c mms/mmsb_io.c modem/qrtr_io.c modem/uqmid_ubus.c
DAEMON_SRCS = $(CORE) $(SDP_SRC) $(SMSCODEC_SRC) $(SMSRELAY_SOURCES) $(SMSRELAY_MOD_SOURCES) $(MMS_SRC) $(MMS_MOD_SRC) $(STORE_SRC) $(STORE_MOD_SRC) $(MEDIA_SRCS) $(GMCALL_SRC) $(B2B_SRC) $(CS_SRCS) $(DAEMON)
DAEMON_LIBS = -lubus -lubox -lmnl -luci $(MEDIA_LIBS) -lpthread

# ------------------------------------------------------------------ daemon
OBJ = $(OUT)/obj
DOBJS = $(patsubst %.c,$(OBJ)/%.o,$(DAEMON_SRCS))

all: imsd

imsd: $(OUT)/imsd

$(OUT)/imsd: $(DOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(DOBJS) $(DAEMON_LIBS)

# the vendored G.722 (public domain, upstream style) is built with its own, relaxed flags
$(OBJ)/media/g722/%.o: XFLAGS = -w
$(OBJ)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(MEDIA_CPPFLAGS) $(XFLAGS) -DHAVE_ULOG -DIMSD_VERSION=\"$(VERSION)\" -MMD -MP -c -o $@ $<

# ------------------------------------------------------------------ host tests
# VARIANT selects the output tree: "" -> $(TESTOUT), asan -> $(TESTOUT)/asan, tsan -> $(TESTOUT)/tsan
TOUT = $(TESTOUT)$(if $(VARIANT),/$(VARIANT))
TOBJ = $(TOUT)/obj
SAN = -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
HFLAGS = -g -O1 $(WARN) -D_GNU_SOURCE -std=gnu11 -I. $(HINC) $(MEDIA_CPPFLAGS) $(SANFLAGS)
HLIBS = $(HLIBDIR) -lpthread

CORE_TESTSRC = $(wildcard test/*.c)
UTIL_COMMON = util/buf.c util/log.c util/sys.c util/addr.c util/codec.c
UA_FOUNDATION = $(UTIL_COMMON) sip/msg.c sip/transport.c sip/txn.c sip/dialog.c test/evloop_fake.c test/fakeep.c

obj_of = $(patsubst %.c,$(TOBJ)/%.o,$(1))
ALL_SUITES = test_imsd test_ua test_smsrelay test_mms test_store test_gmcall test_gmcall_util test_b2b test_cs test_sdp test_sdp_neg test_tpdu test_media
# suites that need a host codec library that is not there are skipped with a message, never failed:
#   test_media test_cs test_b2b  need opencore-amr / vo-amrwbenc;  test_b2b also needs Opus (it negotiates and plays it)
MEDIA_SUITES = test_media test_cs test_b2b
SKIP_SUITES =
SKIP_WHY =
ifeq ($(HAVE_AMR),)
SKIP_SUITES += $(MEDIA_SUITES)
SKIP_WHY += (no host libopencore-amrnb / libopencore-amrwb / libvo-amrwbenc headers+libs: install them or set HOSTINST=<prefix>)
else ifeq ($(IMSD_WITH_OPUS),0)
SKIP_SUITES += test_b2b
SKIP_WHY += (test_b2b needs Opus: no host libopus, or IMSD_WITH_OPUS=0)
endif
SUITES ?= $(filter-out $(SKIP_SUITES),$(ALL_SUITES))
SKIPPED = $(if $(filter command line,$(origin SUITES)),,$(SKIP_SUITES))

$(TOBJ)/media/g722/%.o: XFLAGS = -w $(if $(SANFLAGS),-fno-sanitize=shift-base)
$(TOBJ)/media/%.o: XFLAGS += $(if $(SANFLAGS),-fno-sanitize=shift-base)
$(TOBJ)/%.o: %.c
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HFLAGS) $(XFLAGS) -MMD -MP -c -o $@ $<

# core runner: everything of the daemon except the libubox / libubus / libmnl parts (fake event loop in test/)
$(TOUT)/test_imsd: $(call obj_of,$(CORE) $(SMSCODEC_SRC) $(SMSRELAY_SOURCES) $(SMSRELAY_MOD_SOURCES) $(MMS_SRC) $(MMS_MOD_SRC) $(STORE_SRC) $(STORE_MOD_SRC) $(CORE_TESTSRC))
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS)
$(TOUT)/test_ua: $(call obj_of,$(UA_SRC) $(UA_TEST) $(UA_FOUNDATION) $(STORE_SRC))
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS)
$(TOUT)/test_smsrelay: $(call obj_of,$(SMSRELAY_SOURCES) $(SMSRELAY_TEST_SOURCES) $(STORE_SRC) carrier.c mms/wsp.c mms/mmspdu.c ua/test_common.c $(UA_SRC) $(SMSCODEC_SRC) sms/rp.c $(UA_FOUNDATION))
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS)
# MMS: codecs, clients, manager and LAN delivery on the real lan / registrar of the UA tests, fake event loop
$(TOUT)/test_mms: $(call obj_of,$(MMS_SRC) $(MMS_TEST_SRC) $(STORE_SRC) carrier.c smsrelay/smsfmt.c ua/test_common.c $(UA_SRC) $(SMSCODEC_SRC) $(UA_FOUNDATION))
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS)
GMCALL_FOUNDATION = $(UTIL_COMMON) sip/msg.c sip/transport.c sip/txn.c sip/dialog.c sdp/sdp.c sdp/sdp_neg.c test/evloop_fake.c test/fakeep.c
$(TOUT)/test_store: $(call obj_of,$(STORE_SRC) $(STORE_TEST_SRC) util/log.c util/codec.c test/evloop_fake.c)
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS)
$(TOUT)/test_gmcall: $(call obj_of,$(GMCALL_HOST_SRC) call/test_gmcall.c $(GMCALL_FOUNDATION))
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS)
$(TOUT)/test_gmcall_util: $(call obj_of,$(GMCALL_HOST_SRC) call/test_gmcall_util.c $(GMCALL_FOUNDATION))
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS)
$(TOUT)/test_b2b: $(call obj_of,$(CORE) $(SDP_SRC) $(MEDIA_SRCS) $(GMCALL_SRC) $(B2B_SRC) $(CS_B2B_SRC) $(B2B_TEST_SRC) $(SMSCODEC_SRC) $(SMSRELAY_SOURCES) $(SMSRELAY_MOD_SOURCES) $(STORE_SRC) $(STORE_MOD_SRC) test/evloop_fake.c test/fakeep.c)
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS) $(MEDIA_LIBS)
# circuit switched backend (fake uqmid; csubus.c / carrier_gm.c are daemon only) and its PCM device leg
CS_HOST = $(filter-out %/csubus.c %/carrier_gm.c,$(CS_SRCS))
CS_FOUNDATION = call/gmcall_util.c sip/msg.c smscodec/gsm7.c smscodec/utf8.c util/log.c util/sys.c util/addr.c util/buf.c util/codec.c test/evloop_fake.c
$(TOUT)/test_cs: $(call obj_of,$(CS_HOST) $(CS_TEST_SRCS) $(MEDIA_SRCS) $(CS_FOUNDATION))
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS) $(MEDIA_LIBS)
$(TOUT)/test_sdp: $(call obj_of,$(SDP_SRC) sdp/test_sdp.c util/buf.c util/addr.c)
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS)
$(TOUT)/test_sdp_neg: $(call obj_of,$(SDP_SRC) sdp/test_sdp_neg.c util/buf.c util/addr.c)
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS)
$(TOUT)/test_tpdu: $(call obj_of,$(SMSCODEC_SRC) $(SMSCODEC_TEST_SRC) util/buf.c util/codec.c)
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS)
$(TOUT)/test_media: $(call obj_of,$(MEDIA_SRCS) $(MEDIA_TEST_SRCS) util/log.c util/sys.c util/addr.c util/codec.c)
	$(HOSTCC) $(HFLAGS) -o $@ $^ $(HLIBS) $(MEDIA_LIBS)

run-tests: $(addprefix $(TOUT)/,$(SUITES))
	@mkdir -p $(TOUT)/tmp
	@$(if $(SKIPPED),echo "SKIPPED suites: $(SKIPPED) $(SKIP_WHY)")
	IMSD_TEST_TMP=$(TOUT)/tmp ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
		sh test/run_suites.sh $(TOUT) $(SUITES)

test:
	$(MAKE) run-tests VARIANT=

test-asan:
	$(MAKE) run-tests VARIANT=asan SANFLAGS="$(SAN)"

# the real-thread tests under ThreadSanitizer (ASLR off: TSan maps its shadow at fixed addresses)
TSAN_SUITES = $(filter-out $(SKIP_SUITES),test_store test_media)
run-tsan: $(addprefix $(TOUT)/,$(TSAN_SUITES))
	@mkdir -p $(TOUT)/tmp
	@$(if $(filter test_media,$(SKIP_SUITES)),echo "SKIPPED test_media under TSan $(SKIP_WHY)")
	set -e; for s in $(TSAN_SUITES); do echo "== $$s threads"; \
		IMSD_TEST_TMP=$(TOUT)/tmp setarch $$(uname -m) -R $(TOUT)/$$s threads; done

test-tsan:
	$(MAKE) run-tsan VARIANT=tsan SANFLAGS=-fsanitize=thread

# CPU cost of the media bridge (host number); needs a recorded AMR-WB capture
$(TESTOUT)/bench_media: $(MEDIA_SRCS) $(addprefix util/,log.c sys.c addr.c codec.c) media/test/bench.c $(wildcard media/*.h)
	@mkdir -p $(TESTOUT)
	$(HOSTCC) -std=gnu11 -D_GNU_SOURCE $(WARN) -O2 -I. $(HINC) $(MEDIA_CPPFLAGS) -o $@ $(MEDIA_SRCS) $(addprefix util/,log.c sys.c addr.c codec.c) media/test/bench.c $(HLIBDIR) $(MEDIA_LIBS)
bench: $(TESTOUT)/bench_media
	$<

# PCM device smoke tool (run on the target by hand; cross-check compiles it for the target as well)
SMOKE_SRCS = cs/tools/pcmsmoke.c media/pcmdev.c util/log.c util/codec.c
$(TESTOUT)/pcmsmoke: $(SMOKE_SRCS)
	@mkdir -p $(TESTOUT)
	$(HOSTCC) -std=gnu11 -D_GNU_SOURCE $(WARN) -O2 -I. -o $@ $^ -lm
pcmsmoke: $(TESTOUT)/pcmsmoke

# ------------------------------------------------------------------ LAN demo (host, real sockets; libubox of the build host tree)
lan-demo: $(TESTOUT)/lan_demo
$(TESTOUT)/lan_demo: demo/lan_demo.c $(CORE) util/evloop_uloop.c $(wildcard */*.h *.h)
	@test -d $(STAGING_DIR)/host/include/libubox || { echo "lan-demo: no libubox in $(STAGING_DIR)/host (set TOPDIR or STAGING_DIR)"; exit 1; }
	@mkdir -p $(TESTOUT)
	$(HOSTCC) -g -O1 $(WARN) -D_GNU_SOURCE -std=gnu11 -I. -I$(STAGING_DIR)/host/include \
		-o $@ demo/lan_demo.c $(CORE) store/sio.c util/evloop_uloop.c \
		-L$(STAGING_DIR)/host/lib -Wl,-rpath,$(STAGING_DIR)/host/lib -lubox -lpthread

# ------------------------------------------------------------------ cross compile check
# Every daemon source, the pcmsmoke tool and the module test sources that only need host headers, compiled with the
# OpenWrt target gcc, -Os -Wall -Wextra -Werror. Opus is not staged for the target: codec_opus.c is compile-checked
# against the host's opus headers (CROSS_OPUS=0 skips it).
XCC ?= $(firstword $(wildcard $(STAGING_DIR)/toolchain-*/bin/*-openwrt-linux-*-gcc))
XINC ?= $(firstword $(wildcard $(STAGING_DIR)/target-*/usr/include))
CROSS_OPUS ?= 1
CROSS_SRCS = $(filter-out media/codec_opus.c,$(DAEMON_SRCS)) cs/tools/pcmsmoke.c $(GMCALL_TEST_SRC) $(SMSRELAY_TEST_SOURCES) $(SMSCODEC_TEST_SRC) sdp/test_sdp.c sdp/test_sdp_neg.c
XFLAGS_ALL = -std=gnu11 -D_GNU_SOURCE -Os $(WARN) -Werror -DHAVE_ULOG -I. -I$(XINC) $(filter-out -DIMSD_WITH_OPUS,$(MEDIA_CPPFLAGS))
cross-check:
	@test -n "$(XCC)" && test -n "$(XINC)" || { echo "cross-check: no OpenWrt toolchain / target staging dir under $(STAGING_DIR) (build the toolchain, or set TOPDIR / STAGING_DIR / XCC / XINC)"; exit 1; }
	@mkdir -p $(TESTOUT)/cross
	@set -e; for f in $(CROSS_SRCS); do \
		echo "CROSS-CC $$f"; \
		STAGING_DIR=$(STAGING_DIR) $(XCC) $(XFLAGS_ALL) -c $$f -o $(TESTOUT)/cross/$$(echo $$f | tr / _).o; done
ifneq ($(and $(filter 1,$(CROSS_OPUS)),$(filter 1,$(IMSD_WITH_OPUS))),)
	@test -d /usr/include/opus || { echo "cross-check: CROSS_OPUS=1 but no host opus headers in /usr/include/opus (CROSS_OPUS=0 skips)"; exit 1; }
	@mkdir -p $(TESTOUT)/cross/opusinc && ln -sfn /usr/include/opus $(TESTOUT)/cross/opusinc/opus
	@echo "CROSS-CC media/codec_opus.c (opus is not staged for the target: host headers, compile check only)"
	@STAGING_DIR=$(STAGING_DIR) $(XCC) $(XFLAGS_ALL) -DIMSD_WITH_OPUS -idirafter $(TESTOUT)/cross/opusinc -c media/codec_opus.c -o $(TESTOUT)/cross/codec_opus.o
endif
	@echo "cross-check: ok (zero warnings)"

# the daemon's source list, for the cross warning check (compile each with the target gcc -Os -Wall -Wextra)
print-sources:
	@echo $(DAEMON_SRCS)

clean:
	rm -rf $(OUT)
	rm -rf $(TESTOUT)

-include $(shell find $(OUT) $(TESTOUT) -name '*.d' 2>/dev/null)

.PHONY: print-sources all imsd test test-asan test-tsan run-tests run-tsan bench pcmsmoke lan-demo cross-check clean
