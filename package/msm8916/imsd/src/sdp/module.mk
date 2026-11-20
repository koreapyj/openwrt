# SPDX-License-Identifier: GPL-2.0-or-later
# Fragment for the integrator: paths relative to src/ (needs util/buf.c and util/addr.c, already in CORE)
SDP_SRC = sdp/sdp.c sdp/sdp_neg.c
# each test file has its own main(): build them as separate binaries (see src/Makefile)
SDP_TEST_SRC = sdp/test_sdp.c sdp/test_sdp_neg.c
