# SPDX-License-Identifier: GPL-2.0-or-later
# MMS reception (WSP / MMS PDU codecs, DNS and HTTP clients on the event loop, attachment store, manager, LAN delivery).
# Fragment for the integrator: paths relative to src/. The pure parts and the clients need util/{buf,log,sys,addr}.c and the
# event loop (util/evloop_uloop.c or test/evloop_fake.c); mms_lan.c also needs ua/, smsrelay/smsfmt.c and smscodec/; the
# core module glue (mms_mod.c) needs core.c and smsrelay/smsrelay_mod.c.
MMS_SRC = mms/wsp.c mms/mmspdu.c mms/netio.c mms/dns.c mms/http.c mms/mmsstore.c mms/mmsrender.c mms/mms.c mms/mms_lan.c mms/httpd.c mms/mmsproxy.c mms/mmsguard.c mms/mmsguard_io.c mms/mmsbearer.c
MMS_MOD_SRC = mms/mms_mod.c
MMS_TEST_SRC = mms/test_main.c mms/t_common.c mms/t_codec.c mms/t_net.c mms/t_mms.c mms/t_flow.c mms/t_proxy.c mms/t_bearer.c
