# SPDX-License-Identifier: GPL-2.0-or-later
# Persistent message store with per-device redelivery. Fragment for the integrator: paths relative to src/.
# sio.c (file layer, writer thread) needs util/log.c and -lpthread; store.c (index, devices, delivery engine) the event loop
# (util/evloop_uloop.c or test/evloop_fake.c) and util/log.c; store_mod.c (core module glue) also core.c.
STORE_SRC = store/sio.c store/store.c
STORE_MOD_SRC = store/store_mod.c
STORE_TEST_SRC = store/test_main.c store/t_sio.c store/t_store.c
