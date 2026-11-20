/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_STORE_T_STORE_H
#define IMSD_STORE_T_STORE_H
#include "../test/test.h"
#include "../test/evloop_fake.h"
#include "store.h"

void test_sio_basic(void);
void test_sio_torn(void);
void test_sio_compact(void);
void test_sio_faults(void);
void test_sio_threads(void);
void test_store_cursors(void);
void test_store_engine(void);
void test_store_carbons(void);
void test_store_limits(void);
void test_store_health(void);
void test_store_threads(void);

/* a fresh empty directory below IMSD_TEST_TMP (or /tmp); out is at least 256 bytes */
void t_tmpdir(const char *tag, char *out, size_t n);
void t_rmtree(const char *dir);
#endif
