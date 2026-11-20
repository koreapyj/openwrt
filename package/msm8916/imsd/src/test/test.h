/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_TEST_H
#define IMSD_TEST_H
#include <stdio.h>
#include <string.h>

extern int t_checks, t_fails;

#define CHECK(c) do { t_checks++; if (!(c)) { t_fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_EQ(a, b) do { long long _a = (long long)(a), _b = (long long)(b); t_checks++; \
	if (_a != _b) { t_fails++; printf("FAIL %s:%d: %s == %lld, expected %lld\n", __FILE__, __LINE__, #a, _a, _b); } } while (0)
#define CHECK_STR(a, b) do { const char *_a = (a), *_b = (b); t_checks++; \
	if (!_a || !_b || strcmp(_a, _b)) { t_fails++; printf("FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, _a ? _a : "(null)", _b ? _b : "(null)"); } } while (0)

/* test groups */
void test_util(void);
void test_msg(void);
void test_secagree(void);
void test_aka(void);
void test_dialog(void);
void test_txn(void);
void test_xfrm(void);
void test_udp(void);
void test_isim(void);
void test_rp(void);
void test_net(void);
void test_qrtr(void);
void test_regmsg(void);
void test_imsmodem(void);
void test_reg(void);
void test_config(void);
void test_carrier(void);
void test_core(void);
void test_smsmod(void);
#endif
