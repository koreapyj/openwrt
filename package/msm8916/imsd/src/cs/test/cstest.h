/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_CS_TEST_H
#define IMSD_CS_TEST_H
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

extern int t_checks, t_fails;

#define CHECK(c) do { t_checks++; if (!(c)) { t_fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_EQ(a, b) do { long long _a = (long long)(a), _b = (long long)(b); t_checks++; \
	if (_a != _b) { t_fails++; printf("FAIL %s:%d: %s == %lld, expected %lld\n", __FILE__, __LINE__, #a, _a, _b); } } while (0)
#define CHECK_STR(a, b) do { const char *_a = (a), *_b = (b); t_checks++; \
	if (!_a || !_b || strcmp(_a, _b)) { t_fails++; printf("FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, _a ? _a : "(null)", _b ? _b : "(null)"); } } while (0)

void test_line(void);
void test_call(void);
void test_sms(void);
void test_backend(void);
void test_misc(void);
#endif
