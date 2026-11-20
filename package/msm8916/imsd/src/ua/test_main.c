/* SPDX-License-Identifier: GPL-2.0-or-later */
/* host unit tests of the LAN-side UA: make -C src/ua test OUT=<dir> */
#include <stdio.h>
#include <time.h>
#include "test_ua.h"

int t_checks, t_fails;

#define RUN(f) do { int c0 = t_checks, f0 = t_fails; f(); \
	printf("%-14s %4d checks, %d failures\n", #f, t_checks - c0, t_fails - f0); ngroups++; } while (0)

int main(void)
{
	struct timespec a, b;
	int ngroups = 0;

	imsd_log_level(LOG_ERR);
	clock_gettime(CLOCK_MONOTONIC, &a);
	RUN(test_registrar);
	RUN(test_lan);
	RUN(test_fork);
	RUN(test_regpersist);
	clock_gettime(CLOCK_MONOTONIC, &b);
	printf("%d groups, %d checks, %d failures, %.0f ms\n", ngroups, t_checks, t_fails,
	       (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1e6);
	return t_fails ? 1 : 0;
}
