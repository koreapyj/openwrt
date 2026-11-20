/* SPDX-License-Identifier: GPL-2.0-or-later */
/* host tests of the MMS client: make -C src test (suite test_mms) */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "t_common.h"
#include "../util/log.h"

int t_checks, t_fails;

#define RUN(f) do { int c0 = t_checks, f0 = t_fails; f(); \
	printf("%-16s %6d checks, %d failures\n", #f, t_checks - c0, t_fails - f0); ngroups++; } while (0)

int main(void)
{
	struct timespec a, b;
	int ngroups = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	imsd_log_level(getenv("T_LOG") ? atoi(getenv("T_LOG")) : LOG_ERR);
	clock_gettime(CLOCK_MONOTONIC, &a);
	RUN(test_mms_codec);
	RUN(test_mms_robust);
	RUN(test_mms_net);
	RUN(test_mms_mgr);
	RUN(test_mms_flow);
	RUN(test_mms_proxy);
	RUN(test_mms_store);
	RUN(test_mms_bearer);
	RUN(test_mms_cs);
	clock_gettime(CLOCK_MONOTONIC, &b);
	printf("%d groups, %d checks, %d failures, %.0f ms\n", ngroups, t_checks, t_fails,
	       (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1e6);
	return t_fails ? 1 : 0;
}
