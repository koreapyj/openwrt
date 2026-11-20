/* SPDX-License-Identifier: GPL-2.0-or-later */
/* host unit tests: make -C src test */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "test.h"
#include "../util/log.h"

int t_checks, t_fails;

#define RUN(f) do { int c0 = t_checks, f0 = t_fails; f(); \
	printf("%-12s %4d checks, %d failures\n", #f, t_checks - c0, t_fails - f0); ngroups++; } while (0)

int main(void)
{
	struct timespec a, b;
	int ngroups = 0;

	imsd_log_level(getenv("T_LOG") ? atoi(getenv("T_LOG")) : LOG_ERR);
	clock_gettime(CLOCK_MONOTONIC, &a);
	RUN(test_util);
	RUN(test_msg);
	RUN(test_secagree);
	RUN(test_aka);
	RUN(test_dialog);
	RUN(test_txn);
	RUN(test_xfrm);
	RUN(test_udp);
	RUN(test_isim);
	RUN(test_rp);
	RUN(test_net);
	RUN(test_qrtr);
	RUN(test_regmsg);
	RUN(test_imsmodem);
	RUN(test_reg);
	RUN(test_config);
	RUN(test_carrier);
	RUN(test_core);
	RUN(test_smsmod);
	clock_gettime(CLOCK_MONOTONIC, &b);
	printf("%d groups, %d checks, %d failures, %.0f ms\n", ngroups, t_checks, t_fails,
	       (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1e6);
	return t_fails ? 1 : 0;
}
