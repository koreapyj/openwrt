/* SPDX-License-Identifier: GPL-2.0-or-later */
/* host tests of the message store: make -C src test (suite test_store); "threads" runs only the real-thread tests (TSan) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "t_store.h"
#include "../util/log.h"

int t_checks, t_fails;

#define RUN(f) do { int c0 = t_checks, f0 = t_fails; f(); \
	printf("%-16s %6d checks, %d failures\n", #f, t_checks - c0, t_fails - f0); ngroups++; } while (0)

int main(int argc, char **argv)
{
	struct timespec a, b;
	int ngroups = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	imsd_log_level(getenv("T_LOG") ? atoi(getenv("T_LOG")) : LOG_CRIT);
	clock_gettime(CLOCK_MONOTONIC, &a);
	if (argc > 1 && !strcmp(argv[1], "threads")) {
		RUN(test_sio_threads);
		RUN(test_store_threads);
	} else {
		RUN(test_sio_basic);
		RUN(test_sio_torn);
		RUN(test_sio_compact);
		RUN(test_sio_faults);
		RUN(test_sio_threads);
		RUN(test_store_cursors);
		RUN(test_store_engine);
		RUN(test_store_carbons);
		RUN(test_store_limits);
		RUN(test_store_health);
		RUN(test_store_threads);
	}
	clock_gettime(CLOCK_MONOTONIC, &b);
	printf("%d groups, %d checks, %d failures, %.0f ms\n", ngroups, t_checks, t_fails,
	       (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1e6);
	return t_fails ? 1 : 0;
}
