/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_TEST_EVLOOP_FAKE_H
#define IMSD_TEST_EVLOOP_FAKE_H
#include <stdint.h>

/* Test control of the fake event loop (virtual clock, manual fd / timer firing). */

/* drop all timers and watches, clock to a fixed non-zero start */
void evfake_reset(void);
/* run every timer due within the next ms of virtual time, in deadline order; the clock stops at each timer's deadline while its callback runs */
void evfake_advance(uint64_t ms);
/* poll() the registered fds without blocking and call the callbacks of the readable ones; returns how many fired */
int evfake_poll_fds(void);
/* number of armed timers / registered fd watches */
int evfake_armed_timers(void);
int evfake_fd_watches(void);
#endif
