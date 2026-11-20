/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UTIL_EVLOOP_H
#define IMSD_UTIL_EVLOOP_H
#include <stdbool.h>
#include <stdint.h>

/*
 * Event loop abstraction. Transport / transaction / dialog code only uses
 * this interface, never uloop directly, so host tests can drive it with a
 * virtual clock (test/evloop_fake.c). The implementation is chosen at link
 * time: util/evloop_uloop.c (daemon) or test/evloop_fake.c (tests).
 *
 * Everything runs on the single main-loop thread. Callbacks may free the
 * handle that triggered them (ev_timer_free / ev_fd_del on itself).
 */

#define EV_READ 1u
#define EV_WRITE 2u

struct ev_fd;
struct ev_timer;

typedef void (*ev_fd_cb)(void *arg, int fd);
typedef void (*ev_timer_cb)(void *arg);

/* Monotonic milliseconds (the loop's notion of "now"). */
uint64_t ev_now_ms(void);

/* Watch fd for readability. Returns a handle or NULL. The fd stays owned by the caller. */
struct ev_fd *ev_fd_add(int fd, ev_fd_cb cb, void *arg);
/* Like ev_fd_add with an explicit event mask (EV_READ | EV_WRITE; level triggered). The callback does not learn which
 * event fired: it tries its non-blocking operation. */
struct ev_fd *ev_fd_add_ev(int fd, unsigned events, ev_fd_cb cb, void *arg);
/* Change the mask of a watch (a non-zero mask). */
void ev_fd_set_events(struct ev_fd *w, unsigned events);
/* Stop watching and free the handle (NULL ok). Does not close the fd. */
void ev_fd_del(struct ev_fd *w);

/* One-shot timer object; created idle. NULL on OOM. */
struct ev_timer *ev_timer_new(ev_timer_cb cb, void *arg);
/* (Re)arm to fire once after ms (0 = next loop iteration). */
void ev_timer_set(struct ev_timer *t, uint64_t ms);
/* Disarm (no-op if idle). */
void ev_timer_cancel(struct ev_timer *t);
/* Cancel and free (NULL ok). */
void ev_timer_free(struct ev_timer *t);
#endif
