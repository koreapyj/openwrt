/* SPDX-License-Identifier: GPL-2.0-or-later */
/* evloop implementation for host tests: virtual clock, no sleeping. */
#include <poll.h>
#include <stdlib.h>
#include "evloop_fake.h"
#include "../util/evloop.h"

struct ev_fd {
	struct ev_fd *next;
	int fd;
	unsigned events;
	ev_fd_cb cb;
	void *arg;
};

struct ev_timer {
	struct ev_timer *next;
	ev_timer_cb cb;
	void *arg;
	int armed;
	uint64_t due;
	uint64_t seq;
};

static struct ev_fd *fds;
static struct ev_timer *timers;
static uint64_t now = 1000000;
static uint64_t seq_counter;

void evfake_reset(void)
{
	while (fds) {
		struct ev_fd *f = fds;

		fds = f->next;
		free(f);
	}
	while (timers) {
		struct ev_timer *t = timers;

		timers = t->next;
		free(t);
	}
	now = 1000000;
	seq_counter = 0;
}

uint64_t ev_now_ms(void)
{
	return now;
}

struct ev_fd *ev_fd_add(int fd, ev_fd_cb cb, void *arg)
{
	return ev_fd_add_ev(fd, EV_READ, cb, arg);
}

void ev_fd_set_events(struct ev_fd *w, unsigned events)
{
	if (w && events)
		w->events = events;
}

struct ev_fd *ev_fd_add_ev(int fd, unsigned events, ev_fd_cb cb, void *arg)
{
	struct ev_fd *f = calloc(1, sizeof(*f));

	f->events = events;
	f->fd = fd;
	f->cb = cb;
	f->arg = arg;
	f->next = fds;
	fds = f;
	return f;
}

void ev_fd_del(struct ev_fd *w)
{
	struct ev_fd **pp;

	if (!w)
		return;
	for (pp = &fds; *pp; pp = &(*pp)->next)
		if (*pp == w) {
			*pp = w->next;
			break;
		}
	free(w);
}

struct ev_timer *ev_timer_new(ev_timer_cb cb, void *arg)
{
	struct ev_timer *t = calloc(1, sizeof(*t));

	t->cb = cb;
	t->arg = arg;
	t->next = timers;
	timers = t;
	return t;
}

void ev_timer_set(struct ev_timer *t, uint64_t ms)
{
	t->armed = 1;
	t->due = now + ms;
	t->seq = ++seq_counter;
}

void ev_timer_cancel(struct ev_timer *t)
{
	t->armed = 0;
}

void ev_timer_free(struct ev_timer *t)
{
	struct ev_timer **pp;

	if (!t)
		return;
	for (pp = &timers; *pp; pp = &(*pp)->next)
		if (*pp == t) {
			*pp = t->next;
			break;
		}
	free(t);
}

void evfake_advance(uint64_t ms)
{
	uint64_t target = now + ms;

	for (;;) {
		struct ev_timer *t, *best = NULL;

		for (t = timers; t; t = t->next)
			if (t->armed && t->due <= target &&
			    (!best || t->due < best->due || (t->due == best->due && t->seq < best->seq)))
				best = t;
		if (!best)
			break;
		if (best->due > now)
			now = best->due;
		best->armed = 0;
		best->cb(best->arg);
	}
	now = target;
}

int evfake_poll_fds(void)
{
	int fired = 0;
	struct ev_fd *f;

	for (f = fds; f; f = f->next) {
		struct pollfd p = { .fd = f->fd, .events = (short)(((f->events & EV_READ) ? POLLIN : 0) |
								  ((f->events & EV_WRITE) ? POLLOUT : 0)) };

		if (poll(&p, 1, 0) > 0 && (p.revents & (POLLIN | POLLOUT))) {
			f->cb(f->arg, f->fd);
			fired++;
			f = fds;	/* callbacks may change the list: restart (each fd drains itself) */
			if (!f)
				break;
		}
	}
	return fired;
}

int evfake_armed_timers(void)
{
	struct ev_timer *t;
	int n = 0;

	for (t = timers; t; t = t->next)
		n += t->armed;
	return n;
}

int evfake_fd_watches(void)
{
	struct ev_fd *f;
	int n = 0;

	for (f = fds; f; f = f->next)
		n++;
	return n;
}
