/* SPDX-License-Identifier: GPL-2.0-or-later */
/* evloop implementation on libubox uloop (the daemon). */
#include <stdlib.h>
#include <libubox/uloop.h>
#include "evloop.h"
#include "sys.h"

struct ev_fd {
	struct uloop_fd ufd;
	ev_fd_cb cb;
	void *arg;
};

struct ev_timer {
	struct uloop_timeout to;
	ev_timer_cb cb;
	void *arg;
};

uint64_t ev_now_ms(void)
{
	return mono_ms();
}

static void fd_trampoline(struct uloop_fd *u, unsigned int events)
{
	struct ev_fd *w = (struct ev_fd *)u;

	(void)events;
	w->cb(w->arg, u->fd);
}

static unsigned uflags(unsigned events)
{
	return ((events & EV_READ) ? ULOOP_READ : 0) | ((events & EV_WRITE) ? ULOOP_WRITE : 0);
}

struct ev_fd *ev_fd_add(int fd, ev_fd_cb cb, void *arg)
{
	return ev_fd_add_ev(fd, EV_READ, cb, arg);
}

void ev_fd_set_events(struct ev_fd *w, unsigned events)
{
	if (w && events)
		uloop_fd_add(&w->ufd, uflags(events));
}

struct ev_fd *ev_fd_add_ev(int fd, unsigned events, ev_fd_cb cb, void *arg)
{
	struct ev_fd *w = calloc(1, sizeof(*w));

	if (!w)
		return NULL;
	w->cb = cb;
	w->arg = arg;
	w->ufd.fd = fd;
	w->ufd.cb = fd_trampoline;
	if (uloop_fd_add(&w->ufd, uflags(events))) {
		free(w);
		return NULL;
	}
	return w;
}

void ev_fd_del(struct ev_fd *w)
{
	if (!w)
		return;
	uloop_fd_delete(&w->ufd);
	free(w);
}

static void timer_trampoline(struct uloop_timeout *t)
{
	struct ev_timer *e = (struct ev_timer *)t;

	e->cb(e->arg);
}

struct ev_timer *ev_timer_new(ev_timer_cb cb, void *arg)
{
	struct ev_timer *t = calloc(1, sizeof(*t));

	if (!t)
		return NULL;
	t->cb = cb;
	t->arg = arg;
	t->to.cb = timer_trampoline;
	return t;
}

void ev_timer_set(struct ev_timer *t, uint64_t ms)
{
	uloop_timeout_set(&t->to, ms > 0x7fffffff ? 0x7fffffff : (int)ms);
}

void ev_timer_cancel(struct ev_timer *t)
{
	uloop_timeout_cancel(&t->to);
}

void ev_timer_free(struct ev_timer *t)
{
	if (!t)
		return;
	uloop_timeout_cancel(&t->to);
	free(t);
}
