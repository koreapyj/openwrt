/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * The process runner of the traffic guard (mmsguard.h): `nft` as a child process, without ever waiting for it on the main loop.
 * posix_spawnp, the script on its stdin and the output on its stdout through two non-blocking unix socketpairs (send / recv with
 * MSG_NOSIGNAL: a child that exits early must not raise SIGPIPE in the daemon), watched by the event loop; once the child closed its
 * output, waitpid(WNOHANG) is polled by a short timer. A child that is not finished after RUN_TIMEOUT_MS is killed (-ETIMEDOUT).
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include "mmsguard.h"
#include "../util/evloop.h"
#include "../util/log.h"

#define RUN_TIMEOUT_MS	10000u
#define REAP_POLL_MS	20u
#define OUT_MAX		8192

extern char **environ;

struct gx {
	pid_t pid;
	int in_fd, out_fd;
	struct ev_fd *wr, *rd;
	struct ev_timer *t;
	char *in;
	size_t in_len, in_off;
	char out[OUT_MAX];
	size_t out_len;
	bool out_eof;
	uint64_t deadline;
	void (*cb)(void *arg, int status, const char *out);
	void *arg;
};

static void gx_free(struct gx *x)
{
	ev_fd_del(x->wr);
	ev_fd_del(x->rd);
	ev_timer_free(x->t);
	if (x->in_fd >= 0)
		close(x->in_fd);
	if (x->out_fd >= 0)
		close(x->out_fd);
	free(x->in);
	free(x);
}

static void finish(struct gx *x, int status)
{
	void (*cb)(void *, int, const char *) = x->cb;
	void *arg = x->arg;

	x->out[x->out_len < OUT_MAX ? x->out_len : OUT_MAX - 1] = 0;
	cb(arg, status, x->out);
	gx_free(x);
}

static void try_reap(struct gx *x)
{
	int st = 0;
	pid_t r;

	if (!x->out_eof || x->in_fd >= 0)
		return;
	r = waitpid(x->pid, &st, WNOHANG);
	if (r == x->pid) {
		x->pid = 0;
		finish(x, WIFEXITED(st) ? WEXITSTATUS(st) : 128 + (WIFSIGNALED(st) ? WTERMSIG(st) : 0));
		return;
	}
	if (r < 0 && errno != EINTR) {
		x->pid = 0;
		finish(x, -errno);
		return;
	}
	ev_timer_set(x->t, REAP_POLL_MS);
}

static void on_timer(void *arg)
{
	struct gx *x = arg;

	if (ev_now_ms() >= x->deadline) {
		LOGW("mms: traffic guard: nft did not finish in %u ms, killed", RUN_TIMEOUT_MS);
		kill(x->pid, SIGKILL);
		waitpid(x->pid, NULL, WNOHANG);	/* never waits; a zombie that is not reaped here is harmless */
		x->pid = 0;
		finish(x, -ETIMEDOUT);
		return;
	}
	if (x->out_eof && x->in_fd < 0) {
		try_reap(x);		/* re-arms itself while the child has not exited yet */
		return;
	}
	ev_timer_set(x->t, 500);
}

static void on_read(void *arg, int fd)
{
	struct gx *x = arg;
	ssize_t n;

	(void)fd;
	for (;;) {
		char tmp[1024];

		n = recv(x->out_fd, tmp, sizeof(tmp), MSG_DONTWAIT);
		if (n > 0) {
			size_t room = OUT_MAX - 1 - x->out_len;

			if ((size_t)n > room)
				n = (ssize_t)room;
			memcpy(x->out + x->out_len, tmp, (size_t)n);
			x->out_len += (size_t)n;
			continue;
		}
		if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
			x->out_eof = true;
			ev_fd_del(x->rd);
			x->rd = NULL;
			close(x->out_fd);
			x->out_fd = -1;
			try_reap(x);
		}
		return;
	}
}

static void on_write(void *arg, int fd)
{
	struct gx *x = arg;

	(void)fd;
	while (x->in_off < x->in_len) {
		ssize_t n = send(x->in_fd, x->in + x->in_off, x->in_len - x->in_off, MSG_DONTWAIT | MSG_NOSIGNAL);

		if (n > 0) {
			x->in_off += (size_t)n;
			continue;
		}
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			return;
		break;		/* EPIPE and the like: the child closed its input, the exit status tells the rest */
	}
	ev_fd_del(x->wr);
	x->wr = NULL;
	close(x->in_fd);
	x->in_fd = -1;
	try_reap(x);
}

static void *r_run(void *ctx, const char *const *argv, const char *stdin_text, void (*cb)(void *arg, int status, const char *out), void *arg)
{
	struct gx *x = calloc(1, sizeof(*x));
	int sin[2] = { -1, -1 }, sout[2] = { -1, -1 }, e = 0;
	posix_spawn_file_actions_t fa;
	bool fa_ok = false;

	(void)ctx;
	if (!x)
		return NULL;
	x->in_fd = x->out_fd = -1;
	x->cb = cb;
	x->arg = arg;
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sin) || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sout)) {
		e = errno;
		goto fail;
	}
	if (posix_spawn_file_actions_init(&fa)) {
		e = ENOMEM;
		goto fail;
	}
	fa_ok = true;
	posix_spawn_file_actions_adddup2(&fa, sin[0], 0);
	posix_spawn_file_actions_adddup2(&fa, sout[0], 1);
	posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
	e = posix_spawnp(&x->pid, argv[0], &fa, NULL, (char *const *)argv, environ);
	posix_spawn_file_actions_destroy(&fa);
	fa_ok = false;
	if (e)
		goto fail;
	close(sin[0]);
	close(sout[0]);
	x->in_fd = sin[1];
	x->out_fd = sout[1];
	if (stdin_text && stdin_text[0]) {
		x->in = strdup(stdin_text);
		x->in_len = x->in ? strlen(x->in) : 0;
	}
	x->t = ev_timer_new(on_timer, x);
	x->rd = ev_fd_add(x->out_fd, on_read, x);
	if (x->in_len)
		x->wr = ev_fd_add_ev(x->in_fd, EV_WRITE, on_write, x);
	if (!x->t || !x->rd || (x->in_len && !x->wr)) {
		kill(x->pid, SIGKILL);
		waitpid(x->pid, NULL, WNOHANG);
		e = ENOMEM;
		goto fail2;
	}
	if (!x->in_len) {
		close(x->in_fd);	/* nothing to feed: EOF on its stdin */
		x->in_fd = -1;
	}
	x->deadline = ev_now_ms() + RUN_TIMEOUT_MS;
	ev_timer_set(x->t, 500);
	return x;
fail:
	if (sin[0] >= 0)
		close(sin[0]);
	if (sout[0] >= 0)
		close(sout[0]);
	if (sin[1] >= 0)
		close(sin[1]);
	if (sout[1] >= 0)
		close(sout[1]);
	if (fa_ok)
		posix_spawn_file_actions_destroy(&fa);
	free(x);
	errno = e;
	return NULL;
fail2:
	gx_free(x);
	errno = e;
	return NULL;
}

static void r_cancel(void *ctx, void *h)
{
	struct gx *x = h;

	(void)ctx;
	if (x->pid > 0) {
		kill(x->pid, SIGKILL);
		waitpid(x->pid, NULL, WNOHANG);	/* never waits */
	}
	gx_free(x);
}

static const struct guard_exec_ops real_ops = { .run = r_run, .cancel = r_cancel };

const struct guard_exec_ops *guard_exec_real(void)
{
	return &real_ops;
}
