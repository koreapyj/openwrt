/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "log.h"
#include "codec.h"
#ifdef HAVE_ULOG
#include <libubox/ulog.h>
#endif

static int cur_level = LOG_INFO;
#ifndef HAVE_ULOG
static void (*log_hook)(int prio, const char *msg);

void imsd_log_set_hook(void (*hook)(int prio, const char *msg))
{
	log_hook = hook;
}
#endif

void imsd_log_open(const char *ident, int to_stderr)
{
#ifdef HAVE_ULOG
	ulog_open(ULOG_SYSLOG | (to_stderr ? ULOG_STDIO : 0), LOG_DAEMON, ident);
	ulog_threshold(LOG_DEBUG);	/* filtering is done here */
#else
	(void)ident;
	(void)to_stderr;
#endif
}

void imsd_log_level(int level)
{
	cur_level = level;
}

int imsd_log_get_level(void)
{
	return cur_level;
}

int imsd_log_parse_level(const char *s)
{
	static const struct { const char *n; int l; } t[] = {
		{ "error", LOG_ERR }, { "err", LOG_ERR }, { "warn", LOG_WARNING },
		{ "warning", LOG_WARNING }, { "notice", LOG_NOTICE },
		{ "info", LOG_INFO }, { "debug", LOG_DEBUG },
	};
	size_t i;

	if (s[0] >= '0' && s[0] <= '7' && !s[1])
		return s[0] - '0';
	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++)
		if (!strcasecmp(s, t[i].n))
			return t[i].l;
	return -1;
}

void imsd_log(int prio, const char *fmt, ...)
{
	va_list ap;

	if (prio > cur_level)
		return;
	va_start(ap, fmt);
#ifdef HAVE_ULOG
	{
		char msg[1024];

		vsnprintf(msg, sizeof(msg), fmt, ap);
		ulog(prio, "%s", msg);
	}
#else
	if (log_hook) {
		char msg[1024];
		va_list ap2;

		va_copy(ap2, ap);
		vsnprintf(msg, sizeof(msg), fmt, ap2);
		va_end(ap2);
		log_hook(prio, msg);
	}
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
#endif
	va_end(ap);
}

void imsd_hexdump(int prio, const char *what, const void *data, size_t n)
{
	char hex[2 * 256 + 1];
	size_t m = n > 256 ? 256 : n;

	if (prio > cur_level)
		return;
	hex_encode(data, m, hex);
	imsd_log(prio, "%s (%zu bytes): %s%s", what, n, hex, n > m ? "..." : "");
}
