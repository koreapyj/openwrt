/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UTIL_LOG_H
#define IMSD_UTIL_LOG_H
#include <stddef.h>
#include <stdint.h>
#include <syslog.h>

/*
 * Logging. With -DHAVE_ULOG (the daemon) messages go through libubox ulog
 * (syslog / stdio); without it (host unit tests) they go to stderr.
 * Levels are syslog priorities: LOG_ERR .. LOG_DEBUG.
 */

/* open the log backend; ident is the syslog identity; to_stderr adds a stdio channel */
void imsd_log_open(const char *ident, int to_stderr);
/* messages with a priority numerically above level are dropped (default LOG_INFO) */
void imsd_log_level(int level);
int imsd_log_get_level(void);
/* parse "error|warn|notice|info|debug" (or 0..7); -1 if unknown */
int imsd_log_parse_level(const char *s);

#ifndef HAVE_ULOG
/* host tests: every message that passes the level filter is also handed to hook (NULL: none) */
void imsd_log_set_hook(void (*hook)(int prio, const char *msg));
#endif

void imsd_log(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* debug dump of a binary blob as hex, truncated to 256 bytes. Never use for key material. */
void imsd_hexdump(int prio, const char *what, const void *data, size_t n);

#define LOGE(...) imsd_log(LOG_ERR, __VA_ARGS__)
#define LOGW(...) imsd_log(LOG_WARNING, __VA_ARGS__)
#define LOGN(...) imsd_log(LOG_NOTICE, __VA_ARGS__)
#define LOGI(...) imsd_log(LOG_INFO, __VA_ARGS__)
#define LOGD(...) imsd_log(LOG_DEBUG, __VA_ARGS__)
#endif
