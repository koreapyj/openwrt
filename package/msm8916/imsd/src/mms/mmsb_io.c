/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The small file system side of the MMS bearer (daemon only): IPv6 switch of the netdev and the bearer marker. Short writes to procfs / tmpfs. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mmsb_io.h"
#include "../util/log.h"

#define MARKER "/tmp/imsd-mms-bearer"

void mmsb_io_ipv6_disable(void *ctx, const char *ifname, bool disable)
{
	char path[96];
	FILE *f;

	(void)ctx;
	if (!ifname[0] || strchr(ifname, '/'))
		return;
	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", ifname);
	f = fopen(path, "w");
	if (!f) {
		if (errno != ENOENT)
			LOGW("mms: cannot %s IPv6 on %s: %s", disable ? "disable" : "enable", ifname, strerror(errno));
		return;
	}
	fputs(disable ? "1\n" : "0\n", f);
	fclose(f);
}

void mmsb_io_marker_load(void *ctx, char *modem, size_t mn, char *bearer, size_t bn)
{
	FILE *f = fopen(MARKER, "r");

	(void)ctx;
	modem[0] = bearer[0] = 0;
	if (!f)
		return;
	if (fgets(modem, (int)mn, f))
		modem[strcspn(modem, "\r\n")] = 0;
	if (fgets(bearer, (int)bn, f))
		bearer[strcspn(bearer, "\r\n")] = 0;
	fclose(f);
}

void mmsb_io_marker_save(void *ctx, const char *modem, const char *bearer)
{
	FILE *f = fopen(MARKER, "w");

	(void)ctx;
	if (!f)
		return;
	fprintf(f, "%s\n%s\n", modem, bearer);
	fclose(f);
}

void mmsb_io_marker_clear(void *ctx)
{
	(void)ctx;
	unlink(MARKER);
}
