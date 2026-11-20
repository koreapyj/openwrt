/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_MMSB_IO_H
#define IMSD_MMS_MMSB_IO_H
#include <stdbool.h>
#include <stddef.h>

/* IPv6 on the netdev (/proc/sys/net/ipv6/conf/<if>/disable_ipv6) */
void mmsb_io_ipv6_disable(void *ctx, const char *ifname, bool disable);
/* the marker of the MMS bearer imsd created (/tmp/imsd-mms-bearer: modem path, bearer path), so that a crashed run's bearer is cleaned up */
void mmsb_io_marker_load(void *ctx, char *modem, size_t mn, char *bearer, size_t bn);
void mmsb_io_marker_save(void *ctx, const char *modem, const char *bearer);
void mmsb_io_marker_clear(void *ctx);
#endif
