/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "qrtr.h"

static void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

static uint32_t get_le32(const uint8_t *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
}

int qrtr_build_lookup(uint8_t *out, size_t cap, uint32_t service)
{
	if (cap < QRTR_CTRL_PKT_LEN)
		return -1;
	memset(out, 0, QRTR_CTRL_PKT_LEN);
	put_le32(out, QRTR_CTRL_NEW_LOOKUP);
	put_le32(out + 4, service);
	return QRTR_CTRL_PKT_LEN;
}

int qrtr_parse_ctrl(const uint8_t *d, size_t n, uint32_t *cmd, struct qrtr_server *s)
{
	if (n < QRTR_CTRL_PKT_LEN)
		return -1;
	*cmd = get_le32(d);
	s->service = get_le32(d + 4);
	s->instance = get_le32(d + 8);
	s->node = get_le32(d + 12);
	s->port = get_le32(d + 16);
	return 0;
}

bool qrtr_is_end(const struct qrtr_server *s)
{
	return !s->service && !s->instance && !s->node && !s->port;
}

bool qrtr_is_ims_service(uint32_t service)
{
	return service == QRTR_SVC_IMS_SETTINGS || service == QRTR_SVC_IMS_APP;
}
