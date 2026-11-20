/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "fakeep.h"

static int fk_send(struct sip_endpoint *ep, const struct addr *dst, const void *data, size_t len)
{
	struct fakeep *f = ep->priv;

	if (f->fail_errno)
		return -f->fail_errno;
	if (f->nsent >= FAKE_MAX_SENT)
		return -ENOBUFS;
	f->sent[f->nsent].data = malloc(len + 1);
	memcpy(f->sent[f->nsent].data, data, len);
	f->sent[f->nsent].data[len] = 0;
	f->sent[f->nsent].len = len;
	f->sent[f->nsent].dst = *dst;
	f->nsent++;
	return 0;
}

static const struct sip_ep_ops fk_ops = { .send = fk_send, .close = NULL };

struct fakeep *fakeep_new(const char *name, bool reliable, const struct addr *resp_override)
{
	struct fakeep *f = calloc(1, sizeof(*f));
	struct sip_ep_cfg c;

	memset(&c, 0, sizeof(c));
	c.name = name;
	c.reliable = reliable;
	addr_set(&c.rx_bind, "2001:db8::1", 5060);
	if (resp_override) {
		c.has_resp_override = true;
		c.resp_override = *resp_override;
	}
	f->ep = sip_ep_create_custom(&c, &fk_ops, f);
	return f;
}

void fakeep_clear(struct fakeep *f)
{
	int i;

	for (i = 0; i < f->nsent; i++)
		free(f->sent[i].data);
	f->nsent = 0;
}

void fakeep_free(struct fakeep *f)
{
	fakeep_clear(f);
	sip_ep_retire(f->ep);
	free(f);
}

int fakeep_parse(const struct fakeep *f, int i, struct sip_msg *m)
{
	return i < f->nsent ? sip_parse(f->sent[i].data, f->sent[i].len, m) : -1;
}

void fakeep_rx_n(struct fakeep *f, const struct addr *src, const void *msg, size_t n)
{
	sip_ep_deliver(f->ep, src, msg, n);
}

void fakeep_rx(struct fakeep *f, const struct addr *src, const char *msg)
{
	sip_ep_deliver(f->ep, src, (const uint8_t *)msg, strlen(msg));
}

static void fk_close(struct sip_endpoint *ep)
{
	struct fakeep *f = ep->priv;

	f->closed = true;
	f->ep = NULL;
}

static const struct sip_ep_ops fk_ops_open = { .send = fk_send, .close = fk_close };

struct fakeep *fakeep_open(const struct sip_ep_cfg *cfg)
{
	struct fakeep *f = calloc(1, sizeof(*f));

	f->ep = sip_ep_create_custom(cfg, &fk_ops_open, f);
	return f;
}

void fakeep_destroy(struct fakeep *f)
{
	fakeep_clear(f);
	free(f);
}
