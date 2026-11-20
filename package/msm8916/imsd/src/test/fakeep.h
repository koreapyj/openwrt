/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_TEST_FAKEEP_H
#define IMSD_TEST_FAKEEP_H
#include "../sip/transport.h"
#include "../sip/msg.h"

/* An endpoint whose "network" is an in-memory log of sent datagrams. */
#define FAKE_MAX_SENT 128
struct fakeep {
	struct sip_endpoint *ep;
	struct {
		uint8_t *data;
		size_t len;
		struct addr dst;
	} sent[FAKE_MAX_SENT];
	int nsent;
	bool closed;		/* the backend close op ran: the last reference is gone */
	int fail_errno;		/* when nonzero sends fail with -fail_errno (and are not logged) */
};

/* endpoint from a full config (the ep registry of the registration tests); tracks closing. fakeep_destroy frees the log and the struct (after the endpoint closed or when it does not matter) */
struct fakeep *fakeep_open(const struct sip_ep_cfg *cfg);
void fakeep_destroy(struct fakeep *f);
/* create; reliable/split/override per args */
struct fakeep *fakeep_new(const char *name, bool reliable, const struct addr *resp_override);
void fakeep_free(struct fakeep *f);	/* drops the creator reference and the log */
void fakeep_clear(struct fakeep *f);
/* parse sent[i] into m (caller frees with sip_msg_free); 0 / -1 */
int fakeep_parse(const struct fakeep *f, int i, struct sip_msg *m);
/* inject a datagram as if received from src */
void fakeep_rx(struct fakeep *f, const struct addr *src, const char *msg);
void fakeep_rx_n(struct fakeep *f, const struct addr *src, const void *msg, size_t n);
#endif
