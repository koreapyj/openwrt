/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_MMS_MMSITEM_H
#define IMSD_MMS_MMSITEM_H
#include <stdint.h>
#include <string.h>
#include "mmspdu.h"
#include "../store/pack.h"

/*
 * The "meta" of a STORE_MMS item (store/store.h); the body is the m-retrieve-conf as the MMSC sent it (absent when the retrieval failed):
 *   u8 version (1), u8 flags, i64 arrival (Unix time), u32 announced size, str from, str subject, str tid (transaction id of the
 *   notification), str message_id (of the retrieve-conf, may be ""), str location (X-Mms-Content-Location), bytes pdu (the original
 *   m-notification-ind, empty when it was too long to keep)
 * and of a STORE_CARBON_MMS item (the body is the M-Send.req):
 *   u8 version (1), u8 truncated-recipients, i64 time, str id (32 hex digits: /mms/sent/<id>), str message_id, str peers, str subject
 */
#define MMSI_HAS_BODY	1u	/* the retrieve-conf is the body */
#define MMSI_FAILED	2u	/* the retrieval failed for good: no body */
#define MMSI_TOOBIG	4u	/* ... because the message is larger than mms_max_size (refused) */

struct mms_item {
	uint8_t flags;
	int64_t arrive;
	uint32_t size;
	char from[MMS_ADDR_MAX], subject[MMS_SUBJ_MAX], tid[MMS_ID_MAX], mid[MMS_ID_MAX], location[MMS_URL_MAX];
	const uint8_t *pdu;
	size_t pdu_len;
};

static inline size_t mmsi_pack(const struct mms_item *it, uint8_t *out, size_t cap)
{
	struct pkw w;

	pkw_init(&w, out, cap);
	pkw_u8(&w, 1);
	pkw_u8(&w, it->flags);
	pkw_u64(&w, (uint64_t)it->arrive);
	pkw_u32(&w, it->size);
	pkw_str(&w, it->from);
	pkw_str(&w, it->subject);
	pkw_str(&w, it->tid);
	pkw_str(&w, it->mid);
	pkw_str(&w, it->location);
	pkw_bytes(&w, it->pdu, it->pdu_len);
	return w.ovf ? 0 : w.len;
}

/* 0 / -1 */
static inline int mmsi_parse(const uint8_t *meta, size_t n, struct mms_item *it)
{
	struct pkr r;

	memset(it, 0, sizeof(*it));
	pkr_init(&r, meta, n);
	if (pkr_u8(&r) != 1)
		return -1;
	it->flags = pkr_u8(&r);
	it->arrive = (int64_t)pkr_u64(&r);
	it->size = pkr_u32(&r);
	pkr_str(&r, it->from, sizeof(it->from));
	pkr_str(&r, it->subject, sizeof(it->subject));
	pkr_str(&r, it->tid, sizeof(it->tid));
	pkr_str(&r, it->mid, sizeof(it->mid));
	pkr_str(&r, it->location, sizeof(it->location));
	it->pdu = pkr_bytes(&r, &it->pdu_len);
	return r.bad ? -1 : 0;
}

struct mms_carbon_item {
	bool trunc;
	int64_t time;
	char id[40], mid[MMS_ID_MAX], peers[1100], subject[MMS_SUBJ_MAX];
};

static inline size_t mmsc_pack(const struct mms_carbon_item *c, uint8_t *out, size_t cap)
{
	struct pkw w;

	pkw_init(&w, out, cap);
	pkw_u8(&w, 1);
	pkw_u8(&w, c->trunc);
	pkw_u64(&w, (uint64_t)c->time);
	pkw_str(&w, c->id);
	pkw_str(&w, c->mid);
	pkw_str(&w, c->peers);
	pkw_str(&w, c->subject);
	return w.ovf ? 0 : w.len;
}

static inline int mmsc_parse(const uint8_t *meta, size_t n, struct mms_carbon_item *c)
{
	struct pkr r;

	memset(c, 0, sizeof(*c));
	pkr_init(&r, meta, n);
	if (pkr_u8(&r) != 1)
		return -1;
	c->trunc = pkr_u8(&r) != 0;
	c->time = (int64_t)pkr_u64(&r);
	pkr_str(&r, c->id, sizeof(c->id));
	pkr_str(&r, c->mid, sizeof(c->mid));
	pkr_str(&r, c->peers, sizeof(c->peers));
	pkr_str(&r, c->subject, sizeof(c->subject));
	return r.bad ? -1 : 0;
}
#endif
