/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>
#include "rp.h"

int rp_parse(const uint8_t *d, size_t n, struct rp_info *r)
{
	if (n < 2)
		return -1;
	r->mti = d[0] & 7;
	r->mr = d[1];
	r->cause = -1;
	/* RP-ERROR: RP-Cause is a length + value element, the cause itself is the first value octet */
	if ((r->mti == RP_ERROR_N_MS || r->mti == RP_ERROR_MS_N) && n >= 4 && d[2] >= 1)
		r->cause = d[3] & 0x7f;
	return 0;
}

const char *rp_mti_name(int mti)
{
	switch (mti) {
	case RP_DATA_MS_N: return "RP-DATA(ms->n)";
	case RP_DATA_N_MS: return "RP-DATA(n->ms)";
	case RP_ACK_MS_N: return "RP-ACK(ms->n)";
	case RP_ACK_N_MS: return "RP-ACK(n->ms)";
	case RP_ERROR_MS_N: return "RP-ERROR(ms->n)";
	case RP_ERROR_N_MS: return "RP-ERROR(n->ms)";
	case RP_SMMA: return "RP-SMMA";
	}
	return "RP-?";
}

void rp_build_ack(uint8_t mr, uint8_t out[2])
{
	out[0] = 0x02;
	out[1] = mr;
}

int rp_addr_from_str(const char *s, struct rp_addr *a)
{
	uint8_t toa = 0x81;
	int nd = 0, i;
	uint8_t dig[20];

	memset(a, 0, sizeof(*a));
	if (*s == '+') {
		toa = 0x91;
		s++;
	}
	for (; *s; s++) {
		if (nd >= 20)
			return -1;
		if (*s >= '0' && *s <= '9')
			dig[nd++] = *s - '0';
		else if (*s == '*')
			dig[nd++] = 0xa;
		else if (*s == '#')
			dig[nd++] = 0xb;
		else
			return -1;
	}
	if (!nd)
		return -1;
	a->b[0] = toa;
	for (i = 0; i < nd; i += 2) {
		uint8_t lo = dig[i], hi = i + 1 < nd ? dig[i + 1] : 0xf;

		a->b[1 + i / 2] = lo | (hi << 4);
	}
	a->len = 1 + (nd + 1) / 2;
	return 0;
}

int rp_addr_to_str(const struct rp_addr *a, char *out, size_t n)
{
	size_t k = 0, i;
	static const char dg[] = "0123456789*#abc";

	if (a->len < 2 || a->len > RP_ADDR_MAX)
		return -1;
	if (n < (size_t)(a->len - 1) * 2 + 2)
		return -1;
	if ((a->b[0] & 0x70) == 0x10)
		out[k++] = '+';
	for (i = 1; i < a->len; i++) {
		uint8_t lo = a->b[i] & 0xf, hi = a->b[i] >> 4;

		out[k++] = dg[lo];
		if (hi != 0xf)
			out[k++] = dg[hi];
	}
	out[k] = 0;
	return 0;
}

/* one length-prefixed address; 0 and advances *p, or -1 */
static int get_addr(const uint8_t *d, size_t n, size_t *p, struct rp_addr *a)
{
	size_t l;

	memset(a, 0, sizeof(*a));
	if (*p >= n)
		return -1;
	l = d[(*p)++];
	if (l == 0)
		return 0;
	if (l < 2 || l > RP_ADDR_MAX || *p + l > n)
		return -1;
	a->len = l;
	memcpy(a->b, d + *p, l);
	*p += l;
	return 0;
}

int rp_parse_data(const uint8_t *d, size_t n, struct rp_data *r)
{
	size_t p = 2, l;

	memset(r, 0, sizeof(*r));
	if (n < 5)
		return -1;
	r->mti = d[0] & 7;
	if (r->mti > 1)
		return -1;
	r->mr = d[1];
	if (get_addr(d, n, &p, &r->oa) || get_addr(d, n, &p, &r->da))
		return -1;
	if (p >= n)
		return -1;
	l = d[p++];
	if (p + l > n)
		return -1;
	r->ud = d + p;
	r->ud_len = l;
	return 0;
}

int rp_build_data_ms_n(uint8_t mr, const struct rp_addr *da, const uint8_t *tpdu, size_t n, uint8_t *out, size_t cap)
{
	size_t p = 0;

	if (n > 233 || !da->len || cap < 5u + da->len + n)
		return -1;
	out[p++] = 0x00;
	out[p++] = mr;
	out[p++] = 0x00;
	out[p++] = da->len;
	memcpy(out + p, da->b, da->len);
	p += da->len;
	out[p++] = (uint8_t)n;
	memcpy(out + p, tpdu, n);
	return (int)(p + n);
}

void rp_build_error(uint8_t mr, uint8_t cause, uint8_t out[4])
{
	out[0] = 0x04;
	out[1] = mr;
	out[2] = 0x01;
	out[3] = cause & 0x7f;
}

int rp_report_tpdu(const uint8_t *d, size_t n, const uint8_t **tpdu, size_t *len)
{
	size_t p = 2;
	int mti;

	*tpdu = NULL;
	*len = 0;
	if (n < 2)
		return -1;
	mti = d[0] & 7;
	if (mti == 5 || mti == 4) {		/* RP-ERROR: RP-Cause (length + value) comes first */
		if (n < 3 || d[2] < 1 || p + 1 + d[2] > n)
			return -1;
		p += 1 + d[2];
	}
	if (p == n)
		return 0;
	if (d[p] != 0x41 || p + 2 > n || p + 2 + d[p + 1] > n)
		return -1;
	*tpdu = d + p + 2;
	*len = d[p + 1];
	return 0;
}

const char *rp_cause_text(int cause)
{
	switch (cause) {
	case 1: return "unassigned (unallocated) number";
	case 8: return "operator determined barring";
	case 10: return "call barred";
	case 11: return "reserved";
	case 21: return "short message transfer rejected";
	case 22: return "memory capacity exceeded";
	case 27: return "destination out of order";
	case 28: return "unidentified subscriber";
	case 29: return "facility rejected";
	case 30: return "unknown subscriber";
	case 38: return "network out of order";
	case 41: return "temporary failure";
	case 42: return "congestion";
	case 47: return "resources unavailable, unspecified";
	case 50: return "requested facility not subscribed";
	case 69: return "requested facility not implemented";
	case 81: return "invalid short message transfer reference value";
	case 95: return "semantically incorrect message";
	case 96: return "invalid mandatory information";
	case 97: return "message type non-existent or not implemented";
	case 98: return "message not compatible with short message protocol state";
	case 99: return "information element non-existent or not implemented";
	case 111: return "protocol error, unspecified";
	case 127: return "interworking, unspecified";
	}
	return "unspecified cause";
}

int rp_cause_temporary(int cause)
{
	switch (cause) {
	case 22: case 27: case 38: case 41: case 42: case 47:
		return 1;
	}
	return 0;
}
