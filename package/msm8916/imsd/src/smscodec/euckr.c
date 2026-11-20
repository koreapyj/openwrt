/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "euckr.h"
#include "utf8.h"
#include "euckr_tab.h"

static uint32_t euckr_lookup(uint8_t lead, uint8_t trail)
{
	unsigned row, col = trail - 0xA1u;

	if (trail < 0xA1 || trail > 0xFE)
		return 0;
	if (lead >= EUCKR_SYM_LEAD0 && lead <= EUCKR_SYM_LEAD1) {
		row = lead - EUCKR_SYM_LEAD0;
		return euckr_sym[row * 94 + col];
	}
	if (lead >= EUCKR_HANGUL_LEAD0 && lead <= EUCKR_HANGUL_LEAD1) {
		row = lead - EUCKR_HANGUL_LEAD0;
		return euckr_hangul[row * 94 + col];
	}
	if (lead >= EUCKR_HANJA_LEAD0 && lead <= EUCKR_HANJA_LEAD1) {
		row = lead - EUCKR_HANJA_LEAD0;
		return euckr_hanja[row * 94 + col];
	}
	return 0;
}

int euckr_to_utf8(const uint8_t *in, size_t n, struct buf *out, bool *lossy)
{
	size_t i = 0;

	while (i < n) {
		uint32_t cp;
		char t[4];
		int k;

		if (in[i] < 0x80) {
			cp = in[i++];
		} else if (i + 1 >= n) {
			cp = UTF8_REPLACEMENT;
			i++;
			if (lossy)
				*lossy = true;
		} else {
			cp = euckr_lookup(in[i], in[i + 1]);
			if (!cp) {
				cp = UTF8_REPLACEMENT;
				if (lossy)
					*lossy = true;
			}
			i += 2;
		}
		k = utf8_encode(cp, t);
		if (buf_add(out, t, (size_t)k) < 0)
			return -1;
	}
	return 0;
}
