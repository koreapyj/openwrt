/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "smsfmt.h"
#include "../sip/msg.h"

int smsfmt_sender(const struct tp_addr *a, char *user, size_t un, char *display, size_t dn)
{
	size_t k = 0, i;

	display[0] = 0;
	if (!a->alnum) {
		for (i = 0; a->str[i] && k + 4 < un; i++) {
			char c = a->str[i];

			if (c == '#') {
				user[k++] = '%';
				user[k++] = '2';
				user[k++] = '3';
			} else if (isdigit((unsigned char)c) || c == '*' || (c == '+' && i == 0)) {
				user[k++] = c;
			}
		}
		if (!k)
			user[k++] = '0';
		user[k] = 0;
		return 0;
	}
	k = (size_t)snprintf(user, un, "alnum.");
	for (i = 0; a->str[i] && k + 1 < un; i++) {
		unsigned char c = a->str[i];

		user[k++] = (isalnum(c) && c < 0x80) || c == '.' || c == '_' || c == '-' ? (char)c : '-';
	}
	user[k] = 0;
	smsfmt_quote_safe(a->str, display, dn);
	for (i = 0; display[i]; i++)
		if (display[i] == '<' || display[i] == '>')
			display[i] = '?';
	return 1;
}

void smsfmt_quote_safe(const char *s, char *out, size_t n)
{
	size_t i, k = 0;

	if (!n)
		return;
	for (i = 0; s[i]; i++) {
		unsigned char c = s[i];

		if (k + 1 >= n) {
			if (n > 4) {
				memcpy(out + n - 4, "...", 3);
				k = n - 1;
			}
			break;
		}
		out[k++] = (c < 0x20 || c == 0x7f || c == '"' || c == '\\') ? '?' : (char)c;
	}
	out[k] = 0;
}

int smsfmt_iso(const struct tp_scts *t, char *out, size_t n)
{
	int q, m;

	if (!t->valid || n < 26)
		return -1;
	q = t->tz_quarters;
	m = (q < 0 ? -q : q) * 15;
	snprintf(out, n, "%04d-%02d-%02dT%02d:%02d:%02d%c%02d:%02d", t->year, t->mon, t->day, t->hour, t->min,
		 t->sec, q < 0 ? '-' : '+', m / 60, m % 60);
	return 0;
}

int smsfmt_date(int64_t epoch, char *out, size_t n)
{
	static const char *const wd[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	static const char *const mo[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	struct tm tm;
	time_t tt = (time_t)epoch;

	if (n < 30 || (int64_t)tt != epoch || !gmtime_r(&tt, &tm))
		return -1;
	snprintf(out, n, "%s, %02d %s %04d %02d:%02d:%02d GMT", wd[tm.tm_wday], tm.tm_mday, mo[tm.tm_mon], tm.tm_year + 1900,
		 tm.tm_hour, tm.tm_min, tm.tm_sec);
	return 0;
}

static int hexv(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int smsfmt_dest(const char *ruri, char *out, size_t n)
{
	struct sip_uri u;
	char tmp[128];
	size_t i, k = 0, nd = 0;

	if (sip_uri_parse(ruri, &u))
		return SMSFMT_E_NOTNUM;
	if (strcmp(u.scheme, "sip") && strcmp(u.scheme, "sips") && strcmp(u.scheme, "tel"))
		return SMSFMT_E_NOTNUM;
	if (!u.user[0])
		return SMSFMT_E_NOTNUM;
	for (i = 0; u.user[i]; i++) {
		char c = u.user[i];

		if (c == '%') {
			int h = hexv(u.user[i + 1]), l = h < 0 ? -1 : hexv(u.user[i + 2]);

			if (h < 0 || l < 0)
				return SMSFMT_E_NOTNUM;
			c = (char)(h * 16 + l);
			i += 2;
		}
		if (c == ' ' || c == '-' || c == '.' || c == '(' || c == ')')
			continue;
		if (k + 1 >= sizeof(tmp))
			return SMSFMT_E_LENGTH;
		if (c == '+' && k == 0) {
			tmp[k++] = c;
		} else if (isdigit((unsigned char)c) || c == '*' || c == '#') {
			tmp[k++] = c;
			nd++;
		} else {
			return SMSFMT_E_NOTNUM;
		}
	}
	tmp[k] = 0;
	if (nd == 0 || nd > 20 || n < k + 1)
		return SMSFMT_E_LENGTH;
	memcpy(out, tmp, k + 1);
	return 0;
}
