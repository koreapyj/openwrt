/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Text rendering of a received MMS, see mmsrender.h. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "mmsrender.h"
#include "../ua/lan_text.h"
#include "../smscodec/utf8.h"

bool mmsr_is_smil(const struct mms_part *p)
{
	return !strcasecmp(p->type, "application/smil") || !strcasecmp(p->type, "text/smil");
}

bool mmsr_is_text(const struct mms_part *p)
{
	return !strcasecmp(p->type, "text/plain") || !strcasecmp(p->type, "text/html");
}

/* ------------------------------------------------------------------ */
/* HTML                                                                */

static bool tag_is(const char *t, size_t l, const char *name)
{
	return strlen(name) == l && !strncasecmp(t, name, l);
}

static void put_nl(struct buf *b, size_t start)
{
	if (b->len > start && b->p[b->len - 1] != '\n')
		buf_putc(b, '\n');
}

static void put_cp(struct buf *b, uint32_t cp)
{
	char t[4];
	int l = utf8_encode(cp, t);

	if (l)
		buf_add(b, t, (size_t)l);
}

/* an entity starting at s[0] == '&'; returns the length consumed, 0 if it is not one */
static size_t entity(const char *s, struct buf *b)
{
	static const struct { const char *n; const char *r; } E[] = {
		{ "amp", "&" }, { "lt", "<" }, { "gt", ">" }, { "quot", "\"" }, { "apos", "'" }, { "nbsp", " " },
	};
	size_t i, k;

	if (s[1] == '#') {
		unsigned long v = 0;
		bool hex = s[2] == 'x' || s[2] == 'X';

		k = hex ? 3 : 2;
		if (!isxdigit((unsigned char)s[k]) && !isdigit((unsigned char)s[k]))
			return 0;
		for (; s[k] && s[k] != ';' && k < 12; k++) {
			unsigned char c = (unsigned char)s[k];

			if (hex ? !isxdigit(c) : !isdigit(c))
				return 0;
			v = v * (hex ? 16 : 10) + (unsigned long)(isdigit(c) ? c - '0' : tolower(c) - 'a' + 10);
		}
		if (s[k] != ';' || v == 0 || v > 0x10ffff)
			return 0;
		put_cp(b, (uint32_t)v);
		return k + 1;
	}
	for (i = 0; i < sizeof(E) / sizeof(E[0]); i++) {
		size_t l = strlen(E[i].n);

		if (!strncmp(s + 1, E[i].n, l) && s[1 + l] == ';') {
			buf_puts(b, E[i].r);
			return l + 2;
		}
	}
	return 0;
}

void mmsr_html_to_text(const char *h, struct buf *b)
{
	size_t start = b->len;
	bool space = false;

	while (*h) {
		if (*h == '<') {
			const char *t = h + 1, *e;
			size_t l;

			if (!strncmp(h, "<!--", 4)) {
				e = strstr(h + 4, "-->");
				h = e ? e + 3 : h + strlen(h);
				continue;
			}
			if (*t == '/')
				t++;
			l = 0;
			while (isalnum((unsigned char)t[l]))
				l++;
			e = strchr(h, '>');
			if (!e) {
				h += strlen(h);
				break;
			}
			if (tag_is(t, l, "script") || tag_is(t, l, "style")) {
				char close[16];
				const char *c;

				snprintf(close, sizeof(close), "</%.*s", (int)l, t);
				c = strcasestr(e, close);
				if (!c)
					break;
				e = strchr(c, '>');
				if (!e)
					break;
			} else if (tag_is(t, l, "br") || tag_is(t, l, "p") || tag_is(t, l, "div") || tag_is(t, l, "li") ||
				   tag_is(t, l, "tr") || (l == 2 && toupper((unsigned char)t[0]) == 'H' && isdigit((unsigned char)t[1]))) {
				put_nl(b, start);
				space = false;
			}
			h = e + 1;
			continue;
		}
		if (*h == '&') {
			size_t k = entity(h, b);

			if (k) {
				h += k;
				space = false;
				continue;
			}
		}
		if (*h == ' ' || *h == '\t' || *h == '\r' || *h == '\n') {
			if (b->len > start && b->p[b->len - 1] != '\n')
				space = true;
			h++;
			continue;
		}
		if (space) {
			buf_putc(b, ' ');
			space = false;
		}
		buf_putc(b, *h++);
	}
	while (b->len > start && (b->p[b->len - 1] == '\n' || b->p[b->len - 1] == ' ')) {
		b->len--;
		b->p[b->len] = 0;
	}
}

void mmsr_part_text(const struct mms_part *p, struct buf *out)
{
	size_t n = p->len > MMSR_PART_TEXT_MAX ? MMSR_PART_TEXT_MAX : p->len;
	size_t cap = n * 3 + 4, k;
	char *t;

	if (cap > MMSR_PART_TEXT_MAX * 3 + 4)
		cap = MMSR_PART_TEXT_MAX * 3 + 4;
	t = malloc(cap);
	if (!t)
		return;
	k = wsp_to_utf8((unsigned)p->charset, p->data, n, t, cap);
	if (!strcasecmp(p->type, "text/html")) {
		mmsr_html_to_text(t, out);
	} else {
		/* keep the text as it is; trailing line breaks and a stray NUL do not matter */
		while (k && (t[k - 1] == '\n' || t[k - 1] == '\r'))
			k--;
		buf_add(out, t, k);
	}
	free(t);
}

/* ------------------------------------------------------------------ */
/* SMIL order                                                          */

static bool ref_matches(const struct mms_part *p, const char *ref)
{
	if (!strncasecmp(ref, "cid:", 4))
		return p->content_id[0] && !strcmp(p->content_id, ref + 4);
	return (p->location[0] && !strcmp(p->location, ref)) || (p->content_id[0] && !strcmp(p->content_id, ref));
}

unsigned mmsr_order(const struct mms_part *parts, unsigned n, unsigned *order)
{
	bool used[MMS_MAX_PARTS] = { false };
	unsigned i, k = 0, smil = n;

	if (n > MMS_MAX_PARTS)
		n = MMS_MAX_PARTS;
	for (i = 0; i < n; i++)
		if (mmsr_is_smil(&parts[i])) {
			smil = i;
			used[i] = true;
			break;
		}
	if (smil < n && parts[smil].len) {
		char *s = malloc(parts[smil].len + 1);
		const char *p;

		if (s) {
			memcpy(s, parts[smil].data, parts[smil].len);
			s[parts[smil].len] = 0;
			for (p = s; (p = strcasestr(p, "src=")); p += 4) {
				char q = p[4], ref[WSP_NAME_MAX];
				const char *e;
				size_t l;

				if (p == s || !isspace((unsigned char)p[-1]) || (q != '"' && q != '\''))
					continue;
				e = strchr(p + 5, q);
				if (!e)
					break;
				l = (size_t)(e - (p + 5));
				if (l >= sizeof(ref))
					continue;
				memcpy(ref, p + 5, l);
				ref[l] = 0;
				for (i = 0; i < n; i++)
					if (!used[i] && ref_matches(&parts[i], ref)) {
						used[i] = true;
						order[k++] = i;
						break;
					}
			}
			free(s);
		}
	}
	for (i = 0; i < n; i++) {
		if (!used[i] && !mmsr_is_smil(&parts[i]))
			order[k++] = i;
	}
	return k;
}

/* ------------------------------------------------------------------ */

void mmsr_oneline(const char *in, char *out, size_t n)
{
	size_t k = 0, i;

	if (!n)
		return;
	for (i = 0; in[i] && k + 1 < n; i++) {
		unsigned char c = (unsigned char)in[i];

		out[k++] = c < 0x20 || c == 0x7f ? ' ' : (char)c;
	}
	/* cut in the middle of a multi-byte character: drop the partial character */
	if (in[i] && ((unsigned char)in[i] & 0xc0) == 0x80) {
		while (k && ((unsigned char)out[k - 1] & 0xc0) == 0x80)
			k--;
		if (k)
			k--;
	}
	out[k] = 0;
}

void mmsr_human_size(size_t n, char *out, size_t cap)
{
	if (n >= 1024 * 1024)
		snprintf(out, cap, "%.1f MB", (double)n / (1024.0 * 1024.0));
	else if (n >= 1024)
		snprintf(out, cap, "%zu KB", (n + 512) / 1024);
	else
		snprintf(out, cap, "%zu B", n);
}

unsigned mmsr_split(const char *s, size_t len, size_t limit, size_t *off, size_t *plen, unsigned max, bool *truncated)
{
	return lan_text_split(s, len, limit, off, plen, max, truncated);
}
