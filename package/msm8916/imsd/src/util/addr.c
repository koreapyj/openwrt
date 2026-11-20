/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "addr.h"

static void map_v4(struct in6_addr *o, uint32_t be)
{
	memset(o, 0, sizeof(*o));
	o->s6_addr[10] = o->s6_addr[11] = 0xff;
	memcpy(o->s6_addr + 12, &be, 4);
}

int addr_set(struct addr *a, const char *host, uint16_t port)
{
	char tmp[64];
	struct in_addr v4;
	size_t l = strlen(host);

	memset(a, 0, sizeof(*a));
	a->sa.sin6_family = AF_INET6;
	a->sa.sin6_port = htons(port);
	if (l >= 2 && host[0] == '[' && host[l - 1] == ']') {
		if (l - 2 >= sizeof(tmp))
			return -1;
		memcpy(tmp, host + 1, l - 2);
		tmp[l - 2] = 0;
		host = tmp;
	}
	if (inet_pton(AF_INET6, host, &a->sa.sin6_addr) == 1)
		return 0;
	if (inet_pton(AF_INET, host, &v4) == 1) {
		map_v4(&a->sa.sin6_addr, v4.s_addr);
		return 0;
	}
	return -1;
}

void addr_from_sa6(struct addr *a, const struct sockaddr_in6 *sa)
{
	memset(a, 0, sizeof(*a));
	a->sa = *sa;
	a->sa.sin6_family = AF_INET6;
	a->sa.sin6_flowinfo = 0;
}

void addr_set_v4(struct addr *a, uint32_t be, uint16_t port)
{
	memset(a, 0, sizeof(*a));
	a->sa.sin6_family = AF_INET6;
	a->sa.sin6_port = htons(port);
	map_v4(&a->sa.sin6_addr, be);
}

void addr_set_v6(struct addr *a, const uint8_t v6[16], uint16_t port)
{
	memset(a, 0, sizeof(*a));
	a->sa.sin6_family = AF_INET6;
	a->sa.sin6_port = htons(port);
	memcpy(a->sa.sin6_addr.s6_addr, v6, 16);
}

bool addr_is_v4(const struct addr *a)
{
	return IN6_IS_ADDR_V4MAPPED(&a->sa.sin6_addr);
}

uint16_t addr_port(const struct addr *a)
{
	return ntohs(a->sa.sin6_port);
}

void addr_set_port(struct addr *a, uint16_t port)
{
	a->sa.sin6_port = htons(port);
}

int addr_family(const struct addr *a)
{
	return addr_is_v4(a) ? AF_INET : AF_INET6;
}

int addr_host(const struct addr *a, char *out, size_t n)
{
	if (addr_is_v4(a))
		return inet_ntop(AF_INET, a->sa.sin6_addr.s6_addr + 12, out, n) ? 0 : -1;
	return inet_ntop(AF_INET6, &a->sa.sin6_addr, out, n) ? 0 : -1;
}

int addr_uri_host(const struct addr *a, char *out, size_t n)
{
	char h[INET6_ADDRSTRLEN];
	int r;

	if (addr_host(a, h, sizeof(h)))
		return -1;
	r = snprintf(out, n, addr_is_v4(a) ? "%s" : "[%s]", h);
	return r < 0 || (size_t)r >= n ? -1 : 0;
}

int addr_str(const struct addr *a, char *out, size_t n)
{
	char h[INET6_ADDRSTRLEN + 2];
	int r;

	if (addr_uri_host(a, h, sizeof(h)))
		return -1;
	r = snprintf(out, n, "%s:%u", h, addr_port(a));
	return r < 0 || (size_t)r >= n ? -1 : 0;
}

int addr_sdp(const struct addr *a, char *out, size_t n)
{
	char h[INET6_ADDRSTRLEN];
	int r;

	if (addr_host(a, h, sizeof(h)))
		return -1;
	r = snprintf(out, n, "%s %s", addr_is_v4(a) ? "IP4" : "IP6", h);
	return r < 0 || (size_t)r >= n ? -1 : 0;
}

bool addr_equal_ip(const struct addr *a, const struct addr *b)
{
	return !memcmp(&a->sa.sin6_addr, &b->sa.sin6_addr, 16);
}

bool addr_equal(const struct addr *a, const struct addr *b)
{
	return addr_equal_ip(a, b) && a->sa.sin6_port == b->sa.sin6_port;
}

int addr_raw(const struct addr *a, uint8_t out[16])
{
	if (addr_is_v4(a)) {
		memcpy(out, a->sa.sin6_addr.s6_addr + 12, 4);
		return 4;
	}
	memcpy(out, a->sa.sin6_addr.s6_addr, 16);
	return 16;
}

bool host_is_v6(const char *s)
{
	return strchr(s, ':') != NULL;
}
