/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IMSD_UTIL_ADDR_H
#define IMSD_UTIL_ADDR_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

/*
 * One IP address + port. Always stored as AF_INET6; IPv4 is v4-mapped
 * (::ffff:a.b.c.d), so a single dual-stack AF_INET6 socket serves both
 * families. Text output always un-maps: IPv4 prints bare, IPv6 in brackets
 * when used in URIs / Via / SDP-less contexts (addr_uri_host / addr_str).
 */
struct addr {
	struct sockaddr_in6 sa;
};

/* Parse an IPv4 or IPv6 literal (optionally in [brackets]) and set the port. 0 / -1. No DNS. */
int addr_set(struct addr *a, const char *host, uint16_t port);
/* Build from a struct sockaddr_in6 (as returned by recvfrom on our sockets). */
void addr_from_sa6(struct addr *a, const struct sockaddr_in6 *sa);
/* Build from a raw IPv4 (network order) address */
void addr_set_v4(struct addr *a, uint32_t be_addr, uint16_t port);
void addr_set_v6(struct addr *a, const uint8_t v6[16], uint16_t port);
bool addr_is_v4(const struct addr *a);
uint16_t addr_port(const struct addr *a);
void addr_set_port(struct addr *a, uint16_t port);
/* AF_INET or AF_INET6 (what the address means, not how it is stored) */
int addr_family(const struct addr *a);
/* bare literal: "192.0.2.1" or "2001:db8::1" (no brackets). 0 / -1 if out is too small */
int addr_host(const struct addr *a, char *out, size_t n);
/* literal as used in a URI / Via sent-by: IPv6 in brackets, IPv4 bare */
int addr_uri_host(const struct addr *a, char *out, size_t n);
/* "host:port" with the bracket rule */
int addr_str(const struct addr *a, char *out, size_t n);
/* "IP4 x" / "IP6 x" as used in SDP o=/c= lines */
int addr_sdp(const struct addr *a, char *out, size_t n);
bool addr_equal(const struct addr *a, const struct addr *b);	/* ip and port */
bool addr_equal_ip(const struct addr *a, const struct addr *b);
/* 4 raw bytes (v4) or 16 raw bytes (v6) of the address, per addr_family(); returns the byte count */
int addr_raw(const struct addr *a, uint8_t out[16]);
/* true if s looks like a bare IPv6 literal (contains ':') */
bool host_is_v6(const char *s);
#endif
