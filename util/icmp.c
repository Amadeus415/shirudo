// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Best-effort ICMP echo (v4 + v6). Like iputils ping we try an
 * unprivileged dgram ICMP socket first (SOCK_DGRAM + IPPROTO_ICMP[V6],
 * gated by net.ipv4.ping_group_range, no CAP_NET_RAW needed) and fall
 * back to a raw ICMP socket when that is refused -- which a root
 * operator gets via CAP_NET_RAW without any sysctl change. Only when
 * neither works do we report NO_PRIVILEGE.
 *
 * The two socket types differ in two ways we must handle:
 *   - id: a dgram socket has the kernel rewrite the ICMP `id` to the
 *     socket's source port in both directions, so we correlate by
 *     sequence alone; a raw socket leaves `id` untouched, so we stamp
 *     our pid and match it (raw sockets also see unrelated ICMP).
 *   - receive framing / checksum: a raw IPv4 socket prepends the IP
 *     header on recv and does not compute the ICMP checksum on send;
 *     dgram sockets and raw ICMPv6 do neither (v6 kernel-fills csum).
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "icmp.h"
#include "log.h"

/*
 * Wall-time RTT in microseconds between two monotonic timestamps.
 */
static uint64_t rtt_us(const struct timespec *a, const struct timespec *b)
{
	int64_t s = (int64_t)b->tv_sec - (int64_t)a->tv_sec;
	int64_t ns = (int64_t)b->tv_nsec - (int64_t)a->tv_nsec;

	return (uint64_t)(s * 1000000 + ns / 1000);
}

/*
 * Internet checksum (RFC 1071). Needed only for the raw IPv4 path: the
 * kernel fills the ICMP checksum for dgram sockets and for raw ICMPv6,
 * but a raw IPv4 ICMP socket sends the transport payload verbatim.
 */
static uint16_t in_cksum(const void *data, size_t len)
{
	const uint16_t *p = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
	if (len)
		sum += *(const uint8_t *)p;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

enum shirudo_icmp_status shirudo_icmp_ping(const char *host,
					   unsigned timeout_ms,
					   unsigned probes,
					   uint64_t *rtt_us_out,
					   char *resolved, size_t resolved_cap)
{
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
	};
	enum shirudo_icmp_status best = SHIRUDO_ICMP_TIMEOUT;
	uint16_t ident = (uint16_t)(getpid() & 0xffff);
	uint64_t best_rtt = UINT64_MAX;
	int gai, fd, save_errno, proto;
	uint8_t echo_type, reply_type;
	struct addrinfo *res = NULL;
	bool raw = false;
	unsigned p;
	int af;

	if (resolved && resolved_cap)
		resolved[0] = '\0';

	/* probes = 0 in shirudo.conf means "ICMP disabled" -- no socket. */
	if (probes == 0)
		return SHIRUDO_ICMP_DISABLED;

	gai = getaddrinfo(host, NULL, &hints, &res);
	if (gai != 0 || !res)
		return SHIRUDO_ICMP_DNS_FAIL;

	af = res->ai_family;
	if (af == AF_INET6) {
		proto = IPPROTO_ICMPV6;
		echo_type = ICMP6_ECHO_REQUEST;	/* 128 */
		reply_type = ICMP6_ECHO_REPLY;	/* 129 */
	} else {
		proto = IPPROTO_ICMP;
		echo_type = ICMP_ECHO;		/* 8 */
		reply_type = ICMP_ECHOREPLY;	/* 0 */
	}

	if (resolved && resolved_cap) {
		const void *sa;

		if (af == AF_INET6)
			sa = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
		else
			sa = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
		inet_ntop(af, sa, resolved, resolved_cap);
	}

	fd = socket(af, SOCK_DGRAM, proto);
	if (fd < 0 && (errno == EACCES || errno == EPERM ||
		       errno == EPROTONOSUPPORT)) {
		/*
		 * No unprivileged dgram ICMP (gid not in
		 * net.ipv4.ping_group_range, or no ping-socket support):
		 * fall back to a raw ICMP socket, which CAP_NET_RAW (e.g. a
		 * root operator) grants without touching any sysctl.
		 */
		fd = socket(af, SOCK_RAW, proto);
		if (fd >= 0)
			raw = true;
	}
	if (fd < 0) {
		save_errno = errno;
		freeaddrinfo(res);
		if (save_errno == EACCES || save_errno == EPERM ||
		    save_errno == EPROTONOSUPPORT)
			return SHIRUDO_ICMP_NO_PRIVILEGE;
		return SHIRUDO_ICMP_ERROR;
	}

	if (probes == 0)
		probes = 1;
	if (timeout_ms == 0)
		timeout_ms = 1000;

	for (p = 0; p < probes; p++) {
		struct {
			uint8_t  type;
			uint8_t  code;
			uint16_t checksum;	/* kernel fills */
			uint16_t id;		/* kernel rewrites */
			uint16_t seq;
		} pkt = { 0 };
		uint16_t want_seq = (uint16_t)p;
		struct timespec t0, t1;
		struct pollfd pfd;
		ssize_t s;

		pkt.type = echo_type;
		pkt.seq = htons(want_seq);
		if (raw) {
			/*
			 * Raw sockets do not rewrite `id`; stamp it so we
			 * can pick our own replies out of all the ICMP the
			 * socket sees. IPv4 needs the checksum filled too
			 * (set last, over the finished header); IPv6 is
			 * kernel-computed.
			 */
			pkt.id = htons(ident);
			if (af == AF_INET)
				pkt.checksum = in_cksum(&pkt, sizeof(pkt));
		}
		clock_gettime(CLOCK_MONOTONIC, &t0);
		s = sendto(fd, &pkt, sizeof(pkt), 0, res->ai_addr,
			   res->ai_addrlen);
		if (s < 0) {
			if (errno == ENETUNREACH || errno == EHOSTUNREACH) {
				if (best != SHIRUDO_ICMP_OK)
					best = SHIRUDO_ICMP_NO_ROUTE;
				continue;
			}
			if (best != SHIRUDO_ICMP_OK)
				best = SHIRUDO_ICMP_ERROR;
			continue;
		}

		/*
		 * Wait for a matching reply with poll(2): we may receive
		 * stray packets (slow-path errors, replies from a previous
		 * probe) before ours arrives; ignore mismatched seqs but
		 * never wait past `timeout_ms` in total.
		 */
		pfd.fd = fd;
		pfd.events = POLLIN;
		for (;;) {
			uint16_t got_seq, got_id;
			int waited_ms, remaining;
			struct timespec now;
			char reply[128];
			size_t off;
			ssize_t r;

			clock_gettime(CLOCK_MONOTONIC, &now);
			waited_ms = (int)(rtt_us(&t0, &now) / 1000);
			remaining = (int)timeout_ms - waited_ms;
			if (remaining <= 0) {
				if (best != SHIRUDO_ICMP_OK)
					best = SHIRUDO_ICMP_TIMEOUT;
				break;
			}
			pfd.revents = 0;
			if (poll(&pfd, 1, remaining) <= 0) {
				if (best != SHIRUDO_ICMP_OK)
					best = SHIRUDO_ICMP_TIMEOUT;
				break;
			}
			r = recv(fd, reply, sizeof(reply), 0);
			if (r < (ssize_t)sizeof(pkt))
				continue;
			/*
			 * A raw IPv4 socket hands us the IP header ahead of
			 * the ICMP message; everything else (dgram, raw
			 * ICMPv6) starts at offset 0.
			 */
			off = 0;
			if (raw && af == AF_INET)
				off = ((size_t)(uint8_t)reply[0] & 0x0f) * 4;
			if (r < (ssize_t)(off + sizeof(pkt)))
				continue;
			if ((uint8_t)reply[off] != reply_type)
				continue;
			if (raw) {
				memcpy(&got_id, reply + off + 4, 2);
				if (ntohs(got_id) != ident)
					continue;
			}
			memcpy(&got_seq, reply + off + 6, 2);
			if (ntohs(got_seq) != want_seq)
				continue;
			clock_gettime(CLOCK_MONOTONIC, &t1);
			{
				uint64_t r_us = rtt_us(&t0, &t1);

				if (r_us < best_rtt)
					best_rtt = r_us;
			}
			best = SHIRUDO_ICMP_OK;
			break;
		}
	}

	close(fd);
	freeaddrinfo(res);

	if (best == SHIRUDO_ICMP_OK && rtt_us_out)
		*rtt_us_out = best_rtt;
	return best;
}
