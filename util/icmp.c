// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Unprivileged ICMPv4 echo. We rely on Linux's dgram ICMP support
 * (SOCK_DGRAM + IPPROTO_ICMP, gated by net.ipv4.ping_group_range) so
 * no CAP_NET_RAW is needed. The kernel rewrites the ICMP `id` to the
 * socket's source port in both directions, so correlation is by
 * sequence number alone.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <poll.h>
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
	struct addrinfo *res = NULL;
	enum shirudo_icmp_status best = SHIRUDO_ICMP_TIMEOUT;
	uint64_t best_rtt = UINT64_MAX;
	int gai, fd, save_errno, proto;
	uint8_t echo_type, reply_type;
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
			struct timespec now;
			int waited_ms, remaining;
			char reply[128];
			ssize_t r;
			uint16_t got_seq;

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
			if ((uint8_t)reply[0] != reply_type)
				continue;
			memcpy(&got_seq, reply + 6, 2);
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
