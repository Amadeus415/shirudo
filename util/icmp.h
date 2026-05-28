/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Best-effort ICMP echo (v4 + v6 via getaddrinfo), used by `shirudo
 * nodes` to tell "host up" apart from "SSH broken". Tries an
 * unprivileged dgram ICMP socket first (needs the operator gid in
 * net.ipv4.ping_group_range, no CAP_NET_RAW) and falls back to a raw
 * ICMP socket (CAP_NET_RAW, e.g. a root operator). Only when neither
 * is permitted do we report NO_PRIVILEGE, rather than silently
 * degrading to TCP-probing.
 */

#ifndef SHIRUDO_ICMP_H
#define SHIRUDO_ICMP_H

#include <stdint.h>

enum shirudo_icmp_status {
	SHIRUDO_ICMP_OK,		/* got a reply -- rtt_us is valid */
	SHIRUDO_ICMP_TIMEOUT,		/* no reply within budget (firewalled) */
	SHIRUDO_ICMP_NO_ROUTE,		/* destination unreachable */
	SHIRUDO_ICMP_DNS_FAIL,		/* getaddrinfo could not resolve */
	SHIRUDO_ICMP_NO_PRIVILEGE,	/* no dgram (ping_group_range) nor raw (CAP_NET_RAW) */
	SHIRUDO_ICMP_DISABLED,		/* nodes.icmp_probes = 0 (off by config) */
	SHIRUDO_ICMP_ERROR,		/* other (logged via pr_warn) */
};

/*
 * Send up to `probes` ICMP echo requests to <host> (v4 or v6) with `timeout_ms`
 * budget per probe; return the BEST (lowest) RTT seen, or the most
 * informative failure status. *rtt_us is filled only on SHIRUDO_ICMP_OK.
 * Sequential; one probe at a time. Resolved-to address is written into
 * *resolved (NUL-terminated) when non-NULL.
 */
enum shirudo_icmp_status shirudo_icmp_ping(const char *host,
					   unsigned timeout_ms,
					   unsigned probes,
					   uint64_t *rtt_us,
					   char *resolved, size_t resolved_cap);

#endif /* SHIRUDO_ICMP_H */
