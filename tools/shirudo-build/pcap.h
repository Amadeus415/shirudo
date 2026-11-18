/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A pcap filter expression compiled into classic BPF by the libpcap of
 * the operator host, opened at run time.
 */

#ifndef SHIRUDO_BUILD_PCAP_H
#define SHIRUDO_BUILD_PCAP_H

#include <stddef.h>

#include <linux/filter.h>

#include <shirudo/compiler.h>
#include <shirudo/types.h>

/* Link-layer types, as libpcap numbers them on Linux. */
#define PCAP_DLT_EN10MB		1	/* from the Ethernet header on */
#define PCAP_DLT_RAW		12	/* from the IPv4 or IPv6 header on */

/* The longest message libpcap gives, and its terminator. */
#define PCAP_ERRBUF_SIZE	256

struct pcap_lib;

struct pcap_filter {
	struct sock_filter	*insns;
	__u32			len;
};

/* -ENOENT when the host has no libpcap, with a message given. */
int pcap_lib_open(struct pcap_lib **out) __must_check;
void pcap_lib_close(struct pcap_lib *lib);

/*
 * Compiles expr, optimized, for a capture of link-layer type linktype.
 * -EINVAL for an expression libpcap refuses, its message in msg, which
 * holds it whole with PCAP_ERRBUF_SIZE bytes.
 */
int pcap_lib_compile(struct pcap_lib *lib, const char *expr, int linktype,
		     struct pcap_filter *out, char *msg,
		     size_t msg_size) __must_check;
void pcap_filter_free(struct pcap_filter *filter);

#endif /* SHIRUDO_BUILD_PCAP_H */
