/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Read /dev/kmsg records with ISO wallclock timestamps. No subprocess
 * fallback to dmesg(1) -- direct kernel interface only.
 */

#ifndef SHIRUDO_UTIL_KMSG_H
#define SHIRUDO_UTIL_KMSG_H

#include <stddef.h>

#define SHIRUDO_KMSG_TS_LEN	24	/* "2026-05-28T14:32:01Z" + slack */
#define SHIRUDO_KMSG_MSG_LEN	480	/* one printk record, joined */

struct shirudo_kmsg_record {
	char	ts[SHIRUDO_KMSG_TS_LEN];	/* ISO-8601 UTC, NUL-term */
	char	msg[SHIRUDO_KMSG_MSG_LEN];	/* control bytes stripped */
};

/*
 * Read the last <cap> records from /dev/kmsg in chronological order
 * into <out>. Returns the number written (<= cap) on success, -errno
 * otherwise. Records older than the ring buffer's current head are
 * silently skipped (the ring buffer wraps; kernel returns EPIPE which
 * we treat as "restart and skip ahead").
 */
int shirudo_kmsg_tail(struct shirudo_kmsg_record *out, size_t cap);

#endif /* SHIRUDO_UTIL_KMSG_H */
