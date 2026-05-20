/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * /var/lib/shirudo/eventlog appender and replay.
 */

#ifndef SHIRUDO_EVENTLOG_H
#define SHIRUDO_EVENTLOG_H

#include <stddef.h>
#include <stdint.h>

/*
 * Conservative upper bound on one appended JSON line (the emit buffers
 * are this size); used by would_exceed to honour "would exceed".
 */
#define SHIRUDO_EVENTLOG_LINE_MAX	4096

int shirudo_eventlog_append(const char *json_line);
int shirudo_eventlog_replay(uint8_t out[32]);

/*
 * 1 if appending one more event would push the eventlog past max_bytes;
 * 0 if it fits or max_bytes is 0 (unlimited). The chain and the log must
 * stay in lockstep, so a caller refuses the whole operation (no
 * PROG_LOAD, no NV_extend, no append) when this returns 1.
 */
int shirudo_eventlog_would_exceed(unsigned long max_bytes);

/* Helpers for building eventlog entries. */
void shirudo_eventlog_timestamp(char *out, size_t cap);	/* ISO-8601 UTC */
void shirudo_eventlog_boot_id(char *out, size_t cap);	/* /proc boot_id */

#endif /* SHIRUDO_EVENTLOG_H */
