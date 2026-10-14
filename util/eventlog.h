/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * /var/lib/shirudo/eventlog appender and per-boot replay.
 */

#ifndef SHIRUDO_EVENTLOG_H
#define SHIRUDO_EVENTLOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tpm_wire.h"

/*
 * Conservative upper bound on one appended JSON line (the emit buffers
 * are this size); used by would_exceed to honour "would exceed".
 */
#define SHIRUDO_EVENTLOG_LINE_MAX	4096

/* The on-disk path; SHIRUDO_EVENTLOG_PATH in the environment overrides it. */
const char *shirudo_eventlog_path(void);

int shirudo_eventlog_append(const char *json_line);

/*
 * Replay this boot's records, from its last "init" record on, the way
 * the register accumulates them. -ENOENT when this boot has no init
 * record, -EINVAL on a malformed line.
 */
int shirudo_eventlog_replay(uint8_t out[SHIRUDO_TPM_DIGEST_LEN]);

/*
 * What the last init record of this boot says about the register, and
 * how many init records the boot holds: more than one for the TPM reset
 * the last one names means the register was bound again.
 */
struct shirudo_eventlog_init {
	unsigned int	pcr;
	uint8_t		pcr_before[SHIRUDO_TPM_DIGEST_LEN];
	uint8_t		name[SHIRUDO_TPM_NAME_LEN];
	size_t		name_len;
	uint8_t		anchor_digest[SHIRUDO_TPM_DIGEST_LEN];
	bool		have_reset_count;
	uint32_t	reset_count;
	unsigned int	records;	/* init records this boot */
	unsigned int	records_epoch;	/* for this reset count */
};

int shirudo_eventlog_boot_init(struct shirudo_eventlog_init *out);

/* This boot's records in order, from its last init record on. */
int shirudo_eventlog_boot_lines(int (*cb)(const char *line, size_t len,
					  void *ctx), void *ctx);

/*
 * 1 if appending one more event would push the eventlog past max_bytes;
 * 0 if it fits or max_bytes is 0 (unlimited). The register and the log
 * must stay in lockstep, so a caller refuses the whole operation (no
 * PROG_LOAD, no extend, no append) when this returns 1.
 */
int shirudo_eventlog_would_exceed(unsigned long max_bytes);

/* Helpers for building eventlog entries. */
void shirudo_eventlog_timestamp(char *out, size_t cap);	/* ISO-8601 UTC */
void shirudo_eventlog_boot_id(char *out, size_t cap);	/* /proc boot_id */

#endif /* SHIRUDO_EVENTLOG_H */
