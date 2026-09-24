/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared NAME / LOCATION / MAPS / AGE renderer for the "upatches
 * loaded" section. Used by:
 *   - `shirudo status` (local view, both human and --json).
 *
 * The caller assembles a row[] vector from the target-local file walk;
 * the renderer doesn't
 * touch syscalls or eventlog state itself.
 */

#ifndef SHIRUDO_UTIL_UPATCH_TABLE_H
#define SHIRUDO_UTIL_UPATCH_TABLE_H

#include <stddef.h>
#include <stdint.h>

#include "upatch_resolve.h"

struct shirudo_json_emit;

struct shirudo_upatch_table_row {
	char		name[64];
	char		location[SHIRUDO_UPATCH_LOCATION_MAX];	/* SEC()-style */
	char		loaded_at[32];	/* ISO-8601 UTC, "" if unknown */
	char		status[64];	/* success or a tree skip reason */
	uint32_t	n_maps;
	int64_t		age_sec;	/* derived from loaded_at; -1 if unknown */
	char		payload_sha256[65];	/* "" if unavailable; JSON only */
};

/*
 * Print the table to stdout. Renders the heading line "upatches
 * loaded (N):" and an empty body when n == 0.
 */
void shirudo_upatch_table_print(const struct shirudo_upatch_table_row *rows,
				size_t n);

/*
 * Emit the JSON "upatches_loaded": [...] array on the open emitter.
 * Caller has already opened the parent object.
 */
void shirudo_upatch_table_emit_json(struct shirudo_json_emit *e,
				    const struct shirudo_upatch_table_row *rows,
				    size_t n);

/*
 * Derive a wall-clock age in seconds from an ISO-8601 UTC timestamp.
 * Returns -1 if ts is empty / unparseable.
 */
int64_t shirudo_upatch_age_sec(const char *ts);

#endif /* SHIRUDO_UTIL_UPATCH_TABLE_H */
