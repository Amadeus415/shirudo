// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The upatch tree's state.json, its eventlog and its outcomes record, as
 * a target reads them back before a sync. The eventlog matches a state
 * only when the state was read, and replays the same either way.
 */

#include <stdlib.h>

#include "fuzz.h"
#include "paths.h"

static char fuzz_path[64];

#undef BPM_TREE_STATE_PATH
#define BPM_TREE_STATE_PATH fuzz_path
#undef BPM_TREE_EVENTLOG_PATH
#define BPM_TREE_EVENTLOG_PATH fuzz_path

#include "bpm_tree_state.c"

#define OUTCOMES_READ	8

/* A line the reader takes is written again as one it takes the same. */
static __s64 outcomes_read_back_as_written(int fd, size_t size)
{
	struct outcome_line line, back;
	char buf[OUTCOME_LINE_MAX];
	__s64 lines = 0;
	off_t off = 0;
	size_t len;

	while (outcome_next(fd, &off, &line) > 0) {
		if ((size_t)off > size ||
		    outcome_emit(&line, buf, sizeof(buf), &len) ||
		    outcome_parse(buf, len, &back) ||
		    back.seq != line.seq || back.outcome != line.outcome ||
		    memcmp(back.projection_root, line.projection_root, 32) ||
		    memcmp(back.history_root, line.history_root, 32))
			abort();
		lines++;
	}
	return lines;
}

/* The lines a range read takes are lines of the record, within it. */
static void outcomes_range_is_in_the_record(int fd, size_t size, __s64 lines)
{
	__u8 codes[OUTCOMES_READ], projection[32], history[32];
	off_t end = 0;
	int ret;

	ret = outcomes_walk(fd, 1, OUTCOMES_READ, codes, projection, history,
			    &end);
	if (!ret && lines < OUTCOMES_READ)
		abort();
	if ((!ret || ret == -ENOENT) && (size_t)end > size)
		abort();
	for (int i = 0; !ret && i < OUTCOMES_READ - 1; i++) {
		if (!outcome_valid(codes[i]))
			abort();
	}
}

static void eventlog_matches_a_state_read(const struct tree_state *state,
					  int state_rc)
{
	__u8 root[32], again[32];
	bool matches = false;
	int ret;

	ret = tree_event_replay(root);
	if (tree_eventlog_matches(state, state_rc, again, &matches) != ret ||
	    (!ret && memcmp(root, again, sizeof(root))) ||
	    (state_rc && matches))
		abort();
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct tree_state state;
	__s64 lines;
	int fd, rc;

	fd = fuzz_file(data, size, fuzz_path, sizeof(fuzz_path));
	if (fd < 0)
		return 0;
	rc = tree_state_read(&state);
	eventlog_matches_a_state_read(&state, rc);
	lines = outcomes_read_back_as_written(fd, size);
	outcomes_range_is_in_the_record(fd, size, lines);
	close(fd);
	return 0;
}
