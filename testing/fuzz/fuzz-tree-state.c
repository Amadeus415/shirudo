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
#include "bpm_tree.h"

static char fuzz_path[64];

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct tree_state state;
	int fd, rc;

	fd = fuzz_file(data, size, fuzz_path, sizeof(fuzz_path));
	if (fd < 0)
		return 0;
	tree_state_read_path(fuzz_path, &state);
	tree_event_replay_path(fuzz_path, root);
	close(fd);
	return 0;
}
