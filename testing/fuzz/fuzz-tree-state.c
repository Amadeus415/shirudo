// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The upatch tree's state.json and its eventlog, as a target reads them
 * back before a sync.
 */

#include "fuzz.h"
#include "bpm_tree.h"

static char fuzz_path[64];

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct tree_state state;
	__u8 root[32];
	int fd;

	fd = fuzz_file(data, size, fuzz_path, sizeof(fuzz_path));
	if (fd < 0)
		return 0;
	tree_state_read_path(fuzz_path, &state);
	tree_event_replay_path(fuzz_path, root);
	close(fd);
	return 0;
}
