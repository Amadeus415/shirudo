// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Offline checker for LOAD program metadata in a .upatch.
 */

#include <endian.h>
#include <stdio.h>
#include <string.h>

#include "upatch.h"

static int fail(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	return 1;
}

int main(int argc, char **argv)
{
	const struct shirudo_upatch_prog_metadata *md;
	const struct shirudo_upatch_prog_entry *prog;
	struct shirudo_upatch u;
	uint32_t nr_progs;
	int rc;

	if (argc != 2)
		return fail("usage: test-upatch-prog-metadata <file.upatch>");

	rc = shirudo_upatch_open(argv[1], &u);
	if (rc)
		return fail("open upatch failed");
	if (u.hdr.nr_maps != 3 || u.hdr.nr_progs != 1) {
		shirudo_upatch_close(&u);
		return fail("unexpected map/prog counts");
	}
	if (u.hdr.metadata_len !=
	    sizeof(*md) + sizeof(struct shirudo_upatch_prog_entry)) {
		shirudo_upatch_close(&u);
		return fail("unexpected metadata length");
	}
	md = shirudo_upatch_metadata(&u);
	if (!md) {
		shirudo_upatch_close(&u);
		return fail("missing metadata");
	}
	if (le32toh(md->magic) != SHIRUDO_UPATCH_PROG_MAGIC ||
	    le32toh(md->version) != SHIRUDO_UPATCH_PROG_VERSION) {
		shirudo_upatch_close(&u);
		return fail("unexpected metadata magic/version");
	}
	nr_progs = le32toh(md->nr_progs);
	if (nr_progs != 1) {
		shirudo_upatch_close(&u);
		return fail("unexpected metadata prog count");
	}
	prog = &md->progs[0];
	if (le32toh(prog->role) != SHIRUDO_UPATCH_PROG_ROLE_SERIALIZER) {
		shirudo_upatch_close(&u);
		return fail("program is not a serializer");
	}
	if (!memchr(prog->map, '\0', sizeof(prog->map)) ||
	    strcmp(prog->map, "tree_arena") != 0) {
		shirudo_upatch_close(&u);
		return fail("serializer map mismatch");
	}

	puts("ok");
	shirudo_upatch_close(&u);
	return 0;
}
