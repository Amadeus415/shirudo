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

static int expect_attach_kind(const struct shirudo_upatch *u, uint32_t kind)
{
	const struct shirudo_upatch_prog_metadata *md;
	const struct shirudo_upatch_prog_entry *prog;

	if (u->hdr.nr_progs != 1)
		return fail("unexpected metadata prog count");
	if (u->hdr.metadata_len !=
	    sizeof(*md) + sizeof(struct shirudo_upatch_prog_entry))
		return fail("unexpected metadata length");
	md = shirudo_upatch_metadata(u);
	if (!md)
		return fail("missing metadata");
	if (le32toh(md->magic) != SHIRUDO_UPATCH_PROG_MAGIC ||
	    le32toh(md->version) != SHIRUDO_UPATCH_PROG_VERSION)
		return fail("unexpected metadata magic/version");
	if (le32toh(md->nr_progs) != 1)
		return fail("unexpected metadata prog count");
	prog = &md->progs[0];
	if (le32toh(prog->role) != SHIRUDO_UPATCH_PROG_ROLE_ATTACH)
		return fail("program is not an attach program");
	if (le32toh(prog->kind) != kind)
		return fail("attach kind mismatch");
	if (le64toh(prog->offset) != 0)
		return fail("unexpected attach offset");
	if (prog->target[0] || prog->map[0])
		return fail("unexpected attach target/map");
	return 0;
}

static int expect_serializer(const struct shirudo_upatch *u)
{
	const struct shirudo_upatch_prog_metadata *md;
	const struct shirudo_upatch_prog_entry *prog;
	uint32_t nr_progs;

	if (u->hdr.nr_maps != 3 || u->hdr.nr_progs != 1)
		return fail("unexpected map/prog counts");
	if (u->hdr.metadata_len !=
	    sizeof(*md) + sizeof(struct shirudo_upatch_prog_entry))
		return fail("unexpected metadata length");
	md = shirudo_upatch_metadata(u);
	if (!md)
		return fail("missing metadata");
	if (le32toh(md->magic) != SHIRUDO_UPATCH_PROG_MAGIC ||
	    le32toh(md->version) != SHIRUDO_UPATCH_PROG_VERSION)
		return fail("unexpected metadata magic/version");
	nr_progs = le32toh(md->nr_progs);
	if (nr_progs != 1)
		return fail("unexpected metadata prog count");
	prog = &md->progs[0];
	if (le32toh(prog->role) != SHIRUDO_UPATCH_PROG_ROLE_SERIALIZER)
		return fail("program is not a serializer");
	if (!memchr(prog->map, '\0', sizeof(prog->map)) ||
	    strcmp(prog->map, "tree_arena") != 0)
		return fail("serializer map mismatch");
	return 0;
}

int main(int argc, char **argv)
{
	struct shirudo_upatch u;
	const char *mode = "serializer";
	int rc;

	if (argc != 2 && argc != 3)
		return fail("usage: test-upatch-prog-metadata <file.upatch> [mode]");
	if (argc == 3)
		mode = argv[2];

	rc = shirudo_upatch_open(argv[1], &u);
	if (rc)
		return fail("open upatch failed");

	if (strcmp(mode, "serializer") == 0)
		rc = expect_serializer(&u);
	else if (strcmp(mode, "cgroup-ingress") == 0)
		rc = expect_attach_kind(&u,
				SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_INGRESS);
	else if (strcmp(mode, "cgroup-egress") == 0)
		rc = expect_attach_kind(&u,
				SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_EGRESS);
	else
		rc = fail("unknown metadata check mode");

	shirudo_upatch_close(&u);
	if (rc)
		return rc;
	puts("ok");
	return 0;
}
