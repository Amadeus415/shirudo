// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_build_parse_beefile() on a Beefile, which bpm build reads from the
 * package source and bpm tree append from a package archive.
 */

#include <errno.h>

#include "fuzz.h"
#include "malloc.h"
#include "tools/shirudo-build/bpm.h"
#include "tools/shirudo-build/compile.h"
#include "tools/shirudo-build/package.h"
#include "tools/shirudo-build/vmlinux.h"
#include "util/loader.h"

/* What bpm build does with a parsed Beefile is out of reach from here. */
int build_bpm_push(int argc, char **argv)
{
	return -ENOSYS;
}

int build_bpm_tree(int argc, char **argv)
{
	return -ENOSYS;
}

const struct embedded_bpf *unload_blob(void)
{
	return NULL;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct bpm_build_spec *spec = xcalloc(1, sizeof(*spec));

	if (!spec)
		return 0;
	bpm_build_parse_beefile(data, size, spec);
	bpm_build_spec_free(spec);
	return 0;
}
