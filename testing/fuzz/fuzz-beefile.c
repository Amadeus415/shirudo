// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_build_parse_beefile() on a Beefile, which bpm build reads from the
 * package context the operator gives it.
 */

#include <stddef.h>

#include "fuzz.h"
#include "tools/shirudo-build/bpm.h"

#define FIX_ID_BYTES \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"

/* The publisher emits fixes as parsed: valid IDs in byte order, each once. */
static void check_fixes(const struct bpm_fixes *fixes)
{
	if (fixes->n < 0 || fixes->n > BPM_BUILD_MAX_FIXES)
		abort();
	for (int i = 0; i < fixes->n; i++) {
		const char *id = fixes->ids[i];

		if (!id[0] || id[strspn(id, FIX_ID_BYTES)])
			abort();
		if (i && strcmp(fixes->ids[i - 1], id) >= 0)
			abort();
	}
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	bpm_build_parse_beefile(data, size);
	return 0;
}
