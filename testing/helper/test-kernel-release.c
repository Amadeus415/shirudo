// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdio.h>

#include "util/kernel_release.h"

struct test_case {
	const char *release;
	const char *prefix;
	int matches;
};

int main(void)
{
	static const struct test_case cases[] = {
		{ "6.1.0", "6.1", 1 },
		{ "6.1-custom", "6.1", 1 },
		{ "6.10.0", "6.1", 0 },
		{ "6.1", "6.1", 1 },
		{ "", "6.1", 0 },
		{ "6.1.0", "", 1 },
		{ NULL, "6.1", 0 },
		{ "6.1.0", NULL, 0 },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int matches = shirudo_kernel_release_prefix_matches(
			cases[i].release, cases[i].prefix);

		if (matches != cases[i].matches) {
			fprintf(stderr, "case %zu: unexpected match result %d\n",
				i, matches);
			return 1;
		}
	}
	return 0;
}
