// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Human-readable formatters.
 */

#include <stdio.h>

#include "format.h"

void shirudo_human_size(uint64_t bytes, char *out, size_t out_cap)
{
	double v = (double)bytes;
	const char *suf = "B";

	if (bytes >= (1ULL << 30)) {
		v /= (double)(1ULL << 30);
		suf = "G";
	} else if (bytes >= (1ULL << 20)) {
		v /= (double)(1ULL << 20);
		suf = "M";
	} else if (bytes >= (1ULL << 10)) {
		v /= (double)(1ULL << 10);
		suf = "K";
	} else {
		snprintf(out, out_cap, "%llu%s",
			 (unsigned long long)bytes, suf);
		return;
	}
	if (v >= 100.0)
		snprintf(out, out_cap, "%.0f%s", v, suf);
	else if (v >= 10.0)
		snprintf(out, out_cap, "%.1f%s", v, suf);
	else
		snprintf(out, out_cap, "%.2f%s", v, suf);
}
