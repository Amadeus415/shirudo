// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared kubectl-style duration formatter.
 */

#include <stdio.h>

#include "timefmt.h"

void shirudo_format_duration(long seconds, char *buf, size_t cap)
{
	if (seconds < 0)
		snprintf(buf, cap, "?");
	else if (seconds < 60)
		snprintf(buf, cap, "%lds", seconds);
	else if (seconds < 3600)
		snprintf(buf, cap, "%ldm", seconds / 60);
	else if (seconds < 86400)
		snprintf(buf, cap, "%ldh", seconds / 3600);
	else
		snprintf(buf, cap, "%ldd", seconds / 86400);
}
