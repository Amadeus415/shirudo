/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#include <string.h>

#include "kernel_release.h"

bool shirudo_kernel_release_prefix_matches(const char *release,
						   const char *prefix)
{
	size_t len;

	if (!release || !prefix)
		return false;
	len = strlen(prefix);
	if (!len)
		return true;
	return !strncmp(release, prefix, len) &&
	       (release[len] == '\0' || release[len] == '.' ||
		release[len] == '-');
}
