// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Print release name and SHIRUDO_VERSION_ID.
 */

#include <stdio.h>
#include <string.h>

#include "builtin.h"

extern const char shirudo_version[];
extern const char shirudo_version_id[];

int cmd_version(int argc, const char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "--version-id") == 0) {
		printf("%s\n", shirudo_version_id);
		return 0;
	}
	printf("shirudo (%s)\n", shirudo_version);
	printf("version-id: %s\n", shirudo_version_id);
	return 0;
}
