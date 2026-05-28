// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Print release name and SHIRUDO_VERSION_ID.
 */

#include <stdio.h>
#include <string.h>

#include "builtin.h"
#include "util/help.h"

extern const char shirudo_version[];
extern const char shirudo_version_id[];

static const struct shirudo_help_item version_options[] = {
	{ "--version-id", "print only the raw SHIRUDO_VERSION_ID, one line" },
};

static const struct shirudo_help_section version_help_sections[] = {
	{ "options:", version_options,
	  sizeof(version_options) / sizeof(version_options[0]) },
};

static const struct shirudo_help version_help = {
	.usage      = "shirudo version [--version-id]",
	.summary    = "Print the release tag plus the architecture-stripped "
		      "SHIRUDO_VERSION_ID\nthat targets compare against the "
		      "operator's signed artifacts.",
	.sections   = version_help_sections,
	.n_sections = sizeof(version_help_sections) /
		      sizeof(version_help_sections[0]),
};

int cmd_version(int argc, const char **argv)
{
	if (argc >= 2 && shirudo_is_help(argv[1])) {
		shirudo_print_help(&version_help);
		return 0;
	}
	if (argc >= 2 && strcmp(argv[1], "--version-id") == 0) {
		printf("%s\n", shirudo_version_id);
		return 0;
	}
	printf("shirudo (%s)\n", shirudo_version);
	printf("version-id: %s\n", shirudo_version_id);
	return 0;
}
