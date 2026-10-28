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
#include "util/macros.h"
#include "util/version.h"

static const struct shirudo_help_item version_options[] = {
	{ "--version-id", "print only the raw SHIRUDO_VERSION_ID, one line" },
};

static const struct shirudo_help_section version_help_sections[] = {
	{ "options:", version_options,
	  ARRAY_SIZE(version_options) },
};

static const struct shirudo_help version_help = {
	.usage      = "shirudo version [--version-id]",
	.summary    = "Print the release tag and the architecture-independent SHIRUDO_VERSION_ID\n"
		      "that targets compare against the operator's signed artifacts.",
	.sections   = version_help_sections,
	.n_sections = ARRAY_SIZE(version_help_sections),
};

int cmd_version(int argc, const char **argv)
{
	if (argc >= 2 && is_help(argv[1])) {
		print_help(&version_help);
		return 0;
	}
	if (argc >= 2 && strcmp(argv[1], "--version-id") == 0) {
		printf("%s\n", shirudo_version_id);
		return 0;
	}
	printf("shirudo (%s%s, \"%s\")\n",
	       shirudo_version, shirudo_extraversion, shirudo_release_name);
	printf("version-id: %s\n", shirudo_version_id);
	return 0;
}
