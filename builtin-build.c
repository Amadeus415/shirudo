// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Sole exec site in the core shirudo binary: dispatch to the
 * operator-only shirudo-build helper.
 */

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "builtin.h"
#include "util/help.h"
#include "util/log.h"

#ifndef SHIRUDO_LIBEXEC_DIR
#define SHIRUDO_LIBEXEC_DIR	"/usr/local/libexec/shirudo"
#endif

static const struct shirudo_help build_help = {
	.usage   = "shirudo build <input.bpf.c|.bpf.o> [-o <output.upatch>] [options]\n"
		   "       shirudo build --unload <upatch-name> [-o <output.upatch>] [options]",
	.summary = "Compile (if needed), gen_loader and CMS-sign a .upatch "
		   "artifact ready\nfor `shirudo rollout`. Operator-only: "
		   "dispatches to the separate\nshirudo-build binary. The "
		   "helper is resolved in this order:\n"
		   "SHIRUDO_BUILD, " SHIRUDO_LIBEXEC_DIR "/shirudo-build, "
		   "then shirudo-build on PATH.\n"
		   "Run the selected helper with --help for the full option list.",
};

int cmd_build(int argc, const char **argv)
{
	const char *override = getenv("SHIRUDO_BUILD");
	const char *installed = SHIRUDO_LIBEXEC_DIR "/shirudo-build";
	const char *path;
	int use_path = 0;
	char **a = (char **)argv;

	if (argc >= 2 && shirudo_is_help(argv[1])) {
		shirudo_print_help(&build_help);
		return 0;
	}
	if (override) {
		if (!*override) {
			pr_err("'build' cannot use empty SHIRUDO_BUILD");
			return 127;
		}
		path = override;
	} else if (access(installed, X_OK) == 0) {
		path = installed;
	} else {
		path = "shirudo-build";
		use_path = 1;
	}

	if (!use_path && access(path, X_OK) != 0) {
		pr_err("'build' is an operator-only subcommand; "
		       "shirudo-build helper '%s' is not executable. Set "
		       "SHIRUDO_BUILD to a helper path or put shirudo-build on "
		       "PATH.", path);
		return 127;
	}

	a[0] = (char *)path;
	if (use_path)
		execvp(path, a);
	else
		execv(path, a);
	pr_err("exec %s: %s", path, strerror(errno));
	return 127;
}
