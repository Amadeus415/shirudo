// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Sole exec site in the core shirudo binary: dispatch to the
 * operator-only shirudo-build helper.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "builtin.h"
#include "util/help.h"
#include "util/log.h"

#ifndef SHIRUDO_LIBEXEC_DIR
#define SHIRUDO_LIBEXEC_DIR	"/usr/local/libexec/shirudo"
#endif

static const struct shirudo_help build_help = {
	.usage   = "shirudo build <input.bpf.c|.bpf.o> [-o <output.upatch>] [options]\n"
		   "       shirudo build --unload <upatch-name> [-o <output.upatch>] [options]",
	.summary = "Build a signed BPF .upatch artifact ready\nfor target-side loading. "
		   "Operator-only: "
		   "dispatches to the separate\nshirudo-build binary. The "
		   "helper is resolved in this order:\n"
		   "SHIRUDO_BUILD, " SHIRUDO_LIBEXEC_DIR "/shirudo-build, "
		   "then shirudo-build on PATH.\n"
		   "Run the selected helper with --help for the full option list.",
};

/*
 * SHIRUDO_BUILD (possibly empty, which the callers reject), the
 * compiled-in libexec path, then a bare name for PATH lookup.
 */
static const char *resolve_helper(bool *use_path)
{
	const char *override = getenv("SHIRUDO_BUILD");
	const char *installed = SHIRUDO_LIBEXEC_DIR "/shirudo-build";

	*use_path = false;
	if (override)
		return override;
	if (access(installed, X_OK) == 0)
		return installed;
	*use_path = true;
	return "shirudo-build";
}

static bool on_path(const char *name)
{
	const char *path = getenv("PATH");

	while (path && *path) {
		const char *end = strchr(path, ':');
		char candidate[PATH_MAX];
		size_t len;

		if (!end)
			end = path + strlen(path);
		len = (size_t)(end - path);
		if (len && len + 1 + strlen(name) < sizeof(candidate)) {
			memcpy(candidate, path, len);
			candidate[len] = '/';
			strcpy(candidate + len + 1, name);
			if (access(candidate, X_OK) == 0)
				return true;
		}
		path = *end ? end + 1 : end;
	}
	return false;
}

bool shirudo_build_available(void)
{
	bool use_path;
	const char *helper = resolve_helper(&use_path);

	if (!*helper)
		return false;
	return use_path ? on_path(helper) : access(helper, X_OK) == 0;
}

/*
 * Replace argv[0] with the resolved helper and exec it. Returns only on
 * failure, with the exit status to report; label names the subcommand
 * in diagnostics.
 */
int shirudo_build_exec(const char *label, char **argv)
{
	bool use_path;
	const char *path = resolve_helper(&use_path);

	if (!*path) {
		pr_err("'%s' cannot use empty SHIRUDO_BUILD", label);
		return 127;
	}
	if (!use_path && access(path, X_OK) != 0) {
		pr_err("'%s' is an operator-only subcommand; "
		       "shirudo-build helper '%s' is not executable. Set "
		       "SHIRUDO_BUILD to a helper path or put shirudo-build on "
		       "PATH.", label, path);
		return 127;
	}
	argv[0] = (char *)path;
	if (use_path)
		execvp(path, argv);
	else
		execv(path, argv);
	pr_err("exec %s: %s", path, strerror(errno));
	return 127;
}

int cmd_build(int argc, const char **argv)
{
	if (argc >= 2 && shirudo_is_help(argv[1])) {
		shirudo_print_help(&build_help);
		return 0;
	}
	return shirudo_build_exec("build", (char **)argv);
}
