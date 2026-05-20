// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Sole execv site in the core shirudo binary: dispatch to the
 * operator-only shirudo-build at a hardcoded libexec path.
 */

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "builtin.h"
#include "util/log.h"

#ifndef SHIRUDO_LIBEXEC_DIR
#define SHIRUDO_LIBEXEC_DIR	"/usr/local/libexec/shirudo"
#endif

int cmd_build(int argc, const char **argv)
{
	const char *path = SHIRUDO_LIBEXEC_DIR "/shirudo-build";
	char **a = (char **)argv;

	(void)argc;

	if (access(path, X_OK) != 0) {
		pr_err("'build' is an operator-only subcommand; "
		       "'%s' is not installed. Install the shirudo-build "
		       "package on the operator machine (the one with the "
		       "signing key) and re-run there.", path);
		return 127;
	}

	a[0] = (char *)path;
	execv(path, a);
	pr_err("exec %s: %s", path, strerror(errno));
	return 127;
}
