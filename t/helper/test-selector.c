// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Harness for util/selector. argv[1] is a --selector expression; it is
 * parsed, then matched against the labels of the first registered
 * remote (the shell test seeds one via a temp XDG_CONFIG_HOME). Prints
 * "parse-error", "no-remote", "match", or "nomatch".
 */

#include <stddef.h>
#include <stdio.h>

#include "remotes.h"
#include "selector.h"

int main(int argc, char **argv)
{
	struct shirudo_remote *remotes = NULL;
	struct shirudo_selector *sel;
	size_t n = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: test-selector <expr>\n");
		return 2;
	}

	sel = shirudo_selector_parse(argv[1]);
	if (!sel) {
		printf("parse-error\n");
		return 0;
	}

	shirudo_remotes_load_all(&remotes, &n);
	if (n == 0) {
		printf("no-remote\n");
		shirudo_selector_free(sel);
		return 0;
	}

	printf("%s\n",
	       shirudo_selector_match(sel, remotes[0].labels) ? "match"
							       : "nomatch");
	shirudo_selector_free(sel);
	shirudo_remotes_free(remotes, n);
	return 0;
}
