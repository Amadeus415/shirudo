// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * util/log.c's line wrapping at a given width.
 */

#include <stdio.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "util/log.h"

int main(int argc, char **argv)
{
	__u64 width, indent;

	if (argc != 5 ||
	    parse_u64(argv[1], strlen(argv[1]), 1000, &width) ||
	    parse_u64(argv[3], strlen(argv[3]), 1000, &indent)) {
		fprintf(stderr, "usage: test-log <width> <lead> <indent> <text>\n");
		return 2;
	}
	print_wrapped_to(stdout, (size_t)width, argv[2], argv[4],
			 (size_t)indent);
	return 0;
}
