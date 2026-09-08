/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "mode.h"

int main(void)
{
	char buf[512];
	struct shirudo_mode_state state;
	size_t len = 0;
	int rc;

	while (len < sizeof(buf)) {
		ssize_t n = read(STDIN_FILENO, buf + len, sizeof(buf) - len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return EXIT_FAILURE;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	if (len == sizeof(buf))
		return EXIT_FAILURE;

	rc = shirudo_mode_parse(buf, len, &state);
	printf("rc=%d\n", rc);
	return 0;
}
