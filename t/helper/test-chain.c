// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Harness for util/chain's pure helpers (hex, sha256, constant-time
 * compare). Subcommand on argv[1]; inputs as argv. Prints the result
 * so a shell test can assert on it.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chain.h"

static void puthex(const uint8_t *b, size_t n)
{
	char h[2 * 64 + 1];

	shirudo_hex_encode(b, n, h);
	printf("%s\n", h);
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 2;

	if (strcmp(argv[1], "sha256") == 0 && argc == 3) {
		uint8_t d[32];

		shirudo_sha256(argv[2], strlen(argv[2]), d);
		puthex(d, 32);
		return 0;
	}
	if (strcmp(argv[1], "decode") == 0 && argc == 4) {
		size_t n = (size_t)strtoul(argv[3], NULL, 10);
		uint8_t buf[256];
		int rc;

		if (n > sizeof(buf))
			return 2;
		rc = shirudo_hex_decode(argv[2], buf, n);
		printf("rc=%d\n", rc);
		if (rc == 0)
			puthex(buf, n);
		return 0;
	}
	if (strcmp(argv[1], "cteq") == 0 && argc == 4) {
		uint8_t a[256], b[256];
		size_t na = strlen(argv[2]) / 2, nb = strlen(argv[3]) / 2;

		if (na != nb || na > sizeof(a))
			return 2;
		if (shirudo_hex_decode(argv[2], a, na) ||
		    shirudo_hex_decode(argv[3], b, nb))
			return 2;
		printf("%d\n", shirudo_ct_eq(a, b, na));
		return 0;
	}
	return 2;
}
