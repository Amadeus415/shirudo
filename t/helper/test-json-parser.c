// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Harness for util/json's schema parser. Reads a JSON document from
 * stdin, parses it against an eventlog-shaped schema, and prints the
 * return code (and extracted fields on success). Doubles as a fuzz
 * entry point: feed it arbitrary bytes -- it must never crash, only
 * return a clean -errno.
 */

#include <stdint.h>
#include <stdio.h>

#include "json.h"

int main(void)
{
	char digest[65] = {}, type[64] = {};
	static char buf[2 * 1024 * 1024];
	int64_t schema = -1;
	struct shirudo_json_field f[] = {
		{ "schema", SHIRUDO_JSON_T_INT,    &schema, 0, 0, NULL, 0 },
		{ "type",   SHIRUDO_JSON_T_STRING, type,   sizeof(type), 0, NULL, 0 },
		{ "digest", SHIRUDO_JSON_T_STRING, digest, sizeof(digest), 0, NULL, 0 },
	};
	size_t n = fread(buf, 1, sizeof(buf), stdin);
	int rc = shirudo_json_parse(buf, n, f, sizeof(f) / sizeof(f[0]));

	printf("rc=%d\n", rc);
	if (rc == 0)
		printf("schema=%lld type=%s digest=%s\n",
		       (long long)schema, type, digest);
	return rc ? 1 : 0;
}
