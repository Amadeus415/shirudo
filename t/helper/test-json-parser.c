// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Harness for util/json's schema parser. Reads a JSON document from
 * stdin, parses it against an eventlog-shaped schema (scalars, a
 * string array, and an object array), and prints the return code and
 * extracted fields on success. Doubles as a fuzz entry point: feed it
 * arbitrary bytes -- it must never crash, only return a clean -errno.
 */

#include <stdint.h>
#include <stdio.h>

#include "json.h"

static int names_seen;
static char first_name[64];
static char name_scratch[64];

static int name_on_elem(void *ctx)
{
	(void)ctx;
	if (names_seen == 0)
		snprintf(first_name, sizeof(first_name), "%s", name_scratch);
	names_seen++;
	return 0;
}

static int events_seen;
static char last_event_type[32];
static char ev_type[32];
static char ev_digest[65];

static int event_on_elem(void *ctx)
{
	(void)ctx;
	snprintf(last_event_type, sizeof(last_event_type), "%s", ev_type);
	events_seen++;
	return 0;
}

int main(void)
{
	char digest[65] = {}, type[64] = {};
	static char buf[2 * 1024 * 1024];
	int64_t schema = -1;
	struct shirudo_json_array name_sink = { name_on_elem, NULL };
	struct shirudo_json_field name_sub[] = {
		{ "", SHIRUDO_JSON_T_STRING, name_scratch,
		  sizeof(name_scratch), 0, NULL, 0 },
	};
	struct shirudo_json_array event_sink = { event_on_elem, NULL };
	struct shirudo_json_field event_sub[] = {
		{ "type",   SHIRUDO_JSON_T_STRING, ev_type,
		  sizeof(ev_type), 0, NULL, 0 },
		{ "digest", SHIRUDO_JSON_T_STRING, ev_digest,
		  sizeof(ev_digest), 0, NULL, 0 },
	};
	struct shirudo_json_field f[] = {
		{ "schema", SHIRUDO_JSON_T_INT,    &schema, 0, 0, NULL, 0 },
		{ "type",   SHIRUDO_JSON_T_STRING, type,   sizeof(type), 0, NULL, 0 },
		{ "digest", SHIRUDO_JSON_T_STRING, digest, sizeof(digest), 0, NULL, 0 },
		{ "names",  SHIRUDO_JSON_T_ARRAY,  &name_sink, 0, 0, name_sub, 1 },
		{ "events", SHIRUDO_JSON_T_ARRAY,  &event_sink, 0, 0, event_sub, 2 },
	};
	size_t n = fread(buf, 1, sizeof(buf), stdin);
	int rc = shirudo_json_parse(buf, n, f, sizeof(f) / sizeof(f[0]));

	printf("rc=%d\n", rc);
	if (rc == 0) {
		printf("schema=%lld type=%s digest=%s\n",
		       (long long)schema, type, digest);
		printf("names=%d first_name=%s events=%d last_type=%s\n",
		       names_seen, first_name, events_seen, last_event_type);
	}
	return rc ? 1 : 0;
}
