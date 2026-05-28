// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Unified upatches-loaded table; see util/upatch_table.h.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "json.h"
#include "timefmt.h"
#include "upatch_table.h"

int64_t shirudo_upatch_age_sec(const char *ts)
{
	struct tm tm = {};

	if (!ts || !ts[0])
		return -1;
	if (!strptime(ts, "%Y-%m-%dT%H:%M:%SZ", &tm))
		return -1;
	return (int64_t)(time(NULL) - timegm(&tm));
}

void shirudo_upatch_table_print(const struct shirudo_upatch_table_row *rows,
				size_t n)
{
	size_t i;

	printf("\nupatches loaded (%zu):\n", n);
	if (n == 0)
		return;
	printf("  %-24s  %-28s  %5s  %s\n", "NAME", "LOCATION", "MAPS", "AGE");
	for (i = 0; i < n; i++) {
		const struct shirudo_upatch_table_row *r = &rows[i];
		char age[16] = "?";

		if (r->age_sec >= 0)
			shirudo_format_duration((long)r->age_sec,
						age, sizeof(age));
		printf("  %-24s  %-28s  %5u  %s\n", r->name,
		       r->location[0] ? r->location : "-",
		       r->n_maps, age);
	}
}

void shirudo_upatch_table_emit_json(struct shirudo_json_emit *e,
				    const struct shirudo_upatch_table_row *rows,
				    size_t n)
{
	size_t i;

	shirudo_json_arr_open(e, "upatches_loaded");
	for (i = 0; i < n; i++) {
		const struct shirudo_upatch_table_row *r = &rows[i];

		shirudo_json_obj_open(e);
		shirudo_json_kv_string(e, "name", r->name);
		shirudo_json_kv_string(e, "location", r->location);
		shirudo_json_kv_int(e, "n_maps", (int64_t)r->n_maps);
		shirudo_json_kv_string(e, "loaded_at", r->loaded_at);
		if (r->age_sec >= 0)
			shirudo_json_kv_int(e, "age_sec", r->age_sec);
		else
			shirudo_json_kv_null(e, "age_sec");
		if (r->payload_sha256[0])
			shirudo_json_kv_string(e, "payload_sha256",
					       r->payload_sha256);
		else
			shirudo_json_kv_null(e, "payload_sha256");
		shirudo_json_obj_close(e);
	}
	shirudo_json_arr_close(e);
}
