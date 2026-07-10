// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Offline checks for the paged serializer map-view output contract.
 */

#include <stdio.h>
#include <string.h>

#include "json.h"
#include "upatch_maps.h"
#include "bpf/lib/shirudo_serializer.h"

static int fail(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	return 1;
}

static int has(const char *haystack, const char *needle)
{
	return strstr(haystack, needle) != NULL;
}

int main(void)
{
	unsigned char page0_data[] = { 0xaa, 0xbb };
	unsigned char page1_data[] = { 0xcc };
	struct shirudo_serial_page pages[2] = {
		{
			.page_index = 0,
			.cursor = 0,
			.next_cursor = 128,
			.flags = 0,
			.chunks = 1,
			.bytes = sizeof(page0_data),
			.done = false,
			.data = page0_data,
		},
		{
			.page_index = 1,
			.cursor = 128,
			.next_cursor = 129,
			.flags = SHIRUDO_SERIAL_F_DONE,
			.chunks = 1,
			.bytes = sizeof(page1_data),
			.done = true,
			.data = page1_data,
		},
	};
	struct shirudo_map_view v = {
		.name = "tree_arena",
		.type_name = "arena",
		.max_entries = 32,
		.serialized = true,
		.n_serial_pages = 2,
		.serial_bytes_total = sizeof(page0_data) + sizeof(page1_data),
		.serial_pages = pages,
	};
	struct shirudo_json_emit e = {};
	char buf[2048];
	char doc[4096];

	e.buf = buf;
	e.cap = sizeof(buf);
	shirudo_upatch_maps_emit_json(&e, &v);
	if (e.err)
		return fail("json emit failed");

	if (!has(buf, "\"serialized\":true"))
		return fail("missing serialized flag");
	if (!has(buf, "\"serialized_pages\":2"))
		return fail("missing page count");
	if (!has(buf, "\"serialized_bytes\":3"))
		return fail("missing byte count");
	if (!has(buf, "\"pages\":["))
		return fail("missing pages array");
	if (!has(buf, "\"page_index\":0") ||
	    !has(buf, "\"cursor\":0") ||
	    !has(buf, "\"next_cursor\":128") ||
	    !has(buf, "\"done\":false") ||
	    !has(buf, "\"data_hex\":\"aabb\""))
		return fail("missing first page fields");
	if (!has(buf, "\"page_index\":1") ||
	    !has(buf, "\"cursor\":128") ||
	    !has(buf, "\"next_cursor\":129") ||
	    !has(buf, "\"done\":true") ||
	    !has(buf, "\"flags\":1") ||
	    !has(buf, "\"data_hex\":\"cc\""))
		return fail("missing final page fields");
	if (has(buf, "\"serialized_chunks\""))
		return fail("old chunk field still emitted");

	e = (struct shirudo_json_emit){ .buf = doc, .cap = sizeof(doc) };
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_kv_string(&e, "upatch", "exec-uid-arena");
	shirudo_json_kv_string(&e, "map", "tree_arena");
	shirudo_json_obj_open_key(&e, "data");
	shirudo_upatch_maps_emit_json_fields(&e, &v);
	shirudo_json_obj_close(&e);
	shirudo_json_obj_close(&e);
	if (e.err)
		return fail("wrapped json emit failed");
	if (has(doc, "\"data\":{{"))
		return fail("wrapped map JSON emitted nested data object");
	if (!has(doc, "\"data\":{\"name\":\"tree_arena\""))
		return fail("wrapped map JSON missing single data object");

	puts("ok");
	return 0;
}
