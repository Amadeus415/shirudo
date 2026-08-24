// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Offline checks for the paged serializer map-view output contract.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "json.h"
#include "serializer.h"
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

static int check_abi_and_nonce(void)
{
	uint64_t generated = 0;
	struct shirudo_serial_chunk chunk = {
		.magic = SHIRUDO_SERIAL_MAGIC,
		.version = SHIRUDO_SERIAL_VERSION,
		.chunk_index = 1,
		.total_chunks = 2,
		.bytes_total = 1,
		.bytes_in_chunk = 1,
		.page_index = 3,
		.cursor = 10,
		.next_cursor = 11,
		.invocation_id = 0x12345678,
	};

	if (SHIRUDO_SERIAL_VERSION != 3 ||
	    sizeof(struct shirudo_serialize_ctx) != 40 ||
	    sizeof(struct shirudo_serial_chunk) != 4096 ||
	    SHIRUDO_SERIAL_CHUNK_PAYLOAD != 4032)
		return fail("serializer v3 ABI layout mismatch");
	if (shirudo_serial_chunk_validate(&chunk, 1, 2, 3, 10, 11, 0x12345678) != 0)
		return fail("valid serializer nonce rejected");
	if (shirudo_serial_chunk_validate(&chunk, 1, 2, 3, 10, 11, 0x87654321) != -EBADMSG)
		return fail("serializer nonce mismatch accepted");
	if (shirudo_serializer_new_invocation_id(&generated) != 0 || generated == 0)
		return fail("serializer invocation ID generation failed");
	return 0;
}

static int check_map_locks(void)
{
	char dir[] = "/tmp/shirudo-serializer-lock-XXXXXX";
	char path1[256], path2[256];
	int first = -1, busy = -1, other = -1, again = -1, rc = 1;

	if (!mkdtemp(dir))
		return fail("mkdtemp failed");
	first = shirudo_serializer_lock_acquire_at(dir, 101);
	if (first < 0) {
		fail("first serializer lock failed");
		goto out;
	}
	busy = shirudo_serializer_lock_acquire_at(dir, 101);
	if (busy != -EBUSY) {
		fail("contended serializer lock did not return EBUSY");
		goto out;
	}
	other = shirudo_serializer_lock_acquire_at(dir, 202);
	if (other < 0) {
		fail("independent serializer map lock failed");
		goto out;
	}
	close(first);
	first = -1;
	again = shirudo_serializer_lock_acquire_at(dir, 101);
	if (again < 0) {
		fail("released serializer lock could not be reacquired");
		goto out;
	}
	rc = 0;
out:
	if (first >= 0)
		close(first);
	if (other >= 0)
		close(other);
	if (again >= 0)
		close(again);
	if (busy >= 0)
		close(busy);
	snprintf(path1, sizeof(path1), "%s/serializer-map-101.lock", dir);
	snprintf(path2, sizeof(path2), "%s/serializer-map-202.lock", dir);
	unlink(path1);
	unlink(path2);
	rmdir(dir);
	return rc;
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

	if (check_abi_and_nonce() || check_map_locks())
		return 1;

	e.buf = buf;
	e.cap = sizeof(buf);
	shirudo_upatch_maps_emit_json_object(&e, &v);
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
