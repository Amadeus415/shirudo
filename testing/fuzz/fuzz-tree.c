// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * tree_parse() on an upatch tree publication, the canonical
 * digest of every operation it accepts and the publication emitted again,
 * bare and with the publisher's fixes, which must read back with the same
 * operations and digests.
 */

#include <stdlib.h>

#include "fuzz.h"

#include <shirudo/string.h>

#include "bpm_tree.h"
#include "json.h"
#include "malloc.h"

static int emit_fixes(struct json_emit *e, int index, void *ctx)
{
	if (index % 2)
		return 0;
	json_arr_open(e, "fixes");
	json_str(e, "EXAMPLE-0101");
	json_str(e, ((const struct tree_publication *)ctx)->tree_id);
	json_arr_close(e);
	return 0;
}

static void read_back(const struct tree_publication *pub,
		      const struct tree_emit_extra *extra)
{
	char digest[72], back[72], *out;
	struct tree_publication again;
	size_t len;

	if (tree_emit_publication(pub, extra, &out, &len))
		return;
	if (tree_parse(out, len, &again) ||
	    again.n_operations != pub->n_operations ||
	    strcmp(again.tree_id, pub->tree_id) ||
	    again.generation != pub->generation ||
	    again.head_seq != pub->head_seq)
		abort();
	for (int i = 0; i < pub->n_operations; i++) {
		if (tree_operation_digest(&pub->operations[i], digest) !=
		    tree_operation_digest(&again.operations[i], back) ||
		    strcmp(digest, back) ||
		    strcmp(again.operations[i].operation_digest,
			   pub->operations[i].operation_digest))
			abort();
	}
	tree_publication_free(&again);
	xfree(out, len);
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct tree_publication pub;
	struct tree_emit_extra extra = { emit_fixes, &pub };

	if (tree_parse((const char *)data, size, &pub))
		return 0;
	read_back(&pub, NULL);
	read_back(&pub, &extra);
	tree_publication_free(&pub);
	return 0;
}
