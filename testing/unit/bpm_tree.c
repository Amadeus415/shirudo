// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdint.h>

#include <shirudo/string.h>

#include "bpm_tree.h"
#include "json.h"
#include "malloc.h"
#include "unit.h"

#define DIGEST "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SEALED "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define ROOT "0123456789abcdef0123456789abcdef0123456789ABCDEF0123456789abcdef"

static void set(char *dst, size_t cap, const char *src)
{
	ASSERT_TRUE(strscpy(dst, src, cap) >= 0);
}

static struct tree_operation *operation(void)
{
	struct tree_operation *op = xcalloc(1, sizeof(*op));
	struct tree_selector_kv *label;

	ASSERT_TRUE(op);
	op->seq = 1;
	set(op->op, sizeof(op->op), "add");
	set(op->id, sizeof(op->id), "t");
	set(op->artifact.repository, sizeof(op->artifact.repository),
	    "oci://registry.example/t");
	set(op->artifact.manifest_digest, sizeof(op->artifact.manifest_digest),
	    DIGEST);
	set(op->artifact.layer_digest, sizeof(op->artifact.layer_digest),
	    DIGEST);
	set(op->artifact.payload_sha256, sizeof(op->artifact.payload_sha256),
	    DIGEST);
	ASSERT_EQ(tree_selector_kv_add(&op->selector.labels,
				       &op->selector.n_labels, TREE_MAX_LABELS,
				       &label), 0);
	set(label->key, sizeof(label->key), "site");
	label->n_values = 1;
	set(label->values[0], sizeof(label->values[0]), "a b");
	return op;
}

/*
 * The node's parser refuses a control character, so a publication
 * holding one would go out, signed, and fail every node's sync.
 */
static void operation_takes_no_control_character(void)
{
	struct tree_operation *op = operation();
	struct tree_selector_kv *label = &op->selector.labels[0];
	char digest[72];

	EXPECT_EQ(tree_operation_digest(op, digest), 0);
	label->values[0][1] = '\t';
	EXPECT_EQ(tree_operation_digest(op, digest), -EINVAL);
	label->values[0][1] = ' ';
	label->key[0] = '\n';
	EXPECT_EQ(tree_operation_digest(op, digest), -EINVAL);
	label->key[0] = 's';
	op->artifact.repository[0] = '\r';
	EXPECT_EQ(tree_operation_digest(op, digest), -EINVAL);
	tree_selector_free(&op->selector);
	xfree(op, sizeof(*op));
}

/* What the publisher writes, the node reads back to the same digest. */
static void publication_reads_back(void)
{
	struct tree_publication pub = { .schema = 1, .generation = 1 };
	struct tree_publication back = {};
	struct tree_operation *op = operation();
	char *doc = NULL, again[72];
	size_t len = 0;

	set(pub.tree_id, sizeof(pub.tree_id), "t");
	ASSERT_EQ(tree_operation_digest(op, op->operation_digest), 0);
	ASSERT_EQ(tree_publication_append(&pub, op), 0);
	pub.head_seq = 1;
	ASSERT_EQ(tree_emit_publication(&pub, NULL, &doc, &len), 0);
	ASSERT_EQ(tree_parse(doc, len, &back), 0);
	EXPECT_EQ(back.schema, 1);
	ASSERT_EQ(back.n_operations, 1);
	ASSERT_EQ(tree_operation_digest(&back.operations[0], again), 0);
	EXPECT_STREQ(again, op->operation_digest);
	EXPECT_STREQ(back.operations[0].selector.labels[0].values[0], "a b");
	xfree(doc, len);
	tree_publication_free(&pub);
	tree_publication_free(&back);
	tree_selector_free(&op->selector);
	xfree(op, sizeof(*op));
}

/* Keys past the emitter's bound, as a publisher's fixes can be. */
static int emit_fixes(struct json_emit *e, int index, void *ctx)
{
	char id[201];

	if (ctx)
		return -EIO;
	memset(id, 'A' + index, sizeof(id) - 1);
	id[sizeof(id) - 1] = '\0';
	json_arr_open(e, "fixes");
	for (int i = 0; i < 64; i++)
		json_str(e, id);
	json_arr_close(e);
	return 0;
}

/*
 * A key the publisher adds goes after the artifact and before the
 * digest, which does not cover it, and the node reads past it.
 */
static void publication_carries_keys_outside_the_digest(void)
{
	struct tree_publication pub = { .schema = 1, .generation = 1 };
	struct tree_emit_extra extra = { emit_fixes, NULL };
	struct tree_publication back = {};
	struct tree_operation *op = operation();
	char *doc = NULL, again[72];
	const char *fixes, *digest;
	size_t len = 0;

	set(pub.tree_id, sizeof(pub.tree_id), "t");
	ASSERT_EQ(tree_operation_digest(op, op->operation_digest), 0);
	ASSERT_EQ(tree_publication_append(&pub, op), 0);
	pub.head_seq = 1;
	ASSERT_EQ(tree_emit_publication(&pub, &extra, &doc, &len), 0);
	EXPECT_GT(len, 64 * 200);
	fixes = strstr(doc, "},\"fixes\":[\"AAAA");
	digest = strstr(doc, "\"],\"operation_digest\":");
	EXPECT_TRUE(fixes && digest && fixes < digest);
	ASSERT_EQ(tree_parse(doc, len, &back), 0);
	ASSERT_EQ(back.n_operations, 1);
	ASSERT_EQ(tree_operation_digest(&back.operations[0], again), 0);
	EXPECT_STREQ(again, op->operation_digest);
	EXPECT_STREQ(back.operations[0].operation_digest, op->operation_digest);
	xfree(doc, len);
	doc = NULL;
	extra.ctx = &extra;
	EXPECT_EQ(tree_emit_publication(&pub, &extra, &doc, &len), -EIO);
	EXPECT_FALSE(doc);
	tree_publication_free(&pub);
	tree_publication_free(&back);
	tree_selector_free(&op->selector);
	xfree(op, sizeof(*op));
}

/* A malformed fixes, which no publisher writes, the node reads past. */
static int emit_malformed_fixes(struct json_emit *e, int index, void *ctx)
{
	json_obj_open_key(e, "fixes");
	json_arr_open(e, "n");
	json_raw_value(e, "null", 4);
	json_str(e, "\a");
	json_arr_close(e);
	json_obj_close(e);
	json_arr_open(e, "fixes");
	json_str(e, "");
	json_arr_close(e);
	return 0;
}

static void publication_reads_past_malformed_fixes(void)
{
	struct tree_emit_extra extra = { emit_malformed_fixes, NULL };
	struct tree_publication pub = { .schema = 1, .generation = 1 };
	struct tree_publication back = {};
	struct tree_operation *op = operation();
	char *doc = NULL;
	size_t len = 0;

	set(pub.tree_id, sizeof(pub.tree_id), "t");
	ASSERT_EQ(tree_operation_digest(op, op->operation_digest), 0);
	ASSERT_EQ(tree_publication_append(&pub, op), 0);
	pub.head_seq = 1;
	ASSERT_EQ(tree_emit_publication(&pub, &extra, &doc, &len), 0);
	EXPECT_TRUE(strstr(doc, "\"fixes\":{\"n\":[null,\"\\u0007\"]}"));
	ASSERT_EQ(tree_parse(doc, len, &back), 0);
	EXPECT_EQ(tree_publication_check(&back), 0);
	ASSERT_EQ(back.n_operations, 1);
	EXPECT_EQ(tree_operation_validate(&back.operations[0]), 0);
	xfree(doc, len);
	tree_publication_free(&pub);
	tree_publication_free(&back);
	tree_selector_free(&op->selector);
	xfree(op, sizeof(*op));
}

/* A later segment names its sealed predecessor and the history before it. */
static void segment_reads_back(void)
{
	struct tree_publication pub = { .schema = 1, .generation = 4,
					.base_seq = 2, .head_seq = 3 };
	struct tree_publication back = {};
	struct tree_operation *op = operation();
	char *doc = NULL;
	size_t len = 0;

	set(pub.tree_id, sizeof(pub.tree_id), "t");
	set(pub.parent_manifest_digest, sizeof(pub.parent_manifest_digest),
	    SEALED);
	set(pub.segment_manifest_digest, sizeof(pub.segment_manifest_digest),
	    SEALED);
	set(pub.history_root, sizeof(pub.history_root), ROOT);
	op->seq = 3;
	ASSERT_EQ(tree_operation_digest(op, op->operation_digest), 0);
	ASSERT_EQ(tree_publication_append(&pub, op), 0);
	ASSERT_EQ(tree_emit_publication(&pub, NULL, &doc, &len), 0);
	EXPECT_TRUE(strstr(doc, "\"base\":{\"seq\":2,"
			   "\"segment_manifest_digest\":\"" SEALED "\","
			   "\"history_root\":\"" ROOT "\"},"));
	ASSERT_EQ(tree_parse(doc, len, &back), 0);
	EXPECT_EQ(back.base_seq, 2);
	EXPECT_STREQ(back.segment_manifest_digest, SEALED);
	EXPECT_STREQ(back.history_root, ROOT);
	EXPECT_EQ(tree_publication_check(&back), 0);
	ASSERT_EQ(back.n_operations, 1);
	EXPECT_EQ(tree_operation_validate(&back.operations[0]), 0);
	xfree(doc, len);
	tree_publication_free(&back);
	pub.history_root[0] = '\0';
	ASSERT_EQ(tree_emit_publication(&pub, NULL, &doc, &len), 0);
	EXPECT_FALSE(strstr(doc, "history_root"));
	xfree(doc, len);
	tree_publication_free(&pub);
	tree_selector_free(&op->selector);
	xfree(op, sizeof(*op));
}

/* A root too long for its key, or a digest that is no string, does not parse. */
static void segment_refuses_malformed_keys(void)
{
	static const char *const docs[] = {
		"{\"schema\":1,\"tree_id\":\"t\",\"generation\":1,"
		"\"base\":{\"seq\":0,\"history_root\":\"" ROOT "0\"},"
		"\"operations\":[],\"head\":{\"seq\":0}}",
		"{\"schema\":1,\"tree_id\":\"t\",\"generation\":1,"
		"\"base\":{\"seq\":0,\"segment_manifest_digest\":3},"
		"\"operations\":[],\"head\":{\"seq\":0}}",
	};
	struct tree_publication pub;

	for (size_t i = 0; i < ARRAY_SIZE(docs); i++)
		EXPECT_NE(tree_parse(docs[i], strlen(docs[i]), &pub), 0);
}

/* What sync checks of an operation before it applies one. */
static void operation_validates_against_its_digest(void)
{
	struct tree_operation *op = operation();

	ASSERT_EQ(tree_operation_digest(op, op->operation_digest), 0);
	EXPECT_EQ(tree_operation_validate(op), 0);
	op->seq = 2;
	EXPECT_EQ(tree_operation_validate(op), -EKEYREJECTED);
	op->seq = 0;
	EXPECT_EQ(tree_operation_validate(op), -EINVAL);
	op->seq = 1;
	set(op->op, sizeof(op->op), "replace");
	EXPECT_EQ(tree_operation_validate(op), -EINVAL);
	set(op->op, sizeof(op->op), "add");
	set(op->id, sizeof(op->id), "../t");
	EXPECT_EQ(tree_operation_validate(op), -EINVAL);
	set(op->id, sizeof(op->id), "t");
	set(op->artifact.layer_digest, sizeof(op->artifact.layer_digest),
	    "sha256:aa");
	EXPECT_EQ(tree_operation_validate(op), -EINVAL);
	tree_selector_free(&op->selector);
	xfree(op, sizeof(*op));
}

static void publication_runs_from_base_to_head(void)
{
	struct tree_operation ops[2] = { { .seq = 1 }, { .seq = 2 } };
	struct tree_publication pub = { .operations = ops, .n_operations = 2,
					.head_seq = 2 };

	EXPECT_EQ(tree_publication_check(&pub), 0);
	pub.head_seq = 3;
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	pub.head_seq = 2;
	ops[0].seq = 2;
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	ops[0].seq = 1;
	set(pub.parent_manifest_digest, sizeof(pub.parent_manifest_digest),
	    "sha256:aa");
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	set(pub.parent_manifest_digest, sizeof(pub.parent_manifest_digest),
	    DIGEST);
	EXPECT_EQ(tree_publication_check(&pub), 0);
	pub.n_operations = 0;
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	pub.head_seq = 0;
	EXPECT_EQ(tree_publication_check(&pub), 0);
	pub.base_seq = -1;
	pub.head_seq = -1;
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
}

/*
 * A segment past the first names its sealed predecessor and the history
 * root at its base and holds an operation; the first names neither.
 */
static void segment_names_its_base(void)
{
	struct tree_operation ops[2] = { { .seq = 3 }, { .seq = 4 } };
	struct tree_publication pub = { .operations = ops, .n_operations = 2,
					.base_seq = 2, .head_seq = 4 };

	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	set(pub.segment_manifest_digest, sizeof(pub.segment_manifest_digest),
	    SEALED);
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	set(pub.history_root, sizeof(pub.history_root), ROOT);
	EXPECT_EQ(tree_publication_check(&pub), 0);
	pub.segment_manifest_digest[0] = '\0';
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	set(pub.segment_manifest_digest, sizeof(pub.segment_manifest_digest),
	    "sha256:bb");
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	set(pub.segment_manifest_digest, sizeof(pub.segment_manifest_digest),
	    "sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	set(pub.segment_manifest_digest, sizeof(pub.segment_manifest_digest),
	    SEALED);
	set(pub.history_root, sizeof(pub.history_root),
	    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde");
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	set(pub.history_root, sizeof(pub.history_root),
	    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg");
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	set(pub.history_root, sizeof(pub.history_root), ROOT);
	EXPECT_EQ(tree_publication_check(&pub), 0);
	pub.n_operations = 0;
	pub.head_seq = 2;
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);

	ops[0].seq = 1;
	ops[1].seq = 2;
	pub = (struct tree_publication){ .operations = ops, .n_operations = 2,
					 .head_seq = 2 };
	set(pub.segment_manifest_digest, sizeof(pub.segment_manifest_digest),
	    SEALED);
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	pub.segment_manifest_digest[0] = '\0';
	set(pub.history_root, sizeof(pub.history_root), ROOT);
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	set(pub.history_root, sizeof(pub.history_root),
	    "0000000000000000000000000000000000000000000000000000000000000000");
	EXPECT_EQ(tree_publication_check(&pub), -EINVAL);
	pub.history_root[0] = '\0';
	EXPECT_EQ(tree_publication_check(&pub), 0);
}

/* A node never goes back to an older tree, or skips past its cursor. */
static void publication_follows_the_recorded_state(void)
{
	struct tree_state state = { .generation = 5, .last_seq = 3 };
	struct tree_publication pub = { .generation = 6, .head_seq = 4 };

	set(state.tree_id, sizeof(state.tree_id), "t");
	set(state.manifest_digest, sizeof(state.manifest_digest), "m5");
	set(pub.tree_id, sizeof(pub.tree_id), "t");
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m6"), 0);
	EXPECT_EQ(tree_publication_follows(&pub, NULL, "m6"), 0);
	set(pub.parent_manifest_digest, sizeof(pub.parent_manifest_digest),
	    "m5");
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m6"), 0);
	set(pub.parent_manifest_digest, sizeof(pub.parent_manifest_digest),
	    "m4");
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m6"), -ERANGE);
	pub.generation = 7;
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m7"), 0);
	pub.generation = 5;
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m5"), 0);
	EXPECT_EQ(tree_publication_follows(&pub, &state, "other"), -ERANGE);
	pub.generation = 7;
	pub.head_seq = 2;
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m7"), -ERANGE);
	pub.head_seq = 4;
	set(pub.tree_id, sizeof(pub.tree_id), "u");
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m7"), -EINVAL);
	state.generation = INT64_MAX;
	set(pub.tree_id, sizeof(pub.tree_id), "t");
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m7"), -ERANGE);
}

/*
 * A node behind a segment's base walks back to it, once the publication
 * would otherwise follow; a node at or past the base does not.
 */
static void segment_asks_for_a_walk(void)
{
	struct tree_state state = { .generation = 5, .last_seq = 3,
				    .head_seq = 4 };
	struct tree_publication pub = { .generation = 8, .base_seq = 4,
					.head_seq = 6 };

	set(state.tree_id, sizeof(state.tree_id), "t");
	set(state.manifest_digest, sizeof(state.manifest_digest), "m5");
	set(pub.tree_id, sizeof(pub.tree_id), "t");
	EXPECT_EQ(tree_publication_follows(&pub, NULL, "m8"),
		  TREE_FOLLOWS_WALK);
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m8"),
		  TREE_FOLLOWS_WALK);
	state.last_seq = 4;
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m8"), 0);
	state.last_seq = 5;
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m8"), 0);
	state.last_seq = 6;
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m8"), 0);
	state.last_seq = 7;
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m8"), -ERANGE);

	state.last_seq = 3;
	pub.generation = 6;
	set(pub.parent_manifest_digest, sizeof(pub.parent_manifest_digest),
	    "m5");
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m6"),
		  TREE_FOLLOWS_WALK);
	set(pub.parent_manifest_digest, sizeof(pub.parent_manifest_digest),
	    "m4");
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m6"), -ERANGE);
	pub.generation = 5;
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m6"), -ERANGE);
	pub.generation = 8;
	set(pub.tree_id, sizeof(pub.tree_id), "u");
	EXPECT_EQ(tree_publication_follows(&pub, &state, "m8"), -EINVAL);
}

/* One step back: the sealed segment the successor names, right before it. */
static void segment_precedes_its_successor(void)
{
	struct tree_publication pred = { .generation = 3, .base_seq = 0,
					 .head_seq = 2 };
	struct tree_publication succ = { .generation = 4, .base_seq = 2,
					 .head_seq = 4 };

	set(pred.tree_id, sizeof(pred.tree_id), "t");
	set(succ.tree_id, sizeof(succ.tree_id), "t");
	set(succ.segment_manifest_digest, sizeof(succ.segment_manifest_digest),
	    SEALED);
	EXPECT_EQ(tree_segment_precedes(&pred, SEALED, &succ), 0);
	EXPECT_EQ(tree_segment_precedes(&pred, DIGEST, &succ), -ERANGE);
	set(pred.tree_id, sizeof(pred.tree_id), "u");
	EXPECT_EQ(tree_segment_precedes(&pred, SEALED, &succ), -ERANGE);
	set(pred.tree_id, sizeof(pred.tree_id), "t");
	pred.head_seq = 1;
	EXPECT_EQ(tree_segment_precedes(&pred, SEALED, &succ), -ERANGE);
	pred.head_seq = 3;
	EXPECT_EQ(tree_segment_precedes(&pred, SEALED, &succ), -ERANGE);
	pred.head_seq = 2;
	pred.generation = 4;
	EXPECT_EQ(tree_segment_precedes(&pred, SEALED, &succ), -ERANGE);
	pred.generation = 5;
	EXPECT_EQ(tree_segment_precedes(&pred, SEALED, &succ), -ERANGE);
	pred.generation = 1;
	EXPECT_EQ(tree_segment_precedes(&pred, SEALED, &succ), 0);
	succ.base_seq = 0;
	pred.head_seq = 0;
	EXPECT_EQ(tree_segment_precedes(&pred, SEALED, &succ), -ERANGE);
	succ.segment_manifest_digest[0] = '\0';
	EXPECT_EQ(tree_segment_precedes(&pred, "", &succ), -ERANGE);
}

static const struct unit_case cases[] = {
	UNIT_CASE(operation_takes_no_control_character),
	UNIT_CASE(publication_reads_back),
	UNIT_CASE(publication_carries_keys_outside_the_digest),
	UNIT_CASE(publication_reads_past_malformed_fixes),
	UNIT_CASE(segment_reads_back),
	UNIT_CASE(segment_refuses_malformed_keys),
	UNIT_CASE(operation_validates_against_its_digest),
	UNIT_CASE(publication_runs_from_base_to_head),
	UNIT_CASE(segment_names_its_base),
	UNIT_CASE(publication_follows_the_recorded_state),
	UNIT_CASE(segment_asks_for_a_walk),
	UNIT_CASE(segment_precedes_its_successor),
	{}
};

UNIT_SUITE(bpm_tree, cases);
