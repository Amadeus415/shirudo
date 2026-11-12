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
	pub.base_seq = 1;
	EXPECT_EQ(tree_publication_check(&pub), -ENOTSUP);
	pub.base_seq = 0;
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

static const struct unit_case cases[] = {
	UNIT_CASE(operation_takes_no_control_character),
	UNIT_CASE(publication_reads_back),
	UNIT_CASE(publication_carries_keys_outside_the_digest),
	UNIT_CASE(publication_reads_past_malformed_fixes),
	UNIT_CASE(operation_validates_against_its_digest),
	UNIT_CASE(publication_runs_from_base_to_head),
	UNIT_CASE(publication_follows_the_recorded_state),
	{}
};

UNIT_SUITE(bpm_tree, cases);
