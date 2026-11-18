// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The inline helpers of include/shirudo/string.h, which the C left in the
 * tree still uses; the rest of the header is the Rust text module's, which
 * its own tests cover.
 */

#include <shirudo/string.h>

#include "unit.h"

static void memzero_explicit_clears_its_span_only(void)
{
	__u8 want[16], buf[16];

	memset(buf, 0xa5, sizeof(buf));
	memset(want, 0xa5, sizeof(want));
	memset(want + 4, 0, 8);
	memzero_explicit(buf + 4, 8);
	EXPECT_MEMEQ(buf, want, sizeof(buf));
}

#define TEST_DIR "/run"

static void str_has_prefix_gives_its_length(void)
{
	EXPECT_UEQ(str_has_prefix("oci://registry", "oci://"), 6);
	EXPECT_UEQ(str_has_prefix("oci://", "oci://"), 6);
	EXPECT_UEQ(str_has_prefix("oci:/", "oci://"), 0);
	EXPECT_UEQ(str_has_prefix("OCI://registry", "oci://"), 0);
	EXPECT_UEQ(str_has_prefix("", "oci://"), 0);
	EXPECT_UEQ(str_has_prefix("/run/x", TEST_DIR "/"), 5);
}

static void str_skip_prefix_moves_only_on_a_match(void)
{
	const char *p = "realm=\"x\"";
	char buf[] = "s3://bucket";
	char *q = buf;

	EXPECT_FALSE(str_skip_prefix(&p, "scope=\""));
	EXPECT_STREQ(p, "realm=\"x\"");
	EXPECT_TRUE(str_skip_prefix(&p, "realm=\""));
	EXPECT_STREQ(p, "x\"");
	EXPECT_TRUE(str_skip_prefix(&q, "s3://"));
	EXPECT_TRUE(q == buf + 5);
}

static void span_equals_wants_the_whole_literal(void)
{
	const char *path = "a/../b";

	EXPECT_TRUE(span_equals(path + 2, 2, ".."));
	EXPECT_FALSE(span_equals(path + 2, 3, ".."));
	EXPECT_FALSE(span_equals(path + 2, 1, ".."));
	EXPECT_TRUE(span_equals(path + 2, 1, "."));
	EXPECT_FALSE(span_equals(path, 1, "."));
	EXPECT_TRUE(span_equals(path, 0, ""));
}

static const struct unit_case cases[] = {
	UNIT_CASE(memzero_explicit_clears_its_span_only),
	UNIT_CASE(str_has_prefix_gives_its_length),
	UNIT_CASE(str_skip_prefix_moves_only_on_a_match),
	UNIT_CASE(span_equals_wants_the_whole_literal),
	{}
};

UNIT_SUITE(string, cases);
