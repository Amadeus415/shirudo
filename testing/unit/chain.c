// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "chain.h"
#include "hex.h"
#include "unit.h"

static void sha256_matches_fips_180_vector(void)
{
	static const char want[] =
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
	char hex[2 * 32 + 1];
	__u8 d[32];

	ASSERT_EQ(sha256_calc("abc", 3, d), 0);
	hex_encode(d, sizeof(d), hex);
	EXPECT_STREQ(hex, want);
}

static void sha256_2_hashes_the_concatenation(void)
{
	__u8 one[32], two[32];

	ASSERT_EQ(sha256_calc("abc", 3, one), 0);
	ASSERT_EQ(sha256_2("ab", 2, "c", 1, two), 0);
	EXPECT_MEMEQ(two, one, sizeof(one));
	ASSERT_EQ(sha256_2("abc", 3, NULL, 0, two), 0);
	EXPECT_MEMEQ(two, one, sizeof(one));
}

/* A failure must be reported, not left to a zeroed digest to mismatch. */
static void sha256_2_reports_a_failure(void)
{
	__u8 out[32], zero[32] = {};

	memset(out, 0xff, sizeof(out));
	EXPECT_NE(sha256_2(NULL, 3, "c", 1, out), 0);
	EXPECT_MEMEQ(out, zero, sizeof(out));
}

static void chain_events_hash_their_documented_input(void)
{
	static const char tag[] = "shirudo-key-revoke";
	__u8 cert[32], buf[sizeof(tag) + 32], want[32], event[32];

	memset(cert, 0xa5, sizeof(cert));
	memcpy(buf, tag, sizeof(tag));
	memcpy(buf + sizeof(tag), cert, sizeof(cert));
	ASSERT_EQ(sha256_calc(buf, sizeof(buf), want), 0);
	ASSERT_EQ(chain_key_event(tag, cert, event), 0);
	EXPECT_MEMEQ(event, want, sizeof(want));
}

static void chain_fold_extends_like_the_register(void)
{
	__u8 chain[32] = {}, event[32], cat[64] = {}, want[32];

	memset(event, 0x5a, sizeof(event));
	memcpy(cat + 32, event, sizeof(event));
	ASSERT_EQ(sha256_calc(cat, sizeof(cat), want), 0);
	ASSERT_EQ(chain_fold(chain, event), 0);
	EXPECT_MEMEQ(chain, want, sizeof(want));
}

/*
 * The operation digests of a three-operation tree, and the history root
 * after none, one, two and all of them as Python's hashlib gives it:
 *
 *   root = bytes(32)
 *   for d in digests:
 *       root = sha256(b"shirudo-tree-history\0" + root + d).digest()
 */
static const char *const tree_operations[] = {
	"13b248d4a85d91150717e3e96dc9c2d7a8a43633e3b58f8f6168d408aed26c43",
	"5ce215313f29f87bfb87aa0cc65c237bf21bdc7702606e9cc29be187f950074b",
	"bd98b27dd5cfc9deeb0e4f49a7d4bd0f991762ec784be9ea838a59966d9dd0dc",
};

static const char *const history_roots[] = {
	"0000000000000000000000000000000000000000000000000000000000000000",
	"470779d64e1302c4826a4be3222020050e70784ae6016040eabde9d0d8770d80",
	"889efeb27650c0111168d523c935f051addbcc049d079e440e518dd3939722f0",
	"bdc9ee89e753beca03d6e9ae89344269cb3a2e8ba3662122f55b1e3f7ff34011",
};

static void history_root_after(size_t n, char hex[2 * 32 + 1])
{
	__u8 root[32] = {}, digest[32];
	size_t i;

	for (i = 0; i < n; i++) {
		ASSERT_EQ(hex_decode(tree_operations[i], digest, 32), 0);
		ASSERT_EQ(chain_history_step(root, digest, root), 0);
	}
	hex_encode(root, sizeof(root), hex);
}

static void history_root_matches_the_reference(void)
{
	char hex[2 * 32 + 1];

	history_root_after(0, hex);
	EXPECT_STREQ(hex, history_roots[0]);
	history_root_after(1, hex);
	EXPECT_STREQ(hex, history_roots[1]);
	history_root_after(3, hex);
	EXPECT_STREQ(hex, history_roots[3]);
}

static void history_step_writes_beside_its_input(void)
{
	__u8 prev[32] = {}, zero[32] = {}, digest[32], out[32];
	char hex[2 * 32 + 1];

	ASSERT_EQ(hex_decode(tree_operations[0], digest, 32), 0);
	ASSERT_EQ(chain_history_step(prev, digest, out), 0);
	hex_encode(out, sizeof(out), hex);
	EXPECT_STREQ(hex, history_roots[1]);
	EXPECT_MEMEQ(prev, zero, sizeof(prev));
}

/* The tag keeps the two roots of one tree apart at every operation. */
static void history_root_differs_from_the_projection_root(void)
{
	static const char *const projection_roots[] = {
		"04f83540c1727aefcf3c53449a99594c8fd1cc15e1466dbdbf3168cc8f9dc136",
		"a042a582b3a3d8c1b633b8ed0356e0b52f1f5aa25af85b06cc3f481562dcda93",
		"154522480ff8884daa95589e80f26f20248bbf9c192dfbb3cee04e03b4f136a1",
	};
	__u8 history[32] = {}, projection[32] = {}, digest[32];
	char hex[2 * 32 + 1];
	size_t i;

	for (i = 0; i < ARRAY_SIZE(tree_operations); i++) {
		ASSERT_EQ(hex_decode(tree_operations[i], digest, 32), 0);
		ASSERT_EQ(chain_history_step(history, digest, history), 0);
		ASSERT_EQ(sha256_2(projection, 32, digest, 32, projection), 0);
		hex_encode(projection, sizeof(projection), hex);
		EXPECT_STREQ(hex, projection_roots[i]);
		hex_encode(history, sizeof(history), hex);
		EXPECT_STREQ(hex, history_roots[i + 1]);
		EXPECT_TRUE(memcmp(history, projection, sizeof(history)) != 0);
	}
}

static const struct unit_case cases[] = {
	UNIT_CASE(sha256_matches_fips_180_vector),
	UNIT_CASE(sha256_2_hashes_the_concatenation),
	UNIT_CASE(sha256_2_reports_a_failure),
	UNIT_CASE(chain_events_hash_their_documented_input),
	UNIT_CASE(chain_fold_extends_like_the_register),
	UNIT_CASE(history_root_matches_the_reference),
	UNIT_CASE(history_step_writes_beside_its_input),
	UNIT_CASE(history_root_differs_from_the_projection_root),
	{}
};

UNIT_SUITE(chain, cases);
