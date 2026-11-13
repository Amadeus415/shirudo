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

static const struct unit_case cases[] = {
	UNIT_CASE(sha256_matches_fips_180_vector),
	UNIT_CASE(sha256_2_hashes_the_concatenation),
	UNIT_CASE(sha256_2_reports_a_failure),
	UNIT_CASE(chain_events_hash_their_documented_input),
	UNIT_CASE(chain_fold_extends_like_the_register),
	{}
};

UNIT_SUITE(chain, cases);
