// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include "keepalive.h"
#include "unit.h"

#define APPLIED		1
#define PASSED_OVER	2
#define NOT_ATTACHED	3

static void expect_mask(const __u8 *codes, size_t n, const char *want)
{
	char b64[KEEPALIVE_MASK_B64_MAX];

	ASSERT_EQ(keepalive_mask(codes, n, b64, sizeof(b64)), 0);
	EXPECT_STREQ(b64, want);
}

static void mask_of_one_operation(void)
{
	static const __u8 applied[] = { APPLIED };
	static const __u8 passed_over[] = { PASSED_OVER };

	expect_mask(applied, 1, "QA==");
	expect_mask(passed_over, 1, "gA==");
}

static void mask_of_the_release_example(void)
{
	static const __u8 node_a[] = { APPLIED, APPLIED, APPLIED };
	static const __u8 node_b[] = { PASSED_OVER, PASSED_OVER, PASSED_OVER };

	expect_mask(node_a, ARRAY_SIZE(node_a), "VA==");
	expect_mask(node_b, ARRAY_SIZE(node_b), "qA==");
}

static void mask_of_sixteen_operations(void)
{
	static const __u8 codes[] = {
		APPLIED, APPLIED, PASSED_OVER, APPLIED,
		NOT_ATTACHED, APPLIED, PASSED_OVER, APPLIED,
		APPLIED, APPLIED, PASSED_OVER, APPLIED,
		0, 0, 0, 0,
	};

	expect_mask(codes, ARRAY_SIZE(codes), "WdlZAA==");
}

static void mask_of_no_operation_is_empty(void)
{
	static const __u8 codes[] = { APPLIED };

	expect_mask(codes, 0, "");
}

static void mask_fills_a_byte_then_pads_the_next(void)
{
	static const __u8 codes[] = {
		APPLIED, APPLIED, APPLIED, APPLIED, APPLIED,
	};

	expect_mask(codes, 4, "VQ==");
	expect_mask(codes, 5, "VUA=");
}

static void mask_of_a_full_window(void)
{
	char want[KEEPALIVE_MASK_B64_MAX];
	__u8 codes[KEEPALIVE_MASK_OPS + 1];
	char b64[KEEPALIVE_MASK_B64_MAX];

	memset(codes, APPLIED, sizeof(codes));
	memset(want, 'V', sizeof(want) - 1);
	memcpy(want + sizeof(want) - 5, "VVU=", 5);

	EXPECT_EQ(sizeof(want), 173);
	expect_mask(codes, KEEPALIVE_MASK_OPS, want);
	EXPECT_EQ(keepalive_mask(codes, KEEPALIVE_MASK_OPS + 1, b64,
				 sizeof(b64)), -EINVAL);
}

static void mask_refuses_a_code_past_two_bits(void)
{
	static const __u8 codes[] = { APPLIED, 4 };
	char b64[KEEPALIVE_MASK_B64_MAX];

	EXPECT_EQ(keepalive_mask(codes, ARRAY_SIZE(codes), b64, sizeof(b64)),
		  -EINVAL);
}

static void mask_refuses_a_buffer_too_small(void)
{
	static const __u8 codes[] = {
		APPLIED, APPLIED, APPLIED, APPLIED, APPLIED,
	};
	char b64[5];

	EXPECT_EQ(keepalive_mask(codes, 0, b64, 0), -E2BIG);
	EXPECT_EQ(keepalive_mask(codes, 0, b64, 1), 0);
	EXPECT_STREQ(b64, "");
	EXPECT_EQ(keepalive_mask(codes, 1, b64, 4), -E2BIG);
	EXPECT_EQ(keepalive_mask(codes, 5, b64, 4), -E2BIG);
	EXPECT_EQ(keepalive_mask(codes, 5, b64, sizeof(b64)), 0);
	EXPECT_STREQ(b64, "VUA=");
}

static void cond_of_all_ok(void)
{
	static const struct condition conds[] = {
		{ .type = "LsmAttached", .status = "OK" },
		{ .type = "KeyringSealed", .status = "OK" },
		{ .type = "ChainIntact", .status = "OK" },
		{ .type = "UpatchesMeasured", .status = "OK" },
		{ .type = "TpmMeasured", .status = "OK" },
		{ .type = "ConfigActive", .status = "OK" },
		{ .type = "XdpCovered", .status = "OK" },
	};
	static const struct condition reordered[] = {
		{ .type = "XdpCovered", .status = "OK" },
		{ .type = "ChainIntact", .status = "OK" },
		{ .type = "ConfigActive", .status = "OK" },
		{ .type = "LsmAttached", .status = "OK" },
		{ .type = "TpmMeasured", .status = "OK" },
		{ .type = "KeyringSealed", .status = "OK" },
		{ .type = "UpatchesMeasured", .status = "OK" },
	};

	EXPECT_EQ(keepalive_cond(conds, ARRAY_SIZE(conds)), 5461);
	EXPECT_EQ(keepalive_cond(reordered, ARRAY_SIZE(reordered)), 5461);
}

static void cond_of_a_config_warning(void)
{
	static const struct condition conds[] = {
		{ .type = "LsmAttached", .status = "OK" },
		{ .type = "KeyringSealed", .status = "OK" },
		{ .type = "ChainIntact", .status = "OK" },
		{ .type = "UpatchesMeasured", .status = "OK" },
		{ .type = "TpmMeasured", .status = "OK" },
		{ .type = "ConfigActive", .status = "WARN" },
		{ .type = "XdpCovered", .status = "OK" },
	};
	static const struct condition reordered[] = {
		{ .type = "ConfigActive", .status = "WARN" },
		{ .type = "XdpCovered", .status = "OK" },
		{ .type = "TpmMeasured", .status = "OK" },
		{ .type = "UpatchesMeasured", .status = "OK" },
		{ .type = "ChainIntact", .status = "OK" },
		{ .type = "KeyringSealed", .status = "OK" },
		{ .type = "LsmAttached", .status = "OK" },
	};

	EXPECT_EQ(keepalive_cond(conds, ARRAY_SIZE(conds)), 6485);
	EXPECT_EQ(keepalive_cond(reordered, ARRAY_SIZE(reordered)), 6485);
}

static void cond_leaves_a_missing_condition_at_zero(void)
{
	static const struct condition conds[] = {
		{ .type = "LsmAttached", .status = "OK" },
		{ .type = "KeyringSealed", .status = "OK" },
		{ .type = "UpatchesMeasured", .status = "OK" },
		{ .type = "TpmMeasured", .status = "OK" },
		{ .type = "ConfigActive", .status = "OK" },
		{ .type = "XdpCovered", .status = "OK" },
	};

	EXPECT_EQ(keepalive_cond(conds, ARRAY_SIZE(conds)), 5461 & ~(3 << 4));
	EXPECT_EQ(keepalive_cond(conds, 0), 0);
}

static void cond_places_each_status_by_name(void)
{
	static const struct condition conds[] = {
		{ .type = "XdpCovered", .status = "ALERT" },
		{ .type = "Unknown", .status = "ALERT" },
		{ .type = "LsmAttached", .status = "ALERT" },
		{ .type = "KeyringSealed", .status = "WARN" },
	};

	EXPECT_EQ(keepalive_cond(conds, ARRAY_SIZE(conds)),
		  (3 << 12) | (2 << 2) | 3);
}

static void cond_follows_the_order_conditions_returns(void)
{
	struct conditions_input in = {
		.reachable = true,
		.parsed = true,
		.lsm_attached = 1,
	};
	struct condition conds[CONDITIONS_MAX];
	size_t n = conditions(&in, conds, CONDITIONS_MAX), i;
	__u16 cond = keepalive_cond(conds, n);

	ASSERT_EQ(n, CONDITIONS_MAX);
	for (i = 0; i < n; i++)
		EXPECT_NE((cond >> (2 * i)) & 3, 0);
	EXPECT_EQ(cond & 3, 1);
}

static const struct unit_case cases[] = {
	UNIT_CASE(mask_of_one_operation),
	UNIT_CASE(mask_of_the_release_example),
	UNIT_CASE(mask_of_sixteen_operations),
	UNIT_CASE(mask_of_no_operation_is_empty),
	UNIT_CASE(mask_fills_a_byte_then_pads_the_next),
	UNIT_CASE(mask_of_a_full_window),
	UNIT_CASE(mask_refuses_a_code_past_two_bits),
	UNIT_CASE(mask_refuses_a_buffer_too_small),
	UNIT_CASE(cond_of_all_ok),
	UNIT_CASE(cond_of_a_config_warning),
	UNIT_CASE(cond_leaves_a_missing_condition_at_zero),
	UNIT_CASE(cond_places_each_status_by_name),
	UNIT_CASE(cond_follows_the_order_conditions_returns),
	{}
};

UNIT_SUITE(keepalive, cases);
