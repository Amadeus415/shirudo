// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "kernel_abi.h"
#include "kernel_btf.h"
#include "unit.h"

enum fixture {
	VALID,
	NO_MAP,
	NO_SHA,
	SHA_LENGTH,
	SHA_WIDTH,
	SHA_SIGNED,
	NO_EXCL_PROG_SHA,
	EXCL_PROG_SHA_TYPE,
	EXCL_PROG_SHA_TARGET,
	NO_PROG_AUX,
	NO_SIG,
	SIG_TYPE,
	NO_KEYRING_SERIAL,
	KEYRING_SERIAL_WIDTH,
	NO_KEYRING_TYPE,
	KEYRING_TYPE_WIDTH,
	NO_VERDICT,
	VERDICT_SIGNED,
	TRAILING_DRIFT,
};

static struct btf *make_fixture(enum fixture fixture)
{
	struct btf *btf;
	int raw_u8, raw_u32, u8, u16, u32, s8, s32, index;
	int sha32, sha31, sha_u16, sha_s8, byte_ptr, u32_ptr;
	int sig_struct = -1;
	int ret;

	btf = btf__new_empty();
	if (libbpf_get_error(btf))
		return NULL;
	raw_u8 = btf__add_int(btf, "unsigned char", 1, BTF_INT_CHAR);
	u16 = btf__add_int(btf, "u16", 2, 0);
	raw_u32 = btf__add_int(btf, "unsigned int", 4, 0);
	s8 = btf__add_int(btf, "s8", 1, BTF_INT_SIGNED);
	s32 = btf__add_int(btf, "s32", 4, BTF_INT_SIGNED);
	index = btf__add_int(btf, "index", 4, 0);
	u8 = btf__add_typedef(btf, "u8", raw_u8);
	u32 = btf__add_typedef(btf, "u32", raw_u32);
	sha32 = btf__add_array(btf, index, u8, 32);
	sha31 = btf__add_array(btf, index, u8, 31);
	sha_u16 = btf__add_array(btf, index, u16, 32);
	sha_s8 = btf__add_array(btf, index, s8, 32);
	byte_ptr = btf__add_ptr(btf, raw_u8);
	u32_ptr = btf__add_ptr(btf, u32);
	if (raw_u8 < 0 || raw_u32 < 0 || u8 < 0 || u16 < 0 || u32 < 0 ||
	    s8 < 0 || s32 < 0 || index < 0 || sha32 < 0 || sha31 < 0 ||
	    sha_u16 < 0 || sha_s8 < 0 || byte_ptr < 0 || u32_ptr < 0)
		goto err;

	if (fixture != NO_MAP) {
		ret = btf__add_struct(btf, "bpf_map", 64);
		if (ret < 0)
			goto err;
		if (fixture != NO_SHA) {
			int sha_type = sha32;

			if (fixture == SHA_LENGTH)
				sha_type = sha31;
			else if (fixture == SHA_WIDTH)
				sha_type = sha_u16;
			else if (fixture == SHA_SIGNED)
				sha_type = sha_s8;
			if (btf__add_field(btf, "sha", sha_type, 0, 0) < 0)
				goto err;
		}
		if (fixture != NO_EXCL_PROG_SHA) {
			int excl_type = byte_ptr;

			if (fixture == EXCL_PROG_SHA_TYPE)
				excl_type = u32;
			else if (fixture == EXCL_PROG_SHA_TARGET)
				excl_type = u32_ptr;
			if (btf__add_field(btf, "excl_prog_sha", excl_type,
					   256, 0) < 0)
				goto err;
		}
		if (fixture == TRAILING_DRIFT &&
		    btf__add_field(btf, "future_map_field", u32, 320, 0) < 0)
			goto err;
	}

	if (fixture == NO_PROG_AUX)
		return btf;
	if (fixture != SIG_TYPE) {
		sig_struct = btf__add_struct(btf, NULL, 8);
		if (sig_struct < 0)
			goto err;
		if (fixture != NO_KEYRING_SERIAL &&
		    btf__add_field(btf, "keyring_serial",
				   fixture == KEYRING_SERIAL_WIDTH ? s8 : s32,
				   0, 0) < 0)
			goto err;
		if (fixture != NO_KEYRING_TYPE &&
		    btf__add_field(btf, "keyring_type",
				   fixture == KEYRING_TYPE_WIDTH ? u32 : u8,
				   32, 0) < 0)
			goto err;
		if (fixture != NO_VERDICT &&
		    btf__add_field(btf, "verdict",
				   fixture == VERDICT_SIGNED ? s8 : u8,
				   40, 0) < 0)
			goto err;
	}
	ret = btf__add_struct(btf, "bpf_prog_aux", 32);
	if (ret < 0)
		goto err;
	if (fixture != NO_SIG &&
	    btf__add_field(btf, "sig",
			   fixture == SIG_TYPE ? u32 : sig_struct,
			   0, 0) < 0)
		goto err;
	if (fixture == TRAILING_DRIFT &&
	    btf__add_field(btf, "future_aux_field", u32, 64, 0) < 0)
		goto err;
	return btf;

err:
	btf__free(btf);
	return NULL;
}

static void check(enum fixture fixture, int want_ok, const char *want)
{
	char detail[KERNEL_ABI_DETAIL_MAX] = {};
	struct btf *btf = make_fixture(fixture);
	struct shirudo_btf *parsed;
	const void *raw;
	__u32 size;
	int ret;

	ASSERT_TRUE(btf);
	/* The check reads BTF as shirudo parses it: the fixture's bytes. */
	raw = btf__raw_data(btf, &size);
	parsed = raw ? shirudo_btf_new(raw, size) : NULL;
	btf__free(btf);
	ASSERT_TRUE(parsed);
	ret = kernel_abi_validate_btf(parsed, detail, sizeof(detail));
	shirudo_btf_free(parsed);
	if (want_ok) {
		EXPECT_EQ(ret, 0);
		return;
	}
	EXPECT_NE(ret, 0);
	UNIT_CHECK(0, strstr(detail, want), "detail \"%s\" lacks \"%s\"",
		   detail, want);
}

static void accepts_the_required_prefix(void)
{
	check(VALID, 1, NULL);
}

static void accepts_fields_past_the_prefix(void)
{
	check(TRAILING_DRIFT, 1, NULL);
}

static void needs_struct_bpf_map(void)
{
	check(NO_MAP, 0, "no struct bpf_map");
}

static void needs_map_sha(void)
{
	check(NO_SHA, 0, "bpf_map.sha is missing");
}

static void needs_map_sha_of_32_bytes(void)
{
	check(SHA_LENGTH, 0, "u8[32]");
}

static void needs_map_sha_of_bytes(void)
{
	check(SHA_WIDTH, 0, "u8[32]");
}

static void needs_map_sha_unsigned(void)
{
	check(SHA_SIGNED, 0, "u8[32]");
}

static void needs_excl_prog_sha(void)
{
	check(NO_EXCL_PROG_SHA, 0, "bpf_map.excl_prog_sha is missing");
}

static void needs_excl_prog_sha_pointer(void)
{
	check(EXCL_PROG_SHA_TYPE, 0, "must have pointer type");
}

static void needs_excl_prog_sha_byte_pointer(void)
{
	check(EXCL_PROG_SHA_TARGET, 0, "must point to a byte");
}

static void needs_struct_bpf_prog_aux(void)
{
	check(NO_PROG_AUX, 0, "no struct bpf_prog_aux");
}

static void needs_prog_aux_sig(void)
{
	check(NO_SIG, 0, "bpf_prog_aux.sig is missing");
}

static void needs_sig_struct(void)
{
	check(SIG_TYPE, 0, "sig must have struct type");
}

static void needs_keyring_serial(void)
{
	check(NO_KEYRING_SERIAL, 0, "keyring_serial must have type s32");
}

static void needs_keyring_serial_s32(void)
{
	check(KEYRING_SERIAL_WIDTH, 0, "keyring_serial must have type s32");
}

static void needs_keyring_type(void)
{
	check(NO_KEYRING_TYPE, 0, "keyring_type must have type u8");
}

static void needs_keyring_type_u8(void)
{
	check(KEYRING_TYPE_WIDTH, 0, "keyring_type must have type u8");
}

static void needs_verdict(void)
{
	check(NO_VERDICT, 0, "verdict must have type u8");
}

static void needs_verdict_unsigned(void)
{
	check(VERDICT_SIGNED, 0, "verdict must have type u8");
}

static const struct unit_case cases[] = {
	UNIT_CASE(accepts_the_required_prefix),
	UNIT_CASE(accepts_fields_past_the_prefix),
	UNIT_CASE(needs_struct_bpf_map),
	UNIT_CASE(needs_map_sha),
	UNIT_CASE(needs_map_sha_of_32_bytes),
	UNIT_CASE(needs_map_sha_of_bytes),
	UNIT_CASE(needs_map_sha_unsigned),
	UNIT_CASE(needs_excl_prog_sha),
	UNIT_CASE(needs_excl_prog_sha_pointer),
	UNIT_CASE(needs_excl_prog_sha_byte_pointer),
	UNIT_CASE(needs_struct_bpf_prog_aux),
	UNIT_CASE(needs_prog_aux_sig),
	UNIT_CASE(needs_sig_struct),
	UNIT_CASE(needs_keyring_serial),
	UNIT_CASE(needs_keyring_serial_s32),
	UNIT_CASE(needs_keyring_type),
	UNIT_CASE(needs_keyring_type_u8),
	UNIT_CASE(needs_verdict),
	UNIT_CASE(needs_verdict_unsigned),
	{}
};

UNIT_SUITE(kernel_abi, cases);
