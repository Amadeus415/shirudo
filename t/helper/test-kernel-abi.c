// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "kernel_abi.h"

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
	int rc;

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
		rc = btf__add_struct(btf, "bpf_map", 64);
		if (rc < 0)
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
	rc = btf__add_struct(btf, "bpf_prog_aux", 32);
	if (rc < 0)
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

static int check(enum fixture fixture, int want_ok, const char *want_detail)
{
	char detail[SHIRUDO_KERNEL_ABI_DETAIL_MAX];
	struct btf *btf = make_fixture(fixture);
	int rc;

	if (!btf) {
		fprintf(stderr, "cannot construct fixture %d\n", fixture);
		return 1;
	}
	rc = shirudo_kernel_abi_validate_btf(btf, detail, sizeof(detail));
	btf__free(btf);
	if ((rc == 0) != want_ok) {
		fprintf(stderr, "fixture %d: rc=%d detail=%s\n",
			fixture, rc, detail);
		return 1;
	}
	if (want_detail && !strstr(detail, want_detail)) {
		fprintf(stderr, "fixture %d: expected detail '%s', got '%s'\n",
			fixture, want_detail, detail);
		return 1;
	}
	return 0;
}

int main(void)
{
	int failed = 0;

	failed += check(VALID, 1, NULL);
	failed += check(TRAILING_DRIFT, 1, NULL);
	failed += check(NO_MAP, 0, "no struct bpf_map");
	failed += check(NO_SHA, 0, "bpf_map.sha is missing");
	failed += check(SHA_LENGTH, 0, "u8[32]");
	failed += check(SHA_WIDTH, 0, "u8[32]");
	failed += check(SHA_SIGNED, 0, "u8[32]");
	failed += check(NO_EXCL_PROG_SHA, 0,
			"bpf_map.excl_prog_sha is missing");
	failed += check(EXCL_PROG_SHA_TYPE, 0, "must have pointer type");
	failed += check(EXCL_PROG_SHA_TARGET, 0, "must point to a byte");
	failed += check(NO_PROG_AUX, 0, "no struct bpf_prog_aux");
	failed += check(NO_SIG, 0, "bpf_prog_aux.sig is missing");
	failed += check(SIG_TYPE, 0, "sig must have struct type");
	failed += check(NO_KEYRING_SERIAL, 0,
			"keyring_serial must have type s32");
	failed += check(KEYRING_SERIAL_WIDTH, 0,
			"keyring_serial must have type s32");
	failed += check(NO_KEYRING_TYPE, 0,
			"keyring_type must have type u8");
	failed += check(KEYRING_TYPE_WIDTH, 0,
			"keyring_type must have type u8");
	failed += check(NO_VERDICT, 0, "verdict must have type u8");
	failed += check(VERDICT_SIGNED, 0, "verdict must have type u8");
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
