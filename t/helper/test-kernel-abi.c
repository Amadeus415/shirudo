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
	SHA_OFFSET,
	SHA_LENGTH,
	SHA_WIDTH,
	SHA_SIGNED,
	NO_EXCL,
	EXCL_OFFSET,
	EXCL_WIDTH,
	EXCL_SIGNED,
	TRAILING_DRIFT,
};

static struct btf *make_fixture(enum fixture fixture)
{
	struct btf *btf;
	int raw_u8, raw_u32, u8, u16, u32, s8, s32, index;
	int sha32, sha31, sha_u16, sha_s8;
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
	if (raw_u8 < 0 || raw_u32 < 0 || u8 < 0 || u16 < 0 || u32 < 0 ||
	    s8 < 0 || s32 < 0 || index < 0 || sha32 < 0 || sha31 < 0 ||
	    sha_u16 < 0 || sha_s8 < 0)
		goto err;
	if (fixture == NO_MAP)
		return btf;

	rc = btf__add_struct(btf, "bpf_map", 48);
	if (rc < 0)
		goto err;
	if (fixture != NO_SHA) {
		int sha_type = sha32;
		uint32_t sha_off = fixture == SHA_OFFSET ? 8 : 0;

		if (fixture == SHA_LENGTH)
			sha_type = sha31;
		else if (fixture == SHA_WIDTH)
			sha_type = sha_u16;
		else if (fixture == SHA_SIGNED)
			sha_type = sha_s8;
		if (btf__add_field(btf, "sha", sha_type, sha_off, 0) < 0)
			goto err;
	}
	if (fixture != NO_EXCL) {
		int excl_type = u32;
		uint32_t excl_off = fixture == EXCL_OFFSET ? 264 : 256;

		if (fixture == EXCL_WIDTH)
			excl_type = u8;
		else if (fixture == EXCL_SIGNED)
			excl_type = s32;
		if (btf__add_field(btf, "excl", excl_type, excl_off, 0) < 0)
			goto err;
	}
	if (fixture == TRAILING_DRIFT &&
	    btf__add_field(btf, "future_field", u32, 320, 0) < 0)
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
	failed += check(SHA_OFFSET, 0, "byte offset 0");
	failed += check(SHA_LENGTH, 0, "u8[32]");
	failed += check(SHA_WIDTH, 0, "u8[32]");
	failed += check(SHA_SIGNED, 0, "u8[32]");
	failed += check(NO_EXCL, 0, "bpf_map.excl is missing");
	failed += check(EXCL_OFFSET, 0, "byte offset 32");
	failed += check(EXCL_WIDTH, 0, "type u32");
	failed += check(EXCL_SIGNED, 0, "type u32");
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
