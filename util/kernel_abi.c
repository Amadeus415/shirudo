// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The generated signed loader reads Shirudo-private fields at the beginning
 * of struct bpf_map.  Stock kernels can expose BPF and the BPF LSM while still
 * lacking this contract, so reject those kernels before BPF_PROG_LOAD.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "kernel_abi.h"

#define SHIRUDO_MAP_SHA_SIZE	32U
#define SHIRUDO_MAP_EXCL_OFFSET	32U
#define SHIRUDO_BTF_MAX_UNWRAP	32

static int abi_fail(char *detail, size_t detail_sz, const char *fmt, ...)
{
	va_list ap;

	if (detail && detail_sz) {
		va_start(ap, fmt);
		vsnprintf(detail, detail_sz, fmt, ap);
		va_end(ap);
	}
	return -EOPNOTSUPP;
}

static const struct btf_type *unwrap_type(const struct btf *btf, uint32_t id)
{
	const struct btf_type *t;
	int i;

	for (i = 0; i < SHIRUDO_BTF_MAX_UNWRAP; i++) {
		t = btf__type_by_id(btf, id);
		if (!t)
			return NULL;
		if (!btf_is_typedef(t) && !btf_is_mod(t))
			return t;
		id = t->type;
	}
	return NULL;
}

static const struct btf_member *find_member(const struct btf *btf,
					     const struct btf_type *t,
					     const char *name,
					     uint32_t *index)
{
	const struct btf_member *members = btf_members(t);
	uint32_t i;

	for (i = 0; i < btf_vlen(t); i++) {
		const char *member_name =
			btf__name_by_offset(btf, members[i].name_off);

		if (member_name && strcmp(member_name, name) == 0) {
			*index = i;
			return &members[i];
		}
	}
	return NULL;
}

static bool is_unsigned_int(const struct btf_type *t, uint32_t bytes)
{
	return t && btf_is_int(t) && t->size == bytes &&
	       btf_int_offset(t) == 0 && btf_int_bits(t) == bytes * 8 &&
	       !(btf_int_encoding(t) & BTF_INT_SIGNED);
}

int shirudo_kernel_abi_validate_btf(const struct btf *btf,
				    char *detail, size_t detail_sz)
{
	const struct btf_member *sha, *excl;
	const struct btf_type *map, *sha_type, *elem_type, *excl_type;
	const struct btf_array *array;
	uint32_t sha_idx, excl_idx;
	int map_id;

	if (detail && detail_sz)
		detail[0] = '\0';
	if (!btf)
		return abi_fail(detail, detail_sz,
				"kernel BTF is unavailable; boot a Shirudo-patched kernel");

	map_id = btf__find_by_name_kind(btf, "bpf_map", BTF_KIND_STRUCT);
	if (map_id < 0)
		return abi_fail(detail, detail_sz,
				"kernel BTF has no struct bpf_map; boot a Shirudo-patched kernel");
	map = btf__type_by_id(btf, (uint32_t)map_id);
	if (!map)
		return abi_fail(detail, detail_sz,
				"kernel BTF cannot resolve struct bpf_map");

	sha = find_member(btf, map, "sha", &sha_idx);
	if (!sha)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.sha is missing; boot a Shirudo-patched kernel");
	if (btf_member_bitfield_size(map, sha_idx) != 0 ||
	    btf_member_bit_offset(map, sha_idx) != 0)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.sha must be a non-bitfield at byte offset 0");
	sha_type = unwrap_type(btf, sha->type);
	if (!sha_type || !btf_is_array(sha_type))
		return abi_fail(detail, detail_sz,
				"struct bpf_map.sha must have type u8[32]");
	array = btf_array(sha_type);
	elem_type = unwrap_type(btf, array->type);
	if (array->nelems != SHIRUDO_MAP_SHA_SIZE ||
	    !is_unsigned_int(elem_type, 1))
		return abi_fail(detail, detail_sz,
				"struct bpf_map.sha must have type u8[32]");

	excl = find_member(btf, map, "excl", &excl_idx);
	if (!excl)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.excl is missing; boot a Shirudo-patched kernel");
	if (btf_member_bitfield_size(map, excl_idx) != 0 ||
	    btf_member_bit_offset(map, excl_idx) != SHIRUDO_MAP_EXCL_OFFSET * 8)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.excl must be a non-bitfield at byte offset 32");
	excl_type = unwrap_type(btf, excl->type);
	if (!is_unsigned_int(excl_type, 4))
		return abi_fail(detail, detail_sz,
				"struct bpf_map.excl must have type u32");

	return 0;
}

int shirudo_kernel_abi_check(char *detail, size_t detail_sz)
{
	struct btf *btf;
	long err;
	int rc;

	if (detail && detail_sz)
		detail[0] = '\0';
	btf = btf__load_vmlinux_btf();
	err = libbpf_get_error(btf);
	if (err)
		return abi_fail(detail, detail_sz,
				"cannot read target kernel BTF: %s; boot a Shirudo-patched kernel",
				strerror((int)-err));

	rc = shirudo_kernel_abi_validate_btf(btf, detail, detail_sz);
	btf__free(btf);
	return rc;
}
