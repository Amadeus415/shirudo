// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The signed loader requires map hashing, exclusive-map binding, and signed
 * program metadata.  Stock kernels can expose BPF and the BPF LSM while still
 * lacking this contract, so reject those kernels before BPF_PROG_LOAD.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "kernel_abi.h"

#define SHIRUDO_MAP_SHA_SIZE	32U
#define SHIRUDO_BTF_MAX_UNWRAP	32

static int abi_fail(char *detail, size_t detail_sz, const char *fmt, ...)
{
	va_list ap;

	if (detail && detail_sz) {
		va_start(ap, fmt);
		if (vstrsprintf(detail, detail_sz, fmt, ap) < 0)
			strscpy(detail, "?", detail_sz);
		va_end(ap);
	}
	return -EOPNOTSUPP;
}

static const struct btf_type *unwrap_type(const struct btf *btf, __u32 id)
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
					    __u32 *index)
{
	const struct btf_member *members = btf_members(t);
	__u32 i;

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

static bool is_unsigned_int(const struct btf_type *t, __u32 bytes)
{
	return t && btf_is_int(t) && t->size == bytes &&
	       btf_int_offset(t) == 0 && btf_int_bits(t) == bytes * 8 &&
	       !(btf_int_encoding(t) & BTF_INT_SIGNED);
}

static bool is_signed_int(const struct btf_type *t, __u32 bytes)
{
	return t && btf_is_int(t) && t->size == bytes &&
	       btf_int_offset(t) == 0 && btf_int_bits(t) == bytes * 8 &&
	       (btf_int_encoding(t) & BTF_INT_SIGNED);
}

static bool is_byte_int(const struct btf_type *t)
{
	return t && btf_is_int(t) && t->size == 1 &&
	       btf_int_offset(t) == 0 && btf_int_bits(t) == 8;
}

int kernel_abi_validate_btf(const struct btf *btf,
			    char *detail, size_t detail_sz)
{
	const struct btf_member *sha, *excl_prog_sha, *sig;
	const struct btf_member *keyring_serial, *keyring_type, *verdict;
	const struct btf_type *map, *aux, *sha_type, *elem_type;
	const struct btf_type *excl_type, *sig_type, *member_type;
	const struct btf_array *array;
	__u32 member_idx;
	int map_id, aux_id;

	if (detail && detail_sz)
		detail[0] = '\0';
	if (!btf)
		return abi_fail(detail, detail_sz,
				"kernel BTF is unavailable; boot a kernel built with CONFIG_DEBUG_INFO_BTF=y");

	map_id = btf__find_by_name_kind(btf, "bpf_map", BTF_KIND_STRUCT);
	if (map_id < 0)
		return abi_fail(detail, detail_sz,
				"kernel BTF has no struct bpf_map; boot a bpf-next kernel with the signed BPF loader ABI");
	map = btf__type_by_id(btf, (__u32)map_id);
	if (!map)
		return abi_fail(detail, detail_sz,
				"kernel BTF cannot resolve struct bpf_map");

	sha = find_member(btf, map, "sha", &member_idx);
	if (!sha)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.sha is missing; boot a bpf-next kernel with the signed BPF loader ABI");
	if (btf_member_bitfield_size(map, member_idx) != 0)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.sha must not be a bitfield");
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

	excl_prog_sha = find_member(btf, map, "excl_prog_sha", &member_idx);
	if (!excl_prog_sha)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.excl_prog_sha is missing; boot a bpf-next kernel with the signed BPF loader ABI");
	if (btf_member_bitfield_size(map, member_idx) != 0)
		return abi_fail(detail, detail_sz,
				"struct bpf_map.excl_prog_sha must not be a bitfield");
	excl_type = unwrap_type(btf, excl_prog_sha->type);
	if (!excl_type || !btf_is_ptr(excl_type))
		return abi_fail(detail, detail_sz,
				"struct bpf_map.excl_prog_sha must have pointer type");
	elem_type = unwrap_type(btf, excl_type->type);
	if (!is_byte_int(elem_type))
		return abi_fail(detail, detail_sz,
				"struct bpf_map.excl_prog_sha must point to a byte");

	aux_id = btf__find_by_name_kind(btf, "bpf_prog_aux", BTF_KIND_STRUCT);
	if (aux_id < 0)
		return abi_fail(detail, detail_sz,
				"kernel BTF has no struct bpf_prog_aux; boot a bpf-next kernel with the signed BPF loader ABI");
	aux = btf__type_by_id(btf, (__u32)aux_id);
	if (!aux)
		return abi_fail(detail, detail_sz,
				"kernel BTF cannot resolve struct bpf_prog_aux");

	sig = find_member(btf, aux, "sig", &member_idx);
	if (!sig)
		return abi_fail(detail, detail_sz,
				"struct bpf_prog_aux.sig is missing; boot a bpf-next kernel with the signed BPF loader ABI");
	sig_type = unwrap_type(btf, sig->type);
	if (!sig_type || !btf_is_struct(sig_type))
		return abi_fail(detail, detail_sz,
				"struct bpf_prog_aux.sig must have struct type");

	keyring_serial = find_member(btf, sig_type, "keyring_serial", &member_idx);
	member_type = keyring_serial ? unwrap_type(btf, keyring_serial->type) : NULL;
	if (!keyring_serial || !is_signed_int(member_type, 4))
		return abi_fail(detail, detail_sz,
				"struct bpf_prog_aux.sig.keyring_serial must have type s32");
	keyring_type = find_member(btf, sig_type, "keyring_type", &member_idx);
	member_type = keyring_type ? unwrap_type(btf, keyring_type->type) : NULL;
	if (!keyring_type || !is_unsigned_int(member_type, 1))
		return abi_fail(detail, detail_sz,
				"struct bpf_prog_aux.sig.keyring_type must have type u8");
	verdict = find_member(btf, sig_type, "verdict", &member_idx);
	member_type = verdict ? unwrap_type(btf, verdict->type) : NULL;
	if (!verdict || !is_unsigned_int(member_type, 1))
		return abi_fail(detail, detail_sz,
				"struct bpf_prog_aux.sig.verdict must have type u8");

	return 0;
}

int kernel_abi_check(char *detail, size_t detail_sz)
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
				"cannot read the kernel BTF at /sys/kernel/btf/vmlinux: %s; boot a kernel built with CONFIG_DEBUG_INFO_BTF=y",
				strerror((int)-err));

	rc = kernel_abi_validate_btf(btf, detail, detail_sz);
	btf__free(btf);
	return rc;
}
