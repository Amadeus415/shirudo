/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The GNU build ID of a uprobe.multi target and the offsets of the
 * symbols it names, which rust/src/util/elf_target.rs implements.
 */

#ifndef SHIRUDO_ELF_TARGET_H
#define SHIRUDO_ELF_TARGET_H

#include <shirudo/misc.h>
#include <shirudo/upatch.h>

struct elf_target {
	__u8		build_id[UPATCH_BUILD_ID_MAX];
	__u32		build_id_len;
	__u64		*offsets;
	__u32		nr_offsets;
	__u32		offsets_cap;
};

int elf_target_resolve(const char *path, const char *pattern,
		       struct elf_target *out);

int elf_build_id_fd(int fd,
		    __u8 build_id[UPATCH_BUILD_ID_MAX],
		    __u32 *build_id_len);

void elf_target_free(struct elf_target *target);

#endif /* SHIRUDO_ELF_TARGET_H */
