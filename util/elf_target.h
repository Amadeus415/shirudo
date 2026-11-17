/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The GNU build ID of a uprobe.multi target, which
 * rust/src/util/elf_target.rs implements, for the fuzz target.
 */

#ifndef SHIRUDO_ELF_TARGET_H
#define SHIRUDO_ELF_TARGET_H

#include <shirudo/misc.h>
#include <shirudo/upatch.h>

int elf_build_id_fd(int fd,
		    __u8 build_id[UPATCH_BUILD_ID_MAX],
		    __u32 *build_id_len);

#endif /* SHIRUDO_ELF_TARGET_H */
