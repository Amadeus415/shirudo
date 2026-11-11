/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Live-kernel capability checks required by shirudo's signed BPF loader,
 * which rust/src/util/kernel_abi.rs implements.
 */

#ifndef SHIRUDO_KERNEL_ABI_H
#define SHIRUDO_KERNEL_ABI_H

#include <stddef.h>

struct btf;

#define KERNEL_ABI_DETAIL_MAX 256

/*
 * Validate an already-parsed vmlinux BTF object.  Exposed separately so the
 * structural contract can be tested with synthetic BTF without depending on
 * the kernel running the test.
 */
int kernel_abi_validate_btf(const struct btf *btf,
			    char *detail, size_t detail_sz);

int kernel_abi_check(char *detail, size_t detail_sz);

#endif /* SHIRUDO_KERNEL_ABI_H */
