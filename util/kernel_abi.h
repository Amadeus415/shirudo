/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Live-kernel ABI checks required by Shirudo's signed BPF loader.
 */

#ifndef SHIRUDO_KERNEL_ABI_H
#define SHIRUDO_KERNEL_ABI_H

#include <stddef.h>

struct btf;

#define SHIRUDO_KERNEL_ABI_DETAIL_MAX 256

/*
 * Validate an already-parsed vmlinux BTF object.  Exposed separately so the
 * structural contract can be tested with synthetic BTF without depending on
 * the kernel running the test.
 */
int shirudo_kernel_abi_validate_btf(const struct btf *btf,
				    char *detail, size_t detail_sz);

/* Load the running kernel's BTF and validate the signed-loader ABI. */
int shirudo_kernel_abi_check(char *detail, size_t detail_sz);

#endif /* SHIRUDO_KERNEL_ABI_H */
