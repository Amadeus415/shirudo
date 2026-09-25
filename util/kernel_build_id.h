/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_KERNEL_BUILD_ID_H
#define SHIRUDO_KERNEL_BUILD_ID_H

#include <stddef.h>

#define SHIRUDO_KERNEL_BUILD_ID_MAX 64u
#define SHIRUDO_KERNEL_BUILD_ID_STRING_MAX \
	(SHIRUDO_KERNEL_BUILD_ID_MAX * 2u + 1u)

/* Parse raw Linux kernel note records and return the GNU build ID as hex. */
int shirudo_kernel_build_id_from_notes(const void *notes, size_t notes_len,
					       char out[SHIRUDO_KERNEL_BUILD_ID_STRING_MAX]);

/* Read the running kernel's GNU build ID from /sys/kernel/notes. */
int shirudo_kernel_build_id_read(
		char out[SHIRUDO_KERNEL_BUILD_ID_STRING_MAX]);

#endif /* SHIRUDO_KERNEL_BUILD_ID_H */
