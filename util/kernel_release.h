/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_KERNEL_RELEASE_H
#define SHIRUDO_KERNEL_RELEASE_H

#include <stdbool.h>

/* Match a complete kernel release component prefix, such as 6.1. */
bool shirudo_kernel_release_prefix_matches(const char *release,
						   const char *prefix);

#endif /* SHIRUDO_KERNEL_RELEASE_H */
