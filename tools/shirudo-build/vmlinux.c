// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * vmlinux.h locator.
 */

#include <stddef.h>
#include <unistd.h>

#include "vmlinux.h"

#ifndef SHIRUDO_VMLINUX_PATH
#define SHIRUDO_VMLINUX_PATH "/usr/local/share/shirudo/vmlinux.h"
#endif

const char *shirudo_build_locate_vmlinux(const char *override)
{
	if (override)
		return access(override, R_OK) == 0 ? override : NULL;
	if (access("./vmlinux.h", R_OK) == 0)
		return "./vmlinux.h";
	if (access("./bpf/vmlinux.h", R_OK) == 0)
		return "./bpf/vmlinux.h";
	if (access(SHIRUDO_VMLINUX_PATH, R_OK) == 0)
		return SHIRUDO_VMLINUX_PATH;
	return NULL;
}
