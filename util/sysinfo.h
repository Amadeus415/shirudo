/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The host overview of `status --include-system`, without a subprocess,
 * which rust/src/util/sysinfo.rs gathers.
 */

#ifndef SHIRUDO_SYSINFO_H
#define SHIRUDO_SYSINFO_H

#include "kernel_build_id.h"

struct sysinfo {
	char	hostname[256];
	char	os_pretty[256];		/* /etc/os-release PRETTY_NAME */
	char	kernel_release[96];	/* uname -r */
	char	kernel_version[256];	/* uname -v */
	char	kernel_build_id[KERNEL_BUILD_ID_STRING_MAX];
	char	machine[96];		/* uname -m */
	char	machine_id[64];		/* /etc/machine-id */
	char	boot_id[64];		/* /proc boot_id */
	long	nproc;			/* online CPUs, -1 if unknown */
	long	mem_total_kb;		/* total RAM in KiB, -1 if unknown */
	long	mem_avail_kb;		/* MemAvailable in KiB, -1 if unknown */
	long	uptime_sec;		/* seconds since boot, -1 if unknown */
	/* Used is total minus the non-reserved free space, as df reports it. */
	long	disk_total_kb;
	long	disk_used_kb;
};

/* Fill *si; missing values become "" (strings) or -1 (numbers). */
void sysinfo_gather(struct sysinfo *si);

struct json_emit;

typedef void (*shirudo_kernel_config_cb)(void *ctx, const char *key,
					 const char *value);

int sysinfo_kernel_config_foreach(const char *kernel_release,
				  shirudo_kernel_config_cb cb,
				  void *ctx);

void sysinfo_emit_json(struct json_emit *e,
		       const struct sysinfo *si);

#endif /* SHIRUDO_SYSINFO_H */
