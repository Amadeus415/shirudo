/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Host system overview gathered from /proc, /etc and uname(2) -- no
 * subprocess. Surfaced by `shirudo status --include-system` and
 * rendered by `shirudo status`.
 */

#ifndef SHIRUDO_SYSINFO_H
#define SHIRUDO_SYSINFO_H

struct shirudo_sysinfo {
	char	hostname[256];
	char	os_pretty[256];		/* /etc/os-release PRETTY_NAME */
	char	kernel_release[96];	/* uname -r */
	char	kernel_version[256];	/* uname -v */
	char	machine[96];		/* uname -m */
	char	machine_id[64];		/* /etc/machine-id */
	char	boot_id[64];		/* /proc boot_id */
	long	nproc;			/* online CPUs, -1 if unknown */
	long	mem_total_kb;		/* total RAM in KiB, -1 if unknown */
	long	mem_avail_kb;		/* MemAvailable in KiB, -1 if unknown */
	long	uptime_sec;		/* seconds since boot, -1 if unknown */
	/*
	 * Root-filesystem capacity, statvfs("/"). "Used" is total minus the
	 * non-reserved free space (matches `df` row's Used column). -1 when
	 * the statvfs call failed.
	 */
	long	disk_total_kb;
	long	disk_used_kb;
};

/* Fill *si; missing values become "" (strings) or -1 (numbers). */
void shirudo_sysinfo_gather(struct shirudo_sysinfo *si);

struct shirudo_json_emit;

/*
 * Emit *si as a JSON "system":{...} object. The single source of truth
 * for the `shirudo status --include-system` JSON shape.
 */
void shirudo_sysinfo_emit_json(struct shirudo_json_emit *e,
			       const struct shirudo_sysinfo *si);

#endif /* SHIRUDO_SYSINFO_H */
