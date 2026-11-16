/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The host overview of `status --include-system` and the identity of the
 * booted image, without a subprocess.
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

#define SYSINFO_IMAGE_VALUE_MAX	256u
#define SYSINFO_IMAGE_ROOT_MAX	65u

/*
 * IMAGE_ID and IMAGE_VERSION of os-release, and the dm-verity root hash
 * the kernel command line names: roothash=, else usrhash=.
 */
struct sysinfo_image {
	char	id[SYSINFO_IMAGE_VALUE_MAX];
	char	version[SYSINFO_IMAGE_VALUE_MAX];
	char	root[SYSINFO_IMAGE_ROOT_MAX];
};

/*
 * Fill *img; a value that is absent or refused becomes "". An os-release
 * value is unquoted as os-release(5) defines and must then be 1 to 255
 * bytes of printable ASCII; of a key given twice the last one counts.
 * os_release_fallback is read only when os_release does not exist. The
 * root is 64 hex digits, in lowercase whatever the command line has.
 */
void sysinfo_image_read_at(const char *os_release,
			   const char *os_release_fallback,
			   const char *cmdline, struct sysinfo_image *img);

/* The same from /etc/os-release, /usr/lib/os-release and /proc/cmdline. */
void sysinfo_image_read(struct sysinfo_image *img);

#endif /* SHIRUDO_SYSINFO_H */
