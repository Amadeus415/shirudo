// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Host system overview from /proc, /etc and uname(2). No subprocess.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "json.h"
#include "sysinfo.h"

/* Read the first line of a file into buf, trimming the trailing newline. */
static void read_first_line(const char *path, char *buf, size_t cap)
{
	ssize_t n;
	int fd;

	buf[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n <= 0) {
		buf[0] = '\0';
		return;
	}
	buf[n] = '\0';
	buf[strcspn(buf, "\r\n")] = '\0';
}

/*
 * Pull PRETTY_NAME from /etc/os-release into buf, stripping the
 * surrounding double quotes os-release uses for the human label.
 */
static void read_os_pretty(char *buf, size_t cap)
{
	char line[512];
	FILE *f;

	buf[0] = '\0';
	f = fopen("/etc/os-release", "re");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		const char *v;
		size_t len;

		if (strncmp(line, "PRETTY_NAME=", 12) != 0)
			continue;
		v = line + 12;
		if (*v == '"')
			v++;
		snprintf(buf, cap, "%.*s", (int)(cap - 1), v);
		len = strlen(buf);
		while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
			       buf[len - 1] == '"'))
			buf[--len] = '\0';
		break;
	}
	fclose(f);
}

/* Seconds since boot from /proc/uptime's first (float) field, or -1. */
static long read_uptime_sec(void)
{
	char buf[64];
	int fd;
	ssize_t n;

	fd = open("/proc/uptime", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	return (long)strtod(buf, NULL);
}

/* MemTotal in KiB from /proc/meminfo, or -1. */
static long read_mem_total_kb(void)
{
	char line[256];
	long kb = -1;
	FILE *f;

	f = fopen("/proc/meminfo", "re");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "MemTotal: %ld kB", &kb) == 1)
			break;
	}
	fclose(f);
	return kb;
}

void shirudo_sysinfo_gather(struct shirudo_sysinfo *si)
{
	struct utsname u;

	*si = (struct shirudo_sysinfo){};
	si->nproc = -1;
	si->mem_total_kb = -1;
	si->uptime_sec = -1;

	if (gethostname(si->hostname, sizeof(si->hostname)) != 0)
		si->hostname[0] = '\0';
	si->hostname[sizeof(si->hostname) - 1] = '\0';

	if (uname(&u) == 0) {
		snprintf(si->kernel_release, sizeof(si->kernel_release),
			 "%s", u.release);
		snprintf(si->kernel_version, sizeof(si->kernel_version),
			 "%s", u.version);
		snprintf(si->machine, sizeof(si->machine), "%s", u.machine);
		if (si->hostname[0] == '\0')
			snprintf(si->hostname, sizeof(si->hostname), "%s",
				 u.nodename);
	}

	read_os_pretty(si->os_pretty, sizeof(si->os_pretty));
	read_first_line("/etc/machine-id", si->machine_id,
			sizeof(si->machine_id));
	read_first_line("/proc/sys/kernel/random/boot_id", si->boot_id,
			sizeof(si->boot_id));

	si->nproc = sysconf(_SC_NPROCESSORS_ONLN);
	si->mem_total_kb = read_mem_total_kb();
	si->uptime_sec = read_uptime_sec();
}

void shirudo_sysinfo_emit_json(struct shirudo_json_emit *e,
			       const struct shirudo_sysinfo *si)
{
	shirudo_json_obj_open_key(e, "system");
	shirudo_json_kv_string(e, "hostname", si->hostname);
	shirudo_json_kv_string(e, "os", si->os_pretty);
	shirudo_json_kv_string(e, "kernel_release", si->kernel_release);
	shirudo_json_kv_string(e, "kernel_version", si->kernel_version);
	shirudo_json_kv_string(e, "architecture", si->machine);
	shirudo_json_kv_string(e, "machine_id", si->machine_id);
	shirudo_json_kv_string(e, "boot_id", si->boot_id);
	shirudo_json_kv_int(e, "nproc", si->nproc);
	shirudo_json_kv_int(e, "mem_total_kb", si->mem_total_kb);
	shirudo_json_kv_int(e, "uptime_seconds", si->uptime_sec);
	shirudo_json_obj_close(e);
}
