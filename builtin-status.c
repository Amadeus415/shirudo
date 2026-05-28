// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Local readiness + state report: shirudo status [--json] [--include-tpm].
 * Local-only -- never contacts a remote (that is `shirudo nodes`). Safe
 * to run before `init` (everything degrades to "absent"/false).
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <limits.h>
#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <time.h>

#include "builtin.h"
#include "util/chain.h"
#include "util/conditions.h"
#include "util/eventlog.h"
#include "util/help.h"
#include "util/json.h"
#include "util/macros.h"
#include "util/keyring.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/kmodules.h"
#include "util/kmsg.h"
#include "util/format.h"
#include "util/sysinfo.h"
#include "util/timefmt.h"
#include "util/upatch_maps.h"

extern const char shirudo_version_id[];

static int notdot(const struct dirent *e)
{
	return strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0;
}

/* Count JSON-lines (one chain event per line) and the file size. */
static int count_eventlog(long *entries, long *bytes)
{
	char buf[65536];
	struct stat st;
	long lines = 0;
	ssize_t n;
	int fd;

	if (stat(SHIRUDO_EVENTLOG_PATH, &st) != 0)
		return -errno;
	*bytes = (long)st.st_size;
	fd = open(SHIRUDO_EVENTLOG_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		ssize_t i;

		for (i = 0; i < n; i++)
			if (buf[i] == '\n')
				lines++;
	}
	close(fd);
	*entries = lines;
	return 0;
}

/* On-disk inventory under /var/lib/shirudo. -1 counts mean "dir absent". */
struct asset_view {
	long eventlog_bytes;
	int n_upatches;
	int n_incoming;
	bool cert;
	bool signing_key;
	bool keyring_serial;
	bool eventlog;
	bool bpffs_mounted;
};

/* Count entries in <dir>; with upatch_only, only ".upatch" files. */
static int count_dir(const char *dir, bool upatch_only)
{
	struct dirent **list = NULL;
	int n, i, count = 0;

	n = scandir(dir, &list, notdot, alphasort);
	if (n < 0)
		return -1;	/* directory absent */
	for (i = 0; i < n; i++) {
		const char *nm = list[i]->d_name;
		size_t len = strlen(nm);

		if (!upatch_only ||
		    (len > 7 && strcmp(nm + len - 7, ".upatch") == 0))
			count++;
		shirudo_libc_free(list[i]);	/* scandir-owned */
	}
	shirudo_libc_free(list);		/* scandir-owned */
	return count;
}

static bool bpffs_is_mounted(void)
{
	char line[4096];
	bool found = false;
	FILE *f;

	f = fopen("/proc/self/mounts", "r");
	if (!f)
		return false;
	while (fgets(line, sizeof(line), f)) {
		char *mp = strchr(line, ' ');	/* field 2 = mountpoint */

		if (mp && strncmp(mp + 1, SHIRUDO_BPFFS_DIR " ",
				  strlen(SHIRUDO_BPFFS_DIR) + 1) == 0) {
			found = true;
			break;
		}
	}
	fclose(f);
	return found;
}

static void gather_assets(struct asset_view *a)
{
	struct stat st;

	*a = (struct asset_view){};
	a->cert = access(SHIRUDO_CERT_PATH, F_OK) == 0;
	a->signing_key = access(SHIRUDO_SIGNING_KEY_PATH, F_OK) == 0;
	a->keyring_serial = access(SHIRUDO_KEYRING_SERIAL_PATH, F_OK) == 0;
	if (stat(SHIRUDO_EVENTLOG_PATH, &st) == 0) {
		a->eventlog = true;
		a->eventlog_bytes = (long)st.st_size;
	}
	a->n_upatches = count_dir(SHIRUDO_UPATCHES_DIR, true);
	a->n_incoming = count_dir(SHIRUDO_INCOMING_DIR, false);
	a->bpffs_mounted = bpffs_is_mounted();
}

/*
 * Projection of one eventlog line for display: enough for the compact
 * table and the events[] JSON, not the full record (the authoritative
 * copy stays the on-disk log, replayed by --include-tpm).
 */
struct ev_proj {
	char ts[40];
	char type[24];
	char digest[65];
	char set_digest[65];
	char up_name[128];
	char up_payload[65];
};

static int parse_event_line(const char *line, size_t len, struct ev_proj *ev)
{
	struct shirudo_json_field up[] = {
		{ "name", SHIRUDO_JSON_T_STRING, ev->up_name,
		  sizeof(ev->up_name), 0, NULL, 0 },
		{ "payload_sha256", SHIRUDO_JSON_T_STRING, ev->up_payload,
		  sizeof(ev->up_payload), 0, NULL, 0 },
	};
	struct shirudo_json_field f[] = {
		{ "ts", SHIRUDO_JSON_T_STRING, ev->ts, sizeof(ev->ts),
		  0, NULL, 0 },
		{ "type", SHIRUDO_JSON_T_STRING, ev->type, sizeof(ev->type),
		  0, NULL, 0 },
		{ "digest", SHIRUDO_JSON_T_STRING, ev->digest,
		  sizeof(ev->digest), 0, NULL, 0 },
		{ "set_digest", SHIRUDO_JSON_T_STRING, ev->set_digest,
		  sizeof(ev->set_digest), 0, NULL, 0 },
		{ "upatch", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, up, 2 },
	};

	*ev = (struct ev_proj){};
	return shirudo_json_parse(line, len, f, ARRAY_SIZE(f));
}

/* Slurp the whole eventlog. 0 with buf/len set, or -errno (buf == NULL). */
static int read_eventlog(char **buf, size_t *len)
{
	struct stat st;
	ssize_t got;
	int fd, rc = 0;

	*buf = NULL;
	*len = 0;
	fd = open(SHIRUDO_EVENTLOG_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) != 0 || st.st_size > (off_t)SHIRUDO_JSON_MAX_BYTES) {
		rc = fd < 0 ? -errno : -EFBIG;
		close(fd);
		return rc;
	}
	*buf = xmalloc((size_t)st.st_size + 1);
	if (!*buf) {
		close(fd);
		return -ENOMEM;
	}
	got = read(fd, *buf, (size_t)st.st_size);
	close(fd);
	if (got != st.st_size) {
		xfree(*buf, (size_t)st.st_size + 1);
		*buf = NULL;
		return -EIO;
	}
	(*buf)[got] = '\0';
	*len = (size_t)st.st_size + 1;
	return 0;
}

/* Emit the eventlog as a JSON "events":[...] array (projected fields). */
static void emit_eventlog_events(struct shirudo_json_emit *e)
{
	char *save, *line, *buf;
	size_t len;

	shirudo_json_arr_open(e, "events");
	if (read_eventlog(&buf, &len) != 0) {
		shirudo_json_arr_close(e);
		return;
	}
	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		struct ev_proj ev;

		shirudo_json_obj_open(e);
		if (parse_event_line(line, strlen(line), &ev) != 0) {
			shirudo_json_kv_string(e, "type", "unparseable");
			shirudo_json_obj_close(e);
			continue;
		}
		shirudo_json_kv_string(e, "ts", ev.ts);
		shirudo_json_kv_string(e, "type", ev.type);
		shirudo_json_kv_string(e, "digest", ev.digest);
		if (ev.set_digest[0])
			shirudo_json_kv_string(e, "set_digest", ev.set_digest);
		if (ev.up_name[0]) {
			shirudo_json_obj_open_key(e, "upatch");
			shirudo_json_kv_string(e, "name", ev.up_name);
			shirudo_json_kv_string(e, "payload_sha256",
					       ev.up_payload);
			shirudo_json_obj_close(e);
		}
		shirudo_json_obj_close(e);
	}
	xfree(buf, len);
	shirudo_json_arr_close(e);
}

/* One-line human detail for an eventlog row. */
static void event_detail(const struct ev_proj *ev, char *out, size_t cap)
{
	if (ev->up_name[0])
		snprintf(out, cap, "%s payload=%.12s..", ev->up_name,
			 ev->up_payload);
	else if (ev->set_digest[0])
		snprintf(out, cap, "set_digest=%.12s..", ev->set_digest);
	else
		out[0] = '\0';
}

/* Compact TIME/TYPE/DIGEST/DETAIL table, read from the local log. */
static void print_eventlog_table(void)
{
	char *save, *line, *buf;
	size_t len;

	if (read_eventlog(&buf, &len) != 0)
		return;
	printf("\nEventlog (audit trail):\n");
	printf("  %-20s %-13s %-13s %s\n", "TIME", "TYPE", "DIGEST",
	       "DETAIL");
	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char detail[256];
		struct ev_proj ev;

		if (parse_event_line(line, strlen(line), &ev) != 0) {
			printf("  %-20s %-13s %-13s\n", "?", "unparseable",
			       "");
			continue;
		}
		event_detail(&ev, detail, sizeof(detail));
		printf("  %-20s %-13s %-13.12s %s\n", ev.ts, ev.type,
		       ev.digest[0] ? ev.digest : "-", detail);
	}
	xfree(buf, len);
}

/*
 * Same shape `shirudo nodes show` renders -- "System Info:" header,
 * 2-space indent, 16-col label column. Caller prints any preceding
 * blank line, this prints the section starting with the header.
 */
static void print_system_human(const struct shirudo_sysinfo *si)
{
	printf("\nSystem Info:\n");
	printf("  %-16s %s\n", "OS:", si->os_pretty);
	printf("  %-16s %s\n", "Kernel:", si->kernel_release);
	if (si->kernel_version[0])
		printf("  %-16s %s\n", "Kernel Version:", si->kernel_version);
	printf("  %-16s %s\n", "Architecture:", si->machine);
	if (si->nproc > 0)
		printf("  %-16s %ld\n", "CPUs:", si->nproc);
	if (si->mem_total_kb > 0) {
		char tot[16], used[16];

		shirudo_human_size((uint64_t)si->mem_total_kb * 1024,
				   tot, sizeof(tot));
		if (si->mem_avail_kb >= 0 &&
		    si->mem_avail_kb <= si->mem_total_kb) {
			shirudo_human_size(
				(uint64_t)(si->mem_total_kb -
					   si->mem_avail_kb) * 1024,
				used, sizeof(used));
			printf("  %-16s %s/%s\n", "Memory:", used, tot);
		} else {
			printf("  %-16s %s\n", "Memory:", tot);
		}
	}
	if (si->disk_total_kb > 0) {
		char tot[16], used[16];

		shirudo_human_size((uint64_t)si->disk_total_kb * 1024,
				   tot, sizeof(tot));
		shirudo_human_size((uint64_t)si->disk_used_kb * 1024,
				   used, sizeof(used));
		printf("  %-16s %s/%s\n", "Disk:", used, tot);
	}
	if (si->uptime_sec >= 0)
		printf("  %-16s %ldd %ldh %ldm\n", "Uptime:",
		       si->uptime_sec / 86400,
		       (si->uptime_sec % 86400) / 3600,
		       (si->uptime_sec % 3600) / 60);
	if (si->hostname[0])
		printf("  %-16s %s\n", "Hostname:", si->hostname);
	if (si->machine_id[0])
		printf("  %-16s %s\n", "Machine ID:", si->machine_id);
	if (si->boot_id[0])
		printf("  %-16s %s\n", "Boot ID:", si->boot_id);
}

static const struct shirudo_help_item status_options[] = {
	{ "--json",                 "machine-readable JSON output" },
	{ "--include-tpm",          "read the live NV chain and replay the eventlog" },
	{ "--include-system",       "add a `system` block (hostname, kernel, arch, cpus, ...)" },
	{ "--include-eventlog",     "dump eventlog entries (implies --include-tpm)" },
	{ "--include-kernel-log",   "last 10 lines of the kernel ring buffer" },
	{ "--include-modules",      "loaded kernel modules (10 most recent; --show-full for tree)" },
	{ "--include-maps",         "loaded upatches' pinned maps (BTF type-aware; cap 256 entries)" },
	{ "--show-full",            "opt into a full dump: implies every --include-* flag and "
				    "expands the loaded-modules dependency tree" },
};

static const struct shirudo_help_section status_help_sections[] = {
	{ "options:", status_options,
	  ARRAY_SIZE(status_options) },
};

static const struct shirudo_help status_help = {
	.usage      = "shirudo status [--json] [--include-tpm] "
		      "[--include-system] [--include-eventlog]\n"
		      "                       [--include-kernel-log] "
		      "[--include-modules] [--include-maps] [--show-full]",
	.summary    = "Local readiness + state report. Auto-detects target "
		      "vs operator role.\nSafe to run before `shirudo init`.",
	.sections   = status_help_sections,
	.n_sections = sizeof(status_help_sections) /
		      sizeof(status_help_sections[0]),
};

static void usage(void)
{
	fprintf(stderr, "usage: %s\n", status_help.usage);
}

/*
 * "If this upatch is loaded, when was it last loaded and what was its
 * payload digest?" map built from one pass over the on-disk eventlog.
 * Used by the Upatches loaded section so the operator sees the same
 * NAME / PAYLOAD-SHA256 / APPLIED columns `nodes show` renders.
 */
struct upatch_load_info {
	char	name[128];
	char	payload[65];
	char	ts[40];
};

static size_t scan_eventlog_loads(struct upatch_load_info *out, size_t cap)
{
	char *buf = NULL, *line, *save;
	size_t len = 0, n = 0;

	if (read_eventlog(&buf, &len) != 0)
		return 0;
	for (line = strtok_r(buf, "\n", &save); line && n <= cap;
	     line = strtok_r(NULL, "\n", &save)) {
		struct ev_proj ev;
		size_t k;

		if (parse_event_line(line, strlen(line), &ev) != 0)
			continue;
		if (strcmp(ev.type, "upatch_load") != 0)
			continue;
		for (k = 0; k < n; k++)
			if (strcmp(out[k].name, ev.up_name) == 0)
				break;
		if (k == n) {
			if (n >= cap)
				continue;
			n++;
		}
		snprintf(out[k].name, sizeof(out[k].name), "%s", ev.up_name);
		snprintf(out[k].payload, sizeof(out[k].payload), "%s",
			 ev.up_payload);
		snprintf(out[k].ts, sizeof(out[k].ts), "%s", ev.ts);
	}
	xfree(buf, len);
	return n;
}

static const struct upatch_load_info *find_load(
	const struct upatch_load_info *loads, size_t n, const char *name)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (strcmp(loads[i].name, name) == 0)
			return &loads[i];
	return NULL;
}

/*
 * Convert local probes into the shared conditions input. `shirudo
 * status` always runs on-host, so reachable/parsed are trivially
 * true; that gives the shared verdict / Conditions block the same
 * meaning here as in `shirudo nodes show`.
 */
static void local_cond_input(struct shirudo_conditions_input *in,
			     int lsm_attached, int keyring_present,
			     int64_t keyring_serial,
			     int64_t keyring_serial_pinned,
			     int ks_seen, int ksp_seen, int ksm_seen,
			     int ks_matches,
			     int chain_seen, int chain_matches, int cm_seen,
			     const char *nv_index)
{
	*in = (struct shirudo_conditions_input){
		.reachable		= true,
		.parsed			= true,
		.lsm_attached		= lsm_attached,
		.keyring_present	= keyring_present,
		.keyring_serial		= keyring_serial,
		.keyring_serial_pinned	= keyring_serial_pinned,
		.keyring_serial_matches	= ks_matches,
		.ks_seen		= ks_seen,
		.ksp_seen		= ksp_seen,
		.ksm_seen		= ksm_seen,
		.chain_seen		= chain_seen,
		.chain_matches		= chain_matches,
		.cm_seen		= cm_seen,
		.nv_index		= nv_index,
	};
}

/*
 * BPF prog_type + expected_attach_type -> SEC()-style prefix. Mirrors the
 * libbpf convention shirudo upatches actually use today: BPF_PROG_TYPE_LSM
 * is "lsm/...", BPF_PROG_TYPE_TRACING is fentry/fexit/fmod_ret/tp_btf/iter
 * keyed on expected_attach_type. NULL for anything else (we render the
 * libbpf type-string then).
 */
static const char *upatch_loc_prefix(uint32_t prog_type, uint32_t attach_type)
{
	if (prog_type == BPF_PROG_TYPE_LSM)
		return "lsm";
	if (prog_type == BPF_PROG_TYPE_TRACING) {
		switch (attach_type) {
		case BPF_TRACE_FENTRY:		return "fentry";
		case BPF_TRACE_FEXIT:		return "fexit";
		case BPF_MODIFY_RETURN:		return "fmod_ret";
		case BPF_TRACE_RAW_TP:		return "tp_btf";
		case BPF_TRACE_ITER:		return "iter";
		default:			return NULL;
		}
	}
	return NULL;
}

/*
 * Resolve a loaded upatch's bpffs link pin to its attach hook string
 * ("lsm/socket_create", "fentry/tcp_v4_connect", ...). The link pin is
 * opened with read-only bpf() ops (BPF_OBJ_GET / *_GET_INFO_BY_FD /
 * PROG_GET_FD_BY_ID -- all LSM-allowed). vmlinux BTF resolves
 * attach_btf_id back to a function name; caller loads it once and
 * reuses across the per-upatch loop (a fresh load per upatch would
 * re-read /sys/kernel/btf/vmlinux on every iteration).
 *
 * The attach kind (fentry/fexit/lsm/...) comes from the link's
 * tracing.attach_type rather than prog_info -- bpf_prog_info has
 * attach_btf_id but no expected_attach_type. Both LSM and tracing
 * progs use BPF_LINK_TYPE_TRACING when attached via
 * BPF_RAW_TRACEPOINT_OPEN with a NULL name (the path shirudo uses),
 * so linfo.tracing.attach_type is always populated for our links.
 *
 * Returns 0 on success with `out` populated, or -errno; on failure
 * `out` is "" so the JSON field degrades to empty rather than absent.
 */
static int resolve_upatch_location(struct btf *vbtf, const char *name,
				   char *out, size_t cap)
{
	struct bpf_link_info linfo = {};
	struct bpf_prog_info info = {};
	const char *attach_name = NULL;
	uint32_t attach_type = 0;
	int link_fd, prog_fd, rc;
	char pin[PATH_MAX];
	const char *prefix;
	uint32_t len;

	out[0] = '\0';
	if ((size_t)snprintf(pin, sizeof(pin), "%s/%s/link",
			     SHIRUDO_BPFFS_UPATCHES_DIR, name) >= sizeof(pin))
		return -ENAMETOOLONG;

	link_fd = bpf_obj_get(pin);
	if (link_fd < 0)
		return -errno;
	len = sizeof(linfo);
	rc = bpf_link_get_info_by_fd(link_fd, &linfo, &len);
	close(link_fd);
	if (rc != 0 || linfo.prog_id == 0)
		return rc ? -errno : -EINVAL;
	if (linfo.type == BPF_LINK_TYPE_TRACING)
		attach_type = linfo.tracing.attach_type;

	prog_fd = bpf_prog_get_fd_by_id(linfo.prog_id);
	if (prog_fd < 0)
		return -errno;
	len = sizeof(info);
	rc = bpf_prog_get_info_by_fd(prog_fd, &info, &len);
	close(prog_fd);
	if (rc != 0)
		return -errno;

	/*
	 * Look up the attach BTF type in vmlinux BTF. The kernel sets
	 * attach_btf_obj_id to btf_obj_id(attach_btf) -- vmlinux has a
	 * non-zero id (typically 1), so we don't gate the lookup on it
	 * being zero (that bug let LSM hooks render as bare "lsm" with
	 * no hook name). All shirudo upatches attach to vmlinux, not
	 * module BTFs, so a vmlinux lookup is always correct.
	 */
	if (vbtf && info.attach_btf_id &&
	    info.attach_btf_id < btf__type_cnt(vbtf)) {
		const struct btf_type *t;

		t = btf__type_by_id(vbtf, info.attach_btf_id);
		if (t)
			attach_name = btf__name_by_offset(vbtf, t->name_off);
	}

	prefix = upatch_loc_prefix(info.type, attach_type);
	if (!prefix)
		prefix = libbpf_bpf_prog_type_str(info.type);
	if (!prefix)
		prefix = "?";

	/* LSM hook funcs are named bpf_lsm_<hook>; strip the prefix. */
	if (info.type == BPF_PROG_TYPE_LSM && attach_name &&
	    strncmp(attach_name, "bpf_lsm_", 8) == 0)
		attach_name += 8;

	if (attach_name && *attach_name)
		snprintf(out, cap, "%s/%s", prefix, attach_name);
	else
		snprintf(out, cap, "%s", prefix);
	return 0;
}

/*
 * "When did this upatch become active in this boot?" -- ctime of the
 * upatch's bpffs pin directory. bpffs is RAM-backed (gone on reboot,
 * re-created by boot-restore), so the ctime is honest about the active-
 * since point even after boot-restore: it is the timestamp the kernel
 * inode came into existence on the current boot. Defaults to "" if the
 * dir is missing or stat fails; the operator-side table then renders
 * AGE as "?".
 */
static void upatch_loaded_at(const char *name, char *out, size_t cap)
{
	char dir[PATH_MAX];
	struct stat st;
	struct tm tm;

	out[0] = '\0';
	if ((size_t)snprintf(dir, sizeof(dir), "%s/%s",
			     SHIRUDO_BPFFS_UPATCHES_DIR, name) >= sizeof(dir))
		return;
	if (stat(dir, &st) != 0)
		return;
	if (!gmtime_r(&st.st_ctim.tv_sec, &tm))
		return;
	strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* Compose roles like nodes show: "target", "operator", or both. */
static const char *roles_str(int is_target, int is_operator)
{
	if (is_target && is_operator)
		return "target, operator";
	if (is_operator)
		return "operator";
	if (is_target)
		return "target";
	return "none";
}

int cmd_status(int argc, const char **argv)
{
	bool json = false, include_tpm = false;
	bool include_system = false, include_eventlog = false;
	bool include_kernel_log = false, include_modules = false;
	bool include_maps = false;
	bool show_full = false;
	bool lsm_attached, keyring_present, is_operator, cert_present, is_target;
	key_serial_t keyring_serial, keyring_pinned;
	struct shirudo_sysinfo sysi = {};
	struct asset_view assets;
	struct dirent **ups = NULL;
	uint8_t chain[SHIRUDO_CHAIN_DIGEST_LEN];
	char chain_hex[2 * SHIRUDO_CHAIN_DIGEST_LEN + 1];
	char nv_index[16];
	char *json_buf = NULL;
	size_t json_cap = 0;
	long ev_entries = 0, ev_bytes = 0;
	int chain_rc = 0, ev_rc = -ENOENT;
	int match = -1;		/* -1 unknown, 0 mismatch, 1 match */
	int n_ups, i, fd, ret = 0;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--json") == 0)
			json = true;
		else if (strcmp(argv[i], "--include-tpm") == 0)
			include_tpm = true;
		else if (strcmp(argv[i], "--include-system") == 0)
			include_system = true;
		else if (strcmp(argv[i], "--include-eventlog") == 0)
			include_eventlog = true;
		else if (strcmp(argv[i], "--include-kernel-log") == 0)
			include_kernel_log = true;
		else if (strcmp(argv[i], "--include-modules") == 0)
			include_modules = true;
		else if (strcmp(argv[i], "--include-maps") == 0)
			include_maps = true;
		else if (strcmp(argv[i], "--show-full") == 0)
			show_full = true;
		else if (shirudo_is_help(argv[i])) {
			shirudo_print_help(&status_help);
			return 0;
		} else {
			fprintf(stderr, "status: unknown option '%s'\n", argv[i]);
			usage();
			return 2;
		}
	}

	/*
	 * --show-full is the one-switch verbose mode: every section the
	 * --include-* flags can opt into, plus the modules dep-tree. Stack
	 * it on first so any individual --include-* already given is a no-op.
	 */
	if (show_full) {
		include_tpm = true;
		include_system = true;
		include_eventlog = true;
		include_kernel_log = true;
		include_modules = true;
		include_maps = true;
	}
	/* The events[] array lives under tpm.eventlog, so it needs that. */
	if (include_eventlog)
		include_tpm = true;
	if (include_system)
		shirudo_sysinfo_gather(&sysi);

	fd = bpf_obj_get(SHIRUDO_LSM_LINK_PIN);
	lsm_attached = fd >= 0;
	if (fd >= 0)
		close(fd);
	keyring_serial = shirudo_keyring_find(SHIRUDO_KEYRING_NAME);
	keyring_present = keyring_serial >= 0;
	keyring_pinned = shirudo_keyring_read_pinned_serial();
	is_operator = access(SHIRUDO_SIGNING_KEY_PATH, F_OK) == 0;
	cert_present = access(SHIRUDO_CERT_PATH, F_OK) == 0;
	is_target = cert_present || lsm_attached || keyring_present;

	n_ups = scandir(SHIRUDO_BPFFS_UPATCHES_DIR, &ups, notdot, alphasort);
	if (n_ups < 0)
		n_ups = 0;

	gather_assets(&assets);

	if (include_tpm) {
		snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
		chain_rc = shirudo_chain_read(chain);
		if (chain_rc == 0)
			shirudo_hex_encode(chain, sizeof(chain), chain_hex);
		ev_rc = count_eventlog(&ev_entries, &ev_bytes);

		/*
		 * Tamper check: a live chain must equal the eventlog
		 * replayed from zero. Any replay failure (malformed or
		 * missing log while a chain exists) is a mismatch.
		 */
		if (chain_rc == 0) {
			uint8_t replay[SHIRUDO_CHAIN_DIGEST_LEN];

			match = shirudo_eventlog_replay(replay) == 0 &&
				shirudo_ct_eq(chain, replay, sizeof(replay));
		}
	}

	if (json) {
		struct shirudo_json_emit e;

		/*
		 * The events[] dump re-emits one object per logged line, so
		 * size the buffer to the on-disk log plus headroom for the
		 * fixed fields; 16 KiB covers the no-eventlog case.
		 * --include-modules pads ~250 B per module; --include-kernel-log
		 * pads up to 8 KiB total (15 lines * ~500 B). Eyeball-padded,
		 * the cap-clamp at the bottom keeps us under SHIRUDO_JSON_MAX_BYTES.
		 */
		json_cap = 16384;
		if (include_eventlog && ev_rc == 0)
			json_cap = 65536 + 3 * (size_t)ev_bytes;
		if (include_kernel_log)
			json_cap += 8192;
		if (include_modules)
			json_cap += 64 * 1024;
		if (json_cap > SHIRUDO_JSON_MAX_BYTES)
			json_cap = SHIRUDO_JSON_MAX_BYTES;
		json_buf = xmalloc(json_cap);
		if (!json_buf) {
			fprintf(stderr, "status: out of memory\n");
			ret = 1;
			goto out;
		}
		e = (struct shirudo_json_emit){ .buf = json_buf, .cap = json_cap };

		shirudo_json_obj_open(&e);
		shirudo_json_kv_int(&e, "schema", 1);
		shirudo_json_kv_string(&e, "version_id", shirudo_version_id);
		shirudo_json_kv_bool(&e, "is_target", is_target);
		shirudo_json_kv_bool(&e, "is_operator", is_operator);
		{
			struct shirudo_conditions_input cin;
			struct shirudo_condition conds[SHIRUDO_CONDITIONS_MAX];
			size_t nc, ci;

			local_cond_input(&cin, lsm_attached, keyring_present,
				keyring_serial,
				keyring_pinned >= 1 ? keyring_pinned : 0,
				keyring_present, keyring_pinned >= 1,
				keyring_present && keyring_pinned >= 1,
				keyring_present && keyring_pinned >= 1 &&
					keyring_serial == keyring_pinned,
				include_tpm && chain_rc == 0,
				match == 1, match >= 0,
				include_tpm ? nv_index : NULL);
			shirudo_json_kv_string(&e, "status",
					       shirudo_status_verdict(&cin));
			nc = shirudo_conditions(&cin, conds,
						ARRAY_SIZE(conds));
			shirudo_json_arr_open(&e, "conditions");
			for (ci = 0; ci < nc; ci++) {
				shirudo_json_obj_open(&e);
				shirudo_json_kv_string(&e, "type",
						       conds[ci].type);
				shirudo_json_kv_string(&e, "status",
						       conds[ci].status);
				shirudo_json_kv_string(&e, "detail",
						       conds[ci].detail);
				shirudo_json_obj_close(&e);
			}
			shirudo_json_arr_close(&e);
		}
		shirudo_json_kv_bool(&e, "lsm_attached", lsm_attached);
		shirudo_json_kv_bool(&e, "keyring_present", keyring_present);
		if (keyring_present)
			shirudo_json_kv_int(&e, "keyring_serial",
					    keyring_serial);
		else
			shirudo_json_kv_null(&e, "keyring_serial");
		if (keyring_pinned >= 1)
			shirudo_json_kv_int(&e, "keyring_serial_pinned",
					    keyring_pinned);
		else
			shirudo_json_kv_null(&e, "keyring_serial_pinned");
		if (keyring_present && keyring_pinned >= 1)
			shirudo_json_kv_bool(&e, "keyring_serial_matches",
					     keyring_serial == keyring_pinned);
		else
			shirudo_json_kv_null(&e, "keyring_serial_matches");
		shirudo_json_kv_bool(&e, "cert_present", cert_present);
		shirudo_json_kv_bool(&e, "signing_key_present", is_operator);
		{
			/*
			 * vmlinux BTF is loaded once and reused across the
			 * per-upatch resolve. NULL is fine -- resolver falls
			 * back to "?". A single load is ~MiBs read from
			 * /sys/kernel/btf/vmlinux; per-upatch reload would
			 * be a needless syscall storm on a fleet host.
			 */
			struct btf *vbtf = btf__load_vmlinux_btf();

			shirudo_json_arr_open(&e, "upatches_loaded");
			for (i = 0; i < n_ups; i++) {
				struct shirudo_map_summary *list = NULL;
				char loc[160] = "";
				char la[32] = "";
				size_t nm = 0;

				resolve_upatch_location(vbtf, ups[i]->d_name,
							loc, sizeof(loc));
				upatch_loaded_at(ups[i]->d_name, la, sizeof(la));
				shirudo_upatch_maps_list_one(ups[i]->d_name,
							     &list, &nm);
				shirudo_json_obj_open(&e);
				shirudo_json_kv_string(&e, "name",
						       ups[i]->d_name);
				shirudo_json_kv_string(&e, "location", loc);
				shirudo_json_kv_int(&e, "n_maps", (int64_t)nm);
				shirudo_json_kv_string(&e, "loaded_at", la);
				shirudo_json_obj_close(&e);
				shirudo_map_summary_free(list, nm);
			}
			shirudo_json_arr_close(&e);
			if (vbtf)
				btf__free(vbtf);
		}
		shirudo_json_obj_open_key(&e, "assets");
		shirudo_json_kv_string(&e, "root", SHIRUDO_VAR_LIB);
		shirudo_json_kv_bool(&e, "cert", assets.cert);
		shirudo_json_kv_bool(&e, "signing_key", assets.signing_key);
		shirudo_json_kv_bool(&e, "keyring_serial", assets.keyring_serial);
		shirudo_json_kv_bool(&e, "eventlog", assets.eventlog);
		shirudo_json_kv_int(&e, "eventlog_bytes", assets.eventlog_bytes);
		if (assets.n_upatches >= 0)
			shirudo_json_kv_int(&e, "upatches", assets.n_upatches);
		else
			shirudo_json_kv_null(&e, "upatches");
		if (assets.n_incoming >= 0)
			shirudo_json_kv_int(&e, "incoming", assets.n_incoming);
		else
			shirudo_json_kv_null(&e, "incoming");
		shirudo_json_kv_bool(&e, "bpffs_mounted", assets.bpffs_mounted);
		shirudo_json_obj_close(&e);
		if (include_system)
			shirudo_sysinfo_emit_json(&e, &sysi);
		if (include_tpm) {
			shirudo_json_obj_open_key(&e, "tpm");
			shirudo_json_kv_string(&e, "nv_index", nv_index);
			if (chain_rc == 0)
				shirudo_json_kv_string(&e, "chain", chain_hex);
			else
				shirudo_json_kv_null(&e, "chain");
			if (match < 0)
				shirudo_json_kv_null(&e, "chain_matches_eventlog");
			else
				shirudo_json_kv_bool(&e, "chain_matches_eventlog",
						     match);
			shirudo_json_obj_open_key(&e, "eventlog");
			shirudo_json_kv_bool(&e, "present", ev_rc == 0);
			shirudo_json_kv_int(&e, "entries",
					    ev_rc == 0 ? ev_entries : 0);
			shirudo_json_kv_int(&e, "bytes", ev_rc == 0 ? ev_bytes : 0);
			if (include_eventlog)
				emit_eventlog_events(&e);
			shirudo_json_obj_close(&e);
			shirudo_json_obj_close(&e);
		}
		if (include_kernel_log) {
			struct shirudo_kmsg_record recs[10];
			int nr = shirudo_kmsg_tail(recs, ARRAY_SIZE(recs));
			int j;

			shirudo_json_arr_open(&e, "kernel_log");
			for (j = 0; j < nr; j++) {
				shirudo_json_obj_open(&e);
				shirudo_json_kv_string(&e, "ts", recs[j].ts);
				shirudo_json_kv_string(&e, "msg", recs[j].msg);
				shirudo_json_obj_close(&e);
			}
			shirudo_json_arr_close(&e);
		}
		if (include_modules) {
			struct shirudo_kmod_set ks = {};
			int mrc = shirudo_kmodules_read(&ks);
			struct timespec rt = {}, bt = {};
			int64_t boot_sec = 0;
			char boot_iso[32] = "";
			size_t mi;

			if (clock_gettime(CLOCK_REALTIME, &rt) == 0 &&
			    clock_gettime(CLOCK_BOOTTIME, &bt) == 0) {
				boot_sec = (int64_t)rt.tv_sec - bt.tv_sec;
				struct tm tm = {};
				time_t t = (time_t)boot_sec;

				if (gmtime_r(&t, &tm))
					strftime(boot_iso, sizeof(boot_iso),
						 "%Y-%m-%dT%H:%M:%SZ", &tm);
			}
			shirudo_json_kv_string(&e, "boot_at",
					       boot_iso[0] ? boot_iso : "");
			shirudo_json_arr_open(&e, "modules");
			if (mrc == 0) {
				for (mi = 0; mi < ks.n; mi++) {
					const struct shirudo_kmod *m =
						&ks.mods[mi];
					char loaded_iso[32] = "";
					uint16_t di;

					if (m->loaded_at_sec > 0) {
						struct tm tm = {};
						time_t t = (time_t)m->loaded_at_sec;

						if (gmtime_r(&t, &tm))
							strftime(loaded_iso,
								 sizeof(loaded_iso),
								 "%Y-%m-%dT%H:%M:%SZ",
								 &tm);
					}
					shirudo_json_obj_open(&e);
					shirudo_json_kv_string(&e, "name",
							       m->name);
					shirudo_json_kv_int(&e, "size",
							    (int64_t)m->size);
					shirudo_json_kv_int(&e, "refcount",
							    m->refcount);
					shirudo_json_kv_string(&e, "loaded_at",
							       loaded_iso);
					if (boot_sec > 0 &&
					    m->loaded_at_sec >= boot_sec)
						shirudo_json_kv_int(&e,
							"since_boot_sec",
							m->loaded_at_sec - boot_sec);
					else
						shirudo_json_kv_null(&e,
							"since_boot_sec");
					shirudo_json_arr_open(&e, "deps");
					for (di = 0; di < m->n_deps; di++) {
						size_t dk = ks.deps[m->deps_off
								    + di];
						shirudo_json_str(&e,
							ks.mods[dk].name);
					}
					shirudo_json_arr_close(&e);
					shirudo_json_obj_close(&e);
				}
			}
			shirudo_json_arr_close(&e);
			shirudo_kmodules_free(&ks);
		}
		if (include_maps) {
			shirudo_json_arr_open(&e, "upatch_maps");
			for (i = 0; i < n_ups; i++) {
				struct shirudo_map_summary *list = NULL;
				size_t nm = 0;
				size_t k;

				shirudo_upatch_maps_list_one(ups[i]->d_name,
							     &list, &nm);
				shirudo_json_obj_open(&e);
				shirudo_json_kv_string(&e, "upatch",
						       ups[i]->d_name);
				shirudo_json_arr_open(&e, "maps");
				for (k = 0; k < nm; k++) {
					struct shirudo_map_view v = {};
					uint32_t cap = show_full ? 0 :
						SHIRUDO_MAP_ENTRIES_DEFAULT;

					if (shirudo_upatch_maps_read(
						list[k].upatch, list[k].name,
						cap, &v) == 0)
						shirudo_upatch_maps_emit_json(
							&e, &v);
					shirudo_map_view_free(&v);
				}
				shirudo_json_arr_close(&e);
				shirudo_json_obj_close(&e);
				shirudo_map_summary_free(list, nm);
			}
			shirudo_json_arr_close(&e);
		}
		shirudo_json_obj_close(&e);

		if (e.err)
			fprintf(stderr, "status: json encode failed: %s\n",
				strerror(-e.err));
		else
			printf("%s\n", json_buf);
	} else {
		struct shirudo_conditions_input cin;
		struct shirudo_condition conds[SHIRUDO_CONDITIONS_MAX];
		struct upatch_load_info loads[256];
		size_t nc, n_loads;
		char hostname[256] = "?";
		char reason[160];
		const char *verdict;

		local_cond_input(&cin, lsm_attached, keyring_present,
			keyring_serial,
			keyring_pinned >= 1 ? keyring_pinned : 0,
			keyring_present, keyring_pinned >= 1,
			keyring_present && keyring_pinned >= 1,
			keyring_present && keyring_pinned >= 1 &&
				keyring_serial == keyring_pinned,
			include_tpm && chain_rc == 0,
			match == 1, match >= 0,
			include_tpm ? nv_index : NULL);
		verdict = shirudo_status_verdict(&cin);
		shirudo_status_reason(&cin, reason, sizeof(reason));
		nc = shirudo_conditions(&cin, conds, ARRAY_SIZE(conds));
		n_loads = scan_eventlog_loads(loads, ARRAY_SIZE(loads));
		(void)gethostname(hostname, sizeof(hostname));
		hostname[sizeof(hostname) - 1] = '\0';

		printf("Host:              %s\n", hostname);
		printf("Roles:             %s\n",
		       roles_str(is_target, is_operator));
		if (reason[0])
			printf("Status:            %s  (%s)\n", verdict,
			       reason);
		else
			printf("Status:            %s\n", verdict);
		printf("Version-ID:        %s\n", shirudo_version_id);

		printf("\n");
		shirudo_conditions_print(conds, nc);

		printf("\nKeyring (%s):\n", SHIRUDO_KEYRING_NAME);
		if (keyring_present)
			printf("  %-22s %lld\n", "Serial:",
			       (long long)keyring_serial);
		else
			printf("  %-22s %s\n", "Serial:",
			       "absent  (operator host, or `shirudo init` "
			       "not yet run)");
		if (keyring_pinned == (key_serial_t)-ENOENT)
			printf("  %-22s %s\n", "Pinned serial:",
			       "(none recorded)");
		else if (keyring_pinned < 0)
			printf("  %-22s unreadable (%s)\n", "Pinned serial:",
			       strerror(-keyring_pinned));
		else
			printf("  %-22s %lld%s\n", "Pinned serial:",
			       (long long)keyring_pinned, !keyring_present ? "" :
			       keyring_serial == keyring_pinned ?
				       "  (matches)" :
				       "  (MISMATCH -- swapped?)");

		if (include_system)
			print_system_human(&sysi);

		printf("\nUpatches loaded (%d):\n", n_ups);
		if (n_ups > 0) {
			printf("  %-30s %-18s %s\n", "NAME", "PAYLOAD-SHA256",
			       "APPLIED");
			for (i = 0; i < n_ups; i++) {
				const struct upatch_load_info *li =
					find_load(loads, n_loads,
						  ups[i]->d_name);
				char age[16] = "?";
				char pay[20];

				if (li) {
					struct tm tm = {};

					snprintf(pay, sizeof(pay), "%.16s..",
						 li->payload);
					if (strptime(li->ts,
						     "%Y-%m-%dT%H:%M:%SZ",
						     &tm))
						shirudo_format_duration(
							(long)(time(NULL) -
							       timegm(&tm)),
							age, sizeof(age));
				} else {
					snprintf(pay, sizeof(pay), "-");
				}
				printf("  %-30s %-18s %s\n",
				       ups[i]->d_name, pay, age);
				if (include_maps) {
					struct shirudo_map_summary *list = NULL;
					size_t nm = 0;
					size_t k;

					shirudo_upatch_maps_list_one(
						ups[i]->d_name, &list, &nm);
					if (nm) {
						printf("    Maps:\n");
						for (k = 0; k < nm; k++)
							shirudo_upatch_map_print_inline(
								&list[k]);
					}
					shirudo_map_summary_free(list, nm);
				}
			}
		}

		if (include_tpm) {
			printf("\nTPM Measurement:\n");
			printf("  %-18s %s\n", "NV index:", nv_index);
			if (chain_rc == 0)
				printf("  %-18s %s\n", "Chain:", chain_hex);
			else
				printf("  %-18s %s\n", "Chain:",
				       "unavailable (no TPM / index "
				       "undefined)");
			printf("  %-18s %s\n", "Chain vs eventlog:",
			       match < 0 ? "n/a" :
			       match ? "matches" : "MISMATCH (tamper?)");
			if (ev_rc == 0)
				printf("  %-18s %s  (%ld entries, %ld bytes)\n",
				       "Eventlog:", SHIRUDO_EVENTLOG_PATH,
				       ev_entries, ev_bytes);
			else
				printf("  %-18s absent\n", "Eventlog:");
		}

		if (include_eventlog)
			print_eventlog_table();

		printf("\nAssets (%s):\n", SHIRUDO_VAR_LIB);
		printf("  %-22s %s\n", "keys/cert.der",
		       assets.cert ? "present" : "absent");
		printf("  %-22s %s\n", "keys/signing_key.pem",
		       assets.signing_key ? "present" : "absent");
		printf("  %-22s %s\n", "keyring.serial",
		       assets.keyring_serial ? "present" : "absent");
		if (assets.eventlog)
			printf("  %-22s present (%ld bytes)\n", "eventlog",
			       assets.eventlog_bytes);
		else
			printf("  %-22s absent\n", "eventlog");
		if (assets.n_upatches < 0)
			printf("  %-22s absent\n", "upatches/");
		else
			printf("  %-22s %d .upatch\n", "upatches/",
			       assets.n_upatches);
		if (assets.n_incoming < 0)
			printf("  %-22s absent\n", "incoming/");
		else if (assets.n_incoming == 0)
			printf("  %-22s empty\n", "incoming/");
		else
			printf("  %-22s %d staged\n", "incoming/",
			       assets.n_incoming);
		printf("  %-22s %s\n", "bpffs/",
		       assets.bpffs_mounted ? "mounted" : "not mounted");

		if (include_kernel_log) {
			struct shirudo_kmsg_record recs[10];
			int nr = shirudo_kmsg_tail(recs, ARRAY_SIZE(recs));
			int j;

			printf("\nKernel log (last %zu lines, newest first):\n",
			       ARRAY_SIZE(recs));
			if (nr <= 0)
				printf("  (unavailable)\n");
			else
				for (j = nr; j-- > 0;)
					printf("  [%s]  %s\n", recs[j].ts,
					       recs[j].msg);
		}
		if (include_modules) {
			struct shirudo_kmod_set ks = {};
			int mrc = shirudo_kmodules_read(&ks);
			struct timespec rt = {}, bt = {};
			int64_t boot_sec = 0;
			size_t last = 10;
			size_t shown = ks.n < last ? ks.n : last;

			if (clock_gettime(CLOCK_REALTIME, &rt) == 0 &&
			    clock_gettime(CLOCK_BOOTTIME, &bt) == 0)
				boot_sec = (int64_t)rt.tv_sec - bt.tv_sec;

			if (mrc != 0) {
				printf("\nLoaded modules:\n");
				printf("  (unavailable: %s)\n", strerror(-mrc));
			} else {
				printf("\nLoaded modules (total %zu, "
				       "last %zu loads, newest first):\n",
				       ks.n, shown);
				shirudo_kmodules_print_recent(&ks, last,
							      boot_sec);
				if (!show_full)
					printf("  (Use --show-full to show "
					       "all loaded modules in a "
					       "dependency tree)\n");
				else {
					printf("\nDependency tree:\n");
					shirudo_kmodules_print_tree(&ks);
				}
			}
			shirudo_kmodules_free(&ks);
		}
	}

out:
	for (i = 0; i < n_ups; i++)
		shirudo_libc_free(ups[i]);	/* scandir-owned */
	shirudo_libc_free(ups);			/* scandir-owned */
	if (json_buf)
		xfree(json_buf, json_cap);
	return ret;
}
