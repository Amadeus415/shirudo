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

#include <bpf/bpf.h>

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
#include "util/sysinfo.h"
#include "util/timefmt.h"

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
	printf("Eventlog (audit trail):\n");
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
	if (si->mem_total_kb > 0)
		printf("  %-16s %ld kB\n", "Memory:", si->mem_total_kb);
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
	{ "--include-kernel-log",   "last 15 lines of the kernel ring buffer" },
	{ "--include-modules",      "loaded kernel modules + dependency tree" },
};

static const struct shirudo_help_section status_help_sections[] = {
	{ "options:", status_options,
	  ARRAY_SIZE(status_options) },
};

static const struct shirudo_help status_help = {
	.usage      = "shirudo status [--json] [--include-tpm] "
		      "[--include-system] [--include-eventlog]\n"
		      "                       [--include-kernel-log] [--include-modules]",
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
		else if (shirudo_is_help(argv[i])) {
			shirudo_print_help(&status_help);
			return 0;
		} else {
			fprintf(stderr, "status: unknown option '%s'\n", argv[i]);
			usage();
			return 2;
		}
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
		 */
		json_cap = 16384;
		if (include_eventlog && ev_rc == 0)
			json_cap = 65536 + 3 * (size_t)ev_bytes;
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
		shirudo_json_arr_open(&e, "upatches_loaded");
		for (i = 0; i < n_ups; i++)
			shirudo_json_str(&e, ups[i]->d_name);
		shirudo_json_arr_close(&e);
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
			struct shirudo_kmsg_record recs[15];
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
			size_t mi;

			shirudo_json_arr_open(&e, "modules");
			if (mrc == 0) {
				for (mi = 0; mi < ks.n; mi++) {
					const struct shirudo_kmod *m =
						&ks.mods[mi];
					uint16_t di;

					shirudo_json_obj_open(&e);
					shirudo_json_kv_string(&e, "name",
							       m->name);
					shirudo_json_kv_int(&e, "size",
							    (int64_t)m->size);
					shirudo_json_kv_int(&e, "refcount",
							    m->refcount);
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

		if (include_eventlog) {
			printf("\n");
			print_eventlog_table();
		}

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
			struct shirudo_kmsg_record recs[15];
			int nr = shirudo_kmsg_tail(recs, ARRAY_SIZE(recs));
			int j;

			printf("\nKernel log (last %zu lines):\n",
			       ARRAY_SIZE(recs));
			if (nr <= 0)
				printf("  (unavailable)\n");
			else
				for (j = 0; j < nr; j++)
					printf("  [%s]  %s\n", recs[j].ts,
					       recs[j].msg);
		}
		if (include_modules) {
			struct shirudo_kmod_set ks = {};
			int mrc = shirudo_kmodules_read(&ks);

			printf("\nLoaded modules (%zu):\n",
			       mrc == 0 ? ks.n : (size_t)0);
			if (mrc != 0)
				printf("  (unavailable: %s)\n", strerror(-mrc));
			else
				shirudo_kmodules_print_tree(&ks);
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
