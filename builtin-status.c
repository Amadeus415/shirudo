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

#include "builtin.h"
#include "util/chain.h"
#include "util/eventlog.h"
#include "util/json.h"
#include "util/keyring.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/sysinfo.h"

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
	return shirudo_json_parse(line, len, f, sizeof(f) / sizeof(f[0]));
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
	printf("  eventlog entries:\n");
	printf("    %-20s %-13s %-13s %s\n", "TIME", "TYPE", "DIGEST",
	       "DETAIL");
	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char detail[256];
		struct ev_proj ev;

		if (parse_event_line(line, strlen(line), &ev) != 0) {
			printf("    %-20s %-13s %-13s\n", "?", "unparseable",
			       "");
			continue;
		}
		event_detail(&ev, detail, sizeof(detail));
		printf("    %-20s %-13s %-13.12s %s\n", ev.ts, ev.type,
		       ev.digest[0] ? ev.digest : "-", detail);
	}
	xfree(buf, len);
}

static void print_system_human(const struct shirudo_sysinfo *si)
{
	printf("  system info:\n");
	printf("    %-18s %s\n", "hostname", si->hostname);
	printf("    %-18s %s\n", "os", si->os_pretty);
	printf("    %-18s %s\n", "kernel", si->kernel_release);
	printf("    %-18s %s\n", "architecture", si->machine);
	if (si->nproc > 0)
		printf("    %-18s %ld\n", "cpus", si->nproc);
	if (si->mem_total_kb > 0)
		printf("    %-18s %ld kB\n", "memory", si->mem_total_kb);
	if (si->uptime_sec >= 0)
		printf("    %-18s %ldd %ldh %ldm\n", "uptime",
		       si->uptime_sec / 86400, (si->uptime_sec % 86400) / 3600,
		       (si->uptime_sec % 3600) / 60);
	if (si->machine_id[0])
		printf("    %-18s %s\n", "machine-id", si->machine_id);
	if (si->boot_id[0])
		printf("    %-18s %s\n", "boot-id", si->boot_id);
}

static void usage(void)
{
	fprintf(stderr, "usage: shirudo status [--json] [--include-tpm] "
		"[--include-system] [--include-eventlog]\n");
}

int cmd_status(int argc, const char **argv)
{
	bool json = false, include_tpm = false;
	bool include_system = false, include_eventlog = false;
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
		else if (strcmp(argv[i], "-h") == 0 ||
			 strcmp(argv[i], "--help") == 0) {
			usage();
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
		shirudo_json_obj_close(&e);

		if (e.err)
			fprintf(stderr, "status: json encode failed: %s\n",
				strerror(-e.err));
		else
			printf("%s\n", json_buf);
	} else {
		printf("shirudo status\n");
		printf("  version-id:      %s\n", shirudo_version_id);
		printf("  role:            target=%s operator=%s\n",
		       is_target ? "yes" : "no", is_operator ? "yes" : "no");
		printf("  lsm:             %s\n",
		       lsm_attached ? "attached" : "not attached");
		if (keyring_present)
			printf("  keyring:         present (%s, serial=%d)\n",
			       SHIRUDO_KEYRING_NAME, (int)keyring_serial);
		else
			printf("  keyring:         missing\n");
		if (keyring_pinned == -ENOENT)
			printf("  keyring pin:     none\n");
		else if (keyring_pinned < 0)
			printf("  keyring pin:     unreadable (%s)\n",
			       strerror(-keyring_pinned));
		else
			printf("  keyring pin:     serial=%d%s\n",
			       (int)keyring_pinned, !keyring_present ? "" :
			       keyring_serial == keyring_pinned ?
			       " (matches)" : " (MISMATCH -- swapped?)");
		printf("  cert:            %s\n",
		       cert_present ? "present" : "absent");
		if (is_operator)
			printf("  signing key:     present\n");
		printf("  upatches loaded: %d\n", n_ups);
		for (i = 0; i < n_ups; i++)
			printf("    %s\n", ups[i]->d_name);
		printf("  assets (%s):\n", SHIRUDO_VAR_LIB);
		printf("    %-20s %s\n", "keys/cert.der",
		       assets.cert ? "present" : "absent");
		printf("    %-20s %s\n", "keys/signing_key.pem",
		       assets.signing_key ? "present" : "absent");
		printf("    %-20s %s\n", "keyring.serial",
		       assets.keyring_serial ? "present" : "absent");
		if (assets.eventlog)
			printf("    %-20s present (%ld bytes)\n", "eventlog",
			       assets.eventlog_bytes);
		else
			printf("    %-20s absent\n", "eventlog");
		if (assets.n_upatches < 0)
			printf("    %-20s absent\n", "upatches/");
		else
			printf("    %-20s %d .upatch\n", "upatches/",
			       assets.n_upatches);
		if (assets.n_incoming < 0)
			printf("    %-20s absent\n", "incoming/");
		else if (assets.n_incoming == 0)
			printf("    %-20s empty\n", "incoming/");
		else
			printf("    %-20s %d staged\n", "incoming/",
			       assets.n_incoming);
		printf("    %-20s %s\n", "bpffs/",
		       assets.bpffs_mounted ? "mounted" : "not mounted");
		if (include_tpm) {
			printf("  tpm chain:       ");
			if (chain_rc == 0)
				printf("%s\n", chain_hex);
			else
				printf("unavailable (no TPM / index undefined)\n");
			printf("  chain vs log:    %s\n",
			       match < 0 ? "n/a" :
			       match ? "matches" : "MISMATCH (tamper?)");
			if (ev_rc == 0)
				printf("  eventlog:        %s (%ld entries, "
				       "%ld bytes)\n", SHIRUDO_EVENTLOG_PATH,
				       ev_entries, ev_bytes);
			else
				printf("  eventlog:        absent\n");
		}
		if (include_system)
			print_system_human(&sysi);
		if (include_eventlog)
			print_eventlog_table();
	}

out:
	for (i = 0; i < n_ups; i++)
		shirudo_libc_free(ups[i]);	/* scandir-owned */
	shirudo_libc_free(ups);			/* scandir-owned */
	if (json_buf)
		xfree(json_buf, json_cap);
	return ret;
}
