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
#include "util/paths.h"

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
		free(list[i]);
	}
	free(list);
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

static void usage(void)
{
	fprintf(stderr, "usage: shirudo status [--json] [--include-tpm]\n");
}

int cmd_status(int argc, const char **argv)
{
	bool json = false, include_tpm = false;
	bool lsm_attached, keyring_present, is_operator, cert_present, is_target;
	key_serial_t keyring_serial, keyring_pinned;
	struct asset_view assets;
	struct dirent **ups = NULL;
	uint8_t chain[SHIRUDO_CHAIN_DIGEST_LEN];
	char chain_hex[2 * SHIRUDO_CHAIN_DIGEST_LEN + 1];
	char nv_index[16];
	long ev_entries = 0, ev_bytes = 0;
	int chain_rc = 0, ev_rc = -ENOENT;
	int match = -1;		/* -1 unknown, 0 mismatch, 1 match */
	int n_ups, i, fd;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--json") == 0)
			json = true;
		else if (strcmp(argv[i], "--include-tpm") == 0)
			include_tpm = true;
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
		char buf[16384];
		struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };

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
			shirudo_json_obj_close(&e);
			shirudo_json_obj_close(&e);
		}
		shirudo_json_obj_close(&e);

		if (e.err)
			fprintf(stderr, "status: json encode failed: %s\n",
				strerror(-e.err));
		else
			printf("%s\n", buf);
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
	}

	for (i = 0; i < n_ups; i++)
		free(ups[i]);
	free(ups);
	return 0;
}
