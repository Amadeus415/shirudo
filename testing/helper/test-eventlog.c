// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Drives the eventlog's pending record, with the log and the pending
 * file redirected by SHIRUDO_EVENTLOG_PATH and
 * SHIRUDO_EVENTLOG_PENDING_PATH. Subcommand on argv[1]; prints what a
 * shell test asserts on.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "chain.h"
#include "eventlog.h"
#include "hex.h"
#include "json.h"
#include "paths.h"

/* An init record of this boot with fixed values, bound where told. */
static int append_init(const char *path, const char *bound_in,
		       unsigned int reset_count)
{
	char buf[4096], ts[32], boot_id[64], nv_index[16], hex[65];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	char name_hex[2 * SHIRUDO_TPM_NAME_LEN + 1];
	uint8_t zero[SHIRUDO_TPM_NAME_LEN] = {};

	shirudo_eventlog_timestamp(ts, sizeof(ts));
	shirudo_eventlog_boot_id(boot_id, sizeof(boot_id));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
	shirudo_hex_encode(zero, 32, hex);
	shirudo_hex_encode(zero, SHIRUDO_TPM_NAME_LEN, name_hex);
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 2);
	shirudo_json_kv_string(&e, "ts", ts);
	shirudo_json_kv_string(&e, "nv_index", nv_index);
	shirudo_json_kv_string(&e, "alg", "sha256");
	shirudo_json_kv_string(&e, "digest", hex);
	shirudo_json_kv_string(&e, "type", "init");
	shirudo_json_kv_string(&e, "boot_id", boot_id);
	shirudo_json_kv_int(&e, "tpm_reset_count", reset_count);
	shirudo_json_kv_int(&e, "pcr", SHIRUDO_CHAIN_PCR);
	shirudo_json_kv_string(&e, "pcr_before", hex);
	shirudo_json_kv_int(&e, "phase_pcr", SHIRUDO_CHAIN_PHASE_PCR);
	shirudo_json_kv_string(&e, "phase_before", hex);
	shirudo_json_kv_string(&e, "bound_in", bound_in);
	shirudo_json_kv_string(&e, "nv_name", name_hex);
	shirudo_json_kv_string(&e, "anchor", "shirudo-anchor:test");
	shirudo_json_kv_string(&e, "anchor_digest", hex);
	shirudo_json_kv_string(&e, "chain", hex);
	shirudo_json_obj_close(&e);
	if (e.err)
		return e.err;
	return shirudo_eventlog_append_to(path, buf);
}

static int count_lines(const char *line, size_t len, void *ctx)
{
	unsigned int *n = ctx;

	(void)line;
	(void)len;
	(*n)++;
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s init log|pending <bound_in> "
			"[reset] | boot-init | lines | adopt\n", argv[0]);
		return 2;
	}
	if (strcmp(argv[1], "init") == 0 && (argc == 4 || argc == 5)) {
		const char *path = strcmp(argv[2], "pending") == 0 ?
				   shirudo_eventlog_pending_path() :
				   shirudo_eventlog_path();
		unsigned int reset = 1;
		int rc;

		if (argc == 5)
			reset = (unsigned int)strtoul(argv[4], NULL, 10);
		rc = append_init(path, argv[3], reset);

		printf("rc=%d\n", rc);
		return rc ? 1 : 0;
	}
	if (strcmp(argv[1], "boot-init") == 0) {
		struct shirudo_eventlog_init rec;
		int rc = shirudo_eventlog_boot_init(&rec);

		printf("rc=%d\n", rc);
		if (rc)
			return 1;
		printf("bound_in=%s\nrecords=%u\nreset_count=%u\n",
		       rec.initrd ? "initrd" : "root", rec.records,
		       rec.reset_count);
		return 0;
	}
	if (strcmp(argv[1], "lines") == 0) {
		unsigned int n = 0;
		int rc = shirudo_eventlog_boot_lines(count_lines, &n);

		printf("rc=%d\nlines=%u\n", rc, n);
		return rc ? 1 : 0;
	}
	if (strcmp(argv[1], "adopt") == 0) {
		int rc = shirudo_eventlog_adopt_pending();

		printf("rc=%d\npending=%s\n", rc,
		       access(shirudo_eventlog_pending_path(), F_OK) == 0 ?
		       "present" : "absent");
		return rc ? 1 : 0;
	}
	fprintf(stderr, "unknown subcommand\n");
	return 2;
}
