// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/*
 * Drives util/conditions.c for t0050 with the input `shirudo status`
 * derives from what it reads off the host.
 *
 *   test-conditions <lsm 0|1> <bpf|none> <serial> <pinned> \
 *                   <notpm|none|match|mismatch>
 *
 * serial is the live keyring's, -1 when it is absent; pinned the one init
 * froze, 0 when it froze none; the last word the register's replay, with
 * notpm for no TPM answering and none for no register bound.
 */

#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shirudo/string.h>

#include "util/conditions.h"
#include "util/macros.h"

static int arg_s64(const char *s, __s64 *out)
{
	return parse_s64(s, strlen(s), -1, INT32_MAX, out);
}

int main(int argc, char **argv)
{
	struct shirudo_condition conds[SHIRUDO_CONDITIONS_MAX];
	struct shirudo_conditions_input in = {};
	__s64 lsm, serial, pinned;
	const char *mode, *hint, *config;
	char reason[160];
	size_t n, i;

	if ((argc != 6 && argc != 7) || arg_s64(argv[1], &lsm) ||
	    arg_s64(argv[3], &serial) || arg_s64(argv[4], &pinned)) {
		fprintf(stderr, "usage: test-conditions <lsm> <mode> <serial> <pinned> <notpm|none|match|mismatch> [<why>]\n");
		return 2;
	}
	mode = argv[2];

	in.reachable = true;
	in.parsed = true;
	in.lsm_attached = lsm != 0;
	in.keyring_present = serial >= 0;
	in.keyring_mode = mode;
	in.keyring_serial = serial;
	in.keyring_serial_pinned = pinned;
	in.ks_seen = in.keyring_present;
	in.ksp_seen = pinned >= 1;
	in.ksm_seen = in.keyring_present && pinned >= 1;
	in.keyring_serial_matches = in.ksm_seen && serial == pinned;
	in.tpm_reachable = strcmp(argv[5], "notpm") != 0;
	in.chain_seen = in.tpm_reachable && strcmp(argv[5], "none") != 0;
	in.cm_seen = in.chain_seen;
	in.chain_matches = !strcmp(argv[5], "match");
	in.nv_index = "0x01818E00";
	in.chain_mismatch = argc == 7 ? argv[6] : NULL;
	config = getenv("SHIRUDO_TEST_CONFIG_STATE");
	in.config_seen = !config || strcmp(config, "none");
	in.config_state = !config ? 0 :
			  !strcmp(config, "pending") ? -EINPROGRESS :
			  !strcmp(config, "untrusted") ? -EUCLEAN :
			  !strcmp(config, "stale") ? -ESTALE : 0;
	in.config_root = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

	status_reason(&in, reason, sizeof(reason));
	printf("status=%s\n", status_verdict(&in));
	printf("reason=%s\n", reason);
	hint = status_hint(&in);
	printf("hint=%s\n", hint ? hint : "");
	n = conditions(&in, conds, ARRAY_SIZE(conds));
	for (i = 0; i < n; i++) {
		printf("%s %s %s\n", conds[i].type, conds[i].status,
		       conds[i].detail);
		if (conds[i].hint)
			printf("%s hint=%s\n", conds[i].type, conds[i].hint);
	}
	return 0;
}
