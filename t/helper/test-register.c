// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Drives the measurement register against a TPM (SHIRUDO_TPM_TCTI) with
 * the eventlog and certificate redirected by environment. Subcommand on
 * argv[1]; prints what a shell test asserts on.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attest.h"
#include "chain.h"
#include "config.h"
#include "eventlog.h"
#include "hex.h"
#include "json.h"
#include "malloc.h"
#include "paths.h"
#include "tpm.h"

static void puthex(const uint8_t *b, size_t n)
{
	char h[2 * 256 + 1];

	if (n > 256)
		return;
	shirudo_hex_encode(b, n, h);
	printf("%s\n", h);
}

/* Record an init the way shirudo init does, minus the set details. */
static int append_init(const uint8_t event[32],
		       const struct shirudo_chain_init_info *info)
{
	char buf[4096], ts[32], boot_id[64], nv_index[16], hex[256];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };

	shirudo_eventlog_timestamp(ts, sizeof(ts));
	shirudo_eventlog_boot_id(boot_id, sizeof(boot_id));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 2);
	shirudo_json_kv_string(&e, "ts", ts);
	shirudo_json_kv_string(&e, "nv_index", nv_index);
	shirudo_json_kv_string(&e, "alg", "sha256");
	shirudo_hex_encode(event, 32, hex);
	shirudo_json_kv_string(&e, "digest", hex);
	shirudo_json_kv_string(&e, "type", "init");
	shirudo_json_kv_string(&e, "boot_id", boot_id);
	shirudo_json_kv_int(&e, "pcr", SHIRUDO_CHAIN_PCR);
	shirudo_hex_encode(info->pcr_before, 32, hex);
	shirudo_json_kv_string(&e, "pcr_before", hex);
	shirudo_hex_encode(info->name, info->name_len, hex);
	shirudo_json_kv_string(&e, "nv_name", hex);
	shirudo_json_kv_string(&e, "anchor", info->anchor);
	shirudo_hex_encode(info->anchor_digest, 32, hex);
	shirudo_json_kv_string(&e, "anchor_digest", hex);
	shirudo_hex_encode(info->value, 32, hex);
	shirudo_json_kv_string(&e, "chain", hex);
	shirudo_json_obj_close(&e);
	if (e.err)
		return e.err;
	return shirudo_eventlog_append(buf);
}

static int append_event(const char *type, const char *name,
			const uint8_t event[32], const uint8_t chain[32])
{
	char buf[4096], ts[32], boot_id[64], nv_index[16], hex[65];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };

	shirudo_eventlog_timestamp(ts, sizeof(ts));
	shirudo_eventlog_boot_id(boot_id, sizeof(boot_id));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 2);
	shirudo_json_kv_string(&e, "ts", ts);
	shirudo_json_kv_string(&e, "nv_index", nv_index);
	shirudo_json_kv_string(&e, "alg", "sha256");
	shirudo_hex_encode(event, 32, hex);
	shirudo_json_kv_string(&e, "digest", hex);
	shirudo_json_kv_string(&e, "type", type);
	shirudo_json_kv_string(&e, "boot_id", boot_id);
	shirudo_json_obj_open_key(&e, "upatch");
	shirudo_json_kv_string(&e, "name", name);
	shirudo_json_obj_close(&e);
	shirudo_hex_encode(chain, 32, hex);
	shirudo_json_kv_string(&e, "chain", hex);
	shirudo_json_obj_close(&e);
	if (e.err)
		return e.err;
	return shirudo_eventlog_append(buf);
}

int main(int argc, char **argv)
{
	uint8_t event[32], chain[32];
	int rc;

	if (argc < 2)
		return 2;

	if (strcmp(argv[1], "init") == 0 && argc == 3) {
		struct shirudo_chain_init_info info;

		if (shirudo_hex_decode(argv[2], event, 32))
			return 2;
		rc = shirudo_chain_init(event, &info);
		printf("rc=%d\n", rc);
		if (rc)
			return 1;
		printf("reused=%d\n", info.reused);
		printf("value=");
		puthex(info.value, 32);
		printf("name=");
		puthex(info.name, info.name_len);
		printf("pcr_before=");
		puthex(info.pcr_before, 32);
		printf("anchor=%s\n", info.anchor);
		if (!info.reused && append_init(event, &info))
			return 1;
		return 0;
	}
	if (strcmp(argv[1], "load") == 0 && argc == 4) {
		uint8_t payload[32];

		if (shirudo_hex_decode(argv[3], payload, 32))
			return 2;
		shirudo_chain_upatch_event("shirudo-upatch", argv[2], payload,
					    event);
		rc = shirudo_chain_extend(event, chain);
		printf("rc=%d\n", rc);
		if (rc)
			return 1;
		printf("value=");
		puthex(chain, 32);
		return append_event("upatch_load", argv[2], event, chain) ?
		       1 : 0;
	}
	if (strcmp(argv[1], "extend-raw") == 0 && argc == 3) {
		if (shirudo_hex_decode(argv[2], event, 32))
			return 2;
		rc = shirudo_chain_extend(event, chain);
		printf("rc=%d\n", rc);
		if (rc)
			return 1;
		printf("value=");
		puthex(chain, 32);
		return 0;
	}
	if (strcmp(argv[1], "read") == 0) {
		rc = shirudo_chain_read(chain);
		printf("rc=%d\n", rc);
		if (rc)
			return 1;
		printf("value=");
		puthex(chain, 32);
		return 0;
	}
	if (strcmp(argv[1], "status") == 0) {
		struct shirudo_chain_status st;

		rc = shirudo_chain_status(&st);
		printf("rc=%d\n", rc);
		printf("tpm=%d defined=%d written=%d logged=%d anchored=%d\n",
		       st.tpm, st.defined, st.written, st.logged, st.anchored);
		if (st.defined && st.written) {
			printf("value=");
			puthex(st.value, 32);
		}
		return rc ? 1 : 0;
	}
	if (strcmp(argv[1], "pcr") == 0 && argc == 3) {
		struct shirudo_tpm *tpm = NULL;
		uint8_t v[32];

		if (shirudo_tpm_open(&tpm))
			return 1;
		rc = shirudo_tpm_pcr_read(tpm, (unsigned int)atoi(argv[2]), v);
		shirudo_tpm_close(tpm);
		if (rc)
			return 1;
		puthex(v, 32);
		return 0;
	}
	/* The attack: recreate the index with the same public area. */
	if (strcmp(argv[1], "recreate") == 0) {
		struct shirudo_tpm_nv_info nv;
		struct shirudo_tpm *tpm = NULL;

		if (shirudo_tpm_open(&tpm))
			return 1;
		rc = shirudo_tpm_nv_info(tpm, SHIRUDO_NV_INDEX, &nv);
		if (!rc && nv.defined)
			rc = shirudo_tpm_nv_undefine(tpm, SHIRUDO_NV_INDEX,
						     NULL, 0);
		if (!rc)
			rc = shirudo_tpm_nv_define(tpm, SHIRUDO_NV_INDEX,
						   nv.policy, NULL, 0);
		if (!rc)
			rc = shirudo_tpm_nv_info(tpm, SHIRUDO_NV_INDEX, &nv);
		shirudo_tpm_close(tpm);
		printf("rc=%d\n", rc);
		if (rc)
			return 1;
		printf("written=%d\nname=", nv.written);
		puthex(nv.name, nv.name_len);
		return 0;
	}
	/* The attack: try the init branch again after the anchor. */
	if (strcmp(argv[1], "first-write") == 0 && argc == 3) {
		uint8_t branch_written[32], branch_init[32], policy[32];
		struct shirudo_eventlog_init rec;
		struct shirudo_tpm *tpm = NULL;

		if (shirudo_hex_decode(argv[2], event, 32) ||
		    shirudo_eventlog_boot_init(&rec))
			return 2;
		shirudo_tpm_register_policy(SHIRUDO_CHAIN_PCR_MASK,
					    rec.pcr_before, branch_written,
					    branch_init, policy);
		if (shirudo_tpm_open(&tpm))
			return 1;
		rc = shirudo_tpm_nv_extend_first(tpm, SHIRUDO_NV_INDEX,
						 SHIRUDO_CHAIN_PCR_MASK,
						 branch_written, branch_init,
						 event);
		shirudo_tpm_close(tpm);
		printf("rc=%d\n", rc);
		return rc ? 1 : 0;
	}
	if (strcmp(argv[1], "evidence") == 0 && argc == 3) {
		uint8_t nonce[64];
		size_t nonce_len = strlen(argv[2]) / 2, len, cap;
		char *doc;

		if (nonce_len > sizeof(nonce) ||
		    shirudo_hex_decode(argv[2], nonce, nonce_len))
			return 2;
		rc = shirudo_attest_evidence(nonce, nonce_len,
					     SHIRUDO_ATTEST_PCR_DEFAULT, &doc,
					     &len, &cap);
		if (rc) {
			fprintf(stderr, "evidence: %s\n", strerror(-rc));
			return 1;
		}
		fwrite(doc, 1, len, stdout);
		fputc('\n', stdout);
		xfree(doc, cap);
		return 0;
	}
	return 2;
}
