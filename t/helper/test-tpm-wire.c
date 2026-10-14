// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Harness for util/tpm_wire: policy digests, names and attestation
 * structure parsing. Subcommand on argv[1]; hex inputs as argv.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hex.h"
#include "tpm_wire.h"

static void puthex(const uint8_t *b, size_t n)
{
	char h[2 * 2048 + 1];

	if (n > 2048)
		return;
	shirudo_hex_encode(b, n, h);
	printf("%s\n", h);
}

static int gethex(const char *hex, uint8_t *out, size_t cap, size_t *len)
{
	size_t n = strlen(hex);

	if (n & 1 || n / 2 > cap)
		return -1;
	*len = n / 2;
	return shirudo_hex_decode(hex, out, n / 2);
}

int main(int argc, char **argv)
{
	uint8_t a[32], b[32], out[32], buf[2048];
	size_t len;

	if (argc < 2)
		return 2;
	if (strcmp(argv[1], "nv-written") == 0 && argc == 4) {
		if (shirudo_hex_decode(argv[2], a, 32))
			return 2;
		shirudo_tpm_policy_nv_written(a, atoi(argv[3]) != 0, out);
		puthex(out, 32);
		return 0;
	}
	if (strcmp(argv[1], "pcr") == 0 && argc == 5) {
		if (shirudo_hex_decode(argv[2], a, 32) ||
		    shirudo_hex_decode(argv[4], b, 32))
			return 2;
		shirudo_tpm_policy_pcr(a, (uint32_t)strtoul(argv[3], NULL, 0),
				       b, out);
		puthex(out, 32);
		return 0;
	}
	if (strcmp(argv[1], "or") == 0 && argc == 4) {
		if (shirudo_hex_decode(argv[2], a, 32) ||
		    shirudo_hex_decode(argv[3], b, 32))
			return 2;
		shirudo_tpm_policy_or(a, b, out);
		puthex(out, 32);
		return 0;
	}
	if (strcmp(argv[1], "register-policy") == 0 && argc == 4) {
		uint8_t w[32], i[32], p[32];

		if (shirudo_hex_decode(argv[3], a, 32))
			return 2;
		shirudo_tpm_register_policy((uint32_t)strtoul(argv[2], NULL, 0),
					    a, w, i, p);
		puthex(w, 32);
		puthex(i, 32);
		puthex(p, 32);
		return 0;
	}
	if (strcmp(argv[1], "nv-name") == 0 && argc == 5) {
		uint8_t name[SHIRUDO_TPM_NAME_LEN];

		if (shirudo_hex_decode(argv[4], a, 32))
			return 2;
		shirudo_tpm_nv_name((uint32_t)strtoul(argv[2], NULL, 0),
				    (uint32_t)strtoul(argv[3], NULL, 0), a, 32,
				    name);
		puthex(name, sizeof(name));
		return 0;
	}
	if (strcmp(argv[1], "object-name") == 0 && argc == 3) {
		uint8_t name[SHIRUDO_TPM_NAME_LEN];

		if (gethex(argv[2], buf, sizeof(buf), &len) ||
		    shirudo_tpm_object_name(buf, len, name))
			return 1;
		puthex(name, sizeof(name));
		return 0;
	}
	if (strcmp(argv[1], "ecc-public") == 0 && argc == 3) {
		struct shirudo_tpm_ecc_public pub;
		int rc;

		if (gethex(argv[2], buf, sizeof(buf), &len))
			return 2;
		rc = shirudo_tpm_ecc_public_parse(buf, len, &pub);
		printf("rc=%d\n", rc);
		if (rc)
			return 0;
		printf("attrs=0x%08x scheme=0x%04x hash=0x%04x curve=0x%04x\n",
		       pub.attrs, pub.scheme, pub.hash, pub.curve);
		puthex(pub.x, 32);
		puthex(pub.y, 32);
		return 0;
	}
	if (strcmp(argv[1], "signature") == 0 && argc == 3) {
		uint8_t r[32], s[32];
		int rc;

		if (gethex(argv[2], buf, sizeof(buf), &len))
			return 2;
		rc = shirudo_tpm_ecdsa_signature_parse(buf, len, r, s);
		printf("rc=%d\n", rc);
		if (rc)
			return 0;
		puthex(r, 32);
		puthex(s, 32);
		return 0;
	}
	if (strcmp(argv[1], "attest") == 0 && argc == 3) {
		struct shirudo_tpm_attest at;
		int rc;

		if (gethex(argv[2], buf, sizeof(buf), &len))
			return 2;
		rc = shirudo_tpm_attest_parse(buf, len, &at);
		printf("rc=%d\n", rc);
		if (rc)
			return 0;
		printf("type=0x%04x reset=%u restart=%u safe=%d\n", at.type,
		       at.reset_count, at.restart_count, at.safe);
		printf("signer=");
		puthex(at.signer, at.signer_len);
		printf("extra=");
		puthex(at.extra, at.extra_len);
		if (at.type == SHIRUDO_TPM_ST_ATTEST_QUOTE) {
			printf("mask=0x%06x\n", at.pcr_mask);
			printf("pcr_digest=");
			puthex(at.pcr_digest, 32);
		} else {
			printf("index_name=");
			puthex(at.index_name, at.index_name_len);
			printf("offset=%u\nnv=", at.offset);
			puthex(at.nv_data, at.nv_len);
		}
		return 0;
	}
	return 2;
}
