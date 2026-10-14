/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libtss2 wrappers for the measurement register and attestation.
 */

#ifndef SHIRUDO_TPM_H
#define SHIRUDO_TPM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tpm_wire.h"

#define SHIRUDO_TPM_NV_DIGEST_LEN	SHIRUDO_TPM_DIGEST_LEN
#define SHIRUDO_TPM_PUBLIC_MAX		256
#define SHIRUDO_TPM_ATTEST_MAX		1024
#define SHIRUDO_TPM_SIGNATURE_MAX	160
#define SHIRUDO_TPM_NONCE_MAX		64

struct shirudo_tpm;

int shirudo_tpm_open(struct shirudo_tpm **out);
void shirudo_tpm_close(struct shirudo_tpm *t);

/* PCRs of the SHA-256 bank. */
int shirudo_tpm_pcr_read(struct shirudo_tpm *t, unsigned int pcr,
			 uint8_t out[SHIRUDO_TPM_DIGEST_LEN]);
int shirudo_tpm_pcr_extend(struct shirudo_tpm *t, unsigned int pcr,
			   const uint8_t digest[SHIRUDO_TPM_DIGEST_LEN]);

struct shirudo_tpm_nv_info {
	bool		defined;
	bool		written;
	uint32_t	attrs;
	uint16_t	data_size;
	uint8_t		policy[SHIRUDO_TPM_DIGEST_LEN];
	uint8_t		name[SHIRUDO_TPM_NAME_LEN];
	size_t		name_len;
};

/*
 * The measurement register is an NV index with the attributes and the
 * write policy from tpm_wire.h. Defining and undefining it is owner
 * authorised; owner_auth/owner_auth_len carry that hierarchy's
 * password when set, NULL/0 for the empty default. Reads need no
 * authorisation. Extends present one of the two policy branches:
 * the first write of a boot the init branch, which TPM2_PolicyPCR
 * only satisfies while the anchoring PCR still holds the value the
 * policy was computed from, every later one the written branch.
 */
int shirudo_tpm_nv_info(struct shirudo_tpm *t, uint32_t index,
			struct shirudo_tpm_nv_info *info);
int shirudo_tpm_nv_define(struct shirudo_tpm *t, uint32_t index,
			  const uint8_t policy[SHIRUDO_TPM_DIGEST_LEN],
			  const void *owner_auth, size_t owner_auth_len);
int shirudo_tpm_nv_undefine(struct shirudo_tpm *t, uint32_t index,
			    const void *owner_auth, size_t owner_auth_len);
/* -ENOENT: not defined; -ENODATA: defined but not written this boot. */
int shirudo_tpm_nv_read(struct shirudo_tpm *t, uint32_t index,
			uint8_t out[SHIRUDO_TPM_DIGEST_LEN]);
int shirudo_tpm_nv_extend_first(struct shirudo_tpm *t, uint32_t index,
				uint32_t pcr_mask,
				const uint8_t branch_written[32],
				const uint8_t branch_init[32],
				const uint8_t event[32]);
int shirudo_tpm_nv_extend(struct shirudo_tpm *t, uint32_t index,
			  const uint8_t branch_written[32],
			  const uint8_t branch_init[32],
			  const uint8_t event[32]);

/*
 * The attestation key: a restricted P-256 ECDSA primary under the
 * endorsement hierarchy with a fixed template, so the same TPM always
 * yields the same key and an operator can pin it by name.
 */
struct shirudo_tpm_key {
	uint32_t	handle;
	uint8_t		public[SHIRUDO_TPM_PUBLIC_MAX];
	size_t		public_len;
	uint8_t		name[SHIRUDO_TPM_NAME_LEN];
	size_t		name_len;
};

struct shirudo_tpm_attestation {
	uint8_t		attest[SHIRUDO_TPM_ATTEST_MAX];
	size_t		attest_len;
	uint8_t		signature[SHIRUDO_TPM_SIGNATURE_MAX];
	size_t		signature_len;
};

int shirudo_tpm_ak_create(struct shirudo_tpm *t, struct shirudo_tpm_key *ak);
void shirudo_tpm_key_flush(struct shirudo_tpm *t, struct shirudo_tpm_key *key);
int shirudo_tpm_quote(struct shirudo_tpm *t, const struct shirudo_tpm_key *ak,
		      const uint8_t *nonce, size_t nonce_len, uint32_t pcr_mask,
		      struct shirudo_tpm_attestation *out);
int shirudo_tpm_nv_certify(struct shirudo_tpm *t,
			   const struct shirudo_tpm_key *ak, uint32_t index,
			   const uint8_t *nonce, size_t nonce_len,
			   struct shirudo_tpm_attestation *out);

/* The endorsement key certificate from its TCG NV index; -ENOENT if none. */
int shirudo_tpm_ek_certificate(struct shirudo_tpm *t, uint8_t *out,
			       size_t cap, size_t *len);

#endif /* SHIRUDO_TPM_H */
