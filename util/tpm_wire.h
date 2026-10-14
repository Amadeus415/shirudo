/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * TPM 2.0 wire-format helpers that need no TPM: policy digests, NV and
 * object names, and the attestation structures a verifier parses.
 */

#ifndef SHIRUDO_TPM_WIRE_H
#define SHIRUDO_TPM_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHIRUDO_TPM_DIGEST_LEN		32
#define SHIRUDO_TPM_NAME_LEN		(2 + SHIRUDO_TPM_DIGEST_LEN)
#define SHIRUDO_TPM_ALG_RSA		0x0001u
#define SHIRUDO_TPM_ALG_AES		0x0006u
#define SHIRUDO_TPM_ALG_SHA256		0x000Bu
#define SHIRUDO_TPM_ALG_ECC		0x0023u
#define SHIRUDO_TPM_ALG_ECDSA		0x0018u
#define SHIRUDO_TPM_ALG_NULL		0x0010u
#define SHIRUDO_TPM_ALG_CFB		0x0043u
#define SHIRUDO_TPM_ECC_NIST_P256	0x0003u
#define SHIRUDO_TPM_ST_ATTEST_NV	0x8014u
#define SHIRUDO_TPM_ST_ATTEST_QUOTE	0x8018u
#define SHIRUDO_TPM_GENERATED		0xFF544347u
#define SHIRUDO_TPM_PCR_SELECT_LEN	3
#define SHIRUDO_TPM_PCR_SELECTION_LEN	(7 + SHIRUDO_TPM_PCR_SELECT_LEN)

/*
 * Attributes of the measurement register: an extend-only NV index
 * whose contents clear at every TPM reset, written only under its
 * policy, readable by anyone, kept in TPM RAM until an orderly
 * shutdown (TPMA_NV_CLEAR_STCLEAR | ORDERLY | POLICYWRITE | OWNERREAD |
 * AUTHREAD | NO_DA | TPM2_NT_EXTEND).
 */
#define SHIRUDO_TPM_REGISTER_ATTRS	0x0E060048u
#define SHIRUDO_TPM_NV_WRITTEN		0x20000000u

/* Policy digest evolution for the assertions the register uses. */
void shirudo_tpm_policy_nv_written(const uint8_t prev[SHIRUDO_TPM_DIGEST_LEN],
				   bool written,
				   uint8_t out[SHIRUDO_TPM_DIGEST_LEN]);
void shirudo_tpm_policy_pcr(const uint8_t prev[SHIRUDO_TPM_DIGEST_LEN],
			    uint32_t pcr_mask,
			    const uint8_t pcr_digest[SHIRUDO_TPM_DIGEST_LEN],
			    uint8_t out[SHIRUDO_TPM_DIGEST_LEN]);
void shirudo_tpm_policy_or(const uint8_t a[SHIRUDO_TPM_DIGEST_LEN],
			   const uint8_t b[SHIRUDO_TPM_DIGEST_LEN],
			   uint8_t out[SHIRUDO_TPM_DIGEST_LEN]);

/*
 * The register's write policy from the values the binding PCRs held
 * at binding time, given in PCR order: PolicyOR(PolicyNvWritten(YES),
 * PolicyNvWritten(NO) + PolicyPCR(mask, SHA-256(values))). The two
 * branch digests are what a session has to present to PolicyOR.
 */
void shirudo_tpm_register_policy(uint32_t pcr_mask,
				 const uint8_t *pcr_values, size_t n_values,
				 uint8_t branch_written[32],
				 uint8_t branch_init[32],
				 uint8_t policy[32]);

/* TPML_PCR_SELECTION with one SHA-256 bank over the 24 PCRs in mask. */
void shirudo_tpm_pcr_selection(uint32_t pcr_mask,
			       uint8_t out[SHIRUDO_TPM_PCR_SELECTION_LEN]);

/* Name of an NV index: nameAlg || SHA-256(TPMS_NV_PUBLIC). */
void shirudo_tpm_nv_name(uint32_t index, uint32_t attrs,
			 const uint8_t policy[SHIRUDO_TPM_DIGEST_LEN],
			 uint16_t data_size,
			 uint8_t name[SHIRUDO_TPM_NAME_LEN]);

/* Name of a SHA-256-named object from its marshalled TPMT_PUBLIC. */
int shirudo_tpm_object_name(const uint8_t *public, size_t len,
			    uint8_t name[SHIRUDO_TPM_NAME_LEN]);

/*
 * Qualified name of a primary object: nameAlg || SHA-256(hierarchy
 * handle || name). Attestations carry the signer's qualified name.
 */
#define SHIRUDO_TPM_RH_ENDORSEMENT	0x4000000Bu
void shirudo_tpm_qualified_name(uint32_t hierarchy,
				const uint8_t name[SHIRUDO_TPM_NAME_LEN],
				uint8_t out[SHIRUDO_TPM_NAME_LEN]);

/*
 * The TCG default endorsement key templates: a restricted decryption
 * key under the endorsement hierarchy's policy, protecting with
 * AES-128-CFB (fixedTPM | fixedParent | sensitiveDataOrigin |
 * adminWithPolicy | restricted | decrypt).
 */
#define SHIRUDO_TPM_EK_ATTRS		0x000300B2u
extern const uint8_t shirudo_tpm_ek_policy[SHIRUDO_TPM_DIGEST_LEN];

/*
 * A TPMT_PUBLIC of the shapes shirudo makes or checks: a SHA-256-named
 * P-256 or RSA-2048 key, its symmetric protector absent or
 * AES-128-CFB, its scheme absent or ECDSA with SHA-256.
 */
struct shirudo_tpm_public {
	uint16_t	type;
	uint32_t	attrs;
	size_t		policy_len;	/* 0 or 32 */
	uint8_t		policy[SHIRUDO_TPM_DIGEST_LEN];
	uint16_t	sym_alg;
	uint16_t	sym_bits;
	uint16_t	sym_mode;
	uint16_t	scheme;
	uint16_t	scheme_hash;
	uint16_t	curve;		/* ECC */
	uint8_t		x[32];
	uint8_t		y[32];
	uint16_t	rsa_bits;	/* RSA */
	uint32_t	rsa_exponent;
	size_t		n_len;
	uint8_t		n[256];
};

int shirudo_tpm_public_parse(const uint8_t *buf, size_t len,
			     struct shirudo_tpm_public *out);
int shirudo_tpm_public_marshal(const struct shirudo_tpm_public *pub,
			       uint8_t *out, size_t cap, size_t *len);

struct shirudo_tpm_ecc_public {
	uint32_t	attrs;
	uint16_t	scheme;
	uint16_t	hash;
	uint16_t	curve;
	uint8_t		x[32];
	uint8_t		y[32];
};

/* Parse a marshalled TPMT_PUBLIC of a P-256 ECDSA key. */
int shirudo_tpm_ecc_public_parse(const uint8_t *buf, size_t len,
				 struct shirudo_tpm_ecc_public *out);

/*
 * The key derivations of TPM 2.0 Part 1 with SHA-256: KDFa (SP800-108
 * in counter mode) and KDFe (SP800-56A one-step). Labels are given
 * without their terminating NUL, which the derivation adds.
 */
int shirudo_tpm_kdfa(const uint8_t *key, size_t key_len, const char *label,
		     const uint8_t *ctx_u, size_t u_len,
		     const uint8_t *ctx_v, size_t v_len,
		     uint8_t *out, size_t out_len);
void shirudo_tpm_kdfe(const uint8_t z[32], const char *label,
		      const uint8_t *party_u, size_t u_len,
		      const uint8_t *party_v, size_t v_len, uint8_t out[32]);

/*
 * Credential protection (Part 1, 24.4): from a seed shared with the
 * endorsement key, the TPM2B_ID_OBJECT contents that
 * TPM2_ActivateCredential accepts for the object of the given name:
 * the integrity HMAC and the credential encrypted under keys both
 * derived from the seed and the name.
 */
#define SHIRUDO_TPM_CREDENTIAL_LEN	32
#define SHIRUDO_TPM_ID_OBJECT_LEN	(2 + 32 + 2 + SHIRUDO_TPM_CREDENTIAL_LEN)
int shirudo_tpm_credential_protect(const uint8_t seed[32],
				   const uint8_t name[SHIRUDO_TPM_NAME_LEN],
				   const uint8_t credential[SHIRUDO_TPM_CREDENTIAL_LEN],
				   uint8_t out[SHIRUDO_TPM_ID_OBJECT_LEN]);

/* Parse a marshalled TPMT_SIGNATURE carrying ECDSA/SHA-256 r and s. */
int shirudo_tpm_ecdsa_signature_parse(const uint8_t *buf, size_t len,
				      uint8_t r[32], uint8_t s[32]);

struct shirudo_tpm_attest {
	uint16_t	type;
	uint8_t		signer[SHIRUDO_TPM_NAME_LEN];
	size_t		signer_len;
	const uint8_t	*extra;
	size_t		extra_len;
	uint64_t	clock;
	uint32_t	reset_count;
	uint32_t	restart_count;
	bool		safe;
	uint64_t	firmware_version;
	/* TPM_ST_ATTEST_QUOTE */
	uint32_t	pcr_mask;
	uint8_t		pcr_digest[SHIRUDO_TPM_DIGEST_LEN];
	/* TPM_ST_ATTEST_NV */
	uint8_t		index_name[SHIRUDO_TPM_NAME_LEN];
	size_t		index_name_len;
	uint16_t	offset;
	const uint8_t	*nv_data;
	size_t		nv_len;
};

/*
 * Parse a TPMS_ATTEST produced by TPM2_Quote or TPM2_NV_Certify. Only a
 * single SHA-256 PCR bank is accepted in a quote. Pointers into the
 * input stay valid as long as buf does.
 */
int shirudo_tpm_attest_parse(const uint8_t *buf, size_t len,
			     struct shirudo_tpm_attest *out);

#endif /* SHIRUDO_TPM_WIRE_H */
