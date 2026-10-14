// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * TPM 2.0 wire-format helpers shared by the target and the verifier.
 */

#include <errno.h>
#include <string.h>

#include "crypto.h"
#include "tpm_wire.h"

#define TPM_CC_POLICY_OR		0x00000171u
#define TPM_CC_POLICY_PCR		0x0000017Fu
#define TPM_CC_POLICY_NV_WRITTEN	0x0000018Fu

struct reader {
	const uint8_t	*p;
	size_t		left;
};

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static int get8(struct reader *r, uint8_t *v)
{
	if (r->left < 1)
		return -EINVAL;
	*v = r->p[0];
	r->p++;
	r->left--;
	return 0;
}

static int get16(struct reader *r, uint16_t *v)
{
	if (r->left < 2)
		return -EINVAL;
	*v = (uint16_t)(((uint16_t)r->p[0] << 8) | r->p[1]);
	r->p += 2;
	r->left -= 2;
	return 0;
}

static int get32(struct reader *r, uint32_t *v)
{
	if (r->left < 4)
		return -EINVAL;
	*v = ((uint32_t)r->p[0] << 24) | ((uint32_t)r->p[1] << 16) |
	     ((uint32_t)r->p[2] << 8) | r->p[3];
	r->p += 4;
	r->left -= 4;
	return 0;
}

static int get64(struct reader *r, uint64_t *v)
{
	uint32_t hi, lo;

	if (get32(r, &hi) || get32(r, &lo))
		return -EINVAL;
	*v = ((uint64_t)hi << 32) | lo;
	return 0;
}

/* A TPM2B: 16-bit size then that many bytes, returned by reference. */
static int get2b(struct reader *r, const uint8_t **data, size_t *len,
		 size_t max)
{
	uint16_t n;

	if (get16(r, &n) || n > r->left || n > max)
		return -EINVAL;
	*data = r->p;
	*len = n;
	r->p += n;
	r->left -= n;
	return 0;
}

static int get2b_fixed(struct reader *r, uint8_t *out, size_t want)
{
	const uint8_t *d;
	size_t n;

	if (get2b(r, &d, &n, want) || n != want)
		return -EINVAL;
	memcpy(out, d, n);
	return 0;
}

static void policy_hash(const uint8_t prev[32], uint32_t cc,
			const uint8_t *a, size_t a_len,
			const uint8_t *b, size_t b_len, uint8_t out[32])
{
	struct shirudo_sha256_ctx ctx;
	uint8_t cc_be[4];

	put32(cc_be, cc);
	if (shirudo_sha256_init(&ctx) != 0) {
		memset(out, 0, 32);
		return;
	}
	if (shirudo_sha256_update(&ctx, prev, 32) != 0 ||
	    shirudo_sha256_update(&ctx, cc_be, sizeof(cc_be)) != 0 ||
	    (a_len && shirudo_sha256_update(&ctx, a, a_len) != 0) ||
	    (b_len && shirudo_sha256_update(&ctx, b, b_len) != 0) ||
	    shirudo_sha256_final(&ctx, out) != 0) {
		memset(out, 0, 32);
		shirudo_sha256_free(&ctx);
	}
}

void shirudo_tpm_policy_nv_written(const uint8_t prev[32], bool written,
				   uint8_t out[32])
{
	uint8_t set = written ? 1 : 0;

	policy_hash(prev, TPM_CC_POLICY_NV_WRITTEN, &set, 1, NULL, 0, out);
}

void shirudo_tpm_pcr_selection(uint32_t pcr_mask,
			       uint8_t out[SHIRUDO_TPM_PCR_SELECTION_LEN])
{
	put32(out, 1);
	put16(out + 4, SHIRUDO_TPM_ALG_SHA256);
	out[6] = SHIRUDO_TPM_PCR_SELECT_LEN;
	out[7] = (uint8_t)pcr_mask;
	out[8] = (uint8_t)(pcr_mask >> 8);
	out[9] = (uint8_t)(pcr_mask >> 16);
}

void shirudo_tpm_policy_pcr(const uint8_t prev[32], uint32_t pcr_mask,
			    const uint8_t pcr_digest[32], uint8_t out[32])
{
	uint8_t sel[SHIRUDO_TPM_PCR_SELECTION_LEN];

	shirudo_tpm_pcr_selection(pcr_mask, sel);
	policy_hash(prev, TPM_CC_POLICY_PCR, sel, sizeof(sel), pcr_digest, 32,
		    out);
}

void shirudo_tpm_policy_or(const uint8_t a[32], const uint8_t b[32],
			   uint8_t out[32])
{
	static const uint8_t zero[32];

	policy_hash(zero, TPM_CC_POLICY_OR, a, 32, b, 32, out);
}

void shirudo_tpm_register_policy(uint32_t pcr_mask,
				 const uint8_t pcr_value[32],
				 uint8_t branch_written[32],
				 uint8_t branch_init[32], uint8_t policy[32])
{
	static const uint8_t zero[32];
	uint8_t pcr_digest[32], unwritten[32];

	shirudo_tpm_policy_nv_written(zero, true, branch_written);
	shirudo_tpm_policy_nv_written(zero, false, unwritten);
	shirudo_sha256_buffer(pcr_value, 32, pcr_digest);
	shirudo_tpm_policy_pcr(unwritten, pcr_mask, pcr_digest, branch_init);
	shirudo_tpm_policy_or(branch_written, branch_init, policy);
}

void shirudo_tpm_nv_name(uint32_t index, uint32_t attrs,
			 const uint8_t policy[32], uint16_t data_size,
			 uint8_t name[SHIRUDO_TPM_NAME_LEN])
{
	uint8_t pub[4 + 2 + 4 + 2 + 32 + 2];

	put32(pub, index);
	put16(pub + 4, SHIRUDO_TPM_ALG_SHA256);
	put32(pub + 6, attrs);
	put16(pub + 10, 32);
	memcpy(pub + 12, policy, 32);
	put16(pub + 44, data_size);
	put16(name, SHIRUDO_TPM_ALG_SHA256);
	shirudo_sha256_buffer(pub, sizeof(pub), name + 2);
}

int shirudo_tpm_object_name(const uint8_t *public, size_t len,
			    uint8_t name[SHIRUDO_TPM_NAME_LEN])
{
	struct reader r = { public, len };
	uint16_t type, alg;

	if (get16(&r, &type) || get16(&r, &alg) ||
	    alg != SHIRUDO_TPM_ALG_SHA256)
		return -EINVAL;
	put16(name, SHIRUDO_TPM_ALG_SHA256);
	shirudo_sha256_buffer(public, len, name + 2);
	return 0;
}

void shirudo_tpm_qualified_name(uint32_t hierarchy,
				const uint8_t name[SHIRUDO_TPM_NAME_LEN],
				uint8_t out[SHIRUDO_TPM_NAME_LEN])
{
	uint8_t buf[4 + SHIRUDO_TPM_NAME_LEN];

	put32(buf, hierarchy);
	memcpy(buf + 4, name, SHIRUDO_TPM_NAME_LEN);
	put16(out, SHIRUDO_TPM_ALG_SHA256);
	shirudo_sha256_buffer(buf, sizeof(buf), out + 2);
}

int shirudo_tpm_ecc_public_parse(const uint8_t *buf, size_t len,
				 struct shirudo_tpm_ecc_public *out)
{
	struct reader r = { buf, len };
	uint16_t type, alg, sym, kdf;
	const uint8_t *policy;
	size_t policy_len;

	memset(out, 0, sizeof(*out));
	if (get16(&r, &type) || type != SHIRUDO_TPM_ALG_ECC ||
	    get16(&r, &alg) || alg != SHIRUDO_TPM_ALG_SHA256 ||
	    get32(&r, &out->attrs) ||
	    get2b(&r, &policy, &policy_len, 64) ||
	    get16(&r, &sym) || sym != SHIRUDO_TPM_ALG_NULL ||
	    get16(&r, &out->scheme))
		return -EINVAL;
	if (out->scheme != SHIRUDO_TPM_ALG_NULL && get16(&r, &out->hash))
		return -EINVAL;
	if (get16(&r, &out->curve) || get16(&r, &kdf) ||
	    kdf != SHIRUDO_TPM_ALG_NULL ||
	    get2b_fixed(&r, out->x, 32) || get2b_fixed(&r, out->y, 32) ||
	    r.left != 0)
		return -EINVAL;
	if (out->scheme != SHIRUDO_TPM_ALG_ECDSA ||
	    out->hash != SHIRUDO_TPM_ALG_SHA256 ||
	    out->curve != SHIRUDO_TPM_ECC_NIST_P256)
		return -EPROTONOSUPPORT;
	return 0;
}

int shirudo_tpm_ecdsa_signature_parse(const uint8_t *buf, size_t len,
				      uint8_t r_out[32], uint8_t s_out[32])
{
	struct reader r = { buf, len };
	uint16_t alg, hash;

	if (get16(&r, &alg) || alg != SHIRUDO_TPM_ALG_ECDSA ||
	    get16(&r, &hash) || hash != SHIRUDO_TPM_ALG_SHA256 ||
	    get2b_fixed(&r, r_out, 32) || get2b_fixed(&r, s_out, 32) ||
	    r.left != 0)
		return -EINVAL;
	return 0;
}

static int get_name(struct reader *r, uint8_t *name, size_t *name_len)
{
	const uint8_t *d;
	size_t n;

	if (get2b(r, &d, &n, SHIRUDO_TPM_NAME_LEN))
		return -EINVAL;
	memcpy(name, d, n);
	*name_len = n;
	return 0;
}

int shirudo_tpm_attest_parse(const uint8_t *buf, size_t len,
			     struct shirudo_tpm_attest *out)
{
	struct reader r = { buf, len };
	uint32_t magic;
	uint8_t safe;

	memset(out, 0, sizeof(*out));
	if (get32(&r, &magic) || magic != SHIRUDO_TPM_GENERATED ||
	    get16(&r, &out->type) ||
	    get_name(&r, out->signer, &out->signer_len) ||
	    get2b(&r, &out->extra, &out->extra_len, 64) ||
	    get64(&r, &out->clock) || get32(&r, &out->reset_count) ||
	    get32(&r, &out->restart_count) || get8(&r, &safe) ||
	    get64(&r, &out->firmware_version))
		return -EINVAL;
	out->safe = safe != 0;

	if (out->type == SHIRUDO_TPM_ST_ATTEST_QUOTE) {
		uint32_t count;
		uint16_t alg;
		uint8_t n;

		if (get32(&r, &count) || count != 1 || get16(&r, &alg) ||
		    alg != SHIRUDO_TPM_ALG_SHA256 || get8(&r, &n) ||
		    n != SHIRUDO_TPM_PCR_SELECT_LEN || r.left < n)
			return -EINVAL;
		out->pcr_mask = (uint32_t)r.p[0] | ((uint32_t)r.p[1] << 8) |
				((uint32_t)r.p[2] << 16);
		r.p += n;
		r.left -= n;
		if (get2b_fixed(&r, out->pcr_digest, 32) || r.left != 0)
			return -EINVAL;
		return 0;
	}
	if (out->type == SHIRUDO_TPM_ST_ATTEST_NV) {
		if (get_name(&r, out->index_name, &out->index_name_len) ||
		    get16(&r, &out->offset) ||
		    get2b(&r, &out->nv_data, &out->nv_len, 2048) ||
		    r.left != 0)
			return -EINVAL;
		return 0;
	}
	return -EPROTONOSUPPORT;
}
