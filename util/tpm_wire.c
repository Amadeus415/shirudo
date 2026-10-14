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
				 const uint8_t *pcr_values, size_t n_values,
				 uint8_t branch_written[32],
				 uint8_t branch_init[32], uint8_t policy[32])
{
	static const uint8_t zero[32];
	uint8_t pcr_digest[32], unwritten[32];

	shirudo_tpm_policy_nv_written(zero, true, branch_written);
	shirudo_tpm_policy_nv_written(zero, false, unwritten);
	shirudo_sha256_buffer(pcr_values, 32 * n_values, pcr_digest);
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

const uint8_t shirudo_tpm_ek_policy[32] = {
	0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc,
	0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52,
	0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
};

int shirudo_tpm_public_parse(const uint8_t *buf, size_t len,
			     struct shirudo_tpm_public *out)
{
	struct reader r = { buf, len };
	const uint8_t *policy, *n;
	uint16_t name_alg, kdf;

	memset(out, 0, sizeof(*out));
	if (get16(&r, &out->type) || get16(&r, &name_alg) ||
	    name_alg != SHIRUDO_TPM_ALG_SHA256 || get32(&r, &out->attrs) ||
	    get2b(&r, &policy, &out->policy_len, 32) ||
	    (out->policy_len && out->policy_len != 32))
		return -EINVAL;
	memcpy(out->policy, policy, out->policy_len);
	if (get16(&r, &out->sym_alg))
		return -EINVAL;
	if (out->sym_alg != SHIRUDO_TPM_ALG_NULL &&
	    (get16(&r, &out->sym_bits) || get16(&r, &out->sym_mode)))
		return -EINVAL;
	if (get16(&r, &out->scheme))
		return -EINVAL;
	if (out->scheme != SHIRUDO_TPM_ALG_NULL && get16(&r, &out->scheme_hash))
		return -EINVAL;
	if (out->type == SHIRUDO_TPM_ALG_ECC) {
		if (get16(&r, &out->curve) || get16(&r, &kdf) ||
		    kdf != SHIRUDO_TPM_ALG_NULL ||
		    get2b_fixed(&r, out->x, 32) || get2b_fixed(&r, out->y, 32))
			return -EINVAL;
	} else if (out->type == SHIRUDO_TPM_ALG_RSA) {
		if (get16(&r, &out->rsa_bits) || get32(&r, &out->rsa_exponent) ||
		    get2b(&r, &n, &out->n_len, sizeof(out->n)))
			return -EINVAL;
		memcpy(out->n, n, out->n_len);
	} else {
		return -EPROTONOSUPPORT;
	}
	if (r.left != 0)
		return -EINVAL;
	if ((out->sym_alg != SHIRUDO_TPM_ALG_NULL &&
	     (out->sym_alg != SHIRUDO_TPM_ALG_AES || out->sym_bits != 128 ||
	      out->sym_mode != SHIRUDO_TPM_ALG_CFB)) ||
	    (out->scheme != SHIRUDO_TPM_ALG_NULL &&
	     (out->scheme != SHIRUDO_TPM_ALG_ECDSA ||
	      out->scheme_hash != SHIRUDO_TPM_ALG_SHA256)) ||
	    (out->type == SHIRUDO_TPM_ALG_ECC &&
	     out->curve != SHIRUDO_TPM_ECC_NIST_P256) ||
	    (out->type == SHIRUDO_TPM_ALG_RSA &&
	     (out->rsa_bits != 2048 || out->n_len != 256)))
		return -EPROTONOSUPPORT;
	return 0;
}

static size_t put2b(uint8_t *p, const uint8_t *data, size_t len)
{
	put16(p, (uint16_t)len);
	memcpy(p + 2, data, len);
	return 2 + len;
}

int shirudo_tpm_public_marshal(const struct shirudo_tpm_public *pub,
			       uint8_t *out, size_t cap, size_t *len)
{
	size_t need = 2 + 2 + 4 + 2 + pub->policy_len + 2 + 2, off = 0;

	if (pub->policy_len != 0 && pub->policy_len != 32)
		return -EINVAL;
	if (pub->sym_alg != SHIRUDO_TPM_ALG_NULL)
		need += 4;
	if (pub->scheme != SHIRUDO_TPM_ALG_NULL)
		need += 2;
	if (pub->type == SHIRUDO_TPM_ALG_ECC)
		need += 2 + 2 + 2 + 32 + 2 + 32;
	else if (pub->type == SHIRUDO_TPM_ALG_RSA && pub->n_len <= sizeof(pub->n))
		need += 2 + 4 + 2 + pub->n_len;
	else
		return -EINVAL;
	if (cap < need)
		return -E2BIG;
	put16(out + off, pub->type);
	off += 2;
	put16(out + off, SHIRUDO_TPM_ALG_SHA256);
	off += 2;
	put32(out + off, pub->attrs);
	off += 4;
	off += put2b(out + off, pub->policy, pub->policy_len);
	put16(out + off, pub->sym_alg);
	off += 2;
	if (pub->sym_alg != SHIRUDO_TPM_ALG_NULL) {
		put16(out + off, pub->sym_bits);
		put16(out + off + 2, pub->sym_mode);
		off += 4;
	}
	put16(out + off, pub->scheme);
	off += 2;
	if (pub->scheme != SHIRUDO_TPM_ALG_NULL) {
		put16(out + off, pub->scheme_hash);
		off += 2;
	}
	if (pub->type == SHIRUDO_TPM_ALG_ECC) {
		put16(out + off, pub->curve);
		put16(out + off + 2, SHIRUDO_TPM_ALG_NULL);
		off += 4;
		off += put2b(out + off, pub->x, 32);
		off += put2b(out + off, pub->y, 32);
	} else {
		put16(out + off, pub->rsa_bits);
		put32(out + off + 2, pub->rsa_exponent);
		off += 6;
		off += put2b(out + off, pub->n, pub->n_len);
	}
	*len = off;
	return 0;
}

int shirudo_tpm_ecc_public_parse(const uint8_t *buf, size_t len,
				 struct shirudo_tpm_ecc_public *out)
{
	struct shirudo_tpm_public pub;
	int rc;

	memset(out, 0, sizeof(*out));
	rc = shirudo_tpm_public_parse(buf, len, &pub);
	if (rc)
		return rc;
	if (pub.type != SHIRUDO_TPM_ALG_ECC ||
	    pub.sym_alg != SHIRUDO_TPM_ALG_NULL ||
	    pub.scheme != SHIRUDO_TPM_ALG_ECDSA)
		return -EPROTONOSUPPORT;
	out->attrs = pub.attrs;
	out->scheme = pub.scheme;
	out->hash = pub.scheme_hash;
	out->curve = pub.curve;
	memcpy(out->x, pub.x, 32);
	memcpy(out->y, pub.y, 32);
	return 0;
}

int shirudo_tpm_kdfa(const uint8_t *key, size_t key_len, const char *label,
		     const uint8_t *ctx_u, size_t u_len,
		     const uint8_t *ctx_v, size_t v_len,
		     uint8_t *out, size_t out_len)
{
	uint8_t buf[4 + 64 + 1 + 2 * SHIRUDO_TPM_NAME_LEN + 4], block[32];
	size_t label_len = strlen(label), done = 0, off, n;
	uint32_t i;

	if (label_len > 64 || u_len > SHIRUDO_TPM_NAME_LEN ||
	    v_len > SHIRUDO_TPM_NAME_LEN || out_len > 4096)
		return -EINVAL;
	for (i = 1; done < out_len; i++) {
		put32(buf, i);
		off = 4;
		memcpy(buf + off, label, label_len);
		off += label_len;
		buf[off++] = 0;
		if (u_len)
			memcpy(buf + off, ctx_u, u_len);
		off += u_len;
		if (v_len)
			memcpy(buf + off, ctx_v, v_len);
		off += v_len;
		put32(buf + off, (uint32_t)(out_len * 8));
		off += 4;
		if (shirudo_hmac_sha256(key, key_len, buf, off, block))
			return -EIO;
		n = out_len - done < 32 ? out_len - done : 32;
		memcpy(out + done, block, n);
		done += n;
	}
	explicit_bzero(block, sizeof(block));
	return 0;
}

void shirudo_tpm_kdfe(const uint8_t z[32], const char *label,
		      const uint8_t *party_u, size_t u_len,
		      const uint8_t *party_v, size_t v_len, uint8_t out[32])
{
	uint8_t buf[4 + 32 + 64 + 1 + 2 * 64];
	size_t label_len = strlen(label), off = 4;

	if (label_len > 64 || u_len > 64 || v_len > 64) {
		memset(out, 0, 32);
		return;
	}
	put32(buf, 1);
	memcpy(buf + off, z, 32);
	off += 32;
	memcpy(buf + off, label, label_len);
	off += label_len;
	buf[off++] = 0;
	if (u_len)
		memcpy(buf + off, party_u, u_len);
	off += u_len;
	if (v_len)
		memcpy(buf + off, party_v, v_len);
	off += v_len;
	shirudo_sha256_buffer(buf, off, out);
	explicit_bzero(buf, sizeof(buf));
}

int shirudo_tpm_credential_protect(const uint8_t seed[32],
				   const uint8_t name[SHIRUDO_TPM_NAME_LEN],
				   const uint8_t credential[SHIRUDO_TPM_CREDENTIAL_LEN],
				   uint8_t out[SHIRUDO_TPM_ID_OBJECT_LEN])
{
	uint8_t plain[2 + SHIRUDO_TPM_CREDENTIAL_LEN], enc[sizeof(plain)];
	uint8_t mac_in[sizeof(enc) + SHIRUDO_TPM_NAME_LEN], mac[32];
	uint8_t sym_key[16], hmac_key[32];
	int rc = -EIO;

	if (shirudo_tpm_kdfa(seed, 32, "STORAGE", name, SHIRUDO_TPM_NAME_LEN,
			     NULL, 0, sym_key, sizeof(sym_key)))
		goto out;
	put16(plain, SHIRUDO_TPM_CREDENTIAL_LEN);
	memcpy(plain + 2, credential, SHIRUDO_TPM_CREDENTIAL_LEN);
	if (shirudo_aes128_cfb_encrypt(sym_key, plain, sizeof(plain), enc) ||
	    shirudo_tpm_kdfa(seed, 32, "INTEGRITY", NULL, 0, NULL, 0, hmac_key,
			     sizeof(hmac_key)))
		goto out;
	memcpy(mac_in, enc, sizeof(enc));
	memcpy(mac_in + sizeof(enc), name, SHIRUDO_TPM_NAME_LEN);
	if (shirudo_hmac_sha256(hmac_key, sizeof(hmac_key), mac_in,
				sizeof(mac_in), mac))
		goto out;
	put16(out, 32);
	memcpy(out + 2, mac, 32);
	memcpy(out + 34, enc, sizeof(enc));
	rc = 0;
out:
	explicit_bzero(plain, sizeof(plain));
	explicit_bzero(sym_key, sizeof(sym_key));
	explicit_bzero(hmac_key, sizeof(hmac_key));
	return rc;
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
