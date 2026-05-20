/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Measurement-chain helpers: cert hashing, NV index auth derivation,
 * and reading the live NV chain value. The auth and digest formulas
 * live here so the init (extend) and upatch-load (pre-flight read)
 * paths can never disagree.
 */

#ifndef SHIRUDO_CHAIN_H
#define SHIRUDO_CHAIN_H

#include <stddef.h>
#include <stdint.h>

#define SHIRUDO_CHAIN_DIGEST_LEN	32

void shirudo_sha256(const void *data, size_t len,
		    uint8_t out[SHIRUDO_CHAIN_DIGEST_LEN]);
void shirudo_hex_encode(const uint8_t *in, size_t n, char *out);

/* Decode exactly 2*n lowercase/uppercase hex chars. 0 / -EINVAL. */
int shirudo_hex_decode(const char *hex, uint8_t *out, size_t n);

/* Constant-time equality of two equal-length buffers (1 == equal). */
int shirudo_ct_eq(const void *a, const void *b, size_t n);

/* SHA-256 of the on-disk cert.der. 0 on success, -errno on failure. */
int shirudo_chain_cert_sha256(uint8_t out[SHIRUDO_CHAIN_DIGEST_LEN]);

/* auth_value = SHA256("shirudo-nv-auth\0" || cert_sha256). */
void shirudo_chain_auth_value(const uint8_t cert_sha[SHIRUDO_CHAIN_DIGEST_LEN],
			      uint8_t out[SHIRUDO_CHAIN_DIGEST_LEN]);

/*
 * Read the live NV chain value. Returns 0 with the value in out,
 * -ENODEV when the chain cannot be read (no TPM, index undefined or
 * never written -- degraded mode), or another -errno on hard error.
 */
int shirudo_chain_read(uint8_t out[SHIRUDO_CHAIN_DIGEST_LEN]);

/*
 * Extend the existing chain by one event digest (does NOT define the
 * index -- that is init's job). Returns 0 on success with the new
 * chain value in out_chain (may be NULL), -ENODEV when there is no
 * usable chain to extend (no TPM, or index undefined -- degraded:
 * caller proceeds unmeasured), or -EIO when the extend fails against
 * an existing, readable index (the "tpm_error" hard case: state is
 * out of sync with the chain).
 */
int shirudo_chain_extend(const uint8_t event[SHIRUDO_CHAIN_DIGEST_LEN],
			 uint8_t out_chain[SHIRUDO_CHAIN_DIGEST_LEN]);

#endif /* SHIRUDO_CHAIN_H */
