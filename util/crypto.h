/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Small crypto interface shared by the operator and target profiles.
 * Hashing, X.509, CMS verification and the libcurl TLS policy all run
 * on OpenSSL (shared on the operator, static on the target), so every
 * key algorithm the kernel verifies and the hybrid ML-KEM key exchange
 * come from one implementation. Callers must not depend on the
 * provider's types.
 */

#ifndef SHIRUDO_CRYPTO_H
#define SHIRUDO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include <curl/curl.h>

#define SHIRUDO_CRYPTO_SHA256_LEN 32

struct shirudo_sha256_ctx {
	void *impl;
};

int shirudo_sha256_init(struct shirudo_sha256_ctx *ctx);
int shirudo_sha256_update(struct shirudo_sha256_ctx *ctx,
			 const void *data, size_t len);
int shirudo_sha256_final(struct shirudo_sha256_ctx *ctx,
			uint8_t out[SHIRUDO_CRYPTO_SHA256_LEN]);
void shirudo_sha256_free(struct shirudo_sha256_ctx *ctx);
int shirudo_sha256_buffer(const void *data, size_t len,
			 uint8_t out[SHIRUDO_CRYPTO_SHA256_LEN]);
int shirudo_base64_encode(const uint8_t *data, size_t len,
			  char *out, size_t out_sz);

/*
 * Verify an ECDSA P-256 signature (r, s) over a SHA-256 digest with
 * the public point (x, y). Returns 0 when valid, -EKEYREJECTED when
 * not, another -errno when the key or signature cannot be built.
 */
int shirudo_ecdsa_p256_verify(const uint8_t x[32], const uint8_t y[32],
			      const uint8_t digest[SHIRUDO_CRYPTO_SHA256_LEN],
			      const uint8_t r[32], const uint8_t s[32]);

struct shirudo_cert {
	void *impl;
};

int shirudo_cert_read_file(const char *path, struct shirudo_cert *cert);
void shirudo_cert_free(struct shirudo_cert *cert);
int shirudo_cert_pubkey_digest(const struct shirudo_cert *cert,
			       uint8_t out[SHIRUDO_CRYPTO_SHA256_LEN]);
/* The provider's name for the cert's public key, e.g. "ML-DSA-87". */
int shirudo_cert_key_algorithm(const struct shirudo_cert *cert,
			       char *out, size_t out_sz);
int shirudo_verify_detached(const uint8_t *payload, size_t payload_len,
			    const uint8_t *signature, size_t signature_len,
			    const struct shirudo_cert *cert);

struct shirudo_tls_ca {
	const char *path;
	void *impl;
};

void shirudo_tls_ca_cleanup(struct shirudo_tls_ca *ca);

/* CURLOPT_SSL_CTX_FUNCTION callback. userptr points to shirudo_tls_ca. */
CURLcode shirudo_sslctx_callback(CURL *curl, void *sslctx, void *userptr);

/*
 * shirudo's TLS policy for every libcurl handle it opens: TLS 1.3 only
 * and hybrid ML-KEM key exchange only (X25519MLKEM768, with the P-256
 * hybrid as fallback), so neither a version downgrade nor a classical
 * group can be negotiated. ca may be NULL; otherwise it is the extra
 * trust anchor fed to the SSL_CTX callback. Returns 0 or a negative
 * errno; callers must not connect when it fails.
 */
int shirudo_tls_curl_policy(CURL *curl, struct shirudo_tls_ca *ca);

#endif /* SHIRUDO_CRYPTO_H */
