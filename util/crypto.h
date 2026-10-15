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

#include <stdbool.h>
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
/*
 * Whether a signer of the CMS blob names this certificate, by key id
 * or by issuer and serial: 1 when one does, 0 when none, -EINVAL when
 * the blob does not parse. Says nothing about the signature's validity.
 */
int shirudo_cms_signed_by(const uint8_t *signature, size_t signature_len,
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

/* HMAC-SHA-256 of data under key. */
int shirudo_hmac_sha256(const uint8_t *key, size_t key_len,
			const void *data, size_t len,
			uint8_t out[SHIRUDO_CRYPTO_SHA256_LEN]);

/* AES-128 in CFB mode with a zero IV and no padding. */
int shirudo_aes128_cfb_encrypt(const uint8_t key[16], const uint8_t *in,
			       size_t len, uint8_t *out);

/*
 * RSA-OAEP with SHA-256, MGF1-SHA-256 and the given label to the
 * modulus n with the public exponent e (0 for 65537).
 */
int shirudo_rsa_oaep_encrypt(const uint8_t *n, size_t n_len, uint32_t e,
			     const void *label, size_t label_len,
			     const uint8_t *in, size_t in_len,
			     uint8_t *out, size_t cap, size_t *out_len);

/*
 * One ephemeral P-256 ECDH against the point (x, y): the ephemeral
 * public point and the shared secret's x coordinate.
 */
int shirudo_ecdh_p256_ephemeral(const uint8_t x[32], const uint8_t y[32],
				uint8_t eph_x[32], uint8_t eph_y[32],
				uint8_t z[32]);

int shirudo_base64_decode(const char *in, size_t in_len, uint8_t *out,
			  size_t cap, size_t *out_len);

int shirudo_cert_read_der(const uint8_t *der, size_t len,
			  struct shirudo_cert *cert);

/* The raw public key of a certificate: RSA (n, e) or EC P-256 (x, y). */
struct shirudo_cert_pubkey {
	bool		rsa;
	uint8_t		n[512];
	size_t		n_len;
	uint32_t	e;
	uint8_t		x[32];
	uint8_t		y[32];
};

int shirudo_cert_pubkey(const struct shirudo_cert *cert,
			struct shirudo_cert_pubkey *out);

/*
 * Chain the certificate to the PEM bundle of trusted issuers at path.
 * -EKEYREJECTED when it does not chain, with *reason set to libcrypto's
 * static explanation; -EINVAL when the bundle cannot be loaded.
 */
int shirudo_cert_verify_chain(const struct shirudo_cert *cert,
			      const char *bundle_path, const char **reason);

#endif /* SHIRUDO_CRYPTO_H */
