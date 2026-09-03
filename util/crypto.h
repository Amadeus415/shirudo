/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Small crypto interface shared by the operator and target profiles.
 * The operator implementation uses OpenSSL; the target implementation
 * uses mbedTLS.  Callers must not depend on either provider's types.
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

struct shirudo_cert {
	void *impl;
};

int shirudo_cert_read_file(const char *path, struct shirudo_cert *cert);
void shirudo_cert_free(struct shirudo_cert *cert);
int shirudo_cert_pubkey_digest(const struct shirudo_cert *cert,
			       uint8_t out[SHIRUDO_CRYPTO_SHA256_LEN]);
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

#endif /* SHIRUDO_CRYPTO_H */
