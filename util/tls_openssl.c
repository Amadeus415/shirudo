// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libcurl TLS policy and trust-anchor glue for the OpenSSL-backed profile.
 */

#include <errno.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "crypto.h"

/*
 * Hybrid ML-KEM only: X25519MLKEM768 with a key share, the P-256 hybrid
 * as the HelloRetryRequest fallback, and no classical group at all, so
 * a server without ML-KEM gets a handshake failure rather than a
 * classical key exchange. Both names exist in OpenSSL 3.5+.
 */
#define SHIRUDO_TLS_GROUPS	"*X25519MLKEM768:SecP256r1MLKEM768"

void shirudo_tls_ca_cleanup(struct shirudo_tls_ca *ca)
{
	if (ca)
		ca->impl = NULL;
}

CURLcode shirudo_sslctx_callback(CURL *curl, void *sslctx, void *userptr)
{
	const struct shirudo_tls_ca *ca = userptr;
	const char *path = ca ? ca->path : NULL;
	SSL_CTX *ctx = sslctx;
	X509 *cert;
	BIO *bio;

	(void)curl;
	if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
	    SSL_CTX_set1_groups_list(ctx, SHIRUDO_TLS_GROUPS) != 1) {
		ERR_clear_error();
		return CURLE_SSL_CIPHER;
	}
	if (!path || !path[0])
		return CURLE_OK;
	bio = BIO_new_file(path, "rb");
	if (!bio)
		return CURLE_SSL_CACERT_BADFILE;
	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!cert)
		return CURLE_SSL_CACERT_BADFILE;
	if (X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert) != 1)
		ERR_clear_error();
	X509_free(cert);
	return CURLE_OK;
}

int shirudo_tls_curl_policy(CURL *curl, struct shirudo_tls_ca *ca)
{
	if (!curl)
		return -EINVAL;
	if (curl_easy_setopt(curl, CURLOPT_SSLVERSION,
			     (long)CURL_SSLVERSION_TLSv1_3) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION,
			     shirudo_sslctx_callback) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, ca) != CURLE_OK)
		return -EINVAL;
	return 0;
}
