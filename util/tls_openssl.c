// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libcurl TLS trust-anchor glue for the OpenSSL-backed operator profile.
 */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "crypto.h"

void shirudo_tls_ca_cleanup(struct shirudo_tls_ca *ca)
{
	if (ca)
		ca->impl = NULL;
}

CURLcode shirudo_sslctx_callback(CURL *curl, void *sslctx, void *userptr)
{
	const struct shirudo_tls_ca *ca = userptr;
	const char *path = ca ? ca->path : NULL;
	BIO *bio;
	X509 *cert;

	(void)curl;
	if (!path || !path[0])
		return CURLE_OK;
	bio = BIO_new_file(path, "rb");
	if (!bio)
		return CURLE_SSL_CACERT_BADFILE;
	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!cert)
		return CURLE_SSL_CACERT_BADFILE;
	if (X509_STORE_add_cert(SSL_CTX_get_cert_store(sslctx), cert) != 1)
		ERR_clear_error();
	X509_free(cert);
	return CURLE_OK;
}
