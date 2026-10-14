// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libcurl TLS trust-anchor glue for the mbedTLS-backed target profile.
 */

#include <unistd.h>

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include "crypto.h"
#include "malloc.h"

void shirudo_tls_ca_cleanup(struct shirudo_tls_ca *ca)
{
	mbedtls_x509_crt *crt;

	if (!ca || !ca->impl)
		return;
	crt = ca->impl;
	mbedtls_x509_crt_free(crt);
	xfree(crt, sizeof(*crt));
	ca->impl = NULL;
}

/*
 * libcurl's mbedTLS backend has already selected its normal CA bundle;
 * CURLINFO_CAINFO exposes that path so the configured CA is added to the
 * normal trust roots instead of replacing them.
 */
CURLcode shirudo_sslctx_callback(CURL *curl, void *sslctx, void *userptr)
{
	struct shirudo_tls_ca *ca = userptr;
	const char *default_ca = NULL;
	mbedtls_x509_crt *crt;
	CURLcode cc;

	(void)curl;
	if (!ca || !ca->path || !ca->path[0])
		return CURLE_OK;
	if (!ca->impl) {
		crt = xcalloc(1, sizeof(*crt));
		if (!crt)
			return CURLE_OUT_OF_MEMORY;
		mbedtls_x509_crt_init(crt);
		cc = curl_easy_getinfo(curl, CURLINFO_CAINFO, &default_ca);
		if (cc == CURLE_OK && default_ca && default_ca[0] &&
		    access(default_ca, R_OK) == 0 &&
		    mbedtls_x509_crt_parse_file(crt, default_ca) < 0) {
			mbedtls_x509_crt_free(crt);
			xfree(crt, sizeof(*crt));
			return CURLE_SSL_CACERT_BADFILE;
		}
		if (mbedtls_x509_crt_parse_file(crt, ca->path) < 0) {
			mbedtls_x509_crt_free(crt);
			xfree(crt, sizeof(*crt));
			return CURLE_SSL_CACERT_BADFILE;
		}
		ca->impl = crt;
	}
	mbedtls_ssl_conf_ca_chain((mbedtls_ssl_config *)sslctx, ca->impl, NULL);
	return CURLE_OK;
}
