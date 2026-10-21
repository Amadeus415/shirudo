// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libcurl TLS policy and trust-anchor glue for the OpenSSL-backed profile.
 */

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "crypto.h"

/*
 * Hybrid ML-KEM is the default. Explicit compatibility hosts may also
 * negotiate classical groups, without relaxing TLS 1.3 or peer checks.
 */
#define SHIRUDO_TLS_GROUPS	"*X25519MLKEM768:SecP256r1MLKEM768"
#define SHIRUDO_TLS_COMPAT_GROUPS	SHIRUDO_TLS_GROUPS ":X25519:P-256"

static bool classical_allowed(CURL *curl, const struct shirudo_tls_ca *ca)
{
	char *effective_url, *host = NULL, *port = NULL;
	const char *entries, *entry, *end;
	size_t host_len, port_len, len;
	bool allowed = false;
	CURLU *url;

	if (!ca || !ca->compat_hosts || !*ca->compat_hosts ||
	    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL,
			      &effective_url) != CURLE_OK || !effective_url)
		return false;
	url = curl_url();
	if (!url)
		return false;
	if (curl_url_set(url, CURLUPART_URL, effective_url, 0) ||
	    curl_url_get(url, CURLUPART_HOST, &host, 0) ||
	    curl_url_get(url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT))
		goto out;
	host_len = strlen(host);
	port_len = strlen(port);
	entries = ca->compat_hosts;
	while (entries && *entries) {
		entry = entries;
		end = strchr(entry, ',');
		entries = end ? end + 1 : NULL;
		if (!end)
			end = entry + strlen(entry);
		while (entry < end && isspace((unsigned char)*entry))
			entry++;
		while (end > entry && isspace((unsigned char)end[-1]))
			end--;
		len = end - entry;
		if ((len == host_len && !strcmp(port, "443") &&
		     !strncasecmp(entry, host, host_len)) ||
		    (len == host_len + 1 + port_len &&
		     !strncasecmp(entry, host, host_len) &&
		     entry[host_len] == ':' &&
		     !memcmp(entry + host_len + 1, port, port_len))) {
			allowed = true;
			break;
		}
	}
out:
	curl_free(host);
	curl_free(port);
	curl_url_cleanup(url);
	return allowed;
}

void shirudo_tls_ca_cleanup(struct shirudo_tls_ca *ca)
{
	if (ca)
		ca->impl = NULL;
}

static CURLcode shirudo_sslctx_callback(CURL *curl, void *sslctx, void *userptr)
{
	const struct shirudo_tls_ca *ca = userptr;
	const char *groups = classical_allowed(curl, ca) ?
		SHIRUDO_TLS_COMPAT_GROUPS : SHIRUDO_TLS_GROUPS;
	const char *path = ca ? ca->path : NULL;
	SSL_CTX *ctx = sslctx;
	X509 *cert;
	BIO *bio;

	if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
	    SSL_CTX_set1_groups_list(ctx, groups) != 1) {
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
	/* Compatibility must not escape to another host through connection reuse. */
	if (ca && ca->compat_hosts && *ca->compat_hosts &&
	    (curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L) != CURLE_OK ||
	     curl_easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 0L) != CURLE_OK))
		return -EINVAL;
	if (curl_easy_setopt(curl, CURLOPT_SSLVERSION,
			     (long)CURL_SSLVERSION_TLSv1_3) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION,
			     shirudo_sslctx_callback) != CURLE_OK ||
	    curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, ca) != CURLE_OK)
		return -EINVAL;
	return 0;
}
