/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/asn1.h>
#include <mbedtls/base64.h>
#include <mbedtls/oid.h>
#include <mbedtls/pkcs7.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include "crypto.h"
#include "malloc.h"

/*
 * mbedTLS 3.6's PKCS#7 parser does not accept the subjectKeyIdentifier
 * SignerIdentifier emitted by the kernel-compatible CMS_USE_KEYID form.
 * Keep that wire format unchanged for the kernel and verify Shirudo's
 * detached, no-attributes form directly with the operator certificate.
 */
static int asn1_skip(unsigned char **p, const unsigned char *end)
{
	size_t len;
	int tag;

	if (!p || !*p || *p >= end)
		return MBEDTLS_ERR_ASN1_OUT_OF_DATA;
	tag = **p;
	if ((tag & MBEDTLS_ASN1_TAG_VALUE_MASK) == 0x1f)
		return MBEDTLS_ERR_ASN1_INVALID_DATA;
	if (mbedtls_asn1_get_tag(p, end, &len, tag) != 0 ||
		len > (size_t)(end - *p))
		return MBEDTLS_ERR_ASN1_INVALID_LENGTH;
	*p += len;
	return 0;
}

static int verify_detached_keyid_cms(const uint8_t *payload,
					 size_t payload_len,
					 const uint8_t *signature,
					 size_t signature_len,
					 const mbedtls_x509_crt *cert)
{
	unsigned char *p = (unsigned char *)signature;
	const unsigned char *end = signature + signature_len;
	const unsigned char *section_end;
	mbedtls_asn1_buf oid = {}, params = {};
	mbedtls_md_type_t md_alg;
	uint8_t digest[SHIRUDO_CRYPTO_SHA256_LEN];
	const unsigned char *sig;
	size_t len;
	int rc;

	/* ContentInfo ::= SEQUENCE { contentType, [0] SignedData } */
	rc = mbedtls_asn1_get_tag(&p, end, &len,
				  MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	if (rc)
		return rc;
	section_end = p + len;
	if (section_end > end ||
		mbedtls_asn1_get_tag(&p, section_end, &len, MBEDTLS_ASN1_OID))
		return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
	if (len != sizeof(MBEDTLS_OID_PKCS7_SIGNED_DATA) - 1 ||
		memcmp(p, MBEDTLS_OID_PKCS7_SIGNED_DATA, len) != 0)
		return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
	p += len;
	if (mbedtls_asn1_get_tag(&p, section_end, &len,
					 MBEDTLS_ASN1_CONTEXT_SPECIFIC |
					 MBEDTLS_ASN1_CONSTRUCTED | 0))
		return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
	section_end = p + len;
	if (section_end > end ||
		mbedtls_asn1_get_tag(&p, section_end, &len,
					 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
		return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
	section_end = p + len;

	/* SignedData.version, digestAlgorithms, encapContentInfo. */
	if (asn1_skip(&p, section_end) || asn1_skip(&p, section_end) ||
		asn1_skip(&p, section_end))
		return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;

	/* Optional certificates and CRLs precede signerInfos. */
	while (p < section_end && (*p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC |
						 MBEDTLS_ASN1_CONSTRUCTED | 0) ||
				   *p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC |
						 MBEDTLS_ASN1_CONSTRUCTED | 1))) {
		if (asn1_skip(&p, section_end))
			return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
	}

	/* signerInfos SET OF SignerInfo; this format carries one signer. */
	if (mbedtls_asn1_get_tag(&p, section_end, &len,
					 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET))
		return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
	section_end = p + len;
	if (section_end > end ||
		mbedtls_asn1_get_tag(&p, section_end, &len,
					 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
		return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
	section_end = p + len;

	/* SignerInfo.version and the key-id SignerIdentifier. */
	if (asn1_skip(&p, section_end) || asn1_skip(&p, section_end))
		return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;

	/* digestAlgorithm must be SHA-256. */
	if (mbedtls_asn1_get_alg(&p, section_end, &oid, &params) ||
		mbedtls_oid_get_md_alg(&oid, &md_alg) ||
		md_alg != MBEDTLS_MD_SHA256)
		return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;

	/* CMS_NOATTR means signatureAlgorithm follows immediately. */
	if (mbedtls_asn1_get_alg(&p, section_end, &oid, &params) ||
		mbedtls_asn1_get_tag(&p, section_end, &len,
					 MBEDTLS_ASN1_OCTET_STRING) ||
		len > (size_t)(section_end - p))
		return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
	sig = p;

	rc = shirudo_sha256_buffer(payload, payload_len, digest);
	if (rc)
		return rc;
	return mbedtls_pk_verify((mbedtls_pk_context *)&cert->pk, md_alg,
				 digest, sizeof(digest), sig, len);
}

int shirudo_sha256_init(struct shirudo_sha256_ctx *ctx)
{
	mbedtls_sha256_context *md;

	if (!ctx)
		return -EINVAL;
	ctx->impl = NULL;
	md = xcalloc(1, sizeof(*md));
	if (!md)
		return -ENOMEM;
	mbedtls_sha256_init(md);
	if (mbedtls_sha256_starts(md, 0) != 0) {
		mbedtls_sha256_free(md);
		xfree(md, sizeof(*md));
		return -EIO;
	}
	ctx->impl = md;
	return 0;
}

int shirudo_sha256_update(struct shirudo_sha256_ctx *ctx,
			 const void *data, size_t len)
{
	if (!ctx || !ctx->impl || (len && !data))
		return -EINVAL;
	return mbedtls_sha256_update(ctx->impl, data, len) == 0 ? 0 : -EIO;
}

int shirudo_sha256_final(struct shirudo_sha256_ctx *ctx,
			uint8_t out[SHIRUDO_CRYPTO_SHA256_LEN])
{
	int rc;

	if (!ctx || !ctx->impl || !out)
		return -EINVAL;
	rc = mbedtls_sha256_finish(ctx->impl, out) == 0 ? 0 : -EIO;
	mbedtls_sha256_free(ctx->impl);
	xfree(ctx->impl, sizeof(mbedtls_sha256_context));
	ctx->impl = NULL;
	return rc;
}

void shirudo_sha256_free(struct shirudo_sha256_ctx *ctx)
{
	if (!ctx || !ctx->impl)
		return;
	mbedtls_sha256_free(ctx->impl);
	xfree(ctx->impl, sizeof(mbedtls_sha256_context));
	ctx->impl = NULL;
}

int shirudo_sha256_buffer(const void *data, size_t len,
			 uint8_t out[SHIRUDO_CRYPTO_SHA256_LEN])
{
	struct shirudo_sha256_ctx ctx;
	int rc;

	rc = shirudo_sha256_init(&ctx);
	if (!rc)
		rc = shirudo_sha256_update(&ctx, data, len);
	if (!rc)
		rc = shirudo_sha256_final(&ctx, out);
	else
		shirudo_sha256_free(&ctx);
	return rc;
}

int shirudo_base64_encode(const uint8_t *data, size_t len,
			  char *out, size_t out_sz)
{
	size_t need = 4 * ((len + 2) / 3) + 1;
	size_t olen = 0;
	int rc;

	if (!data || !out || out_sz < need || len > INT_MAX)
		return -EINVAL;
	rc = mbedtls_base64_encode((unsigned char *)out, out_sz - 1, &olen,
				   data, len);
	if (rc != 0)
		return -EIO;
	if (olen >= out_sz)
		return -ENOSPC;
	out[olen] = '\0';
	return 0;
}

int shirudo_cert_read_file(const char *path, struct shirudo_cert *cert)
{
	mbedtls_x509_crt *crt;

	if (!path || !cert)
		return -EINVAL;
	cert->impl = NULL;
	crt = xcalloc(1, sizeof(*crt));
	if (!crt)
		return -ENOMEM;
	mbedtls_x509_crt_init(crt);
	if (mbedtls_x509_crt_parse_file(crt, path) != 0 || !crt->raw.p) {
		mbedtls_x509_crt_free(crt);
		xfree(crt, sizeof(*crt));
		return -EINVAL;
	}
	cert->impl = crt;
	return 0;
}

void shirudo_cert_free(struct shirudo_cert *cert)
{
	mbedtls_x509_crt *crt;

	if (!cert || !cert->impl)
		return;
	crt = cert->impl;
	mbedtls_x509_crt_free(crt);
	xfree(crt, sizeof(*crt));
	cert->impl = NULL;
}

int shirudo_cert_pubkey_digest(const struct shirudo_cert *cert,
			       uint8_t out[SHIRUDO_CRYPTO_SHA256_LEN])
{
	mbedtls_x509_crt *crt;
	unsigned char der[2048];
	int n;

	if (!cert || !cert->impl || !out)
		return -EINVAL;
	crt = cert->impl;
	n = mbedtls_pk_write_pubkey_der(&crt->pk, der, sizeof(der));
	if (n <= 0 || n > (int)sizeof(der))
		return -EIO;
	return shirudo_sha256_buffer(der + sizeof(der) - n, (size_t)n, out);
}

int shirudo_verify_detached(const uint8_t *payload, size_t payload_len,
			    const uint8_t *signature, size_t signature_len,
			    const struct shirudo_cert *cert)
{
	mbedtls_pkcs7 pkcs7;
	int rc;

	if (!payload || !signature || !cert || !cert->impl ||
	    signature_len == 0)
		return -EINVAL;
	mbedtls_pkcs7_init(&pkcs7);
	rc = mbedtls_pkcs7_parse_der(&pkcs7, signature, signature_len);
	if (rc >= 0 && rc == MBEDTLS_PKCS7_SIGNED_DATA)
		rc = mbedtls_pkcs7_signed_data_verify(&pkcs7, cert->impl,
						      payload, payload_len);
	mbedtls_pkcs7_free(&pkcs7);
	if (rc != 0)
		rc = verify_detached_keyid_cms(payload, payload_len, signature,
						 signature_len, cert->impl);
	return rc == 0 ? 0 : -EINVAL;
}

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

CURLcode shirudo_sslctx_callback(CURL *curl, void *sslctx, void *userptr)
{
	struct shirudo_tls_ca *ca = userptr;
	mbedtls_x509_crt *crt;
	const char *default_ca = NULL;
	CURLcode cc;

	(void)curl;
	if (!ca || !ca->path || !ca->path[0])
		return CURLE_OK;
	if (!ca->impl) {
		crt = xcalloc(1, sizeof(*crt));
		if (!crt)
			return CURLE_OUT_OF_MEMORY;
		mbedtls_x509_crt_init(crt);
		/* libcurl's mbedTLS backend has already selected its normal CA
		 * bundle.  CURLINFO_CAINFO exposes that path, allowing this
		 * callback to retain the normal trust roots and add the configured
		 * CA rather than replacing them. */
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
