// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * SHA-256, X.509 and CMS primitives on libcrypto; linked into both profiles.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "crypto.h"
#include "malloc.h"

static X509 *read_x509(const char *path)
{
	BIO *bio = BIO_new_file(path, "rb");
	X509 *cert;

	if (!bio)
		return NULL;
	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!cert) {
		ERR_clear_error();
		/* file BIOs report a successful reset as 0, not 1 */
		if (BIO_reset(bio) >= 0)
			cert = d2i_X509_bio(bio, NULL);
	}
	BIO_free(bio);
	if (!cert)
		ERR_clear_error();
	return cert;
}

int shirudo_sha256_init(struct shirudo_sha256_ctx *ctx)
{
	EVP_MD_CTX *md;

	if (!ctx)
		return -EINVAL;
	ctx->impl = NULL;
	md = EVP_MD_CTX_new();
	if (!md || EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(md);
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
	return EVP_DigestUpdate(ctx->impl, data, len) == 1 ? 0 : -EIO;
}

int shirudo_sha256_final(struct shirudo_sha256_ctx *ctx,
			uint8_t out[SHIRUDO_CRYPTO_SHA256_LEN])
{
	unsigned int len = 0;
	int rc;

	if (!ctx || !ctx->impl || !out)
		return -EINVAL;
	rc = EVP_DigestFinal_ex(ctx->impl, out, &len) == 1 && len == 32 ? 0 : -EIO;
	EVP_MD_CTX_free(ctx->impl);
	ctx->impl = NULL;
	return rc;
}

void shirudo_sha256_free(struct shirudo_sha256_ctx *ctx)
{
	if (!ctx)
		return;
	EVP_MD_CTX_free(ctx->impl);
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

	if (!data || !out || out_sz < need || len > INT_MAX)
		return -EINVAL;
	if (EVP_EncodeBlock((unsigned char *)out, data, (int)len) < 0)
		return -EIO;
	out[need - 1] = '\0';
	return 0;
}

int shirudo_ecdsa_p256_verify(const uint8_t x[32], const uint8_t y[32],
			      const uint8_t digest[32],
			      const uint8_t r[32], const uint8_t s[32])
{
	unsigned char point[65], *der = NULL;
	EVP_PKEY_CTX *kctx = NULL, *vctx = NULL;
	OSSL_PARAM params[3];
	BIGNUM *br = NULL, *bs = NULL;
	ECDSA_SIG *sig = NULL;
	EVP_PKEY *pkey = NULL;
	int der_len, rc = -EIO;

	point[0] = 0x04;
	memcpy(point + 1, x, 32);
	memcpy(point + 33, y, 32);
	params[0] = OSSL_PARAM_construct_utf8_string("group", (char *)"P-256",
						     0);
	params[1] = OSSL_PARAM_construct_octet_string("pub", point,
						      sizeof(point));
	params[2] = OSSL_PARAM_construct_end();
	kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!kctx || EVP_PKEY_fromdata_init(kctx) <= 0 ||
	    EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
		rc = -EINVAL;
		goto out;
	}
	br = BN_bin2bn(r, 32, NULL);
	bs = BN_bin2bn(s, 32, NULL);
	sig = ECDSA_SIG_new();
	if (!br || !bs || !sig || !ECDSA_SIG_set0(sig, br, bs))
		goto out;
	br = NULL;
	bs = NULL;
	der_len = i2d_ECDSA_SIG(sig, &der);
	if (der_len <= 0)
		goto out;
	vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (!vctx || EVP_PKEY_verify_init(vctx) <= 0 ||
	    EVP_PKEY_CTX_set_signature_md(vctx, EVP_sha256()) <= 0)
		goto out;
	rc = EVP_PKEY_verify(vctx, der, (size_t)der_len, digest, 32) == 1 ?
	     0 : -EKEYREJECTED;
out:
	OPENSSL_free(der);
	ECDSA_SIG_free(sig);
	BN_free(br);
	BN_free(bs);
	EVP_PKEY_CTX_free(vctx);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(pkey);
	ERR_clear_error();
	return rc;
}

int shirudo_cert_read_file(const char *path, struct shirudo_cert *cert)
{
	if (!path || !cert)
		return -EINVAL;
	cert->impl = read_x509(path);
	return cert->impl ? 0 : -EINVAL;
}

void shirudo_cert_free(struct shirudo_cert *cert)
{
	if (!cert)
		return;
	X509_free(cert->impl);
	cert->impl = NULL;
}

/*
 * SHA-256 over the DER SubjectPublicKeyInfo. Re-encoding through
 * i2d_X509_PUBKEY keeps the value identical for every key algorithm the
 * X.509 parser accepts, including ML-DSA keys libcrypto cannot otherwise
 * marshal as a bare EVP_PKEY on older releases.
 */
int shirudo_cert_pubkey_digest(const struct shirudo_cert *cert,
			       uint8_t out[SHIRUDO_CRYPTO_SHA256_LEN])
{
	unsigned char *der = NULL, *p;
	int der_len, encoded_len, rc = -EINVAL;
	unsigned int len = 0;
	X509_PUBKEY *spki;

	if (!cert || !cert->impl || !out)
		return -EINVAL;
	spki = X509_get_X509_PUBKEY(cert->impl);
	if (!spki)
		return -EINVAL;
	der_len = i2d_X509_PUBKEY(spki, NULL);
	if (der_len <= 0)
		return -EINVAL;
	der = xmalloc((size_t)der_len);
	if (!der)
		return -ENOMEM;
	p = der;
	encoded_len = i2d_X509_PUBKEY(spki, &p);
	if (encoded_len != der_len)
		goto out;
	if (!EVP_Digest(der, (size_t)der_len, out, &len,
			EVP_sha256(), NULL) || len != SHIRUDO_CRYPTO_SHA256_LEN)
		goto out;
	rc = 0;
out:
	xfree(der, (size_t)der_len);
	return rc;
}

int shirudo_cert_key_algorithm(const struct shirudo_cert *cert,
			       char *out, size_t out_sz)
{
	const char *name;
	EVP_PKEY *pub;

	if (!cert || !cert->impl || !out || !out_sz)
		return -EINVAL;
	pub = X509_get0_pubkey(cert->impl);
	name = pub ? EVP_PKEY_get0_type_name(pub) : NULL;
	if (!name)
		return -ENOPKG;
	snprintf(out, out_sz, "%s", name);
	return 0;
}

/*
 * Verify a detached CMS signature against one operator certificate. The
 * signature algorithm comes from the SignerInfo, so an ML-DSA signature
 * (signedAttrs + SHA-512, or no attributes on OpenSSL 4) and an RSA
 * signature verify through the same call; libcrypto >= 3.5 is needed for
 * ML-DSA.
 */
int shirudo_verify_detached(const uint8_t *payload, size_t payload_len,
			    const uint8_t *signature, size_t signature_len,
			    const struct shirudo_cert *cert)
{
	BIO *sig = NULL, *data = NULL, *out = NULL;
	CMS_ContentInfo *cms = NULL;
	STACK_OF(X509) *signers = NULL;
	X509_STORE *store = NULL;
	int rc = -EINVAL;

	if (!payload || !signature || !cert || !cert->impl ||
	    payload_len > INT_MAX || signature_len > INT_MAX)
		return -EINVAL;
	sig = BIO_new_mem_buf(signature, (int)signature_len);
	data = BIO_new_mem_buf(payload, (int)payload_len);
	out = BIO_new(BIO_s_null());
	store = X509_STORE_new();
	if (!sig || !data || !out || !store ||
	    X509_STORE_add_cert(store, cert->impl) != 1)
		goto done;
	signers = sk_X509_new_null();
	if (!signers || !sk_X509_push(signers, cert->impl))
		goto done;
	cms = d2i_CMS_bio(sig, NULL);
	if (cms && CMS_verify(cms, signers, store, data, out,
				     CMS_BINARY | CMS_DETACHED) == 1)
		rc = 0;
done:
	if (rc)
		ERR_clear_error();
	CMS_ContentInfo_free(cms);
	sk_X509_free(signers);
	X509_STORE_free(store);
	BIO_free(out);
	BIO_free(data);
	BIO_free(sig);
	return rc;
}
