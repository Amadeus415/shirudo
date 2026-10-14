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
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

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

int shirudo_hmac_sha256(const uint8_t *key, size_t key_len,
			const void *data, size_t len, uint8_t out[32])
{
	EVP_MAC_CTX *ctx = NULL;
	OSSL_PARAM params[2];
	size_t outl = 0;
	int rc = -EIO;
	EVP_MAC *mac;

	mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (!mac)
		return -EIO;
	params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)"SHA256",
						     0);
	params[1] = OSSL_PARAM_construct_end();
	ctx = EVP_MAC_CTX_new(mac);
	if (ctx && EVP_MAC_init(ctx, key, key_len, params) == 1 &&
	    EVP_MAC_update(ctx, data, len) == 1 &&
	    EVP_MAC_final(ctx, out, &outl, 32) == 1 && outl == 32)
		rc = 0;
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);
	return rc;
}

int shirudo_aes128_cfb_encrypt(const uint8_t key[16], const uint8_t *in,
			       size_t len, uint8_t *out)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int n = 0, fin = 0, rc = -EIO;
	uint8_t iv[16] = {};

	if (!ctx || len > INT_MAX)
		goto out;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb128(), NULL, key, iv) == 1 &&
	    EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
	    EVP_EncryptUpdate(ctx, out, &n, in, (int)len) == 1 &&
	    EVP_EncryptFinal_ex(ctx, out + n, &fin) == 1 &&
	    (size_t)n + (size_t)fin == len)
		rc = 0;
out:
	EVP_CIPHER_CTX_free(ctx);
	return rc;
}

int shirudo_rsa_oaep_encrypt(const uint8_t *n, size_t n_len, uint32_t e,
			     const void *label, size_t label_len,
			     const uint8_t *in, size_t in_len,
			     uint8_t *out, size_t cap, size_t *out_len)
{
	EVP_PKEY_CTX *kctx = NULL, *ectx = NULL;
	BIGNUM *bn = NULL, *be = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	unsigned char *lbl = NULL;
	EVP_PKEY *pkey = NULL;
	int rc = -EIO;

	if (n_len > INT_MAX || label_len > INT_MAX)
		return -EINVAL;
	bn = BN_bin2bn(n, (int)n_len, NULL);
	be = BN_new();
	bld = OSSL_PARAM_BLD_new();
	if (!bn || !be || !bld || !BN_set_word(be, e ? e : 65537) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, be))
		goto out;
	params = OSSL_PARAM_BLD_to_param(bld);
	kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!params || !kctx || EVP_PKEY_fromdata_init(kctx) <= 0 ||
	    EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
		rc = -EINVAL;
		goto out;
	}
	lbl = OPENSSL_malloc(label_len ? label_len : 1);
	if (!lbl)
		goto out;
	memcpy(lbl, label, label_len);
	ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (!ectx || EVP_PKEY_encrypt_init(ectx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_oaep_md(ectx, EVP_sha256()) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_mgf1_md(ectx, EVP_sha256()) <= 0 ||
	    EVP_PKEY_CTX_set0_rsa_oaep_label(ectx, lbl, (int)label_len) <= 0)
		goto out;
	lbl = NULL;	/* owned by ectx now */
	*out_len = cap;
	if (EVP_PKEY_encrypt(ectx, out, out_len, in, in_len) <= 0)
		goto out;
	rc = 0;
out:
	OPENSSL_free(lbl);
	EVP_PKEY_CTX_free(ectx);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(pkey);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_free(bn);
	BN_free(be);
	return rc;
}

int shirudo_ecdh_p256_ephemeral(const uint8_t x[32], const uint8_t y[32],
				uint8_t eph_x[32], uint8_t eph_y[32],
				uint8_t z[32])
{
	EVP_PKEY_CTX *kctx = NULL, *dctx = NULL;
	EVP_PKEY *eph = NULL, *peer = NULL;
	BIGNUM *bx = NULL, *by = NULL;
	unsigned char point[65];
	OSSL_PARAM params[3];
	size_t zlen = 32;
	int rc = -EIO;

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
	    EVP_PKEY_fromdata(kctx, &peer, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
		rc = -EINVAL;
		goto out;
	}
	eph = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	if (!eph || !EVP_PKEY_get_bn_param(eph, OSSL_PKEY_PARAM_EC_PUB_X, &bx) ||
	    !EVP_PKEY_get_bn_param(eph, OSSL_PKEY_PARAM_EC_PUB_Y, &by) ||
	    BN_bn2binpad(bx, eph_x, 32) != 32 ||
	    BN_bn2binpad(by, eph_y, 32) != 32)
		goto out;
	dctx = EVP_PKEY_CTX_new_from_pkey(NULL, eph, NULL);
	if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(dctx, peer) <= 0 ||
	    EVP_PKEY_derive(dctx, z, &zlen) <= 0 || zlen != 32)
		goto out;
	rc = 0;
out:
	BN_free(bx);
	BN_free(by);
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(eph);
	EVP_PKEY_free(peer);
	return rc;
}

int shirudo_base64_decode(const char *in, size_t in_len, uint8_t *out,
			  size_t cap, size_t *out_len)
{
	EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
	int n = 0, fin = 0, rc = -EINVAL;

	if (!ctx || in_len > INT_MAX || cap < 3 * (in_len / 4) + 3)
		goto out;
	EVP_DecodeInit(ctx);
	if (EVP_DecodeUpdate(ctx, out, &n, (const unsigned char *)in,
			     (int)in_len) < 0 ||
	    EVP_DecodeFinal(ctx, out + n, &fin) < 0)
		goto out;
	*out_len = (size_t)n + (size_t)fin;
	rc = 0;
out:
	EVP_ENCODE_CTX_free(ctx);
	return rc;
}

int shirudo_cert_read_der(const uint8_t *der, size_t len,
			  struct shirudo_cert *cert)
{
	const unsigned char *p = der;

	if (!der || !cert || len > LONG_MAX)
		return -EINVAL;
	cert->impl = d2i_X509(NULL, &p, (long)len);
	return cert->impl ? 0 : -EINVAL;
}

int shirudo_cert_pubkey(const struct shirudo_cert *cert,
			struct shirudo_cert_pubkey *out)
{
	BIGNUM *a = NULL, *b = NULL;
	char group[32] = "";
	int id, rc = -EINVAL;
	EVP_PKEY *pk;

	memset(out, 0, sizeof(*out));
	pk = cert && cert->impl ? X509_get0_pubkey(cert->impl) : NULL;
	if (!pk)
		return -EINVAL;
	id = EVP_PKEY_get_base_id(pk);
	if (id == EVP_PKEY_RSA) {
		if (!EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &a) ||
		    !EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_E, &b) ||
		    BN_num_bytes(a) > (int)sizeof(out->n) || BN_num_bytes(b) > 4)
			goto out;
		out->rsa = true;
		out->n_len = (size_t)BN_bn2bin(a, out->n);
		out->e = (uint32_t)BN_get_word(b);
		rc = 0;
	} else if (id == EVP_PKEY_EC) {
		if (!EVP_PKEY_get_utf8_string_param(pk, OSSL_PKEY_PARAM_GROUP_NAME,
						    group, sizeof(group), NULL) ||
		    (strcmp(group, "P-256") && strcmp(group, "prime256v1")) ||
		    !EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_X, &a) ||
		    !EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_Y, &b) ||
		    BN_bn2binpad(a, out->x, 32) != 32 ||
		    BN_bn2binpad(b, out->y, 32) != 32)
			goto out;
		rc = 0;
	} else {
		rc = -EPROTONOSUPPORT;
	}
out:
	BN_free(a);
	BN_free(b);
	return rc;
}

int shirudo_cert_verify_chain(const struct shirudo_cert *cert,
			      const char *bundle_path, const char **reason)
{
	X509_STORE_CTX *ctx = NULL;
	X509_STORE *store;
	int rc = -EIO;

	*reason = "";
	if (!cert || !cert->impl || !bundle_path)
		return -EINVAL;
	store = X509_STORE_new();
	if (!store)
		return -ENOMEM;
	if (X509_STORE_load_file(store, bundle_path) != 1) {
		rc = -EINVAL;
		goto out;
	}
	/* An intermediate in the bundle is a trust anchor too. */
	X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
	ctx = X509_STORE_CTX_new();
	if (!ctx || X509_STORE_CTX_init(ctx, store, cert->impl, NULL) != 1)
		goto out;
	if (X509_verify_cert(ctx) == 1) {
		rc = 0;
	} else {
		*reason = X509_verify_cert_error_string(
				X509_STORE_CTX_get_error(ctx));
		rc = -EKEYREJECTED;
	}
out:
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return rc;
}
