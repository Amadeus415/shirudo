// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2025 Google LLC.
 * Copyright (c) 2026 Authors of shirudo
 *
 * Vendored from tools/bpf/bpftool/sign.c (dual-licensed
 * (GPL-2.0-only OR BSD-2-Clause); shirudo consumes the BSD branch).
 * Adapted to take pkey/cert paths as arguments, route errors
 * through util/log.h, and present a shirudo-local I/O struct
 * instead of libbpf's bpf_load_and_run_opts (shirudo issues raw
 * BPF_PROG_LOAD; the bpftool struct is incidental). The
 * register_session_key() helper, which adds a cert to the calling
 * task's session keyring, is dropped -- shirudo's operator side
 * doesn't need it; the target side uses util/keyring.c against
 * the named "shirudo" keyring.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "log.h"
#include "malloc.h"
#include "sign.h"

#define OPEN_SSL_ERR_BUF_LEN	256

#if !defined(OPENSSL_VERSION_MAJOR) || (OPENSSL_VERSION_MAJOR < 3)
#define ERR_get_error_all(file, line, func, data, flags) \
	ERR_get_error_line_data(file, line, data, flags)
#endif

static void display_openssl_errors(void)
{
	char buf[OPEN_SSL_ERR_BUF_LEN];
	const char *file;
	const char *data;
	unsigned long e;
	int flags;
	int line;

	while ((e = ERR_get_error_all(&file, &line, NULL, &data, &flags))) {
		ERR_error_string_n(e, buf, sizeof(buf));
		if (data && (flags & ERR_TXT_STRING))
			pr_err("OpenSSL %s: %s:%d: %s", buf, file, line, data);
		else
			pr_err("OpenSSL %s: %s:%d", buf, file, line);
	}
}

#define DISPLAY_OSSL_ERR(cond)				\
	do {						\
		bool __cond = (cond);			\
		if (__cond && ERR_peek_error())		\
			display_openssl_errors();	\
	} while (0)

static bool openssl_has_mldsa(void)
{
	return OPENSSL_version_major() > 3 ||
	       (OPENSSL_version_major() == 3 && OPENSSL_version_minor() >= 5);
}

int open_signing_key(const char *pkey_path)
{
	struct stat st;
	int fd, rc;

	/* A FIFO in its place would block open() before fstat() refuses it. */
	fd = open(pkey_path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		rc = -errno;
		pr_err("open private key %s: %s", pkey_path, strerror(errno));
		if (rc == -ENOENT)
			pr_hint("run `shirudo genkey` on the operator, or point --keys-dir (or SHIRUDO_KEYS_DIR) at the directory holding signing_key.pem and cert.der");
		else if (rc == -EACCES)
			pr_hint("run as the user that owns %s rather than loosening its mode 0600",
				pkey_path);
		return rc;
	}
	if (fstat(fd, &st)) {
		rc = -errno;
		pr_err("stat private key %s: %s", pkey_path, strerror(errno));
		goto err;
	}
	rc = -EPERM;
	if (!S_ISREG(st.st_mode)) {
		pr_err("signing key %s is not a regular file", pkey_path);
		goto err;
	}
	if ((st.st_mode & 07777) != 0600) {
		pr_err("signing key %s has mode 0%o, must be 0600",
		       pkey_path, (__u32)(st.st_mode & 07777));
		pr_hint("run `chmod 0600 %s`", pkey_path);
		goto err;
	}
	return fd;
err:
	close(fd);
	return rc;
}

static EVP_PKEY *read_private_key(const char *pkey_path)
{
	EVP_PKEY *private_key = NULL;
	BIO *b;
	int fd;

	fd = open_signing_key(pkey_path);
	if (fd < 0)
		return NULL;
	b = BIO_new_fd(fd, BIO_CLOSE);
	if (!b) {
		close(fd);
		DISPLAY_OSSL_ERR(1);
		return NULL;
	}
	private_key = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
	BIO_free(b);
	DISPLAY_OSSL_ERR(!private_key);
	if (!private_key) {
		pr_err("signing key %s: OpenSSL cannot read it as a PEM private key",
		       pkey_path);
		if (!openssl_has_mldsa())
			pr_hint("this host runs %s; ML-DSA-87 keys need OpenSSL 3.5 or newer",
				OpenSSL_version(OPENSSL_VERSION));
	}
	return private_key;
}

static X509 *read_x509(const char *x509_name)
{
	unsigned char buf[2];
	X509 *x509 = NULL;
	BIO *b;
	int n;

	b = BIO_new_file(x509_name, "rb");
	if (!b)
		goto cleanup;

	/* sniff the first two bytes: 0x30 + length-of-length -> raw DER */
	n = BIO_read(b, buf, 2);
	if (n != 2)
		goto cleanup;
	if (BIO_reset(b) != 0)
		goto cleanup;

	if (buf[0] == 0x30 && buf[1] >= 0x81 && buf[1] <= 0x84)
		x509 = d2i_X509_bio(b, NULL);
	else
		x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

cleanup:
	BIO_free(b);
	DISPLAY_OSSL_ERR(!x509);
	return x509;
}

static bool pkey_is_mldsa(const EVP_PKEY *pkey)
{
	const char *name = EVP_PKEY_get0_type_name(pkey);

	return name && strncasecmp(name, "ML-DSA", 6) == 0;
}

int cms_sign(struct shirudo_sign_io *io,
	     const char *pkey_path, const char *cert_path)
{
	unsigned int signer_flags = CMS_NOCERTS | CMS_BINARY | CMS_NOSMIMECAP |
#ifdef CMS_NO_SIGNING_TIME
				    CMS_NO_SIGNING_TIME |
#endif
				    CMS_USE_KEYID | CMS_NOATTR;
	unsigned int hash_len = SHIRUDO_SHA256_LEN;
	const EVP_MD *cms_digest = EVP_sha256();
	BIO *bd_in = NULL, *bd_out = NULL;
	EVP_PKEY *private_key = NULL;
	CMS_ContentInfo *cms = NULL;
	long actual_sig_len = 0;
	void *content = NULL;
	X509 *x509 = NULL;
	size_t content_sz;
	int err = 0;

	/*
	 * The signature and the payload hash both span insns || data --
	 * the concatenation the kernel folds and verifies at load. Build
	 * that once and feed it to both CMS_final and the digest.
	 */
	content_sz = io->insns_sz + io->data_sz;
	content = xmalloc(content_sz);
	if (!content) {
		err = -ENOMEM;
		goto cleanup;
	}
	memcpy(content, io->insns, io->insns_sz);
	if (io->data_sz)
		memcpy((char *)content + io->insns_sz, io->data, io->data_sz);

	bd_in = BIO_new_mem_buf(content, content_sz);
	if (!bd_in) {
		err = -ENOMEM;
		goto cleanup;
	}

	private_key = read_private_key(pkey_path);
	if (!private_key) {
		err = -EINVAL;
		goto cleanup;
	}
	if (!pkey_is_mldsa(private_key)) {
		pr_err("%s: %s key; shirudo signs with ML-DSA only", pkey_path,
		       EVP_PKEY_get0_type_name(private_key) ?: "unknown");
		pr_hint("create an ML-DSA-87 pair with `shirudo genkey --keys-dir <dir>`");
		err = -EINVAL;
		goto cleanup;
	}

	x509 = read_x509(cert_path);
	if (!x509) {
		pr_err("certificate %s: not an X.509 certificate in DER or PEM form",
		       cert_path);
		pr_hint("pass the cert.der `shirudo genkey` wrote beside the signing key");
		err = -EINVAL;
		goto cleanup;
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && OPENSSL_VERSION_NUMBER < 0x40000000L
	/*
	 * OpenSSL 3.x cannot combine ML-DSA with CMS_NOATTR, so fall back
	 * to signedAttrs, where the kernel accepts only SHA-512 for ML-DSA
	 * (crypto/asymmetric_keys/public_key.c). Same workaround as
	 * bpftool and module signing; OpenSSL 4 signs the content directly.
	 */
	if (pkey_is_mldsa(private_key)) {
		signer_flags &= ~CMS_NOATTR;
		cms_digest = EVP_sha512();
	}
#endif

	cms = CMS_sign(NULL, NULL, NULL, NULL,
		       CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY | CMS_DETACHED |
		       CMS_STREAM);
	if (!cms) {
		err = -EINVAL;
		goto cleanup;
	}

	if (!CMS_add1_signer(cms, x509, private_key, cms_digest,
			     signer_flags)) {
		unsigned long e = ERR_peek_last_error();

		display_openssl_errors();
		if (ERR_GET_LIB(e) == ERR_LIB_CMS &&
		    ERR_GET_REASON(e) == CMS_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE) {
			pr_err("signing key %s and certificate %s are not a pair",
			       pkey_path, cert_path);
			pr_hint("pass the cert.der `shirudo genkey` wrote with this key; `shirudo keys --keys-dir <dir>` compares a pair");
		}
		err = -EINVAL;
		goto cleanup;
	}

	if (CMS_final(cms, bd_in, NULL, CMS_NOCERTS | CMS_BINARY) != 1) {
		err = -EIO;
		goto cleanup;
	}

	if (EVP_Digest(content, content_sz, io->payload_sha256,
		       &hash_len, EVP_sha256(), NULL) != 1) {
		err = -EIO;
		goto cleanup;
	}

	bd_out = BIO_new(BIO_s_mem());
	if (!bd_out) {
		err = -ENOMEM;
		goto cleanup;
	}

	if (!i2d_CMS_bio_stream(bd_out, cms, NULL, 0)) {
		err = -EIO;
		goto cleanup;
	}

	actual_sig_len = BIO_get_mem_data(bd_out, NULL);
	if (actual_sig_len <= 0) {
		err = -EIO;
		goto cleanup;
	}

	if ((size_t)actual_sig_len > io->signature_sz) {
		err = -ENOSPC;
		goto cleanup;
	}

	if (BIO_read(bd_out, io->signature, actual_sig_len) != actual_sig_len) {
		err = -EIO;
		goto cleanup;
	}

	io->signature_sz = (size_t)actual_sig_len;
cleanup:
	BIO_free(bd_out);
	CMS_ContentInfo_free(cms);
	X509_free(x509);
	EVP_PKEY_free(private_key);
	BIO_free(bd_in);
	xfree(content, content_sz);
	DISPLAY_OSSL_ERR(err < 0);
	return err;
}
