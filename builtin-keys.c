// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Inspect the cert / keyring material this host holds.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "builtin.h"
#include "util/help.h"
#include "util/keyring.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/paths.h"

static void openssl_complain(const char *where)
{
	unsigned long e = ERR_get_error();
	char buf[256];

	ERR_error_string_n(e, buf, sizeof(buf));
	pr_err("openssl: %s: %s", where, buf);
}

static int path_exists(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0;
}

static X509 *read_cert_der(const char *path)
{
	BIO *bio;
	X509 *c;

	bio = BIO_new_file(path, "rb");
	if (!bio) {
		openssl_complain("BIO_new_file");
		return NULL;
	}
	c = d2i_X509_bio(bio, NULL);
	BIO_free(bio);
	if (!c)
		openssl_complain("d2i_X509_bio");
	return c;
}

static EVP_PKEY *read_priv_pem(const char *path)
{
	EVP_PKEY *k;
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp) {
		pr_err("open %s: %s", path, strerror(errno));
		return NULL;
	}
	k = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!k)
		openssl_complain("PEM_read_PrivateKey");
	return k;
}

static void name_to_str(X509_NAME *name, char *out, size_t out_sz)
{
	if (!X509_NAME_oneline(name, out, (int)out_sz)) {
		snprintf(out, out_sz, "(parse error)");
		return;
	}
}

static void asn1_time_to_iso(const ASN1_TIME *t, char *out, size_t out_sz)
{
	struct tm tm;

	if (!ASN1_TIME_to_tm(t, &tm)) {
		snprintf(out, out_sz, "(unparseable)");
		return;
	}
	if (!strftime(out, out_sz, "%Y-%m-%dT%H:%M:%SZ", &tm))
		snprintf(out, out_sz, "(format error)");
}

static long days_remaining(const ASN1_TIME *not_after)
{
	int days, secs;

	if (!ASN1_TIME_diff(&days, &secs, NULL, not_after))
		return -1;
	return days;
}

static int compute_cert_fpr(X509 *c, unsigned char fpr[SHA256_DIGEST_LENGTH])
{
	unsigned int n = SHA256_DIGEST_LENGTH;

	if (X509_digest(c, EVP_sha256(), fpr, &n) != 1) {
		openssl_complain("X509_digest");
		return -1;
	}
	return 0;
}

/* SHA-256 over the SPKI; comparable across a cert and its key. */
static int compute_spki_fpr(EVP_PKEY *pkey,
			    unsigned char fpr[SHA256_DIGEST_LENGTH])
{
	unsigned int n = SHA256_DIGEST_LENGTH;
	unsigned char *der = NULL;
	int der_len;
	int rc = -1;

	der_len = i2d_PUBKEY(pkey, &der);
	if (der_len <= 0) {
		openssl_complain("i2d_PUBKEY");
		return -1;
	}
	if (EVP_Digest(der, (size_t)der_len, fpr, &n,
		       EVP_sha256(), NULL) != 1) {
		openssl_complain("EVP_Digest");
		goto out;
	}
	rc = 0;
out:
	OPENSSL_free(der);
	return rc;
}

static void print_fpr(const char *label, const unsigned char *fpr)
{
	printf("    %s: SHA256:", label);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", fpr[i]);
	printf("\n");
}

static const char *pkey_algorithm(EVP_PKEY *pkey)
{
	int t = EVP_PKEY_base_id(pkey);

	switch (t) {
	case EVP_PKEY_RSA:	return "RSA";
	case EVP_PKEY_EC:	return "EC";
	case EVP_PKEY_ED25519:	return "Ed25519";
	case EVP_PKEY_ED448:	return "Ed448";
	default:		return "unknown";
	}
}

static int dump_operator_cert(X509 *cert, const char *cert_path)
{
	X509_NAME *subj = X509_get_subject_name(cert);
	X509_NAME *iss  = X509_get_issuer_name(cert);
	const ASN1_TIME *nb = X509_get0_notBefore(cert);
	const ASN1_TIME *na = X509_get0_notAfter(cert);
	EVP_PKEY *pub = X509_get0_pubkey(cert);
	unsigned char fpr[SHA256_DIGEST_LENGTH];
	char subj_s[256], iss_s[256], nb_s[32], na_s[32];
	long left;
	int self_signed;

	name_to_str(subj, subj_s, sizeof(subj_s));
	name_to_str(iss, iss_s, sizeof(iss_s));
	asn1_time_to_iso(nb, nb_s, sizeof(nb_s));
	asn1_time_to_iso(na, na_s, sizeof(na_s));
	left = days_remaining(na);
	self_signed = (X509_NAME_cmp(subj, iss) == 0);

	printf("  %s:\n", cert_path);
	printf("    subject:    %s\n", subj_s);
	printf("    issuer:     %s%s\n", iss_s,
	       self_signed ? " (self-signed)" : "");
	printf("    notBefore:  %s\n", nb_s);
	if (left < 0)
		printf("    notAfter:   %s  (EXPIRED %ld days ago)\n",
		       na_s, -left);
	else
		printf("    notAfter:   %s  (%ld days remaining)\n",
		       na_s, left);
	if (pub)
		printf("    public-key: %s-%d\n",
		       pkey_algorithm(pub), EVP_PKEY_get_bits(pub));
	if (compute_cert_fpr(cert, fpr) == 0)
		print_fpr("cert-sha256", fpr);
	return 0;
}

static int compare_priv_to_cert(X509 *cert, const char *pkey_path)
{
	EVP_PKEY *priv;
	EVP_PKEY *pub_in_cert = X509_get0_pubkey(cert);
	unsigned char fpr_priv[SHA256_DIGEST_LENGTH];
	unsigned char fpr_cert[SHA256_DIGEST_LENGTH];
	int rc = 0;

	if (!path_exists(pkey_path)) {
		printf("  %s: (not present on this host -- target mode)\n",
		       pkey_path);
		return 0;
	}

	priv = read_priv_pem(pkey_path);
	if (!priv)
		return -1;

	printf("  %s:\n", pkey_path);
	printf("    algorithm:  %s-%d\n",
	       pkey_algorithm(priv), EVP_PKEY_get_bits(priv));

	if (compute_spki_fpr(priv, fpr_priv) != 0 ||
	    compute_spki_fpr(pub_in_cert, fpr_cert) != 0) {
		rc = -1;
		goto out;
	}
	print_fpr("spki-sha256", fpr_priv);

	if (memcmp(fpr_priv, fpr_cert, SHA256_DIGEST_LENGTH) == 0) {
		printf("    cert-match: OK (signing key matches cert)\n");
	} else {
		printf("    cert-match: MISMATCH (private key does NOT match cert)\n");
		pr_warn("keys: private key and cert have different public keys");
		rc = -1;
	}
out:
	EVP_PKEY_free(priv);
	return rc;
}

static int keys_dump_disk_material(const char *cert_path,
				   const char *pkey_path)
{
	X509 *cert;
	int rc;

	cert = read_cert_der(cert_path);
	if (!cert)
		return 1;

	printf("on-disk key material:\n");
	rc = dump_operator_cert(cert, cert_path);
	if (rc == 0)
		rc = compare_priv_to_cert(cert, pkey_path);
	X509_free(cert);
	return rc ? 1 : 0;
}

struct list_ctx {
	int count;
};

static void print_key(key_serial_t serial, const char *type,
		      const char *description, void *ud)
{
	struct list_ctx *c = ud;

	printf("  serial=%-10d type=%-10s %s\n",
	       (int)serial, type, description);
	c->count++;
}

static int keys_list_keyring(key_serial_t ring)
{
	struct list_ctx c = {};
	int rc;

	printf("target keyring \"%s\" (serial=%d):\n",
	       SHIRUDO_KEYRING_NAME, (int)ring);
	rc = shirudo_keyring_list(ring, print_key, &c);
	if (rc) {
		pr_err("keyring list: %s", strerror(-rc));
		return 1;
	}
	if (c.count == 0)
		printf("  (empty)\n");
	return 0;
}

static const struct shirudo_help_item keys_options[] = {
	{ "--keys-dir <dir>", "read signing_key.pem + cert.der from <dir>" },
};

static const struct shirudo_help_section keys_help_sections[] = {
	{ "options:", keys_options,
	  ARRAY_SIZE(keys_options) },
};

static const struct shirudo_help keys_help = {
	.usage   = "shirudo keys [--keys-dir <dir>]",
	.summary = "Inspect the shirudo key material this host holds: the "
		   "on-disk cert and\nsigning key (if present) and the "
		   "\"" SHIRUDO_KEYRING_NAME "\" named kernel keyring (if "
		   "init'd).\nLocal-only on either side.",
	.sections   = keys_help_sections,
	.n_sections = ARRAY_SIZE(keys_help_sections),
	.footer  = "Default paths:\n"
		   "  " SHIRUDO_CERT_PATH "\n"
		   "  " SHIRUDO_SIGNING_KEY_PATH "\n"
		   "Or set the " SHIRUDO_KEYS_DIR_ENV
		   " environment variable.",
};

static void usage(void)
{
	fprintf(stderr, "usage: %s\n", keys_help.usage);
}

int cmd_keys(int argc, const char **argv)
{
	const char *keys_dir_arg = NULL;
	const char *keys_dir;
	char pkey_path[PATH_MAX];
	char cert_path[PATH_MAX];
	bool shown = false;
	key_serial_t ring;
	int rc = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--keys-dir") == 0 &&
		    i + 1 < argc) {
			keys_dir_arg = argv[++i];
		} else if (strncmp(argv[i], "--keys-dir=", 11) == 0) {
			keys_dir_arg = argv[i] + 11;
		} else if (shirudo_is_help(argv[i])) {
			shirudo_print_help(&keys_help);
			return 0;
		} else {
			pr_err("keys: unknown option '%s'", argv[i]);
			usage();
			return 2;
		}
	}

	keys_dir = shirudo_keys_dir_resolve(keys_dir_arg);

	rc = shirudo_key_paths(keys_dir, pkey_path, sizeof(pkey_path),
			       cert_path, sizeof(cert_path));
	if (rc) {
		pr_err("keys: invalid keys dir %s: %s",
		       keys_dir, strerror(-rc));
		return 2;
	}

	/*
	 * Both roles can coexist on one host (cert.der is held by the
	 * target as well as the operator), so report whatever is present
	 * rather than picking one mode: the on-disk cert + signing key,
	 * then the kernel keyring once `shirudo init` has populated one.
	 */
	if (path_exists(cert_path)) {
		if (keys_dump_disk_material(cert_path, pkey_path))
			rc = 1;
		shown = true;
	}

	ring = shirudo_keyring_find(SHIRUDO_KEYRING_NAME);
	if (ring >= 0) {
		if (shown)
			printf("\n");
		if (keys_list_keyring(ring))
			rc = 1;
		shown = true;
	} else if (ring != -ENOKEY) {
		pr_err("keyring \"%s\" lookup: %s",
		       SHIRUDO_KEYRING_NAME, strerror(-ring));
		rc = 1;
	}

	if (!shown) {
		pr_err("no shirudo key material on this host: no %s and no "
		       "\"%s\" kernel keyring -- run `shirudo genkey` "
		       "(operator) or `shirudo init` (target)",
		       cert_path, SHIRUDO_KEYRING_NAME);
		rc = 1;
	}
	return rc;
}
