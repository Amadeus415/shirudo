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

#ifdef SHIRUDO_CRYPTO_MBEDTLS
#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include "util/crypto.h"
#else
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#endif

#include "builtin.h"
#include "util/help.h"
#include "util/keyring.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/malloc.h"
#include "util/paths.h"

#ifndef SHIRUDO_CRYPTO_MBEDTLS

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

/*
 * Format an "Expires in:" value: "9y 213d" / "182d" / "EXPIRED 3 days ago".
 * Keeps the same expired-on-negative convention as days_remaining().
 */
static void format_expires_in(long days, char *out, size_t out_sz)
{
	if (days < 0) {
		snprintf(out, out_sz, "EXPIRED %ld days ago", -days);
		return;
	}
	if (days >= 365)
		snprintf(out, out_sz, "%ldy %ldd", days / 365, days % 365);
	else
		snprintf(out, out_sz, "%ldd", days);
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
	printf("  %-22s SHA256:", label);
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

static int dump_operator_cert(X509 *cert, const char *cert_path,
			      const unsigned char cert_spki_fpr[SHA256_DIGEST_LENGTH])
{
	X509_NAME *subj = X509_get_subject_name(cert);
	X509_NAME *iss  = X509_get_issuer_name(cert);
	const ASN1_TIME *nb = X509_get0_notBefore(cert);
	const ASN1_TIME *na = X509_get0_notAfter(cert);
	EVP_PKEY *pub = X509_get0_pubkey(cert);
	unsigned char fpr[SHA256_DIGEST_LENGTH];
	char subj_s[256], iss_s[256], nb_s[32], na_s[32], exp_s[48];
	long left;
	int self_signed;

	name_to_str(subj, subj_s, sizeof(subj_s));
	name_to_str(iss, iss_s, sizeof(iss_s));
	asn1_time_to_iso(nb, nb_s, sizeof(nb_s));
	asn1_time_to_iso(na, na_s, sizeof(na_s));
	left = days_remaining(na);
	format_expires_in(left, exp_s, sizeof(exp_s));
	self_signed = (X509_NAME_cmp(subj, iss) == 0);

	printf("Cert (%s):\n", cert_path);
	printf("  %-22s %s\n", "Subject:", subj_s);
	printf("  %-22s %s%s\n", "Issuer:", iss_s,
	       self_signed ? "  (self-signed)" : "");
	if (pub)
		printf("  %-22s %s-%d\n", "Public-key:",
		       pkey_algorithm(pub), EVP_PKEY_get_bits(pub));
	if (compute_cert_fpr(cert, fpr) == 0)
		print_fpr("Fingerprint:", fpr);
	print_fpr("SPKI fingerprint:", cert_spki_fpr);
	printf("  %-22s %s\n", "Valid from:", nb_s);
	printf("  %-22s %s\n", "Valid until:", na_s);
	printf("  %-22s %s\n", "Expires in:", exp_s);
	return 0;
}

static int dump_signing_key(const char *pkey_path,
			    const unsigned char cert_spki_fpr[SHA256_DIGEST_LENGTH])
{
	EVP_PKEY *priv;
	unsigned char fpr_priv[SHA256_DIGEST_LENGTH];
	int rc = 0;

	if (!path_exists(pkey_path)) {
		printf("Signing key (%s):\n", pkey_path);
		printf("  %-22s %s\n", "Present:",
		       "no  (target host -- private key lives on the operator)");
		return 0;
	}

	priv = read_priv_pem(pkey_path);
	if (!priv)
		return -1;

	printf("Signing key (%s):\n", pkey_path);
	printf("  %-22s %s\n", "Present:", "yes");
	printf("  %-22s %s-%d\n", "Algorithm:",
	       pkey_algorithm(priv), EVP_PKEY_get_bits(priv));

	if (compute_spki_fpr(priv, fpr_priv) != 0) {
		rc = -1;
		goto out;
	}
	print_fpr("SPKI fingerprint:", fpr_priv);

	if (memcmp(fpr_priv, cert_spki_fpr, SHA256_DIGEST_LENGTH) == 0) {
		printf("  %-22s %s\n", "Cert match:",
		       "OK  (signing key matches cert)");
	} else {
		printf("  %-22s %s\n", "Cert match:",
		       "MISMATCH  (private key does NOT match cert)");
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
	EVP_PKEY *pub;
	unsigned char cert_spki_fpr[SHA256_DIGEST_LENGTH];
	int rc;

	cert = read_cert_der(cert_path);
	if (!cert)
		return 1;

	pub = X509_get0_pubkey(cert);
	if (!pub) {
		X509_free(cert);
		return 1;
	}
	if (compute_spki_fpr(pub, cert_spki_fpr) != 0) {
		X509_free(cert);
		return 1;
	}

	rc = dump_operator_cert(cert, cert_path, cert_spki_fpr);
	if (rc == 0) {
		printf("\n");
		rc = dump_signing_key(pkey_path, cert_spki_fpr);
	}
	X509_free(cert);
	return rc ? 1 : 0;
}

#else

struct local_cert {
	mbedtls_x509_crt crt;
};

static int path_exists(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0;
}

static int read_cert_der(const char *path, struct local_cert *cert)
{
	int rc;

	mbedtls_x509_crt_init(&cert->crt);
	rc = mbedtls_x509_crt_parse_file(&cert->crt, path);
	if (rc || !cert->crt.raw.p) {
		char buf[128];
		mbedtls_strerror(rc, buf, sizeof(buf));
		pr_err("mbedTLS: read certificate %s: %s", path, buf);
		mbedtls_x509_crt_free(&cert->crt);
		return -1;
	}
	return 0;
}

static void free_cert(struct local_cert *cert)
{
	mbedtls_x509_crt_free(&cert->crt);
}

static mbedtls_pk_context *read_priv_pem(const char *path)
{
	mbedtls_pk_context *key = xmalloc(sizeof(*key));
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
	int rc;

	mbedtls_pk_init(key);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&drbg);
	rc = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (!rc)
		rc = mbedtls_pk_parse_keyfile(key, path, NULL,
					       mbedtls_ctr_drbg_random, &drbg);
	mbedtls_ctr_drbg_free(&drbg);
	mbedtls_entropy_free(&entropy);
	if (rc) {
		char buf[128];
		mbedtls_strerror(rc, buf, sizeof(buf));
		pr_err("mbedTLS: read private key %s: %s", path, buf);
		mbedtls_pk_free(key);
		xfree(key, sizeof(*key));
		return NULL;
	}
	return key;
}

static void name_to_str(const mbedtls_x509_name *name, char *out, size_t out_sz)
{
	if (mbedtls_x509_dn_gets(out, out_sz, name) < 0)
		snprintf(out, out_sz, "(parse error)");
}

static time_t x509_time_epoch(const mbedtls_x509_time *t)
{
	struct tm tm = {
		.tm_year = t->year - 1900, .tm_mon = t->mon - 1,
		.tm_mday = t->day, .tm_hour = t->hour,
		.tm_min = t->min, .tm_sec = t->sec, .tm_isdst = 0,
	};

	return timegm(&tm);
}

static void asn1_time_to_iso(const mbedtls_x509_time *t,
			     char *out, size_t out_sz)
{
	struct tm tm = {
		.tm_year = t->year - 1900, .tm_mon = t->mon - 1,
		.tm_mday = t->day, .tm_hour = t->hour,
		.tm_min = t->min, .tm_sec = t->sec, .tm_isdst = 0,
	};

	if (!strftime(out, out_sz, "%Y-%m-%dT%H:%M:%SZ", &tm))
		snprintf(out, out_sz, "(format error)");
}

static long days_remaining(const mbedtls_x509_time *not_after)
{
	time_t now = time(NULL), expiry = x509_time_epoch(not_after);

	if (now == (time_t)-1 || expiry == (time_t)-1)
		return -1;
	return (long)(difftime(expiry, now) / (24 * 60 * 60));
}

static void format_expires_in(long days, char *out, size_t out_sz)
{
	if (days < 0)
		snprintf(out, out_sz, "EXPIRED %ld days ago", -days);
	else if (days >= 365)
		snprintf(out, out_sz, "%ldy %ldd", days / 365, days % 365);
	else
		snprintf(out, out_sz, "%ldd", days);
}

static int compute_cert_fpr(const struct local_cert *cert,
			    unsigned char fpr[SHIRUDO_CRYPTO_SHA256_LEN])
{
	return shirudo_sha256_buffer(cert->crt.raw.p, cert->crt.raw.len, fpr);
}

static int compute_spki_fpr(const mbedtls_pk_context *key,
			    unsigned char fpr[SHIRUDO_CRYPTO_SHA256_LEN])
{
	unsigned char der[2048];
	int n = mbedtls_pk_write_pubkey_der(key, der, sizeof(der));

	if (n <= 0)
		return -1;
	return shirudo_sha256_buffer(der + sizeof(der) - n, (size_t)n, fpr);
}

static void print_fpr(const char *label, const unsigned char *fpr)
{
	printf("  %-22s SHA256:", label);
	for (int i = 0; i < SHIRUDO_CRYPTO_SHA256_LEN; i++)
		printf("%02x", fpr[i]);
	printf("\n");
}

static int dump_operator_cert(const struct local_cert *cert, const char *path,
			      const unsigned char spki[SHIRUDO_CRYPTO_SHA256_LEN])
{
	char subject[256], issuer[256], nb[32], na[32], exp[48];
	unsigned char fpr[SHIRUDO_CRYPTO_SHA256_LEN];

	name_to_str(&cert->crt.subject, subject, sizeof(subject));
	name_to_str(&cert->crt.issuer, issuer, sizeof(issuer));
	asn1_time_to_iso(&cert->crt.valid_from, nb, sizeof(nb));
	asn1_time_to_iso(&cert->crt.valid_to, na, sizeof(na));
	format_expires_in(days_remaining(&cert->crt.valid_to), exp, sizeof(exp));
	printf("Cert (%s):\n", path);
	printf("  %-22s %s\n", "Subject:", subject);
	printf("  %-22s %s%s\n", "Issuer:", issuer,
		   cert->crt.subject_raw.len == cert->crt.issuer_raw.len &&
		   !memcmp(cert->crt.subject_raw.p, cert->crt.issuer_raw.p,
			   cert->crt.subject_raw.len) ? "  (self-signed)" : "");
	printf("  %-22s %s-%zu\n", "Public-key:",
		   mbedtls_pk_get_name(&cert->crt.pk),
		   mbedtls_pk_get_bitlen(&cert->crt.pk));
	if (!compute_cert_fpr(cert, fpr))
		print_fpr("Fingerprint:", fpr);
	print_fpr("SPKI fingerprint:", spki);
	printf("  %-22s %s\n", "Valid from:", nb);
	printf("  %-22s %s\n", "Valid until:", na);
	printf("  %-22s %s\n", "Expires in:", exp);
	return 0;
}

static int dump_signing_key(const char *path,
			    const unsigned char cert_spki[SHIRUDO_CRYPTO_SHA256_LEN])
{
	mbedtls_pk_context *key;
	unsigned char fpr[SHIRUDO_CRYPTO_SHA256_LEN];
	int rc = 0;

	if (!path_exists(path)) {
		printf("Signing key (%s):\n  %-22s %s\n", path, "Present:",
		       "no  (target host -- private key lives on the operator)");
		return 0;
	}
	key = read_priv_pem(path);
	if (!key)
		return -1;
	printf("Signing key (%s):\n", path);
	printf("  %-22s %s\n", "Present:", "yes");
	printf("  %-22s %s-%zu\n", "Algorithm:",
	       mbedtls_pk_get_name(key), mbedtls_pk_get_bitlen(key));
	if (compute_spki_fpr(key, fpr))
		rc = -1;
	else {
		print_fpr("SPKI fingerprint:", fpr);
		if (!memcmp(fpr, cert_spki, sizeof(fpr)))
			printf("  %-22s %s\n", "Cert match:", "OK  (signing key matches cert)");
		else {
			printf("  %-22s %s\n", "Cert match:", "MISMATCH  (private key does NOT match cert)");
			rc = -1;
		}
	}
	mbedtls_pk_free(key);
	xfree(key, sizeof(*key));
	return rc;
}

static int keys_dump_disk_material(const char *cert_path, const char *pkey_path)
{
	struct local_cert cert;
	unsigned char spki[SHIRUDO_CRYPTO_SHA256_LEN];
	int rc;

	if (read_cert_der(cert_path, &cert) ||
	    compute_spki_fpr(&cert.crt.pk, spki)) {
		free_cert(&cert);
		return 1;
	}
	rc = dump_operator_cert(&cert, cert_path, spki);
	if (!rc) {
		printf("\n");
		rc = dump_signing_key(pkey_path, spki);
	}
	free_cert(&cert);
	return rc ? 1 : 0;
}

#endif

struct list_row {
	key_serial_t	serial;
	char		*type;
	char		*description;
};

#define LIST_ROW_CAP	256

struct list_ctx {
	struct list_row	rows[LIST_ROW_CAP];
	int		count;
};

static void collect_key(key_serial_t serial, const char *type,
			const char *description, void *ud)
{
	struct list_ctx *c = ud;

	if (c->count >= LIST_ROW_CAP)
		return;
	c->rows[c->count].serial = serial;
	c->rows[c->count].type = xstrdup(type);
	c->rows[c->count].description = xstrdup(description);
	c->count++;
}

static int keys_list_keyring(key_serial_t ring)
{
	struct list_ctx c = {};
	key_serial_t pin;
	int rc, i;

	printf("Keyring (%s):\n", SHIRUDO_KEYRING_NAME);
	printf("  %-22s %d\n", "Serial:", (int)ring);

	pin = shirudo_keyring_read_pinned_serial();
	if (pin >= 1) {
		const char *match = pin == ring ? "matches" : "MISMATCH";

		printf("  %-22s %d  (%s)\n", "Pinned serial:",
		       (int)pin, match);
		if (pin != ring)
			pr_warn("keyring serial pin %d != live serial %d "
				"(swap?)", (int)pin, (int)ring);
	} else if (pin == (key_serial_t)-ENOENT) {
		printf("  %-22s %s\n", "Pinned serial:",
		       "(none recorded)");
	} else {
		printf("  %-22s read error: %s\n", "Pinned serial:",
		       strerror(-pin));
	}

	rc = shirudo_keyring_list(ring, collect_key, &c);
	if (rc) {
		pr_err("keyring list: %s", strerror(-rc));
		goto out;
	}
	printf("  Members (%d):\n", c.count);
	if (c.count == 0)
		printf("    (empty)\n");
	for (i = 0; i < c.count; i++)
		printf("    serial=%-10d  type=%-10s  %s\n",
		       (int)c.rows[i].serial,
		       c.rows[i].type ? c.rows[i].type : "?",
		       c.rows[i].description ? c.rows[i].description : "?");
out:
	for (i = 0; i < c.count; i++) {
		xstrfree(c.rows[i].type);
		xstrfree(c.rows[i].description);
	}
	return rc ? 1 : 0;
}

static void keyring_absent(key_serial_t rc)
{
	printf("Keyring (%s):\n", SHIRUDO_KEYRING_NAME);
	if (rc == (key_serial_t)-ENOKEY)
		printf("  %-22s %s\n", "Present:",
		       "no  (operator host, or `shirudo init` not yet run)");
	else
		printf("  %-22s lookup error: %s\n", "Present:",
		       strerror(-rc));
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
		   "  " SHIRUDO_SIGNING_KEY_PATH "\n\n"
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
	} else if (ring == -ENOKEY) {
		if (shown) {
			printf("\n");
			keyring_absent(ring);
		}
	} else {
		if (shown)
			printf("\n");
		keyring_absent(ring);
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
