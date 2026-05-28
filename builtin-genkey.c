// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Generate the shirudo X.509 self-signed signing cert.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "builtin.h"
#include "util/help.h"
#include "util/log.h"
#include "util/paths.h"

#define ALG_RSA_BITS	2048
#define VALIDITY_DAYS	(10L * 365L)
#define CERT_CN		"shirudo"

static void openssl_complain(const char *where)
{
	unsigned long e = ERR_get_error();
	char buf[256];

	ERR_error_string_n(e, buf, sizeof(buf));
	pr_err("openssl: %s: %s", where, buf);
}

static int mkdir_p_mode(const char *path, mode_t mode)
{
	struct stat st;
	char tmp[PATH_MAX];
	size_t len;
	int n;

	if (!path || !*path) {
		pr_err("mkdir: empty path");
		return -1;
	}

	n = snprintf(tmp, sizeof(tmp), "%s", path);
	if (n < 0 || (size_t)n >= sizeof(tmp)) {
		pr_err("mkdir %s: path too long", path);
		return -1;
	}

	len = strlen(tmp);
	while (len > 1 && tmp[len - 1] == '/')
		tmp[--len] = '\0';
	if (strcmp(tmp, "/") == 0) {
		pr_err("keys dir cannot be /");
		return -1;
	}

	for (char *p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
			pr_err("mkdir %s: %s", tmp, strerror(errno));
			return -1;
		}
		*p = '/';
		while (p[1] == '/')
			p++;
	}

	if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
		pr_err("mkdir %s: %s", tmp, strerror(errno));
		return -1;
	}
	if (stat(tmp, &st) != 0) {
		pr_err("stat %s: %s", tmp, strerror(errno));
		return -1;
	}
	if (!S_ISDIR(st.st_mode)) {
		pr_err("keys dir %s is not a directory", tmp);
		return -1;
	}
	/* Defeat umask on the final key directory. */
	if (chmod(tmp, mode) != 0) {
		pr_err("chmod %s: %s", tmp, strerror(errno));
		return -1;
	}
	return 0;
}

static int ensure_keys_dir(const char *keys_dir)
{
	return mkdir_p_mode(keys_dir, 0700);
}

static int path_exists(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0;
}

static EVP_PKEY *gen_keypair(void)
{
	EVP_PKEY *k = EVP_RSA_gen(ALG_RSA_BITS);

	if (!k)
		openssl_complain("EVP_RSA_gen");
	return k;
}

static int set_subject_and_issuer(X509 *c)
{
	X509_NAME *name = X509_get_subject_name(c);

	if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
				       (const unsigned char *)CERT_CN,
				       -1, -1, 0) != 1) {
		openssl_complain("X509_NAME_add_entry_by_txt");
		return -1;
	}
	if (X509_set_issuer_name(c, name) != 1) {
		openssl_complain("X509_set_issuer_name");
		return -1;
	}
	return 0;
}

static int add_ext(X509 *c, int nid, const char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	int rc;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, c, c, NULL, NULL, 0);

	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) {
		openssl_complain("X509V3_EXT_conf_nid");
		return -1;
	}
	rc = X509_add_ext(c, ex, -1);
	X509_EXTENSION_free(ex);
	if (rc != 1) {
		openssl_complain("X509_add_ext");
		return -1;
	}
	return 0;
}

static int build_serial(X509 *c)
{
	if (ASN1_INTEGER_set(X509_get_serialNumber(c), 1) != 1) {
		openssl_complain("ASN1_INTEGER_set");
		return -1;
	}
	return 0;
}

static int build_validity(X509 *c)
{
	if (!X509_gmtime_adj(X509_getm_notBefore(c), 0)) {
		openssl_complain("X509_gmtime_adj notBefore");
		return -1;
	}
	if (!X509_gmtime_adj(X509_getm_notAfter(c),
			     VALIDITY_DAYS * 24L * 60L * 60L)) {
		openssl_complain("X509_gmtime_adj notAfter");
		return -1;
	}
	return 0;
}

static int build_cert(X509 *c, EVP_PKEY *pkey)
{
	if (X509_set_version(c, 2) != 1) {	/* X.509 v3 */
		openssl_complain("X509_set_version");
		return -1;
	}
	if (build_serial(c) != 0)
		return -1;
	if (build_validity(c) != 0)
		return -1;
	if (X509_set_pubkey(c, pkey) != 1) {
		openssl_complain("X509_set_pubkey");
		return -1;
	}
	if (set_subject_and_issuer(c) != 0)
		return -1;

	if (add_ext(c, NID_basic_constraints, "critical,CA:FALSE") != 0)
		return -1;
	if (add_ext(c, NID_key_usage, "digitalSignature") != 0)
		return -1;
	if (add_ext(c, NID_subject_key_identifier, "hash") != 0)
		return -1;
	if (add_ext(c, NID_authority_key_identifier, "keyid") != 0)
		return -1;

	if (X509_sign(c, pkey, EVP_sha256()) == 0) {
		openssl_complain("X509_sign");
		return -1;
	}
	return 0;
}

static int write_private_pem(EVP_PKEY *pkey, const char *path)
{
	int fd, rc = -1;
	FILE *fp = NULL;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		pr_err("open %s: %s", path, strerror(errno));
		return -1;
	}
	if (fchmod(fd, 0600) != 0) {
		pr_err("fchmod %s: %s", path, strerror(errno));
		goto out;
	}
	fp = fdopen(fd, "w");
	if (!fp) {
		pr_err("fdopen %s: %s", path, strerror(errno));
		goto out;
	}
	fd = -1;	/* now owned by fp */
	if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
		openssl_complain("PEM_write_PrivateKey");
		goto out;
	}
	if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
		pr_err("flush %s: %s", path, strerror(errno));
		goto out;
	}
	rc = 0;
out:
	if (fp)
		fclose(fp);
	else if (fd >= 0)
		close(fd);
	if (rc != 0)
		unlink(path);
	return rc;
}

static int write_cert_der(X509 *c, const char *path)
{
	int fd, rc = -1;
	BIO *bio = NULL;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		pr_err("open %s: %s", path, strerror(errno));
		return -1;
	}
	if (fchmod(fd, 0600) != 0) {
		pr_err("fchmod %s: %s", path, strerror(errno));
		goto out;
	}
	bio = BIO_new_fd(fd, BIO_NOCLOSE);
	if (!bio) {
		openssl_complain("BIO_new_fd");
		goto out;
	}
	if (i2d_X509_bio(bio, c) != 1) {
		openssl_complain("i2d_X509_bio");
		goto out;
	}
	if (fsync(fd) != 0) {
		pr_err("fsync %s: %s", path, strerror(errno));
		goto out;
	}
	rc = 0;
out:
	if (bio)
		BIO_free(bio);
	if (fd >= 0)
		close(fd);
	if (rc != 0)
		unlink(path);
	return rc;
}

static const struct shirudo_help_item genkey_options[] = {
	{ "--force, -f",      "overwrite an existing key/cert (refused otherwise)" },
	{ "--keys-dir <dir>", "write signing_key.pem + cert.der under <dir> "
			      "instead of the default" },
};

static const struct shirudo_help_section genkey_help_sections[] = {
	{ "options:", genkey_options,
	  sizeof(genkey_options) / sizeof(genkey_options[0]) },
};

static const struct shirudo_help genkey_help = {
	.usage   = "shirudo genkey [--force] [--keys-dir <dir>]",
	.summary = "Generate a self-signed X.509 cert + RSA-2048 private key "
		   "for signing\n.upatch loader bytes. Operator-only.",
	.sections   = genkey_help_sections,
	.n_sections = sizeof(genkey_help_sections) /
		      sizeof(genkey_help_sections[0]),
	.footer  = "Default output paths:\n"
		   "  " SHIRUDO_SIGNING_KEY_PATH "\n"
		   "  " SHIRUDO_CERT_PATH "\n"
		   "If unset on the command line, the " SHIRUDO_KEYS_DIR_ENV
		   " environment variable\noverrides the default directory.",
};

static void usage(void)
{
	fprintf(stderr, "usage: %s\n", genkey_help.usage);
}

int cmd_genkey(int argc, const char **argv)
{
	EVP_PKEY *pkey = NULL;
	const char *keys_dir_arg = NULL;
	const char *keys_dir;
	char pkey_path[PATH_MAX];
	char cert_path[PATH_MAX];
	X509 *cert = NULL;
	int force = 0;
	int rc = 1;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--force") == 0 ||
		    strcmp(argv[i], "-f") == 0) {
			force = 1;
		} else if (strcmp(argv[i], "--keys-dir") == 0 &&
			   i + 1 < argc) {
			keys_dir_arg = argv[++i];
		} else if (strncmp(argv[i], "--keys-dir=", 11) == 0) {
			keys_dir_arg = argv[i] + 11;
		} else if (shirudo_is_help(argv[i])) {
			shirudo_print_help(&genkey_help);
			return 0;
		} else {
			pr_err("genkey: unknown option '%s'", argv[i]);
			usage();
			return 2;
		}
	}

	keys_dir = shirudo_keys_dir_resolve(keys_dir_arg);

	rc = shirudo_key_paths(keys_dir, pkey_path, sizeof(pkey_path),
			       cert_path, sizeof(cert_path));
	if (rc) {
		pr_err("genkey: invalid keys dir %s: %s",
		       keys_dir, strerror(-rc));
		return 1;
	}

	if (geteuid() != 0 && strcmp(keys_dir, SHIRUDO_KEYS_DIR) == 0) {
		pr_err("genkey: default keys dir %s requires root; "
		       "rerun with sudo or pass --keys-dir <dir>",
		       SHIRUDO_KEYS_DIR);
		return 1;
	}

	if (ensure_keys_dir(keys_dir) != 0)
		return 1;

	if (!force) {
		if (path_exists(pkey_path) || path_exists(cert_path)) {
			pr_err("genkey: %s or %s already exists; pass --force",
			       pkey_path, cert_path);
			return 1;
		}
	} else {
		/* clear the way for the O_EXCL writes below */
		unlink(pkey_path);
		unlink(cert_path);
	}

	pkey = gen_keypair();
	if (!pkey)
		goto out;
	cert = X509_new();
	if (!cert) {
		openssl_complain("X509_new");
		goto out;
	}
	if (build_cert(cert, pkey) != 0)
		goto out;

	if (write_private_pem(pkey, pkey_path) != 0)
		goto out;
	if (write_cert_der(cert, cert_path) != 0) {
		unlink(pkey_path);
		goto out;
	}

	pr_info("wrote %s (RSA-%d, mode 0600)",
		pkey_path, ALG_RSA_BITS);
	pr_info("wrote %s (X.509 self-signed, %ld-day validity)",
		cert_path, VALIDITY_DAYS);
	pr_audit("genkey: created shirudo signing material at %s",
		 keys_dir);
	rc = 0;
out:
	if (cert)
		X509_free(cert);
	if (pkey)
		EVP_PKEY_free(pkey);
	return rc;
}
