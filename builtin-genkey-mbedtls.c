/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509_crt.h>

#include "builtin.h"
#include "util/help.h"
#include "util/io.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/paths.h"

#define ALG_RSA_BITS 2048
#define VALIDITY_DAYS (10L * 365L)
#define CERT_CN "shirudo"

struct gen_state {
	mbedtls_pk_context key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context drbg;
};

static void mbedtls_complain(const char *where, int err)
{
	char buf[256];

	mbedtls_strerror(err, buf, sizeof(buf));
	pr_err("mbedTLS: %s: %s", where, buf);
}

static int mkdir_p_mode(const char *path, mode_t mode)
{
	struct stat st;
	char tmp[PATH_MAX];
	size_t len;

	if (!path || !*path || strlen(path) >= sizeof(tmp))
		return -1;
	strcpy(tmp, path);
	len = strlen(tmp);
	while (len > 1 && tmp[len - 1] == '/')
		tmp[--len] = '\0';
	if (!strcmp(tmp, "/"))
		return -1;
	for (char *p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, mode) && errno != EEXIST)
			return -1;
		*p = '/';
	}
	if (mkdir(tmp, mode) && errno != EEXIST)
		return -1;
	if (stat(tmp, &st) || !S_ISDIR(st.st_mode) || chmod(tmp, mode))
		return -1;
	return 0;
}

static int path_exists(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0;
}

static int init_key(struct gen_state *s)
{
	static const unsigned char personalization[] = "shirudo genkey";
	int rc;

	memset(s, 0, sizeof(*s));
	mbedtls_pk_init(&s->key);
	mbedtls_entropy_init(&s->entropy);
	mbedtls_ctr_drbg_init(&s->drbg);
	rc = mbedtls_ctr_drbg_seed(&s->drbg, mbedtls_entropy_func,
				   &s->entropy, personalization,
				   sizeof(personalization) - 1);
	if (!rc)
		rc = mbedtls_pk_setup(&s->key,
				       mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	if (!rc)
		rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(s->key),
					  mbedtls_ctr_drbg_random, &s->drbg,
					  ALG_RSA_BITS, 65537);
	if (rc) {
		mbedtls_complain("RSA key generation", rc);
		mbedtls_pk_free(&s->key);
		mbedtls_ctr_drbg_free(&s->drbg);
		mbedtls_entropy_free(&s->entropy);
		return -1;
	}
	return 0;
}

static void free_key(struct gen_state *s)
{
	mbedtls_pk_free(&s->key);
	mbedtls_ctr_drbg_free(&s->drbg);
	mbedtls_entropy_free(&s->entropy);
}

static int build_cert(struct gen_state *s, mbedtls_x509write_cert *cert)
{
	static unsigned char serial[] = { 1 };
	char not_before[16], not_after[16];
	time_t now = time(NULL), later = now + VALIDITY_DAYS * 24L * 60L * 60L;
	struct tm before_tm, after_tm;
	int rc;

	if (now == (time_t)-1 || gmtime_r(&now, &before_tm) == NULL ||
	    gmtime_r(&later, &after_tm) == NULL)
		return -1;
	if (!strftime(not_before, sizeof(not_before), "%Y%m%d%H%M%S", &before_tm) ||
	    !strftime(not_after, sizeof(not_after), "%Y%m%d%H%M%S", &after_tm))
		return -1;
	mbedtls_x509write_crt_init(cert);
	mbedtls_x509write_crt_set_version(cert, MBEDTLS_X509_CRT_VERSION_3);
	rc = mbedtls_x509write_crt_set_serial_raw(cert, serial, sizeof(serial));
	if (!rc) rc = mbedtls_x509write_crt_set_validity(cert, not_before, not_after);
	if (!rc) rc = mbedtls_x509write_crt_set_subject_name(cert, "CN=" CERT_CN);
	if (!rc) rc = mbedtls_x509write_crt_set_issuer_name(cert, "CN=" CERT_CN);
	if (!rc) mbedtls_x509write_crt_set_subject_key(cert, &s->key);
	if (!rc) mbedtls_x509write_crt_set_issuer_key(cert, &s->key);
	if (!rc) mbedtls_x509write_crt_set_md_alg(cert, MBEDTLS_MD_SHA256);
	if (!rc) rc = mbedtls_x509write_crt_set_basic_constraints(cert, 0, -1);
	if (!rc) rc = mbedtls_x509write_crt_set_key_usage(cert,
							 MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
	if (!rc) rc = mbedtls_x509write_crt_set_subject_key_identifier(cert);
	if (!rc) rc = mbedtls_x509write_crt_set_authority_key_identifier(cert);
	if (rc)
		mbedtls_complain("certificate construction", rc);
	return rc ? -1 : 0;
}

static int write_private_pem(struct gen_state *s, const char *path)
{
	unsigned char pem[4096];
	int fd, n, rc = -1;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		pr_err("open %s: %s", path, strerror(errno));
		return -1;
	}
	if (fchmod(fd, 0600))
		goto out;
	n = mbedtls_pk_write_key_pem(&s->key, pem, sizeof(pem));
	if (n || shirudo_write_all(fd, pem, strlen((char *)pem)) || fsync(fd))
		goto out;
	rc = 0;
out:
	if (rc)
		unlink(path);
	close(fd);
	return rc;
}

static int write_cert_der(struct gen_state *s, mbedtls_x509write_cert *cert,
			  const char *path)
{
	unsigned char der[8192];
	int fd, n, rc = -1;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		pr_err("open %s: %s", path, strerror(errno));
		return -1;
	}
	if (fchmod(fd, 0600))
		goto out;
	n = mbedtls_x509write_crt_der(cert, der, sizeof(der),
					      mbedtls_ctr_drbg_random, &s->drbg);
	if (n <= 0 || shirudo_write_all(fd, der + sizeof(der) - n,
					(size_t)n) || fsync(fd))
		goto out;
	rc = 0;
out:
	if (rc)
		unlink(path);
	close(fd);
	return rc;
}

static const struct shirudo_help_item genkey_options[] = {
	{ "--force, -f", "overwrite an existing key/cert (refused otherwise)" },
	{ "--keys-dir <dir>", "write signing_key.pem + cert.der under <dir> instead of the default" },
};

static const struct shirudo_help_section genkey_help_sections[] = {
	{ "options:", genkey_options, ARRAY_SIZE(genkey_options) },
};

static const struct shirudo_help genkey_help = {
	.usage = "shirudo genkey [--force] [--keys-dir <dir>]",
	.summary = "Generate a self-signed X.509 cert + RSA-2048 private key for signing\n.upatch loader bytes. Operator-only.",
	.sections = genkey_help_sections,
	.n_sections = ARRAY_SIZE(genkey_help_sections),
	.footer = "Default output paths:\n  " SHIRUDO_SIGNING_KEY_PATH "\n  " SHIRUDO_CERT_PATH,
};

int cmd_genkey(int argc, const char **argv)
{
	struct gen_state state;
	mbedtls_x509write_cert cert;
	const char *keys_dir_arg = NULL, *keys_dir;
	char pkey_path[PATH_MAX], cert_path[PATH_MAX];
	int force = 0, rc = 1;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--force") || !strcmp(argv[i], "-f"))
			force = 1;
		else if (!strcmp(argv[i], "--keys-dir") && i + 1 < argc)
			keys_dir_arg = argv[++i];
		else if (!strncmp(argv[i], "--keys-dir=", 11))
			keys_dir_arg = argv[i] + 11;
		else if (shirudo_is_help(argv[i])) {
			shirudo_print_help(&genkey_help);
			return 0;
		} else {
			pr_err("genkey: unknown option '%s'", argv[i]);
			return 2;
		}
	}
	keys_dir = shirudo_keys_dir_resolve(keys_dir_arg);
	if (shirudo_key_paths(keys_dir, pkey_path, sizeof(pkey_path),
			      cert_path, sizeof(cert_path)))
		return 1;
	if (geteuid() != 0 && !strcmp(keys_dir, SHIRUDO_KEYS_DIR)) {
		pr_err("genkey: default keys dir %s requires root; rerun with sudo or pass --keys-dir <dir>", SHIRUDO_KEYS_DIR);
		return 1;
	}
	if (mkdir_p_mode(keys_dir, 0700))
		return 1;
	if (!force && (path_exists(pkey_path) || path_exists(cert_path))) {
		pr_err("genkey: output already exists; pass --force");
		return 1;
	}
	if (force) {
		unlink(pkey_path);
		unlink(cert_path);
	}
	if (init_key(&state))
		return 1;
	if (build_cert(&state, &cert))
		goto out_key;
	if (write_private_pem(&state, pkey_path) ||
	    write_cert_der(&state, &cert, cert_path)) {
		unlink(pkey_path);
		unlink(cert_path);
		goto out_cert;
	}
	pr_info("wrote %s (RSA-%d, mode 0600)", pkey_path, ALG_RSA_BITS);
	pr_info("wrote %s (X.509 self-signed, %ld-day validity)", cert_path, VALIDITY_DAYS);
	pr_audit("genkey: created shirudo signing material at %s", keys_dir);
	rc = 0;
out_cert:
	mbedtls_x509write_crt_free(&cert);
out_key:
	free_key(&state);
	return rc;
}
