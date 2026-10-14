// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The certificates a target trusts: the primary one and the trusted set.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "chain.h"
#include "crypto.h"
#include "hex.h"
#include "keys.h"
#include "malloc.h"
#include "paths.h"

#define KEYS_DER_MAX	(1024 * 1024)

static int read_file_bounded(const char *path, unsigned char **out,
			     size_t *out_sz)
{
	unsigned char *buf;
	struct stat st;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) < 0) {
		int rc = -errno;

		close(fd);
		return rc;
	}
	if (st.st_size <= 0 || st.st_size > KEYS_DER_MAX) {
		close(fd);
		return -EINVAL;
	}
	buf = xmalloc((size_t)st.st_size);
	if (!buf) {
		close(fd);
		return -ENOMEM;
	}
	n = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (n != st.st_size) {
		xfree(buf, (size_t)st.st_size);
		return -EIO;
	}
	*out = buf;
	*out_sz = (size_t)st.st_size;
	return 0;
}

int shirudo_keys_digest_file(const char *path, uint8_t sha256[32],
			     uint8_t fingerprint[32])
{
	struct shirudo_cert cert = {};
	unsigned char *der = NULL;
	size_t der_sz = 0;
	int rc;

	rc = read_file_bounded(path, &der, &der_sz);
	if (rc)
		return rc;
	shirudo_sha256(der, der_sz, sha256);
	xfree(der, der_sz);
	rc = shirudo_cert_read_file(path, &cert);
	if (rc)
		return rc;
	rc = shirudo_cert_pubkey_digest(&cert, fingerprint);
	shirudo_cert_free(&cert);
	return rc;
}

int shirudo_keys_path_for(const char *dir, const uint8_t fingerprint[32],
			  char *out, size_t cap)
{
	char hex[65];

	shirudo_hex_encode(fingerprint, 32, hex);
	if ((size_t)snprintf(out, cap, "%s/%s.der", dir, hex) >= cap)
		return -ENAMETOOLONG;
	return 0;
}

bool shirudo_keys_is_revoked(const char *revoked_dir,
			     const uint8_t fingerprint[32])
{
	char path[PATH_MAX];

	if (shirudo_keys_path_for(revoked_dir, fingerprint, path,
				  sizeof(path)))
		return false;
	return access(path, F_OK) == 0;
}

static int cert_cmp(const void *a, const void *b)
{
	return memcmp(((const struct shirudo_trusted_cert *)a)->sha256,
		      ((const struct shirudo_trusted_cert *)b)->sha256, 32);
}

/* Add one file to the set unless its key is there or revoked. */
static int set_add(struct shirudo_trusted_set *set, const char *path,
		   const char *revoked_dir, bool primary)
{
	struct shirudo_trusted_cert c = { .primary = primary };
	size_t i;
	int rc;

	if (snprintf(c.path, sizeof(c.path), "%s", path) >= (int)sizeof(c.path))
		return -ENAMETOOLONG;
	rc = shirudo_keys_digest_file(path, c.sha256, c.fingerprint);
	if (rc)
		return rc;
	if (shirudo_keys_is_revoked(revoked_dir, c.fingerprint)) {
		set->n_revoked++;
		return 0;
	}
	for (i = 0; i < set->n; i++)
		if (memcmp(set->certs[i].fingerprint, c.fingerprint, 32) == 0) {
			set->certs[i].primary |= primary;
			return 0;
		}
	if (set->n >= SHIRUDO_KEYS_MAX)
		return -E2BIG;
	set->certs[set->n++] = c;
	return 0;
}

static int select_der(const struct dirent *e)
{
	size_t n = strlen(e->d_name);

	return n > 4 && strcmp(e->d_name + n - 4, ".der") == 0;
}

int shirudo_keys_load(const char *keys_dir, const char *revoked_dir,
		      bool with_trusted, struct shirudo_trusted_set *set)
{
	struct dirent **names = NULL;
	char revoked[PATH_MAX];
	char path[PATH_MAX];
	int n, i, rc;

	memset(set, 0, sizeof(*set));
	if (!revoked_dir) {
		if (snprintf(revoked, sizeof(revoked), "%s/revoked",
			     keys_dir) >= (int)sizeof(revoked))
			return -ENAMETOOLONG;
		revoked_dir = revoked;
	}
	if (snprintf(path, sizeof(path), "%s/%s", keys_dir,
		     SHIRUDO_CERT_FILE) >= (int)sizeof(path))
		return -ENAMETOOLONG;
	rc = set_add(set, path, revoked_dir, true);
	if (rc)
		return rc;
	if (!with_trusted)
		return 0;

	if (snprintf(path, sizeof(path), "%s/trusted", keys_dir) >=
	    (int)sizeof(path))
		return -ENAMETOOLONG;
	n = scandir(path, &names, select_der, alphasort);
	if (n < 0)
		return errno == ENOENT ? 0 : -errno;
	for (i = 0; i < n && !rc; i++) {
		char file[PATH_MAX];

		if (snprintf(file, sizeof(file), "%s/trusted/%s", keys_dir,
			     names[i]->d_name) >= (int)sizeof(file))
			rc = -ENAMETOOLONG;
		else
			rc = set_add(set, file, revoked_dir, false);
	}
	for (i = 0; i < n; i++)
		shirudo_libc_free(names[i]);	/* scandir-owned */
	shirudo_libc_free(names);		/* scandir-owned */
	if (rc)
		return rc;
	if (set->n > 1)
		qsort(set->certs, set->n, sizeof(set->certs[0]), cert_cmp);
	return 0;
}

static int digest_cmp(const void *a, const void *b)
{
	return memcmp(a, b, 32);
}

void shirudo_keys_anchor_digest(const uint8_t (*sha256)[32], size_t n,
				uint8_t out[32])
{
	uint8_t sorted[SHIRUDO_KEYS_MAX][32];
	size_t i;

	if (n == 1) {
		memcpy(out, sha256[0], 32);
		return;
	}
	if (n == 0 || n > SHIRUDO_KEYS_MAX) {
		memset(out, 0, 32);
		return;
	}
	for (i = 0; i < n; i++)
		memcpy(sorted[i], sha256[i], 32);
	qsort(sorted, n, 32, digest_cmp);
	shirudo_sha256(sorted, n * 32, out);
}

void shirudo_keys_set_digest(const struct shirudo_trusted_set *set,
			     uint8_t out[32])
{
	uint8_t sha[SHIRUDO_KEYS_MAX][32];
	size_t i;

	for (i = 0; i < set->n; i++)
		memcpy(sha[i], set->certs[i].sha256, 32);
	shirudo_keys_anchor_digest(sha, set->n, out);
}
