/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .bee archives, signed repository indexes and tree publications.
 */

#ifndef SHIRUDO_BPM_PACKAGE_H
#define SHIRUDO_BPM_PACKAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bpm_oci.h"
#include "bpm_tree.h"

struct bpm_index_entry {
	char name[BPM_MAX_NAME];
	char version[BPM_MAX_NAME];
	char repository[BPM_MAX_ENDPOINT];
	char manifest_digest[BPM_MAX_DIGEST];
	char package_digest[BPM_MAX_DIGEST];
	char signer[BPM_MAX_DIGEST];
	int64_t package_size;
};

struct bpm_package_info {
	char name[BPM_MAX_NAME];
	char version[BPM_MAX_NAME];
	char signer[BPM_MAX_DIGEST];
	unsigned char *cert;
	size_t cert_len;
};

/* Parse and validate shirudo/bpm-index:stable; at most BPM_MAX_ENTRIES. */
int bpm_index_parse(const unsigned char *body, size_t len,
		    struct bpm_index_entry *entries, int *n_entries);
/* Detached CMS over payload against the certificate at cert_path. */
int bpm_verify_cms(const unsigned char *payload, size_t payload_len,
		   const unsigned char *sig, size_t sig_len,
		   const char *cert_path);

/* ustar helpers shared with the installer's extractor. */
int bpm_tar_octal(const char *p, size_t n, uint64_t *out);
bool bpm_archive_rel_ok(const char *name);

/*
 * Read one member of a gzip'd ustar .bee into an xmalloc'd buffer of
 * out_len + 1 bytes. member is relative to the single top-level package
 * directory; package_dir pins that directory when known, found_dir
 * reports it otherwise.
 */
int bpm_pkg_read_member_in(const char *archive, const char *member,
			   const char *package_dir, char *found_dir,
			   size_t found_dir_sz, unsigned char **out,
			   size_t *out_len, size_t max);
int bpm_pkg_read_member(const char *archive, const char *member,
			unsigned char **out, size_t *out_len, size_t max);
/* Name, version, signer fingerprint and cert.der (xmalloc'd) of a .bee. */
int bpm_pkg_load_info(const char *archive, struct bpm_package_info *info);

/*
 * Fetch the signed tree publication at repository:reference, check every
 * layer against its descriptor and the payload against cert_path, and
 * parse it. -ENOENT when the reference does not exist yet.
 */
int bpm_tree_fetch_publication(struct bpm_oci_client *c,
			       const char *repository, const char *reference,
			       const char *cert_path,
			       struct shirudo_tree_publication *pub,
			       char *manifest_digest, size_t digest_sz);

#endif /* SHIRUDO_BPM_PACKAGE_H */
