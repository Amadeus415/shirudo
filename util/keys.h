/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The certificates a target trusts: the primary one and the trusted set.
 */

#ifndef SHIRUDO_UTIL_KEYS_H
#define SHIRUDO_UTIL_KEYS_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHIRUDO_KEYS_MAX	16
#define SHIRUDO_KEYS_DER_MAX	(1024 * 1024)

/*
 * A vouch is a detached CMS signature by a member's key over this
 * prefix, NUL included, followed by the vouched certificate's DER.
 */
#define SHIRUDO_KEYS_VOUCH_PREFIX	"shirudo-key-vouch"

/* voucher is the admitting member's fingerprint, zero for the primary. */
struct shirudo_trusted_cert {
	char		path[PATH_MAX];
	uint8_t		sha256[32];		/* of the DER file */
	uint8_t		fingerprint[32];	/* of the public key */
	uint8_t		voucher[32];
	bool		primary;		/* cert.der */
};

/*
 * The set is sorted by DER digest and holds each public key once. A
 * trusted certificate is a member only with a vouch beside it that
 * verifies under the primary or under a member admitted before it;
 * one without is counted in n_unvouched and is not a member, nor is
 * one whose fingerprint the revoked directory names. n_revoked counts
 * that directory's certificates.
 */
struct shirudo_trusted_set {
	struct shirudo_trusted_cert	certs[SHIRUDO_KEYS_MAX];
	size_t				n;
	size_t				n_revoked;
	size_t				n_unvouched;
};

/*
 * Load cert.der and, when with_trusted, trusted/<fingerprint>.der from
 * the keys directory, leaving out the keys revoked_dir names; NULL
 * means revoked/ beside them. -ENOENT when there is no cert.der.
 */
int shirudo_keys_load(const char *keys_dir, const char *revoked_dir,
		      bool with_trusted, struct shirudo_trusted_set *set);

/* A whole file of at most SHIRUDO_KEYS_DER_MAX bytes, xmalloc'd. */
int shirudo_keys_read_der(const char *path, unsigned char **out,
			  size_t *out_sz);

/* One certificate's digests, from its DER or from its file. */
int shirudo_keys_digest_der(const unsigned char *der, size_t der_sz,
			    uint8_t sha256[32], uint8_t fingerprint[32]);
int shirudo_keys_digest_file(const char *path, uint8_t sha256[32],
			     uint8_t fingerprint[32]);

/*
 * The digest the init event covers: the one certificate's digest, or
 * the SHA-256 over the sorted digests of several. The same function
 * serves the operator predicting a register for a set.
 */
void shirudo_keys_anchor_digest(const uint8_t (*sha256)[32], size_t n,
				uint8_t out[32]);
void shirudo_keys_set_digest(const struct shirudo_trusted_set *set,
			     uint8_t out[32]);

/* Whether <revoked_dir>/<fingerprint>.der exists for this public key. */
bool shirudo_keys_is_revoked(const char *revoked_dir,
			     const uint8_t fingerprint[32]);

/* <dir>/<fingerprint hex><suffix>, the name a certificate has in a set. */
int shirudo_keys_path_for(const char *dir, const uint8_t fingerprint[32],
			  const char *suffix, char *out, size_t cap);

/* The bytes a vouch signs: the prefix and the certificate, xmalloc'd. */
int shirudo_keys_vouch_payload(const unsigned char *der, size_t der_sz,
			       unsigned char **out, size_t *out_sz);

/*
 * Whether a member of the set signed the vouch for this certificate:
 * 0 with the member's fingerprint in voucher, -EKEYREJECTED when none
 * did.
 */
int shirudo_keys_verify_vouch(const struct shirudo_trusted_set *set,
			      const unsigned char *der, size_t der_sz,
			      const unsigned char *sig, size_t sig_sz,
			      uint8_t voucher[32]);

/* Write a file whole and rename it into place, mode 0644. */
int shirudo_keys_write_file(const char *path, const void *data, size_t len);

/*
 * Write the certificate and its vouch under <keys_dir>/trusted, named
 * by fingerprint, the vouch first so a visible certificate always has
 * one. out gets the certificate's path.
 */
int shirudo_keys_install(const char *keys_dir, const unsigned char *der,
			 size_t der_sz, const unsigned char *sig,
			 size_t sig_sz, char *out, size_t cap);

#endif /* SHIRUDO_UTIL_KEYS_H */
