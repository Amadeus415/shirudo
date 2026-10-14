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

struct shirudo_trusted_cert {
	char		path[PATH_MAX];
	uint8_t		sha256[32];		/* of the DER file */
	uint8_t		fingerprint[32];	/* of the public key */
	bool		primary;		/* cert.der */
};

/*
 * The set is sorted by DER digest and holds each public key once; a
 * certificate whose fingerprint is in the revoked directory is left
 * out and counted in n_revoked.
 */
struct shirudo_trusted_set {
	struct shirudo_trusted_cert	certs[SHIRUDO_KEYS_MAX];
	size_t				n;
	size_t				n_revoked;
};

/*
 * Load cert.der and, when with_trusted, trusted/<fingerprint>.der from
 * the keys directory, leaving out the keys revoked_dir names; NULL
 * means revoked/ beside them. -ENOENT when there is no cert.der.
 */
int shirudo_keys_load(const char *keys_dir, const char *revoked_dir,
		      bool with_trusted, struct shirudo_trusted_set *set);

/* One certificate's digests, from its DER. */
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

/* <dir>/<fingerprint hex>.der, the name a certificate has in a set. */
int shirudo_keys_path_for(const char *dir, const uint8_t fingerprint[32],
			  char *out, size_t cap);

#endif /* SHIRUDO_UTIL_KEYS_H */
