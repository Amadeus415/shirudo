/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * CMS/PKCS#7 signer. Linked only into shirudo-build.
 */

#ifndef SHIRUDO_SIGN_H
#define SHIRUDO_SIGN_H

#include <stddef.h>
#include <stdint.h>

#define SHIRUDO_SHA256_LEN	32

/*
 * Caller supplies the input bytes and a signature buffer of capacity
 * signature_sz; on success that field is overwritten with the actual
 * size and payload_sha256 holds the SHA-256 of the input.
 */
struct shirudo_sign_io {
	const void	*insns;
	size_t		insns_sz;

	void		*signature;
	size_t		signature_sz;

	uint8_t		payload_sha256[SHIRUDO_SHA256_LEN];
};

/*
 * CMS-sign io->insns with the PEM private key at pkey_path and the
 * X.509 cert at cert_path (DER or PEM, auto-detected). Returns 0 on
 * success or a negative errno: -ENOSPC if the signature buffer is
 * too small, -EINVAL on parse failure, -EIO on OpenSSL marshalling
 * failure, -ENOMEM on allocation failure.
 */
int shirudo_cms_sign(struct shirudo_sign_io *io,
		     const char *pkey_path, const char *cert_path);

#endif /* SHIRUDO_SIGN_H */
