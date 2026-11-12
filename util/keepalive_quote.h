/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The shirudo.quote of a keepalive: the attestation key's quote of the
 * SHA-256 of the body, as the attest, sig and ak fields in base64.
 */

#ifndef SHIRUDO_KEEPALIVE_QUOTE_H
#define SHIRUDO_KEEPALIVE_QUOTE_H

#include <stddef.h>

#include <shirudo/misc.h>

#include "tpm.h"

#define KEEPALIVE_B64_SIZE(n)	(4 * (((n) + 2) / 3) + 1)

/* Holds the longest quote and its terminator. */
#define KEEPALIVE_QUOTE_MAX	(sizeof("attest=;sig=;ak=") +		\
				 KEEPALIVE_B64_SIZE(TPM_ATTEST_MAX) +	\
				 KEEPALIVE_B64_SIZE(TPM_SIGNATURE_MAX) +	\
				 KEEPALIVE_B64_SIZE(TPM_PUBLIC_MAX))

/*
 * Writes attest=<TPMS_ATTEST>;sig=<TPMT_SIGNATURE>;ak=<TPMT_PUBLIC> in
 * padded base64 with its terminator. -E2BIG when cap does not hold it.
 */
int keepalive_quote_format(const struct tpm_attestation *att,
			   const struct tpm_key *ak, char *out,
			   size_t cap) __must_check;

/*
 * Quotes the SHA-256 of the body with the attestation key of
 * tpm_ak_create() over no PCR and writes the quote as
 * keepalive_quote_format() does. -ENXIO when no TPM opens.
 */
int keepalive_quote(const char *body, size_t len, char *quote,
		    size_t cap) __must_check;

#endif /* SHIRUDO_KEEPALIVE_QUOTE_H */
