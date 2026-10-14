/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Attestation: the evidence a target emits, the prediction and the
 * verification an operator runs against it.
 */

#ifndef SHIRUDO_ATTEST_H
#define SHIRUDO_ATTEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "chain.h"
#include "tpm_wire.h"

/* PCRs quoted by default: firmware and boot loader, kernel, initrd, systemd. */
#define SHIRUDO_ATTEST_PCR_DEFAULT	0x0000FAFFu
#define SHIRUDO_ATTEST_NONCE_MAX	64
#define SHIRUDO_ATTEST_MEMBERS_MAX	256
#define SHIRUDO_ATTEST_REPORT_MAX	8192

/*
 * A challenge an operator made with `shirudo attest challenge`: the
 * blob and the encrypted seed TPM2_ActivateCredential takes, for the
 * attestation key of the given name under the endorsement key of the
 * given type.
 */
struct shirudo_attest_challenge {
	bool		ek_rsa;
	uint8_t		ak_name[SHIRUDO_TPM_NAME_LEN];
	uint8_t		blob[SHIRUDO_TPM_ID_OBJECT_LEN];
	size_t		blob_len;
	uint8_t		secret[256];
	size_t		secret_len;
};

#define SHIRUDO_ATTEST_CHALLENGE_MAX	(16 * 1024)

int shirudo_attest_challenge_read(const char *path,
				  struct shirudo_attest_challenge *out);

/*
 * Target side: the evidence document for nonce over the PCRs in
 * pcr_mask, activating the challenge when one is given. The buffer is
 * xmalloc'd to *cap bytes and NUL-terminated; the caller frees it with
 * xfree(buf, cap). -EKEYREJECTED when the TPM refuses the challenge.
 */
int shirudo_attest_evidence(const uint8_t *nonce, size_t nonce_len,
			    uint32_t pcr_mask,
			    const struct shirudo_attest_challenge *challenge,
			    char **out, size_t *len, size_t *cap);

/*
 * Operator side: from an evidence document, a challenge for its
 * attestation key under its endorsement key. The credential the
 * target has to recover is handed to the caller and kept nowhere
 * else. ek_ca names a PEM bundle the endorsement certificate must
 * chain to, or NULL. report receives one line per check; the document
 * is xmalloc'd to *cap bytes. -EKEYREJECTED when a check failed and no
 * challenge was made.
 */
int shirudo_attest_challenge_make(const char *evidence, size_t len,
				  const char *ek_ca,
				  uint8_t credential[SHIRUDO_TPM_CREDENTIAL_LEN],
				  char **out, size_t *out_len, size_t *cap,
				  char *report, size_t report_cap);

struct shirudo_attest_expect {
	const uint8_t	*nonce;
	size_t		nonce_len;
	bool		have_ak_name;
	uint8_t		ak_name[SHIRUDO_TPM_NAME_LEN];
	bool		have_chain;
	uint8_t		chain[32];
	bool		have_init;	/* cert, set, tree root known */
	uint8_t		init_event[32];
	bool		allow_runtime_events;
	bool		strict_anchor;
	uint32_t	pcr_expect_mask;
	uint8_t		pcrs[24][32];
	bool		have_credential;
	uint8_t		credential[SHIRUDO_TPM_CREDENTIAL_LEN];
	bool		require_initrd;	/* the binding must be the initrd's */
	uint32_t	bind_expect_mask; /* PCR values at binding time */
	uint8_t		bind_values[24][32];
};

/*
 * Operator side: check an evidence document against the expectation.
 * report receives one line per check. Returns 0 when every check
 * passed, -EKEYREJECTED when one failed, -EINVAL when the document is
 * malformed.
 */
int shirudo_attest_verify(const char *evidence, size_t len,
			  const struct shirudo_attest_expect *expect,
			  char *report, size_t report_cap);

#endif /* SHIRUDO_ATTEST_H */
