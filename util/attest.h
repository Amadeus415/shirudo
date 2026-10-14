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
 * Target side: the evidence document for nonce over the PCRs in
 * pcr_mask. The buffer is xmalloc'd to *cap bytes and NUL-terminated;
 * the caller frees it with xfree(buf, cap).
 */
int shirudo_attest_evidence(const uint8_t *nonce, size_t nonce_len,
			    uint32_t pcr_mask, char **out, size_t *len,
			    size_t *cap);

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
