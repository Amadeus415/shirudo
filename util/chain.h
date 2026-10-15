/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The measurement register: a per-boot NV extend index anchored in a
 * PCR, plus the digest helpers every measuring path shares.
 */

#ifndef SHIRUDO_CHAIN_H
#define SHIRUDO_CHAIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "eventlog.h"
#include "hex.h"
#include "tpm_wire.h"
#include "upatch.h"

#define SHIRUDO_CHAIN_DIGEST_LEN	32
#define SHIRUDO_CHAIN_NAME		"shirudo"
/*
 * The register binds to PCR 9, which holds the initrd and nothing
 * measured after it, and to PCR 11, which systemd extends with the
 * boot phase: bound while the initrd runs, the init branch closes at
 * "leave-initrd" and no later process can bind. PCR 9 also takes the
 * anchor, so it stays exact afterwards.
 */
#define SHIRUDO_CHAIN_PCR		9u
#define SHIRUDO_CHAIN_PHASE_PCR		11u
#define SHIRUDO_CHAIN_PCR_MASK		((1u << SHIRUDO_CHAIN_PCR) | \
					 (1u << SHIRUDO_CHAIN_PHASE_PCR))
#define SHIRUDO_CHAIN_ANCHOR_MAX	128

void shirudo_sha256(const void *data, size_t len,
		    uint8_t out[SHIRUDO_CHAIN_DIGEST_LEN]);

/* SHA-256 over the concatenation a || b, without allocating a joined buffer. */
void shirudo_sha256_2(const void *a, size_t a_len,
		      const void *b, size_t b_len,
		      uint8_t out[SHIRUDO_CHAIN_DIGEST_LEN]);

/* Constant-time equality of two equal-length buffers (1 == equal). */
int shirudo_ct_eq(const void *a, const void *b, size_t n);


/* One upatch of the set an init event covers. */
struct shirudo_measured_upatch {
	char	name[SHIRUDO_UPATCH_NAME_MAX + 1];
	char	payload_hex[2 * SHIRUDO_UPATCH_PAYLOAD_HASH_LEN + 1];
};

/*
 * The event digests every measuring path and the predictor share.
 * The set is sorted by name before hashing.
 */
void shirudo_chain_init_event(const uint8_t cert_sha[32],
			       struct shirudo_measured_upatch *set, size_t n,
			       const uint8_t tree_root[32],
			       uint8_t set_digest[32], uint8_t event[32]);
/* SHA256(tag || NUL || cert_sha256), tag "shirudo-key-revoke". */
void shirudo_chain_key_event(const char *tag, const uint8_t cert_sha[32],
			     uint8_t event[32]);
void shirudo_chain_upatch_event(const char *tag, const char *name,
				 const uint8_t payload[32], uint8_t event[32]);
void shirudo_chain_tree_event(int64_t seq, const uint8_t operation_digest[32],
			       uint8_t event[32]);
void shirudo_chain_fold(uint8_t chain[32], const uint8_t event[32]);

/* The PCR record anchoring a register name: nvpcr-init:shirudo:0x..:<name>. */
void shirudo_chain_anchor(const uint8_t name[SHIRUDO_TPM_NAME_LEN],
			  char *out, size_t cap);

struct shirudo_chain_init_info {
	bool		reused;		/* written and on record */
	bool		initrd;		/* bound while the initrd ran */
	uint32_t	reset_count;	/* the TPM's, for the record */
	uint8_t		value[SHIRUDO_CHAIN_DIGEST_LEN];
	uint8_t		pcr_before[SHIRUDO_CHAIN_DIGEST_LEN];
	uint8_t		phase_before[SHIRUDO_CHAIN_DIGEST_LEN];
	uint8_t		name[SHIRUDO_TPM_NAME_LEN];
	size_t		name_len;
	char		anchor[SHIRUDO_CHAIN_ANCHOR_MAX];
	uint8_t		anchor_digest[SHIRUDO_CHAIN_DIGEST_LEN];
};

/*
 * Bind the register to this boot and perform its first write with the
 * init event: define (or redefine) the index under a policy computed
 * from the anchoring PCR, extend it through the init branch, then
 * extend the PCR with the index name so the branch can never be
 * satisfied again until the next reset. A register written this boot
 * and on record for the TPM's current reset count is reused untouched;
 * a record for this reset count whose index is gone, unwritten or
 * renamed refuses with -EEXIST, since binding another would restart
 * the history the record vouches for. -ENODEV without a TPM, -EACCES
 * when the owner hierarchy refuses, -EPROTO when the TPM's name is not
 * the computed one, or another -errno.
 */
int shirudo_chain_init(const uint8_t event[SHIRUDO_CHAIN_DIGEST_LEN],
		       struct shirudo_chain_init_info *info);

/*
 * Extend this boot's register by one event through the written
 * branch. -ENODEV when there is no register this boot (no TPM, no
 * init record, index unwritten), -EACCES when the index on the TPM is
 * not the one init recorded (recreated), -EIO on a TPM failure.
 */
int shirudo_chain_extend(const uint8_t event[SHIRUDO_CHAIN_DIGEST_LEN],
			 uint8_t out_chain[SHIRUDO_CHAIN_DIGEST_LEN]);

/* The live value; -ENODEV when no register is written this boot. */
int shirudo_chain_read(uint8_t out[SHIRUDO_CHAIN_DIGEST_LEN]);

struct shirudo_chain_status {
	bool		tpm;		/* a TPM answered */
	bool		defined;
	bool		written;
	bool		logged;		/* init record this boot */
	bool		anchored;	/* recorded name, same reset */
	bool		rebound;	/* two records for one reset */
	uint8_t		value[SHIRUDO_CHAIN_DIGEST_LEN];
	uint8_t		name[SHIRUDO_TPM_NAME_LEN];
	size_t		name_len;
	struct shirudo_eventlog_init init;
};

int shirudo_chain_status(struct shirudo_chain_status *st);

#endif /* SHIRUDO_CHAIN_H */
