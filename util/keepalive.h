/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The keepalive body, the status record a node's TPM quotes, and its
 * packed fields: the per-operation outcome mask and the conditions word.
 */

#ifndef SHIRUDO_KEEPALIVE_H
#define SHIRUDO_KEEPALIVE_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#include "bpf/lib/tamper.h"
#include "conditions.h"

#define KEEPALIVE_MASK_OPS	512
#define KEEPALIVE_MASK_BYTES	(KEEPALIVE_MASK_OPS / 4)
#define KEEPALIVE_MASK_B64_MAX	(4 * ((KEEPALIVE_MASK_BYTES + 2) / 3) + 1)

/* Holds the largest body and its terminator. */
#define KEEPALIVE_BODY_MAX	4096

/*
 * The values of the body, one member per key but "schema", which the
 * emitter knows. A hash is 64 lowercase hex digits. A string that may
 * be null is so when it is NULL or, but for mask, empty, as sysinfo and
 * the tree state leave what is absent.
 */
struct keepalive_input {
	const char	*boot_id;
	const char	*version_id;		/* hash */
	const char	*config_root;		/* hash or null */
	const char	*kernel_release;
	const char	*image_id;		/* or null */
	const char	*image_version;		/* or null */
	const char	*image_root;		/* hash or null */
	const char	*verdict;
	__u16		cond;			/* keepalive_cond() */
	__u32		flags;
	const __u64	*tamper;		/* TAMPER_MAX counters or null */
	/* Not set: the node follows no tree and the seven tree keys are null. */
	bool		tree;
	const char	*tree_id;
	__u64		generation;
	__u64		base_seq;
	__u64		last_seq;
	const char	*base_root;		/* hash or null */
	const char	*projection_root;	/* hash */
	/* From keepalive_mask(): NULL is null, "" a window of no operation. */
	const char	*mask;
	const char	*set_sha256;		/* hash */
	__u64		count;
	__u64		not_ok;
};

/*
 * Writes the body as one compact JSON object with its terminator and no
 * newline, and its length without the terminator in *len: the bytes to
 * hash, send and store. -E2BIG when cap does not hold them, -EINVAL for
 * a string that is NULL where the body needs one or a hash that is not
 * one, -EILSEQ for a string that is not UTF-8; buf is then empty and
 * *len 0.
 */
int keepalive_emit(const struct keepalive_input *in, char *buf, size_t cap,
		   size_t *len) __must_check;

/*
 * Packs n outcome codes of 0 to 3, the first in the highest bits of the
 * first byte, and writes them as padded base64 with its terminator.
 * -EINVAL for a code above 3 or more than KEEPALIVE_MASK_OPS codes,
 * -E2BIG when cap is too small.
 */
int keepalive_mask(const __u8 *codes, size_t n, char *b64,
		   size_t cap) __must_check;

/*
 * Two bits per condition, each placed by its type name whatever its
 * place in conds: 0 not evaluated, 1 OK, 2 WARN, 3 ALERT.
 */
__u16 keepalive_cond(const struct condition *conds, size_t n);

#endif /* SHIRUDO_KEEPALIVE_H */
