/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPM_TREE_H
#define SHIRUDO_BPM_TREE_H

#include <stddef.h>

#include <shirudo/misc.h>

#include "chain.h"

#define TREE_MAX_OPS 512
#define TREE_MAX_KCONFIG 64
#define TREE_MAX_LABELS 64
#define TREE_MAX_SELECTOR_VALUES 16
#define TREE_STRING_MAX 256

struct json_emit;

struct tree_kv {
	char key[TREE_STRING_MAX];
	char value[TREE_STRING_MAX];
};

struct tree_selector_kv {
	char key[TREE_STRING_MAX];
	char values[TREE_MAX_SELECTOR_VALUES][TREE_STRING_MAX];
	int n_values;
};

struct tree_selector {
	char kernel_release_prefix[TREE_MAX_SELECTOR_VALUES][TREE_STRING_MAX];
	int n_kernel_release_prefix;
	char kernel_build_id[TREE_MAX_SELECTOR_VALUES][TREE_STRING_MAX];
	int n_kernel_build_id;
	char architecture[TREE_MAX_SELECTOR_VALUES][TREE_STRING_MAX];
	int n_architecture;
	/*
	 * Owned and sized to what a selector names: at their full limits,
	 * every operation of a publication took 545 KiB for them.
	 */
	struct tree_selector_kv *kconfig;
	int n_kconfig;
	struct tree_selector_kv *labels;
	int n_labels;
};

/*
 * A new zeroed pair at the end of the n at *kvs, of at most max: 0 with
 * it in *kv, -E2BIG or -ENOMEM. tree_selector_copy() fills dst, which
 * holds no pairs, with copies of src's; tree_selector_free() releases
 * the pairs, and a zeroed selector holds none.
 */
int tree_selector_kv_add(struct tree_selector_kv **kvs, int *n, int max,
			 struct tree_selector_kv **kv);
int tree_selector_copy(struct tree_selector *dst,
		       const struct tree_selector *src);
void tree_selector_free(struct tree_selector *s);

struct tree_artifact {
	char repository[512];
	char manifest_digest[128];
	char layer_digest[128];
	char payload_sha256[128];
};

struct tree_operation {
	__s64 seq;
	char op[16];
	char id[TREE_STRING_MAX];
	struct tree_selector selector;
	struct tree_artifact artifact;
	char operation_digest[128];
};

struct tree_publication {
	int schema;
	char tree_id[TREE_STRING_MAX];
	__s64 generation;
	char parent_manifest_digest[128];
	__s64 base_seq;
	struct tree_operation *operations;
	int operations_capacity;
	int n_operations;
	__s64 head_seq;
};

struct tree_state {
	int schema;
	char tree_id[TREE_STRING_MAX];
	__s64 generation;
	__s64 last_seq;
	/* Software projection is only a crash-recovery cursor when TPM is absent. */
	char projection_root[65];
	char projection_root_tpm[65];
	char manifest_digest[128];
	/* head.seq and base.seq of the recorded publication. */
	__s64 head_seq;
	__s64 segment_base_seq;
};

int tree_parse(const char *body, size_t len,
	       struct tree_publication *out);
/* Appends a copy of op, its selector included. */
int tree_publication_append(struct tree_publication *pub,
			    const struct tree_operation *op);
void tree_publication_free(struct tree_publication *pub);

/*
 * Canonical forms shared by publisher and target: the operation digest
 * ("sha256:" + 64 hex) over an operation without its digest field, and
 * the publication document. The emitted document is xmalloc'd; release
 * it with xfree(out, out_len).
 *
 * extra, NULL for none, adds keys to the operation at index of
 * pub->operations after its artifact, outside the operation digest: the
 * publisher's fixes, which no node reads.
 */
struct tree_emit_extra {
	int	(*operation)(struct json_emit *e, int index, void *ctx);
	void	*ctx;
};

int tree_operation_digest(const struct tree_operation *op,
			  char out[72]);
int tree_emit_publication(const struct tree_publication *pub,
			  const struct tree_emit_extra *extra,
			  char **out, size_t *out_len);

/*
 * What tree sync checks before it applies anything. An operation has a
 * positive sequence number, an upatch name, add or delete, well-formed
 * digests and the operation digest its fields hash to: 0, -EINVAL, or
 * -EKEYREJECTED for a digest that does not match. A publication names a
 * well-formed parent digest if any, and its operations run from
 * base_seq + 1 to head_seq, or head_seq is base_seq without them: 0 or
 * -EINVAL, and -ENOTSUP for a base past 0, which snapshot compaction, a
 * later schema, would need. And it may follow the state the node
 * recorded, NULL for none, with manifest_digest its manifest's: the same
 * tree, a later generation unless it is the same manifest, the parent
 * the node recorded when it is the next generation and names one, no
 * head before the node's cursor and no base after it. 0, -EINVAL for
 * another tree, or -ERANGE.
 */
int tree_operation_validate(const struct tree_operation *op);
int tree_publication_check(const struct tree_publication *pub);
int tree_publication_follows(const struct tree_publication *pub,
			     const struct tree_state *state,
			     const char *manifest_digest);

/*
 * Evaluate a publication selector against the running node.  An empty
 * selector is an unconstrained wildcard and matches every node.  1 on a
 * match, 0 without one, -errno when the node's labels or kernel config
 * cannot be read.
 */
int tree_selector_matches(const struct tree_selector *selector);

/*
 * The operation tree sync is applying, recorded before it starts so that
 * a sync after a crash reconciles it with the tree eventlog: its
 * sequence number, upatch name and operation digest. Parsing refuses a
 * record that does not have those; reading is -ENOENT for none.
 */
struct tree_pending {
	__s64 seq;
	char id[TREE_STRING_MAX];
	char operation_digest[128];
};

int tree_pending_parse(const char *body, size_t len,
		       struct tree_pending *out);
int tree_pending_read(struct tree_pending *out);
int tree_pending_write(const struct tree_operation *op);

int tree_state_read(struct tree_state *out);
int tree_state_write(const struct tree_state *state);
int tree_event_append(__s64 seq, const char *operation_digest,
		      const __u8 projection_root[32]);
int tree_event_replay(__u8 out[32]);

/* What a node did with a tree operation, as its outcomes record has it. */
enum tree_outcome {
	TREE_OUTCOME_APPLIED = 1,
	TREE_OUTCOME_UNMATCHED = 2,
	TREE_OUTCOME_MODULE_ABSENT = 3,
};

/*
 * The outcomes record: one line per operation the node processed, in
 * order from seq 1, with the projection and history roots after it. A
 * last line without its newline is an append that did not finish, which
 * every reader skips. A writer holds the bpm lock.
 *
 * tree_outcome_append() writes the line of seq and syncs it to disk,
 * without looking at the lines before it; -EINVAL for a seq below 1 or
 * an outcome that is none of the three.
 *
 * tree_outcomes_read() gives the outcomes of from + 1 through to in the
 * to - from bytes at codes, and both roots after from, 32 zero bytes
 * for 0. -ENOENT when the record ends before to, -EBADMSG for a line up
 * to it that is malformed or not the next seq, -EINVAL for a range that
 * is none.
 *
 * tree_outcomes_truncate() drops every line past last_seq and a last
 * line without its newline; no record is nothing to drop. -EBADMSG as
 * above for a line up to last_seq.
 *
 * tree_outcomes_check() is what a sync holds a state with last_seq to:
 * a line for every seq from 1 to it. -EBADMSG without the record, for
 * one that ends before last_seq and as above; a last_seq of 0 asks
 * nothing.
 */
int tree_outcome_append(__s64 seq, enum tree_outcome outcome,
			const __u8 projection_root[32],
			const __u8 history_root[32]) __must_check;
int tree_outcomes_read(__s64 from, __s64 to, __u8 *codes,
		       __u8 projection_root[32],
		       __u8 history_root[32]) __must_check;
int tree_outcomes_truncate(__s64 last_seq) __must_check;
int tree_outcomes_check(__s64 last_seq) __must_check;

void tree_emit_status(struct json_emit *e);

/* Whether a tree is configured, in the config image when one is active. */
bool tree_configured(void);

#endif /* SHIRUDO_BPM_TREE_H */
