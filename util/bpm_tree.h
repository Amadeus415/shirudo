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
 */
int tree_operation_digest(const struct tree_operation *op,
			  char out[72]);
int tree_emit_publication(const struct tree_publication *pub,
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
 * The selector match and the state below are
 * rust/src/util/bpm_tree_state.rs.
 *
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

void tree_emit_status(struct json_emit *e);

/* Whether a tree is configured, in the config image when one is active. */
bool tree_configured(void);

/*
 * For the unit test and fuzz targets, which reached these by including
 * the C once: the values the kernel config at path, gzip'd or not,
 * gives the selector's kconfig keys, as the selector match reads
 * /proc/config.gz and /boot/config-*, 0 with found[i] and values[i]
 * for each key i the config sets, or -errno; the key = value lines of
 * a node.labels at path into the max pairs at labels, *n of them; and
 * tree_state_read() and tree_event_replay() on the file at path.
 */
int tree_kconfig_read(const char *path, const struct tree_selector *s,
		      char values[][TREE_STRING_MAX], bool found[], bool gz);
int tree_labels_read(const char *path, struct tree_kv *labels, int *n,
		     int max);
int tree_state_read_path(const char *path, struct tree_state *out);
int tree_event_replay_path(const char *path, __u8 out[32]);

#endif /* SHIRUDO_BPM_TREE_H */
