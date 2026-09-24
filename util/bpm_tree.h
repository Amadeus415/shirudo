/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPM_TREE_H
#define SHIRUDO_BPM_TREE_H

#include <stddef.h>
#include <stdint.h>

#include "chain.h"

#define SHIRUDO_TREE_MAX_OPS 512
#define SHIRUDO_TREE_MAX_KCONFIG 64
#define SHIRUDO_TREE_MAX_LABELS 64
#define SHIRUDO_TREE_MAX_SELECTOR_VALUES 16
#define SHIRUDO_TREE_STRING_MAX 256

struct shirudo_json_emit;

struct shirudo_tree_kv {
	char key[SHIRUDO_TREE_STRING_MAX];
	char value[SHIRUDO_TREE_STRING_MAX];
};

struct shirudo_tree_selector_kv {
	char key[SHIRUDO_TREE_STRING_MAX];
	char values[SHIRUDO_TREE_MAX_SELECTOR_VALUES][SHIRUDO_TREE_STRING_MAX];
	int n_values;
};

struct shirudo_tree_selector {
	char kernel_release_prefix[SHIRUDO_TREE_MAX_SELECTOR_VALUES][SHIRUDO_TREE_STRING_MAX];
	int n_kernel_release_prefix;
	char kernel_build_id[SHIRUDO_TREE_MAX_SELECTOR_VALUES][SHIRUDO_TREE_STRING_MAX];
	int n_kernel_build_id;
	char architecture[SHIRUDO_TREE_MAX_SELECTOR_VALUES][SHIRUDO_TREE_STRING_MAX];
	int n_architecture;
	struct shirudo_tree_selector_kv kconfig[SHIRUDO_TREE_MAX_KCONFIG];
	int n_kconfig;
	struct shirudo_tree_selector_kv labels[SHIRUDO_TREE_MAX_LABELS];
	int n_labels;
};

struct shirudo_tree_artifact {
	char repository[512];
	char manifest_digest[128];
	char layer_digest[128];
	char payload_sha256[128];
};

struct shirudo_tree_operation {
	int64_t seq;
	char op[16];
	char id[SHIRUDO_TREE_STRING_MAX];
	struct shirudo_tree_selector selector;
	struct shirudo_tree_artifact artifact;
	char expected_payload_sha256[128];
	char operation_digest[128];
};

struct shirudo_tree_publication {
	int schema;
	char tree_id[SHIRUDO_TREE_STRING_MAX];
	int64_t generation;
	char parent_manifest_digest[128];
	int64_t base_seq;
	struct shirudo_tree_operation *operations;
	int operations_capacity;
	int n_operations;
	int64_t head_seq;
};

struct shirudo_tree_state {
	int schema;
	char tree_id[SHIRUDO_TREE_STRING_MAX];
	int64_t generation;
	int64_t last_seq;
	/* Software projection is only a crash-recovery cursor when TPM is absent. */
	char projection_root[65];
	char projection_root_tpm[65];
	char manifest_digest[128];
};

/* Parse the signed tree payload. Unknown JSON fields are ignored. */
int shirudo_tree_parse(const char *body, size_t len,
			       struct shirudo_tree_publication *out);
void shirudo_tree_publication_free(struct shirudo_tree_publication *pub);

/* Evaluate a publication selector against the running node.  An empty
 * selector is an unconstrained wildcard and matches every node. */
int shirudo_tree_selector_matches(const struct shirudo_tree_selector *selector);

/* Persistent tree state and selected-operation eventlog. */
int shirudo_tree_state_read(struct shirudo_tree_state *out);
int shirudo_tree_state_write(const struct shirudo_tree_state *state);
int shirudo_tree_event_append(int64_t seq, const char *operation_digest,
			      const uint8_t projection_root[32]);
int shirudo_tree_event_replay(uint8_t out[32]);

/* Dedicated TPM projection chain. */
int shirudo_tree_chain_ensure(void);
int shirudo_tree_chain_read(uint8_t out[32]);
int shirudo_tree_chain_extend(const uint8_t operation_digest[32],
			     uint8_t out[32]);

/* Emit report-only tree state into an already-open JSON object. */
void shirudo_tree_emit_status(struct shirudo_json_emit *e);

#endif /* SHIRUDO_BPM_TREE_H */
