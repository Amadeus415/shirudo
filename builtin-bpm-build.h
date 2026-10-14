/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Beefile model shared by `bpm build` and `bpm tree append`.
 */

#ifndef SHIRUDO_BUILTIN_BPM_BUILD_H
#define SHIRUDO_BUILTIN_BPM_BUILD_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include "util/bpm_tree.h"
#include "util/crypto.h"
#include "util/upatch.h"

#define BPM_BUILD_MAX_ENTRIES 128

struct bpm_build_file {
	char source[PATH_MAX];
	char target[PATH_MAX];
};

/*
 * Optional [upatches.tree] table. Publication metadata read by `bpm tree
 * append` on the operator; the target consumes the signed publication and
 * never sees the Beefile. The selector lives on the heap because it is
 * large and rarely present.
 */
struct bpm_build_tree {
	bool present;
	char id[SHIRUDO_UPATCH_NAME_MAX];
	char load_artifact[PATH_MAX];
	char unload_artifact[PATH_MAX];
	struct shirudo_tree_selector *selector;
};

struct bpm_build_upatch {
	char source[PATH_MAX];
	char type[16];
	char load_target[PATH_MAX];
	char unload_target[PATH_MAX];
	char load_path[PATH_MAX];
	char unload_path[PATH_MAX];
	char name[SHIRUDO_UPATCH_NAME_MAX];
	char payload_sha256[SHIRUDO_CRYPTO_SHA256_LEN * 2 + 1];
	struct bpm_build_tree tree;
};

struct bpm_build_spec {
	char name[128];
	char scope[PATH_MAX];
	unsigned char *build_file;
	size_t build_file_len;
	struct bpm_build_file files[BPM_BUILD_MAX_ENTRIES];
	size_t n_files;
	struct bpm_build_upatch upatches[BPM_BUILD_MAX_ENTRIES];
	size_t n_upatches;
};

/*
 * Parse a Beefile into spec. The spec keeps a copy of the original bytes
 * in build_file (the archive embeds them verbatim). Release with
 * bpm_build_spec_free(); the spec itself is large and belongs on the heap.
 */
int bpm_build_parse_beefile(const unsigned char *body, size_t len,
			    struct bpm_build_spec *spec);
void bpm_build_spec_free(struct bpm_build_spec *spec);

/*
 * The operator-only shirudo-build helper: SHIRUDO_BUILD, the compiled-in
 * libexec path, then PATH. bpm_build_run_helper() forks and execs the
 * NULL-terminated argv (argv[0] names the helper) in workdir and returns 0
 * only on a zero exit status.
 */
const char *bpm_build_helper(void);
bool bpm_build_helper_available(void);
int bpm_build_run_helper(const char *workdir, char *const argv[]);

#endif /* SHIRUDO_BUILTIN_BPM_BUILD_H */
