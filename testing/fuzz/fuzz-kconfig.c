// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A kernel config, plain or gzip'd, as an upatch tree selector reads it,
 * and node.labels.
 */

#include "fuzz.h"

#include <shirudo/string.h>

#include "bpm_tree.h"

static struct tree_selector sel;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	static const char * const keys[] = {
		"CONFIG_BPF_LSM", "CONFIG_DEBUG_INFO_BTF", "CONFIG_LOCALVERSION",
		"CONFIG_LSM", "CONFIG_MODULES",
	};

	for (size_t i = 0; i < ARRAY_SIZE(keys); i++) {
		struct tree_selector_kv *kv;

		if (tree_selector_kv_add(&sel.kconfig, &sel.n_kconfig,
					 TREE_MAX_KCONFIG, &kv))
			abort();
		strscpy(kv->key, keys[i], sizeof(kv->key));
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	static char values[TREE_MAX_KCONFIG][TREE_STRING_MAX];
	static struct tree_kv labels[TREE_MAX_LABELS];
	bool found[TREE_MAX_KCONFIG] = {};
	char path[64];
	int fd, n;

	fd = fuzz_file(data, size, path, sizeof(path));
	if (fd < 0)
		return 0;
	tree_kconfig_read(path, &sel, values, found, false);
	tree_kconfig_read(path, &sel, values, found, true);
	tree_labels_read(path, labels, &n, ARRAY_SIZE(labels));
	close(fd);
	return 0;
}
