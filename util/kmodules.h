/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Parse /proc/modules and render an ASCII dependency tree. Used by
 * `shirudo status --include-modules` and `shirudo nodes show`.
 */

#ifndef SHIRUDO_UTIL_KMODULES_H
#define SHIRUDO_UTIL_KMODULES_H

#include <stddef.h>
#include <stdint.h>

#define SHIRUDO_KMOD_NAME_LEN	64

struct shirudo_kmod {
	char		name[SHIRUDO_KMOD_NAME_LEN];
	uint64_t	size;		/* bytes */
	uint32_t	refcount;	/* /proc/modules column 3 */
	uint16_t	n_deps;
	uint16_t	deps_off;	/* index into the global deps[] */
};

struct shirudo_kmod_set {
	struct shirudo_kmod	*mods;	/* sorted by name, ascending */
	size_t			n;
	uint16_t		*deps;	/* flat: mods[i].deps_off..+n_deps */
	size_t			n_deps;
};

/* Read /proc/modules into <set>. Returns 0 / -errno. */
int  shirudo_kmodules_read(struct shirudo_kmod_set *set);
void shirudo_kmodules_free(struct shirudo_kmod_set *set);

/* Render as an ASCII tree with the kubectl-describe 2-space indent. */
void shirudo_kmodules_print_tree(const struct shirudo_kmod_set *set);

/*
 * Format a size in human units (16K, 1.8M, ...) into <out>. The form
 * `shirudo_human_size` is exposed so the JSON path can share it.
 */
void shirudo_human_size(uint64_t bytes, char *out, size_t out_cap);

#endif /* SHIRUDO_UTIL_KMODULES_H */
