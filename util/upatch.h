/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .upatch container parser. On-disk layout in <shirudo/upatch.h>.
 */

#ifndef SHIRUDO_UTIL_UPATCH_H
#define SHIRUDO_UTIL_UPATCH_H

#include <shirudo/upatch.h>
#include <stdbool.h>
#include <stddef.h>

struct shirudo_upatch {
	struct shirudo_upatch_header	hdr;	/* host byte order */
	const unsigned char		*map;
	size_t				map_size;
	/* Parsed extras: embedded C source (all zero when absent). */
	const char			*source;
	uint32_t			source_len;
	const char			*source_name;
	uint32_t			source_name_len;
};

/*
 * Returns 0 on success, -errno on failure. Logs nothing -- caller
 * decides whether to emit user-facing diagnostics.
 */
int  shirudo_upatch_open(const char *path, struct shirudo_upatch *out);
void shirudo_upatch_close(struct shirudo_upatch *u);

/*
 * Section accessors. Pointers reference the mmap; valid only until
 * shirudo_upatch_close().
 */
const void *shirudo_upatch_loader(const struct shirudo_upatch *u);
const void *shirudo_upatch_signature(const struct shirudo_upatch *u);
const void *shirudo_upatch_metadata(const struct shirudo_upatch *u);
const void *shirudo_upatch_data(const struct shirudo_upatch *u);

bool shirudo_upatch_is_unload(const struct shirudo_upatch *u);

/* True if a parsed extras blob (embedded C source) is present. */
bool shirudo_upatch_has_source(const struct shirudo_upatch *u);

/*
 * Validate an externally-provided upatch name: non-empty, doesn't
 * start with '.', and matches [A-Za-z0-9._-]+. Rejects anything that
 * could escape the bpffs / on-disk path namespace.
 */
bool shirudo_upatch_name_valid(const char *name);

#endif /* SHIRUDO_UTIL_UPATCH_H */
