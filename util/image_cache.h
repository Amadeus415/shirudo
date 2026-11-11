/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The config image cache, which rust/src/util/image_cache.rs implements.
 */

#ifndef SHIRUDO_IMAGE_CACHE_H
#define SHIRUDO_IMAGE_CACHE_H

struct config_update_target;

/* The caller holds the update lock and owns the sealed cache directory. */
int image_cache_fetch(const char *source,
		      struct config_update_target *target);

#endif /* SHIRUDO_IMAGE_CACHE_H */
