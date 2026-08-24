/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_UTIL_SERIALIZER_H
#define SHIRUDO_UTIL_SERIALIZER_H

#include <stdint.h>

#include "bpf/lib/shirudo_serializer.h"

int shirudo_serializer_lock_acquire(uint32_t map_id);
int shirudo_serializer_lock_acquire_at(const char *dir, uint32_t map_id);
int shirudo_serializer_new_invocation_id(uint64_t *out);

int shirudo_serial_chunk_validate(const struct shirudo_serial_chunk *chunk,
				  uint32_t want_index,
				  uint32_t total_chunks,
				  uint32_t page_index,
				  uint64_t cursor,
				  uint64_t next_cursor,
				  uint64_t invocation_id);

#endif /* SHIRUDO_UTIL_SERIALIZER_H */
