/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Human-readable formatters shared across status/nodes/keys renderers.
 */

#ifndef SHIRUDO_UTIL_FORMAT_H
#define SHIRUDO_UTIL_FORMAT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Format a byte count in IEC-binary human units: B/K/M/G. Precision is
 * picked so the rendered value stays within four significant digits
 * regardless of magnitude (16K / 1.8M / 5.57G / 1.23G / 124G).
 */
void shirudo_human_size(uint64_t bytes, char *out, size_t out_cap);

#endif /* SHIRUDO_UTIL_FORMAT_H */
