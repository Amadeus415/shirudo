/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Lowercase hex encoding of digests.
 */

#ifndef SHIRUDO_HEX_H
#define SHIRUDO_HEX_H

#include <stddef.h>
#include <stdint.h>

/* out needs 2 * n + 1 bytes. */
void shirudo_hex_encode(const uint8_t *in, size_t n, char *out);

/* Exactly 2 * n hex digits, either case. 0 or -EINVAL. */
int shirudo_hex_decode(const char *hex, uint8_t *out, size_t n);

#endif /* SHIRUDO_HEX_H */
