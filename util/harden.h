/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Process-hardening primitives applied at startup.
 */

#ifndef SHIRUDO_HARDEN_H
#define SHIRUDO_HARDEN_H

#include <stddef.h>

void shirudo_harden_self(void);

int shirudo_mlock_buffer(void *buf, size_t len);
void shirudo_zero_buffer(void *buf, size_t len);

#endif /* SHIRUDO_HARDEN_H */
