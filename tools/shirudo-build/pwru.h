/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo pwru, the helper's half.
 */

#ifndef SHIRUDO_BUILD_PWRU_H
#define SHIRUDO_BUILD_PWRU_H

/* The object and the decoder pwru.c carries, from .incbin. */
extern const char shirudo_pwru_bpf_o[], shirudo_pwru_bpf_o_end[];
extern const char shirudo_pwru_lua[], shirudo_pwru_lua_end[];

int build_pwru(int argc, const char **argv);

#endif /* SHIRUDO_BUILD_PWRU_H */
