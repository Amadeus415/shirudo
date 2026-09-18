/* SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0) */
/* Copyright (c) 2026 Authors of shirudo */

/* Build the compatibility variant without kernel signature ABI or
 * BPF admission hooks. Trusted-root verifies the loader in userspace;
 * filesystem and mount-lifecycle hooks remain active. */
#define SHIRUDO_BPF2_LEGACY 1
#define SHIRUDO_BPF2_NO_ADMISSION 1
#include "bpf2.c"
