/* SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0) */
/* Copyright (c) 2026 Authors of shirudo */

/* Build the compatibility BPF-LSM variant without kernel signature ABI. */
#define SHIRUDO_BPF2_LEGACY 1
#include "bpf2.c"
