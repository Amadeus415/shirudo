// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * verifier-reject-null-deref.bpf.c -- intentionally unsafe BPF example.
 *
 * This is a negative test artifact for operator workflows. It is expected
 * to compile and package into a signed .upatch, then fail when a target
 * attempts to load the payload. The program deliberately dereferences a
 * null/scalar pointer, which violates BPF verifier memory-safety rules.
 *
 * Expected use:
 *     shirudo build examples/verifier-reject-null-deref.bpf.c \
 *         -o verifier-reject-null-deref.upatch
 *     shirudo rollout verifier-reject-null-deref.upatch <target>
 *
 * Expected target-side result: payload_load / verifier_rejected.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("lsm/socket_create")
int BPF_PROG(verifier_reject_null_deref, int family, int type,
	     int protocol, int kern)
{
	volatile int *bad = (volatile int *)0;

	/* Keep hook arguments live while preserving the unsafe load. */
	return *bad + family + type + protocol + kern;
}
