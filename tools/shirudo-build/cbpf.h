/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Classic BPF, as libpcap compiles a filter, translated into eBPF that
 * reads the packet through bpf_probe_read_kernel().
 */

#ifndef SHIRUDO_BUILD_CBPF_H
#define SHIRUDO_BUILD_CBPF_H

#include <linux/bpf.h>
#include <linux/filter.h>

#include <shirudo/compiler.h>
#include <shirudo/types.h>

/* The stack below r10 the translation uses: M[] and the word a load reads. */
#define CBPF_STACK_SIZE		(4 * BPF_MEMWORDS + 8)

struct ebpf_prog {
	struct bpf_insn	*insns;
	__u32		len;
	__u32		cap;
};

/* Appends the n instructions of insns to prog: 0, -E2BIG or -ENOMEM. */
int ebpf_prog_append(struct ebpf_prog *prog, const struct bpf_insn *insns,
		     __u32 n) __must_check;
void ebpf_prog_free(struct ebpf_prog *prog);

/*
 * Appends to out the translation of the len instructions of filter: code
 * entered with r1 at the first byte of the packet and r2 past its last,
 * which returns in w0 what filter returns, and 0 where filter would
 * read past the end or divide by zero, or where the packet cannot be
 * read. It writes r0 to r9 and CBPF_STACK_SIZE bytes below r10 and
 * reaches nothing else, so it can stand as the body of a subprogram.
 *
 * -EINVAL for a filter the kernel's classic BPF checker refuses,
 * -EOPNOTSUPP for a load at an offset no packet reaches, which is how
 * Linux encodes its ancillary data, -E2BIG for a jump eBPF cannot
 * encode, -ENOMEM; out is left as it was.
 */
int cbpf_translate(const struct sock_filter *filter, __u32 len,
		   struct ebpf_prog *out) __must_check;

#endif /* SHIRUDO_BUILD_CBPF_H */
