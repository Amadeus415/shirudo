// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * cbpf_translate() of tools/shirudo-build/cbpf.c, appending to a program
 * of one instruction: a filter of LEN instructions it accepts ends in a
 * return and stays inside itself and M[], and becomes code that jumps only
 * forward to its own instructions, reaches each, ends in an exit and
 * writes only r0 to r9 and its stack; a refusal appends nothing.
 */

#include "proof.h"
/* The C cuts a jump's offset to 16 bits and k to an immediate on purpose. */
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#include "../../../tools/shirudo-build/cbpf.c"
#pragma CPROVER check pop

/*
 * The prologue with M[] zeroed, the shared refusal and an indirect load,
 * the longest an instruction becomes.
 */
#define EMIT_MAX	(16 + 12 * LEN)
/* The instruction the program holds before, and the translation. */
#define PROG_MAX	(1 + EMIT_MAX)

static struct bpf_insn prog_store[PROG_MAX];
static __u32 start_store[LEN];
static bool reachable_store[LEN];

static bool allocation_fails(void)
{
	bool fails;

	return fails;
}

/*
 * In place of util/malloc.c, whose xreallocarray() allocates a size the
 * filter decides and copies into it, which costs the solver more memory
 * than it has: fixed storage, and any allocation may fail.
 */
void *xcalloc(size_t nmemb, size_t size)
{
	__CPROVER_assert(nmemb == LEN && (size == sizeof(start_store[0]) ||
					  size == sizeof(reachable_store[0])),
			 "only the tables of the filter are allocated");
	if (allocation_fails())
		return NULL;
	if (size == sizeof(start_store[0]))
		return start_store;
	return reachable_store;
}

void *xreallocarray(void *ptr, size_t old_nmemb, size_t new_nmemb,
		    size_t size)
{
	__CPROVER_assert(size == sizeof(prog_store[0]) &&
			 new_nmemb <= PROG_MAX && (!ptr || ptr == prog_store),
			 "only the program grows, to at most PROG_MAX");
	if (allocation_fails())
		return NULL;
	return prog_store;
}

void xfree(void *ptr, size_t size)
{
	__CPROVER_assert(!ptr || ptr == prog_store || ptr == start_store ||
			 ptr == reachable_store,
			 "only what was allocated is freed");
}

static bool insn_equal(const struct bpf_insn *a, const struct bpf_insn *b)
{
	return a->code == b->code && a->dst_reg == b->dst_reg &&
	       a->src_reg == b->src_reg && a->off == b->off && a->imm == b->imm;
}

static bool names_memory(__u16 code)
{
	__u16 class = BPF_CLASS(code);

	return class == BPF_ST || class == BPF_STX ||
	       ((class == BPF_LD || class == BPF_LDX) &&
		BPF_MODE(code) == BPF_MEM);
}

static bool jumps_inside(const struct sock_filter *insn, __u32 left)
{
	if (BPF_CLASS(insn->code) != BPF_JMP)
		return true;
	if (BPF_OP(insn->code) == BPF_JA)
		return insn->k < left;
	return insn->jt < left && insn->jf < left;
}

static void check_accepted_filter(const struct sock_filter *filter)
{
	__u32 i;

	for (i = 0; i < LEN; i++) {
		__CPROVER_assert(jumps_inside(&filter[i], LEN - i - 1),
				 "an accepted filter jumps inside itself");
		__CPROVER_assert(!names_memory(filter[i].code) ||
				 filter[i].k < BPF_MEMWORDS,
				 "an accepted filter names only words of M[]");
	}
}

static __s32 access_bytes(__u8 code)
{
	switch (BPF_SIZE(code)) {
	case BPF_DW:
		return 8;
	case BPF_W:
		return 4;
	case BPF_H:
		return 2;
	default:
		return 1;
	}
}

static bool on_stack(const struct bpf_insn *insn)
{
	return BPF_MODE(insn->code) == BPF_MEM &&
	       insn->off >= -CBPF_STACK_SIZE &&
	       insn->off + access_bytes(insn->code) <= 0;
}

/*
 * The registers and memory cbpf.h promises: r0 to r9 written, r10 read,
 * the CBPF_STACK_SIZE bytes below it, and bpf_probe_read_kernel() the one
 * call. An ALU instruction's off of 0 rules out v4's signed division and
 * sign-extending moves.
 */
static bool insn_confined(const struct bpf_insn *insn)
{
	switch (BPF_CLASS(insn->code)) {
	case BPF_ALU:
	case BPF_ALU64:
		return insn->dst_reg <= BPF_REG_9 &&
		       insn->src_reg <= BPF_REG_10 && !insn->off;
	case BPF_LDX:
		return insn->dst_reg <= BPF_REG_9 &&
		       insn->src_reg == BPF_REG_10 && on_stack(insn);
	case BPF_ST:
	case BPF_STX:
		return insn->dst_reg == BPF_REG_10 &&
		       insn->src_reg <= BPF_REG_9 && on_stack(insn);
	case BPF_JMP:
		if (BPF_OP(insn->code) == BPF_CALL)
			return !insn->src_reg &&
			       insn->imm == BPF_FUNC_probe_read_kernel;
		return insn->dst_reg <= BPF_REG_9 && insn->src_reg <= BPF_REG_9;
	case BPF_JMP32:
		return BPF_OP(insn->code) != BPF_CALL &&
		       BPF_OP(insn->code) != BPF_EXIT &&
		       BPF_OP(insn->code) != BPF_JA &&
		       insn->dst_reg <= BPF_REG_9 && insn->src_reg <= BPF_REG_9;
	default:
		return false;
	}
}

static bool insn_jumps(const struct bpf_insn *insn)
{
	__u8 class = BPF_CLASS(insn->code), op = BPF_OP(insn->code);

	return (class == BPF_JMP || class == BPF_JMP32) && op != BPF_CALL &&
	       op != BPF_EXIT;
}

static bool insn_falls_through(const struct bpf_insn *insn)
{
	return insn->code != (BPF_JMP | BPF_EXIT) &&
	       insn->code != (BPF_JMP | BPF_JA);
}

/*
 * Every jump goes forward, so one pass in order marks what is reachable
 * before it is read.
 */
static void check_translation(const struct bpf_insn *code, __u32 n)
{
	bool reached[EMIT_MAX] = {};
	__s64 to;
	__u32 p;

	__CPROVER_assert(n > 0 && n <= EMIT_MAX,
			 "the code is no longer than EMIT_MAX");
	if (!n || n > EMIT_MAX)
		return;
	__CPROVER_assert(code[n - 1].code == (BPF_JMP | BPF_EXIT),
			 "the code ends in an exit");
	reached[0] = true;
	for (p = 0; p < n; p++) {
		__CPROVER_assert(reached[p], "every instruction is reachable");
		__CPROVER_assert(insn_confined(&code[p]),
				 "an instruction reaches only its registers and stack");
		if (insn_falls_through(&code[p]) && p + 1 < n)
			reached[p + 1] = true;
		if (!insn_jumps(&code[p]))
			continue;
		to = (__s64)p + 1 + code[p].off;
		__CPROVER_assert(to > p && to < n,
				 "a jump goes forward to an instruction of the code");
		if (to > p && to < n)
			reached[to] = true;
	}
}

void harness(void)
{
	struct sock_filter filter[LEN];
	struct ebpf_prog out = {};
	struct bpf_insn before;
	int ret;

	__CPROVER_assume(!ebpf_prog_append(&out, &before, 1));
	ret = cbpf_translate(filter, LEN, &out);
	__CPROVER_assert(!ret || ret == -EINVAL || ret == -EOPNOTSUPP ||
			 ret == -E2BIG || ret == -ENOMEM,
			 "the result is 0 or an error cbpf.h names");
	__CPROVER_assert(insn_equal(&out.insns[0], &before),
			 "the program's instruction is kept");
	if (BPF_CLASS(filter[LEN - 1].code) != BPF_RET)
		__CPROVER_assert(ret == -EINVAL || ret == -ENOMEM,
				 "a filter that does not end in a return is refused");
	if (ret) {
		__CPROVER_assert(out.len == 1, "a refusal appends nothing");
	} else {
		check_accepted_filter(filter);
		check_translation(out.insns + 1, out.len - 1);
	}
	ebpf_prog_free(&out);
}
