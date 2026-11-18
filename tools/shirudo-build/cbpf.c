// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Classic BPF into eBPF: A and X in w6 and w7, the packet's start and
 * length in r8 and r9, M[] on the stack, and every packet load checked
 * against the length and made with bpf_probe_read_kernel().
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>

#include "cbpf.h"
#include "malloc.h"

#define REG_A		BPF_REG_6
#define REG_X		BPF_REG_7
#define REG_DATA	BPF_REG_8
#define REG_LEN		BPF_REG_9

#define SCRATCH_OFF	(-8)
#define MEM_OFF		(-CBPF_STACK_SIZE)

/*
 * The furthest offset a load takes. Every packet ends far below it, and
 * the end of a load from there still fits a positive eBPF immediate;
 * Linux encodes its ancillary loads as offsets above it.
 */
#define LOAD_OFF_MAX	(0x7fffffffU - 4U)

/* BPF_COMPLEXITY_LIMIT_INSNS, the most instructions a program loads with. */
#define EBPF_INSNS_MAX	1000000U

struct xlat {
	const struct sock_filter	*filter;
	__u32				len;
	__u32				*start;
	bool				*reachable;
	bool				uses_mem;
	__u32				fail;
	struct bpf_insn			*out;
	__u32				size;
	__u32				pos;
	int				err;
};

static void emit(struct xlat *x, __u8 code, __u8 dst, __u8 src, __s16 off,
		 __s32 imm)
{
	if (x->out && x->pos < x->size)
		x->out[x->pos] = (struct bpf_insn){
			.code = code, .dst_reg = dst, .src_reg = src,
			.off = off, .imm = imm,
		};
	x->pos++;
}

/* A jump from the instruction emitted next to target. */
static void emit_jump(struct xlat *x, __u8 code, __u8 dst, __u8 src,
		      __s32 imm, __u32 target)
{
	__s64 off = (__s64)target - x->pos - 1;

	if (x->out && off != (__s16)off)
		x->err = -E2BIG;
	emit(x, code, dst, src, (__s16)off, imm);
}

static __u32 load_size(__u16 code)
{
	switch (BPF_SIZE(code)) {
	case BPF_H:
		return 2;
	case BPF_B:
		return 1;
	default:
		return 4;
	}
}

/*
 * dst = the bytes at r3, which the caller points at the packet, in host
 * order; classic BPF reads them in network order.
 */
static void emit_read(struct xlat *x, __u8 dst, __u16 size_code)
{
	__u32 size = load_size(size_code);

	emit(x, BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_10, 0, 0);
	emit(x, BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_1, 0, 0, SCRATCH_OFF);
	emit(x, BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_2, 0, 0, size);
	emit(x, BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_probe_read_kernel);
	emit_jump(x, BPF_JMP | BPF_JNE | BPF_K, BPF_REG_0, 0, 0, x->fail);
	emit(x, BPF_LDX | BPF_MEM | BPF_SIZE(size_code), dst, BPF_REG_10,
	     SCRATCH_OFF, 0);
	if (size > 1)
		emit(x, BPF_ALU | BPF_END | BPF_TO_BE, dst, 0, 0, size * 8);
}

static void emit_load_abs(struct xlat *x, __u8 dst, __u16 size_code,
			  __u32 off)
{
	__u32 end = off + load_size(size_code);

	emit_jump(x, BPF_JMP | BPF_JLT | BPF_K, REG_LEN, 0, end, x->fail);
	emit(x, BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_3, REG_DATA, 0, 0);
	emit(x, BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_3, 0, 0, off);
	emit_read(x, dst, size_code);
}

/* X holds 32 bits, so X + off cannot wrap in 64. */
static void emit_load_ind(struct xlat *x, __u16 size_code, __u32 off)
{
	emit(x, BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_3, REG_X, 0, 0);
	emit(x, BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_3, 0, 0, off);
	emit(x, BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_3, 0, 0);
	emit(x, BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0,
	     load_size(size_code));
	emit_jump(x, BPF_JMP | BPF_JGT | BPF_X, BPF_REG_2, REG_LEN, 0, x->fail);
	emit(x, BPF_ALU64 | BPF_ADD | BPF_X, BPF_REG_3, REG_DATA, 0, 0);
	emit_read(x, REG_A, size_code);
}

static __s16 mem_off(__u32 k)
{
	return (__s16)(MEM_OFF + 4 * (__s32)k);
}

static void emit_ld(struct xlat *x, const struct sock_filter *insn)
{
	__u8 dst = BPF_CLASS(insn->code) == BPF_LD ? REG_A : REG_X;

	switch (BPF_MODE(insn->code)) {
	case BPF_IMM:
		emit(x, BPF_ALU | BPF_MOV | BPF_K, dst, 0, 0, insn->k);
		break;
	case BPF_MEM:
		emit(x, BPF_LDX | BPF_MEM | BPF_W, dst, BPF_REG_10,
		     mem_off(insn->k), 0);
		break;
	case BPF_LEN:
		emit(x, BPF_ALU | BPF_MOV | BPF_X, dst, REG_LEN, 0, 0);
		break;
	case BPF_ABS:
		emit_load_abs(x, REG_A, insn->code, insn->k);
		break;
	case BPF_IND:
		emit_load_ind(x, insn->code, insn->k);
		break;
	case BPF_MSH:
		emit_load_abs(x, REG_X, BPF_B, insn->k);
		emit(x, BPF_ALU | BPF_AND | BPF_K, REG_X, 0, 0, 0xf);
		emit(x, BPF_ALU | BPF_LSH | BPF_K, REG_X, 0, 0, 2);
		break;
	default:
		break;
	}
}

/*
 * A division by an X of 0 refuses the packet, and a shift by an X of 32
 * or more leaves 0, as libpcap's interpreter has it.
 */
static void emit_alu(struct xlat *x, const struct sock_filter *insn)
{
	__u8 op = BPF_OP(insn->code);

	if (op == BPF_NEG) {
		emit(x, BPF_ALU | BPF_NEG, REG_A, 0, 0, 0);
		return;
	}
	if (BPF_SRC(insn->code) == BPF_K) {
		emit(x, BPF_ALU | op | BPF_K, REG_A, 0, 0, insn->k);
		return;
	}
	switch (op) {
	case BPF_DIV:
	case BPF_MOD:
		emit_jump(x, BPF_JMP32 | BPF_JEQ | BPF_K, REG_X, 0, 0, x->fail);
		break;
	case BPF_LSH:
	case BPF_RSH:
		emit(x, BPF_JMP32 | BPF_JGT | BPF_K, REG_X, 0, 2, 31);
		emit(x, BPF_ALU | op | BPF_X, REG_A, REG_X, 0, 0);
		emit(x, BPF_JMP | BPF_JA, 0, 0, 1, 0);
		emit(x, BPF_ALU | BPF_MOV | BPF_K, REG_A, 0, 0, 0);
		return;
	default:
		break;
	}
	emit(x, BPF_ALU | op | BPF_X, REG_A, REG_X, 0, 0);
}

/* The condition false where op is true; BPF_JSET has none. */
static __u8 jump_inverse(__u8 op)
{
	switch (op) {
	case BPF_JEQ:
		return BPF_JNE;
	case BPF_JGT:
		return BPF_JLE;
	case BPF_JGE:
		return BPF_JLT;
	default:
		return 0;
	}
}

/* Classic BPF compares A as 32 unsigned bits, which BPF_JMP32 does. */
static void emit_jmp(struct xlat *x, __u32 i, const struct sock_filter *insn)
{
	__u8 op = BPF_OP(insn->code), src = BPF_SRC(insn->code);
	__u8 reg = src == BPF_X ? REG_X : 0;
	__u32 t, f;

	if (op == BPF_JA) {
		if (insn->k)
			emit_jump(x, BPF_JMP | BPF_JA, 0, 0, 0,
				  x->start[i + 1 + insn->k]);
		return;
	}
	t = x->start[i + 1 + insn->jt];
	f = x->start[i + 1 + insn->jf];
	if (insn->jt == insn->jf) {
		if (insn->jt)
			emit_jump(x, BPF_JMP | BPF_JA, 0, 0, 0, t);
		return;
	}
	if (!insn->jt && jump_inverse(op)) {
		emit_jump(x, BPF_JMP32 | jump_inverse(op) | src, REG_A, reg,
			  insn->k, f);
		return;
	}
	emit_jump(x, BPF_JMP32 | op | src, REG_A, reg, insn->k, t);
	if (insn->jf)
		emit_jump(x, BPF_JMP | BPF_JA, 0, 0, 0, f);
}

static void emit_insn(struct xlat *x, __u32 i)
{
	const struct sock_filter *insn = &x->filter[i];

	switch (BPF_CLASS(insn->code)) {
	case BPF_LD:
	case BPF_LDX:
		emit_ld(x, insn);
		break;
	case BPF_ST:
		emit(x, BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, REG_A,
		     mem_off(insn->k), 0);
		break;
	case BPF_STX:
		emit(x, BPF_STX | BPF_MEM | BPF_W, BPF_REG_10, REG_X,
		     mem_off(insn->k), 0);
		break;
	case BPF_ALU:
		emit_alu(x, insn);
		break;
	case BPF_JMP:
		emit_jmp(x, i, insn);
		break;
	case BPF_RET:
		if (BPF_RVAL(insn->code) == BPF_A)
			emit(x, BPF_ALU | BPF_MOV | BPF_X, BPF_REG_0, REG_A,
			     0, 0);
		else
			emit(x, BPF_ALU | BPF_MOV | BPF_K, BPF_REG_0, 0, 0,
			     insn->k);
		emit(x, BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
		break;
	case BPF_MISC:
		if (BPF_MISCOP(insn->code) == BPF_TAX)
			emit(x, BPF_ALU | BPF_MOV | BPF_X, REG_X, REG_A, 0, 0);
		else
			emit(x, BPF_ALU | BPF_MOV | BPF_X, REG_A, REG_X, 0, 0);
		break;
	default:
		break;
	}
}

/*
 * The registers a call keeps hold the state, so each starts written: the
 * verifier does not let a subprogram read the ones its caller holds. M[]
 * starts zeroed where the filter uses it.
 */
static void emit_prologue(struct xlat *x)
{
	__u32 i;

	emit_jump(x, BPF_JMP | BPF_JGT | BPF_X, BPF_REG_1, BPF_REG_2, 0, x->fail);
	emit(x, BPF_ALU64 | BPF_MOV | BPF_X, REG_DATA, BPF_REG_1, 0, 0);
	emit(x, BPF_ALU64 | BPF_MOV | BPF_X, REG_LEN, BPF_REG_2, 0, 0);
	emit(x, BPF_ALU64 | BPF_SUB | BPF_X, REG_LEN, BPF_REG_1, 0, 0);
	emit(x, BPF_ALU | BPF_MOV | BPF_K, REG_A, 0, 0, 0);
	emit(x, BPF_ALU | BPF_MOV | BPF_K, REG_X, 0, 0, 0);
	if (!x->uses_mem)
		return;
	for (i = 0; i < BPF_MEMWORDS / 2; i++)
		emit(x, BPF_ST | BPF_MEM | BPF_DW, BPF_REG_10, 0,
		     (__s16)(MEM_OFF + 8 * (__s32)i), 0);
}

/*
 * An instruction no path reaches emits nothing, as the verifier refuses
 * unreachable code. Only the sizing pass records where each starts.
 */
static void emit_all(struct xlat *x)
{
	__u32 i;

	x->pos = 0;
	emit_prologue(x);
	for (i = 0; i < x->len; i++) {
		if (!x->out)
			x->start[i] = x->pos;
		if (x->reachable[i])
			emit_insn(x, i);
	}
	if (!x->out)
		x->fail = x->pos;
	emit(x, BPF_ALU | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0);
	emit(x, BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
}

static bool code_valid(__u16 code)
{
	switch (code) {
	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU | BPF_MOD | BPF_K:
	case BPF_ALU | BPF_MOD | BPF_X:
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU | BPF_OR | BPF_K:
	case BPF_ALU | BPF_OR | BPF_X:
	case BPF_ALU | BPF_XOR | BPF_K:
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU | BPF_LSH | BPF_K:
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU | BPF_RSH | BPF_K:
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU | BPF_NEG:
	case BPF_LD | BPF_W | BPF_ABS:
	case BPF_LD | BPF_H | BPF_ABS:
	case BPF_LD | BPF_B | BPF_ABS:
	case BPF_LD | BPF_W | BPF_IND:
	case BPF_LD | BPF_H | BPF_IND:
	case BPF_LD | BPF_B | BPF_IND:
	case BPF_LD | BPF_W | BPF_LEN:
	case BPF_LD | BPF_IMM:
	case BPF_LD | BPF_MEM:
	case BPF_LDX | BPF_W | BPF_LEN:
	case BPF_LDX | BPF_B | BPF_MSH:
	case BPF_LDX | BPF_IMM:
	case BPF_LDX | BPF_MEM:
	case BPF_ST:
	case BPF_STX:
	case BPF_MISC | BPF_TAX:
	case BPF_MISC | BPF_TXA:
	case BPF_RET | BPF_K:
	case BPF_RET | BPF_A:
	case BPF_JMP | BPF_JA:
	case BPF_JMP | BPF_JEQ | BPF_K:
	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_K:
	case BPF_JMP | BPF_JSET | BPF_X:
		return true;
	default:
		return false;
	}
}

static bool uses_mem(__u16 code)
{
	return code == BPF_ST || code == BPF_STX ||
	       code == (BPF_LD | BPF_MEM) || code == (BPF_LDX | BPF_MEM);
}

static bool loads_packet(__u16 code)
{
	__u16 mode = BPF_MODE(code);

	return (BPF_CLASS(code) == BPF_LD || BPF_CLASS(code) == BPF_LDX) &&
	       (mode == BPF_ABS || mode == BPF_IND || mode == BPF_MSH);
}

/* What the kernel's classic BPF checker refuses, it refuses too. */
static int check_insn(const struct sock_filter *insn, __u32 left)
{
	__u16 code = insn->code;
	__u8 op = BPF_OP(code);

	if (!code_valid(code))
		return -EINVAL;
	if (uses_mem(code) && insn->k >= BPF_MEMWORDS)
		return -EINVAL;
	if (loads_packet(code) && insn->k > LOAD_OFF_MAX)
		return -EOPNOTSUPP;
	if (BPF_CLASS(code) == BPF_ALU && BPF_SRC(code) == BPF_K &&
	    (((op == BPF_DIV || op == BPF_MOD) && !insn->k) ||
	     ((op == BPF_LSH || op == BPF_RSH) && insn->k >= 32)))
		return -EINVAL;
	if (code == (BPF_JMP | BPF_JA))
		return insn->k < left ? 0 : -EINVAL;
	if (BPF_CLASS(code) == BPF_JMP && (insn->jt >= left || insn->jf >= left))
		return -EINVAL;
	return 0;
}

static void mark_successors(struct xlat *x, __u32 i)
{
	const struct sock_filter *insn = &x->filter[i];

	switch (BPF_CLASS(insn->code)) {
	case BPF_RET:
		return;
	case BPF_JMP:
		if (BPF_OP(insn->code) == BPF_JA) {
			x->reachable[i + 1 + insn->k] = true;
			return;
		}
		x->reachable[i + 1 + insn->jt] = true;
		x->reachable[i + 1 + insn->jf] = true;
		return;
	default:
		x->reachable[i + 1] = true;
		return;
	}
}

/* Every jump goes forward, so one pass in order finds what is reachable. */
static int check_filter(struct xlat *x)
{
	__u32 i;
	int ret;

	if (BPF_CLASS(x->filter[x->len - 1].code) != BPF_RET)
		return -EINVAL;
	x->reachable[0] = true;
	for (i = 0; i < x->len; i++) {
		ret = check_insn(&x->filter[i], x->len - i - 1);
		if (ret)
			return ret;
		x->uses_mem |= uses_mem(x->filter[i].code);
		if (x->reachable[i])
			mark_successors(x, i);
	}
	return 0;
}

static struct bpf_insn *ebpf_prog_reserve(struct ebpf_prog *prog, __u32 n)
{
	struct bpf_insn *insns;
	__u32 need, cap;

	if (check_add_overflow(prog->len, n, &need) || need > EBPF_INSNS_MAX)
		return NULL;
	if (need > prog->cap) {
		cap = max(need, 2 * prog->cap);
		insns = xreallocarray(prog->insns, prog->cap, cap,
				      sizeof(*insns));
		if (!insns)
			return NULL;
		prog->insns = insns;
		prog->cap = cap;
	}
	return prog->insns + prog->len;
}

int ebpf_prog_append(struct ebpf_prog *prog, const struct bpf_insn *insns,
		     __u32 n)
{
	struct bpf_insn *dst = ebpf_prog_reserve(prog, n);

	if (!dst)
		return -ENOMEM;
	memcpy(dst, insns, (size_t)n * sizeof(*insns));
	prog->len += n;
	return 0;
}

void ebpf_prog_free(struct ebpf_prog *prog)
{
	xfree(prog->insns, (size_t)prog->cap * sizeof(*prog->insns));
	memset(prog, 0, sizeof(*prog));
}

/* Sizes the translation, then emits it where out has room for it. */
static int xlat_run(struct xlat *x, struct ebpf_prog *out)
{
	int ret;

	ret = check_filter(x);
	if (ret)
		return ret;
	emit_all(x);
	x->size = x->pos;
	x->out = ebpf_prog_reserve(out, x->size);
	if (!x->out)
		return -ENOMEM;
	emit_all(x);
	if (x->err)
		return x->err;
	out->len += x->size;
	return 0;
}

int cbpf_translate(const struct sock_filter *filter, __u32 len,
		   struct ebpf_prog *out)
{
	struct xlat x = { .filter = filter, .len = len };
	int ret;

	if (!len || len > BPF_MAXINSNS)
		return -EINVAL;
	x.start = xcalloc(len, sizeof(*x.start));
	x.reachable = xcalloc(len, sizeof(*x.reachable));
	ret = x.start && x.reachable ? xlat_run(&x, out) : -ENOMEM;
	xfree(x.reachable, len * sizeof(*x.reachable));
	xfree(x.start, len * sizeof(*x.start));
	return ret;
}
