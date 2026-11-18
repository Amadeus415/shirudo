// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>

#include <shirudo/byteorder.h>

#include "tools/shirudo-build/cbpf.h"
#include "tools/shirudo-build/pcap.h"
#include "unit.h"

/*
 * The translation runs on a small eBPF machine, little-endian as every
 * target is, with the packet and the stack at addresses of their own:
 * a read outside the packet is a fault, as the kernel would read
 * whatever lies past an sk_buff's data, and so is a register read before
 * it is written or an instruction no path reaches, which the verifier
 * refuses.
 */
#define PKT_BASE	0x100000000ULL
#define STACK_BASE	0x200000000ULL
#define STACK_SIZE	512
#define STEPS_MAX	100000
#define PKT_MAX		128
#define CORPUS_MAX	4096
#define EBPF_LEN_MAX	16384

struct vm {
	__u64		r[11];
	__u16		init;
	__u8		stack[STACK_SIZE];
	const __u8	*pkt;
	__u32		pkt_len;
	const char	*fault;
};

struct packet {
	__u8	data[PKT_MAX];
	__u32	len;
};

static struct packet corpus[CORPUS_MAX];
static __u32 corpus_len;
static __u64 rng_state = 0x9e3779b97f4a7c15ULL;

static __u64 rng(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

static bool in_range(__u64 off, __u64 size, __u64 len)
{
	return off <= len && size <= len - off;
}

static __u32 be_load(const __u8 *p, __u32 size)
{
	__u32 v = 0, i;

	for (i = 0; i < size; i++)
		v = v << 8 | p[i];
	return v;
}

/* libpcap's bpf_filter(), with M[] zeroed as the translation has it. */
static __u32 cbpf_run(const struct sock_filter *f, __u32 len,
		      const __u8 *pkt, __u32 n)
{
	__u32 a = 0, x = 0, mem[BPF_MEMWORDS] = {}, pc, k, size;
	const struct sock_filter *insn;

	for (pc = 0; pc < len; pc++) {
		insn = &f[pc];
		k = insn->k;
		switch (insn->code) {
		case BPF_RET | BPF_K:
			return k;
		case BPF_RET | BPF_A:
			return a;
		case BPF_LD | BPF_W | BPF_ABS:
		case BPF_LD | BPF_H | BPF_ABS:
		case BPF_LD | BPF_B | BPF_ABS:
			size = BPF_SIZE(insn->code) == BPF_W ? 4 :
			       BPF_SIZE(insn->code) == BPF_H ? 2 : 1;
			if (!in_range(k, size, n))
				return 0;
			a = be_load(pkt + k, size);
			break;
		case BPF_LD | BPF_W | BPF_IND:
		case BPF_LD | BPF_H | BPF_IND:
		case BPF_LD | BPF_B | BPF_IND:
			size = BPF_SIZE(insn->code) == BPF_W ? 4 :
			       BPF_SIZE(insn->code) == BPF_H ? 2 : 1;
			if (!in_range((__u64)x + k, size, n))
				return 0;
			a = be_load(pkt + x + k, size);
			break;
		case BPF_LDX | BPF_B | BPF_MSH:
			if (!in_range(k, 1, n))
				return 0;
			x = (pkt[k] & 0xf) << 2;
			break;
		case BPF_LD | BPF_W | BPF_LEN:
			a = n;
			break;
		case BPF_LDX | BPF_W | BPF_LEN:
			x = n;
			break;
		case BPF_LD | BPF_IMM:
			a = k;
			break;
		case BPF_LDX | BPF_IMM:
			x = k;
			break;
		case BPF_LD | BPF_MEM:
			a = mem[k];
			break;
		case BPF_LDX | BPF_MEM:
			x = mem[k];
			break;
		case BPF_ST:
			mem[k] = a;
			break;
		case BPF_STX:
			mem[k] = x;
			break;
		case BPF_JMP | BPF_JA:
			pc += k;
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
			pc += a == k ? insn->jt : insn->jf;
			break;
		case BPF_JMP | BPF_JGT | BPF_K:
			pc += a > k ? insn->jt : insn->jf;
			break;
		case BPF_JMP | BPF_JGE | BPF_K:
			pc += a >= k ? insn->jt : insn->jf;
			break;
		case BPF_JMP | BPF_JSET | BPF_K:
			pc += a & k ? insn->jt : insn->jf;
			break;
		case BPF_JMP | BPF_JEQ | BPF_X:
			pc += a == x ? insn->jt : insn->jf;
			break;
		case BPF_JMP | BPF_JGT | BPF_X:
			pc += a > x ? insn->jt : insn->jf;
			break;
		case BPF_JMP | BPF_JGE | BPF_X:
			pc += a >= x ? insn->jt : insn->jf;
			break;
		case BPF_JMP | BPF_JSET | BPF_X:
			pc += a & x ? insn->jt : insn->jf;
			break;
		case BPF_ALU | BPF_NEG:
			a = -a;
			break;
		case BPF_MISC | BPF_TAX:
			x = a;
			break;
		case BPF_MISC | BPF_TXA:
			a = x;
			break;
		default:
			if (BPF_CLASS(insn->code) != BPF_ALU)
				return 0;
			if (BPF_SRC(insn->code) == BPF_K)
				k = insn->k;
			else
				k = x;
			switch (BPF_OP(insn->code)) {
			case BPF_ADD:
				a += k;
				break;
			case BPF_SUB:
				a -= k;
				break;
			case BPF_MUL:
				a *= k;
				break;
			case BPF_DIV:
				if (!k)
					return 0;
				a /= k;
				break;
			case BPF_MOD:
				if (!k)
					return 0;
				a %= k;
				break;
			case BPF_AND:
				a &= k;
				break;
			case BPF_OR:
				a |= k;
				break;
			case BPF_XOR:
				a ^= k;
				break;
			case BPF_LSH:
				a = k < 32 ? a << k : 0;
				break;
			case BPF_RSH:
				a = k < 32 ? a >> k : 0;
				break;
			default:
				return 0;
			}
			break;
		}
	}
	return 0;
}

static __u64 vm_reg(struct vm *vm, __u8 reg)
{
	if (reg > BPF_REG_10 || !(vm->init & (1u << reg))) {
		vm->fault = "read of a register not written";
		return 0;
	}
	return vm->r[reg];
}

static void vm_set(struct vm *vm, __u8 reg, __u64 value)
{
	if (reg >= BPF_REG_10) {
		vm->fault = "write of r10";
		return;
	}
	vm->r[reg] = value;
	vm->init |= 1u << reg;
}

static __u8 *vm_stack(struct vm *vm, __u64 addr, __u32 size)
{
	if (addr < STACK_BASE ||
	    !in_range(addr - STACK_BASE, size, STACK_SIZE)) {
		vm->fault = "access outside the stack";
		return NULL;
	}
	return vm->stack + (addr - STACK_BASE);
}

static __u32 mem_size(__u8 code)
{
	switch (BPF_SIZE(code)) {
	case BPF_B:
		return 1;
	case BPF_H:
		return 2;
	case BPF_W:
		return 4;
	default:
		return 8;
	}
}

static __u64 le_load(const __u8 *p, __u32 size)
{
	__u64 v = 0;
	__u32 i;

	for (i = size; i > 0; i--)
		v = v << 8 | p[i - 1];
	return v;
}

static void le_store(__u8 *p, __u32 size, __u64 v)
{
	__u32 i;

	for (i = 0; i < size; i++, v >>= 8)
		p[i] = (__u8)v;
}

static void vm_probe_read(struct vm *vm)
{
	__u64 dst = vm_reg(vm, BPF_REG_1), size = vm_reg(vm, BPF_REG_2);
	__u64 src = vm_reg(vm, BPF_REG_3);
	__u8 *to = vm_stack(vm, dst, (__u32)size);
	__u8 reg;

	if (!to)
		return;
	if (src < PKT_BASE || !in_range(src - PKT_BASE, size, vm->pkt_len)) {
		vm->fault = "read outside the packet";
		return;
	}
	memcpy(to, vm->pkt + (src - PKT_BASE), size);
	vm_set(vm, BPF_REG_0, 0);
	for (reg = BPF_REG_1; reg <= BPF_REG_5; reg++)
		vm->init &= ~(1u << reg);
}

static __u64 alu(struct vm *vm, __u8 op, __u64 dst, __u64 src, bool wide)
{
	__u32 bits = wide ? 64 : 32;

	switch (op) {
	case BPF_ADD:
		return dst + src;
	case BPF_SUB:
		return dst - src;
	case BPF_MUL:
		return dst * src;
	case BPF_DIV:
		return src ? dst / src : 0;
	case BPF_MOD:
		return src ? dst % src : dst;
	case BPF_OR:
		return dst | src;
	case BPF_AND:
		return dst & src;
	case BPF_XOR:
		return dst ^ src;
	case BPF_LSH:
		return src < bits ? dst << src : 0;
	case BPF_RSH:
		return src < bits ? dst >> src : 0;
	case BPF_MOV:
		return src;
	case BPF_NEG:
		return -dst;
	default:
		vm->fault = "unexpected ALU operation";
		return 0;
	}
}

static __u64 bswap(__u64 v, __s32 bits)
{
	__u64 out = 0;
	__s32 i;

	for (i = 0; i < bits / 8; i++, v >>= 8)
		out = out << 8 | (v & 0xff);
	return out;
}

static void vm_alu(struct vm *vm, const struct bpf_insn *insn)
{
	bool wide = BPF_CLASS(insn->code) == BPF_ALU64;
	__u8 op = BPF_OP(insn->code);
	__u64 dst, src, res;

	if (op == BPF_END) {
		if (wide || BPF_SRC(insn->code) != BPF_TO_BE ||
		    (insn->imm != 16 && insn->imm != 32)) {
			vm->fault = "unexpected byte swap";
			return;
		}
		vm_set(vm, insn->dst_reg,
		       bswap(vm_reg(vm, insn->dst_reg), insn->imm));
		return;
	}
	dst = op == BPF_MOV ? 0 : vm_reg(vm, insn->dst_reg);
	if (BPF_SRC(insn->code) == BPF_X)
		src = vm_reg(vm, insn->src_reg);
	else
		src = (__u64)(__s64)insn->imm;
	if (!wide) {
		dst = (__u32)dst;
		src = (__u32)src;
	}
	res = alu(vm, op, dst, src, wide);
	vm_set(vm, insn->dst_reg, wide ? res : (__u32)res);
}

static bool vm_cond(struct vm *vm, const struct bpf_insn *insn)
{
	bool wide = BPF_CLASS(insn->code) == BPF_JMP;
	__u64 dst = vm_reg(vm, insn->dst_reg), src;

	if (BPF_SRC(insn->code) == BPF_X)
		src = vm_reg(vm, insn->src_reg);
	else
		src = (__u64)(__s64)insn->imm;
	if (!wide) {
		dst = (__u32)dst;
		src = (__u32)src;
	}
	switch (BPF_OP(insn->code)) {
	case BPF_JEQ:
		return dst == src;
	case BPF_JNE:
		return dst != src;
	case BPF_JGT:
		return dst > src;
	case BPF_JGE:
		return dst >= src;
	case BPF_JLT:
		return dst < src;
	case BPF_JLE:
		return dst <= src;
	case BPF_JSET:
		return dst & src;
	default:
		vm->fault = "unexpected jump";
		return false;
	}
}

static void vm_mem(struct vm *vm, const struct bpf_insn *insn)
{
	__u32 size = mem_size(insn->code);
	__u8 *p;

	if (BPF_MODE(insn->code) != BPF_MEM) {
		vm->fault = "unexpected memory mode";
		return;
	}
	switch (BPF_CLASS(insn->code)) {
	case BPF_LDX:
		p = vm_stack(vm, vm_reg(vm, insn->src_reg) + insn->off, size);
		if (p)
			vm_set(vm, insn->dst_reg, le_load(p, size));
		break;
	case BPF_STX:
		p = vm_stack(vm, vm_reg(vm, insn->dst_reg) + insn->off, size);
		if (p)
			le_store(p, size, vm_reg(vm, insn->src_reg));
		break;
	default:
		p = vm_stack(vm, vm_reg(vm, insn->dst_reg) + insn->off, size);
		if (p)
			le_store(p, size, (__u64)(__s64)insn->imm);
		break;
	}
}

/* The next pc, or len once the program has exited. */
static __u32 vm_step(struct vm *vm, const struct bpf_insn *insns, __u32 pc,
		     __u32 len)
{
	const struct bpf_insn *insn = &insns[pc];
	__u8 class = BPF_CLASS(insn->code);

	if (class == BPF_ALU || class == BPF_ALU64) {
		vm_alu(vm, insn);
		return pc + 1;
	}
	if (class == BPF_LDX || class == BPF_STX || class == BPF_ST) {
		vm_mem(vm, insn);
		return pc + 1;
	}
	if (class != BPF_JMP && class != BPF_JMP32) {
		vm->fault = "unexpected instruction class";
		return len;
	}
	switch (BPF_OP(insn->code)) {
	case BPF_EXIT:
		vm_reg(vm, BPF_REG_0);
		return len;
	case BPF_CALL:
		if (insn->src_reg || insn->imm != BPF_FUNC_probe_read_kernel)
			vm->fault = "call of another function";
		else
			vm_probe_read(vm);
		return pc + 1;
	case BPF_JA:
		return pc + 1 + insn->off;
	default:
		return vm_cond(vm, insn) ? pc + 1 + insn->off : pc + 1;
	}
}

static __u32 ebpf_run(const struct bpf_insn *insns, __u32 len,
		      const __u8 *pkt, __u32 pkt_len)
{
	struct vm vm = { .pkt = pkt, .pkt_len = pkt_len };
	__u32 pc = 0, steps;

	vm.r[BPF_REG_1] = PKT_BASE;
	vm.r[BPF_REG_2] = PKT_BASE + pkt_len;
	vm.r[BPF_REG_10] = STACK_BASE + STACK_SIZE;
	vm.init = 1u << BPF_REG_1 | 1u << BPF_REG_2 | 1u << BPF_REG_10;
	for (steps = 0; steps < STEPS_MAX && pc < len && !vm.fault; steps++)
		pc = vm_step(&vm, insns, pc, len);
	UNIT_CHECK(1, !vm.fault && pc == len, "eBPF run: %s at %u",
		   vm.fault ?: "no exit", pc);
	return (__u32)vm.r[BPF_REG_0];
}

/* The structure the verifier checks before it runs a path. */
static void ebpf_check_cfg(const struct bpf_insn *insns, __u32 len)
{
	bool seen[EBPF_LEN_MAX] = {};
	__u32 pc, target;
	__u8 class, op;

	ASSERT_TRUE(len > 0 && len <= ARRAY_SIZE(seen));
	seen[0] = true;
	for (pc = 0; pc < len; pc++) {
		if (!seen[pc])
			continue;
		class = BPF_CLASS(insns[pc].code);
		op = BPF_OP(insns[pc].code);
		if (class != BPF_JMP && class != BPF_JMP32) {
			ASSERT_TRUE(pc + 1 < len);
			seen[pc + 1] = true;
			continue;
		}
		if (op == BPF_EXIT)
			continue;
		if (op != BPF_CALL) {
			target = pc + 1 + insns[pc].off;
			ASSERT_TRUE(insns[pc].off >= 0 && target < len);
			seen[target] = true;
		}
		if (op != BPF_JA) {
			ASSERT_TRUE(pc + 1 < len);
			seen[pc + 1] = true;
		}
	}
	for (pc = 0; pc < len; pc++)
		UNIT_CHECK(1, seen[pc], "instruction %u is unreachable", pc);
}

static void check_filter(const struct sock_filter *f, __u32 len, __u32 skip)
{
	struct ebpf_prog prog = {};
	__u32 i, want, got;

	ASSERT_EQ(cbpf_translate(f, len, &prog), 0);
	ebpf_check_cfg(prog.insns, prog.len);
	for (i = 0; i < corpus_len; i++) {
		const struct packet *pkt = &corpus[i];
		const __u8 *data = pkt->data + min(skip, pkt->len);
		__u32 n = pkt->len - min(skip, pkt->len);

		want = cbpf_run(f, len, data, n);
		got = ebpf_run(prog.insns, prog.len, data, n);
		UNIT_CHECK(1, want == got,
			   "packet %u of %u bytes: classic %u, eBPF %u",
			   i, n, want, got);
	}
	ebpf_prog_free(&prog);
}

static __u32 put_eth(__u8 *p, __u16 type)
{
	static const __u8 macs[12] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
	};

	memcpy(p, macs, sizeof(macs));
	put_be16(p + 12, type);
	return 14;
}

static __u32 put_ipv4(__u8 *p, __u8 proto, __u32 ihl, __u16 frag,
		      __u32 payload)
{
	memset(p, 0, ihl * 4);
	p[0] = 0x40 | ihl;
	put_be16(p + 2, (__u16)(ihl * 4 + payload));
	put_be16(p + 6, frag);
	p[8] = 64;
	p[9] = proto;
	put_be32(p + 12, 0x0a000001);
	put_be32(p + 16, 0x0a000002);
	return ihl * 4;
}

static __u32 put_ipv6(__u8 *p, __u8 next, __u32 payload)
{
	memset(p, 0, 40);
	p[0] = 0x60;
	put_be16(p + 4, (__u16)payload);
	p[6] = next;
	p[7] = 64;
	put_be32(p + 8, 0x20010db8);
	p[23] = 1;
	put_be32(p + 24, 0x20010db8);
	p[39] = 2;
	return 40;
}

static __u32 put_l4(__u8 *p, __u8 proto, __u16 sport, __u16 dport,
		    __u8 flags)
{
	static const char get[] = "GET / HTTP/1.1";

	put_be16(p, sport);
	put_be16(p + 2, dport);
	if (proto != IPPROTO_TCP) {
		put_be16(p + 4, 8 + sizeof(get) - 1);
		put_be16(p + 6, 0);
		memcpy(p + 8, get, sizeof(get) - 1);
		return 8 + sizeof(get) - 1;
	}
	memset(p + 4, 0, 16);
	p[12] = 5 << 4;
	p[13] = flags;
	memcpy(p + 20, get, sizeof(get) - 1);
	return 20 + sizeof(get) - 1;
}

static void corpus_add(const __u8 *data, __u32 len)
{
	if (corpus_len < CORPUS_MAX) {
		memcpy(corpus[corpus_len].data, data, len);
		corpus[corpus_len++].len = len;
	}
}

/* A packet, every prefix of it and some of it with bytes changed. */
static void corpus_add_variants(const __u8 *data, __u32 len)
{
	__u8 copy[PKT_MAX];
	__u32 i, j;

	for (i = 0; i <= len; i++)
		corpus_add(data, i);
	for (i = 0; i < 16; i++) {
		memcpy(copy, data, len);
		for (j = 0; j < 3; j++)
			copy[rng() % len] = (__u8)rng();
		corpus_add(copy, len);
	}
}

static void corpus_add_ipv4(__u8 proto, __u32 ihl, __u16 frag, __u16 sport,
			    __u16 dport, __u8 flags, bool vlan)
{
	__u8 p[PKT_MAX] = {};
	__u32 n, l4;

	if (vlan) {
		n = put_eth(p, 0x8100);
		put_be16(p + n, 100);
		put_be16(p + n + 2, 0x0800);
		n += 4;
	} else {
		n = put_eth(p, 0x0800);
	}
	l4 = put_l4(p + n + ihl * 4, proto, sport, dport, flags);
	n += put_ipv4(p + n, proto, ihl, frag, l4);
	corpus_add_variants(p, n + l4);
}

static void corpus_add_ipv6(__u8 proto, __u16 sport, __u16 dport,
			    __u8 flags)
{
	__u8 p[PKT_MAX] = {};
	__u32 n = put_eth(p, 0x86dd), l4;

	l4 = put_l4(p + n + 40, proto, sport, dport, flags);
	n += put_ipv6(p + n, proto, l4);
	corpus_add_variants(p, n + l4);
}

static void corpus_build(void)
{
	__u8 p[PKT_MAX];
	__u32 i, j, n;

	if (corpus_len)
		return;
	corpus_add_ipv4(IPPROTO_TCP, 5, 0, 12345, 80, 0x02, false);
	corpus_add_ipv4(IPPROTO_TCP, 6, 0, 443, 50000, 0x12, false);
	corpus_add_ipv4(IPPROTO_UDP, 5, 0, 5353, 53, 0, false);
	corpus_add_ipv4(IPPROTO_ICMP, 5, 0, 0x0800, 0, 0, false);
	corpus_add_ipv4(IPPROTO_UDP, 5, 0x2001, 1000, 2000, 0, false);
	corpus_add_ipv4(IPPROTO_TCP, 5, 0, 22, 1500, 0x10, true);
	corpus_add_ipv6(IPPROTO_TCP, 50000, 443, 0x12);
	corpus_add_ipv6(IPPROTO_UDP, 53, 5353, 0);
	n = put_eth(p, 0x0806);
	memset(p + n, 0xa5, 28);
	corpus_add_variants(p, n + 28);
	for (i = 0; i < 256; i++) {
		n = rng() % PKT_MAX;
		for (j = 0; j < n; j++)
			p[j] = (__u8)rng();
		if (n > 14 && i % 2)
			put_be16(p + 12, i % 4 == 1 ? 0x0800 : 0x86dd);
		if (n > 15 && i % 2)
			p[14] = i % 4 == 1 ? 0x45 : 0x60;
		corpus_add(p, n);
	}
}

#define S(code, k)		{ code, 0, 0, k }
#define J(code, k, jt, jf)	{ code, jt, jf, k }

static void matches_classic_loads(void)
{
	static const struct sock_filter f[] = {
		S(BPF_LD | BPF_H | BPF_ABS, 12),
		J(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 8),
		S(BPF_LD | BPF_B | BPF_ABS, 23),
		J(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 0, 6),
		S(BPF_LDX | BPF_B | BPF_MSH, 14),
		S(BPF_LD | BPF_H | BPF_IND, 16),
		J(BPF_JMP | BPF_JEQ | BPF_K, 80, 2, 0),
		S(BPF_LD | BPF_W | BPF_IND, 14),
		J(BPF_JMP | BPF_JGT | BPF_K, 0x30000000, 0, 1),
		S(BPF_RET | BPF_K, 0x40000),
		S(BPF_LD | BPF_W | BPF_ABS, 26),
		S(BPF_RET | BPF_A, 0),
	};

	corpus_build();
	check_filter(f, ARRAY_SIZE(f), 0);
}

static void matches_classic_alu(void)
{
	static const __u16 ops[] = {
		BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_MOD, BPF_AND,
		BPF_OR, BPF_XOR, BPF_LSH, BPF_RSH,
	};
	struct sock_filter f[] = {
		S(BPF_LD | BPF_W | BPF_ABS, 14),
		S(BPF_LDX | BPF_B | BPF_MSH, 20),
		S(BPF_ALU | BPF_ADD | BPF_X, 0),
		S(BPF_ALU | BPF_ADD | BPF_K, 7),
		S(BPF_RET | BPF_A, 0),
	};
	size_t i;

	corpus_build();
	for (i = 0; i < ARRAY_SIZE(ops); i++) {
		f[2].code = BPF_ALU | ops[i] | BPF_X;
		f[3].code = BPF_ALU | ops[i] | BPF_K;
		f[3].k = ops[i] == BPF_LSH || ops[i] == BPF_RSH ? 3 : 7;
		check_filter(f, ARRAY_SIZE(f), 0);
	}
}

/* X from a whole byte, so that a shift by it often goes past 31. */
static void matches_classic_shift_by_x(void)
{
	struct sock_filter f[] = {
		S(BPF_LD | BPF_B | BPF_ABS, 15),
		S(BPF_MISC | BPF_TAX, 0),
		S(BPF_LD | BPF_W | BPF_ABS, 16),
		S(BPF_ALU | BPF_LSH | BPF_X, 0),
		S(BPF_ALU | BPF_NEG, 0),
		S(BPF_RET | BPF_A, 0),
	};

	corpus_build();
	check_filter(f, ARRAY_SIZE(f), 0);
	f[3].code = BPF_ALU | BPF_RSH | BPF_X;
	check_filter(f, ARRAY_SIZE(f), 0);
}

static void matches_classic_memory_and_jumps(void)
{
	static const struct sock_filter f[] = {
		S(BPF_LD | BPF_W | BPF_LEN, 0),
		S(BPF_ST, 3),
		S(BPF_LDX | BPF_IMM, 60),
		J(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 7),
		S(BPF_LD | BPF_B | BPF_ABS, 13),
		J(BPF_JMP | BPF_JSET | BPF_K, 0x08, 0, 2),
		S(BPF_LDX | BPF_MEM, 3),
		S(BPF_MISC | BPF_TXA, 0),
		J(BPF_JMP | BPF_JSET | BPF_X, 0, 1, 1),
		S(BPF_JMP | BPF_JA, 1),
		S(BPF_RET | BPF_K, 1),
		S(BPF_LD | BPF_MEM, 15),
		S(BPF_STX, 15),
		S(BPF_RET | BPF_A, 0),
		S(BPF_RET | BPF_K, 2),
	};

	corpus_build();
	check_filter(f, ARRAY_SIZE(f), 0);
}

static void matches_libpcap(void)
{
	static const char *const exprs[] = {
		"", "ip", "ip6", "arp", "tcp", "udp port 53", "icmp",
		"host 10.0.0.1", "src net 10.0.0.0/8 and dst port 80",
		"tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn",
		"ip[2:2] > 40", "len > 60", "less 64", "not port 22",
		"portrange 1000-2000", "ip[6:2] & 0x1fff != 0",
		"ip6 and tcp port 443", "ip6 host 2001:db8::1",
		"vlan 100 and tcp", "ether host 00:11:22:33:44:55",
		"tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420",
		"ip and (ip[2:2] - ((ip[0] & 0xf) << 2) - ((tcp[12] & 0xf0) >> 2)) != 0",
		"udp[8:4] / (ip[1] & 3) == 7 or tcp[4] % (tcp[5] & 1) == 0",
	};
	char msg[PCAP_ERRBUF_SIZE];
	struct pcap_filter filter;
	struct pcap_lib *lib;
	__u32 compiled = 0;
	size_t i;
	int ret;

	if (pcap_lib_open(&lib))
		unit_skip("libpcap is not installed");
	corpus_build();
	for (i = 0; i < ARRAY_SIZE(exprs); i++) {
		ret = pcap_lib_compile(lib, exprs[i], PCAP_DLT_EN10MB, &filter,
				       msg, sizeof(msg));
		UNIT_CHECK(1, !ret, "%s: %s", exprs[i], msg);
		check_filter(filter.insns, filter.len, 0);
		pcap_filter_free(&filter);
		ret = pcap_lib_compile(lib, exprs[i], PCAP_DLT_RAW, &filter,
				       msg, sizeof(msg));
		if (ret)
			continue;
		check_filter(filter.insns, filter.len, 14);
		pcap_filter_free(&filter);
		compiled++;
	}
	EXPECT_GT(compiled, ARRAY_SIZE(exprs) - 4);
	pcap_lib_close(lib);
}

static void refuses_what_the_checker_does(void)
{
	static const struct {
		struct sock_filter	f[3];
		__u32			len;
		int			err;
	} cases[] = {
		{ { S(BPF_LD | BPF_IMM, 1) }, 1, -EINVAL },
		{ { J(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
		    S(BPF_RET | BPF_K, 0) }, 2, -EINVAL },
		{ { S(BPF_JMP | BPF_JA, 1), S(BPF_RET | BPF_K, 0) }, 2, -EINVAL },
		{ { S(BPF_LD | BPF_MEM, BPF_MEMWORDS),
		    S(BPF_RET | BPF_K, 0) }, 2, -EINVAL },
		{ { S(BPF_ALU | BPF_DIV | BPF_K, 0),
		    S(BPF_RET | BPF_K, 0) }, 2, -EINVAL },
		{ { S(BPF_ALU | BPF_LSH | BPF_K, 32),
		    S(BPF_RET | BPF_K, 0) }, 2, -EINVAL },
		{ { S(BPF_RET | BPF_X, 0) }, 1, -EINVAL },
		{ { S(BPF_LD | BPF_W | BPF_ABS,
		      (__u32)(SKF_AD_OFF + SKF_AD_PROTOCOL)),
		    S(BPF_RET | BPF_A, 0) }, 2, -EOPNOTSUPP },
		{ { S(BPF_LDX | BPF_B | BPF_MSH, (__u32)SKF_NET_OFF),
		    S(BPF_RET | BPF_K, 0) }, 2, -EOPNOTSUPP },
	};
	struct ebpf_prog prog = {};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		UNIT_CHECK(0, cbpf_translate(cases[i].f, cases[i].len, &prog) ==
			   cases[i].err, "case %zu", i);
		EXPECT_EQ(prog.len, 0);
	}
	EXPECT_EQ(cbpf_translate(cases[0].f, 0, &prog), -EINVAL);
	ebpf_prog_free(&prog);
}

static void appends_after_what_is_there(void)
{
	static const struct sock_filter f[] = {
		S(BPF_LD | BPF_B | BPF_ABS, 0),
		S(BPF_RET | BPF_A, 0),
	};
	static const struct bpf_insn lead[2] = {
		{ .code = BPF_ALU | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	static const __u8 pkt[] = { 0x7f };
	struct ebpf_prog prog = {};

	ASSERT_EQ(ebpf_prog_append(&prog, lead, ARRAY_SIZE(lead)), 0);
	ASSERT_EQ(cbpf_translate(f, ARRAY_SIZE(f), &prog), 0);
	ASSERT_TRUE(prog.len > ARRAY_SIZE(lead));
	EXPECT_MEMEQ(prog.insns, lead, sizeof(lead));
	EXPECT_EQ(ebpf_run(prog.insns + 2, prog.len - 2, pkt, sizeof(pkt)),
		  0x7f);
	EXPECT_EQ(ebpf_run(prog.insns + 2, prog.len - 2, pkt, 0), 0);
	ebpf_prog_free(&prog);
}

static const struct unit_case cases[] = {
	UNIT_CASE(matches_classic_loads),
	UNIT_CASE(matches_classic_alu),
	UNIT_CASE(matches_classic_shift_by_x),
	UNIT_CASE(matches_classic_memory_and_jumps),
	UNIT_CASE(matches_libpcap),
	UNIT_CASE(refuses_what_the_checker_does),
	UNIT_CASE(appends_after_what_is_there),
	{}
};

UNIT_SUITE(cbpf, cases);
