/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * On-disk .upatch container layout. Little-endian throughout.
 */

#ifndef SHIRUDO_UPATCH_H
#define SHIRUDO_UPATCH_H

#include <stdint.h>

#define SHIRUDO_UPATCH_MAGIC		0x53485244554e4150ULL	/* "SHRDUNAP" */
/*
 * The PKCS#7 signature covers insns || data (the gen_loader metadata
 * blob), verified by the kernel at load time; payload_sha256 is SHA-256
 * of that same concatenation. See Documentation/bpf/signing.rst and
 * PLAN.md "signed loader scheme".
 */
#define SHIRUDO_UPATCH_VERSION		1u

/* Flag bits in struct shirudo_upatch_header.flags. */
#define SHIRUDO_DIRECTIVE_UNLOAD	(1u << 0)

#define SHIRUDO_UPATCH_NAME_MAX		256
#define SHIRUDO_UPATCH_PAYLOAD_HASH_LEN	32	/* SHA-256 */

struct shirudo_upatch_header {
	uint64_t	magic;			/* SHIRUDO_UPATCH_MAGIC */
	uint32_t	version;		/* SHIRUDO_UPATCH_VERSION */
	uint32_t	flags;			/* SHIRUDO_DIRECTIVE_* */
	char		name[SHIRUDO_UPATCH_NAME_MAX];
	/*
	 * SHA-256 of the signed content, insns || data. Distinct from the
	 * loader's excl_prog_hash (SHA-256 of insns alone), which the target
	 * recomputes at load. This is the value recorded as the pin xattr,
	 * the TPM chain event, and the unload match target.
	 */
	uint8_t		payload_sha256[SHIRUDO_UPATCH_PAYLOAD_HASH_LEN];
	uint32_t	loader_insns_off;	/* file offset */
	uint32_t	loader_insns_len;
	uint32_t	signature_off;
	uint32_t	signature_len;
	uint32_t	metadata_off;
	uint32_t	metadata_len;
	uint32_t	data_off;		/* gen_loader_opts.data */
	uint32_t	data_len;
	uint32_t	log_buf_sz;		/* verifier-log buf size */
	uint32_t	nr_maps;		/* loader ctx bpf_map_desc count */
	uint32_t	nr_progs;		/* loader ctx bpf_prog_desc count */
	uint32_t	extra_off;		/* offset of the extras blob, 0 = none */
};

/*
 * Optional trailing "extras" blob at header.extra_off (0 = absent).
 * Carries the BPF program's **C source** so `shirudo upatch info` can
 * print the full source without loading. (The kernel never receives the
 * source, so the on-target `shirudo upatch get` instead resolves the
 * loaded program's line_info against the kernel BTF.) Additive and
 * backward-compatible: this offset was the old `reserved` field (0 in
 * older files), and the blob trails every signature-covered section, so
 * a reader that predates it ignores both. It is NOT signature-covered --
 * informational only; tampering mis-renders a pre-load source dump but
 * cannot affect the loaded, hash-verified program.
 *
 * Only the top-level source file passed to `shirudo build` is embedded
 * (a `.bpf.c`); included headers (vmlinux.h, etc.) are not, and a
 * pre-compiled `.bpf.o` input has no source to embed (extras absent).
 */
#define SHIRUDO_UPATCH_EXTRAS_MAGIC	0x52545853u	/* "SXTR" le */
#define SHIRUDO_UPATCH_EXTRAS_SOURCE	1u		/* format: embedded source */

struct shirudo_upatch_extras {
	uint32_t	magic;		/* SHIRUDO_UPATCH_EXTRAS_MAGIC */
	uint32_t	format;		/* SHIRUDO_UPATCH_EXTRAS_SOURCE */
	uint32_t	name_len;	/* source path length (bytes, no NUL) */
	uint32_t	source_len;	/* source text length (bytes, no NUL) */
	/*
	 * Then: name_len bytes of source path, then source_len bytes of
	 * source text (neither NUL-terminated on disk).
	 */
};

/*
 * Optional metadata format for LOAD upatches. This tells the target how
 * each program should be attached after the signed loader has created it.
 * Programs without a special attach kind use RAW_TRACEPOINT, preserving
 * the original attach_btf_id behavior.
 *
 * Metadata is not signature-covered in the v1 upatch format. The program
 * bytes are still hash-locked by the signed loader; this blob is attach
 * policy for the target to validate before creating links.
 */
#define SHIRUDO_UPATCH_ATTACH_TARGET_MAX	128u
#define SHIRUDO_UPATCH_PROG_MAGIC	0x4d475055u	/* "UPGM" le */
#define SHIRUDO_UPATCH_PROG_VERSION	1u
#define SHIRUDO_UPATCH_PROG_MAP_MAX	16u		/* BPF_OBJ_NAME_LEN */

enum shirudo_upatch_attach_kind {
	SHIRUDO_UPATCH_ATTACH_RAW_TRACEPOINT = 0,
	SHIRUDO_UPATCH_ATTACH_KPROBE = 1,
	SHIRUDO_UPATCH_ATTACH_KRETPROBE = 2,
	SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_INGRESS = 3,
	SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_EGRESS = 4,
	SHIRUDO_UPATCH_ATTACH_FMOD_RET = 5,
};

enum shirudo_upatch_prog_role {
	SHIRUDO_UPATCH_PROG_ROLE_ATTACH = 0,
	SHIRUDO_UPATCH_PROG_ROLE_SERIALIZER = 1,
};

struct shirudo_upatch_prog_entry {
	uint32_t	role;		/* enum shirudo_upatch_prog_role */
	uint32_t	kind;		/* enum shirudo_upatch_attach_kind */
	uint64_t	offset;		/* kprobe offset; zero for kretprobe */
	char		target[SHIRUDO_UPATCH_ATTACH_TARGET_MAX]; /* kprobe symbol */
	char		map[SHIRUDO_UPATCH_PROG_MAP_MAX];
};

struct shirudo_upatch_prog_metadata {
	uint32_t	magic;		/* SHIRUDO_UPATCH_PROG_MAGIC */
	uint32_t	version;		/* SHIRUDO_UPATCH_PROG_VERSION */
	uint32_t	nr_progs;
	uint32_t	reserved;
	/*
	 * Then: nr_progs struct shirudo_upatch_prog_entry entries in
	 * libbpf/gen_loader program iteration order.
	 */
	struct shirudo_upatch_prog_entry progs[];
};

#endif /* SHIRUDO_UPATCH_H */
