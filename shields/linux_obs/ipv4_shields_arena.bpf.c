// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
/* Build-time IPv4 destination shield trie and counter serializer. */

#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "shirudo_decoder.h"
#include "shirudo_serializer.h"

#if !defined(__BPF_FEATURE_ADDR_SPACE_CAST)
#error "BPF arena access requires clang address-space cast support"
#endif

#define __arena __attribute__((address_space(1))) \
		__attribute__((btf_type_tag("arena")))
#define NUMA_NO_NODE (-1)
#define EINVAL 22
#define EACCES 13
#define ENOSPC 28
#define ENOMEM 12

#define IPV4_SHIELDS_SERIAL_RECORD_SIZE 16
#define IPV4_SHIELDS_SERIAL_PAGE_BYTES \
	(IPV4_SHIELDS_SERIAL_RECORD_SIZE * 2)
#define IPV4_SHIELDS_MAX_CPU_SCAN 8192

#ifndef LINUX_OBS_COMBINED
char _license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 4096);
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	enum { ipv4_shields_map_extra = 1ULL << 32 } map_extra;
#else
	enum { ipv4_shields_map_extra = 1ULL << 44 } map_extra;
#endif
} ipv4_shields SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");
#endif

struct ipv4_shields_node {
	__u16 child[256];
	__u8 terminal;
	__u8 reserved;
};

#include "ipv4_shields_generated.h"

struct ipv4_shields_state {
	__u32 ready;
	__u32 node_count;
	struct ipv4_shields_node nodes[IPV4_SHIELDS_NODE_COUNT];
};

struct ipv4_shields_counter {
	__u64 allowed_pkts;
	__u64 denied_pkts;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ipv4_shields_counter);
} obs_i_v4cnt SEC(".maps");

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr,
				    __u32 page_cnt, int node_id,
				    __u64 flags) __ksym __weak;
void bpf_arena_free_pages(void *map, void __arena *ptr,
				  __u32 page_cnt) __ksym __weak;

static struct ipv4_shields_state __arena *ipv4_shields_state;

enum {
	IPV4_SHIELDS_STATE_PAGES =
		(sizeof(struct ipv4_shields_state) + 4095) / 4096,
};

SEC("syscall")
int shirudo_test__ipv4_shields(void *ctx)
{
	struct ipv4_shields_state __arena *state, *old;
	int rc;

	(void)ctx;
	if (ipv4_shields_state)
		return 0;

	state = bpf_arena_alloc_pages(&ipv4_shields, 0,
					     IPV4_SHIELDS_STATE_PAGES,
					     NUMA_NO_NODE, 0);
	if (!state)
		return -ENOMEM;
	state->ready = 0;
	state->node_count = IPV4_SHIELDS_NODE_COUNT;
	IPV4_SHIELDS_COPY_NODES(state);
	rc = 0;
	if (rc < 0) {
		bpf_arena_free_pages(&ipv4_shields, state,
				     IPV4_SHIELDS_STATE_PAGES);
		return rc;
	}
	state->ready = 1;
	old = __sync_val_compare_and_swap(&ipv4_shields_state, 0, state);
	if (old) {
		bpf_arena_free_pages(&ipv4_shields, state,
				     IPV4_SHIELDS_STATE_PAGES);
	}
	return 0;
}

static __always_inline void ipv4_shields_count(bool denied)
{
	struct ipv4_shields_counter *counter;
	__u32 key = 0;

	counter = bpf_map_lookup_elem(&obs_i_v4cnt, &key);
	if (!counter)
		return;
	if (denied)
		__sync_fetch_and_add(&counter->denied_pkts, 1);
	else
		__sync_fetch_and_add(&counter->allowed_pkts, 1);
}

static __always_inline bool ipv4_shields_lookup(__u32 addr4)
{
	struct ipv4_shields_state __arena *state = ipv4_shields_state;
	struct ipv4_shields_node __arena *node;
	__u32 node_index = 0;
	__u32 address = bpf_ntohl(addr4);
	int depth;

	/* Fail closed if the signed load-time initialization did not run. */
	if (!state || !state->ready || state->node_count == 0)
		return true;

	if (node_index >= state->node_count)
		return true;
	node = &state->nodes[node_index];
	if (node->terminal)
		return true;

#pragma clang loop unroll(disable)
	for (depth = 0; depth < 4; depth++) {
		__u32 octet = (address >> (24 - depth * 8)) & 0xff;
		__u16 child = node->child[octet];

		if (!child)
			return false;
		node_index = (__u32)child - 1;
		if (node_index >= state->node_count)
			return true;
		node = &state->nodes[node_index];
		if (node->terminal)
			return true;
	}
	return false;
}

static __always_inline int ipv4_shields_enforce(__u32 addr4)
{
	bool denied = ipv4_shields_lookup(addr4);

	ipv4_shields_count(denied);
	return denied ? -EACCES : 0;
}

const struct shirudo_decoder_manifest ipv4_shields_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_METRIC,
	.upatch = "linux-observability",
	.map = "ipv4_shields",
	.source = "decoders/ipv4_shields.lua",
	.entrypoint = "decode",
};

static __always_inline void ipv4_shields_serial_error(
	struct shirudo_serialize_ctx *ctx, int status)
{
	struct shirudo_serial_chunk *chunk;
	__u32 key = 0;

	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return;
	chunk->magic = SHIRUDO_SERIAL_MAGIC;
	chunk->version = SHIRUDO_SERIAL_VERSION;
	chunk->flags = SHIRUDO_SERIAL_F_DONE;
	chunk->status = status;
	chunk->chunk_index = 0;
	chunk->total_chunks = 1;
	chunk->bytes_total = 0;
	chunk->bytes_in_chunk = 0;
	chunk->page_index = ctx ? ctx->page_index : 0;
	chunk->reserved = 0;
	chunk->cursor = ctx ? ctx->cursor : 0;
	chunk->next_cursor = chunk->cursor;
	chunk->invocation_id = ctx ? ctx->invocation_id : 0;
}

struct ipv4_shields_sum_ctx {
	__u64 allowed_pkts;
	__u64 denied_pkts;
};

static int ipv4_shields_sum_cpu_cb(__u32 cpu, void *data)
{
	struct ipv4_shields_sum_ctx *sum = data;
	struct ipv4_shields_counter *counter;
	__u32 key = 0;

	if (!sum)
		return 1;
	counter = bpf_map_lookup_percpu_elem(&obs_i_v4cnt, &key, cpu);
	if (counter) {
		sum->allowed_pkts += counter->allowed_pkts;
		sum->denied_pkts += counter->denied_pkts;
	}
	return 0;
}

SEC("syscall")
int shirudo_serialize__ipv4_shields(
	struct shirudo_serialize_ctx *ctx)
{
	struct ipv4_shields_sum_ctx sum = {};
	struct shirudo_serial_chunk *chunk;
	__u32 key = 0;
	int rc;

	if (!ctx || ctx->magic != SHIRUDO_SERIAL_MAGIC ||
	    ctx->version != SHIRUDO_SERIAL_VERSION || ctx->max_chunks < 1 ||
	    ctx->chunk_payload_size != SHIRUDO_SERIAL_CHUNK_PAYLOAD ||
	    ctx->page_index != 0 || ctx->cursor != 0 ||
	    ctx->invocation_id == 0) {
		ipv4_shields_serial_error(ctx, -EINVAL);
		return -EINVAL;
	}

	rc = bpf_loop(IPV4_SHIELDS_MAX_CPU_SCAN, ipv4_shields_sum_cpu_cb,
		      &sum, 0);
	if (rc < 0) {
		ipv4_shields_serial_error(ctx, rc);
		return rc;
	}
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk) {
		ipv4_shields_serial_error(ctx, -ENOSPC);
		return -ENOSPC;
	}
	/* Slot zero is reserved for the serializer page header. */
	*(__u64 *)&chunk->data[IPV4_SHIELDS_SERIAL_RECORD_SIZE] =
		sum.allowed_pkts;
	*(__u64 *)&chunk->data[IPV4_SHIELDS_SERIAL_RECORD_SIZE + 8] =
		sum.denied_pkts;
	chunk->magic = SHIRUDO_SERIAL_MAGIC;
	chunk->version = SHIRUDO_SERIAL_VERSION;
	chunk->flags = SHIRUDO_SERIAL_F_DONE;
	chunk->status = 0;
	chunk->chunk_index = 0;
	chunk->total_chunks = 1;
	chunk->bytes_total = IPV4_SHIELDS_SERIAL_PAGE_BYTES;
	chunk->bytes_in_chunk = IPV4_SHIELDS_SERIAL_PAGE_BYTES;
	chunk->page_index = 0;
	chunk->reserved = 0;
	chunk->cursor = 0;
	chunk->next_cursor = 1;
	chunk->invocation_id = ctx->invocation_id;
	return 0;
}
