// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
/*
 * udp_arena.bpf.c -- track UDP remote IPs by executable uid.
 *
 * On socket_sendmsg, read the current task executable identity from the
 * shared task storage map and add or update a udp_arena entry keyed by
 * { executable uid, destination IP }. The destination port is retained as
 * metadata, but is not part of the key.
 */

#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "shirudo_serializer.h"

#if !defined(__BPF_FEATURE_ADDR_SPACE_CAST)
#error "BPF arena access requires clang address-space cast support"
#endif

#define __arena		__attribute__((address_space(1))) \
			__attribute__((btf_type_tag("arena")))
#define NUMA_NO_NODE	(-1)

#include "exec_uid_common.h"

#define E2BIG			7
#define EINVAL			22
#define ENOSPC			28

#define AF_INET			2
#define AF_INET6		10
#define SOCK_TYPE_MASK		0xf

#define UDP_BUCKETS		512
#define UDP_MAX_LOOKUP_STEPS	2
#define UDP_MAX_IPS		4096
#define UDP_SERIAL_MAGIC	0x49504455u /* "UDPI" little-endian */
#define UDP_SERIAL_VERSION	1
#define UDP_SERIAL_RECORD_PRESENT	(1u << 0)

#ifndef LINUX_OBS_COMBINED
char _license[] SEC("license") = "Dual BSD/GPL";
#endif

struct udp_ip_key {
	__u8 family;
	__u8 _pad0;
	__u16 _pad1;
	__u32 addr4;		/* network order */
	__u32 addr6[4];		/* network order */
};

struct udp_key {
	struct exec_uid uid;
	struct udp_ip_key ip;
};

struct udp_stats {
	__u64 send_count;
	__u64 last_send_ns;
	__u16 last_port;	/* host order */
	__u16 _pad0;
	__u32 _pad1;
};

struct udp_entry {
	__u32 next_idx;
	__u16 bucket_idx;
	__u8 used;
	__u8 _pad0;
	__u32 pending;
	struct udp_key key;
	struct udp_stats stats;
};

struct udp_bucket {
	__u32 head_idx;
	__u32 _pad;
};

struct udp_arena_state {
	__u32 next_slot;
	__u32 _pad;
	struct udp_bucket buckets[UDP_BUCKETS];
	struct udp_entry entries[UDP_MAX_IPS + 1];
};

static __always_inline void udp_pending_set(__u32 __arena *pending)
{
	__u32 old = *pending;

	if (!(old & 1u))
		(void)__sync_val_compare_and_swap(pending, old, old | 1u);
}

static __always_inline bool udp_pending_take(__u32 __arena *pending)
{
	__u32 old = *pending;

	if (!(old & 1u))
		return false;
	return __sync_val_compare_and_swap(pending, old, old & ~1u) == old;
}

struct udp_serial_header {
	__u32 magic;
	__u16 version;
	__u16 header_size;
	__u16 bucket_count;
	__u16 max_lookup_steps;
	__u16 record_size;
	__u16 record_count;
	__u32 flags;
	__u32 key_size;
	__u32 value_size;
	__u32 ip_key_size;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
	__u64 reserved4;
	__u64 reserved5;
	__u64 reserved6;
	__u64 reserved7;
	__u64 reserved8;
};

struct udp_serial_record {
	__u32 index;
	__u16 bucket;
	__u8 flags;
	__u8 family;
	__u16 last_port;
	__u16 _pad0;
	__u32 uid_dev;
	__u64 uid_ino;
	__u32 addr4;
	__u32 addr6[4];
	__u32 _pad1;
	__u64 send_count;
	__u64 last_send_ns;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
	__u64 reserved4;
};

enum {
	UDP_STATE_PAGES =
		(sizeof(struct udp_arena_state) + 4095) / 4096,
	UDP_SERIAL_RECORDS = UDP_MAX_IPS,
	UDP_SERIAL_RECORD_SLOTS = UDP_SERIAL_RECORDS,
	UDP_SERIAL_SLOT_SIZE = sizeof(struct udp_serial_record),
	UDP_SERIAL_HEADER_SIZE = sizeof(struct udp_serial_header),
	UDP_SERIAL_SLOTS = UDP_SERIAL_RECORD_SLOTS + 1,
	UDP_SERIAL_SLOTS_PER_CHUNK =
		SHIRUDO_SERIAL_CHUNK_PAYLOAD / UDP_SERIAL_SLOT_SIZE,
	UDP_SERIAL_SLOTS_PER_PAGE = 32,
	UDP_SERIAL_PAGE_BYTES =
		UDP_SERIAL_SLOTS_PER_PAGE * UDP_SERIAL_SLOT_SIZE,
	UDP_SERIAL_PAGE_CHUNKS = 1,
};

_Static_assert((UDP_BUCKETS & (UDP_BUCKETS - 1)) == 0,
	       "udp buckets must be a power of two");
_Static_assert(sizeof(struct udp_serial_header) == UDP_SERIAL_SLOT_SIZE,
	       "udp serializer header must occupy one slot");
_Static_assert(UDP_SERIAL_RECORDS <= 0xffff,
	       "udp serializer record count must fit header");
_Static_assert(UDP_SERIAL_SLOTS_PER_CHUNK >= UDP_SERIAL_SLOTS_PER_PAGE,
	       "udp serializer page must fit one chunk");
_Static_assert(UDP_SERIAL_PAGE_BYTES <= SHIRUDO_SERIAL_CHUNK_PAYLOAD,
	       "udp serializer page must fit chunk payload");

#ifndef LINUX_OBS_COMBINED
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 4096); /* pages */
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	enum { udp_map_extra = 1ULL << 32 } map_extra;
#else
	enum { udp_map_extra = 1ULL << 44 } map_extra;
#endif
} udp_arena SEC(".maps");
#endif

#ifndef LINUX_OBS_COMBINED
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, UDP_SERIAL_PAGE_CHUNKS);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");
#endif

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr,
				    __u32 page_cnt, int node_id,
				    __u64 flags) __ksym __weak;
void bpf_arena_free_pages(void *map, void __arena *ptr,
			  __u32 page_cnt) __ksym __weak;

static struct udp_arena_state __arena *udp_state;

static __always_inline bool udp_ip_equal_arena(
	const struct udp_ip_key __arena *a, const struct udp_ip_key *b)
{
	if (a->family != b->family || a->addr4 != b->addr4)
		return false;
	if (a->addr6[0] != b->addr6[0] || a->addr6[1] != b->addr6[1] ||
	    a->addr6[2] != b->addr6[2] || a->addr6[3] != b->addr6[3])
		return false;
	return true;
}

static __always_inline bool udp_key_equal_arena(
	const struct udp_key __arena *a, const struct udp_key *b)
{
	if (!exec_uid_equal_arena(&a->uid, &b->uid))
		return false;
	return udp_ip_equal_arena(&a->ip, &b->ip);
}

static __always_inline __u64 udp_hash_mix(__u64 h, __u64 v)
{
	h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	return h;
}

static __always_inline __u32 udp_hash(const struct udp_key *key)
{
	__u64 h = exec_uid_hash_mix(0, &key->uid);

	h = udp_hash_mix(h, key->ip.family);
	h = udp_hash_mix(h, key->ip.addr4);
	h = udp_hash_mix(h, key->ip.addr6[0]);
	h = udp_hash_mix(h, key->ip.addr6[1]);
	h = udp_hash_mix(h, key->ip.addr6[2]);
	h = udp_hash_mix(h, key->ip.addr6[3]);
	return (__u32)h;
}

static __always_inline struct udp_arena_state __arena *udp_table_init(void)
{
	struct udp_arena_state __arena *state, *old;

	state = udp_state;
	if (state)
		return state;

	state = bpf_arena_alloc_pages(&udp_arena, 0, UDP_STATE_PAGES,
				      NUMA_NO_NODE, 0);
	if (!state)
		return 0;

	state->next_slot = 1;
	state->_pad = 0;
	old = __sync_val_compare_and_swap(&udp_state, 0, state);
	if (old) {
		bpf_arena_free_pages(&udp_arena, state, UDP_STATE_PAGES);
		return old;
	}

	return state;
}

static __always_inline struct udp_entry __arena *
udp_entry_by_index(struct udp_arena_state __arena *state, __u32 idx)
{
	if (!state || idx == 0 || idx > UDP_MAX_IPS)
		return 0;
	return &state->entries[idx];
}

static __always_inline struct udp_entry __arena *
udp_table_lookup(struct udp_arena_state __arena *state,
		 struct udp_bucket __arena *bucket,
		 const struct udp_key *key)
{
	struct udp_entry __arena *entry;
	__u32 idx;
	int i;

	idx = bucket->head_idx;

#pragma clang loop unroll(disable)
	for (i = 0; i < UDP_MAX_LOOKUP_STEPS; i++) {
		if (idx == 0 || idx > UDP_MAX_IPS)
			break;

		entry = &state->entries[idx];
		if (entry->used && udp_key_equal_arena(&entry->key, key))
			return entry;
		idx = entry->next_idx;
	}

	return 0;
}

static __always_inline __u32
udp_entry_alloc(struct udp_arena_state __arena *state, __u16 bucket_idx,
		const struct udp_key *key, __u16 port, __u64 now)
{
	struct udp_entry __arena *entry;
	__u32 idx;

	idx = __sync_fetch_and_add(&state->next_slot, 1);
	if (idx == 0 || idx > UDP_MAX_IPS)
		return 0;

	entry = &state->entries[idx];
	entry->next_idx = 0;
	entry->bucket_idx = bucket_idx;
	entry->used = 0;
	entry->_pad0 = 0;
	entry->pending = 1;
	entry->key.uid.ino = key->uid.ino;
	entry->key.uid.dev = key->uid.dev;
	entry->key.uid._pad = 0;
	entry->key.ip.family = key->ip.family;
	entry->key.ip._pad0 = 0;
	entry->key.ip._pad1 = 0;
	entry->key.ip.addr4 = key->ip.addr4;
	entry->key.ip.addr6[0] = key->ip.addr6[0];
	entry->key.ip.addr6[1] = key->ip.addr6[1];
	entry->key.ip.addr6[2] = key->ip.addr6[2];
	entry->key.ip.addr6[3] = key->ip.addr6[3];
	entry->stats.send_count = 1;
	entry->stats.last_send_ns = now;
	entry->stats.last_port = port;
	entry->stats._pad0 = 0;
	entry->stats._pad1 = 0;
	udp_pending_set(&entry->pending);

	return idx;
}

static __always_inline void udp_entry_touch(struct udp_entry __arena *entry,
					    __u16 port, __u64 now)
{
	__sync_fetch_and_add(&entry->stats.send_count, 1);
	entry->stats.last_send_ns = now;
	entry->stats.last_port = port;
	udp_pending_set(&entry->pending);
}

static __always_inline void udp_table_touch(const struct exec_uid *uid,
					    const struct udp_ip_key *ip,
					    __u16 port, __u64 now)
{
	struct udp_arena_state __arena *state;
	struct udp_bucket __arena *bucket;
	struct udp_entry __arena *entry, *new_entry;
	struct udp_key key = {};
	__u32 hash, idx, new_idx, old_head, prev;

	if (!uid || !ip)
		return;

	state = udp_table_init();
	if (!state)
		return;

	key.uid = *uid;
	key.ip = *ip;
	hash = udp_hash(&key);
	idx = hash & (UDP_BUCKETS - 1);
	bucket = &state->buckets[idx];

	entry = udp_table_lookup(state, bucket, &key);
	if (entry) {
		udp_entry_touch(entry, port, now);
		return;
	}

	new_idx = udp_entry_alloc(state, idx, &key, port, now);
	if (!new_idx)
		return;

	new_entry = udp_entry_by_index(state, new_idx);
	if (!new_entry)
		return;

	old_head = bucket->head_idx;
	new_entry->next_idx = old_head;
	prev = __sync_val_compare_and_swap(&bucket->head_idx, old_head,
					   new_idx);
	if (prev == old_head) {
		new_entry->used = 1;
		return;
	}

	new_entry->used = 0;
}

static __always_inline bool udp_ip_from_sockaddr(struct sockaddr *addr,
						 int addrlen,
						 struct udp_ip_key *ip,
						 __u16 *port)
{
	struct sockaddr_in sin = {};
	struct sockaddr_in6 sin6 = {};
	__u16 family = 0;

	if (!addr || addrlen < (int)sizeof(struct sockaddr))
		return false;
	if (bpf_probe_read_kernel(&family, sizeof(family), &addr->sa_family))
		return false;

	if (family == AF_INET) {
		if (addrlen < (int)sizeof(sin))
			return false;
		if (bpf_probe_read_kernel(&sin, sizeof(sin), addr))
			return false;

		__builtin_memset(ip, 0, sizeof(*ip));
		ip->family = AF_INET;
		ip->addr4 = sin.sin_addr.s_addr;
		*port = bpf_ntohs(sin.sin_port);
		return true;
	}

	if (family == AF_INET6) {
		if (addrlen < (int)sizeof(sin6))
			return false;
		if (bpf_probe_read_kernel(&sin6, sizeof(sin6), addr))
			return false;

		__builtin_memset(ip, 0, sizeof(*ip));
		ip->family = AF_INET6;
		ip->addr6[0] = sin6.sin6_addr.in6_u.u6_addr32[0];
		ip->addr6[1] = sin6.sin6_addr.in6_u.u6_addr32[1];
		ip->addr6[2] = sin6.sin6_addr.in6_u.u6_addr32[2];
		ip->addr6[3] = sin6.sin6_addr.in6_u.u6_addr32[3];
		*port = bpf_ntohs(sin6.sin6_port);
		return true;
	}

	return false;
}

static __always_inline bool udp_ip_from_connected_sock(struct sock *sk,
						       struct udp_ip_key *ip,
						       __u16 *port)
{
	__u16 family;
	__be16 dport;

	if (!sk)
		return false;

	family = sk->__sk_common.skc_family;
	dport = sk->__sk_common.skc_dport;
	if (!dport)
		return false;

	if (family == AF_INET) {
		__builtin_memset(ip, 0, sizeof(*ip));
		ip->family = AF_INET;
		ip->addr4 = sk->__sk_common.skc_daddr;
		*port = bpf_ntohs(dport);
		return ip->addr4 != 0;
	}

	if (family == AF_INET6) {
		__builtin_memset(ip, 0, sizeof(*ip));
		ip->family = AF_INET6;
		ip->addr6[0] = sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0];
		ip->addr6[1] = sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[1];
		ip->addr6[2] = sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2];
		ip->addr6[3] = sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[3];
		*port = bpf_ntohs(dport);
		return ip->addr6[0] || ip->addr6[1] ||
		       ip->addr6[2] || ip->addr6[3];
	}

	return false;
}

static __always_inline void serial_set_error(struct shirudo_serialize_ctx *ctx,
					     int status)
{
	struct shirudo_serial_chunk *chunk;
	__u32 key = 0;
	__u32 page_index = ctx ? ctx->page_index : 0;
	__u64 cursor = ctx ? ctx->cursor : 0;

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
	chunk->page_index = page_index;
	chunk->reserved = 0;
	chunk->cursor = cursor;
	chunk->next_cursor = cursor;
	chunk->invocation_id = ctx ? ctx->invocation_id : 0;
}

static __always_inline int serial_init_page_chunk(__u32 slots, __u32 flags,
						  __u32 page_index,
						  __u64 cursor,
						  __u64 next_cursor,
						  __u64 invocation_id)
{
	struct shirudo_serial_chunk *chunk;
	__u32 key = 0;
	__u32 page_bytes;

	if (slots > UDP_SERIAL_SLOTS_PER_PAGE)
		return -ENOSPC;

	page_bytes = slots * UDP_SERIAL_SLOT_SIZE;
	if (page_bytes > SHIRUDO_SERIAL_CHUNK_PAYLOAD)
		return -ENOSPC;

	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return -ENOSPC;

	chunk->magic = SHIRUDO_SERIAL_MAGIC;
	chunk->version = SHIRUDO_SERIAL_VERSION;
	chunk->flags = flags;
	chunk->status = 0;
	chunk->chunk_index = 0;
	chunk->total_chunks = 1;
	chunk->bytes_total = page_bytes;
	chunk->bytes_in_chunk = page_bytes;
	chunk->page_index = page_index;
	chunk->reserved = 0;
	chunk->cursor = cursor;
	chunk->next_cursor = next_cursor;
	chunk->invocation_id = invocation_id;

	return 0;
}

static __always_inline struct shirudo_serial_chunk *
serial_chunk_for_slot(__u32 page_slot, __u32 *off_out)
{
	struct shirudo_serial_chunk *chunk;
	__u32 key = 0;
	__u32 off;

	barrier_var(page_slot);
	if (page_slot >= UDP_SERIAL_SLOTS_PER_PAGE)
		return 0;

	off = page_slot * UDP_SERIAL_SLOT_SIZE;
	barrier_var(off);
	if (off > SHIRUDO_SERIAL_CHUNK_PAYLOAD - UDP_SERIAL_SLOT_SIZE)
		return 0;

	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return 0;

	*off_out = off;
	return chunk;
}

static __always_inline int serial_emit_header(__u32 page_slot)
{
	struct shirudo_serial_chunk *chunk;
	__u32 off;

	chunk = serial_chunk_for_slot(page_slot, &off);
	if (!chunk)
		return -ENOSPC;

	*(__u32 *)&chunk->data[off] = UDP_SERIAL_MAGIC;
	*(__u16 *)&chunk->data[off + 4] = UDP_SERIAL_VERSION;
	*(__u16 *)&chunk->data[off + 6] = UDP_SERIAL_HEADER_SIZE;
	*(__u16 *)&chunk->data[off + 8] = UDP_BUCKETS;
	*(__u16 *)&chunk->data[off + 10] = UDP_MAX_LOOKUP_STEPS;
	*(__u16 *)&chunk->data[off + 12] = UDP_SERIAL_SLOT_SIZE;
	*(__u16 *)&chunk->data[off + 14] = UDP_SERIAL_RECORDS;
	*(__u32 *)&chunk->data[off + 16] = 0;
	*(__u32 *)&chunk->data[off + 20] = sizeof(struct udp_key);
	*(__u32 *)&chunk->data[off + 24] = sizeof(struct udp_stats);
	*(__u32 *)&chunk->data[off + 28] = sizeof(struct udp_ip_key);
	return 0;
}

static __always_inline void serial_associate_arena(void)
{
	(void)bpf_arena_alloc_pages(&udp_arena, 0, 0, NUMA_NO_NODE, 0);
}

static __always_inline struct udp_entry __arena *
serial_entry_at(struct udp_arena_state __arena *state, __u32 record_idx)
{
	struct udp_entry __arena *entry;
	__u32 idx = record_idx + 1;

	if (!state || record_idx >= UDP_MAX_IPS)
		return 0;

	entry = &state->entries[idx];
	if (!entry->used)
		return 0;
	return entry;
}

static __always_inline int
serial_emit_record(__u32 page_slot, __u32 record_idx,
		   const struct udp_entry __arena *entry)
{
	struct shirudo_serial_chunk *chunk;
	__u32 off;

	chunk = serial_chunk_for_slot(page_slot, &off);
	if (!chunk)
		return -ENOSPC;

	*(__u32 *)&chunk->data[off] = record_idx + 1;
	*(__u16 *)&chunk->data[off + 4] = 0;
	chunk->data[off + 6] = 0;
	chunk->data[off + 7] = 0;
	*(__u16 *)&chunk->data[off + 8] = 0;
	*(__u16 *)&chunk->data[off + 10] = 0;
	*(__u32 *)&chunk->data[off + 12] = 0;
	if (!entry)
		return 0;

	*(__u16 *)&chunk->data[off + 4] = entry->bucket_idx;
	chunk->data[off + 6] = UDP_SERIAL_RECORD_PRESENT;
	chunk->data[off + 7] = entry->key.ip.family;
	*(__u16 *)&chunk->data[off + 8] = entry->stats.last_port;
	*(__u32 *)&chunk->data[off + 12] = entry->key.uid.dev;
	*(__u64 *)&chunk->data[off + 16] = entry->key.uid.ino;
	*(__u32 *)&chunk->data[off + 24] = entry->key.ip.addr4;
	*(__u32 *)&chunk->data[off + 28] = entry->key.ip.addr6[0];
	*(__u32 *)&chunk->data[off + 32] = entry->key.ip.addr6[1];
	*(__u32 *)&chunk->data[off + 36] = entry->key.ip.addr6[2];
	*(__u32 *)&chunk->data[off + 40] = entry->key.ip.addr6[3];
	*(__u32 *)&chunk->data[off + 44] = 0;
	*(__u64 *)&chunk->data[off + 48] = entry->stats.send_count;
	*(__u64 *)&chunk->data[off + 56] = entry->stats.last_send_ns;
	*(__u64 *)&chunk->data[off + 64] = 0;
	*(__u64 *)&chunk->data[off + 72] = 0;
	*(__u64 *)&chunk->data[off + 80] = 0;
	*(__u64 *)&chunk->data[off + 88] = 0;
	return 0;
}

struct udp_serial_emit_ctx {
	struct udp_arena_state __arena *state;
	__u32 start;
	__u32 output_slots;
	__u32 next;
	int rc;
};

static int serial_emit_slot_cb(__u32 scanned, void *data)
{
	struct udp_serial_emit_ctx *emit = data;
	struct udp_entry __arena *entry;
	__u32 record_idx;
	int rc;

	if (emit->rc)
		return 1;

	record_idx = emit->start + scanned;
	if (record_idx >= UDP_SERIAL_RECORDS) {
		emit->next = UDP_SERIAL_RECORDS;
		return 1;
	}

	if (emit->output_slots >= UDP_SERIAL_SLOTS_PER_PAGE) {
		emit->next = record_idx;
		return 1;
	}
	emit->next = record_idx + 1;
	entry = serial_entry_at(emit->state, record_idx);
	if (!entry)
		return 0;
	if (!udp_pending_take(&entry->pending))
		return 0;
	rc = serial_emit_record(emit->output_slots, record_idx, entry);
	if (rc) {
		emit->rc = rc;
		return 1;
	}
	emit->output_slots++;
	return 0;
}

SEC("syscall")
int shirudo_serialize__udp_arena(struct shirudo_serialize_ctx *ctx)
{
	struct udp_arena_state __arena *state;
	struct udp_serial_emit_ctx emit = {};
	struct shirudo_serial_chunk *chunk;
	__u32 start, scan, flags = 0, key = 0;
	__u64 next_cursor;
	int rc;

	if (!ctx || ctx->magic != SHIRUDO_SERIAL_MAGIC ||
	    ctx->version != SHIRUDO_SERIAL_VERSION ||
	    ctx->chunk_payload_size != SHIRUDO_SERIAL_CHUNK_PAYLOAD)
		return -EINVAL;
	if (ctx->max_chunks < UDP_SERIAL_PAGE_CHUNKS) {
		serial_set_error(ctx, -E2BIG);
		return -E2BIG;
	}
	if (ctx->cursor > UDP_SERIAL_RECORDS) {
		serial_set_error(ctx, -EINVAL);
		return -EINVAL;
	}

	start = (__u32)ctx->cursor;
	rc = serial_init_page_chunk(1, 0, ctx->page_index,
				    ctx->cursor, ctx->cursor,
				    ctx->invocation_id);
	if (rc) {
		serial_set_error(ctx, rc);
		return rc;
	}
	rc = serial_emit_header(0);
	if (rc) {
		serial_set_error(ctx, rc);
		return rc;
	}

	serial_associate_arena();
	state = udp_state;
	emit.state = state;
	emit.start = start;
	emit.output_slots = 1;
	emit.next = start;
	if (!state) {
		emit.next = UDP_SERIAL_RECORDS;
	} else {
		scan = UDP_SERIAL_RECORDS - start;
		rc = bpf_loop(scan, serial_emit_slot_cb, &emit, 0);
		if (rc < 0) {
			serial_set_error(ctx, rc);
			return rc;
		}
		if (emit.rc) {
			serial_set_error(ctx, emit.rc);
			return emit.rc;
		}
	}

	next_cursor = emit.next;
	if (next_cursor >= UDP_SERIAL_RECORDS)
		flags = SHIRUDO_SERIAL_F_DONE;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk) {
		serial_set_error(ctx, -EINVAL);
		return -EINVAL;
	}
	chunk->flags = flags;
	chunk->bytes_total = emit.output_slots * UDP_SERIAL_SLOT_SIZE;
	chunk->bytes_in_chunk = chunk->bytes_total;
	chunk->next_cursor = next_cursor;

	return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(track_udp_sendmsg, struct socket *sock, struct msghdr *msg,
	     int size)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct udp_ip_key ip = {};
	struct exec_uid uid = {};
	struct sockaddr *addr;
	__u16 port = 0;
	struct sock *sk;
	int addrlen;

	if (size <= 0 || !sock || !msg)
		return 0;
	if ((sock->type & SOCK_TYPE_MASK) != SOCK_DGRAM)
		return 0;

	sk = sock->sk;
	if (!sk)
		return 0;
	if (sk->sk_protocol != IPPROTO_UDP)
		return 0;
	if (!task_exec_current_uid(task, &uid))
		return 0;

	addr = msg->msg_name;
	addrlen = msg->msg_namelen;
	if (addr && addrlen > 0) {
		if (!udp_ip_from_sockaddr(addr, addrlen, &ip, &port))
			return 0;
	} else {
		if (!udp_ip_from_connected_sock(sk, &ip, &port))
			return 0;
	}

	udp_table_touch(&uid, &ip, port, bpf_ktime_get_ns());
	return 0;
}
