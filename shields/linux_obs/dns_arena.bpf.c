// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
/*
 * dns_arena.bpf.c -- map DNS answers from IP endpoints to DNS names.
 *
 * Egress DNS queries are tracked by network namespace, UDP flow, and
 * transaction id. Ingress DNS responses consume the pending query and add
 * A/AAAA answers into dns_arena keyed by IP.
 */

#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
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
#define ETH_P_IP		0x0800
#define ETH_P_IPV6		0x86DD

#define DNS_PORT		53
#define DNS_TYPE_A		1
#define DNS_TYPE_AAAA		28
#define DNS_BUCKETS		512
#define DNS_MAX_LOOKUP_STEPS	2
#define DNS_MAX_IPS		4096
#define DNS_MAX_NAMES_PER_IP	4
#define DNS_MAX_NAME_CHARS	255
#define DNS_NAME_BYTES		(DNS_MAX_NAME_CHARS + 1)
#define DNS_MAX_WIRE_NAME_BYTES	255
#define DNS_MAX_LABEL_BYTES	63
#define DNS_MAX_LABELS		127
#define DNS_MAX_NAME_STEPS	(DNS_MAX_LABELS + 1)
/* A 1232-byte UDP response can hold at most 75 minimal 16-byte A answers. */
#define DNS_MAX_ANSWERS		75
#define DNS_MAX_UDP_BYTES	1232
#define DNS_MAX_IP_HEADER_BYTES	60
#define DNS_MAX_PACKET_BYTES	(DNS_MAX_UDP_BYTES + DNS_MAX_IP_HEADER_BYTES)
#define DNS_REQ_MAP_ENTRIES	1024
#define DNS_SERIAL_MAGIC	0x41534e44u /* "DNSA" little-endian */
#define DNS_SERIAL_VERSION	3
#define DNS_SERIAL_RECORD_PRESENT	(1u << 0)
#define DNS_COMPRESSED_MASK	0xc0

enum dns_debug_counter {
	DNS_DBG_QUERY_PACKET,
	DNS_DBG_QUERY_NO_UID,
	DNS_DBG_QUERY_HDR_FAIL,
	DNS_DBG_QUERY_IS_RESPONSE,
	DNS_DBG_QUERY_QDCOUNT_BAD,
	DNS_DBG_QUERY_SCRATCH_MISS,
	DNS_DBG_QUERY_NAME_FAIL,
	DNS_DBG_QUERY_EMPTY_NAME,
	DNS_DBG_QUERY_QTYPE_READ_FAIL,
	DNS_DBG_QUERY_QTYPE_UNSUPPORTED,
	DNS_DBG_QUERY_STORED,
	DNS_DBG_RESP_PACKET,
	DNS_DBG_RESP_HDR_FAIL,
	DNS_DBG_RESP_NOT_RESPONSE,
	DNS_DBG_RESP_QDCOUNT_BAD,
	DNS_DBG_RESP_NO_ANSWER,
	DNS_DBG_RESP_REQ_MISS,
	DNS_DBG_RESP_QNAME_SKIP_FAIL,
	DNS_DBG_RESP_QTYPE_READ_FAIL,
	DNS_DBG_RESP_QTYPE_MISMATCH,
	DNS_DBG_RESP_ANSWER_SEEN,
	DNS_DBG_RESP_ANSWER_SKIP_FAIL,
	DNS_DBG_RESP_RR_READ_FAIL,
	DNS_DBG_RESP_RDATA_BOUNDS_FAIL,
	DNS_DBG_RESP_ADDR_UNSUPPORTED,
	DNS_DBG_RESP_ADDR_PARSED,
	DNS_DBG_RESP_TOUCH,
	DNS_DBG_RESP_DELETE,
	DNS_DBG_TOUCH_CALLED,
	DNS_DBG_TOUCH_INIT_FAIL,
	DNS_DBG_TOUCH_HIT,
	DNS_DBG_ALLOC_ATTEMPT,
	DNS_DBG_ALLOC_BAD_IDX,
	DNS_DBG_ALLOC_OK,
	DNS_DBG_ALLOC_ENTRY_MISS,
	DNS_DBG_CAS_OK,
	DNS_DBG_CAS_FAIL,
	DNS_DBG_PACKET_IPV4,
	DNS_DBG_PACKET_IPV6,
	DNS_DBG_PACKET_NOT_UDP,
	DNS_DBG_PACKET_PORT_SKIP,
	DNS_DBG_MAX,
};

#ifndef LINUX_OBS_COMBINED
char _license[] SEC("license") = "Dual BSD/GPL";
#endif

struct dns_ip_key {
	__u8 family;
	__u8 _pad0;
	__u16 _pad1;
	__u32 addr4;
	__u32 addr6[4];
};

struct dns_key {
	struct exec_uid uid;
	struct dns_ip_key ip;
};

struct dns_name_stat {
	__u64 seen_count;
	__u64 last_seen_ns;
	char name[DNS_NAME_BYTES];
};

struct dns_entry {
	__u32 next_idx;
	__u16 bucket_idx;
	__u8 used;
	__u8 _pad0;
	__u32 pending;
	struct dns_key key;
	struct dns_name_stat names[DNS_MAX_NAMES_PER_IP];
};

struct dns_bucket {
	__u32 head_idx;
	__u32 _pad;
};

struct dns_arena_state {
	__u32 next_slot;
	__u32 _pad;
	struct dns_bucket buckets[DNS_BUCKETS];
	struct dns_entry entries[DNS_MAX_IPS + 1];
};

static __always_inline void dns_pending_set(__u32 __arena *pending)
{
	__u32 old = *pending;

	if (!(old & 1u))
		(void)__sync_val_compare_and_swap(pending, old, old | 1u);
}

static __always_inline bool dns_pending_take(__u32 __arena *pending)
{
	__u32 old = *pending;

	if (!(old & 1u))
		return false;
	return __sync_val_compare_and_swap(pending, old, old & ~1u) == old;
}

struct dns_request {
	struct exec_uid uid;
	char name[DNS_NAME_BYTES];
	__u16 qtype;
	__u16 _pad;
};

/* Canonical client-to-resolver tuple. Packet address/port bytes stay in
 * network order, so reversing an ingress response produces the query key.
 */
struct dns_request_key {
	__u64 netns_cookie;
	__u32 client_addr[4];
	__u32 resolver_addr[4];
	__u16 id;
	__u16 client_port;
	__u16 resolver_port;
	__u8 family;
	__u8 _pad;
};

struct dns_scratch {
	struct dns_request req;
	/* Tailroom lets the verifier bound a full final-label direct copy. */
	char verifier_bounds[DNS_MAX_LABEL_BYTES];
};

struct dns_init_ctx {
	struct dns_arena_state __arena *state;
};

struct dns_hdr {
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
};

struct dns_serial_name {
	__u64 seen_count;
	__u64 last_seen_ns;
	char name[DNS_NAME_BYTES];
};

struct dns_serial_header {
	__u32 magic;
	__u16 version;
	__u16 header_size;
	__u16 bucket_count;
	__u16 max_lookup_steps;
	__u16 record_size;
	__u16 record_count;
	__u32 flags;
	__u32 key_size;
	__u32 name_slots;
	__u32 name_bytes;
	__u64 reserved[140];
};

struct dns_serial_record {
	__u32 index;
	__u16 bucket;
	__u8 flags;
	__u8 family;
	__u32 addr4;
	__u32 addr6[4];
	__u16 name_count;
	__u16 _pad0;
	__u64 total_seen;
	__u64 last_seen_ns;
	struct dns_serial_name names[DNS_MAX_NAMES_PER_IP];
	__u64 reserved[2];
};

enum {
	DNS_STATE_PAGES =
		(sizeof(struct dns_arena_state) + 4095) / 4096,
	DNS_SERIAL_RECORDS = DNS_MAX_IPS,
	DNS_SERIAL_RECORD_SLOTS = DNS_SERIAL_RECORDS,
	DNS_SERIAL_SLOT_SIZE = sizeof(struct dns_serial_record),
	DNS_SERIAL_NAME_SIZE = sizeof(struct dns_serial_name),
	DNS_SERIAL_NAMES_OFFSET = 48,
	DNS_SERIAL_UID_OFFSET = DNS_SERIAL_NAMES_OFFSET +
		DNS_MAX_NAMES_PER_IP * DNS_SERIAL_NAME_SIZE,
	DNS_SERIAL_HEADER_SIZE = sizeof(struct dns_serial_header),
	DNS_SERIAL_SLOTS = DNS_SERIAL_RECORD_SLOTS + 1,
	DNS_SERIAL_SLOTS_PER_CHUNK =
		SHIRUDO_SERIAL_CHUNK_PAYLOAD / DNS_SERIAL_SLOT_SIZE,
	DNS_SERIAL_PAGE_CHUNKS = 4,
	DNS_SERIAL_SLOTS_PER_PAGE =
		DNS_SERIAL_SLOTS_PER_CHUNK * DNS_SERIAL_PAGE_CHUNKS,
	DNS_SERIAL_PAGE_BYTES =
		DNS_SERIAL_SLOTS_PER_PAGE * DNS_SERIAL_SLOT_SIZE,
};

_Static_assert((DNS_BUCKETS & (DNS_BUCKETS - 1)) == 0,
	       "dns buckets must be a power of two");
_Static_assert(sizeof(struct dns_request_key) == 48,
	       "dns request key ABI must remain verifier-friendly");
_Static_assert(sizeof(struct dns_serial_header) == DNS_SERIAL_SLOT_SIZE,
	       "dns serializer header must occupy one slot");
_Static_assert(DNS_SERIAL_UID_OFFSET + sizeof(struct exec_uid) ==
	       DNS_SERIAL_SLOT_SIZE,
	       "dns serializer UID must occupy the record tail");
_Static_assert(DNS_SERIAL_RECORDS <= 0xffff,
	       "dns serializer record count must fit header");
_Static_assert(DNS_SERIAL_SLOTS_PER_CHUNK > 0,
	       "dns serializer record must fit chunk payload");
_Static_assert(DNS_SERIAL_PAGE_CHUNKS <= SHIRUDO_SERIAL_MAX_CHUNKS,
	       "dns serializer page chunk count must fit ABI");
_Static_assert(DNS_SERIAL_SLOTS_PER_CHUNK * DNS_SERIAL_SLOT_SIZE <=
	       SHIRUDO_SERIAL_CHUNK_PAYLOAD,
	       "dns serializer chunk payload must fit records");

#ifndef LINUX_OBS_COMBINED
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 4096); /* pages */
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	enum { dns_map_extra = 1ULL << 32 } map_extra;
#else
	enum { dns_map_extra = 1ULL << 44 } map_extra;
#endif
} dns_arena SEC(".maps");
#endif

#ifndef LINUX_OBS_COMBINED
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DNS_SERIAL_PAGE_CHUNKS);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, DNS_REQ_MAP_ENTRIES);
	__type(key, struct dns_request_key);
	__type(value, struct dns_request);
} obs_i_dns_req SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dns_scratch);
} obs_i_dns_tmp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, DNS_DBG_MAX);
	__type(key, __u32);
	__type(value, __u64);
} obs_i_dns_dbg SEC(".maps");

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr,
				    __u32 page_cnt, int node_id,
				    __u64 flags) __ksym __weak;
void bpf_arena_free_pages(void *map, void __arena *ptr,
			  __u32 page_cnt) __ksym __weak;

static struct dns_arena_state __arena *dns_state;

static __always_inline void dns_debug_inc(__u32 key)
{
	__u64 *value;

	if (key >= DNS_DBG_MAX)
		return;

	value = bpf_map_lookup_elem(&obs_i_dns_dbg, &key);
	if (value)
		__sync_fetch_and_add(value, 1);
}

static __always_inline bool dns_ip_equal_arena(
	const struct dns_ip_key __arena *a, const struct dns_ip_key *b)
{
	if (a->family != b->family || a->addr4 != b->addr4)
		return false;
	if (a->addr6[0] != b->addr6[0] || a->addr6[1] != b->addr6[1] ||
	    a->addr6[2] != b->addr6[2] || a->addr6[3] != b->addr6[3])
		return false;
	return true;
}

static __always_inline bool dns_key_equal_arena(
	const struct dns_key __arena *a, const struct dns_key *b)
{
	if (!exec_uid_equal_arena(&a->uid, &b->uid))
		return false;
	return dns_ip_equal_arena(&a->ip, &b->ip);
}

static int dns_bucket_clear_cb(__u32 idx, void *data)
{
	struct dns_init_ctx *ctx = data;
	struct dns_bucket __arena *bucket;

	if (!ctx || !ctx->state || idx >= DNS_BUCKETS)
		return 1;

	bucket = &ctx->state->buckets[idx];
	bucket->head_idx = 0;
	bucket->_pad = 0;
	return 0;
}

static __always_inline __u64 dns_hash_mix(__u64 h, __u64 v)
{
	h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	return h;
}

static __always_inline __u32 dns_hash(const struct dns_key *key)
{
	__u64 h = exec_uid_hash_mix(0, &key->uid);

	h = dns_hash_mix(h, key->ip.family);
	h = dns_hash_mix(h, key->ip.addr4);
	h = dns_hash_mix(h, key->ip.addr6[0]);
	h = dns_hash_mix(h, key->ip.addr6[1]);
	h = dns_hash_mix(h, key->ip.addr6[2]);
	h = dns_hash_mix(h, key->ip.addr6[3]);
	return (__u32)h;
}

static __always_inline struct dns_arena_state __arena *dns_table_init(void)
{
	struct dns_arena_state __arena *state, *old;
	struct dns_init_ctx init = {};
	int rc;

	state = dns_state;
	if (state)
		return state;

	state = bpf_arena_alloc_pages(&dns_arena, 0, DNS_STATE_PAGES,
				      NUMA_NO_NODE, 0);
	if (!state)
		return 0;

	state->next_slot = 1;
	state->_pad = 0;
	init.state = state;
	rc = bpf_loop(DNS_BUCKETS, dns_bucket_clear_cb, &init, 0);
	if (rc < 0) {
		bpf_arena_free_pages(&dns_arena, state, DNS_STATE_PAGES);
		return 0;
	}

	old = __sync_val_compare_and_swap(&dns_state, 0, state);
	if (old) {
		bpf_arena_free_pages(&dns_arena, state, DNS_STATE_PAGES);
		return old;
	}

	return state;
}

static __always_inline struct dns_entry __arena *
dns_entry_by_index(struct dns_arena_state __arena *state, __u32 idx)
{
	if (!state || idx == 0 || idx > DNS_MAX_IPS)
		return 0;
	return &state->entries[idx];
}

static __always_inline struct dns_entry __arena *
dns_table_lookup(struct dns_arena_state __arena *state,
		 struct dns_bucket __arena *bucket,
		 const struct dns_key *key)
{
	struct dns_entry __arena *entry;
	__u32 idx;
	int i;

	idx = bucket->head_idx;

#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_LOOKUP_STEPS; i++) {
		if (idx == 0 || idx > DNS_MAX_IPS || idx >= state->next_slot)
			break;

		entry = &state->entries[idx];
		if (entry->used && dns_key_equal_arena(&entry->key, key))
			return entry;
		idx = entry->next_idx;
	}

	return 0;
}

__attribute__((noinline)) bool
obs_dns_name_equal_arena(const char __arena *a,
			 const struct dns_request *req)
{
	int i;

	if (!a || !req)
		return false;

#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_NAME_BYTES; i++) {
		char ca = a[i];
		char cb = req->name[i];

		if (ca != cb)
			return false;
		if (ca == '\0')
			return true;
	}
	return true;
}

__attribute__((noinline)) void
obs_dns_name_copy_to_arena(char __arena *dst,
			   const struct dns_request *req)
{
	int i;

	if (!dst || !req)
		return;

#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAME_CHARS; i++)
		dst[i] = req->name[i];
	dst[DNS_MAX_NAME_CHARS] = 0;
}

static __always_inline void dns_name_clear(char *name)
{
	name[0] = 0;
}

static __always_inline void dns_entry_set_name(
	struct dns_name_stat __arena *stat, const struct dns_request *req,
	__u64 now)
{
	stat->seen_count = 1;
	stat->last_seen_ns = now;
	obs_dns_name_copy_to_arena(stat->name, req);
}

static __always_inline void dns_entry_touch(struct dns_entry __arena *entry,
					    const struct dns_request *req,
					    __u64 now)
{
	struct dns_name_stat __arena *stat, *oldest_stat = 0;
	struct dns_name_stat __arena *empty_stat = 0;
	__u64 oldest = ~0ULL;
	int i;

	if (!entry || !req || !req->name[0])
		return;

#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAMES_PER_IP; i++) {
		stat = &entry->names[i];
		if (stat->seen_count &&
		    obs_dns_name_equal_arena(stat->name, req)) {
			__sync_fetch_and_add(&stat->seen_count, 1);
			stat->last_seen_ns = now;
			return;
		}
		if (!stat->seen_count && !empty_stat)
			empty_stat = stat;
		if (stat->last_seen_ns < oldest) {
			oldest = stat->last_seen_ns;
			oldest_stat = stat;
		}
	}

	stat = empty_stat ? empty_stat : oldest_stat;
	if (!stat)
		return;
	dns_entry_set_name(stat, req, now);
}

static __always_inline __u32
dns_entry_alloc(struct dns_arena_state __arena *state, __u16 bucket_idx,
		const struct dns_key *key, const struct dns_request *req,
		__u64 now)
{
	struct dns_entry __arena *entry;
	__u32 idx;

	dns_debug_inc(DNS_DBG_ALLOC_ATTEMPT);
	idx = __sync_fetch_and_add(&state->next_slot, 1);
	if (idx == 0 || idx > DNS_MAX_IPS) {
		dns_debug_inc(DNS_DBG_ALLOC_BAD_IDX);
		return 0;
	}

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
	dns_entry_set_name(&entry->names[0], req, now);
	dns_debug_inc(DNS_DBG_ALLOC_OK);

	return idx;
}

static __always_inline void dns_table_touch(const struct dns_request *req,
					    const struct dns_ip_key *ip,
					    __u64 now)
{
	struct dns_arena_state __arena *state;
	struct dns_bucket __arena *bucket;
	struct dns_entry __arena *entry, *new_entry;
	struct dns_key key = {};
	__u32 hash, idx, new_idx, old_head, prev;

	if (!req || !ip || !req->name[0])
		return;

	dns_debug_inc(DNS_DBG_TOUCH_CALLED);
	state = dns_table_init();
	if (!state) {
		dns_debug_inc(DNS_DBG_TOUCH_INIT_FAIL);
		return;
	}

	key.uid = req->uid;
	key.ip = *ip;
	hash = dns_hash(&key);
	idx = hash & (DNS_BUCKETS - 1);
	bucket = &state->buckets[idx];

	entry = dns_table_lookup(state, bucket, &key);
	if (entry) {
		dns_debug_inc(DNS_DBG_TOUCH_HIT);
		dns_entry_touch(entry, req, now);
		dns_pending_set(&entry->pending);
		return;
	}

	new_idx = dns_entry_alloc(state, idx, &key, req, now);
	if (!new_idx)
		return;

	new_entry = dns_entry_by_index(state, new_idx);
	if (!new_entry) {
		dns_debug_inc(DNS_DBG_ALLOC_ENTRY_MISS);
		return;
	}

	old_head = bucket->head_idx;
	if (old_head == 0 || old_head > DNS_MAX_IPS ||
	    old_head >= state->next_slot)
		new_entry->next_idx = 0;
	else
		new_entry->next_idx = old_head;
	prev = __sync_val_compare_and_swap(&bucket->head_idx, old_head,
					   new_idx);
	if (prev == old_head) {
		new_entry->used = 1;
		dns_debug_inc(DNS_DBG_CAS_OK);
		return;
	}

	new_entry->used = 0;
	dns_debug_inc(DNS_DBG_CAS_FAIL);
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

static __always_inline int serial_init_page_chunks(__u32 slots, __u32 flags,
						   __u32 page_index,
						   __u64 cursor,
						   __u64 next_cursor,
						   __u64 invocation_id)
{
	struct shirudo_serial_chunk *chunk;
	__u32 page_bytes, total_chunks, last_slots, prior_chunks;
	__u32 i;

	if (slots > DNS_SERIAL_SLOTS_PER_PAGE)
		return -ENOSPC;

	total_chunks =
		(slots + DNS_SERIAL_SLOTS_PER_CHUNK - 1) /
		DNS_SERIAL_SLOTS_PER_CHUNK;
	if (total_chunks == 0)
		total_chunks = 1;
	if (total_chunks > DNS_SERIAL_PAGE_CHUNKS)
		return -ENOSPC;
	prior_chunks = total_chunks - 1;
	last_slots = slots - (prior_chunks * DNS_SERIAL_SLOTS_PER_CHUNK);
	page_bytes = (prior_chunks * SHIRUDO_SERIAL_CHUNK_PAYLOAD) +
		     (last_slots * DNS_SERIAL_SLOT_SIZE);

#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_SERIAL_PAGE_CHUNKS; i++) {
		__u32 key = i;
		__u32 used;

		if (i >= total_chunks)
			break;
		used = page_bytes - i * SHIRUDO_SERIAL_CHUNK_PAYLOAD;
		if (used > SHIRUDO_SERIAL_CHUNK_PAYLOAD)
			used = SHIRUDO_SERIAL_CHUNK_PAYLOAD;

		chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
		if (!chunk)
			return -ENOSPC;

		chunk->magic = SHIRUDO_SERIAL_MAGIC;
		chunk->version = SHIRUDO_SERIAL_VERSION;
		chunk->flags = flags;
		chunk->status = 0;
		chunk->chunk_index = i;
		chunk->total_chunks = total_chunks;
		chunk->bytes_total = page_bytes;
		chunk->bytes_in_chunk = used;
		chunk->page_index = page_index;
		chunk->reserved = 0;
		chunk->cursor = cursor;
		chunk->next_cursor = next_cursor;
		chunk->invocation_id = invocation_id;
	}

	return 0;
}

static __always_inline struct shirudo_serial_chunk *
serial_chunk_for_slot(__u32 page_slot, __u32 *off_out)
{
	struct shirudo_serial_chunk *chunk;
	__u32 key, slot, off;

	barrier_var(page_slot);
	if (page_slot >= DNS_SERIAL_SLOTS_PER_PAGE)
		return 0;

	key = page_slot / DNS_SERIAL_SLOTS_PER_CHUNK;
	slot = page_slot % DNS_SERIAL_SLOTS_PER_CHUNK;
	barrier_var(key);
	barrier_var(slot);
	if (key >= DNS_SERIAL_PAGE_CHUNKS)
		return 0;

	off = slot * DNS_SERIAL_SLOT_SIZE;
	barrier_var(off);
	if (off > SHIRUDO_SERIAL_CHUNK_PAYLOAD - DNS_SERIAL_SLOT_SIZE)
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

	*(__u32 *)&chunk->data[off] = DNS_SERIAL_MAGIC;
	*(__u16 *)&chunk->data[off + 4] = DNS_SERIAL_VERSION;
	*(__u16 *)&chunk->data[off + 6] = DNS_SERIAL_HEADER_SIZE;
	*(__u16 *)&chunk->data[off + 8] = DNS_BUCKETS;
	*(__u16 *)&chunk->data[off + 10] = DNS_MAX_LOOKUP_STEPS;
	*(__u16 *)&chunk->data[off + 12] = DNS_SERIAL_SLOT_SIZE;
	*(__u16 *)&chunk->data[off + 14] = DNS_SERIAL_RECORDS;
	*(__u32 *)&chunk->data[off + 16] = 0;
	*(__u32 *)&chunk->data[off + 20] = sizeof(struct dns_key);
	*(__u32 *)&chunk->data[off + 24] = DNS_MAX_NAMES_PER_IP;
	*(__u32 *)&chunk->data[off + 28] = DNS_NAME_BYTES;
	return 0;
}

static __always_inline void serial_associate_arena(void)
{
	(void)bpf_arena_alloc_pages(&dns_arena, 0, 0, NUMA_NO_NODE, 0);
}

static __always_inline struct dns_entry __arena *
serial_entry_at(struct dns_arena_state __arena *state, __u32 record_idx)
{
	struct dns_entry __arena *entry;
	__u32 idx = record_idx + 1;

	if (!state || record_idx >= DNS_MAX_IPS)
		return 0;

	if (idx >= state->next_slot)
		return 0;

	entry = &state->entries[idx];
	if (!entry->used)
		return 0;
	return entry;
}

__attribute__((noinline)) void
obs_dns_serial_emit_name(struct shirudo_serial_chunk *chunk, __u32 base,
			 const struct dns_name_stat __arena *stat)
{
	int i;

	if (!chunk || !stat ||
	    base > SHIRUDO_SERIAL_CHUNK_PAYLOAD - DNS_SERIAL_NAME_SIZE)
		return;
	barrier_var(base);

	*(__u64 *)&chunk->data[base] = stat->seen_count;
	*(__u64 *)&chunk->data[base + 8] = stat->last_seen_ns;
#pragma clang loop unroll(disable)
	/* Copy all 255 characters and the terminating NUL. */
	for (i = 0; i < DNS_NAME_BYTES; i++)
		chunk->data[base + 16 + i] = stat->name[i];
}

static __always_inline int
serial_emit_record(__u32 page_slot, __u32 record_idx,
		   const struct dns_entry __arena *entry)
{
	struct shirudo_serial_chunk *chunk;
	const struct dns_name_stat __arena *stat;
	__u64 total_seen = 0;
	__u64 last_seen = 0;
	__u32 off, name_base;
	__u16 name_count = 0;
	int i;

	chunk = serial_chunk_for_slot(page_slot, &off);
	if (!chunk)
		return -ENOSPC;

	*(__u32 *)&chunk->data[off] = record_idx + 1;
	*(__u16 *)&chunk->data[off + 4] = 0;
	chunk->data[off + 6] = 0;
	chunk->data[off + 7] = 0;
	*(__u32 *)&chunk->data[off + 8] = 0;
	if (!entry)
		return 0;

#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAMES_PER_IP; i++) {
		stat = &entry->names[i];
		if (!stat->seen_count)
			continue;
		name_count++;
		total_seen += stat->seen_count;
		if (stat->last_seen_ns > last_seen)
			last_seen = stat->last_seen_ns;
	}

	*(__u16 *)&chunk->data[off + 4] = entry->bucket_idx;
	chunk->data[off + 6] = DNS_SERIAL_RECORD_PRESENT;
	chunk->data[off + 7] = entry->key.ip.family;
	*(__u32 *)&chunk->data[off + 8] = entry->key.ip.addr4;
	*(__u32 *)&chunk->data[off + 12] = entry->key.ip.addr6[0];
	*(__u32 *)&chunk->data[off + 16] = entry->key.ip.addr6[1];
	*(__u32 *)&chunk->data[off + 20] = entry->key.ip.addr6[2];
	*(__u32 *)&chunk->data[off + 24] = entry->key.ip.addr6[3];
	*(__u16 *)&chunk->data[off + 28] = name_count;
	*(__u16 *)&chunk->data[off + 30] = 0;
	*(__u64 *)&chunk->data[off + 32] = total_seen;
	*(__u64 *)&chunk->data[off + 40] = last_seen;

#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAMES_PER_IP; i++) {
		stat = &entry->names[i];
		name_base = off + DNS_SERIAL_NAMES_OFFSET +
			(i * DNS_SERIAL_NAME_SIZE);
		if (stat->seen_count) {
			obs_dns_serial_emit_name(chunk, name_base, stat);
		} else {
			*(__u64 *)&chunk->data[name_base] = 0;
			*(__u64 *)&chunk->data[name_base + 8] = 0;
			chunk->data[name_base + 16] = 0;
		}
	}
	*(__u32 *)&chunk->data[off + DNS_SERIAL_UID_OFFSET] =
		entry->key.uid.dev;
	*(__u32 *)&chunk->data[off + DNS_SERIAL_UID_OFFSET + 4] = 0;
	*(__u64 *)&chunk->data[off + DNS_SERIAL_UID_OFFSET + 8] =
		entry->key.uid.ino;
	return 0;
}

static __always_inline int
serial_finalize_chunk(__u32 key, __u32 flags, __u32 total_chunks,
			      __u32 page_bytes, __u64 next_cursor)
{
	struct shirudo_serial_chunk *chunk;
	__u32 used;

	if (key >= total_chunks)
		return 0;
	used = page_bytes - key * SHIRUDO_SERIAL_CHUNK_PAYLOAD;
	if (used > SHIRUDO_SERIAL_CHUNK_PAYLOAD)
		used = SHIRUDO_SERIAL_CHUNK_PAYLOAD;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return -EINVAL;
	chunk->flags = flags;
	chunk->total_chunks = total_chunks;
	chunk->bytes_total = page_bytes;
	chunk->bytes_in_chunk = used;
	chunk->next_cursor = next_cursor;
	return 0;
}

struct dns_serial_emit_ctx {
	struct dns_arena_state __arena *state;
	__u32 start;
	__u32 output_slots;
	__u32 record_index;
	__u32 next;
	int rc;
};

static int serial_emit_slot_cb(__u32 scanned, void *data)
{
	struct dns_serial_emit_ctx *emit = data;
	struct dns_entry __arena *entry;
	__u32 record_idx;

	if (emit->rc)
		return 1;

	record_idx = emit->start + scanned;
	if (record_idx >= DNS_SERIAL_RECORDS) {
		emit->next = DNS_SERIAL_RECORDS;
		return 1;
	}

	if (emit->output_slots >= DNS_SERIAL_SLOTS_PER_PAGE) {
		emit->next = record_idx;
		return 1;
	}
	emit->next = record_idx + 1;
	entry = serial_entry_at(emit->state, record_idx);
	if (!entry)
		return 0;
	if (!dns_pending_take(&entry->pending))
		return 0;
	emit->record_index = record_idx;
	emit->output_slots = 2;
	return 1;
}

SEC("syscall")
int shirudo_serialize__dns_arena(struct shirudo_serialize_ctx *ctx)
{
	struct dns_arena_state __arena *state;
	struct dns_serial_emit_ctx emit = {};
	__u32 start, scan, flags = 0, total_chunks, page_bytes;
	__u64 next_cursor;
	int rc;

	if (!ctx || ctx->magic != SHIRUDO_SERIAL_MAGIC ||
	    ctx->version != SHIRUDO_SERIAL_VERSION ||
	    ctx->chunk_payload_size != SHIRUDO_SERIAL_CHUNK_PAYLOAD)
		return -EINVAL;
	if (ctx->max_chunks < DNS_SERIAL_PAGE_CHUNKS) {
		serial_set_error(ctx, -E2BIG);
		return -E2BIG;
	}
	if (ctx->cursor > DNS_SERIAL_RECORDS) {
		serial_set_error(ctx, -EINVAL);
		return -EINVAL;
	}

	start = (__u32)ctx->cursor;
	rc = serial_init_page_chunks(DNS_SERIAL_SLOTS_PER_PAGE, 0,
				     ctx->page_index, ctx->cursor, ctx->cursor,
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
	state = dns_state;
	emit.state = state;
	emit.start = start;
	emit.output_slots = 1;
	emit.next = start;
	if (!state) {
		emit.next = DNS_SERIAL_RECORDS;
	} else {
		scan = DNS_SERIAL_RECORDS - start;
		rc = bpf_loop(scan, serial_emit_slot_cb, &emit, 0);
		if (rc < 0) {
			serial_set_error(ctx, rc);
			return rc;
		}
		if (emit.rc) {
			serial_set_error(ctx, emit.rc);
			return emit.rc;
		}
		if (emit.output_slots > 1) {
			struct dns_entry __arena *entry;

			entry = serial_entry_at(state, emit.record_index);
			if (!entry) {
				serial_set_error(ctx, -EINVAL);
				return -EINVAL;
			}
			rc = serial_emit_record(1, emit.record_index, entry);
			if (rc) {
				serial_set_error(ctx, rc);
				return rc;
			}
		}
	}

	next_cursor = emit.next;
	if (next_cursor >= DNS_SERIAL_RECORDS)
		flags = SHIRUDO_SERIAL_F_DONE;
	total_chunks = (emit.output_slots + DNS_SERIAL_SLOTS_PER_CHUNK - 1) /
		DNS_SERIAL_SLOTS_PER_CHUNK;
	if (total_chunks == 0)
		total_chunks = 1;
	page_bytes = ((total_chunks - 1) * SHIRUDO_SERIAL_CHUNK_PAYLOAD) +
		((emit.output_slots - ((total_chunks - 1) *
			DNS_SERIAL_SLOTS_PER_CHUNK)) * DNS_SERIAL_SLOT_SIZE);
	rc = serial_finalize_chunk(0, flags, total_chunks, page_bytes,
				   next_cursor);
	if (rc)
		return rc;
	rc = serial_finalize_chunk(1, flags, total_chunks, page_bytes,
				   next_cursor);
	if (rc)
		return rc;
	rc = serial_finalize_chunk(2, flags, total_chunks, page_bytes,
				   next_cursor);
	if (rc)
		return rc;
	rc = serial_finalize_chunk(3, flags, total_chunks, page_bytes,
				   next_cursor);
	if (rc)
		return rc;

	return 0;
}

static __always_inline bool dns_read_u16(struct __sk_buff *skb, __u32 off,
					 __u16 *value)
{
	const __u8 *data = (const __u8 *)(long)skb->data;
	const __u8 *data_end = (const __u8 *)(long)skb->data_end;
	const __u8 *src;

	if (!value || off > DNS_MAX_PACKET_BYTES - sizeof(*value))
		return false;
	src = data + off;
	if (src + sizeof(*value) > data_end)
		return false;
	*value = ((__u16)src[0] << 8) | (__u16)src[1];
	return true;
}

static __always_inline bool dns_read_u32_raw(struct __sk_buff *skb,
					     __u32 off, __u32 *value)
{
	const __u8 *data = (const __u8 *)(long)skb->data;
	const __u8 *data_end = (const __u8 *)(long)skb->data_end;
	const __u8 *src;
	__u8 *dst = (__u8 *)value;

	if (!value || off > DNS_MAX_PACKET_BYTES - sizeof(*value))
		return false;
	src = data + off;
	if (src + sizeof(*value) > data_end)
		return false;
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	dst[3] = src[3];
	return true;
}

__attribute__((noinline)) int
obs_dns_parse_name_label(struct __sk_buff *skb, __u32 off, __u32 start)
{
	__u8 *data = (__u8 *)(long)skb->data;
	__u8 *data_end = (__u8 *)(long)skb->data_end;
	__u8 *src;
	struct dns_scratch *scratch;
	char *out;
	__u32 zero = 0;
	__u32 wire_offset, dst, i;
	__u8 len;

	if (off < start || off >= DNS_MAX_PACKET_BYTES)
		return -EINVAL;
	wire_offset = off - start;
	if (wire_offset >= DNS_MAX_WIRE_NAME_BYTES)
		return -EINVAL;

	src = data + off;
	if (src + 1 > data_end)
		return -EINVAL;
	len = *src;
	if (len & DNS_COMPRESSED_MASK)
		return -EINVAL;
	src++;

	scratch = bpf_map_lookup_elem(&obs_i_dns_tmp, &zero);
	if (!scratch)
		return -EINVAL;
	out = scratch->req.name;

	if (len == 0) {
		dst = wire_offset ? wire_offset - 1 : 0;
		if (dst >= DNS_MAX_NAME_CHARS)
			return -EINVAL;
		out[dst] = 0;
		return 0;
	}
	if (len > DNS_MAX_LABEL_BYTES)
		return -EINVAL;

	dst = wire_offset;
	if (dst >= DNS_MAX_NAME_CHARS)
		return -EINVAL;
	if (dst) {
		out[dst - 1] = '.';
	}
	if (len > DNS_MAX_NAME_CHARS - dst)
		return -EINVAL;

	/* The verifier needs the packet bound checked for each direct byte read. */
#pragma clang loop unroll(disable)
	for (i = 0; i < len; i++) {
		if (src + i + 1 > data_end)
			return -EINVAL;
		out[dst + i] = src[i];
	}

	return (int)len + 1;
}

static __always_inline int dns_parse_name(struct __sk_buff *skb, __u32 off,
					  char *out, __u32 *next_off)
{
	__u32 start = off;
	__u32 pos = off;
	int consumed;
	int i;

	if (!out || !next_off)
		return -EINVAL;
	dns_name_clear(out);

#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAME_STEPS; i++) {
		consumed = obs_dns_parse_name_label(skb, pos, start);
		if (consumed < 0)
			return consumed;
		if (consumed == 0) {
			*next_off = pos + 1;
			return 0;
		}
		if ((__u32)consumed > DNS_MAX_PACKET_BYTES - pos)
			return -EINVAL;
		pos += (__u32)consumed;
		if (pos - start >= DNS_MAX_WIRE_NAME_BYTES)
			return -EINVAL;
	}

	return -EINVAL;
}

static __always_inline int dns_skip_name(struct __sk_buff *skb, __u32 off,
					 __u32 *next_off)
{
	const __u8 *data = (const __u8 *)(long)skb->data;
	const __u8 *data_end = (const __u8 *)(long)skb->data_end;
	const __u8 *src;
	__u32 consumed = 0;
	__u32 label_len, pos;
	__u8 len;
	int i;

	if (!next_off || off >= DNS_MAX_PACKET_BYTES)
		return -EINVAL;

#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_NAME_STEPS; i++) {
		if (consumed >= DNS_MAX_WIRE_NAME_BYTES)
			return -EINVAL;
		if (consumed >= DNS_MAX_PACKET_BYTES - off)
			return -EINVAL;
		pos = off + consumed;
		src = data + pos;
		if (src + 1 > data_end)
			return -EINVAL;
		len = *src;

		if ((len & DNS_COMPRESSED_MASK) == DNS_COMPRESSED_MASK) {
			if (consumed + 2 < consumed ||
			    consumed + 2 > DNS_MAX_WIRE_NAME_BYTES)
				return -EINVAL;
			if (pos > DNS_MAX_PACKET_BYTES - 2)
				return -EINVAL;
			if (src + 2 > data_end)
				return -EINVAL;
			*next_off = off + consumed + 2;
			return 0;
		}
		if (len & DNS_COMPRESSED_MASK)
			return -EINVAL;

		consumed++;
		if (len == 0) {
			*next_off = off + consumed;
			return 0;
		}
		if (len > DNS_MAX_LABEL_BYTES)
			return -EINVAL;

		label_len = (__u32)len;
		if (consumed + label_len < consumed ||
		    consumed + label_len >= DNS_MAX_WIRE_NAME_BYTES)
			return -EINVAL;
		if (label_len > DNS_MAX_PACKET_BYTES - pos - 1)
			return -EINVAL;
		if (src + 1 + label_len > data_end)
			return -EINVAL;
		consumed += label_len;
	}

	return -EINVAL;
}

static __always_inline void dns_parse_query_payload(struct __sk_buff *skb,
						    __u32 dns_off,
						    struct dns_request_key *req_key)
{
	struct dns_scratch *scratch;
	struct task_struct *task = bpf_get_current_task_btf();
	struct exec_uid uid = {};
	__u32 zero = 0;
	__u32 next = 0;
	__u16 id, flags, qdcount, qtype, qclass;

	dns_debug_inc(DNS_DBG_QUERY_PACKET);
	if (!task_exec_current_uid(task, &uid)) {
		dns_debug_inc(DNS_DBG_QUERY_NO_UID);
		return;
	}

	if (!dns_read_u16(skb, dns_off, &id) ||
	    !dns_read_u16(skb, dns_off + 2, &flags) ||
	    !dns_read_u16(skb, dns_off + 4, &qdcount)) {
		dns_debug_inc(DNS_DBG_QUERY_HDR_FAIL);
		return;
	}
	if (flags & 0x8000) {
		dns_debug_inc(DNS_DBG_QUERY_IS_RESPONSE);
		return;
	}
	if (qdcount != 1) {
		dns_debug_inc(DNS_DBG_QUERY_QDCOUNT_BAD);
		return;
	}

	scratch = bpf_map_lookup_elem(&obs_i_dns_tmp, &zero);
	if (!scratch) {
		dns_debug_inc(DNS_DBG_QUERY_SCRATCH_MISS);
		return;
	}

	if (dns_parse_name(skb, dns_off + sizeof(struct dns_hdr),
			   scratch->req.name, &next)) {
		dns_debug_inc(DNS_DBG_QUERY_NAME_FAIL);
		return;
	}
	if (!scratch->req.name[0]) {
		dns_debug_inc(DNS_DBG_QUERY_EMPTY_NAME);
		return;
	}
	if (!dns_read_u16(skb, next, &qtype) ||
	    !dns_read_u16(skb, next + 2, &qclass)) {
		dns_debug_inc(DNS_DBG_QUERY_QTYPE_READ_FAIL);
		return;
	}
	if (qtype != DNS_TYPE_A && qtype != DNS_TYPE_AAAA) {
		dns_debug_inc(DNS_DBG_QUERY_QTYPE_UNSUPPORTED);
		return;
	}

	scratch->req.uid = uid;
	scratch->req.qtype = qtype;
	scratch->req._pad = 0;
	req_key->id = id;
	bpf_map_update_elem(&obs_i_dns_req, req_key, &scratch->req, BPF_ANY);
	dns_debug_inc(DNS_DBG_QUERY_STORED);
}

static __always_inline bool dns_answer_ip_key(struct __sk_buff *skb,
					      __u32 rdata_off, __u16 rtype,
					      __u16 rdlen,
					      struct dns_ip_key *key)
{
	__builtin_memset(key, 0, sizeof(*key));
	if (rtype == DNS_TYPE_A) {
		if (rdlen != 4) {
			dns_debug_inc(DNS_DBG_RESP_ADDR_UNSUPPORTED);
			return false;
		}
		key->family = AF_INET;
		if (!dns_read_u32_raw(skb, rdata_off, &key->addr4))
			return false;
		dns_debug_inc(DNS_DBG_RESP_ADDR_PARSED);
		return true;
	}
	if (rtype == DNS_TYPE_AAAA) {
		if (rdlen != 16) {
			dns_debug_inc(DNS_DBG_RESP_ADDR_UNSUPPORTED);
			return false;
		}
		key->family = AF_INET6;
		if (!dns_read_u32_raw(skb, rdata_off, &key->addr6[0]) ||
		    !dns_read_u32_raw(skb, rdata_off + 4, &key->addr6[1]) ||
		    !dns_read_u32_raw(skb, rdata_off + 8, &key->addr6[2]) ||
		    !dns_read_u32_raw(skb, rdata_off + 12, &key->addr6[3]))
			return false;
		dns_debug_inc(DNS_DBG_RESP_ADDR_PARSED);
		return true;
	}
	dns_debug_inc(DNS_DBG_RESP_ADDR_UNSUPPORTED);
	return false;
}

__attribute__((noinline)) int
obs_dns_parse_answer(struct __sk_buff *skb, const struct dns_request *req,
		     __u32 off, __u64 now)
{
	struct dns_ip_key key = {};
	__u32 next = 0, rdata_off;
	__u16 rtype, rdlen;

	dns_debug_inc(DNS_DBG_RESP_ANSWER_SEEN);
	if (dns_skip_name(skb, off, &next)) {
		dns_debug_inc(DNS_DBG_RESP_ANSWER_SKIP_FAIL);
		return -EINVAL;
	}
	if (!dns_read_u16(skb, next, &rtype) ||
	    !dns_read_u16(skb, next + 8, &rdlen)) {
		dns_debug_inc(DNS_DBG_RESP_RR_READ_FAIL);
		return -EINVAL;
	}
	rdata_off = next + 10;
	barrier_var(rtype);
	barrier_var(rdlen);
	barrier_var(rdata_off);
	if (rdata_off > DNS_MAX_PACKET_BYTES ||
	    rdlen > DNS_MAX_PACKET_BYTES ||
	    rdata_off + rdlen < rdata_off ||
	    rdata_off + rdlen > DNS_MAX_PACKET_BYTES) {
		dns_debug_inc(DNS_DBG_RESP_RDATA_BOUNDS_FAIL);
		return -EINVAL;
	}

	if (dns_answer_ip_key(skb, rdata_off, rtype, rdlen, &key)) {
		dns_debug_inc(DNS_DBG_RESP_TOUCH);
		dns_table_touch(req, &key, now);
	}

	return (int)(rdata_off + rdlen);
}

static __always_inline void dns_parse_response_payload(struct __sk_buff *skb,
						       __u32 dns_off,
						       struct dns_request_key *req_key)
{
	struct dns_request *req;
	__u32 off, next = 0;
	__u64 now = bpf_ktime_get_ns();
	__u16 id, flags, qdcount, ancount, qtype, qclass;
	int answer_off, i;

	dns_debug_inc(DNS_DBG_RESP_PACKET);
	if (!dns_read_u16(skb, dns_off, &id) ||
	    !dns_read_u16(skb, dns_off + 2, &flags) ||
	    !dns_read_u16(skb, dns_off + 4, &qdcount) ||
	    !dns_read_u16(skb, dns_off + 6, &ancount)) {
		dns_debug_inc(DNS_DBG_RESP_HDR_FAIL);
		return;
	}
	if ((flags & 0x8000) == 0) {
		dns_debug_inc(DNS_DBG_RESP_NOT_RESPONSE);
		return;
	}
	if (qdcount != 1) {
		dns_debug_inc(DNS_DBG_RESP_QDCOUNT_BAD);
		return;
	}
	if (ancount == 0) {
		dns_debug_inc(DNS_DBG_RESP_NO_ANSWER);
		return;
	}

	req_key->id = id;
	req = bpf_map_lookup_elem(&obs_i_dns_req, req_key);
	if (!req) {
		dns_debug_inc(DNS_DBG_RESP_REQ_MISS);
		return;
	}

	if (dns_skip_name(skb, dns_off + sizeof(struct dns_hdr), &next)) {
		dns_debug_inc(DNS_DBG_RESP_QNAME_SKIP_FAIL);
		bpf_map_delete_elem(&obs_i_dns_req, req_key);
		return;
	}
	if (!dns_read_u16(skb, next, &qtype) ||
	    !dns_read_u16(skb, next + 2, &qclass)) {
		dns_debug_inc(DNS_DBG_RESP_QTYPE_READ_FAIL);
		bpf_map_delete_elem(&obs_i_dns_req, req_key);
		return;
	}
	if (qtype != req->qtype) {
		dns_debug_inc(DNS_DBG_RESP_QTYPE_MISMATCH);
		bpf_map_delete_elem(&obs_i_dns_req, req_key);
		return;
	}

	off = next + 4;
#pragma clang loop unroll(disable)
	for (i = 0; i < DNS_MAX_ANSWERS; i++) {
		if (i >= ancount)
			break;

		answer_off = obs_dns_parse_answer(skb, req, off, now);
		if (answer_off < 0)
			break;
		off = (__u32)answer_off;
	}

	bpf_map_delete_elem(&obs_i_dns_req, req_key);
	dns_debug_inc(DNS_DBG_RESP_DELETE);
}

static __always_inline void dns_parse_packet(struct __sk_buff *skb, bool send)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct dns_request_key req_key = {};
	struct iphdr *ip4;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	__u32 ip_hlen, dns_off;

	switch (bpf_ntohs(skb->protocol)) {
	case ETH_P_IP:
		dns_debug_inc(DNS_DBG_PACKET_IPV4);
		ip4 = data;
		if ((void *)(ip4 + 1) > data_end)
			return;
		if (ip4->protocol != IPPROTO_UDP) {
			dns_debug_inc(DNS_DBG_PACKET_NOT_UDP);
			return;
		}
		ip_hlen = ip4->ihl * sizeof(__u32);
		if (ip_hlen < sizeof(struct iphdr) || ip_hlen > 60)
			return;
		udp = data + ip_hlen;
		if ((void *)(udp + 1) > data_end)
			return;
		req_key.family = AF_INET;
		if (send) {
			req_key.client_addr[0] = ip4->saddr;
			req_key.resolver_addr[0] = ip4->daddr;
		} else {
			req_key.client_addr[0] = ip4->daddr;
			req_key.resolver_addr[0] = ip4->saddr;
		}
		break;
	case ETH_P_IPV6:
		dns_debug_inc(DNS_DBG_PACKET_IPV6);
		ip6 = data;
		if ((void *)(ip6 + 1) > data_end)
			return;
		if (ip6->nexthdr != IPPROTO_UDP) {
			dns_debug_inc(DNS_DBG_PACKET_NOT_UDP);
			return;
		}
		udp = data + sizeof(struct ipv6hdr);
		if ((void *)(udp + 1) > data_end)
			return;
		req_key.family = AF_INET6;
		if (send) {
			req_key.client_addr[0] = ip6->saddr.in6_u.u6_addr32[0];
			req_key.client_addr[1] = ip6->saddr.in6_u.u6_addr32[1];
			req_key.client_addr[2] = ip6->saddr.in6_u.u6_addr32[2];
			req_key.client_addr[3] = ip6->saddr.in6_u.u6_addr32[3];
			req_key.resolver_addr[0] = ip6->daddr.in6_u.u6_addr32[0];
			req_key.resolver_addr[1] = ip6->daddr.in6_u.u6_addr32[1];
			req_key.resolver_addr[2] = ip6->daddr.in6_u.u6_addr32[2];
			req_key.resolver_addr[3] = ip6->daddr.in6_u.u6_addr32[3];
		} else {
			req_key.client_addr[0] = ip6->daddr.in6_u.u6_addr32[0];
			req_key.client_addr[1] = ip6->daddr.in6_u.u6_addr32[1];
			req_key.client_addr[2] = ip6->daddr.in6_u.u6_addr32[2];
			req_key.client_addr[3] = ip6->daddr.in6_u.u6_addr32[3];
			req_key.resolver_addr[0] = ip6->saddr.in6_u.u6_addr32[0];
			req_key.resolver_addr[1] = ip6->saddr.in6_u.u6_addr32[1];
			req_key.resolver_addr[2] = ip6->saddr.in6_u.u6_addr32[2];
			req_key.resolver_addr[3] = ip6->saddr.in6_u.u6_addr32[3];
		}
		break;
	default:
		return;
	}

	if (send) {
		if (udp->dest != bpf_htons(DNS_PORT)) {
			dns_debug_inc(DNS_DBG_PACKET_PORT_SKIP);
			return;
		}
		req_key.client_port = udp->source;
		req_key.resolver_port = udp->dest;
	} else {
		if (udp->source != bpf_htons(DNS_PORT)) {
			dns_debug_inc(DNS_DBG_PACKET_PORT_SKIP);
			return;
		}
		req_key.client_port = udp->dest;
		req_key.resolver_port = udp->source;
	}

	req_key.netns_cookie = bpf_get_netns_cookie(skb);
	dns_off = (__u32)((void *)udp + sizeof(struct udphdr) - data);
	if (send)
		dns_parse_query_payload(skb, dns_off, &req_key);
	else
		dns_parse_response_payload(skb, dns_off, &req_key);
}

SEC("cgroup_skb/egress")
int track_dns_query(struct __sk_buff *skb)
{
	dns_parse_packet(skb, true);
	return 1;
}

SEC("cgroup_skb/ingress")
int track_dns_response(struct __sk_buff *skb)
{
	dns_parse_packet(skb, false);
	return 1;
}
