// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
/*
 * exec_uid_arena.bpf.c -- track executable identity and exec parent edges.
 *
 * On exec, derive the executable identity from {dev, inode}, link it to the
 * parent task's last known executable identity, and update an arena-backed
 * edge table so userspace can reconstruct an execution tree.
 */

#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "shirudo_serializer.h"

#if !defined(__BPF_FEATURE_ADDR_SPACE_CAST)
#error "BPF arena access requires clang address-space cast support"
#endif

#define __arena		__attribute__((address_space(1)))
#define NUMA_NO_NODE	(-1)

#include "exec_uid_common.h"

#define E2BIG			7
#define EINVAL			22
#define ENOSPC			28

#define EXEC_BUCKETS		256
#define EXEC_MAX_LOOKUP_STEPS	2
#define EXEC_MAX_EDGES		1024
#define EXEC_NAME_LEN		32
#define EXEC_SERIAL_MAGIC	0x43455845u /* "EXEC" little-endian */
#define EXEC_SERIAL_VERSION	4
#define EXEC_SERIAL_HEADER_HAS_NAME	(1u << 0)
#define EXEC_SERIAL_HEADER_HAS_PARENT	(1u << 1)
#define EXEC_SERIAL_RECORD_PRESENT	(1u << 0)
#define EXEC_SERIAL_RECORD_HAS_PARENT	(1u << 1)

#ifndef LINUX_OBS_COMBINED
char _license[] SEC("license") = "Dual BSD/GPL";
#endif

struct exec_edge_key {
	struct exec_uid uid;
	struct exec_uid parent_uid;
	__u8 parent_present;
	__u8 _pad[7];
};

struct exec_edge_stats {
	__u64 exec_count;
	__u64 last_exec_ns;
	__u32 name_len;
	__u8 _pad[4];
	char name[EXEC_NAME_LEN];
};

struct exec_entry {
	__u32 next_idx;
	__u16 bucket_idx;
	__u8 used;
	__u8 _pad0;
	__u32 pending;
	struct exec_edge_key key;
	struct exec_edge_stats stats;
};

/*
 * Keep the event table in an ordinary BPF array. Arena allocation is
 * available to syscall and networking programs, but is not dependable from
 * the exec LSM hook before the first serializer invocation. The public
 * exec_arena view remains the stable serializer name; this table is an
 * implementation detail and is not pinned for operators.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, EXEC_BUCKETS);
	__type(key, __u32);
	__type(value, struct exec_entry);
} obs_i_exec_entries SEC(".maps");

struct exec_bucket {
	__u32 head_idx;
	__u32 _pad;
};

struct exec_arena_state {
	__u32 next_slot;
	__u32 _pad;
	struct exec_bucket buckets[EXEC_BUCKETS];
	struct exec_entry entries[EXEC_MAX_EDGES + 1];
};

static __always_inline void exec_pending_set(__u32 __arena *pending)
{
	__u32 old = *pending;

	if (!(old & 1u))
		(void)__sync_val_compare_and_swap(pending, old, old | 1u);
}

static __always_inline bool exec_pending_take(__u32 __arena *pending)
{
	__u32 old = *pending;

	if (!(old & 1u))
		return false;
	return __sync_val_compare_and_swap(pending, old, old & ~1u) == old;
}

static __always_inline bool exec_pending_take_map(__u32 *pending)
{
	__u32 old = *pending;

	if (!(old & 1u))
		return false;
	return __sync_val_compare_and_swap(pending, old, old & ~1u) == old;
}

struct exec_serial_header {
	__u32 magic;
	__u16 version;
	__u16 header_size;
	__u16 bucket_count;
	__u16 max_lookup_steps;
	__u16 record_size;
	__u16 record_count;
	__u32 flags;
	__u32 layout;		/* low 16: name bytes; high 16: slots/record */
	__u32 key_size;
	__u32 value_size;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
	__u64 reserved4;
	__u64 reserved5;
	__u64 reserved6;
	__u64 reserved7;
	__u64 reserved8;
	__u64 reserved9;
	__u64 reserved10;
	__u64 reserved11;
	__u64 reserved12;
};

struct exec_serial_record {
	__u32 index;
	__u16 bucket;
	__u8 flags;
	__u8 _pad0;
	__u32 name_len;
	__u32 dev;
	__u32 parent_dev;
	__u32 _pad1;
	__u64 ino;
	__u64 parent_ino;
	__u64 exec_count;
	__u64 last_exec_ns;
	char name[EXEC_NAME_LEN];
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
	__u64 reserved4;
	__u64 reserved5;
};

enum {
	EXEC_STATE_PAGES =
		(sizeof(struct exec_arena_state) + 4095) / 4096,
	EXEC_SERIAL_RECORDS = EXEC_MAX_EDGES,
	EXEC_SERIAL_SLOTS_PER_RECORD = 1,
	EXEC_SERIAL_RECORD_SLOTS = EXEC_SERIAL_RECORDS,
	EXEC_SERIAL_SLOT_SIZE = sizeof(struct exec_serial_record),
	EXEC_SERIAL_HEADER_SIZE = sizeof(struct exec_serial_header),
	EXEC_SERIAL_SLOTS = EXEC_SERIAL_RECORD_SLOTS + 1,
	EXEC_SERIAL_SLOTS_PER_CHUNK =
		SHIRUDO_SERIAL_CHUNK_PAYLOAD / EXEC_SERIAL_SLOT_SIZE,
	EXEC_SERIAL_SLOTS_PER_PAGE = 8,
	EXEC_SERIAL_PAGE_BYTES =
		EXEC_SERIAL_SLOTS_PER_PAGE * EXEC_SERIAL_SLOT_SIZE,
	EXEC_SERIAL_PAGE_CHUNKS = 1,
};

_Static_assert((EXEC_BUCKETS & (EXEC_BUCKETS - 1)) == 0,
	       "exec buckets must be a power of two");
_Static_assert(sizeof(struct exec_serial_header) == EXEC_SERIAL_SLOT_SIZE,
	       "exec serializer header must occupy one slot");
_Static_assert(EXEC_SERIAL_RECORDS <= 0xffff,
	       "exec serializer record count must fit header");
_Static_assert(EXEC_SERIAL_SLOTS_PER_CHUNK >= EXEC_SERIAL_SLOTS_PER_PAGE,
	       "exec serializer page must fit one chunk");
_Static_assert(EXEC_SERIAL_PAGE_BYTES <= SHIRUDO_SERIAL_CHUNK_PAYLOAD,
	       "exec serializer page must fit chunk payload");

#ifndef LINUX_OBS_COMBINED
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 4096); /* pages */
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	enum { exec_map_extra = 1ULL << 32 } map_extra;
#else
	enum { exec_map_extra = 1ULL << 44 } map_extra;
#endif
} exec_arena SEC(".maps");
#endif

#ifndef LINUX_OBS_COMBINED
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, EXEC_SERIAL_PAGE_CHUNKS);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");
#endif

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr,
				    __u32 page_cnt, int node_id,
				    __u64 flags) __ksym __weak;
void bpf_arena_free_pages(void *map, void __arena *ptr,
			  __u32 page_cnt) __ksym __weak;

static struct exec_arena_state __arena *exec_state;

static __always_inline bool exec_edge_key_equal_arena(
	const struct exec_edge_key __arena *a, const struct exec_edge_key *b)
{
	if (!exec_uid_equal_arena(&a->uid, &b->uid))
		return false;
	if (a->parent_present != b->parent_present)
		return false;
	if (!b->parent_present)
		return true;
	return exec_uid_equal_arena(&a->parent_uid, &b->parent_uid);
}

static __always_inline __u64 exec_hash_mix(__u64 h, __u64 v)
{
	h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	return h;
}

static __always_inline __u32 exec_edge_hash(const struct exec_edge_key *key)
{
	__u64 h = key->uid.ino;

	h = exec_hash_mix(h, key->uid.dev);
	if (key->parent_present) {
		h = exec_hash_mix(h, key->parent_uid.ino);
		h = exec_hash_mix(h, key->parent_uid.dev);
	}
	h = exec_hash_mix(h, key->parent_present);
	return (__u32)h;
}

static __always_inline void exec_name_copy_to_arena(char __arena *dst,
						    const char *src)
{
	__u32 i;

#pragma clang loop unroll(full)
	for (i = 0; i < EXEC_NAME_LEN; i++)
		dst[i] = src[i];
}

static __always_inline __u32 exec_name_from_file(struct file *file,
						 char *name)
{
	struct dentry *dentry;
	const unsigned char *name_ptr;
	long copied;

	name[0] = '\0';
	if (!file)
		return 0;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return 0;

	name_ptr = BPF_CORE_READ(dentry, d_name.name);
	if (!name_ptr)
		return 0;

	copied = bpf_probe_read_kernel_str(name, EXEC_NAME_LEN, name_ptr);
	if (copied <= 0) {
		name[0] = '\0';
		return 0;
	}
	if (copied > EXEC_NAME_LEN)
		copied = EXEC_NAME_LEN;

	return (__u32)copied - 1;
}

static __always_inline void exec_edge_key_init(
	struct exec_edge_key *key, const struct exec_uid *uid,
	const struct exec_uid *parent_uid, bool parent_present)
{
	__builtin_memset(key, 0, sizeof(*key));
	key->uid = *uid;
	if (parent_present) {
		key->parent_present = 1;
		key->parent_uid = *parent_uid;
	}
}

static __always_inline struct exec_arena_state __arena *exec_table_init(void)
{
	struct exec_arena_state __arena *state, *old;

	state = exec_state;
	if (state)
		return state;

	state = bpf_arena_alloc_pages(&exec_arena, 0, EXEC_STATE_PAGES,
				      NUMA_NO_NODE, 0);
	if (!state)
		return 0;

	state->next_slot = 1;
	state->_pad = 0;
	old = __sync_val_compare_and_swap(&exec_state, 0, state);
	if (old) {
		bpf_arena_free_pages(&exec_arena, state, EXEC_STATE_PAGES);
		return old;
	}

	return state;
}

static __always_inline struct exec_entry __arena *
exec_entry_by_index(struct exec_arena_state __arena *state, __u32 idx)
{
	if (!state || idx == 0 || idx > EXEC_MAX_EDGES)
		return 0;
	return &state->entries[idx];
}

static __always_inline struct exec_entry __arena *
exec_table_lookup(struct exec_arena_state __arena *state,
		  struct exec_bucket __arena *bucket,
		  const struct exec_edge_key *key)
{
	struct exec_entry __arena *entry;
	__u32 idx;
	int i;

	idx = bucket->head_idx;

#pragma clang loop unroll(disable)
	for (i = 0; i < EXEC_MAX_LOOKUP_STEPS; i++) {
		if (idx == 0 || idx > EXEC_MAX_EDGES)
			break;

		entry = &state->entries[idx];
		if (entry->used && exec_edge_key_equal_arena(&entry->key, key))
			return entry;
		idx = entry->next_idx;
	}

	return 0;
}

static __always_inline __u32
exec_entry_alloc(struct exec_arena_state __arena *state, __u16 bucket_idx,
		 const struct exec_edge_key *key, const char *name,
		 __u32 name_len, __u64 now)
{
	struct exec_entry __arena *entry;
	__u32 idx;

	idx = __sync_fetch_and_add(&state->next_slot, 1);
	if (idx == 0 || idx > EXEC_MAX_EDGES)
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
	entry->key.parent_uid.ino = key->parent_uid.ino;
	entry->key.parent_uid.dev = key->parent_uid.dev;
	entry->key.parent_uid._pad = 0;
	entry->key.parent_present = key->parent_present;
	entry->stats.exec_count = 1;
	entry->stats.last_exec_ns = now;
	entry->stats.name_len = name_len;
	entry->stats._pad[0] = 0;
	entry->stats._pad[1] = 0;
	entry->stats._pad[2] = 0;
	entry->stats._pad[3] = 0;
	exec_name_copy_to_arena(entry->stats.name, name);

	return idx;
}

static __always_inline void exec_entry_touch(struct exec_entry __arena *entry,
					     const char *name, __u32 name_len,
					     __u64 now)
{
	__sync_fetch_and_add(&entry->stats.exec_count, 1);
	entry->stats.last_exec_ns = now;
	entry->stats.name_len = name_len;
	exec_name_copy_to_arena(entry->stats.name, name);
	exec_pending_set(&entry->pending);
}

static __always_inline void exec_name_copy(char *dst, const char *src)
{
	__u32 i;

#pragma clang loop unroll(full)
	for (i = 0; i < EXEC_NAME_LEN; i++)
		dst[i] = src[i];
}

static __always_inline void exec_map_entry_touch(
	struct exec_entry *entry, const char *name, __u32 name_len, __u64 now)
{
	__sync_fetch_and_add(&entry->stats.exec_count, 1);
	entry->stats.last_exec_ns = now;
	entry->stats.name_len = name_len;
	exec_name_copy(entry->stats.name, name);
	__sync_fetch_and_or(&entry->pending, 1);
}

static __always_inline void exec_table_touch(
	const struct exec_uid *uid, const struct exec_uid *parent_uid,
	bool parent_present, const char *name, __u32 name_len, __u64 now)
{
	struct exec_entry *entry;
	struct exec_edge_key key;
	__u32 idx;

	exec_edge_key_init(&key, uid, parent_uid, parent_present);
	idx = exec_edge_hash(&key) & (EXEC_BUCKETS - 1);
	entry = bpf_map_lookup_elem(&obs_i_exec_entries, &idx);
	if (!entry)
		return;
	if (entry->used && entry->key.uid.ino == key.uid.ino &&
	    entry->key.uid.dev == key.uid.dev &&
	    entry->key.parent_present == key.parent_present &&
	    (!key.parent_present ||
	     (entry->key.parent_uid.ino == key.parent_uid.ino &&
	      entry->key.parent_uid.dev == key.parent_uid.dev))) {
		exec_map_entry_touch(entry, name, name_len, now);
		return;
	}

	entry->next_idx = 0;
	entry->bucket_idx = idx;
	entry->used = 1;
	entry->_pad0 = 0;
	entry->pending = 1;
	entry->key = key;
	entry->stats.exec_count = 1;
	entry->stats.last_exec_ns = now;
	entry->stats.name_len = name_len;
	exec_name_copy(entry->stats.name, name);
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

	if (slots > EXEC_SERIAL_SLOTS_PER_PAGE)
		return -ENOSPC;

	page_bytes = slots * EXEC_SERIAL_SLOT_SIZE;
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
	if (page_slot >= EXEC_SERIAL_SLOTS_PER_PAGE)
		return 0;

	off = page_slot * EXEC_SERIAL_SLOT_SIZE;
	barrier_var(off);
	if (off > SHIRUDO_SERIAL_CHUNK_PAYLOAD - EXEC_SERIAL_SLOT_SIZE)
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

	*(__u32 *)&chunk->data[off] = EXEC_SERIAL_MAGIC;
	*(__u16 *)&chunk->data[off + 4] = EXEC_SERIAL_VERSION;
	*(__u16 *)&chunk->data[off + 6] = EXEC_SERIAL_HEADER_SIZE;
	*(__u16 *)&chunk->data[off + 8] = EXEC_BUCKETS;
	*(__u16 *)&chunk->data[off + 10] = EXEC_MAX_LOOKUP_STEPS;
	*(__u16 *)&chunk->data[off + 12] = EXEC_SERIAL_SLOT_SIZE;
	*(__u16 *)&chunk->data[off + 14] = EXEC_SERIAL_RECORDS;
	*(__u32 *)&chunk->data[off + 16] =
		EXEC_SERIAL_HEADER_HAS_NAME | EXEC_SERIAL_HEADER_HAS_PARENT;
	*(__u32 *)&chunk->data[off + 20] =
		((__u32)EXEC_SERIAL_SLOTS_PER_RECORD << 16) | EXEC_NAME_LEN;
	*(__u32 *)&chunk->data[off + 24] = sizeof(struct exec_edge_key);
	*(__u32 *)&chunk->data[off + 28] = sizeof(struct exec_edge_stats);
	return 0;
}

static __always_inline void serial_associate_arena(void)
{
	(void)bpf_arena_alloc_pages(&exec_arena, 0, 0, NUMA_NO_NODE, 0);
}

static __always_inline int
serial_emit_record(__u32 page_slot, __u32 record_idx,
		   const struct exec_entry *entry)
{
	struct shirudo_serial_chunk *chunk;
	__u32 off, i;
	__u8 flags;

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

	flags = EXEC_SERIAL_RECORD_PRESENT;
	if (entry->key.parent_present)
		flags |= EXEC_SERIAL_RECORD_HAS_PARENT;

	*(__u16 *)&chunk->data[off + 4] = entry->bucket_idx;
	chunk->data[off + 6] = flags;
	*(__u32 *)&chunk->data[off + 8] = entry->stats.name_len;
	*(__u32 *)&chunk->data[off + 12] = entry->key.uid.dev;
	*(__u32 *)&chunk->data[off + 16] = entry->key.parent_uid.dev;
	*(__u64 *)&chunk->data[off + 24] = entry->key.uid.ino;
	*(__u64 *)&chunk->data[off + 32] = entry->key.parent_uid.ino;
	*(__u64 *)&chunk->data[off + 40] = entry->stats.exec_count;
	*(__u64 *)&chunk->data[off + 48] = entry->stats.last_exec_ns;
#pragma clang loop unroll(full)
	for (i = 0; i < EXEC_NAME_LEN; i++)
		chunk->data[off + 56 + i] = entry->stats.name[i];
	return 0;
}

struct exec_serial_emit_ctx {
	__u32 start;
	__u32 output_slots;
	__u32 next;
	int rc;
};

static int serial_emit_slot_cb(__u32 scanned, void *data)
{
	struct exec_serial_emit_ctx *emit = data;
	struct exec_entry *entry;
	__u32 record_idx;
	__u32 key;
	int rc;

	if (emit->rc)
		return 1;

	record_idx = emit->start + scanned;
	if (record_idx >= EXEC_SERIAL_RECORDS) {
		emit->next = EXEC_SERIAL_RECORDS;
		return 1;
	}

	if (emit->output_slots >= EXEC_SERIAL_SLOTS_PER_PAGE) {
		emit->next = record_idx;
		return 1;
	}
	emit->next = record_idx + 1;
	key = record_idx;
	entry = bpf_map_lookup_elem(&obs_i_exec_entries, &key);
	if (!entry)
		return 0;
	if (!entry->used)
		return 0;
	if (!exec_pending_take_map(&entry->pending))
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
int shirudo_serialize__exec_arena(struct shirudo_serialize_ctx *ctx)
{
	struct exec_serial_emit_ctx emit = {};
	struct shirudo_serial_chunk *chunk;
	__u32 start, scan, flags = 0, key = 0;
	__u64 next_cursor;
	int rc;

	if (!ctx || ctx->magic != SHIRUDO_SERIAL_MAGIC ||
	    ctx->version != SHIRUDO_SERIAL_VERSION ||
	    ctx->chunk_payload_size != SHIRUDO_SERIAL_CHUNK_PAYLOAD)
		return -EINVAL;
	if (ctx->max_chunks < EXEC_SERIAL_PAGE_CHUNKS) {
		serial_set_error(ctx, -E2BIG);
		return -E2BIG;
	}
	if (ctx->cursor > EXEC_SERIAL_RECORDS) {
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

	emit.start = start;
	emit.output_slots = 1;
	emit.next = start;
	scan = EXEC_SERIAL_RECORDS - start;
	rc = bpf_loop(scan, serial_emit_slot_cb, &emit, 0);
	if (rc < 0) {
		serial_set_error(ctx, rc);
		return rc;
	}
	if (emit.rc) {
		serial_set_error(ctx, emit.rc);
		return emit.rc;
	}

	next_cursor = emit.next;
	if (next_cursor >= EXEC_SERIAL_RECORDS)
		flags = SHIRUDO_SERIAL_F_DONE;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk) {
		serial_set_error(ctx, -EINVAL);
		return -EINVAL;
	}
	chunk->flags = flags;
	chunk->bytes_total = emit.output_slots * EXEC_SERIAL_SLOT_SIZE;
	chunk->bytes_in_chunk = chunk->bytes_total;
	chunk->next_cursor = next_cursor;

	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(track_exec_uid, struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct file *file;
	struct exec_uid uid = {};
	struct exec_uid parent_uid = {};
	char exec_name[EXEC_NAME_LEN] = {};
	bool parent_present;
	__u32 name_len;
	__u64 now;

	file = BPF_CORE_READ(bprm, file);
	if (!file)
		file = BPF_CORE_READ(task, mm, exe_file);
	if (exec_uid_from_file(file, &uid)) {
		task_exec_delete(task);
		return 0;
	}
	name_len = exec_name_from_file(file, exec_name);
	now = bpf_ktime_get_ns();
	parent_present = task_exec_parent_uid(task, &parent_uid);
	exec_table_touch(&uid, &parent_uid, parent_present, exec_name,
			 name_len, now);
	task_exec_set(task, &uid);
	return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(track_task_exec_clone, struct task_struct *child, __u64 clone_flags)
{
	struct task_struct *parent = bpf_get_current_task_btf();
	struct exec_uid uid = {};

	(void)clone_flags;

	if (task_exec_current_uid(parent, &uid)) {
		task_exec_set(child, &uid);
	}

	return 0;
}
