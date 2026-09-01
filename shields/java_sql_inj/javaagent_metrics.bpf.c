// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
/*
 * javaagent_metrics.bpf.c -- telemetry sink for userspace Java agents.
 *
 * The Java agent supplies a stable JAR id and a monotonically assigned hook
 * id through BPF_PROG_TEST_RUN.  The syscall program adds the event to an
 * arena-backed cumulative counter keyed by the current executable's device
 * and inode.  This keeps the Java path independent of kernel hook points
 * while still giving the normal Shirudo map serializer a process identity.
 */

#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "shirudo_decoder.h"
#include "shirudo_serializer.h"

#if !defined(__BPF_FEATURE_ADDR_SPACE_CAST)
#error "BPF arena access requires clang address-space cast support"
#endif

#define __arena __attribute__((address_space(1))) \
		__attribute__((btf_type_tag("arena")))
#define NUMA_NO_NODE (-1)

#define EINVAL 22
#define ENOSPC 28

#define JAVAAGENT_BUCKETS 512
#define JAVAAGENT_MAX_RECORDS 1024
#define JAVAAGENT_MAX_LOOKUP_STEPS 16
#define JAVAAGENT_SERIAL_RECORD_PRESENT (1u << 0)
#define JAVAAGENT_SERIAL_SLOTS_PER_PAGE 32

char _license[] SEC("license") = "Dual BSD/GPL";

struct javaagent_key {
	__u64 jar_id;
	__u64 hook_id;
	__u64 executable_ino;
	__u32 executable_dev;
	__u32 _pad;
};

struct javaagent_value {
	__u64 count;
	__u64 last_seen_ns;
};

struct javaagent_entry {
	__u32 next_idx;
	__u16 bucket_idx;
	__u8 used;
	__u8 _pad0;
	__u32 pending;
	struct javaagent_key key;
	struct javaagent_value value;
};

struct javaagent_bucket {
	__u32 head_idx;
	__u32 _pad;
};

struct javaagent_state {
	__u32 next_slot;
	__u32 _pad;
	struct javaagent_bucket buckets[JAVAAGENT_BUCKETS];
	struct javaagent_entry entries[JAVAAGENT_MAX_RECORDS + 1];
};

struct javaagent_test_ctx {
	__u64 jar_id;
	__u64 hook_id;
};

struct javaagent_serial_record {
	__u64 jar_id;
	__u64 hook_id;
	__u64 executable_ino;
	__u32 executable_dev;
	__u32 flags;
	__u64 count;
	__u64 last_seen_ns;
};

struct javaagent_serial_header {
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
	__u32 reserved0;
	__u64 reserved1;
	__u64 reserved2;
};

_Static_assert(sizeof(struct javaagent_serial_record) == 48,
		       "Java-agent serialized record ABI changed");
_Static_assert(sizeof(struct javaagent_serial_header) == 48,
		       "Java-agent serialized header ABI changed");

enum {
	JAVAAGENT_STATE_PAGES =
		(sizeof(struct javaagent_state) + 4095) / 4096,
	JAVAAGENT_SERIAL_SLOT_SIZE = sizeof(struct javaagent_serial_record),
	JAVAAGENT_SERIAL_SLOTS_PER_CHUNK =
		SHIRUDO_SERIAL_CHUNK_PAYLOAD / JAVAAGENT_SERIAL_SLOT_SIZE,
};

_Static_assert(JAVAAGENT_SERIAL_SLOTS_PER_CHUNK >=
		       JAVAAGENT_SERIAL_SLOTS_PER_PAGE,
		       "Java-agent serializer page does not fit a chunk");

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 64); /* pages reserved for one system agent */
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	enum { javaagent_map_extra = 1ULL << 32 } map_extra;
#else
	enum { javaagent_map_extra = 1ULL << 44 } map_extra;
#endif
} javaagent_arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");

const struct shirudo_decoder_manifest javaagent_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_METRIC,
	.upatch = "javaagent_metrics",
	.map = "javaagent_arena",
	.source = "decoders/javaagent.lua",
	.entrypoint = "decode",
};

void __arena *bpf_arena_alloc_pages(void *map, void __arena *addr,
				    __u32 page_cnt, int node_id,
				    __u64 flags) __ksym __weak;
void bpf_arena_free_pages(void *map, void __arena *ptr,
				  __u32 page_cnt) __ksym __weak;

static struct javaagent_state __arena *javaagent_state;

static __always_inline __u64 javaagent_hash_mix(__u64 h, __u64 v)
{
	h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	return h;
}

static __always_inline __u32 javaagent_hash(const struct javaagent_key *key)
{
	__u64 h = javaagent_hash_mix(0, key->jar_id);

	h = javaagent_hash_mix(h, key->hook_id);
	h = javaagent_hash_mix(h, key->executable_ino);
	h = javaagent_hash_mix(h, key->executable_dev);
	return (__u32)h;
}

static __always_inline struct javaagent_state __arena *
javaagent_table_init(void)
{
	struct javaagent_state __arena *state, *old;

	state = javaagent_state;
	if (state)
		return state;
	state = bpf_arena_alloc_pages(&javaagent_arena, 0,
					     JAVAAGENT_STATE_PAGES,
					     NUMA_NO_NODE, 0);
	if (!state)
		return 0;
	state->next_slot = 1;
	state->_pad = 0;
	old = __sync_val_compare_and_swap(&javaagent_state, 0, state);
	if (old) {
		bpf_arena_free_pages(&javaagent_arena, state,
				      JAVAAGENT_STATE_PAGES);
		return old;
	}
	return state;
}

static __always_inline bool javaagent_current_executable(
	struct javaagent_key *key)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct file *file;
	struct inode *inode;
	struct super_block *super;

	if (!task)
		return false;
	file = BPF_CORE_READ(task, mm, exe_file);
	if (!file)
		return false;
	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return false;
	super = BPF_CORE_READ(inode, i_sb);
	if (!super)
		return false;
	key->executable_ino = BPF_CORE_READ(inode, i_ino);
	key->executable_dev = BPF_CORE_READ(super, s_dev);
	key->_pad = 0;
	return key->executable_ino != 0;
}

static __always_inline void javaagent_mark_pending(
	struct javaagent_entry __arena *entry)
{
	__u32 old = entry->pending;

	if (!old)
		(void)__sync_val_compare_and_swap(&entry->pending, old, 1);
}

static __always_inline struct javaagent_entry __arena *
javaagent_lookup(struct javaagent_state __arena *state,
			struct javaagent_bucket __arena *bucket,
			const struct javaagent_key *key)
{
	struct javaagent_entry __arena *entry;
	__u32 idx = bucket->head_idx;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < JAVAAGENT_MAX_LOOKUP_STEPS; i++) {
		if (idx == 0 || idx > JAVAAGENT_MAX_RECORDS)
			break;
		entry = &state->entries[idx];
		if (entry->used && entry->key.jar_id == key->jar_id &&
		    entry->key.hook_id == key->hook_id &&
		    entry->key.executable_ino == key->executable_ino &&
		    entry->key.executable_dev == key->executable_dev)
			return entry;
		idx = entry->next_idx;
	}
	return 0;
}

static __always_inline struct javaagent_entry __arena *
javaagent_insert(struct javaagent_state __arena *state, __u32 bucket_idx,
			 const struct javaagent_key *key, __u64 now)
{
	struct javaagent_entry __arena *entry;
	struct javaagent_bucket __arena *bucket = &state->buckets[bucket_idx];
	__u32 idx, old_head;
	int i;

	idx = __sync_fetch_and_add(&state->next_slot, 1);
	if (idx == 0 || idx > JAVAAGENT_MAX_RECORDS)
		return 0;
	entry = &state->entries[idx];
	entry->next_idx = 0;
	entry->bucket_idx = bucket_idx;
	entry->used = 0;
	entry->_pad0 = 0;
	entry->pending = 1;
	entry->key = *key;
	entry->value.count = 1;
	entry->value.last_seen_ns = now;

	/* Publish the new node at the bucket head. */
#pragma clang loop unroll(disable)
	for (i = 0; i < 2; i++) {
		old_head = bucket->head_idx;
		entry->next_idx = old_head;
		if (__sync_val_compare_and_swap(&bucket->head_idx, old_head,
						idx) == old_head) {
			entry->used = 1;
			return entry;
		}
	}
	entry->used = 0;
	return 0;
}

static __always_inline void javaagent_record(const struct javaagent_test_ctx *ctx)
{
	struct javaagent_state __arena *state;
	struct javaagent_bucket __arena *bucket;
	struct javaagent_entry __arena *entry;
	struct javaagent_key key = {};
	__u32 bucket_idx;
	__u64 now;

	if (!ctx || !ctx->jar_id || !ctx->hook_id)
		return;
	key.jar_id = ctx->jar_id;
	key.hook_id = ctx->hook_id;
	if (!javaagent_current_executable(&key))
		return;
	state = javaagent_table_init();
	if (!state)
		return;
	bucket_idx = javaagent_hash(&key) & (JAVAAGENT_BUCKETS - 1);
	bucket = &state->buckets[bucket_idx];
	now = bpf_ktime_get_ns();
	entry = javaagent_lookup(state, bucket, &key);
	if (entry) {
		__sync_fetch_and_add(&entry->value.count, 1);
		entry->value.last_seen_ns = now;
		javaagent_mark_pending(entry);
		return;
	}
	(void)javaagent_insert(state, bucket_idx, &key, now);
}

static __always_inline struct shirudo_serial_chunk *
javaagent_serial_chunk(__u32 slot, __u32 *off_out)
{
	struct shirudo_serial_chunk *chunk;
	__u32 key = 0, off;

	if (slot >= JAVAAGENT_SERIAL_SLOTS_PER_PAGE)
		return 0;
	off = slot * JAVAAGENT_SERIAL_SLOT_SIZE;
	if (off > SHIRUDO_SERIAL_CHUNK_PAYLOAD -
			JAVAAGENT_SERIAL_SLOT_SIZE)
		return 0;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return 0;
	*off_out = off;
	return chunk;
}

static __always_inline int javaagent_serial_init(__u64 cursor,
						 __u32 page_index,
						 __u64 invocation_id)
{
	struct shirudo_serial_chunk *chunk;
	__u32 key = 0;

	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return -ENOSPC;
	chunk->magic = SHIRUDO_SERIAL_MAGIC;
	chunk->version = SHIRUDO_SERIAL_VERSION;
	chunk->flags = 0;
	chunk->status = 0;
	chunk->chunk_index = 0;
	chunk->total_chunks = 1;
	chunk->bytes_total = JAVAAGENT_SERIAL_SLOT_SIZE;
	chunk->bytes_in_chunk = JAVAAGENT_SERIAL_SLOT_SIZE;
	chunk->page_index = page_index;
	chunk->reserved = 0;
	chunk->cursor = cursor;
	chunk->next_cursor = cursor;
	chunk->invocation_id = invocation_id;
	return 0;
}

static __always_inline int javaagent_serial_header(void)
{
	struct javaagent_serial_header header = {
		.magic = 0x4a41564du,
		.version = 1,
		.header_size = sizeof(struct javaagent_serial_header),
		.bucket_count = JAVAAGENT_BUCKETS,
		.max_lookup_steps = JAVAAGENT_MAX_LOOKUP_STEPS,
		.record_size = JAVAAGENT_SERIAL_SLOT_SIZE,
		.record_count = JAVAAGENT_MAX_RECORDS,
		.key_size = sizeof(struct javaagent_key),
		.value_size = sizeof(struct javaagent_value),
	};
	struct shirudo_serial_chunk *chunk;
	__u32 off;

	chunk = javaagent_serial_chunk(0, &off);
	if (!chunk)
		return -ENOSPC;
	__builtin_memcpy(&chunk->data[off], &header, sizeof(header));
	return 0;
}

static __always_inline struct javaagent_entry __arena *
javaagent_serial_entry(struct javaagent_state __arena *state, __u32 index)
{
	struct javaagent_entry __arena *entry;

	if (!state || index >= JAVAAGENT_MAX_RECORDS)
		return 0;
	entry = &state->entries[index + 1];
	return entry->used ? entry : 0;
}

static __always_inline int javaagent_serial_record(__u32 slot, __u32 index,
						   struct javaagent_entry __arena *entry)
{
	struct javaagent_serial_record record = {};
	struct shirudo_serial_chunk *chunk;
	__u32 off;

	chunk = javaagent_serial_chunk(slot, &off);
	if (!chunk)
		return -ENOSPC;
	record.flags = entry ? JAVAAGENT_SERIAL_RECORD_PRESENT : 0;
	if (entry) {
		record.jar_id = entry->key.jar_id;
		record.hook_id = entry->key.hook_id;
		record.executable_ino = entry->key.executable_ino;
		record.executable_dev = entry->key.executable_dev;
		record.count = entry->value.count;
		record.last_seen_ns = entry->value.last_seen_ns;
	}
	(void)index;
	__builtin_memcpy(&chunk->data[off], &record, sizeof(record));
	return 0;
}

struct javaagent_serial_emit_ctx {
	struct javaagent_state __arena *state;
	__u32 start;
	__u32 output_slots;
	__u32 next;
	int rc;
};

static int javaagent_serial_emit_cb(__u32 scanned, void *data)
{
	struct javaagent_serial_emit_ctx *emit = data;
	struct javaagent_entry __arena *entry;
	__u32 index;

	if (emit->rc)
		return 1;
	index = emit->start + scanned;
	if (index >= JAVAAGENT_MAX_RECORDS) {
		emit->next = JAVAAGENT_MAX_RECORDS;
		return 1;
	}
	if (emit->output_slots >= JAVAAGENT_SERIAL_SLOTS_PER_PAGE) {
		emit->next = index;
		return 1;
	}
	emit->next = index + 1;
	entry = javaagent_serial_entry(emit->state, index);
	if (!entry)
		return 0;
	if (__sync_val_compare_and_swap(&entry->pending, 1, 0) != 1)
		return 0;
	emit->rc = javaagent_serial_record(emit->output_slots, index, entry);
	if (emit->rc)
		return 1;
	emit->output_slots++;
	return 0;
}

SEC("syscall")
int shirudo_test__j(struct javaagent_test_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;
	if (!ctx->jar_id && !ctx->hook_id) {
		return javaagent_table_init() ? 0 : -ENOSPC;
	}
	if (!ctx->jar_id || !ctx->hook_id)
		return -EINVAL;
	javaagent_record(ctx);
	return 0;
}

SEC("syscall")
int shirudo_serialize__javaagent_arena(struct shirudo_serialize_ctx *ctx)
{
	struct javaagent_serial_emit_ctx emit = {};
	struct javaagent_state __arena *state;
	struct shirudo_serial_chunk *chunk;
	__u32 start, scan, key = 0;
	__u64 next_cursor;
	int rc;

	if (!ctx || ctx->magic != SHIRUDO_SERIAL_MAGIC ||
	    ctx->version != SHIRUDO_SERIAL_VERSION ||
	    ctx->chunk_payload_size != SHIRUDO_SERIAL_CHUNK_PAYLOAD ||
	    ctx->max_chunks < 1 || ctx->cursor > JAVAAGENT_MAX_RECORDS)
		return -EINVAL;
	rc = javaagent_serial_init(ctx->cursor, ctx->page_index,
					   ctx->invocation_id);
	if (rc)
		return rc;
	rc = javaagent_serial_header();
	if (rc)
		return rc;
	(void)bpf_arena_alloc_pages(&javaagent_arena, 0, 0, NUMA_NO_NODE, 0);
	state = javaagent_state;
	start = (__u32)ctx->cursor;
	emit.state = state;
	emit.start = start;
	emit.output_slots = 1;
	emit.next = start;
	if (!state) {
		emit.next = JAVAAGENT_MAX_RECORDS;
	} else {
		scan = JAVAAGENT_MAX_RECORDS - start;
		rc = bpf_loop(scan, javaagent_serial_emit_cb, &emit, 0);
		if (rc < 0)
			return rc;
		if (emit.rc)
			return emit.rc;
	}

	next_cursor = emit.next;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return -EINVAL;
	chunk->flags = next_cursor >= JAVAAGENT_MAX_RECORDS ?
		SHIRUDO_SERIAL_F_DONE : 0;
	chunk->bytes_total = emit.output_slots * JAVAAGENT_SERIAL_SLOT_SIZE;
	chunk->bytes_in_chunk = chunk->bytes_total;
	chunk->next_cursor = next_cursor;
	return 0;
}
