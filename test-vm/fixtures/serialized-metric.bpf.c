// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "shirudo_decoder.h"
#include "shirudo_serializer.h"

#define EINVAL 22

char _license[] SEC("license") = "Dual BSD/GPL";

struct counter_value { __u64 packets; __u64 bytes; };
struct counter_record {
	__u32 key;
	__u32 reserved;
	__u64 packets;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct counter_value);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");

const struct shirudo_decoder_manifest counters_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_METRIC,
	.upatch = "shirudo-test-serialized-metric",
	.map = "counters",
	.source = "decoders/counters.lua",
	.entrypoint = "decode",
};

SEC("syscall")
int shirudo_serialize__counters(struct shirudo_serialize_ctx *ctx)
{
	struct shirudo_serial_chunk *chunk;
	struct counter_value *value;
	struct counter_record record = {};
	__u32 key, output_key = 0;

	if (!ctx || ctx->magic != SHIRUDO_SERIAL_MAGIC ||
	    ctx->version != SHIRUDO_SERIAL_VERSION || ctx->max_chunks < 1 ||
	    ctx->chunk_payload_size != SHIRUDO_SERIAL_CHUNK_PAYLOAD ||
	    ctx->page_index != 0 || ctx->cursor != 0 || ctx->invocation_id == 0)
		return -EINVAL;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &output_key);
	if (!chunk)
		return -EINVAL;
	key = 0;
	value = bpf_map_lookup_elem(&counters, &key);
	if (!value)
		return -EINVAL;
	value->packets = 7;
	value->bytes = 100;
	record.key = key;
	record.packets = value->packets;
	record.bytes = value->bytes;
	__builtin_memcpy(&chunk->data[0], &record, sizeof(record));
	key = 1;
	value = bpf_map_lookup_elem(&counters, &key);
	if (!value)
		return -EINVAL;
	value->packets = 3;
	value->bytes = 50;
	record.key = key;
	record.packets = value->packets;
	record.bytes = value->bytes;
	__builtin_memcpy(&chunk->data[sizeof(record)], &record, sizeof(record));
	chunk->magic = SHIRUDO_SERIAL_MAGIC;
	chunk->version = SHIRUDO_SERIAL_VERSION;
	chunk->flags = SHIRUDO_SERIAL_F_DONE;
	chunk->status = 0;
	chunk->chunk_index = 0;
	chunk->total_chunks = 1;
	chunk->bytes_total = 2 * sizeof(record);
	chunk->bytes_in_chunk = 2 * sizeof(record);
	chunk->page_index = ctx->page_index;
	chunk->reserved = 0;
	chunk->cursor = ctx->cursor;
	chunk->next_cursor = 2;
	chunk->invocation_id = ctx->invocation_id;
	return 0;
}
