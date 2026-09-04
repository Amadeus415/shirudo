// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
/*
 * linux-observability.bpf.c -- combined exec, TCP, UDP, and DNS telemetry.
 *
 * The domain implementations remain in the neighbouring files, but are
 * included here so all hooks share task executable storage and one serializer
 * output map.
 */

#define LINUX_OBS_COMBINED

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "shirudo_decoder.h"
#include "shirudo_serializer.h"

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 4096);
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	enum { obs_map_extra = 1ULL << 32 } map_extra;
#else
	enum { obs_map_extra = 1ULL << 44 } map_extra;
#endif
} obs_i_arena SEC(".maps");

/*
 * The exporter associates serializers with named maps. libbpf permits only
 * one ARENA map per object, so these five one-slot public views provide the
 * stable map names while the actual records live in obs_i_arena.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} exec_arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} tcp_arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} udp_arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} dns_arena SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} ipv4_shields SEC(".maps");

#define exec_arena obs_i_arena
#define tcp_arena obs_i_arena
#define udp_arena obs_i_arena
#define dns_arena obs_i_arena
#define ipv4_shields obs_i_arena

const struct shirudo_decoder_manifest exec_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_LOG,
	.upatch = "linux-observability",
	.map = "exec_arena",
	.source = "decoders/exec.lua",
	.entrypoint = "decode",
};

const struct shirudo_decoder_manifest tcp_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_LOG,
	.upatch = "linux-observability",
	.map = "tcp_arena",
	.source = "decoders/tcp.lua",
	.entrypoint = "decode",
};

const struct shirudo_decoder_manifest udp_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_LOG,
	.upatch = "linux-observability",
	.map = "udp_arena",
	.source = "decoders/udp.lua",
	.entrypoint = "decode",
};

const struct shirudo_decoder_manifest dns_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_LOG,
	.upatch = "linux-observability",
	.map = "dns_arena",
	.source = "decoders/dns.lua",
	.entrypoint = "decode",
};

#include "ipv4_shields_arena.bpf.c"
#undef ipv4_shields

#define serial_set_error exec_serial_set_error
#define serial_init_page_chunk exec_serial_init_page_chunk
#define serial_init_page_chunks exec_serial_init_page_chunks
#define serial_chunk_for_slot exec_serial_chunk_for_slot
#define serial_emit_header exec_serial_emit_header
#define serial_associate_arena exec_serial_associate_arena
#define serial_entry_at exec_serial_entry_at
#define serial_emit_record exec_serial_emit_record
#define serial_emit_slot_cb exec_serial_emit_slot_cb
#include "exec_uid_arena.bpf.c"
#undef serial_emit_slot_cb
#undef serial_emit_record
#undef serial_entry_at
#undef serial_associate_arena
#undef serial_emit_header
#undef serial_chunk_for_slot
#undef serial_init_page_chunks
#undef serial_init_page_chunk
#undef serial_set_error

#define serial_set_error tcp_serial_set_error
#define serial_init_page_chunk tcp_serial_init_page_chunk
#define serial_chunk_for_slot tcp_serial_chunk_for_slot
#define serial_emit_header tcp_serial_emit_header
#define serial_associate_arena tcp_serial_associate_arena
#define serial_entry_at tcp_serial_entry_at
#define serial_emit_record tcp_serial_emit_record
#define serial_emit_slot_cb tcp_serial_emit_slot_cb
#include "tcp_connect_arena.bpf.c"
#undef serial_emit_slot_cb
#undef serial_emit_record
#undef serial_entry_at
#undef serial_associate_arena
#undef serial_emit_header
#undef serial_chunk_for_slot
#undef serial_init_page_chunk
#undef serial_set_error

#define serial_set_error udp_serial_set_error
#define serial_init_page_chunk udp_serial_init_page_chunk
#define serial_chunk_for_slot udp_serial_chunk_for_slot
#define serial_emit_header udp_serial_emit_header
#define serial_associate_arena udp_serial_associate_arena
#define serial_entry_at udp_serial_entry_at
#define serial_emit_record udp_serial_emit_record
#define serial_emit_slot_cb udp_serial_emit_slot_cb
#include "udp_arena.bpf.c"
#undef serial_emit_slot_cb
#undef serial_emit_record
#undef serial_entry_at
#undef serial_associate_arena
#undef serial_emit_header
#undef serial_chunk_for_slot
#undef serial_init_page_chunk
#undef serial_set_error

#define serial_set_error dns_serial_set_error
#define serial_init_page_chunks dns_serial_init_page_chunks
#define serial_chunk_for_slot dns_serial_chunk_for_slot
#define serial_emit_header dns_serial_emit_header
#define serial_associate_arena dns_serial_associate_arena
#define serial_entry_at dns_serial_entry_at
#define serial_emit_record dns_serial_emit_record
#define serial_emit_slot_cb dns_serial_emit_slot_cb
#include "dns_arena.bpf.c"
#undef serial_emit_slot_cb
#undef serial_emit_record
#undef serial_entry_at
#undef serial_associate_arena
#undef serial_emit_header
#undef serial_chunk_for_slot
#undef serial_init_page_chunks
#undef serial_set_error
