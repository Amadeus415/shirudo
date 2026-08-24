/* SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0) */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * ABI for upatch-local map serializers. Serializer programs are
 * SEC("syscall") BPF programs named shirudo_serialize__<map_name>.
 */

#ifndef SHIRUDO_SERIALIZER_H
#define SHIRUDO_SERIALIZER_H

#define SHIRUDO_SERIAL_MAP_NAME		"shirudo_ser"
#define SHIRUDO_SERIAL_MAGIC		0x5a4c5253u	/* "SRLZ" le */
#define SHIRUDO_SERIAL_VERSION		3u
#define SHIRUDO_SERIAL_MAP_NAME_MAX	16u
#define SHIRUDO_SERIAL_MAX_CHUNKS	256u
#define SHIRUDO_SERIAL_MAX_PAGES	256u
#define SHIRUDO_SERIAL_F_DONE		(1u << 0)

/*
 * Keep the syscall test-run context within the older five-u64 argument
 * limit. Page result metadata lives in struct shirudo_serial_chunk.
 */
#define SHIRUDO_SERIAL_CTX_MAX_BYTES	40u

/*
 * Keep the chunk value at exactly 4096 bytes: a 64-byte header plus
 * payload. This is friendly to map value allocation and easy to inspect.
 */
#define SHIRUDO_SERIAL_CHUNK_PAYLOAD	4032u

struct shirudo_serialize_ctx {
	uint32_t	magic;
	uint32_t	version;
	uint32_t	flags;
	uint32_t	max_chunks;
	uint32_t	chunk_payload_size;
	uint32_t	page_index;
	uint64_t	cursor;
	uint64_t	invocation_id;
};

struct shirudo_serial_chunk {
	uint32_t	magic;
	uint32_t	version;
	uint32_t	flags;
	int		status;
	uint32_t	chunk_index;
	uint32_t	total_chunks;
	uint32_t	bytes_total;
	uint32_t	bytes_in_chunk;
	uint32_t	page_index;
	uint32_t	reserved;
	uint64_t	cursor;
	uint64_t	next_cursor;
	uint64_t	invocation_id;
	unsigned char	data[SHIRUDO_SERIAL_CHUNK_PAYLOAD];
};

_Static_assert(sizeof(struct shirudo_serialize_ctx) ==
	       SHIRUDO_SERIAL_CTX_MAX_BYTES,
	       "serializer context ABI size changed");
_Static_assert(sizeof(struct shirudo_serial_chunk) == 4096,
	       "serializer chunk ABI must remain one page");

#endif /* SHIRUDO_SERIALIZER_H */
