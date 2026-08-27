/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Userspace upatch map decoders.
 */

#ifndef SHIRUDO_UTIL_UPATCH_DECODE_H
#define SHIRUDO_UTIL_UPATCH_DECODE_H

#include <stddef.h>
#include <stdint.h>

struct shirudo_map_view;

/*
 * Try to decode a complete map view with a signed decoder embedded in
 * /var/lib/shirudo/upatches/<upatch>.upatch.
 *
 * On success, *out receives an xmalloc-owned JSON document and *out_len
 * receives strlen(*out). Free with xfree(*out, *out_len + 1).
 *
 * Returns:
 *   0        decoded
 *  -ENOENT  no usable decoder; export callers must fail the map
 *  -errno   decoder/runtime error; caller should report failure
 */
int shirudo_upatch_decode_map_json(const struct shirudo_map_view *v,
				   char **out, size_t *out_len);

/* Variant for consumers such as S3 archival with a larger output budget. */
int shirudo_upatch_decode_map_json_limit(const struct shirudo_map_view *v,
					 size_t max_bytes,
					 char **out, size_t *out_len);

/*
 * Decode the map and encode the Lua return value as an OTLP AnyValue JSON
 * fragment. The caller owns *out as above. Return values match the JSON API.
 */
int shirudo_upatch_decode_map_otel(const struct shirudo_map_view *v,
				   char **out, size_t *out_len);

/* Explicit-artifact variants used by offline consumers and tests. */
int shirudo_upatch_decode_map_file_json(const char *path,
					const struct shirudo_map_view *v,
					char **out, size_t *out_len);
int shirudo_upatch_decode_map_file_json_limit(
					const char *path, const struct shirudo_map_view *v,
					size_t max_bytes, char **out, size_t *out_len);
int shirudo_upatch_decode_map_file_otel(const char *path,
					const struct shirudo_map_view *v,
					char **out, size_t *out_len);

/* Return the static, signature-covered export signal of the matching decoder. */
int shirudo_upatch_decode_map_signal(const struct shirudo_map_view *v,
				    uint32_t *signal_out);

#endif /* SHIRUDO_UTIL_UPATCH_DECODE_H */
