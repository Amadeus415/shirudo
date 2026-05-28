/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * In-tree JSON emitter and schema-callback parser.
 */

#ifndef SHIRUDO_JSON_H
#define SHIRUDO_JSON_H

#include <stddef.h>
#include <stdint.h>

#ifndef SHIRUDO_JSON_MAX_BYTES
#define SHIRUDO_JSON_MAX_BYTES		(8u * 1024u * 1024u)
#endif
#ifndef SHIRUDO_JSON_MAX_DEPTH
#define SHIRUDO_JSON_MAX_DEPTH		32u
#endif
#ifndef SHIRUDO_JSON_MAX_STRING_BYTES
#define SHIRUDO_JSON_MAX_STRING_BYTES	(16u * 1024u * 1024u)
#endif

/* Emitter -- streaming, caller-supplied output buffer. */
struct shirudo_json_emit {
	char		*buf;
	size_t		cap;
	size_t		len;
	int		err;	/* sticky; -ENOSPC, -EILSEQ, -E2BIG */
	unsigned	depth;	/* open-container nesting */
	uint32_t	nonempty; /* bit d set: container at depth d has a member */
};

/*
 * Streaming emitter. Commas and string escaping are handled
 * automatically; the caller pairs opens with closes. obj_open emits a
 * bare object (the document root, or an array element); arr_open emits
 * a keyed array ("key":[...]). On any error (buffer full, bad UTF-8,
 * over-nesting) the sticky err latches and further calls are no-ops --
 * check e->err once after the final close.
 */
void shirudo_json_obj_open(struct shirudo_json_emit *e);
void shirudo_json_obj_open_key(struct shirudo_json_emit *e, const char *key);
void shirudo_json_obj_close(struct shirudo_json_emit *e);
void shirudo_json_arr_open(struct shirudo_json_emit *e, const char *key);
void shirudo_json_arr_close(struct shirudo_json_emit *e);
void shirudo_json_kv_string(struct shirudo_json_emit *e,
			    const char *key, const char *val);
void shirudo_json_kv_int(struct shirudo_json_emit *e,
			 const char *key, int64_t val);
void shirudo_json_kv_bool(struct shirudo_json_emit *e,
			  const char *key, int val);
void shirudo_json_kv_null(struct shirudo_json_emit *e, const char *key);
/* Bare array element (string), for arrays of scalars. */
void shirudo_json_str(struct shirudo_json_emit *e, const char *val);

/*
 * Schema-driven parser. Not a generic deserialiser: the caller
 * declares the top-level keys it cares about and where each value
 * goes; the parser dispatches matches and fully parses-and-discards
 * everything else (unknown keys, nested objects/arrays). Bounded by
 * SHIRUDO_JSON_MAX_BYTES / _DEPTH / _STRING_BYTES so hostile input
 * cannot exhaust the stack or a buffer.
 */
enum shirudo_json_vtype {
	SHIRUDO_JSON_T_STRING,	/* dst: char[dst_cap] (NUL-terminated)   */
	SHIRUDO_JSON_T_INT,	/* dst: int64_t *                        */
	SHIRUDO_JSON_T_BOOL,	/* dst: int *  (0/1)                     */
	SHIRUDO_JSON_T_OBJECT,	/* nested object -> sub[] sub-schema     */
	SHIRUDO_JSON_T_ARRAY,	/* sub[] schema; dst = shirudo_json_array * */
};

/*
 * Sink for SHIRUDO_JSON_T_ARRAY: the parser dispatches each element
 * into the field's sub[] schema (an object element against the whole
 * sub[]; a scalar element into sub[0]), resets the sub fields' `seen`
 * per element, then calls on_elem(ctx) so the caller can snapshot the
 * just-parsed element out of its scratch dst buffers before the next
 * element overwrites them. on_elem returns 0 to continue or a negative
 * errno to abort the parse. An ARRAY field stores a pointer to this in
 * its `dst` (so the field struct itself stays at the original layout
 * and existing positional initializers keep compiling).
 */
struct shirudo_json_array {
	int	(*on_elem)(void *ctx);
	void	*ctx;
};

struct shirudo_json_field {
	const char			*key;
	enum shirudo_json_vtype		type;
	void				*dst;
	size_t				dst_cap;	/* STRING only */
	int				seen;		/* set by the parser */
	struct shirudo_json_field	*sub;		/* OBJECT/ARRAY schema */
	size_t				n_sub;		/* OBJECT/ARRAY schema */
};

/*
 * Parse one top-level JSON object. Returns 0 on a well-formed object,
 * -EINVAL on malformed input or a scalar/struct type mismatch on a
 * declared key, -E2BIG on a bounds violation (size/depth/string),
 * -ENOSPC if a declared string value exceeds its dst_cap. Each matched
 * field's `seen` is set; callers check it for required keys.
 */
int shirudo_json_parse(const char *data, size_t len,
		       struct shirudo_json_field *fields, size_t n_fields);

#endif /* SHIRUDO_JSON_H */
