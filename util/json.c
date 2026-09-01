// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * In-tree JSON emitter and schema-callback parser. The emitter is
 * streaming with a caller-supplied buffer, automatic comma placement
 * and string escaping; the parser dispatches declared keys into caller
 * structs and parses-and-discards everything else.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

static int flush_sink(struct shirudo_json_emit *e)
{
	int rc;

	if (e->err)
		return e->err;
	if (!e->sink || e->len == 0)
		return 0;
	rc = e->sink(e->sink_ctx, e->buf, e->len);
	if (rc) {
		e->err = rc < 0 ? rc : -EIO;
		return e->err;
	}
	e->len = 0;
	if (e->cap)
		e->buf[0] = '\0';
	return 0;
}

static void put(struct shirudo_json_emit *e, char c)
{
	if (e->err)
		return;
	if (e->len + 1 >= e->cap) {
		if (!e->sink || flush_sink(e)) {
			if (!e->err)
				e->err = -ENOSPC;
			return;
		}
		if (e->len + 1 >= e->cap) {
			e->err = -ENOSPC;
			return;
		}
	}
	e->buf[e->len++] = c;
	e->buf[e->len] = '\0';
}

static void put_raw(struct shirudo_json_emit *e, const char *s)
{
	while (*s && !e->err)
		put(e, *s++);
}

/*
 * Emit one escaped JSON string (surrounding quotes included). Escapes
 * the mandatory characters and rejects malformed UTF-8 with -EILSEQ so
 * a stray byte can never produce invalid JSON.
 */
static void put_string(struct shirudo_json_emit *e, const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	put(e, '"');
	while (*p && !e->err) {
		unsigned char c = *p;

		if (c == '"' || c == '\\') {
			put(e, '\\');
			put(e, (char)c);
			p++;
		} else if (c == '\n') {
			put_raw(e, "\\n");
			p++;
		} else if (c == '\r') {
			put_raw(e, "\\r");
			p++;
		} else if (c == '\t') {
			put_raw(e, "\\t");
			p++;
		} else if (c < 0x20) {
			char u[7];

			snprintf(u, sizeof(u), "\\u%04x", c);
			put_raw(e, u);
			p++;
		} else if (c < 0x80) {
			put(e, (char)c);
			p++;
		} else {
			/* Validate a UTF-8 multi-byte sequence. */
			int n;

			if ((c & 0xE0) == 0xC0)
				n = 2;
			else if ((c & 0xF0) == 0xE0)
				n = 3;
			else if ((c & 0xF8) == 0xF0)
				n = 4;
			else {
				e->err = -EILSEQ;
				return;
			}
			for (int i = 0; i < n; i++) {
				if (i > 0 && (p[i] & 0xC0) != 0x80) {
					e->err = -EILSEQ;
					return;
				}
			}
			for (int i = 0; i < n; i++)
				put(e, (char)p[i]);
			p += n;
		}
	}
	put(e, '"');
}

/* Comma before the next member of the innermost open container. */
static void sep(struct shirudo_json_emit *e)
{
	if (e->err)
		return;
	if (e->nonempty & (1u << e->depth))
		put(e, ',');
	else
		e->nonempty |= (1u << e->depth);
}

static void enter(struct shirudo_json_emit *e)
{
	if (e->err)
		return;
	if (e->depth + 1 >= SHIRUDO_JSON_MAX_DEPTH) {
		e->err = -E2BIG;
		return;
	}
	e->depth++;
	e->nonempty &= ~(1u << e->depth);
}

static void leave(struct shirudo_json_emit *e)
{
	if (e->depth)
		e->depth--;
}

void shirudo_json_obj_open(struct shirudo_json_emit *e)
{
	sep(e);
	put(e, '{');
	enter(e);
}

void shirudo_json_obj_open_key(struct shirudo_json_emit *e, const char *key)
{
	sep(e);
	put_string(e, key);
	put(e, ':');
	put(e, '{');
	enter(e);
}

void shirudo_json_obj_close(struct shirudo_json_emit *e)
{
	put(e, '}');
	leave(e);
}

void shirudo_json_arr_open(struct shirudo_json_emit *e, const char *key)
{
	sep(e);
	put_string(e, key);
	put(e, ':');
	put(e, '[');
	enter(e);
}

void shirudo_json_arr_close(struct shirudo_json_emit *e)
{
	put(e, ']');
	leave(e);
}

void shirudo_json_kv_string(struct shirudo_json_emit *e,
			    const char *key, const char *val)
{
	sep(e);
	put_string(e, key);
	put(e, ':');
	put_string(e, val);
}

void shirudo_json_kv_int(struct shirudo_json_emit *e,
			 const char *key, int64_t val)
{
	char num[24];

	sep(e);
	put_string(e, key);
	put(e, ':');
	snprintf(num, sizeof(num), "%lld", (long long)val);
	put_raw(e, num);
}

void shirudo_json_kv_bool(struct shirudo_json_emit *e, const char *key, int val)
{
	sep(e);
	put_string(e, key);
	put(e, ':');
	put_raw(e, val ? "true" : "false");
}

void shirudo_json_kv_null(struct shirudo_json_emit *e, const char *key)
{
	sep(e);
	put_string(e, key);
	put(e, ':');
	put_raw(e, "null");
}

void shirudo_json_kv_raw(struct shirudo_json_emit *e, const char *key,
			 const char *value, size_t value_len)
{
	size_t i;

	sep(e);
	put_string(e, key);
	put(e, ':');
	for (i = 0; i < value_len && !e->err; i++)
		put(e, value[i]);
}

void shirudo_json_str(struct shirudo_json_emit *e, const char *val)
{
	sep(e);
	put_string(e, val);
}

int shirudo_json_emit_flush(struct shirudo_json_emit *e)
{
	if (!e)
		return -EINVAL;
	return flush_sink(e);
}

/* ---- Schema-driven parser ---------------------------------------- */

struct pctx {
	const char			*p;
	const char			*end;
	unsigned			depth;
	struct shirudo_json_field	*fields;
	size_t				n_fields;
};

static void skip_ws(struct pctx *c)
{
	while (c->p < c->end) {
		char ch = *c->p;

		if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r')
			c->p++;
		else
			break;
	}
}

static int hex_nibble(char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	return -1;
}

static int hex4(const char *s)
{
	int v = 0, i;

	for (i = 0; i < 4; i++) {
		int n = hex_nibble(s[i]);

		if (n < 0)
			return -1;
		v = (v << 4) | n;
	}
	return v;
}

/* Append one byte to dst (if non-NULL), tracking decoded length. */
static int emit_byte(char *dst, size_t cap, size_t *len, unsigned char b)
{
	size_t n = *len;

	if (n >= SHIRUDO_JSON_MAX_STRING_BYTES)
		return -E2BIG;
	if (dst) {
		if (n + 1 >= cap)	/* leave room for NUL */
			return -ENOSPC;
		dst[n] = (char)b;
	}
	*len = n + 1;
	return 0;
}

static int utf8_emit(char *dst, size_t cap, size_t *len, unsigned cp)
{
	int rc;

	if (cp < 0x80) {
		return emit_byte(dst, cap, len, cp);
	} else if (cp < 0x800) {
		rc = emit_byte(dst, cap, len, 0xC0 | (cp >> 6));
		if (!rc)
			rc = emit_byte(dst, cap, len, 0x80 | (cp & 0x3F));
		return rc;
	}
	rc = emit_byte(dst, cap, len, 0xE0 | (cp >> 12));
	if (!rc)
		rc = emit_byte(dst, cap, len, 0x80 | ((cp >> 6) & 0x3F));
	if (!rc)
		rc = emit_byte(dst, cap, len, 0x80 | (cp & 0x3F));
	return rc;
}

/*
 * Parse a JSON string starting at *p == '"'. Decodes escapes into dst
 * (NUL-terminated) when dst != NULL, or just consumes when dst == NULL.
 */
static int parse_string(struct pctx *c, char *dst, size_t cap)
{
	size_t len = 0;
	int rc;

	if (c->p >= c->end || *c->p != '"')
		return -EINVAL;
	c->p++;
	for (;;) {
		unsigned char ch;

		if (c->p >= c->end)
			return -EINVAL;		/* unterminated */
		ch = (unsigned char)*c->p++;
		if (ch == '"')
			break;
		if (ch == '\\') {
			char e;

			if (c->p >= c->end)
				return -EINVAL;
			e = *c->p++;
			switch (e) {
			case '"': rc = emit_byte(dst, cap, &len, '"'); break;
			case '\\': rc = emit_byte(dst, cap, &len, '\\'); break;
			case '/': rc = emit_byte(dst, cap, &len, '/'); break;
			case 'b': rc = emit_byte(dst, cap, &len, '\b'); break;
			case 'f': rc = emit_byte(dst, cap, &len, '\f'); break;
			case 'n': rc = emit_byte(dst, cap, &len, '\n'); break;
			case 'r': rc = emit_byte(dst, cap, &len, '\r'); break;
			case 't': rc = emit_byte(dst, cap, &len, '\t'); break;
			case 'u': {
				int cp, lo;

				if (c->end - c->p < 4)
					return -EINVAL;
				cp = hex4(c->p);
				if (cp < 0)
					return -EINVAL;
				c->p += 4;
				if (cp >= 0xD800 && cp <= 0xDBFF) {
					/* high surrogate: need \uDC00..DFFF */
					if (c->end - c->p < 6 ||
					    c->p[0] != '\\' || c->p[1] != 'u')
						return -EINVAL;
					lo = hex4(c->p + 2);
					if (lo < 0xDC00 || lo > 0xDFFF)
						return -EINVAL;
					c->p += 6;
					cp = 0x10000 +
					     ((cp - 0xD800) << 10) +
					     (lo - 0xDC00);
				} else if (cp >= 0xDC00 && cp <= 0xDFFF) {
					return -EINVAL;	/* lone low surrogate */
				}
				if (cp < 0x10000)
					rc = utf8_emit(dst, cap, &len, cp);
				else {
					rc = emit_byte(dst, cap, &len,
						       0xF0 | (cp >> 18));
					if (!rc)
						rc = emit_byte(dst, cap, &len,
							0x80 | ((cp >> 12) & 0x3F));
					if (!rc)
						rc = emit_byte(dst, cap, &len,
							0x80 | ((cp >> 6) & 0x3F));
					if (!rc)
						rc = emit_byte(dst, cap, &len,
							0x80 | (cp & 0x3F));
				}
				break;
			}
			default:
				return -EINVAL;
			}
			if (rc)
				return rc;
		} else if (ch < 0x20) {
			return -EINVAL;		/* unescaped control char */
		} else {
			rc = emit_byte(dst, cap, &len, ch);
			if (rc)
				return rc;
		}
	}
	if (dst)
		dst[len] = '\0';
	return 0;
}

static int parse_value(struct pctx *c, struct shirudo_json_field *f);

static int parse_object(struct pctx *c)
{
	char key[256];
	int rc;

	if (++c->depth > SHIRUDO_JSON_MAX_DEPTH)
		return -E2BIG;
	c->p++;				/* consume '{' */
	skip_ws(c);
	if (c->p < c->end && *c->p == '}') {
		c->p++;
		c->depth--;
		return 0;
	}
	for (;;) {
		struct shirudo_json_field *f = NULL;
		size_t i;

		skip_ws(c);
		rc = parse_string(c, key, sizeof(key));
		if (rc)
			return rc;
		skip_ws(c);
		if (c->p >= c->end || *c->p != ':')
			return -EINVAL;
		c->p++;
		for (i = 0; i < c->n_fields; i++) {
			if (c->fields[i].key && strcmp(c->fields[i].key, key) == 0) {
				f = &c->fields[i];
				break;
			}
		}
		rc = parse_value(c, f);
		if (rc)
			return rc;
		skip_ws(c);
		if (c->p >= c->end)
			return -EINVAL;
		if (*c->p == ',') {
			c->p++;
			continue;
		}
		if (*c->p == '}') {
			c->p++;
			break;
		}
		return -EINVAL;
	}
	c->depth--;
	return 0;
}

static int parse_array(struct pctx *c)
{
	int rc;

	if (++c->depth > SHIRUDO_JSON_MAX_DEPTH)
		return -E2BIG;
	c->p++;				/* consume '[' */
	skip_ws(c);
	if (c->p < c->end && *c->p == ']') {
		c->p++;
		c->depth--;
		return 0;
	}
	for (;;) {
		rc = parse_value(c, NULL);	/* elements never dispatched */
		if (rc)
			return rc;
		skip_ws(c);
		if (c->p >= c->end)
			return -EINVAL;
		if (*c->p == ',') {
			c->p++;
			continue;
		}
		if (*c->p == ']') {
			c->p++;
			break;
		}
		return -EINVAL;
	}
	c->depth--;
	return 0;
}

/*
 * Parse a '['-led array into a declared SHIRUDO_JSON_T_ARRAY field:
 * each element is dispatched against f->sub[] (an object element uses
 * the whole sub-schema; a scalar element goes to sub[0]), then the
 * sink's on_elem(ctx) is called so the caller can copy the element out.
 */
static int parse_array_into(struct pctx *c, struct shirudo_json_field *f)
{
	struct shirudo_json_array *sink = f->dst;
	int rc;

	if (++c->depth > SHIRUDO_JSON_MAX_DEPTH)
		return -E2BIG;
	c->p++;				/* consume '[' */
	skip_ws(c);
	if (c->p < c->end && *c->p == ']') {
		c->p++;
		c->depth--;
		f->seen = 1;
		return 0;
	}
	for (;;) {
		size_t i;

		for (i = 0; i < f->n_sub; i++)
			f->sub[i].seen = 0;
		skip_ws(c);
		if (c->p >= c->end)
			return -EINVAL;
		if (*c->p == '{') {
			struct shirudo_json_field *save_f = c->fields;
			size_t save_n = c->n_fields;

			c->fields = f->sub;
			c->n_fields = f->n_sub;
			rc = parse_object(c);
			c->fields = save_f;
			c->n_fields = save_n;
		} else {
			/* Scalar (or nested array/object) element -> sub[0]. */
			rc = parse_value(c, f->n_sub ? &f->sub[0] : NULL);
		}
		if (rc)
			return rc;
		if (sink && sink->on_elem) {
			rc = sink->on_elem(sink->ctx);
			if (rc)
				return rc;
		}
		skip_ws(c);
		if (c->p >= c->end)
			return -EINVAL;
		if (*c->p == ',') {
			c->p++;
			continue;
		}
		if (*c->p == ']') {
			c->p++;
			break;
		}
		return -EINVAL;
	}
	c->depth--;
	f->seen = 1;
	return 0;
}

static int lit(struct pctx *c, const char *s)
{
	size_t n = strlen(s);

	if ((size_t)(c->end - c->p) < n || memcmp(c->p, s, n) != 0)
		return -EINVAL;
	c->p += n;
	return 0;
}

static int parse_number(struct pctx *c, struct shirudo_json_field *f)
{
	const char *start = c->p;

	if (c->p < c->end && *c->p == '-')
		c->p++;
	while (c->p < c->end && ((*c->p >= '0' && *c->p <= '9') ||
				 *c->p == '.' || *c->p == 'e' ||
				 *c->p == 'E' || *c->p == '+' || *c->p == '-'))
		c->p++;
	if (c->p == start)
		return -EINVAL;
	if (f) {
		char numbuf[32];
		size_t nlen = (size_t)(c->p - start);

		if (f->type != SHIRUDO_JSON_T_INT)
			return -EINVAL;
		/*
		 * strtoll scans to a non-numeric byte or NUL; the input
		 * buffer is not guaranteed NUL-terminated (the API is
		 * (data, len)), so copy the already-bounded token into a
		 * NUL-terminated scratch first. A token too long to be a
		 * valid int64 is rejected rather than read.
		 */
		if (nlen >= sizeof(numbuf))
			return -EINVAL;
		memcpy(numbuf, start, nlen);
		numbuf[nlen] = '\0';
		*(int64_t *)f->dst = (int64_t)strtoll(numbuf, NULL, 10);
		f->seen = 1;
	}
	return 0;
}

static int parse_value(struct pctx *c, struct shirudo_json_field *f)
{
	skip_ws(c);
	if (c->p >= c->end)
		return -EINVAL;
	switch (*c->p) {
	case '{': {
		struct shirudo_json_field *save_f = c->fields;
		size_t save_n = c->n_fields;
		int rc;

		if (f) {
			if (f->type != SHIRUDO_JSON_T_OBJECT)
				return -EINVAL;
			c->fields = f->sub;
			c->n_fields = f->n_sub;
		} else {
			/*
			 * Discarded object: parse with an empty schema so its
			 * keys cannot collide with the enclosing schema and
			 * mis-dispatch (or type-mismatch) a value into it.
			 */
			c->fields = NULL;
			c->n_fields = 0;
		}
		rc = parse_object(c);
		c->fields = save_f;
		c->n_fields = save_n;
		if (rc)
			return rc;
		if (f)
			f->seen = 1;
		return 0;
	}
	case '[':
		if (f) {
			if (f->type != SHIRUDO_JSON_T_ARRAY)
				return -EINVAL;	/* declared scalar, got array */
			return parse_array_into(c, f);
		}
		return parse_array(c);
	case '"':
		if (f) {
			int rc;

			if (f->type != SHIRUDO_JSON_T_STRING)
				return -EINVAL;
			rc = parse_string(c, f->dst, f->dst_cap);
			if (rc)
				return rc;
			f->seen = 1;
			return 0;
		}
		return parse_string(c, NULL, 0);
	case 't':
		if (lit(c, "true"))
			return -EINVAL;
		if (f) {
			if (f->type != SHIRUDO_JSON_T_BOOL)
				return -EINVAL;
			*(int *)f->dst = 1;
			f->seen = 1;
		}
		return 0;
	case 'f':
		if (lit(c, "false"))
			return -EINVAL;
		if (f) {
			if (f->type != SHIRUDO_JSON_T_BOOL)
				return -EINVAL;
			*(int *)f->dst = 0;
			f->seen = 1;
		}
		return 0;
	case 'n':
		if (lit(c, "null"))
			return -EINVAL;
		return 0;		/* null never dispatched */
	default:
		return parse_number(c, f);
	}
}

int shirudo_json_parse(const char *data, size_t len,
		       struct shirudo_json_field *fields, size_t n_fields)
{
	struct pctx c = {
		.p = data, .end = data + len,
		.fields = fields, .n_fields = n_fields,
	};
	size_t i;
	int rc;

	if (len > SHIRUDO_JSON_MAX_BYTES)
		return -E2BIG;
	for (i = 0; i < n_fields; i++)
		fields[i].seen = 0;

	skip_ws(&c);
	if (c.p >= c.end || *c.p != '{')
		return -EINVAL;
	rc = parse_object(&c);
	if (rc)
		return rc;
	skip_ws(&c);
	if (c.p != c.end)
		return -EINVAL;		/* trailing garbage */
	return 0;
}
