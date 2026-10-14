// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Pinned upatch maps reader. Walks /var/lib/shirudo/bpffs/upatches/
 * <name>/maps/<map>, opens each pin via BPF_OBJ_GET, dispatches to a
 * per-type reader for the entries. BTF type names come from
 * libbpf::btf__name_by_offset() when the map carries a btf_id.
 *
 * Generic map reads are read-only. Serializer-backed reads also clear
 * the reserved output map and run the pinned serializer program with
 * BPF_PROG_TEST_RUN; the serializer writes serialized chunks back to
 * that reserved map for userspace to print.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/upatch.h>

#include "json.h"
#include "malloc.h"
#include "paths.h"
#include "serializer.h"
#include "upatch_map_types.h"
#include "upatch_maps.h"
#include "upatch_resolve.h"
#include "bpf/lib/shirudo_serializer.h"

/*
 * Per-call recursion bound for the BTF value renderer. Real-world map
 * value structs are flat; nested-struct chains beyond ~4 hops would
 * either be an attacker-crafted BTF or a layout we should not be
 * pretty-printing in a "shirudo upatch get" view.
 */
#define SHIRUDO_BTF_MAX_DEPTH		6

/* Resolve the parent upatch location without making it required for reads. */
static void resolve_map_location(struct shirudo_map_view *v)
{
	struct btf *vbtf;

	if (!v)
		return;
	vbtf = btf__load_vmlinux_btf();
	if (libbpf_get_error(vbtf))
		vbtf = NULL;
	(void)shirudo_upatch_resolve_location(vbtf, v->upatch,
					      v->location, sizeof(v->location));
	if (vbtf)
		btf__free(vbtf);
}
#define SHIRUDO_SERIAL_MAX_BYTES \
	(SHIRUDO_SERIAL_MAX_CHUNKS * SHIRUDO_SERIAL_CHUNK_PAYLOAD)
#define SHIRUDO_SERIAL_MAX_TOTAL_BYTES \
	((uint64_t)SHIRUDO_SERIAL_MAX_PAGES * SHIRUDO_SERIAL_MAX_BYTES)

bool shirudo_upatch_map_is_percpu(uint32_t type)
{
	return type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	       type == BPF_MAP_TYPE_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

static uint32_t map_value_stride(uint32_t type, uint32_t value_size)
{
	if (!shirudo_upatch_map_is_percpu(type))
		return value_size;
	return (value_size + 7U) & ~7U;
}

uint32_t shirudo_upatch_map_value_stride(const struct shirudo_map_view *v)
{
	return v->value_stride ? v->value_stride : v->value_size;
}

static bool is_array_type(uint32_t type)
{
	return type == BPF_MAP_TYPE_ARRAY ||
	       type == BPF_MAP_TYPE_PERCPU_ARRAY;
}

static bool is_hash_type(uint32_t type)
{
	return type == BPF_MAP_TYPE_HASH ||
	       type == BPF_MAP_TYPE_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_LRU_HASH ||
	       type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

/* Resolve a BTF type id to a printable type name in dst[]. */
static void btf_type_name(struct btf *btf, uint32_t type_id,
			  char *dst, size_t dst_cap)
{
	const struct btf_type *t;
	const char *name;

	dst[0] = '\0';
	if (!btf || !type_id)
		return;
	t = btf__type_by_id(btf, type_id);
	if (!t)
		return;
	name = btf__name_by_offset(btf, t->name_off);
	if (name && name[0]) {
		snprintf(dst, dst_cap, "%s", name);
		return;
	}
	/*
	 * Anonymous types: walk one indirection to pick up a useful
	 * label (e.g. unnamed PTR -> named STRUCT). Bounded loop.
	 */
	{
		uint32_t id = type_id;
		int hops;

		for (hops = 0; hops < 4; hops++) {
			t = btf__type_by_id(btf, id);
			if (!t)
				break;
			name = btf__name_by_offset(btf, t->name_off);
			if (name && name[0]) {
				snprintf(dst, dst_cap, "%s", name);
				return;
			}
			id = t->type;
			if (!id)
				break;
		}
	}
}

/* Forward decl: defined further down, used by the BTF formatters. */
static char *fmt_alloc(const char *fmt, ...) __attribute__((format(printf,1,2)));

/*
 * Unwrap qualifier / typedef chains. Returns the resolved type id
 * (or `id` unchanged if no unwrap was possible / depth exceeded).
 */
static uint32_t btf_unwrap(const struct btf *btf, uint32_t id)
{
	const struct btf_type *t;
	int hops;

	for (hops = 0; hops < SHIRUDO_BTF_MAX_DEPTH; hops++) {
		t = btf__type_by_id(btf, id);
		if (!t)
			return id;
		switch (BTF_INFO_KIND(t->info)) {
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
			id = t->type;
			continue;
		default:
			return id;
		}
	}
	return id;
}

/*
 * Short kind tag for the "struct foo" / "union bar" / "enum baz"
 * prefix; for typedefs and primitives the BTF name carries enough
 * context on its own (no prefix needed).
 */
static const char *btf_kind_prefix(uint16_t kind)
{
	switch (kind) {
	case BTF_KIND_STRUCT:		return "struct ";
	case BTF_KIND_UNION:		return "union ";
	case BTF_KIND_ENUM:		return "enum ";
	case BTF_KIND_ENUM64:		return "enum ";
	default:			return "";
	}
}

/*
 * `btf_type_signature_into` writes a multi-line definition of `id`
 * into the caller-owned buffer at offset *off (bounded by cap). For
 * struct/union it emits `struct foo {\n  type field;\n  ...\n}`; for
 * anything else, just the type name. Truncates with `; ...` rather
 * than failing if the buffer is too small. depth bounds recursion.
 */
static void btf_type_signature_into(const struct btf *btf, uint32_t id,
				    char *buf, size_t cap, size_t *off,
				    int depth);

static void append_str(char *buf, size_t cap, size_t *off, const char *s)
{
	size_t n;

	if (*off >= cap || !s)
		return;
	n = strlen(s);
	if (n > cap - 1 - *off)
		n = cap - 1 - *off;
	memcpy(buf + *off, s, n);
	*off += n;
	buf[*off] = '\0';
}

static void append_indent(char *buf, size_t cap, size_t *off, int depth)
{
	int i;

	for (i = 0; i < depth && *off + 2 < cap; i++) {
		buf[(*off)++] = ' ';
		buf[(*off)++] = ' ';
	}
	if (*off < cap)
		buf[*off] = '\0';
}

static void btf_type_signature_into(const struct btf *btf, uint32_t id,
				    char *buf, size_t cap, size_t *off,
				    int depth)
{
	const struct btf_type *t;
	const char *name;
	uint16_t kind;
	int i, vlen;

	if (depth >= SHIRUDO_BTF_MAX_DEPTH || !btf || !id || *off >= cap)
		return;
	id = btf_unwrap(btf, id);
	t = btf__type_by_id(btf, id);
	if (!t) {
		append_str(buf, cap, off, "?");
		return;
	}
	kind = BTF_INFO_KIND(t->info);
	name = btf__name_by_offset(btf, t->name_off);

	if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) {
		const struct btf_member *m =
			(const struct btf_member *)(t + 1);

		append_str(buf, cap, off, btf_kind_prefix(kind));
		append_str(buf, cap, off, name && name[0] ? name : "<anon>");
		append_str(buf, cap, off, " {\n");
		vlen = BTF_INFO_VLEN(t->info);
		for (i = 0; i < vlen; i++) {
			const char *mname = btf__name_by_offset(btf,
								m[i].name_off);

			if (cap - *off < 8) {
				append_str(buf, cap, off, "  ...\n");
				break;
			}
			append_indent(buf, cap, off, depth + 1);
			/*
			 * Render the field type. For nested struct fields we
			 * print the short name (struct bar / int) instead of
			 * recursing, to keep the signature single-screen.
			 */
			{
				uint32_t mid = btf_unwrap(btf, m[i].type);
				const struct btf_type *mt = btf__type_by_id(btf, mid);
				const char *mtype = mt ?
						    btf__name_by_offset(btf,
								mt->name_off) :
						    NULL;
				uint16_t mkind = mt ? BTF_INFO_KIND(mt->info)
						    : 0;

				append_str(buf, cap, off, btf_kind_prefix(mkind));
				append_str(buf, cap, off,
					   mtype && mtype[0] ? mtype : "?");
			}
			append_str(buf, cap, off, " ");
			append_str(buf, cap, off,
				   mname && mname[0] ? mname : "<anon>");
			append_str(buf, cap, off, ";\n");
		}
		append_indent(buf, cap, off, depth);
		append_str(buf, cap, off, "}");
		return;
	}
	if (kind == BTF_KIND_ARRAY) {
		const struct btf_array *a = (const struct btf_array *)(t + 1);
		const struct btf_type *et = btf__type_by_id(btf,
							    btf_unwrap(btf, a->type));
		const char *en = et ? btf__name_by_offset(btf, et->name_off)
				    : "?";
		char nbuf[32];

		append_str(buf, cap, off, en && en[0] ? en : "?");
		snprintf(nbuf, sizeof(nbuf), "[%u]", a->nelems);
		append_str(buf, cap, off, nbuf);
		return;
	}
	if (kind == BTF_KIND_ENUM || kind == BTF_KIND_ENUM64) {
		append_str(buf, cap, off, "enum ");
		append_str(buf, cap, off, name && name[0] ? name : "<anon>");
		return;
	}
	append_str(buf, cap, off, name && name[0] ? name : "?");
}

/*
 * Compose a heap-owned formatted-value string for a BTF type. For
 * structs/unions: `{ field=val, field=val }`. For arrays: `[v0, v1, ...]`.
 * For primitives: decimal (signed/unsigned by BTF_INT_SIGNED); for ptr,
 * hex; for enum, the symbol name when known.
 * Returns NULL only on allocation failure.
 */
static char *btf_format_value(const struct btf *btf, uint32_t type_id,
			      const void *bytes, uint32_t bytes_size,
			      int depth);

/* Append one heap-formatted token to an open `out` buffer; takes ownership. */
static int strbuf_append_take(char **out, size_t *cap, size_t *off,
			      char *piece)
{
	size_t n;

	if (!piece)
		return -1;
	n = strlen(piece);
	if (*off + n + 1 > *cap) {
		size_t nc = *cap ? *cap * 2 : 64;
		char *p;

		while (nc < *off + n + 1)
			nc *= 2;
		p = xmalloc(nc);
		if (!p) {
			xstrfree(piece);
			return -1;
		}
		memcpy(p, *out, *off);
		xfree(*out, *cap);
		*out = p;
		*cap = nc;
	}
	memcpy(*out + *off, piece, n);
	*off += n;
	(*out)[*off] = '\0';
	xstrfree(piece);
	return 0;
}

static char *btf_format_int(const struct btf_type *t, const void *bytes,
			    uint32_t bytes_size)
{
	uint32_t enc_word = *(const uint32_t *)(t + 1);
	uint32_t bits = BTF_INT_BITS(enc_word);
	uint32_t encoding = BTF_INT_ENCODING(enc_word);
	bool is_signed = (encoding & BTF_INT_SIGNED) != 0;
	uint8_t bytes_used = (uint8_t)((bits + 7) / 8);

	if (bytes_used == 0 || bytes_used > bytes_size || bytes_used > 8)
		return fmt_alloc("?");
	if (is_signed) {
		int64_t v = 0;
		uint8_t i;

		for (i = 0; i < bytes_used; i++)
			v |= (int64_t)((const uint8_t *)bytes)[i] << (8 * i);
		/* Sign-extend from `bits`. */
		if (bits < 64 && (v & ((int64_t)1 << (bits - 1))))
			v |= ~(((int64_t)1 << bits) - 1);
		return fmt_alloc("%" PRId64, v);
	} else {
		uint64_t v = 0;
		uint8_t i;

		for (i = 0; i < bytes_used; i++)
			v |= (uint64_t)((const uint8_t *)bytes)[i] << (8 * i);
		return fmt_alloc("%" PRIu64, v);
	}
}

static char *btf_format_value(const struct btf *btf, uint32_t type_id,
			      const void *bytes, uint32_t bytes_size,
			      int depth)
{
	const struct btf_type *t;
	uint16_t kind;

	if (depth >= SHIRUDO_BTF_MAX_DEPTH || !btf || !type_id || !bytes ||
	    !bytes_size)
		return NULL;
	type_id = btf_unwrap(btf, type_id);
	t = btf__type_by_id(btf, type_id);
	if (!t)
		return NULL;
	kind = BTF_INFO_KIND(t->info);

	if (kind == BTF_KIND_INT)
		return btf_format_int(t, bytes, bytes_size);

	if (kind == BTF_KIND_PTR) {
		uint64_t v = 0;

		if (bytes_size >= 8)
			memcpy(&v, bytes, 8);
		else if (bytes_size >= 4)
			memcpy(&v, bytes, 4);
		return fmt_alloc("0x%" PRIx64, v);
	}

	if (kind == BTF_KIND_ENUM) {
		const struct btf_enum *e = (const struct btf_enum *)(t + 1);
		int vlen = BTF_INFO_VLEN(t->info);
		int32_t v = 0;
		int i;

		if (bytes_size >= 4)
			memcpy(&v, bytes, 4);
		for (i = 0; i < vlen; i++)
			if (e[i].val == v) {
				const char *nm = btf__name_by_offset(btf,
								e[i].name_off);
				return fmt_alloc("%s", nm && nm[0] ? nm : "?");
			}
		return fmt_alloc("%" PRId32, v);
	}

	if (kind == BTF_KIND_ENUM64) {
		const struct btf_enum64 *e =
			(const struct btf_enum64 *)(t + 1);
		int vlen = BTF_INFO_VLEN(t->info);
		uint64_t v = 0;
		int i;

		if (bytes_size >= 8)
			memcpy(&v, bytes, 8);
		for (i = 0; i < vlen; i++) {
			uint64_t ev = ((uint64_t)e[i].val_hi32 << 32) |
				      e[i].val_lo32;

			if (ev == v) {
				const char *nm = btf__name_by_offset(btf,
								e[i].name_off);
				return fmt_alloc("%s", nm && nm[0] ? nm : "?");
			}
		}
		return fmt_alloc("0x%" PRIx64, v);
	}

	if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) {
		const struct btf_member *m =
			(const struct btf_member *)(t + 1);
		int vlen = BTF_INFO_VLEN(t->info);
		size_t cap = 64, off = 0;
		char *out = xmalloc(cap);
		int i;

		if (!out)
			return NULL;
		out[0] = '\0';
		if (strbuf_append_take(&out, &cap, &off,
				       fmt_alloc("{ ")) != 0) {
			xfree(out, cap);
			return NULL;
		}
		for (i = 0; i < vlen; i++) {
			uint32_t bit_off = BTF_INFO_KFLAG(t->info) ?
					   BTF_MEMBER_BIT_OFFSET(m[i].offset) :
					   m[i].offset;
			uint32_t byte_off = bit_off / 8;
			const struct btf_type *ft;
			uint32_t fsize = 0;
			const char *fname;
			char *fval;

			if (byte_off >= bytes_size)
				continue;
			ft = btf__type_by_id(btf, btf_unwrap(btf, m[i].type));
			fname = btf__name_by_offset(btf, m[i].name_off);
			if (ft) {
				int64_t sz = btf__resolve_size(btf, m[i].type);

				if (sz > 0)
					fsize = (uint32_t)sz;
			}
			if (!fsize || byte_off + fsize > bytes_size)
				fsize = bytes_size - byte_off;
			fval = btf_format_value(btf, m[i].type,
						(const char *)bytes + byte_off,
						fsize, depth + 1);
			if (!fval)
				fval = fmt_alloc("?");
			strbuf_append_take(&out, &cap, &off,
					   fmt_alloc("%s%s=%s",
						     i ? ", " : "",
						     fname && fname[0] ?
								fname : "?",
						     fval ? fval : "?"));
			xstrfree(fval);
		}
		strbuf_append_take(&out, &cap, &off, fmt_alloc(" }"));
		return out;
	}

	if (kind == BTF_KIND_ARRAY) {
		const struct btf_array *a = (const struct btf_array *)(t + 1);
		int64_t esz = btf__resolve_size(btf, a->type);
		uint32_t i, n = a->nelems;
		size_t cap = 64, off = 0;
		char *out;

		if (esz <= 0 || (uint64_t)esz * n > bytes_size)
			return NULL;
		out = xmalloc(cap);
		if (!out)
			return NULL;
		out[0] = '\0';
		strbuf_append_take(&out, &cap, &off, fmt_alloc("[ "));
		for (i = 0; i < n && i < 16; i++) {
			char *ev = btf_format_value(btf, a->type,
				(const char *)bytes + i * (size_t)esz,
				(uint32_t)esz, depth + 1);

			strbuf_append_take(&out, &cap, &off,
					   fmt_alloc("%s%s",
						     i ? ", " : "",
						     ev ? ev : "?"));
			xstrfree(ev);
		}
		if (n > 16)
			strbuf_append_take(&out, &cap, &off,
					   fmt_alloc(", ... (%u more)",
						     n - 16));
		strbuf_append_take(&out, &cap, &off, fmt_alloc(" ]"));
		return out;
	}

	return NULL;
}

/* Heap snprintf into a fresh buffer with the printf result. */
static char *fmt_alloc(const char *fmt, ...)
{
	char small[64];
	va_list ap;
	int n;
	char *p;

	va_start(ap, fmt);
	n = vsnprintf(small, sizeof(small), fmt, ap);
	va_end(ap);
	if (n < 0)
		return NULL;
	if ((size_t)n < sizeof(small))
		return xstrdup(small);
	p = xmalloc((size_t)n + 1);
	if (!p)
		return NULL;
	va_start(ap, fmt);
	vsnprintf(p, (size_t)n + 1, fmt, ap);
	va_end(ap);
	return p;
}

static int nproc_possible(void)
{
	long n = sysconf(_SC_NPROCESSORS_CONF);

	return n > 0 ? (int)n : 1;
}

/*
 * Dispatch on (size, signedness) to render a primitive value. Falls
 * back to a hex dump for anything else (string, struct, unknown).
 * out_buf is heap-owned; caller xfree's. value_bytes are read-only.
 */
static char *format_value(const void *value, uint32_t value_size,
			  const char *btf_type)
{
	if (btf_type && btf_type[0]) {
		if (value_size == 8 &&
		    (strcmp(btf_type, "__u64") == 0 ||
		     strcmp(btf_type, "u64") == 0 ||
		     strcmp(btf_type, "long long unsigned int") == 0)) {
			uint64_t v;

			memcpy(&v, value, 8);
			return fmt_alloc("%" PRIu64, v);
		}
		if (value_size == 8 &&
		    (strcmp(btf_type, "__s64") == 0 ||
		     strcmp(btf_type, "s64") == 0 ||
		     strcmp(btf_type, "long long int") == 0)) {
			int64_t v;

			memcpy(&v, value, 8);
			return fmt_alloc("%" PRId64, v);
		}
		if (value_size == 4 &&
		    (strcmp(btf_type, "__u32") == 0 ||
		     strcmp(btf_type, "u32") == 0 ||
		     strcmp(btf_type, "unsigned int") == 0)) {
			uint32_t v;

			memcpy(&v, value, 4);
			return fmt_alloc("%" PRIu32, v);
		}
		if (value_size == 4 &&
		    (strcmp(btf_type, "__s32") == 0 ||
		     strcmp(btf_type, "s32") == 0 ||
		     strcmp(btf_type, "int") == 0)) {
			int32_t v;

			memcpy(&v, value, 4);
			return fmt_alloc("%" PRId32, v);
		}
	}
	if (value_size == 8) {
		uint64_t v;

		memcpy(&v, value, 8);
		return fmt_alloc("%" PRIu64, v);
	}
	if (value_size == 4) {
		uint32_t v;

		memcpy(&v, value, 4);
		return fmt_alloc("%" PRIu32, v);
	}
	/* Hex fallback (cap at 32 bytes shown for readability). */
	{
		const unsigned char *p = value;
		uint32_t cap = value_size < 32 ? value_size : 32;
		size_t buf_sz = (size_t)cap * 2 + 8;
		char *out = xmalloc(buf_sz);
		size_t off = 0;
		uint32_t i;

		if (!out)
			return NULL;
		out[off++] = '0';
		out[off++] = 'x';
		for (i = 0; i < cap; i++) {
			snprintf(out + off, buf_sz - off, "%02x", p[i]);
			off += 2;
		}
		if (value_size > cap) {
			snprintf(out + off, buf_sz - off, "...");
			off += 3;
		}
		out[off] = '\0';
		return out;
	}
}

char *shirudo_upatch_map_format_percpu_sum(const struct shirudo_map_view *v,
					   const void *values_per_cpu,
					   const char *btf_type)
{
	if (v->value_size == 1 || v->value_size == 2 ||
	    v->value_size == 4 || v->value_size == 8) {
		uint64_t sum = 0;
		uint32_t i;

		for (i = 0; i < v->n_cpus; i++) {
			uint64_t one = 0;

			memcpy(&one, (const char *)values_per_cpu +
			       (size_t)i * shirudo_upatch_map_value_stride(v),
			       v->value_size);
			sum += one;
		}
		return fmt_alloc("%" PRIu64, sum);
	}
	(void)btf_type;
	return xstrdup("(unsupported width)");
}

/* Open a pinned map and return its fd + filled info. -errno on failure. */
static int open_map_pin(const char *upatch, const char *map_name,
			int *fd_out, struct bpf_map_info *info_out)
{
	char path[PATH_MAX];
	char bpffs_name[SHIRUDO_UPATCH_BPFFS_NAME_MAX + 1];
	uint32_t info_len = sizeof(*info_out);
	int fd;

	if (shirudo_upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), upatch))
		return -ENAMETOOLONG;
	if ((size_t)snprintf(path, sizeof(path), "%s/%s/maps/%s",
			     SHIRUDO_BPFFS_UPATCHES_DIR, bpffs_name, map_name)
	    >= sizeof(path))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(path);
	if (fd < 0)
		return -errno;
	memset(info_out, 0, sizeof(*info_out));
	if (bpf_map_get_info_by_fd(fd, info_out, &info_len)) {
		int e = -errno;

		close(fd);
		return e;
	}
	*fd_out = fd;
	return 0;
}

static struct btf *try_load_btf(uint32_t btf_id)
{
	if (!btf_id)
		return NULL;
	return btf__load_from_kernel_by_id(btf_id);
}

static int open_serializer_pin(const char *upatch, const char *map_name)
{
	char path[PATH_MAX];
	char bpffs_name[SHIRUDO_UPATCH_BPFFS_NAME_MAX + 1];
	int fd;

	if (shirudo_upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), upatch))
		return -ENAMETOOLONG;
	if ((size_t)snprintf(path, sizeof(path), "%s/%s/serializers/%s",
			     SHIRUDO_BPFFS_UPATCHES_DIR, bpffs_name, map_name) >=
		    sizeof(path))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(path);
	if (fd < 0)
		return -errno;
	return fd;
}

static int prog_test_run_ctx(int prog_fd, void *ctx, uint32_t ctx_sz,
			     uint32_t *retval)
{
	union bpf_attr attr = {};
	long ret;

	attr.test.prog_fd = prog_fd;
	attr.test.ctx_in = (uint64_t)(uintptr_t)ctx;
	attr.test.ctx_size_in = ctx_sz;
	ret = syscall(__NR_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
	if (ret < 0)
		return -errno;
	*retval = attr.test.retval;
	return 0;
}

static int validate_serial_map(const struct bpf_map_info *info)
{
	if (info->type != BPF_MAP_TYPE_ARRAY)
		return -EINVAL;
	if (info->key_size != sizeof(uint32_t))
		return -EINVAL;
	if (info->value_size != sizeof(struct shirudo_serial_chunk))
		return -EINVAL;
	if (info->max_entries == 0 ||
	    info->max_entries > SHIRUDO_SERIAL_MAX_CHUNKS)
		return -E2BIG;
	return 0;
}

static int clear_serial_map(int fd, const struct bpf_map_info *info)
{
	void *zero;
	uint32_t i;

	zero = xcalloc(1, info->value_size);
	if (!zero)
		return -ENOMEM;
	for (i = 0; i < info->max_entries; i++) {
		if (bpf_map_update_elem(fd, &i, zero, BPF_ANY) != 0) {
			int e = -errno;

			xfree(zero, info->value_size);
			return e;
		}
	}
	xfree(zero, info->value_size);
	return 0;
}

static int append_serial_page(struct shirudo_map_view *out,
			      struct shirudo_serial_page *page)
{
	void *p;

	p = xreallocarray(out->serial_pages, out->n_serial_pages,
			  out->n_serial_pages + 1, sizeof(*out->serial_pages));
	if (!p)
		return -ENOMEM;
	out->serial_pages = p;
	out->serial_pages[out->n_serial_pages++] = *page;
	memset(page, 0, sizeof(*page));
	return 0;
}

static int read_serial_page(int serial_fd,
			    const struct bpf_map_info *serial_info,
			    uint32_t want_page_index, uint64_t want_cursor,
			    uint64_t invocation_id,
			    struct shirudo_serial_page *page)
{
	struct shirudo_serial_chunk *chunk;
	uint32_t key, total_chunks, bytes_total, copied = 0;
	uint32_t page_index, flags;
	uint64_t cursor, next_cursor;
	unsigned char *data = NULL;
	int rc;

	chunk = xmalloc(sizeof(*chunk));
	if (!chunk)
		return -ENOMEM;
	key = 0;
	if (bpf_map_lookup_elem(serial_fd, &key, chunk) != 0) {
		rc = -errno;
		goto out_chunk;
	}
	if (chunk->magic != SHIRUDO_SERIAL_MAGIC ||
	    chunk->version != SHIRUDO_SERIAL_VERSION ||
	    chunk->invocation_id != invocation_id) {
		rc = -EBADMSG;
		goto out_chunk;
	}
	if (chunk->status != 0) {
		rc = chunk->status < 0 ? chunk->status : -EIO;
		goto out_chunk;
	}
	total_chunks = chunk->total_chunks;
	bytes_total = chunk->bytes_total;
	page_index = chunk->page_index;
	cursor = chunk->cursor;
	next_cursor = chunk->next_cursor;
	flags = chunk->flags;
	if (total_chunks == 0 || total_chunks > serial_info->max_entries ||
	    total_chunks > SHIRUDO_SERIAL_MAX_CHUNKS ||
	    bytes_total > SHIRUDO_SERIAL_MAX_BYTES ||
	    bytes_total > total_chunks * SHIRUDO_SERIAL_CHUNK_PAYLOAD) {
		rc = -EBADMSG;
		goto out_chunk;
	}
	if (page_index != want_page_index || cursor != want_cursor ||
	    next_cursor < cursor) {
		rc = -EBADMSG;
		goto out_chunk;
	}
	data = bytes_total ? xmalloc(bytes_total) : NULL;
	if (bytes_total && !data) {
		rc = -ENOMEM;
		goto out_chunk;
	}
	for (key = 0; key < total_chunks; key++) {
		if (key != 0 &&
		    bpf_map_lookup_elem(serial_fd, &key, chunk) != 0) {
			rc = -errno;
			goto out_data;
		}
		rc = shirudo_serial_chunk_validate(chunk, key, total_chunks,
						   page_index, cursor,
						   next_cursor, invocation_id);
		if (rc)
			goto out_data;
		if (chunk->status != 0) {
			rc = chunk->status < 0 ? chunk->status : -EIO;
			goto out_data;
		}
		if (chunk->bytes_total != bytes_total ||
		    copied + chunk->bytes_in_chunk > bytes_total) {
			rc = -EBADMSG;
			goto out_data;
		}
		if (chunk->bytes_in_chunk)
			memcpy(data + copied, chunk->data,
			       chunk->bytes_in_chunk);
		copied += chunk->bytes_in_chunk;
	}
	if (copied != bytes_total) {
		rc = -EBADMSG;
		goto out_data;
	}

	memset(page, 0, sizeof(*page));
	page->page_index = page_index;
	page->cursor = cursor;
	page->next_cursor = next_cursor;
	page->flags = flags;
	page->chunks = total_chunks;
	page->bytes = bytes_total;
	page->done = (page->flags & SHIRUDO_SERIAL_F_DONE) != 0;
	page->data = data;
	xfree(chunk, sizeof(*chunk));
	return 0;

out_data:
	xfree(data, bytes_total);
out_chunk:
	xfree(chunk, sizeof(*chunk));
	return rc;
}

/*
 * Return 1 when a serializer was found and populated out, 0 when none
 * exists for this map, or -errno on serializer/output failure.
 */
static int try_read_serialized(const char *upatch, const char *map,
			       struct shirudo_map_view *out)
{
	struct bpf_map_info serial_info = {};
	uint64_t cursor = 0, bytes_total = 0, invocation_id;
	uint32_t page_index;
	int prog_fd = -1, serial_fd = -1, lock_fd = -1, rc;

	if (strcmp(map, SHIRUDO_SERIAL_MAP_NAME) == 0)
		return 0;
	prog_fd = open_serializer_pin(upatch, map);
	if (prog_fd < 0) {
		if (prog_fd == -ENOENT)
			return 0;
		return prog_fd;
	}
	rc = open_map_pin(upatch, SHIRUDO_SERIAL_MAP_NAME,
			  &serial_fd, &serial_info);
	if (rc)
		goto out;
	rc = validate_serial_map(&serial_info);
	if (rc)
		goto out;
	/*
	 * Clearing, running and reading are one transaction. Key the lock by
	 * the kernel map ID so every process sharing this exact output map
	 * contends, while unrelated upatches remain independent.
	 */
	lock_fd = shirudo_serializer_lock_acquire(serial_info.id);
	if (lock_fd < 0) {
		rc = lock_fd;
		lock_fd = -1;
		goto out;
	}
	rc = shirudo_serializer_new_invocation_id(&invocation_id);
	if (rc)
		goto out;

	for (page_index = 0; page_index < SHIRUDO_SERIAL_MAX_PAGES;
	     page_index++) {
		struct shirudo_serialize_ctx ctx = {};
		struct shirudo_serial_page page = {};
		uint32_t retval = 0;

		rc = clear_serial_map(serial_fd, &serial_info);
		if (rc)
			goto out;

		ctx.magic = SHIRUDO_SERIAL_MAGIC;
		ctx.version = SHIRUDO_SERIAL_VERSION;
		ctx.max_chunks = serial_info.max_entries;
		ctx.chunk_payload_size = SHIRUDO_SERIAL_CHUNK_PAYLOAD;
		ctx.page_index = page_index;
		ctx.cursor = cursor;
		ctx.invocation_id = invocation_id;

		rc = prog_test_run_ctx(prog_fd, &ctx, sizeof(ctx), &retval);
		if (rc)
			goto out;
		if ((int32_t)retval < 0) {
			rc = (int32_t)retval;
			goto out;
		}
		if (ctx.magic != SHIRUDO_SERIAL_MAGIC ||
		    ctx.version != SHIRUDO_SERIAL_VERSION ||
		    ctx.page_index != page_index ||
		    ctx.cursor != cursor ||
		    ctx.invocation_id != invocation_id) {
			rc = -EBADMSG;
			goto out;
		}

		rc = read_serial_page(serial_fd, &serial_info, page_index,
				      cursor, invocation_id, &page);
		if (rc)
			goto out;
		if (bytes_total + page.bytes > SHIRUDO_SERIAL_MAX_TOTAL_BYTES) {
			xfree(page.data, page.bytes);
			rc = -E2BIG;
			goto out;
		}
		bytes_total += page.bytes;
		rc = append_serial_page(out, &page);
		if (rc) {
			xfree(page.data, page.bytes);
			goto out;
		}

		page = out->serial_pages[out->n_serial_pages - 1];
		if (page.done)
			break;
		if (page.next_cursor == cursor) {
			rc = -EBADMSG;
			goto out;
		}
		cursor = page.next_cursor;
	}
	if (out->n_serial_pages == 0 ||
	    !out->serial_pages[out->n_serial_pages - 1].done) {
		rc = -E2BIG;
		goto out;
	}

	out->serialized = true;
	out->serial_bytes_total = bytes_total;
	close(lock_fd);
	close(serial_fd);
	close(prog_fd);
	return 1;

out:
	if (rc < 0 && out->serial_pages) {
		uint32_t i;

		for (i = 0; i < out->n_serial_pages; i++)
			xfree(out->serial_pages[i].data,
			      out->serial_pages[i].bytes);
		xfree(out->serial_pages,
		      out->n_serial_pages * sizeof(*out->serial_pages));
		out->serial_pages = NULL;
		out->n_serial_pages = 0;
		out->serial_bytes_total = 0;
	}
	if (serial_fd >= 0)
		close(serial_fd);
	if (lock_fd >= 0)
		close(lock_fd);
	if (prog_fd >= 0)
		close(prog_fd);
	return rc;
}

/* Iterate every entry of a map with cap; populate v->entries. */
static int read_entries(int fd, struct shirudo_map_view *v,
			uint32_t cap)
{
	size_t value_count = shirudo_upatch_map_is_percpu(v->type) ?
		v->n_cpus : 1;
	size_t value_alloc;
	uint32_t i;
	int err;

	if (shirudo_upatch_map_value_stride(v) != 0 &&
	    value_count > SIZE_MAX / shirudo_upatch_map_value_stride(v))
		return -EOVERFLOW;
	value_alloc = (size_t)shirudo_upatch_map_value_stride(v) * value_count;

	v->entries = NULL;
	v->n_entries = 0;
	v->truncated = false;
	v->n_truncated_at = cap;

	if (is_array_type(v->type)) {
		uint32_t take = v->max_entries;
		size_t bytes;

		if (cap && take > cap) {
			take = cap;
			v->truncated = (v->max_entries > cap);
		}
		if (take == 0)
			return 0;
		bytes = (size_t)take * sizeof(*v->entries);
		v->entries = xcalloc(take, sizeof(*v->entries));
		if (!v->entries)
			return -ENOMEM;
		(void)bytes;
		for (i = 0; i < take; i++) {
			void *key = xmalloc(v->key_size);
			void *value = xmalloc(value_alloc);

			if (!key || !value) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				return -ENOMEM;
			}
			memcpy(key, &i, sizeof(i) <= v->key_size ?
				       sizeof(i) : v->key_size);
			if (v->key_size > sizeof(i))
				memset((char *)key + sizeof(i), 0,
				       v->key_size - sizeof(i));
			err = bpf_map_lookup_elem(fd, key, value);
			if (err) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				continue;	/* hole; rare for ARRAY */
			}
			v->entries[v->n_entries].key = key;
			v->entries[v->n_entries].value = value;
			v->n_entries++;
		}
		return 0;
	}
	if (is_hash_type(v->type)) {
		void *prev_key = NULL;
		void *next_key;
		size_t entries_cap = 32;

		v->entries = xcalloc(entries_cap, sizeof(*v->entries));
		if (!v->entries)
			return -ENOMEM;
		next_key = xmalloc(v->key_size);
		if (!next_key)
			return -ENOMEM;
		while (bpf_map_get_next_key(fd, prev_key, next_key) == 0) {
			void *key = xmalloc(v->key_size);
			void *value = xmalloc(value_alloc);

			if (!key || !value) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				break;
			}
			memcpy(key, next_key, v->key_size);
			if (bpf_map_lookup_elem(fd, key, value) != 0) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				prev_key = next_key;
				continue;
			}
			if (v->n_entries == entries_cap) {
				void *p = xreallocarray(v->entries,
					entries_cap, entries_cap * 2,
					sizeof(*v->entries));
				if (!p) {
					xfree(key, v->key_size);
					xfree(value, value_alloc);
					break;
				}
				v->entries = p;
				memset((char *)v->entries +
				       entries_cap * sizeof(*v->entries),
				       0, entries_cap * sizeof(*v->entries));
				entries_cap *= 2;
			}
			v->entries[v->n_entries].key = key;
			v->entries[v->n_entries].value = value;
			v->n_entries++;
			if (cap && v->n_entries >= cap) {
				v->truncated = true;
				break;
			}
			prev_key = next_key;
		}
		xfree(next_key, v->key_size);
		return 0;
	}
	return -EOPNOTSUPP;
}

void shirudo_map_view_free(struct shirudo_map_view *v)
{
	size_t value_alloc;
	uint32_t i;

	if (!v)
		return;
	if (v->entries) {
		value_alloc = (size_t)shirudo_upatch_map_value_stride(v) *
			      (shirudo_upatch_map_is_percpu(v->type) ?
			       v->n_cpus : 1);
		for (i = 0; i < v->n_entries; i++) {
			xfree(v->entries[i].key, v->key_size);
			xfree(v->entries[i].value, value_alloc);
		}
		xfree(v->entries, v->n_entries * sizeof(*v->entries));
		v->entries = NULL;
		v->n_entries = 0;
	}
	if (v->btf) {
		btf__free(v->btf);
		v->btf = NULL;
	}
	if (v->serial_pages) {
		for (i = 0; i < v->n_serial_pages; i++)
			xfree(v->serial_pages[i].data,
			      v->serial_pages[i].bytes);
		xfree(v->serial_pages,
		      v->n_serial_pages * sizeof(*v->serial_pages));
		v->serial_pages = NULL;
		v->n_serial_pages = 0;
		v->serial_bytes_total = 0;
	}
}

int shirudo_upatch_maps_read(const char *upatch, const char *map,
			     uint32_t max_entries_cap,
			     struct shirudo_map_view *out)
{
	struct bpf_map_info info = {};
	char upatch_dir[PATH_MAX];
	char bpffs_name[SHIRUDO_UPATCH_BPFFS_NAME_MAX + 1];
	struct stat upatch_st;
	int fd = -1;
	int rc;

	memset(out, 0, sizeof(*out));
	snprintf(out->upatch, sizeof(out->upatch), "%s", upatch);
	snprintf(out->name, sizeof(out->name), "%s", map);

	rc = open_map_pin(upatch, map, &fd, &info);
	if (rc)
		return rc;
	out->type = info.type;
	out->type_name = shirudo_map_type_name(info.type);
	out->key_size = info.key_size;
	out->value_size = info.value_size;
	out->value_stride = map_value_stride(info.type, info.value_size);
	out->max_entries = info.max_entries;
	out->n_cpus = shirudo_upatch_map_is_percpu(info.type) ?
			(uint32_t)nproc_possible() : 1;
	resolve_map_location(out);
	if (!shirudo_upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), upatch) &&
	    (size_t)snprintf(upatch_dir, sizeof(upatch_dir), "%s/%s",
			     SHIRUDO_BPFFS_UPATCHES_DIR, bpffs_name) <
	    sizeof(upatch_dir) && stat(upatch_dir, &upatch_st) == 0)
		out->lifetime_start_ns =
			(uint64_t)upatch_st.st_ctim.tv_sec * 1000000000ULL +
			(uint64_t)upatch_st.st_ctim.tv_nsec;

	rc = try_read_serialized(upatch, map, out);
	if (rc < 0) {
		close(fd);
		return rc;
	}
	if (rc > 0) {
		close(fd);
		return 0;
	}

	if (shirudo_map_skip_reason(info.type)) {
		out->skipped = true;
		out->skipped_reason = shirudo_map_skip_reason(info.type);
		close(fd);
		return 0;
	}

	out->btf = try_load_btf(info.btf_id);
	if (out->btf) {
		size_t off;

		out->key_type_id = info.btf_key_type_id;
		out->value_type_id = info.btf_value_type_id;
		btf_type_name(out->btf, info.btf_key_type_id,
			      out->btf_key_type, sizeof(out->btf_key_type));
		btf_type_name(out->btf, info.btf_value_type_id,
			      out->btf_value_type, sizeof(out->btf_value_type));
		off = 0;
		out->key_type_def[0] = '\0';
		btf_type_signature_into(out->btf, info.btf_key_type_id,
					out->key_type_def,
					sizeof(out->key_type_def), &off, 0);
		off = 0;
		out->value_type_def[0] = '\0';
		btf_type_signature_into(out->btf, info.btf_value_type_id,
					out->value_type_def,
					sizeof(out->value_type_def), &off, 0);
	}

	rc = read_entries(fd, out, max_entries_cap);

	close(fd);
	return rc;
}

/* === Listing === */

static void summary_append(struct shirudo_map_summary **list, size_t *n,
			   size_t *cap, const struct shirudo_map_summary *one)
{
	if (*n == *cap) {
		size_t nc = *cap ? *cap * 2 : 8;
		void *p = xreallocarray(*list, *cap, nc, sizeof(**list));

		if (!p)
			return;
		*list = p;
		*cap = nc;
	}
	(*list)[(*n)++] = *one;
}

/* Read /var/lib/shirudo/bpffs/upatches/<upatch>/maps/<entry> dir. */
static void scan_upatch_maps(const char *upatch,
			     struct shirudo_map_summary **list, size_t *n,
			     size_t *cap)
{
	char dir[PATH_MAX];
	char bpffs_name[SHIRUDO_UPATCH_BPFFS_NAME_MAX + 1];
	struct dirent *e;
	DIR *d;

	if (shirudo_upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), upatch))
		return;
	if ((size_t)snprintf(dir, sizeof(dir), "%s/%s/maps",
			     SHIRUDO_BPFFS_UPATCHES_DIR, bpffs_name) >=
	    sizeof(dir))
		return;
	d = opendir(dir);
	if (!d)
		return;
	while ((e = readdir(d))) {
		struct bpf_map_info info = {};
		struct shirudo_map_summary one = {};
		int fd, rc;

		if (e->d_name[0] == '.')
			continue;
		if (strcmp(e->d_name, SHIRUDO_SERIAL_MAP_NAME) == 0)
			continue;
		rc = open_map_pin(upatch, e->d_name, &fd, &info);
		if (rc)
			continue;
		close(fd);
		snprintf(one.upatch, sizeof(one.upatch), "%s", upatch);
		snprintf(one.name, sizeof(one.name), "%.*s",
			 (int)(sizeof(one.name) - 1), e->d_name);
		one.type = info.type;
		one.type_name = shirudo_map_type_name(info.type);
		one.max_entries = info.max_entries;
		one.n_cpus = shirudo_upatch_map_is_percpu(info.type) ?
				(uint32_t)nproc_possible() : 1;
		summary_append(list, n, cap, &one);
	}
	closedir(d);
}

int shirudo_upatch_maps_list_one(const char *upatch,
				 struct shirudo_map_summary **out,
				 size_t *n_out)
{
	struct shirudo_map_summary *list = NULL;
	size_t n = 0, cap = 0;

	scan_upatch_maps(upatch, &list, &n, &cap);
	*out = list;
	*n_out = n;
	return 0;
}

int shirudo_upatch_maps_list_all(struct shirudo_map_summary **out,
				 size_t *n_out)
{
	struct shirudo_map_summary *list = NULL;
	size_t n = 0, cap = 0;
	struct dirent *e;
	DIR *d;

	d = opendir(SHIRUDO_BPFFS_UPATCHES_DIR);
	if (!d) {
		*out = NULL;
		*n_out = 0;
		return 0;
	}
	while ((e = readdir(d))) {
		char raw_name[SHIRUDO_UPATCH_NAME_MAX + 1];

		if (e->d_name[0] == '.')
			continue;
		if (shirudo_upatch_name_from_bpffs(raw_name, sizeof(raw_name),
						   e->d_name))
			continue;
		scan_upatch_maps(raw_name, &list, &n, &cap);
	}
	closedir(d);
	*out = list;
	*n_out = n;
	return 0;
}

void shirudo_map_summary_free(struct shirudo_map_summary *list, size_t n)
{
	if (list)
		xfree(list, n * sizeof(*list));
}

/* === Human render === */

void shirudo_upatch_maps_print_summary(const struct shirudo_map_summary *list,
				       size_t n)
{
	size_t i;

	if (n == 0) {
		printf("  (no pinned maps)\n");
		return;
	}
	printf("  %-22s %-16s %-18s %s\n", "UPATCH", "MAP", "TYPE",
	       "ENTRIES");
	for (i = 0; i < n; i++) {
		const struct shirudo_map_summary *m = &list[i];

		printf("  %-22s %-16s %-18s max=%u%s\n",
		       m->upatch, m->name, m->type_name, m->max_entries,
		       m->n_cpus > 1 ? "  (per-cpu)" : "");
	}
}

void shirudo_upatch_map_print_inline(const struct shirudo_map_summary *m)
{
	printf("      %-22s %-16s max=%u%s\n",
	       m->name, m->type_name, m->max_entries,
	       m->n_cpus > 1 ? "  (per-cpu)" : "");
}

/*
 * Format one (key, value) cell. Prefer the BTF-aware recursive
 * renderer (struct/union/array/enum expansion) when the view carries
 * the loaded BTF; fall back to the primitive/hex formatter for raw
 * scalars and the no-BTF case.
 */
char *shirudo_upatch_map_format_cell(const struct shirudo_map_view *v,
				     uint32_t type_id, const void *bytes,
				     uint32_t bytes_size,
				     const char *btf_name)
{
	char *s = NULL;

	if (v->btf && type_id)
		s = btf_format_value(v->btf, type_id, bytes, bytes_size, 0);
	if (!s)
		s = format_value(bytes, bytes_size, btf_name);
	return s;
}

/*
 * Render a captured multi-line type-def block under a "<label>:" header,
 * indenting continuation lines so the block lines up under the header
 * column. The first line stays inline with the label; every subsequent
 * '\n' gets 21 spaces of indent (the width of the existing
 * "Value type:          " label).
 */
static void print_type_def(const char *label, const char *def, uint32_t size)
{
	const char *p = def;

	printf("%-21s", label);
	while (*p) {
		const char *nl = strchr(p, '\n');

		if (nl) {
			printf("%.*s\n%-21s", (int)(nl - p), p, "");
			p = nl + 1;
		} else {
			printf("%s", p);
			break;
		}
	}
	printf(" (%u B)\n", size);
}

char *shirudo_upatch_map_hex_alloc(const void *data, uint32_t len)
{
	static const char hexdigits[] = "0123456789abcdef";
	const unsigned char *p = data;
	char *out;
	uint32_t i;

	out = xmalloc((size_t)len * 2 + 1);
	if (!out)
		return NULL;
	for (i = 0; i < len; i++) {
		out[2 * i] = hexdigits[p[i] >> 4];
		out[2 * i + 1] = hexdigits[p[i] & 0xf];
	}
	out[(size_t)len * 2] = '\0';
	return out;
}

static void print_serialized_hex(const unsigned char *data, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("  %08x: ", i);
		printf("%02x", data[i]);
		if (i % 16 == 15 || i + 1 == len)
			printf("\n");
		else if (i % 2 == 1)
			printf(" ");
	}
}

void shirudo_upatch_maps_print_detail(const struct shirudo_map_view *v)
{
	uint32_t i;

	printf("upatch:              %s\n", v->upatch);
	printf("Map:                 %s\n", v->name);
	if (shirudo_upatch_map_is_percpu(v->type))
		printf("Type:                %s (%u CPUs)\n",
		       v->type_name, v->n_cpus);
	else
		printf("Type:                %s\n", v->type_name);
	printf("Max entries:         %u\n", v->max_entries);
	if (v->skipped) {
		printf("Status:              skipped -- %s\n",
		       v->skipped_reason ? v->skipped_reason : "(no reason)");
		return;
	}
	if (v->serialized) {
		uint32_t p;

		printf("Status:              serialized\n");
		printf("Serialized pages:    %u\n", v->n_serial_pages);
		printf("Serialized bytes:    %" PRIu64 "\n",
		       v->serial_bytes_total);
		for (p = 0; p < v->n_serial_pages; p++) {
			const struct shirudo_serial_page *page =
				&v->serial_pages[p];

			printf("\nPage %u:\n", page->page_index);
			printf("  Cursor:            %" PRIu64 "\n",
			       page->cursor);
			printf("  Next cursor:       %" PRIu64 "\n",
			       page->next_cursor);
			printf("  Done:              %s\n",
			       page->done ? "true" : "false");
			printf("  Flags:             0x%x\n", page->flags);
			printf("  Chunks:            %u\n", page->chunks);
			printf("  Bytes:             %u\n", page->bytes);
			if (page->bytes) {
				printf("\n  Data (hex):\n");
				print_serialized_hex(page->data, page->bytes);
			}
		}
		return;
	}
	printf("Entries:             %u of %u%s\n", v->n_entries,
	       v->max_entries,
	       v->truncated ? "  (truncated; use --show-full)" : "");
	if (v->key_type_def[0])
		print_type_def("Key type:", v->key_type_def, v->key_size);
	else if (v->btf_key_type[0])
		printf("Key type:            %s (%u B)\n",
		       v->btf_key_type, v->key_size);
	else
		printf("Key size:            %u B  (no BTF)\n", v->key_size);
	if (v->value_type_def[0])
		print_type_def("Value type:", v->value_type_def, v->value_size);
	else if (v->btf_value_type[0])
		printf("Value type:          %s (%u B per CPU)\n",
		       v->btf_value_type, v->value_size);
	else
		printf("Value size:          %u B  (no BTF)\n", v->value_size);

	if (v->n_entries == 0)
		return;
	printf("\nContents:\n");
	for (i = 0; i < v->n_entries; i++) {
		const struct shirudo_map_entry *en = &v->entries[i];
		char *key_s = shirudo_upatch_map_format_cell(v, v->key_type_id,
						  en->key, v->key_size,
						  v->btf_key_type);

		if (shirudo_upatch_map_is_percpu(v->type)) {
			char *sum_s = shirudo_upatch_map_format_percpu_sum(v,
				en->value, v->btf_value_type);
			int j;

			printf("  key=%s: sum=%s\n", key_s ? key_s : "?",
			       sum_s ? sum_s : "?");
			for (j = 0; j < (int)v->n_cpus; j++) {
				char *one = shirudo_upatch_map_format_cell(v,
					v->value_type_id,
					(const char *)en->value
						+ (size_t)j *
						  shirudo_upatch_map_value_stride(v),
					v->value_size, v->btf_value_type);

				if (j % 4 == 0)
					printf("    ");
				printf("cpu%d=%-7s  ", j, one ? one : "?");
				if ((j + 1) % 4 == 0)
					printf("\n");
				xstrfree(one);
			}
			if (v->n_cpus % 4 != 0)
				printf("\n");
			xstrfree(sum_s);
		} else {
			char *val_s = shirudo_upatch_map_format_cell(v,
				v->value_type_id, en->value, v->value_size,
				v->btf_value_type);

			printf("  key = %s\n     -> %s\n", key_s ? key_s : "?",
			       val_s ? val_s : "?");
			xstrfree(val_s);
		}
		xstrfree(key_s);
	}
}

/* === JSON === */

void shirudo_upatch_maps_emit_json_fields(struct shirudo_json_emit *e,
					  const struct shirudo_map_view *v)
{
	uint32_t i, j;

	if (!v)
		return;
	shirudo_json_kv_string(e, "name", v->name);
	shirudo_json_kv_string(e, "type", v->type_name);
	shirudo_json_kv_int(e, "max_entries", v->max_entries);
	shirudo_json_kv_int(e, "n_entries", v->n_entries);
	if (shirudo_upatch_map_is_percpu(v->type))
		shirudo_json_kv_int(e, "n_cpus", v->n_cpus);
	if (v->serialized) {
		uint32_t p;

		shirudo_json_kv_bool(e, "serialized", true);
		shirudo_json_kv_int(e, "serialized_pages",
				    v->n_serial_pages);
		shirudo_json_kv_int(e, "serialized_bytes",
				    v->serial_bytes_total);
		shirudo_json_arr_open(e, "pages");
		for (p = 0; p < v->n_serial_pages; p++) {
			const struct shirudo_serial_page *page =
				&v->serial_pages[p];
			char *hex = shirudo_upatch_map_hex_alloc(page->data,
							 page->bytes);

			shirudo_json_obj_open(e);
			shirudo_json_kv_int(e, "page_index",
					    page->page_index);
			shirudo_json_kv_int(e, "cursor", page->cursor);
			shirudo_json_kv_int(e, "next_cursor",
					    page->next_cursor);
			shirudo_json_kv_bool(e, "done", page->done);
			shirudo_json_kv_int(e, "flags", page->flags);
			shirudo_json_kv_int(e, "chunks", page->chunks);
			shirudo_json_kv_int(e, "bytes", page->bytes);
			shirudo_json_kv_string(e, "data_hex",
					       hex ? hex : "");
			xfree(hex, (size_t)page->bytes * 2 + 1);
			shirudo_json_obj_close(e);
		}
		shirudo_json_arr_close(e);
		return;
	}
	shirudo_json_kv_bool(e, "serialized", false);
	if (v->skipped) {
		shirudo_json_kv_string(e, "skipped",
				       v->skipped_reason ?
					       v->skipped_reason : "");
		return;
	}
	shirudo_json_kv_bool(e, "truncated", v->truncated);
	if (v->truncated)
		shirudo_json_kv_int(e, "n_truncated_at", v->n_truncated_at);
	if (v->btf_key_type[0] || v->btf_value_type[0]) {
		shirudo_json_obj_open_key(e, "btf");
		shirudo_json_kv_string(e, "key_type",
				       v->btf_key_type[0] ? v->btf_key_type
							  : "");
		shirudo_json_kv_string(e, "value_type",
				       v->btf_value_type[0] ?
					       v->btf_value_type : "");
		if (v->key_type_def[0])
			shirudo_json_kv_string(e, "key_type_def",
					       v->key_type_def);
		if (v->value_type_def[0])
			shirudo_json_kv_string(e, "value_type_def",
					       v->value_type_def);
		shirudo_json_obj_close(e);
	}
	shirudo_json_arr_open(e, "entries");
	for (i = 0; i < v->n_entries; i++) {
		const struct shirudo_map_entry *en = &v->entries[i];
		char *key_s = shirudo_upatch_map_format_cell(v, v->key_type_id,
						  en->key, v->key_size,
						  v->btf_key_type);

		shirudo_json_obj_open(e);
		shirudo_json_kv_string(e, "key", key_s ? key_s : "");
		if (shirudo_upatch_map_is_percpu(v->type)) {
			char *sum_s = shirudo_upatch_map_format_percpu_sum(v,
				en->value, v->btf_value_type);

			shirudo_json_arr_open(e, "values_per_cpu");
			for (j = 0; j < v->n_cpus; j++) {
				char *one = shirudo_upatch_map_format_cell(v,
					v->value_type_id,
					(const char *)en->value
						+ (size_t)j *
						  shirudo_upatch_map_value_stride(v),
					v->value_size, v->btf_value_type);

				shirudo_json_str(e, one ? one : "");
				xstrfree(one);
			}
			shirudo_json_arr_close(e);
			shirudo_json_kv_string(e, "sum",
					       sum_s ? sum_s : "");
			xstrfree(sum_s);
		} else {
			char *val_s = shirudo_upatch_map_format_cell(v,
				v->value_type_id, en->value, v->value_size,
				v->btf_value_type);

			shirudo_json_kv_string(e, "value",
					       val_s ? val_s : "");
			xstrfree(val_s);
		}
		shirudo_json_obj_close(e);
		xstrfree(key_s);
	}
	shirudo_json_arr_close(e);
}

void shirudo_upatch_maps_emit_json_object(struct shirudo_json_emit *e,
					  const struct shirudo_map_view *v)
{
	if (!v)
		return;
	shirudo_json_obj_open(e);
	shirudo_upatch_maps_emit_json_fields(e, v);
	shirudo_json_obj_close(e);
}
