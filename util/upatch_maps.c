// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Pinned upatch maps reader. Walks /var/lib/shirudo/bpffs/upatches/
 * <name>/maps/<map>, opens each pin via BPF_OBJ_GET, dispatches to a
 * per-type reader for the entries. BTF type names come from
 * libbpf::btf__name_by_offset() when the map carries a btf_id.
 *
 * Read-only -- every bpf() syscall used here is on shirudo's LSM
 * allow-list (BPF_OBJ_GET, MAP_LOOKUP_ELEM, MAP_GET_NEXT_KEY,
 * OBJ_GET_INFO_BY_FD).
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>

#include "json.h"
#include "malloc.h"
#include "paths.h"
#include "upatch_maps.h"

/* Map of BPF_MAP_TYPE_* -> short label used in JSON and human render. */
static const char *map_type_name(uint32_t type)
{
	switch (type) {
	case BPF_MAP_TYPE_ARRAY:		return "array";
	case BPF_MAP_TYPE_PERCPU_ARRAY:		return "percpu_array";
	case BPF_MAP_TYPE_HASH:			return "hash";
	case BPF_MAP_TYPE_PERCPU_HASH:		return "percpu_hash";
	case BPF_MAP_TYPE_LRU_HASH:		return "lru_hash";
	case BPF_MAP_TYPE_LRU_PERCPU_HASH:	return "lru_percpu_hash";
	case BPF_MAP_TYPE_RINGBUF:		return "ringbuf";
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:	return "perf_event_array";
	case BPF_MAP_TYPE_STACK_TRACE:		return "stack_trace";
	case BPF_MAP_TYPE_PROG_ARRAY:		return "prog_array";
	default:				return "unknown";
	}
}

static bool is_percpu_type(uint32_t type)
{
	return type == BPF_MAP_TYPE_PERCPU_ARRAY ||
	       type == BPF_MAP_TYPE_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
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

/*
 * Types for which `--include-maps` should not attempt to dump contents
 * inline: ringbufs are queue-like, stack-traces and perf-event-arrays
 * need bespoke renderers, prog-arrays carry function pointers. Listed
 * (so the operator sees they exist) but content read is deferred to
 * future verbs.
 */
static const char *skip_reason(uint32_t type)
{
	switch (type) {
	case BPF_MAP_TYPE_RINGBUF:
		return "use `shirudo upatch ringbuf` (future work)";
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		return "perf-event-array: use `shirudo upatch perfbuf` "
		       "(future work)";
	case BPF_MAP_TYPE_STACK_TRACE:
		return "stack-trace: use `shirudo upatch stacktrace` "
		       "(future work)";
	case BPF_MAP_TYPE_PROG_ARRAY:
		return "prog-array carries function pointers; not dumpable";
	default:
		return NULL;
	}
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

/* Heap snprintf into a fresh buffer with the printf result. */
static char *fmt_alloc(const char *fmt, ...) __attribute__((format(printf,1,2)));
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

static char *format_percpu_sum(const void *values_per_cpu,
			       uint32_t value_size, int n_cpus,
			       const char *btf_type)
{
	if (value_size == 8) {
		uint64_t sum = 0;
		int i;

		for (i = 0; i < n_cpus; i++) {
			uint64_t v;

			memcpy(&v, (const char *)values_per_cpu +
			       (size_t)i * value_size, 8);
			sum += v;
		}
		return fmt_alloc("%" PRIu64, sum);
	}
	if (value_size == 4) {
		uint64_t sum = 0;
		int i;

		for (i = 0; i < n_cpus; i++) {
			uint32_t v;

			memcpy(&v, (const char *)values_per_cpu +
			       (size_t)i * value_size, 4);
			sum += v;
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
	uint32_t info_len = sizeof(*info_out);
	int fd;

	if ((size_t)snprintf(path, sizeof(path), "%s/%s/maps/%s",
			     SHIRUDO_BPFFS_UPATCHES_DIR, upatch, map_name)
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

/* Iterate every entry of a map with cap; populate v->entries. */
static int read_entries(int fd, struct shirudo_map_view *v,
			uint32_t cap)
{
	uint32_t value_alloc = v->value_size *
			       (v->n_cpus > 1 ? v->n_cpus : 1);
	uint32_t i;
	int err;

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
	uint32_t i;
	uint32_t value_alloc;

	if (!v || !v->entries)
		return;
	value_alloc = v->value_size * (v->n_cpus > 1 ? v->n_cpus : 1);
	for (i = 0; i < v->n_entries; i++) {
		xfree(v->entries[i].key, v->key_size);
		xfree(v->entries[i].value, value_alloc);
	}
	xfree(v->entries, v->n_entries * sizeof(*v->entries));
	v->entries = NULL;
	v->n_entries = 0;
}

int shirudo_upatch_maps_read(const char *upatch, const char *map,
			     uint32_t max_entries_cap,
			     struct shirudo_map_view *out)
{
	struct bpf_map_info info = {};
	struct btf *btf;
	int fd = -1;
	int rc;

	memset(out, 0, sizeof(*out));
	snprintf(out->upatch, sizeof(out->upatch), "%s", upatch);
	snprintf(out->name, sizeof(out->name), "%s", map);

	rc = open_map_pin(upatch, map, &fd, &info);
	if (rc)
		return rc;
	out->type = info.type;
	out->type_name = map_type_name(info.type);
	out->key_size = info.key_size;
	out->value_size = info.value_size;
	out->max_entries = info.max_entries;
	out->n_cpus = is_percpu_type(info.type) ?
			(uint32_t)nproc_possible() : 1;

	if (skip_reason(info.type)) {
		out->skipped = true;
		out->skipped_reason = skip_reason(info.type);
		close(fd);
		return 0;
	}

	btf = try_load_btf(info.btf_id);
	if (btf) {
		btf_type_name(btf, info.btf_key_type_id,
			      out->btf_key_type, sizeof(out->btf_key_type));
		btf_type_name(btf, info.btf_value_type_id,
			      out->btf_value_type, sizeof(out->btf_value_type));
	}

	rc = read_entries(fd, out,
			  max_entries_cap ? max_entries_cap
					  : SHIRUDO_MAP_ENTRIES_DEFAULT);

	btf__free(btf);
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
	struct dirent *e;
	DIR *d;

	if ((size_t)snprintf(dir, sizeof(dir), "%s/%s/maps",
			     SHIRUDO_BPFFS_UPATCHES_DIR, upatch) >=
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
		rc = open_map_pin(upatch, e->d_name, &fd, &info);
		if (rc)
			continue;
		close(fd);
		snprintf(one.upatch, sizeof(one.upatch), "%s", upatch);
		snprintf(one.name, sizeof(one.name), "%.*s",
			 (int)(sizeof(one.name) - 1), e->d_name);
		one.type = info.type;
		one.type_name = map_type_name(info.type);
		one.max_entries = info.max_entries;
		one.n_cpus = is_percpu_type(info.type) ?
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
		if (e->d_name[0] == '.')
			continue;
		scan_upatch_maps(e->d_name, &list, &n, &cap);
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

void shirudo_upatch_maps_print_detail(const struct shirudo_map_view *v)
{
	uint32_t i;

	printf("Upatch:            %s\n", v->upatch);
	printf("Map:                %s\n", v->name);
	if (v->n_cpus > 1)
		printf("Type:                %s (%u CPUs)\n",
		       v->type_name, v->n_cpus);
	else
		printf("Type:                %s\n", v->type_name);
	if (v->skipped) {
		printf("Status:              skipped -- %s\n",
		       v->skipped_reason ? v->skipped_reason : "(no reason)");
		return;
	}
	printf("Entries:             %u of %u%s\n", v->n_entries,
	       v->max_entries,
	       v->truncated ? "  (truncated; use --show-full)" : "");
	if (v->btf_key_type[0])
		printf("Key type:            %s (%u B)\n",
		       v->btf_key_type, v->key_size);
	else
		printf("Key size:            %u B  (no BTF)\n", v->key_size);
	if (v->btf_value_type[0])
		printf("Value type:          %s (%u B per CPU)\n",
		       v->btf_value_type, v->value_size);
	else
		printf("Value size:          %u B  (no BTF)\n", v->value_size);

	printf("\nContents:\n");
	for (i = 0; i < v->n_entries; i++) {
		const struct shirudo_map_entry *en = &v->entries[i];
		char *key_s = format_value(en->key, v->key_size,
					   v->btf_key_type);

		if (v->n_cpus > 1) {
			char *sum_s = format_percpu_sum(en->value,
				v->value_size, (int)v->n_cpus,
				v->btf_value_type);
			int j;

			printf("  key=%s: sum=%s\n", key_s ? key_s : "?",
			       sum_s ? sum_s : "?");
			for (j = 0; j < (int)v->n_cpus; j++) {
				char *one = format_value((const char *)en->value
					+ (size_t)j * v->value_size,
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
			char *val_s = format_value(en->value, v->value_size,
						   v->btf_value_type);

			printf("  key=%s  ->  %s\n", key_s ? key_s : "?",
			       val_s ? val_s : "?");
			xstrfree(val_s);
		}
		xstrfree(key_s);
	}
}

/* === JSON === */

void shirudo_upatch_maps_emit_json(struct shirudo_json_emit *e,
				   const struct shirudo_map_view *v)
{
	uint32_t i, j;

	if (!v)
		return;
	shirudo_json_obj_open(e);
	shirudo_json_kv_string(e, "name", v->name);
	shirudo_json_kv_string(e, "type", v->type_name);
	shirudo_json_kv_int(e, "max_entries", v->max_entries);
	shirudo_json_kv_int(e, "n_entries", v->n_entries);
	if (v->n_cpus > 1)
		shirudo_json_kv_int(e, "n_cpus", v->n_cpus);
	if (v->skipped) {
		shirudo_json_kv_string(e, "skipped",
				       v->skipped_reason ?
					       v->skipped_reason : "");
		shirudo_json_obj_close(e);
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
		shirudo_json_obj_close(e);
	}
	shirudo_json_arr_open(e, "entries");
	for (i = 0; i < v->n_entries; i++) {
		const struct shirudo_map_entry *en = &v->entries[i];
		char *key_s = format_value(en->key, v->key_size,
					   v->btf_key_type);

		shirudo_json_obj_open(e);
		shirudo_json_kv_string(e, "key", key_s ? key_s : "");
		if (v->n_cpus > 1) {
			char *sum_s = format_percpu_sum(en->value,
				v->value_size, (int)v->n_cpus,
				v->btf_value_type);

			shirudo_json_arr_open(e, "values_per_cpu");
			for (j = 0; j < v->n_cpus; j++) {
				char *one = format_value((const char *)en->value
					+ (size_t)j * v->value_size,
					v->value_size, v->btf_value_type);

				shirudo_json_str(e, one ? one : "");
				xstrfree(one);
			}
			shirudo_json_arr_close(e);
			shirudo_json_kv_string(e, "sum",
					       sum_s ? sum_s : "");
			xstrfree(sum_s);
		} else {
			char *val_s = format_value(en->value, v->value_size,
						   v->btf_value_type);

			shirudo_json_kv_string(e, "value",
					       val_s ? val_s : "");
			xstrfree(val_s);
		}
		shirudo_json_obj_close(e);
		xstrfree(key_s);
	}
	shirudo_json_arr_close(e);
	shirudo_json_obj_close(e);
}
