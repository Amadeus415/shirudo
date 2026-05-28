/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Read pinned upatch maps under /var/lib/shirudo/bpffs/upatches/<name>/
 * maps/<map>. Shared by `shirudo upatch map` (CLI), `shirudo status
 * --include-maps` (target-local JSON/human), and `shirudo nodes show`
 * (operator pulls the same JSON over SSH).
 *
 * Surface targets the common observability case (counters, small
 * hash tables) and degrades gracefully on richer types: ringbufs,
 * stack-traces, perf-event arrays are listed as
 * `skipped: "use 'shirudo upatch <verb>' (future work)"`.
 */

#ifndef SHIRUDO_UTIL_UPATCH_MAPS_H
#define SHIRUDO_UTIL_UPATCH_MAPS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Default truncation cap; --show-full lifts it. */
#define SHIRUDO_MAP_ENTRIES_DEFAULT	256

#define SHIRUDO_MAP_NAME_MAX		16	/* BPF_OBJ_NAME_LEN */
#define SHIRUDO_MAP_TYPENAME_MAX	64

struct shirudo_json_emit;

/*
 * One key+value pair as the reader produced it. The raw key/value
 * bytes are heap-owned (xmalloc); render code decides how to
 * format them based on the surrounding `shirudo_map_view`.
 */
struct shirudo_map_entry {
	void		*key;		/* key_size bytes */
	void		*value;		/* value_size * (per-CPU ? n_cpus : 1) */
};

/*
 * SHIRUDO_MAP_TYPEDEF_MAX bounds the multi-line struct/array
 * "definition" string captured at read time (struct foo { __u32 a; ... }).
 * Big enough for the common shirudo case (~10 fields); structs larger
 * than this are truncated with "; ..." and the renderer still works.
 */
#define SHIRUDO_MAP_TYPEDEF_MAX		1024

struct btf;

struct shirudo_map_view {
	char		upatch[64];
	char		name[SHIRUDO_MAP_NAME_MAX + 1];
	uint32_t	type;		/* BPF_MAP_TYPE_* */
	const char	*type_name;	/* "percpu_array" / "hash" / ... */
	uint32_t	key_size;
	uint32_t	value_size;	/* per-CPU value size (not multiplied) */
	uint32_t	max_entries;
	uint32_t	n_entries;	/* live entries iterated */
	uint32_t	n_cpus;		/* 1 for non-percpu types */
	bool		truncated;
	uint32_t	n_truncated_at;
	bool		skipped;
	const char	*skipped_reason;
	char		btf_key_type[SHIRUDO_MAP_TYPENAME_MAX];
	char		btf_value_type[SHIRUDO_MAP_TYPENAME_MAX];
	char		key_type_def[SHIRUDO_MAP_TYPEDEF_MAX];
	char		value_type_def[SHIRUDO_MAP_TYPEDEF_MAX];
	uint32_t	key_type_id;
	uint32_t	value_type_id;
	struct btf	*btf;		/* heap; owned by the view */
	struct shirudo_map_entry	*entries;	/* n_entries long */
};

void shirudo_map_view_free(struct shirudo_map_view *v);

/*
 * Lightweight directory enumeration: list every pinned map across
 * every loaded upatch, with name/type/max_entries only (no entry
 * read). out[] is xmalloc'd, free with shirudo_map_summary_free().
 */
struct shirudo_map_summary {
	char		upatch[64];
	char		name[SHIRUDO_MAP_NAME_MAX + 1];
	uint32_t	type;
	const char	*type_name;
	uint32_t	max_entries;
	uint32_t	n_cpus;
};

int  shirudo_upatch_maps_list_all(struct shirudo_map_summary **out,
				  size_t *n_out);
int  shirudo_upatch_maps_list_one(const char *upatch,
				  struct shirudo_map_summary **out,
				  size_t *n_out);
void shirudo_map_summary_free(struct shirudo_map_summary *list, size_t n);

/*
 * Read one map's contents. <max_entries_cap> bounds the number of
 * (key, value) pairs returned; SHIRUDO_MAP_ENTRIES_DEFAULT for the
 * default, 0 for unlimited (--show-full). Returns 0/-errno.
 */
int  shirudo_upatch_maps_read(const char *upatch, const char *map,
			      uint32_t max_entries_cap,
			      struct shirudo_map_view *out);

/* Human-readable describe-style render. */
void shirudo_upatch_maps_print_summary(const struct shirudo_map_summary *list,
				       size_t n);
void shirudo_upatch_maps_print_detail(const struct shirudo_map_view *v);

/* Compact one-liner used inside the upatches loaded section. */
void shirudo_upatch_map_print_inline(const struct shirudo_map_summary *m);

/*
 * Emit one map view as a JSON object. Caller wraps in `maps[]` and
 * the upatch object. NULL `v` emits nothing. The shape matches the
 * one documented in PLAN.md so target-local status and operator-side
 * nodes show agree.
 */
void shirudo_upatch_maps_emit_json(struct shirudo_json_emit *e,
				   const struct shirudo_map_view *v);

#endif /* SHIRUDO_UTIL_UPATCH_MAPS_H */
