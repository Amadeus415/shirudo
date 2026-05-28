// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * /proc/modules parser + ASCII dependency-tree printer. Roots are
 * modules nothing else depends on (the operator-loaded entry points);
 * each root descends into its `Depends:` chain. Shared subtrees
 * expand once and are marked `(shared)` thereafter.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <time.h>

#include "kmodules.h"
#include "malloc.h"
#include "timefmt.h"

void shirudo_human_size(uint64_t bytes, char *out, size_t out_cap)
{
	double v = (double)bytes;
	const char *suf = "B";

	if (bytes >= (1ULL << 30)) {
		v /= (double)(1ULL << 30);
		suf = "G";
	} else if (bytes >= (1ULL << 20)) {
		v /= (double)(1ULL << 20);
		suf = "M";
	} else if (bytes >= (1ULL << 10)) {
		v /= (double)(1ULL << 10);
		suf = "K";
	} else {
		snprintf(out, out_cap, "%llu%s",
			 (unsigned long long)bytes, suf);
		return;
	}
	if (v >= 100.0)
		snprintf(out, out_cap, "%.0f%s", v, suf);
	else if (v >= 10.0)
		snprintf(out, out_cap, "%.1f%s", v, suf);
	else
		snprintf(out, out_cap, "%.2f%s", v, suf);
}

/* Read /proc/modules into a heap-grown buffer. */
static int slurp(char **buf_out, size_t *len_out)
{
	size_t cap = 16384, len = 0;
	char *buf;
	int fd;

	fd = open("/proc/modules", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	buf = xmalloc(cap);
	if (!buf) {
		close(fd);
		return -ENOMEM;
	}
	for (;;) {
		ssize_t n = read(fd, buf + len, cap - len - 1);

		if (n < 0) {
			int e = -errno;

			xfree(buf, cap);
			close(fd);
			return e;
		}
		if (n == 0)
			break;
		len += (size_t)n;
		if (cap - len < 4096) {
			void *p = xreallocarray(buf, cap, cap * 2, 1);

			if (!p) {
				xfree(buf, cap);
				close(fd);
				return -ENOMEM;
			}
			buf = p;
			cap *= 2;
		}
	}
	close(fd);
	buf[len] = '\0';
	*buf_out = buf;
	*len_out = cap;	/* freed at full cap by caller */
	return 0;
}

static int kmod_cmp(const void *a, const void *b)
{
	return strcmp(((const struct shirudo_kmod *)a)->name,
		      ((const struct shirudo_kmod *)b)->name);
}

/* Find module index by name; -1 if not present (a stale dep entry). */
static int kmod_find(const struct shirudo_kmod_set *set, const char *name)
{
	size_t lo = 0, hi = set->n;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		int c = strcmp(set->mods[mid].name, name);

		if (c == 0)
			return (int)mid;
		if (c < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return -1;
}

int shirudo_kmodules_read(struct shirudo_kmod_set *set)
{
	char *buf = NULL;
	size_t buf_cap = 0;
	size_t mod_cap = 64, deps_cap = 256;
	char *line, *save = NULL;
	int rc;

	memset(set, 0, sizeof(*set));
	rc = slurp(&buf, &buf_cap);
	if (rc)
		return rc;

	set->mods = xmalloc(mod_cap * sizeof(*set->mods));
	set->deps = xmalloc(deps_cap * sizeof(*set->deps));
	if (!set->mods || !set->deps) {
		rc = -ENOMEM;
		goto fail;
	}

	/*
	 * First pass: collect each module's name, size, refcount, and
	 * a dep-string slice. We resolve dep names to indices after the
	 * full set is sorted (so we know all names exist).
	 */
	struct raw_dep {
		uint16_t	mod_idx;	/* index into set->mods */
		const char	*dep_name;
		size_t		dep_len;
	};
	size_t raw_cap = 256, n_raw = 0;
	struct raw_dep *raws = xmalloc(raw_cap * sizeof(*raws));

	if (!raws) {
		rc = -ENOMEM;
		goto fail;
	}

	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *p = line, *e;
		size_t name_len;
		struct shirudo_kmod *m;

		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			continue;
		e = p;
		while (*e && *e != ' ' && *e != '\t')
			e++;
		name_len = (size_t)(e - p);
		if (name_len == 0 || name_len >= SHIRUDO_KMOD_NAME_LEN)
			continue;

		if (set->n == mod_cap) {
			void *np = xreallocarray(set->mods, mod_cap,
						 mod_cap * 2,
						 sizeof(*set->mods));
			if (!np) {
				rc = -ENOMEM;
				goto fail_raws;
			}
			set->mods = np;
			mod_cap *= 2;
		}
		m = &set->mods[set->n];
		memcpy(m->name, p, name_len);
		m->name[name_len] = '\0';
		p = e;
		while (*p == ' ' || *p == '\t')
			p++;

		m->size = strtoull(p, &p, 10);
		while (*p == ' ' || *p == '\t')
			p++;
		m->refcount = (uint32_t)strtoul(p, &p, 10);
		while (*p == ' ' || *p == '\t')
			p++;

		m->n_deps = 0;
		m->deps_off = 0;

		/*
		 * Dep column is `dep1,dep2,...,` (trailing comma) or `-`.
		 * Stash raw name slices; resolve to indices after sort.
		 */
		if (*p && *p != '-') {
			const char *q = p;

			while (*q && *q != ' ' && *q != '\t') {
				const char *start = q;

				while (*q && *q != ',' && *q != ' ' && *q != '\t')
					q++;
				if (q > start) {
					if (n_raw == raw_cap) {
						void *np = xreallocarray(raws,
							raw_cap, raw_cap * 2,
							sizeof(*raws));
						if (!np) {
							rc = -ENOMEM;
							goto fail_raws;
						}
						raws = np;
						raw_cap *= 2;
					}
					raws[n_raw].mod_idx = (uint16_t)set->n;
					raws[n_raw].dep_name = start;
					raws[n_raw].dep_len =
						(size_t)(q - start);
					n_raw++;
				}
				if (*q == ',')
					q++;
			}
		}
		set->n++;
	}

	qsort(set->mods, set->n, sizeof(*set->mods), kmod_cmp);

	/* qsort scrambled indices; rebuild raws[].mod_idx by lookup. */
	for (size_t i = 0; i < n_raw; i++) {
		/* The original raws[i].mod_idx is invalid post-sort. We
		 * stored the *raw* name slice but lost which module it
		 * belonged to. Re-discover by reparsing. */
		(void)0;
	}
	/*
	 * The qsort above invalidated raws[].mod_idx. We have no way
	 * to recover the owner without re-parsing, so do a second pass
	 * over /proc/modules' text. Cheap: typically ~100 lines.
	 */
	n_raw = 0;
	/*
	 * Reload /proc/modules: strtok_r mutated `buf` on the first
	 * pass and there is no portable rewind for an in-memory blob,
	 * so we slurp fresh.
	 */
	{
		char *buf2;
		size_t buf2_cap;

		rc = slurp(&buf2, &buf2_cap);
		if (rc)
			goto fail_raws;
		xfree(buf, buf_cap);
		buf = buf2;
		buf_cap = buf2_cap;
	}
	save = NULL;
	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *p = line, *e;
		size_t name_len;
		int child_idx;
		char namebuf[SHIRUDO_KMOD_NAME_LEN];
		int col;

		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			continue;
		e = p;
		while (*e && *e != ' ' && *e != '\t')
			e++;
		name_len = (size_t)(e - p);
		if (name_len == 0 || name_len >= SHIRUDO_KMOD_NAME_LEN)
			continue;
		memcpy(namebuf, p, name_len);
		namebuf[name_len] = '\0';
		child_idx = kmod_find(set, namebuf);
		if (child_idx < 0)
			continue;

		/*
		 * /proc/modules columns: name size refcount used_by state
		 * offset. The 4th column is *who uses this module*, not
		 * the other way around. So for line `m ... ... u1,u2,u3`
		 * we want edges u1->m, u2->m, u3->m (m becomes a child
		 * of each user in the tree). Skip 2 columns to land on
		 * the used_by list.
		 */
		p = e;
		for (col = 0; col < 2 && *p; col++) {
			while (*p == ' ' || *p == '\t')
				p++;
			while (*p && *p != ' ' && *p != '\t')
				p++;
		}
		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p || *p == '-')
			continue;
		while (*p && *p != ' ' && *p != '\t') {
			const char *start = p;

			while (*p && *p != ',' && *p != ' ' && *p != '\t')
				p++;
			if (p > start) {
				char user[SHIRUDO_KMOD_NAME_LEN];
				size_t ulen = (size_t)(p - start);
				int user_idx;

				if (ulen >= sizeof(user))
					goto skip;
				memcpy(user, start, ulen);
				user[ulen] = '\0';
				user_idx = kmod_find(set, user);
				if (user_idx < 0)
					goto skip;
				if (n_raw == raw_cap) {
					void *np = xreallocarray(raws, raw_cap,
						raw_cap * 2, sizeof(*raws));
					if (!np) {
						rc = -ENOMEM;
						goto fail_raws;
					}
					raws = np;
					raw_cap *= 2;
				}
				raws[n_raw].mod_idx = (uint16_t)user_idx;
				raws[n_raw].dep_name = set->mods[child_idx].name;
				raws[n_raw].dep_len = strlen(raws[n_raw].dep_name);
				n_raw++;
			}
skip:
			if (*p == ',')
				p++;
		}
	}

	/* Compact raws[] into set->deps[]. Group by mod_idx. */
	for (size_t i = 0; i < set->n; i++) {
		set->mods[i].deps_off = (uint16_t)set->n_deps;
		for (size_t j = 0; j < n_raw; j++) {
			char namebuf[SHIRUDO_KMOD_NAME_LEN];
			int idx;

			if (raws[j].mod_idx != i)
				continue;
			if (raws[j].dep_len >= sizeof(namebuf))
				continue;
			memcpy(namebuf, raws[j].dep_name, raws[j].dep_len);
			namebuf[raws[j].dep_len] = '\0';
			idx = kmod_find(set, namebuf);
			if (idx < 0)
				continue;
			if (set->n_deps == deps_cap) {
				void *np = xreallocarray(set->deps, deps_cap,
					deps_cap * 2, sizeof(*set->deps));
				if (!np) {
					rc = -ENOMEM;
					goto fail_raws;
				}
				set->deps = np;
				deps_cap *= 2;
			}
			set->deps[set->n_deps++] = (uint16_t)idx;
			set->mods[i].n_deps++;
		}
	}

	/*
	 * Stat each /sys/module/<name>/ for its kernfs mtime, which the
	 * kernel sets when sysfs_create_dir registers the module's
	 * kobject during init_module/finit_module. That mtime is the
	 * load time. ENOENT on a race (rmmod between /proc/modules read
	 * and this stat) is non-fatal; leave loaded_at zero.
	 */
	for (size_t i = 0; i < set->n; i++) {
		struct shirudo_kmod *m = &set->mods[i];
		char path[64 + sizeof("/sys/module/")];
		struct stat st;

		snprintf(path, sizeof(path), "/sys/module/%s", m->name);
		if (stat(path, &st) == 0) {
			m->loaded_at_sec  = (int64_t)st.st_mtim.tv_sec;
			m->loaded_at_nsec = (int32_t)st.st_mtim.tv_nsec;
		}
	}

	xfree(raws, raw_cap * sizeof(*raws));
	xfree(buf, buf_cap);
	return 0;

fail_raws:
	xfree(raws, raw_cap * sizeof(*raws));
fail:
	xfree(buf, buf_cap);
	xfree(set->mods, mod_cap * sizeof(*set->mods));
	xfree(set->deps, deps_cap * sizeof(*set->deps));
	memset(set, 0, sizeof(*set));
	return rc;
}

void shirudo_kmodules_free(struct shirudo_kmod_set *set)
{
	xfree(set->mods, set->n * sizeof(*set->mods));
	xfree(set->deps, set->n_deps * sizeof(*set->deps));
	memset(set, 0, sizeof(*set));
}

/*
 * Print one module + its dependency subtree. `prefix` carries the
 * accumulated `│   `/`    ` indent for nested levels. `is_last` picks
 * `└── ` vs `├── `. `seen[]` is a bitset of "already expanded
 * somewhere above"; on a hit, the subtree collapses to `(shared)`.
 */
static void print_subtree(const struct shirudo_kmod_set *set, size_t i,
			  const char *prefix, int is_last, uint8_t *seen)
{
	const struct shirudo_kmod *m = &set->mods[i];
	const char *branch = is_last ? "└── " : "├── ";
	int already = (seen[i >> 3] >> (i & 7)) & 1;
	char size_s[16];
	char child_prefix[256];

	shirudo_human_size(m->size, size_s, sizeof(size_s));

	if (already) {
		printf("%s%s%s (shared)\n", prefix, branch, m->name);
		return;
	}
	seen[i >> 3] |= (uint8_t)(1U << (i & 7));

	printf("%s%s%s (%s, refs=%u)\n", prefix, branch, m->name,
	       size_s, (unsigned)m->refcount);

	snprintf(child_prefix, sizeof(child_prefix), "%s%s", prefix,
		 is_last ? "    " : "│   ");

	for (uint16_t k = 0; k < m->n_deps; k++) {
		size_t dep = set->deps[m->deps_off + k];
		int last_child = (k == m->n_deps - 1);

		print_subtree(set, dep, child_prefix, last_child, seen);
	}
}

void shirudo_kmodules_print_tree(const struct shirudo_kmod_set *set)
{
	uint8_t *used_by;
	uint8_t *seen;
	size_t bitmap_bytes;
	size_t n_roots = 0;
	size_t *roots;

	if (set->n == 0) {
		printf("  (no modules loaded)\n");
		return;
	}

	bitmap_bytes = (set->n + 7) / 8;
	used_by = xcalloc(bitmap_bytes, 1);
	seen   = xcalloc(bitmap_bytes, 1);
	roots  = xmalloc(set->n * sizeof(*roots));
	if (!used_by || !seen || !roots) {
		xfree(used_by, bitmap_bytes);
		xfree(seen, bitmap_bytes);
		xfree(roots, set->n * sizeof(*roots));
		printf("  (out of memory)\n");
		return;
	}

	/*
	 * Mark "is a dep of someone": that module is NOT a root.
	 * The remainder are entry-point modules nothing else uses.
	 */
	for (size_t i = 0; i < set->n; i++) {
		const struct shirudo_kmod *m = &set->mods[i];

		for (uint16_t k = 0; k < m->n_deps; k++) {
			size_t d = set->deps[m->deps_off + k];

			used_by[d >> 3] |= (uint8_t)(1U << (d & 7));
		}
	}
	for (size_t i = 0; i < set->n; i++)
		if (((used_by[i >> 3] >> (i & 7)) & 1) == 0)
			roots[n_roots++] = i;

	for (size_t r = 0; r < n_roots; r++) {
		int is_last = (r == n_roots - 1);

		print_subtree(set, roots[r], "  ", is_last, seen);
	}

	xfree(used_by, bitmap_bytes);
	xfree(seen, bitmap_bytes);
	xfree(roots, set->n * sizeof(*roots));
}

/* Format an int64 epoch seconds value as ISO-8601 UTC. */
static void iso_utc(int64_t sec, char *out, size_t out_cap)
{
	struct tm tm = {};
	time_t t = (time_t)sec;

	if (sec > 0 && gmtime_r(&t, &tm))
		strftime(out, out_cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
	else
		snprintf(out, out_cap, "?");
}

/*
 * qsort comparator: descending by (loaded_at_sec, loaded_at_nsec).
 * Indices into set->mods[]. Modules with loaded_at_sec == 0 (stat
 * failure) sort to the bottom so they don't crowd out real entries.
 */
struct recent_idx {
	const struct shirudo_kmod_set	*set;
	size_t				idx;
};

static int recent_cmp(const void *a, const void *b)
{
	const struct recent_idx *x = a, *y = b;
	const struct shirudo_kmod *mx = &x->set->mods[x->idx];
	const struct shirudo_kmod *my = &y->set->mods[y->idx];

	if (mx->loaded_at_sec == 0 && my->loaded_at_sec != 0)
		return 1;
	if (mx->loaded_at_sec != 0 && my->loaded_at_sec == 0)
		return -1;
	if (mx->loaded_at_sec != my->loaded_at_sec)
		return mx->loaded_at_sec < my->loaded_at_sec ? 1 : -1;
	if (mx->loaded_at_nsec != my->loaded_at_nsec)
		return mx->loaded_at_nsec < my->loaded_at_nsec ? 1 : -1;
	return strcmp(mx->name, my->name);
}

void shirudo_kmodules_print_recent(const struct shirudo_kmod_set *set,
				   size_t last_n, int64_t boot_sec)
{
	struct recent_idx *all;
	size_t take, i;

	if (set->n == 0) {
		printf("  (no modules loaded)\n");
		return;
	}

	all = xmalloc(set->n * sizeof(*all));
	if (!all) {
		printf("  (out of memory)\n");
		return;
	}
	for (i = 0; i < set->n; i++) {
		all[i].set = set;
		all[i].idx = i;
	}
	qsort(all, set->n, sizeof(*all), recent_cmp);
	take = set->n < last_n ? set->n : last_n;
	/* qsort already put the freshest first -- print in that order. */
	for (i = 0; i < take; i++) {
		const struct shirudo_kmod *m = &set->mods[all[i].idx];
		char ts[32], size_s[16], age[24];

		iso_utc(m->loaded_at_sec, ts, sizeof(ts));
		shirudo_human_size(m->size, size_s, sizeof(size_s));
		if (boot_sec > 0 && m->loaded_at_sec >= boot_sec)
			shirudo_format_duration(
				(long)(m->loaded_at_sec - boot_sec),
				age, sizeof(age));
		else
			snprintf(age, sizeof(age), "?");

		printf("  [%s]  %s (%s, refs=%u, %s since boot)\n",
		       ts, m->name, size_s, (unsigned)m->refcount, age);
	}
	xfree(all, set->n * sizeof(*all));
}
