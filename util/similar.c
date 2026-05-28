// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Levenshtein edit distance + a top-N "closest match" helper. Used by
 * the top-level dispatcher to suggest a real subcommand when the user
 * mistypes one.
 */

#include <string.h>

#include "similar.h"

/* Two-row Levenshtein DP, allocation-free, early-out at `max`. */
int shirudo_edit_distance(const char *s, const char *t, int max)
{
	int prev[SHIRUDO_SIMILAR_MAX_LEN + 1];
	int curr[SHIRUDO_SIMILAR_MAX_LEN + 1];
	size_t m = strlen(s), n = strlen(t);
	int diff;
	size_t i, j;

	if (m > SHIRUDO_SIMILAR_MAX_LEN || n > SHIRUDO_SIMILAR_MAX_LEN)
		return max + 1;
	if (m == 0)
		return (int)n;
	if (n == 0)
		return (int)m;

	/* Any common edit must close at least the length gap. */
	diff = (int)(m > n ? m - n : n - m);
	if (diff > max)
		return max + 1;

	for (j = 0; j <= n; j++)
		prev[j] = (int)j;

	for (i = 1; i <= m; i++) {
		int row_min;

		curr[0] = (int)i;
		row_min = curr[0];
		for (j = 1; j <= n; j++) {
			int cost = (s[i - 1] == t[j - 1]) ? 0 : 1;
			int del = prev[j] + 1;
			int ins = curr[j - 1] + 1;
			int sub = prev[j - 1] + cost;
			int v = del;

			if (ins < v)
				v = ins;
			if (sub < v)
				v = sub;
			curr[j] = v;
			if (v < row_min)
				row_min = v;
		}
		/*
		 * Every cell in subsequent rows is >= row_min, so if the
		 * best of this row already exceeds the cap there is no
		 * point continuing.
		 */
		if (row_min > max)
			return max + 1;
		memcpy(prev, curr, (n + 1) * sizeof(prev[0]));
	}
	return prev[n];
}

size_t shirudo_suggest(const char *name,
		       const char *const *commands, size_t n_commands,
		       int max_dist,
		       struct shirudo_suggestion *out, size_t cap)
{
	size_t n_out = 0;
	size_t i;

	if (!cap)
		return 0;

	for (i = 0; i < n_commands; i++) {
		int d = shirudo_edit_distance(name, commands[i], max_dist);
		size_t pos;

		if (d > max_dist)
			continue;
		/*
		 * Insertion sort by ascending distance. Move larger entries
		 * right; discard the one that falls off the end so `out`
		 * always holds the cap-best matches.
		 */
		pos = n_out < cap ? n_out : cap;
		while (pos > 0 && out[pos - 1].dist > d) {
			if (pos < cap)
				out[pos] = out[pos - 1];
			pos--;
		}
		if (pos < cap) {
			out[pos].name = commands[i];
			out[pos].dist = d;
			if (n_out < cap)
				n_out++;
		}
	}
	return n_out;
}

size_t shirudo_resolve(const char *input,
		       const char *const *candidates, size_t n,
		       size_t *matches, size_t cap)
{
	size_t i, m = 0, len = strlen(input);

	/* Tier 1: exact match. Unique by definition; short-circuit. */
	for (i = 0; i < n; i++) {
		if (strcmp(input, candidates[i]) == 0) {
			if (cap >= 1)
				matches[0] = i;
			return 1;
		}
	}
	/* Tier 2: input is a prefix of a candidate ("node" -> "nodes"). */
	for (i = 0; i < n; i++) {
		size_t clen = strlen(candidates[i]);

		if (clen > len &&
		    strncmp(input, candidates[i], len) == 0) {
			if (m < cap)
				matches[m] = i;
			m++;
		}
	}
	if (m)
		return m;
	/* Tier 3: candidate is a prefix of input ("remotes" -> "remote"). */
	for (i = 0; i < n; i++) {
		size_t clen = strlen(candidates[i]);

		if (clen < len &&
		    strncmp(input, candidates[i], clen) == 0) {
			if (m < cap)
				matches[m] = i;
			m++;
		}
	}
	return m;
}
