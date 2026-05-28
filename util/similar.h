/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Edit-distance "did you mean ..." helper used by the top-level
 * subcommand dispatcher when the user mistypes a command. Keep it
 * small and allocation-free: shirudo's command set is tiny.
 */

#ifndef SHIRUDO_SIMILAR_H
#define SHIRUDO_SIMILAR_H

#include <stddef.h>

/*
 * Soft upper bound on the length of a string compared here. Strings
 * longer than this short-circuit to "no match" rather than allocating.
 * Comfortably larger than every shirudo subcommand and option name.
 */
#define SHIRUDO_SIMILAR_MAX_LEN	64

struct shirudo_suggestion {
	const char	*name;
	int		dist;
};

/*
 * Levenshtein edit distance between s and t, capped at `max`: returns
 * the real distance when it fits, or any value > max otherwise (with
 * early exit). NUL-terminated inputs; either side longer than
 * SHIRUDO_SIMILAR_MAX_LEN is reported as "exceeds max".
 */
int shirudo_edit_distance(const char *s, const char *t, int max);

/*
 * Pick up to `cap` candidates from `commands[0..n_commands)` whose
 * edit distance to `name` is at most `max_dist`. Writes them into
 * `out` sorted by ascending distance and returns the count. `out` is
 * a caller-provided stack array of size `cap`.
 */
size_t shirudo_suggest(const char *name,
		       const char *const *commands, size_t n_commands,
		       int max_dist,
		       struct shirudo_suggestion *out, size_t cap);

/*
 * Resolve `input` against `candidates[0..n)` and fill `matches[]`
 * with the indices that match, returning the count (clamped to cap).
 *
 * Three resolution tiers, short-circuit at the first that hits:
 *   1. exact match (strcmp).
 *   2. input is a prefix of candidate ("node" -> "nodes", "li" -> "list").
 *   3. candidate is a prefix of input ("remotes" -> "remote").
 *
 * Caller dispatches on count: 1 = unique match (matches[0]), 0 = no
 * match (let Levenshtein "did you mean" kick in), >1 = ambiguous
 * (list `matches` to the user).
 */
size_t shirudo_resolve(const char *input,
		       const char *const *candidates, size_t n,
		       size_t *matches, size_t cap);

#endif /* SHIRUDO_SIMILAR_H */
