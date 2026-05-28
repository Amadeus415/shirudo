/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * kubectl-style compact duration formatting -- the single source of
 * truth shared by `shirudo remote` (AGE), `shirudo nodes` (UPTIME,
 * UPATCHES last-applied age), and any future column that wants the
 * same look ("12s", "5m", "3h", "7d").
 */

#ifndef SHIRUDO_TIMEFMT_H
#define SHIRUDO_TIMEFMT_H

#include <stddef.h>

/*
 * Format `seconds` into `buf` using the largest sensible unit:
 *   <  60s -> "<n>s"
 *   <  60m -> "<n>m"
 *   <  24h -> "<n>h"
 *   else   -> "<n>d"
 * A negative `seconds` writes "?" (used for "unknown" durations).
 * `cap` must be at least 24 bytes for the worst-case "%ldd" + NUL.
 */
void shirudo_format_duration(long seconds, char *buf, size_t cap);

#endif /* SHIRUDO_TIMEFMT_H */
