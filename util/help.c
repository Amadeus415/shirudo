// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared structured-help printer for the top-level subcommands.
 */

#include <stdio.h>
#include <string.h>

#include "help.h"
#include "similar.h"

int shirudo_is_help(const char *arg)
{
	return arg && (strcmp(arg, "help") == 0 ||
		       strcmp(arg, "--help") == 0 ||
		       strcmp(arg, "-h") == 0);
}

void shirudo_print_help(const struct shirudo_help *h)
{
	size_t i, j;

	if (h->usage)
		fprintf(stderr, "usage: %s\n", h->usage);
	if (h->summary && *h->summary)
		fprintf(stderr, "\n%s\n", h->summary);

	for (i = 0; i < h->n_sections; i++) {
		const struct shirudo_help_section *s = &h->sections[i];
		size_t w = 0;

		if (s->n_items == 0)
			continue;
		/* Per-section column width: align the summaries under the
		 * longest name + a 2-char gutter. Computing it here so an
		 * "Options:" section with --include-eventlog reads as
		 * cleanly as a "Subcommands:" section with `add`/`rm`. */
		for (j = 0; j < s->n_items; j++) {
			size_t l = strlen(s->items[j].name);

			if (l > w)
				w = l;
		}
		w += 2;
		fprintf(stderr, "\n%s\n", s->header);
		for (j = 0; j < s->n_items; j++)
			fprintf(stderr, "  %-*s%s\n", (int)w,
				s->items[j].name, s->items[j].summary);
	}
	if (h->footer && *h->footer)
		fprintf(stderr, "\n%s\n", h->footer);
}

#define SHIRUDO_SUBCMD_MAX	32

void shirudo_help_unknown_subcommand(const char *cmd_label, const char *bad,
				     const struct shirudo_help_item *subcmds,
				     size_t n_subcmds)
{
	struct shirudo_suggestion sugg[4];
	const char *names[SHIRUDO_SUBCMD_MAX];
	size_t i, n_names = 0, n;
	int max_dist, len;

	fprintf(stderr, "%s: '%s' is not a known subcommand.\n"
		"See '%s --help'.\n", cmd_label, bad, cmd_label);

	if (!subcmds || !n_subcmds)
		return;

	/* Same threshold heuristic as the top-level dispatcher. */
	len = (int)strlen(bad);
	max_dist = len / 2 + 1;
	if (max_dist > 3)
		max_dist = 3;

	for (i = 0; i < n_subcmds && n_names < SHIRUDO_SUBCMD_MAX; i++)
		names[n_names++] = subcmds[i].name;
	n = shirudo_suggest(bad, names, n_names, max_dist, sugg,
			    sizeof(sugg) / sizeof(sugg[0]));
	if (n) {
		fprintf(stderr, "\nDid you mean one of:\n");
		for (i = 0; i < n; i++)
			fprintf(stderr, "\t%s\n", sugg[i].name);
	}
}
