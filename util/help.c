// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared structured-help printer for the top-level subcommands.
 */

#include <stdio.h>
#include <string.h>

#include "help.h"
#include "macros.h"
#include "similar.h"

#define SHIRUDO_SUBCMD_MAX	32

/* Wrap target for help-item summaries; covers a 100-col terminal with slack. */
#define SHIRUDO_HELP_WIDTH	90

static void wrap_print(const char *text, size_t indent, size_t avail)
{
	const char *p = text;
	size_t col = 0;

	if (avail < 1)
		avail = 1;
	while (*p) {
		const char *w;
		size_t wlen;

		while (*p == ' ' || *p == '\t')
			p++;
		if (!*p)
			break;
		w = p;
		while (*p && *p != ' ' && *p != '\t')
			p++;
		wlen = (size_t)(p - w);

		if (col == 0) {
			fwrite(w, 1, wlen, stderr);
			col = wlen;
		} else if (col + 1 + wlen <= avail) {
			fputc(' ', stderr);
			fwrite(w, 1, wlen, stderr);
			col += 1 + wlen;
		} else {
			size_t i;

			fputc('\n', stderr);
			for (i = 0; i < indent; i++)
				fputc(' ', stderr);
			fwrite(w, 1, wlen, stderr);
			col = wlen;
		}
	}
	fputc('\n', stderr);
}

int is_help(const char *arg)
{
	return arg && (strcmp(arg, "help") == 0 ||
		       strcmp(arg, "--help") == 0 ||
		       strcmp(arg, "-h") == 0);
}

int is_list_cmds(const char *arg)
{
	return arg && strcmp(arg, "--list-cmds") == 0;
}

void print_subcmd_list(const struct shirudo_help_item *items,
		       size_t n_items)
{
	size_t i;

	for (i = 0; i < n_items; i++)
		printf("%s\n", items[i].name);
}

void print_help(const struct shirudo_help *h)
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
		/*
		 * Per section, so an Options section reads as cleanly as a
		 * Subcommands one.
		 */
		for (j = 0; j < s->n_items; j++) {
			size_t l = strlen(s->items[j].name);

			if (l > w)
				w = l;
		}
		w += 2;
		fprintf(stderr, "\n%s\n", s->header);
		for (j = 0; j < s->n_items; j++) {
			size_t indent = 2 + w;
			size_t avail = indent < SHIRUDO_HELP_WIDTH ?
				       SHIRUDO_HELP_WIDTH - indent : 1;

			fprintf(stderr, "  %-*s", (int)w, s->items[j].name);
			wrap_print(s->items[j].summary, indent, avail);
		}
	}
	if (h->footer && *h->footer)
		fprintf(stderr, "\n%s\n", h->footer);
}

static void
shirudo_help_unknown_subcommand(const char *cmd_label, const char *bad,
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
	n = suggest(bad, names, n_names, max_dist, sugg,
		    ARRAY_SIZE(sugg));
	if (n) {
		fprintf(stderr, "\nDid you mean one of:\n");
		for (i = 0; i < n; i++)
			fprintf(stderr, "\t%s\n", sugg[i].name);
	}
}

const char *resolve_subcommand(const char *cmd_label,
			       const char *input,
			       const struct shirudo_help_item *subcmds,
			       size_t n_subcmds)
{
	const char *names[SHIRUDO_SUBCMD_MAX];
	size_t matches[SHIRUDO_SUBCMD_MAX];
	size_t i, n_names = 0, n;

	if (!subcmds || !n_subcmds) {
		shirudo_help_unknown_subcommand(cmd_label, input,
						subcmds, n_subcmds);
		return NULL;
	}
	for (i = 0; i < n_subcmds && n_names < ARRAY_SIZE(names); i++)
		names[n_names++] = subcmds[i].name;

	n = resolve(input, names, n_names, matches,
		    ARRAY_SIZE(matches));
	if (n == 1)
		return names[matches[0]];
	if (n == 0) {
		shirudo_help_unknown_subcommand(cmd_label, input,
						subcmds, n_subcmds);
		return NULL;
	}
	fprintf(stderr, "%s: '%s' is ambiguous; it matches:\n", cmd_label,
		input);
	for (i = 0; i < n; i++)
		fprintf(stderr, "\t%s\n", names[matches[i]]);
	return NULL;
}
