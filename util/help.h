/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared structured-help printer. Every top-level subcommand defines
 * a `struct shirudo_help` and prints it through shirudo_print_help()
 * on `help` / `--help` / `-h`, so the UX stays consistent with the
 * top-level `shirudo help` block: usage line, optional summary,
 * one or more named sections of (name, one-line summary), optional
 * footer (examples, see-also).
 */

#ifndef SHIRUDO_HELP_H
#define SHIRUDO_HELP_H

#include <stddef.h>

struct shirudo_help_item {
	const char	*name;
	const char	*summary;
};

struct shirudo_help_section {
	const char			*header;
	const struct shirudo_help_item	*items;
	size_t				n_items;
};

struct shirudo_help {
	const char				*usage;
	const char				*summary;
	const struct shirudo_help_section	*sections;
	size_t					n_sections;
	const char				*footer;
};

/* Does argv match "help", "--help" or "-h"? Safe on NULL. */
int shirudo_is_help(const char *arg);

/* Does argv match "--list-cmds"? */
int shirudo_is_list_cmds(const char *arg);

/* Print to stderr in the top-level `shirudo help` style. */
void shirudo_print_help(const struct shirudo_help *h);

/*
 * Print the bare names from an items[] array to stdout, one per line.
 * The hook bash completion uses (via `shirudo <command> --list-cmds`)
 * so newly added subcommands appear in tab-completion without editing
 * the completion script.
 */
void shirudo_print_subcmd_list(const struct shirudo_help_item *items,
			       size_t n_items);

/*
 * Render the unknown-subcommand error for a dispatcher (`shirudo
 * remote bogus`, `shirudo upatch foo`, ...) in the same style the
 * top-level `shirudo` dispatcher already uses for unknown commands:
 * a "'<bad>' is not a known subcommand" line, a "See ... --help"
 * pointer, and Levenshtein-derived "Did you mean one of:" matches
 * drawn from `subcmds`. cmd_label is e.g. "shirudo remote".
 */
void shirudo_help_unknown_subcommand(const char *cmd_label,
				     const char *bad,
				     const struct shirudo_help_item *subcmds,
				     size_t n_subcmds);

/*
 * Resolve `input` against `subcmds` using shirudo_resolve()'s tiered
 * matching (exact, then unique prefix-of-candidate, then candidate-
 * is-prefix-of-input) so that `nod` -> `nodes`, `remotes` -> `remote`,
 * `li` -> `list`, `ad` -> `add` all work.
 *
 * Returns the canonical name on a unique match. Returns NULL on
 * failure with stderr already populated: a Levenshtein "Did you
 * mean" block when nothing matched, or a "is ambiguous; matches:"
 * listing when more than one candidate matched the same tier.
 */
const char *shirudo_resolve_subcommand(const char *cmd_label,
				       const char *input,
				       const struct shirudo_help_item *subcmds,
				       size_t n_subcmds);

#endif /* SHIRUDO_HELP_H */
