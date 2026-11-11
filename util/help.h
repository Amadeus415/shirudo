/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The structured help every subcommand prints, which
 * rust/src/util/help.rs implements.
 */

#ifndef SHIRUDO_HELP_H
#define SHIRUDO_HELP_H

#include <stdbool.h>
#include <string.h>
#include <stddef.h>

struct help_item {
	const char	*name;
	const char	*summary;
};

struct help_section {
	const char			*header;
	const struct help_item	*items;
	size_t				n_items;
};

struct help {
	const char				*usage;
	const char				*summary;
	const struct help_section	*sections;
	size_t					n_sections;
	const char				*footer;
};

int is_help(const char *arg);

int is_list_cmds(const char *arg);

/*
 * A valued option takes its value after an equals sign or as the next
 * argument. opt_arg() says whether arg, argv[*i] or a name a caller
 * substituted for it, is the option name: it hands the value out and
 * steps *i past a value that followed, or reports an option that came
 * last with nothing after it.
 */
enum opt_status {
	OPT_NONE,
	OPT_VALUE,
	OPT_MISSING,
};

static inline bool opt_arg(const char *name, const char *arg, int argc,
			   const char **argv, size_t *i, const char **value,
			   enum opt_status *status)
{
	size_t n = strlen(name);

	*status = OPT_NONE;
	if (strncmp(arg, name, n))
		return false;
	if (arg[n] == '=') {
		*value = arg + n + 1;
		*status = OPT_VALUE;
		return true;
	}
	if (arg[n])
		return false;
	if (*i + 1 >= (size_t)argc) {
		*status = OPT_MISSING;
		return true;
	}
	*value = argv[++*i];
	*status = OPT_VALUE;
	return true;
}

void print_help(const struct help *h);

/*
 * The names among n_names close enough to bad, a word the user typed
 * that matches none, printed as a did-you-mean block on stderr.
 */
void help_suggest(const char *bad, const char *const *names, size_t n_names);

/* What bash completion reads through --list-cmds. */
void print_subcmd_list(const struct help_item *items,
		       size_t n_items);

/*
 * NULL on failure with stderr already written: a did-you-mean block,
 * or the ambiguous matches.
 */
const char *resolve_subcommand(const char *cmd_label,
			       const char *input,
			       const struct help_item *subcmds,
			       size_t n_subcmds);

#endif /* SHIRUDO_HELP_H */
