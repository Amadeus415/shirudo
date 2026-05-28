// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * main() and the subcommand dispatch table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "builtin.h"
#include "util/harden.h"
#include "util/log.h"
#include "util/similar.h"

/*
 * Which side a command runs on. The operator holds the signing key and
 * drives remote targets; the target runs one-shot under sshd; local
 * commands work on either side.
 */
enum cmd_group {
	GROUP_OPERATOR,
	GROUP_TARGET,
	GROUP_LOCAL,
	GROUP_GENERAL,
};

struct cmd {
	const char	*name;
	int		(*fn)(int argc, const char **argv);
	enum cmd_group	group;
	const char	*summary;
};

static int cmd_help(int argc, const char **argv);

/*
 * Single source of truth for subcommands. Adding an entry updates the
 * dispatch, `shirudo help`, and bash completion's top-level list (which
 * is pulled live via `shirudo help --list-cmds`, so it never drifts).
 * completion/shirudo.bash needs editing only for new *sub*commands or
 * flags, not for new top-level commands.
 */
static const struct cmd commands[] = {
	{ "genkey",	cmd_genkey,	GROUP_OPERATOR,	"generate the signing key + cert" },
	{ "build",	cmd_build,	GROUP_OPERATOR,	"compile + sign a .upatch" },
	{ "rollout",	cmd_rollout,	GROUP_OPERATOR,	"push a .upatch (load or unload) to registered remotes" },
	{ "remote",	cmd_remote,	GROUP_OPERATOR,	"manage the remote registry" },
	{ "nodes",	cmd_nodes,	GROUP_OPERATOR,	"fleet observability across registered remotes" },

	{ "init",	cmd_init,	GROUP_TARGET,	"bootstrap the BPF LSM on this target" },
	{ "upatch",	cmd_upatch,	GROUP_TARGET,	"load / unload (target); list / info (read-only, anywhere)" },

	{ "status",	cmd_status,	GROUP_LOCAL,	"local readiness + state report" },
	{ "keys",	cmd_keys,	GROUP_LOCAL,	"inspect cert / keyring contents" },
	{ "version",	cmd_version,	GROUP_LOCAL,	"print version and SHIRUDO_VERSION_ID" },

	{ "help",	cmd_help,	GROUP_GENERAL,	"show this list" },
};

static const size_t commands_n = sizeof(commands) / sizeof(commands[0]);

static void print_group(enum cmd_group g, const char *header)
{
	int first = 1;

	for (size_t i = 0; i < commands_n; i++) {
		if (commands[i].group != g)
			continue;
		if (first) {
			fprintf(stderr, "%s\n", header);
			first = 0;
		}
		fprintf(stderr, "  %-9s %s\n",
			commands[i].name, commands[i].summary);
	}
	if (!first)
		fprintf(stderr, "\n");
}

static int cmd_help(int argc, const char **argv)
{
	/*
	 * `help --list-cmds` prints the bare command names to stdout, one
	 * per line -- the hook bash completion uses so a newly added
	 * command shows up without editing the completion script.
	 */
	if (argc > 1 && strcmp(argv[1], "--list-cmds") == 0) {
		for (size_t i = 0; i < commands_n; i++)
			printf("%s\n", commands[i].name);
		return 0;
	}

	fprintf(stderr, "usage: shirudo <command> [<args>]\n\n");
	print_group(GROUP_OPERATOR,
		    "operator commands (hold the signing key; drive targets):");
	print_group(GROUP_TARGET,
		    "target commands (run on the target, fronted by sshd):");
	print_group(GROUP_LOCAL, "local commands (operator or target):");
	print_group(GROUP_GENERAL, "other:");
	fprintf(stderr, "See PLAN.md and Documentation/ for the design.\n");
	return 0;
}

static const struct cmd *find_cmd(const char *name)
{
	for (size_t i = 0; i < commands_n; i++)
		if (strcmp(commands[i].name, name) == 0)
			return &commands[i];
	return NULL;
}

int main(int argc, const char **argv)
{
	const struct cmd *c;

	shirudo_log_init();
	shirudo_harden_self();

	if (argc < 2) {
		cmd_help(0, NULL);
		return 1;
	}

	c = find_cmd(argv[1]);
	if (!c) {
		struct shirudo_suggestion sugg[4];
		const char *names[sizeof(commands) / sizeof(commands[0])];
		size_t i, n;
		int max_dist, len;

		fprintf(stderr,
			"'%s' is not a shirudo command.\n"
			"See 'shirudo help'.\n", argv[1]);

		/*
		 * Edit-distance threshold: a quarter is too tight for short
		 * inputs and "anything goes" for long ones, so cap at 3.
		 */
		len = (int)strlen(argv[1]);
		max_dist = len / 2 + 1;
		if (max_dist > 3)
			max_dist = 3;

		for (i = 0; i < commands_n; i++)
			names[i] = commands[i].name;
		n = shirudo_suggest(argv[1], names, commands_n, max_dist,
				    sugg, sizeof(sugg) / sizeof(sugg[0]));
		if (n) {
			fprintf(stderr, "\nDid you mean one of:\n");
			for (i = 0; i < n; i++)
				fprintf(stderr, "\t%s\n", sugg[i].name);
		}
		return 1;
	}

	return c->fn(argc - 1, argv + 1);
}
