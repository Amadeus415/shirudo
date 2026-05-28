// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Manage the operator-local remote registry: one <name>.conf per remote
 * under the per-user remotes.d. Writes only the user dir; the system
 * /etc/shirudo/remotes.d is read-only here. Labels are operator-side
 * metadata only -- no security boundary, never sent to targets.
 */

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "builtin.h"
#include "util/help.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/remotes.h"
#include "util/selector.h"
#include "util/timefmt.h"

struct kv {
	const char	*key;	/* points at "key=value" */
	const char	*eq;	/* the '=' within it */
};

static bool name_ok(const char *name)
{
	const char *p;

	if (!*name || strlen(name) > 200 || name[0] == '.')
		return false;
	for (p = name; *p; p++)
		if (!(isalnum((unsigned char)*p) || *p == '-' ||
		      *p == '_' || *p == '.'))
			return false;
	return true;
}

/* Parse [user@]host[:port]; defaults user=root, port=22. 0 / -1. */
/*
 * Parse `[user@]host[:port]` where host may be an IPv4 literal, a DNS
 * name, or an IPv6 literal. IPv6 forms:
 *   [2001:db8::1]:22   -- bracketed; brackets stripped on storage
 *   [2001:db8::1]      -- bracketed, default port 22
 *   2001:db8::1        -- bare; default port 22 (any >=2-colon string)
 *
 * Bare IPv6 with a port-like trailing segment (e.g. `2001:db8::1:2222`)
 * is genuinely ambiguous between "address ending in :2222" and
 * "address plus port 2222" -- we reject it (-2) so the user can
 * disambiguate with brackets.
 *
 * Returns 0 ok, -1 malformed, -2 ambiguous IPv6+port.
 */
static int parse_dest(const char *dest, char *user, size_t ulen,
		      char *host, size_t hlen, int *port)
{
	const char *at = strchr(dest, '@');
	const char *hp = at ? at + 1 : dest;
	const char *q;
	size_t hostlen;
	int colons = 0;

	*port = 22;
	if (at) {
		size_t n = (size_t)(at - dest);

		if (n == 0 || n >= ulen)
			return -1;
		memcpy(user, dest, n);
		user[n] = '\0';
	} else {
		snprintf(user, ulen, "root");
	}

	/* Bracketed IPv6 literal: "[addr]" or "[addr]:port". */
	if (*hp == '[') {
		const char *rbr = strchr(hp, ']');

		if (!rbr || rbr == hp + 1)
			return -1;
		hostlen = (size_t)(rbr - (hp + 1));
		if (hostlen >= hlen)
			return -1;
		memcpy(host, hp + 1, hostlen);
		host[hostlen] = '\0';
		if (rbr[1] == '\0')
			return 0;
		if (rbr[1] != ':' || rbr[2] == '\0')
			return -1;
		{
			long p;
			char *end;

			p = strtol(rbr + 2, &end, 10);
			if (*end != '\0' || p <= 0 || p >= 65536)
				return -1;
			*port = (int)p;
		}
		return 0;
	}

	/* Count colons to disambiguate bare IPv6 from IPv4/DNS. */
	for (q = hp; *q; q++)
		if (*q == ':')
			colons++;

	if (colons >= 2) {
		/*
		 * Bare IPv6. If the trailing segment is two-or-more decimal
		 * digits in port range (1..65535) the input is ambiguous --
		 * could be the address itself or address+port. Reject and
		 * point the user at brackets.
		 */
		const char *last_colon = strrchr(hp, ':');
		const char *tail = last_colon + 1;
		size_t taillen = strlen(tail);
		size_t k;
		int all_digits = taillen > 0;

		for (k = 0; k < taillen; k++)
			if (tail[k] < '0' || tail[k] > '9') {
				all_digits = 0;
				break;
			}
		if (all_digits && taillen >= 2) {
			long v = strtol(tail, NULL, 10);

			if (v >= 1 && v < 65536)
				return -2;
		}
		hostlen = strlen(hp);
		if (hostlen >= hlen)
			return -1;
		memcpy(host, hp, hostlen);
		host[hostlen] = '\0';
		return 0;
	}

	/* 0 or 1 colon: IPv4 literal or DNS name, with optional ":port". */
	{
		const char *colon = strrchr(hp, ':');

		if (colon && colon[1]) {
			long p;
			char *end;

			p = strtol(colon + 1, &end, 10);
			if (*end == '\0' && p > 0 && p < 65536) {
				*port = (int)p;
				hostlen = (size_t)(colon - hp);
			} else {
				hostlen = strlen(hp);
			}
		} else {
			hostlen = strlen(hp);
		}
	}
	if (hostlen == 0 || hostlen >= hlen)
		return -1;
	memcpy(host, hp, hostlen);
	host[hostlen] = '\0';
	return 0;
}

static int mkdir_p(const char *path)
{
	char tmp[1024];
	size_t len = strlen(path);
	char *p;

	if (len >= sizeof(tmp))
		return -ENAMETOOLONG;
	memcpy(tmp, path, len + 1);
	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
			return -errno;
		*p = '/';
	}
	if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
		return -errno;
	return 0;
}

/* Build <user remotes.d>/<name>.conf. 0 / -1 (no HOME) / -ENAMETOOLONG. */
static int conf_path(const char *name, char *buf, size_t cap)
{
	char dir[1024];

	if (shirudo_remotes_user_dir(dir, sizeof(dir)) != 0) {
		pr_err("remote: neither XDG_CONFIG_HOME nor HOME is set");
		return -1;
	}
	if ((size_t)snprintf(buf, cap, "%s/%s.conf", dir, name) >= cap)
		return -ENAMETOOLONG;
	return 0;
}

static const struct shirudo_help_item remote_subcmds[] = {
	{ "list",   "list registered remotes (default; supports --filter / --selector)" },
	{ "add",    "register a new remote: add <name> <[user@]host[:port]> [--label k=v ...]" },
	{ "show",   "describe one remote in detail: show <name>" },
	{ "rm",     "unregister a remote: rm <name>" },
	{ "rename", "rename a remote: rename <old> <new>" },
};

static const struct shirudo_help_item remote_list_options[] = {
	{ "--filter=<glob>",   "match remotes by name (shell-glob, fnmatch(3))" },
	{ "--selector=<expr>", "match by label expression (k=v, !k, &&, ||, ...)" },
};

static const struct shirudo_help_section remote_help_sections[] = {
	{ "subcommands:", remote_subcmds,
	  ARRAY_SIZE(remote_subcmds) },
	{ "options (list form):", remote_list_options,
	  ARRAY_SIZE(remote_list_options) },
};

static const struct shirudo_help remote_help = {
	.usage      = "shirudo remote [<subcommand>] [<args>...]",
	.summary    = "Manage the operator-local remote registry. Bare\n"
		      "`shirudo remote` (or `remote list`) lists registered\n"
		      "remotes, optionally filtered by --filter / --selector.",
	.sections   = remote_help_sections,
	.n_sections = ARRAY_SIZE(remote_help_sections),
	.footer     =
"--filter=<glob> matches the registry name via shell-glob (fnmatch(3)):\n"
"  shirudo remote --filter='prod-*'\n"
"  shirudo remote --filter='*-edge-?\?'\n"
"  shirudo remote --filter='db[0-9][0-9]'\n"
"\n"
"--selector=<expr> matches the remote's labels:\n"
"  atoms: k=v, k!=v, k (exists), !k (absent)\n"
"  combine with &&, ||, (), where && binds tighter than ||\n"
"  shirudo remote --selector='env=production'\n"
"  shirudo remote --selector='env=prod && tier=edge'\n"
"  shirudo remote --selector=\"(role=db || role=cache) && env!=staging\"\n"
"\n"
"--filter and --selector may be combined; when both are given a remote\n"
"must satisfy both to be listed (intersection). Labels and other\n"
"registry metadata never leave the operator -- they are not pushed to\n"
"targets.",
};

static int cmd_add(int argc, const char **argv)
{
	char user[256], host[256], path[1024], dir[1024];
	struct kv labels[64];
	int nlabels = 0, port, i, rc;
	const char *name, *dest;
	struct stat st;
	FILE *f;

	if (argc < 3) {
		fprintf(stderr,
			"usage: shirudo remote add <name> <[user@]host[:port]> "
			"[--label key=value ...]\n");
		return 2;
	}
	name = argv[1];
	dest = argv[2];

	if (!name_ok(name)) {
		pr_err("remote add: invalid name '%s' "
		       "(allowed: alnum . _ -, no leading dot)", name);
		return 2;
	}
	rc = parse_dest(dest, user, sizeof(user), host, sizeof(host),
			&port);
	if (rc == -2) {
		pr_err("remote add: '%s' is ambiguous (looks like an IPv6 "
		       "address with a trailing port). Use brackets: "
		       "[addr]:port for the port form, or [addr] if you really "
		       "mean the bare address.", dest);
		return 2;
	}
	if (rc != 0) {
		pr_err("remote add: cannot parse destination '%s'", dest);
		return 2;
	}

	for (i = 3; i < argc; i++) {
		const char *spec, *eq;

		if (strcmp(argv[i], "--label") == 0) {
			if (++i >= argc) {
				pr_err("remote add: --label needs key=value");
				return 2;
			}
			spec = argv[i];
		} else if (strncmp(argv[i], "--label=", 8) == 0) {
			spec = argv[i] + 8;
		} else {
			pr_err("remote add: unexpected argument '%s'", argv[i]);
			return 2;
		}
		eq = strchr(spec, '=');
		if (!eq || eq == spec) {
			pr_err("remote add: malformed label '%s' "
			       "(want key=value)", spec);
			return 2;
		}
		if (nlabels == (int)ARRAY_SIZE(labels)) {
			pr_err("remote add: too many labels");
			return 2;
		}
		labels[nlabels].key = spec;
		labels[nlabels].eq = eq;
		nlabels++;
	}

	if (shirudo_remotes_user_dir(dir, sizeof(dir)) != 0) {
		pr_err("remote add: neither XDG_CONFIG_HOME nor HOME is set");
		return 1;
	}
	if (conf_path(name, path, sizeof(path)))
		return 1;
	if (stat(path, &st) == 0) {
		pr_err("remote add: '%s' already exists (%s); "
		       "`shirudo remote rm %s` first", name, path, name);
		return 1;
	}
	rc = mkdir_p(dir);
	if (rc) {
		pr_err("remote add: mkdir %s: %s", dir, strerror(-rc));
		return 1;
	}

	f = fopen(path, "w");
	if (!f) {
		pr_err("remote add: open %s: %s", path, strerror(errno));
		return 1;
	}
	{
		char ts[32];
		struct tm tm;
		time_t now = time(NULL);

		gmtime_r(&now, &tm);
		strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
		fprintf(f, "# shirudo remote: %s\n", name);
		fprintf(f, "created = %s\n", ts);
	}
	fprintf(f, "host = %s\n", host);
	fprintf(f, "user = %s\n", user);
	fprintf(f, "port = %d\n", port);
	for (i = 0; i < nlabels; i++) {
		int klen = (int)(labels[i].eq - labels[i].key);

		fprintf(f, "label.%.*s = %s\n", klen, labels[i].key,
			labels[i].eq + 1);
	}
	if (fclose(f) != 0) {
		pr_err("remote add: write %s: %s", path, strerror(errno));
		return 1;
	}
	{
		/*
		 * Bracket IPv6 hosts on display so the confirmation matches
		 * what `shirudo remote show <name>` will render and stays
		 * unambiguous for the user.
		 */
		struct shirudo_remote tmp = { .user = user, .host = host,
					      .port = port };
		char endpoint[320];

		shirudo_remote_endpoint(&tmp, endpoint, sizeof(endpoint));
		pr_info("remote add: %s -> %s (%d label%s) [%s]", name, endpoint,
			nlabels, nlabels == 1 ? "" : "s", path);
	}
	return 0;
}

/*
 * "When was this remote registered?" displayed in the AGE column;
 * delegates to the shared duration formatter so AGE here, UPTIME in
 * `nodes`, and the upatch-applied age all read the same.
 */
static void format_age(time_t added, char *buf, size_t cap)
{
	if (added <= 0)
		snprintf(buf, cap, "?");
	else
		shirudo_format_duration((long)(time(NULL) - added), buf,
					cap);
}

static int cmd_list(int argc, const char **argv)
{
	const char *filter = NULL, *selexpr = NULL;
	struct shirudo_selector *sel = NULL;
	struct shirudo_remote *remotes = NULL;
	size_t n = 0, i, shown = 0;
	int ret = 0;

	for (i = 1; i < (size_t)argc; i++) {
		const char *a = argv[i];

		if (shirudo_is_help(a)) {
			shirudo_print_help(&remote_help);
			return 0;
		}
		if (strncmp(a, "--filter=", 9) == 0)
			filter = a + 9;
		else if (strncmp(a, "--selector=", 11) == 0)
			selexpr = a + 11;
		else {
			pr_err("remote list: unexpected argument '%s'", a);
			return 2;
		}
	}

	if (selexpr) {
		sel = shirudo_selector_parse(selexpr);
		if (!sel) {
			pr_err("remote list: invalid --selector expression");
			return 2;
		}
	}

	shirudo_remotes_load_all(&remotes, &n);
	if (n == 0) {
		printf("(no remotes registered)\n");
		goto out;
	}

	for (i = 0; i < n; i++) {
		char dest[300], age[32];

		if (filter && fnmatch(filter, remotes[i].name, 0) != 0)
			continue;
		if (sel && !shirudo_selector_match(sel, remotes[i].labels))
			continue;
		if (shown == 0)
			printf("%-20s  %-28s  %s\n", "NAME",
			       "DESTINATION", "AGE");
		snprintf(dest, sizeof(dest), "%s@%s:%d", remotes[i].user,
			 remotes[i].host, remotes[i].port);
		format_age(remotes[i].added, age, sizeof(age));
		printf("%-20s  %-28s  %s\n", remotes[i].name, dest, age);
		shown++;
	}
	if (shown == 0)
		printf("(no remotes match --filter / --selector)\n");

out:
	shirudo_remotes_free(remotes, n);
	shirudo_selector_free(sel);
	return ret;
}

/*
 * `shirudo remote show <name>` -- describe one registry entry, in the
 * same `kubectl describe`-style layout as `shirudo nodes show <name>`
 * (which is registry header + live target sections). show is local
 * registry only: no SSH probe, no remote sections. The trailing hint
 * points operators at `nodes show` when they want live state.
 */
static int cmd_show(int argc, const char **argv)
{
	struct shirudo_remote *remotes;
	const struct shirudo_remote *r = NULL;
	size_t n, i, k, nl;

	if (argc < 2) {
		fprintf(stderr, "usage: shirudo remote show <name>\n");
		return 2;
	}
	shirudo_remotes_load_all(&remotes, &n);
	for (i = 0; i < n; i++) {
		if (strcmp(remotes[i].name, argv[1]) == 0) {
			r = &remotes[i];
			break;
		}
	}
	if (!r) {
		shirudo_remotes_free(remotes, n);
		pr_err("remote show: no such remote '%s'", argv[1]);
		return 1;
	}

	{
		char endpoint[320], created[32] = "unknown", age[32];

		shirudo_remote_endpoint(r, endpoint, sizeof(endpoint));
		if (r->added > 0) {
			struct tm tm;

			gmtime_r(&r->added, &tm);
			strftime(created, sizeof(created),
				 "%Y-%m-%dT%H:%M:%SZ", &tm);
		}
		format_age(r->added, age, sizeof(age));

		printf("Name:              %s\n", r->name);
		printf("Endpoint:          %s\n", endpoint);
		printf("Role:              target (registered)\n");
		printf("Created:           %s\n", created);
		printf("Age:               %s\n", age);
		if (r->path)
			printf("Config:            %s\n", r->path);

		nl = shirudo_labels_count(r->labels);
		printf("Labels:            ");
		if (!nl) {
			printf("<none>\n");
		} else {
			for (k = 0; k < nl; k++) {
				const char *key, *val;

				shirudo_labels_at(r->labels, k, &key, &val);
				printf("%s%s=%s\n",
				       k ? "                   " : "",
				       key, val);
			}
		}

		printf("\nRun `shirudo nodes show %s` for live state from "
		       "the target.\n", r->name);
	}

	shirudo_remotes_free(remotes, n);
	return 0;
}

static int cmd_rm(int argc, const char **argv)
{
	char path[1024];

	if (argc < 2) {
		fprintf(stderr, "usage: shirudo remote rm <name>\n");
		return 2;
	}
	if (!name_ok(argv[1])) {
		pr_err("remote rm: invalid name '%s'", argv[1]);
		return 2;
	}
	if (conf_path(argv[1], path, sizeof(path)))
		return 1;
	if (unlink(path) != 0) {
		if (errno == ENOENT)
			pr_err("remote rm: no user-registered remote '%s' "
			       "(a /etc remote is not removable here)",
			       argv[1]);
		else
			pr_err("remote rm: unlink %s: %s", path,
			       strerror(errno));
		return 1;
	}
	pr_info("remote rm: removed %s (%s)", argv[1], path);
	return 0;
}

static int cmd_rename(int argc, const char **argv)
{
	char old_path[1024], new_path[1024];
	struct stat st;

	if (argc < 3) {
		fprintf(stderr, "usage: shirudo remote rename <old> <new>\n");
		return 2;
	}
	if (!name_ok(argv[1]) || !name_ok(argv[2])) {
		pr_err("remote rename: invalid name");
		return 2;
	}
	if (conf_path(argv[1], old_path, sizeof(old_path)) ||
	    conf_path(argv[2], new_path, sizeof(new_path)))
		return 1;
	if (stat(new_path, &st) == 0) {
		pr_err("remote rename: '%s' already exists", argv[2]);
		return 1;
	}
	if (rename(old_path, new_path) != 0) {
		if (errno == ENOENT)
			pr_err("remote rename: no user-registered remote '%s'",
			       argv[1]);
		else
			pr_err("remote rename: %s -> %s: %s", old_path,
			       new_path, strerror(errno));
		return 1;
	}
	pr_info("remote rename: %s -> %s", argv[1], argv[2]);
	return 0;
}

int cmd_remote(int argc, const char **argv)
{
	const char *canonical;

	/*
	 * Bare `shirudo remote` lists the registered remotes (most common
	 * use); explicit `list` keeps working.
	 */
	if (argc < 2)
		return cmd_list(argc, argv);
	if (shirudo_is_help(argv[1])) {
		shirudo_print_help(&remote_help);
		return 0;
	}
	/*
	 * `shirudo remote --filter=...` / `--selector=...` -- the user
	 * supplied list-form options without the verb. Route straight to
	 * cmd_list (which itself parses these).
	 */
	if (argv[1][0] == '-')
		return cmd_list(argc, argv);
	/*
	 * Tolerant resolution: 'remotes', 'li', 'ad', etc. all resolve as
	 * long as the match is unique (see util/similar.c).
	 */
	canonical = shirudo_resolve_subcommand("shirudo remote", argv[1],
					       remote_subcmds,
					       ARRAY_SIZE(remote_subcmds));
	if (!canonical)
		return 2;
	if (strcmp(canonical, "add") == 0)
		return cmd_add(argc - 1, argv + 1);
	if (strcmp(canonical, "list") == 0)
		return cmd_list(argc - 1, argv + 1);
	if (strcmp(canonical, "show") == 0)
		return cmd_show(argc - 1, argv + 1);
	if (strcmp(canonical, "rm") == 0)
		return cmd_rm(argc - 1, argv + 1);
	if (strcmp(canonical, "rename") == 0)
		return cmd_rename(argc - 1, argv + 1);
	return 2;	/* unreachable: resolve returned a non-matching name */
}
