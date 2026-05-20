// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo nodes -- operator fleet observability. Iterates the
 * registered remote set (optionally filtered by name glob and/or a
 * label selector), runs `shirudo status --json --include-tpm` on each
 * over an SSH exec channel, and prints a drift table (human or --json).
 * Local-only registry; the only network is the per-node SSH.
 */

#include <errno.h>
#include <fnmatch.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "builtin.h"
#include "util/json.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/remotes.h"
#include "util/selector.h"
#include "util/ssh.h"

#define NODE_CMD	"shirudo status --json --include-tpm"

struct node_state {
	const char	*name;
	bool		reachable;
	char		version_id[80];
	int		lsm_attached;
	char		chain[80];	/* "" if absent/null */
	int		chain_seen;
	int		matches;	/* -1 unknown, 0/1 */
};

static void query_node(const struct shirudo_remote *r, struct node_state *st)
{
	struct shirudo_ssh_session *sess;
	char *out = NULL;
	size_t len = 0;
	int rc;

	st->name = r->name;
	st->matches = -1;

	sess = shirudo_ssh_connect(r->user, r->host, r->port);
	if (!sess)
		return;
	rc = shirudo_ssh_exec(sess, NODE_CMD, &out, &len);
	shirudo_ssh_close(sess);
	if (rc < 0 || !out) {
		xfree(out, len);
		return;
	}

	{
		struct shirudo_json_field tpm[] = {
			{ "chain", SHIRUDO_JSON_T_STRING, st->chain,
			  sizeof(st->chain), 0, NULL, 0 },
			{ "chain_matches_eventlog", SHIRUDO_JSON_T_BOOL,
			  &st->matches, 0, 0, NULL, 0 },
		};
		struct shirudo_json_field top[] = {
			{ "version_id", SHIRUDO_JSON_T_STRING, st->version_id,
			  sizeof(st->version_id), 0, NULL, 0 },
			{ "lsm_attached", SHIRUDO_JSON_T_BOOL, &st->lsm_attached,
			  0, 0, NULL, 0 },
			{ "tpm", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, tpm, 2 },
		};

		if (shirudo_json_parse(out, len, top,
				       sizeof(top) / sizeof(top[0])) == 0) {
			st->reachable = true;
			st->chain_seen = tpm[0].seen;
			if (!tpm[1].seen)
				st->matches = -1;
		} else {
			pr_warn("nodes: %s: unparseable status JSON", r->name);
		}
	}
	xfree(out, len);
}

static const char *short_chain(const struct node_state *s, char *buf, size_t n)
{
	if (!s->reachable)
		return "-";
	if (!s->chain_seen)
		return "no-tpm";
	snprintf(buf, n, "%.16s..", s->chain);
	return buf;
}

static const char *match_str(const struct node_state *s)
{
	if (!s->reachable || s->matches < 0)
		return "?";
	return s->matches ? "ok" : "MISMATCH";
}

int cmd_nodes(int argc, const char **argv)
{
	const char *filter = NULL, *selexpr = NULL;
	struct shirudo_remote *remotes = NULL;
	struct shirudo_selector *sel = NULL;
	struct node_state *nodes = NULL;
	const char *names[256];
	size_t n_remotes = 0, n = 0, nnames = 0, i, j;
	bool json = false;
	int ret = 0;

	for (i = 1; i < (size_t)argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--json") == 0)
			json = true;
		else if (strncmp(a, "--filter=", 9) == 0)
			filter = a + 9;
		else if (strncmp(a, "--selector=", 11) == 0)
			selexpr = a + 11;
		else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
			fprintf(stderr, "usage: shirudo nodes [<name>...] "
				"[--json] [--filter=<glob>] [--selector=<expr>]\n");
			return 0;
		} else if (a[0] == '-') {
			fprintf(stderr, "nodes: unknown option '%s'\n", a);
			return 2;
		} else if (nnames < sizeof(names) / sizeof(names[0])) {
			names[nnames++] = a;	/* positional remote name */
		} else {
			fprintf(stderr, "nodes: too many names\n");
			return 2;
		}
	}

	if (selexpr) {
		sel = shirudo_selector_parse(selexpr);
		if (!sel) {
			pr_err("nodes: invalid --selector expression");
			return 2;
		}
	}

	shirudo_remotes_load_all(&remotes, &n_remotes);
	if (n_remotes == 0) {
		pr_err("nodes: no remotes registered (see remotes.d)");
		shirudo_selector_free(sel);
		return 1;
	}

	/* Positional names must be registered (exact match), like rollout. */
	for (j = 0; j < nnames; j++) {
		bool found = false;

		for (i = 0; i < n_remotes; i++)
			if (strcmp(remotes[i].name, names[j]) == 0) {
				found = true;
				break;
			}
		if (!found) {
			pr_err("nodes: '%s' is not a registered remote", names[j]);
			shirudo_remotes_free(remotes, n_remotes);
			shirudo_selector_free(sel);
			return 1;
		}
	}

	nodes = xcalloc(n_remotes, sizeof(*nodes));
	if (!nodes) {
		shirudo_remotes_free(remotes, n_remotes);
		shirudo_selector_free(sel);
		return 1;
	}

	/*
	 * Select, then query each match sequentially. Names, --filter and
	 * --selector all intersect (PLAN.md "Subcommands" / nodes).
	 */
	for (i = 0; i < n_remotes; i++) {
		if (nnames) {
			bool named = false;

			for (j = 0; j < nnames; j++)
				if (strcmp(remotes[i].name, names[j]) == 0) {
					named = true;
					break;
				}
			if (!named)
				continue;
		}
		if (filter && fnmatch(filter, remotes[i].name, 0) != 0)
			continue;
		if (sel && !shirudo_selector_match(sel, remotes[i].labels))
			continue;
		query_node(&remotes[i], &nodes[n]);
		n++;
	}

	if (n == 0) {
		pr_err("nodes: name/filter/selector matched zero "
		       "registered remotes");
		ret = 1;
		goto out;
	}

	if (json) {
		char buf[64 * 1024];
		struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };

		shirudo_json_obj_open(&e);
		shirudo_json_kv_int(&e, "schema", 1);
		shirudo_json_arr_open(&e, "nodes");
		for (i = 0; i < n; i++) {
			struct node_state *s = &nodes[i];

			shirudo_json_obj_open(&e);
			shirudo_json_kv_string(&e, "name", s->name);
			shirudo_json_kv_bool(&e, "reachable", s->reachable);
			if (s->reachable) {
				shirudo_json_kv_bool(&e, "lsm_attached",
						     s->lsm_attached);
				shirudo_json_kv_string(&e, "version_id",
						       s->version_id);
				if (s->chain_seen)
					shirudo_json_kv_string(&e, "chain",
							       s->chain);
				else
					shirudo_json_kv_null(&e, "chain");
				if (s->matches < 0)
					shirudo_json_kv_null(&e,
						"chain_matches_eventlog");
				else
					shirudo_json_kv_bool(&e,
						"chain_matches_eventlog",
						s->matches);
			}
			shirudo_json_obj_close(&e);
		}
		shirudo_json_arr_close(&e);
		shirudo_json_obj_close(&e);
		if (e.err) {
			pr_err("nodes: json encode failed: %s",
			       strerror(-e.err));
			ret = 1;
		} else {
			printf("%s\n", buf);
		}
	} else {
		printf("%-20s %-9s %-8s %-18s %-10s %s\n",
		       "NODE", "REACHABLE", "LSM", "CHAIN", "VERSION",
		       "CHAIN/LOG");
		for (i = 0; i < n; i++) {
			struct node_state *s = &nodes[i];
			char cb[24];

			printf("%-20s %-9s %-8s %-18s %-10.8s %s\n",
			       s->name,
			       s->reachable ? "yes" : "NO",
			       !s->reachable ? "-" :
				 s->lsm_attached ? "attached" : "DETACHED",
			       short_chain(s, cb, sizeof(cb)),
			       s->reachable ? s->version_id : "-",
			       match_str(s));
		}
	}

out:
	xfree(nodes, (size_t)n_remotes * sizeof(*nodes));
	shirudo_remotes_free(remotes, n_remotes);
	shirudo_selector_free(sel);
	return ret;
}
