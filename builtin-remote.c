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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "builtin.h"
#include "util/log.h"
#include "util/remotes.h"

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
static int parse_dest(const char *dest, char *user, size_t ulen,
		      char *host, size_t hlen, int *port)
{
	const char *at = strchr(dest, '@');
	const char *hp = at ? at + 1 : dest;
	const char *colon = strrchr(hp, ':');
	size_t hostlen;

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

	if (colon && colon[1]) {
		long p;
		char *end;

		p = strtol(colon + 1, &end, 10);
		if (*end == '\0' && p > 0 && p < 65536) {
			*port = (int)p;
			hostlen = (size_t)(colon - hp);
		} else {
			hostlen = strlen(hp);	/* colon belongs to host */
		}
	} else {
		hostlen = strlen(hp);
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
	if (parse_dest(dest, user, sizeof(user), host, sizeof(host),
		       &port) != 0) {
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
		if (nlabels == (int)(sizeof(labels) / sizeof(labels[0]))) {
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
	fprintf(f, "# shirudo remote: %s\n", name);
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
	pr_info("remote add: %s -> %s@%s:%d (%d label%s) [%s]", name, user,
		host, port, nlabels, nlabels == 1 ? "" : "s", path);
	return 0;
}

static void print_labels_inline(const struct shirudo_remote *r)
{
	size_t nl = shirudo_labels_count(r->labels), k;

	if (nl == 0) {
		printf("-");
		return;
	}
	for (k = 0; k < nl; k++) {
		const char *key, *val;

		shirudo_labels_at(r->labels, k, &key, &val);
		printf("%s%s=%s", k ? "," : "", key, val);
	}
}

static int cmd_list(int argc, const char **argv)
{
	struct shirudo_remote *remotes;
	size_t n, i;

	(void)argc;
	(void)argv;
	shirudo_remotes_load_all(&remotes, &n);
	if (n == 0) {
		printf("(no remotes registered)\n");
		shirudo_remotes_free(remotes, n);
		return 0;
	}
	printf("%-20s  %-28s  %s\n", "NAME", "DESTINATION", "LABELS");
	for (i = 0; i < n; i++) {
		char dest[300];

		snprintf(dest, sizeof(dest), "%s@%s:%d", remotes[i].user,
			 remotes[i].host, remotes[i].port);
		printf("%-20s  %-28s  ", remotes[i].name, dest);
		print_labels_inline(&remotes[i]);
		printf("\n");
	}
	shirudo_remotes_free(remotes, n);
	return 0;
}

static int cmd_show(int argc, const char **argv)
{
	struct shirudo_remote *remotes;
	size_t n, i, k, nl;
	int found = 0;

	if (argc < 2) {
		fprintf(stderr, "usage: shirudo remote show <name>\n");
		return 2;
	}
	shirudo_remotes_load_all(&remotes, &n);
	for (i = 0; i < n; i++) {
		if (strcmp(remotes[i].name, argv[1]) != 0)
			continue;
		found = 1;
		printf("%s:\n", remotes[i].name);
		printf("  host:   %s\n", remotes[i].host);
		printf("  user:   %s\n", remotes[i].user);
		printf("  port:   %d\n", remotes[i].port);
		nl = shirudo_labels_count(remotes[i].labels);
		if (nl == 0) {
			printf("  labels: (none)\n");
		} else {
			printf("  labels:\n");
			for (k = 0; k < nl; k++) {
				const char *key, *val;

				shirudo_labels_at(remotes[i].labels, k, &key,
						  &val);
				printf("    %s = %s\n", key, val);
			}
		}
		break;
	}
	shirudo_remotes_free(remotes, n);
	if (!found) {
		pr_err("remote show: no such remote '%s'", argv[1]);
		return 1;
	}
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
	if (argc < 2) {
		fprintf(stderr,
			"usage: shirudo remote {add|list|show|rm|rename} ...\n");
		return 2;
	}
	if (strcmp(argv[1], "add") == 0)
		return cmd_add(argc - 1, argv + 1);
	if (strcmp(argv[1], "list") == 0)
		return cmd_list(argc - 1, argv + 1);
	if (strcmp(argv[1], "show") == 0)
		return cmd_show(argc - 1, argv + 1);
	if (strcmp(argv[1], "rm") == 0)
		return cmd_rm(argc - 1, argv + 1);
	if (strcmp(argv[1], "rename") == 0)
		return cmd_rename(argc - 1, argv + 1);

	fprintf(stderr, "shirudo remote: unknown subcommand '%s'\n", argv[1]);
	return 2;
}
