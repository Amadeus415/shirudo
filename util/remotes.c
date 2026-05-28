// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Operator-local remote registry. One <name>.conf per remote under
 * $XDG_CONFIG_HOME/shirudo/remotes.d/ (or ~/.config) and
 * /etc/shirudo/remotes.d/. Lines are `key = value`; recognised keys
 * are host, user, port, and label.<k>. The remote's name is the file
 * basename. Labels are operator-side metadata only -- no security
 * boundary, never sent to targets.
 */

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "log.h"
#include "malloc.h"
#include "remotes.h"

struct shirudo_label {
	char	*key;
	char	*val;
};

struct shirudo_labels {
	struct shirudo_label	*items;
	size_t			n;
};

const char *shirudo_labels_get(const struct shirudo_labels *l, const char *key)
{
	size_t i;

	if (!l)
		return NULL;
	for (i = 0; i < l->n; i++)
		if (strcmp(l->items[i].key, key) == 0)
			return l->items[i].val;
	return NULL;
}

size_t shirudo_labels_count(const struct shirudo_labels *l)
{
	return l ? l->n : 0;
}

void shirudo_labels_at(const struct shirudo_labels *l, size_t i,
		       const char **key, const char **val)
{
	*key = l->items[i].key;
	*val = l->items[i].val;
}

static int labels_add(struct shirudo_labels *l, const char *k, const char *v)
{
	struct shirudo_label *it = xreallocarray(l->items, l->n, l->n + 1,
						 sizeof(*it));

	if (!it)
		return -ENOMEM;
	l->items = it;
	it[l->n].key = strdup(k);
	it[l->n].val = strdup(v);
	if (!it[l->n].key || !it[l->n].val)
		return -ENOMEM;
	l->n++;
	return 0;
}

static char *trim(char *s)
{
	char *e;

	while (*s == ' ' || *s == '\t')
		s++;
	e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' ||
			 e[-1] == '\n' || e[-1] == '\r'))
		*--e = '\0';
	return s;
}

/* Append a freshly-parsed remote to *list. Returns 0 / -errno. */
static int parse_conf(const char *dir, const char *fname,
		      struct shirudo_remote **list, size_t *n)
{
	char path[1024], line[1024];
	struct shirudo_remote r = {};
	struct shirudo_labels *labels;
	struct shirudo_remote *grown;
	size_t namelen = strlen(fname) - 5;	/* strip ".conf" */
	FILE *f;
	int rc = 0;

	labels = calloc(1, sizeof(*labels));
	if (!labels)
		return -ENOMEM;

	r.name = strndup(fname, namelen);
	r.user = strdup("root");
	r.port = 22;
	r.labels = labels;
	if (!r.name || !r.user) {
		rc = -ENOMEM;
		goto fail;
	}

	if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir, fname) >=
	    sizeof(path)) {
		rc = -ENAMETOOLONG;
		goto fail;
	}
	f = fopen(path, "r");
	if (!f) {
		rc = -errno;
		goto fail;
	}
	while (fgets(line, sizeof(line), f)) {
		char *p = trim(line), *eq, *key, *val;

		if (*p == '\0' || *p == '#')
			continue;
		eq = strchr(p, '=');
		if (!eq)
			continue;
		*eq = '\0';
		key = trim(p);
		val = trim(eq + 1);
		if (strcmp(key, "host") == 0) {
			free(r.host);
			r.host = strdup(val);
		} else if (strcmp(key, "user") == 0) {
			free(r.user);
			r.user = strdup(val);
		} else if (strcmp(key, "port") == 0) {
			r.port = atoi(val);
		} else if (strcmp(key, "created") == 0) {
			struct tm tm = {};

			if (strptime(val, "%Y-%m-%dT%H:%M:%SZ", &tm))
				r.added = timegm(&tm);
		} else if (strncmp(key, "label.", 6) == 0) {
			if (labels_add(labels, key + 6, val)) {
				rc = -ENOMEM;
				break;
			}
		}
	}
	fclose(f);
	if (rc)
		goto fail;
	/*
	 * Legacy remotes (registered before `created =` existed) have no
	 * timestamp in the conf -- fall back to the file's mtime so AGE
	 * is still meaningful, just approximate.
	 */
	if (r.added == 0) {
		struct stat st;

		if (stat(path, &st) == 0)
			r.added = st.st_mtime;
	}
	if (!r.host) {
		pr_warn("remote %s: no host=, skipping", r.name);
		rc = 0;
		goto fail;	/* free partial, don't append */
	}

	grown = xreallocarray(*list, *n, *n + 1, sizeof(**list));
	if (!grown) {
		rc = -ENOMEM;
		goto fail;
	}
	*list = grown;
	(*list)[*n] = r;
	(*n)++;
	return 0;

fail:
	free(r.name);
	free(r.host);
	free(r.user);
	if (labels) {
		size_t i;

		for (i = 0; i < labels->n; i++) {
			free(labels->items[i].key);
			free(labels->items[i].val);
		}
		free(labels->items);
		free(labels);
	}
	return rc;
}

static int has_suffix(const char *s, const char *suf)
{
	size_t ls = strlen(s), lf = strlen(suf);

	return ls > lf && strcmp(s + ls - lf, suf) == 0;
}

/* Already-loaded remote with this name? (user dir wins over /etc). */
static int already(struct shirudo_remote *list, size_t n, const char *fname)
{
	size_t namelen = strlen(fname) - 5, i;

	for (i = 0; i < n; i++)
		if (strncmp(list[i].name, fname, namelen) == 0 &&
		    list[i].name[namelen] == '\0')
			return 1;
	return 0;
}

static void load_dir(const char *dir, struct shirudo_remote **list, size_t *n)
{
	struct dirent **ents;
	int ne, i;

	ne = scandir(dir, &ents, NULL, alphasort);
	if (ne < 0)
		return;
	for (i = 0; i < ne; i++) {
		if (has_suffix(ents[i]->d_name, ".conf") &&
		    !already(*list, *n, ents[i]->d_name))
			parse_conf(dir, ents[i]->d_name, list, n);
		free(ents[i]);
	}
	free(ents);
}

int shirudo_remotes_user_dir(char *buf, size_t cap)
{
	const char *xdg = getenv("XDG_CONFIG_HOME");
	const char *home = getenv("HOME");

	if (xdg && *xdg) {
		if ((size_t)snprintf(buf, cap, "%s/shirudo/remotes.d",
				     xdg) >= cap)
			return -1;
		return 0;
	}
	if (home && *home) {
		if ((size_t)snprintf(buf, cap, "%s/.config/shirudo/remotes.d",
				     home) >= cap)
			return -1;
		return 0;
	}
	return -1;
}

int shirudo_remotes_load_all(struct shirudo_remote **out, size_t *n)
{
	char user_dir[1024];

	*out = NULL;
	*n = 0;

	if (shirudo_remotes_user_dir(user_dir, sizeof(user_dir)) == 0)
		load_dir(user_dir, out, n);		/* user dir wins */
	load_dir("/etc/shirudo/remotes.d", out, n);
	return 0;
}

void shirudo_remotes_free(struct shirudo_remote *list, size_t n)
{
	size_t i, j;

	for (i = 0; i < n; i++) {
		free(list[i].name);
		free(list[i].host);
		free(list[i].user);
		if (list[i].labels) {
			for (j = 0; j < list[i].labels->n; j++) {
				free(list[i].labels->items[j].key);
				free(list[i].labels->items[j].val);
			}
			free(list[i].labels->items);
			free(list[i].labels);
		}
	}
	free(list);
}
