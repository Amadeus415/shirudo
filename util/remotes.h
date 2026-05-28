/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Operator-local remote registry (routing metadata + labels).
 */

#ifndef SHIRUDO_REMOTES_H
#define SHIRUDO_REMOTES_H

#include <stddef.h>
#include <time.h>

struct shirudo_labels;

struct shirudo_remote {
	char		*name;
	char		*host;
	char		*user;
	int		port;
	struct shirudo_labels	*labels;
	/*
	 * When this remote was first registered: the `created = <ISO-8601 UTC>`
	 * line written by `shirudo remote add`, or -- for entries from before
	 * that field existed -- the conf file's mtime as a best-effort fallback.
	 */
	time_t		added;
	/* The .conf path this entry was loaded from (per-user or /etc). */
	char		*path;
};

int shirudo_remotes_load_all(struct shirudo_remote **out, size_t *n);
void shirudo_remotes_free(struct shirudo_remote *list, size_t n);

/*
 * "user@host:port" (or "host:port" if user is empty), bounded by cap.
 * Single source of truth: `shirudo remote show` and `shirudo nodes show`
 * both render through this so the endpoint format never drifts.
 */
void shirudo_remote_endpoint(const struct shirudo_remote *r,
			     char *buf, size_t cap);

/*
 * Per-user remotes.d directory ($XDG_CONFIG_HOME/shirudo/remotes.d, else
 * ~/.config/shirudo/remotes.d). 0 with the path in buf, or -1 if neither
 * XDG_CONFIG_HOME nor HOME is set. This is where `remote add` writes;
 * /etc/shirudo/remotes.d is read-only system config.
 */
int shirudo_remotes_user_dir(char *buf, size_t cap);

/* Look up a label value by key; NULL if absent. */
const char *shirudo_labels_get(const struct shirudo_labels *l, const char *key);

/* Iterate labels: count, then fetch the i-th key/value. */
size_t shirudo_labels_count(const struct shirudo_labels *l);
void shirudo_labels_at(const struct shirudo_labels *l, size_t i,
		       const char **key, const char **val);

#endif /* SHIRUDO_REMOTES_H */
