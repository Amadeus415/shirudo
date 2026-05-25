// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Path helpers complementing util/paths.h.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "paths.h"

const char *shirudo_keys_dir_resolve(const char *keys_dir_arg)
{
	const char *env;

	if (keys_dir_arg)
		return keys_dir_arg;
	env = getenv(SHIRUDO_KEYS_DIR_ENV);
	if (env)
		return env;
	return SHIRUDO_KEYS_DIR;
}

int shirudo_key_path(char *out, size_t out_sz,
		     const char *keys_dir, const char *file)
{
	const char *dir = keys_dir ? keys_dir : SHIRUDO_KEYS_DIR;
	const char *sep;
	int n;

	if (!out || out_sz == 0 || !dir || !*dir || !file || !*file)
		return -EINVAL;

	sep = dir[strlen(dir) - 1] == '/' ? "" : "/";
	n = snprintf(out, out_sz, "%s%s%s", dir, sep, file);
	if (n < 0 || (size_t)n >= out_sz)
		return -ENAMETOOLONG;
	return 0;
}

int shirudo_key_paths(const char *keys_dir,
		      char *pkey_path, size_t pkey_sz,
		      char *cert_path, size_t cert_sz)
{
	int rc;

	rc = shirudo_key_path(pkey_path, pkey_sz, keys_dir,
			      SHIRUDO_SIGNING_KEY_FILE);
	if (rc)
		return rc;
	return shirudo_key_path(cert_path, cert_sz, keys_dir,
				SHIRUDO_CERT_FILE);
}
