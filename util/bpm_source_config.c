// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "bpm_source_config.h"

int shirudo_bpm_parse_source_line(char *line,
				  char *endpoint, size_t endpoint_sz,
				  char *key_file, size_t key_file_sz)
{
	char *eq, *key, *key_end, *val;

	if (!line || !endpoint || !endpoint_sz || !key_file || !key_file_sz)
		return -EINVAL;

	key = line;
	while (isspace((unsigned char)*key))
		key++;
	eq = strchr(key, '=');
	if (!eq)
		return 0;
	*eq++ = '\0';
	key_end = eq - 1;
	while (key_end > key && isspace((unsigned char)key_end[-1]))
		*--key_end = '\0';

	val = eq;
	while (isspace((unsigned char)*val))
		val++;
	val[strcspn(val, "\r\n")] = '\0';

	if (!strcmp(key, "endpoint"))
		snprintf(endpoint, endpoint_sz, "%s", val);
	else if (!strcmp(key, "key_file"))
		snprintf(key_file, key_file_sz, "%s", val);
	return 0;
}
