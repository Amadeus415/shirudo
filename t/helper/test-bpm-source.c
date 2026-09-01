// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Focused tests for target-local BPM repository source parsing.
 */

#include <stdio.h>
#include <string.h>

#include "util/bpm_source_config.h"

int main(void)
{
	char endpoint[512] = {};
	char key_file[256] = {};
	char endpoint_line[] = "endpoint = oci://registry.test:5443\n";
	char key_file_line[] = "key_file = /etc/shirudo/bpm/keys/jbrust.pem\n";

	if (shirudo_bpm_parse_source_line(endpoint_line, endpoint,
					  sizeof(endpoint), key_file,
					  sizeof(key_file)) ||
	    shirudo_bpm_parse_source_line(key_file_line, endpoint,
					   sizeof(endpoint), key_file,
					   sizeof(key_file)))
		return 1;
	if (strcmp(endpoint, "oci://registry.test:5443") ||
	    strcmp(key_file, "/etc/shirudo/bpm/keys/jbrust.pem"))
		return 1;

	printf("endpoint=%s\nkey_file=%s\n", endpoint, key_file);
	return 0;
}
