// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Exercise the OCI client's TLS, authentication and redirect paths.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bpm_oci.h"

int main(int argc, char **argv)
{
	struct bpm_http_response response = {};
	struct bpm_oci_client client = {};
	char url[BPM_MAX_ENDPOINT * 2];
	int rc;

	if (argc < 3 || argc > 4) {
		fprintf(stderr, "usage: %s oci://host[:port] /path [output]\n",
			argv[0]);
		return 2;
	}
	alarm(10);
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return 1;
	rc = bpm_oci_parse_endpoint(argv[1], &client);
	if (rc)
		goto out;
	if (snprintf(url, sizeof(url), "%s%s", client.base_url, argv[2]) >=
	    (int)sizeof(url)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	if (argc == 4) {
		rc = bpm_oci_get_file(&client, url, NULL, argv[3]);
	} else {
		rc = bpm_oci_request(&client, "GET", url, NULL, NULL,
				     NULL, 0, &response);
		if (!rc && response.status != 200)
			rc = -EACCES;
		bpm_buffer_free(&response.body);
	}
out:
	if (rc)
		fprintf(stderr, "rc=%d: %s\n", rc, strerror(-rc));
	curl_global_cleanup();
	return rc ? 1 : 0;
}
