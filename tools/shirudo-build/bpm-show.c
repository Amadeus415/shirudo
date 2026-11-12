// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Operator-only `bpm tree show`: print a tree publication verified as a
 * node verifies it, with its document bytes verbatim.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#include <shirudo/misc.h>

#include "bpm.h"
#include "bpm_oci.h"
#include "bpm_package.h"
#include "bpm_tree.h"
#include "io.h"
#include "json.h"
#include "keys.h"
#include "log.h"
#include "malloc.h"

static void tree_show_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm tree show <repository> --cert <cert.der>\n"
		"                             [--reference <ref>]\n\n"
		"Fetches the tree publication at <repository>:<ref> (default stable),\n"
		"verifies it against the certificate as tree sync does, and prints\n"
		"{\"manifest_digest\":\"sha256:<hex>\",\"document\":<document>} with the\n"
		"document's bytes verbatim, then a newline.\n");
}

/* The checks tree sync makes before it compares with its own state. */
static int tree_show_check(const struct bpm_buffer *document)
{
	struct tree_publication pub = {};
	int ret;

	ret = tree_parse((const char *)document->data, document->len, &pub);
	if (ret)
		return ret;
	if (!bpm_package_name_ok(pub.tree_id))
		ret = -EINVAL;
	if (!ret)
		ret = tree_publication_check(&pub);
	for (int i = 0; !ret && i < pub.n_operations; i++)
		ret = tree_operation_validate(&pub.operations[i]);
	tree_publication_free(&pub);
	return ret;
}

static int tree_show_print(const char *manifest_digest,
			   const struct bpm_buffer *document)
{
	struct json_emit e = { .max = JSON_MAX_BYTES * 2 };
	int ret;

	json_obj_open(&e);
	json_kv_string(&e, "manifest_digest", manifest_digest);
	json_kv_raw(&e, "document", (const char *)document->data,
		    document->len);
	json_obj_close(&e);
	ret = e.err;
	if (!ret)
		ret = write_complete(STDOUT_FILENO, e.buf, e.len);
	if (!ret)
		ret = write_complete(STDOUT_FILENO, "\n", 1);
	xfree(e.buf, e.cap);
	return ret;
}

static int cmd_bpm_tree_show(int argc, char **argv)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	const char *raw_repository = NULL, *cert = NULL;
	char repository[BPM_MAX_ENDPOINT], digest[BPM_MAX_DIGEST];
	const char *reference = "stable";
	struct trusted_set *trusted = NULL;
	struct bpm_buffer document = {};
	int ret;

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (!strcmp(a, "--cert") && i + 1 < argc) {
			cert = argv[++i];
		} else if (!strncmp(a, "--cert=", 7)) {
			cert = a + 7;
		} else if (!strcmp(a, "--reference") && i + 1 < argc) {
			reference = argv[++i];
		} else if (!strncmp(a, "--reference=", 12)) {
			reference = a + 12;
		} else if (a[0] != '-' && !raw_repository) {
			raw_repository = a;
		} else {
			tree_show_usage();
			return -EINVAL;
		}
	}
	if (!raw_repository || !cert || !cert[0]) {
		tree_show_usage();
		return -EINVAL;
	}
	ret = bpm_oci_parse_tree_repo(raw_repository, &c, repository,
				      sizeof(repository));
	if (ret) {
		pr_err("bpm tree show: the repository must be oci://registry/repository");
		return ret;
	}
	trusted = xcalloc(1, sizeof(*trusted));
	if (!trusted)
		return -ENOMEM;
	/*
	 * A node verifies against its config image's set; a set of this
	 * certificate alone takes the same path, so a refusal names the
	 * errno sync would.
	 */
	ret = keys_load_image_at(cert, -ENOENT, false, trusted);
	if (ret) {
		pr_err("bpm tree show: cannot read the certificate %s", cert);
		goto out;
	}
	ret = bpm_tree_fetch_document(&c, repository, reference, NULL, trusted,
				      &document, digest, sizeof(digest));
	if (!ret)
		ret = tree_show_check(&document);
	if (!ret)
		ret = tree_show_print(digest, &document);
	bpm_buffer_free(&document);
out:
	xfree(trusted, sizeof(*trusted));
	return ret;
}

int build_bpm_tree_show(int argc, char **argv)
{
	int ret;

	if (argc == 2 && build_is_help(argv[1])) {
		tree_show_usage();
		return 0;
	}
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		pr_err("bpm tree show: %s", strerror(EIO));
		return 1;
	}
	ret = cmd_bpm_tree_show(argc, argv);
	curl_global_cleanup();
	if (ret < 0)
		pr_err("bpm tree show: %s", strerror(-ret));
	return ret ? 1 : 0;
}
