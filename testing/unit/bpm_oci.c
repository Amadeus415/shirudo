// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <shirudo/string.h>

#include "bpm_oci.h"
#include "unit.h"

#define DIGEST "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define MEDIA "\"mediaType\":\"application/vnd.shirudo.upatch.v1\""

static int manifest_of(const char *layers, int *n)
{
	struct bpm_descriptor descs[4];
	char text[1024];

	ASSERT_TRUE(snprintf(text, sizeof(text),
			     "{\"schemaVersion\":2,\"layers\":[%s]}",
			     layers) > 0);
	*n = -1;
	return bpm_oci_parse_manifest((const __u8 *)text, strlen(text), descs,
				      ARRAY_SIZE(descs), n, NULL, 0);
}

/*
 * The registry writes the manifest before anything is verified: a layer
 * without its digest or with a negative size would be fetched from an
 * empty URL or skip the size check.
 */
static void manifest_layer_is_a_whole_descriptor(void)
{
	int n;

	ASSERT_EQ(manifest_of("{" MEDIA ",\"digest\":\"" DIGEST "\","
			      "\"size\":5}", &n), 0);
	EXPECT_EQ(n, 1);
	EXPECT_EQ(manifest_of("{" MEDIA ",\"size\":5}", &n), -EINVAL);
	EXPECT_EQ(manifest_of("{" MEDIA ",\"digest\":\"sha512:aa\","
			      "\"size\":5}", &n), -EINVAL);
	EXPECT_EQ(manifest_of("{" MEDIA ",\"digest\":\"" DIGEST "\"}", &n),
		  -EINVAL);
	EXPECT_EQ(manifest_of("{" MEDIA ",\"digest\":\"" DIGEST "\","
			      "\"size\":-5}", &n), -EINVAL);
	EXPECT_EQ(manifest_of("{\"digest\":\"" DIGEST "\",\"size\":5}", &n),
		  -EINVAL);
	EXPECT_EQ(manifest_of("{" MEDIA ",\"digest\":\"" DIGEST "\","
			      "\"size\":5},{" MEDIA ",\"size\":5}", &n),
		  -EINVAL);
}

/* SHA-256 of "abc", FIPS 180-2 appendix B.1. */
#define ABC_DIGEST \
	"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

static void digest_names_a_blob_as_a_registry_does(void)
{
	char out[80];

	memset(out, 'x', sizeof(out));
	ASSERT_EQ(bpm_sha256_digest("abc", 3, out, 72), 0);
	EXPECT_STREQ(out, ABC_DIGEST);
	EXPECT_EQ(bpm_sha256_digest("abc", 3, out, 71), -ENAMETOOLONG);
}

static const struct unit_case cases[] = {
	UNIT_CASE(manifest_layer_is_a_whole_descriptor),
	UNIT_CASE(digest_names_a_blob_as_a_registry_does),
	{}
};

UNIT_SUITE(bpm_oci, cases);
