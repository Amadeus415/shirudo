// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include <shirudo/string.h>

#include "../../util/bpm_tree.h"
#include "../../util/io.h"

#include "unit.h"

static char path[4096];

static void write_config(const char *text, bool gz)
{
	const char *tmp = getenv("TMPDIR");
	int fd;

	ASSERT_TRUE(snprintf(path, sizeof(path), "%s/shirudo-unit-kconfig-XXXXXX",
			     tmp && tmp[0] ? tmp : "/tmp") > 0);
	fd = mkstemp(path);
	ASSERT_TRUE(fd >= 0);
	if (gz) {
		gzFile f = gzdopen(fd, "wb");

		ASSERT_TRUE(f);
		ASSERT_EQ(gzwrite(f, text, (__u32)strlen(text)),
			  (int)strlen(text));
		ASSERT_EQ(gzclose(f), Z_OK);
	} else {
		ASSERT_EQ(write_complete(fd, text, strlen(text)), 0);
		ASSERT_EQ(close(fd), 0);
	}
}

static const char *modules_in(const char *text, bool gz)
{
	static char values[TREE_MAX_KCONFIG][TREE_STRING_MAX];
	static struct tree_selector sel;
	bool found[TREE_MAX_KCONFIG] = {};
	struct tree_selector_kv *kv;
	int ret;

	memset(&sel, 0, sizeof(sel));
	memset(values, 0, sizeof(values));
	ASSERT_EQ(tree_selector_kv_add(&sel.kconfig, &sel.n_kconfig,
				       TREE_MAX_KCONFIG, &kv), 0);
	strscpy(kv->key, "CONFIG_MODULES", sizeof(kv->key));
	write_config(text, gz);
	ret = tree_kconfig_read(path, &sel, values, found, gz);
	tree_selector_free(&sel);
	unlink(path);
	ASSERT_EQ(ret, 0);
	return found[0] ? values[0] : "-";
}

/*
 * A line longer than the read buffer came in parts, and the part from
 * the middle of a long string read as an option of its own.
 */
static void long_line_is_one_line(void)
{
	static const char head[] =
		"# CONFIG_MODULES is not set\nCONFIG_CMDLINE=\"";
	static const char tail[] = "CONFIG_MODULES=y\"\nCONFIG_X=y\n";
	char text[4096];

	memcpy(text, head, sizeof(head) - 1);
	memset(text + sizeof(head) - 1, ' ', 2014);
	memcpy(text + sizeof(head) - 1 + 2014, tail, sizeof(tail));
	EXPECT_STREQ(modules_in(text, false), "n");
	EXPECT_STREQ(modules_in(text, true), "n");
	EXPECT_STREQ(modules_in("CONFIG_MODULES=y\n", false), "y");
	EXPECT_STREQ(modules_in("CONFIG_MODULES=m", true), "m");
}

/* A config written gzip'd or not, cut by cut bytes and extra appended. */
static int read_gz(bool gz, off_t cut, const char *extra)
{
	static char values[TREE_MAX_KCONFIG][TREE_STRING_MAX];
	bool found[TREE_MAX_KCONFIG] = {};
	struct tree_selector sel = {};
	struct tree_selector_kv *kv;
	struct stat st;
	int fd, ret;

	ASSERT_EQ(tree_selector_kv_add(&sel.kconfig, &sel.n_kconfig,
				       TREE_MAX_KCONFIG, &kv), 0);
	strscpy(kv->key, "CONFIG_MODULES", sizeof(kv->key));
	write_config("CONFIG_MODULES=y\n", gz);
	ASSERT_EQ(stat(path, &st), 0);
	ASSERT_EQ(truncate(path, st.st_size - cut), 0);
	if (extra) {
		fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
		ASSERT_TRUE(fd >= 0);
		ASSERT_EQ(write_complete(fd, extra, strlen(extra)), 0);
		ASSERT_EQ(close(fd), 0);
	}
	ret = tree_kconfig_read(path, &sel, values, found, true);
	tree_selector_free(&sel);
	unlink(path);
	if (!ret && (!found[0] || strcmp(values[0], "y")))
		return 1;
	return ret;
}

static void gzip_config_is_one_whole_member(void)
{
	EXPECT_EQ(read_gz(true, 0, NULL), 0);
	EXPECT_EQ(read_gz(true, 1, NULL), -EINVAL);
	EXPECT_EQ(read_gz(true, 8, NULL), -EINVAL);
	EXPECT_EQ(read_gz(true, 0, "x"), -EINVAL);
	EXPECT_EQ(read_gz(false, 0, NULL), -EINVAL);
}

#define PENDING_DIGEST \
	"sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

static int pending(const char *doc, struct tree_pending *out)
{
	return tree_pending_parse(doc, strlen(doc), out);
}

static void pending_is_an_operation_in_flight(void)
{
	struct tree_pending p;

	ASSERT_EQ(pending("{\"schema\":1,\"seq\":3,\"id\":\"fix\","
			  "\"operation_digest\":\"" PENDING_DIGEST "\"}", &p), 0);
	EXPECT_EQ(p.seq, 3);
	EXPECT_STREQ(p.id, "fix");
	EXPECT_EQ(pending("{\"schema\":2,\"seq\":3,\"id\":\"fix\","
			  "\"operation_digest\":\"" PENDING_DIGEST "\"}", &p),
		  -EINVAL);
	EXPECT_EQ(pending("{\"schema\":1,\"seq\":0,\"id\":\"fix\","
			  "\"operation_digest\":\"" PENDING_DIGEST "\"}", &p),
		  -EINVAL);
	EXPECT_EQ(pending("{\"schema\":1,\"seq\":3,\"id\":\"../fix\","
			  "\"operation_digest\":\"" PENDING_DIGEST "\"}", &p),
		  -EINVAL);
	EXPECT_EQ(pending("{\"schema\":1,\"seq\":3,\"id\":\"fix\","
			  "\"operation_digest\":\"sha256:00\"}", &p), -EINVAL);
}

static const struct unit_case cases[] = {
	UNIT_CASE(long_line_is_one_line),
	UNIT_CASE(gzip_config_is_one_whole_member),
	UNIT_CASE(pending_is_an_operation_in_flight),
	{}
};

UNIT_SUITE(bpm_tree_state, cases);
