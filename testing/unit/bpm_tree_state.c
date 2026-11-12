// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include "../../util/paths.h"

static char tree_dir[4200], state_path[4300], outcomes_path[4300];
static char events_path[4300], pending_path[4300];

#undef BPM_TREE_VAR_DIR
#define BPM_TREE_VAR_DIR tree_dir
#undef BPM_TREE_STATE_PATH
#define BPM_TREE_STATE_PATH state_path
#undef BPM_TREE_EVENTLOG_PATH
#define BPM_TREE_EVENTLOG_PATH events_path
#undef BPM_TREE_PENDING_PATH
#define BPM_TREE_PENDING_PATH pending_path
#undef BPM_TREE_OUTCOMES_PATH
#define BPM_TREE_OUTCOMES_PATH outcomes_path

#include "../../util/bpm_tree_state.c"

#include "unit.h"

static char path[4096];

static void write_config(const char *text, bool gz)
{
	const char *tmp = getenv("TMPDIR");
	int fd;

	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/shirudo-unit-kconfig-XXXXXX",
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
	static int slots[TREE_SELECTOR_HASH_SIZE];
	static struct tree_selector sel;
	bool found[TREE_MAX_KCONFIG] = {};
	struct tree_selector_kv *kv;
	int ret;

	memset(&sel, 0, sizeof(sel));
	memset(values, 0, sizeof(values));
	ASSERT_EQ(tree_selector_kv_add(&sel.kconfig, &sel.n_kconfig,
				       TREE_MAX_KCONFIG, &kv), 0);
	strscpy(kv->key, "CONFIG_MODULES", sizeof(kv->key));
	selector_hash_build(&sel, slots);
	write_config(text, gz);
	ret = read_selector_config_file(path, &sel, slots, values, found, gz);
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
	static int slots[TREE_SELECTOR_HASH_SIZE];
	bool found[TREE_MAX_KCONFIG] = {};
	struct tree_selector sel = {};
	struct tree_selector_kv *kv;
	struct stat st;
	int fd, ret;

	ASSERT_EQ(tree_selector_kv_add(&sel.kconfig, &sel.n_kconfig,
				       TREE_MAX_KCONFIG, &kv), 0);
	strscpy(kv->key, "CONFIG_MODULES", sizeof(kv->key));
	selector_hash_build(&sel, slots);
	write_config("CONFIG_MODULES=y\n", gz);
	ASSERT_EQ(stat(path, &st), 0);
	ASSERT_EQ(truncate(path, st.st_size - cut), 0);
	if (extra) {
		fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
		ASSERT_TRUE(fd >= 0);
		ASSERT_EQ(write_complete(fd, extra, strlen(extra)), 0);
		ASSERT_EQ(close(fd), 0);
	}
	ret = read_selector_config_file(path, &sel, slots, values, found, true);
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

static char top_dir[4096];

static void use_tree(void)
{
	const char *tmp = getenv("TMPDIR");

	ASSERT_TRUE(strsprintf(top_dir, sizeof(top_dir),
			       "%s/shirudo-unit-tree-XXXXXX",
			       tmp && tmp[0] ? tmp : "/tmp") > 0);
	ASSERT_TRUE(mkdtemp(top_dir));
	ASSERT_TRUE(strsprintf(tree_dir, sizeof(tree_dir), "%s/upatch-tree",
			       top_dir) > 0);
	ASSERT_TRUE(strsprintf(state_path, sizeof(state_path),
			       "%s/state.json", tree_dir) > 0);
	ASSERT_TRUE(strsprintf(outcomes_path, sizeof(outcomes_path),
			       "%s/outcomes", tree_dir) > 0);
	ASSERT_TRUE(strsprintf(events_path, sizeof(events_path),
			       "%s/tree-eventlog", tree_dir) > 0);
	ASSERT_TRUE(strsprintf(pending_path, sizeof(pending_path),
			       "%s/pending.json", tree_dir) > 0);
}

static void drop_tree(void)
{
	unlink(state_path);
	unlink(outcomes_path);
	rmdir(tree_dir);
	rmdir(top_dir);
}

static void write_text(const char *file, const char *text, int flags)
{
	int fd;

	ASSERT_TRUE(mkdir(tree_dir, 0700) == 0 || errno == EEXIST);
	fd = open(file, O_WRONLY | O_CREAT | O_CLOEXEC | flags, 0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, text, strlen(text)), 0);
	ASSERT_EQ(close(fd), 0);
}

static off_t outcomes_size(void)
{
	struct stat st;

	ASSERT_EQ(stat(outcomes_path, &st), 0);
	return st.st_size;
}

/* The roots a test gives the line of seq: every byte seq, or seq + 100. */
static void append_outcome(__s64 seq, enum tree_outcome outcome)
{
	__u8 projection[32], history[32];

	memset(projection, (int)seq, sizeof(projection));
	memset(history, (int)seq + 100, sizeof(history));
	ASSERT_EQ(tree_outcome_append(seq, outcome, projection, history), 0);
}

static void expect_roots(const __u8 projection[32], const __u8 history[32],
			 __s64 seq)
{
	__u8 want_projection[32] = {}, want_history[32] = {};

	if (seq) {
		memset(want_projection, (int)seq, sizeof(want_projection));
		memset(want_history, (int)seq + 100, sizeof(want_history));
	}
	EXPECT_MEMEQ(projection, want_projection, 32);
	EXPECT_MEMEQ(history, want_history, 32);
}

#define OUTCOME_LINE(seq, outcome)					\
	"{\"schema\":1,\"seq\":" #seq ",\"outcome\":" #outcome ","	\
	"\"projection_root\":\""					\
	"0101010101010101010101010101010101010101010101010101010101010101" \
	"\",\"history_root\":\""					\
	"6565656565656565656565656565656565656565656565656565656565656565" \
	"\"}\n"

static void outcomes_append_and_read_back(void)
{
	__u8 codes[3] = {}, projection[32], history[32];
	char *text;
	size_t len;

	use_tree();
	append_outcome(1, TREE_OUTCOME_APPLIED);
	ASSERT_EQ(read_file(outcomes_path, 4096, &text, &len), 0);
	EXPECT_STREQ(text, OUTCOME_LINE(1, 1));
	xfree(text, len + 1);
	append_outcome(2, TREE_OUTCOME_UNMATCHED);
	append_outcome(3, TREE_OUTCOME_MODULE_ABSENT);

	ASSERT_EQ(tree_outcomes_read(0, 3, codes, projection, history), 0);
	EXPECT_EQ(codes[0], 1);
	EXPECT_EQ(codes[1], 2);
	EXPECT_EQ(codes[2], 3);
	expect_roots(projection, history, 0);

	memset(codes, 0, sizeof(codes));
	ASSERT_EQ(tree_outcomes_read(1, 3, codes, projection, history), 0);
	EXPECT_EQ(codes[0], 2);
	EXPECT_EQ(codes[1], 3);
	EXPECT_EQ(codes[2], 0);
	expect_roots(projection, history, 1);

	ASSERT_EQ(tree_outcomes_read(3, 3, codes, projection, history), 0);
	expect_roots(projection, history, 3);
	ASSERT_EQ(tree_outcomes_read(0, 0, codes, projection, history), 0);
	expect_roots(projection, history, 0);

	EXPECT_EQ(tree_outcomes_read(2, 1, codes, projection, history),
		  -EINVAL);
	EXPECT_EQ(tree_outcomes_read(-1, 1, codes, projection, history),
		  -EINVAL);
	EXPECT_EQ(tree_outcome_append(0, TREE_OUTCOME_APPLIED, projection,
				      history), -EINVAL);
	EXPECT_EQ(tree_outcome_append(4, 0, projection, history), -EINVAL);
	EXPECT_EQ(tree_outcome_append(4, 4, projection, history), -EINVAL);
	drop_tree();
}

static void outcomes_torn_last_line_is_dropped(void)
{
	__u8 codes[3], projection[32], history[32];
	off_t whole;

	use_tree();
	append_outcome(1, TREE_OUTCOME_APPLIED);
	append_outcome(2, TREE_OUTCOME_UNMATCHED);
	whole = outcomes_size();
	write_text(outcomes_path, "{\"schema\":1,\"seq\":3,\"outc", O_APPEND);

	ASSERT_EQ(tree_outcomes_read(0, 2, codes, projection, history), 0);
	EXPECT_EQ(tree_outcomes_read(0, 3, codes, projection, history),
		  -ENOENT);
	EXPECT_EQ(tree_outcomes_check(2), 0);
	EXPECT_EQ(tree_outcomes_check(3), -EBADMSG);

	ASSERT_EQ(tree_outcomes_truncate(2), 0);
	EXPECT_EQ(outcomes_size(), whole);

	write_text(outcomes_path, "{\"schema\":1,\"seq\":3,\"outc", O_APPEND);
	append_outcome(3, TREE_OUTCOME_APPLIED);
	ASSERT_EQ(tree_outcomes_read(0, 3, codes, projection, history), 0);
	EXPECT_EQ(codes[2], 1);
	drop_tree();
}

static void outcomes_truncate_past_last_seq(void)
{
	__u8 codes[4], projection[32], history[32];
	off_t two;

	use_tree();
	EXPECT_EQ(tree_outcomes_truncate(2), 0);
	EXPECT_EQ(access(outcomes_path, F_OK), -1);
	EXPECT_EQ(tree_outcomes_truncate(-1), -EINVAL);

	append_outcome(1, TREE_OUTCOME_APPLIED);
	append_outcome(2, TREE_OUTCOME_UNMATCHED);
	two = outcomes_size();
	append_outcome(3, TREE_OUTCOME_MODULE_ABSENT);
	append_outcome(4, TREE_OUTCOME_APPLIED);

	ASSERT_EQ(tree_outcomes_truncate(2), 0);
	EXPECT_EQ(outcomes_size(), two);
	ASSERT_EQ(tree_outcomes_read(0, 2, codes, projection, history), 0);
	EXPECT_EQ(codes[0], 1);
	EXPECT_EQ(codes[1], 2);
	EXPECT_EQ(tree_outcomes_read(0, 3, codes, projection, history),
		  -ENOENT);

	ASSERT_EQ(tree_outcomes_truncate(5), 0);
	EXPECT_EQ(outcomes_size(), two);

	/* What follows last_seq goes unread: it need not be a line. */
	write_text(outcomes_path, "not a line\n" OUTCOME_LINE(9, 1),
		   O_APPEND);
	ASSERT_EQ(tree_outcomes_truncate(2), 0);
	EXPECT_EQ(outcomes_size(), two);

	ASSERT_EQ(tree_outcomes_truncate(0), 0);
	EXPECT_EQ(outcomes_size(), 0);
	drop_tree();
}

static int read_outcomes(const char *text, __s64 to)
{
	__u8 codes[8], projection[32], history[32];

	write_text(outcomes_path, text, O_TRUNC);
	return tree_outcomes_read(0, to, codes, projection, history);
}

static void outcomes_gap_and_missing_line(void)
{
	__u8 codes[2], projection[32], history[32];

	use_tree();
	EXPECT_EQ(tree_outcomes_read(0, 1, codes, projection, history),
		  -ENOENT);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 1), 1), 0);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 1), 2), -ENOENT);
	EXPECT_EQ(read_outcomes("", 1), -ENOENT);

	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 1) OUTCOME_LINE(3, 1), 3),
		  -EBADMSG);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 1) OUTCOME_LINE(3, 1), 1), 0);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(2, 1), 2), -EBADMSG);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 1) OUTCOME_LINE(1, 1), 2),
		  -EBADMSG);
	EXPECT_EQ(tree_outcomes_truncate(2), -EBADMSG);

	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 0), 1), -EBADMSG);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 4), 1), -EBADMSG);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(0, 1), 1), -EBADMSG);
	EXPECT_EQ(read_outcomes("\n" OUTCOME_LINE(1, 1), 1), -EBADMSG);
	EXPECT_EQ(read_outcomes("not a line\n", 1), -EBADMSG);
	EXPECT_EQ(read_outcomes("{\"schema\":2,\"seq\":1,\"outcome\":1,"
				"\"projection_root\":\"\","
				"\"history_root\":\"\"}\n", 1), -EBADMSG);
	EXPECT_EQ(read_outcomes("{\"schema\":1,\"seq\":1,\"outcome\":1,"
				"\"projection_root\":\"01\","
				"\"history_root\":\"65\"}\n", 1), -EBADMSG);
	EXPECT_EQ(read_outcomes("{\"schema\":1,\"seq\":1,\"outcome\":1}\n", 1),
		  -EBADMSG);
	drop_tree();
}

static void outcomes_longer_line_is_malformed(void)
{
	char text[2 * OUTCOME_LINE_MAX];

	use_tree();
	memset(text, ' ', sizeof(text));
	text[sizeof(text) - 2] = '\n';
	text[sizeof(text) - 1] = '\0';
	EXPECT_EQ(read_outcomes(text, 1), -EBADMSG);
	text[sizeof(text) - 2] = ' ';
	EXPECT_EQ(read_outcomes(text, 1), -EBADMSG);
	drop_tree();
}

static void outcomes_cover_the_state(void)
{
	use_tree();
	EXPECT_EQ(tree_outcomes_check(0), 0);
	EXPECT_EQ(tree_outcomes_check(-1), -EINVAL);
	EXPECT_EQ(tree_outcomes_check(1), -EBADMSG);

	write_text(outcomes_path, OUTCOME_LINE(1, 1) OUTCOME_LINE(2, 2),
		   O_TRUNC);
	EXPECT_EQ(tree_outcomes_check(0), 0);
	EXPECT_EQ(tree_outcomes_check(1), 0);
	EXPECT_EQ(tree_outcomes_check(2), 0);
	EXPECT_EQ(tree_outcomes_check(3), -EBADMSG);

	write_text(outcomes_path, OUTCOME_LINE(1, 1) OUTCOME_LINE(3, 2),
		   O_TRUNC);
	EXPECT_EQ(tree_outcomes_check(1), 0);
	EXPECT_EQ(tree_outcomes_check(3), -EBADMSG);

	write_text(outcomes_path, "", O_TRUNC);
	EXPECT_EQ(tree_outcomes_check(1), -EBADMSG);
	drop_tree();
}

#define STATE_ROOT \
	"5c7761b120a9cf59e79e5a078227b450b7a39294db74bb3ba28e28c6ae196d27"
#define STATE_HEAD \
	"{\"schema\":1,\"tree_id\":\"prod\",\"generation\":3,\"last_seq\":5," \
	"\"projection_root\":\"" STATE_ROOT "\","			\
	"\"projection_root_tpm\":\"" STATE_ROOT "\","			\
	"\"manifest_digest\":\"" PENDING_DIGEST "\""

static int read_state(const char *text, struct tree_state *out)
{
	write_text(state_path, text, O_TRUNC);
	return tree_state_read(out);
}

static void state_names_its_publication_head_and_base(void)
{
	struct tree_state s, back;

	use_tree();
	EXPECT_EQ(tree_state_read(&s), -ENOENT);
	EXPECT_EQ(read_state(STATE_HEAD "}", &s), -EINVAL);
	EXPECT_EQ(read_state(STATE_HEAD ",\"head_seq\":7}", &s), -EINVAL);
	EXPECT_EQ(read_state(STATE_HEAD ",\"segment_base_seq\":0}", &s),
		  -EINVAL);
	ASSERT_EQ(read_state(STATE_HEAD ",\"head_seq\":7,"
			     "\"segment_base_seq\":2}", &s), 0);
	EXPECT_EQ(s.last_seq, 5);
	EXPECT_EQ(s.head_seq, 7);
	EXPECT_EQ(s.segment_base_seq, 2);

	s.head_seq = 9;
	s.segment_base_seq = 4;
	ASSERT_EQ(tree_state_write(&s), 0);
	ASSERT_EQ(tree_state_read(&back), 0);
	EXPECT_STREQ(back.tree_id, "prod");
	EXPECT_EQ(back.generation, 3);
	EXPECT_EQ(back.last_seq, 5);
	EXPECT_STREQ(back.projection_root, STATE_ROOT);
	EXPECT_STREQ(back.projection_root_tpm, STATE_ROOT);
	EXPECT_STREQ(back.manifest_digest, PENDING_DIGEST);
	EXPECT_EQ(back.head_seq, 9);
	EXPECT_EQ(back.segment_base_seq, 4);
	drop_tree();
}

#define STATE_TAIL \
	"\"manifest_digest\":\"" PENDING_DIGEST "\",\"head_seq\":7,"	\
	"\"segment_base_seq\":0}"
#define STATE_NO_TPM_ROOT \
	"{\"schema\":1,\"tree_id\":\"prod\",\"generation\":3,\"last_seq\":5," \
	"\"projection_root\":\"" STATE_ROOT "\","

static void state_needs_both_projection_roots(void)
{
	struct tree_state s;

	use_tree();
	EXPECT_EQ(read_state(STATE_NO_TPM_ROOT STATE_TAIL, &s), -EINVAL);
	EXPECT_EQ(read_state(STATE_NO_TPM_ROOT "\"projection_root_tpm\":\"\","
			     STATE_TAIL, &s), -EINVAL);
	EXPECT_EQ(read_state(STATE_NO_TPM_ROOT "\"projection_root_tpm\":\"5c\","
			     STATE_TAIL, &s), -EINVAL);
	ASSERT_EQ(read_state(STATE_NO_TPM_ROOT "\"projection_root_tpm\":\""
			     STATE_ROOT "\"," STATE_TAIL, &s), 0);
	EXPECT_STREQ(s.projection_root_tpm, STATE_ROOT);
	drop_tree();
}

static const struct unit_case cases[] = {
	UNIT_CASE(long_line_is_one_line),
	UNIT_CASE(gzip_config_is_one_whole_member),
	UNIT_CASE(pending_is_an_operation_in_flight),
	UNIT_CASE(outcomes_append_and_read_back),
	UNIT_CASE(outcomes_torn_last_line_is_dropped),
	UNIT_CASE(outcomes_truncate_past_last_seq),
	UNIT_CASE(outcomes_gap_and_missing_line),
	UNIT_CASE(outcomes_longer_line_is_malformed),
	UNIT_CASE(outcomes_cover_the_state),
	UNIT_CASE(state_names_its_publication_head_and_base),
	UNIT_CASE(state_needs_both_projection_roots),
	{}
};

UNIT_SUITE(bpm_tree_state, cases);
