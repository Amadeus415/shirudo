// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "io.h"
#include "unit.h"

static int log_with(const char *text, size_t len)
{
	const char *dir = getenv("TMPDIR");
	char path[4096];
	int fd;

	ASSERT_TRUE(snprintf(path, sizeof(path), "%s/shirudo-unit-io-XXXXXX",
			     dir && dir[0] ? dir : "/tmp") > 0);
	fd = mkstemp(path);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(unlink(path), 0);
	ASSERT_EQ(fcntl(fd, F_SETFL, O_APPEND), 0);
	ASSERT_EQ(write_complete(fd, text, len), 0);
	return fd;
}

static void expect_log(int fd, const char *want)
{
	char buf[16384];
	ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);

	ASSERT_TRUE(n >= 0);
	buf[n] = '\0';
	EXPECT_STREQ(buf, want);
}

static void lines_len_ends_at_the_last_newline(void)
{
	EXPECT_EQ(lines_len("", 0), 0);
	EXPECT_EQ(lines_len("abc", 3), 0);
	EXPECT_EQ(lines_len("a\n", 2), 2);
	EXPECT_EQ(lines_len("a\nb", 3), 2);
	EXPECT_EQ(lines_len("a\nb\n", 4), 4);
	EXPECT_EQ(lines_len("\n\n", 2), 2);
}

static void append_line_adds_one_record(void)
{
	int fd = log_with("", 0);

	EXPECT_EQ(append_line(fd, "log", "x", 1), 0);
	EXPECT_EQ(append_line(fd, "log", "y\n", 2), 0);
	expect_log(fd, "x\ny\n");
	close(fd);
}

/*
 * A record killed before its newline would run into the next one on
 * its line, and every reader after would refuse the log.
 */
static void append_line_drops_what_did_not_finish(void)
{
	char text[12000];
	int fd;

	fd = log_with("x\n{\"half\":", 10);
	EXPECT_EQ(append_line(fd, "log", "z", 1), 0);
	expect_log(fd, "x\nz\n");
	close(fd);

	fd = log_with("{\"whole\":1}", 11);
	EXPECT_EQ(append_line(fd, "log", "z", 1), 0);
	expect_log(fd, "z\n");
	close(fd);

	memcpy(text, "x\n", 2);
	memset(text + 2, 'a', sizeof(text) - 2);
	fd = log_with(text, sizeof(text));
	EXPECT_EQ(append_line(fd, "log", "z", 1), 0);
	expect_log(fd, "x\nz\n");
	close(fd);
}

static void append_line_takes_one_line_alone(void)
{
	int fd = log_with("x\n", 2);

	EXPECT_EQ(append_line(fd, "log", "a\nb", 3), -EINVAL);
	EXPECT_EQ(append_line(fd, "log", "a\0b", 3), -EINVAL);
	expect_log(fd, "x\n");
	close(fd);
}

static void lock_exclusive_keeps_others_out(void)
{
	int fd = log_with("", 0), other;
	char path[64];

	ASSERT_TRUE(snprintf(path, sizeof(path), "/proc/self/fd/%d", fd) > 0);
	other = open(path, O_RDONLY | O_CLOEXEC);
	ASSERT_TRUE(other >= 0);
	EXPECT_EQ(lock_exclusive(fd), 0);
	EXPECT_EQ(flock(other, LOCK_EX | LOCK_NB), -1);
	EXPECT_EQ(errno, EWOULDBLOCK);
	close(fd);
	EXPECT_EQ(lock_exclusive(other), 0);
	close(other);
}

static void kernel_dev_is_major_over_20_minor_bits(void)
{
	EXPECT_EQ(kernel_dev(makedev(8, 1)), 0x800001U);
	EXPECT_EQ(kernel_dev(makedev(253, 0x12345)), 253U << 20 | 0x12345U);
	EXPECT_EQ(kernel_dev(makedev(0xfff, 0xfffff)), 0xffffffffU);
}

static void bpffs_mounted_at_wants_the_root_of_a_bpffs(void)
{
	const char *dir = getenv("TMPDIR");

	EXPECT_EQ(bpffs_mounted_at(dir && dir[0] ? dir : "/tmp"), 0);
	EXPECT_EQ(bpffs_mounted_at("/"), 0);
	EXPECT_EQ(bpffs_mounted_at("/nonexistent/shirudo"), 0);
	EXPECT_EQ(bpffs_mounted_at("/dev/null"), -ENOTDIR);
}

static const struct unit_case cases[] = {
	UNIT_CASE(lines_len_ends_at_the_last_newline),
	UNIT_CASE(append_line_adds_one_record),
	UNIT_CASE(append_line_drops_what_did_not_finish),
	UNIT_CASE(append_line_takes_one_line_alone),
	UNIT_CASE(lock_exclusive_keeps_others_out),
	UNIT_CASE(kernel_dev_is_major_over_20_minor_bits),
	UNIT_CASE(bpffs_mounted_at_wants_the_root_of_a_bpffs),
	{}
};

UNIT_SUITE(io, cases);
