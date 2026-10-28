// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/openat2.h>

#include <shirudo/misc.h>

#include "io.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

static bool under(const char *path, const char *dir);

int write_complete(int fd, const void *buf, size_t len)
{
	const __u8 *p = buf;

	while (len) {
		ssize_t n = write(fd, p, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			return -EIO;
		p += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

/*
 * A path under a verified root resolves from its descriptor alone: no
 * symbolic link, no magic link and no step out of it, so nothing root
 * mounts or links elsewhere, /proc/<pid>/fd before an exec say, is
 * followed.
 */
int open_beneath(int dirfd, const char *rel, int flags)
{
	struct open_how how = {
		.flags = (__u64)flags | O_CLOEXEC,
		.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
			   RESOLVE_NO_MAGICLINKS,
	};
	long fd;

	if (dirfd < 0 || !rel || !*rel || *rel == '/')
		return -EINVAL;
	fd = syscall(SYS_openat2, dirfd, rel, &how, sizeof(how));
	return fd < 0 ? -errno : (int)fd;
}

/* The whole file behind the descriptor, from its start, xmalloc'd. */
int read_fd(int fd, const char *label, size_t max, void *out, size_t *len)
{
	struct stat st;
	char *buf, *p;
	size_t left;
	off_t off;
	int rc;

	if (fstat(fd, &st) != 0)
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EINVAL;
	rc = check_trusted(fd, label, false);
	if (rc)
		return rc;
	if ((uintmax_t)st.st_size > max)
		return -EFBIG;
	buf = xmalloc((size_t)st.st_size + 1);
	if (!buf)
		return -ENOMEM;
	for (p = buf, left = (size_t)st.st_size, off = 0; left; ) {
		ssize_t n = pread(fd, p, left, off);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			xfree(buf, (size_t)st.st_size + 1);
			return n < 0 ? -errno : -EIO;
		}
		p += n;
		off += n;
		left -= (size_t)n;
	}
	*(char **)out = buf;
	*len = (size_t)st.st_size;
	return 0;
}

/*
 * One line of text, at most max bytes before its newline, in getline's
 * buffer, which the caller frees with libc_free: 1, 0 at the end, -E2BIG
 * for a longer line and -EINVAL for one holding a NUL. fgets cut a long
 * line into two that each parsed, and a NUL ended the string where the
 * line went on.
 */
int read_text_line(FILE *f, char **line, size_t *cap, size_t max)
{
	ssize_t n;

	errno = 0;
	n = getline(line, cap, f);
	if (n < 0)
		return errno ? -errno : 0;
	if (memchr(*line, '\0', (size_t)n))
		return -EINVAL;
	if ((*line)[n - 1] == '\n')
		n--;
	return (size_t)n > max ? -E2BIG : 1;
}

int read_file(const char *path, size_t max, void *out, size_t *len)
{
	int fd, rc;

	if (under(path, SHIRUDO_VAR_LIB)) {
		fd = seal_open_read(path);
		if (fd < 0)
			return fd;
	} else {
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			return -errno;
	}
	rc = read_fd(fd, path, max, out, len);
	close(fd);
	return rc;
}

int read_file_at(int dirfd, const char *rel, size_t max, void *out,
		 size_t *len)
{
	int fd, rc;

	fd = open_beneath(dirfd, rel, O_RDONLY);
	if (fd < 0)
		return fd;
	rc = read_fd(fd, rel, max, out, len);
	close(fd);
	return rc;
}

static bool under(const char *path, const char *dir)
{
	size_t n = strlen(dir);

	return !strncmp(path, dir, n) && path[n] == '/';
}

static bool trusted_owner(uid_t uid)
{
	return uid == 0 || uid == geteuid();
}

int check_trusted(int fd, const char *path, bool secret)
{
	char real[PATH_MAX], *slash;
	struct stat st;

	if (!under(path, SHIRUDO_ETC_DIR) && !under(path, SHIRUDO_VAR_LIB))
		return 0;
	if (fstat(fd, &st))
		return -errno;
	if (!S_ISREG(st.st_mode)) {
		pr_err("refusing %s: it is not a regular file", path);
		return -EPERM;
	}
	if (!trusted_owner(st.st_uid) ||
	    (st.st_mode & (secret ? 077 : 022))) {
		pr_err("refusing %s: another user could %s it (owner uid %u, mode %04o)",
		       path, secret ? "read or change" : "change",
		       (__u32)st.st_uid, (__u32)(st.st_mode & 07777));
		pr_hint("make %s owned by root or the invoking user and %s",
			path, secret ?
			"accessible only to its owner (mode 0600)" :
			"not writable by group or others (mode 0644)");
		return -EPERM;
	}
	if (!realpath(path, real))
		return -errno;
	do {
		slash = strrchr(real, '/');
		if (slash == real)
			slash[1] = '\0';
		else
			*slash = '\0';
		if (stat(real, &st))
			return -errno;
		if (!S_ISDIR(st.st_mode) || !trusted_owner(st.st_uid) ||
		    ((st.st_mode & 022) &&
		     !((st.st_mode & S_ISVTX) && st.st_uid == 0))) {
			pr_err("refusing %s: another user could replace it through the directory %s (owner uid %u, mode %04o)",
			       path, real, (__u32)st.st_uid,
			       (__u32)(st.st_mode & 07777));
			pr_hint("make %s owned by root or the invoking user and not writable by group or others",
				real);
			return -EPERM;
		}
	} while (slash != real);
	return 0;
}
