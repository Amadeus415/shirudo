/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "chain.h"
#include "mode.h"
#include "paths.h"

#define MODE_FILE_MAX 256

static int write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;

	while (len) {
		ssize_t n = write(fd, p, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			return -EIO;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

const char *shirudo_mode_file_name(enum shirudo_mode mode)
{
	return mode == SHIRUDO_MODE_TRUSTED_ROOT ?
		"trusted_root" : "untrusted_root";
}

const char *shirudo_mode_status_name(enum shirudo_mode mode)
{
	return mode == SHIRUDO_MODE_TRUSTED_ROOT ?
		"trusted-root" : "untrusted-root";
}

const char *shirudo_mode_authorization(enum shirudo_mode mode,
					bool native_kernel_signing)
{
	if (mode == SHIRUDO_MODE_TRUSTED_ROOT) {
		return native_kernel_signing ?
			"userspace-and-kernel-signature" :
			"userspace-signature-then-unsigned-loader";
	}
	return "kernel-signature";
}

int shirudo_mode_parse(const char *buf, size_t len,
			       struct shirudo_mode_state *state)
{
	char copy[MODE_FILE_MAX + 1];
	char *line, *end;
	enum shirudo_mode mode;
	uint8_t digest[SHIRUDO_CHAIN_DIGEST_LEN];
	size_t remaining;
	bool version = false, have_mode = false, have_digest = false;

	if (!buf || !state || len == 0 || len > MODE_FILE_MAX ||
	    memchr(buf, '\0', len))
		return -EINVAL;
	memcpy(copy, buf, len);
	copy[len] = '\0';
	line = copy;
	remaining = len;
	for (;;) {
		end = memchr(line, '\n', remaining);
		if (end) {
			*end = '\0';
			if (end == line)
				return -EINVAL;
		} else if (!*line) {
			return -EINVAL;
		}

		if (strcmp(line, "version=1") == 0) {
			if (version)
				return -EINVAL;
			version = true;
		} else if (strncmp(line, "mode=", 5) == 0) {
			if (have_mode)
				return -EINVAL;
			if (strcmp(line + 5, "trusted_root") == 0)
				mode = SHIRUDO_MODE_TRUSTED_ROOT;
			else if (strcmp(line + 5, "untrusted_root") == 0)
				mode = SHIRUDO_MODE_UNTRUSTED_ROOT;
			else
				return -EINVAL;
			have_mode = true;
		} else if (strncmp(line, "cert_sha256=", 12) == 0) {
			if (have_digest || strlen(line + 12) !=
				2 * SHIRUDO_CHAIN_DIGEST_LEN ||
			    shirudo_hex_decode(line + 12, digest,
					       SHIRUDO_CHAIN_DIGEST_LEN))
				return -EINVAL;
			have_digest = true;
		} else {
			return -EINVAL;
		}

		if (!end)
			break;
		remaining -= (size_t)(end - line) + 1;
		if (!remaining)
			break;
		line = end + 1;
	}
	if (!version || !have_mode || !have_digest)
		return -EINVAL;
	state->mode = mode;
	memcpy(state->cert_sha256, digest, sizeof(digest));
	return 0;
}

int shirudo_mode_read(struct shirudo_mode_state *state)
{
	char buf[MODE_FILE_MAX + 1];
	ssize_t n;
	int fd, rc;

	if (!state)
		return -EINVAL;
	fd = open(SHIRUDO_MODE_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, sizeof(buf));
	rc = n < 0 ? -errno : shirudo_mode_parse(buf, (size_t)n, state);
	close(fd);
	return rc;
}

int shirudo_mode_commit(enum shirudo_mode mode,
			const uint8_t cert_sha256[32])
{
	char digest[2 * SHIRUDO_CHAIN_DIGEST_LEN + 1], buf[MODE_FILE_MAX];
	struct shirudo_mode_state existing;
	int fd, rc, n;

	if (!cert_sha256 || (mode != SHIRUDO_MODE_UNTRUSTED_ROOT &&
			    mode != SHIRUDO_MODE_TRUSTED_ROOT))
		return -EINVAL;
	shirudo_hex_encode(cert_sha256, SHIRUDO_CHAIN_DIGEST_LEN, digest);
	n = snprintf(buf, sizeof(buf), "version=1\nmode=%s\ncert_sha256=%s\n",
		     shirudo_mode_file_name(mode), digest);
	if (n < 0 || (size_t)n >= sizeof(buf))
		return -EOVERFLOW;

	fd = open(SHIRUDO_MODE_PATH,
		  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0400);
	if (fd >= 0) {
		rc = write_all(fd, buf, strlen(buf));
		if (!rc && fsync(fd) != 0)
			rc = -errno;
		if (close(fd) != 0 && !rc)
			rc = -errno;
		return rc;
	}
	if (errno != EEXIST)
		return -errno;

	rc = shirudo_mode_read(&existing);
	if (rc)
		return rc;
	if (existing.mode != mode ||
	    !shirudo_ct_eq(existing.cert_sha256, cert_sha256, 32))
		return -EPERM;
	return 0;
}
