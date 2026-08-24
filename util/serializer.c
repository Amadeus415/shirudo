// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include "paths.h"
#include "serializer.h"

int shirudo_serializer_lock_acquire_at(const char *dir, uint32_t map_id)
{
	char name[64];
	struct stat st;
	int dir_fd, fd, rc;

	if (!dir || !dir[0] || map_id == 0)
		return -EINVAL;
	if (mkdir(dir, 0700) != 0 && errno != EEXIST)
		return -errno;
	dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (dir_fd < 0)
		return -errno;
	if (snprintf(name, sizeof(name), "serializer-map-%u.lock", map_id) >=
	    (int)sizeof(name)) {
		close(dir_fd);
		return -ENAMETOOLONG;
	}
	fd = openat(dir_fd, name, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
	close(dir_fd);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) != 0) {
		rc = -errno;
		close(fd);
		return rc;
	}
	if (!S_ISREG(st.st_mode)) {
		close(fd);
		return -EINVAL;
	}
	/* The open fd owns the lock; callers release it with close(). */
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		rc = (errno == EWOULDBLOCK || errno == EAGAIN) ? -EBUSY : -errno;
		close(fd);
		return rc;
	}
	return fd;
}

int shirudo_serializer_lock_acquire(uint32_t map_id)
{
	return shirudo_serializer_lock_acquire_at(SHIRUDO_LOCKS_DIR, map_id);
}

int shirudo_serializer_new_invocation_id(uint64_t *out)
{
	uint64_t id;
	unsigned char *p = (unsigned char *)&id;
	size_t off;

	if (!out)
		return -EINVAL;
	do {
		off = 0;
		while (off < sizeof(id)) {
			ssize_t n = getrandom(p + off, sizeof(id) - off, 0);

			if (n < 0) {
				if (errno == EINTR)
					continue;
				return -errno;
			}
			if (n == 0)
				return -EIO;
			off += (size_t)n;
		}
	} while (id == 0);
	*out = id;
	return 0;
}

int shirudo_serial_chunk_validate(const struct shirudo_serial_chunk *c,
				  uint32_t want_index,
				  uint32_t total_chunks,
				  uint32_t page_index,
				  uint64_t cursor,
				  uint64_t next_cursor,
				  uint64_t invocation_id)
{
	if (!c || invocation_id == 0)
		return -EINVAL;
	if (c->magic != SHIRUDO_SERIAL_MAGIC ||
	    c->version != SHIRUDO_SERIAL_VERSION)
		return -EBADMSG;
	if (c->chunk_index != want_index || c->total_chunks != total_chunks)
		return -EBADMSG;
	if (c->bytes_in_chunk > SHIRUDO_SERIAL_CHUNK_PAYLOAD)
		return -EBADMSG;
	if (c->page_index != page_index || c->cursor != cursor ||
	    c->next_cursor != next_cursor ||
	    c->invocation_id != invocation_id)
		return -EBADMSG;
	return 0;
}
