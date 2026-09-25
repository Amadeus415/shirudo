/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "kernel_build_id.h"

#define KERNEL_NOTES_PATH "/sys/kernel/notes"
#define KERNEL_NOTES_MAX (64u * 1024u)

static size_t align4(size_t value)
{
	return (value + 3u) & ~(size_t)3u;
}

static int read_u32(const unsigned char *p, size_t remaining, uint32_t *out)
{
	if (remaining < sizeof(*out))
		return -EINVAL;
	memcpy(out, p, sizeof(*out));
	return 0;
}

int shirudo_kernel_build_id_from_notes(const void *notes, size_t notes_len,
					       char out[SHIRUDO_KERNEL_BUILD_ID_STRING_MAX])
{
	const unsigned char *p = notes;

	if (!notes || !out)
		return -EINVAL;
	out[0] = '\0';
	while (notes_len) {
		uint32_t namesz, descsz, type;
		size_t name_off, desc_off, next;

		if (notes_len < 12 || read_u32(p, notes_len, &namesz) ||
		    read_u32(p + 4, notes_len - 4, &descsz) ||
		    read_u32(p + 8, notes_len - 8, &type))
			return -EINVAL;
		name_off = 12;
		if (namesz > notes_len - name_off ||
		    align4(namesz) > notes_len - name_off)
			return -EINVAL;
		desc_off = name_off + align4(namesz);
		if (descsz > notes_len - desc_off ||
		    align4(descsz) > notes_len - desc_off)
			return -EINVAL;
		next = desc_off + align4(descsz);
		if (type == 3 && namesz >= 3 && !memcmp(p + name_off, "GNU", 3)) {
			if (!descsz || descsz > SHIRUDO_KERNEL_BUILD_ID_MAX)
				return -E2BIG;
			for (uint32_t i = 0; i < descsz; i++)
				snprintf(out + i * 2, 3, "%02x", p[desc_off + i]);
			return 0;
		}
		p += next;
		notes_len -= next;
	}
	return -ENOENT;
}

int shirudo_kernel_build_id_read(
	char out[SHIRUDO_KERNEL_BUILD_ID_STRING_MAX])
{
	unsigned char notes[KERNEL_NOTES_MAX];
	size_t len = 0;
	int fd, rc;

	if (!out)
		return -EINVAL;
	fd = open(KERNEL_NOTES_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	while (len < sizeof(notes)) {
		ssize_t n = read(fd, notes + len, sizeof(notes) - len);

		if (n < 0) {
			rc = -errno;
			goto out;
		}
		if (!n)
			break;
		len += (size_t)n;
	}
	rc = len == sizeof(notes) ? -E2BIG :
		shirudo_kernel_build_id_from_notes(notes, len, out);
out:
	close(fd);
	return rc;
}
