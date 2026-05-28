// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .upatch container parser.
 */

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "upatch.h"

static uint32_t rd_le32(const void *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));
	return le32toh(v);
}

static uint64_t rd_le64(const void *p)
{
	uint64_t v;

	memcpy(&v, p, sizeof(v));
	return le64toh(v);
}

static int parse_header(const unsigned char *m, size_t n,
			struct shirudo_upatch_header *out)
{
	const unsigned char *p = m;

	if (n < sizeof(*out))
		return -EINVAL;

	out->magic = rd_le64(p); p += 8;
	if (out->magic != SHIRUDO_UPATCH_MAGIC)
		return -EINVAL;

	out->version = rd_le32(p); p += 4;
	if (out->version != SHIRUDO_UPATCH_VERSION)
		return -EINVAL;

	out->flags = rd_le32(p); p += 4;

	memcpy(out->name, p, sizeof(out->name));
	p += sizeof(out->name);

	memcpy(out->payload_sha256, p, sizeof(out->payload_sha256));
	p += sizeof(out->payload_sha256);

	out->loader_insns_off	= rd_le32(p); p += 4;
	out->loader_insns_len	= rd_le32(p); p += 4;
	out->signature_off	= rd_le32(p); p += 4;
	out->signature_len	= rd_le32(p); p += 4;
	out->metadata_off	= rd_le32(p); p += 4;
	out->metadata_len	= rd_le32(p); p += 4;
	out->data_off		= rd_le32(p); p += 4;
	out->data_len		= rd_le32(p); p += 4;
	out->log_buf_sz		= rd_le32(p); p += 4;
	out->nr_maps		= rd_le32(p); p += 4;
	out->nr_progs		= rd_le32(p); p += 4;
	out->extra_off		= rd_le32(p); p += 4;

	return 0;
}

static int section_inside(uint32_t off, uint32_t len, size_t n)
{
	if (off > n || len > n)
		return 0;
	if ((uint64_t)off + (uint64_t)len > (uint64_t)n)
		return 0;
	if (len != 0 && off < sizeof(struct shirudo_upatch_header))
		return 0;
	return 1;
}

static int validate_bounds(const struct shirudo_upatch_header *h, size_t n)
{
	if (!section_inside(h->loader_insns_off, h->loader_insns_len, n))
		return -EINVAL;
	if (!section_inside(h->signature_off, h->signature_len, n))
		return -EINVAL;
	if (!section_inside(h->metadata_off, h->metadata_len, n))
		return -EINVAL;
	if (!section_inside(h->data_off, h->data_len, n))
		return -EINVAL;
	/* loader insns and signature are mandatory; data may be empty */
	if (h->loader_insns_len == 0 || h->signature_len == 0)
		return -EINVAL;
	return 0;
}

/*
 * Parse the optional extras blob (embedded C source). Advisory only:
 * any malformation leaves the fields zero (treated as "no source"); it
 * never fails the open, since the signed sections are validated
 * separately and the extras are not signature-covered.
 */
static void parse_extras(struct shirudo_upatch *u)
{
	const unsigned char *m = u->map;
	uint32_t off = u->hdr.extra_off;
	uint32_t name_len, source_len;
	uint64_t need;

	if (off == 0)
		return;
	if (off < sizeof(struct shirudo_upatch_header) ||
	    (uint64_t)off + sizeof(struct shirudo_upatch_extras) >
	    (uint64_t)u->map_size)
		return;
	if (rd_le32(m + off) != SHIRUDO_UPATCH_EXTRAS_MAGIC ||
	    rd_le32(m + off + 4) != SHIRUDO_UPATCH_EXTRAS_SOURCE)
		return;
	name_len   = rd_le32(m + off + 8);
	source_len = rd_le32(m + off + 12);

	need = (uint64_t)off + sizeof(struct shirudo_upatch_extras) +
	       (uint64_t)name_len + (uint64_t)source_len;
	if (need > (uint64_t)u->map_size)
		return;

	off += sizeof(struct shirudo_upatch_extras);
	if (name_len) {
		u->source_name = (const char *)(m + off);
		u->source_name_len = name_len;
	}
	if (source_len) {
		u->source = (const char *)(m + off + name_len);
		u->source_len = source_len;
	}
}

int shirudo_upatch_open(const char *path, struct shirudo_upatch *out)
{
	struct stat st;
	void *m;
	int fd;
	int rc;

	memset(out, 0, sizeof(*out));

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) != 0) {
		rc = -errno;
		close(fd);
		return rc;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0) {
		close(fd);
		return -EINVAL;
	}
	/* refuse pathologically-large inputs; .upatch is small */
	if ((uintmax_t)st.st_size > 16u * 1024u * 1024u) {
		close(fd);
		return -EFBIG;
	}

	m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (m == MAP_FAILED)
		return -errno;

	out->map = m;
	out->map_size = (size_t)st.st_size;

	rc = parse_header(out->map, out->map_size, &out->hdr);
	if (rc != 0) {
		shirudo_upatch_close(out);
		return rc;
	}
	rc = validate_bounds(&out->hdr, out->map_size);
	if (rc != 0) {
		shirudo_upatch_close(out);
		return rc;
	}
	parse_extras(out);
	return 0;
}

void shirudo_upatch_close(struct shirudo_upatch *u)
{
	if (u->map) {
		munmap((void *)u->map, u->map_size);
		u->map = NULL;
		u->map_size = 0;
		u->source = NULL;
		u->source_len = 0;
		u->source_name = NULL;
		u->source_name_len = 0;
	}
}

const void *shirudo_upatch_loader(const struct shirudo_upatch *u)
{
	if (!u->map)
		return NULL;
	return u->map + u->hdr.loader_insns_off;
}

const void *shirudo_upatch_signature(const struct shirudo_upatch *u)
{
	if (!u->map)
		return NULL;
	return u->map + u->hdr.signature_off;
}

const void *shirudo_upatch_metadata(const struct shirudo_upatch *u)
{
	if (!u->map || u->hdr.metadata_len == 0)
		return NULL;
	return u->map + u->hdr.metadata_off;
}

const void *shirudo_upatch_data(const struct shirudo_upatch *u)
{
	if (!u->map || u->hdr.data_len == 0)
		return NULL;
	return u->map + u->hdr.data_off;
}

bool shirudo_upatch_is_unload(const struct shirudo_upatch *u)
{
	return (u->hdr.flags & SHIRUDO_DIRECTIVE_UNLOAD) != 0;
}

bool shirudo_upatch_has_source(const struct shirudo_upatch *u)
{
	return u->map && u->source && u->source_len > 0;
}

bool shirudo_upatch_name_valid(const char *name)
{
	size_t i;

	if (!name || name[0] == '\0' || name[0] == '.')
		return false;
	for (i = 0; name[i]; i++) {
		char c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		      c == '-'))
			return false;
	}
	return true;
}
