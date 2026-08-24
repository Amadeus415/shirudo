// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .upatch container parser.
 */

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
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

static bool has_nul(const char *s, size_t n)
{
	return memchr(s, '\0', n) != NULL;
}

static uint32_t decoder_entry_u32(const struct shirudo_upatch_decoder_entry *d,
				  size_t off)
{
	return rd_le32((const unsigned char *)d + off);
}

/*
 * Parse the optional signed decoder blob. Advisory for now: malformed
 * decoder metadata is treated as absent so old upatches and ordinary
 * gen_loader data remain readable by `upatch info`.
 */
static void parse_decoders(struct shirudo_upatch *u)
{
	const unsigned char *data, *trp, *bp;
	uint32_t magic, version, decoder_off, decoder_len, nr_decoders;
	uint64_t entries_end;
	size_t i;

	if (u->hdr.data_len < sizeof(struct shirudo_upatch_decoder_trailer))
		return;

	data = u->map + u->hdr.data_off;
	trp = data + u->hdr.data_len -
	      sizeof(struct shirudo_upatch_decoder_trailer);
	magic = rd_le32(trp);
	if (magic != SHIRUDO_UPATCH_DECODER_TRAILER_MAGIC)
		return;
	version = rd_le32(trp + 4);
	if (version != SHIRUDO_UPATCH_DECODER_VERSION)
		return;

	decoder_off = rd_le32(trp + 8);
	decoder_len = rd_le32(trp + 12);
	if (decoder_len < sizeof(struct shirudo_upatch_decoder_blob))
		return;
	if ((uint64_t)decoder_off + decoder_len >
	    (uint64_t)u->hdr.data_len -
	    sizeof(struct shirudo_upatch_decoder_trailer))
		return;

	bp = data + decoder_off;
	if (rd_le32(bp) != SHIRUDO_UPATCH_DECODER_MAGIC ||
	    rd_le32(bp + 4) != SHIRUDO_UPATCH_DECODER_VERSION)
		return;

	nr_decoders = rd_le32(bp + 8);
	if (nr_decoders == 0)
		return;
	entries_end = sizeof(struct shirudo_upatch_decoder_blob) +
		      (uint64_t)nr_decoders *
		      sizeof(struct shirudo_upatch_decoder_entry);
	if (entries_end > decoder_len)
		return;

	for (i = 0; i < nr_decoders; i++) {
		const struct shirudo_upatch_decoder_entry *d;
		uint32_t source_off, source_len;

		d = (const void *)(bp +
				   sizeof(struct shirudo_upatch_decoder_blob) +
				   i * sizeof(*d));
		if (!has_nul(d->upatch, sizeof(d->upatch)) ||
		    !has_nul(d->map, sizeof(d->map)) ||
		    !has_nul(d->source, sizeof(d->source)) ||
		    !has_nul(d->entrypoint, sizeof(d->entrypoint)))
			return;
		if (rd_le32(&d->language) == 0 ||
		    rd_le32(&d->api_version) == 0 ||
		    rd_le32(&d->input_format) == 0)
			return;

		source_off = decoder_entry_u32(d, offsetof(
			struct shirudo_upatch_decoder_entry, source_off));
		source_len = decoder_entry_u32(d, offsetof(
			struct shirudo_upatch_decoder_entry, source_len));
		if (source_len == 0 || source_off < entries_end ||
		    source_off > decoder_len ||
		    source_len > decoder_len - source_off)
			return;
	}

	u->decoder_blob = (const void *)bp;
	u->decoder_blob_len = decoder_len;
	u->nr_decoders = nr_decoders;
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
	parse_decoders(out);
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
		u->decoder_blob = NULL;
		u->decoder_blob_len = 0;
		u->nr_decoders = 0;
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

bool shirudo_upatch_has_decoders(const struct shirudo_upatch *u)
{
	return u->map && u->decoder_blob && u->nr_decoders > 0;
}

int shirudo_upatch_decoder_view(const struct shirudo_upatch *u, uint32_t idx,
				struct shirudo_upatch_decoder_view *out)
{
	const unsigned char *bp, *src_base;
	const struct shirudo_upatch_decoder_entry *d;
	uint32_t source_off, source_len;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!shirudo_upatch_has_decoders(u) || idx >= u->nr_decoders)
		return -ENOENT;

	bp = (const unsigned char *)u->decoder_blob;
	d = (const void *)(bp + sizeof(struct shirudo_upatch_decoder_blob) +
			   (size_t)idx * sizeof(*d));
	out->language = rd_le32(&d->language);
	out->api_version = rd_le32(&d->api_version);
	out->input_format = rd_le32(&d->input_format);
	memcpy(out->upatch, d->upatch, sizeof(out->upatch));
	memcpy(out->map, d->map, sizeof(out->map));
	memcpy(out->source_name, d->source, sizeof(out->source_name));
	memcpy(out->entrypoint, d->entrypoint, sizeof(out->entrypoint));

	source_off = decoder_entry_u32(d, offsetof(
		struct shirudo_upatch_decoder_entry, source_off));
	source_len = decoder_entry_u32(d, offsetof(
		struct shirudo_upatch_decoder_entry, source_len));
	src_base = (const unsigned char *)u->decoder_blob;
	out->source = (const char *)(src_base + source_off);
	out->source_len = source_len;
	return 0;
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
