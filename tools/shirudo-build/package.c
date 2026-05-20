// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * gen_loader + CMS sign + .upatch container writer.
 */

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include <shirudo/upatch.h>

#include "loader.h"
#include "log.h"
#include "malloc.h"
#include "package.h"
#include "sign.h"

#define SHIRUDO_MAX_SIG_SIZE	4096

struct shirudo_unload_params {
	char	name[SHIRUDO_UPATCH_NAME_MAX];
	uint8_t	expected_sha256[SHIRUDO_UPATCH_PAYLOAD_HASH_LEN];
};

static int write_all(int fd, const void *buf, size_t n)
{
	const char *p = buf;

	while (n) {
		ssize_t w = write(fd, p, n);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		p += w;
		n -= (size_t)w;
	}
	return 0;
}

static void pack_header(struct shirudo_upatch_header *h,
			const char *name, uint32_t flags,
			const uint8_t *payload_sha256,
			uint32_t loader_off, uint32_t loader_len,
			uint32_t sig_off, uint32_t sig_len,
			uint32_t meta_off, uint32_t meta_len,
			uint32_t data_off, uint32_t data_len,
			uint32_t log_buf_sz,
			uint32_t nr_maps, uint32_t nr_progs,
			uint32_t extra_off)
{
	memset(h, 0, sizeof(*h));
	h->magic   = htole64(SHIRUDO_UPATCH_MAGIC);
	h->version = htole32(SHIRUDO_UPATCH_VERSION);
	h->flags   = htole32(flags);
	strncpy(h->name, name, sizeof(h->name) - 1);
	memcpy(h->payload_sha256, payload_sha256,
	       SHIRUDO_UPATCH_PAYLOAD_HASH_LEN);
	h->loader_insns_off = htole32(loader_off);
	h->loader_insns_len = htole32(loader_len);
	h->signature_off    = htole32(sig_off);
	h->signature_len    = htole32(sig_len);
	h->metadata_off     = htole32(meta_off);
	h->metadata_len     = htole32(meta_len);
	h->data_off         = htole32(data_off);
	h->data_len         = htole32(data_len);
	h->log_buf_sz       = htole32(log_buf_sz);
	h->nr_maps          = htole32(nr_maps);
	h->nr_progs         = htole32(nr_progs);
	h->extra_off        = htole32(extra_off);
}

/* Read a small regular file (<= 1 MiB) into a malloc'd buffer. 0/-errno. */
static int read_small_file(const char *path, char **out, uint32_t *out_len)
{
	struct stat st;
	ssize_t got;
	char *buf;
	int fd;

	*out = NULL;
	*out_len = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) != 0) {
		int e = -errno;

		close(fd);
		return e;
	}
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
	    st.st_size > 1024 * 1024) {
		close(fd);
		return -EINVAL;
	}
	buf = xmalloc((size_t)st.st_size);
	if (!buf) {
		close(fd);
		return -ENOMEM;
	}
	got = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (got != st.st_size) {
		xfree(buf, (size_t)st.st_size);
		return -EIO;
	}
	*out = buf;
	*out_len = (uint32_t)st.st_size;
	return 0;
}

/*
 * Run gen_loader on an already-opened object, CMS-sign the produced
 * loader bytes, and write the .upatch container. Takes ownership of
 * obj (closes it on every exit path). src_path, if non-NULL, is the C
 * source file embedded for `shirudo upatch info` (NULL for a .bpf.o
 * input or an unload directive).
 */
static int finalize_object(struct bpf_object *obj, const char *out_path,
			   const char *upatch_name, uint32_t flags,
			   const void *meta, uint32_t meta_len,
			   const char *src_path,
			   const char *pkey_path, const char *cert_path)
{
	LIBBPF_OPTS(gen_loader_opts, opts);
	struct shirudo_sign_io sio = {};
	struct shirudo_upatch_header hdr;
	struct bpf_map *m;
	struct bpf_program *p;
	void *sig_buf = NULL;
	char *src_buf = NULL;
	int fd = -1;
	int err = 0;
	uint32_t loader_off, sig_off;
	uint32_t nr_maps = 0, nr_progs = 0;
	uint32_t src_len = 0, name_len = 0;

	opts.gen_hash = true;
	err = bpf_object__gen_loader(obj, &opts);
	if (err) {
		pr_err("bpf_object__gen_loader: %d", err);
		goto out;
	}
	err = bpf_object__load(obj);
	if (err) {
		pr_err("bpf_object__load: %d", err);
		goto out;
	}

	/*
	 * The loader writes map_fd/prog_fd back into descriptor arrays
	 * trailing its ctx, in the same order libbpf iterates the
	 * object. The target needs these counts to locate prog_fd[]
	 * after BPF_PROG_TEST_RUN -- it has only the .upatch, not the
	 * object. Iteration order here matches gen_loader's.
	 */
	bpf_object__for_each_map(m, obj)
		nr_maps++;
	bpf_object__for_each_program(p, obj)
		nr_progs++;

	sig_buf = xmalloc(SHIRUDO_MAX_SIG_SIZE);
	if (!sig_buf) {
		err = -ENOMEM;
		goto out;
	}
	sio.insns        = opts.insns;
	sio.insns_sz     = opts.insns_sz;
	sio.signature    = sig_buf;
	sio.signature_sz = SHIRUDO_MAX_SIG_SIZE;
	err = shirudo_cms_sign(&sio, pkey_path, cert_path);
	if (err) {
		pr_err("shirudo_cms_sign: %d", err);
		goto out;
	}

	/*
	 * Informational extras: the BPF program's C source, so `shirudo
	 * upatch info` can print the full source without loading. Only the
	 * top-level source passed to `shirudo build` (a .bpf.c). Best-effort
	 * and not signature-covered; a NULL src_path (a .bpf.o input or an
	 * unload directive) or an unreadable file means no source extras.
	 */
	if (src_path) {
		int srerr = read_small_file(src_path, &src_buf, &src_len);

		if (srerr)
			pr_warn("source %s unreadable: %s (no source embedded)",
				src_path, strerror(-srerr));
		else
			name_len = (uint32_t)strlen(src_path);
	}

	loader_off = (uint32_t)sizeof(hdr);
	sig_off    = loader_off + opts.insns_sz;
	uint32_t data_off = sig_off + (uint32_t)sio.signature_sz;
	uint32_t data_len = opts.data_sz;
	uint32_t meta_off = data_off + data_len;
	uint32_t extra_off = src_buf ? meta_off + meta_len : 0;
	struct shirudo_upatch_extras ex = {};

	ex.magic      = htole32(SHIRUDO_UPATCH_EXTRAS_MAGIC);
	ex.format     = htole32(SHIRUDO_UPATCH_EXTRAS_SOURCE);
	ex.name_len   = htole32(name_len);
	ex.source_len = htole32(src_len);

	pack_header(&hdr, upatch_name, flags,
		    sio.payload_sha256,
		    loader_off, opts.insns_sz,
		    sig_off, (uint32_t)sio.signature_sz,
		    meta_len ? meta_off : 0, meta_len,
		    data_len ? data_off : 0, data_len,
		    1u * 1024u * 1024u,
		    nr_maps, nr_progs, extra_off);

	fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		err = -errno;
		pr_err("open %s: %s", out_path, strerror(errno));
		goto out;
	}
	err = write_all(fd, &hdr, sizeof(hdr));
	if (!err)
		err = write_all(fd, opts.insns, opts.insns_sz);
	if (!err)
		err = write_all(fd, sig_buf, sio.signature_sz);
	if (!err && data_len)
		err = write_all(fd, opts.data, data_len);
	if (!err && meta_len)
		err = write_all(fd, meta, meta_len);
	if (!err && extra_off) {
		err = write_all(fd, &ex, sizeof(ex));
		if (!err && name_len)
			err = write_all(fd, src_path, name_len);
		if (!err && src_len)
			err = write_all(fd, src_buf, src_len);
	}
	if (!err && fsync(fd) != 0)
		err = -errno;
	close(fd);
	fd = -1;
	xfree(src_buf, src_len);
	src_buf = NULL;
	if (err) {
		unlink(out_path);
		goto out;
	}

	pr_info("wrote %s (insns=%u sig=%zu data=%u maps=%u progs=%u source=%u name=%s%s)",
		out_path, opts.insns_sz, sio.signature_sz, data_len,
		nr_maps, nr_progs, src_len, upatch_name,
		(flags & SHIRUDO_DIRECTIVE_UNLOAD) ? " UNLOAD" : "");
out:
	if (fd >= 0)
		close(fd);
	xfree(src_buf, src_len);
	xfree(sig_buf, SHIRUDO_MAX_SIG_SIZE);
	bpf_object__close(obj);
	return err;
}

int shirudo_build_package_load(const char *bpf_o, const char *src_path,
			       const char *out_path, const char *upatch_name,
			       const char *pkey_path, const char *cert_path)
{
	struct bpf_object *obj = bpf_object__open_file(bpf_o, NULL);
	int err = libbpf_get_error(obj);

	if (err) {
		pr_err("open %s: %d", bpf_o, err);
		return err;
	}
	return finalize_object(obj, out_path, upatch_name, 0,
			       NULL, 0, src_path, pkey_path, cert_path);
}

/* Locate the BPF .rodata map. libbpf names it "<objname>.rodata". */
static struct bpf_map *find_rodata(struct bpf_object *obj)
{
	struct bpf_map *m;

	bpf_object__for_each_map(m, obj) {
		const char *name = bpf_map__name(m);
		size_t n = strlen(name);

		if (n >= 7 && strcmp(name + n - 7, ".rodata") == 0)
			return m;
	}
	return NULL;
}

int shirudo_build_package_unload(const char *upatch_name,
				 const unsigned char payload_sha256[32],
				 const char *out_upatch,
				 const char *pkey_path,
				 const char *cert_path)
{
	const struct shirudo_embedded_bpf *blob = shirudo_unload_blob();
	struct shirudo_unload_params params = {};
	struct bpf_object *obj;
	struct bpf_map *rodata;
	int err;

	if (!blob || !blob->data || !blob->size) {
		pr_err("embedded unload template missing");
		return -ENOENT;
	}

	obj = bpf_object__open_mem(blob->data, blob->size, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		pr_err("open embedded unload template: %d", err);
		return err;
	}

	rodata = find_rodata(obj);
	if (!rodata) {
		pr_err("unload template has no .rodata map");
		bpf_object__close(obj);
		return -EINVAL;
	}

	strncpy(params.name, upatch_name, sizeof(params.name) - 1);
	memcpy(params.expected_sha256, payload_sha256,
	       sizeof(params.expected_sha256));
	err = bpf_map__set_initial_value(rodata, &params, sizeof(params));
	if (err) {
		pr_err("set_initial_value(.rodata): %d", err);
		bpf_object__close(obj);
		return err;
	}

	/*
	 * Carry the target's expected payload_sha256 as metadata so the
	 * target can compute the unload chain event (and a future
	 * payload_mismatch check) without parsing the loader data blob.
	 * The metadata is not signature-covered; tampering only produces
	 * a chain value the operator's expectation rejects.
	 */
	return finalize_object(obj, out_upatch, upatch_name,
			       SHIRUDO_DIRECTIVE_UNLOAD,
			       payload_sha256, 32,
			       NULL, pkey_path, cert_path);
}
