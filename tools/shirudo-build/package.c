// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * gen_loader + CMS sign + .upatch container writer.
 */

#include <endian.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include <shirudo/upatch.h>

#include "bpf/lib/shirudo_serializer.h"
#include "loader.h"
#include "log.h"
#include "malloc.h"
#include "package.h"
#include "sign.h"

#define SHIRUDO_MAX_SIG_SIZE	4096
#define SHIRUDO_SERIALIZER_PREFIX	"shirudo_serialize__"

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

static bool unsupported_kprobe_section(const char *sec)
{
	if (sec && sec[0] == '?')
		sec++;
	return sec &&
	       (strcmp(sec, "kprobe") == 0 ||
		strcmp(sec, "kretprobe") == 0 ||
		strcmp(sec, "kprobe/") == 0 ||
		strcmp(sec, "kretprobe/") == 0 ||
		strncmp(sec, "kprobe.multi", 12) == 0 ||
		strncmp(sec, "kretprobe.multi", 15) == 0);
}

static bool unsupported_sk_skb_section(const char *sec)
{
	if (sec && sec[0] == '?')
		sec++;
	return sec && (strcmp(sec, "sk_skb") == 0 ||
		       strncmp(sec, "sk_skb/", 7) == 0);
}

static bool unsupported_socket_filter_section(const char *sec)
{
	if (sec && sec[0] == '?')
		sec++;
	return sec && (strcmp(sec, "socket") == 0 ||
		       strcmp(sec, "socket_filter") == 0 ||
		       strncmp(sec, "socket/", 7) == 0 ||
		       strncmp(sec, "socket_filter/", 14) == 0);
}

static bool unsupported_cgroup_skb_section(const char *sec)
{
	if (!sec)
		return false;
	if (sec[0] == '?')
		sec++;
	if (strcmp(sec, "cgroup_skb/ingress") == 0 ||
	    strcmp(sec, "cgroup_skb/egress") == 0)
		return false;
	return strcmp(sec, "cgroup/skb") == 0 ||
	       strcmp(sec, "cgroup_skb") == 0 ||
	       strncmp(sec, "cgroup_skb/", 11) == 0;
}

static bool unsupported_fmod_ret_section(const char *sec)
{
	if (!sec)
		return false;
	if (sec[0] == '?')
		sec++;
	return strcmp(sec, "fmod_ret") == 0 ||
	       strcmp(sec, "fmod_ret/") == 0 ||
	       strcmp(sec, "fmod_ret.s") == 0 ||
	       strcmp(sec, "fmod_ret.s/") == 0;
}

static uint32_t attach_kind_from_section(const char *sec,
					 const char **target)
{
	*target = NULL;
	if (!sec)
		return SHIRUDO_UPATCH_ATTACH_RAW_TRACEPOINT;
	if (sec[0] == '?')
		sec++;
	if (strncmp(sec, "kprobe/", 7) == 0 && sec[7]) {
		*target = sec + 7;
		return SHIRUDO_UPATCH_ATTACH_KPROBE;
	}
	if (strncmp(sec, "kretprobe/", 10) == 0 && sec[10]) {
		*target = sec + 10;
		return SHIRUDO_UPATCH_ATTACH_KRETPROBE;
	}
	if (strcmp(sec, "cgroup_skb/ingress") == 0)
		return SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_INGRESS;
	if (strcmp(sec, "cgroup_skb/egress") == 0)
		return SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_EGRESS;
	if (strncmp(sec, "fmod_ret/", 9) == 0 && sec[9])
		return SHIRUDO_UPATCH_ATTACH_FMOD_RET;
	if (strncmp(sec, "fmod_ret.s/", 11) == 0 && sec[11])
		return SHIRUDO_UPATCH_ATTACH_FMOD_RET;
	if (strcmp(sec, "netfilter") == 0)
		return SHIRUDO_UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING;
	return SHIRUDO_UPATCH_ATTACH_RAW_TRACEPOINT;
}

static int split_probe_target(const char *src, char *target,
			      size_t target_sz, uint64_t *offset)
{
	const char *plus = strrchr(src, '+');
	size_t len;

	*offset = 0;
	if (!src || !src[0])
		return -EINVAL;
	if (plus) {
		char *end = NULL;
		unsigned long long parsed;

		if (plus == src || plus[1] == '\0')
			return -EINVAL;
		errno = 0;
		parsed = strtoull(plus + 1, &end, 0);
		if (errno || !end || *end != '\0')
			return -EINVAL;
		*offset = (uint64_t)parsed;
		len = (size_t)(plus - src);
	} else {
		len = strlen(src);
	}
	if (len == 0 || len >= target_sz)
		return -EINVAL;
	memcpy(target, src, len);
	target[len] = '\0';
	return 0;
}

static bool is_syscall_section(const char *sec)
{
	return sec && strcmp(sec, "syscall") == 0;
}

static const char *serializer_map_name(const struct bpf_program *p)
{
	const char *name = bpf_program__name(p);
	size_t prefix_len = strlen(SHIRUDO_SERIALIZER_PREFIX);

	if (!name || strncmp(name, SHIRUDO_SERIALIZER_PREFIX, prefix_len) != 0)
		return NULL;
	return name + prefix_len;
}

static bool object_has_map(struct bpf_object *obj, const char *want)
{
	struct bpf_map *m;

	bpf_object__for_each_map(m, obj) {
		const char *name = bpf_map__name(m);

		if (name && strcmp(name, want) == 0)
			return true;
	}
	return false;
}

static int validate_serializer_output_map(struct bpf_object *obj)
{
	struct bpf_map *m;

	bpf_object__for_each_map(m, obj) {
		const char *name = bpf_map__name(m);

		if (!name || strcmp(name, SHIRUDO_SERIAL_MAP_NAME) != 0)
			continue;
		if (bpf_map__type(m) != BPF_MAP_TYPE_ARRAY) {
			pr_err("%s must be BPF_MAP_TYPE_ARRAY",
			       SHIRUDO_SERIAL_MAP_NAME);
			return -EINVAL;
		}
		if (bpf_map__key_size(m) != sizeof(uint32_t)) {
			pr_err("%s must use a u32 key",
			       SHIRUDO_SERIAL_MAP_NAME);
			return -EINVAL;
		}
		if (bpf_map__value_size(m) !=
		    sizeof(struct shirudo_serial_chunk)) {
			pr_err("%s value must be struct shirudo_serial_chunk",
			       SHIRUDO_SERIAL_MAP_NAME);
			return -EINVAL;
		}
		if (bpf_map__max_entries(m) == 0 ||
		    bpf_map__max_entries(m) > SHIRUDO_SERIAL_MAX_CHUNKS) {
			pr_err("%s max_entries must be 1..%u",
			       SHIRUDO_SERIAL_MAP_NAME,
			       SHIRUDO_SERIAL_MAX_CHUNKS);
			return -EINVAL;
		}
		return 0;
	}
	pr_err("serializer upatch requires %s output map",
	       SHIRUDO_SERIAL_MAP_NAME);
	return -EINVAL;
}

static int build_prog_metadata(struct bpf_object *obj, uint32_t nr_progs,
			       void **out, uint32_t *out_len)
{
	struct shirudo_upatch_prog_metadata *md;
	char (*seen_maps)[SHIRUDO_UPATCH_PROG_MAP_MAX] = NULL;
	struct bpf_program *p;
	size_t len;
	uint32_t i = 0, n_seen = 0;
	bool has_serializer = false;
	int err;

	*out = NULL;
	*out_len = 0;
	bpf_object__for_each_program(p, obj) {
		if (serializer_map_name(p)) {
			has_serializer = true;
			break;
		}
	}
	if (has_serializer) {
		err = validate_serializer_output_map(obj);
		if (err)
			return err;
	}
	if (nr_progs >
	    (UINT32_MAX - sizeof(*md)) / sizeof(md->progs[0]))
		return -EOVERFLOW;
	len = sizeof(*md) + (size_t)nr_progs * sizeof(md->progs[0]);
	md = xmalloc(len);
	if (!md)
		return -ENOMEM;
	memset(md, 0, len);
	md->magic = htole32(SHIRUDO_UPATCH_PROG_MAGIC);
	md->version = htole32(SHIRUDO_UPATCH_PROG_VERSION);
	md->nr_progs = htole32(nr_progs);
	seen_maps = xcalloc(nr_progs, sizeof(*seen_maps));
	if (!seen_maps) {
		err = -ENOMEM;
		goto err_free;
	}

	bpf_object__for_each_program(p, obj) {
		const char *sec = bpf_program__section_name(p);
		const char *ser_map = serializer_map_name(p);
		const char *target = NULL;
		uint64_t offset = 0;
		uint32_t kind, j;

		if (ser_map) {
			size_t ser_len = strlen(ser_map);

			if (!is_syscall_section(sec)) {
				pr_err("serializer '%s' must use SEC(\"syscall\")",
				       bpf_program__name(p));
				err = -EINVAL;
				goto err_free;
			}
			if (ser_len == 0 ||
			    ser_len >= SHIRUDO_UPATCH_PROG_MAP_MAX) {
				pr_err("serializer '%s' has invalid target map '%s'",
				       bpf_program__name(p), ser_map);
				err = -EINVAL;
				goto err_free;
			}
			if (strcmp(ser_map, SHIRUDO_SERIAL_MAP_NAME) == 0) {
				pr_err("serializer cannot target reserved map %s",
				       SHIRUDO_SERIAL_MAP_NAME);
				err = -EINVAL;
				goto err_free;
			}
			if (!object_has_map(obj, ser_map)) {
				pr_err("serializer '%s' targets missing map '%s'",
				       bpf_program__name(p), ser_map);
				err = -EINVAL;
				goto err_free;
			}
			for (j = 0; j < n_seen; j++) {
				if (strcmp(seen_maps[j], ser_map) == 0) {
					pr_err("duplicate serializer for map '%s'",
					       ser_map);
					err = -EINVAL;
					goto err_free;
				}
			}
			snprintf(seen_maps[n_seen++], sizeof(seen_maps[0]),
				 "%s", ser_map);
			md->progs[i].role =
				htole32(SHIRUDO_UPATCH_PROG_ROLE_SERIALIZER);
			snprintf(md->progs[i].map, sizeof(md->progs[i].map),
				 "%s", ser_map);
			i++;
			continue;
		}
		if (is_syscall_section(sec)) {
			pr_err("SEC(\"syscall\") program '%s' must be named %s<map>",
			       bpf_program__name(p), SHIRUDO_SERIALIZER_PREFIX);
			err = -EINVAL;
			goto err_free;
		}
		if (unsupported_kprobe_section(sec)) {
			pr_err("unsupported kprobe section '%s'; use kprobe/<symbol> or kretprobe/<symbol>",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		if (unsupported_sk_skb_section(sec)) {
			pr_err("unsupported sk_skb section '%s'; supported network packet sections are cgroup_skb/ingress, cgroup_skb/egress, and netfilter",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		if (unsupported_socket_filter_section(sec)) {
			pr_err("unsupported socket filter section '%s'; Shirudo upatches require a pinnable bpf_link lifecycle",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		if (unsupported_cgroup_skb_section(sec)) {
			pr_err("unsupported cgroup_skb section '%s'; use cgroup_skb/ingress or cgroup_skb/egress",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		if (unsupported_fmod_ret_section(sec)) {
			pr_err("unsupported fmod_ret section '%s'; use fmod_ret/<symbol> or fmod_ret.s/<symbol>",
			       sec);
			err = -EOPNOTSUPP;
			goto err_free;
		}
		kind = attach_kind_from_section(sec, &target);
		md->progs[i].role =
			htole32(SHIRUDO_UPATCH_PROG_ROLE_ATTACH);
		md->progs[i].kind = htole32(kind);
		if (target) {
			err = split_probe_target(target, md->progs[i].target,
						 sizeof(md->progs[i].target),
						 &offset);
			if (err) {
				pr_err("invalid kprobe target in section '%s'",
				       sec);
				goto err_free;
			}
			if (kind == SHIRUDO_UPATCH_ATTACH_KRETPROBE && offset) {
				pr_err("kretprobe offsets are unsupported in section '%s'",
				       sec);
				err = -EINVAL;
				goto err_free;
			}
		}
		md->progs[i].offset = htole64(offset);
		i++;
	}

	*out = md;
	*out_len = (uint32_t)len;
	xfree(seen_maps, (size_t)nr_progs * sizeof(*seen_maps));
	return 0;

err_free:
	xfree(seen_maps, (size_t)nr_progs * sizeof(*seen_maps));
	xfree(md, len);
	return err;
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
	void *attach_meta = NULL;
	const void *write_meta = meta;
	uint32_t write_meta_len = meta_len, attach_meta_len = 0;
	char *src_buf = NULL;
	int fd = -1;
	int err = 0;
	uint32_t loader_off, sig_off;
	uint32_t nr_maps = 0, nr_progs = 0;
	uint32_t src_len = 0, name_len = 0;

	/*
	 * The loader writes map_fd/prog_fd back into descriptor arrays
	 * trailing its ctx, in the same order libbpf iterates the
	 * object. The target needs these counts to locate prog_fd[]
	 * after BPF_PROG_TEST_RUN -- it has only the .upatch, not the
	 * object. Iteration order here matches gen_loader's. Build
	 * attach metadata before loader generation so unsupported section
	 * names fail with Shirudo's own diagnostics instead of depending
	 * on host kernel load behavior.
	 */
	bpf_object__for_each_map(m, obj)
		nr_maps++;
	bpf_object__for_each_program(p, obj)
		nr_progs++;

	if (!(flags & SHIRUDO_DIRECTIVE_UNLOAD)) {
		err = build_prog_metadata(obj, nr_progs,
					  &attach_meta, &attach_meta_len);
		if (err)
			goto out;
		write_meta = attach_meta;
		write_meta_len = attach_meta_len;
	}

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

	sig_buf = xmalloc(SHIRUDO_MAX_SIG_SIZE);
	if (!sig_buf) {
		err = -ENOMEM;
		goto out;
	}
	sio.insns        = opts.insns;
	sio.insns_sz     = opts.insns_sz;
	sio.data         = opts.data;
	sio.data_sz      = opts.data_sz;
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
	uint32_t extra_off = src_buf ? meta_off + write_meta_len : 0;
	struct shirudo_upatch_extras ex = {};

	ex.magic      = htole32(SHIRUDO_UPATCH_EXTRAS_MAGIC);
	ex.format     = htole32(SHIRUDO_UPATCH_EXTRAS_SOURCE);
	ex.name_len   = htole32(name_len);
	ex.source_len = htole32(src_len);

	pack_header(&hdr, upatch_name, flags,
		    sio.payload_sha256,
		    loader_off, opts.insns_sz,
		    sig_off, (uint32_t)sio.signature_sz,
		    write_meta_len ? meta_off : 0, write_meta_len,
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
	if (!err && write_meta_len)
		err = write_all(fd, write_meta, write_meta_len);
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

	pr_info("wrote %s (insns=%u sig=%zu data=%u meta=%u maps=%u progs=%u source=%u name=%s%s)",
		out_path, opts.insns_sz, sio.signature_sz, data_len,
		write_meta_len, nr_maps, nr_progs, src_len, upatch_name,
		(flags & SHIRUDO_DIRECTIVE_UNLOAD) ? " UNLOAD" : "");
out:
	if (fd >= 0)
		close(fd);
	xfree(src_buf, src_len);
	xfree(sig_buf, SHIRUDO_MAX_SIG_SIZE);
	bpf_object__close(obj);
	xfree(attach_meta, attach_meta_len);
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
