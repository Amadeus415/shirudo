// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo upatch {info,load,unload,list} -- subcommand router.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/keyctl.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "builtin.h"
#include "util/chain.h"
#include "util/config.h"
#include "util/eventlog.h"
#include "util/help.h"
#include "util/json.h"
#include "util/macros.h"
#include "util/keyring.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/report.h"
#include "util/seal.h"
#include "util/upatch.h"
#include "util/upatch_maps.h"

extern const char shirudo_version_id[];

static bool safe_upatch_name(const char *name);

/* Print embedded C source with line numbers (slices, not NUL-terminated). */
static void dump_source(const char *name, uint32_t name_len,
			const char *src, uint32_t src_len)
{
	uint32_t i = 0, ln = 1, start;

	printf("Source (%.*s):\n", (int)name_len, name);
	while (i < src_len) {
		start = i;
		while (i < src_len && src[i] != '\n')
			i++;
		printf("  %4u  %.*s\n", ln, (int)(i - start), src + start);
		if (i < src_len)
			i++;		/* consume the newline */
		ln++;
	}
}

/* Fill one failure into a report (NULL report = no-op). */
static void rep_fail(struct shirudo_op_report *rep, const char *phase,
		     const char *cat, int err, const char *msg)
{
	if (!rep)
		return;
	rep->ok = false;
	rep->phase = phase;
	rep->category = cat;
	rep->err = err < 0 ? -err : err;
	if (msg)
		snprintf(rep->message, sizeof(rep->message), "%s", msg);
}

/* Map a BPF_PROG_LOAD errno (positive) to a report category. */
static const char *cat_from_load_errno(int e)
{
	switch (e) {
	case EKEYREJECTED:	return "signature_rejected";
	case ENOKEY:		return "keyring_missing";
	case EACCES:
	case EPERM:		return "lsm_denied";
	default:		return "verifier_rejected";
	}
}

static const char *flag_str(const struct shirudo_upatch *u)
{
	return shirudo_upatch_is_unload(u) ? "UNLOAD-directive" : "LOAD";
}

static int print_sha256_hex(const unsigned char hash[32])
{
	for (int i = 0; i < 32; i++)
		if (printf("%02x", hash[i]) < 0)
			return -1;
	return 0;
}

static const struct shirudo_help upatch_info_help = {
	.usage   = "shirudo upatch info [--json] <file.upatch>",
	.summary = "Describe a .upatch file: header, signature, payload "
		   "digest,\nand (if the build embedded it) the full C "
		   "source. Offline -- no\nkernel state read, runs on any "
		   "host. For source as actually loaded\n(authoritative, "
		   "via kernel BTF line_info) use `shirudo upatch get`.",
	.footer  =
"Examples:\n"
"  shirudo upatch info cve-2026-31431.upatch\n"
"  shirudo upatch info --json /var/lib/shirudo/upatches/foo.upatch",
};

static const struct shirudo_help upatch_list_help = {
	.usage   = "shirudo upatch list [--json]",
	.summary = "List upatches on this host. Shows the persisted set\n"
		   "(under /var/lib/shirudo/upatches/, survives reboot) "
		   "alongside the\nbpffs-pinned active set (loaded now). "
		   "Drift in either direction\n(persisted-but-not-loaded "
		   "or loaded-but-not-persisted) is flagged.",
	.footer  =
"Examples:\n"
"  shirudo upatch list\n"
"  shirudo upatch list --json | jq",
};

static const struct shirudo_help upatch_load_help = {
	.usage   = "shirudo upatch load [--expect-chain=<hex>] "
		   "[--expect-version-id=<hex>]\n"
		   "                       [--no-precheck] [--no-version-check] "
		   "[--report=<path>]\n"
		   "                       <file.upatch>",
	.summary = "Load a signed LOAD .upatch into the target kernel: verify "
		   "the\nsignature, run the loader, pin the resulting link, "
		   "and extend the\nTPM NV chain. Target-only.",
	.footer  =
"Examples:\n"
"  shirudo upatch load cve-2026-31431.upatch\n"
"  shirudo upatch load --expect-chain=$(...) foo.upatch\n"
"  shirudo upatch load --report=- foo.upatch | jq",
};

static const struct shirudo_help upatch_unload_help = {
	.usage   = "shirudo upatch unload [--expect-chain=<hex>] "
		   "[--expect-version-id=<hex>]\n"
		   "                       [--no-precheck] [--no-version-check] "
		   "[--report=<path>]\n"
		   "                       <unload-directive.upatch>",
	.summary = "Apply a signed UNLOAD directive: detach the named upatch,\n"
		   "remove its pin, and extend the TPM NV chain forward "
		   "(unloads\nmove the chain forward, never roll it back). "
		   "Target-only.",
	.footer  =
"Examples:\n"
"  shirudo upatch unload cve-2026-31431.unload.upatch\n"
"  shirudo upatch unload --report=- foo.unload.upatch | jq",
};

static const struct shirudo_help_item upatch_map_options[] = {
	{ "--json",       "machine-readable JSON output" },
	{ "--show-full",  "lift the per-map 256-entry truncation cap" },
};

static const struct shirudo_help_section upatch_map_sections[] = {
	{ "options:", upatch_map_options, ARRAY_SIZE(upatch_map_options) },
};

static const struct shirudo_help upatch_map_help = {
	.usage      = "shirudo upatch map [<upatch>] [<map>] [--json] [--show-full]",
	.summary    = "Read the contents of a pinned upatch map from the\n"
		      "target kernel. With no positional args, list every "
		      "pinned\nmap across every loaded upatch. With "
		      "<upatch>, list maps\nfor that upatch only. With "
		      "<upatch> <map>, dump the map's\ncontents -- BTF "
		      "type-aware where the build embedded `-g`.\n"
		      "Read-only; uses only LSM-allowed bpf() commands.",
	.sections   = upatch_map_sections,
	.n_sections = ARRAY_SIZE(upatch_map_sections),
	.footer     =
"Examples:\n"
"  shirudo upatch map\n"
"  shirudo upatch map cve-2026-31431-counter\n"
"  shirudo upatch map cve-2026-31431-counter blocked_af_alg\n"
"  shirudo upatch map cve-2026-31431-counter blocked_af_alg --json | jq\n"
"  shirudo upatch map cve-2026-31431-counter big_hash --show-full",
};

static const struct shirudo_help upatch_get_help = {
	.usage   = "shirudo upatch get <name>",
	.summary = "Dump source of a loaded upatch from the target kernel,\n"
		   "via the BPF prog's BTF line_info installed by the signed "
		   "loader.\nAuthoritative (reads what is actually loaded), "
		   "but shows only the\nsparse instruction-tagged lines "
		   "`clang -g` recorded -- not the\nfull .c. For the build-"
		   "time-embedded full source see\n`shirudo upatch info`.",
	.footer  =
"Examples:\n"
"  shirudo upatch get cve-2026-31431",
};

static int cmd_upatch_info(int argc, const char **argv)
{
	char name[SHIRUDO_UPATCH_NAME_MAX + 1];	/* not NUL-term on disk */
	struct shirudo_upatch u;
	const char *path = NULL;
	bool json = false;
	int i, rc, ret = 1;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--json") == 0)
			json = true;
		else if (shirudo_is_help(argv[i])) {
			shirudo_print_help(&upatch_info_help);
			return 0;
		} else if (argv[i][0] == '-') {
			fprintf(stderr, "upatch info: unknown option '%s'\n",
				argv[i]);
			return 2;
		} else if (!path) {
			path = argv[i];
		} else {
			fprintf(stderr, "upatch info: unexpected argument '%s'\n",
				argv[i]);
			return 2;
		}
	}
	if (!path) {
		shirudo_print_help(&upatch_info_help);
		return 2;
	}

	rc = shirudo_upatch_open(path, &u);
	if (rc != 0) {
		pr_err("upatch info: %s: %s", path, strerror(-rc));
		return 1;
	}

	memcpy(name, u.hdr.name, sizeof(u.hdr.name));
	name[SHIRUDO_UPATCH_NAME_MAX] = '\0';

	if (json) {
		size_t cap = 8192 + (size_t)u.source_len * 6 + u.source_name_len;
		struct shirudo_json_emit e = {};
		char payload_hex[2 * 32 + 1];
		char *sname = NULL, *stext = NULL;
		char *buf = xmalloc(cap);

		if (!buf)
			goto out;
		if (shirudo_upatch_has_source(&u)) {
			sname = xstrndup(u.source_name, u.source_name_len);
			stext = xstrndup(u.source, u.source_len);
		}
		e.buf = buf;
		e.cap = cap;
		shirudo_hex_encode(u.hdr.payload_sha256, 32, payload_hex);
		shirudo_json_obj_open(&e);
		shirudo_json_kv_int(&e, "schema", 1);
		shirudo_json_kv_string(&e, "path", path);
		shirudo_json_kv_string(&e, "name", name);
		shirudo_json_kv_string(&e, "type",
				       shirudo_upatch_is_unload(&u) ? "unload"
								    : "load");
		shirudo_json_kv_int(&e, "version", u.hdr.version);
		shirudo_json_kv_string(&e, "payload_sha256", payload_hex);
		shirudo_json_kv_int(&e, "loader_insns_len",
				    u.hdr.loader_insns_len);
		shirudo_json_kv_int(&e, "signature_len", u.hdr.signature_len);
		shirudo_json_kv_int(&e, "metadata_len", u.hdr.metadata_len);
		shirudo_json_kv_int(&e, "data_len", u.hdr.data_len);
		shirudo_json_kv_int(&e, "log_buf_sz", u.hdr.log_buf_sz);
		shirudo_json_kv_int(&e, "file_size", (int64_t)u.map_size);
		shirudo_json_kv_bool(&e, "has_source",
				     shirudo_upatch_has_source(&u));
		shirudo_json_kv_string(&e, "source_file", sname ? sname : "");
		shirudo_json_kv_string(&e, "source", stext ? stext : "");
		shirudo_json_obj_close(&e);
		if (e.err)
			fprintf(stderr, "upatch info: json encode failed: %s\n",
				strerror(-e.err));
		else
			printf("%s\n", buf);
		xstrfree(sname);
		xstrfree(stext);
		xfree(buf, cap);
		ret = e.err ? 1 : 0;
		goto out;
	}

	printf("File:                  %s\n", path);
	printf("Name:                  %s\n", name);
	printf("Type:                  %s\n", flag_str(&u));
	printf("Version:               %u\n", u.hdr.version);
	printf("Payload SHA256:        ");
	print_sha256_hex(u.hdr.payload_sha256);
	printf("\n");
	printf("File size:             %zu bytes\n", u.map_size);

	printf("\nLoader:\n");
	printf("  %-22s off=%u len=%u\n", "Instructions:",
	       u.hdr.loader_insns_off, u.hdr.loader_insns_len);
	printf("  %-22s %u\n", "Log buffer size:", u.hdr.log_buf_sz);
	if (u.hdr.metadata_len)
		printf("  %-22s off=%u len=%u\n", "Metadata:",
		       u.hdr.metadata_off, u.hdr.metadata_len);
	else
		printf("  %-22s (none)\n", "Metadata:");
	if (u.hdr.data_len)
		printf("  %-22s off=%u len=%u\n", "Data:",
		       u.hdr.data_off, u.hdr.data_len);
	else
		printf("  %-22s (none)\n", "Data:");

	printf("\nSignature:\n");
	printf("  %-22s %u\n", "Offset:", u.hdr.signature_off);
	printf("  %-22s %u bytes\n", "Length:", u.hdr.signature_len);

	printf("\n");
	if (shirudo_upatch_has_source(&u))
		dump_source(u.source_name, u.source_name_len,
			    u.source, u.source_len);
	else
		printf("Source:                (none -- built from a .bpf.o, "
		       "or older format)\n");
	ret = 0;
out:
	shirudo_upatch_close(&u);
	return ret;
}

static int is_upatch_file(const struct dirent *e)
{
	size_t len = strlen(e->d_name);

	return len > 7 && strcmp(e->d_name + len - 7, ".upatch") == 0;
}

/* Loaded == its bpffs link pin is present. */
static bool upatch_is_loaded(const char *name)
{
	char pin[1024];
	struct stat st;

	if ((size_t)snprintf(pin, sizeof(pin), "%s/%s/link",
			     SHIRUDO_BPFFS_UPATCHES_DIR, name) >= sizeof(pin))
		return false;
	return stat(pin, &st) == 0;
}

/*
 * Cross-reference the persisted archive (/var/lib/shirudo/upatches/
 * *.upatch -- what survives reboot) against the live bpffs pins (what is
 * currently loaded). Drift in either direction is the point: a persisted
 * upatch that is not loaded, or a loaded one with no persisted .upatch
 * (an orphan that will not survive reboot), both show up here.
 */
static int cmd_upatch_list(int argc, const char **argv)
{
	struct dirent **persisted = NULL, **active = NULL;
	struct shirudo_json_emit e = { .buf = NULL };
	int np, na, i, j, rc = 0;
	bool json = false;
	char *jbuf = NULL;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--json") == 0)
			json = true;
		else if (shirudo_is_help(argv[i])) {
			shirudo_print_help(&upatch_list_help);
			return 0;
		} else {
			fprintf(stderr, "upatch list: unknown option '%s'\n",
				argv[i]);
			return 2;
		}
	}

	np = scandir(SHIRUDO_UPATCHES_DIR, &persisted, is_upatch_file,
		     alphasort);
	if (np < 0)
		np = 0;
	na = scandir(SHIRUDO_BPFFS_UPATCHES_DIR, &active, NULL, alphasort);
	if (na < 0)
		na = 0;

	if (json) {
		jbuf = xmalloc(65536);
		if (!jbuf) {
			rc = 1;
			goto out;
		}
		e.buf = jbuf;
		e.cap = 65536;
		shirudo_json_obj_open(&e);
		shirudo_json_kv_int(&e, "schema", 1);
		shirudo_json_arr_open(&e, "upatches");
	} else {
		printf("upatches (%s):\n", SHIRUDO_UPATCHES_DIR);
		if (np == 0)
			printf("  (none persisted)\n");
		else
			printf("  %-6s  %-6s  %-18s  %s\n",
			       "loaded", "type", "payload-sha256", "name");
	}

	for (i = 0; i < np; i++) {
		char path[1024], name[SHIRUDO_UPATCH_NAME_MAX + 1];
		char payload_hex[2 * 32 + 1];
		struct shirudo_upatch u;
		const char *type;
		bool loaded;

		if ((size_t)snprintf(path, sizeof(path), "%s/%s",
				     SHIRUDO_UPATCHES_DIR,
				     persisted[i]->d_name) >= sizeof(path))
			continue;
		if (shirudo_upatch_open(path, &u) != 0) {
			if (!json)
				printf("  %-6s  %-6s  %-18s  %s\n", "?", "?",
				       "(unreadable)", persisted[i]->d_name);
			continue;
		}
		memcpy(name, u.hdr.name, sizeof(u.hdr.name));
		name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
		shirudo_hex_encode(u.hdr.payload_sha256, 32, payload_hex);
		type = shirudo_upatch_is_unload(&u) ? "unload" : "load";
		loaded = upatch_is_loaded(name);
		shirudo_upatch_close(&u);

		if (json) {
			shirudo_json_obj_open(&e);
			shirudo_json_kv_string(&e, "name", name);
			shirudo_json_kv_string(&e, "type", type);
			shirudo_json_kv_bool(&e, "loaded", loaded);
			shirudo_json_kv_bool(&e, "persisted", 1);
			shirudo_json_kv_string(&e, "payload_sha256", payload_hex);
			shirudo_json_obj_close(&e);
		} else {
			char shown[19];

			memcpy(shown, payload_hex, 16);
			memcpy(shown + 16, "..", 3);
			printf("  %-6s  %-6s  %-18s  %s\n",
			       loaded ? "yes" : "no", type, shown, name);
		}
	}

	/* Orphans: a live pin with no persisted .upatch behind it. */
	for (i = 0; i < na; i++) {
		char persist[1024];
		const char *nm = active[i]->d_name;
		struct stat st;

		if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0)
			continue;
		if ((size_t)snprintf(persist, sizeof(persist), "%s/%s.upatch",
				     SHIRUDO_UPATCHES_DIR, nm) >= sizeof(persist))
			continue;
		if (stat(persist, &st) == 0)
			continue;	/* persisted -- already listed above */

		if (json) {
			shirudo_json_obj_open(&e);
			shirudo_json_kv_string(&e, "name", nm);
			shirudo_json_kv_null(&e, "type");
			shirudo_json_kv_bool(&e, "loaded", 1);
			shirudo_json_kv_bool(&e, "persisted", 0);
			shirudo_json_kv_null(&e, "payload_sha256");
			shirudo_json_obj_close(&e);
		} else {
			printf("  %-6s  %-6s  %-18s  %s  (orphan: no persisted "
			       ".upatch, will not survive reboot)\n",
			       "yes", "?", "-", nm);
		}
	}

	if (json) {
		shirudo_json_arr_close(&e);
		shirudo_json_obj_close(&e);
		if (e.err) {
			fprintf(stderr, "upatch list: json encode failed: %s\n",
				strerror(-e.err));
			rc = 1;
		} else {
			printf("%s\n", jbuf);
		}
	}

out:
	for (i = 0; i < np; i++)
		shirudo_libc_free(persisted[i]);	/* scandir-owned */
	shirudo_libc_free(persisted);			/* scandir-owned */
	for (j = 0; j < na; j++)
		shirudo_libc_free(active[j]);		/* scandir-owned */
	shirudo_libc_free(active);			/* scandir-owned */
	if (jbuf)
		xfree(jbuf, 65536);
	return rc;
}

/*
 * The signed-loader path needs a __loader.map populated and frozen
 * before BPF_PROG_LOAD, with the FD passed via attr.fd_array and a
 * bpf_loader_ctx via attr.test.ctx_in. Mirrors upstream
 * tools/lib/bpf/skel_internal.h:bpf_load_and_run(). libbpf's
 * bpf_prog_load_opts wrapper doesn't yet expose
 * signature/signature_size/keyring_id, so the BPF_PROG_LOAD attr
 * is built by hand.
 */

struct shirudo_loader_ctx {
	uint32_t	sz;
	uint32_t	flags;
	uint32_t	log_level;
	uint32_t	log_size;
	uint64_t	log_buf;
};

/*
 * Descriptor arrays trailing the loader ctx. Layout must match
 * tools/lib/bpf/skel_internal.h: the loader writes map_fd/prog_fd
 * here, and BPF_PROG_TEST_RUN copies the ctx back to userspace.
 */
struct shirudo_map_desc {
	int		map_fd;
	uint32_t	max_entries;
	uint64_t	initial_value;
};

struct shirudo_prog_desc {
	int		prog_fd;
};

static int loader_map_create(const char *name, uint32_t value_size,
			     const void *excl_prog_hash,
			     uint32_t excl_prog_hash_sz)
{
	union bpf_attr attr = {};
	long fd;

	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = 4;
	attr.value_size = value_size ? value_size : 4;
	attr.max_entries = 1;
	attr.excl_prog_hash = (uint64_t)(uintptr_t)excl_prog_hash;
	attr.excl_prog_hash_size = excl_prog_hash_sz;
	memcpy(attr.map_name, name, strnlen(name, sizeof(attr.map_name)));

	fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	return (int)fd;
}

static int loader_map_update(int map_fd, const void *value, uint32_t value_sz)
{
	union bpf_attr attr = {};
	uint8_t zero[4] = {};
	uint32_t key = 0;
	long ret;

	attr.map_fd = map_fd;
	attr.key = (uint64_t)(uintptr_t)&key;
	attr.value = (uint64_t)(uintptr_t)(value_sz ? value : zero);
	attr.flags = 0;
	ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
	return (int)ret;
}

static int loader_map_freeze(int map_fd)
{
	union bpf_attr attr = {};
	long ret;

	attr.map_fd = map_fd;
	ret = syscall(__NR_bpf, BPF_MAP_FREEZE, &attr, sizeof(attr));
	return (int)ret;
}

/*
 * The kernel's "exclusive map" signing flow has two SHA-256s on the
 * map: excl_prog_sha (set at MAP_CREATE, checked at PROG_LOAD against
 * the loader prog's own digest), and bpf_map->sha (computed lazily by
 * BPF_OBJ_GET_INFO_BY_FD with info.hash set, read at runtime by the
 * gen_loader's emit_signature_match guard). Without this call,
 * bpf_map->sha stays zero, the runtime comparison fails, and the
 * loader exits -EINVAL. See KP Singh's "libbpf: Update light skeleton
 * for signing" (fb2b0e290147) and skel_internal.h:skel_obj_get_info_by_fd.
 */
static int loader_map_seal_hash(int map_fd)
{
	struct bpf_map_info info = {};
	union bpf_attr attr = {};
	uint8_t sha[32];
	long ret;

	info.hash = (uint64_t)(uintptr_t)sha;
	info.hash_size = sizeof(sha);

	attr.info.bpf_fd = (uint32_t)map_fd;
	attr.info.info = (uint64_t)(uintptr_t)&info;
	attr.info.info_len = sizeof(info);
	ret = syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
	return (int)ret;
}

static int prog_load_signed(const struct bpf_insn *insns, size_t insn_cnt,
			    const char *prog_name,
			    const void *signature, uint32_t signature_sz,
			    int32_t keyring_id, int loader_map_fd,
			    char *log_buf, size_t log_sz)
{
	union bpf_attr attr = {};
	int fd_array[1] = { loader_map_fd };
	long fd;

	attr.prog_type = BPF_PROG_TYPE_SYSCALL;
	attr.insn_cnt = (uint32_t)insn_cnt;
	attr.insns = (uint64_t)(uintptr_t)insns;
	attr.license = (uint64_t)(uintptr_t)"Dual BSD/GPL";
	attr.prog_flags = BPF_F_SLEEPABLE;
	attr.log_level = log_buf ? 1 : 0;
	attr.log_size = (uint32_t)log_sz;
	attr.log_buf = (uint64_t)(uintptr_t)log_buf;
	attr.signature = (uint64_t)(uintptr_t)signature;
	attr.signature_size = signature_sz;
	attr.keyring_id = keyring_id;
	attr.fd_array = (uint64_t)(uintptr_t)fd_array;
	memcpy(attr.prog_name, prog_name,
	       strnlen(prog_name, sizeof(attr.prog_name)));


	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	return (int)fd;
}

static int prog_test_run_ctx(int prog_fd, void *ctx, uint32_t ctx_sz,
			     uint32_t *retval)
{
	union bpf_attr attr = {};
	long ret;

	attr.test.prog_fd = prog_fd;
	attr.test.ctx_in = (uint64_t)(uintptr_t)ctx;
	attr.test.ctx_size_in = ctx_sz;
	ret = syscall(__NR_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
	if (ret < 0)
		return (int)ret;
	*retval = attr.test.retval;
	return 0;
}

/*
 * Attach a loaded LSM/tracing prog by opening a raw-tracepoint link
 * with a NULL name -- the kernel uses the prog's baked-in
 * attach_btf_id. Same mechanism the light skeleton emits for
 * BPF_PROG_TYPE_LSM (bpftool gen.c:codegen_attach_detach). The gen
 * loader resolves attach_btf_id at load time, so the link target is
 * fixed by the signed program, not chosen here. Returns a link fd.
 */
static int prog_attach_raw_tp(int prog_fd)
{
	union bpf_attr attr = {};
	long fd;

	attr.raw_tracepoint.name = 0;
	attr.raw_tracepoint.prog_fd = (uint32_t)prog_fd;
	fd = syscall(__NR_bpf, BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
	return (int)fd;
}

static int obj_pin(int fd, const char *path)
{
	union bpf_attr attr = {};
	long ret;

	attr.pathname = (uint64_t)(uintptr_t)path;
	attr.bpf_fd = (uint32_t)fd;
	ret = syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
	return (int)ret;
}

static int mkdir_if_absent(const char *path, mode_t mode)
{
	if (mkdir(path, mode) == 0 || errno == EEXIST)
		return 0;
	return -errno;
}

/*
 * Attach each inner program (raw-tp link with NULL name, so the
 * kernel uses the prog's baked-in attach_btf_id) and pin the link
 * under the private bpffs. Without a pinned link the program detaches
 * the instant this one-shot CLI exits. A single-program upatch pins
 * as ".../upatches/<name>/link"; multiple programs get "link_<i>".
 */
static int attach_and_pin_progs(const struct shirudo_loader_ctx *cx,
				size_t prog_desc_off, uint32_t nr_progs,
				const char *name)
{
	char dir[PATH_MAX], pin[PATH_MAX + 32];
	uint32_t i;
	int rc;

	if (nr_progs == 0) {
		pr_warn("upatch carries no programs to attach");
		return 0;
	}

	rc = mkdir_if_absent(SHIRUDO_BPFFS_UPATCHES_DIR, 0700);
	if (rc) {
		pr_err("mkdir %s: %s", SHIRUDO_BPFFS_UPATCHES_DIR,
		       strerror(-rc));
		return rc;
	}
	if (snprintf(dir, sizeof(dir), "%s/%s",
		     SHIRUDO_BPFFS_UPATCHES_DIR, name) >= (int)sizeof(dir))
		return -ENAMETOOLONG;
	rc = mkdir_if_absent(dir, 0700);
	if (rc) {
		pr_err("mkdir %s: %s", dir, strerror(-rc));
		return rc;
	}

	for (i = 0; i < nr_progs; i++) {
		const struct shirudo_prog_desc *pd =
			(const void *)((const char *)cx + prog_desc_off +
				       (size_t)i * sizeof(*pd));
		int inner_fd = pd->prog_fd;
		int link_fd;

		if (inner_fd <= 0) {
			pr_err("loader produced no fd for prog %u", i);
			return -EINVAL;
		}
		if (nr_progs == 1)
			snprintf(pin, sizeof(pin), "%s/link", dir);
		else
			snprintf(pin, sizeof(pin), "%s/link_%u", dir, i);

		link_fd = prog_attach_raw_tp(inner_fd);
		if (link_fd < 0) {
			pr_err("attach prog %u: %s", i, strerror(errno));
			return -errno;
		}
		rc = obj_pin(link_fd, pin);
		if (rc) {
			pr_err("pin %s: %s", pin, strerror(errno));
			close(link_fd);
			return -errno;
		}
		close(link_fd);
		pr_info("attached + pinned prog %u -> %s", i, pin);
	}
	return 0;
}

/*
 * For each map the signed loader created (cx->map_descs[].map_fd is
 * populated by gen_loader's MAP_CREATE-from-kernel-context, see
 * skel_internal.h), pin it under <upatches>/<name>/maps/<map_name>.
 * The maps/ dir is created on first hit (mode 0700, under the same
 * seal-LSM coverage as the link pin). Best-effort: a failure to pin
 * one map is logged and skipped -- the upatch already loaded ok, so
 * we want the rest of the loading to succeed, and the unpinned map
 * just isn't observable via `shirudo upatch map` until next load.
 *
 * Skips:
 *  - map_fd <= 0 (loader produced no fd, nothing to pin)
 *  - empty name (kernel will reject the BPF_OBJ_PIN anyway)
 *  - already-pinned maps_dir/name (idempotent on re-runs)
 */
static int pin_upatch_maps(const struct shirudo_loader_ctx *cx,
			   uint32_t nr_maps, const char *name)
{
	char dir[PATH_MAX], maps_dir[PATH_MAX + 8];
	char pin[PATH_MAX + 32];
	uint32_t i;
	int rc;

	if (nr_maps == 0)
		return 0;
	if (snprintf(dir, sizeof(dir), "%s/%s",
		     SHIRUDO_BPFFS_UPATCHES_DIR, name) >= (int)sizeof(dir))
		return -ENAMETOOLONG;
	if (snprintf(maps_dir, sizeof(maps_dir), "%s/maps", dir) >=
	    (int)sizeof(maps_dir))
		return -ENAMETOOLONG;
	rc = mkdir_if_absent(maps_dir, 0700);
	if (rc) {
		pr_warn("upatch maps: mkdir %s: %s (continuing without "
			"map pins)", maps_dir, strerror(-rc));
		return 0;
	}
	for (i = 0; i < nr_maps; i++) {
		const struct shirudo_map_desc *md =
			(const void *)((const char *)cx +
				       sizeof(struct shirudo_loader_ctx) +
				       (size_t)i * sizeof(*md));
		struct bpf_map_info info = {};
		uint32_t info_len = sizeof(info);
		struct stat st;
		int err;

		if (md->map_fd <= 0)
			continue;
		err = bpf_map_get_info_by_fd(md->map_fd, &info, &info_len);
		if (err) {
			pr_warn("upatch maps: get_info(map %u): %s",
				i, strerror(errno));
			continue;
		}
		if (info.name[0] == '\0')
			continue;
		if (snprintf(pin, sizeof(pin), "%s/%s", maps_dir,
			     info.name) >= (int)sizeof(pin))
			continue;
		if (stat(pin, &st) == 0)
			continue;	/* already pinned (idempotent) */
		if (obj_pin(md->map_fd, pin) != 0) {
			pr_warn("upatch maps: pin %s: %s", pin,
				strerror(errno));
			continue;
		}
		pr_info("pinned map %u (%s, type=%u) -> %s",
			i, info.name, (unsigned)info.type, pin);
	}
	return 0;
}

/*
 * Record the loaded upatch's payload_sha256 as an xattr on its pin
 * directory. `upatch unload` reads it back to confirm what is actually
 * loaded under <name> matches the directive's signed expectation; the
 * bpf2 inode_setxattr guard restricts this write to shirudo, so a root
 * attacker cannot forge it. Best-effort: the load already succeeded, so
 * a setxattr failure (e.g. -EOPNOTSUPP on a kernel without the
 * bpffs-xattr patch, TODO.kernel item 7) only disables the unload
 * payload_mismatch check for this upatch -- it is logged, not fatal.
 */
static void set_pin_payload(const char *name, const uint8_t payload[32])
{
	char dir[PATH_MAX];

	if (snprintf(dir, sizeof(dir), "%s/%s", SHIRUDO_BPFFS_UPATCHES_DIR,
		     name) >= (int)sizeof(dir))
		return;
	if (setxattr(dir, SHIRUDO_XATTR_PAYLOAD, payload, 32, 0) != 0)
		pr_warn("upatch: cannot record payload xattr on %s: %s "
			"(payload_mismatch check unavailable for this upatch)",
			dir, strerror(errno));
}

/*
 * Read the payload_sha256 recorded on <name>'s pin directory. Returns 0
 * and fills out on success, -ENOENT if the pin dir is gone, -ENODATA if
 * the xattr is absent, or another -errno (notably -EOPNOTSUPP on a
 * kernel without the bpffs-xattr patch).
 */
static int get_pin_payload(const char *name, uint8_t out[32])
{
	char dir[PATH_MAX];
	ssize_t n;

	if (snprintf(dir, sizeof(dir), "%s/%s", SHIRUDO_BPFFS_UPATCHES_DIR,
		     name) >= (int)sizeof(dir))
		return -ENAMETOOLONG;
	n = getxattr(dir, SHIRUDO_XATTR_PAYLOAD, out, 32);
	if (n < 0)
		return -errno;
	if (n != 32)
		return -EINVAL;
	return 0;
}

/*
 * Load, attach, and pin one signed LOAD upatch. Shared by the
 * operator-facing `shirudo upatch load` and by `shirudo init`
 * boot-restore, so both go through the identical signature-verified
 * path. Returns 0 on success, non-zero on failure.
 */
static int upatch_apply(const char *path, bool verify_only,
			struct shirudo_op_report *rep)
{
	struct shirudo_upatch u;
	const struct bpf_insn *insns;
	const void *sig, *data;
	key_serial_t keyring;
	char prog_name[BPF_OBJ_NAME_LEN];
	char upatch_name[SHIRUDO_UPATCH_NAME_MAX + 1];
	char *vlog;			/* shared PROG_LOAD / TEST_RUN log_buf */
	size_t insn_cnt, ctx_sz = 0, prog_desc_off;
	int prog_fd = -1, map_fd = -1, rc;
	struct shirudo_loader_ctx *cx = NULL;
	uint32_t retval = 0;

	vlog = xmalloc(SHIRUDO_VERIFIER_LOG_MAX);
	if (!vlog) {
		rep_fail(rep, "parse", "unknown", ENOMEM, "out of memory");
		return 1;
	}
	vlog[0] = '\0';

	rc = shirudo_upatch_open(path, &u);
	if (rc) {
		pr_err("open %s: %s", path, strerror(-rc));
		rep_fail(rep, "parse", "parser_rejected", -rc,
			 "cannot open .upatch");
		xfree(vlog, SHIRUDO_VERIFIER_LOG_MAX);
		return 1;
	}
	/*
	 * verify_only loads the signed loader purely to make the kernel
	 * verify its CMS signature (the unload-directive authorization
	 * gate) -- so it deliberately accepts an UNLOAD directive and
	 * stops before TEST_RUN/attach.
	 */
	if (!verify_only && shirudo_upatch_is_unload(&u)) {
		pr_err("upatch load: %s is an UNLOAD directive; "
		       "use `shirudo upatch unload`", path);
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "is an UNLOAD directive");
		rc = 1;
		goto out;
	}
	if (u.hdr.loader_insns_len % sizeof(struct bpf_insn)) {
		pr_err("upatch load: loader_insns_len=%u not a multiple of %zu",
		       u.hdr.loader_insns_len, sizeof(struct bpf_insn));
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "loader_insns_len misaligned");
		rc = 1;
		goto out;
	}

	/*
	 * Verify the CMS signature against the **sealed "shirudo" keyring
	 * only**, by passing that keyring's serial as keyring_id rather
	 * than KEY_SPEC_USER_KEYRING (-4). With -4 the kernel's
	 * keyring_search recurses through the whole user keyring (_uid.0),
	 * so a root attacker who links their own cert anywhere in _uid.0
	 * could get BPF they signed accepted. Scoping to the shirudo
	 * keyring -- which init sealed read-only, so no cert can be added
	 * for the boot -- confines the trust anchor to exactly the operator
	 * cert init linked there, closing that hole. A positive serial is
	 * accepted: the loading task possesses the keyring (a subkeyring of
	 * _uid.0) and lookup_user_key only rejects id < 1.
	 */
	keyring = shirudo_keyring_find(SHIRUDO_KEYRING_NAME);
	if (keyring < 0) {
		pr_err("keyring \"%s\" not found: %s (run `shirudo init`)",
		       SHIRUDO_KEYRING_NAME, strerror(-keyring));
		rep_fail(rep, "pre_flight", "keyring_missing", -keyring,
			 "shirudo keyring not found");
		rc = 1;
		goto out;
	}
	/* keyring now holds the sealed shirudo keyring's serial. */

	/*
	 * Swap detection: init pinned the keyring serial under the sealed
	 * tree. If the resolved-by-name serial no longer matches, a
	 * same-named "shirudo" keyring was substituted (a root attacker can
	 * unlink the real one from _uid.0 and link a fake) -- refuse rather
	 * than verify against an attacker-chosen cert. Absent pin (pre-pin
	 * init) degrades to a warning, like the payload-xattr check; a
	 * present-but-bad pin is treated as tampering. The complete fix
	 * needs an lsm/key_permission hook with a key_ref->key kfunc
	 * (TODO.kernel item 9).
	 */
	{
		key_serial_t pinned = shirudo_keyring_read_pinned_serial();

		if (pinned == -ENOENT) {
			pr_warn("keyring: no pinned serial at %s; swap "
				"detection skipped (re-run `shirudo init`)",
				SHIRUDO_KEYRING_SERIAL_PATH);
		} else if (pinned < 0) {
			pr_err("keyring: pinned serial unreadable: %s",
			       strerror(-pinned));
			rep_fail(rep, "pre_flight", "tampered", -pinned,
				 "keyring serial pin unreadable");
			rc = 1;
			goto out;
		} else if (pinned != keyring) {
			pr_err("keyring \"%s\" serial %d != pinned %d -- a "
			       "same-named keyring was substituted",
			       SHIRUDO_KEYRING_NAME, (int)keyring, (int)pinned);
			rep_fail(rep, "pre_flight", "tampered", 0,
				 "keyring serial mismatch (substituted keyring)");
			rc = 1;
			goto out;
		}
	}

	insns = shirudo_upatch_loader(&u);
	sig   = shirudo_upatch_signature(&u);
	data  = shirudo_upatch_data(&u);
	insn_cnt = u.hdr.loader_insns_len / sizeof(struct bpf_insn);

	/*
	 * Sanitise the on-disk upatch name into a bpf_obj_name_cpy-
	 * compatible string: keep alphanumerics, '_', '.'; replace
	 * everything else (notably '-' which is common in CVE-style
	 * names) with '_'. The kernel returns EINVAL on any other
	 * character.
	 */
	memset(prog_name, 0, sizeof(prog_name));
	{
		size_t i, n = strnlen(u.hdr.name, sizeof(u.hdr.name));
		if (n > sizeof(prog_name) - 1)
			n = sizeof(prog_name) - 1;
		for (i = 0; i < n; i++) {
			char c = u.hdr.name[i];
			int ok = (c >= 'a' && c <= 'z') ||
				 (c >= 'A' && c <= 'Z') ||
				 (c >= '0' && c <= '9') ||
				 c == '_' || c == '.';
			prog_name[i] = ok ? c : '_';
		}
	}

	/*
	 * The pin directory uses the canonical (raw) upatch name -- the
	 * same name persist and unload use -- so the three agree. The
	 * sanitised prog_name above is only for attr.prog_name (the
	 * kernel restricts that charset). Validate the raw name here too,
	 * since boot-restore reaches this path without the cmd-level check.
	 */
	memcpy(upatch_name, u.hdr.name, SHIRUDO_UPATCH_NAME_MAX);
	upatch_name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
	if (!safe_upatch_name(upatch_name)) {
		pr_err("upatch: refusing unsafe upatch name '%s'", upatch_name);
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "unsafe upatch name");
		rc = 1;
		goto out;
	}

	/*
	 * 1. Create __loader.map with excl_prog_hash = payload_sha256.
	 *    Binds the data map to a specific (signed) loader prog hash;
	 *    the kernel checks the binding when the prog is verified.
	 */
	map_fd = loader_map_create("__loader.map", u.hdr.data_len,
				   u.hdr.payload_sha256,
				   SHIRUDO_UPATCH_PAYLOAD_HASH_LEN);
	if (map_fd < 0) {
		pr_err("__loader.map create: %s", strerror(errno));
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(errno),
			 errno, "__loader.map create failed");
		rc = 1;
		goto out;
	}

	/* 2. Populate the loader map with opts.data. */
	rc = loader_map_update(map_fd, data, u.hdr.data_len);
	if (rc) {
		pr_err("__loader.map update: %s", strerror(errno));
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(errno),
			 errno, "__loader.map update failed");
		rc = 1;
		goto out;
	}

	/* 3. Freeze: userspace can no longer mutate. */
	rc = loader_map_freeze(map_fd);
	if (rc) {
		pr_err("__loader.map freeze: %s", strerror(errno));
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(errno),
			 errno, "__loader.map freeze failed");
		rc = 1;
		goto out;
	}

	/*
	 * 4. OBJ_GET_INFO_BY_FD with info.hash set -- triggers the
	 *    kernel to compute SHA-256(map_value) and store it in
	 *    bpf_map->sha. The signed loader reads that field at
	 *    runtime and compares against a hash baked into its own
	 *    insns. No-op for the kernel ledger we care about, but
	 *    skipping it bricks the loader.
	 */
	rc = loader_map_seal_hash(map_fd);
	if (rc) {
		pr_err("__loader.map OBJ_GET_INFO_BY_FD: %s", strerror(errno));
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(errno),
			 errno, "__loader.map hash seal failed");
		rc = 1;
		goto out;
	}

	/*
	 * 5. BPF_PROG_LOAD with signature + keyring_id + fd_array.
	 *    Kernel: verify CMS against keyring, then verifier runs
	 *    with the data map's FD reachable through fd_array[0].
	 */
	vlog[0] = '\0';
	prog_fd = prog_load_signed(insns, insn_cnt, prog_name,
				   sig, u.hdr.signature_len,
				   (int32_t)keyring, map_fd,
				   vlog, SHIRUDO_VERIFIER_LOG_MAX);
	if (prog_fd < 0) {
		int e = errno;

		pr_err("BPF_PROG_LOAD (signed loader): %s", strerror(e));
		if (vlog[0])
			fprintf(stderr, "loader verifier log:\n%s\n", vlog);
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(e), e,
			 "BPF_PROG_LOAD of signed loader failed");
		shirudo_report_set_log(rep, vlog);
		rc = 1;
		goto out;
	}

	pr_info("loaded signed loader: prog_fd=%d keyring=%d "
		"sig=%uB insns=%zu data=%uB",
		prog_fd, (int)keyring, u.hdr.signature_len, insn_cnt,
		u.hdr.data_len);

	/*
	 * Signature verified by the successful PROG_LOAD above. For the
	 * unload-directive authorization check that is all we need --
	 * stop before running/attaching anything.
	 */
	if (verify_only) {
		rc = 0;
		goto out;
	}

	/*
	 * 6. Invoke the loader. Kernel context (kernel == true) inside
	 *    the loader -- it does BPF_PROG_LOAD/BTF_LOAD/MAP_CREATE for
	 *    the embedded upatch programs from there, bypassing the
	 *    userspace lsm/bpf restrictions. The loader does NOT attach:
	 *    gen_loader has no link-create emit, and bpf_sys_bpf() can't
	 *    BPF_OBJ_PIN. The inner prog fds it opens are installed in
	 *    shirudo's fd table and surface in the ctx; shirudo attaches
	 *    and pins them below (step 7). See TODO.kernel items 1-3.
	 *
	 * gen_loader writes map/prog descriptors into the trailing bytes
	 * of its ctx, so the ctx is larger than struct
	 * shirudo_loader_ctx. Size the descriptor tail from the recorded
	 * counts; bpftool over-allocates a fixed 1024, but the exact
	 * size is known here from the header.
	 */
	prog_desc_off = sizeof(struct shirudo_loader_ctx) +
			(size_t)u.hdr.nr_maps * sizeof(struct shirudo_map_desc);
	/*
	 * prog_fd[i] lands at prog_desc_off + i*sizeof(prog_desc) -- the
	 * exact offset gen_loader writes (bpf_gen__finish). The loader's
	 * verifier-recorded max_ctx_offset can exceed that tail, so
	 * over-allocate a generous pad; TEST_RUN rejects ctx_size_in
	 * below max_ctx_offset. Extra bytes are harmless.
	 */
	ctx_sz = prog_desc_off +
		 (size_t)u.hdr.nr_progs * sizeof(struct shirudo_prog_desc) +
		 1024;
	cx = xmalloc(ctx_sz);
	if (!cx) {
		pr_err("ctx alloc");
		rep_fail(rep, "payload_load", "unknown", ENOMEM,
			 "ctx alloc failed");
		rc = 1;
		goto out;
	}
	vlog[0] = '\0';
	cx->sz = (uint32_t)ctx_sz;
	cx->log_level = 1 | 2 | 4;	/* bpftool's verifier_logs */
	cx->log_size = SHIRUDO_VERIFIER_LOG_MAX;
	cx->log_buf = (uint64_t)(uintptr_t)vlog;

	rc = prog_test_run_ctx(prog_fd, cx, (uint32_t)ctx_sz, &retval);
	if (rc) {
		pr_err("BPF_PROG_TEST_RUN: %s", strerror(errno));
		if (vlog[0])
			fprintf(stderr, "loader runtime log:\n%s\n", vlog);
		rep_fail(rep, "payload_load", "verifier_rejected", errno,
			 "BPF_PROG_TEST_RUN failed");
		shirudo_report_set_log(rep, vlog);
		rc = 1;
		goto out;
	}
	if ((int32_t)retval < 0) {
		pr_err("loader returned error: %d", (int32_t)retval);
		fprintf(stderr, "loader runtime log (len=%zu):\n%.4096s\n",
			strnlen(vlog, SHIRUDO_VERIFIER_LOG_MAX), vlog);
		rep_fail(rep, "payload_load", "verifier_rejected",
			 -(int32_t)retval, "inner loader returned error");
		if (rep)
			rep->loader_return = (int32_t)retval;
		shirudo_report_set_log(rep, vlog);
		rc = 1;
		goto out;
	}

	pr_info("loader ok, retval=%d (maps=%u progs=%u)", (int32_t)retval,
		u.hdr.nr_maps, u.hdr.nr_progs);

	/*
	 * 7. Attach and pin each inner program. The loader left them
	 *    loaded; without a pinned link they detach the moment this
	 *    one-shot CLI exits and the link fd closes. Pins live under
	 *    the private bpffs so the seal/inode_unlink LSM protects
	 *    them.
	 */
	rc = attach_and_pin_progs(cx, prog_desc_off, u.hdr.nr_progs,
				  upatch_name);
	if (rc) {
		int e = -rc;

		rep_fail(rep, "link_create",
			 (e == EACCES || e == EPERM) ? "lsm_denied" : "unknown",
			 e, "attach or pin failed");
		rc = 1;
		goto out;
	}

	/*
	 * 7b. Pin every map the signed loader created under
	 *     <pin_dir>/maps/<map_name>, so userspace can read it back
	 *     via `shirudo upatch map`. Non-fatal: a pin failure here
	 *     does not roll back the load (which already succeeded);
	 *     it just makes that map unobservable until next load.
	 */
	pin_upatch_maps(cx, u.hdr.nr_maps, upatch_name);

	/*
	 * Record payload_sha256 on the pin dir for the unload-time
	 * payload_mismatch check. After attach+pin so the dir exists and
	 * the value reflects an actually-loaded upatch (no rollback window
	 * -- see TODO.kernel item 7 discussion).
	 */
	set_pin_payload(upatch_name, u.hdr.payload_sha256);

	pr_audit("upatch load: name=%s keyring=%d progs=%u", upatch_name,
		 (int)keyring, u.hdr.nr_progs);
	if (rep)
		rep->loader_return = (int32_t)retval;
	rc = 0;
out:
	xfree(vlog, SHIRUDO_VERIFIER_LOG_MAX);
	xfree(cx, ctx_sz);
	if (prog_fd >= 0)
		close(prog_fd);
	if (map_fd >= 0)
		close(map_fd);
	shirudo_upatch_close(&u);
	return rc;
}

int shirudo_upatch_apply(const char *path)
{
	return upatch_apply(path, false, NULL);
}

/*
 * Operator-side pre-flight gate (PLAN.md "Pre-flight state check").
 * Runs before any BPF_PROG_LOAD: the shirudo keyring must exist, the
 * LSM link must still be pinned (enforcing), and -- when the caller
 * supplied --expect-chain -- the live TPM NV chain must still match
 * what the operator last observed. Any mismatch refuses with
 * category: tampered and a message naming the failed check; no kernel
 * state is touched. This is the optimistic-concurrency / tamper gate:
 * a concurrent operator that advanced the chain, a detached LSM, or a
 * missing keyring all surface here. Returns 0 to proceed.
 */
static int upatch_preflight(const char *expect_chain)
{
	uint8_t want[SHIRUDO_CHAIN_DIGEST_LEN], have[SHIRUDO_CHAIN_DIGEST_LEN];
	char have_hex[2 * SHIRUDO_CHAIN_DIGEST_LEN + 1];
	int fd, rc;

	if (shirudo_keyring_find(SHIRUDO_KEYRING_NAME) < 0) {
		pr_err("upatch load: pre-flight refused (category: tampered, "
		       "message: keyring_missing) -- run `shirudo init`");
		return -1;
	}

	fd = bpf_obj_get(SHIRUDO_LSM_LINK_PIN);
	if (fd < 0) {
		pr_err("upatch load: pre-flight refused (category: tampered, "
		       "message: lsm_detached) -- %s not pinned",
		       SHIRUDO_LSM_LINK_PIN);
		return -1;
	}
	close(fd);

	if (!expect_chain)
		return 0;

	if (shirudo_hex_decode(expect_chain, want, sizeof(want))) {
		pr_err("upatch load: --expect-chain must be %d hex chars",
		       2 * SHIRUDO_CHAIN_DIGEST_LEN);
		return -1;
	}
	rc = shirudo_chain_read(have);
	if (rc == -ENODEV) {
		pr_err("upatch load: pre-flight refused (category: tampered, "
		       "message: chain_drift) -- TPM chain unreadable, cannot "
		       "confirm --expect-chain");
		return -1;
	}
	if (rc) {
		pr_err("upatch load: chain read failed: %s", strerror(-rc));
		return -1;
	}
	if (!shirudo_ct_eq(want, have, sizeof(want))) {
		shirudo_hex_encode(have, sizeof(have), have_hex);
		pr_err("upatch load: pre-flight refused (category: tampered, "
		       "message: chain_drift) -- live chain %s != expected; "
		       "re-status and re-issue with the refreshed value",
		       have_hex);
		return -1;
	}
	return 0;
}

/*
 * Refuse if the eventlog would overflow its configured cap before any
 * state change. The chain and the log must advance together, so an
 * extend we could not log would break replay -- no load, no extend, no
 * append. Default eventlog.max_bytes=0 (unlimited) makes this a no-op.
 * Returns 0 to proceed.
 */
static int eventlog_room(struct shirudo_op_report *rep, const char *op)
{
	struct shirudo_config cfg;

	shirudo_config_load(&cfg);
	if (shirudo_eventlog_would_exceed(cfg.eventlog_max_bytes)) {
		pr_err("upatch %s: eventlog %s would exceed "
		       "eventlog.max_bytes=%lu; refusing -- no load, no extend",
		       op, SHIRUDO_EVENTLOG_PATH, cfg.eventlog_max_bytes);
		rep_fail(rep, "pre_flight", "eventlog_full", ENOSPC,
			 "eventlog would exceed eventlog.max_bytes");
		return -1;
	}
	return 0;
}

/*
 * First pre-flight gate: refuse a version-skewed operator/target pair.
 * The caller (rollout) passes the operator's SHIRUDO_VERSION_ID as
 * --expect-version-id; if it differs from this target's, the two were
 * built from different shirudo sources and no fleet op should proceed
 * (version_mismatch, EPERM). Runs before the chain/keyring checks
 * because a skew makes those comparisons meaningless. A standalone load
 * with no --expect-version-id (or --no-version-check) skips it.
 */
static int version_gate(const char *expect_version_id, bool no_version_check,
			struct shirudo_op_report *rep, const char *op)
{
	if (no_version_check || !expect_version_id)
		return 0;
	if (strcmp(expect_version_id, shirudo_version_id) != 0) {
		pr_err("upatch %s: version mismatch -- operator expects %s, "
		       "target is %s; redeploy a matching shirudo or pass "
		       "--no-version-check", op, expect_version_id,
		       shirudo_version_id);
		rep_fail(rep, "pre_flight", "version_mismatch", EPERM,
			 "SHIRUDO_VERSION_ID mismatch (operator vs target)");
		return -1;
	}
	return 0;
}

/* Eventlog entry ("upatch_load" / "upatch_unload") mirroring an extend. */
static int append_upatch_event(const char *type, const char *name,
			       const uint8_t payload[32], const uint8_t event[32])
{
	char buf[4096];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	char ts[32], nv_index[16], payload_hex[65], digest_hex[65];

	shirudo_eventlog_timestamp(ts, sizeof(ts));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
	shirudo_hex_encode(payload, 32, payload_hex);
	shirudo_hex_encode(event, 32, digest_hex);

	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_kv_string(&e, "ts", ts);
	shirudo_json_kv_string(&e, "nv_index", nv_index);
	shirudo_json_kv_string(&e, "alg", "sha256");
	shirudo_json_kv_string(&e, "digest", digest_hex);
	shirudo_json_kv_string(&e, "type", type);
	shirudo_json_obj_open_key(&e, "upatch");
	shirudo_json_kv_string(&e, "name", name);
	shirudo_json_kv_string(&e, "payload_sha256", payload_hex);
	shirudo_json_obj_close(&e);
	shirudo_json_obj_close(&e);

	if (e.err) {
		pr_err("eventlog: %s entry encode failed: %s", type,
		       strerror(-e.err));
		return e.err;
	}
	return shirudo_eventlog_append(buf);
}

/*
 * Operator-driven chain event. load extends with tag "shirudo-upatch"
 * and logs type "upatch_load"; unload extends with "shirudo-unload"
 * and logs "upatch_unload". Each operator op is its own
 * forward-progress event (boot-restore coalesces into one init event
 * instead). Returns 0 on success or graceful degradation (no TPM/chain
 * -- the op is done, just unmeasured), negative on the tpm_error case
 * (op done but chain not advanced).
 */
static int upatch_chain_event(const char *tag, const char *type,
			      const char *op, const char *name,
			      const uint8_t payload[32], char out_chain[65])
{
	uint8_t buf[sizeof("shirudo-unload") + 32 + SHIRUDO_UPATCH_NAME_MAX];
	uint8_t event[32], chain[32];
	char chain_hex[65];
	size_t taglen = strlen(tag) + 1, namelen, off = 0;
	int rc;

	if (out_chain)
		out_chain[0] = '\0';
	namelen = strnlen(name, SHIRUDO_UPATCH_NAME_MAX);
	memcpy(buf + off, tag, taglen);		/* tag + its NUL */
	off += taglen;
	memcpy(buf + off, payload, 32);
	off += 32;
	memcpy(buf + off, name, namelen);
	off += namelen;
	shirudo_sha256(buf, off, event);

	rc = shirudo_chain_extend(event, chain);
	if (rc == -ENODEV) {
		pr_warn("upatch %s: TPM/chain unavailable, not measured "
			"(degraded)", op);
		return 0;
	}
	if (rc) {
		pr_err("upatch %s: chain extend failed (category: tpm_error) "
		       "-- op done but chain NOT advanced; operator must "
		       "reconcile", op);
		return rc;
	}
	rc = append_upatch_event(type, name, payload, event);
	if (rc) {
		pr_err("upatch %s: eventlog append failed after extend -- "
		       "chain/log desync; operator must reconcile", op);
		return rc;
	}
	shirudo_hex_encode(chain, 32, chain_hex);
	if (out_chain)
		memcpy(out_chain, chain_hex, sizeof(chain_hex));
	pr_info("upatch %s: chain extended, value=%s", op, chain_hex);
	pr_audit("upatch %s measured: name=%s chain=%s", op, name, chain_hex);
	return 0;
}

/*
 * The upatch's on-disk name is NOT covered by the loader signature, so
 * treat it as untrusted when it becomes a filesystem path: allow only
 * a single safe path component (no '/', no leading '.', bounded
 * charset). Prevents an attacker-crafted name from escaping the
 * upatches dir when persisted.
 */
static bool safe_upatch_name(const char *name)
{
	size_t i;

	if (name[0] == '\0' || name[0] == '.')
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
		p += (size_t)w;
		n -= (size_t)w;
	}
	return 0;
}

static int copy_file_atomic(const char *src, const char *dst)
{
	char tmp[PATH_MAX + 8], buf[65536];
	int in, out, dir, rc = 0;
	ssize_t r;

	snprintf(tmp, sizeof(tmp), "%s.new", dst);
	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -errno;
	out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out < 0) {
		rc = -errno;
		close(in);
		return rc;
	}
	while ((r = read(in, buf, sizeof(buf))) > 0) {
		rc = write_all(out, buf, (size_t)r);
		if (rc)
			break;
	}
	if (r < 0 && !rc)
		rc = -errno;
	if (!rc && fsync(out) != 0)
		rc = -errno;
	close(in);
	if (close(out) != 0 && !rc)
		rc = -errno;
	if (rc) {
		unlink(tmp);
		return rc;
	}
	if (rename(tmp, dst) != 0) {
		rc = -errno;
		unlink(tmp);
		return rc;
	}
	/* Persist the rename so a crash can't lose a "loaded" upatch. */
	dir = open(SHIRUDO_UPATCHES_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dir >= 0) {
		fsync(dir);
		close(dir);
	}
	return 0;
}

/*
 * Persist the loaded .upatch into /var/lib/shirudo/upatches/<name>.upatch
 * so boot-restore re-applies it after a reboot. Idempotent when the
 * source already is that file (re-applying an installed upatch).
 */
static int persist_upatch(const char *src, const char *name)
{
	char dst[PATH_MAX];
	struct stat ss, ds;
	int rc;

	rc = mkdir_if_absent(SHIRUDO_UPATCHES_DIR, 0700);
	if (rc) {
		pr_err("mkdir %s: %s", SHIRUDO_UPATCHES_DIR, strerror(-rc));
		return rc;
	}
	if (snprintf(dst, sizeof(dst), "%s/%s.upatch", SHIRUDO_UPATCHES_DIR,
		     name) >= (int)sizeof(dst))
		return -ENAMETOOLONG;

	if (stat(src, &ss) == 0 && stat(dst, &ds) == 0 &&
	    ss.st_ino == ds.st_ino && ss.st_dev == ds.st_dev)
		return 0;	/* already the installed copy */

	rc = copy_file_atomic(src, dst);
	if (rc)
		return rc;
	/* Bring the new file under the seal LSM. */
	if (shirudo_seal_label(dst) != 0)
		pr_warn("upatch: could not seal-label %s: %s", dst,
			strerror(errno));
	return 0;
}

/*
 * Shared option parsing for `upatch load` / `upatch unload`:
 * [--expect-chain=<hex>] [--no-precheck] [--report=<path>] <file.upatch>.
 * Returns 0 on success, 2 on a usage error (message already printed).
 */
static int parse_op_args(int argc, const char **argv, const char *verb,
			 const struct shirudo_help *help,
			 const char **file, const char **expect_chain,
			 const char **expect_version_id, bool *no_precheck,
			 bool *no_version_check, const char **report)
{
	int i;

	*file = NULL;
	*expect_chain = NULL;
	*expect_version_id = NULL;
	*no_precheck = false;
	*no_version_check = false;
	*report = NULL;
	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strncmp(a, "--expect-chain=", 15) == 0)
			*expect_chain = a + 15;
		else if (strncmp(a, "--expect-version-id=", 20) == 0)
			*expect_version_id = a + 20;
		else if (strcmp(a, "--no-version-check") == 0)
			*no_version_check = true;
		else if (strncmp(a, "--report=", 9) == 0)
			*report = a + 9;
		else if (strcmp(a, "--no-precheck") == 0)
			*no_precheck = true;
		else if (a[0] == '-') {
			fprintf(stderr, "upatch %s: unknown option '%s'\n",
				verb, a);
			return 2;
		} else if (!*file) {
			*file = a;
		} else {
			fprintf(stderr, "upatch %s: unexpected argument '%s'\n",
				verb, a);
			return 2;
		}
	}
	if (!*file) {
		shirudo_print_help(help);
		return 2;
	}
	return 0;
}

/* Unlink every file under <dir>, then rmdir <dir>. -errno on failure. */
static int wipe_dir_flat(const char *dir)
{
	struct dirent *e;
	int dfd, rc = 0;
	DIR *d;

	d = opendir(dir);
	if (!d)
		return -errno;
	dfd = dirfd(d);
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		if (unlinkat(dfd, e->d_name, 0) != 0 && errno != ENOENT) {
			rc = -errno;
			break;
		}
	}
	closedir(d);
	if (rc)
		return rc;
	if (rmdir(dir) != 0 && errno != ENOENT)
		return -errno;
	return 0;
}

/*
 * Detach + unpin an upatch: descend into <upatches>/<name>/, wipe the
 * maps/ subdir first (unpinning every BPF_OBJ_PIN'd map), then unlink
 * the link pin (dropping the link refcount detaches the program), then
 * rmdir the top dir. The bpf2 inode_unlink hook permits this because
 * the caller is shirudo. Returns 0 on success, -ENOENT if the dir is
 * absent (already unloaded), -errno otherwise.
 */
static int remove_pin_dir(const char *name)
{
	char dir[PATH_MAX], maps_dir[PATH_MAX + 8];
	struct stat st;
	int rc;

	if (snprintf(dir, sizeof(dir), "%s/%s", SHIRUDO_BPFFS_UPATCHES_DIR,
		     name) >= (int)sizeof(dir))
		return -ENAMETOOLONG;
	if (snprintf(maps_dir, sizeof(maps_dir), "%s/maps", dir) >=
	    (int)sizeof(maps_dir))
		return -ENAMETOOLONG;
	if (stat(dir, &st) != 0)
		return -errno;
	/*
	 * maps/ must be torn down before the top dir, so the parent
	 * isn't holding an unwipeable subdir when we rmdir it.
	 */
	if (stat(maps_dir, &st) == 0) {
		rc = wipe_dir_flat(maps_dir);
		if (rc)
			return rc;
	}
	return wipe_dir_flat(dir);
}

static int cmd_upatch_load(int argc, const char **argv)
{
	const char *file, *expect_chain, *expect_version_id, *report;
	char name[SHIRUDO_UPATCH_NAME_MAX + 1] = {};
	uint8_t payload[SHIRUDO_UPATCH_PAYLOAD_HASH_LEN];
	struct shirudo_upatch u;
	struct shirudo_op_report rep = { .op = "upatch_load", .phase = "done" };
	bool no_precheck, no_version_check, have_id = false;
	int rc, ret = 1;

	for (int i = 1; i < argc; i++)
		if (shirudo_is_help(argv[i])) {
			shirudo_print_help(&upatch_load_help);
			return 0;
		}
	rc = parse_op_args(argc, argv, "load", &upatch_load_help,
			   &file, &expect_chain, &expect_version_id,
			   &no_precheck, &no_version_check, &report);
	if (rc)
		return rc;
	rep.path = file;

	if (version_gate(expect_version_id, no_version_check, &rep, "load") != 0)
		goto done;

	if (no_precheck) {
		pr_warn("upatch load: --no-precheck, pre-flight state check "
			"skipped");
	} else if (upatch_preflight(expect_chain) != 0) {
		rep_fail(&rep, "pre_flight", "tampered", EPERM,
			 "pre-flight check failed");
		goto done;
	}

	if (eventlog_room(&rep, "load") != 0)
		goto done;

	/* Capture the identity for persistence + the post-load chain event. */
	if (shirudo_upatch_open(file, &u) == 0) {
		memcpy(name, u.hdr.name, SHIRUDO_UPATCH_NAME_MAX);
		name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
		memcpy(payload, u.hdr.payload_sha256, sizeof(payload));
		shirudo_hex_encode(payload, sizeof(payload), rep.payload_hex);
		rep.name = name;
		shirudo_upatch_close(&u);
		have_id = true;
	}
	if (have_id && !safe_upatch_name(name)) {
		pr_err("upatch load: refusing unsafe upatch name '%s'", name);
		rep_fail(&rep, "parse", "parser_rejected", 0,
			 "unsafe upatch name");
		goto done;
	}

	if (upatch_apply(file, false, &rep) != 0)
		goto done;
	if (!have_id) {		/* loaded but couldn't read identity */
		ret = 0;
		rep.ok = true;
		goto done;
	}

	/*
	 * Persist before extending: the upatches dir is the on-disk
	 * record of intent that boot-restore replays, and the chain
	 * measures that intent. If we can't persist, don't measure --
	 * a chain event for an upatch that won't survive reboot would
	 * drift from reality.
	 */
	rc = persist_upatch(file, name);
	if (rc) {
		pr_err("upatch load: loaded but failed to persist to %s: %s "
		       "-- not measured", SHIRUDO_UPATCHES_DIR, strerror(-rc));
		rep_fail(&rep, "persist", "unknown", -rc, "persist failed");
		goto done;
	}

	if (upatch_chain_event("shirudo-upatch", "upatch_load", "load",
			       name, payload, rep.chain_after) != 0) {
		rep_fail(&rep, "tpm_extend", "tpm_error", EIO,
			 "chain extend failed");
		goto done;
	}
	rep.ok = true;
	rep.phase = "done";
	rep.tpm_present = rep.chain_after[0] != '\0';
	ret = 0;
done:
	if (report)
		shirudo_report_emit(report, &rep);
	shirudo_report_free(&rep);
	return ret;
}

static int cmd_upatch_unload(int argc, const char **argv)
{
	const char *file, *expect_chain, *expect_version_id, *report;
	char name[SHIRUDO_UPATCH_NAME_MAX + 1] = {};
	char persisted[PATH_MAX];
	uint8_t payload[SHIRUDO_UPATCH_PAYLOAD_HASH_LEN] = {};
	struct shirudo_upatch u;
	struct shirudo_op_report rep = { .op = "upatch_unload", .phase = "done" };
	bool no_precheck, no_version_check;
	int rc, ret = 1;

	for (int i = 1; i < argc; i++)
		if (shirudo_is_help(argv[i])) {
			shirudo_print_help(&upatch_unload_help);
			return 0;
		}
	rc = parse_op_args(argc, argv, "unload", &upatch_unload_help,
			   &file, &expect_chain, &expect_version_id,
			   &no_precheck, &no_version_check, &report);
	if (rc)
		return rc;
	rep.path = file;

	if (version_gate(expect_version_id, no_version_check, &rep, "unload") != 0)
		goto done;

	/* Read the target name + expected payload from the directive. */
	rc = shirudo_upatch_open(file, &u);
	if (rc) {
		pr_err("open %s: %s", file, strerror(-rc));
		rep_fail(&rep, "parse", "parser_rejected", -rc,
			 "cannot open .upatch");
		goto done;
	}
	if (!shirudo_upatch_is_unload(&u)) {
		pr_err("upatch unload: %s is a LOAD upatch; use "
		       "`shirudo upatch load`", file);
		rep_fail(&rep, "parse", "parser_rejected", 0,
			 "is a LOAD upatch");
		shirudo_upatch_close(&u);
		goto done;
	}
	memcpy(name, u.hdr.name, SHIRUDO_UPATCH_NAME_MAX);
	name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
	if (u.hdr.metadata_len == sizeof(payload))
		memcpy(payload, shirudo_upatch_metadata(&u), sizeof(payload));
	else
		pr_warn("upatch unload: directive carries no payload metadata; "
			"chain event uses zeros");
	shirudo_upatch_close(&u);
	rep.name = name;
	shirudo_hex_encode(payload, sizeof(payload), rep.payload_hex);

	if (!safe_upatch_name(name)) {
		pr_err("upatch unload: refusing unsafe upatch name '%s'", name);
		rep_fail(&rep, "parse", "parser_rejected", 0,
			 "unsafe upatch name");
		goto done;
	}
	if (snprintf(persisted, sizeof(persisted), "%s/%s.upatch",
		     SHIRUDO_UPATCHES_DIR, name) >= (int)sizeof(persisted))
		goto done;

	if (no_precheck) {
		pr_warn("upatch unload: --no-precheck, pre-flight state check "
			"skipped");
	} else if (upatch_preflight(expect_chain) != 0) {
		rep_fail(&rep, "pre_flight", "tampered", EPERM,
			 "pre-flight check failed");
		goto done;
	}

	if (eventlog_room(&rep, "unload") != 0)
		goto done;

	/*
	 * Authorization: load the directive's signed loader so the kernel
	 * verifies its CMS signature. A bad signature fails here and
	 * nothing is removed.
	 */
	if (upatch_apply(file, true, &rep) != 0) {
		pr_err("upatch unload: signature verification failed; refusing");
		goto done;
	}

	/*
	 * payload_mismatch: confirm the upatch actually loaded under
	 * <name> is the one the directive was signed to remove. The
	 * expected value is the directive's signature-covered payload; the
	 * live value is the xattr bpf2 protects on the pin dir. Skipped
	 * when the directive carries no expected payload (all-zero), or
	 * when the live value is unavailable (no xattr / kernel without the
	 * bpffs-xattr patch) -- in which case the detach proceeds as before.
	 */
	{
		uint8_t zero[SHIRUDO_UPATCH_PAYLOAD_HASH_LEN] = {};
		uint8_t live[SHIRUDO_UPATCH_PAYLOAD_HASH_LEN];
		int xrc;

		if (memcmp(payload, zero, sizeof(payload)) == 0) {
			pr_warn("upatch unload: directive carries no expected "
				"payload; skipping payload_mismatch check");
		} else if ((xrc = get_pin_payload(name, live)) == 0) {
			if (!shirudo_ct_eq(live, payload, sizeof(payload))) {
				pr_err("upatch unload: payload_mismatch -- the "
				       "upatch loaded under '%s' is not what the "
				       "directive expects; refusing", name);
				rep_fail(&rep, "pin", "payload_mismatch", EPERM,
					 "loaded payload does not match directive");
				goto done;
			}
			pr_info("upatch unload: payload matches for '%s'", name);
		} else if (xrc == -ENODATA || xrc == -ENOENT ||
			   xrc == -EOPNOTSUPP) {
			pr_warn("upatch unload: cannot verify payload for '%s' "
				"(%s); proceeding", name, strerror(-xrc));
		} else {
			pr_warn("upatch unload: payload xattr read failed for "
				"'%s': %s; proceeding", name, strerror(-xrc));
		}
	}

	/* Idempotent: no live pin -> already unloaded. */
	rc = remove_pin_dir(name);
	if (rc == -ENOENT) {
		if (unlink(persisted) != 0 && errno != ENOENT)
			pr_warn("upatch unload: could not remove %s: %s",
				persisted, strerror(errno));
		pr_info("upatch unload: %s already unloaded (no pin)", name);
		pr_audit("upatch unload: name=%s already_unloaded", name);
		rep.ok = true;
		rep.phase = "done";
		rep.category = "already_unloaded";
		snprintf(rep.message, sizeof(rep.message), "already unloaded");
		ret = 0;
		goto done;
	}
	if (rc) {
		pr_err("upatch unload: failed to remove pin for %s: %s",
		       name, strerror(-rc));
		rep_fail(&rep, "pin", "detach_failed", -rc,
			 "pin removal failed");
		goto done;
	}
	pr_info("upatch unload: detached + unpinned %s", name);

	/* Drop the on-disk record so boot-restore won't re-apply it. */
	if (unlink(persisted) != 0 && errno != ENOENT)
		pr_warn("upatch unload: could not remove %s: %s",
			persisted, strerror(errno));

	if (upatch_chain_event("shirudo-unload", "upatch_unload", "unload",
			       name, payload, rep.chain_after) != 0) {
		rep_fail(&rep, "tpm_extend", "tpm_error", EIO,
			 "chain extend failed");
		goto done;
	}
	rep.ok = true;
	rep.phase = "done";
	rep.tpm_present = rep.chain_after[0] != '\0';
	ret = 0;
done:
	if (report)
		shirudo_report_emit(report, &rep);
	shirudo_report_free(&rep);
	return ret;
}

/*
 * Render the source lines clang -g embedded in a program's BTF
 * (resolved via line_info records: line_off -> the source text, in the
 * BTF string section). Grouped by source file. rec_size is the record
 * stride (the kernel may grow struct bpf_line_info; we read the prefix
 * we know). Shared by `upatch get` (kernel BTF) and `upatch info` (the
 * .upatch's stored copy).
 */
struct li_entry {
	const char	*file;	/* into the BTF string section */
	const char	*src;
	uint32_t	line;
};

static int li_cmp(const void *a, const void *b)
{
	const struct li_entry *x = a, *y = b;
	int c = strcmp(x->file, y->file);

	if (c)
		return c;
	return (x->line > y->line) - (x->line < y->line);
}

/*
 * line_info records are in instruction order, so a source line maps to
 * several records (prologue, body, return all carry the same line) and
 * lines reappear out of order. For a *source* view that reads badly, so
 * collect the unique (file, line, src) tuples and sort them by file then
 * line. Returns the count; *out (allocated, caller xfrees with the same
 * n) holds the sorted unique entries pointing into the BTF strings.
 */
static uint32_t li_collect(const struct btf *btf, const void *recs,
			   uint32_t rec_size, uint32_t n, struct li_entry **out)
{
	struct li_entry *e;
	uint32_t i, c = 0, k;

	*out = NULL;
	if (!btf || !recs || n == 0 || rec_size < sizeof(struct bpf_line_info))
		return 0;
	e = xmalloc((size_t)n * sizeof(*e));
	if (!e)
		return 0;
	for (i = 0; i < n; i++) {
		const struct bpf_line_info *li = (const void *)
			((const char *)recs + (size_t)i * rec_size);
		const char *src = btf__name_by_offset(btf, li->line_off);
		const char *file = btf__name_by_offset(btf, li->file_name_off);

		if (src)
			while (*src == ' ' || *src == '\t')
				src++;
		if (!src || !*src)
			continue;
		e[c].file = (file && *file) ? file : "?";
		e[c].src = src;
		e[c].line = BPF_LINE_INFO_LINE_NUM(li->line_col);
		c++;
	}
	if (c == 0) {
		xfree(e, (size_t)n * sizeof(*e));
		return 0;
	}
	qsort(e, c, sizeof(*e), li_cmp);
	for (i = 0, k = 0; i < c; i++) {
		if (k && e[k - 1].line == e[i].line &&
		    strcmp(e[k - 1].file, e[i].file) == 0)
			continue;	/* same source line, different insns */
		e[k++] = e[i];
	}
	*out = e;
	return k;
}

static void dump_line_info(const struct btf *btf, const void *recs,
			   uint32_t rec_size, uint32_t n)
{
	struct li_entry *ents = NULL;
	const char *last = NULL;
	uint32_t k, i;

	k = li_collect(btf, recs, rec_size, n, &ents);
	if (k == 0) {
		printf("  (no line info)\n");
		xfree(ents, (size_t)n * sizeof(*ents));
		return;
	}
	for (i = 0; i < k; i++) {
		if (!last || strcmp(ents[i].file, last) != 0) {
			printf("  %s:\n", ents[i].file);
			last = ents[i].file;
		}
		printf("    %5u: %s\n", ents[i].line, ents[i].src);
	}
	xfree(ents, (size_t)n * sizeof(*ents));
}

/*
 * Dump the BPF line info (source) of a loaded upatch, read from the
 * kernel: the pinned link -> its prog -> the prog's line_info + BTF
 * (preserved through the signed gen_loader at load). All read-only
 * bpf() cmds, allowed by the LSM. The BTF here was loaded by the signed
 * loader, so this view is authoritative (unlike the .upatch's stored,
 * unsigned copy that `upatch info` shows).
 */
/*
 * Emit one map view as part of a `{ "schema": 1, "upatch": "...",
 * "map": "...", ... }` document so consumers don't have to bolt the
 * scaffolding on themselves.
 */
static int dump_one_map_json(const struct shirudo_map_view *v)
{
	struct shirudo_json_emit e = {};
	size_t cap;
	char *buf;

	cap = 8192 + 128 * v->n_entries +
	      (size_t)v->value_size * v->n_cpus * (size_t)v->n_entries * 8;
	if (cap > SHIRUDO_JSON_MAX_BYTES)
		cap = SHIRUDO_JSON_MAX_BYTES;
	buf = xmalloc(cap);
	if (!buf)
		return 1;
	e.buf = buf;
	e.cap = cap;
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_kv_string(&e, "upatch", v->upatch);
	shirudo_json_kv_string(&e, "map", v->name);
	shirudo_json_obj_open_key(&e, "data");
	shirudo_upatch_maps_emit_json(&e, v);
	shirudo_json_obj_close(&e);
	shirudo_json_obj_close(&e);
	if (e.err) {
		fprintf(stderr, "upatch map: json encode failed: %s\n",
			strerror(-e.err));
		xfree(buf, cap);
		return 1;
	}
	printf("%s\n", buf);
	xfree(buf, cap);
	return 0;
}

static int cmd_upatch_map(int argc, const char **argv)
{
	struct shirudo_map_summary *list = NULL;
	const char *upatch = NULL, *map = NULL;
	bool json = false, show_full = false;
	size_t n = 0;
	int i, ret = 0;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (shirudo_is_help(a)) {
			shirudo_print_help(&upatch_map_help);
			return 0;
		}
		if (strcmp(a, "--json") == 0) {
			json = true;
		} else if (strcmp(a, "--show-full") == 0) {
			show_full = true;
		} else if (a[0] == '-') {
			fprintf(stderr, "upatch map: unknown option '%s'\n", a);
			return 2;
		} else if (!upatch) {
			upatch = a;
		} else if (!map) {
			map = a;
		} else {
			fprintf(stderr, "upatch map: unexpected argument '%s'\n",
				a);
			return 2;
		}
	}

	if (upatch && map) {
		struct shirudo_map_view v = {};
		uint32_t cap = show_full ? 0 : SHIRUDO_MAP_ENTRIES_DEFAULT;
		int rc;

		if (!safe_upatch_name(upatch)) {
			pr_err("upatch map: invalid upatch name '%s'", upatch);
			return 2;
		}
		rc = shirudo_upatch_maps_read(upatch, map, cap, &v);
		if (rc) {
			pr_err("upatch map: read %s/%s: %s", upatch, map,
			       strerror(-rc));
			return 1;
		}
		if (json)
			ret = dump_one_map_json(&v);
		else
			shirudo_upatch_maps_print_detail(&v);
		shirudo_map_view_free(&v);
		return ret;
	}

	if (upatch) {
		if (!safe_upatch_name(upatch)) {
			pr_err("upatch map: invalid upatch name '%s'", upatch);
			return 2;
		}
		shirudo_upatch_maps_list_one(upatch, &list, &n);
	} else {
		shirudo_upatch_maps_list_all(&list, &n);
	}

	if (json) {
		struct shirudo_json_emit e = {};
		size_t cap = 8192 + 256 * n;
		char *buf;
		size_t k;

		buf = xmalloc(cap);
		if (!buf) {
			shirudo_map_summary_free(list, n);
			return 1;
		}
		e.buf = buf;
		e.cap = cap;
		shirudo_json_obj_open(&e);
		shirudo_json_kv_int(&e, "schema", 1);
		shirudo_json_arr_open(&e, "maps");
		for (k = 0; k < n; k++) {
			shirudo_json_obj_open(&e);
			shirudo_json_kv_string(&e, "upatch", list[k].upatch);
			shirudo_json_kv_string(&e, "name", list[k].name);
			shirudo_json_kv_string(&e, "type",
					       list[k].type_name);
			shirudo_json_kv_int(&e, "max_entries",
					    list[k].max_entries);
			if (list[k].n_cpus > 1)
				shirudo_json_kv_int(&e, "n_cpus",
						    list[k].n_cpus);
			shirudo_json_obj_close(&e);
		}
		shirudo_json_arr_close(&e);
		shirudo_json_obj_close(&e);
		if (e.err)
			ret = 1;
		else
			printf("%s\n", buf);
		xfree(buf, cap);
	} else {
		shirudo_upatch_maps_print_summary(list, n);
	}
	shirudo_map_summary_free(list, n);
	return ret;
}

static int cmd_upatch_get(int argc, const char **argv)
{
	struct bpf_prog_info info = {};
	struct bpf_link_info linfo = {};
	const char *want = NULL;
	char pin[PATH_MAX];
	struct btf *btf = NULL;
	void *recs = NULL;
	size_t recs_sz = 0;
	uint32_t len, nr, rec_size, btf_id;
	int link_fd = -1, prog_fd = -1, rc = 1, i;

	for (i = 1; i < argc; i++) {
		if (shirudo_is_help(argv[i])) {
			shirudo_print_help(&upatch_get_help);
			return 0;
		} else if (argv[i][0] == '-') {
			fprintf(stderr, "upatch get: unknown option '%s'\n",
				argv[i]);
			return 2;
		} else if (!want) {
			want = argv[i];
		} else {
			fprintf(stderr, "upatch get: unexpected argument '%s'\n",
				argv[i]);
			return 2;
		}
	}
	if (!want) {
		shirudo_print_help(&upatch_get_help);
		return 2;
	}
	if (!safe_upatch_name(want)) {
		pr_err("upatch get: invalid name '%s'", want);
		return 2;
	}

	if (snprintf(pin, sizeof(pin), "%s/%s/link",
		     SHIRUDO_BPFFS_UPATCHES_DIR, want) >= (int)sizeof(pin))
		return 2;
	link_fd = bpf_obj_get(pin);
	if (link_fd < 0) {
		pr_err("upatch get: '%s' not loaded (%s): %s", want, pin,
		       strerror(errno));
		return 1;
	}

	len = sizeof(linfo);
	if (bpf_link_get_info_by_fd(link_fd, &linfo, &len) != 0) {
		pr_err("upatch get: link info: %s", strerror(errno));
		goto out;
	}
	if (linfo.prog_id == 0) {
		pr_err("upatch get: link has no program");
		goto out;
	}
	prog_fd = bpf_prog_get_fd_by_id(linfo.prog_id);
	if (prog_fd < 0) {
		pr_err("upatch get: prog id %u: %s", linfo.prog_id,
		       strerror(errno));
		goto out;
	}

	len = sizeof(info);
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len) != 0) {
		pr_err("upatch get: prog info: %s", strerror(errno));
		goto out;
	}
	nr = info.nr_line_info;
	rec_size = info.line_info_rec_size;
	btf_id = info.btf_id;
	printf("upatch %s: prog id=%u, %u line-info record%s\n",
	       want, linfo.prog_id, nr, nr == 1 ? "" : "s");
	if (nr == 0 || btf_id == 0 || rec_size == 0) {
		printf("  (no line info -- built without `clang -g`?)\n");
		rc = 0;
		goto out;
	}

	recs_sz = (size_t)nr * rec_size;
	recs = xmalloc(recs_sz);
	if (!recs)
		goto out;
	/*
	 * Second pass: a fresh info requesting only the line_info array
	 * (a kernel-populated info has other count fields set, which would
	 * make the kernel try to fill arrays we have no buffer for).
	 */
	memset(&info, 0, sizeof(info));
	info.nr_line_info = nr;
	info.line_info_rec_size = rec_size;
	info.line_info = (uint64_t)(unsigned long)recs;
	len = sizeof(info);
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len) != 0) {
		pr_err("upatch get: prog line_info: %s", strerror(errno));
		goto out;
	}
	btf = btf__load_from_kernel_by_id(btf_id);
	if (!btf) {
		pr_err("upatch get: load BTF id %u: %s", btf_id,
		       strerror(errno));
		goto out;
	}
	dump_line_info(btf, recs, rec_size, nr);
	rc = 0;
out:
	if (btf)
		btf__free(btf);
	if (recs)
		xfree(recs, recs_sz);
	if (prog_fd >= 0)
		close(prog_fd);
	if (link_fd >= 0)
		close(link_fd);
	return rc;
}

static const struct shirudo_help_item upatch_subcmds[] = {
	{ "load",   "load a signed .upatch into the target kernel (target-only)" },
	{ "unload", "apply a signed UNLOAD directive (forward chain extension)" },
	{ "list",   "list persisted + bpffs-pinned upatches on this host" },
	{ "info",   "describe a .upatch file (any host; offline, no kernel state)" },
	{ "get",    "dump source of a loaded upatch from the target kernel (BTF line_info)" },
	{ "map",    "read pinned map contents (target-only; BTF type-aware)" },
};

static const struct shirudo_help_section upatch_help_sections[] = {
	{ "subcommands:", upatch_subcmds,
	  ARRAY_SIZE(upatch_subcmds) },
};

static const struct shirudo_help upatch_help = {
	.usage      = "shirudo upatch <subcommand> [<args>...]",
	.summary    = "Manage signed BPF programs (.upatch). load/unload are "
		      "target-only;\nlist/info/get are read-only and run on "
		      "either side.",
	.sections   = upatch_help_sections,
	.n_sections = ARRAY_SIZE(upatch_help_sections),
};

int cmd_upatch(int argc, const char **argv)
{
	const char *canonical;

	if (argc < 2 || shirudo_is_help(argv[1])) {
		shirudo_print_help(&upatch_help);
		return argc < 2 ? 2 : 0;
	}
	if (shirudo_is_list_cmds(argv[1])) {
		shirudo_print_subcmd_list(upatch_subcmds,
					  ARRAY_SIZE(upatch_subcmds));
		return 0;
	}
	canonical = shirudo_resolve_subcommand("shirudo upatch", argv[1],
					       upatch_subcmds,
					       ARRAY_SIZE(upatch_subcmds));
	if (!canonical)
		return 2;
	if (strcmp(canonical, "info") == 0)
		return cmd_upatch_info(argc - 1, argv + 1);
	if (strcmp(canonical, "load") == 0)
		return cmd_upatch_load(argc - 1, argv + 1);
	if (strcmp(canonical, "unload") == 0)
		return cmd_upatch_unload(argc - 1, argv + 1);
	if (strcmp(canonical, "list") == 0)
		return cmd_upatch_list(argc - 1, argv + 1);
	if (strcmp(canonical, "get") == 0)
		return cmd_upatch_get(argc - 1, argv + 1);
	if (strcmp(canonical, "map") == 0)
		return cmd_upatch_map(argc - 1, argv + 1);
	return 2;	/* unreachable */
}
