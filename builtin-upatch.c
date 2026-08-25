// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo upatch {info,load,unload,list} -- subcommand router.
 */

#include <endian.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/keyctl.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "builtin.h"
#include "util/chain.h"
#include "util/config.h"
#include "util/eventlog.h"
#include "util/elf_target.h"
#include "util/help.h"
#include "util/json.h"
#include "util/kernel_abi.h"
#include "util/macros.h"
#include "util/keyring.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/report.h"
#include "util/seal.h"
#include "util/timefmt.h"
#include "util/upatch.h"
#include "util/upatch_decode.h"
#include "util/upatch_maps.h"
#include "util/upatch_maps_otel.h"
#include "util/upatch_resolve.h"

extern const char shirudo_version_id[];

static bool safe_upatch_name(const char *name);

#ifndef NFPROTO_IPV6
#define NFPROTO_IPV6			10
#endif
#ifndef NF_INET_PRE_ROUTING
#define NF_INET_PRE_ROUTING		0
#endif
#ifndef NF_IP6_PRI_RAW_BEFORE_DEFRAG
#define NF_IP6_PRI_RAW_BEFORE_DEFRAG	(-450)
#endif

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

static const char *decoder_language_str(uint32_t language)
{
	return language == SHIRUDO_UPATCH_DECODER_LANG_LUA ? "lua" : "unknown";
}

static const char *decoder_input_str(uint32_t input_format)
{
	return input_format == SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1 ?
		"shirudo.map.v1" : "unknown";
}

static const char *decoder_signal_str(uint32_t signal)
{
	return signal == SHIRUDO_UPATCH_DECODER_EXPORT_LOG ? "log" :
		signal == SHIRUDO_UPATCH_DECODER_EXPORT_METRIC ? "metric" :
		"unknown";
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
	{ "--all", "export every map from every loaded upatch" },
	{ "--json=<path>", "append the signed Lua decoder's NDJSON record to path" },
	{ "--show-full",  "lift the per-map 256-entry truncation cap" },
	{ "--otel", "export through OTLP using each decoder's signed signal" },
	{ "--otel-endpoint=<url>", "OTLP base URL (signal path is appended)" },
	{ "--tenant-id=<id>", "add X-Tenant-ID to OTLP requests" },
	{ "--otel-insecure", "allow cleartext remote OTLP or disable HTTPS verification" },
	{ "--otel-retries=<0-10>", "OTLP retries after the first attempt (default: 3)" },
	{ "--s3-uri=<uri>", "S3 overflow destination for OTLP payloads" },
};

static const struct shirudo_help_section upatch_map_sections[] = {
	{ "options:", upatch_map_options, ARRAY_SIZE(upatch_map_options) },
};

static const struct shirudo_help upatch_map_help = {
	.usage      = "shirudo upatch map [--all] [<upatch>] [<map>] "
		      "[--json=<path>] [--show-full]\n"
		      "                          [--otel] "
		      "[--otel-endpoint=<url>]\n"
		      "                          [--otel-insecure] "
		      "[--otel-retries=<0-10>] [--s3-uri=<uri>]",
	.summary    = "Read the contents of a pinned upatch map from the\n"
		      "target kernel. With no positional args, list every "
		      "pinned\nmap across every loaded upatch. With "
		      "<upatch>, list maps\nfor that upatch only. With "
		      "<upatch> <map>, dump the map's\ncontents -- BTF "
		      "type-aware where the build embedded `-g`. If the "
		      "upatch\npins a serializer for the map, run it and "
		      "print the serialized\npages. With --all, export detailed "
		      "contents for every loaded map\nusing command-line or "
		      "map_export.* configuration.",
	.sections   = upatch_map_sections,
	.n_sections = ARRAY_SIZE(upatch_map_sections),
	.footer     =
"Examples:\n"
"  shirudo upatch map\n"
"  shirudo upatch map --all\n"
"  shirudo upatch map cve-2026-31431-counter\n"
"  shirudo upatch map cve-2026-31431-counter blocked_af_alg\n"
"  shirudo upatch map cve-2026-31431-counter blocked_af_alg \\\n"
"    --json=/var/log/shirudo/maps.ndjson\n"
"  shirudo upatch map cve-2026-31431-counter blocked_af_alg --otel\n"
"  shirudo upatch map foo values --otel \\\n"
"    --otel-endpoint=https://collector:4318\n"
"  shirudo upatch map cve-2026-31431-counter big_hash --show-full",
};

static const struct shirudo_help_item upatch_get_options[] = {
	{ "--json",       "machine-readable JSON output" },
	{ "--show-full",  "lift the per-map 256-entry truncation cap" },
};

static const struct shirudo_help_section upatch_get_sections[] = {
	{ "options:", upatch_get_options, ARRAY_SIZE(upatch_get_options) },
};

static const struct shirudo_help upatch_get_help = {
	.usage   = "shirudo upatch get <name> [--json] [--show-full]",
	.summary = "Describe a loaded upatch from the target kernel:\n"
		   "  - the SEC()-style attach hook (e.g. fexit/tcp_v4_connect),\n"
		   "  - the prog source via BTF line_info installed by the\n"
		   "    signed loader (authoritative, but sparse),\n"
		   "  - every pinned map: BTF key/value type definitions plus\n"
		   "    the live key/value contents.\n"
		   "Read-only; uses only LSM-allowed bpf() ops + xattr / stat.\n"
		   "For the build-time-embedded full source see\n"
		   "`shirudo upatch info`.",
	.sections   = upatch_get_sections,
	.n_sections = ARRAY_SIZE(upatch_get_sections),
	.footer  =
"Examples:\n"
"  shirudo upatch get cve-2026-31431\n"
"  shirudo upatch get cve-2026-31431 --json | jq",
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
		size_t cap = 8192 + (size_t)u.source_len * 6 +
			u.source_name_len + (size_t)u.nr_decoders * 768;
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
		shirudo_json_arr_open(&e, "decoders");
		for (uint32_t j = 0; j < u.nr_decoders; j++) {
			struct shirudo_upatch_decoder_view d;

			if (shirudo_upatch_decoder_view(&u, j, &d))
				continue;
			shirudo_json_obj_open(&e);
			shirudo_json_kv_string(&e, "language",
					       decoder_language_str(d.language));
			shirudo_json_kv_int(&e, "api_version", d.api_version);
			shirudo_json_kv_string(&e, "input_format",
					       decoder_input_str(d.input_format));
			shirudo_json_kv_string(&e, "export_signal",
					       decoder_signal_str(d.export_signal));
			shirudo_json_kv_string(&e, "upatch", d.upatch);
			shirudo_json_kv_string(&e, "map", d.map);
			shirudo_json_kv_string(&e, "source_file", d.source_name);
			shirudo_json_kv_string(&e, "entrypoint", d.entrypoint);
			shirudo_json_kv_int(&e, "source_len", d.source_len);
			shirudo_json_obj_close(&e);
		}
		shirudo_json_arr_close(&e);
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

	printf("\nDecoders:\n");
	if (!shirudo_upatch_has_decoders(&u)) {
		printf("  (none)\n");
	} else {
		for (uint32_t j = 0; j < u.nr_decoders; j++) {
			struct shirudo_upatch_decoder_view d;

			if (shirudo_upatch_decoder_view(&u, j, &d))
				continue;
			printf("  %-22s %s/%s\n", "Target:", d.upatch, d.map);
			printf("    %-20s %s (api=%u)\n", "Language:",
			       decoder_language_str(d.language), d.api_version);
			printf("    %-20s %s\n", "Input:",
			       decoder_input_str(d.input_format));
			printf("    %-20s %s\n", "Export signal:",
			       decoder_signal_str(d.export_signal));
			printf("    %-20s %s:%s (%u bytes)\n", "Source:",
			       d.source_name, d.entrypoint, d.source_len);
		}
	}

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
	int fd;

	fd = shirudo_upatch_open_first_link(name);
	if (fd < 0)
		return false;
	close(fd);
	return true;
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
	/*
	 * fd_array_cnt makes the verifier resolve the exclusive metadata
	 * map up front and fold its frozen contents into the signed buffer
	 * (insns || metadata). A signed load without it is rejected: the
	 * kernel refuses to bind a map through the sparse fd_array path.
	 */
	attr.fd_array_cnt = 1;
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
 * attach_btf_id. Older kernels required this path, while newer kernels
 * prefer BPF_LINK_CREATE for BTF-attached programs such as sleepable
 * LSM. The gen loader resolves attach_btf_id at load time, so the link
 * target is fixed by the signed program, not chosen here. Returns a link
 * fd. On failure, returns a negative errno.
 */
static int prog_attach_raw_tp(int prog_fd)
{
	union bpf_attr attr = {};
	long fd;

	attr.raw_tracepoint.name = 0;
	attr.raw_tracepoint.prog_fd = (uint32_t)prog_fd;
	fd = syscall(__NR_bpf, BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

static int prog_attach_cgroup_skb(int prog_fd,
				  enum bpf_attach_type attach_type);

static bool attach_type_has_raw_tp_fallback(enum bpf_attach_type attach_type)
{
	switch (attach_type) {
	case BPF_TRACE_RAW_TP:
	case BPF_TRACE_FENTRY:
	case BPF_TRACE_FEXIT:
	case BPF_MODIFY_RETURN:
	case BPF_LSM_MAC:
		return true;
	default:
		return false;
	}
}

static int prog_attach_btf_link(int prog_fd, enum bpf_attach_type attach_type)
{
	union bpf_attr attr = {};
	long fd;

	attr.link_create.prog_fd = (uint32_t)prog_fd;
	attr.link_create.target_fd = 0;
	attr.link_create.attach_type = attach_type;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

static int prog_attach_btf_link_or_raw_tp(int prog_fd,
					  enum bpf_attach_type attach_type)
{
	int rc;

	rc = prog_attach_btf_link(prog_fd, attach_type);
	if (rc < 0 && rc == -EINVAL &&
	    attach_type_has_raw_tp_fallback(attach_type))
		return prog_attach_raw_tp(prog_fd);
	return rc;
}

static int prog_func_name(int prog_fd, const struct bpf_prog_info *base,
			  char *out, size_t cap)
{
	struct bpf_prog_info info = {};
	struct bpf_func_info fi;
	struct btf *btf;
	const struct btf_type *t;
	const char *name;
	void *recs;
	size_t recs_sz;
	uint32_t len;
	int rc = 0;

	if (!out || cap == 0)
		return -EINVAL;
	out[0] = '\0';
	if (base->nr_func_info == 0 || base->func_info_rec_size == 0 ||
	    base->btf_id == 0)
		return -ENOENT;
	if (base->func_info_rec_size < sizeof(struct bpf_func_info))
		return -EINVAL;
	recs_sz = (size_t)base->nr_func_info * base->func_info_rec_size;
	recs = xmalloc(recs_sz);
	if (!recs)
		return -ENOMEM;

	info.nr_func_info = base->nr_func_info;
	info.func_info_rec_size = base->func_info_rec_size;
	info.func_info = (uint64_t)(uintptr_t)recs;
	len = sizeof(info);
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len) != 0) {
		rc = -errno;
		goto out_free;
	}
	memcpy(&fi, recs, sizeof(fi));
	btf = btf__load_from_kernel_by_id(base->btf_id);
	if (!btf) {
		rc = -errno;
		goto out_free;
	}
	t = btf__type_by_id(btf, fi.type_id);
	name = t ? btf__name_by_offset(btf, t->name_off) : NULL;
	if (!name || !name[0]) {
		rc = -ENOENT;
	} else {
		snprintf(out, cap, "%s", name);
		rc = 0;
	}
	btf__free(btf);
out_free:
	xfree(recs, recs_sz);
	return rc;
}

static int cgroup_skb_attach_type_from_name(const char *name,
					    enum bpf_attach_type *attach_type)
{
	if (!name || !name[0])
		return -EINVAL;
	if (strstr(name, "egress") || strstr(name, "query") ||
	    strstr(name, "send")) {
		*attach_type = BPF_CGROUP_INET_EGRESS;
		return 0;
	}
	if (strstr(name, "ingress") || strstr(name, "response") ||
	    strstr(name, "recv") || strstr(name, "receive")) {
		*attach_type = BPF_CGROUP_INET_INGRESS;
		return 0;
	}
	return -EINVAL;
}

static int prog_attach_cgroup_skb_fallback(int prog_fd,
					   const struct bpf_prog_info *info)
{
	enum bpf_attach_type attach_type;
	char func[128];
	int rc;

	snprintf(func, sizeof(func), "%s", info->name);
	rc = prog_func_name(prog_fd, info, func, sizeof(func));
	if (rc && !func[0]) {
		pr_err("program metadata says raw_tracepoint, but loaded "
		       "program type is cgroup_skb and function name is "
		       "unavailable; rebuild the upatch with cgroup_skb "
		       "metadata");
		return rc;
	}
	rc = cgroup_skb_attach_type_from_name(func, &attach_type);
	if (rc) {
		pr_err("program metadata says raw_tracepoint, but loaded "
		       "program type is cgroup_skb and function '%s' does "
		       "not identify ingress or egress; rebuild the upatch "
		       "with cgroup_skb metadata", func);
		return rc;
	}
	pr_warn("program metadata says raw_tracepoint, but loaded program "
		"type is cgroup_skb; inferring %s from function '%s'",
		attach_type == BPF_CGROUP_INET_EGRESS ? "egress" : "ingress",
		func);
	rc = prog_attach_cgroup_skb(prog_fd, attach_type);
	if (rc >= 0)
		pr_info("attached cgroup_skb fallback as %s",
			attach_type == BPF_CGROUP_INET_EGRESS ?
			"egress" : "ingress");
	return rc;
}

static int prog_attach_default(int prog_fd)
{
	struct bpf_prog_info info = {};
	uint32_t info_len = sizeof(info);
	enum bpf_attach_type attach_type;

	if (bpf_prog_get_info_by_fd(prog_fd, &info, &info_len) != 0)
		return prog_attach_raw_tp(prog_fd);

	switch (info.type) {
	case BPF_PROG_TYPE_LSM:
		attach_type = BPF_LSM_MAC;
		break;
	case BPF_PROG_TYPE_CGROUP_SKB:
		return prog_attach_cgroup_skb_fallback(prog_fd, &info);
	default:
		return prog_attach_raw_tp(prog_fd);
	}

	return prog_attach_btf_link_or_raw_tp(prog_fd, attach_type);
}

static int prog_attach_cgroup_skb(int prog_fd, enum bpf_attach_type attach_type)
{
	union bpf_attr attr = {};
	int cgroup_fd, rc;
	long fd;

	cgroup_fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cgroup_fd < 0)
		return -errno;

	attr.link_create.prog_fd = (uint32_t)prog_fd;
	attr.link_create.target_fd = (uint32_t)cgroup_fd;
	attr.link_create.attach_type = attach_type;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	rc = fd >= 0 ? (int)fd : -errno;
	close(cgroup_fd);
	return rc;
}

static int prog_attach_netfilter_ipv6_pre_routing(int prog_fd)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		.netfilter.pf = NFPROTO_IPV6,
		.netfilter.hooknum = NF_INET_PRE_ROUTING,
		.netfilter.priority = NF_IP6_PRI_RAW_BEFORE_DEFRAG,
		.netfilter.flags = 0);

	return bpf_link_create(prog_fd, 0, BPF_NETFILTER, &opts);
}

static int read_int_file(const char *path, const char *fmt)
{
	char buf[64];
	ssize_t n;
	int fd, value;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0) {
		int e = -errno;

		close(fd);
		return e;
	}
	close(fd);
	if (n == 0)
		return -EINVAL;
	buf[n] = '\0';
	if (sscanf(buf, fmt, &value) != 1 || value < 0)
		return -EINVAL;
	return value;
}

static int determine_kprobe_perf_type(void)
{
	return read_int_file("/sys/bus/event_source/devices/kprobe/type",
			     "%d\n");
}

static int determine_kprobe_retprobe_bit(void)
{
	return read_int_file("/sys/bus/event_source/devices/kprobe/format/retprobe",
			     "config:%d\n");
}

static int perf_event_open_kprobe(const char *target, uint64_t offset,
				  bool retprobe)
{
	struct perf_event_attr attr = {};
	int type, bit;
	long fd;

	type = determine_kprobe_perf_type();
	if (type < 0)
		return type;
	attr.size = sizeof(attr);
	attr.type = (uint32_t)type;
	attr.config1 = (uint64_t)(uintptr_t)target;
	attr.config2 = offset;
	if (retprobe) {
		bit = determine_kprobe_retprobe_bit();
		if (bit < 0)
			return bit;
		if (bit >= 64)
			return -EINVAL;
		attr.config |= 1ULL << bit;
	}

	fd = syscall(__NR_perf_event_open, &attr,
		     -1 /* pid */, 0 /* cpu */,
		     -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
	return fd >= 0 ? (int)fd : -errno;
}

static int prog_attach_perf_event(int prog_fd, int perf_fd)
{
	union bpf_attr attr = {};
	long fd;

	attr.link_create.prog_fd = (uint32_t)prog_fd;
	attr.link_create.target_fd = (uint32_t)perf_fd;
	attr.link_create.attach_type = BPF_PERF_EVENT;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

struct shirudo_prog_spec {
	uint32_t role;
	uint32_t kind;
	uint64_t offset;
	char target[SHIRUDO_UPATCH_ATTACH_TARGET_MAX];
	char map[SHIRUDO_UPATCH_PROG_MAP_MAX];
	char *uprobe_path;
	uint32_t uprobe_path_len;
	uint8_t build_id[SHIRUDO_UPATCH_BUILD_ID_MAX];
	uint32_t build_id_len;
	uint64_t *uprobe_offsets;
	uint32_t nr_uprobe_offsets;
	int target_fd;
	struct stat target_stat;
};

static const char *attach_kind_name(uint32_t kind)
{
	switch (kind) {
	case SHIRUDO_UPATCH_ATTACH_RAW_TRACEPOINT:
		return "raw_tracepoint";
	case SHIRUDO_UPATCH_ATTACH_KPROBE:
		return "kprobe";
	case SHIRUDO_UPATCH_ATTACH_KRETPROBE:
		return "kretprobe";
	case SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_INGRESS:
		return "cgroup_skb/ingress";
	case SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_EGRESS:
		return "cgroup_skb/egress";
	case SHIRUDO_UPATCH_ATTACH_FMOD_RET:
		return "fmod_ret";
	case SHIRUDO_UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
		return "netfilter/ipv6-pre-routing";
	case SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI:
		return "uprobe.multi";
	default:
		return "unknown";
	}
}

static void prog_specs_free(struct shirudo_prog_spec *specs,
			    uint32_t nr_progs)
{
	uint32_t i;

	if (!specs)
		return;
	for (i = 0; i < nr_progs; i++) {
		if (specs[i].target_fd >= 0)
			close(specs[i].target_fd);
		xstrfree(specs[i].uprobe_path);
		xfree(specs[i].uprobe_offsets,
		      (size_t)specs[i].nr_uprobe_offsets *
		      sizeof(*specs[i].uprobe_offsets));
	}
	xfree(specs, (size_t)nr_progs * sizeof(*specs));
}

static int prog_specs_parse(const void *metadata, uint32_t metadata_len,
			    uint32_t nr_progs,
			    struct shirudo_prog_spec **out)
{
	struct shirudo_upatch_prog_metadata md;
	struct shirudo_prog_spec *specs = NULL;
	const unsigned char *cursor, *end;
	size_t base_len;
	uint32_t magic, version, count, i, nr_uprobes = 0;
	int rc = -EINVAL;

	*out = NULL;
	if (!metadata || metadata_len < sizeof(uint32_t))
		return -EINVAL;
	memcpy(&magic, metadata, sizeof(magic));
	magic = le32toh(magic);
	if (magic != SHIRUDO_UPATCH_PROG_MAGIC)
		return -EINVAL;
	if (metadata_len < sizeof(md))
		return -EINVAL;
	memcpy(&md, metadata, sizeof(md));
	version = le32toh(md.version);
	count = le32toh(md.nr_progs);
	if (version != SHIRUDO_UPATCH_PROG_VERSION)
		return -EOPNOTSUPP;
	if (count != nr_progs || le32toh(md.reserved) != 0)
		return -EINVAL;
	if (count > (UINT32_MAX - sizeof(md)) /
	    sizeof(struct shirudo_upatch_prog_entry))
		return -EOVERFLOW;
	base_len = sizeof(md) + (size_t)count *
		   sizeof(struct shirudo_upatch_prog_entry);
	if (metadata_len < base_len)
		return -EINVAL;
	specs = xcalloc(nr_progs, sizeof(*specs));
	if (!specs)
		return -ENOMEM;
	for (i = 0; i < nr_progs; i++)
		specs[i].target_fd = -1;

	for (i = 0; i < nr_progs; i++) {
		struct shirudo_upatch_prog_entry prog;
		struct shirudo_prog_spec *spec = &specs[i];
		uint32_t role, kind;

		memcpy(&prog, (const unsigned char *)metadata + sizeof(md) +
		       (size_t)i * sizeof(prog), sizeof(prog));
		role = le32toh(prog.role);
		switch (role) {
	case SHIRUDO_UPATCH_PROG_ROLE_ATTACH:
		break;
	case SHIRUDO_UPATCH_PROG_ROLE_SERIALIZER:
		if (prog.kind || prog.offset || prog.target[0])
			goto out;
		if (!memchr(prog.map, '\0', sizeof(prog.map)) ||
		    prog.map[0] == '\0')
			goto out;
		spec->role = role;
		memcpy(spec->map, prog.map, sizeof(spec->map));
		spec->map[sizeof(spec->map) - 1] = '\0';
		continue;
	default:
		goto out;
		}
		if (prog.map[0])
			goto out;
		spec->role = role;

		kind = le32toh(prog.kind);
		switch (kind) {
	case SHIRUDO_UPATCH_ATTACH_RAW_TRACEPOINT:
		spec->kind = kind;
		if (prog.target[0] || prog.offset)
			goto out;
		continue;
	case SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_INGRESS:
	case SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_EGRESS:
	case SHIRUDO_UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
		spec->kind = kind;
		if (prog.target[0] || prog.offset)
			goto out;
		continue;
	case SHIRUDO_UPATCH_ATTACH_FMOD_RET:
		spec->kind = kind;
		if (prog.target[0] || prog.offset)
			goto out;
		continue;
	case SHIRUDO_UPATCH_ATTACH_KPROBE:
	case SHIRUDO_UPATCH_ATTACH_KRETPROBE:
		break;
	case SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI:
		if (prog.offset)
			goto out;
		nr_uprobes++;
		break;
	default:
		goto out;
		}
		if (!memchr(prog.target, '\0', sizeof(prog.target)) ||
		    prog.target[0] == '\0')
			goto out;
		spec->kind = kind;
		spec->offset = le64toh(prog.offset);
		memcpy(spec->target, prog.target, sizeof(spec->target));
		spec->target[sizeof(spec->target) - 1] = '\0';
		if (kind == SHIRUDO_UPATCH_ATTACH_KRETPROBE && spec->offset)
			goto out;
		if (kind == SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI &&
		    (strchr(spec->target, ',') || strchr(spec->target, '|')))
			goto out;
	}

	if (!nr_uprobes) {
		if (metadata_len != base_len)
			goto out;
		*out = specs;
		return 0;
	}

	cursor = (const unsigned char *)metadata + base_len;
	end = (const unsigned char *)metadata + metadata_len;
	if ((size_t)(end - cursor) <
	    sizeof(struct shirudo_upatch_uprobe_targets))
		goto out;
	{
		struct shirudo_upatch_uprobe_targets targets;
		uint32_t nr_targets;

		memcpy(&targets, cursor, sizeof(targets));
		cursor += sizeof(targets);
		nr_targets = le32toh(targets.nr_targets);
		if (le32toh(targets.magic) !=
		    SHIRUDO_UPATCH_UPROBE_TARGET_MAGIC ||
		    le32toh(targets.version) !=
		    SHIRUDO_UPATCH_UPROBE_TARGET_VERSION ||
		    le32toh(targets.reserved) != 0 || nr_targets != nr_uprobes)
			goto out;

		for (i = 0; i < nr_targets; i++) {
			struct shirudo_upatch_uprobe_target record;
			struct shirudo_prog_spec *spec;
			uint32_t prog_idx, path_len, build_id_len, nr_offsets, j;
			size_t payload_len;

			if ((size_t)(end - cursor) < sizeof(record))
				goto out;
			memcpy(&record, cursor, sizeof(record));
			cursor += sizeof(record);
			prog_idx = le32toh(record.prog_idx);
			path_len = le32toh(record.path_len);
			build_id_len = le32toh(record.build_id_len);
			nr_offsets = le32toh(record.nr_offsets);
			if (prog_idx >= nr_progs ||
			    specs[prog_idx].kind !=
			    SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI ||
			    specs[prog_idx].uprobe_path || path_len == 0 ||
			    path_len >= SHIRUDO_UPATCH_UPROBE_PATH_MAX ||
			    build_id_len == 0 ||
			    build_id_len > SHIRUDO_UPATCH_BUILD_ID_MAX ||
			    nr_offsets == 0 ||
			    nr_offsets > SHIRUDO_UPATCH_UPROBE_OFFSETS_MAX)
				goto out;
			payload_len = (size_t)path_len + build_id_len +
				      (size_t)nr_offsets * sizeof(uint64_t);
			if ((size_t)(end - cursor) < payload_len ||
			    cursor[0] != '/' || memchr(cursor, '\0', path_len))
				goto out;
			spec = &specs[prog_idx];
			spec->uprobe_path = xstrndup((const char *)cursor,
						     path_len);
			if (!spec->uprobe_path) {
				rc = -ENOMEM;
				goto out;
			}
			spec->uprobe_path_len = path_len;
			cursor += path_len;
			memcpy(spec->build_id, cursor, build_id_len);
			spec->build_id_len = build_id_len;
			cursor += build_id_len;
			spec->uprobe_offsets =
				xcalloc(nr_offsets, sizeof(*spec->uprobe_offsets));
			if (!spec->uprobe_offsets) {
				rc = -ENOMEM;
				goto out;
			}
			spec->nr_uprobe_offsets = nr_offsets;
			for (j = 0; j < nr_offsets; j++) {
				uint64_t offset;

				memcpy(&offset, cursor, sizeof(offset));
				cursor += sizeof(offset);
				spec->uprobe_offsets[j] = le64toh(offset);
				if (j && spec->uprobe_offsets[j] <=
					 spec->uprobe_offsets[j - 1])
					goto out;
			}
		}
	}
	if (cursor != end)
		goto out;
	for (i = 0; i < nr_progs; i++) {
		if (specs[i].kind == SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI &&
		    !specs[i].uprobe_path)
			goto out;
	}
	*out = specs;
	return 0;
out:
	prog_specs_free(specs, nr_progs);
	return rc;
}

static int prepare_uprobe_targets(struct shirudo_prog_spec *specs,
				  uint32_t nr_progs)
{
	uint32_t i;

	for (i = 0; i < nr_progs; i++) {
		struct shirudo_prog_spec *spec = &specs[i];
		uint8_t build_id[SHIRUDO_UPATCH_BUILD_ID_MAX];
		uint32_t build_id_len = 0;
		char proc_path[64];
		struct stat opened_stat;
		int path_fd, fd, rc;

		if (spec->kind != SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI)
			continue;
		path_fd = open(spec->uprobe_path, O_PATH | O_CLOEXEC);
		if (path_fd < 0)
			return -errno;
		if (fstat(path_fd, &spec->target_stat) != 0) {
			rc = -errno;
			close(path_fd);
			return rc;
		}
		if (!S_ISREG(spec->target_stat.st_mode)) {
			close(path_fd);
			return -ESTALE;
		}
		snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", path_fd);
		fd = open(proc_path, O_RDONLY | O_CLOEXEC);
		close(path_fd);
		if (fd < 0)
			return -errno;
		if (fstat(fd, &opened_stat) != 0) {
			rc = -errno;
			close(fd);
			return rc;
		}
		if (opened_stat.st_dev != spec->target_stat.st_dev ||
		    opened_stat.st_ino != spec->target_stat.st_ino) {
			close(fd);
			return -ESTALE;
		}
		for (uint32_t j = 0; j < spec->nr_uprobe_offsets; j++) {
			if (spec->uprobe_offsets[j] >= (uint64_t)opened_stat.st_size) {
				close(fd);
				return -ERANGE;
			}
		}
		rc = shirudo_elf_build_id_fd(fd, build_id, &build_id_len);
		if (rc) {
			close(fd);
			return rc == -EACCES || rc == -EPERM ? rc : -ESTALE;
		}
		if (build_id_len != spec->build_id_len ||
		    memcmp(build_id, spec->build_id, build_id_len) != 0) {
			close(fd);
			return -ESTALE;
		}
		spec->target_fd = fd;
	}
	return 0;
}

static int prog_attach_uprobe_multi(int prog_fd,
				    const struct shirudo_prog_spec *spec)
{
	union bpf_attr attr = {};
	struct stat path_stat;
	long fd;
	int first_err;

	if (spec->target_fd < 0 || !spec->uprobe_path ||
	    !spec->uprobe_offsets || !spec->nr_uprobe_offsets)
		return -EINVAL;
	attr.link_create.prog_fd = (uint32_t)prog_fd;
	attr.link_create.attach_type = BPF_TRACE_UPROBE_MULTI;
	attr.link_create.uprobe_multi.offsets =
		(uint64_t)(uintptr_t)spec->uprobe_offsets;
	attr.link_create.uprobe_multi.cnt = spec->nr_uprobe_offsets;
	attr.link_create.uprobe_multi.flags = BPF_F_UPROBE_MULTI_PATH_FD;
	attr.link_create.uprobe_multi.path_fd = (uint32_t)spec->target_fd;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	if (fd >= 0)
		return (int)fd;
	first_err = errno;
	if (first_err != EINVAL && first_err != EOPNOTSUPP)
		return -first_err;

	/*
	 * Older uprobe.multi kernels accept only a pathname. Make sure the
	 * current name still resolves to the inode whose build ID was checked
	 * before falling back; the path-fd ABI remains the preferred path.
	 */
	if (stat(spec->uprobe_path, &path_stat) != 0)
		return -errno;
	if (path_stat.st_dev != spec->target_stat.st_dev ||
	    path_stat.st_ino != spec->target_stat.st_ino)
		return -ESTALE;
	pr_warn("uprobe.multi path-fd attach unsupported; falling back to pathname for %s",
		spec->uprobe_path);
	memset(&attr, 0, sizeof(attr));
	attr.link_create.prog_fd = (uint32_t)prog_fd;
	attr.link_create.attach_type = BPF_TRACE_UPROBE_MULTI;
	attr.link_create.uprobe_multi.path =
		(uint64_t)(uintptr_t)spec->uprobe_path;
	attr.link_create.uprobe_multi.offsets =
		(uint64_t)(uintptr_t)spec->uprobe_offsets;
	attr.link_create.uprobe_multi.cnt = spec->nr_uprobe_offsets;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	if (fd >= 0)
		return (int)fd;
	if (errno == EINVAL || errno == EOPNOTSUPP)
		return -EOPNOTSUPP;
	return -errno;
}

static int prog_attach_for_spec(int prog_fd,
				const struct shirudo_prog_spec *spec)
{
	int perf_fd, link_fd;

	switch (spec->kind) {
	case SHIRUDO_UPATCH_ATTACH_RAW_TRACEPOINT:
		return prog_attach_default(prog_fd);
	case SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_INGRESS:
		return prog_attach_cgroup_skb(prog_fd,
					      BPF_CGROUP_INET_INGRESS);
	case SHIRUDO_UPATCH_ATTACH_CGROUP_SKB_EGRESS:
		return prog_attach_cgroup_skb(prog_fd,
					      BPF_CGROUP_INET_EGRESS);
	case SHIRUDO_UPATCH_ATTACH_FMOD_RET:
		return prog_attach_btf_link_or_raw_tp(prog_fd,
						      BPF_MODIFY_RETURN);
	case SHIRUDO_UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
		return prog_attach_netfilter_ipv6_pre_routing(prog_fd);
	case SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI:
		return prog_attach_uprobe_multi(prog_fd, spec);
	case SHIRUDO_UPATCH_ATTACH_KPROBE:
	case SHIRUDO_UPATCH_ATTACH_KRETPROBE:
		perf_fd = perf_event_open_kprobe(spec->target, spec->offset,
				spec->kind == SHIRUDO_UPATCH_ATTACH_KRETPROBE);
		if (perf_fd < 0)
			return perf_fd;
		link_fd = prog_attach_perf_event(prog_fd, perf_fd);
		close(perf_fd);
		return link_fd;
	default:
		return -EINVAL;
	}
}

static int obj_pin(int fd, const char *path)
{
	union bpf_attr attr = {};
	long ret;

	attr.pathname = (uint64_t)(uintptr_t)path;
	attr.bpf_fd = (uint32_t)fd;
	ret = syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
	return ret >= 0 ? 0 : -errno;
}

static int mkdir_if_absent(const char *path, mode_t mode)
{
	if (mkdir(path, mode) == 0 || errno == EEXIST)
		return 0;
	return -errno;
}

static void count_attach_progs(const struct shirudo_prog_spec *specs,
			       uint32_t nr_progs, uint32_t *out)
{
	uint32_t i, n = 0;

	for (i = 0; i < nr_progs; i++) {
		if (specs[i].role == SHIRUDO_UPATCH_PROG_ROLE_ATTACH)
			n++;
	}
	*out = n;
}

/*
 * Attach or pin each inner program according to the upatch program
 * metadata. Attached programs get pinned links; serializer programs are
 * pinned as programs and invoked later by `shirudo upatch map`.
 */
static int attach_and_pin_progs(const struct shirudo_loader_ctx *cx,
				size_t prog_desc_off, uint32_t nr_progs,
				const char *name,
				const struct shirudo_prog_spec *specs)
{
	char dir[PATH_MAX], serializers_dir[PATH_MAX + 16];
	char pin[PATH_MAX + 32];
	uint32_t i, attach_count = 0, attach_seen = 0;
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
	count_attach_progs(specs, nr_progs, &attach_count);
	if (snprintf(serializers_dir, sizeof(serializers_dir),
		     "%s/serializers", dir) >= (int)sizeof(serializers_dir))
		return -ENAMETOOLONG;

	for (i = 0; i < nr_progs; i++) {
		const struct shirudo_prog_desc *pd =
			(const void *)((const char *)cx + prog_desc_off +
				       (size_t)i * sizeof(*pd));
		int inner_fd = pd->prog_fd;
		const struct shirudo_prog_spec *spec = &specs[i];
		int link_fd;

		if (inner_fd <= 0) {
			pr_err("loader produced no fd for prog %u", i);
			return -EINVAL;
		}
		if (spec->role == SHIRUDO_UPATCH_PROG_ROLE_SERIALIZER) {
			struct stat st;

			rc = mkdir_if_absent(serializers_dir, 0700);
			if (rc) {
				pr_err("mkdir %s: %s", serializers_dir,
				       strerror(-rc));
				return rc;
			}
			if (snprintf(pin, sizeof(pin), "%s/%s",
				     serializers_dir, spec->map) >=
			    (int)sizeof(pin))
				return -ENAMETOOLONG;
			if (stat(pin, &st) == 0)
				continue;	/* idempotent re-run */
			rc = obj_pin(inner_fd, pin);
			if (rc) {
				pr_err("pin serializer %s: %s", pin,
				       strerror(-rc));
				return rc;
			}
			pr_info("pinned serializer prog %u -> %s", i, pin);
			continue;
		}
		if (attach_count == 1)
			snprintf(pin, sizeof(pin), "%s/link", dir);
		else
			snprintf(pin, sizeof(pin), "%s/link_%u", dir,
				 attach_seen);
		attach_seen++;

		link_fd = prog_attach_for_spec(inner_fd, spec);
		if (link_fd < 0) {
			if (spec->kind == SHIRUDO_UPATCH_ATTACH_UPROBE_MULTI)
				pr_err("attach prog %u (%s %s:%s): %s", i,
				       attach_kind_name(spec->kind),
				       spec->uprobe_path, spec->target,
				       strerror(-link_fd));
			else if (spec->target[0])
				pr_err("attach prog %u (%s %s): %s",
				       i, attach_kind_name(spec->kind),
				       spec->target, strerror(-link_fd));
			else
				pr_err("attach prog %u (%s): %s",
				       i, attach_kind_name(spec->kind),
				       strerror(-link_fd));
			return link_fd;
		}
		rc = obj_pin(link_fd, pin);
		if (rc) {
			pr_err("pin %s: %s", pin, strerror(-rc));
			close(link_fd);
			return rc;
		}
		close(link_fd);
		pr_info("attached + pinned prog %u (%s) -> %s",
			i, attach_kind_name(spec->kind), pin);
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
 *  - names containing '.' (bpffs reserves dots in path components;
 *    libbpf synthetic global-data maps such as .bss use them)
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
		if (strchr(info.name, '.'))
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
 * attacker cannot forge it. Not fatal -- the load already succeeded and
 * there is nothing to roll back -- but unload is fail-closed on a
 * missing value, so a failure here is an error, not a warning: it leaves
 * <name> loaded and un-unloadable through the normal path.
 */
static void set_pin_payload(const char *name, const uint8_t payload[32])
{
	char dir[PATH_MAX];

	if (snprintf(dir, sizeof(dir), "%s/%s", SHIRUDO_BPFFS_UPATCHES_DIR,
		     name) >= (int)sizeof(dir))
		return;
	if (setxattr(dir, SHIRUDO_XATTR_PAYLOAD, payload, 32, 0) != 0)
		pr_err("upatch: cannot record payload xattr on %s: %s "
		       "(unload of this upatch will refuse)",
		       dir, strerror(errno));
}

/*
 * Read the payload_sha256 recorded on <name>'s pin directory. Returns 0
 * and fills out on success, -ENOENT if the pin dir is gone, -ENODATA if
 * the xattr is absent, or another -errno.
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
	struct shirudo_prog_spec *prog_specs = NULL;
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
	 * Bind the recorded identity to the signed bytes: the header's
	 * payload_sha256 must equal SHA-256(insns || data), the exact
	 * content the kernel folds and verifies below. The signature is
	 * authoritative for the load itself, but payload_sha256 is what
	 * shirudo records as the pin xattr, the chain event, and the unload
	 * match target -- so a corrupted or mis-set header value must not be
	 * trusted as identity even if the signature is valid.
	 */
	{
		uint8_t content_digest[SHIRUDO_UPATCH_PAYLOAD_HASH_LEN];

		shirudo_sha256_2(insns, u.hdr.loader_insns_len,
				 data, u.hdr.data_len, content_digest);
		if (!shirudo_ct_eq(content_digest, u.hdr.payload_sha256,
				   sizeof(content_digest))) {
			pr_err("upatch: payload_sha256 does not match signed "
			       "content (insns || data); refusing");
			rep_fail(rep, "parse", "parser_rejected", 0,
				 "payload_sha256 mismatch");
			rc = 1;
			goto out;
		}
	}

	/*
	 * Program metadata is intentionally outside the loader signature, so
	 * parse it strictly and bind every uprobe target to its recorded GNU
	 * build ID before loading any BPF program. Open target fds stay live
	 * through link creation to prevent pathname replacement races.
	 */
	if (!verify_only) {
		rc = prog_specs_parse(shirudo_upatch_metadata(&u),
				      u.hdr.metadata_len, u.hdr.nr_progs,
				      &prog_specs);
		if (rc) {
			pr_err("upatch program metadata rejected: %s",
			       strerror(-rc));
			rep_fail(rep, "parse", "parser_rejected", -rc,
				 "invalid program attach metadata");
			rc = 1;
			goto out;
		}
		rc = prepare_uprobe_targets(prog_specs, u.hdr.nr_progs);
		if (rc) {
			int e = -rc;
			const char *cat;

			if (e == ENOENT || e == ENOTDIR)
				cat = "attach_target_missing";
			else if (e == ESTALE)
				cat = "binary_mismatch";
			else if (e == EACCES || e == EPERM)
				cat = "lsm_denied";
			else if (e == ERANGE || e == EINVAL || e == E2BIG)
				cat = "parser_rejected";
			else
				cat = "unknown";
			pr_err("uprobe target verification failed (%s): %s",
			       cat, strerror(e));
			rep_fail(rep, "target_verify", cat, e,
				 "uprobe target verification failed");
			rc = 1;
			goto out;
		}
	}

	/*
	 * 1. Create __loader.map bound to the loader's own digest
	 *    (excl_prog_hash = SHA-256(insns)). The verifier enforces
	 *    map->excl_prog_sha == prog->digest, so this frozen metadata map
	 *    can be used by exactly this signed loader and no other program.
	 *    Note this is the digest of the instructions alone -- distinct
	 *    from payload_sha256, which covers insns || data.
	 */
	{
		uint8_t loader_digest[SHIRUDO_UPATCH_PAYLOAD_HASH_LEN];

		shirudo_sha256(insns, u.hdr.loader_insns_len, loader_digest);
		map_fd = loader_map_create("__loader.map", u.hdr.data_len,
					   loader_digest, sizeof(loader_digest));
	}
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

	/*
	 * 3. Freeze: userspace can no longer mutate the metadata map, so the
	 *    bytes the kernel folds into the signature cannot change before
	 *    the loader runs. The kernel refuses a signed load whose bound
	 *    map is not frozen.
	 */
	rc = loader_map_freeze(map_fd);
	if (rc) {
		pr_err("__loader.map freeze: %s", strerror(errno));
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(errno),
			 errno, "__loader.map freeze failed");
		rc = 1;
		goto out;
	}

	/*
	 * 4. BPF_PROG_LOAD with signature + keyring_id + fd_array_cnt=1.
	 *    The kernel resolves the exclusive metadata map from fd_array,
	 *    appends its frozen contents to the instructions, and verifies
	 *    the CMS signature over insns || metadata against the keyring --
	 *    all before the verifier proper and the lsm/bpf_prog_load
	 *    admission hook run. The loader carries no metadata self-check;
	 *    the kernel attests the metadata directly (see
	 *    Documentation/bpf/signing.rst, "Load-time verification").
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
	/*
	 * Keep inner verifier diagnostics enabled without bpftool's full
	 * accepted-program trace; the verbose mode can make valid payload
	 * loads fail with -ENOSPC when the log buffer fills.
	 */
	cx->log_level = 1;
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
				  upatch_name, prog_specs);
	if (rc) {
		int e = -rc;
		const char *cat;

		if (e == ENOENT || e == ENOTDIR)
			cat = "attach_target_missing";
		else if (e == ESTALE)
			cat = "binary_mismatch";
		else if (e == EOPNOTSUPP)
			cat = "kernel_abi_unsupported";
		else if (e == EACCES || e == EPERM)
			cat = "lsm_denied";
		else
			cat = "unknown";

		rep_fail(rep, "link_create", cat, e, "attach or pin failed");
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
	 * the value reflects an actually-loaded upatch (no rollback window).
	 */
	set_pin_payload(upatch_name, u.hdr.payload_sha256);

	pr_audit("upatch load: name=%s keyring=%d progs=%u", upatch_name,
		 (int)keyring, u.hdr.nr_progs);
	if (rep)
		rep->loader_return = (int32_t)retval;
	rc = 0;
out:
	prog_specs_free(prog_specs, u.hdr.nr_progs);
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
 * Runs before any BPF_PROG_LOAD: the live kernel must expose the private
 * signed-loader ABI, the shirudo keyring must exist, the LSM link must still
 * be pinned (enforcing), and -- when the caller supplied --expect-chain --
 * the live TPM NV chain must still match what the operator last observed.
 * An ABI mismatch is kernel_abi_unsupported; state mismatches are tampered.
 * No kernel state is touched. This is the optimistic-concurrency / tamper
 * gate: a concurrent operator that advanced the chain, a detached LSM, or a
 * missing keyring all surface here. Returns 0 to proceed.
 */
static int upatch_preflight(const char *expect_chain,
			    struct shirudo_op_report *rep)
{
	uint8_t want[SHIRUDO_CHAIN_DIGEST_LEN], have[SHIRUDO_CHAIN_DIGEST_LEN];
	char have_hex[2 * SHIRUDO_CHAIN_DIGEST_LEN + 1];
	char abi_detail[SHIRUDO_KERNEL_ABI_DETAIL_MAX];
	int fd, rc;

	rc = shirudo_kernel_abi_check(abi_detail, sizeof(abi_detail));
	if (rc) {
		pr_err("upatch: pre-flight refused (category: "
		       "kernel_abi_unsupported, message: %s)", abi_detail);
		rep_fail(rep, "pre_flight", "kernel_abi_unsupported",
			 EOPNOTSUPP, abi_detail);
		return rc;
	}

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

/* Append one complete JSON document as an NDJSON record. */
static int append_json_record(const char *path, const char *json, size_t len)
{
	struct stat st;
	char last;
	off_t original_size;
	int fd, rc = 0;

	if (!path || !path[0] || !json)
		return -EINVAL;
	fd = open(path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;
	while (flock(fd, LOCK_EX) != 0) {
		if (errno != EINTR) {
			rc = -errno;
			goto out;
		}
	}
	if (fstat(fd, &st) != 0) {
		rc = -errno;
		goto out_unlock;
	}
	if (!S_ISREG(st.st_mode)) {
		rc = -EINVAL;
		goto out_unlock;
	}
	original_size = st.st_size;
	if (original_size > 0) {
		ssize_t n = pread(fd, &last, 1, original_size - 1);

		if (n != 1) {
			rc = n < 0 ? -errno : -EIO;
			goto out_unlock;
		}
		if (last != '\n')
			rc = write_all(fd, "\n", 1);
	}
	if (!rc)
		rc = write_all(fd, json, len);
	if (!rc)
		rc = write_all(fd, "\n", 1);
	if (!rc && fsync(fd) != 0)
		rc = -errno;
	if (rc && ftruncate(fd, original_size) != 0)
		pr_warn("upatch map: could not roll back partial JSON append to %s: %s",
			path, strerror(errno));
out_unlock:
	(void)flock(fd, LOCK_UN);
out:
	if (close(fd) != 0 && !rc)
		rc = -errno;
	return rc;
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
	char serializers_dir[PATH_MAX + 16];
	struct stat st;
	int rc;

	if (snprintf(dir, sizeof(dir), "%s/%s", SHIRUDO_BPFFS_UPATCHES_DIR,
		     name) >= (int)sizeof(dir))
		return -ENAMETOOLONG;
	if (snprintf(maps_dir, sizeof(maps_dir), "%s/maps", dir) >=
	    (int)sizeof(maps_dir))
		return -ENAMETOOLONG;
	if (snprintf(serializers_dir, sizeof(serializers_dir),
		     "%s/serializers", dir) >= (int)sizeof(serializers_dir))
		return -ENAMETOOLONG;
	if (stat(dir, &st) != 0)
		return -errno;
	/*
	 * Child pin directories must be torn down before the top dir, so
	 * the parent isn't holding unwipeable subdirs when we rmdir it.
	 */
	if (stat(maps_dir, &st) == 0) {
		rc = wipe_dir_flat(maps_dir);
		if (rc)
			return rc;
	}
	if (stat(serializers_dir, &st) == 0) {
		rc = wipe_dir_flat(serializers_dir);
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
	} else if (upatch_preflight(expect_chain, &rep) != 0) {
		if (!rep.category)
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
	} else if (upatch_preflight(expect_chain, &rep) != 0) {
		if (!rep.category)
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
	 * <name> is the one the directive was signed to remove. The live
	 * value is the xattr bpf2 protects on the pin dir (unforgeable). The
	 * expected value read here is the directive's unsigned metadata
	 * blob; a signature-covered copy also rides in the loader's .rodata
	 * (inside insns || data), but the in-kernel detach that would read
	 * it back is not implementable yet (TODO.kernel item 6), so this
	 * catches honest/accidental substitution, not a root attacker who
	 * edits both the metadata and the expected value in lockstep.
	 * Fail-closed: a live pin whose payload cannot be read is refused.
	 * -ENOENT means there is no pin dir at all, which falls through to
	 * the idempotent already_unloaded path below. Skipped only when the
	 * directive carries no expected payload (all-zero).
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
		} else if (xrc != -ENOENT) {
			pr_err("upatch unload: cannot read the payload "
			       "recorded for '%s': %s; refusing", name,
			       strerror(-xrc));
			rep_fail(&rep, "pin", "payload_mismatch", -xrc,
				 "payload xattr unreadable");
			goto done;
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

static void dump_line_info_text(struct li_entry *ents, uint32_t k)
{
	const char *last = NULL;
	uint32_t i;

	if (k == 0) {
		printf("  (no line info)\n");
		return;
	}
	for (i = 0; i < k; i++) {
		if (!last || strcmp(ents[i].file, last) != 0) {
			printf("  %s:\n", ents[i].file);
			last = ents[i].file;
		}
		printf("    %5u: %s\n", ents[i].line, ents[i].src);
	}
}

/*
 * Emit a {"files":[{"path":..., "lines":[{line, src}, ...]}, ...]}
 * object body inside the caller's open "source" key. ents is the
 * file-then-line sorted unique tuple list from li_collect().
 */
static void emit_line_info_json(struct shirudo_json_emit *e,
				struct li_entry *ents, uint32_t k)
{
	uint32_t i = 0;

	shirudo_json_arr_open(e, "files");
	while (i < k) {
		const char *path = ents[i].file;
		uint32_t j;

		shirudo_json_obj_open(e);
		shirudo_json_kv_string(e, "path", path);
		shirudo_json_arr_open(e, "lines");
		for (j = i; j < k && strcmp(ents[j].file, path) == 0; j++) {
			shirudo_json_obj_open(e);
			shirudo_json_kv_int(e, "line", ents[j].line);
			shirudo_json_kv_string(e, "src", ents[j].src);
			shirudo_json_obj_close(e);
		}
		shirudo_json_arr_close(e);
		shirudo_json_obj_close(e);
		i = j;
	}
	shirudo_json_arr_close(e);
}

/* Build and append one detailed schema-1 map snapshot. */
static int append_one_map_json(const char *path,
			       const struct shirudo_map_view *v)
{
	char *decoded = NULL;
	size_t decoded_len = 0;
	int rc;

	rc = shirudo_upatch_decode_map_json(v, &decoded, &decoded_len);
	if (rc == 0) {
		while (decoded_len && (decoded[decoded_len - 1] == '\n' ||
		       decoded[decoded_len - 1] == '\r'))
			decoded_len--;
		rc = append_json_record(path, decoded, decoded_len);
		xfree(decoded, decoded_len + 1);
		return rc;
	}
	return rc;
}

static int export_one_map(const char *upatch, const char *map,
			  const char *json_path, bool otel,
			  const struct shirudo_otel_opts *otel_opts,
			  bool show_full, bool print_detail)
{
	struct shirudo_map_view v = {};
	uint32_t cap = (show_full || json_path || otel) ? 0 :
		SHIRUDO_MAP_ENTRIES_DEFAULT;
	int rc, ret = 0;

	rc = shirudo_upatch_maps_read(upatch, map, cap, &v);
	if (rc) {
		pr_err("upatch map: read %s/%s: %s", upatch, map,
		       strerror(-rc));
		return 1;
	}
	if (json_path) {
		rc = append_one_map_json(json_path, &v);
		if (rc) {
			pr_err("upatch map: append JSON to %s: %s",
			       json_path, strerror(-rc));
			ret = 1;
		}
	}
	if (otel) {
		uint32_t decoder_signal;

		rc = shirudo_upatch_decode_map_signal(&v, &decoder_signal);
		if (!rc)
			rc = shirudo_upatch_maps_otel_send_decoded(&v, decoder_signal,
							    otel_opts);
		if (rc) {
			pr_err("upatch map: OTLP export %s/%s: %s", upatch, map,
			       strerror(-rc));
			ret = 1;
		}
	}
	if (print_detail) {
		shirudo_upatch_maps_print_detail(&v);
		if (ferror(stdout))
			ret = 1;
	}
	shirudo_map_view_free(&v);
	return ret;
}

static int cmd_upatch_map(int argc, const char **argv)
{
	struct shirudo_map_summary *list = NULL;
	struct shirudo_config export_cfg = {};
	struct shirudo_otel_opts otel_opts = {
		.retries = 3,
	};
	const char *upatch = NULL, *map = NULL, *json_path = NULL;
	bool all = false, show_full = false, otel = false;
	bool insecure_set = false;
	bool retries_set = false;
	size_t n = 0;
	int i, ret = 0;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (shirudo_is_help(a)) {
			shirudo_print_help(&upatch_map_help);
			return 0;
		}
		if (strcmp(a, "--all") == 0) {
			if (all) {
				fprintf(stderr, "upatch map: duplicate --all\n");
				return 2;
			}
			all = true;
		} else if (strncmp(a, "--json=", 7) == 0) {
			if (json_path || !a[7]) {
				fprintf(stderr,
					"upatch map: invalid or duplicate --json\n");
				return 2;
			}
			json_path = a + 7;
		} else if (strcmp(a, "--json") == 0) {
			fprintf(stderr, "upatch map: --json requires a path\n");
			return 2;
		} else if (strcmp(a, "--show-full") == 0) {
			show_full = true;
		} else if (strcmp(a, "--otel") == 0) {
			if (otel) {
				fprintf(stderr, "upatch map: duplicate --otel\n");
				return 2;
			}
			otel = true;
		} else if (strncmp(a, "--otel-endpoint=", 16) == 0) {
			if (otel_opts.endpoint || !a[16]) {
				fprintf(stderr, "upatch map: invalid or duplicate "
					"--otel-endpoint\n");
				return 2;
			}
			otel_opts.endpoint = a + 16;
		} else if (strncmp(a, "--tenant-id=", 12) == 0) {
			if (otel_opts.tenant_id ||
			    !shirudo_tenant_id_valid(a + 12)) {
				fprintf(stderr, "upatch map: invalid or duplicate "
					"--tenant-id; expected 1..128 characters using "
					"A-Z, a-z, 0-9, '.', '_', or '-'\n");
				return 2;
			}
			otel_opts.tenant_id = a + 12;
		} else if (strcmp(a, "--otel-insecure") == 0) {
			if (insecure_set) {
				fprintf(stderr, "upatch map: duplicate --otel-insecure\n");
				return 2;
			}
			insecure_set = true;
			otel_opts.allow_insecure = true;
		} else if (strncmp(a, "--otel-retries=", 15) == 0) {
			char *end;
			unsigned long value;

			if (retries_set || !a[15]) {
				fprintf(stderr, "upatch map: invalid or duplicate "
					"--otel-retries\n");
				return 2;
			}
			errno = 0;
			value = strtoul(a + 15, &end, 10);
			if (errno || *end || value > 10) {
				fprintf(stderr, "upatch map: --otel-retries must be 0..10\n");
				return 2;
			}
			otel_opts.retries = (unsigned int)value;
			retries_set = true;
		} else if (strncmp(a, "--s3-uri=", 9) == 0) {
			if (otel_opts.s3_uri || !a[9]) {
				fprintf(stderr, "upatch map: invalid or duplicate "
					"--s3-uri\n");
				return 2;
			}
			otel_opts.s3_uri = a + 9;
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
	if (all) {
		int rc = shirudo_config_load(&export_cfg);

		if (rc) {
			pr_err("upatch map: load export configuration: %s",
			       strerror(-rc));
			return 1;
		}
		if (!export_cfg.map_export_valid) {
			pr_err("upatch map: invalid map_export configuration");
			return 2;
		}
		if (!json_path && export_cfg.map_export_json_path[0])
			json_path = export_cfg.map_export_json_path;
		if (!otel && export_cfg.map_export_otel_endpoint[0]) {
			otel = true;
		}
		if (otel) {
			if (!otel_opts.endpoint &&
			    export_cfg.map_export_otel_endpoint[0])
				otel_opts.endpoint =
					export_cfg.map_export_otel_endpoint;
			if (!otel_opts.tenant_id &&
			    export_cfg.map_export_tenant_id[0])
				otel_opts.tenant_id =
					export_cfg.map_export_tenant_id;
			if (!insecure_set)
				otel_opts.allow_insecure =
					export_cfg.map_export_otel_insecure;
			if (!retries_set)
				otel_opts.retries =
					export_cfg.map_export_otel_retries;
			if (!otel_opts.s3_uri && export_cfg.map_export_s3_uri[0])
				otel_opts.s3_uri = export_cfg.map_export_s3_uri;
		}
	}

	{
		if ((otel_opts.endpoint || otel_opts.tenant_id || insecure_set ||
		     retries_set ||
		     otel_opts.s3_uri) && !otel) {
			fprintf(stderr, "upatch map: OTLP options require --otel\n");
			return 2;
		}
		if (all && (upatch || map)) {
			fprintf(stderr,
				"upatch map: --all does not accept positional arguments\n");
			return 2;
		}
		if (otel && !all && (!upatch || !map)) {
			fprintf(stderr, "upatch map: --otel requires <upatch> and <map>\n");
			return 2;
		}
	}
	if (all && !json_path && !otel)
		return 0;

	if (upatch && map) {
		if (!safe_upatch_name(upatch)) {
			pr_err("upatch map: invalid upatch name '%s'", upatch);
			return 2;
		}
		return export_one_map(upatch, map, json_path, otel,
				      &otel_opts, show_full,
				      !json_path && !otel);
	}

	if (all) {
		size_t k;

		shirudo_upatch_maps_list_all(&list, &n);
		for (k = 0; k < n; k++) {
			if (export_one_map(list[k].upatch, list[k].name,
					   json_path, otel, &otel_opts,
					   show_full, false) != 0)
				ret = 1;
		}
		shirudo_map_summary_free(list, n);
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

	if (json_path) {
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
		if (e.err) {
			ret = 1;
		} else {
			int rc = append_json_record(json_path, buf, e.len);

			if (rc) {
				pr_err("upatch map: append JSON to %s: %s",
				       json_path, strerror(-rc));
				ret = 1;
			}
		}
		xfree(buf, cap);
	} else {
		shirudo_upatch_maps_print_summary(list, n);
	}
	shirudo_map_summary_free(list, n);
	return ret;
}

/*
 * Format a payload SHA-256 (32 raw bytes) as lowercase hex; "" if the
 * xattr is not readable (upatch not loaded, or value never recorded).
 */
static void payload_hex(const char *upatch, char *out, size_t cap)
{
	uint8_t raw[32];
	int rc = get_pin_payload(upatch, raw);
	size_t i;

	out[0] = '\0';
	if (rc != 0)
		return;
	if (cap < 65)
		return;
	for (i = 0; i < 32; i++)
		snprintf(out + 2 * i, cap - 2 * i, "%02x", raw[i]);
}

struct upatch_get_ctx {
	const char	*upatch;
	uint32_t	prog_id;
	char		location[160];
	char		loaded_at[32];
	char		payload[65];
	struct li_entry	*ents;	/* sorted unique source lines */
	uint32_t	n_ents;
	uint32_t	n_recs;	/* raw line_info record count, for free() */
	struct btf	*btf;
};

static void upatch_get_ctx_free(struct upatch_get_ctx *c)
{
	if (c->ents)
		xfree(c->ents, (size_t)c->n_recs * sizeof(*c->ents));
	if (c->btf)
		btf__free(c->btf);
	c->ents = NULL;
	c->btf = NULL;
}

/*
 * Populate the ctx: open the pin, read link+prog info, load BTF,
 * collect line_info. Returns 0 on success; -errno on failure. On
 * partial failure (e.g. no line_info), still returns 0 and leaves
 * the source-related fields empty so the caller can render the rest.
 */
static int upatch_get_collect(const char *want, struct upatch_get_ctx *c)
{
	struct bpf_link_info linfo = {};
	struct bpf_prog_info info = {};
	struct btf *vbtf = NULL;
	void *recs = NULL;
	size_t recs_sz = 0;
	uint32_t len, nr, rec_size, btf_id;
	int link_fd = -1, prog_fd = -1, rc = 0;

	c->upatch = want;
	c->ents = NULL;
	c->n_ents = 0;
	c->n_recs = 0;
	c->btf = NULL;
	c->location[0] = '\0';
	c->loaded_at[0] = '\0';
	c->payload[0] = '\0';
	c->prog_id = 0;

	link_fd = shirudo_upatch_open_first_link(want);
	if (link_fd < 0)
		return link_fd;
	len = sizeof(linfo);
	if (bpf_link_get_info_by_fd(link_fd, &linfo, &len) != 0) {
		rc = -errno;
		close(link_fd);
		return rc;
	}
	close(link_fd);
	if (linfo.prog_id == 0)
		return -EINVAL;
	c->prog_id = linfo.prog_id;
	shirudo_upatch_loaded_at(want, c->loaded_at, sizeof(c->loaded_at));
	payload_hex(want, c->payload, sizeof(c->payload));

	vbtf = btf__load_vmlinux_btf();
	shirudo_upatch_resolve_location(vbtf, want, c->location,
					sizeof(c->location));
	if (vbtf)
		btf__free(vbtf);

	prog_fd = bpf_prog_get_fd_by_id(linfo.prog_id);
	if (prog_fd < 0)
		return -errno;
	len = sizeof(info);
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len) != 0) {
		rc = -errno;
		close(prog_fd);
		return rc;
	}
	nr = info.nr_line_info;
	rec_size = info.line_info_rec_size;
	btf_id = info.btf_id;
	if (nr == 0 || btf_id == 0 || rec_size == 0) {
		close(prog_fd);
		return 0;	/* no source -- still a usable get */
	}
	recs_sz = (size_t)nr * rec_size;
	recs = xmalloc(recs_sz);
	if (!recs) {
		close(prog_fd);
		return -ENOMEM;
	}
	memset(&info, 0, sizeof(info));
	info.nr_line_info = nr;
	info.line_info_rec_size = rec_size;
	info.line_info = (uint64_t)(unsigned long)recs;
	len = sizeof(info);
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len) != 0) {
		rc = -errno;
		xfree(recs, recs_sz);
		close(prog_fd);
		return rc;
	}
	close(prog_fd);
	c->btf = btf__load_from_kernel_by_id(btf_id);
	if (!c->btf) {
		xfree(recs, recs_sz);
		return -errno;
	}
	c->n_recs = nr;
	c->n_ents = li_collect(c->btf, recs, rec_size, nr, &c->ents);
	xfree(recs, recs_sz);
	return 0;
}

/* "since <ts>" human helper. "" if ts is empty / unparseable. */
static void age_from_ts(const char *ts, char *out, size_t cap)
{
	struct tm tm = {};

	out[0] = '\0';
	if (!ts || !ts[0])
		return;
	if (!strptime(ts, "%Y-%m-%dT%H:%M:%SZ", &tm))
		return;
	shirudo_format_duration((long)(time(NULL) - timegm(&tm)), out, cap);
}

/* Text render of one map; cap=0 means "lift the truncation". */
static void render_one_map_text(const char *upatch, const char *map,
				uint32_t cap)
{
	struct shirudo_map_view v = {};
	int rc = shirudo_upatch_maps_read(upatch, map,
					  cap,
					  &v);

	printf("\n== Map: %s ==\n", map);
	if (rc != 0) {
		printf("  (read failed: %s)\n", strerror(-rc));
		shirudo_map_view_free(&v);
		return;
	}
	shirudo_upatch_maps_print_detail(&v);
	shirudo_map_view_free(&v);
}

/* Text render of the bundled get document. */
static void render_get_text(const struct upatch_get_ctx *c,
			    const struct shirudo_map_summary *maps, size_t nm,
			    uint32_t map_cap)
{
	char age[16] = "";
	size_t k;

	age_from_ts(c->loaded_at, age, sizeof(age));

	printf("upatch:        %s\n", c->upatch);
	printf("Location:      %s\n",
	       c->location[0] ? c->location : "?");
	printf("Prog id:       %u\n", c->prog_id);
	if (c->loaded_at[0])
		printf("Loaded at:     %s%s%s%s\n", c->loaded_at,
		       age[0] ? "  (" : "", age, age[0] ? " ago)" : "");
	if (c->payload[0])
		printf("Payload:       %s  (signature-bound)\n", c->payload);
	else
		printf("Payload:       (unavailable)\n");
	printf("Maps (%zu):    ", nm);
	for (k = 0; k < nm; k++)
		printf("%s%s", maps[k].name, k + 1 < nm ? ", " : "");
	printf("\n");

	printf("\nSource (kernel BTF line_info):\n\n");
	if (c->n_ents == 0)
		printf("  (no line info -- built without `clang -g`?)\n");
	else
		dump_line_info_text(c->ents, c->n_ents);

	for (k = 0; k < nm; k++)
		render_one_map_text(c->upatch, maps[k].name, map_cap);
}

/* JSON render of the bundled get document. */
static int render_get_json(const struct upatch_get_ctx *c,
			   const struct shirudo_map_summary *maps, size_t nm,
			   uint32_t map_cap)
{
	struct shirudo_json_emit e = {};
	size_t cap = 64 * 1024 + 1024 * nm;
	char age[16] = "";
	char *buf;
	size_t k;
	int ret = 0;

	if (cap > SHIRUDO_JSON_MAX_BYTES)
		cap = SHIRUDO_JSON_MAX_BYTES;
	buf = xmalloc(cap);
	if (!buf)
		return 1;
	e.buf = buf;
	e.cap = cap;

	age_from_ts(c->loaded_at, age, sizeof(age));

	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_obj_open_key(&e, "upatch");
	shirudo_json_kv_string(&e, "name", c->upatch);
	shirudo_json_kv_string(&e, "location", c->location);
	shirudo_json_kv_int(&e, "prog_id", c->prog_id);
	shirudo_json_kv_string(&e, "loaded_at", c->loaded_at);
	shirudo_json_kv_string(&e, "age", age);
	if (c->payload[0])
		shirudo_json_kv_string(&e, "payload_sha256", c->payload);
	else
		shirudo_json_kv_null(&e, "payload_sha256");
	shirudo_json_obj_open_key(&e, "source");
	emit_line_info_json(&e, c->ents, c->n_ents);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_open(&e, "maps");
	for (k = 0; k < nm; k++) {
		struct shirudo_map_view v = {};
		int rc;

		rc = shirudo_upatch_maps_read(c->upatch, maps[k].name,
					      map_cap,
					      &v);
		if (rc != 0) {
			shirudo_json_obj_open(&e);
			shirudo_json_kv_string(&e, "name", maps[k].name);
			shirudo_json_kv_string(&e, "type",
					       maps[k].type_name);
			shirudo_json_kv_int(&e, "max_entries",
					    maps[k].max_entries);
			shirudo_json_kv_string(&e, "error", strerror(-rc));
			shirudo_json_obj_close(&e);
		} else {
			shirudo_upatch_maps_emit_json_object(&e, &v);
		}
		shirudo_map_view_free(&v);
	}
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);	/* upatch */
	shirudo_json_obj_close(&e);	/* root */
	if (e.err) {
		fprintf(stderr, "upatch get: json encode failed: %s\n",
			strerror(-e.err));
		ret = 1;
	} else {
		printf("%s\n", buf);
	}
	xfree(buf, cap);
	return ret;
}

static int cmd_upatch_get(int argc, const char **argv)
{
	struct shirudo_map_summary *maps = NULL;
	struct upatch_get_ctx ctx = {};
	const char *want = NULL;
	bool json = false, show_full = false;
	size_t nm = 0;
	uint32_t map_cap;
	int rc, i;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (shirudo_is_help(a)) {
			shirudo_print_help(&upatch_get_help);
			return 0;
		}
		if (strcmp(a, "--json") == 0) {
			json = true;
		} else if (strcmp(a, "--show-full") == 0) {
			show_full = true;
		} else if (a[0] == '-') {
			fprintf(stderr, "upatch get: unknown option '%s'\n", a);
			return 2;
		} else if (!want) {
			want = a;
		} else {
			fprintf(stderr,
				"upatch get: unexpected argument '%s'\n", a);
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

	rc = upatch_get_collect(want, &ctx);
	if (rc != 0) {
		pr_err("upatch get: '%s': %s", want, strerror(-rc));
		upatch_get_ctx_free(&ctx);
		return 1;
	}
	shirudo_upatch_maps_list_one(want, &maps, &nm);
	map_cap = show_full ? 0 : SHIRUDO_MAP_ENTRIES_DEFAULT;

	if (json)
		rc = render_get_json(&ctx, maps, nm, map_cap);
	else
		render_get_text(&ctx, maps, nm, map_cap), rc = 0;

	shirudo_map_summary_free(maps, nm);
	upatch_get_ctx_free(&ctx);
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
