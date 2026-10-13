// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Operator-side BPM package builder.  The format intentionally mirrors the
 * standalone Go builder: a Beefile describes ordinary files and upatches,
 * shirudo-build creates the signed upatches, and the result is a deterministic
 * gzip-compressed ustar archive.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "builtin.h"
#include "util/crypto.h"
#include "util/json.h"
#include "util/paths.h"
#include "util/upatch.h"

#ifndef SHIRUDO_LIBEXEC_DIR
#define SHIRUDO_LIBEXEC_DIR "/usr/local/libexec/shirudo"
#endif

#define BPM_BUILD_MAX_ENTRIES 128
#define BPM_BUILD_MAX_FILE (256u * 1024u * 1024u)
#define BPM_BUILD_MAX_JSON (256u * 1024u)
#define BPM_BUILD_MAX_VALUE 1024

extern const char shirudo_version[];

struct bpm_build_file {
	char source[PATH_MAX];
	char target[PATH_MAX];
};

struct bpm_build_upatch {
	char source[PATH_MAX];
	char type[16];
	char load_target[PATH_MAX];
	char unload_target[PATH_MAX];
	char load_path[PATH_MAX];
	char unload_path[PATH_MAX];
	char name[SHIRUDO_UPATCH_NAME_MAX];
	char payload_sha256[SHIRUDO_CRYPTO_SHA256_LEN * 2 + 1];
};

struct bpm_build_spec {
	char name[128];
	char scope[PATH_MAX];
	unsigned char *build_file;
	size_t build_file_len;
	struct bpm_build_file files[BPM_BUILD_MAX_ENTRIES];
	size_t n_files;
	struct bpm_build_upatch upatches[BPM_BUILD_MAX_ENTRIES];
	size_t n_upatches;
};

static void build_copy(char *dst, size_t cap, const char *src)
{
	if (!cap)
		return;
	if (!src)
		src = "";
	snprintf(dst, cap, "%s", src);
}

static char *build_trim(char *s)
{
	char *end;

	while (isspace((unsigned char)*s))
		s++;
	end = s + strlen(s);
	while (end > s && isspace((unsigned char)end[-1]))
		*--end = '\0';
	return s;
}

static void build_strip_comment(char *s)
{
	bool basic = false, literal = false, escaped = false;

	for (; *s; s++) {
		if (escaped) {
			escaped = false;
			continue;
		}
		if (basic && *s == '\\') {
			escaped = true;
			continue;
		}
		if (!literal && *s == '"') {
			basic = !basic;
			continue;
		}
		if (!basic && *s == '\'') {
			literal = !literal;
			continue;
		}
		if (!basic && !literal && *s == '#') {
			*s = '\0';
			return;
		}
	}
}

static int build_read_file(const char *path, unsigned char **out, size_t *len,
			   size_t max)
{
	struct stat st;
	unsigned char *body;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) || st.st_size < 0 || (uintmax_t)st.st_size > max) {
		int rc = errno ? -errno : -E2BIG;

		close(fd);
		return rc;
	}
	body = malloc((size_t)st.st_size + 1);
	if (!body) {
		close(fd);
		return -ENOMEM;
	}
	n = 0;
	while ((size_t)n < (size_t)st.st_size) {
		ssize_t got = read(fd, body + n, (size_t)st.st_size - (size_t)n);

		if (got <= 0) {
			int rc = got < 0 ? -errno : -EIO;

			close(fd);
			free(body);
			return rc;
		}
		n += got;
	}
	close(fd);
	body[n] = '\0';
	*out = body;
	*len = (size_t)n;
	return 0;
}

static int build_parse_string(const char *value, char *out, size_t cap)
{
	const char *p = value;
	char quote;
	size_t n = 0;

	while (isspace((unsigned char)*p))
		p++;
	if (*p != '"' && *p != '\'')
		return -EINVAL;
	quote = *p++;
	while (*p && *p != quote) {
		unsigned char c = (unsigned char)*p++;

		if (c == '\\' && quote == '"') {
			c = (unsigned char)*p++;
			switch (c) {
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			case 't': c = '\t'; break;
			case '\\': case '"': break;
			default: return -EINVAL;
			}
		}
		if (n + 1 >= cap)
			return -ENAMETOOLONG;
		out[n++] = (char)c;
	}
	if (*p != quote)
		return -EINVAL;
	p++;
	while (isspace((unsigned char)*p))
		p++;
	if (*p)
		return -EINVAL;
	out[n] = '\0';
	return 0;
}

static int build_parse_value(const char *value, char *out, size_t cap,
			     bool array_ok)
{
	const char *p = value;

	while (isspace((unsigned char)*p))
		p++;
	if (array_ok && *p == '[') {
		const char *end = strrchr(p, ']');

		if (!end)
			return -EINVAL;
		while (isspace((unsigned char)end[1]))
			end++;
		return end[1] ? -EINVAL : 0;
	}
	return build_parse_string(value, out, cap);
}

static bool build_name_ok(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	if (!s || !*s || !isalnum((unsigned char)s[0]) || strlen(s) >= 128)
		return false;
	for (; *p; p++)
		if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-'))
			return false;
	return true;
}

static bool build_version_ok(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	if (!s || !*s || !isalnum((unsigned char)s[0]) || strlen(s) >= 128)
		return false;
	for (; *p; p++)
		if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-' || *p == '+'))
			return false;
	return true;
}

static int build_default_targets(struct bpm_build_upatch *u)
{
	char base[PATH_MAX];
	char *slash;

	build_copy(base, sizeof(base), u->source);
	slash = strrchr(base, '/');
	if (slash)
		memmove(base, slash + 1, strlen(slash + 1) + 1);
	if (strlen(base) > 6 && !strcmp(base + strlen(base) - 6, ".bpf.c"))
		base[strlen(base) - 6] = '\0';
	else if (strlen(base) > 6 && !strcmp(base + strlen(base) - 6, ".bpf.o"))
		base[strlen(base) - 6] = '\0';
	else {
		slash = strrchr(base, '.');
		if (slash)
			*slash = '\0';
	}
	if (!*base)
		return -EINVAL;
	if (!u->load_target[0] && snprintf(u->load_target, sizeof(u->load_target),
				"upatches/%s.upatch", base) >= (int)sizeof(u->load_target))
		return -ENAMETOOLONG;
	if (!u->unload_target[0] && snprintf(u->unload_target,
				 sizeof(u->unload_target), "upatches/%s.unload.upatch",
				 base) >= (int)sizeof(u->unload_target))
		return -ENAMETOOLONG;
	return 0;
}

static int build_parse_spec(struct bpm_build_spec *spec)
{
	char *body = (char *)spec->build_file;
	char *save = NULL, *line;
	char section[32] = {};
	struct bpm_build_file *file = NULL;
	struct bpm_build_upatch *upatch = NULL;

	for (line = strtok_r(body, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *s, *eq, *key, *value;

		build_strip_comment(line);
		s = build_trim(line);
		if (!*s)
			continue;
		if (s[0] == '[') {
			bool array = s[1] == '[';
			const char *start = s + (array ? 2 : 1);
			const char *close = array ? "]]" : "]";
			const char *end = strstr(start, close);

			if (!end || end[strlen(close)])
				return -EINVAL;
			if ((size_t)(end - start) >= sizeof(section))
				return -ENAMETOOLONG;
			memcpy(section, start, (size_t)(end - start));
			section[end - start] = '\0';
			s = build_trim(section);
			if (s != section)
				memmove(section, s, strlen(s) + 1);
			file = NULL;
			upatch = NULL;
			if (array && !strcmp(section, "files")) {
				if (spec->n_files >= BPM_BUILD_MAX_ENTRIES)
					return -E2BIG;
				file = &spec->files[spec->n_files++];
			} else if (array && !strcmp(section, "upatches")) {
				if (spec->n_upatches >= BPM_BUILD_MAX_ENTRIES)
					return -E2BIG;
				upatch = &spec->upatches[spec->n_upatches++];
			} else if (array) {
				return -EINVAL;
			}
			continue;
		}
		eq = strchr(s, '=');
		if (!eq)
			return -EINVAL;
		*eq = '\0';
		key = build_trim(s);
		value = build_trim(eq + 1);
		if (!strcmp(section, "package")) {
			char ignored[BPM_BUILD_MAX_VALUE];

			if (!strcmp(key, "name")) {
				if (build_parse_value(value, spec->name, sizeof(spec->name), false))
					return -EINVAL;
			} else if (!strcmp(key, "description") || !strcmp(key, "license")) {
				if (build_parse_value(value, ignored, sizeof(ignored), false))
					return -EINVAL;
			} else if (!strcmp(key, "authors")) {
				if (build_parse_value(value, ignored, sizeof(ignored), true))
					return -EINVAL;
			} else {
				return -EINVAL;
			}
		} else if (file) {
			if (!strcmp(key, "source")) {
				if (build_parse_string(value, file->source, sizeof(file->source)))
					return -EINVAL;
			} else if (!strcmp(key, "target")) {
				if (build_parse_string(value, file->target, sizeof(file->target)))
					return -EINVAL;
			} else {
				return -EINVAL;
			}
		} else if (upatch) {
			char *dst = NULL;
			size_t cap = 0;

			if (!strcmp(key, "source")) { dst = upatch->source; cap = sizeof(upatch->source); }
			else if (!strcmp(key, "type")) { dst = upatch->type; cap = sizeof(upatch->type); }
			else if (!strcmp(key, "load_target")) { dst = upatch->load_target; cap = sizeof(upatch->load_target); }
			else if (!strcmp(key, "unload_target")) { dst = upatch->unload_target; cap = sizeof(upatch->unload_target); }
			else return -EINVAL;
			if (build_parse_string(value, dst, cap))
				return -EINVAL;
		}
	}
	if (!build_name_ok(spec->name))
		return -EINVAL;
	for (size_t i = 0; i < spec->n_files; i++) {
		if (!spec->files[i].source[0])
			return -EINVAL;
		if (!spec->files[i].target[0])
			build_copy(spec->files[i].target, sizeof(spec->files[i].target),
				   spec->files[i].source);
	}
	for (size_t i = 0; i < spec->n_upatches; i++) {
		struct bpm_build_upatch *u = &spec->upatches[i];
		char *p;

		if (!u->source[0])
			return -EINVAL;
		if (!u->type[0])
			build_copy(u->type, sizeof(u->type), "bpf");
		for (p = u->type; *p; p++)
			*p = (char)tolower((unsigned char)*p);
		if (strcmp(u->type, "bpf") || build_default_targets(u))
			return -EINVAL;
	}
	return 0;
}

static bool build_within(const char *dir, const char *path)
{
	char resolved[PATH_MAX];
	size_t n;

	if (!realpath(path, resolved))
		return false;
	n = strlen(dir);
	return !strncmp(dir, resolved, n) && (resolved[n] == '\0' || resolved[n] == '/');
}

static int build_resolve_source(const struct bpm_build_spec *spec,
				const char *source, char *out, size_t cap,
				struct stat *st)
{
	char path[PATH_MAX];

	if (!source[0] || source[0] == '/' || strstr(source, "../") ||
	    !strcmp(source, ".."))
		return -EINVAL;
	if (snprintf(path, sizeof(path), "%s/%s", spec->scope, source) >= (int)sizeof(path) ||
	    stat(path, st) || !S_ISREG(st->st_mode) || !build_within(spec->scope, path) ||
	    !realpath(path, out))
		return errno ? -errno : -EINVAL;
	if (strlen(out) >= cap)
		return -ENAMETOOLONG;
	return 0;
}

static int build_target_ok(const char *target)
{
	const char *p = target;

	if (!target[0] || target[0] == '/' || !strcmp(target, ".") ||
	    !strcmp(target, ".."))
		return -EINVAL;
	while (*p) {
		const char *q = strchr(p, '/');
		size_t n = q ? (size_t)(q - p) : strlen(p);

		if (!n || (n == 2 && !strncmp(p, "..", 2)))
			return -EINVAL;
		p = q ? q + 1 : p + n;
	}
	return 0;
}

static int build_add_target(char seen[][PATH_MAX], size_t *n, const char *target)
{
	if (build_target_ok(target))
		return -EINVAL;
	if (!strcmp(target, "Beefile") || !strcmp(target, "README.md") ||
	    !strcmp(target, "cert.der") || !strcmp(target, "build-environment.json"))
		return -EEXIST;
	for (size_t i = 0; i < *n; i++)
		if (!strcmp(seen[i], target))
			return -EEXIST;
	if (*n >= BPM_BUILD_MAX_ENTRIES * 3)
		return -E2BIG;
	build_copy(seen[(*n)++], PATH_MAX, target);
	return 0;
}

static int build_validate(struct bpm_build_spec *spec)
{
	char seen[BPM_BUILD_MAX_ENTRIES * 3][PATH_MAX];
	char resolved[PATH_MAX];
	struct stat st;
	size_t n = 0;

	for (size_t i = 0; i < spec->n_files; i++) {
		if (build_add_target(seen, &n, spec->files[i].target) ||
		    build_resolve_source(spec, spec->files[i].source, resolved,
					  sizeof(resolved), &st))
			return -EINVAL;
	}
	for (size_t i = 0; i < spec->n_upatches; i++) {
		struct bpm_build_upatch *u = &spec->upatches[i];

		if (build_add_target(seen, &n, u->load_target) ||
		    build_add_target(seen, &n, u->unload_target) ||
		    build_resolve_source(spec, u->source, resolved, sizeof(resolved), &st))
			return -EINVAL;
	}
	return 0;
}

static int build_join(char *out, size_t cap, const char *dir, const char *name)
{
	return snprintf(out, cap, "%s/%s", dir, name) >= (int)cap ? -ENAMETOOLONG : 0;
}

static int build_entry_name(char *out, size_t cap, const char *top,
				    const char *entry)
{
	size_t top_len = strlen(top);
	size_t entry_len = strlen(entry);

	if (top_len >= cap || cap - top_len < 2 ||
	    entry_len > cap - top_len - 2)
		return -ENAMETOOLONG;
	memcpy(out, top, top_len);
	out[top_len] = '/';
	memcpy(out + top_len + 1, entry, entry_len + 1);
	return 0;
}

static const char *build_helper(void)
{
	const char *override = getenv("SHIRUDO_BUILD");

	if (override && *override)
		return override;
	if (!access(SHIRUDO_LIBEXEC_DIR "/shirudo-build", X_OK))
		return SHIRUDO_LIBEXEC_DIR "/shirudo-build";
	return "shirudo-build";
}

static int build_run_helper(const char *workdir, const char *keys_dir,
				const char *source, const char *output,
				const char *unload_name, const char *payload)
{
	const char *helper = build_helper();
	char *argv[16];
	pid_t pid;
	int n = 0, status;

	if (unload_name) {
		argv[n++] = (char *)helper;
		argv[n++] = (char *)"--unload";
		argv[n++] = (char *)unload_name;
	} else {
		argv[n++] = (char *)helper;
		argv[n++] = (char *)source;
	}
	argv[n++] = (char *)"-o";
	argv[n++] = (char *)output;
	argv[n++] = (char *)"--keys-dir";
	argv[n++] = (char *)keys_dir;
	if (unload_name) {
		argv[n++] = (char *)"--payload-sha256";
		argv[n++] = (char *)payload;
	}
	argv[n] = NULL;

	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid) {
		if (chdir(workdir))
			_exit(127);
		if (strchr(helper, '/'))
			execv(helper, argv);
		else
			execvp(helper, argv);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -errno;
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		return -EIO;
	return 0;
}

static void build_hex(const unsigned char *in, char *out, size_t n)
{
	static const char hex[] = "0123456789abcdef";

	for (size_t i = 0; i < n; i++) {
		out[i * 2] = hex[in[i] >> 4];
		out[i * 2 + 1] = hex[in[i] & 15];
	}
	out[n * 2] = '\0';
}

static int build_upatches(struct bpm_build_spec *spec, const char *keys_dir)
{
	for (size_t i = 0; i < spec->n_upatches; i++) {
		struct bpm_build_upatch *u = &spec->upatches[i];
		struct shirudo_upatch parsed = {};
		char source[PATH_MAX], load[PATH_MAX], unload[PATH_MAX];
		int rc;

		if (build_resolve_source(spec, u->source, source, sizeof(source),
					 &(struct stat){}))
			return -EINVAL;
		if (build_join(load, sizeof(load), spec->scope, strrchr(u->load_target, '/') ?
					 strrchr(u->load_target, '/') + 1 : u->load_target) ||
		    build_join(unload, sizeof(unload), spec->scope, strrchr(u->unload_target, '/') ?
					 strrchr(u->unload_target, '/') + 1 : u->unload_target))
			return -ENAMETOOLONG;
		build_copy(u->load_path, sizeof(u->load_path), load);
		build_copy(u->unload_path, sizeof(u->unload_path), unload);
		unlink(load);
		unlink(unload);
		rc = build_run_helper(spec->scope, keys_dir, u->source, load,
				      NULL, NULL);
		if (rc)
			return rc;
		if (shirudo_upatch_open(load, &parsed))
			return -EINVAL;
		if (shirudo_upatch_is_unload(&parsed) || !parsed.hdr.name[0]) {
			shirudo_upatch_close(&parsed);
			return -EINVAL;
		}
		build_copy(u->name, sizeof(u->name), parsed.hdr.name);
		build_hex(parsed.hdr.payload_sha256, u->payload_sha256,
			  SHIRUDO_CRYPTO_SHA256_LEN);
		build_copy(u->type, sizeof(u->type), shirudo_upatch_type_str(&parsed));
		shirudo_upatch_close(&parsed);
		rc = build_run_helper(spec->scope, keys_dir, NULL, unload,
				      u->name, u->payload_sha256);
		if (rc)
			return rc;
	}
	return 0;
}

static int build_environment(const struct bpm_build_spec *spec,
				     const char *version, const char *fingerprint,
				     unsigned char **out, size_t *out_len)
{
	char *body = calloc(1, BPM_BUILD_MAX_JSON);
	struct shirudo_json_emit e = { .buf = body, .cap = BPM_BUILD_MAX_JSON };
	struct utsname un = {};
	char self[PATH_MAX] = "shirudo";
	char timestamp[32] = {};
	time_t now = time(NULL);
	struct tm tm;
	ssize_t self_len;

	if (!body || uname(&un) || !gmtime_r(&now, &tm) ||
	    !strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm)) {
		free(body);
		return -EIO;
	}
	self_len = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (self_len > 0)
		self[self_len] = '\0';
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "format_version", 1);
	shirudo_json_kv_string(&e, "builder", "bpm build");
	shirudo_json_kv_string(&e, "created_at", timestamp);
	shirudo_json_obj_open_key(&e, "package");
	shirudo_json_kv_string(&e, "name", spec->name);
	shirudo_json_kv_string(&e, "version", version);
	shirudo_json_obj_close(&e);
	shirudo_json_kv_string(&e, "os", un.sysname);
	shirudo_json_kv_string(&e, "arch", un.machine);
	shirudo_json_kv_string(&e, "go_version", "n/a");
	shirudo_json_kv_string(&e, "bpm_version", shirudo_version);
	shirudo_json_obj_open_key(&e, "shirudo");
	shirudo_json_kv_string(&e, "path", self);
	shirudo_json_kv_string(&e, "version", shirudo_version);
	shirudo_json_kv_string(&e, "spki_sha256_fingerprint", fingerprint);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_open(&e, "upatches");
	for (size_t i = 0; i < spec->n_upatches; i++) {
		const struct bpm_build_upatch *u = &spec->upatches[i];

		shirudo_json_obj_open(&e);
		shirudo_json_kv_string(&e, "source", u->source);
		shirudo_json_kv_string(&e, "type", u->type);
		shirudo_json_kv_string(&e, "load_target", u->load_target);
		shirudo_json_kv_string(&e, "load_output", strrchr(u->load_target, '/') ?
					strrchr(u->load_target, '/') + 1 : u->load_target);
		shirudo_json_kv_string(&e, "unload_target", u->unload_target);
		shirudo_json_kv_string(&e, "unload_output", strrchr(u->unload_target, '/') ?
					strrchr(u->unload_target, '/') + 1 : u->unload_target);
		shirudo_json_kv_string(&e, "upatch_name", u->name);
		shirudo_json_kv_string(&e, "payload_sha256", u->payload_sha256);
		shirudo_json_obj_close(&e);
	}
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);
	if (e.err) {
		free(body);
		return e.err;
	}
	*out = (unsigned char *)body;
	*out_len = e.len;
	return 0;
}

struct bpm_tar {
	gzFile gz;
};

static int tar_write(struct bpm_tar *tar, const void *data, size_t len)
{
	if (!len)
		return 0;
	return gzwrite(tar->gz, data, (unsigned)len) == (int)len ? 0 : -EIO;
}

static int tar_entry(struct bpm_tar *tar, const char *name, const void *data,
			     size_t len, mode_t mode, char type)
{
	unsigned char h[512] = {};
	unsigned int sum = 0;
	unsigned char zeros[512] = {};

	if (strlen(name) >= 100 || (type == '0' && len > 077777777777ULL))
		return -ENAMETOOLONG;
	memcpy(h, name, strlen(name));
	snprintf((char *)h + 100, 8, "%07o", (unsigned)(mode & 07777));
	snprintf((char *)h + 108, 8, "%07o", 0u);
	snprintf((char *)h + 116, 8, "%07o", 0u);
	snprintf((char *)h + 124, 12, "%011o", (unsigned)len);
	snprintf((char *)h + 136, 12, "%011o", 0u);
	memset(h + 148, ' ', 8);
	h[156] = (unsigned char)type;
	memcpy(h + 257, "ustar\0", 6);
	memcpy(h + 263, "00", 2);
	for (size_t i = 0; i < sizeof(h); i++)
		sum += h[i];
	snprintf((char *)h + 148, 8, "%06o ", sum);
	if (tar_write(tar, h, sizeof(h)) || tar_write(tar, data, len))
		return -EIO;
	if (type == '0' && (len & 511))
		return tar_write(tar, zeros, 512 - (len & 511));
	return 0;
}

static int tar_path(struct bpm_tar *tar, const char *name, const char *path)
{
	unsigned char *body;
	size_t len;
	struct stat st;
	int rc;

	if (stat(path, &st))
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EINVAL;
	rc = build_read_file(path, &body, &len, BPM_BUILD_MAX_FILE);
	if (!rc)
		rc = tar_entry(tar, name, body, len, st.st_mode, '0');
	free(body);
	return rc;
}

static int build_archive(const struct bpm_build_spec *spec, const char *version,
			 const char *keys_dir, const char *fingerprint)
{
	char output[PATH_MAX], top[PATH_MAX], name[PATH_MAX], path[PATH_MAX];
	unsigned char *environment = NULL, *cert = NULL;
	size_t environment_len, cert_len;
	struct bpm_tar tar;
	int rc;

	if (snprintf(top, sizeof(top), "%s-%s", spec->name, version) >= (int)sizeof(top) ||
	    snprintf(output, sizeof(output), "%s.bee", top) >= (int)sizeof(output))
		return -ENAMETOOLONG;
	if (build_environment(spec, version, fingerprint, &environment,
			       &environment_len))
		return -EIO;
	if (build_join(path, sizeof(path), keys_dir, SHIRUDO_CERT_FILE) ||
	    build_read_file(path, &cert, &cert_len, BPM_BUILD_MAX_FILE)) {
		free(environment);
		return -ENOENT;
	}
	tar.gz = gzopen(output, "wb9");
	if (!tar.gz) {
		free(environment);
		free(cert);
		return -errno;
	}
	rc = build_entry_name(name, sizeof(name), top, "");
	if (!rc)
		rc = tar_entry(&tar, name, NULL, 0, 0755, '5');
	if (!rc) {
		rc = build_entry_name(name, sizeof(name), top, "Beefile");
		if (!rc)
			rc = tar_entry(&tar, name, spec->build_file,
					spec->build_file_len, 0644, '0');
	}
	for (size_t i = 0; !rc && i < spec->n_files; i++) {
		char resolved[PATH_MAX];
		struct stat st;

		rc = build_resolve_source(spec, spec->files[i].source, resolved,
					   sizeof(resolved), &st);
		if (!rc)
			rc = build_entry_name(name, sizeof(name), top,
					      spec->files[i].target);
		if (!rc)
			rc = tar_path(&tar, name, resolved);
	}
	for (size_t i = 0; !rc && i < spec->n_upatches; i++) {
		const struct bpm_build_upatch *u = &spec->upatches[i];

		rc = build_entry_name(name, sizeof(name), top, u->load_target);
		if (!rc)
			rc = tar_path(&tar, name, u->load_path);
		if (!rc)
			rc = build_entry_name(name, sizeof(name), top, u->unload_target);
		if (!rc)
			rc = tar_path(&tar, name, u->unload_path);
	}
	if (!rc) {
		char readme[PATH_MAX];
		struct stat st;

		rc = build_join(readme, sizeof(readme), spec->scope, "README.md");
		if (!rc) {
			if (!stat(readme, &st)) {
				if (!build_within(spec->scope, readme))
					rc = -EINVAL;
			} else if (errno != ENOENT) {
				rc = -errno;
			}
		}
		if (!rc && !access(readme, R_OK)) {
			rc = build_entry_name(name, sizeof(name), top, "README.md");
			if (!rc)
				rc = tar_path(&tar, name, readme);
		}
	}
	if (!rc) {
		rc = build_entry_name(name, sizeof(name), top, "cert.der");
		if (!rc)
			rc = tar_entry(&tar, name, cert, cert_len, 0644, '0');
	}
	if (!rc) {
		rc = build_entry_name(name, sizeof(name), top,
				       "build-environment.json");
		if (!rc)
			rc = tar_entry(&tar, name, environment, environment_len, 0644, '0');
	}
	if (!rc) {
		unsigned char end[1024] = {};

		rc = tar_write(&tar, end, sizeof(end));
	}
	if (gzclose(tar.gz) != Z_OK)
		rc = rc ? rc : -EIO;
	free(environment);
	free(cert);
	if (rc)
		unlink(output);
	else
		printf("%s\n", output);
	return rc;
}

static const char *build_resolve_keys_dir(const char *arg, char *out, size_t cap)
{
	const char *home = getenv("HOME");

	if (!arg || !*arg)
		arg = "~/.config/bpm/";
	if (arg[0] == '~' && (!arg[1] || arg[1] == '/')) {
		if (!home || snprintf(out, cap, "%s%s", home, arg + 1) >= (int)cap)
			return NULL;
		return out;
	}
	if (strlen(arg) >= cap)
		return NULL;
	build_copy(out, cap, arg);
	return out;
}

int cmd_bpm_build(int argc, const char **argv)
{
	const char *context = ".", *file_arg = NULL, *version = NULL, *keys_arg = NULL;
	char build_file[PATH_MAX], resolved_file[PATH_MAX], keys_dir[PATH_MAX];
	struct bpm_build_spec spec = {};
	struct shirudo_cert cert = {};
	unsigned char digest[SHIRUDO_CRYPTO_SHA256_LEN];
	char fingerprint[SHIRUDO_CRYPTO_SHA256_LEN * 2 + 1];
	unsigned char *original_build_file;
	int positional = 0, rc;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) {
			if (++i >= argc)
				return -EINVAL;
			file_arg = argv[i];
		} else if (!strncmp(argv[i], "--file=", 7)) {
			file_arg = argv[i] + 7;
		} else if (!strcmp(argv[i], "--version")) {
			if (++i >= argc)
				return -EINVAL;
			version = argv[i];
		} else if (!strncmp(argv[i], "--version=", 10)) {
			version = argv[i] + 10;
		} else if (!strcmp(argv[i], "--keys-dir")) {
			if (++i >= argc)
				return -EINVAL;
			keys_arg = argv[i];
		} else if (!strncmp(argv[i], "--keys-dir=", 11)) {
			keys_arg = argv[i] + 11;
		} else if (argv[i][0] == '-') {
			return -EINVAL;
		} else if (++positional == 1) {
			context = argv[i];
		} else {
			return -EINVAL;
		}
	}
	if (!version || !build_version_ok(version))
		return -EINVAL;
	if (!build_resolve_keys_dir(keys_arg, keys_dir, sizeof(keys_dir)))
		return -EINVAL;
	if (file_arg)
		build_copy(build_file, sizeof(build_file), file_arg);
	else if (build_join(build_file, sizeof(build_file), context, "Beefile"))
		return -ENAMETOOLONG;
	if (!realpath(build_file, resolved_file))
		return -errno;
	if (strlen(resolved_file) >= sizeof(resolved_file))
		return -ENAMETOOLONG;
	build_copy(spec.scope, sizeof(spec.scope), resolved_file);
	{
		char *slash = strrchr(spec.scope, '/');

		if (!slash)
			return -EINVAL;
		*slash = '\0';
	}
	rc = build_read_file(resolved_file, &spec.build_file, &spec.build_file_len,
			     BPM_BUILD_MAX_FILE);
	if (rc)
		return rc;
	original_build_file = malloc(spec.build_file_len + 1);
	if (!original_build_file) {
		free(spec.build_file);
		return -ENOMEM;
	}
	memcpy(original_build_file, spec.build_file, spec.build_file_len + 1);
	rc = build_parse_spec(&spec);
	free(spec.build_file);
	spec.build_file = original_build_file;
	if (!rc)
		rc = build_validate(&spec);
	if (rc)
		goto out;
	if (build_join(build_file, sizeof(build_file), keys_dir, SHIRUDO_CERT_FILE) ||
	    shirudo_cert_read_file(build_file, &cert)) {
		rc = -ENOENT;
		goto out;
	}
	rc = shirudo_cert_pubkey_digest(&cert, digest);
	if (rc)
		goto out_cert;
	build_hex(digest, fingerprint, sizeof(digest));
	rc = build_upatches(&spec, keys_dir);
	if (!rc)
		rc = build_archive(&spec, version, keys_dir, fingerprint);
out_cert:
	shirudo_cert_free(&cert);
out:
	free(spec.build_file);
	return rc;
}
