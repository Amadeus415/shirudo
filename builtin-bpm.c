// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Target-local BPM package manager: repositories, signed indexes, the
 * upatch tree and the .bee lifecycle. The operator-only build, push and
 * tree append commands live in shirudo-build and are only dispatched.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "builtin.h"
#include "util/bpm_oci.h"
#include "util/bpm_package.h"
#include "util/bpm_tree.h"
#include "util/bpm_source_config.h"
#include "util/chain.h"
#include "util/crypto.h"
#include "util/eventlog.h"
#include "util/help.h"
#include "util/hex.h"
#include "util/io.h"
#include "util/json.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/macros.h"
#include "util/paths.h"
#include "util/seal.h"
#include "util/upatch.h"

struct bpm_source {
	char name[BPM_MAX_NAME];
	char endpoint[BPM_MAX_ENDPOINT];
	char key_file[BPM_MAX_KEY];
};

struct bpm_state_entry {
	char name[BPM_MAX_NAME];
	char version[BPM_MAX_NAME];
	char source[BPM_MAX_NAME];
	char path[PATH_MAX];
};

static int sha256_file_hex(const char *path, char *hex, size_t hex_sz);


static int prepare_direct_install(const char *raw, struct bpm_source *source,
					  struct bpm_index_entry *entry)
{
	struct bpm_oci_client c = {};
	struct bpm_descriptor layers[8];
	struct bpm_buffer manifest = {};
	char repository[BPM_MAX_ENDPOINT], tag[BPM_MAX_NAME];
	char package_name[BPM_MAX_NAME] = {};
	char endpoint[BPM_MAX_ENDPOINT];
	char url[PATH_MAX];
	int n_layers, rc;

	rc = bpm_oci_parse_pull_ref(raw, &c, repository, sizeof(repository), tag,
			    sizeof(tag));
	if (rc)
		return rc;
	if ((rc = bpm_oci_url(&c, repository, "manifests", tag, url,
				       sizeof(url))))
		return rc;
	if ((rc = bpm_oci_get_memory(&c, url,
				 "application/vnd.oci.image.manifest.v1+json",
				 &manifest)))
		goto out;
	if ((rc = bpm_oci_parse_manifest(manifest.data, manifest.len, layers, &n_layers,
				 package_name, sizeof(package_name))))
		goto out;
	if (!package_name[0]) {
		const char *base = strrchr(repository, '/');

		bpm_copy_string(package_name, sizeof(package_name),
				base ? base + 1 : repository);
	}
	if (!bpm_package_name_ok(package_name)) {
		rc = -EINVAL;
		goto out;
	}
	if (snprintf(endpoint, sizeof(endpoint), "oci://%s", c.registry) >=
	    (int)sizeof(endpoint)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	memset(source, 0, sizeof(*source));
	bpm_copy_string(source->name, sizeof(source->name), "direct");
	bpm_copy_string(source->endpoint, sizeof(source->endpoint), endpoint);
	memset(entry, 0, sizeof(*entry));
	bpm_copy_string(entry->name, sizeof(entry->name), package_name);
	bpm_copy_string(entry->version, sizeof(entry->version), tag);
	bpm_copy_string(entry->repository, sizeof(entry->repository), repository);
	/* package_install treats a non-digest reference as a tag. */
	bpm_copy_string(entry->manifest_digest, sizeof(entry->manifest_digest), tag);
	entry->package_size = -1;
	rc = 0;
out:
	bpm_buffer_free(&manifest);
	return rc;
}

static int download_package(const char *raw, const char *destination)
{
	struct bpm_oci_client c = {};
	struct bpm_descriptor layers[8];
	struct bpm_buffer manifest = {};
	char repository[BPM_MAX_ENDPOINT], tag[BPM_MAX_NAME];
	char url[PATH_MAX], filename[PATH_MAX], title[PATH_MAX];
	char digest[65], package_name[BPM_MAX_NAME] = {};
	int n_layers = 0, rc;

	rc = bpm_oci_parse_pull_ref(raw, &c, repository, sizeof(repository),
			    tag, sizeof(tag));
	if (rc)
		return rc;
	if ((rc = bpm_oci_url(&c, repository, "manifests", tag,
			       url, sizeof(url))))
		return rc;
	if ((rc = bpm_oci_get_memory(&c, url, "application/vnd.oci.image.manifest.v1+json",
				 &manifest)))
		goto out;
	if ((rc = bpm_oci_parse_manifest(manifest.data, manifest.len, layers, &n_layers,
				 package_name, sizeof(package_name))))
		goto out;
	bpm_trim(package_name, package_name, sizeof(package_name));
	for (int i = 0; i < n_layers; i++) {
		if (strcmp(layers[i].media, BPM_PACKAGE_MEDIA))
			continue;
		if ((rc = bpm_oci_url(&c, repository, "blobs", layers[i].digest,
				       url, sizeof(url))))
			goto out;
		bpm_trim(layers[i].title, title, sizeof(title));
		if (destination) {
			bpm_copy_string(filename, sizeof(filename), destination);
		} else if (title[0] && !strchr(title, '/') &&
		    strlen(title) >= strlen(".bee") &&
		    !strcmp(title + strlen(title) - strlen(".bee"), ".bee")) {
			bpm_copy_string(filename, sizeof(filename), title);
		} else {
			const char *base = strrchr(repository, '/');
			base = base ? base + 1 : repository;
			if (package_name[0])
				base = package_name;
			if (!bpm_package_name_ok(base)) {
				rc = -EINVAL;
				goto out;
			}
			if (snprintf(filename, sizeof(filename), "%s-%s.bee",
				     base, tag) >= (int)sizeof(filename)) {
				rc = -ENAMETOOLONG;
				goto out;
			}
		}
		rc = bpm_oci_get_file(&c, url, BPM_PACKAGE_MEDIA, filename);
		if (rc)
			goto out;
		if (sha256_file_hex(filename, digest, sizeof(digest)) ||
		    !bpm_digest_matches(layers[i].digest, digest)) {
			rc = -EKEYREJECTED;
			unlink(filename);
			goto out;
		}
		if (layers[i].size >= 0) {
			struct stat st;
			if (stat(filename, &st) || st.st_size != layers[i].size) {
				rc = -EKEYREJECTED;
				unlink(filename);
				goto out;
			}
		}
		rc = 0;
		goto out;
	}
	rc = -EINVAL;
out:
	bpm_buffer_free(&manifest);
	return rc;
}

static int pull_package(const char *raw)
{
	return download_package(raw, NULL);
}

static int copy_file_ex(const char *src, const char *dst, mode_t mode,
			bool exclusive)
{
	unsigned char buf[65536];
	ssize_t n;
	int in, out, rc = 0;

	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0) return -errno;
	out = open(dst, O_WRONLY | O_CREAT | O_CLOEXEC |
		   (exclusive ? O_EXCL : O_TRUNC), mode);
	if (out < 0) { rc = -errno; close(in); return rc; }
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		rc = shirudo_write_all(out, buf, (size_t)n);
		if (rc)
			break;
	}
	if (n < 0 && !rc) rc = -errno;
	if (fsync(out) && !rc) rc = -errno;
	close(in); close(out);
	if (rc) unlink(dst);
	return rc;
}

static int copy_file(const char *src, const char *dst, mode_t mode)
{
	return copy_file_ex(src, dst, mode, false);
}

static int atomic_write(const char *path, const void *data, size_t len, mode_t mode)
{
	char tmp[PATH_MAX];
	int fd, rc = 0;
	if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof(tmp)) return -ENAMETOOLONG;
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0) return -errno;
	rc = shirudo_write_all(fd, data, len);
	if (!rc && fsync(fd)) rc = -errno;
	close(fd);
	if (!rc && rename(tmp, path)) rc = -errno;
	if (rc) unlink(tmp);
	return rc;
}

static int source_path(const char *name, char *out, size_t out_sz)
{
	if (!bpm_name_ok(name)) return -EINVAL;
	if (snprintf(out, out_sz, "%s/%s.conf", SHIRUDO_BPM_REGISTRIES_DIR, name) >= (int)out_sz) return -ENAMETOOLONG;
	return 0;
}

static int load_source(const char *name, struct bpm_source *s)
{
	char path[PATH_MAX], line[PATH_MAX];
	FILE *fp;
	int rc;

	memset(s, 0, sizeof(*s));
	rc = source_path(name, path, sizeof(path)); if (rc) return rc;
	fp = fopen(path, "r"); if (!fp) return -errno;
	snprintf(s->name, sizeof(s->name), "%s", name);
	while (fgets(line, sizeof(line), fp)) {
		rc = shirudo_bpm_parse_source_line(line,
					    s->endpoint, sizeof(s->endpoint),
					    s->key_file, sizeof(s->key_file));
		if (rc) {
			fclose(fp);
			return rc;
		}
	}
	fclose(fp);
	if (!s->endpoint[0] || !s->key_file[0]) return -EINVAL;
	return 0;
}

static int save_source(const struct bpm_source *s)
{
	char path[PATH_MAX], data[PATH_MAX * 2];
	int rc = source_path(s->name, path, sizeof(path));
	if (rc) return rc;
	if (snprintf(data, sizeof(data), "endpoint = %s\nkey_file = %s\n", s->endpoint, s->key_file) >= (int)sizeof(data)) return -E2BIG;
	return atomic_write(path, data, strlen(data), 0644);
}

static int with_bpm_lock(void)
{
	int fd;
	{ int rc = bpm_mkdir_p(SHIRUDO_LOCKS_DIR, 0700); if (rc) return rc; }
	fd = open(SHIRUDO_BPM_LOCK_PATH, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0) return -errno;
	if (flock(fd, LOCK_EX)) { int rc = -errno; close(fd); return rc; }
	return fd;
}

static int bpm_fail(const char *action, int rc)
{
	if (rc < 0)
		pr_err("bpm %s: %s", action, strerror(-rc));
	else
		pr_err("bpm %s failed", action);
	return 1;
}

static int cache_path(const char *source, char *out, size_t sz)
{
	if (!bpm_name_ok(source)) return -EINVAL;
	if (snprintf(out, sz, "%s/%s/index.json", SHIRUDO_BPM_REPOS_DIR, source) >= (int)sz) return -ENAMETOOLONG;
	return 0;
}

static int sha256_file_hex(const char *path, char *hex, size_t hex_sz)
{
	struct shirudo_sha256_ctx ctx;
	unsigned char digest[SHIRUDO_CRYPTO_SHA256_LEN];
	unsigned char buf[65536];
	ssize_t nr;
	int fd, rc = -EIO;

	if (hex_sz < 65 || shirudo_sha256_init(&ctx) != 0) return -EINVAL;
	fd = open(path, O_RDONLY | O_CLOEXEC); if (fd < 0) { shirudo_sha256_free(&ctx); return -errno; }
	while ((nr = read(fd, buf, sizeof(buf))) > 0)
		if (shirudo_sha256_update(&ctx, buf, (size_t)nr) != 0) goto done;
	if (nr < 0 || shirudo_sha256_final(&ctx, digest) != 0) goto done;
	for (unsigned int i = 0; i < sizeof(digest); i++) snprintf(hex + i * 2, 3, "%02x", digest[i]);
	hex[64] = 0; rc = 0;
done:
	close(fd); shirudo_sha256_free(&ctx); return rc;
}

static int print_package_readme(const char *source)
{
	char temporary[] = "/tmp/shirudo-bpm-info-XXXXXX";
	unsigned char *beefile = NULL, *readme = NULL;
	size_t beefile_len = 0, readme_len = 0;
	const char *archive = source;
	char package_dir[101];
	int fd, rc;

	if (!strncmp(source, "oci://", 6)) {
		fd = mkstemp(temporary);
		if (fd < 0)
			return -errno;
		close(fd);
		archive = temporary;
		rc = download_package(source, archive);
		if (rc)
			goto out;
	}
	rc = bpm_pkg_read_member_in(archive, "Beefile", NULL, package_dir,
				    sizeof(package_dir), &beefile, &beefile_len,
				    4u * 1024u * 1024u);
	if (rc) {
		if (rc == -ENOENT)
			pr_err("bpm info: package %s does not include Beefile", source);
		goto out;
	}
	rc = bpm_pkg_read_member_in(archive, "README.md", package_dir, NULL, 0,
				    &readme, &readme_len, 4u * 1024u * 1024u);
	if (rc) {
		if (rc == -ENOENT)
			pr_err("bpm info: package %s does not include README.md", source);
		goto out;
	}
	rc = shirudo_write_all(STDOUT_FILENO, readme, readme_len);
out:
	xfree(beefile, beefile_len + 1);
	xfree(readme, readme_len + 1);
	if (archive == temporary)
		unlink(temporary);
	return rc;
}

static int extract_archive(const char *archive, const char *dest)
{
	gzFile gz = gzopen(archive, "rb");
	unsigned char h[512];
	char root[256] = {};
	int rc = 0;

	if (!gz) return -EINVAL;
	if ((rc = bpm_mkdir_p(dest, 0700))) { gzclose(gz); return rc; }
	for (;;) {
		int n = gzread(gz, h, sizeof(h));
		uint64_t size, remain, pad;
		char name[PATH_MAX], rel[PATH_MAX], path[PATH_MAX], *slash;
		int type;
		if (n == 0) break;
		if (n != (int)sizeof(h)) { rc = -EINVAL; break; }
		bool zero = true; for (size_t i = 0; i < sizeof(h); i++) if (h[i]) { zero = false; break; }
		if (zero) break;
		if (!memchr(h, '\0', 100)) { rc = -EINVAL; break; }
		snprintf(name, sizeof(name), "%s", (char *)h);
		if (!bpm_archive_rel_ok(name) || bpm_tar_octal((char *)h + 124, 12, &size)) { rc = -EINVAL; break; }
		type = h[156]; if (!type) type = '0';
		if (!root[0]) {
			slash = strchr(name, '/'); if (!slash || slash == name || (size_t)(slash - name) >= sizeof(root)) { rc = -EINVAL; break; }
			memcpy(root, name, slash - name); root[slash - name] = 0;
		}
		if (strncmp(name, root, strlen(root)) || name[strlen(root)] != '/') { rc = -EINVAL; break; }
		snprintf(rel, sizeof(rel), "%s", name + strlen(root) + 1);
		if ((!*rel && type != '5') || (*rel && !bpm_archive_rel_ok(rel))) { rc = -EINVAL; break; }
		if (snprintf(path, sizeof(path), "%s/%s", dest, rel) >= (int)sizeof(path)) { rc = -ENAMETOOLONG; break; }
		if (type == '5') {
			if ((rc = bpm_mkdir_p(path, 0700))) break;
		} else if (type == '0') {
			char parent[PATH_MAX];
			FILE *fp;
			snprintf(parent, sizeof(parent), "%s", path);
			slash = strrchr(parent, '/'); if (slash) { *slash = 0; if ((rc = bpm_mkdir_p(parent, 0700))) break; }
			fp = fopen(path, "wb"); if (!fp) { rc = -errno; break; }
			remain = size;
			while (remain) {
				unsigned char buf[65536]; size_t want = remain > sizeof(buf) ? sizeof(buf) : (size_t)remain;
				n = gzread(gz, buf, (unsigned)want);
				if (n <= 0 || fwrite(buf, 1, (size_t)n, fp) != (size_t)n) { rc = -EIO; break; }
				remain -= (size_t)n;
			}
			fclose(fp); if (rc) break;
			chmod(path, 0644);
		} else { rc = -EPERM; break; }
		pad = (512 - (size % 512)) % 512;
		while (pad) { unsigned char buf[512]; size_t want = pad > sizeof(buf) ? sizeof(buf) : (size_t)pad; n = gzread(gz, buf, (unsigned)want); if (n <= 0) { rc = -EINVAL; break; } pad -= (size_t)n; }
		if (rc) break;
	}
	if (gzclose(gz) != Z_OK && !rc) rc = -EINVAL;
	if (rc) return rc;
	return root[0] ? 0 : -EINVAL;
}

static int cert_matches_active(const char *path)
{
	struct shirudo_cert a = {}, b = {};
	unsigned char da[SHIRUDO_CRYPTO_SHA256_LEN], db[SHIRUDO_CRYPTO_SHA256_LEN];
	int rc = -EINVAL;
	if (!shirudo_cert_read_file(path, &a) &&
	    !shirudo_cert_read_file(SHIRUDO_CERT_PATH, &b) &&
	    !shirudo_cert_pubkey_digest(&a, da) &&
	    !shirudo_cert_pubkey_digest(&b, db) &&
	    !memcmp(da, db, sizeof(da)))
		rc = 0;
	shirudo_cert_free(&a);
	shirudo_cert_free(&b);
	return rc;
}

static int key_file_fingerprint(const char *path, char hex[65])
{
	struct shirudo_cert cert = {};
	unsigned char digest[SHIRUDO_CRYPTO_SHA256_LEN];
	int rc;

	rc = shirudo_cert_read_file(path, &cert);
	if (!rc)
		rc = shirudo_cert_pubkey_digest(&cert, digest);
	shirudo_cert_free(&cert);
	if (rc)
		return rc;
	for (size_t i = 0; i < sizeof(digest); i++)
		snprintf(hex + 2 * i, 3, "%02x", digest[i]);
	return 0;
}

static int install_key_file(const char *src)
{
	char hex[65], dst[PATH_MAX];
	struct stat st;
	bool active;
	int rc;

	rc = key_file_fingerprint(src, hex);
	if (rc)
		return rc;
	rc = bpm_mkdir_p(SHIRUDO_KEYS_DIR, 0700);
	if (rc)
		return rc;
	active = lstat(SHIRUDO_CERT_PATH, &st) == 0;
	if (!active && errno != ENOENT)
		return -errno;
	if (active && cert_matches_active(src))
		return -EPERM;
	if (snprintf(dst, sizeof(dst), "%s/%s.der", SHIRUDO_KEYS_DIR,
		     hex) >= (int)sizeof(dst))
		return -ENAMETOOLONG;
	if (lstat(dst, &st) == 0) {
		char existing[65];

		if (!S_ISREG(st.st_mode) || key_file_fingerprint(dst, existing) ||
		    strcmp(existing, hex))
			return -EKEYREJECTED;
	} else {
		if (errno != ENOENT)
			return -errno;
		rc = copy_file_ex(src, dst, 0644, true);
		if (rc)
			return rc;
	}
	if (!active && symlink(dst, SHIRUDO_CERT_PATH)) {
		if (errno != EEXIST)
			return -errno;
		if (cert_matches_active(src))
			return -EPERM;
	}
	return 0;
}

static int extract_package_cert(const char *archive, char *out, size_t out_sz)
{
	char tmp[] = "/tmp/shirudo-bpm-cert-XXXXXX";
	unsigned char *body = NULL;
	size_t len = 0;
	int fd, rc;

	rc = bpm_pkg_read_member(archive, "cert.der", &body, &len, 1024 * 1024);
	if (rc)
		return rc;
	if (sizeof(tmp) > out_sz) {
		xfree(body, len + 1);
		return -ENAMETOOLONG;
	}
	fd = mkstemp(tmp);
	if (fd < 0) {
		xfree(body, len + 1);
		return -errno;
	}
	rc = shirudo_write_all(fd, body, len);
	if (close(fd) && !rc)
		rc = -errno;
	xfree(body, len + 1);
	if (rc)
		unlink(tmp);
	else
		bpm_copy_string(out, out_sz, tmp);
	return rc;
}

static int key_source_file(const char *source, char *temp, size_t temp_sz)
{
	char archive[] = "/tmp/shirudo-bpm-key-XXXXXX";
	size_t len = strlen(source);
	int fd, rc;

	if (!strncmp(source, "oci://", 6)) {
		fd = mkstemp(archive);
		if (fd < 0)
			return -errno;
		close(fd);
		rc = download_package(source, archive);
		if (!rc)
			rc = extract_package_cert(archive, temp, temp_sz);
		unlink(archive);
		return rc;
	}
	if (len >= 4 && !strcmp(source + len - 4, ".bee"))
		return extract_package_cert(source, temp, temp_sz);
	return 0;
}

static int key_fingerprint_compare(const void *a, const void *b)
{
	return strcmp(*(char * const *)a, *(char * const *)b);
}

static int list_keys(void)
{
	char **fingerprints = NULL;
	size_t count = 0, cap = 0;
	struct dirent *entry;
	DIR *dir;
	int rc = 0;

	dir = opendir(SHIRUDO_KEYS_DIR);
	if (!dir)
		return errno == ENOENT ? 0 : -errno;
	for (;;) {
		char path[PATH_MAX], hex[65], **next;
		struct stat st;
		bool valid = true;

		errno = 0;
		entry = readdir(dir);
		if (!entry) {
			rc = -errno;
			break;
		}
		if (strlen(entry->d_name) != 68 ||
		    strcasecmp(entry->d_name + 64, ".der"))
			continue;
		for (size_t i = 0; i < 64; i++)
			if (!isxdigit((unsigned char)entry->d_name[i]))
				valid = false;
		if (!valid || snprintf(path, sizeof(path), "%s/%s",
				       SHIRUDO_KEYS_DIR, entry->d_name) >=
				       (int)sizeof(path))
			continue;
		if (lstat(path, &st) || !S_ISREG(st.st_mode) ||
		    key_file_fingerprint(path, hex) ||
		    strncasecmp(entry->d_name, hex, 64))
			continue;
		next = xreallocarray(fingerprints, cap, count + 1,
				     sizeof(*next));
		if (!next) {
			rc = -ENOMEM;
			break;
		}
		fingerprints = next;
		cap = count + 1;
		fingerprints[count] = xstrdup(hex);
		if (!fingerprints[count]) {
			rc = -ENOMEM;
			break;
		}
		count++;
	}
	closedir(dir);
	if (!rc && count) {
		qsort(fingerprints, count, sizeof(*fingerprints),
		      key_fingerprint_compare);
		for (size_t i = 0; i < count; i++)
			puts(fingerprints[i]);
	}
	for (size_t i = 0; i < count; i++)
		xstrfree(fingerprints[i]);
	xfree(fingerprints, cap * sizeof(*fingerprints));
	return rc;
}

struct state_sink {
	struct bpm_state_entry *items;
	int n;
	struct bpm_state_entry scratch;
};

static int on_state_entry(void *ud)
{
	struct state_sink *s = ud;
	char expected[PATH_MAX];

	if (s->n >= BPM_MAX_STATE || !s->scratch.name[0] || !s->scratch.version[0])
		return -E2BIG;
	if (!bpm_name_ok(s->scratch.name) || !bpm_version_ok(s->scratch.version) ||
	    !bpm_name_ok(s->scratch.source))
		return -EINVAL;
	if (snprintf(expected, sizeof(expected), "%s/%s/%s",
			SHIRUDO_BPM_PACKAGES_DIR, s->scratch.name,
			s->scratch.version) >= (int)sizeof(expected) ||
	    strcmp(expected, s->scratch.path))
		return -EINVAL;
	s->items[s->n++] = s->scratch;
	return 0;
}

static int state_read(struct bpm_state_entry *st, int *n)
{
	unsigned char *body; size_t len; int rc;
	struct state_sink sink = { .items = st };
	struct shirudo_json_array arr = { on_state_entry, &sink };
	struct shirudo_json_field sub[4], root[1];
	int64_t unused = 0;

	rc = bpm_read_file(SHIRUDO_BPM_STATE_PATH, &body, &len, 8u * 1024u * 1024u);
	if (rc == -ENOENT) { *n = 0; return 0; }
	if (rc) return rc;
	sub[0] = (struct shirudo_json_field){ .key = "name", .type = SHIRUDO_JSON_T_STRING, .dst = sink.scratch.name, .dst_cap = sizeof(sink.scratch.name) };
	sub[1] = (struct shirudo_json_field){ .key = "version", .type = SHIRUDO_JSON_T_STRING, .dst = sink.scratch.version, .dst_cap = sizeof(sink.scratch.version) };
	sub[2] = (struct shirudo_json_field){ .key = "source", .type = SHIRUDO_JSON_T_STRING, .dst = sink.scratch.source, .dst_cap = sizeof(sink.scratch.source) };
	sub[3] = (struct shirudo_json_field){ .key = "path", .type = SHIRUDO_JSON_T_STRING, .dst = sink.scratch.path, .dst_cap = sizeof(sink.scratch.path) };
	root[0] = (struct shirudo_json_field){ .key = "packages", .type = SHIRUDO_JSON_T_ARRAY, .dst = &arr, .sub = sub, .n_sub = ARRAY_SIZE(sub) };
	(void)unused;
	rc = shirudo_json_parse((const char *)body, len, root, ARRAY_SIZE(root));
	xfree(body, len + 1);
	if (rc || !root[0].seen) return rc ? rc : -EINVAL;
	*n = sink.n;
	return 0;
}

static int state_write(const struct bpm_state_entry *st, int n)
{
	char buf[1024 * 1024]; struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	int rc;
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_arr_open(&e, "packages");
	for (int i = 0; i < n; i++) {
		shirudo_json_obj_open(&e);
		shirudo_json_kv_string(&e, "name", st[i].name);
		shirudo_json_kv_string(&e, "version", st[i].version);
		shirudo_json_kv_string(&e, "source", st[i].source);
		shirudo_json_kv_string(&e, "path", st[i].path);
		shirudo_json_obj_close(&e);
	}
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);
	if (e.err) return -E2BIG;
	rc = bpm_mkdir_p(SHIRUDO_BPM_VAR_DIR, 0700);
	if (!rc) rc = atomic_write(SHIRUDO_BPM_STATE_PATH, buf, e.len, 0600);
	return rc;
}

static int load_cached_index(const char *source, struct bpm_index_entry *entries, int *n)
{
	char path[PATH_MAX];
	unsigned char *body;
	size_t len;
	int rc;

	rc = cache_path(source, path, sizeof(path));
	if (rc)
		return rc;
	rc = bpm_read_file(path, &body, &len, 64u * 1024u * 1024u);
	if (rc)
		return rc;
	rc = bpm_index_parse(body, len, entries, n);
	xfree(body, len + 1);
	return rc;
}

/* Strict enough for repository selection: numeric dotted core, optional
 * prerelease, and build metadata.  Build metadata does not affect order. */
static int semver_compare(const char *a, const char *b)
{
	const char *pa = a, *pb = b;
	for (int part = 0; part < 3; part++) {
		char *ea, *eb; unsigned long va, vb;
		va = strtoul(pa, &ea, 10); vb = strtoul(pb, &eb, 10);
		if (ea == pa || eb == pb) return strcmp(a, b);
		if (va != vb) return va > vb ? 1 : -1;
		pa = *ea == '.' ? ea + 1 : ea; pb = *eb == '.' ? eb + 1 : eb;
	}
	if (*pa == '-' || *pb == '-') {
		if (*pa != '-' || *pb != '-') return *pa == '-' ? -1 : 1;
		return strcmp(pa + 1, pb + 1);
	}
	return 0;
}

static int repo_update_one(const char *name)
{
	struct bpm_source s; struct bpm_oci_client c = {};
	struct bpm_descriptor layers[8]; int nl = 0;
	struct bpm_buffer manifest = {}, index = {}, sig = {};
	char url[PATH_MAX], cache[PATH_MAX], dir[PATH_MAX]; int rc;
	if ((rc = load_source(name, &s))) return rc;
	if ((rc = bpm_oci_parse_endpoint(s.endpoint, &c))) return rc;
	if ((rc = bpm_oci_url(&c, BPM_INDEX_REPOSITORY, "manifests", BPM_INDEX_TAG, url, sizeof(url)))) return rc;
	rc = bpm_oci_get_memory(&c, url, "application/vnd.oci.image.manifest.v1+json", &manifest); if (rc) goto out;
	if ((rc = bpm_oci_parse_manifest(manifest.data, manifest.len, layers, &nl,
				 NULL, 0)) || nl < 2) goto out;
	for (int i = 0; i < nl; i++) {
		if (!strcmp(layers[i].media, BPM_INDEX_MEDIA)) {
			char layer_hex[65];
			if ((rc = bpm_oci_url(&c, BPM_INDEX_REPOSITORY, "blobs", layers[i].digest, url, sizeof(url)))) goto out;
			rc = bpm_oci_get_memory(&c, url, BPM_INDEX_MEDIA, &index);
			if (!rc && (bpm_sha256_hex(index.data, index.len, layer_hex, sizeof(layer_hex)) ||
				    !bpm_digest_matches(layers[i].digest, layer_hex)))
				rc = -EKEYREJECTED;
			break;
		}
	}
	if (rc) goto out;
	for (int i = 0; i < nl; i++) if (!strcmp(layers[i].media, BPM_INDEX_SIG_MEDIA)) {
			char sig_hex[65];
			if ((rc = bpm_oci_url(&c, BPM_INDEX_REPOSITORY, "blobs", layers[i].digest, url, sizeof(url)))) goto out;
			rc = bpm_oci_get_memory(&c, url, BPM_INDEX_SIG_MEDIA, &sig);
			if (!rc && (bpm_sha256_hex(sig.data, sig.len, sig_hex, sizeof(sig_hex)) ||
				    !bpm_digest_matches(layers[i].digest, sig_hex)))
				rc = -EKEYREJECTED;
			break;
	}
	if (rc || !sig.data) { rc = -EINVAL; goto out; }
	if (bpm_verify_cms(index.data, index.len, sig.data, sig.len, s.key_file)) { rc = -EKEYREJECTED; goto out; }
	{
		struct bpm_index_entry checked[BPM_MAX_ENTRIES];
		int checked_n = 0;
		if (bpm_index_parse(index.data, index.len, checked, &checked_n)) { rc = -EINVAL; goto out; }
	}
	if (snprintf(dir, sizeof(dir), "%s/%s", SHIRUDO_BPM_REPOS_DIR, name) >= (int)sizeof(dir)) { rc = -ENAMETOOLONG; goto out; }
	if ((rc = bpm_mkdir_p(dir, 0700))) goto out;
	if ((rc = cache_path(name, cache, sizeof(cache)))) goto out;
	rc = atomic_write(cache, index.data, index.len, 0600);
out:
	bpm_buffer_free(&manifest);
	bpm_buffer_free(&index);
	bpm_buffer_free(&sig);
	return rc;
}

static int find_entry(const struct bpm_index_entry *e, int n, const char *name,
		      const char *version, struct bpm_index_entry *out)
{
	int found = -1;
	for (int i = 0; i < n; i++) {
		if (strcmp(e[i].name, name)) continue;
		if (version && strcmp(e[i].version, version)) continue;
		if (found < 0 || (!version && semver_compare(e[found].version, e[i].version) < 0)) found = i;
	}
	if (found < 0) return -ENOENT;
	*out = e[found]; return 0;
}

static int package_install(const struct bpm_source *s, const struct bpm_index_entry *entry,
			   const char *old_path, const char *old_version)
{
	struct bpm_oci_client c = {}; struct bpm_descriptor layers[8]; int nl = 0;
	struct bpm_buffer manifest = {};
	char url[PATH_MAX], archive[PATH_MAX] = {}, dir[PATH_MAX], package_dir[PATH_MAX];
	char digest[65]; int rc; DIR *d; struct dirent *de;
	bool found_package = false;
	char loaded[128][PATH_MAX]; char old_loads[128][PATH_MAX];
	char old_unloads[128][PATH_MAX]; int nloaded = 0, nactive = 0, nold = 0, nold_removed = 0;
	(void)old_version;
	if ((rc = bpm_oci_parse_endpoint(s->endpoint, &c))) return rc;
	if ((rc = bpm_oci_url(&c, entry->repository[0] ? entry->repository : entry->name, "manifests", entry->manifest_digest, url, sizeof(url)))) return rc;
	if ((rc = bpm_oci_get_memory(&c, url, "application/vnd.oci.image.manifest.v1+json", &manifest))) goto out;
	/* Repository indexes carry a sha256 manifest digest; direct OCI
	 * references carry the tag in this field and cannot be digest-checked. */
	if (!strncmp(entry->manifest_digest, "sha256:", 7)) {
		char manifest_hex[65];
		if (bpm_sha256_hex(manifest.data, manifest.len, manifest_hex, sizeof(manifest_hex)) ||
		    !bpm_digest_matches(entry->manifest_digest, manifest_hex)) {
			rc = -EKEYREJECTED;
			goto out;
		}
	}
	if ((rc = bpm_oci_parse_manifest(manifest.data, manifest.len, layers, &nl,
				 NULL, 0))) goto out;
	for (int i = 0; i < nl; i++) if (!strcmp(layers[i].media, BPM_PACKAGE_MEDIA)) {
		found_package = true;
		if (entry->package_digest[0] && strcmp(entry->package_digest, layers[i].digest)) { rc = -EKEYREJECTED; goto out; }
		if (entry->package_size > 0 && entry->package_size != layers[i].size) { rc = -EKEYREJECTED; goto out; }
		if ((rc = bpm_oci_url(&c, entry->repository[0] ? entry->repository : entry->name, "blobs", layers[i].digest, url, sizeof(url)))) goto out;
		if (snprintf(dir, sizeof(dir), "%s/%s", SHIRUDO_BPM_PACKAGES_DIR, entry->name) >= (int)sizeof(dir)) { rc = -ENAMETOOLONG; goto out; }
		if ((rc = bpm_mkdir_p(dir, 0700))) goto out;
		if (snprintf(package_dir, sizeof(package_dir), "%s/%s", dir, entry->version) >= (int)sizeof(package_dir)) { rc = -ENAMETOOLONG; goto out; }
		if ((rc = bpm_mkdir_p(SHIRUDO_BPM_STAGING_DIR, 0700))) goto out;
		if (snprintf(archive, sizeof(archive), "%s/%s-%s.bee", SHIRUDO_BPM_STAGING_DIR, entry->name, entry->version) >= (int)sizeof(archive)) { rc = -ENAMETOOLONG; goto out; }
		rc = bpm_oci_get_file(&c, url, BPM_PACKAGE_MEDIA, archive); if (rc) goto out;
	if (sha256_file_hex(archive, digest, sizeof(digest)) || !bpm_digest_matches(layers[i].digest, digest)) { rc = -EKEYREJECTED; goto out; }
		if (access(package_dir, F_OK) == 0) { rc = -EEXIST; goto out; }
		rc = extract_archive(archive, package_dir); if (rc) goto out;
		{
			char cert[PATH_MAX];
			if (strlen(package_dir) + strlen("/cert.der") >= sizeof(cert)) {
				rc = -ENAMETOOLONG;
				goto out;
			}
			sprintf(cert, "%s/cert.der", package_dir);
			if (cert_matches_active(cert)) { rc = -EKEYREJECTED; goto out; }
		}
		{
			char updir[PATH_MAX];
			if (snprintf(updir, sizeof(updir), "%s/upatches", package_dir) >= (int)sizeof(updir)) { rc = -ENAMETOOLONG; goto out; }
			d = opendir(updir); if (!d) { rc = -errno; goto out; }
		}
		while ((de = readdir(d))) {
			char up[PATH_MAX]; struct stat st;
			if (de->d_name[0] == '.') continue;
			if (!strstr(de->d_name, ".upatch") || strstr(de->d_name, ".unload.upatch")) continue;
			if (snprintf(up, sizeof(up), "%s/upatches/%s", package_dir, de->d_name) >= (int)sizeof(up)) { rc = -ENAMETOOLONG; break; }
			if (stat(up, &st) || !S_ISREG(st.st_mode)) continue;
			if (nloaded >= 128) { rc = -E2BIG; break; }
			snprintf(loaded[nloaded], sizeof(loaded[nloaded]), "%s", up);
			nloaded++;
		}
		closedir(d);
		if (rc || !nloaded) { if (!rc) rc = -EINVAL; goto out; }
		if (old_path && old_path[0]) {
			char olddir[PATH_MAX];
			if (snprintf(olddir, sizeof(olddir), "%s/upatches", old_path) >= (int)sizeof(olddir)) { rc = -ENAMETOOLONG; goto out; }
			d = opendir(olddir);
			if (d) {
				while ((de = readdir(d))) {
					const char *suffix = strstr(de->d_name, ".unload.upatch");
					if (suffix && nold < 128) {
						size_t dir_len = strlen(olddir);
						size_t entry_len = strlen(de->d_name);
						size_t base_len = (size_t)(suffix - de->d_name);
						if (dir_len + 1 + entry_len + 1 >= sizeof(old_unloads[nold]) ||
							dir_len + 1 + base_len + strlen(".upatch") + 1 >= sizeof(old_loads[nold])) {
							rc = -ENAMETOOLONG;
							break;
						}
						memcpy(old_unloads[nold], olddir, dir_len);
						old_unloads[nold][dir_len] = '/';
						memcpy(old_unloads[nold] + dir_len + 1, de->d_name,
							entry_len + 1);
						memcpy(old_loads[nold], olddir, dir_len);
						old_loads[nold][dir_len] = '/';
						memcpy(old_loads[nold] + dir_len + 1, de->d_name, base_len);
						memcpy(old_loads[nold] + dir_len + 1 + base_len,
							".upatch", strlen(".upatch") + 1);
						nold++;
					}
				}
				closedir(d);
			}
			for (int old_i = 0; old_i < nold; old_i++) {
				if (shirudo_upatch_remove(old_unloads[old_i])) {
					rc = -EIO;
					for (int restore_i = nold_removed - 1; restore_i >= 0; restore_i--)
						(void)shirudo_upatch_install(old_loads[restore_i]);
					goto out;
				}
				nold_removed++;
			}
		}
		for (int loaded_i = 0; loaded_i < nloaded; loaded_i++) {
			if (shirudo_upatch_install(loaded[loaded_i])) { rc = -EIO; goto rollback; }
			nactive++;
		}
		{
			char saved[PATH_MAX];
			if (snprintf(saved, sizeof(saved), "%s/%s-%s.bee", dir, entry->name, entry->version) < (int)sizeof(saved))
				(void)rename(archive, saved);
		}
		break;
	}
	if (!rc && !found_package) rc = -EINVAL;
	goto out;
rollback:
	for (int active_i = nactive - 1; active_i >= 0; active_i--) {
		char unload[PATH_MAX];
		const char *base = strrchr(loaded[active_i], '/');
		if (!base) continue;
		{
			size_t dir_len = (size_t)(base - loaded[active_i]);
			size_t name_len = strlen(base + 1);
			if (name_len < strlen(".upatch") ||
				dir_len + 1 + name_len - strlen(".upatch") +
				strlen(".unload.upatch") + 1 >= sizeof(unload))
				continue;
			memcpy(unload, loaded[active_i], dir_len);
			unload[dir_len] = '/';
			memcpy(unload + dir_len + 1, base + 1,
				name_len - strlen(".upatch"));
			memcpy(unload + dir_len + 1 + name_len - strlen(".upatch"),
				".unload.upatch", strlen(".unload.upatch") + 1);
		}
		(void)shirudo_upatch_remove(unload);
	}
	for (int restore_i = nold - 1; restore_i >= 0; restore_i--)
		(void)shirudo_upatch_install(old_loads[restore_i]);
out:
	bpm_buffer_free(&manifest);
	if (rc && archive[0]) unlink(archive);
	return rc;
}

static int parse_package_ref(const char *raw, char *source, size_t ssz,
			     char *name, size_t nsz, char *version, size_t vsz)
{
	const char *slash, *at;
	if (!raw || !(slash = strchr(raw, '/')) || slash == raw) return -EINVAL;
	if ((size_t)(slash - raw) >= ssz) return -ENAMETOOLONG;
	memcpy(source, raw, slash - raw); source[slash - raw] = 0;
	at = strchr(slash + 1, '@');
	if (!at) { snprintf(name, nsz, "%s", slash + 1); version[0] = 0; }
	else { if ((size_t)(at - slash - 1) >= nsz) return -ENAMETOOLONG; memcpy(name, slash + 1, at - slash - 1); name[at - slash - 1] = 0; snprintf(version, vsz, "%s", at + 1); }
	return bpm_name_ok(source) && bpm_name_ok(name) && strlen(name) < nsz &&
		(!version[0] || (strlen(version) < vsz && bpm_version_ok(version))) ?
		0 : -EINVAL;
}

static int cmd_bpm_config(int argc, const char **argv)
{
	const char *op = argc > 1 ? argv[1] : NULL;
	if (!op || shirudo_is_help(op)) { fprintf(stderr, "usage: shirudo bpm config register {add|list|remove} ...\n"); return op ? 0 : 2; }
	if (strcmp(op, "register")) return 2;
	if (argc < 3) return 2;
	if (!strcmp(argv[2], "list")) {
		DIR *d = opendir(SHIRUDO_BPM_REGISTRIES_DIR); struct dirent *e;
		if (!d) return errno == ENOENT ? 0 : 1;
		while ((e = readdir(d))) { size_t n = strlen(e->d_name); if (n > 5 && !strcmp(e->d_name + n - 5, ".conf")) printf("%.*s\n", (int)(n - 5), e->d_name); }
		closedir(d); return 0;
	}
	if ((!strcmp(argv[2], "remove") || !strcmp(argv[2], "rm")) && argc == 4) {
		char p[PATH_MAX], key[PATH_MAX]; struct bpm_source s;
		if (source_path(argv[3], p, sizeof(p))) return 2;
		if (load_source(argv[3], &s) == 0 && s.key_file[0]) unlink(s.key_file);
		if (unlink(p) && errno != ENOENT) return 1;
		if (snprintf(key, sizeof(key), "%s/%s.der", SHIRUDO_BPM_KEYS_DIR, argv[3]) < (int)sizeof(key)) unlink(key);
		return 0;
	}
	if (!strcmp(argv[2], "add") && argc >= 5) {
		struct bpm_source s = {}; const char *key = NULL; char managed[PATH_MAX];
		struct shirudo_cert cert = {};
		bpm_copy_string(s.name, sizeof(s.name), argv[3]);
		bpm_copy_string(s.endpoint, sizeof(s.endpoint), argv[4]);
		for (int i = 5; i < argc; i++) {
			if (!strncmp(argv[i], "--key-file=", 11)) key = argv[i] + 11;
			else if (!strcmp(argv[i], "--key-file") && i + 1 < argc) key = argv[++i];
		}
		if (!key || shirudo_cert_read_file(key, &cert)) { shirudo_cert_free(&cert); pr_err("bpm: register add requires a valid oci:// endpoint and --key-file certificate"); return 2; }
		if (!bpm_name_ok(s.name) || bpm_oci_parse_endpoint(s.endpoint, &(struct bpm_oci_client){}) ) { shirudo_cert_free(&cert); pr_err("bpm: register add requires a valid oci:// endpoint and --key-file certificate"); return 2; }
		shirudo_cert_free(&cert);
		if (bpm_mkdir_p(SHIRUDO_BPM_REGISTRIES_DIR, 0700) || bpm_mkdir_p(SHIRUDO_BPM_KEYS_DIR, 0700)) return 1;
		if (snprintf(managed, sizeof(managed), "%s/%s.der", SHIRUDO_BPM_KEYS_DIR, s.name) >= (int)sizeof(managed)) return 1;
		if (copy_file(key, managed, 0644)) return 1;
		if (strlen(managed) >= sizeof(s.key_file))
			return 1;
		bpm_copy_string(s.key_file, sizeof(s.key_file), managed);
		return save_source(&s) ? 1 : 0;
	}
	return 2;
}

struct bpm_tree_config {
	char endpoint[BPM_MAX_ENDPOINT];
	char reference[BPM_MAX_DIGEST];
};

static int load_tree_config(struct bpm_tree_config *cfg)
{
	char line[PATH_MAX];
	FILE *fp;

	*cfg = (struct bpm_tree_config){};
	fp = fopen(SHIRUDO_BPM_TREE_ETC_PATH, "r");
	if (!fp)
		return -errno;
	while (fgets(line, sizeof(line), fp)) {
		char key[64], value[PATH_MAX];
		char *eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq++ = '\0';
		bpm_trim(line, key, sizeof(key));
		bpm_trim(eq, value, sizeof(value));
		if (value[0] == '"') {
			size_t len = strlen(value);
			if (len < 2 || value[len - 1] != '"') {
				fclose(fp);
				return -EINVAL;
			}
			memmove(value, value + 1, len - 2);
			value[len - 2] = '\0';
		}
		if (!strcmp(key, "endpoint"))
			bpm_copy_string(cfg->endpoint, sizeof(cfg->endpoint), value);
		else if (!strcmp(key, "reference"))
			bpm_copy_string(cfg->reference, sizeof(cfg->reference), value);
	}
	fclose(fp);
	if (!cfg->endpoint[0] || !cfg->reference[0])
		return -EINVAL;
	return 0;
}

static int parse_tree_repository(const char *raw, struct bpm_oci_client *c,
					 char *repository, size_t repository_sz)
{
	const char *p, *slash;
	char endpoint[BPM_MAX_ENDPOINT];

	if (!raw || strncmp(raw, "oci://", 6))
		return -EINVAL;
	p = raw + 6;
	slash = strchr(p, '/');
	if (!slash || slash == p || !slash[1] || strchr(p, '?') ||
	    strchr(p, '#') || strchr(p, '@'))
		return -EINVAL;
	if ((size_t)(slash - p) + 6 >= sizeof(endpoint) ||
	    strlen(slash + 1) >= repository_sz)
		return -ENAMETOOLONG;
	memcpy(endpoint, "oci://", 6);
	memcpy(endpoint + 6, p, (size_t)(slash - p));
	endpoint[6 + (size_t)(slash - p)] = '\0';
	bpm_copy_string(repository, repository_sz, slash + 1);
	if (strstr(repository, "..") || strstr(repository, "//") ||
	    strchr(repository, ':'))
		return -EINVAL;
	return bpm_oci_parse_endpoint(endpoint, c);
}

static int tree_digest_hex(const char *digest, uint8_t out[32])
{
	if (!digest || strncmp(digest, "sha256:", 7))
		return -EINVAL;
	return shirudo_hex_decode(digest + 7, out, 32);
}

static int tree_fetch_publication(const struct bpm_tree_config *cfg,
					 struct shirudo_tree_publication *pub,
					 char *manifest_digest, size_t digest_sz)
{
	struct bpm_oci_client c = {};
	char repository[BPM_MAX_ENDPOINT];
	int rc = parse_tree_repository(cfg->endpoint, &c,
						 repository, sizeof(repository));

	if (rc)
		return rc;
	return bpm_tree_fetch_publication(&c, repository, cfg->reference,
					 SHIRUDO_CERT_PATH, pub,
					 manifest_digest, digest_sz);
}

static int tree_verify_upatch(const char *path, const char *expected,
				      const char *id, bool unload)
{
	struct shirudo_upatch u;
	char name[SHIRUDO_UPATCH_NAME_MAX + 1];
	char actual[65];
	int rc = shirudo_upatch_open(path, &u);
	if (rc)
		return rc;
	memcpy(name, u.hdr.name, SHIRUDO_UPATCH_NAME_MAX);
	name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
	shirudo_hex_encode(u.hdr.payload_sha256, 32, actual);
	if (!bpm_digest_matches(expected, actual) ||
	    (id && strcmp(name, id)) ||
	    shirudo_upatch_is_unload(&u) != unload)
		rc = -EKEYREJECTED;
	shirudo_upatch_close(&u);
	return rc;
}

static int tree_pull_artifact(const struct shirudo_tree_operation *op,
				      char *path, size_t path_sz)
{
	struct bpm_oci_client c = {};
	struct bpm_descriptor layers[BPM_MAX_ENTRIES];
	struct bpm_buffer manifest = {}, blob = {};
	char repository[BPM_MAX_ENDPOINT], url[PATH_MAX], cache[PATH_MAX];
	char hex[65];
	unsigned int expected_flags;
	int nl = 0, rc;

	if (tree_digest_hex(op->artifact.payload_sha256, (uint8_t[32]){}))
		return -EINVAL;
	/* Load and unload directives intentionally share payload_sha256.  Keep
	 * both variants in the local cache by including the expected directive
	 * flags in the cache key. */
	expected_flags = !strcmp(op->op, "delete") ? SHIRUDO_DIRECTIVE_UNLOAD : 0;
	if (snprintf(cache, sizeof(cache), "%s/%s-flags-%u.upatch",
		     SHIRUDO_BPM_TREE_ARTIFACTS_DIR,
		     op->artifact.payload_sha256 +
		     (!strncmp(op->artifact.payload_sha256, "sha256:", 7) ? 7 : 0),
		     expected_flags) >=
	    (int)sizeof(cache))
		return -ENAMETOOLONG;
	if (!access(cache, R_OK)) {
		bpm_copy_string(path, path_sz, cache);
		return tree_verify_upatch(path, op->artifact.payload_sha256, op->id,
					  !strcmp(op->op, "delete"));
	}
	rc = parse_tree_repository(op->artifact.repository, &c, repository,
					   sizeof(repository));
	if (rc)
		return rc;
	rc = bpm_oci_url(&c, repository, "manifests",
				  op->artifact.manifest_digest, url, sizeof(url));
	if (rc)
		return rc;
	rc = bpm_oci_get_memory(&c, url,
				"application/vnd.oci.image.manifest.v1+json", &manifest);
	if (rc)
		goto out;
	if (bpm_sha256_hex(manifest.data, manifest.len, hex, sizeof(hex)) ||
	    !bpm_digest_matches(op->artifact.manifest_digest, hex)) {
		rc = -EKEYREJECTED;
		goto out;
	}
	rc = bpm_oci_parse_manifest(manifest.data, manifest.len, layers, &nl, NULL, 0);
	if (rc)
		goto out;
	for (int i = 0; i < nl; i++) {
		if (strcmp(layers[i].digest, op->artifact.layer_digest) ||
		    strcmp(layers[i].media, BPM_UPATCH_MEDIA))
			continue;
		rc = bpm_oci_url(&c, repository, "blobs", layers[i].digest,
				   url, sizeof(url));
		if (rc)
			goto out;
		rc = bpm_oci_get_memory(&c, url, layers[i].media, &blob);
		if (rc)
			goto out;
		if (bpm_sha256_hex(blob.data, blob.len, hex, sizeof(hex)) ||
		    !bpm_digest_matches(layers[i].digest, hex) ||
		    (layers[i].size >= 0 && (int64_t)blob.len != layers[i].size))
			rc = -EKEYREJECTED;
		if (rc)
			goto out;
		if (bpm_mkdir_p(SHIRUDO_BPM_TREE_ARTIFACTS_DIR, 0700)) {
			rc = -errno;
			goto out;
		}
		rc = atomic_write(cache, blob.data, blob.len, 0600);
		if (rc)
			goto out;
		(void)shirudo_seal_label(cache);
		bpm_copy_string(path, path_sz, cache);
		rc = tree_verify_upatch(path, op->artifact.payload_sha256, op->id,
					 !strcmp(op->op, "delete"));
		goto out;
	}
	rc = -ENOENT;
out:
	bpm_buffer_free(&manifest);
	bpm_buffer_free(&blob);
	return rc;
}

static int tree_write_report(const char *path, const struct shirudo_tree_state *s,
				     int selected, int skipped, int applied,
				     int module_skipped, int dry_run,
				     int tpm_available)
{
	char buf[4096];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_kv_bool(&e, "dry_run", dry_run);
	shirudo_json_kv_int(&e, "selected", selected);
	shirudo_json_kv_int(&e, "skipped", skipped);
	shirudo_json_kv_int(&e, "applied", applied);
	shirudo_json_kv_int(&e, "module_skipped", module_skipped);
	shirudo_json_kv_bool(&e, "tpm_available", tpm_available);
	shirudo_json_kv_int(&e, "last_seq", s->last_seq);
	if (tpm_available)
		shirudo_json_kv_string(&e, "projection_root_tpm",
				       s->projection_root_tpm);
	else
		shirudo_json_kv_null(&e, "projection_root_tpm");
	shirudo_json_obj_close(&e);
	if (e.err)
		return e.err;
	if (path)
		return atomic_write(path, buf, e.len, 0600);
	printf("%s\n", buf);
	return 0;
}

static int tree_write_pending(const struct shirudo_tree_operation *op)
{
	char buf[1024];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	int rc;

	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_kv_int(&e, "seq", op->seq);
	shirudo_json_kv_string(&e, "id", op->id);
	shirudo_json_kv_string(&e, "operation_digest", op->operation_digest);
	shirudo_json_obj_close(&e);
	if (e.err)
		return e.err;
	if (bpm_mkdir_p(SHIRUDO_BPM_TREE_VAR_DIR, 0700))
		return -errno;
	rc = atomic_write(SHIRUDO_BPM_TREE_PENDING_PATH, buf, e.len, 0600);
	if (rc)
		return rc;
	(void)shirudo_seal_label(SHIRUDO_BPM_TREE_PENDING_PATH);
	return 0;
}

static int tree_status_write(const char *id, const char *status)
{
	char path[PATH_MAX];
	int rc;

	if (!id || !shirudo_upatch_name_valid(id) || !status || !status[0])
		return -EINVAL;
	rc = bpm_mkdir_p(SHIRUDO_BPM_TREE_STATUS_DIR, 0700);
	if (rc)
		return rc;
	if (snprintf(path, sizeof(path), "%s/%s",
		     SHIRUDO_BPM_TREE_STATUS_DIR, id) >= (int)sizeof(path))
		return -ENAMETOOLONG;
	return atomic_write(path, status, strlen(status), 0600);
}

static void tree_status_clear(const char *id)
{
	char path[PATH_MAX];

	if (!id || !shirudo_upatch_name_valid(id) ||
	    snprintf(path, sizeof(path), "%s/%s",
		     SHIRUDO_BPM_TREE_STATUS_DIR, id) >= (int)sizeof(path))
		return;
	(void)unlink(path);
}

struct bpm_tree_pending {
	int64_t seq;
	char id[SHIRUDO_TREE_STRING_MAX];
	char operation_digest[128];
};

static int tree_read_pending(struct bpm_tree_pending *pending)
{
	unsigned char *body;
	size_t len;
	int64_t schema = 0;
	struct shirudo_json_field fields[] = {
		{ "schema", SHIRUDO_JSON_T_INT, &schema, 0, 0, NULL, 0 },
		{ "seq", SHIRUDO_JSON_T_INT, &pending->seq, 0, 0, NULL, 0 },
		{ "id", SHIRUDO_JSON_T_STRING, pending->id,
		  sizeof(pending->id), 0, NULL, 0 },
		{ "operation_digest", SHIRUDO_JSON_T_STRING,
		  pending->operation_digest, sizeof(pending->operation_digest),
		  0, NULL, 0 },
	};
	int rc = bpm_read_file(SHIRUDO_BPM_TREE_PENDING_PATH, &body, &len,
					 64u * 1024u);
	if (rc)
		return rc;
	rc = shirudo_json_parse((const char *)body, len, fields, ARRAY_SIZE(fields));
	if (!rc && (schema != 1 || pending->seq <= 0 ||
			!shirudo_upatch_name_valid(pending->id) ||
			tree_digest_hex(pending->operation_digest, (uint8_t[32]){})))
		rc = -EINVAL;
	xfree(body, len + 1);
	return rc;
}

/*
 * Measure one applied tree operation into this boot's register and
 * record it: event = SHA256("shirudo-tree\0" || seq || operation_digest).
 * The tree's own projection stays a file-based chain; the register is
 * what an operator attests.
 */
static int tree_measure_operation(const struct shirudo_tree_operation *op,
				  const uint8_t operation_digest[32])
{
	uint8_t event[32], chain[32];
	struct shirudo_json_emit e;
	char line[4096], ts[32], boot_id[64], nv_index[16];
	char digest_hex[65], chain_hex[65];
	int rc;

	shirudo_chain_tree_event(op->seq, operation_digest, event);
	rc = shirudo_chain_extend(event, chain);
	if (rc)
		return rc;

	shirudo_eventlog_timestamp(ts, sizeof(ts));
	shirudo_eventlog_boot_id(boot_id, sizeof(boot_id));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
	shirudo_hex_encode(event, 32, digest_hex);
	shirudo_hex_encode(chain, 32, chain_hex);
	e = (struct shirudo_json_emit){ .buf = line, .cap = sizeof(line) };
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 2);
	shirudo_json_kv_string(&e, "ts", ts);
	shirudo_json_kv_string(&e, "nv_index", nv_index);
	shirudo_json_kv_string(&e, "alg", "sha256");
	shirudo_json_kv_string(&e, "digest", digest_hex);
	shirudo_json_kv_string(&e, "type", "tree_op");
	shirudo_json_kv_string(&e, "boot_id", boot_id);
	shirudo_json_obj_open_key(&e, "tree");
	shirudo_json_kv_int(&e, "seq", op->seq);
	shirudo_json_kv_string(&e, "op", op->op);
	shirudo_json_kv_string(&e, "id", op->id);
	shirudo_json_kv_string(&e, "operation_digest", op->operation_digest);
	shirudo_json_obj_close(&e);
	shirudo_json_kv_string(&e, "chain", chain_hex);
	shirudo_json_obj_close(&e);
	if (e.err)
		return e.err;
	return shirudo_eventlog_append(line);
}

/* Complete the only non-idempotent window: the process may have
 * appended the event before the sealed cursor was committed. */
static int tree_recover_pending(const struct shirudo_tree_publication *pub,
					struct shirudo_tree_state *state)
{
	struct bpm_tree_pending pending = {};
	const struct shirudo_tree_operation *op = NULL;
	uint8_t digest[32], previous[32], next[32], replay[32];
	bool applied = false, event_present = false;
	int rc;

	rc = tree_read_pending(&pending);
	if (rc == -ENOENT)
		return 0;
	if (rc)
		return rc;
	for (int i = 0; i < pub->n_operations; i++) {
		if (pub->operations[i].seq == pending.seq &&
		    !strcmp(pub->operations[i].id, pending.id) &&
		    !strcmp(pub->operations[i].operation_digest,
			    pending.operation_digest)) {
			op = &pub->operations[i];
			break;
		}
	}
	if (!op)
		return -ERANGE;
	if (pending.seq <= state->last_seq) {
		(void)unlink(SHIRUDO_BPM_TREE_PENDING_PATH);
		return 0;
	}
	if (tree_digest_hex(pending.operation_digest, digest) ||
	    shirudo_hex_decode(state->projection_root, previous, 32))
		return -EINVAL;
	shirudo_sha256_2(previous, sizeof(previous), digest, sizeof(digest), next);

	rc = shirudo_tree_event_replay(replay);
	if (!rc) {
		if (shirudo_ct_eq(replay, next, sizeof(replay))) {
			applied = true;
			event_present = true;
		} else if (!shirudo_ct_eq(replay, previous, sizeof(replay))) {
			return -EKEYREJECTED;
		}
	} else if (rc != -ENOENT) {
		return -EKEYREJECTED;
	}
	if (!applied)
		return 0; /* Still pre-operation; retry normally. */
	if (!event_present) {
		rc = shirudo_tree_event_append(op->seq, op->operation_digest, next);
		if (rc)
			return rc;
	}
	shirudo_hex_encode(next, sizeof(next), state->projection_root);
	shirudo_hex_encode(next, sizeof(next), state->projection_root_tpm);
	state->last_seq = op->seq;
	rc = shirudo_tree_state_write(state);
	if (rc)
		return rc;
	(void)unlink(SHIRUDO_BPM_TREE_PENDING_PATH);
	return 0;
}

static int tree_validate_operation(const struct shirudo_tree_operation *op)
{
	uint8_t digest[32];
	char expected_digest[72];

	if (!op || op->seq <= 0 || !shirudo_upatch_name_valid(op->id) ||
	    (strcmp(op->op, "add") && strcmp(op->op, "delete")))
		return -EINVAL;
	if (tree_digest_hex(op->operation_digest, digest) ||
	    tree_digest_hex(op->artifact.manifest_digest, digest) ||
	    tree_digest_hex(op->artifact.layer_digest, digest) ||
	    tree_digest_hex(op->artifact.payload_sha256, digest))
		return -EINVAL;
	if (shirudo_tree_operation_digest(op, expected_digest))
		return -EINVAL;
	if (strcmp(op->operation_digest, expected_digest))
		return -EKEYREJECTED;
	if (op->expected_payload_sha256[0] &&
	    tree_digest_hex(op->expected_payload_sha256, digest))
		return -EINVAL;
	return 0;
}

static void tree_sync_report_error(const char *phase,
				   const struct shirudo_tree_operation *op, int rc)
{
	int err;

	if (rc > 0) {
		if (op)
			pr_err("bpm tree sync: phase=%s seq=%lld id=%s rc=%d "
			       "(command status)", phase, (long long)op->seq,
			       op->id, rc);
		else
			pr_err("bpm tree sync: phase=%s rc=%d (command status)",
			       phase, rc);
		return;
	}
	err = rc < 0 ? -rc : 0;

	if (op)
		pr_err("bpm tree sync: phase=%s seq=%lld id=%s rc=%d (%s)",
		       phase, (long long)op->seq, op->id, rc,
		       err ? strerror(err) : "success");
	else
		pr_err("bpm tree sync: phase=%s rc=%d (%s)", phase, rc,
		       err ? strerror(err) : "success");
}

static int cmd_bpm_tree_sync(int argc, const char **argv)
{
	struct bpm_tree_config cfg;
	struct shirudo_tree_publication pub = {};
	struct shirudo_tree_state state = {};
	char manifest_digest[BPM_MAX_DIGEST];
	char report[PATH_MAX] = {};
	bool dry_run = false, have_state = false;
	bool same_manifest;
	int selected = 0, skipped = 0, applied = 0, module_skipped = 0;
	int tpm_available = 0;
	int rc;
	#define TREE_SYNC_RETURN(value) do { \
		shirudo_tree_publication_free(&pub); \
		return (value); \
	} while (0)

	if (argc < 2 || strcmp(argv[1], "sync"))
		TREE_SYNC_RETURN(-EINVAL);
	for (int i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "--dry-run"))
			dry_run = true;
		else if (!strncmp(argv[i], "--report=", 9))
			bpm_copy_string(report, sizeof(report), argv[i] + 9);
		else if (!strcmp(argv[i], "--report") && i + 1 < argc)
			bpm_copy_string(report, sizeof(report), argv[++i]);
		else if (shirudo_is_help(argv[i])) {
			printf("usage: shirudo bpm tree sync [--dry-run] [--report=<path>]\n");
			TREE_SYNC_RETURN(0);
		} else {
			TREE_SYNC_RETURN(-EINVAL);
		}
	}
	rc = load_tree_config(&cfg);
	if (rc == -ENOENT)
		TREE_SYNC_RETURN(0); /* Optional integration: manual `shirudo upatch` remains valid. */
	if (rc)
		TREE_SYNC_RETURN(rc);
	rc = shirudo_tree_state_read(&state);
	if (!rc) {
		have_state = true;
	} else if (rc != -ENOENT) {
		TREE_SYNC_RETURN(rc);
	}
	rc = tree_fetch_publication(&cfg, &pub, manifest_digest,
					 sizeof(manifest_digest));
	if (rc)
		TREE_SYNC_RETURN(rc);
	if (pub.parent_manifest_digest[0] &&
	    tree_digest_hex(pub.parent_manifest_digest, (uint8_t[32]){}))
		TREE_SYNC_RETURN(-EINVAL);
	if (pub.base_seq != 0)
		TREE_SYNC_RETURN(-ENOTSUP); /* snapshot compaction belongs to a later schema */
	if (pub.n_operations && pub.operations[0].seq != pub.base_seq + 1)
		TREE_SYNC_RETURN(-EINVAL);
	if (pub.n_operations && pub.head_seq != pub.operations[pub.n_operations - 1].seq)
		TREE_SYNC_RETURN(-EINVAL);
	if (!pub.n_operations && pub.head_seq != pub.base_seq)
		TREE_SYNC_RETURN(-EINVAL);
	for (int i = 0; i < pub.n_operations; i++) {
		rc = tree_validate_operation(&pub.operations[i]);
		if (rc) {
			tree_sync_report_error("operation_validate", &pub.operations[i], rc);
			TREE_SYNC_RETURN(rc);
		}
	}
	same_manifest = have_state && !strcmp(state.manifest_digest, manifest_digest);
	if (have_state && strcmp(state.tree_id, pub.tree_id))
		TREE_SYNC_RETURN(-EINVAL);
	if (have_state && !same_manifest && pub.generation <= state.generation)
		TREE_SYNC_RETURN(-ERANGE);
	if (have_state && !same_manifest && pub.parent_manifest_digest[0] &&
	    strcmp(pub.parent_manifest_digest, state.manifest_digest))
		TREE_SYNC_RETURN(-ERANGE);
	if (have_state && pub.head_seq < state.last_seq)
		TREE_SYNC_RETURN(-ERANGE);
	if (have_state && pub.base_seq > state.last_seq)
		TREE_SYNC_RETURN(-ERANGE); /* The publication must contain the cursor base. */
	if (!have_state && pub.base_seq != 0)
		TREE_SYNC_RETURN(-ERANGE);
	if (!have_state) {
		state.schema = 1;
		bpm_copy_string(state.tree_id, sizeof(state.tree_id), pub.tree_id);
		memset(state.projection_root, '0', 64);
		state.projection_root[64] = '\0';
		memset(state.projection_root_tpm, '0', 64);
		state.projection_root_tpm[64] = '\0';
	}
	rc = tree_recover_pending(&pub, &state);
	if (rc) {
		tree_sync_report_error("pending_recovery", NULL, rc);
		TREE_SYNC_RETURN(rc);
	}
	tpm_available = shirudo_chain_read((uint8_t[32]){}) == 0;
	for (int i = 0; i < pub.n_operations; i++) {
		struct shirudo_tree_operation *op = &pub.operations[i];
		uint8_t digest[32], previous[32], next[32];
		char artifact[PATH_MAX];
		bool match, skipped_module = false;

		if (op->seq <= state.last_seq)
			continue;
		match = shirudo_tree_selector_matches(&op->selector);
		if (!match) {
			skipped++;
			if (!dry_run) state.last_seq = op->seq;
			continue;
		}
		selected++;
		if (dry_run)
			continue;
		rc = tree_digest_hex(op->operation_digest, digest);
		if (rc) {
			tree_sync_report_error("operation_digest_parse", op, rc);
			TREE_SYNC_RETURN(-EINVAL);
		}
		if (op->expected_payload_sha256[0] &&
		    strcmp(op->expected_payload_sha256, op->artifact.payload_sha256)) {
			tree_sync_report_error("expected_payload_digest", op,
					       -EKEYREJECTED);
			TREE_SYNC_RETURN(-EKEYREJECTED);
		}
		rc = tree_write_pending(op);
		if (rc) {
			tree_sync_report_error("pending_write", op, rc);
			TREE_SYNC_RETURN(rc);
		}
		rc = tree_pull_artifact(op, artifact, sizeof(artifact));
		if (rc) {
			tree_sync_report_error("artifact_fetch_or_verify", op, rc);
			TREE_SYNC_RETURN(rc);
		}
		if (!strcmp(op->op, "add"))
			rc = shirudo_upatch_install(artifact);
		else if (!strcmp(op->op, "delete"))
			rc = shirudo_upatch_remove(artifact);
		else
			TREE_SYNC_RETURN(-EINVAL);
		if (rc == SHIRUDO_UPATCH_INSTALL_TARGET_MISSING &&
		    !strcmp(op->op, "add")) {
			skipped_module = true;
			rc = 0;
			module_skipped++;
			pr_warn("bpm tree: skipped %s: module not loaded", op->id);
		}
		if (rc) {
			tree_sync_report_error("upatch_install", op, rc);
			TREE_SYNC_RETURN(rc);
		}
		if (shirudo_hex_decode(state.projection_root, previous, 32))
		{
			tree_sync_report_error("projection_root_decode", op, -EINVAL);
			TREE_SYNC_RETURN(-EINVAL);
		}
		rc = tree_measure_operation(op, digest);
		if (rc) {
			tree_sync_report_error("register_extend", op, rc);
			TREE_SYNC_RETURN(rc);
		}
		shirudo_sha256_2(previous, 32, digest, 32, next);
		shirudo_hex_encode(next, 32, state.projection_root);
		shirudo_hex_encode(next, 32, state.projection_root_tpm);
		rc = shirudo_tree_event_append(op->seq, op->operation_digest, next);
		if (rc) {
			tree_sync_report_error("tree_event_append", op, rc);
			TREE_SYNC_RETURN(rc);
		}
		state.last_seq = op->seq;
		applied++;
		rc = shirudo_tree_state_write(&state);
		if (rc) {
			tree_sync_report_error("tree_state_commit", op, rc);
			TREE_SYNC_RETURN(rc);
		}
		if (skipped_module)
			rc = tree_status_write(op->id, "skipped: module not loaded");
		else
			tree_status_clear(op->id);
		if (rc) {
			tree_sync_report_error("tree_status_write", op, rc);
			TREE_SYNC_RETURN(rc);
		}
		(void)unlink(SHIRUDO_BPM_TREE_PENDING_PATH);
	}
	if (!dry_run) {
		state.generation = pub.generation;
		bpm_copy_string(state.manifest_digest, sizeof(state.manifest_digest),
				manifest_digest);
		if (!state.tree_id[0])
			bpm_copy_string(state.tree_id, sizeof(state.tree_id), pub.tree_id);
		rc = shirudo_tree_state_write(&state);
		if (rc) {
			tree_sync_report_error("tree_state_commit_final", NULL, rc);
			TREE_SYNC_RETURN(rc);
		}
	}
	rc = tree_write_report(report[0] ? report : NULL, &state, selected,
			       skipped, applied, module_skipped, dry_run,
			       tpm_available);
	shirudo_tree_publication_free(&pub);
	#undef TREE_SYNC_RETURN
	return rc;
}

static void bpm_tree_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm tree sync [--dry-run] [--report=<path>]\n"
		"       shirudo bpm tree append <package-file> <repository> [options]\n\n"
		"sync applies the configured tree on a target. append is operator-only:\n"
		"it runs in shirudo-build and publishes the [upatches.tree] entries of a\n"
		"built package as the next operations of the signed tree; see\n"
		"`shirudo bpm tree append --help` where the operator package is installed.\n");
}

static int remove_tree_entry(const char *path, const struct stat *st,
			     int type, struct FTW *ftw)
{
	(void)st;
	(void)ftw;
	if (type == FTW_DP || type == FTW_D)
		return rmdir(path) ? -1 : 0;
	return unlink(path) ? -1 : 0;
}

static int remove_tree(const char *path)
{
	if (nftw(path, remove_tree_entry, 32, FTW_DEPTH | FTW_PHYS))
		return errno ? -errno : -EIO;
	return 0;
}

static int path_compare_desc(const void *left, const void *right)
{
	return strcmp(right, left);
}

/*
 * Detach a package's upatches through the signed unload directives it
 * shipped, in reverse name order, then remove the package tree. The
 * caller drops the state entry only after this succeeded, so a failed
 * detach leaves the package listed and loadable again.
 */
static int package_uninstall(const struct bpm_state_entry *st)
{
	char dir[PATH_MAX], updir[PATH_MAX];
	char (*unloads)[PATH_MAX];
	struct dirent *de;
	int n = 0, rc = 0;
	DIR *d;

	if (snprintf(updir, sizeof(updir), "%s/upatches", st->path) >=
	    (int)sizeof(updir))
		return -ENAMETOOLONG;
	unloads = xcalloc(128, PATH_MAX);
	if (!unloads)
		return -ENOMEM;
	d = opendir(updir);
	if (!d) {
		rc = -errno;
		goto out;
	}
	while ((de = readdir(d))) {
		size_t len = strlen(de->d_name);

		if (de->d_name[0] == '.' || len <= strlen(".unload.upatch") ||
		    strcmp(de->d_name + len - strlen(".unload.upatch"),
			   ".unload.upatch"))
			continue;
		if (n >= 128) {
			rc = -E2BIG;
			break;
		}
		if (snprintf(unloads[n], PATH_MAX, "%s/%s", updir, de->d_name) >=
		    PATH_MAX) {
			rc = -ENAMETOOLONG;
			break;
		}
		n++;
	}
	closedir(d);
	if (rc)
		goto out;
	qsort(unloads, (size_t)n, PATH_MAX, path_compare_desc);
	for (int i = 0; i < n; i++) {
		if (shirudo_upatch_remove(unloads[i])) {
			pr_err("bpm uninstall: unload %s failed", unloads[i]);
			rc = -EIO;
			goto out;
		}
	}
	if (snprintf(dir, sizeof(dir), "%s/%s", SHIRUDO_BPM_PACKAGES_DIR,
		     st->name) >= (int)sizeof(dir)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	rc = remove_tree(dir);
out:
	xfree(unloads, 128 * PATH_MAX);
	return rc;
}

static const struct shirudo_help_item bpm_subcmds[] = {
	{ "config", "register and manage OCI repositories" },
	{ "repo", "refresh signed repository indexes" },
	{ "tree", "synchronize or publish the signed upatch tree" },
	{ "key", "add, fingerprint, and list package certificates" },
	{ "pull", "download an OCI package into the current directory" },
	{ "info", "print a local or OCI package README" },
	{ "push", "publish an OCI package and its signed index entry" },
	{ "build", "build a signed OCI package from a Beefile" },
	{ "install", "download and activate a repository or OCI package" },
	{ "upgrade", "activate newer cached package versions" },
	{ "list", "list installed packages" },
	{ "uninstall", "unload and remove an installed package" },
};


static const struct shirudo_help_item bpm_target_subcmds[] = {
	{ "config", "register and manage OCI repositories" },
	{ "repo", "refresh signed repository indexes" },
	{ "tree", "synchronize the optional signed upatch tree" },
	{ "key", "add, fingerprint, and list package certificates" },
	{ "pull", "download an OCI package into the current directory" },
	{ "info", "print a local or OCI package README" },
	{ "install", "download and activate a repository or OCI package" },
	{ "upgrade", "activate newer cached package versions" },
	{ "list", "list installed packages" },
	{ "uninstall", "unload and remove an installed package" },
};

/*
 * Operator-only subcommands live in shirudo-build; hand the bpm argument
 * vector over unchanged so the helper parses it itself.
 */
static int bpm_exec_operator(const char *sub, int argc, const char **argv)
{
	const char **helper_argv = xcalloc((size_t)argc + 2,
					   sizeof(*helper_argv));
	char label[64];
	int rc;

	if (!helper_argv)
		return bpm_fail(sub, -ENOMEM);
	snprintf(label, sizeof(label), "bpm %s", sub);
	helper_argv[1] = "bpm";
	helper_argv[2] = sub;
	for (int i = 3; i < argc + 1; i++)
		helper_argv[i] = argv[i - 1];
	rc = shirudo_build_exec(label, (char **)helper_argv);
	xfree(helper_argv, ((size_t)argc + 2) * sizeof(*helper_argv));
	return rc;
}

static const struct shirudo_help bpm_target_help = {
	.usage = "shirudo bpm <config|repo|tree|key|pull|info|install|upgrade|list|uninstall>",
	.summary = "Manage signed target-local BPM packages backed by OCI repositories.",
	.sections = (const struct shirudo_help_section[]) {
		{ "subcommands:", bpm_target_subcmds, ARRAY_SIZE(bpm_target_subcmds) },
	},
	.n_sections = 1,
};

static const struct shirudo_help bpm_operator_help = {
	.usage = "shirudo bpm <config|repo|tree|key|pull|info|push|build|install|upgrade|list|uninstall>",
	.summary = "Manage signed OCI packages and publish packages from the operator.",
	.sections = (const struct shirudo_help_section[]) {
		{ "subcommands:", bpm_subcmds, ARRAY_SIZE(bpm_subcmds) },
	},
	.n_sections = 1,
};

static void bpm_pull_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm pull <package-reference>\n\n"
		"The package reference must start with oci://.\n"
		"Example:\n"
		"  shirudo bpm pull oci://quay.io/namespace/package:tag\n");
}

static void bpm_info_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm info <package-file|package-reference>\n\n"
		"Prints README.md from a local .bee file or an OCI package.\n"
		"Examples:\n"
		"  shirudo bpm info ./package.bee\n"
		"  shirudo bpm info oci://quay.io/namespace/package:tag\n");
}

static int bpm_finish(int lock, int rc, const char *action)
{
	if (lock >= 0) {
		flock(lock, LOCK_UN);
		close(lock);
	}
	curl_global_cleanup();
	return rc ? bpm_fail(action, rc) : 0;
}

static const struct shirudo_help_item bpm_key_subcmds[] = {
	{ "add", "install a trusted package certificate and print its fingerprint" },
	{ "fingerprint", "print the SHA-256 fingerprint of a certificate's SPKI" },
	{ "list", "list installed certificate fingerprints" },
};

static const struct shirudo_help bpm_key_help = {
	.usage = "shirudo bpm key <add|fingerprint|list>",
	.summary = "Manage package signing certificates.",
	.sections = (const struct shirudo_help_section[]) {
		{ "subcommands:", bpm_key_subcmds, ARRAY_SIZE(bpm_key_subcmds) },
	},
	.n_sections = 1,
	.footer = "add and fingerprint accept a certificate file, .bee package, or\n"
		  "oci://registry/repository:tag. list reads /var/lib/shirudo/keys.\n"
		  "Examples:\n"
		  "  shirudo bpm key fingerprint ./package.bee\n"
		  "  shirudo bpm key add oci://quay.io/namespace/package:tag\n"
		  "  shirudo bpm key list",
};

static int cmd_bpm_key(int argc, const char **argv)
{
	char temp[PATH_MAX] = {}, hex[65];
	const char *sub, *src;
	int rc;

	if (argc < 2 || shirudo_is_help(argv[1])) {
		shirudo_print_help(&bpm_key_help);
		return argc < 2 ? 2 : 0;
	}
	if (shirudo_is_list_cmds(argv[1])) {
		shirudo_print_subcmd_list(bpm_key_subcmds,
					ARRAY_SIZE(bpm_key_subcmds));
		return 0;
	}
	sub = shirudo_resolve_subcommand("bpm key", argv[1], bpm_key_subcmds,
					ARRAY_SIZE(bpm_key_subcmds));
	if (!sub)
		return 2;
	if (argc == 3 && shirudo_is_help(argv[2])) {
		shirudo_print_help(&bpm_key_help);
		return 0;
	}
	if ((!strcmp(sub, "list") && argc != 2) ||
	    (strcmp(sub, "list") && argc != 3)) {
		shirudo_print_help(&bpm_key_help);
		return 2;
	}
	if (!strcmp(sub, "list")) {
		rc = list_keys();
		return rc ? bpm_fail("key list", rc) : 0;
	}
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return bpm_fail("initialize curl", -EIO);
	src = argv[2];
	rc = key_source_file(src, temp, sizeof(temp));
	if (!rc) {
		if (temp[0])
			src = temp;
		rc = key_file_fingerprint(src, hex);
		if (!rc && !strcmp(sub, "add"))
			rc = install_key_file(src);
		if (!rc)
			puts(hex);
	}
	if (temp[0])
		unlink(temp);
	return bpm_finish(-1, rc, !strcmp(sub, "add") ?
			  "key add" : "key fingerprint");
}

int cmd_bpm(int argc, const char **argv)
{
	const struct shirudo_help *help = shirudo_build_available() ?
		&bpm_operator_help : &bpm_target_help;
	const struct shirudo_help_item *subcmds = shirudo_build_available() ?
		bpm_subcmds : bpm_target_subcmds;
	size_t n_subcmds = shirudo_build_available() ? ARRAY_SIZE(bpm_subcmds) :
		ARRAY_SIZE(bpm_target_subcmds);
	const char *sub;

	if (argc < 2 || shirudo_is_help(argv[1])) {
		shirudo_print_help(help);
		return argc < 2 ? 2 : 0;
	}
	if (shirudo_is_list_cmds(argv[1])) {
		shirudo_print_subcmd_list(subcmds, n_subcmds);
		return 0;
	}
	sub = shirudo_resolve_subcommand("shirudo bpm", argv[1], subcmds,
					 n_subcmds);
	if (!sub)
		return 2;
	if (!strcmp(sub, "config"))
		return cmd_bpm_config(argc - 1, argv + 1);
	if (!strcmp(sub, "info")) {
		int rc;

		if (argc == 3 && shirudo_is_help(argv[2])) {
			bpm_info_usage();
			return 0;
		}
		if (argc != 3) {
			bpm_info_usage();
			return 2;
		}
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			return bpm_fail("initialize curl", -EIO);
		rc = print_package_readme(argv[2]);
		return bpm_finish(-1, rc, "info");
	}
	if (!strcmp(sub, "tree") && (argc < 3 || shirudo_is_help(argv[2]))) {
		bpm_tree_usage();
		return argc < 3 ? 2 : 0;
	}
	if (!strcmp(sub, "tree") && !strcmp(argv[2], "append"))
		return bpm_exec_operator(sub, argc, argv);
	if (!strcmp(sub, "tree") && strcmp(argv[2], "sync")) {
		bpm_tree_usage();
		return 2;
	}
	if (!strcmp(sub, "build") || !strcmp(sub, "push"))
		return bpm_exec_operator(sub, argc, argv);
	if (!strcmp(sub, "pull")) {
		int rc;

		if (argc == 3 && shirudo_is_help(argv[2])) {
			bpm_pull_usage();
			return 0;
		}
		if (argc != 3) {
			bpm_pull_usage();
			return 2;
		}
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			return bpm_fail("initialize curl", -EIO);
		rc = pull_package(argv[2]);
		return bpm_finish(-1, rc, "pull");
	}
	if (!strcmp(sub, "repo") && argc >= 3 && !strcmp(argv[2], "update")) {
		int lock, rc = 0;

		if (argc > 4)
			return 2;
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			return bpm_fail("initialize curl", -EIO);
		lock = with_bpm_lock();
		if (lock < 0)
			return bpm_finish(-1, lock, "lock");
		if (argc == 3) {
			DIR *d = opendir(SHIRUDO_BPM_REGISTRIES_DIR);
			struct dirent *entry;

			if (!d && errno != ENOENT)
				rc = -errno;
			while (!rc && d && (entry = readdir(d))) {
				size_t len = strlen(entry->d_name);
				char source[BPM_MAX_NAME];

				if (len <= 5 || strcmp(entry->d_name + len - 5, ".conf"))
					continue;
				if ((size_t)snprintf(source, sizeof(source), "%.*s",
						(int)(len - 5), entry->d_name) >= sizeof(source)) {
					rc = -ENAMETOOLONG;
					break;
				}
				if (repo_update_one(source))
					rc = -EIO;
			}
			if (d)
				closedir(d);
		} else {
			rc = repo_update_one(argv[3]);
		}
		return bpm_finish(lock, rc, "repo update");
	}
	if (!strcmp(sub, "tree")) {
		int lock, rc;

		if (argc > 6)
			return 2;
		if (argc == 4 && shirudo_is_help(argv[3])) {
			bpm_tree_usage();
			return 0;
		}
		/* The tree is optional. Avoid taking the BPM lock (and avoid
		 * requiring writable state directories) when it is not configured. */
		if (access(SHIRUDO_BPM_TREE_ETC_PATH, F_OK) != 0 && errno == ENOENT)
			return 0;
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			return bpm_fail("initialize curl", -EIO);
		lock = with_bpm_lock();
		if (lock < 0)
			return bpm_finish(-1, lock, "lock");
		rc = cmd_bpm_tree_sync(argc - 1, argv + 1);
		return bpm_finish(lock, rc, "tree sync");
	}
	if (!strcmp(sub, "key"))
		return cmd_bpm_key(argc - 1, argv + 1);
	if (!strcmp(sub, "install") && argc == 3) {
		char source[BPM_MAX_NAME], name[BPM_MAX_NAME], version[BPM_MAX_NAME];
		struct bpm_source source_cfg;
		struct bpm_index_entry entries[BPM_MAX_ENTRIES];
		struct bpm_state_entry state[BPM_MAX_STATE];
		struct bpm_index_entry selected;
		bool direct = !strncmp(argv[2], "oci://", 6);
		int n_entries, n_state, lock, rc, i;

		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			return bpm_fail("initialize curl", -EIO);
		lock = with_bpm_lock();
		if (lock < 0)
			return bpm_finish(-1, lock, "lock");
		if (direct) {
			rc = prepare_direct_install(argv[2], &source_cfg, &selected);
		} else {
			rc = parse_package_ref(argv[2], source, sizeof(source), name,
					 sizeof(name), version, sizeof(version));
		}
		if (!rc)
			rc = state_read(state, &n_state);
		if (rc)
			return bpm_finish(lock, rc, "install");
		for (i = 0; i < n_state; i++) {
			if (!strcmp(state[i].name, direct ? selected.name : name))
				/* Installation is idempotent by package name.  This also
				 * avoids contacting the repository for a package that is
				 * already active.  Use `bpm upgrade` to change versions. */
				return bpm_finish(lock, 0, "install");
		}
		if (!direct) {
			rc = load_source(source, &source_cfg);
			if (!rc)
				rc = load_cached_index(source, entries, &n_entries);
			if (!rc)
				rc = find_entry(entries, n_entries, name,
					version[0] ? version : NULL, &selected);
		}
		if (rc)
			return bpm_finish(lock, rc, "install");
		if (n_state >= BPM_MAX_STATE)
			return bpm_finish(lock, -E2BIG, "install");
		rc = package_install(&source_cfg, &selected, NULL, NULL);
		if (rc)
			return bpm_finish(lock, rc, "install");
		bpm_copy_string(state[n_state].name, sizeof(state[n_state].name),
				direct ? selected.name : name);
		bpm_copy_string(state[n_state].version, sizeof(state[n_state].version),
				selected.version);
		bpm_copy_string(state[n_state].source, sizeof(state[n_state].source),
				direct ? "direct" : source);
		if (snprintf(state[n_state].path, sizeof(state[n_state].path),
				"%s/%s/%s", SHIRUDO_BPM_PACKAGES_DIR,
				direct ? selected.name : name,
				selected.version) >= (int)sizeof(state[n_state].path))
			return bpm_finish(lock, -ENAMETOOLONG, "install");
		rc = state_write(state, n_state + 1);
		return bpm_finish(lock, rc, "write state");
	}
	if (!strcmp(sub, "list")) {
		struct bpm_state_entry *state;
		int n_state, rc;

		if (argc != 2) {
			fprintf(stderr, "usage: shirudo bpm list\n");
			return argc == 3 && shirudo_is_help(argv[2]) ? 0 : 2;
		}
		state = xcalloc(BPM_MAX_STATE, sizeof(*state));
		if (!state)
			return bpm_fail("list", -ENOMEM);
		rc = state_read(state, &n_state);
		for (int i = 0; !rc && i < n_state; i++)
			printf("%s %s %s\n", state[i].name, state[i].version,
			       state[i].source);
		xfree(state, BPM_MAX_STATE * sizeof(*state));
		return rc ? bpm_fail("list", rc) : 0;
	}
	if (!strcmp(sub, "uninstall")) {
		struct bpm_state_entry *state;
		int n_state, lock, rc, i;

		if (argc != 3 || shirudo_is_help(argv[2])) {
			fprintf(stderr, "usage: shirudo bpm uninstall <package>\n");
			return argc == 3 ? 0 : 2;
		}
		if (!bpm_name_ok(argv[2]))
			return bpm_fail("uninstall", -EINVAL);
		state = xcalloc(BPM_MAX_STATE, sizeof(*state));
		if (!state)
			return bpm_fail("uninstall", -ENOMEM);
		lock = with_bpm_lock();
		if (lock < 0) {
			xfree(state, BPM_MAX_STATE * sizeof(*state));
			return bpm_finish(-1, lock, "lock");
		}
		rc = state_read(state, &n_state);
		for (i = 0; !rc && i < n_state; i++)
			if (!strcmp(state[i].name, argv[2]))
				break;
		if (!rc && i == n_state)
			rc = -ENOENT;
		if (!rc)
			rc = package_uninstall(&state[i]);
		if (!rc) {
			memmove(&state[i], &state[i + 1],
				(size_t)(n_state - i - 1) * sizeof(*state));
			rc = state_write(state, n_state - 1);
		}
		xfree(state, BPM_MAX_STATE * sizeof(*state));
		return bpm_finish(lock, rc, "uninstall");
	}
	if (!strcmp(sub, "upgrade") && argc == 2) {
		struct bpm_state_entry state[BPM_MAX_STATE];
		int n_state, lock, rc, i;

		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			return bpm_fail("initialize curl", -EIO);
		lock = with_bpm_lock();
		if (lock < 0)
			return bpm_finish(-1, lock, "lock");
		rc = state_read(state, &n_state);
		if (rc)
			return bpm_finish(lock, rc, "read state");
		for (i = 0; i < n_state; i++) {
			struct bpm_source source_cfg;
			struct bpm_index_entry entries[BPM_MAX_ENTRIES], selected;
			int n_entries;

			if (!strcmp(state[i].source, "direct"))
				continue;
			rc = load_source(state[i].source, &source_cfg);
			if (!rc)
				rc = load_cached_index(state[i].source, entries, &n_entries);
			if (!rc)
				rc = find_entry(entries, n_entries, state[i].name, NULL,
						&selected);
			if (rc == -ENOENT)
				continue;
			if (rc)
				return bpm_finish(lock, rc, "upgrade");
			if (semver_compare(selected.version, state[i].version) <= 0)
				continue;
			rc = package_install(&source_cfg, &selected, state[i].path,
						state[i].version);
			if (rc)
				return bpm_finish(lock, rc, "upgrade");
			bpm_copy_string(state[i].version, sizeof(state[i].version),
					selected.version);
			if (snprintf(state[i].path, sizeof(state[i].path), "%s/%s/%s",
					SHIRUDO_BPM_PACKAGES_DIR, state[i].name,
					selected.version) >= (int)sizeof(state[i].path))
				return bpm_finish(lock, -ENAMETOOLONG, "upgrade");
		}
		rc = state_write(state, n_state);
		return bpm_finish(lock, rc, "write state");
	}
	return 2;
}
