// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Operator-only publishing: `bpm push` with the signed repository index
 * and `bpm tree append`. Signing is a direct call into the CMS signer.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "bpm.h"
#include "bpm_oci.h"
#include "bpm_package.h"
#include "bpm_tree.h"
#include "bpm_tree_overlap.h"
#include "crypto.h"
#include "hex.h"
#include "io.h"
#include "json.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "sign.h"
#include "timefmt.h"
#include "upatch.h"

#define BPM_MANIFEST_CAP	8192u
#define BPM_SIGN_MAX		(64u * 1024u)
#define TREE_SEGMENT_OPS	64

/* One append never splits across segments, so it fits in one. */
BUILD_BUG_ON(BPM_BUILD_MAX_ENTRIES > TREE_MAX_OPS);

static void tree_append_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm tree append <package-file> <repository>\n"
		"                               [--keys-dir <dir>] [--key <signing_key.pem>]\n"
		"                               [--cert <cert.der>] [--previous-cert <cert.der>]\n"
		"                               [--tree-id <id>]\n"
		"                               [--reference <ref>] [--op add|delete]\n"
		"                               [--segment-ops <n>]\n\n"
		"Publishes the [upatches.tree] entries of a built package as the next\n"
		"operations of the signed tree at <repository>:<ref> (default stable).\n"
		"A segment that holds --segment-ops operations (default %d, 1 to %d)\n"
		"is sealed and the entries start the next one.\n"
		"The key defaults to --keys-dir, SHIRUDO_KEYS_DIR or %s.\n",
		TREE_SEGMENT_OPS, TREE_MAX_OPS, KEYS_DIR);
}

static int publish_fail(const char *action, int ret)
{
	if (ret < 0)
		pr_err("bpm %s: %s", action, strerror(-ret));
	else
		pr_err("bpm %s failed", action);
	return 1;
}

/*
 * Detached CMS over payload with the operator key, in the same form as
 * a loader signature so the target verifies both with one code path.
 */
static int sign_detached(const void *payload, size_t len,
			 const char *key, const char *cert,
			 __u8 **sig, size_t *sig_len)
{
	struct sign_io io = {
		.insns = payload, .insns_sz = len, .signature_sz = BPM_SIGN_MAX,
	};
	int ret;

	io.signature = xmalloc(io.signature_sz);
	if (!io.signature)
		return -ENOMEM;
	ret = cms_sign(&io, key, cert);
	if (ret) {
		xfree(io.signature, BPM_SIGN_MAX);
		return ret;
	}
	*sig = io.signature;
	*sig_len = io.signature_sz;
	return 0;
}

static void sig_free(__u8 *sig)
{
	xfree(sig, BPM_SIGN_MAX);
}

static int index_entry_compare(const void *left, const void *right)
{
	const struct bpm_index_entry *a = left, *b = right;
	int ret = strcmp(a->name, b->name);

	return ret ? ret : strcmp(a->version, b->version);
}

static int index_repository_for_package(const char *repository, char *out, size_t out_sz)
{
	const char *name = strrchr(repository, '/');
	size_t namespace_len;

	if (!name || name == repository)
		return -EINVAL;
	namespace_len = (size_t)(name - repository);
	if (strsprintf(out, out_sz, "%.*s/%s", (int)namespace_len, repository,
		       BPM_INDEX_REPOSITORY_NAME) < 0)
		return -ENAMETOOLONG;
	return 0;
}

/* -ENOENT when the registry has no index there. */
static int fetch_index(struct bpm_oci_client *c, const char *repository,
		       const char *cert,
		       struct bpm_index_entry *entries, int *n)
{
	struct bpm_buffer manifest = {}, payload = {}, sig = {};
	struct bpm_descriptor *layers = NULL;
	char url[PATH_MAX], hex[65];
	int nl = 0, ret = 0;

	*n = 0;
	ret = bpm_oci_url(c, repository, "manifests", BPM_INDEX_TAG,
			  url, sizeof(url));
	if (ret)
		return ret;
	ret = bpm_oci_get_memory(c, url, BPM_MANIFEST_MEDIA, &manifest);
	if (ret)
		return ret;
	layers = xcalloc(BPM_MAX_ENTRIES, sizeof(*layers));
	if (!layers) {
		ret = -ENOMEM;
		goto out;
	}
	ret = bpm_oci_parse_manifest(manifest.data, manifest.len, layers,
				     BPM_MAX_ENTRIES, &nl, NULL, 0);
	if (ret)
		goto out;
	for (int i = 0; i < nl; i++) {
		struct bpm_buffer *dst;

		if (!strcmp(layers[i].media, BPM_INDEX_MEDIA))
			dst = &payload;
		else if (!strcmp(layers[i].media, BPM_INDEX_SIG_MEDIA))
			dst = &sig;
		else
			continue;
		if (dst->data) {
			ret = -EINVAL;
			goto out;
		}
		ret = bpm_oci_url(c, repository, "blobs", layers[i].digest,
				  url, sizeof(url));
		if (ret)
			goto out;
		ret = bpm_oci_get_blob(c, url, layers[i].media, dst);
		if (ret)
			goto out;
		if ((layers[i].size >= 0 && (__s64)dst->len != layers[i].size) ||
		    bpm_sha256_hex(dst->data, dst->len, hex, sizeof(hex)) ||
		    !bpm_digest_matches(layers[i].digest, hex)) {
			ret = -EKEYREJECTED;
			goto out;
		}
	}
	if (!payload.data || !sig.data) {
		ret = -EINVAL;
		goto out;
	}
	if (bpm_verify_cms(payload.data, payload.len, sig.data, sig.len, cert)) {
		pr_err("bpm push: the published repository index is not signed by %s",
		       cert);
		ret = -EKEYREJECTED;
		goto out;
	}
	ret = bpm_index_parse(payload.data, payload.len, entries, n);
out:
	xfree(layers, BPM_MAX_ENTRIES * sizeof(*layers));
	bpm_buffer_free(&manifest);
	bpm_buffer_free(&payload);
	bpm_buffer_free(&sig);
	return ret;
}

/*
 * Add or refresh the package's entry in the signed index beside its
 * repository namespace. A version already listed with different content
 * is refused: published versions are immutable. The operator keeps no
 * state, so only new_index tells a namespace without an index from a
 * registry that hides one: the index pushed then would be signed without
 * every package listed before.
 */
static int push_index(struct bpm_oci_client *c, const char *index_repository,
		      const char *repository,
		      const struct bpm_package_info *info,
		      const char *manifest_digest,
		      const struct bpm_descriptor *layer,
		      const char *key, const char *cert, bool new_index)
{
	struct bpm_descriptor config, payload_layer, sig_layer;
	struct bpm_index_entry *entries, *entry = NULL;
	char *body = NULL, *manifest = NULL;
	struct json_emit e = {};
	char timestamp[32], digest[72];
	char empty_config[] = "{}";
	size_t cap = 0, sig_len = 0;
	time_t now = time(NULL);
	__u8 *sig = NULL;
	int n = 0, ret = 0;

	entries = xcalloc(BPM_MAX_ENTRIES, sizeof(*entries));
	if (!entries)
		return -ENOMEM;
	ret = fetch_index(c, index_repository, cert, entries, &n);
	if (ret == -ENOENT && new_index) {
		ret = 0;
	} else if (ret == -ENOENT) {
		pr_err("bpm push: %s has no repository index; pass --new-index to start one, and only for a namespace that never had one",
		       index_repository);
	} else if (!ret && new_index) {
		pr_err("bpm push: %s has a repository index already; --new-index starts one only where there is none",
		       index_repository);
		ret = -EEXIST;
	}
	if (ret)
		goto out;
	for (int i = 0; i < n; i++) {
		if (strcmp(entries[i].name, info->name) ||
		    strcmp(entries[i].version, info->version))
			continue;
		if (strcmp(entries[i].manifest_digest, manifest_digest) ||
		    strcmp(entries[i].package_digest, layer->digest)) {
			pr_err("bpm push: the repository index already lists %s %s "
				  "with different content", info->name, info->version);
			ret = -EEXIST;
			goto out;
		}
		entry = &entries[i];
	}
	if (!entry) {
		if (n >= BPM_MAX_ENTRIES) {
			ret = -E2BIG;
			goto out;
		}
		entry = &entries[n++];
	}
	*entry = (struct bpm_index_entry){ .package_size = layer->size };
	bpm_copy_string(entry->name, sizeof(entry->name), info->name);
	bpm_copy_string(entry->version, sizeof(entry->version), info->version);
	bpm_copy_string(entry->repository, sizeof(entry->repository), repository);
	bpm_copy_string(entry->manifest_digest, sizeof(entry->manifest_digest),
			manifest_digest);
	bpm_copy_string(entry->package_digest, sizeof(entry->package_digest),
			layer->digest);
	bpm_copy_string(entry->signer, sizeof(entry->signer), info->signer);
	qsort(entries, (size_t)n, sizeof(*entries), index_entry_compare);

	if (iso8601(now, timestamp, sizeof(timestamp))) {
		ret = -EIO;
		goto out;
	}
	cap = 4096 + (size_t)n * 4096;
	body = xmalloc(cap);
	if (!body) {
		ret = -ENOMEM;
		goto out;
	}
	e = (struct json_emit){ .buf = body, .cap = cap };
	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "generated_at", timestamp);
	json_arr_open(&e, "packages");
	for (int i = 0; i < n; i++) {
		json_obj_open(&e);
		json_kv_string(&e, "name", entries[i].name);
		json_kv_string(&e, "version", entries[i].version);
		json_kv_string(&e, "repository", entries[i].repository);
		json_kv_string(&e, "manifest_digest", entries[i].manifest_digest);
		json_kv_string(&e, "package_digest", entries[i].package_digest);
		json_kv_int(&e, "package_size", entries[i].package_size);
		json_kv_string(&e, "signer_fingerprint", entries[i].signer);
		json_obj_close(&e);
	}
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err) {
		ret = e.err;
		goto out;
	}
	ret = sign_detached(body, e.len, key, cert, &sig, &sig_len);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(c, index_repository, empty_config,
				strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
				  &config);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(c, index_repository, body, e.len,
				BPM_INDEX_MEDIA, &payload_layer);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(c, index_repository, sig, sig_len,
				BPM_INDEX_SIG_MEDIA, &sig_layer);
	if (ret)
		goto out;
	manifest = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest) {
		ret = -ENOMEM;
		goto out;
	}
	e = (struct json_emit){ .buf = manifest, .cap = BPM_MANIFEST_CAP };
	json_obj_open(&e);
	json_kv_int(&e, "schemaVersion", 2);
	json_kv_string(&e, "mediaType", BPM_MANIFEST_MEDIA);
	json_kv_string(&e, "artifactType", BPM_INDEX_ARTIFACT);
	bpm_oci_emit_descriptor(&e, "config", &config, NULL);
	json_arr_open(&e, "layers");
	bpm_oci_emit_descriptor(&e, NULL, &payload_layer, NULL);
	bpm_oci_emit_descriptor(&e, NULL, &sig_layer, NULL);
	json_arr_close(&e);
	json_obj_close(&e);
	if (e.err) {
		ret = e.err;
		goto out;
	}
	ret = bpm_oci_put_manifest(c, index_repository, BPM_INDEX_TAG,
				   (const __u8 *)manifest, e.len, digest,
				sizeof(digest));
out:
	xfree(manifest, BPM_MANIFEST_CAP);
	sig_free(sig);
	xfree(body, cap);
	xfree(entries, BPM_MAX_ENTRIES * sizeof(*entries));
	return ret;
}

static int push_package(const char *package_path, const char *raw_repository,
			const char *index_key, const char *index_cert,
			bool new_index, const char **reference_out)
{
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct bpm_package_info info = {};
	struct bpm_descriptor config, layer, key_config, key_layer, subject;
	struct json_emit e = {};
	__u8 *archive = NULL, *manifest = NULL;
	const char *base;
	char repository[BPM_MAX_ENDPOINT], package_digest[72], key_digest[72];
	char index_repository[BPM_MAX_ENDPOINT] = {};
	char hex[65];
	char reference[PATH_MAX];
	char config_body[] = "{\"mediaType\":\"" BPM_CONFIG_MEDIA "\"}";
	char empty_config[] = "{}";
	char package_title[PATH_MAX];
	char *manifest_body;
	char *key_manifest_body = NULL;
	struct stat st;
	size_t archive_len, manifest_len, key_manifest_len;
	size_t index_repo_sz = sizeof(index_repository);
	int ret;

	if (!package_path || !*package_path)
		return -EINVAL;
	if (stat(package_path, &st))
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EINVAL;
	ret = read_file(package_path, BPM_MAX_HTTP_BODY, &archive,
			&archive_len);
	if (ret)
		return ret;
	ret = bpm_pkg_load_info(package_path, &info);
	if (ret)
		goto out;
	ret = bpm_oci_parse_push_repo(raw_repository, &c, repository,
				      sizeof(repository));
	if (ret)
		goto out;
	if (index_key && index_cert) {
		ret = index_repository_for_package(repository, index_repository, index_repo_sz);
		if (ret)
			goto out;
	}
	base = strrchr(package_path, '/');
	base = base ? base + 1 : package_path;
	if (!*base || strlen(base) >= sizeof(package_title)) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	bpm_copy_string(package_title, sizeof(package_title), base);

	ret = bpm_oci_push_blob(&c, repository, config_body, strlen(config_body),
				BPM_CONFIG_MEDIA, &config);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(&c, repository, archive, archive_len,
				BPM_PACKAGE_MEDIA, &layer);
	if (ret)
		goto out;

	manifest_body = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest_body) {
		ret = -ENOMEM;
		goto out;
	}
	e.buf = manifest_body;
	e.cap = BPM_MANIFEST_CAP;
	json_obj_open(&e);
	json_kv_int(&e, "schemaVersion", 2);
	json_kv_string(&e, "mediaType", "application/vnd.oci.image.manifest.v1+json");
	bpm_oci_emit_descriptor(&e, "config", &config, NULL);
	json_arr_open(&e, "layers");
	bpm_oci_emit_descriptor(&e, NULL, &layer, package_title);
	json_arr_close(&e);
	json_obj_open_key(&e, "annotations");
	json_kv_string(&e, "dev.shirudo.bpm.package.name", info.name);
	json_kv_string(&e, "dev.shirudo.bpm.package.version", info.version);
	json_kv_string(&e, "org.opencontainers.image.title", info.name);
	json_kv_string(&e, "org.opencontainers.image.version", info.version);
	json_obj_close(&e);
	json_obj_close(&e);
	if (e.err) {
		xfree(manifest_body, BPM_MANIFEST_CAP);
		ret = e.err;
		goto out;
	}
	manifest_len = e.len;
	manifest = (__u8 *)manifest_body;
	if (bpm_sha256_hex(manifest, manifest_len, hex, sizeof(hex)) ||
	    strsprintf(package_digest, sizeof(package_digest), "sha256:%s", hex) < 0) {
		ret = -EINVAL;
		goto out;
	}
	/*
	 * By digest until the index takes the version, so a refused re-push
	 * leaves the tag on the package already published.
	 */
	ret = bpm_oci_put_manifest(&c, repository, package_digest, manifest,
				   manifest_len, key_digest, sizeof(key_digest));
	if (ret)
		goto out;

	/*
	 * Publish the package certificate as an OCI referrer so `bpm key add`
	 * can fetch it without downloading the package.
	 */
	ret = bpm_oci_push_blob(&c, repository, empty_config,
				strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
				&key_config);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(&c, repository, info.cert, info.cert_len,
				BPM_PUBLIC_KEY_MEDIA, &key_layer);
	if (ret)
		goto out;
	subject = (struct bpm_descriptor){
		.media = "application/vnd.oci.image.manifest.v1+json",
	};
	bpm_copy_string(subject.digest, sizeof(subject.digest), package_digest);
	subject.size = (__s64)manifest_len;
	key_manifest_body = xmalloc(BPM_MANIFEST_CAP);
	if (!key_manifest_body) {
		ret = -ENOMEM;
		goto out;
	}
	e = (struct json_emit){ .buf = key_manifest_body, .cap = BPM_MANIFEST_CAP };
	json_obj_open(&e);
	json_kv_int(&e, "schemaVersion", 2);
	json_kv_string(&e, "mediaType", "application/vnd.oci.image.manifest.v1+json");
	json_kv_string(&e, "artifactType", BPM_PUBLIC_KEY_ARTIFACT);
	bpm_oci_emit_descriptor(&e, "config", &key_config, NULL);
	json_arr_open(&e, "layers");
	bpm_oci_emit_descriptor(&e, NULL, &key_layer, NULL);
	json_arr_close(&e);
	json_obj_open_key(&e, "subject");
	json_kv_string(&e, "mediaType", subject.media);
	json_kv_string(&e, "digest", subject.digest);
	json_kv_int(&e, "size", subject.size);
	json_obj_close(&e);
	json_obj_close(&e);
	if (e.err) {
		ret = e.err;
		goto out;
	}
	key_manifest_len = e.len;
	if (bpm_sha256_hex(key_manifest_body, key_manifest_len, hex,
			   sizeof(hex)) ||
	    strsprintf(key_digest, sizeof(key_digest), "sha256:%s", hex) < 0) {
		ret = -EINVAL;
		goto out;
	}
	ret = bpm_oci_put_manifest(&c, repository, key_digest,
				   (const __u8 *)key_manifest_body,
				   key_manifest_len, key_digest,
				   sizeof(key_digest));
	if (ret)
		goto out;
	if (index_key && index_cert) {
		ret = push_index(&c, index_repository, repository, &info,
				 package_digest, &layer, index_key, index_cert,
				 new_index);
		if (ret)
			goto out;
	}
	ret = bpm_oci_put_manifest(&c, repository, info.version, manifest,
				   manifest_len, package_digest,
				   sizeof(package_digest));
	if (ret)
		goto out;
	if (strsprintf(reference, sizeof(reference), "oci://%s/%s:%s",
		       c.registry, repository, info.version) < 0) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	*reference_out = xstrdup(reference);
	ret = *reference_out ? 0 : -ENOMEM;
out:
	xfree(key_manifest_body, BPM_MANIFEST_CAP);
	xfree(manifest, BPM_MANIFEST_CAP);
	xfree(info.cert, info.cert_len + 1);
	xfree(archive, archive_len + 1);
	return ret;
}

static int tree_string_compare(const void *left, const void *right)
{
	return strcmp(left, right);
}

/* Selector lists are sets: sort them so equal Beefiles digest equally. */
static void tree_selector_canonicalize(struct tree_selector *s)
{
	qsort(s->kernel_release_prefix, (size_t)s->n_kernel_release_prefix,
	      TREE_STRING_MAX, tree_string_compare);
	qsort(s->kernel_build_id, (size_t)s->n_kernel_build_id,
	      TREE_STRING_MAX, tree_string_compare);
	qsort(s->architecture, (size_t)s->n_architecture,
	      TREE_STRING_MAX, tree_string_compare);
	for (int i = 0; i < s->n_kconfig; i++)
		qsort(s->kconfig[i].values, (size_t)s->kconfig[i].n_values,
		      TREE_STRING_MAX, tree_string_compare);
	for (int i = 0; i < s->n_labels; i++)
		qsort(s->labels[i].values, (size_t)s->labels[i].n_values,
		      TREE_STRING_MAX, tree_string_compare);
}

/* The fixes of one operation, in the form bpm build keeps them. */
struct tree_fixes {
	__s64	seq;
	char	ids[BPM_BUILD_MAX_FIXES][TREE_STRING_MAX];
	int	n;
};

struct tree_fixes_reader {
	struct tree_fixes	*fixes;		/* one per operation */
	int			n;
	int			cap;
	struct json_field	*operation;	/* seq, fixes */
	struct tree_fixes	op;
	char			id[TREE_STRING_MAX];
};

/* 1 to 16 IDs of [A-Za-z0-9._:-], each once and in byte order. */
static bool tree_fixes_valid(const struct tree_fixes *f)
{
	if (!f->n)
		return false;
	for (int i = 0; i < f->n; i++) {
		if (!f->ids[i][0] || !bpm_fix_id_ok(f->ids[i]) ||
		    (i && strcmp(f->ids[i - 1], f->ids[i]) >= 0))
			return false;
	}
	return true;
}

static int tree_fixes_take_id(void *ctx)
{
	struct tree_fixes_reader *r = ctx;

	if (r->op.n >= BPM_BUILD_MAX_FIXES)
		return -E2BIG;
	memcpy(r->op.ids[r->op.n++], r->id, sizeof(r->id));
	return 0;
}

static int tree_fixes_take_operation(void *ctx)
{
	struct tree_fixes_reader *r = ctx;

	if (r->n >= r->cap)
		return -EINVAL;
	if (r->operation[1].seen && !tree_fixes_valid(&r->op))
		return -EINVAL;
	r->fixes[r->n++] = r->op;
	r->op.seq = 0;
	r->op.n = 0;
	return 0;
}

/*
 * The fixes of each operation of the previous publication, by index,
 * from a second read of its bytes: tree_parse() is the node's parser
 * and keeps no key a node does not use. Only an add carries them, and
 * fixes has room for every operation of pub.
 */
static int tree_read_fixes(const struct bpm_buffer *document,
			   const struct tree_publication *pub,
			   struct tree_fixes *fixes)
{
	struct tree_fixes_reader *r;
	int ret;

	r = xcalloc(1, sizeof(*r));
	if (!r)
		return -ENOMEM;
	r->fixes = fixes;
	r->cap = pub->n_operations;
	{
		struct json_array id_sink = { tree_fixes_take_id, r };
		struct json_array operation_sink = {
			tree_fixes_take_operation, r,
		};
		struct json_field id[] = {
			{ "", JSON_T_STRING, r->id, sizeof(r->id), 0, NULL, 0 },
		};
		struct json_field operation[] = {
			{ "seq", JSON_T_INT, &r->op.seq, 0, 0, NULL, 0 },
			{ "fixes", JSON_T_ARRAY, &id_sink, 0, 0, id,
			  ARRAY_SIZE(id) },
		};
		struct json_field root[] = {
			{ "operations", JSON_T_ARRAY, &operation_sink, 0, 0,
			  operation, ARRAY_SIZE(operation) },
		};

		r->operation = operation;
		ret = json_parse((const char *)document->data, document->len,
				 root, ARRAY_SIZE(root));
	}
	if (!ret && r->n != pub->n_operations)
		ret = -EINVAL;
	for (int i = 0; !ret && i < r->n; i++) {
		if (fixes[i].seq != pub->operations[i].seq ||
		    (fixes[i].n && strcmp(pub->operations[i].op, "add")))
			ret = -EINVAL;
	}
	xfree(r, sizeof(*r));
	return ret;
}

static int tree_emit_fixes(struct json_emit *e, int index, void *ctx)
{
	const struct tree_fixes *f = (const struct tree_fixes *)ctx + index;

	if (!f->n)
		return 0;
	json_arr_open(e, "fixes");
	for (int i = 0; i < f->n; i++)
		json_str(e, f->ids[i]);
	json_arr_close(e);
	return 0;
}

/*
 * Publish one immutable upatch artifact and describe it for the tree.
 * The bytes are checked to be the directive the operation claims (same
 * name, load versus unload) before anything is uploaded, so a target
 * never meets an operation its own tree_verify_upatch() would reject.
 */
static int tree_push_artifact(struct bpm_oci_client *c, const char *repository,
			      const char *raw_repository,
			      const __u8 *body, size_t len,
			      const char *id, bool unload,
			      struct tree_artifact *out)
{
	char name[UPATCH_NAME_MAX + 1], title[UPATCH_NAME_MAX + 16];
	char temporary[] = "/tmp/shirudo-bpm-tree-XXXXXX";
	struct bpm_descriptor layer, config;
	char empty_config[] = "{}";
	struct json_emit e;
	struct upatch u;
	char hex[65], tag[160];
	char *manifest;
	int fd, ret;

	fd = mkstemp(temporary);
	if (fd < 0)
		return -errno;
	ret = write_complete(fd, body, len);
	close(fd);
	if (!ret)
		ret = upatch_open(temporary, &u);
	unlink(temporary);
	if (ret) {
		pr_err("bpm tree append: %s is not a valid upatch", id);
		return ret;
	}
	upatch_header_name(&u, name);
	hex_encode(u.hdr.payload_sha256, 32, hex);
	if (strcmp(name, id) || upatch_is_unload(&u) != unload)
		ret = -EKEYREJECTED;
	upatch_close(&u);
	if (ret) {
		pr_err("bpm tree append: the %s artifact for %s is a %s directive named %s",
		       unload ? "unload" : "load", id,
		       unload ? "load" : "unload", name);
		return ret;
	}
	if (strsprintf(tag, sizeof(tag), "upatch-%s-%.16s", id, hex) < 0 || strlen(tag) > 128)
		return -ENAMETOOLONG;
	if (strsprintf(title, sizeof(title), "%s.upatch", id) < 0)
		return -ENAMETOOLONG;
	ret = bpm_oci_push_blob(c, repository, body, len, BPM_UPATCH_MEDIA,
				&layer);
	if (ret)
		return ret;
	ret = bpm_oci_push_blob(c, repository, empty_config,
				strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
				&config);
	if (ret)
		return ret;
	manifest = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest)
		return -ENOMEM;
	e = (struct json_emit){ .buf = manifest, .cap = BPM_MANIFEST_CAP };
	json_obj_open(&e);
	json_kv_int(&e, "schemaVersion", 2);
	json_kv_string(&e, "mediaType", BPM_MANIFEST_MEDIA);
	json_kv_string(&e, "artifactType", BPM_UPATCH_MEDIA);
	bpm_oci_emit_descriptor(&e, "config", &config, NULL);
	json_arr_open(&e, "layers");
	bpm_oci_emit_descriptor(&e, NULL, &layer, NULL);
	json_arr_close(&e);
	json_obj_open_key(&e, "annotations");
	json_kv_string(&e, "org.opencontainers.image.title", title);
	json_obj_close(&e);
	json_obj_close(&e);
	ret = e.err;
	if (!ret)
		ret = bpm_oci_put_manifest(c, repository, tag,
					   (const __u8 *)manifest, e.len,
					   out->manifest_digest,
					   sizeof(out->manifest_digest));
	xfree(manifest, BPM_MANIFEST_CAP);
	if (ret)
		return ret;
	bpm_copy_string(out->repository, sizeof(out->repository), raw_repository);
	bpm_copy_string(out->layer_digest, sizeof(out->layer_digest), layer.digest);
	if (strsprintf(out->payload_sha256, sizeof(out->payload_sha256),
		       "sha256:%s", hex) < 0)
		return -E2BIG;
	return 0;
}

/* The classes of a load upatch, none for one without an XDP program. */
static int upatch_xdp_classes(const void *body, size_t len, __u32 *classes)
{
	struct prog_spec *specs = NULL;
	const void *attach;
	__u32 attach_len;
	struct upatch u;
	int ret;

	ret = upatch_open_memory(body, len, &u);
	if (ret)
		return ret;
	attach = upatch_signed_attach(&u, &attach_len);
	ret = attach ? prog_specs_parse(attach, attach_len, u.hdr.nr_maps,
					u.hdr.nr_progs, &specs) : -EINVAL;
	if (!ret) {
		*classes = prog_specs_xdp_classes(specs, u.hdr.nr_progs);
		prog_specs_free(specs, u.hdr.nr_progs);
	}
	upatch_close(&u);
	return ret;
}

static int tree_fetch_xdp_classes(struct bpm_oci_client *c,
				  const char *repository, const char *repo_ref,
				  const struct tree_operation *op,
				  __u32 *classes)
{
	struct bpm_oci_client elsewhere __cleanup(bpm_oci_client_clear) = {};
	char other_repository[BPM_MAX_ENDPOINT], url[PATH_MAX], hex[65];
	struct bpm_buffer blob = {};
	__u8 digest[32];
	int ret;

	if (sha256_digest_decode(op->artifact.layer_digest, digest))
		return -EINVAL;
	if (strcmp(op->artifact.repository, repo_ref)) {
		ret = bpm_oci_parse_tree_repo(op->artifact.repository,
					      &elsewhere, other_repository,
					      sizeof(other_repository));
		if (ret)
			return ret;
		c = &elsewhere;
		repository = other_repository;
	}
	ret = bpm_oci_url(c, repository, "blobs", op->artifact.layer_digest,
			  url, sizeof(url));
	if (!ret)
		ret = bpm_oci_get_blob(c, url, BPM_UPATCH_MEDIA, &blob);
	if (!ret && (bpm_sha256_hex(blob.data, blob.len, hex, sizeof(hex)) ||
		     !bpm_digest_matches(op->artifact.layer_digest, hex)))
		ret = -EKEYREJECTED;
	if (!ret)
		ret = upatch_xdp_classes(blob.data, blob.len, classes);
	bpm_buffer_free(&blob);
	return ret;
}

/* The classes of the publication's operations, read once each. */
struct tree_xdp_classes {
	__u32	classes[TREE_MAX_OPS];
	bool	known[TREE_MAX_OPS];
};

/* The deletes of the segments after the one being checked. */
struct tree_later {
	struct tree_operation	*deletes;
	int			n;
	int			cap;
};

static void tree_later_free(struct tree_later *later)
{
	for (int i = 0; i < later->n; i++)
		tree_selector_free(&later->deletes[i].selector);
	xfree(later->deletes, (size_t)later->cap * sizeof(*later->deletes));
	*later = (struct tree_later){};
}

static int tree_later_take(struct tree_later *later,
			   const struct tree_publication *pub)
{
	for (int i = 0; i < pub->n_operations; i++) {
		const struct tree_operation *op = &pub->operations[i];
		struct tree_operation *deletes, *d;
		int cap;

		if (strcmp(op->op, "delete"))
			continue;
		if (later->n == later->cap) {
			if (check_mul_overflow(later->cap ? later->cap : 8, 2,
					       &cap))
				return -E2BIG;
			deletes = xreallocarray(later->deletes,
						(size_t)later->cap, (size_t)cap,
						sizeof(*deletes));
			if (!deletes)
				return -ENOMEM;
			later->deletes = deletes;
			later->cap = cap;
		}
		d = &later->deletes[later->n];
		*d = (struct tree_operation){ .seq = op->seq };
		if (tree_selector_copy(&d->selector, &op->selector))
			return -ENOMEM;
		bpm_copy_string(d->op, sizeof(d->op), op->op);
		bpm_copy_string(d->id, sizeof(d->id), op->id);
		later->n++;
	}
	return 0;
}

/*
 * A device runs one native XDP program. The second of two upatches that
 * select a class fails its load on every node with such a device, and
 * tree sync stops at the first operation that fails. later, NULL for
 * none, holds the deletes published after pub.
 */
static int tree_refuse_shared_xdp_class(struct bpm_oci_client *c,
					const char *repository,
					const char *repo_ref,
					const struct tree_publication *pub,
					const struct tree_later *later,
					struct tree_xdp_classes *seen,
					const struct tree_operation *op,
					__u32 classes)
{
	for (int i = 0; classes && i < pub->n_operations; i++) {
		const struct tree_operation *other = &pub->operations[i];
		int ret;

		if (strcmp(other->op, "add") || !strcmp(other->id, op->id) ||
		    !tree_add_live(pub, i) ||
		    (later && tree_add_withdrawn(other, later->deletes,
						 later->n)) ||
		    tree_selectors_disjoint(&other->selector, &op->selector))
			continue;
		if (!seen->known[i]) {
			ret = tree_fetch_xdp_classes(c, repository, repo_ref,
						     other, &seen->classes[i]);
			if (ret) {
				pr_err("bpm tree append: cannot read the artifact of %s (seq %lld) to compare its XDP device classes",
				       other->id, (long long)other->seq);
				return ret;
			}
			seen->known[i] = true;
		}
		if (!(seen->classes[i] & classes))
			continue;
		pr_err("bpm tree append: %s and %s (seq %lld) both select XDP device classes %u on nodes their selectors share; a device runs one XDP program, so give each class to one upatch or the two selectors that exclude each other",
		       op->id, other->id, (long long)other->seq,
		       seen->classes[i] & classes);
		return -EBUSY;
	}
	return 0;
}

/* The sealed segment succ names, as a node walking back fetches it. */
static int tree_fetch_sealed(struct bpm_oci_client *c, const char *repository,
			     const char *cert,
			     const struct tree_publication *succ,
			     struct tree_publication *pred)
{
	char digest[BPM_MAX_DIGEST];
	int ret;

	ret = build_tree_fetch_sealed(c, repository, cert, NULL, succ, pred,
				      digest, sizeof(digest));
	if (ret)
		pr_err("bpm tree append: the sealed segment %s, which ends at seq %lld, does not verify",
		       succ->segment_manifest_digest,
		       (long long)succ->base_seq);
	return ret;
}

/*
 * The shared class check of an add over the sealed segments before cur,
 * back to seq 0: sealed when this append seals it, the others fetched
 * by digest. An add stays live until a delete of any later segment
 * withdraws it, so the deletes of every segment walked are kept.
 */
static int tree_refuse_sealed_xdp_class(struct bpm_oci_client *c,
					const char *repository,
					const char *repo_ref, const char *cert,
					const struct tree_publication *cur,
					const struct tree_publication *sealed,
					const struct tree_operation *op,
					__u32 classes)
{
	const struct tree_publication *succ = cur, *segment = sealed;
	struct tree_publication fetched[2] = {};
	struct tree_xdp_classes *seen;
	struct tree_later later = {};
	int next = 0, ret;

	ret = tree_walk_within(cur->base_seq, 0);
	if (ret) {
		pr_err("bpm tree append: a joining node walks back %lld operations, past the limit of %d, so the XDP device classes of the sealed segments cannot be checked",
		       (long long)cur->base_seq, TREE_MAX_JOIN_OPS);
		return ret;
	}
	seen = xmalloc(sizeof(*seen));
	if (!seen)
		return -ENOMEM;
	ret = tree_later_take(&later, cur);
	while (!ret) {
		if (!segment) {
			if (!succ->base_seq)
				break;
			tree_publication_free(&fetched[next]);
			ret = tree_fetch_sealed(c, repository, cert, succ,
						&fetched[next]);
			if (ret)
				break;
			segment = &fetched[next];
			next ^= 1;
		}
		memset(seen, 0, sizeof(*seen));
		ret = tree_refuse_shared_xdp_class(c, repository, repo_ref,
						   segment, &later, seen, op,
						   classes);
		if (!ret)
			ret = tree_later_take(&later, segment);
		succ = segment;
		segment = NULL;
	}
	tree_later_free(&later);
	tree_publication_free(&fetched[0]);
	tree_publication_free(&fetched[1]);
	xfree(seen, sizeof(*seen));
	return ret;
}

/* history_root at the head of seg: its base's, over its operations. */
static int tree_history_at_head(const struct tree_publication *seg,
				char out[65])
{
	__u8 root[32];
	int ret;

	ret = tree_history_at(seg, seg->head_seq, root);
	if (ret)
		return ret;
	hex_encode(root, sizeof(root), out);
	return 0;
}

static int tree_segment_tag(__u64 k, char *tag, size_t tag_sz)
{
	return strsprintf(tag, tag_sz, "segment-%llu", k) < 0 ?
	       -ENAMETOOLONG : 0;
}

/* The digest of the manifest segment-<k> tags, -ENOENT without the tag. */
static int tree_segment_tag_digest(struct bpm_oci_client *c,
				   const char *repository, __u64 k,
				   char digest[72])
{
	struct bpm_buffer manifest = {};
	__u8 sum[CRYPTO_SHA256_LEN];
	char tag[32], url[PATH_MAX];
	int ret;

	ret = tree_segment_tag(k, tag, sizeof(tag));
	if (!ret)
		ret = bpm_oci_url(c, repository, "manifests", tag, url,
				  sizeof(url));
	if (!ret)
		ret = bpm_oci_get_memory(c, url, BPM_MANIFEST_MEDIA, &manifest);
	if (!ret && sha256_buffer(manifest.data, manifest.len, sum))
		ret = -EINVAL;
	if (!ret)
		sha256_digest_encode(sum, digest);
	bpm_buffer_free(&manifest);
	return ret;
}

/*
 * The k of the next segment-<k> tag: doubling, then halving, finds a k
 * without a tag in about 2 log2 k requests, so no tag is ever moved. 0
 * when the last tag already names the sealed manifest, which a run that
 * failed after tagging leaves behind.
 */
static int tree_next_segment_tag(struct bpm_oci_client *c,
				 const char *repository,
				 const char *sealed_digest, __u64 *k)
{
	char digest[BPM_MAX_DIGEST], last[BPM_MAX_DIGEST] = {};
	__u64 present = 0, absent = 1, probe;
	bool doubling = true;
	int ret;

	while (doubling || absent - present > 1) {
		probe = doubling ? absent : present + (absent - present) / 2;
		ret = tree_segment_tag_digest(c, repository, probe, digest);
		if (ret == -ENOENT) {
			absent = probe;
			doubling = false;
			continue;
		}
		if (ret)
			return ret;
		present = probe;
		bpm_copy_string(last, sizeof(last), digest);
		if (doubling && check_mul_overflow(absent, 2, &absent))
			return -EOVERFLOW;
	}
	*k = present && !strcmp(last, sealed_digest) ? 0 : absent;
	return 0;
}

/*
 * Tag the sealed manifest segment-<k> so that registry garbage collection
 * keeps it; nodes walk back to it by digest and never read the tag.
 */
static int tree_tag_sealed(struct bpm_oci_client *c, const char *repository,
			   const char *sealed_digest)
{
	char tag[32] = {}, url[PATH_MAX], digest[BPM_MAX_DIGEST], hex[65];
	struct bpm_buffer manifest = {};
	__u64 k;
	int ret;

	ret = tree_next_segment_tag(c, repository, sealed_digest, &k);
	if (ret || !k)
		goto out;
	ret = tree_segment_tag(k, tag, sizeof(tag));
	if (!ret)
		ret = bpm_oci_url(c, repository, "manifests", sealed_digest,
				  url, sizeof(url));
	if (!ret)
		ret = bpm_oci_get_memory(c, url, BPM_MANIFEST_MEDIA, &manifest);
	if (!ret && (bpm_sha256_hex(manifest.data, manifest.len, hex,
				    sizeof(hex)) ||
		     !bpm_digest_matches(sealed_digest, hex)))
		ret = -EKEYREJECTED;
	if (!ret)
		ret = bpm_oci_put_manifest(c, repository, tag, manifest.data,
					   manifest.len, digest, sizeof(digest));
out:
	bpm_buffer_free(&manifest);
	if (ret)
		pr_err("bpm tree append: cannot tag the sealed segment %s",
		       sealed_digest);
	return ret;
}

/*
 * The segment after sealed, whose manifest is sealed_digest, as it
 * starts: at the sealed head, with the history root there.
 */
static int tree_start_segment(const struct tree_publication *sealed,
			      const char *sealed_digest,
			      struct tree_publication *pub)
{
	*pub = (struct tree_publication){
		.schema = 1,
		.generation = sealed->generation,
		.base_seq = sealed->head_seq,
		.head_seq = sealed->head_seq,
	};
	bpm_copy_string(pub->tree_id, sizeof(pub->tree_id), sealed->tree_id);
	bpm_copy_string(pub->segment_manifest_digest,
			sizeof(pub->segment_manifest_digest), sealed_digest);
	return tree_history_at_head(sealed, pub->history_root);
}

static int cmd_bpm_tree_append(int argc, char **argv)
{
	const char *package = NULL, *raw_repository = NULL, *keys_dir_arg = NULL;
	char repository[BPM_MAX_ENDPOINT], repo_ref[BPM_MAX_ENDPOINT];
	struct bpm_descriptor config, payload_layer, sig_layer;
	const char *key = NULL, *cert = NULL, *tree_id = NULL;
	const char *previous_cert = NULL;
	const char *reference = "stable", *operation = "add";
	const char *segment_ops_arg = NULL;
	char key_path[PATH_MAX], cert_path[PATH_MAX];
	char parent[BPM_MAX_DIGEST] = {}, digest[72];
	struct tree_publication *sealed = NULL;
	struct tree_xdp_classes *seen = NULL;
	int segment_ops = TREE_SEGMENT_OPS;
	size_t entries = 0;
	struct bpm_buffer previous = {};
	struct tree_fixes *fixes = NULL;
	struct tree_emit_extra extra;
	size_t n_fixes = 0;
	struct tree_publication pub = {};
	struct tree_operation *op = NULL;
	size_t len, payload_len = 0, sig_len = 0;
	char *payload = NULL, *manifest = NULL;
	struct bpm_build_spec *spec = NULL;
	__u8 *beefile = NULL, *sig = NULL;
	struct bpm_package_info info = {};
	struct bpm_oci_client c __cleanup(bpm_oci_client_clear) = {};
	struct json_emit e;
	char empty_config[] = "{}";
	char package_dir[101];
	int appended = 0, bad_op, ret;
	bool unload;

	for (int i = 2; i < argc; i++) {
		const char *a = argv[i];

		if (!strcmp(a, "--keys-dir") && i + 1 < argc) {
			keys_dir_arg = argv[++i];
		} else if (!strncmp(a, "--keys-dir=", 11)) {
			keys_dir_arg = a + 11;
		} else if (!strcmp(a, "--key") && i + 1 < argc) {
			key = argv[++i];
		} else if (!strncmp(a, "--key=", 6)) {
			key = a + 6;
		} else if (!strcmp(a, "--cert") && i + 1 < argc) {
			cert = argv[++i];
		} else if (!strncmp(a, "--cert=", 7)) {
			cert = a + 7;
		} else if (!strcmp(a, "--previous-cert") && i + 1 < argc) {
			previous_cert = argv[++i];
		} else if (!strncmp(a, "--previous-cert=", 16)) {
			previous_cert = a + 16;
		} else if (!strcmp(a, "--tree-id") && i + 1 < argc) {
			tree_id = argv[++i];
		} else if (!strncmp(a, "--tree-id=", 10)) {
			tree_id = a + 10;
		} else if (!strcmp(a, "--reference") && i + 1 < argc) {
			reference = argv[++i];
		} else if (!strncmp(a, "--reference=", 12)) {
			reference = a + 12;
		} else if (!strcmp(a, "--op") && i + 1 < argc) {
			operation = argv[++i];
		} else if (!strncmp(a, "--op=", 5)) {
			operation = a + 5;
		} else if (!strcmp(a, "--segment-ops") && i + 1 < argc) {
			segment_ops_arg = argv[++i];
		} else if (!strncmp(a, "--segment-ops=", 14)) {
			segment_ops_arg = a + 14;
		} else if (a[0] == '-' || (package && raw_repository)) {
			tree_append_usage();
			return -EINVAL;
		} else if (!package) {
			package = a;
		} else {
			raw_repository = a;
		}
	}
	if (!package || !raw_repository) {
		tree_append_usage();
		return -EINVAL;
	}
	if (strcmp(operation, "add") && strcmp(operation, "delete")) {
		pr_err("bpm tree append: --op must be add or delete");
		return -EINVAL;
	}
	if (tree_id && !bpm_package_name_ok(tree_id)) {
		pr_err("bpm tree append: invalid --tree-id %s", tree_id);
		return -EINVAL;
	}
	if (segment_ops_arg) {
		__u64 n;

		if (parse_u64(segment_ops_arg, strlen(segment_ops_arg),
			      TREE_MAX_OPS, &n) || !n) {
			pr_err("bpm tree append: --segment-ops must be 1 to %d",
			       TREE_MAX_OPS);
			return -EINVAL;
		}
		segment_ops = (int)n;
	}
	unload = !strcmp(operation, "delete");
	if (!key || !cert) {
		const char *keys_dir = keys_dir_resolve(keys_dir_arg);

		if (!key) {
			if (format_key_path(key_path, sizeof(key_path), keys_dir,
					    SIGNING_KEY_FILE))
				return -EINVAL;
			key = key_path;
		}
		if (!cert) {
			if (format_key_path(cert_path, sizeof(cert_path), keys_dir,
					    CERT_FILE))
				return -EINVAL;
			cert = cert_path;
		}
	}
	if (build_check_keys(key, cert))
		return -EACCES;
	if (!previous_cert)
		previous_cert = cert;
	if (bpm_trim(raw_repository, repo_ref, sizeof(repo_ref))) {
		pr_err("bpm tree append: repository is longer than %zu bytes",
		       sizeof(repo_ref) - 1);
		return -ENAMETOOLONG;
	}

	ret = bpm_pkg_load_info(package, &info);
	if (ret)
		return ret;
	ret = bpm_pkg_read_member_in(package, "Beefile", NULL, package_dir,
				     sizeof(package_dir), &beefile, &len,
				     4u * 1024u * 1024u);
	if (ret) {
		pr_err("bpm tree append: package %s does not include Beefile", package);
		goto out;
	}
	spec = xmalloc(sizeof(*spec));
	if (!spec) {
		ret = -ENOMEM;
		goto out;
	}
	ret = bpm_build_parse_beefile(beefile, len, spec);
	if (ret) {
		pr_err("bpm tree append: cannot parse the Beefile of %s", package);
		goto out;
	}
	for (size_t i = 0; i < spec->n_upatches; i++)
		entries += spec->upatches[i].tree.present;
	ret = bpm_oci_parse_push_repo(repo_ref, &c, repository, sizeof(repository));
	if (ret) {
		pr_err("bpm tree append: the repository must be oci://registry/repository");
		goto out;
	}
	ret = bpm_tree_fetch_document(&c, repository, reference, previous_cert,
				      NULL, &previous, parent, sizeof(parent));
	if (!ret)
		ret = tree_parse((const char *)previous.data, previous.len,
				 &pub);
	if (ret == -ENOENT) {
		pub = (struct tree_publication){ .schema = 1,
							 .generation = 1 };
		parent[0] = '\0';
		if (tree_id)
			bpm_copy_string(pub.tree_id, sizeof(pub.tree_id), tree_id);
	} else if (ret) {
		pr_err("bpm tree append: cannot read the publication at %s:%s",
		       repo_ref, reference);
		goto out;
	} else {
		if (tree_id && strcmp(pub.tree_id, tree_id)) {
			pr_err("bpm tree append: tree id mismatch: existing %s, requested %s",
			       pub.tree_id, tree_id);
			ret = -EINVAL;
			goto out;
		}
		ret = tree_publication_verify(&pub, &bad_op);
		if (ret) {
			pr_err("bpm tree append: the publication at %s:%s does not verify",
			       repo_ref, reference);
			goto out;
		}
		if (pub.n_operations >= segment_ops ||
		    (size_t)pub.n_operations + entries > TREE_MAX_OPS) {
			sealed = xmalloc(sizeof(*sealed));
			if (!sealed) {
				ret = -ENOMEM;
				goto out;
			}
			*sealed = pub;
			ret = tree_start_segment(sealed, parent, &pub);
			if (ret)
				goto out;
		}
		if (check_add_overflow(pub.generation, 1, &pub.generation) ||
		    pub.generation == INT64_MAX) {
			pr_err("bpm tree append: the tree's generation is exhausted");
			ret = -EOVERFLOW;
			goto out;
		}
	}
	pub.schema = 1;
	if (!pub.tree_id[0])
		bpm_copy_string(pub.tree_id, sizeof(pub.tree_id), info.name);
	bpm_copy_string(pub.parent_manifest_digest,
			sizeof(pub.parent_manifest_digest), parent);

	n_fixes = min_t(size_t, pub.n_operations + spec->n_upatches,
			TREE_MAX_OPS);
	n_fixes = max(n_fixes, 1U);
	fixes = xcalloc(n_fixes, sizeof(*fixes));
	if (!fixes) {
		ret = -ENOMEM;
		goto out;
	}
	if (previous.data && !sealed &&
	    tree_read_fixes(&previous, &pub, fixes)) {
		pr_err("bpm tree append: the publication at %s:%s has a fixes list bpm tree append would not write, so it cannot carry it into the next generation",
		       repo_ref, reference);
		ret = -EINVAL;
		goto out;
	}

	op = xmalloc(sizeof(*op));
	seen = xcalloc(1, sizeof(*seen));
	if (!op || !seen) {
		ret = -ENOMEM;
		goto out;
	}
	for (size_t i = 0; i < spec->n_upatches; i++) {
		const struct bpm_build_upatch *u = &spec->upatches[i];
		const char *member;
		__u8 *body = NULL;
		__u32 classes = 0;
		size_t body_len;
		__s64 seq;

		if (!u->tree.present)
			continue;
		if (check_add_overflow(pub.head_seq, 1, &seq) ||
		    seq == INT64_MAX) {
			pr_err("bpm tree append: the tree's sequence is exhausted");
			ret = -EOVERFLOW;
			goto out;
		}
		member = unload ? u->tree.unload_artifact : u->tree.load_artifact;
		ret = bpm_pkg_read_member_in(package, member, package_dir, NULL, 0,
					     &body, &body_len, BPM_MAX_HTTP_BODY);
		if (ret) {
			pr_err("bpm tree append: package entry %s not found", member);
			goto out;
		}
		tree_selector_free(&op->selector);
		*op = (struct tree_operation){ .seq = seq };
		bpm_copy_string(op->op, sizeof(op->op), operation);
		bpm_copy_string(op->id, sizeof(op->id), u->tree.id);
		if (u->tree.selector) {
			ret = tree_selector_copy(&op->selector, u->tree.selector);
			if (ret) {
				xfree(body, body_len + 1);
				goto out;
			}
		}
		tree_selector_canonicalize(&op->selector);
		if (!unload) {
			ret = upatch_xdp_classes(body, body_len, &classes);
			if (ret)
				pr_err("bpm tree append: %s is not a valid upatch",
				       u->tree.id);
			else
				ret = tree_refuse_shared_xdp_class(&c, repository,
								   repo_ref, &pub,
								   NULL, seen, op,
								   classes);
			if (!ret && classes)
				ret = tree_refuse_sealed_xdp_class(&c, repository,
								   repo_ref,
								   previous_cert,
								   &pub, sealed,
								   op, classes);
		}
		if (!ret)
			ret = tree_push_artifact(&c, repository, repo_ref, body,
						 body_len, u->tree.id, unload,
						 &op->artifact);
		xfree(body, body_len + 1);
		if (ret)
			goto out;
		ret = tree_operation_digest(op, op->operation_digest);
		if (!ret)
			ret = tree_publication_append(&pub, op);
		if (ret)
			goto out;
		seen->classes[pub.n_operations - 1] = classes;
		seen->known[pub.n_operations - 1] = true;
		fixes[pub.n_operations - 1].seq = op->seq;
		if (!unload) {
			memcpy(fixes[pub.n_operations - 1].ids, u->tree.fixes,
			       sizeof(u->tree.fixes));
			fixes[pub.n_operations - 1].n = u->tree.n_fixes;
		}
		pub.head_seq = op->seq;
		appended++;
	}
	if (!appended) {
		pr_err("bpm tree append: %s has no [upatches.tree] entries", package);
		ret = -ENOENT;
		goto out;
	}
	extra = (struct tree_emit_extra){ tree_emit_fixes, fixes };
	ret = tree_emit_publication(&pub, &extra, &payload, &payload_len);
	if (ret)
		goto out;
	ret = sign_detached(payload, payload_len, key, cert, &sig, &sig_len);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(&c, repository, empty_config,
				strlen(empty_config), BPM_EMPTY_CONFIG_MEDIA,
				&config);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(&c, repository, payload, payload_len,
				BPM_TREE_MEDIA, &payload_layer);
	if (ret)
		goto out;
	ret = bpm_oci_push_blob(&c, repository, sig, sig_len, BPM_TREE_SIG_MEDIA,
				&sig_layer);
	if (ret)
		goto out;
	manifest = xmalloc(BPM_MANIFEST_CAP);
	if (!manifest) {
		ret = -ENOMEM;
		goto out;
	}
	e = (struct json_emit){ .buf = manifest, .cap = BPM_MANIFEST_CAP };
	json_obj_open(&e);
	json_kv_int(&e, "schemaVersion", 2);
	json_kv_string(&e, "mediaType", BPM_MANIFEST_MEDIA);
	json_kv_string(&e, "artifactType", BPM_TREE_ARTIFACT);
	bpm_oci_emit_descriptor(&e, "config", &config, NULL);
	json_arr_open(&e, "layers");
	bpm_oci_emit_descriptor(&e, NULL, &payload_layer, NULL);
	bpm_oci_emit_descriptor(&e, NULL, &sig_layer, NULL);
	json_arr_close(&e);
	json_obj_close(&e);
	ret = e.err;
	if (!ret && sealed)
		ret = tree_tag_sealed(&c, repository, parent);
	if (!ret)
		ret = bpm_oci_put_manifest(&c, repository, reference,
					   (const __u8 *)manifest, e.len,
					   digest, sizeof(digest));
	if (!ret)
		printf("oci://%s/%s:%s %s\n", c.registry, repository, reference,
		       digest);
out:
	xfree(manifest, BPM_MANIFEST_CAP);
	sig_free(sig);
	xfree(payload, payload_len);
	if (op)
		tree_selector_free(&op->selector);
	xfree(op, sizeof(*op));
	xfree(seen, sizeof(*seen));
	xfree(fixes, n_fixes * sizeof(*fixes));
	bpm_buffer_free(&previous);
	tree_publication_free(&pub);
	tree_publication_free(sealed);
	xfree(sealed, sizeof(*sealed));
	bpm_build_spec_free(spec);
	xfree(beefile, len + 1);
	xfree(info.cert, info.cert_len + 1);
	return ret;
}

static void bpm_push_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm push <package-file> <repository>\n"
		"                        [--keys-dir <dir> | --index-cert <cert.der>\n"
		"                         --index-key <signing_key.pem>] [--new-index]\n\n"
		"The repository must start with oci:// and must not include a tag.\n"
		"With signing material the registry's signed index at\n"
		"<namespace>/bpm-index:stable gains the package entry, signed with the\n"
		"operator key; without it only the package is published. A namespace\n"
		"without an index is refused unless --new-index starts one, which in\n"
		"turn is refused where an index exists.\n"
		"Examples:\n"
		"  shirudo bpm push ./package.bee oci://quay.io/namespace/package\n"
		"  shirudo bpm push ./package.bee oci://quay.io/namespace/package \\\n"
		"      --keys-dir /var/lib/shirudo/keys\n");
}

int build_bpm_push(int argc, char **argv)
{
	const char *package = NULL, *repository = NULL, *reference = NULL;
	const char *keys_dir_arg = NULL, *index_cert = NULL, *index_key = NULL;
	char cert_path[PATH_MAX], key_path[PATH_MAX];
	bool new_index = false;
	int ret;

	if (argc == 2 && build_is_help(argv[1])) {
		bpm_push_usage();
		return 0;
	}
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (!strcmp(a, "--keys-dir") && i + 1 < argc) {
			keys_dir_arg = argv[++i];
		} else if (!strncmp(a, "--keys-dir=", 11)) {
			keys_dir_arg = a + 11;
		} else if (!strcmp(a, "--index-cert") && i + 1 < argc) {
			index_cert = argv[++i];
		} else if (!strncmp(a, "--index-cert=", 13)) {
			index_cert = a + 13;
		} else if (!strcmp(a, "--index-key") && i + 1 < argc) {
			index_key = argv[++i];
		} else if (!strncmp(a, "--index-key=", 12)) {
			index_key = a + 12;
		} else if (!strcmp(a, "--new-index")) {
			new_index = true;
		} else if (a[0] == '-' || (package && repository)) {
			bpm_push_usage();
			return 2;
		} else if (!package) {
			package = a;
		} else {
			repository = a;
		}
	}
	if (!package || !repository) {
		bpm_push_usage();
		return 2;
	}
	if (keys_dir_arg) {
		if ((!index_cert &&
		     format_key_path(cert_path, sizeof(cert_path),
				     keys_dir_arg, CERT_FILE)) ||
		    (!index_key &&
		     format_key_path(key_path, sizeof(key_path),
				     keys_dir_arg, SIGNING_KEY_FILE)))
			return publish_fail("push", -EINVAL);
		if (!index_cert)
			index_cert = cert_path;
		if (!index_key)
			index_key = key_path;
	}
	if (!index_cert != !index_key) {
		pr_err("bpm push: --index-cert and --index-key must be supplied together");
		return 2;
	}
	if (new_index && !index_key) {
		pr_err("bpm push: --new-index needs --keys-dir, or --index-cert and --index-key");
		return 2;
	}
	if (index_key && build_check_keys(index_key, index_cert))
		return 1;
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return publish_fail("initialize curl", -EIO);
	ret = push_package(package, repository, index_key, index_cert,
			   new_index, &reference);
	curl_global_cleanup();
	if (ret)
		return publish_fail("push", ret);
	printf("%s\n", reference);
	xstrfree((char *)reference);
	return 0;
}

int build_bpm_tree(int argc, char **argv)
{
	int ret;

	if (argc >= 2 && !strcmp(argv[1], "show"))
		return build_bpm_tree_show(argc - 1, argv + 1);
	if (argc < 2 || strcmp(argv[1], "append")) {
		tree_append_usage();
		return argc >= 2 && build_is_help(argv[1]) ? 0 : 2;
	}
	if (argc == 3 && build_is_help(argv[2])) {
		tree_append_usage();
		return 0;
	}
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return publish_fail("initialize curl", -EIO);
	ret = cmd_bpm_tree_append(argc, argv);
	curl_global_cleanup();
	return ret ? publish_fail("tree append", ret) : 0;
}
