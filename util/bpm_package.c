// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .bee archive reading, package identity, signed index and tree fetch.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "bpm_oci.h"
#include "bpm_package.h"
#include "bpm_tree.h"
#include "crypto.h"
#include "json.h"
#include "log.h"
#include "macros.h"
#include "malloc.h"


struct index_sink {
	struct bpm_index_entry *items;
	int n;
	struct bpm_index_entry scratch;
};

static int on_index_entry(void *ud)
{
	struct index_sink *s = ud;
	if (s->n >= BPM_MAX_ENTRIES) return -E2BIG;
	if (!bpm_name_ok(s->scratch.name) || !bpm_version_ok(s->scratch.version) ||
	    !s->scratch.repository[0] || !s->scratch.manifest_digest[0] ||
	    !s->scratch.package_digest[0] || s->scratch.package_size < 0)
		return -EINVAL;
	s->items[s->n++] = s->scratch;
	return 0;
}

int bpm_index_parse(const unsigned char *body, size_t len,
		       struct bpm_index_entry *entries, int *n_entries)
{
	struct index_sink sink = { .items = entries };
	struct shirudo_json_array arr = { on_index_entry, &sink };
	struct shirudo_json_field sub[7], root[2];
	int64_t schema = 0;

	memset(sub, 0, sizeof(sub));
	sub[0] = (struct shirudo_json_field){ .key = "name", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.name, .dst_cap = sizeof(sink.scratch.name) };
	sub[1] = (struct shirudo_json_field){ .key = "version", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.version, .dst_cap = sizeof(sink.scratch.version) };
	sub[2] = (struct shirudo_json_field){ .key = "repository", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.repository, .dst_cap = sizeof(sink.scratch.repository) };
	sub[3] = (struct shirudo_json_field){ .key = "manifest_digest", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.manifest_digest, .dst_cap = sizeof(sink.scratch.manifest_digest) };
	sub[4] = (struct shirudo_json_field){ .key = "package_digest", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.package_digest, .dst_cap = sizeof(sink.scratch.package_digest) };
	sub[5] = (struct shirudo_json_field){ .key = "signer_fingerprint", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.signer, .dst_cap = sizeof(sink.scratch.signer) };
	sub[6] = (struct shirudo_json_field){ .key = "package_size", .type = SHIRUDO_JSON_T_INT,
		.dst = &sink.scratch.package_size };
	root[0] = (struct shirudo_json_field){ .key = "schema", .type = SHIRUDO_JSON_T_INT,
		.dst = &schema };
	root[1] = (struct shirudo_json_field){ .key = "packages", .type = SHIRUDO_JSON_T_ARRAY,
		.dst = &arr, .sub = sub, .n_sub = ARRAY_SIZE(sub) };
	if (shirudo_json_parse((const char *)body, len, root, ARRAY_SIZE(root)) || schema != 1 || !root[1].seen)
		return -EINVAL;
	*n_entries = sink.n;
	return 0;
}

int bpm_verify_cms(const unsigned char *payload, size_t payload_len,
		      const unsigned char *sig, size_t sig_len, const char *cert_path)
{
	struct shirudo_cert cert = {};
	int rc = -EINVAL;

	if (!shirudo_cert_read_file(cert_path, &cert))
		rc = shirudo_verify_detached(payload, payload_len, sig, sig_len, &cert);
	shirudo_cert_free(&cert);
	return rc;
}

int bpm_tar_octal(const char *p, size_t n, uint64_t *out)
{
	uint64_t v = 0; size_t i = 0;
	while (i < n && (p[i] == ' ' || p[i] == '\0')) i++;
	for (; i < n && p[i] >= '0' && p[i] <= '7'; i++) {
		if (v > (UINT64_MAX >> 3)) return -EOVERFLOW;
		v = (v << 3) | (unsigned)(p[i] - '0');
	}
	*out = v; return 0;
}

bool bpm_archive_rel_ok(const char *name)
{
	const char *p = name, *q;
	if (!name || !*name || *name == '/') return false;
	while (*p) {
		q = strchr(p, '/');
		if (!q) q = p + strlen(p);
		if (q == p || (q - p == 2 && !strncmp(p, "..", 2))) return false;
		p = *q ? q + 1 : q;
	}
	return true;
}

static bool package_member_name_ok(const char *name, const char *member)
{
	const char *slash;

	if (!bpm_archive_rel_ok(name) || !member)
		return false;
	slash = strchr(name, '/');
	return slash && slash != name && strncmp(name, "./", 2) &&
		bpm_archive_rel_ok(member) && !strcmp(slash + 1, member);
}

int bpm_pkg_read_member_in(const char *archive, const char *member,
				 const char *package_dir, char *found_dir,
				 size_t found_dir_sz, unsigned char **out,
				 size_t *out_len, size_t max)
{
	gzFile gz = gzopen(archive, "rb");
	unsigned char h[512];
	int rc = -ENOENT;

	if (!gz)
		return -errno;
	if (gzdirect(gz)) {
		gzclose(gz);
		return -EINVAL;
	}
	for (;;) {
		int n = gzread(gz, h, sizeof(h));
		uint64_t size, remain, pad;
		char name[101];
		bool zero = true;

		if (n == 0)
			break;
		if (n != (int)sizeof(h)) {
			rc = -EINVAL;
			break;
		}
		for (size_t i = 0; i < sizeof(h); i++)
			if (h[i]) {
				zero = false;
				break;
			}
		if (zero)
			break;
		memcpy(name, h, 100);
		name[100] = '\0';
		if (!memchr(h, '\0', 100) || bpm_tar_octal((char *)h + 124, 12, &size)) {
			rc = -EINVAL;
			break;
		}
		remain = size;
		if (package_member_name_ok(name, member) &&
		    (!package_dir ||
		     ((size_t)(strchr(name, '/') - name) == strlen(package_dir) &&
		      !strncmp(name, package_dir, strlen(package_dir))))) {
			size_t dir_len = (size_t)(strchr(name, '/') - name);
			unsigned char *body;

			if ((h[156] && h[156] != '0') || h[345] ||
			    (found_dir && dir_len >= found_dir_sz)) {
				rc = -EINVAL;
				break;
			}
			if (size > max || size > SIZE_MAX - 1) {
				rc = -E2BIG;
				break;
			}
			body = xmalloc((size_t)size + 1);
			if (!body) {
				rc = -ENOMEM;
				break;
			}
			while (remain) {
				size_t want = remain > 65536 ? 65536 : (size_t)remain;
				n = gzread(gz, body + size - remain, (unsigned)want);
				if (n <= 0) {
					xfree(body, (size_t)size + 1);
					rc = -EINVAL;
					goto done;
				}
				remain -= (size_t)n;
			}
			body[size] = '\0';
			*out = body;
			*out_len = (size_t)size;
			if (found_dir) {
				memcpy(found_dir, name, dir_len);
				found_dir[dir_len] = '\0';
			}
			rc = 0;
			break;
		}
		while (remain) {
			unsigned char discard[65536];
			size_t want = remain > sizeof(discard) ? sizeof(discard) : (size_t)remain;
			n = gzread(gz, discard, (unsigned)want);
			if (n <= 0) {
				rc = -EINVAL;
				goto done;
			}
			remain -= (size_t)n;
		}
		pad = (512 - (size % 512)) % 512;
		while (pad) {
			unsigned char discard[512];
			size_t want = pad > sizeof(discard) ? sizeof(discard) : (size_t)pad;
			n = gzread(gz, discard, (unsigned)want);
			if (n <= 0) {
				rc = -EINVAL;
				goto done;
			}
			pad -= (size_t)n;
		}
	}
done:
	if (gzclose(gz) != Z_OK && rc == 0) {
		xfree(*out, *out_len + 1);
		*out = NULL;
		*out_len = 0;
		rc = -EINVAL;
	}
	return rc;
}

int bpm_pkg_read_member(const char *archive, const char *member,
			       unsigned char **out, size_t *out_len, size_t max)
{
	return bpm_pkg_read_member_in(archive, member, NULL, NULL, 0,
				      out, out_len, max);
}

static X509 *read_x509_memory(const unsigned char *body, size_t len)
{
	BIO *b;
	X509 *x;

	if (len > INT_MAX)
		return NULL;
	b = BIO_new_mem_buf(body, (int)len);
	if (!b)
		return NULL;
	x = d2i_X509_bio(b, NULL);
	if (!x && BIO_reset(b) == 1)
		x = PEM_read_bio_X509(b, NULL, NULL, NULL);
	BIO_free(b);
	return x;
}

/* Hash the exact DER SubjectPublicKeyInfo representation used by Go's
 * x509.MarshalPKIXPublicKey.  Keep this explicit instead of relying on
 * X509_pubkey_digest(), whose meaning is easy to confuse with a digest of
 * the key material itself when diagnosing package signer mismatches. */
static int x509_spki_sha256(const X509 *cert, unsigned char digest[32])
{
	X509_PUBKEY *spki;
	unsigned char *der = NULL, *p;
	unsigned int digest_len = 0;
	int der_len, encoded_len, rc = -EINVAL;

	spki = X509_get_X509_PUBKEY((X509 *)cert);
	if (!spki)
		return -EINVAL;
	der_len = i2d_X509_PUBKEY(spki, NULL);
	if (der_len <= 0)
		return -EINVAL;
	der = xmalloc((size_t)der_len);
	if (!der)
		return -ENOMEM;
	p = der;
	encoded_len = i2d_X509_PUBKEY(spki, &p);
	if (encoded_len != der_len)
		goto out;
	if (!EVP_Digest(der, (size_t)der_len, digest, &digest_len,
			EVP_sha256(), NULL) || digest_len != 32)
		goto out;
	rc = 0;
out:
	xfree(der, (size_t)der_len);
	return rc;
}

int bpm_pkg_load_info(const char *archive, struct bpm_package_info *info)
{
	unsigned char *environment = NULL;
	struct {
		char name[BPM_MAX_NAME];
		char version[BPM_MAX_NAME];
		char signer[BPM_MAX_DIGEST];
	} parsed = {};
	struct shirudo_json_field package_fields[2], shirudo_fields[1], root[2];
	unsigned char digest[32];
	X509 *cert = NULL;
	char hex[EVP_MAX_MD_SIZE * 2 + 1];
	size_t environment_len;
	int rc;

	memset(package_fields, 0, sizeof(package_fields));
	package_fields[0] = (struct shirudo_json_field){
		.key = "name", .type = SHIRUDO_JSON_T_STRING,
		.dst = parsed.name, .dst_cap = sizeof(parsed.name),
	};
	package_fields[1] = (struct shirudo_json_field){
		.key = "version", .type = SHIRUDO_JSON_T_STRING,
		.dst = parsed.version, .dst_cap = sizeof(parsed.version),
	};
	shirudo_fields[0] = (struct shirudo_json_field){
		.key = "spki_sha256_fingerprint", .type = SHIRUDO_JSON_T_STRING,
		.dst = parsed.signer, .dst_cap = sizeof(parsed.signer),
	};
	root[0] = (struct shirudo_json_field){
		.key = "package", .type = SHIRUDO_JSON_T_OBJECT,
		.sub = package_fields, .n_sub = ARRAY_SIZE(package_fields),
	};
	root[1] = (struct shirudo_json_field){
		.key = "shirudo", .type = SHIRUDO_JSON_T_OBJECT,
		.sub = shirudo_fields, .n_sub = ARRAY_SIZE(shirudo_fields),
	};

	rc = bpm_pkg_read_member(archive, "build-environment.json", &environment,
				 &environment_len, 4u * 1024u * 1024u);
	if (rc)
		return rc;
	if (shirudo_json_parse((const char *)environment, environment_len,
				       root, ARRAY_SIZE(root)) ||
	    !root[0].seen || !parsed.name[0] || !parsed.version[0] ||
	    !bpm_package_name_ok(parsed.name) || !bpm_version_ok(parsed.version)) {
		rc = -EINVAL;
		goto out;
	}

	rc = bpm_pkg_read_member(archive, "cert.der", &info->cert, &info->cert_len,
				 4u * 1024u * 1024u);
	if (rc)
		goto out;
	cert = read_x509_memory(info->cert, info->cert_len);
	if (!cert || x509_spki_sha256(cert, digest)) {
		rc = -EINVAL;
		goto out;
	}
	for (unsigned int i = 0; i < sizeof(digest); i++)
		snprintf(hex + i * 2, 3, "%02x", digest[i]);
	hex[sizeof(digest) * 2] = '\0';
	if (parsed.signer[0] && strcasecmp(parsed.signer, hex)) {
		pr_err("bpm: package signer fingerprint mismatch: "
		       "certificate=%s build-environment.json=%s",
		       hex, parsed.signer);
		rc = -EKEYREJECTED;
		goto out;
	}
	bpm_copy_string(info->name, sizeof(info->name), parsed.name);
	bpm_copy_string(info->version, sizeof(info->version), parsed.version);
	bpm_copy_string(info->signer, sizeof(info->signer), hex);
	rc = 0;
out:
	X509_free(cert);
	xfree(environment, environment_len + 1);
	if (rc) {
		xfree(info->cert, info->cert_len + 1);
		info->cert = NULL;
		info->cert_len = 0;
	}
	return rc;
}

int bpm_tree_fetch_publication(struct bpm_oci_client *c,
				     const char *repository,
				     const char *reference,
				     const char *cert_path,
				     struct shirudo_tree_publication *pub,
				     char *manifest_digest, size_t digest_sz)
{
	struct bpm_buffer manifest = {}, payload = {}, sig = {};
	struct bpm_descriptor *layers = NULL;
	char url[PATH_MAX], hex[65];
	int nl = 0, payload_layers = 0, sig_layers = 0;
	int rc;

	if (!reference[0] || strchr(reference, '/') || strchr(reference, '?') ||
	    strchr(reference, '#') || strstr(reference, ".."))
		return -EINVAL;
	rc = bpm_oci_url(c, repository, "manifests", reference, url,
			  sizeof(url));
	if (rc)
		return rc;
	rc = bpm_oci_get_memory(c, url, BPM_MANIFEST_MEDIA, &manifest);
	if (rc)
		goto out;
	if (bpm_sha256_hex(manifest.data, manifest.len, hex, sizeof(hex))) {
		rc = -EKEYREJECTED;
		goto out;
	}
	if (snprintf(manifest_digest, digest_sz, "sha256:%s", hex) >=
	    (int)digest_sz) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	layers = xcalloc(BPM_MAX_ENTRIES, sizeof(*layers));
	if (!layers) {
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = bpm_oci_parse_manifest(manifest.data, manifest.len, layers, &nl,
				 NULL, 0)))
		goto out;
	for (int i = 0; i < nl; i++) {
		struct bpm_buffer *dst;

		if (!strcmp(layers[i].media, BPM_TREE_MEDIA)) {
			dst = &payload;
			payload_layers++;
		} else if (!strcmp(layers[i].media, BPM_TREE_SIG_MEDIA)) {
			dst = &sig;
			sig_layers++;
		} else {
			continue;
		}
		if (dst->data) {
			rc = -EINVAL;
			goto out;
		}
		if ((rc = bpm_oci_url(c, repository, "blobs", layers[i].digest,
				       url, sizeof(url))))
			goto out;
		if ((rc = bpm_oci_get_memory(c, url, layers[i].media, dst)))
			goto out;
		if ((layers[i].size >= 0 && (int64_t)dst->len != layers[i].size) ||
		    bpm_sha256_hex(dst->data, dst->len, hex, sizeof(hex)) ||
		    !bpm_digest_matches(layers[i].digest, hex)) {
			rc = -EKEYREJECTED;
			goto out;
		}
	}
	if (payload_layers != 1 || sig_layers != 1 || !payload.data || !sig.data) {
		rc = -EINVAL;
		goto out;
	}
	if (bpm_verify_cms(payload.data, payload.len, sig.data, sig.len, cert_path)) {
		rc = -EKEYREJECTED;
		goto out;
	}
	rc = shirudo_tree_parse((const char *)payload.data, payload.len, pub);
out:
	if (layers)
		xfree(layers, BPM_MAX_ENTRIES * sizeof(*layers));
	bpm_buffer_free(&manifest);
	bpm_buffer_free(&payload);
	bpm_buffer_free(&sig);
	return rc;
}
