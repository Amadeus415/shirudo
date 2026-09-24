// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Target-local BPM repository manager.  The OCI distribution protocol is
 * deliberately kept small here: libcurl supplies HTTP/TLS transport, while
 * this file owns repository configuration, registry auth, signed indexes,
 * and the .bee lifecycle.
 */

#include <ctype.h>
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
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "builtin.h"
#include "util/bpm_tree.h"
#include "util/bpm_source_config.h"
#include "util/crypto.h"
#include "util/help.h"
#include "util/io.h"
#include "util/json.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/paths.h"
#include "util/seal.h"
#include "util/upatch.h"

#ifndef SHIRUDO_LIBEXEC_DIR
#define SHIRUDO_LIBEXEC_DIR "/usr/local/libexec/shirudo"
#endif

#define BPM_MAX_NAME 128
#define BPM_MAX_ENDPOINT 512
#define BPM_MAX_KEY 256
#define BPM_MAX_DIGEST 128
#define BPM_MAX_MEDIA 192
#define BPM_MAX_ENTRIES 512
#define BPM_MAX_SOURCES 64
#define BPM_MAX_STATE 256
#define BPM_MAX_HTTP_BODY (256u * 1024u * 1024u)
#define BPM_INDEX_REPOSITORY "shirudo/bpm-index"
#define BPM_INDEX_TAG "stable"
#define BPM_INDEX_MEDIA "application/vnd.shirudo.bpm.index.v1+json"
#define BPM_INDEX_SIG_MEDIA "application/vnd.shirudo.bpm.index.signature.v1"
#define BPM_PACKAGE_MEDIA "application/vnd.shirudo.bpm.package.v1+gzip"
#define BPM_CONFIG_MEDIA "application/vnd.shirudo.bpm.config.v1+json"
#define BPM_EMPTY_CONFIG_MEDIA "application/vnd.oci.empty.v1+json"
#define BPM_PUBLIC_KEY_ARTIFACT "application/vnd.shirudo.bpm.public-key.v1+der"
#define BPM_PUBLIC_KEY_MEDIA "application/pkix-cert"
#define BPM_TREE_MEDIA "application/vnd.shirudo.upatch.tree.v2+json"
#define BPM_TREE_SIG_MEDIA "application/vnd.shirudo.upatch.tree.signature.v2"
#define BPM_UPATCH_MEDIA "application/vnd.shirudo.upatch.v1"

struct bpm_source {
	char name[BPM_MAX_NAME];
	char endpoint[BPM_MAX_ENDPOINT];
	char key_file[BPM_MAX_KEY];
};

struct bpm_descriptor {
	char media[BPM_MAX_MEDIA];
	char digest[BPM_MAX_DIGEST];
	char title[PATH_MAX];
	int64_t size;
};

struct bpm_index_entry {
	char name[BPM_MAX_NAME];
	char version[BPM_MAX_NAME];
	char repository[BPM_MAX_ENDPOINT];
	char manifest_digest[BPM_MAX_DIGEST];
	char package_digest[BPM_MAX_DIGEST];
	char signer[BPM_MAX_DIGEST];
	int64_t package_size;
};

struct bpm_state_entry {
	char name[BPM_MAX_NAME];
	char version[BPM_MAX_NAME];
	char source[BPM_MAX_NAME];
	char path[PATH_MAX];
};

struct bpm_buffer {
	unsigned char *data;
	size_t len;
	size_t cap;
};

struct bpm_http_response {
	struct bpm_buffer body;
	char www_auth[2048];
	char content_type[BPM_MAX_MEDIA];
	char location[PATH_MAX];
	long status;
};

struct bpm_oci_client {
	char base_url[BPM_MAX_ENDPOINT];
	char registry[BPM_MAX_ENDPOINT];
	char username[256];
	char password[256];
	char token[4096];
	char ca_file[PATH_MAX];
	struct shirudo_tls_ca tls_ca;
};

struct bpm_package_info {
	char name[BPM_MAX_NAME];
	char version[BPM_MAX_NAME];
	char signer[BPM_MAX_DIGEST];
	unsigned char *cert;
	size_t cert_len;
};

static void bpm_copy_string(char *dst, size_t dst_sz, const char *src)
{
	size_t len;

	if (!dst_sz)
		return;
	if (!src)
		src = "";
	len = strlen(src);
	if (len >= dst_sz)
		len = dst_sz - 1;
	memcpy(dst, src, len);
	dst[len] = '\0';
}

static int path_mkdir_p(const char *path, mode_t mode)
{
	char tmp[PATH_MAX];
	char *p;

	if (!path || strlen(path) >= sizeof(tmp))
		return -ENAMETOOLONG;
	snprintf(tmp, sizeof(tmp), "%s", path);
	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, mode) && errno != EEXIST)
			return -errno;
		*p = '/';
	}
	if (mkdir(tmp, mode) && errno != EEXIST)
		return -errno;
	return 0;
}

static bool bpm_component_ok(const char *s, bool plus)
{
	const unsigned char *p = (const unsigned char *)s;

	if (!s || !*s || strlen(s) >= BPM_MAX_NAME || s[0] == '.')
		return false;
	for (; *p; p++)
		if (!(isalnum(*p) || *p == '-' || *p == '_' || *p == '.' ||
		      (plus && *p == '+')))
			return false;
	return true;
}

static bool bpm_name_ok(const char *s)
{
	return bpm_component_ok(s, false);
}

static bool bpm_version_ok(const char *s)
{
	return bpm_component_ok(s, true);
}

static int bpm_buffer_append(struct bpm_buffer *b, const void *data, size_t len)
{
	size_t want;
	unsigned char *p;

	if (len >= BPM_MAX_HTTP_BODY - b->len)
		return -E2BIG;
	want = b->len + len;
	if (want + 1 > b->cap) {
		size_t cap = b->cap ? b->cap : 4096;

		while (cap <= want) {
			if (cap > BPM_MAX_HTTP_BODY / 2) {
				cap = BPM_MAX_HTTP_BODY;
				break;
			}
			cap *= 2;
		}
		p = realloc(b->data, cap);
		if (!p)
			return -ENOMEM;
		b->data = p;
		b->cap = cap;
	}
	memcpy(b->data + b->len, data, len);
	b->len += len;
	b->data[b->len] = '\0';
	return 0;
}

static size_t bpm_write_memory(void *ptr, size_t size, size_t nmemb, void *ud)
{
	struct bpm_http_response *r = ud;
	size_t n = size * nmemb;

	if (bpm_buffer_append(&r->body, ptr, n))
		return 0;
	return n;
}

static size_t bpm_write_file(void *ptr, size_t size, size_t nmemb, void *ud)
{
	FILE *fp = ud;
	size_t n = size * nmemb;

	return fwrite(ptr, 1, n, fp);
}

static size_t bpm_header(void *ptr, size_t size, size_t nmemb, void *ud)
{
	struct bpm_http_response *r = ud;
	char line[4096];
	size_t n = size * nmemb;
	char *v;

	if (n >= sizeof(line))
		return n;
	memcpy(line, ptr, n);
	line[n] = '\0';
	if (!strncasecmp(line, "WWW-Authenticate:", 17)) {
		v = line + 17;
		while (isspace((unsigned char)*v)) v++;
		bpm_copy_string(r->www_auth, sizeof(r->www_auth), v);
	} else if (!strncasecmp(line, "Content-Type:", 13)) {
		v = line + 13;
		while (isspace((unsigned char)*v)) v++;
		v[strcspn(v, " ;\r\n")] = '\0';
		bpm_copy_string(r->content_type, sizeof(r->content_type), v);
	} else if (!strncasecmp(line, "Location:", 9)) {
		v = line + 9;
		while (isspace((unsigned char)*v)) v++;
		v[strcspn(v, "\r\n")] = '\0';
		bpm_copy_string(r->location, sizeof(r->location), v);
	}
	return n;
}

static int base64_value(int c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

static int decode_basic(const char *in, char *user, size_t usz,
			char *pass, size_t psz)
{
	unsigned char out[1024];
	size_t n = 0, i = 0;
	int val = 0, bits = -8, x;
	char *colon;

	for (; *in && *in != '"' && n < sizeof(out); in++) {
		if (isspace((unsigned char)*in) || *in == '=')
			continue;
		x = base64_value((unsigned char)*in);
		if (x < 0)
			return -EINVAL;
		val = (val << 6) | x;
		bits += 6;
		if (bits >= 0) {
			out[n++] = (unsigned char)((val >> bits) & 0xff);
			bits -= 8;
		}
	}
	if (n >= sizeof(out))
		return -E2BIG;
	out[n] = '\0';
	colon = memchr(out, ':', n);
	if (!colon || (size_t)(colon - (char *)out) >= usz ||
	    n - (size_t)(colon - (char *)out) - 1 >= psz)
		return -EINVAL;
	memcpy(user, out, (size_t)(colon - (char *)out));
	user[colon - (char *)out] = '\0';
	memcpy(pass, colon + 1, n - (size_t)(colon - (char *)out) - 1);
	pass[n - (size_t)(colon - (char *)out) - 1] = '\0';
	(void)i;
	return 0;
}

static int encode_basic(const char *user, const char *pass,
			char *out, size_t out_sz)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char raw[1024];
	size_t len, need, i, o = 0;

	if (snprintf(raw, sizeof(raw), "%s:%s", user, pass) >= (int)sizeof(raw))
		return -E2BIG;
	len = strlen(raw);
	need = 4 * ((len + 2) / 3) + 1;
	if (need > out_sz)
		return -ENOSPC;
	for (i = 0; i < len; i += 3) {
		unsigned v = (unsigned char)raw[i] << 16;
		if (i + 1 < len) v |= (unsigned char)raw[i + 1] << 8;
		if (i + 2 < len) v |= (unsigned char)raw[i + 2];
		out[o++] = alphabet[(v >> 18) & 63];
		out[o++] = alphabet[(v >> 12) & 63];
		out[o++] = i + 1 < len ? alphabet[(v >> 6) & 63] : '=';
		out[o++] = i + 2 < len ? alphabet[v & 63] : '=';
	}
	out[o] = '\0';
	return 0;
}

static int read_small_file(const char *path, unsigned char **out, size_t *out_len,
			   size_t max)
{
	struct stat st;
	unsigned char *p;
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
	p = malloc((size_t)st.st_size + 1);
	if (!p) {
		close(fd);
		return -ENOMEM;
	}
	n = read(fd, p, (size_t)st.st_size);
	close(fd);
	if (n != st.st_size) {
		free(p);
		return n < 0 ? -errno : -EIO;
	}
	p[n] = 0;
	*out = p;
	*out_len = (size_t)n;
	return 0;
}

static int load_registry_auth(const char *registry, struct bpm_oci_client *c)
{
	const char *authfile = getenv("REGISTRY_AUTH_FILE");
	const char *docker = getenv("DOCKER_CONFIG");
	char path[PATH_MAX];
	char needle[BPM_MAX_ENDPOINT + 8];
	unsigned char *body = NULL;
	char *p, *end, *auth;
	int rc;

	if (getenv("BPM_OCI_USERNAME") && getenv("BPM_OCI_PASSWORD")) {
		snprintf(c->username, sizeof(c->username), "%s", getenv("BPM_OCI_USERNAME"));
		snprintf(c->password, sizeof(c->password), "%s", getenv("BPM_OCI_PASSWORD"));
		return 0;
	}
	if (!authfile && docker) {
		if (snprintf(path, sizeof(path), "%s/config.json", docker) >= (int)sizeof(path))
			return -ENAMETOOLONG;
		authfile = path;
	}
	if (!authfile) {
		const char *home = getenv("HOME");
		if (!home) home = "/root";
		if (snprintf(path, sizeof(path), "%s/.docker/config.json", home) >= (int)sizeof(path))
			return -ENAMETOOLONG;
		authfile = path;
	}
	rc = read_small_file(authfile, &body, &(size_t){0}, 4u * 1024u * 1024u);
	if (rc) return rc == -ENOENT ? 0 : rc;
	/* The auth file is local input; require the registry key and auth member
	 * to occur in the same JSON object before accepting credentials. */
	snprintf(needle, sizeof(needle), "\"%s\"", registry);
	p = strstr((char *)body, needle);
	if (!p) { free(body); return 0; }
	end = strchr(p, '}');
	if (!end) { free(body); return -EINVAL; }
	auth = strstr(p, "\"auth\"");
	if (!auth || auth > end) { free(body); return 0; }
	auth = strchr(auth, ':');
	if (!auth) { free(body); return -EINVAL; }
	while (*++auth && isspace((unsigned char)*auth)) {}
	if (*auth != '"') { free(body); return -EINVAL; }
	rc = decode_basic(auth + 1, c->username, sizeof(c->username),
			  c->password, sizeof(c->password));
	free(body);
	return rc;
}

static int parse_endpoint(const char *endpoint, struct bpm_oci_client *c)
{
	const char *p, *scheme = getenv("BPM_OCI_SCHEME");
	char transport[16] = "https";

	if (!endpoint || strncmp(endpoint, "oci://", 6) != 0)
		return -EINVAL;
	p = endpoint + 6;
	if (!*p || strchr(p, '/') || strchr(p, '?') || strchr(p, '#') || strchr(p, '@'))
		return -EINVAL;
	if (scheme && *scheme) {
		if (strcmp(scheme, "https") && strcmp(scheme, "http")) {
			pr_err("bpm OCI: BPM_OCI_SCHEME must be https or http");
			return -EINVAL;
		}
		snprintf(transport, sizeof(transport), "%s", scheme);
	}
	snprintf(c->registry, sizeof(c->registry), "%s", p);
	if (snprintf(c->base_url, sizeof(c->base_url), "%s://%s", transport, p) >=
	    (int)sizeof(c->base_url))
		return -ENAMETOOLONG;
	if (getenv("BPM_OCI_CA_FILE")) {
		const char *ca_file = getenv("BPM_OCI_CA_FILE");
		struct shirudo_cert ca = {};

		if (strlen(ca_file) >= sizeof(c->ca_file))
			return -ENAMETOOLONG;
		bpm_copy_string(c->ca_file, sizeof(c->ca_file), ca_file);
		if (shirudo_cert_read_file(c->ca_file, &ca) != 0) {
			pr_err("bpm OCI: BPM_OCI_CA_FILE is not a readable certificate");
			return -EINVAL;
		}
		shirudo_cert_free(&ca);
	}
	if (c->ca_file[0]) {
		struct stat st;
		if (stat(c->ca_file, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0) {
			pr_err("bpm OCI: BPM_OCI_CA_FILE must name a non-empty regular PEM file");
			return -EINVAL;
		}
	}
	c->tls_ca.path = c->ca_file;
	return load_registry_auth(c->registry, c);
}

static int curl_once_ex(struct bpm_oci_client *c, const char *method,
			const char *url, const char *accept,
			const char *content_type, const void *body, size_t body_len,
			const char *auth, struct bpm_http_response *r, FILE *file)
{
	CURL *curl;
	struct curl_slist *headers = NULL;
	CURLcode cc;
	long status = 0;
	char errbuf[CURL_ERROR_SIZE] = {};

	curl = curl_easy_init();
	if (!curl) return -ENOMEM;
	if (accept) {
		char h[256];
		snprintf(h, sizeof(h), "Accept: %s", accept);
		headers = curl_slist_append(headers, h);
	}
	if (content_type) {
		char h[256];
		snprintf(h, sizeof(h), "Content-Type: %s", content_type);
		headers = curl_slist_append(headers, h);
	}
	if (auth) {
		char h[8192];
		snprintf(h, sizeof(h), "Authorization: %s", auth);
		headers = curl_slist_append(headers, h);
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
	if (!strcasecmp(method, "HEAD"))
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	/* OCI registries commonly redirect blob GETs to a signed CDN URL.
	 * Follow only for file downloads, never for manifest or upload calls. */
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, file ? 1L : 0L);
	if (file) {
		const char *redirect_protocols =
			!strncmp(c->base_url, "https://", 8) ? "https" : "http,https";

		curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
	#if LIBCURL_VERSION_NUM >= 0x075500
		curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, redirect_protocols);
	#else
		curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS,
				 !strcmp(redirect_protocols, "https") ? CURLPROTO_HTTPS :
				 CURLPROTO_HTTP | CURLPROTO_HTTPS);
	#endif
		/* Keep Authorization restricted to the original registry host. */
		curl_easy_setopt(curl, CURLOPT_UNRESTRICTED_AUTH, 0L);
	}
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, shirudo_sslctx_callback);
	curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, &c->tls_ca);
	if (body) {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
	}
	if (file) {
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bpm_write_file);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
	} else {
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bpm_write_memory);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, r);
	}
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, bpm_header);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, r);
	if (auth && !strncmp(auth, "Basic ", 6)) {
		/* Header is already constructed; do not let curl negotiate or leak it. */
	}
	cc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
	r->status = status;
	if (cc != CURLE_OK) {
		pr_err("bpm OCI request %s: %s", url, errbuf[0] ? errbuf : curl_easy_strerror(cc));
		status = -1;
	}
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	shirudo_tls_ca_cleanup(&c->tls_ca);
	return status < 0 ? -EHOSTUNREACH : 0;
}

static int curl_once(struct bpm_oci_client *c, const char *method,
			     const char *url, const char *accept, const char *auth,
			     struct bpm_http_response *r, FILE *file)
{
	return curl_once_ex(c, method, url, accept, NULL, NULL, 0, auth, r, file);
}

static int parse_challenge(const char *header, char *realm, size_t rsz,
			    char *service, size_t ssz, char *scope, size_t zsz)
{
	const char *p;
	const char *q;

	if (!header || strncasecmp(header, "Bearer", 6) != 0)
		return -EINVAL;
	for (p = header + 6; *p;) {
		while (*p == ' ' || *p == ',') p++;
		if (!strncmp(p, "realm=\"", 7)) {
			p += 7; q = strchr(p, '"'); if (!q) return -EINVAL;
			if ((size_t)(q - p) >= rsz) return -ENAMETOOLONG;
			memcpy(realm, p, q - p); realm[q - p] = 0; p = q + 1;
		} else if (!strncmp(p, "service=\"", 9)) {
			p += 9; q = strchr(p, '"'); if (!q) return -EINVAL;
			if ((size_t)(q - p) >= ssz) return -ENAMETOOLONG;
			memcpy(service, p, q - p); service[q - p] = 0; p = q + 1;
		} else if (!strncmp(p, "scope=\"", 7)) {
			p += 7; q = strchr(p, '"'); if (!q) return -EINVAL;
			if ((size_t)(q - p) >= zsz) return -ENAMETOOLONG;
			memcpy(scope, p, q - p); scope[q - p] = 0; p = q + 1;
		} else {
			p = strchr(p, ','); if (!p) break;
		}
	}
	return realm[0] ? 0 : -EINVAL;
}

static int get_bearer_token(struct bpm_oci_client *c, const char *challenge)
{
	const char *provided_token = getenv("BPM_OCI_BEARER_TOKEN");
	char realm[PATH_MAX] = {}, service[256] = {}, scope[512] = {};
	char url[PATH_MAX * 2];
	char basic[2048], auth_header[sizeof(basic) + 32];
	CURL *curl = NULL;
	struct curl_slist *headers = NULL;
	struct bpm_http_response r = {};
	CURLcode cc;
	char *esc_service = NULL, *esc_scope = NULL;
	char *token;
	int rc = -EINVAL;

	if (provided_token && *provided_token) {
		if (strlen(provided_token) >= sizeof(c->token))
			return -E2BIG;
		bpm_copy_string(c->token, sizeof(c->token), provided_token);
		return 0;
	}
	if (parse_challenge(challenge, realm, sizeof(realm), service,
			    sizeof(service), scope, sizeof(scope)))
		return -EINVAL;
	curl = curl_easy_init();
	if (!curl)
		return -ENOMEM;
	esc_service = curl_easy_escape(curl, service, 0);
	esc_scope = curl_easy_escape(curl, scope, 0);
	if (!esc_service || !esc_scope)
		goto out;
	if (snprintf(url, sizeof(url), "%s?service=%s&scope=%s", realm,
		     esc_service, esc_scope) >= (int)sizeof(url)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	if (c->username[0]) {
		rc = encode_basic(c->username, c->password, basic,
				   sizeof(basic));
		if (rc)
			goto out;
		if (snprintf(auth_header, sizeof(auth_header),
			     "Authorization: Basic %s", basic) >=
		    (int)sizeof(auth_header)) {
			rc = -E2BIG;
			goto out;
		}
		headers = curl_slist_append(headers, auth_header);
		if (!headers) {
			rc = -ENOMEM;
			goto out;
		}
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bpm_write_memory);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &r);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, shirudo_sslctx_callback);
	curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, &c->tls_ca);
	cc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r.status);
	if (cc != CURLE_OK) {
		rc = -EHOSTUNREACH;
		goto out;
	}
	if (r.status >= 300) {
		rc = -EACCES;
		goto out;
	}
	token = strstr((char *)r.body.data, "\"token\"");
	if (!token) token = strstr((char *)r.body.data, "\"access_token\"");
	if (!token || !(token = strchr(token, ':')))
		goto out;
	while (*++token && isspace((unsigned char)*token)) {}
	if (*token++ != '"')
		goto out;
	{
		char *end = strchr(token, '"');
		if (!end || (size_t)(end - token) >= sizeof(c->token))
			goto out;
		memcpy(c->token, token, end - token); c->token[end - token] = 0;
	}
	rc = 0;
out:
	curl_free(esc_service);
	curl_free(esc_scope);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	shirudo_tls_ca_cleanup(&c->tls_ca);
	free(r.body.data);
	return rc;
}

static int oci_get_memory(struct bpm_oci_client *c, const char *url,
			   const char *accept, struct bpm_buffer *out)
{
	struct bpm_http_response r = {};
	char auth[8192];
	int rc;

	rc = curl_once(c, "GET", url, accept, NULL, &r, NULL);
	if (rc) goto out;
	if (r.status == 401 && r.www_auth[0]) {
		if (!strncasecmp(r.www_auth, "Bearer", 6)) {
			rc = get_bearer_token(c, r.www_auth);
			if (rc) goto out;
			snprintf(auth, sizeof(auth), "Bearer %s", c->token);
		} else if (!strncasecmp(r.www_auth, "Basic", 5) && c->username[0]) {
			char encoded[2048];
			rc = encode_basic(c->username, c->password, encoded, sizeof(encoded));
			if (rc) goto out;
			snprintf(auth, sizeof(auth), "Basic %s", encoded);
		} else { rc = -EACCES; goto out; }
		free(r.body.data); r = (struct bpm_http_response){};
		rc = curl_once(c, "GET", url, accept, auth, &r, NULL);
	}
	if (!rc && (r.status < 200 || r.status >= 300)) rc = r.status == 404 ? -ENOENT : -EACCES;
	if (!rc) { *out = r.body; r.body.data = NULL; }
out:
	free(r.body.data);
	return rc;
}

static int oci_get_file(struct bpm_oci_client *c, const char *url,
			const char *accept, const char *path)
{
	struct bpm_http_response r = {};
	FILE *fp;
	char auth[8192];
	int rc;

	fp = fopen(path, "wb");
	if (!fp) return -errno;
	rc = curl_once(c, "GET", url, accept, NULL, &r, fp);
	if (!rc && r.status == 401 && r.www_auth[0] && !strncasecmp(r.www_auth, "Bearer", 6)) {
		fclose(fp); unlink(path); fp = fopen(path, "wb");
		if (!fp) { free(r.body.data); return -errno; }
		rc = get_bearer_token(c, r.www_auth);
		if (!rc) {
			snprintf(auth, sizeof(auth), "Bearer %s", c->token);
			memset(&r, 0, sizeof(r));
			rc = curl_once(c, "GET", url, accept, auth, &r, fp);
		}
	} else if (!rc && r.status == 401 && r.www_auth[0] &&
		   !strncasecmp(r.www_auth, "Basic", 5) && c->username[0]) {
		char encoded[2048];
		fclose(fp); unlink(path); fp = fopen(path, "wb");
		if (!fp) { free(r.body.data); return -errno; }
		rc = encode_basic(c->username, c->password, encoded, sizeof(encoded));
		if (!rc) {
			snprintf(auth, sizeof(auth), "Basic %s", encoded);
			memset(&r, 0, sizeof(r));
			rc = curl_once(c, "GET", url, accept, auth, &r, fp);
		}
	}
	if (!rc && (r.status < 200 || r.status >= 300)) rc = r.status == 404 ? -ENOENT : -EACCES;
	if (fclose(fp) && !rc) rc = -EIO;
	free(r.body.data);
	if (rc) unlink(path);
	return rc;
}

/* A request helper for OCI uploads. Unlike the download helpers above, it
 * preserves the response headers (notably Location) and supports a request
 * body while still retrying once after a registry authentication challenge. */
static int oci_request(struct bpm_oci_client *c, const char *method,
			const char *url, const char *accept, const char *content_type,
			const void *body, size_t body_len, struct bpm_http_response *r)
{
	char auth[8192] = {};
	int rc;

	*r = (struct bpm_http_response){};
	rc = curl_once_ex(c, method, url, accept, content_type, body, body_len,
			  NULL, r, NULL);
	if (rc)
		return rc;
	if (r->status == 401 && r->www_auth[0]) {
		if (!strncasecmp(r->www_auth, "Bearer", 6)) {
			rc = get_bearer_token(c, r->www_auth);
			if (rc)
				return rc;
			snprintf(auth, sizeof(auth), "Bearer %s", c->token);
		} else if (!strncasecmp(r->www_auth, "Basic", 5) && c->username[0]) {
			char encoded[2048];

			rc = encode_basic(c->username, c->password, encoded,
					   sizeof(encoded));
			if (rc)
				return rc;
			snprintf(auth, sizeof(auth), "Basic %s", encoded);
		} else {
			return -EACCES;
		}
		free(r->body.data);
		*r = (struct bpm_http_response){};
		rc = curl_once_ex(c, method, url, accept, content_type, body,
				   body_len, auth, r, NULL);
		if (rc)
			return rc;
	}
	if (r->status < 200 || r->status >= 300)
	{
		if (r->status != 404) {
			if (r->body.data && r->body.len) {
				size_t n = r->body.len > 512 ? 512 : r->body.len;

				pr_err("bpm OCI request %s: HTTP %ld: %.*s", url,
				       r->status, (int)n, r->body.data);
			} else {
				pr_err("bpm OCI request %s: HTTP %ld", url, r->status);
			}
		}
		return r->status == 404 ? -ENOENT : -EACCES;
	}
	return 0;
}

struct desc_sink {
	struct bpm_descriptor *items;
	int n;
	struct bpm_descriptor scratch;
	char package_name[BPM_MAX_NAME];
};

static int on_descriptor(void *ud)
{
	struct desc_sink *s = ud;
	if (s->n >= BPM_MAX_ENTRIES) return -E2BIG;
	s->items[s->n++] = s->scratch;
	memset(&s->scratch, 0, sizeof(s->scratch));
	return 0;
}

static int parse_manifest(const unsigned char *body, size_t len,
			  struct bpm_descriptor *layers, int *n_layers,
			  char *package_name, size_t package_name_sz)
{
	struct desc_sink sink = { .items = layers };
	struct shirudo_json_array arr = { on_descriptor, &sink };
	struct shirudo_json_field layer_annotations[1], manifest_annotations[1];
	struct shirudo_json_field sub[4], root[3];
	int64_t schema = 0;

	memset(sub, 0, sizeof(sub));
	sub[0] = (struct shirudo_json_field){ .key = "mediaType", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.media, .dst_cap = sizeof(sink.scratch.media) };
	sub[1] = (struct shirudo_json_field){ .key = "digest", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.digest, .dst_cap = sizeof(sink.scratch.digest) };
	sub[2] = (struct shirudo_json_field){ .key = "size", .type = SHIRUDO_JSON_T_INT,
		.dst = &sink.scratch.size };
	layer_annotations[0] = (struct shirudo_json_field){
		.key = "org.opencontainers.image.title", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.scratch.title, .dst_cap = sizeof(sink.scratch.title) };
	sub[3] = (struct shirudo_json_field){ .key = "annotations", .type = SHIRUDO_JSON_T_OBJECT,
		.sub = layer_annotations, .n_sub = ARRAY_SIZE(layer_annotations) };
	manifest_annotations[0] = (struct shirudo_json_field){
		.key = "dev.shirudo.bpm.package.name", .type = SHIRUDO_JSON_T_STRING,
		.dst = sink.package_name, .dst_cap = sizeof(sink.package_name) };
	memset(root, 0, sizeof(root));
	root[0] = (struct shirudo_json_field){ .key = "schemaVersion", .type = SHIRUDO_JSON_T_INT,
		.dst = &schema };
	root[1] = (struct shirudo_json_field){ .key = "layers", .type = SHIRUDO_JSON_T_ARRAY,
		.dst = &arr, .sub = sub, .n_sub = ARRAY_SIZE(sub) };
	root[2] = (struct shirudo_json_field){ .key = "annotations", .type = SHIRUDO_JSON_T_OBJECT,
		.sub = manifest_annotations, .n_sub = ARRAY_SIZE(manifest_annotations) };
	if (shirudo_json_parse((const char *)body, len, root, ARRAY_SIZE(root)) ||
	    !root[0].seen || schema != 2 || !root[1].seen)
		return -EINVAL;
	*n_layers = sink.n;
	if (package_name && package_name_sz)
		bpm_copy_string(package_name, package_name_sz, sink.package_name);
	return 0;
}

static bool bpm_package_name_ok(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	if (!s || !isalnum((unsigned char)*p))
		return false;
	for (; *p; p++)
		if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-'))
			return false;
	return strlen(s) < BPM_MAX_NAME;
}

static void trim_string(const char *in, char *out, size_t out_sz);

static int parse_pull_ref(const char *raw, struct bpm_oci_client *c,
			  char *repository, size_t repository_sz,
			  char *tag, size_t tag_sz)
{
	const char *p, *slash, *colon, *last_slash;
	char endpoint[BPM_MAX_ENDPOINT];
	char normalized[PATH_MAX];

	if (!raw || strlen(raw) >= sizeof(normalized))
		return -EINVAL;
	trim_string(raw, normalized, sizeof(normalized));
	if (strncmp(normalized, "oci://", 6))
		return -EINVAL;
	p = normalized + 6;
	if (!*p || strchr(p, '@') || strchr(p, '?') || strchr(p, '#'))
		return -EINVAL;
	slash = strchr(p, '/');
	if (!slash || slash == p)
		return -EINVAL;
	last_slash = strrchr(p, '/');
	colon = strrchr(p, ':');
	if (!colon || colon <= last_slash || colon == last_slash + 1 || !colon[1])
		return -EINVAL;
	if ((size_t)(slash - p) >= sizeof(endpoint) - 6 ||
	    (size_t)(colon - slash - 1) >= repository_sz ||
	    strlen(colon + 1) >= tag_sz)
		return -ENAMETOOLONG;
	memcpy(endpoint, "oci://", 6);
	memcpy(endpoint + 6, p, slash - p);
	endpoint[6 + (slash - p)] = '\0';
	memcpy(repository, slash + 1, colon - slash - 1);
	repository[colon - slash - 1] = '\0';
	bpm_copy_string(tag, tag_sz, colon + 1);
	if (strstr(repository, "//") || strchr(repository, '?') ||
	    strchr(repository, '#') || strchr(repository, ':'))
		return -EINVAL;
	for (const char *part = repository; *part;) {
		const char *end = strchr(part, '/');
		if (!end) end = part + strlen(part);
		if (end == part || (end - part == 2 && !strncmp(part, "..", 2)))
			return -EINVAL;
		part = *end ? end + 1 : end;
	}
	if (!bpm_package_name_ok(strrchr(repository, '/') ?
				 strrchr(repository, '/') + 1 : repository) ||
	    !bpm_version_ok(tag) || !isalnum((unsigned char)tag[0]))
		return -EINVAL;
	return parse_endpoint(endpoint, c);
}

static int parse_push_repo(const char *raw, struct bpm_oci_client *c,
			   char *repository, size_t repository_sz)
{
	char normalized[PATH_MAX], endpoint[BPM_MAX_ENDPOINT];
	const char *p, *slash;

	if (!raw || strlen(raw) >= sizeof(normalized))
		return -EINVAL;
	trim_string(raw, normalized, sizeof(normalized));
	if (strncmp(normalized, "oci://", 6))
		return -EINVAL;
	p = normalized + 6;
	slash = strchr(p, '/');
	if (!*p || !slash || slash == p || !slash[1] || strchr(p, '@') ||
	    strchr(p, '?') || strchr(p, '#'))
		return -EINVAL;
	if ((size_t)(slash - p) >= sizeof(endpoint) - 6 ||
	    strlen(slash + 1) >= repository_sz)
		return -ENAMETOOLONG;
	memcpy(endpoint, "oci://", 6);
	memcpy(endpoint + 6, p, slash - p);
	endpoint[6 + (slash - p)] = '\0';
	bpm_copy_string(repository, repository_sz, slash + 1);
	if (strchr(repository, ':') || strstr(repository, "//") ||
	    strstr(repository, ".."))
		return -EINVAL;
	for (const char *part = repository; *part;) {
		const char *end = strchr(part, '/');
		if (!end)
			end = part + strlen(part);
		if (end == part || (end - part == 1 && part[0] == '.') ||
		    (end - part == 2 && !strncmp(part, "..", 2)))
			return -EINVAL;
		part = *end ? end + 1 : end;
	}
	if (!bpm_package_name_ok(strrchr(repository, '/') ?
				 strrchr(repository, '/') + 1 : repository))
		return -EINVAL;
	return parse_endpoint(endpoint, c);
}

static int make_oci_url(const struct bpm_oci_client *c, const char *repo,
			const char *kind, const char *ref, char *out, size_t sz);

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

	rc = parse_pull_ref(raw, &c, repository, sizeof(repository), tag,
			    sizeof(tag));
	if (rc)
		return rc;
	if ((rc = make_oci_url(&c, repository, "manifests", tag, url,
				       sizeof(url))))
		return rc;
	if ((rc = oci_get_memory(&c, url,
				 "application/vnd.oci.image.manifest.v1+json",
				 &manifest)))
		goto out;
	if ((rc = parse_manifest(manifest.data, manifest.len, layers, &n_layers,
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
	free(manifest.data);
	return rc;
}

static int sha256_file_hex(const char *path, char *hex, size_t hex_sz);
static bool digest_matches(const char *want, const char *hex);

static void trim_string(const char *in, char *out, size_t out_sz)
{
	const char *start = in, *end;

	while (*start && isspace((unsigned char)*start))
		start++;
	end = start + strlen(start);
	while (end > start && isspace((unsigned char)end[-1]))
		end--;
	if ((size_t)(end - start) >= out_sz)
		end = start + out_sz - 1;
	memmove(out, start, end - start);
	out[end - start] = '\0';
}

static int pull_package(const char *raw)
{
	struct bpm_oci_client c = {};
	struct bpm_descriptor layers[8];
	struct bpm_buffer manifest = {};
	char repository[BPM_MAX_ENDPOINT], tag[BPM_MAX_NAME];
	char url[PATH_MAX], filename[PATH_MAX], title[PATH_MAX];
	char digest[65], package_name[BPM_MAX_NAME] = {};
	int n_layers = 0, rc;

	rc = parse_pull_ref(raw, &c, repository, sizeof(repository),
			    tag, sizeof(tag));
	if (rc)
		return rc;
	if ((rc = make_oci_url(&c, repository, "manifests", tag,
			       url, sizeof(url))))
		return rc;
	if ((rc = oci_get_memory(&c, url, "application/vnd.oci.image.manifest.v1+json",
				 &manifest)))
		goto out;
	if ((rc = parse_manifest(manifest.data, manifest.len, layers, &n_layers,
				 package_name, sizeof(package_name))))
		goto out;
	trim_string(package_name, package_name, sizeof(package_name));
	for (int i = 0; i < n_layers; i++) {
		if (strcmp(layers[i].media, BPM_PACKAGE_MEDIA))
			continue;
		if ((rc = make_oci_url(&c, repository, "blobs", layers[i].digest,
				       url, sizeof(url))))
			goto out;
		trim_string(layers[i].title, title, sizeof(title));
		if (title[0] && !strchr(title, '/') &&
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
		rc = oci_get_file(&c, url, BPM_PACKAGE_MEDIA, filename);
		if (rc)
			goto out;
		if (sha256_file_hex(filename, digest, sizeof(digest)) ||
		    !digest_matches(layers[i].digest, digest)) {
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
	free(manifest.data);
	return rc;
}

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

static int parse_index(const unsigned char *body, size_t len,
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

static int verify_cms(const unsigned char *payload, size_t payload_len,
		      const unsigned char *sig, size_t sig_len, const char *cert_path)
{
	struct shirudo_cert cert = {};
	int rc = -EINVAL;

	if (!shirudo_cert_read_file(cert_path, &cert))
		rc = shirudo_verify_detached(payload, payload_len, sig, sig_len, &cert);
	shirudo_cert_free(&cert);
	return rc;
}

static int copy_file(const char *src, const char *dst, mode_t mode)
{
	unsigned char buf[65536];
	ssize_t n;
	int in, out, rc = 0;

	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0) return -errno;
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
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
	{ int rc = path_mkdir_p(SHIRUDO_LOCKS_DIR, 0700); if (rc) return rc; }
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

static int make_oci_url(const struct bpm_oci_client *c, const char *repo,
			const char *kind, const char *ref, char *out, size_t sz)
{
	if (strstr(repo, "..") || strstr(repo, "//") || strchr(repo, '?') || strchr(repo, '#') ||
	    strstr(ref, "..") || strchr(ref, '/') || strchr(ref, '?') || strchr(ref, '#')) return -EINVAL;
	if (snprintf(out, sz, "%s/v2/%s/%s/%s", c->base_url, repo, kind, ref) >= (int)sz) return -ENAMETOOLONG;
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

static int sha256_buffer_hex(const void *data, size_t len,
			     char *hex, size_t hex_sz)
{
	unsigned char digest[SHIRUDO_CRYPTO_SHA256_LEN];
	if (hex_sz < 65 || shirudo_sha256_buffer(data, len, digest) != 0)
		return -EINVAL;
	for (unsigned int i = 0; i < sizeof(digest); i++)
		snprintf(hex + i * 2, 3, "%02x", digest[i]);
	hex[64] = 0;
	return 0;
}

static bool digest_matches(const char *want, const char *hex)
{
	return want && !strncmp(want, "sha256:", 7) &&
		!strcasecmp(want + 7, hex);
}

static int upload_location(const struct bpm_oci_client *c, const char *location,
			   char *out, size_t out_sz)
{
	size_t base_len = strlen(c->base_url);

	if (!location || !*location)
		return -EINVAL;
	if (location[0] == '/') {
		if (snprintf(out, out_sz, "%s%s", c->base_url, location) >=
		    (int)out_sz)
			return -ENAMETOOLONG;
		return 0;
	}
	if (strncmp(location, c->base_url, base_len) ||
	    location[base_len] != '/')
		return -EPERM;
	if (strlen(location) >= out_sz)
		return -ENAMETOOLONG;
	bpm_copy_string(out, out_sz, location);
	return 0;
}

static int oci_push_blob(struct bpm_oci_client *c, const char *repository,
			 const void *body, size_t body_len, const char *media,
			 struct bpm_descriptor *out)
{
	struct bpm_http_response r = {};
	char hex[65], digest[72], url[PATH_MAX], upload[PATH_MAX];
	char location[PATH_MAX], *sep;
	int rc;

	if (sha256_buffer_hex(body, body_len, hex, sizeof(hex)))
		return -EINVAL;
	if (snprintf(digest, sizeof(digest), "sha256:%s", hex) >=
	    (int)sizeof(digest))
		return -ENAMETOOLONG;
	if ((rc = make_oci_url(c, repository, "blobs", digest, url,
				       sizeof(url))))
		return rc;
	rc = oci_request(c, "HEAD", url, NULL, NULL, NULL, 0, &r);
	free(r.body.data);
	if (!rc) {
		bpm_copy_string(out->media, sizeof(out->media), media);
		bpm_copy_string(out->digest, sizeof(out->digest), digest);
		out->size = (int64_t)body_len;
		return 0;
	}
	if (rc != -ENOENT)
		return rc;

	if ((rc = make_oci_url(c, repository, "blobs/uploads", "", url,
				       sizeof(url))))
		return rc;
	rc = oci_request(c, "POST", url, NULL, NULL, NULL, 0, &r);
	if (rc)
		goto out;
	if (r.status != 202 || !r.location[0]) {
		rc = r.status == 202 ? -EINVAL : -EACCES;
		goto out;
	}
	bpm_copy_string(location, sizeof(location), r.location);
	free(r.body.data);
	r = (struct bpm_http_response){};
	if ((rc = upload_location(c, location, upload, sizeof(upload))))
		goto out;
	sep = strchr(upload, '?') ? "&" : "?";
	if (snprintf(url, sizeof(url), "%s%sdigest=%s", upload, sep, digest) >=
	    (int)sizeof(url)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	rc = oci_request(c, "PUT", url, NULL, "application/octet-stream",
			 body, body_len, &r);
	if (!rc && r.status != 201)
		rc = -EACCES;
	if (!rc) {
		bpm_copy_string(out->media, sizeof(out->media), media);
		bpm_copy_string(out->digest, sizeof(out->digest), digest);
		out->size = (int64_t)body_len;
	}
out:
	free(r.body.data);
	return rc;
}

static int tar_octal(const char *p, size_t n, uint64_t *out)
{
	uint64_t v = 0; size_t i = 0;
	while (i < n && (p[i] == ' ' || p[i] == '\0')) i++;
	for (; i < n && p[i] >= '0' && p[i] <= '7'; i++) {
		if (v > (UINT64_MAX >> 3)) return -EOVERFLOW;
		v = (v << 3) | (unsigned)(p[i] - '0');
	}
	*out = v; return 0;
}

static bool safe_archive_rel(const char *name)
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

	if (!safe_archive_rel(name) || !member)
		return false;
	slash = strchr(name, '/');
	return slash && slash != name && strncmp(name, "./", 2) &&
		!strchr(slash + 1, '/') &&
		!strcmp(slash + 1, member);
}

static int read_package_member(const char *archive, const char *member,
			       unsigned char **out, size_t *out_len, size_t max)
{
	gzFile gz = gzopen(archive, "rb");
	unsigned char h[512];
	int rc = -ENOENT;

	if (!gz)
		return -errno;
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
		if (!memchr(h, '\0', 100) || tar_octal((char *)h + 124, 12, &size)) {
			rc = -EINVAL;
			break;
		}
		remain = size;
		if (package_member_name_ok(name, member)) {
			unsigned char *body;
			if (size > max || size > SIZE_MAX - 1) {
				rc = -E2BIG;
				break;
			}
			body = malloc((size_t)size + 1);
			if (!body) {
				rc = -ENOMEM;
				break;
			}
			while (remain) {
				size_t want = remain > 65536 ? 65536 : (size_t)remain;
				n = gzread(gz, body + size - remain, (unsigned)want);
				if (n <= 0) {
					free(body);
					rc = -EINVAL;
					goto done;
				}
				remain -= (size_t)n;
			}
			body[size] = '\0';
			*out = body;
			*out_len = (size_t)size;
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
		free(*out);
		*out = NULL;
		*out_len = 0;
		rc = -EINVAL;
	}
	return rc;
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
	if (!x) {
		BIO_reset(b);
		x = PEM_read_bio_X509(b, NULL, NULL, NULL);
	}
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
	der = malloc((size_t)der_len);
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
	free(der);
	return rc;
}

static int load_package_info(const char *archive, struct bpm_package_info *info)
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

	rc = read_package_member(archive, "build-environment.json", &environment,
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

	rc = read_package_member(archive, "cert.der", &info->cert, &info->cert_len,
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
		pr_err("bpm push: package signer fingerprint mismatch: "
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
	free(environment);
	if (rc) {
		free(info->cert);
		info->cert = NULL;
		info->cert_len = 0;
	}
	return rc;
}

static void emit_descriptor(struct shirudo_json_emit *e, const char *key,
			    const struct bpm_descriptor *d, const char *title)
{
	if (key)
		shirudo_json_obj_open_key(e, key);
	else
		shirudo_json_obj_open(e);
	shirudo_json_kv_string(e, "mediaType", d->media);
	shirudo_json_kv_string(e, "digest", d->digest);
	shirudo_json_kv_int(e, "size", d->size);
	if (title) {
		shirudo_json_obj_open_key(e, "annotations");
		shirudo_json_kv_string(e, "org.opencontainers.image.title", title);
		shirudo_json_obj_close(e);
	}
	shirudo_json_obj_close(e);
}

static int oci_put_manifest(struct bpm_oci_client *c, const char *repository,
			    const char *reference, const unsigned char *body,
			    size_t body_len, char *digest, size_t digest_sz)
{
	struct bpm_http_response r = {};
	char hex[65], url[PATH_MAX];
	int rc;

	if (sha256_buffer_hex(body, body_len, hex, sizeof(hex)) ||
	    snprintf(digest, digest_sz, "sha256:%s", hex) >= (int)digest_sz)
		return -ENAMETOOLONG;
	if ((rc = make_oci_url(c, repository, "manifests", reference, url,
				       sizeof(url))))
		return rc;
	rc = oci_request(c, "PUT", url, "application/vnd.oci.image.manifest.v1+json",
			 "application/vnd.oci.image.manifest.v1+json", body, body_len, &r);
	free(r.body.data);
	return rc;
}

static int push_package(const char *package_path, const char *raw_repository,
			const char **reference_out)
{
	struct bpm_oci_client c = {};
	struct bpm_package_info info = {};
	struct bpm_descriptor config, layer, key_config, key_layer, subject;
	struct shirudo_json_emit e = {};
	unsigned char *archive = NULL, *manifest = NULL;
	const char *base;
	char repository[BPM_MAX_ENDPOINT], package_digest[72], key_digest[72];
	char hex[65];
	char reference[PATH_MAX];
	char config_body[] = "{\"mediaType\":\"" BPM_CONFIG_MEDIA "\"}";
	char empty_config[] = "{}";
	char package_title[PATH_MAX];
	char *manifest_body;
	char *key_manifest_body = NULL;
	struct stat st;
	size_t archive_len, manifest_len, key_manifest_len;
	int rc;

	if (!package_path || !*package_path)
		return -EINVAL;
	if (stat(package_path, &st))
		return -errno;
	if (!S_ISREG(st.st_mode))
		return -EINVAL;
	if ((rc = read_small_file(package_path, &archive, &archive_len,
				  BPM_MAX_HTTP_BODY)))
		return rc;
	if ((rc = load_package_info(package_path, &info)))
		goto out;
	if ((rc = parse_push_repo(raw_repository, &c, repository,
					 sizeof(repository))))
		goto out;
	base = strrchr(package_path, '/');
	base = base ? base + 1 : package_path;
	if (!*base || strlen(base) >= sizeof(package_title)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	bpm_copy_string(package_title, sizeof(package_title), base);

	if ((rc = oci_push_blob(&c, repository, config_body,
				 strlen(config_body), BPM_CONFIG_MEDIA, &config)))
		goto out;
	if ((rc = oci_push_blob(&c, repository, archive, archive_len,
				 BPM_PACKAGE_MEDIA, &layer)))
		goto out;

	manifest_body = calloc(1, 8192);
	if (!manifest_body) {
		rc = -ENOMEM;
		goto out;
	}
	e.buf = manifest_body;
	e.cap = 8192;
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schemaVersion", 2);
	shirudo_json_kv_string(&e, "mediaType", "application/vnd.oci.image.manifest.v1+json");
	emit_descriptor(&e, "config", &config, NULL);
	shirudo_json_arr_open(&e, "layers");
	emit_descriptor(&e, NULL, &layer, package_title);
	shirudo_json_arr_close(&e);
	shirudo_json_obj_open_key(&e, "annotations");
	shirudo_json_kv_string(&e, "dev.shirudo.bpm.package.name", info.name);
	shirudo_json_kv_string(&e, "dev.shirudo.bpm.package.version", info.version);
	shirudo_json_kv_string(&e, "org.opencontainers.image.title", info.name);
	shirudo_json_kv_string(&e, "org.opencontainers.image.version", info.version);
	shirudo_json_obj_close(&e);
	shirudo_json_obj_close(&e);
	if (e.err) {
		free(manifest_body);
		rc = e.err;
		goto out;
	}
	manifest_len = e.len;
	manifest = (unsigned char *)manifest_body;
	if ((rc = oci_put_manifest(&c, repository, info.version, manifest,
				   manifest_len, package_digest, sizeof(package_digest))))
		goto out;

	/* Publish the package certificate as an OCI referrer, matching the
	 * artifact layout consumed by the Go BPM implementation. */
	if ((rc = oci_push_blob(&c, repository, empty_config, strlen(empty_config),
				 BPM_EMPTY_CONFIG_MEDIA, &key_config)))
		goto out;
	if ((rc = oci_push_blob(&c, repository, info.cert, info.cert_len,
				 BPM_PUBLIC_KEY_MEDIA, &key_layer)))
		goto out;
	subject = (struct bpm_descriptor){
		.media = "application/vnd.oci.image.manifest.v1+json",
	};
	bpm_copy_string(subject.digest, sizeof(subject.digest), package_digest);
	subject.size = (int64_t)manifest_len;
	key_manifest_body = calloc(1, 8192);
	if (!key_manifest_body) {
		rc = -ENOMEM;
		goto out;
	}
	e = (struct shirudo_json_emit){ .buf = key_manifest_body, .cap = 8192 };
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schemaVersion", 2);
	shirudo_json_kv_string(&e, "mediaType", "application/vnd.oci.image.manifest.v1+json");
	shirudo_json_kv_string(&e, "artifactType", BPM_PUBLIC_KEY_ARTIFACT);
	emit_descriptor(&e, "config", &key_config, NULL);
	shirudo_json_arr_open(&e, "layers");
	emit_descriptor(&e, NULL, &key_layer, NULL);
	shirudo_json_arr_close(&e);
	shirudo_json_obj_open_key(&e, "subject");
	shirudo_json_kv_string(&e, "mediaType", subject.media);
	shirudo_json_kv_string(&e, "digest", subject.digest);
	shirudo_json_kv_int(&e, "size", subject.size);
	shirudo_json_obj_close(&e);
	shirudo_json_obj_close(&e);
	if (e.err) {
		rc = e.err;
		goto out;
	}
	key_manifest_len = e.len;
	if (sha256_buffer_hex(key_manifest_body, key_manifest_len, hex,
			      sizeof(hex)) ||
	    snprintf(key_digest, sizeof(key_digest), "sha256:%s", hex) >=
		(int)sizeof(key_digest)) {
		rc = -EINVAL;
		goto out;
	}
	if ((rc = oci_put_manifest(&c, repository, key_digest,
				   (const unsigned char *)key_manifest_body,
				   key_manifest_len, key_digest, sizeof(key_digest))))
		goto out;
	if (snprintf(reference, sizeof(reference), "oci://%s/%s:%s",
		     c.registry, repository, info.version) >= (int)sizeof(reference)) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	*reference_out = strdup(reference);
	rc = *reference_out ? 0 : -ENOMEM;
out:
	free(key_manifest_body);
	free(manifest);
	free(info.cert);
	free(archive);
	return rc;
}

static int extract_archive(const char *archive, const char *dest)
{
	gzFile gz = gzopen(archive, "rb");
	unsigned char h[512];
	char root[256] = {};
	int rc = 0;

	if (!gz) return -EINVAL;
	if ((rc = path_mkdir_p(dest, 0700))) { gzclose(gz); return rc; }
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
		if (!safe_archive_rel(name) || tar_octal((char *)h + 124, 12, &size)) { rc = -EINVAL; break; }
		type = h[156]; if (!type) type = '0';
		if (!root[0]) {
			slash = strchr(name, '/'); if (!slash || slash == name || (size_t)(slash - name) >= sizeof(root)) { rc = -EINVAL; break; }
			memcpy(root, name, slash - name); root[slash - name] = 0;
		}
		if (strncmp(name, root, strlen(root)) || name[strlen(root)] != '/') { rc = -EINVAL; break; }
		snprintf(rel, sizeof(rel), "%s", name + strlen(root) + 1);
		if ((!*rel && type != '5') || (*rel && !safe_archive_rel(rel))) { rc = -EINVAL; break; }
		if (snprintf(path, sizeof(path), "%s/%s", dest, rel) >= (int)sizeof(path)) { rc = -ENAMETOOLONG; break; }
		if (type == '5') {
			if ((rc = path_mkdir_p(path, 0700))) break;
		} else if (type == '0') {
			char parent[PATH_MAX];
			FILE *fp;
			snprintf(parent, sizeof(parent), "%s", path);
			slash = strrchr(parent, '/'); if (slash) { *slash = 0; if ((rc = path_mkdir_p(parent, 0700))) break; }
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

static int install_key_file(const char *src)
{
	struct shirudo_cert x = {};
	unsigned char digest[SHIRUDO_CRYPTO_SHA256_LEN];
	char hex[65], dst[PATH_MAX], linktmp[PATH_MAX];
	struct stat st;
	int rc;
	if (shirudo_cert_read_file(src, &x) || shirudo_cert_pubkey_digest(&x, digest)) { shirudo_cert_free(&x); return -EINVAL; }
	for (unsigned int i = 0; i < sizeof(digest); i++)
		snprintf(hex + 2*i, 3, "%02x", digest[i]);
	hex[64] = 0;
	shirudo_cert_free(&x);
	rc = path_mkdir_p(SHIRUDO_KEYS_DIR, 0700); if (rc) return rc;
	if (snprintf(dst, sizeof(dst), "%s/%s.der", SHIRUDO_KEYS_DIR, hex) >= (int)sizeof(dst)) return -ENAMETOOLONG;
	if (copy_file(src, dst, 0644)) return -EIO;
	if (stat(SHIRUDO_CERT_PATH, &st) == 0) {
		if (cert_matches_active(dst) == 0) { unlink(dst); return 0; }
		unlink(dst);
		return -EPERM;
	}
	snprintf(linktmp, sizeof(linktmp), "%s.tmp.%ld", SHIRUDO_CERT_PATH, (long)getpid());
	unlink(linktmp);
	if (symlink(dst, linktmp) || rename(linktmp, SHIRUDO_CERT_PATH)) { unlink(linktmp); return -errno; }
	return 0;
}

static int extract_package_cert(const char *archive, char *out, size_t out_sz)
{
	gzFile gz = gzopen(archive, "rb");
	unsigned char h[512]; int fd = -1, rc = -ENOENT;
	char tmp[] = "/tmp/shirudo-bpm-cert-XXXXXX";
	if (!gz) return -errno;
	for (;;) {
		int n = gzread(gz, h, sizeof(h)); uint64_t size, remain, pad;
		char name[PATH_MAX]; int type;
		if (n == 0) break;
		if (n != (int)sizeof(h)) { rc = -EINVAL; break; }
		bool zero = true; for (size_t i = 0; i < sizeof(h); i++) if (h[i]) { zero = false; break; }
		if (zero) break;
		snprintf(name, sizeof(name), "%s", (char *)h);
		if (tar_octal((char *)h + 124, 12, &size)) { rc = -EINVAL; break; }
		type = h[156] ? h[156] : '0';
		if (type == '0' && !strcmp(strrchr(name, '/') ? strrchr(name, '/') + 1 : name, "cert.der")) {
			fd = mkstemp(tmp); if (fd < 0) { rc = -errno; break; }
			remain = size;
			while (remain) { unsigned char buf[65536]; size_t want = remain > sizeof(buf) ? sizeof(buf) : (size_t)remain; n = gzread(gz, buf, (unsigned)want); if (n <= 0) { rc = -EIO; break; } rc = shirudo_write_all(fd, buf, (size_t)n); if (rc) break; remain -= (size_t)n; }
			if (!rc) { close(fd); fd = -1; if (strlen(tmp) >= out_sz) rc = -ENAMETOOLONG; else { snprintf(out, out_sz, "%s", tmp); rc = 0; } }
			if (rc) { close(fd); fd = -1; unlink(tmp); }
			if (!rc) break;
		} else {
			remain = size; while (remain) { unsigned char buf[65536]; size_t want = remain > sizeof(buf) ? sizeof(buf) : (size_t)remain; n = gzread(gz, buf, (unsigned)want); if (n <= 0) { rc = -EINVAL; break; } remain -= (size_t)n; }
		}
		pad = (512 - (size % 512)) % 512; while (pad) { unsigned char buf[512]; size_t want = pad > sizeof(buf) ? sizeof(buf) : (size_t)pad; n = gzread(gz, buf, (unsigned)want); if (n <= 0) { rc = -EINVAL; break; } pad -= (size_t)n; }
		if (rc < 0 && rc != -ENOENT) break;
	}
	if (fd >= 0)
		close(fd);
	if (gzclose(gz) != Z_OK && rc == 0) {
		unlink(out);
		rc = -EINVAL;
	}
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

	rc = read_small_file(SHIRUDO_BPM_STATE_PATH, &body, &len, 8u * 1024u * 1024u);
	if (rc == -ENOENT) { *n = 0; return 0; }
	if (rc) return rc;
	sub[0] = (struct shirudo_json_field){ .key = "name", .type = SHIRUDO_JSON_T_STRING, .dst = sink.scratch.name, .dst_cap = sizeof(sink.scratch.name) };
	sub[1] = (struct shirudo_json_field){ .key = "version", .type = SHIRUDO_JSON_T_STRING, .dst = sink.scratch.version, .dst_cap = sizeof(sink.scratch.version) };
	sub[2] = (struct shirudo_json_field){ .key = "source", .type = SHIRUDO_JSON_T_STRING, .dst = sink.scratch.source, .dst_cap = sizeof(sink.scratch.source) };
	sub[3] = (struct shirudo_json_field){ .key = "path", .type = SHIRUDO_JSON_T_STRING, .dst = sink.scratch.path, .dst_cap = sizeof(sink.scratch.path) };
	root[0] = (struct shirudo_json_field){ .key = "packages", .type = SHIRUDO_JSON_T_ARRAY, .dst = &arr, .sub = sub, .n_sub = ARRAY_SIZE(sub) };
	(void)unused;
	rc = shirudo_json_parse((const char *)body, len, root, ARRAY_SIZE(root));
	free(body);
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
	rc = path_mkdir_p(SHIRUDO_BPM_VAR_DIR, 0700);
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
	rc = read_small_file(path, &body, &len, 64u * 1024u * 1024u);
	if (rc)
		return rc;
	rc = parse_index(body, len, entries, n);
	free(body);
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
	if ((rc = parse_endpoint(s.endpoint, &c))) return rc;
	if ((rc = make_oci_url(&c, BPM_INDEX_REPOSITORY, "manifests", BPM_INDEX_TAG, url, sizeof(url)))) return rc;
	rc = oci_get_memory(&c, url, "application/vnd.oci.image.manifest.v1+json", &manifest); if (rc) goto out;
	if ((rc = parse_manifest(manifest.data, manifest.len, layers, &nl,
				 NULL, 0)) || nl < 2) goto out;
	for (int i = 0; i < nl; i++) {
		if (!strcmp(layers[i].media, BPM_INDEX_MEDIA)) {
			char layer_hex[65];
			if ((rc = make_oci_url(&c, BPM_INDEX_REPOSITORY, "blobs", layers[i].digest, url, sizeof(url)))) goto out;
			rc = oci_get_memory(&c, url, BPM_INDEX_MEDIA, &index);
			if (!rc && (sha256_buffer_hex(index.data, index.len, layer_hex, sizeof(layer_hex)) ||
				    !digest_matches(layers[i].digest, layer_hex)))
				rc = -EKEYREJECTED;
			break;
		}
	}
	if (rc) goto out;
	for (int i = 0; i < nl; i++) if (!strcmp(layers[i].media, BPM_INDEX_SIG_MEDIA)) {
			char sig_hex[65];
			if ((rc = make_oci_url(&c, BPM_INDEX_REPOSITORY, "blobs", layers[i].digest, url, sizeof(url)))) goto out;
			rc = oci_get_memory(&c, url, BPM_INDEX_SIG_MEDIA, &sig);
			if (!rc && (sha256_buffer_hex(sig.data, sig.len, sig_hex, sizeof(sig_hex)) ||
				    !digest_matches(layers[i].digest, sig_hex)))
				rc = -EKEYREJECTED;
			break;
	}
	if (rc || !sig.data) { rc = -EINVAL; goto out; }
	if (verify_cms(index.data, index.len, sig.data, sig.len, s.key_file)) { rc = -EKEYREJECTED; goto out; }
	{
		struct bpm_index_entry checked[BPM_MAX_ENTRIES];
		int checked_n = 0;
		if (parse_index(index.data, index.len, checked, &checked_n)) { rc = -EINVAL; goto out; }
	}
	if (snprintf(dir, sizeof(dir), "%s/%s", SHIRUDO_BPM_REPOS_DIR, name) >= (int)sizeof(dir)) { rc = -ENAMETOOLONG; goto out; }
	if ((rc = path_mkdir_p(dir, 0700))) goto out;
	if ((rc = cache_path(name, cache, sizeof(cache)))) goto out;
	rc = atomic_write(cache, index.data, index.len, 0600);
out:
	free(manifest.data); free(index.data); free(sig.data); return rc;
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
	if ((rc = parse_endpoint(s->endpoint, &c))) return rc;
	if ((rc = make_oci_url(&c, entry->repository[0] ? entry->repository : entry->name, "manifests", entry->manifest_digest, url, sizeof(url)))) return rc;
	if ((rc = oci_get_memory(&c, url, "application/vnd.oci.image.manifest.v1+json", &manifest))) goto out;
	/* Repository indexes carry a sha256 manifest digest; direct OCI
	 * references carry the tag in this field and cannot be digest-checked. */
	if (!strncmp(entry->manifest_digest, "sha256:", 7)) {
		char manifest_hex[65];
		if (sha256_buffer_hex(manifest.data, manifest.len, manifest_hex, sizeof(manifest_hex)) ||
		    !digest_matches(entry->manifest_digest, manifest_hex)) {
			rc = -EKEYREJECTED;
			goto out;
		}
	}
	if ((rc = parse_manifest(manifest.data, manifest.len, layers, &nl,
				 NULL, 0))) goto out;
	for (int i = 0; i < nl; i++) if (!strcmp(layers[i].media, BPM_PACKAGE_MEDIA)) {
		found_package = true;
		if (entry->package_digest[0] && strcmp(entry->package_digest, layers[i].digest)) { rc = -EKEYREJECTED; goto out; }
		if (entry->package_size > 0 && entry->package_size != layers[i].size) { rc = -EKEYREJECTED; goto out; }
		if ((rc = make_oci_url(&c, entry->repository[0] ? entry->repository : entry->name, "blobs", layers[i].digest, url, sizeof(url)))) goto out;
		if (snprintf(dir, sizeof(dir), "%s/%s", SHIRUDO_BPM_PACKAGES_DIR, entry->name) >= (int)sizeof(dir)) { rc = -ENAMETOOLONG; goto out; }
		if ((rc = path_mkdir_p(dir, 0700))) goto out;
		if (snprintf(package_dir, sizeof(package_dir), "%s/%s", dir, entry->version) >= (int)sizeof(package_dir)) { rc = -ENAMETOOLONG; goto out; }
		if ((rc = path_mkdir_p(SHIRUDO_BPM_STAGING_DIR, 0700))) goto out;
		if (snprintf(archive, sizeof(archive), "%s/%s-%s.bee", SHIRUDO_BPM_STAGING_DIR, entry->name, entry->version) >= (int)sizeof(archive)) { rc = -ENAMETOOLONG; goto out; }
		rc = oci_get_file(&c, url, BPM_PACKAGE_MEDIA, archive); if (rc) goto out;
	if (sha256_file_hex(archive, digest, sizeof(digest)) || !digest_matches(layers[i].digest, digest)) { rc = -EKEYREJECTED; goto out; }
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
	free(manifest.data);
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
		if (!bpm_name_ok(s.name) || parse_endpoint(s.endpoint, &(struct bpm_oci_client){}) ) { shirudo_cert_free(&cert); pr_err("bpm: register add requires a valid oci:// endpoint and --key-file certificate"); return 2; }
		shirudo_cert_free(&cert);
		if (path_mkdir_p(SHIRUDO_BPM_REGISTRIES_DIR, 0700) || path_mkdir_p(SHIRUDO_BPM_KEYS_DIR, 0700)) return 1;
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
		trim_string(line, key, sizeof(key));
		trim_string(eq, value, sizeof(value));
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
	return parse_endpoint(endpoint, c);
}

static int tree_digest_hex(const char *digest, uint8_t out[32])
{
	if (!digest || strncmp(digest, "sha256:", 7))
		return -EINVAL;
	return shirudo_hex_decode(digest + 7, out, 32);
}

static int tree_selector_kv_compare(const void *left, const void *right)
{
	const struct shirudo_tree_selector_kv *a =
		*(const struct shirudo_tree_selector_kv * const *)left;
	const struct shirudo_tree_selector_kv *b =
		*(const struct shirudo_tree_selector_kv * const *)right;
	return strcmp(a->key, b->key);
}

/* This is the canonical operation representation used by the publishers.
 * Selector object keys are emitted lexicographically, as in Jbrust's
 * serde_json representation, before a target trusts an operation digest. */
static int tree_operation_digest(const struct shirudo_tree_operation *op,
					 char out[72])
{
	char *body, hex[65];
	size_t body_cap = 1024u * 1024u;
	struct shirudo_json_emit e;
	const struct shirudo_tree_selector_kv *kconfig[SHIRUDO_TREE_MAX_KCONFIG];
	const struct shirudo_tree_selector_kv *labels[SHIRUDO_TREE_MAX_LABELS];
	uint8_t digest[32];

	body = malloc(body_cap);
	if (!body)
		return -ENOMEM;
	e = (struct shirudo_json_emit){ .buf = body, .cap = body_cap };

	if (op->selector.n_kconfig > (int)ARRAY_SIZE(kconfig) ||
	    op->selector.n_labels > (int)ARRAY_SIZE(labels)) {
		free(body);
		return -E2BIG;
	}
	for (int i = 0; i < op->selector.n_kconfig; i++)
		kconfig[i] = &op->selector.kconfig[i];
	for (int i = 0; i < op->selector.n_labels; i++)
		labels[i] = &op->selector.labels[i];
	qsort(kconfig, op->selector.n_kconfig, sizeof(kconfig[0]),
	      tree_selector_kv_compare);
	qsort(labels, op->selector.n_labels, sizeof(labels[0]),
	      tree_selector_kv_compare);

	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "seq", op->seq);
	shirudo_json_kv_string(&e, "op", op->op);
	shirudo_json_kv_string(&e, "id", op->id);
	shirudo_json_obj_open_key(&e, "selector");
	if (op->selector.n_architecture) {
		shirudo_json_arr_open(&e, "architecture");
		for (int i = 0; i < op->selector.n_architecture; i++)
			shirudo_json_str(&e, op->selector.architecture[i]);
		shirudo_json_arr_close(&e);
	}
	if (op->selector.n_kconfig) {
		shirudo_json_obj_open_key(&e, "kconfig");
		for (int i = 0; i < op->selector.n_kconfig; i++) {
			shirudo_json_arr_open(&e, kconfig[i]->key);
			for (int j = 0; j < kconfig[i]->n_values; j++)
				shirudo_json_str(&e, kconfig[i]->values[j]);
			shirudo_json_arr_close(&e);
		}
		shirudo_json_obj_close(&e);
	}
	if (op->selector.n_kernel_build_id) {
		shirudo_json_arr_open(&e, "kernel_build_id");
		for (int i = 0; i < op->selector.n_kernel_build_id; i++)
			shirudo_json_str(&e, op->selector.kernel_build_id[i]);
		shirudo_json_arr_close(&e);
	}
	if (op->selector.n_kernel_release_prefix) {
		shirudo_json_arr_open(&e, "kernel_release_prefix");
		for (int i = 0; i < op->selector.n_kernel_release_prefix; i++)
			shirudo_json_str(&e, op->selector.kernel_release_prefix[i]);
		shirudo_json_arr_close(&e);
	}
	if (op->selector.n_labels) {
		shirudo_json_obj_open_key(&e, "labels");
		for (int i = 0; i < op->selector.n_labels; i++) {
			shirudo_json_arr_open(&e, labels[i]->key);
			for (int j = 0; j < labels[i]->n_values; j++)
				shirudo_json_str(&e, labels[i]->values[j]);
			shirudo_json_arr_close(&e);
		}
		shirudo_json_obj_close(&e);
	}
	shirudo_json_obj_close(&e);
	shirudo_json_obj_open_key(&e, "artifact");
	shirudo_json_kv_string(&e, "repository", op->artifact.repository);
	shirudo_json_kv_string(&e, "manifest_digest", op->artifact.manifest_digest);
	shirudo_json_kv_string(&e, "layer_digest", op->artifact.layer_digest);
	shirudo_json_kv_string(&e, "payload_sha256", op->artifact.payload_sha256);
	shirudo_json_obj_close(&e);
	shirudo_json_obj_close(&e);
	if (e.err)
		goto out;
	shirudo_sha256(body, e.len, digest);
	shirudo_hex_encode(digest, sizeof(digest), hex);
	memcpy(out, "sha256:", 7);
	memcpy(out + 7, hex, sizeof(hex));
	free(body);
	return 0;

out:
	free(body);
	return e.err;
}

static int tree_fetch_publication(const struct bpm_tree_config *cfg,
					 struct shirudo_tree_publication *pub,
					 char *manifest_digest, size_t digest_sz)
{
	struct bpm_oci_client c = {};
	struct bpm_descriptor layers[BPM_MAX_ENTRIES];
	struct bpm_buffer manifest = {}, payload = {}, sig = {};
	char repository[BPM_MAX_ENDPOINT], url[PATH_MAX], hex[65];
	int nl = 0, payload_layers = 0, sig_layers = 0;
	int rc = parse_tree_repository(cfg->endpoint, &c,
						 repository, sizeof(repository));
	if (rc)
		return rc;
	if (strchr(cfg->reference, '/') || strchr(cfg->reference, '?') ||
	    strchr(cfg->reference, '#') || strstr(cfg->reference, ".."))
		return -EINVAL;
	rc = make_oci_url(&c, repository, "manifests", cfg->reference,
				  url, sizeof(url));
	if (rc)
		return rc;
	rc = oci_get_memory(&c, url,
				"application/vnd.oci.image.manifest.v1+json", &manifest);
	if (rc)
		goto out;
	if (sha256_buffer_hex(manifest.data, manifest.len, hex, sizeof(hex))) {
		rc = -EKEYREJECTED;
		goto out;
	}
	if (snprintf(manifest_digest, digest_sz, "sha256:%s", hex) >=
	    (int)digest_sz) {
		rc = -ENAMETOOLONG;
		goto out;
	}
	if ((rc = parse_manifest(manifest.data, manifest.len, layers, &nl,
				 NULL, 0)))
		goto out;
	for (int i = 0; i < nl; i++) {
		if (!strcmp(layers[i].media, BPM_TREE_MEDIA)) {
			if (++payload_layers > 1) {
				rc = -EINVAL;
				goto out;
			}
			if ((rc = make_oci_url(&c, repository, "blobs", layers[i].digest,
					       url, sizeof(url))))
				goto out;
			if ((rc = oci_get_memory(&c, url, BPM_TREE_MEDIA, &payload)))
				goto out;
			if ((layers[i].size >= 0 && (int64_t)payload.len != layers[i].size) ||
			    sha256_buffer_hex(payload.data, payload.len, hex,
					       sizeof(hex)) ||
			    !digest_matches(layers[i].digest, hex)) {
				rc = -EKEYREJECTED;
				goto out;
			}
		}
		if (!strcmp(layers[i].media, BPM_TREE_SIG_MEDIA)) {
			if (++sig_layers > 1) {
				rc = -EINVAL;
				goto out;
			}
			if ((rc = make_oci_url(&c, repository, "blobs", layers[i].digest,
					       url, sizeof(url))))
				goto out;
			if ((rc = oci_get_memory(&c, url, BPM_TREE_SIG_MEDIA, &sig)))
				goto out;
			if ((layers[i].size >= 0 && (int64_t)sig.len != layers[i].size) ||
			    sha256_buffer_hex(sig.data, sig.len, hex, sizeof(hex)) ||
			    !digest_matches(layers[i].digest, hex)) {
				rc = -EKEYREJECTED;
				goto out;
			}
		}
	}
	if (payload_layers != 1 || sig_layers != 1 || !payload.data || !sig.data) {
		rc = -EINVAL;
		goto out;
	}
	if (verify_cms(payload.data, payload.len, sig.data, sig.len,
			       SHIRUDO_CERT_PATH)) {
		rc = -EKEYREJECTED;
		goto out;
	}
	rc = shirudo_tree_parse((const char *)payload.data, payload.len, pub);
	out:
	free(manifest.data);
	free(payload.data);
	free(sig.data);
	return rc;
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
	if (!digest_matches(expected, actual) ||
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
	rc = make_oci_url(&c, repository, "manifests",
				  op->artifact.manifest_digest, url, sizeof(url));
	if (rc)
		return rc;
	rc = oci_get_memory(&c, url,
				"application/vnd.oci.image.manifest.v1+json", &manifest);
	if (rc)
		goto out;
	if (sha256_buffer_hex(manifest.data, manifest.len, hex, sizeof(hex)) ||
	    !digest_matches(op->artifact.manifest_digest, hex)) {
		rc = -EKEYREJECTED;
		goto out;
	}
	rc = parse_manifest(manifest.data, manifest.len, layers, &nl, NULL, 0);
	if (rc)
		goto out;
	for (int i = 0; i < nl; i++) {
		if (strcmp(layers[i].digest, op->artifact.layer_digest) ||
		    strcmp(layers[i].media, BPM_UPATCH_MEDIA))
			continue;
		rc = make_oci_url(&c, repository, "blobs", layers[i].digest,
				   url, sizeof(url));
		if (rc)
			goto out;
		rc = oci_get_memory(&c, url, layers[i].media, &blob);
		if (rc)
			goto out;
		if (sha256_buffer_hex(blob.data, blob.len, hex, sizeof(hex)) ||
		    !digest_matches(layers[i].digest, hex) ||
		    (layers[i].size >= 0 && (int64_t)blob.len != layers[i].size))
			rc = -EKEYREJECTED;
		if (rc)
			goto out;
		if (path_mkdir_p(SHIRUDO_BPM_TREE_ARTIFACTS_DIR, 0700)) {
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
	free(manifest.data);
	free(blob.data);
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
	if (path_mkdir_p(SHIRUDO_BPM_TREE_VAR_DIR, 0700))
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
	rc = path_mkdir_p(SHIRUDO_BPM_TREE_STATUS_DIR, 0700);
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
	int rc = read_small_file(SHIRUDO_BPM_TREE_PENDING_PATH, &body, &len,
					 64u * 1024u);
	if (rc)
		return rc;
	rc = shirudo_json_parse((const char *)body, len, fields, ARRAY_SIZE(fields));
	if (!rc && (schema != 1 || pending->seq <= 0 ||
			!shirudo_upatch_name_valid(pending->id) ||
			tree_digest_hex(pending->operation_digest, (uint8_t[32]){})))
		rc = -EINVAL;
	free(body);
	return rc;
}

/* Complete the only non-idempotent window: the process may have extended
 * TPM and/or appended the event before the sealed cursor was committed. */
static int tree_recover_pending(const struct shirudo_tree_publication *pub,
					struct shirudo_tree_state *state)
{
	struct bpm_tree_pending pending = {};
	const struct shirudo_tree_operation *op = NULL;
	uint8_t digest[32], previous[32], next[32], live[32], replay[32];
	bool have_live = false, applied = false, event_present = false;
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

	rc = shirudo_tree_chain_read(live);
	if (!rc) {
		have_live = true;
		if (shirudo_ct_eq(live, next, sizeof(live)))
			applied = true;
		else if (!shirudo_ct_eq(live, previous, sizeof(live)))
			return -EKEYREJECTED;
	} else if (rc != -ENODEV) {
		return rc;
	}
	rc = shirudo_tree_event_replay(replay);
	if (!rc) {
		if (shirudo_ct_eq(replay, next, sizeof(replay))) {
			if (have_live && !shirudo_ct_eq(live, next, sizeof(live)))
				return -EKEYREJECTED;
			applied = true;
			event_present = true;
		} else if (!shirudo_ct_eq(replay, previous, sizeof(replay))) {
			return -EKEYREJECTED;
		}
	} else if (rc != -ENOENT) {
		return -EKEYREJECTED;
	}
	if (!applied)
		return 0; /* TPM/event state is still pre-operation; retry normally. */
	if (!event_present) {
		rc = shirudo_tree_event_append(op->seq, op->operation_digest, next);
		if (rc)
			return rc;
	}
	shirudo_hex_encode(next, sizeof(next), state->projection_root);
	if (have_live)
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
	if (tree_operation_digest(op, expected_digest))
		return -EINVAL;
	if (strcmp(op->operation_digest, expected_digest))
		return -EKEYREJECTED;
	if (op->expected_payload_sha256[0] &&
	    tree_digest_hex(op->expected_payload_sha256, digest))
		return -EINVAL;
	return 0;
}

static int tree_check_live_projection(const struct shirudo_tree_state *state)
{
	uint8_t live[32], replay[32], expected[32] = {};
	int rc;

	rc = shirudo_tree_chain_read(live);
	if (rc == -ENODEV)
		return 0;
	if (rc)
		return rc;
	if (state->last_seq) {
		if (shirudo_hex_decode(state->projection_root_tpm, expected, 32) ||
		    !shirudo_ct_eq(live, expected, 32))
			return -EKEYREJECTED;
	} else if (!shirudo_ct_eq(live, expected, 32)) {
		return -EKEYREJECTED;
	}
	rc = shirudo_tree_event_replay(replay);
	if (rc == 0 && !shirudo_ct_eq(live, replay, 32))
		return -EKEYREJECTED;
	if (rc == -ENOENT && state->last_seq)
		return -EKEYREJECTED;
	if (rc != 0 && rc != -ENOENT)
		return -EKEYREJECTED;
	return 1;
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
	rc = shirudo_tree_chain_ensure();
	if (rc == -ENODEV) {
		tpm_available = 0;
	} else if (rc) {
		tree_sync_report_error("tree_chain_ensure", NULL, rc);
		TREE_SYNC_RETURN(rc);
	} else {
		tpm_available = tree_check_live_projection(&state);
		if (tpm_available < 0) {
			tree_sync_report_error("tree_projection_check", NULL,
					       tpm_available);
			TREE_SYNC_RETURN(tpm_available);
		}
		if (tpm_available) {
			uint8_t live[32];
			char live_hex[65];
			rc = shirudo_tree_chain_read(live);
			if (rc) {
				tree_sync_report_error("tree_chain_read", NULL, rc);
				TREE_SYNC_RETURN(-ENODEV);
			}
			shirudo_hex_encode(live, 32, live_hex);
			bpm_copy_string(state.projection_root_tpm,
					 sizeof(state.projection_root_tpm), live_hex);
		}
	}
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
		if (tpm_available) {
			rc = shirudo_tree_chain_extend(digest, next);
			if (rc) {
				tree_sync_report_error("tree_projection_extend", op, rc);
				TREE_SYNC_RETURN(rc);
			}
		} else {
			shirudo_sha256_2(previous, 32, digest, 32, next);
		}
		shirudo_hex_encode(next, 32, state.projection_root);
		if (tpm_available)
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

static const struct shirudo_help_item bpm_subcmds[] = {
	{ "config", "register and manage OCI repositories" },
	{ "repo", "refresh signed repository indexes" },
	{ "tree", "synchronize the optional signed upatch tree" },
	{ "key", "add a trusted package certificate" },
	{ "pull", "download an OCI package into the current directory" },
	{ "push", "publish an OCI package from the operator" },
	{ "install", "download and activate a repository or OCI package" },
	{ "upgrade", "activate newer cached package versions" },
};

static const struct shirudo_help_item bpm_target_subcmds[] = {
	{ "config", "register and manage OCI repositories" },
	{ "repo", "refresh signed repository indexes" },
	{ "tree", "synchronize the optional signed upatch tree" },
	{ "key", "add a trusted package certificate" },
	{ "pull", "download an OCI package into the current directory" },
	{ "install", "download and activate a repository or OCI package" },
	{ "upgrade", "activate newer cached package versions" },
};

static bool bpm_operator_available(void)
{
	return access(SHIRUDO_LIBEXEC_DIR "/shirudo-build", X_OK) == 0;
}

static const struct shirudo_help bpm_target_help = {
	.usage = "shirudo bpm <config|repo|tree|key|pull|install|upgrade>",
	.summary = "Manage signed target-local BPM packages backed by OCI repositories.",
	.sections = (const struct shirudo_help_section[]) {
		{ "subcommands:", bpm_target_subcmds, ARRAY_SIZE(bpm_target_subcmds) },
	},
	.n_sections = 1,
};

static const struct shirudo_help bpm_operator_help = {
	.usage = "shirudo bpm <config|repo|key|pull|push|install|upgrade>",
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

static void bpm_push_usage(void)
{
	fprintf(stderr,
		"usage: shirudo bpm push <package-file> <repository>\n\n"
		"The repository must start with oci:// and must not include a tag.\n"
		"Example:\n"
		"  shirudo bpm push ./package.bee oci://quay.io/namespace/package\n");
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

int cmd_bpm(int argc, const char **argv)
{
	const struct shirudo_help *help = bpm_operator_available() ?
		&bpm_operator_help : &bpm_target_help;
	const struct shirudo_help_item *subcmds = bpm_operator_available() ?
		bpm_subcmds : bpm_target_subcmds;
	size_t n_subcmds = bpm_operator_available() ? ARRAY_SIZE(bpm_subcmds) :
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
	if (!strcmp(sub, "tree") && (argc < 3 || shirudo_is_help(argv[2]))) {
		fprintf(stderr, "usage: shirudo bpm tree sync [--dry-run] [--report=<path>]\n");
		return argc < 3 ? 2 : 0;
	}
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
	if (!strcmp(sub, "push")) {
		const char *reference = NULL;
		int rc, result;

		if (argc == 3 && shirudo_is_help(argv[2])) {
			bpm_push_usage();
			return 0;
		}
		if (argc != 4) {
			bpm_push_usage();
			return 2;
		}
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
			return bpm_fail("initialize curl", -EIO);
		rc = push_package(argv[2], argv[3], &reference);
		result = bpm_finish(-1, rc, "push");
		if (!result)
			printf("%s\n", reference);
		free((void *)reference);
		return result;
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
	if (!strcmp(sub, "tree") && argc >= 3 && !strcmp(argv[2], "sync")) {
		int lock, rc;

		if (argc > 6)
			return 2;
		if (argc == 4 && shirudo_is_help(argv[3])) {
			printf("usage: shirudo bpm tree sync [--dry-run] [--report=<path>]\n");
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
	if (!strcmp(sub, "key") && argc == 4 && !strcmp(argv[2], "add")) {
		char temp[PATH_MAX] = {};
		const char *src = argv[3];
		int rc;

		if (strstr(src, ".bee")) {
			rc = extract_package_cert(src, temp, sizeof(temp));
			if (rc)
				return bpm_fail("key add", rc);
			src = temp;
		}
		rc = install_key_file(src);
		if (temp[0])
			unlink(temp);
		return rc ? bpm_fail("key add", rc) : 0;
	}
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
