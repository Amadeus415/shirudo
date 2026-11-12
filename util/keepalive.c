// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "crypto.h"
#include "json.h"
#include "keepalive.h"

#define SCHEMA		"shirudo.keepalive/1"
#define HASH_HEX_LEN	(2 * CRYPTO_SHA256_LEN)

#define CODE_BITS	2
#define CODE_MAX	3
#define CODES_PER_BYTE	4

enum cond_code {
	COND_NOT_EVALUATED,
	COND_OK,
	COND_WARN,
	COND_ALERT,
};

/* The backend reads a pair by its place here: append, never reorder. */
static const char * const cond_order[] = {
	"LsmAttached",
	"KeyringSealed",
	"ChainIntact",
	"UpatchesMeasured",
	"TpmMeasured",
	"ConfigActive",
	"XdpCovered",
};

int keepalive_mask(const __u8 *codes, size_t n, char *b64, size_t cap)
{
	size_t len = (n + CODES_PER_BYTE - 1) / CODES_PER_BYTE, i;
	__u8 raw[KEEPALIVE_MASK_BYTES] = {};

	if (n > KEEPALIVE_MASK_OPS)
		return -EINVAL;
	for (i = 0; i < n; i++) {
		size_t slot = CODES_PER_BYTE - 1 - i % CODES_PER_BYTE;

		if (codes[i] > CODE_MAX)
			return -EINVAL;
		raw[i / CODES_PER_BYTE] |= codes[i] << (CODE_BITS * slot);
	}
	if (cap < 4 * ((len + 2) / 3) + 1)
		return -E2BIG;
	return base64_encode(raw, len, b64, cap);
}

static enum cond_code cond_code_of(const char *status)
{
	if (!strcmp(status, "OK"))
		return COND_OK;
	if (!strcmp(status, "WARN"))
		return COND_WARN;
	if (!strcmp(status, "ALERT"))
		return COND_ALERT;
	return COND_NOT_EVALUATED;
}

static enum cond_code cond_code_named(const struct condition *conds, size_t n,
				      const char *type)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (!strcmp(conds[i].type, type))
			return cond_code_of(conds[i].status);
	return COND_NOT_EVALUATED;
}

__u16 keepalive_cond(const struct condition *conds, size_t n)
{
	__u16 cond = 0;
	size_t i;

	BUILD_BUG_ON(ARRAY_SIZE(cond_order) != CONDITIONS_MAX);
	BUILD_BUG_ON(CODE_BITS * ARRAY_SIZE(cond_order) > 8 * sizeof(cond));

	for (i = 0; i < ARRAY_SIZE(cond_order); i++)
		cond |= cond_code_named(conds, n, cond_order[i]) <<
			(CODE_BITS * i);
	return cond;
}

static bool is_hash(const char *s)
{
	size_t i;

	if (!s)
		return false;
	for (i = 0; i < HASH_HEX_LEN; i++)
		if (!(s[i] >= '0' && s[i] <= '9') &&
		    !(s[i] >= 'a' && s[i] <= 'f'))
			return false;
	return !s[HASH_HEX_LEN];
}

static bool is_absent(const char *s)
{
	return !s || !s[0];
}

static bool is_hash_or_absent(const char *s)
{
	return is_absent(s) || is_hash(s);
}

static bool tree_is_valid(const struct keepalive_input *in)
{
	return !in->tree ||
	       (in->tree_id && is_hash_or_absent(in->base_root) &&
		is_hash(in->projection_root));
}

static bool input_is_valid(const struct keepalive_input *in)
{
	return in->boot_id && is_hash(in->version_id) &&
	       is_hash_or_absent(in->config_root) && in->kernel_release &&
	       is_hash_or_absent(in->image_root) && in->verdict &&
	       tree_is_valid(in) && is_hash(in->set_sha256);
}

static void kv_string_or_null(struct json_emit *e, const char *key,
			      const char *val)
{
	if (is_absent(val))
		json_kv_null(e, key);
	else
		json_kv_string(e, key, val);
}

/* json_kv_int() takes an __s64, which a tamper counter can pass. */
static void u64_value(struct json_emit *e, __u64 val)
{
	char num[24];
	int len = strsprintf(num, sizeof(num), "%llu", val);

	if (len < 0)
		e->err = -E2BIG;
	else
		json_raw_value(e, num, len);
}

static void kv_u64(struct json_emit *e, const char *key, __u64 val)
{
	json_key(e, key);
	u64_value(e, val);
}

static void kv_tamper(struct json_emit *e, const __u64 *tamper)
{
	size_t i;

	if (!tamper) {
		json_kv_null(e, "tamper");
		return;
	}
	json_arr_open(e, "tamper");
	for (i = 0; i < TAMPER_MAX; i++)
		u64_value(e, tamper[i]);
	json_arr_close(e);
}

static void kv_no_tree(struct json_emit *e)
{
	static const char * const keys[] = {
		"tree_id", "generation", "base_seq", "last_seq", "base_root",
		"projection_root", "mask",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(keys); i++)
		json_kv_null(e, keys[i]);
}

static void kv_tree(struct json_emit *e, const struct keepalive_input *in)
{
	if (!in->tree) {
		kv_no_tree(e);
		return;
	}
	json_kv_string(e, "tree_id", in->tree_id);
	kv_u64(e, "generation", in->generation);
	kv_u64(e, "base_seq", in->base_seq);
	kv_u64(e, "last_seq", in->last_seq);
	kv_string_or_null(e, "base_root", in->base_root);
	json_kv_string(e, "projection_root", in->projection_root);
	if (in->mask)
		json_kv_string(e, "mask", in->mask);
	else
		json_kv_null(e, "mask");
}

static void body(struct json_emit *e, const struct keepalive_input *in)
{
	json_obj_open(e);
	json_kv_string(e, "schema", SCHEMA);
	json_kv_string(e, "boot_id", in->boot_id);
	json_kv_string(e, "version_id", in->version_id);
	kv_string_or_null(e, "config_root", in->config_root);
	json_kv_string(e, "kernel_release", in->kernel_release);
	kv_string_or_null(e, "image_id", in->image_id);
	kv_string_or_null(e, "image_version", in->image_version);
	kv_string_or_null(e, "image_root", in->image_root);
	json_kv_string(e, "verdict", in->verdict);
	kv_u64(e, "cond", in->cond);
	kv_u64(e, "flags", in->flags);
	kv_tamper(e, in->tamper);
	kv_tree(e, in);
	json_kv_string(e, "set_sha256", in->set_sha256);
	kv_u64(e, "count", in->count);
	kv_u64(e, "not_ok", in->not_ok);
	json_obj_close(e);
}

int keepalive_emit(const struct keepalive_input *in, char *buf, size_t cap,
		   size_t *len)
{
	struct json_emit e = { .buf = buf, .cap = cap };

	*len = 0;
	if (cap)
		buf[0] = '\0';
	if (!input_is_valid(in))
		return -EINVAL;
	body(&e, in);
	if (e.err) {
		if (cap)
			buf[0] = '\0';
		return e.err == -ENOSPC ? -E2BIG : e.err;
	}
	*len = e.len;
	return 0;
}
