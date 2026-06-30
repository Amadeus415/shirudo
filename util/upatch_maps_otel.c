// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * OTLP/HTTP JSON export for pinned upatch map snapshots. Automatic mode
 * chooses a signal from the map's structural BTF; explicit log and metric
 * modes bypass that classifier. Network delivery is synchronous and bounded
 * by the caller-selected retry count.
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/btf.h>

#include <bpf/btf.h>
#include <curl/curl.h>
#include <zlib.h>

#include "json.h"
#include "malloc.h"
#include "paths.h"
#include "upatch_maps_otel.h"

#define OTEL_ENDPOINT_MAX	2048
#define OTEL_RESPONSE_MAX	(64U * 1024U)
#define OTEL_DEFAULT_TIMEOUT_MS	10000L
#define OTEL_MAX_HEADER_BYTES	16384U
#define OTEL_MAX_TYPE_UNWRAP	32

extern const char shirudo_version[];

struct otel_response {
	char		buf[OTEL_RESPONSE_MAX];
	size_t		len;
	unsigned long	retry_after;
};

struct otel_state {
	enum shirudo_otel_signal signal;
	struct shirudo_otel_opts opts;
	char endpoint[OTEL_ENDPOINT_MAX];
	char host[256];
	const char *ca_file;
	const char *client_cert;
	const char *client_key;
	long timeout_ms;
	bool gzip;
	bool insecure_tls;
	struct curl_slist *headers;
};

struct metric_type {
	bool is_signed;
	uint32_t width;
};

static const struct btf_type *unwrap_btf_type(const struct btf *btf,
					       uint32_t id)
{
	const struct btf_type *t;
	int i;

	for (i = 0; i < OTEL_MAX_TYPE_UNWRAP; i++) {
		t = btf__type_by_id(btf, id);
		if (!t)
			return NULL;
		if (!btf_is_typedef(t) && !btf_is_mod(t))
			return t;
		id = t->type;
	}
	return NULL;
}

static int metric_type_from_view(const struct shirudo_map_view *v,
				 struct metric_type *out)
{
	const struct btf_type *t;

	if (!v || !v->btf || !v->value_type_id)
		return -ENODATA;
	t = unwrap_btf_type(v->btf, v->value_type_id);
	if (!t || !btf_is_int(t) || t->size != v->value_size ||
	    btf_int_offset(t) != 0 || btf_int_bits(t) != t->size * 8 ||
	    (t->size != 1 && t->size != 2 && t->size != 4 && t->size != 8))
		return -EOPNOTSUPP;
	out->is_signed = (btf_int_encoding(t) & BTF_INT_SIGNED) != 0;
	out->width = t->size;
	return 0;
}

int shirudo_upatch_maps_otel_classify(const struct shirudo_map_view *v,
				      enum shirudo_otel_signal *signal,
				      char *reason, size_t reason_sz)
{
	struct metric_type mt;
	int rc;

	if (!v || !signal)
		return -EINVAL;
	*signal = SHIRUDO_OTEL_LOG;
	if (v->serialized) {
		snprintf(reason, reason_sz, "map uses a serializer");
		return 0;
	}
	if (v->skipped) {
		snprintf(reason, reason_sz, "map type is not generically readable");
		return 0;
	}
	if (!shirudo_upatch_map_is_percpu(v->type)) {
		snprintf(reason, reason_sz, "map is not per-CPU");
		return 0;
	}
	rc = metric_type_from_view(v, &mt);
	if (rc) {
		snprintf(reason, reason_sz, "value is not a BTF integer scalar");
		return 0;
	}
	if (mt.is_signed) {
		snprintf(reason, reason_sz, "value is signed");
		return 0;
	}
	*signal = SHIRUDO_OTEL_METRIC;
	snprintf(reason, reason_sz, "unsigned per-CPU %u-bit scalar",
		 mt.width * 8);
	return 0;
}

/* ---- OTLP JSON AnyValue helpers ------------------------------------ */

static void otlp_kv_string(struct shirudo_json_emit *e, const char *key,
			   const char *value)
{
	shirudo_json_obj_open(e);
	shirudo_json_kv_string(e, "key", key);
	shirudo_json_obj_open_key(e, "value");
	shirudo_json_kv_string(e, "stringValue", value ? value : "");
	shirudo_json_obj_close(e);
	shirudo_json_obj_close(e);
}

static void otlp_kv_int(struct shirudo_json_emit *e, const char *key,
			int64_t value)
{
	char num[32];

	snprintf(num, sizeof(num), "%" PRId64, value);
	shirudo_json_obj_open(e);
	shirudo_json_kv_string(e, "key", key);
	shirudo_json_obj_open_key(e, "value");
	shirudo_json_kv_string(e, "intValue", num);
	shirudo_json_obj_close(e);
	shirudo_json_obj_close(e);
}

static void otlp_kv_bool(struct shirudo_json_emit *e, const char *key,
			 bool value)
{
	shirudo_json_obj_open(e);
	shirudo_json_kv_string(e, "key", key);
	shirudo_json_obj_open_key(e, "value");
	shirudo_json_kv_bool(e, "boolValue", value);
	shirudo_json_obj_close(e);
	shirudo_json_obj_close(e);
}

static void otlp_kvlist_begin(struct shirudo_json_emit *e, const char *key)
{
	shirudo_json_obj_open(e);
	shirudo_json_kv_string(e, "key", key);
	shirudo_json_obj_open_key(e, "value");
	shirudo_json_obj_open_key(e, "kvlistValue");
	shirudo_json_arr_open(e, "values");
}

static void otlp_kvlist_end(struct shirudo_json_emit *e)
{
	shirudo_json_arr_close(e);
	shirudo_json_obj_close(e);
	shirudo_json_obj_close(e);
	shirudo_json_obj_close(e);
}

static void otlp_array_begin(struct shirudo_json_emit *e, const char *key)
{
	shirudo_json_obj_open(e);
	shirudo_json_kv_string(e, "key", key);
	shirudo_json_obj_open_key(e, "value");
	shirudo_json_obj_open_key(e, "arrayValue");
	shirudo_json_arr_open(e, "values");
}

static void otlp_array_end(struct shirudo_json_emit *e)
{
	shirudo_json_arr_close(e);
	shirudo_json_obj_close(e);
	shirudo_json_obj_close(e);
	shirudo_json_obj_close(e);
}

static void otlp_array_string(struct shirudo_json_emit *e, const char *value)
{
	shirudo_json_obj_open(e);
	shirudo_json_kv_string(e, "stringValue", value ? value : "");
	shirudo_json_obj_close(e);
}

static void otlp_array_kvlist_begin(struct shirudo_json_emit *e)
{
	shirudo_json_obj_open(e);
	shirudo_json_obj_open_key(e, "kvlistValue");
	shirudo_json_arr_open(e, "values");
}

static void otlp_array_kvlist_end(struct shirudo_json_emit *e)
{
	shirudo_json_arr_close(e);
	shirudo_json_obj_close(e);
	shirudo_json_obj_close(e);
}

static void emit_resource_attributes(struct shirudo_json_emit *e)
{
	char hostname[256] = "unknown";

	if (gethostname(hostname, sizeof(hostname)) != 0)
		snprintf(hostname, sizeof(hostname), "unknown");
	hostname[sizeof(hostname) - 1] = '\0';
	shirudo_json_arr_open(e, "attributes");
	otlp_kv_string(e, "service.name", "shirudo");
	otlp_kv_string(e, "service.version", shirudo_version);
	otlp_kv_string(e, "host.name", hostname);
	shirudo_json_arr_close(e);
}

static uint64_t realtime_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void u64_decimal(uint64_t value, char out[32])
{
	snprintf(out, 32, "%" PRIu64, value);
}

static void emit_log_map_data(struct shirudo_json_emit *e,
			      const struct shirudo_map_view *v)
{
	uint32_t i, j;

	otlp_kv_string(e, "name", v->name);
	otlp_kv_string(e, "type", v->type_name);
	otlp_kv_int(e, "max_entries", v->max_entries);
	otlp_kv_int(e, "n_entries", v->n_entries);
	if (shirudo_upatch_map_is_percpu(v->type))
		otlp_kv_int(e, "n_cpus", v->n_cpus);
	if (v->serialized) {
		uint32_t p;

		otlp_kv_bool(e, "serialized", true);
		otlp_kv_int(e, "serialized_pages", v->n_serial_pages);
		otlp_kv_int(e, "serialized_bytes",
			    (int64_t)v->serial_bytes_total);
		otlp_array_begin(e, "pages");
		for (p = 0; p < v->n_serial_pages; p++) {
			const struct shirudo_serial_page *page = &v->serial_pages[p];
			char *hex = shirudo_upatch_map_hex_alloc(page->data,
							 page->bytes);

			otlp_array_kvlist_begin(e);
			otlp_kv_int(e, "page_index", page->page_index);
			otlp_kv_int(e, "cursor", (int64_t)page->cursor);
			otlp_kv_int(e, "next_cursor",
				    (int64_t)page->next_cursor);
			otlp_kv_bool(e, "done", page->done);
			otlp_kv_int(e, "flags", page->flags);
			otlp_kv_int(e, "chunks", page->chunks);
			otlp_kv_int(e, "bytes", page->bytes);
			otlp_kv_string(e, "data_hex", hex ? hex : "");
			xfree(hex, (size_t)page->bytes * 2 + 1);
			otlp_array_kvlist_end(e);
		}
		otlp_array_end(e);
		return;
	}
	otlp_kv_bool(e, "serialized", false);
	if (v->skipped) {
		otlp_kv_string(e, "skipped", v->skipped_reason ?: "");
		return;
	}
	otlp_kv_bool(e, "truncated", v->truncated);
	if (v->truncated)
		otlp_kv_int(e, "n_truncated_at", v->n_truncated_at);
	if (v->btf_key_type[0] || v->btf_value_type[0]) {
		otlp_kvlist_begin(e, "btf");
		otlp_kv_string(e, "key_type", v->btf_key_type);
		otlp_kv_string(e, "value_type", v->btf_value_type);
		if (v->key_type_def[0])
			otlp_kv_string(e, "key_type_def", v->key_type_def);
		if (v->value_type_def[0])
			otlp_kv_string(e, "value_type_def", v->value_type_def);
		otlp_kvlist_end(e);
	}
	otlp_array_begin(e, "entries");
	for (i = 0; i < v->n_entries; i++) {
		const struct shirudo_map_entry *en = &v->entries[i];
		char *key = shirudo_upatch_map_format_cell(v, v->key_type_id,
						 en->key, v->key_size,
						 v->btf_key_type);

		otlp_array_kvlist_begin(e);
		otlp_kv_string(e, "key", key ?: "");
		if (shirudo_upatch_map_is_percpu(v->type)) {
			char *sum = shirudo_upatch_map_format_percpu_sum(v,
				en->value, v->btf_value_type);

			otlp_array_begin(e, "values_per_cpu");
			for (j = 0; j < v->n_cpus; j++) {
				const char *p = (const char *)en->value +
					(size_t)j *
					shirudo_upatch_map_value_stride(v);
				char *one = shirudo_upatch_map_format_cell(v,
					v->value_type_id, p, v->value_size,
					v->btf_value_type);

				otlp_array_string(e, one ?: "");
				xstrfree(one);
			}
			otlp_array_end(e);
			otlp_kv_string(e, "sum", sum ?: "");
			xstrfree(sum);
		} else {
			char *value = shirudo_upatch_map_format_cell(v,
				v->value_type_id, en->value, v->value_size,
				v->btf_value_type);

			otlp_kv_string(e, "value", value ?: "");
			xstrfree(value);
		}
		otlp_array_kvlist_end(e);
		xstrfree(key);
	}
	otlp_array_end(e);
}

int shirudo_upatch_maps_otel_build_log(const struct shirudo_map_view *v,
				       char **out, size_t *out_len)
{
	struct shirudo_json_emit e = {};
	char now[32];
	char *buf;

	buf = xmalloc(SHIRUDO_JSON_MAX_BYTES);
	if (!buf)
		return -ENOMEM;
	e.buf = buf;
	e.cap = SHIRUDO_JSON_MAX_BYTES;
	u64_decimal(realtime_ns(), now);

	shirudo_json_obj_open(&e);
	shirudo_json_arr_open(&e, "resourceLogs");
	shirudo_json_obj_open(&e);
	shirudo_json_obj_open_key(&e, "resource");
	emit_resource_attributes(&e);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_open(&e, "scopeLogs");
	shirudo_json_obj_open(&e);
	shirudo_json_obj_open_key(&e, "scope");
	shirudo_json_kv_string(&e, "name", "shirudo.upatch.maps");
	shirudo_json_kv_string(&e, "version", shirudo_version);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_open(&e, "logRecords");
	shirudo_json_obj_open(&e);
	shirudo_json_kv_string(&e, "timeUnixNano", now);
	shirudo_json_kv_string(&e, "observedTimeUnixNano", now);
	shirudo_json_kv_int(&e, "severityNumber", 9);
	shirudo_json_kv_string(&e, "severityText", "INFO");
	shirudo_json_kv_string(&e, "eventName", "shirudo.bpf.map.snapshot");
	shirudo_json_obj_open_key(&e, "body");
	shirudo_json_obj_open_key(&e, "kvlistValue");
	shirudo_json_arr_open(&e, "values");
	otlp_kv_int(&e, "schema", 1);
	otlp_kv_string(&e, "upatch", v->upatch);
	otlp_kv_string(&e, "map", v->name);
	otlp_kvlist_begin(&e, "data");
	emit_log_map_data(&e, v);
	otlp_kvlist_end(&e);
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_open(&e, "attributes");
	otlp_kv_string(&e, "shirudo.upatch.name", v->upatch);
	otlp_kv_string(&e, "shirudo.map.name", v->name);
	otlp_kv_string(&e, "shirudo.map.type", v->type_name);
	otlp_kv_int(&e, "shirudo.map.n_cpus", v->n_cpus);
	otlp_kv_bool(&e, "shirudo.map.serialized", v->serialized);
	otlp_kv_bool(&e, "shirudo.map.truncated", v->truncated);
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);

	if (e.err) {
		xfree(buf, SHIRUDO_JSON_MAX_BYTES);
		return e.err;
	}
	*out = buf;
	*out_len = e.len;
	return 0;
}

/* ---- Metrics ------------------------------------------------------- */

static int read_integer(const void *p, const struct metric_type *mt,
			__int128 *signed_out, unsigned __int128 *unsigned_out)
{
	uint64_t u = 0;
	int64_t s = 0;

	memcpy(&u, p, mt->width);
	if (mt->is_signed) {
		switch (mt->width) {
		case 1: s = (int8_t)u; break;
		case 2: s = (int16_t)u; break;
		case 4: s = (int32_t)u; break;
		case 8: memcpy(&s, p, 8); break;
		default: return -EOPNOTSUPP;
		}
		*signed_out = s;
	} else {
		*unsigned_out = u;
	}
	return 0;
}

static int entry_metric_value(const struct shirudo_map_view *v,
			      const struct shirudo_map_entry *en,
			      const struct metric_type *mt, int64_t *out)
{
	unsigned int count = shirudo_upatch_map_is_percpu(v->type) ?
		v->n_cpus : 1;
	__int128 signed_sum = 0;
	unsigned __int128 unsigned_sum = 0;
	uint32_t stride = shirudo_upatch_map_value_stride(v);
	unsigned int i;

	for (i = 0; i < count; i++) {
		__int128 s = 0;
		unsigned __int128 u = 0;
		int rc = read_integer((const char *)en->value +
			(size_t)i * stride, mt, &s, &u);

		if (rc)
			return rc;
		if (mt->is_signed)
			signed_sum += s;
		else
			unsigned_sum += u;
	}
	if (mt->is_signed) {
		if (signed_sum < INT64_MIN || signed_sum > INT64_MAX)
			return -ERANGE;
		*out = (int64_t)signed_sum;
	} else {
		if (unsigned_sum > INT64_MAX)
			return -ERANGE;
		*out = (int64_t)unsigned_sum;
	}
	return 0;
}

static bool valid_metric_name(const char *name)
{
	size_t i, n;

	if (!name || !isalpha((unsigned char)name[0]))
		return false;
	n = strlen(name);
	if (n == 0 || n > 255)
		return false;
	for (i = 1; i < n; i++) {
		unsigned char c = (unsigned char)name[i];

		if (!isalnum(c) && c != '_' && c != '.' && c != '-' && c != '/')
			return false;
	}
	return true;
}

static int metric_name(const struct otel_state *st,
		       const struct shirudo_map_view *v, char out[256])
{
	size_t i;
	int n;

	if (st->opts.metric_name) {
		if (!valid_metric_name(st->opts.metric_name))
			return -EINVAL;
		snprintf(out, 256, "%s", st->opts.metric_name);
		return 0;
	}
	n = snprintf(out, 256, "shirudo.%s.%s", v->upatch, v->name);
	if (n < 0 || n >= 256)
		return -ENAMETOOLONG;
	for (i = 0; out[i]; i++) {
		unsigned char c = (unsigned char)out[i];

		if (!isalnum(c) && c != '_' && c != '.' && c != '-' && c != '/')
			out[i] = '_';
	}
	return 0;
}

static int map_start_ns(const struct shirudo_map_view *v, uint64_t *out)
{
	char path[PATH_MAX];
	struct stat st;

	if (v->lifetime_start_ns) {
		*out = v->lifetime_start_ns;
		return 0;
	}
	if ((size_t)snprintf(path, sizeof(path), "%s/%s",
			     SHIRUDO_BPFFS_UPATCHES_DIR, v->upatch) >=
	    sizeof(path))
		return -ENAMETOOLONG;
	if (stat(path, &st) != 0)
		return -errno;
	*out = (uint64_t)st.st_ctim.tv_sec * 1000000000ULL +
	       (uint64_t)st.st_ctim.tv_nsec;
	return 0;
}

static int validate_metric_view(const struct otel_state *st,
				const struct shirudo_map_view *v,
				struct metric_type *mt)
{
	int rc;

	if (v->serialized || v->skipped)
		return -EOPNOTSUPP;
	if (v->truncated)
		return -E2BIG;
	rc = metric_type_from_view(v, mt);
	if (rc)
		return rc;
	if (st->opts.metric_kind == SHIRUDO_OTEL_METRIC_COUNTER &&
	    mt->is_signed)
		return -EDOM;
	return 0;
}

static int build_metric_payload(const struct otel_state *st,
				const struct shirudo_map_view *v,
				char **out, size_t *out_len)
{
	struct shirudo_json_emit e = {};
	struct metric_type mt;
	char name[256], now[32], start[32];
	uint64_t now_ns, start_ns = 0;
	char *buf;
	uint32_t i;
	int rc;

	rc = validate_metric_view(st, v, &mt);
	if (rc)
		return rc;
	if (v->n_entries == 0) {
		*out = NULL;
		*out_len = 0;
		return 0;
	}
	rc = metric_name(st, v, name);
	if (rc)
		return rc;
	now_ns = realtime_ns();
	u64_decimal(now_ns, now);
	if (st->opts.metric_kind == SHIRUDO_OTEL_METRIC_COUNTER) {
		rc = map_start_ns(v, &start_ns);
		if (rc)
			return rc;
		u64_decimal(start_ns, start);
	}
	buf = xmalloc(SHIRUDO_JSON_MAX_BYTES);
	if (!buf)
		return -ENOMEM;
	e.buf = buf;
	e.cap = SHIRUDO_JSON_MAX_BYTES;

	shirudo_json_obj_open(&e);
	shirudo_json_arr_open(&e, "resourceMetrics");
	shirudo_json_obj_open(&e);
	shirudo_json_obj_open_key(&e, "resource");
	emit_resource_attributes(&e);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_open(&e, "scopeMetrics");
	shirudo_json_obj_open(&e);
	shirudo_json_obj_open_key(&e, "scope");
	shirudo_json_kv_string(&e, "name", "shirudo.upatch.maps");
	shirudo_json_kv_string(&e, "version", shirudo_version);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_open(&e, "metrics");
	shirudo_json_obj_open(&e);
	shirudo_json_kv_string(&e, "name", name);
	if (st->opts.metric_description && st->opts.metric_description[0])
		shirudo_json_kv_string(&e, "description",
				       st->opts.metric_description);
	shirudo_json_kv_string(&e, "unit",
			       st->opts.metric_unit ?: "1");
	shirudo_json_obj_open_key(&e,
		st->opts.metric_kind == SHIRUDO_OTEL_METRIC_COUNTER ?
		"sum" : "gauge");
	if (st->opts.metric_kind == SHIRUDO_OTEL_METRIC_COUNTER) {
		shirudo_json_kv_int(&e, "aggregationTemporality", 2);
		shirudo_json_kv_bool(&e, "isMonotonic", true);
	}
	shirudo_json_arr_open(&e, "dataPoints");
	for (i = 0; i < v->n_entries; i++) {
		const struct shirudo_map_entry *en = &v->entries[i];
		char value[32];
		char *key;
		int64_t point;

		rc = entry_metric_value(v, en, &mt, &point);
		if (rc) {
			xfree(buf, SHIRUDO_JSON_MAX_BYTES);
			return rc;
		}
		snprintf(value, sizeof(value), "%" PRId64, point);
		key = shirudo_upatch_map_format_cell(v, v->key_type_id,
			en->key, v->key_size, v->btf_key_type);
		shirudo_json_obj_open(&e);
		if (st->opts.metric_kind == SHIRUDO_OTEL_METRIC_COUNTER)
			shirudo_json_kv_string(&e, "startTimeUnixNano", start);
		shirudo_json_kv_string(&e, "timeUnixNano", now);
		shirudo_json_kv_string(&e, "asInt", value);
		shirudo_json_arr_open(&e, "attributes");
		otlp_kv_string(&e, "shirudo.map.key", key ?: "");
		otlp_kv_string(&e, "shirudo.upatch.name", v->upatch);
		otlp_kv_string(&e, "shirudo.map.name", v->name);
		otlp_kv_string(&e, "shirudo.map.type", v->type_name);
		shirudo_json_arr_close(&e);
		shirudo_json_obj_close(&e);
		xstrfree(key);
	}
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);

	if (e.err) {
		xfree(buf, SHIRUDO_JSON_MAX_BYTES);
		return e.err;
	}
	*out = buf;
	*out_len = e.len;
	return 0;
}

int shirudo_upatch_maps_otel_build_metric(
	const struct shirudo_map_view *v,
	const struct shirudo_otel_opts *opts,
	char **out, size_t *out_len)
{
	struct otel_state st = {};

	st.opts.metric_kind = SHIRUDO_OTEL_METRIC_COUNTER;
	if (opts)
		st.opts = *opts;
	return build_metric_payload(&st, v, out, out_len);
}

/* ---- Configuration and HTTP --------------------------------------- */

static const char *signal_name(enum shirudo_otel_signal signal)
{
	return signal == SHIRUDO_OTEL_LOG ? "LOGS" : "METRICS";
}

static const char *signal_path(enum shirudo_otel_signal signal)
{
	return signal == SHIRUDO_OTEL_LOG ? "v1/logs" : "v1/metrics";
}

static const char *otel_env(enum shirudo_otel_signal signal,
			    const char *suffix)
{
	char name[128];
	const char *value;

	snprintf(name, sizeof(name), "OTEL_EXPORTER_OTLP_%s_%s",
		 signal_name(signal), suffix);
	value = getenv(name);
	if (value && value[0])
		return value;
	snprintf(name, sizeof(name), "OTEL_EXPORTER_OTLP_%s", suffix);
	value = getenv(name);
	return value && value[0] ? value : NULL;
}

static const char *otel_signal_env(enum shirudo_otel_signal signal,
				   const char *suffix)
{
	char name[128];
	const char *value;

	snprintf(name, sizeof(name), "OTEL_EXPORTER_OTLP_%s_%s",
		 signal_name(signal), suffix);
	value = getenv(name);
	return value && value[0] ? value : NULL;
}

static int append_signal_path(const char *base, enum shirudo_otel_signal signal,
			      char *out, size_t out_sz)
{
	const char *tail;
	size_t prefix_len;
	const char *slash;
	int n;

	if (!base || !base[0])
		return -EINVAL;
	tail = strpbrk(base, "?#");
	prefix_len = tail ? (size_t)(tail - base) : strlen(base);
	if (prefix_len == 0)
		return -EINVAL;
	slash = base[prefix_len - 1] == '/' ? "" : "/";
	n = snprintf(out, out_sz, "%.*s%s%s%s", (int)prefix_len, base,
		     slash, signal_path(signal), tail ? tail : "");

	return n < 0 || (size_t)n >= out_sz ? -ENAMETOOLONG : 0;
}

static int resolve_endpoint(struct otel_state *st, const char *spec,
			    bool spec_is_base)
{
	const char *signal_endpoint, *generic_endpoint;

	if (spec && spec[0]) {
		if (spec_is_base)
			return append_signal_path(spec, st->signal, st->endpoint,
					  sizeof(st->endpoint));
		if (strlen(spec) >= sizeof(st->endpoint))
			return -ENAMETOOLONG;
		snprintf(st->endpoint, sizeof(st->endpoint), "%s", spec);
		return 0;
	}
	signal_endpoint = otel_signal_env(st->signal, "ENDPOINT");
	if (signal_endpoint) {
		if (strlen(signal_endpoint) >= sizeof(st->endpoint))
			return -ENAMETOOLONG;
		snprintf(st->endpoint, sizeof(st->endpoint), "%s",
			 signal_endpoint);
		return 0;
	}
	generic_endpoint = getenv("OTEL_EXPORTER_OTLP_ENDPOINT");
	if (!generic_endpoint || !generic_endpoint[0])
		generic_endpoint = "http://localhost:4318";
	return append_signal_path(generic_endpoint, st->signal, st->endpoint,
				  sizeof(st->endpoint));
}

static bool loopback_host(const char *host)
{
	return strcasecmp(host, "localhost") == 0 ||
	       strcmp(host, "127.0.0.1") == 0 || strcmp(host, "::1") == 0;
}

static int validate_endpoint_security(struct otel_state *st)
{
	CURLU *url = curl_url();
	char *scheme = NULL, *host = NULL, *user = NULL, *password = NULL;
	CURLUcode uc;
	int rc = 0;

	if (!url)
		return -ENOMEM;
	uc = curl_url_set(url, CURLUPART_URL, st->endpoint, 0);
	if (uc)
		return curl_url_cleanup(url), -EINVAL;
	if (curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) ||
	    curl_url_get(url, CURLUPART_HOST, &host, 0)) {
		rc = -EINVAL;
		goto out;
	}
	(void)curl_url_get(url, CURLUPART_USER, &user, 0);
	(void)curl_url_get(url, CURLUPART_PASSWORD, &password, 0);
	if ((user && user[0]) || (password && password[0])) {
		rc = -EINVAL;
		goto out;
	}
	snprintf(st->host, sizeof(st->host), "%s", host);
	if (strcmp(scheme, "http") == 0) {
		if (!loopback_host(host) && !st->opts.allow_insecure) {
			rc = -EPERM;
			goto out;
		}
		if (st->opts.allow_insecure)
			fprintf(stderr, "WARNING: --otel-insecure sends OTLP data to "
				"http://%s without encryption; data and credentials "
				"may be intercepted or modified\n", host);
	} else if (strcmp(scheme, "https") == 0) {
		st->insecure_tls = st->opts.allow_insecure;
		if (st->insecure_tls)
			fprintf(stderr, "WARNING: --otel-insecure disables TLS certificate "
				"and hostname verification for %s; the Collector's "
				"identity is not verified\n", host);
	} else {
		rc = -EPROTONOSUPPORT;
	}
out:
	curl_free(scheme);
	curl_free(host);
	curl_free(user);
	curl_free(password);
	curl_url_cleanup(url);
	return rc;
}

static int parse_timeout(const char *value, long *out)
{
	char *end;
	unsigned long n;

	if (!value) {
		*out = OTEL_DEFAULT_TIMEOUT_MS;
		return 0;
	}
	errno = 0;
	n = strtoul(value, &end, 10);
	if (errno || !end || *end || n > LONG_MAX)
		return -EINVAL;
	*out = (long)n;
	return 0;
}

static bool reserved_header(const char *name)
{
	return strcasecmp(name, "content-type") == 0 ||
	       strcasecmp(name, "content-encoding") == 0 ||
	       strcasecmp(name, "content-length") == 0 ||
	       strcasecmp(name, "host") == 0 ||
	       strcasecmp(name, "user-agent") == 0;
}

static int append_header(struct otel_state *st, const char *line)
{
	struct curl_slist *headers = curl_slist_append(st->headers, line);

	if (!headers)
		return -ENOMEM;
	st->headers = headers;
	return 0;
}

static int hex_digit(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int percent_decode(char *s)
{
	char *src = s, *dst = s;

	while (*src) {
		if (*src == '%') {
			if (!src[1] || !src[2])
				return -EINVAL;
			int hi = hex_digit(src[1]);
			int lo = hex_digit(src[2]);

			if (hi < 0 || lo < 0)
				return -EINVAL;
			*dst++ = (char)((hi << 4) | lo);
			src += 3;
		} else {
			*dst++ = *src++;
		}
	}
	*dst = '\0';
	return 0;
}

static int add_configured_headers(struct otel_state *st, const char *input)
{
	char *copy, *save = NULL, *pair;
	size_t total = input ? strlen(input) : 0;
	int rc = 0;

	if (!input)
		return 0;
	if (total > OTEL_MAX_HEADER_BYTES)
		return -E2BIG;
	copy = xstrdup(input);
	if (!copy)
		return -ENOMEM;
	for (pair = strtok_r(copy, ",", &save); pair;
	     pair = strtok_r(NULL, ",", &save)) {
		char *eq = strchr(pair, '=');
		char *name, *value, *line;
		size_t n;

		if (!eq) { rc = -EINVAL; break; }
		*eq = '\0';
		name = pair;
		value = eq + 1;
		while (isspace((unsigned char)*name)) name++;
		while (isspace((unsigned char)*value)) value++;
		for (char *p = name + strlen(name); p > name &&
		     isspace((unsigned char)p[-1]); p--) p[-1] = '\0';
		if (!name[0] || reserved_header(name) ||
		    percent_decode(value) != 0 || strpbrk(name, "\r\n:") ||
		    strpbrk(value, "\r\n")) { rc = -EINVAL; break; }
		n = strlen(name) + strlen(value) + 3;
		line = xmalloc(n);
		if (!line) { rc = -ENOMEM; break; }
		snprintf(line, n, "%s: %s", name, value);
		rc = append_header(st, line);
		explicit_bzero(line, n);
		xfree(line, n);
		if (rc)
			break;
	}
	explicit_bzero(copy, total);
	xfree(copy, total + 1);
	return rc;
}

static int configure_state(struct otel_state *st, const char *spec,
			   bool spec_is_base)
{
	const char *protocol = otel_env(st->signal, "PROTOCOL");
	const char *compression = otel_env(st->signal, "COMPRESSION");
	const char *headers = otel_env(st->signal, "HEADERS");
	int rc;

	if (protocol && strcmp(protocol, "http/json") != 0)
		return -EPROTONOSUPPORT;
	if (compression && strcmp(compression, "none") != 0 &&
	    strcmp(compression, "gzip") != 0)
		return -EINVAL;
	st->gzip = compression && strcmp(compression, "gzip") == 0;
	st->ca_file = otel_env(st->signal, "CERTIFICATE");
	st->client_cert = otel_env(st->signal, "CLIENT_CERTIFICATE");
	st->client_key = otel_env(st->signal, "CLIENT_KEY");
	if (!!st->client_cert != !!st->client_key)
		return -EINVAL;
	rc = parse_timeout(otel_env(st->signal, "TIMEOUT"), &st->timeout_ms);
	if (rc)
		return rc;
	rc = resolve_endpoint(st, spec, spec_is_base);
	if (rc)
		return rc;
	rc = validate_endpoint_security(st);
	if (rc)
		return rc;
	rc = append_header(st, "Content-Type: application/json");
	if (rc)
		return rc;
	if (st->gzip) {
		rc = append_header(st, "Content-Encoding: gzip");
		if (rc)
			return rc;
	}
	return add_configured_headers(st, headers);
}

static size_t response_write(char *ptr, size_t size, size_t nmemb, void *ctx)
{
	struct otel_response *r = ctx;
	size_t n = size * nmemb;

	if (n > sizeof(r->buf) - 1 - r->len)
		return 0;
	memcpy(r->buf + r->len, ptr, n);
	r->len += n;
	r->buf[r->len] = '\0';
	return n;
}

static size_t response_header(char *ptr, size_t size, size_t nmemb, void *ctx)
{
	struct otel_response *r = ctx;
	size_t n = size * nmemb;
	const char prefix[] = "Retry-After:";

	if (n > sizeof(prefix) - 1 &&
	    strncasecmp(ptr, prefix, sizeof(prefix) - 1) == 0) {
		char *p = ptr + sizeof(prefix) - 1;
		char *end;
		unsigned long value;

		while (p < ptr + n && isspace((unsigned char)*p)) p++;
		errno = 0;
		value = strtoul(p, &end, 10);
		if (!errno && end > p)
			r->retry_after = value > 30 ? 30 : value;
	}
	return n;
}

static int gzip_data(const char *in, size_t in_len,
		     unsigned char **out, size_t *out_len)
{
	z_stream z = {};
	size_t cap = compressBound(in_len) + 32;
	unsigned char *buf;
	int zr;

	buf = xmalloc(cap);
	if (!buf)
		return -ENOMEM;
	zr = deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
			  Z_DEFAULT_STRATEGY);
	if (zr != Z_OK) {
		xfree(buf, cap);
		return -EIO;
	}
	z.next_in = (unsigned char *)in;
	z.avail_in = (uInt)in_len;
	z.next_out = buf;
	z.avail_out = (uInt)cap;
	zr = deflate(&z, Z_FINISH);
	if (zr != Z_STREAM_END) {
		deflateEnd(&z);
		xfree(buf, cap);
		return -EIO;
	}
	*out_len = z.total_out;
	*out = buf;
	deflateEnd(&z);
	return 0;
}

static bool retryable_curl(CURLcode code)
{
	switch (code) {
	case CURLE_COULDNT_RESOLVE_HOST:
	case CURLE_COULDNT_CONNECT:
	case CURLE_OPERATION_TIMEDOUT:
	case CURLE_SEND_ERROR:
	case CURLE_RECV_ERROR:
	case CURLE_GOT_NOTHING:
	case CURLE_PARTIAL_FILE:
	case CURLE_HTTP2:
	case CURLE_AGAIN:
		return true;
	default:
		return false;
	}
}

static bool retryable_http(long code)
{
	return code == 429 || code == 502 || code == 503 || code == 504;
}

static int check_partial_success(enum shirudo_otel_signal signal,
				 const char *body, size_t len)
{
	char rejected_text[32] = {};
	char error[256] = {};
	struct shirudo_json_field partial[] = {
		{ signal == SHIRUDO_OTEL_LOG ? "rejectedLogRecords" :
		  "rejectedDataPoints", SHIRUDO_JSON_T_STRING, rejected_text,
		  sizeof(rejected_text), 0, NULL, 0 },
		{ "errorMessage", SHIRUDO_JSON_T_STRING, error, sizeof(error),
		  0, NULL, 0 },
	};
	struct shirudo_json_field root[] = {
		{ "partialSuccess", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0,
		  partial, sizeof(partial) / sizeof(partial[0]) },
	};
	int64_t rejected = 0;
	int rc;

	if (len == 0)
		return 0;
	rc = shirudo_json_parse(body, len, root,
			       sizeof(root) / sizeof(root[0]));
	if (rc)
		return -EBADMSG;
	if (partial[0].seen) {
		char *end;

		errno = 0;
		rejected = strtoll(rejected_text, &end, 10);
		if (errno || !end || *end || rejected < 0)
			return -EBADMSG;
	}
	if (rejected > 0) {
		fprintf(stderr, "otel: Collector partially rejected %" PRId64
			" %s%s%s\n", rejected,
			signal == SHIRUDO_OTEL_LOG ? "log record(s)" :
			"data point(s)", error[0] ? ": " : "", error);
		return -EREMOTEIO;
	}
	return 0;
}

static unsigned int random_below(unsigned int limit)
{
	uint32_t value;

	if (limit == 0)
		return 0;
	if (getrandom(&value, sizeof(value), 0) != sizeof(value))
		value = (uint32_t)time(NULL) ^ (uint32_t)getpid();
	return value % limit;
}

static void retry_wait(unsigned int retry, unsigned long retry_after)
{
	struct timespec ts;
	unsigned int cap_ms = 250U << (retry > 4 ? 4 : retry);
	unsigned int delay_ms;

	if (cap_ms > 5000)
		cap_ms = 5000;
	delay_ms = retry_after ? (unsigned int)retry_after * 1000U :
		 random_below(cap_ms + 1);
	ts.tv_sec = delay_ms / 1000;
	ts.tv_nsec = (long)(delay_ms % 1000) * 1000000L;
	while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
		;
}

static int otel_post(struct otel_state *st, const char *json, size_t json_len)
{
	unsigned char *compressed = NULL;
	const void *body = json;
	size_t body_len = json_len, compressed_cap = 0;
	unsigned int attempt, max_attempts = st->opts.retries + 1;
	int rc = -EIO;

	if (st->gzip) {
		rc = gzip_data(json, json_len, &compressed, &body_len);
		if (rc)
			return rc;
		body = compressed;
		compressed_cap = compressBound(json_len) + 32;
	}
	for (attempt = 0; attempt < max_attempts; attempt++) {
		struct otel_response response = {};
		CURL *curl = curl_easy_init();
		CURLcode cc;
		long status = 0;
		bool retry;

		if (!curl) { rc = -ENOMEM; break; }
		curl_easy_setopt(curl, CURLOPT_URL, st->endpoint);
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
				 (curl_off_t)body_len);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, st->headers);
		curl_easy_setopt(curl, CURLOPT_USERAGENT,
				 "Shirudo OTel-OTLP-Exporter-C/1");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_write);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, response_header);
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, st->timeout_ms);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
				 st->insecure_tls ? 0L : 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
				 st->insecure_tls ? 0L : 2L);
		if (st->ca_file)
			curl_easy_setopt(curl, CURLOPT_CAINFO, st->ca_file);
		if (st->client_cert)
			curl_easy_setopt(curl, CURLOPT_SSLCERT, st->client_cert);
		if (st->client_key)
			curl_easy_setopt(curl, CURLOPT_SSLKEY, st->client_key);
		cc = curl_easy_perform(curl);
		if (cc == CURLE_OK)
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
		if (cc == CURLE_OK && status == 200) {
			rc = check_partial_success(st->signal, response.buf,
						   response.len);
			curl_easy_cleanup(curl);
			break;
		}
		retry = cc != CURLE_OK ? retryable_curl(cc) :
			retryable_http(status);
		if (cc != CURLE_OK)
			fprintf(stderr, "otel: export attempt %u/%u failed: %s\n",
				attempt + 1, max_attempts, curl_easy_strerror(cc));
		else
			fprintf(stderr, "otel: export attempt %u/%u received HTTP %ld\n",
				attempt + 1, max_attempts, status);
		rc = cc == CURLE_OPERATION_TIMEDOUT ? -ETIMEDOUT :
		     cc != CURLE_OK ? -EHOSTUNREACH : -EREMOTEIO;
		curl_easy_cleanup(curl);
		if (!retry || attempt + 1 == max_attempts)
			break;
		retry_wait(attempt, response.retry_after);
	}
	if (compressed)
		xfree(compressed, compressed_cap);
	return rc;
}

/* ---- Export lifecycle --------------------------------------------- */

static int otel_open_common(const char *spec, const struct shirudo_map_view *v,
			    const struct shirudo_otel_opts *opts,
			    bool automatic, enum shirudo_otel_signal forced,
			    void **state)
{
	struct otel_state *st;
	char reason[160];
	int rc;

	if (!v || !state)
		return -EINVAL;
	st = xcalloc(1, sizeof(*st));
	if (!st)
		return -ENOMEM;
	st->opts.retries = 3;
	st->opts.metric_kind = SHIRUDO_OTEL_METRIC_COUNTER;
	if (opts)
		st->opts = *opts;
	if (automatic) {
		rc = shirudo_upatch_maps_otel_classify(v, &st->signal,
						 reason, sizeof(reason));
		if (rc)
			goto err;
		fprintf(stderr, "otel: selected %s for %s map %s: %s\n",
			st->signal == SHIRUDO_OTEL_LOG ? "log" : "metric",
			v->type_name, v->name, reason);
		if (st->signal == SHIRUDO_OTEL_LOG && opts &&
		    (opts->metric_kind_set || opts->metric_name ||
		     opts->metric_unit || opts->metric_description)) {
			rc = -EINVAL;
			goto err;
		}
	} else {
		st->signal = forced;
	}
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		rc = -EIO;
		goto err;
	}
	/* Explicit CLI endpoints are base URLs for the selected signal. */
	rc = configure_state(st, spec, true);
	if (rc)
		goto err_global;
	*state = st;
	return 0;

err_global:
	curl_global_cleanup();
err:
	curl_slist_free_all(st->headers);
	xfree(st, sizeof(*st));
	return rc;
}

static int otel_emit(void *state, const struct shirudo_map_view *v)
{
	struct otel_state *st = state;
	char *payload = NULL;
	size_t len = 0;
	int rc;

	if (!st || !v)
		return -EINVAL;
	if (st->signal == SHIRUDO_OTEL_LOG)
		rc = shirudo_upatch_maps_otel_build_log(v, &payload, &len);
	else
		rc = build_metric_payload(st, v, &payload, &len);
	if (rc) {
		if (st->signal == SHIRUDO_OTEL_METRIC) {
			if (rc == -E2BIG && v->truncated)
				fprintf(stderr, "otel.metric: map view is truncated; "
					"rerun with --show-full or use otel.log\n");
			else if (rc == -ENODATA || rc == -EOPNOTSUPP)
				fprintf(stderr, "otel.metric: map value is not a "
					"BTF integer scalar; use otel.log\n");
			else if (rc == -EDOM)
				fprintf(stderr, "otel.metric: counters require an "
					"unsigned value; use --metric-kind=gauge "
					"or otel.log\n");
			else if (rc == -ERANGE)
				fprintf(stderr, "otel.metric: value or per-CPU sum "
					"does not fit OTLP signed 64-bit asInt\n");
		}
		return rc;
	}
	if (!payload) {
		fprintf(stderr, "otel: metric map %s has no data points; "
			"nothing exported\n", v->name);
		return 0;
	}
	rc = otel_post(st, payload, len);
	xfree(payload, SHIRUDO_JSON_MAX_BYTES);
	return rc;
}

static int otel_close(void *state)
{
	struct otel_state *st = state;

	if (!st)
		return 0;
	curl_slist_free_all(st->headers);
	xfree(st, sizeof(*st));
	curl_global_cleanup();
	return 0;
}

int shirudo_upatch_maps_otel_send(const struct shirudo_map_view *v,
				  enum shirudo_otel_mode mode,
				  const struct shirudo_otel_opts *opts)
{
	const char *endpoint = opts ? opts->endpoint : NULL;
	bool automatic = mode == SHIRUDO_OTEL_AUTO;
	enum shirudo_otel_signal signal;
	void *state = NULL;
	int rc, close_rc;

	if (mode == SHIRUDO_OTEL_FORCE_LOG)
		signal = SHIRUDO_OTEL_LOG;
	else if (mode == SHIRUDO_OTEL_FORCE_METRIC)
		signal = SHIRUDO_OTEL_METRIC;
	else if (mode == SHIRUDO_OTEL_AUTO)
		signal = SHIRUDO_OTEL_LOG;
	else
		return -EINVAL;
	rc = otel_open_common(endpoint, v, opts, automatic, signal, &state);
	if (rc)
		return rc;
	rc = otel_emit(state, v);
	close_rc = otel_close(state);
	return rc ? rc : close_rc;
}
