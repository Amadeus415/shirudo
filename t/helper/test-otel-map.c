// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>
#include <linux/btf.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "json.h"
#include "malloc.h"
#include "upatch_maps.h"
#include "upatch_maps_otel.h"

const char shirudo_version[] = "test-1";

struct fixture {
	struct shirudo_map_view view;
	struct shirudo_map_entry entry;
	struct btf *btf;
	uint32_t key;
	unsigned char values[16];
};

static int fixture_init(struct fixture *f, uint32_t map_type, bool is_signed,
			bool with_btf)
{
	int key_int, value_int, key_type, value_type;
	uint32_t cpu0 = 5, cpu1 = 7, poison = 0xdeadbeef;

	memset(f, 0, sizeof(*f));
	snprintf(f->view.upatch, sizeof(f->view.upatch), "test-upatch");
	snprintf(f->view.name, sizeof(f->view.name), "hits_total");
	f->view.type = map_type;
	f->view.type_name = map_type == BPF_MAP_TYPE_ARRAY ? "array" :
		"percpu_array";
	f->view.key_size = 4;
	f->view.value_size = 4;
	f->view.value_stride = map_type == BPF_MAP_TYPE_ARRAY ? 4 : 8;
	f->view.max_entries = 1;
	f->view.n_entries = 1;
	f->view.n_cpus = map_type == BPF_MAP_TYPE_ARRAY ? 1 : 2;
	f->view.lifetime_start_ns = 1544712660300000000ULL;
	f->entry.key = &f->key;
	f->entry.value = f->values;
	f->view.entries = &f->entry;
	memcpy(f->values, &cpu0, 4);
	memcpy(f->values + 4, &poison, 4);
	memcpy(f->values + 8, &cpu1, 4);
	if (!with_btf)
		return 0;
	f->btf = btf__new_empty();
	if (libbpf_get_error(f->btf))
		return -ENOMEM;
	key_int = btf__add_int(f->btf, "unsigned int", 4, 0);
	value_int = btf__add_int(f->btf,
		is_signed ? "int" : "unsigned int", 4,
		is_signed ? BTF_INT_SIGNED : 0);
	key_type = btf__add_typedef(f->btf, "__u32", key_int);
	value_type = btf__add_typedef(f->btf,
		is_signed ? "__s32" : "__u32", value_int);
	if (key_int < 0 || value_int < 0 || key_type < 0 || value_type < 0)
		return -EINVAL;
	f->view.btf = f->btf;
	f->view.key_type_id = (uint32_t)key_type;
	f->view.value_type_id = (uint32_t)value_type;
	snprintf(f->view.btf_key_type, sizeof(f->view.btf_key_type), "__u32");
	snprintf(f->view.btf_value_type, sizeof(f->view.btf_value_type), "%s",
		is_signed ? "__s32" : "__u32");
	return 0;
}

static void fixture_destroy(struct fixture *f)
{
	btf__free(f->btf);
}

static int print_classification(uint32_t type, bool is_signed, bool with_btf,
				bool serialized)
{
	struct fixture f;
	enum shirudo_otel_signal signal;
	char reason[160];
	int rc = fixture_init(&f, type, is_signed, with_btf);

	if (rc)
		return 1;
	f.view.serialized = serialized;
	rc = shirudo_upatch_maps_otel_classify(&f.view, &signal, reason,
					       sizeof(reason));
	if (!rc)
		printf("%s:%s\n", signal == SHIRUDO_OTEL_METRIC ?
		       "metric" : "log", reason);
	fixture_destroy(&f);
	return rc != 0;
}

static int print_payload(bool metric, bool counter)
{
	struct shirudo_otel_opts opts = {
		.metric_kind = counter ? SHIRUDO_OTEL_METRIC_COUNTER :
			SHIRUDO_OTEL_METRIC_GAUGE,
		.metric_kind_set = true,
		.metric_name = "shirudo.test.hits",
		.metric_unit = "1",
	};
	struct fixture f;
	char *buf = NULL;
	size_t len = 0;
	int rc = fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true);

	if (rc)
		return 1;
	rc = metric ? shirudo_upatch_maps_otel_build_metric(&f.view, &opts,
			&buf, &len) :
		shirudo_upatch_maps_otel_build_log(&f.view, &buf, &len);
	if (!rc && buf)
		fwrite(buf, 1, len, stdout);
	if (buf)
		xfree(buf, SHIRUDO_JSON_MAX_BYTES);
	fixture_destroy(&f);
	return rc != 0;
}

static int print_local_json(void)
{
	struct fixture f;
	struct shirudo_json_emit e = {};
	char buf[4096];

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true))
		return 1;
	e.buf = buf;
	e.cap = sizeof(buf);
	shirudo_json_obj_open(&e);
	shirudo_upatch_maps_emit_json_fields(&e, &f.view);
	shirudo_json_obj_close(&e);
	if (!e.err)
		printf("%s", buf);
	fixture_destroy(&f);
	return e.err != 0;
}

static int metric_validation_errors(void)
{
	struct shirudo_otel_opts gauge = {
		.metric_kind = SHIRUDO_OTEL_METRIC_GAUGE,
	};
	struct shirudo_otel_opts counter = {
		.metric_kind = SHIRUDO_OTEL_METRIC_COUNTER,
	};
	struct fixture f;
	char *buf = NULL;
	size_t len = 0;
	int rc;

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true))
		return 1;
	f.view.truncated = true;
	rc = shirudo_upatch_maps_otel_build_metric(&f.view, &gauge, &buf, &len);
	fixture_destroy(&f);
	if (rc != -E2BIG)
		return 1;
	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, true, true))
		return 1;
	rc = shirudo_upatch_maps_otel_build_metric(&f.view, &counter,
						   &buf, &len);
	fixture_destroy(&f);
	if (rc != -EDOM)
		return 1;
	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true))
		return 1;
	f.view.n_entries = 0;
	rc = shirudo_upatch_maps_otel_build_metric(&f.view, &gauge, &buf, &len);
	fixture_destroy(&f);
	return rc != 0 || buf != NULL || len != 0;
}

static int send_log(const char *url, unsigned int retries, bool insecure)
{
	struct shirudo_otel_opts opts = {
		.endpoint = url,
		.allow_insecure = insecure,
		.retries = retries,
	};
	struct fixture f;
	int rc;

	rc = fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true);
	if (rc)
		return 1;
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_FORCE_LOG,
					   &opts);
	fixture_destroy(&f);
	return rc ? 1 : 0;
}

static int send_auto(const char *base, bool is_signed)
{
	struct shirudo_otel_opts opts = { .endpoint = base, .retries = 0 };
	struct fixture f;
	int rc;

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, is_signed, true))
		return 1;
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_AUTO,
					   &opts);
	fixture_destroy(&f);
	return rc ? 1 : 0;
}

static int send_metric(const char *url)
{
	struct shirudo_otel_opts opts = {
		.endpoint = url,
		.retries = 0,
		.metric_kind = SHIRUDO_OTEL_METRIC_GAUGE,
		.metric_kind_set = true,
	};
	struct fixture f;
	int rc;

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true))
		return 1;
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_FORCE_METRIC,
					   &opts);
	fixture_destroy(&f);
	return rc ? 1 : 0;
}

static bool large_serialized_fixture(struct fixture *f)
{
	const uint32_t pages = 9;
	const uint32_t bytes = 512U * 1024U;

	f->view.serialized = true;
	f->view.n_entries = 0;
	f->view.n_serial_pages = pages;
	f->view.serial_bytes_total = (uint64_t)pages * bytes;
	f->view.serial_pages = xcalloc(pages, sizeof(*f->view.serial_pages));
	if (!f->view.serial_pages)
		return false;
	for (uint32_t i = 0; i < pages; i++) {
		struct shirudo_serial_page *page = &f->view.serial_pages[i];

		page->page_index = i;
		page->cursor = i;
		page->next_cursor = i + 1;
		page->done = i + 1 == pages;
		page->flags = page->done ? 1 : 0;
		page->chunks = 128;
		page->bytes = bytes;
		page->data = xmalloc(bytes);
		if (!page->data)
			return false;
		memset(page->data, (int)('A' + i), bytes);
	}
	return true;
}

static void large_serialized_destroy(struct fixture *f)
{
	if (!f->view.serial_pages)
		return;
	for (uint32_t i = 0; i < f->view.n_serial_pages; i++)
		xfree(f->view.serial_pages[i].data,
		      f->view.serial_pages[i].bytes);
	xfree(f->view.serial_pages,
	      f->view.n_serial_pages * sizeof(*f->view.serial_pages));
	f->view.serial_pages = NULL;
}

static int send_s3(const char *endpoint, unsigned int retries, bool large)
{
	struct shirudo_otel_opts opts = {
		.s3_uri = "s3://test-bucket/prefix",
		.retries = retries,
	};
	struct fixture f;
	int rc;

	if (setenv("AWS_ENDPOINT_URL_S3", endpoint, 1) != 0)
		return 1;
	rc = fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true);
	if (rc)
		return 1;
	if (large) {
		if (!large_serialized_fixture(&f)) {
			large_serialized_destroy(&f);
			fixture_destroy(&f);
			return 1;
		}
	}
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	large_serialized_destroy(&f);
	fixture_destroy(&f);
	return rc ? 1 : 0;
}

static int s3_validation(void)
{
	struct shirudo_otel_opts opts = {
		.s3_uri = "s3://test-bucket/prefix",
		.retries = 0,
	};
	struct fixture f;
	int rc;

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true))
		return 1;
	setenv("AWS_ENDPOINT_URL_S3", "http://127.0.0.1:1", 1);
	unsetenv("AWS_ACCESS_KEY_ID");
	unsetenv("AWS_SECRET_ACCESS_KEY");
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	if (rc != -EACCES)
		goto fail;
	setenv("AWS_ACCESS_KEY_ID", "test", 1);
	setenv("AWS_SECRET_ACCESS_KEY", "secret", 1);
	opts.s3_uri = "s3://BAD_BUCKET/prefix";
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	if (rc != -EINVAL)
		goto fail;
	opts.s3_uri = "s3://test-bucket/prefix";
	f.view.truncated = true;
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	f.view.truncated = false;
	if (rc != -E2BIG)
		goto fail;
	f.view.skipped = true;
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	f.view.skipped = false;
	if (rc != -EOPNOTSUPP)
		goto fail;
	setenv("AWS_ENDPOINT_URL_S3", "http://storage.example", 1);
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_S3, &opts);
	if (rc != -EPERM)
		goto fail;
	fixture_destroy(&f);
	return 0;
fail:
	fixture_destroy(&f);
	return 1;
}

static int security_check(void)
{
	struct shirudo_otel_opts opts = {
		.endpoint = "http://collector.example",
		.retries = 0,
	};
	struct fixture f;
	int rc;

	if (fixture_init(&f, BPF_MAP_TYPE_PERCPU_ARRAY, false, true))
		return 1;
	rc = shirudo_upatch_maps_otel_send(&f.view, SHIRUDO_OTEL_FORCE_LOG,
					   &opts);
	fixture_destroy(&f);
	return rc != -EPERM;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 2;
	if (strcmp(argv[1], "classify-unsigned") == 0)
		return print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, false,
					    true, false);
	if (strcmp(argv[1], "classify-signed") == 0)
		return print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, true,
					    true, false);
	if (strcmp(argv[1], "classify-array") == 0)
		return print_classification(BPF_MAP_TYPE_ARRAY, false, true,
					    false);
	if (strcmp(argv[1], "classify-hash") == 0)
		return print_classification(BPF_MAP_TYPE_PERCPU_HASH, false, true,
					    false);
	if (strcmp(argv[1], "classify-lru-hash") == 0)
		return print_classification(BPF_MAP_TYPE_LRU_PERCPU_HASH, false,
					    true, false);
	if (strcmp(argv[1], "classify-no-btf") == 0)
		return print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, false,
					    false, false);
	if (strcmp(argv[1], "classify-serialized") == 0)
		return print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, false,
					    true, true);
	if (strcmp(argv[1], "log") == 0)
		return print_payload(false, false);
	if (strcmp(argv[1], "metric") == 0)
		return print_payload(true, false);
	if (strcmp(argv[1], "counter") == 0)
		return print_payload(true, true);
	if (strcmp(argv[1], "local-json") == 0)
		return print_local_json();
	if (strcmp(argv[1], "metric-errors") == 0)
		return metric_validation_errors();
	if (strcmp(argv[1], "send-log") == 0 && argc == 4)
		return send_log(argv[2], (unsigned int)strtoul(argv[3], NULL, 10),
				false);
	if (strcmp(argv[1], "send-log-insecure") == 0 && argc == 4)
		return send_log(argv[2], (unsigned int)strtoul(argv[3], NULL, 10),
				true);
	if (strcmp(argv[1], "send-auto-log") == 0 && argc == 3)
		return send_auto(argv[2], true);
	if (strcmp(argv[1], "send-auto-metric") == 0 && argc == 3)
		return send_auto(argv[2], false);
	if (strcmp(argv[1], "send-metric") == 0 && argc == 3)
		return send_metric(argv[2]);
	if (strcmp(argv[1], "send-s3") == 0 && argc == 4)
		return send_s3(argv[2],
			(unsigned int)strtoul(argv[3], NULL, 10), false);
	if (strcmp(argv[1], "send-s3-large") == 0 && argc == 4)
		return send_s3(argv[2],
			(unsigned int)strtoul(argv[3], NULL, 10), true);
	if (strcmp(argv[1], "s3-validation") == 0)
		return s3_validation();
	if (strcmp(argv[1], "security") == 0)
		return security_check();
	return 2;
}
