// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Per-operation JSON report assembly (upatch load/unload --report).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include "json.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "report.h"

int shirudo_report_emit(const char *path, const struct shirudo_op_report *r)
{
	struct shirudo_json_emit e;
	struct utsname uts;
	char nv_index[16];
	const char *errname;
	const char *vlog = r->verifier_log ? r->verifier_log : "";
	size_t loglen = strlen(vlog);
	size_t cap = loglen * 6 + 16384;	/* worst-case escape + slack */
	char *buf;
	FILE *f;
	int rc = 0;

	buf = xmalloc(cap);
	if (!buf)
		return -ENOMEM;
	e = (struct shirudo_json_emit){ .buf = buf, .cap = cap };

	snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
	errname = r->err ? strerrorname_np(r->err) : NULL;

	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_kv_string(&e, "result", r->ok ? "ok" : "failed");
	shirudo_json_kv_string(&e, "op", r->op ? r->op : "");
	shirudo_json_kv_string(&e, "phase", r->phase ? r->phase : "done");
	if (r->err)
		shirudo_json_kv_int(&e, "errno", r->err);
	else
		shirudo_json_kv_null(&e, "errno");
	if (errname)
		shirudo_json_kv_string(&e, "errno_name", errname);
	else
		shirudo_json_kv_null(&e, "errno_name");
	shirudo_json_kv_string(&e, "category", r->category ? r->category
						: (r->ok ? "ok" : "unknown"));
	shirudo_json_kv_string(&e, "message", r->message);
	shirudo_json_kv_string(&e, "verifier_log", vlog);
	shirudo_json_kv_int(&e, "loader_return", r->loader_return);

	shirudo_json_obj_open_key(&e, "upatch");
	shirudo_json_kv_string(&e, "path", r->path ? r->path : "");
	shirudo_json_kv_string(&e, "name", r->name ? r->name : "");
	shirudo_json_kv_string(&e, "payload_sha256", r->payload_hex);
	shirudo_json_obj_close(&e);

	shirudo_json_obj_open_key(&e, "kernel");
	shirudo_json_kv_string(&e, "release",
			       uname(&uts) == 0 ? uts.release : "");
	shirudo_json_obj_close(&e);

	if (r->ok && r->tpm_present) {
		shirudo_json_obj_open_key(&e, "tpm");
		shirudo_json_kv_string(&e, "nv_index", nv_index);
		shirudo_json_kv_string(&e, "chain_after", r->chain_after);
		shirudo_json_obj_close(&e);
	} else {
		shirudo_json_kv_null(&e, "tpm");
	}
	shirudo_json_obj_close(&e);

	if (e.err) {
		pr_err("report: encode failed: %s", strerror(-e.err));
		xfree(buf, cap);
		return e.err;
	}

	if (strcmp(path, "-") == 0) {
		printf("%s\n", buf);
		xfree(buf, cap);
		return 0;
	}
	f = fopen(path, "w");
	if (!f) {
		rc = -errno;
		pr_err("report: open %s: %s", path, strerror(errno));
		xfree(buf, cap);
		return rc;
	}
	fprintf(f, "%s\n", buf);
	fclose(f);
	xfree(buf, cap);
	return 0;
}

void shirudo_report_set_log(struct shirudo_op_report *r, const char *log)
{
	xstrfree(r->verifier_log);
	r->verifier_log = NULL;
	if (!log || !*log)
		return;
	/*
	 * The verifier log is kernel-provided diagnostic output -- bound
	 * the read, copy with xstrndup, and scrub on free via xstrfree.
	 */
	r->verifier_log = xstrndup(log, SHIRUDO_VERIFIER_LOG_MAX);
}

void shirudo_report_free(struct shirudo_op_report *r)
{
	xstrfree(r->verifier_log);
	r->verifier_log = NULL;
}
