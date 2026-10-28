// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Per-operation JSON report assembly (upatch load/unload --report).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "io.h"
#include "json.h"
#include "log.h"
#include "macros.h"
#include "malloc.h"
#include "paths.h"
#include "report.h"
#include "seal.h"

/*
 * One source for the hint a failed `upatch load` or `unload` prints and
 * the one its report carries, kept in step with the categories table of
 * Documentation/operations.rst.
 */
static const struct {
	const char	*category;
	const char	*hint;
} category_hints[] = {
	{
		.category = "tampered",
		.hint = "shirudo considers this node tampered: do not retry or work around it, keep the eventlog and journal as evidence and handle it as an incident",
	},
	{
		.category = "keyring_missing",
		.hint = "shirudo init has not set up the trust anchor this boot: run `shirudo init --check-only` and read `journalctl -b -u shirudo-initrd.service -u shirudo.service`",
	},
	{
		.category = "kernel_abi_unsupported",
		.hint = "this kernel cannot load signed BPF programs, or not with the attach type this upatch uses: boot a newer kernel; `shirudo init --check-only` shows what is missing",
	},
	{
		.category = "version_mismatch",
		.hint = "operator and target run different shirudo builds: compare `shirudo version` on both and deploy matching builds",
	},
	{
		.category = "eventlog_full",
		.hint = "the eventlog has reached its eventlog.max_bytes limit: archive it and raise the limit in the signed config",
	},
	{
		.category = "parser_rejected",
		.hint = "the file is not a valid upatch for this shirudo version, or its name is unsafe: check it with `shirudo upatch info <file>` and rebuild it with `shirudo build`",
	},
	{
		.category = "signature_rejected",
		.hint = "the kernel rejected the signature: the upatch was signed with a key this node does not trust, or was modified after signing; `shirudo status` lists the trusted certificates",
	},
	{
		.category = "signature_unsupported",
		.hint = "the kernel cannot verify ML-DSA-87 signatures: boot a kernel with CONFIG_CRYPTO_MLDSA and CONFIG_CRYPTO_SHA512",
	},
	{
		.category = "lsm_denied",
		.hint = "the shirudo LSM refused this process: run the authenticated binary /run/shirudo/runtime/usr/bin/shirudo as root; `shirudo status` shows which tamper counter went up",
	},
	{
		.category = "verifier_rejected",
		.hint = "the BPF verifier rejected the program: read its log above or with `--report=-`, and rebuild the upatch against this kernel's BTF",
	},
	{
		.category = "attach_target_missing",
		.hint = "the function, tracepoint, module or binary this upatch attaches to does not exist on this host: load the module or install the binary, or do not deploy the upatch here",
	},
	{
		.category = "binary_mismatch",
		.hint = "the binary the uprobe attaches to is not the build the upatch was made for: rebuild the upatch against the installed binary",
	},
	{
		.category = "attach_scope_mismatch",
		.hint = "the kernel attached the program somewhere other than the upatch declares, so the load was refused: rebuild the upatch",
	},
	{
		.category = "payload_mismatch",
		.hint = "the unload directive is for a different payload than the one loaded: build it for the payload-sha256 that `shirudo upatch list` shows",
	},
	{
		.category = "detach_failed",
		.hint = "the unload was recorded in the TPM but the upatch is still attached: run the same unload again and check the journal for the cause",
	},
	{
		.category = "tpm_error",
		.hint = "the TPM register could not be updated: check /dev/tpmrm0, tpm.tcti and tpm.owner_auth, and run `shirudo status` before the next operation",
	},
	{
		.category = "unknown",
		.hint = "see the errno and message above, or the full report with `--report=-`",
	},
};

const char *report_category_hint(const char *category, int err)
{
	size_t i;

	if (!category)
		return NULL;
	/* parser_rejected also covers a file that could not be read at all. */
	if (!strcmp(category, "parser_rejected") &&
	    (err == ENOENT || err == EACCES || err == EISDIR))
		return "the .upatch file could not be read: check its path and permissions";
	for (i = 0; i < ARRAY_SIZE(category_hints); i++) {
		if (!strcmp(category_hints[i].category, category))
			return category_hints[i].hint;
	}
	return NULL;
}

int report_emit(const char *path, const struct shirudo_op_report *r)
{
	struct shirudo_json_emit e;
	struct utsname uts;
	char nv_index[16];
	const char *errname;
	const char *vlog = r->verifier_log ? r->verifier_log : "";
	const char *category, *hint;
	size_t loglen = strlen(vlog);
	size_t cap = loglen * 6 + 16384;	/* worst-case escape + slack */
	int fd, rc = 0;
	char *buf;

	if (strsprintf(nv_index, sizeof(nv_index), "0x%08X",
		       SHIRUDO_NV_INDEX) < 0)
		return -E2BIG;
	buf = xmalloc(cap);
	if (!buf)
		return -ENOMEM;
	e = (struct shirudo_json_emit){ .buf = buf, .cap = cap };

	errname = r->err ? strerrorname_np(r->err) : NULL;
	category = r->category ? r->category : (r->ok ? "ok" : "unknown");
	hint = r->ok ? NULL : report_category_hint(category, r->err);

	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_string(&e, "result", r->ok ? "ok" : "failed");
	json_kv_string(&e, "op", r->op ? r->op : "");
	json_kv_string(&e, "phase", r->phase ? r->phase : "done");
	if (r->err)
		json_kv_int(&e, "errno", r->err);
	else
		json_kv_null(&e, "errno");
	if (errname)
		json_kv_string(&e, "errno_name", errname);
	else
		json_kv_null(&e, "errno_name");
	json_kv_string(&e, "category", category);
	json_kv_string(&e, "message", r->message);
	if (hint)
		json_kv_string(&e, "hint", hint);
	else
		json_kv_null(&e, "hint");
	json_kv_string(&e, "verifier_log", vlog);
	json_kv_int(&e, "loader_return", r->loader_return);

	json_obj_open_key(&e, "upatch");
	json_kv_string(&e, "path", r->path ? r->path : "");
	json_kv_string(&e, "name", r->name ? r->name : "");
	json_kv_string(&e, "payload_sha256", r->payload_hex);
	json_obj_close(&e);

	json_obj_open_key(&e, "kernel");
	json_kv_string(&e, "release",
		       uname(&uts) == 0 ? uts.release : "");
	json_obj_close(&e);

	if (r->ok && r->tpm_present) {
		json_obj_open_key(&e, "tpm");
		json_kv_string(&e, "nv_index", nv_index);
		json_kv_string(&e, "chain_after", r->chain_after);
		json_obj_close(&e);
	} else {
		json_kv_null(&e, "tpm");
	}
	json_obj_close(&e);

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
	fd = seal_output_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_err("report: open %s: %s", path, strerror(-fd));
		xfree(buf, cap);
		return fd;
	}
	rc = write_complete(fd, buf, strlen(buf));
	if (!rc)
		rc = write_complete(fd, "\n", 1);
	if (close(fd) != 0 && !rc)
		rc = -errno;
	if (rc) {
		pr_err("report: write %s: %s", path, strerror(-rc));
		unlink(path);
	}
	xfree(buf, cap);
	return rc;
}

void report_set_log(struct shirudo_op_report *r, const char *log)
{
	if (!r)
		return;
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

void report_free(struct shirudo_op_report *r)
{
	xstrfree(r->verifier_log);
	r->verifier_log = NULL;
}
