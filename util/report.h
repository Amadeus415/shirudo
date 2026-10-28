/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The JSON report of `upatch load` and `unload --report`: category and
 * phase tell a policy problem from a code problem, and the verifier
 * log comes verbatim.
 */

#ifndef SHIRUDO_REPORT_H
#define SHIRUDO_REPORT_H

#include <stdbool.h>

/* Keep enough room for verbose accepted-program verifier traces. */
#define SHIRUDO_VERIFIER_LOG_MAX	(16 * 1024 * 1024)

/*
 * Phase strings (failure-report ordering):
 *   pre_flight, parse, target_verify, signed_loader_load, payload_load,
 *   link_create, pin, persist, tpm_extend, done
 * Category strings: ok, tampered, keyring_missing, kernel_abi_unsupported,
 *   version_mismatch, eventlog_full, lsm_denied, signature_rejected,
 *   signature_unsupported, verifier_rejected, parser_rejected,
 *   attach_target_missing, binary_mismatch, attach_scope_mismatch,
 *   payload_mismatch, already_unloaded, detach_failed, tpm_error,
 *   unknown.
 */
struct shirudo_op_report {
	bool		ok;
	const char	*op;		/* "upatch_load" / "upatch_unload" */
	const char	*phase;
	int		err;		/* errno (>0); 0 = none */
	const char	*category;
	char		message[256];
	char		*verifier_log;	/* heap, owned by the report; may be NULL */
	int		loader_return;
	const char	*path;
	const char	*name;
	char		payload_hex[65];
	bool		tpm_present;
	char		chain_after[65];
};

int report_emit(const char *path, const struct shirudo_op_report *r);

/*
 * What to check or run for a failure category and its errno (positive);
 * NULL when none applies.
 */
const char *report_category_hint(const char *category, int err);

void report_set_log(struct shirudo_op_report *r, const char *log);
void report_free(struct shirudo_op_report *r);

#endif /* SHIRUDO_REPORT_H */
