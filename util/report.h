/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Per-operation JSON report for `upatch load`/`upatch unload --report`.
 * The structured input AI agents iterate on -- category/phase tell the
 * agent whether it's a policy problem or a code problem, and
 * verifier_log carries the kernel's rejection verbatim.
 */

#ifndef SHIRUDO_REPORT_H
#define SHIRUDO_REPORT_H

#include <stdbool.h>

/* The kernel verifier log can be large; PLAN.md sizes log_buf at 1 MiB. */
#define SHIRUDO_VERIFIER_LOG_MAX	(1024 * 1024)

/*
 * Phase strings (failure-report ordering):
 *   pre_flight, parse, signed_loader_load, payload_load, link_create,
 *   pin, persist, tpm_extend, done
 * Category strings: ok, tampered, keyring_missing, lsm_denied,
 *   signature_rejected, verifier_rejected, parser_rejected,
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

/* Emit r as one JSON document to path ("-" for stdout). 0 / -errno. */
int shirudo_report_emit(const char *path, const struct shirudo_op_report *r);

/* Copy a verifier log into the report (truncating to the cap). */
void shirudo_report_set_log(struct shirudo_op_report *r, const char *log);
/* Free heap-owned report fields. */
void shirudo_report_free(struct shirudo_op_report *r);

#endif /* SHIRUDO_REPORT_H */
