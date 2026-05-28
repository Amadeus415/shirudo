/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared "security-operator health" conditions block. Single source
 * of truth for the Conditions block in `shirudo nodes show` (fetched
 * over SSH) and `shirudo status` (computed locally) and any future
 * caller. Both feed in the same flat input shape; both get the same
 * verdict string and the same human-printable block out.
 */

#ifndef SHIRUDO_CONDITIONS_H
#define SHIRUDO_CONDITIONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Fields mirror the `shirudo status` JSON one-for-one. `reachable` /
 * `parsed` are meaningful only for SSH-fetched callers (nodes show);
 * `shirudo status` itself sets both to true and `unreach` to NULL.
 * The *_seen flags reflect "did the JSON carry a non-null value for
 * this nullable scalar," since the schema parser leaves them untouched
 * on null.
 */
struct shirudo_conditions_input {
	bool		reachable;
	bool		parsed;
	const char	*unreach;	/* optional reason on !reachable */

	int		lsm_attached;	/* 0/1 */
	int		keyring_present;
	int64_t		keyring_serial;
	int64_t		keyring_serial_pinned;
	int		keyring_serial_matches;	/* 0/1 if ksm_seen */
	int		ks_seen, ksp_seen, ksm_seen;
	int		chain_seen;
	int		chain_matches;		/* 0/1 if cm_seen */
	int		cm_seen;
	const char	*nv_index;
};

struct shirudo_condition {
	const char	*type;		/* "LsmAttached" / "KeyringSealed" / ... */
	const char	*status;	/* "OK" / "WARN" / "ALERT" */
	char		detail[192];
};

/*
 * Maximum number of conditions returned today (LsmAttached,
 * KeyringSealed, ChainIntact, TpmMeasured); callers can size their
 * stack array off this.
 */
#define SHIRUDO_CONDITIONS_MAX	4

/*
 * Fill `out[0..cap)` with the security-operator conditions derived
 * from `in`. Returns the number actually written (<= cap).
 */
size_t shirudo_conditions(const struct shirudo_conditions_input *in,
			  struct shirudo_condition *out, size_t cap);

/*
 * Print a `Conditions:` block in the same describe-style table the
 * rest of the project uses, with consistent column widths.
 */
void shirudo_conditions_print(const struct shirudo_condition *c, size_t n);

/*
 * Single-word aggregate verdict (severity worst -> best):
 *   unreachable -> unparseable -> tampered -> lsm-off ->
 *   init-pending -> degraded -> ok
 * Used by `shirudo nodes` STATUS column, the `Status:` line in
 * `nodes show` / `shirudo status`, and the drift-table JSON.
 */
const char *shirudo_status_verdict(const struct shirudo_conditions_input *in);

/*
 * Short reason (no surrounding parens) suitable for inlining on a
 * `Status:` line when the verdict isn't ok. Empty when ok.
 */
void shirudo_status_reason(const struct shirudo_conditions_input *in,
			   char *buf, size_t cap);

#endif /* SHIRUDO_CONDITIONS_H */
