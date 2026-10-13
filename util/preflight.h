/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Pre-flight infrastructure-prerequisite gate for `shirudo init`.
 */

#ifndef SHIRUDO_PREFLIGHT_H
#define SHIRUDO_PREFLIGHT_H

#include <stdbool.h>

#define SHIRUDO_PREFLIGHT_DETAIL_MAX	256

enum shirudo_preflight_id {
	SHIRUDO_PRE_ROOT,
	SHIRUDO_PRE_BPF_LSM,
	SHIRUDO_PRE_BPFFS,
	SHIRUDO_PRE_SIGNED_LOADER_ABI,
	SHIRUDO_PRE_CERT_ON_DISK,
	SHIRUDO_PRE_CERT_KERNEL_ALGO,
	SHIRUDO_PRE_KEYRING,
	SHIRUDO_PRE_EMBEDDED_LOADER,
	SHIRUDO_PRE_TPM,
	SHIRUDO_PRE__MAX,
};

struct shirudo_preflight_check {
	enum shirudo_preflight_id	id;
	const char			*name;
	bool				ok;
	char				detail[SHIRUDO_PREFLIGHT_DETAIL_MAX];
};

struct shirudo_preflight_result {
	struct shirudo_preflight_check	checks[SHIRUDO_PRE__MAX];
	int				n;
	int				n_failed;
};

struct shirudo_preflight_opts {
	bool	allow_no_tpm;
};

/*
 * Run every prerequisite check. All checks always run; n_failed is
 * the total number of failures. The function does not write to
 * stdout/stderr/syslog -- the caller presents the outcome.
 */
void shirudo_preflight_run(const struct shirudo_preflight_opts *opts,
			   struct shirudo_preflight_result *out);

#endif /* SHIRUDO_PREFLIGHT_H */
