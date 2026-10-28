/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Pre-flight infrastructure-prerequisite gate for `shirudo init`.
 */

#ifndef SHIRUDO_PREFLIGHT_H
#define SHIRUDO_PREFLIGHT_H

#include <stdbool.h>

#define SHIRUDO_PREFLIGHT_DETAIL_MAX	512

enum shirudo_preflight_id {
	SHIRUDO_PRE_ROOT,
	SHIRUDO_PRE_BPF_LSM,
	SHIRUDO_PRE_BPFFS,
	SHIRUDO_PRE_SIGNED_LOADER_ABI,
	SHIRUDO_PRE_CERT_ON_DISK,
	SHIRUDO_PRE_CERT_ALGORITHM,
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

/*
 * Every check runs and every one is hard: no opt-out for a missing TPM
 * or a classical certificate. Nothing is printed; the caller presents
 * the outcome.
 */
void preflight_run(struct shirudo_preflight_result *out);

#endif /* SHIRUDO_PREFLIGHT_H */
