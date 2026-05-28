/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * /etc/shirudo/shirudo.conf reader.
 */

#ifndef SHIRUDO_CONFIG_H
#define SHIRUDO_CONFIG_H

#include <stddef.h>

#define SHIRUDO_OWNER_AUTH_MAX	256
#define SHIRUDO_TPM_TCTI_MAX	256

struct shirudo_config {
	unsigned long	eventlog_max_bytes;	/* 0 = unlimited */
	/*
	 * Owner-hierarchy auth used to define the NV index on TPMs whose
	 * owner auth is set. Empty (len 0) = empty-password session.
	 */
	char		tpm_owner_auth[SHIRUDO_OWNER_AUTH_MAX];
	size_t		tpm_owner_auth_len;
	/*
	 * TCTI override for util/tpm.c. Empty (default) means
	 * `device:/dev/tpmrm0`. A non-empty value (e.g.
	 * `swtpm:host=127.0.0.1,port=2321`) redirects to a
	 * software TPM for dev/CI. The pre-flight skips the
	 * /dev/tpmrm0 check when the override is set. The
	 * SHIRUDO_TPM_TCTI env var overrides this in turn.
	 */
	char		tpm_tcti[SHIRUDO_TPM_TCTI_MAX];
	/*
	 * Per-target ICMP probe budget for `shirudo nodes`. Best-effort
	 * unprivileged dgram ICMP; an operator without the right
	 * net.ipv4.ping_group_range still sees the table with PING = n/a.
	 */
	unsigned int	nodes_icmp_timeout_ms;	/* default 1000 */
	unsigned int	nodes_icmp_probes;	/* default 1 */
};

/*
 * Load shirudo.conf into <cfg>, applying defaults first. A missing file
 * is not an error (defaults stand). Returns 0, or -errno on an I/O error
 * other than ENOENT.
 */
int shirudo_config_load(struct shirudo_config *cfg);

#endif /* SHIRUDO_CONFIG_H */
