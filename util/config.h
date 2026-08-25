/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * /etc/shirudo/shirudo.conf reader.
 */

#ifndef SHIRUDO_CONFIG_H
#define SHIRUDO_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

#define SHIRUDO_OWNER_AUTH_MAX	256
#define SHIRUDO_TPM_TCTI_MAX	256
#define SHIRUDO_MAP_EXPORT_PATH_MAX	4096
#define SHIRUDO_MAP_EXPORT_ENDPOINT_MAX	2048
#define SHIRUDO_MAP_EXPORT_URI_MAX	2048
#define SHIRUDO_MAP_EXPORT_METRIC_UNIT_MAX	64
#define SHIRUDO_MAP_EXPORT_METRIC_DESCRIPTION_MAX	256

enum shirudo_map_export_otel_mode {
	SHIRUDO_MAP_EXPORT_OTEL_OFF,
	SHIRUDO_MAP_EXPORT_OTEL_AUTO,
	SHIRUDO_MAP_EXPORT_OTEL_LOG,
	SHIRUDO_MAP_EXPORT_OTEL_METRIC,
	SHIRUDO_MAP_EXPORT_OTEL_S3,
};

enum shirudo_map_export_metric_kind {
	SHIRUDO_MAP_EXPORT_METRIC_COUNTER,
	SHIRUDO_MAP_EXPORT_METRIC_GAUGE,
};

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
	 * Per-target ICMP probe budget for `shirudo nodes`. Best-effort:
	 * unprivileged dgram ICMP, falling back to a raw socket
	 * (CAP_NET_RAW); an operator with neither still sees the table
	 * with PING = n/a.
	 */
	unsigned int	nodes_icmp_timeout_ms;	/* default 1000 */
	unsigned int	nodes_icmp_probes;	/* default 1 */
	/*
	 * Per-`shirudo nodes show <name>` display caps. Operator-side
	 * only: the operator asks the target to ship this many kernel-
	 * log records, and truncates the (unbounded) module-load list
	 * to this many rows. 0 disables the section entirely (the
	 * corresponding --include-* flag is dropped from the target's
	 * status invocation). Both default to 10; max 100.
	 */
	unsigned int	nodes_kernel_log_lines;		/* default 10, 0=off */
	unsigned int	nodes_module_loads_lines;	/* default 10, 0=off */
	/*
	 * Periodic `shirudo upatch map --all` export settings. Empty JSON
	 * path plus OTEL_OFF is an intentionally idle configuration.
	 */
	bool		map_export_valid;
	char		map_export_json_path[SHIRUDO_MAP_EXPORT_PATH_MAX];
	enum shirudo_map_export_otel_mode map_export_otel_mode;
	char		map_export_otel_endpoint[SHIRUDO_MAP_EXPORT_ENDPOINT_MAX];
	bool		map_export_otel_insecure;
	unsigned int	map_export_otel_retries;
	char		map_export_s3_uri[SHIRUDO_MAP_EXPORT_URI_MAX];
	bool		map_export_show_full;
	enum shirudo_map_export_metric_kind map_export_metric_kind;
	char		map_export_metric_unit[SHIRUDO_MAP_EXPORT_METRIC_UNIT_MAX];
	char		map_export_metric_description[
			SHIRUDO_MAP_EXPORT_METRIC_DESCRIPTION_MAX];
};

#define SHIRUDO_NODES_RECENT_MAX	100

/*
 * Load shirudo.conf into <cfg>, applying defaults first. A missing file
 * is not an error (defaults stand). Returns 0, or -errno on an I/O error
 * other than ENOENT.
 */
int shirudo_config_load(struct shirudo_config *cfg);

/* Testable path-specific loader; unlike shirudo_config_load(), no env. */
int shirudo_config_load_path(struct shirudo_config *cfg, const char *path);

#endif /* SHIRUDO_CONFIG_H */
