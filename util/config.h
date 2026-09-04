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

#include "tenant_id.h"

#define SHIRUDO_OWNER_AUTH_MAX	256
#define SHIRUDO_TPM_TCTI_MAX	256
#define SHIRUDO_MAP_EXPORT_PATH_MAX	4096
#define SHIRUDO_MAP_EXPORT_ENDPOINT_MAX	2048
#define SHIRUDO_MAP_EXPORT_URI_MAX	2048
#define SHIRUDO_MAP_EXPORT_LOG_RECORD_MAX_DEFAULT	(1u * 1024u * 1024u)
#define SHIRUDO_MAP_EXPORT_OTLP_MAX_DEFAULT		(4u * 1024u * 1024u)

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
	 * Periodic `shirudo upatch map --all` export settings. Empty sinks
	 * are intentionally idle.
	 */
	bool		map_export_valid;
	char		map_export_json_path[SHIRUDO_MAP_EXPORT_PATH_MAX];
	char		map_export_otel_endpoint[SHIRUDO_MAP_EXPORT_ENDPOINT_MAX];
	char		map_export_tenant_id[SHIRUDO_TENANT_ID_MAX + 1];
	bool		map_export_otel_insecure;
	unsigned int	map_export_otel_retries;
	char		map_export_s3_uri[SHIRUDO_MAP_EXPORT_URI_MAX];
	unsigned int	map_export_log_record_max_bytes;
	unsigned int	map_export_otlp_max_bytes;
};

/*
 * Load shirudo.conf into <cfg>, applying defaults first. A missing file
 * is not an error (defaults stand). Returns 0, or -errno on an I/O error
 * other than ENOENT.
 */
int shirudo_config_load(struct shirudo_config *cfg);

/* Testable path-specific loader; unlike shirudo_config_load(), no env. */
int shirudo_config_load_path(struct shirudo_config *cfg, const char *path);

#endif /* SHIRUDO_CONFIG_H */
