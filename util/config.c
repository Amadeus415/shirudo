// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Minimal shirudo.conf reader: `key = value` lines, '#' comments,
 * dotted keys. No third-party parser -- the config surface is tiny.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "log.h"
#include "paths.h"

static char *trim(char *s)
{
	char *e;

	while (*s == ' ' || *s == '\t')
		s++;
	e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' ||
			 e[-1] == '\n' || e[-1] == '\r'))
		*--e = '\0';
	return s;
}

static void map_export_bad(struct shirudo_config *cfg, const char *key,
			   const char *val, const char *reason)
{
	cfg->map_export_valid = false;
	pr_warn("config: %s: bad value '%s' (%s)", key, val, reason);
}

static bool parse_bool(const char *val, bool *out)
{
	if (strcmp(val, "true") == 0) {
		*out = true;
		return true;
	}
	if (strcmp(val, "false") == 0) {
		*out = false;
		return true;
	}
	return false;
}

static bool set_string(char *dst, size_t cap, const char *val)
{
	if (strlen(val) >= cap)
		return false;
	snprintf(dst, cap, "%s", val);
	return true;
}

static bool parse_otel_mode(const char *val,
			    enum shirudo_map_export_otel_mode *out)
{
	if (strcmp(val, "off") == 0)
		*out = SHIRUDO_MAP_EXPORT_OTEL_OFF;
	else if (strcmp(val, "auto") == 0)
		*out = SHIRUDO_MAP_EXPORT_OTEL_AUTO;
	else if (strcmp(val, "log") == 0)
		*out = SHIRUDO_MAP_EXPORT_OTEL_LOG;
	else if (strcmp(val, "metric") == 0)
		*out = SHIRUDO_MAP_EXPORT_OTEL_METRIC;
	else if (strcmp(val, "s3") == 0)
		*out = SHIRUDO_MAP_EXPORT_OTEL_S3;
	else
		return false;
	return true;
}

static bool parse_metric_kind(const char *val,
			      enum shirudo_map_export_metric_kind *out)
{
	if (strcmp(val, "counter") == 0)
		*out = SHIRUDO_MAP_EXPORT_METRIC_COUNTER;
	else if (strcmp(val, "gauge") == 0)
		*out = SHIRUDO_MAP_EXPORT_METRIC_GAUGE;
	else
		return false;
	return true;
}

static void config_defaults(struct shirudo_config *cfg)
{
	*cfg = (struct shirudo_config){};
	cfg->nodes_icmp_timeout_ms = 1000;
	cfg->nodes_icmp_probes = 1;
	cfg->nodes_kernel_log_lines = 10;
	cfg->nodes_module_loads_lines = 10;
	cfg->map_export_valid = true;
	cfg->map_export_otel_mode = SHIRUDO_MAP_EXPORT_OTEL_OFF;
	cfg->map_export_otel_retries = 3;
	cfg->map_export_metric_kind = SHIRUDO_MAP_EXPORT_METRIC_COUNTER;
	snprintf(cfg->map_export_metric_unit,
		 sizeof(cfg->map_export_metric_unit), "1");
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/*
 * Owner auth is a literal passphrase, or "hex:<even hex>" for a binary
 * auth value (what provisioning tools that randomise owner auth emit).
 */
static void set_owner_auth(struct shirudo_config *cfg, const char *val)
{
	size_t l;

	if (strncmp(val, "hex:", 4) == 0) {
		const char *h = val + 4;
		size_t hl = strlen(h), i;

		if (hl % 2 || hl / 2 > sizeof(cfg->tpm_owner_auth)) {
			pr_warn("config: tpm.owner_auth: bad hex length "
				"(ignored)");
			return;
		}
		for (i = 0; i < hl / 2; i++) {
			int hi = hexval(h[2 * i]), lo = hexval(h[2 * i + 1]);

			if (hi < 0 || lo < 0) {
				pr_warn("config: tpm.owner_auth: bad hex "
					"(ignored)");
				return;
			}
			cfg->tpm_owner_auth[i] = (char)((hi << 4) | lo);
		}
		cfg->tpm_owner_auth_len = hl / 2;
		return;
	}

	l = strlen(val);
	if (l > sizeof(cfg->tpm_owner_auth)) {
		pr_warn("config: tpm.owner_auth too long (ignored)");
		return;
	}
	memcpy(cfg->tpm_owner_auth, val, l);
	cfg->tpm_owner_auth_len = l;
}

int shirudo_config_load_path(struct shirudo_config *cfg, const char *path)
{
	char line[1024];
	int rc = 0;
	FILE *f;

	if (!cfg || !path)
		return -EINVAL;
	config_defaults(cfg);

	f = fopen(path, "r");
	if (!f) {
		if (errno != ENOENT)
			rc = -errno;	/* still apply env override below */
	} else {
		while (fgets(line, sizeof(line), f)) {
			char *p = trim(line), *eq, *key, *val;

			if (*p == '\0' || *p == '#')
				continue;
			eq = strchr(p, '=');
			if (!eq)
				continue;
			*eq = '\0';
			key = trim(p);
			val = trim(eq + 1);
			if (strcmp(key, "eventlog.max_bytes") == 0) {
				unsigned long v;
				char *end;

				v = strtoul(val, &end, 0);
				if (*end != '\0')
					pr_warn("config: eventlog.max_bytes: "
						"bad value '%s' (ignored)", val);
				else
					cfg->eventlog_max_bytes = v;
			} else if (strcmp(key, "tpm.owner_auth") == 0) {
				set_owner_auth(cfg, val);
			} else if (strcmp(key, "tpm.tcti") == 0) {
				size_t l = strlen(val);

				if (l >= sizeof(cfg->tpm_tcti))
					pr_warn("config: tpm.tcti too long "
						"(ignored)");
				else
					snprintf(cfg->tpm_tcti,
						 sizeof(cfg->tpm_tcti),
						 "%s", val);
			} else if (strcmp(key, "nodes.icmp_timeout_ms") == 0) {
				unsigned long v;
				char *end;

				v = strtoul(val, &end, 0);
				if (*end != '\0' || v > UINT_MAX)
					pr_warn("config: nodes.icmp_timeout_ms:"
						" bad value '%s' (ignored)",
						val);
				else
					cfg->nodes_icmp_timeout_ms =
						(unsigned int)v;
			} else if (strcmp(key, "nodes.icmp_probes") == 0) {
				unsigned long v;
				char *end;

				v = strtoul(val, &end, 0);
				if (*end != '\0' || v > 16)
					pr_warn("config: nodes.icmp_probes:"
						" bad value '%s' (ignored;"
						" must be 0..16, 0=disabled)",
						val);
				else
					cfg->nodes_icmp_probes = (unsigned int)v;
			} else if (strcmp(key, "nodes.kernel_log_lines") == 0) {
				unsigned long v;
				char *end;

				v = strtoul(val, &end, 0);
				if (*end != '\0' ||
				    v > SHIRUDO_NODES_RECENT_MAX)
					pr_warn("config: nodes.kernel_log_lines:"
						" bad value '%s' (ignored;"
						" must be 0..%d, 0=disabled)",
						val, SHIRUDO_NODES_RECENT_MAX);
				else
					cfg->nodes_kernel_log_lines =
						(unsigned int)v;
			} else if (strcmp(key, "nodes.module_loads_lines") == 0) {
				unsigned long v;
				char *end;

				v = strtoul(val, &end, 0);
				if (*end != '\0' ||
				    v > SHIRUDO_NODES_RECENT_MAX)
					pr_warn("config: nodes.module_loads_lines:"
						" bad value '%s' (ignored;"
						" must be 0..%d, 0=disabled)",
						val, SHIRUDO_NODES_RECENT_MAX);
				else
					cfg->nodes_module_loads_lines =
						(unsigned int)v;
			} else if (strcmp(key, "map_export.json_path") == 0) {
				if (!set_string(cfg->map_export_json_path,
						sizeof(cfg->map_export_json_path), val))
					map_export_bad(cfg, key, val, "value too long");
				else if (val[0] && val[0] != '/')
					map_export_bad(cfg, key, val,
							"path must be absolute");
			} else if (strcmp(key, "map_export.otel_mode") == 0) {
				if (!parse_otel_mode(val,
						     &cfg->map_export_otel_mode))
					map_export_bad(cfg, key, val,
							"expected off, auto, log, metric, or s3");
			} else if (strcmp(key, "map_export.otel_endpoint") == 0) {
				if (!set_string(cfg->map_export_otel_endpoint,
						sizeof(cfg->map_export_otel_endpoint), val))
					map_export_bad(cfg, key, val, "value too long");
			} else if (strcmp(key, "map_export.otel_insecure") == 0) {
				if (!parse_bool(val,
						&cfg->map_export_otel_insecure))
					map_export_bad(cfg, key, val,
							"expected true or false");
			} else if (strcmp(key, "map_export.otel_retries") == 0) {
				unsigned long v;
				char *end;

				errno = 0;
				v = strtoul(val, &end, 10);
				if (errno || *end || v > 10)
					map_export_bad(cfg, key, val,
							"expected 0..10");
				else
					cfg->map_export_otel_retries =
						(unsigned int)v;
			} else if (strcmp(key, "map_export.s3_uri") == 0) {
				if (!set_string(cfg->map_export_s3_uri,
						sizeof(cfg->map_export_s3_uri), val))
					map_export_bad(cfg, key, val, "value too long");
			} else if (strcmp(key, "map_export.show_full") == 0) {
				if (!parse_bool(val, &cfg->map_export_show_full))
					map_export_bad(cfg, key, val,
							"expected true or false");
			} else if (strcmp(key, "map_export.metric_kind") == 0) {
				if (!parse_metric_kind(val,
						       &cfg->map_export_metric_kind))
					map_export_bad(cfg, key, val,
							"expected counter or gauge");
			} else if (strcmp(key, "map_export.metric_unit") == 0) {
				if (!val[0] ||
				    !set_string(cfg->map_export_metric_unit,
						 sizeof(cfg->map_export_metric_unit), val))
					map_export_bad(cfg, key, val,
							"expected a non-empty unit");
			} else if (strcmp(key,
					  "map_export.metric_description") == 0) {
				if (!set_string(cfg->map_export_metric_description,
						sizeof(cfg->map_export_metric_description),
						val))
					map_export_bad(cfg, key, val, "value too long");
			} else {
				if (strncmp(key, "map_export.", 11) == 0)
					map_export_bad(cfg, key, val, "unknown key");
				else
					pr_warn("config: unknown key '%s' (ignored)",
						key);
			}
		}
		fclose(f);
	}
	if (cfg->map_export_otel_mode == SHIRUDO_MAP_EXPORT_OTEL_S3 &&
	    !cfg->map_export_s3_uri[0])
		map_export_bad(cfg, "map_export.s3_uri", "",
			       "required when otel_mode is s3");
	return rc;
}

int shirudo_config_load(struct shirudo_config *cfg)
{
	const char *env;
	int rc;

	rc = shirudo_config_load_path(cfg, SHIRUDO_CONF_PATH);
	if (rc && rc != -ENOENT)
		return rc;

	/* Env override (handy for tests / not persisting a secret to disk). */
	env = getenv("SHIRUDO_TPM_OWNER_AUTH");
	if (env)
		set_owner_auth(cfg, env);

	/*
	 * TCTI env override -- mirrors the pre-existing
	 * SHIRUDO_TPM_TCTI behaviour in util/tpm.c so the env wins
	 * over the on-disk config (handy when the conf file is shared
	 * but a single dev run wants swtpm).
	 */
	env = getenv("SHIRUDO_TPM_TCTI");
	if (env && *env) {
		size_t l = strlen(env);

		if (l < sizeof(cfg->tpm_tcti))
			snprintf(cfg->tpm_tcti, sizeof(cfg->tpm_tcti),
				 "%s", env);
		else
			pr_warn("SHIRUDO_TPM_TCTI too long (ignored)");
	}

	return rc == -ENOENT ? 0 : rc;
}
