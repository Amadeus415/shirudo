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
#include "json.h"
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

static void config_defaults(struct shirudo_config *cfg)
{
	*cfg = (struct shirudo_config){};
	cfg->map_export_valid = true;
	cfg->map_export_otel_retries = 3;
	cfg->map_export_log_record_max_bytes = SHIRUDO_MAP_EXPORT_LOG_RECORD_MAX_DEFAULT;
	cfg->map_export_otlp_max_bytes = SHIRUDO_MAP_EXPORT_OTLP_MAX_DEFAULT;
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
			} else if (strcmp(key, "map_export.json_path") == 0) {
				if (!set_string(cfg->map_export_json_path,
						sizeof(cfg->map_export_json_path), val))
					map_export_bad(cfg, key, val, "value too long");
				else if (val[0] && val[0] != '/')
					map_export_bad(cfg, key, val,
							"path must be absolute");
			} else if (strcmp(key, "map_export.otel_endpoint") == 0) {
				if (!set_string(cfg->map_export_otel_endpoint,
						sizeof(cfg->map_export_otel_endpoint), val))
					map_export_bad(cfg, key, val, "value too long");
			} else if (strcmp(key, "map_export.tenant_id") == 0) {
				if (val[0] && !shirudo_tenant_id_valid(val))
					map_export_bad(cfg, key, val,
							"expected 1..128 characters from "
							"A-Z, a-z, 0-9, '.', '_', '-'");
				else
					(void)set_string(cfg->map_export_tenant_id,
							 sizeof(cfg->map_export_tenant_id),
							 val);
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
			} else if (strcmp(key, "map_export.log_record_max_bytes") == 0 ||
				   strcmp(key, "map_export.otlp_max_bytes") == 0) {
				unsigned long v;
				char *end;

				errno = 0;
				v = strtoul(val, &end, 10);
				if (errno || *end || v == 0 || v > SHIRUDO_JSON_MAX_BYTES)
					map_export_bad(cfg, key, val, "expected 1..8388608 bytes");
				else if (strcmp(key, "map_export.log_record_max_bytes") == 0)
					cfg->map_export_log_record_max_bytes = (unsigned int)v;
				else
					cfg->map_export_otlp_max_bytes = (unsigned int)v;
			} else {
				if (strncmp(key, "map_export.", 11) == 0)
					map_export_bad(cfg, key, val, "unknown key");
				else
					pr_warn("config: unknown key '%s' (ignored)",
						key);
			}
		}
		if (ferror(f) && !rc)
			rc = -EIO;
		if (fclose(f) && !rc)
			rc = -errno;
	}
	if (cfg->map_export_s3_uri[0] && !cfg->map_export_otel_endpoint[0])
		map_export_bad(cfg, "map_export.s3_uri", "",
			       "requires map_export.otel_endpoint for its reference event");
	if (cfg->map_export_log_record_max_bytes > cfg->map_export_otlp_max_bytes)
		map_export_bad(cfg, "map_export.log_record_max_bytes", "",
			       "must not exceed otlp_max_bytes");
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
