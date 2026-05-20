// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Minimal shirudo.conf reader: `key = value` lines, '#' comments,
 * dotted keys. No third-party parser -- the config surface is tiny.
 */

#include <errno.h>
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

int shirudo_config_load(struct shirudo_config *cfg)
{
	const char *env;
	char line[1024];
	int rc = 0;
	FILE *f;

	*cfg = (struct shirudo_config){};	/* defaults: all zero */

	f = fopen(SHIRUDO_CONF_PATH, "r");
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
			} else {
				pr_warn("config: unknown key '%s' (ignored)",
					key);
			}
		}
		fclose(f);
	}

	/* Env override (handy for tests / not persisting a secret to disk). */
	env = getenv("SHIRUDO_TPM_OWNER_AUTH");
	if (env)
		set_owner_auth(cfg, env);

	return rc;
}
