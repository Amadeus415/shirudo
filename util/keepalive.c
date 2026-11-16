// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <shirudo/misc.h>

#include "crypto.h"
#include "keepalive.h"

#define CODE_BITS	2
#define CODE_MAX	3
#define CODES_PER_BYTE	4

enum cond_code {
	COND_NOT_EVALUATED,
	COND_OK,
	COND_WARN,
	COND_ALERT,
};

/* The backend reads a pair by its place here: append, never reorder. */
static const char * const cond_order[] = {
	"LsmAttached",
	"KeyringSealed",
	"ChainIntact",
	"UpatchesMeasured",
	"TpmMeasured",
	"ConfigActive",
	"XdpCovered",
};

int keepalive_mask(const __u8 *codes, size_t n, char *b64, size_t cap)
{
	size_t len = (n + CODES_PER_BYTE - 1) / CODES_PER_BYTE, i;
	__u8 raw[KEEPALIVE_MASK_BYTES] = {};

	if (n > KEEPALIVE_MASK_OPS)
		return -EINVAL;
	for (i = 0; i < n; i++) {
		size_t slot = CODES_PER_BYTE - 1 - i % CODES_PER_BYTE;

		if (codes[i] > CODE_MAX)
			return -EINVAL;
		raw[i / CODES_PER_BYTE] |= codes[i] << (CODE_BITS * slot);
	}
	if (cap < 4 * ((len + 2) / 3) + 1)
		return -E2BIG;
	return base64_encode(raw, len, b64, cap);
}

static enum cond_code cond_code_of(const char *status)
{
	if (!strcmp(status, "OK"))
		return COND_OK;
	if (!strcmp(status, "WARN"))
		return COND_WARN;
	if (!strcmp(status, "ALERT"))
		return COND_ALERT;
	return COND_NOT_EVALUATED;
}

static enum cond_code cond_code_named(const struct condition *conds, size_t n,
				      const char *type)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (!strcmp(conds[i].type, type))
			return cond_code_of(conds[i].status);
	return COND_NOT_EVALUATED;
}

__u16 keepalive_cond(const struct condition *conds, size_t n)
{
	__u16 cond = 0;
	size_t i;

	BUILD_BUG_ON(ARRAY_SIZE(cond_order) != CONDITIONS_MAX);
	BUILD_BUG_ON(CODE_BITS * ARRAY_SIZE(cond_order) > 8 * sizeof(cond));

	for (i = 0; i < ARRAY_SIZE(cond_order); i++)
		cond |= cond_code_named(conds, n, cond_order[i]) <<
			(CODE_BITS * i);
	return cond;
}
