/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_UTIL_TENANT_ID_H
#define SHIRUDO_UTIL_TENANT_ID_H

#include <stdbool.h>
#include <stddef.h>

#define SHIRUDO_TENANT_ID_MAX	128

static inline bool shirudo_tenant_id_valid(const char *id)
{
	size_t i;

	if (!id || !id[0])
		return false;
	for (i = 0; id[i]; i++) {
		unsigned char c = (unsigned char)id[i];

		if (i >= SHIRUDO_TENANT_ID_MAX ||
		    !((c >= 'a' && c <= 'z') ||
		      (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') ||
		      c == '.' || c == '_' || c == '-'))
			return false;
	}
	return true;
}

#endif /* SHIRUDO_UTIL_TENANT_ID_H */
