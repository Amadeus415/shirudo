// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The history root of an upatch tree, apart from the register code of
 * chain.c, so that the publisher computes a segment's base without the TPM.
 */

#include <string.h>

#include "chain.h"
#include "crypto.h"

int chain_history_step(const __u8 prev[32], const __u8 operation_digest[32],
		       __u8 out[32])
{
	__u8 buf[sizeof("shirudo-tree-history") + 64];
	size_t taglen = sizeof("shirudo-tree-history");
	int ret;

	memcpy(buf, "shirudo-tree-history", taglen);
	memcpy(buf + taglen, prev, 32);
	memcpy(buf + taglen + 32, operation_digest, 32);
	ret = sha256_buffer(buf, sizeof(buf), out);
	if (ret)
		memset(out, 0, 32);
	return ret;
}
