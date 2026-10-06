// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "util/kernel_build_id.h"

static void put_u32(unsigned char *p, uint32_t value)
{
	memcpy(p, &value, sizeof(value));
}

int main(void)
{
	/* One GNU build-id note with a four-byte descriptor: 01 23 45 67. */
	static const unsigned char notes[] = {
		4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0,
		'G', 'N', 'U', 0, 1, 0x23, 0x45, 0x67,
	};
	unsigned char malformed[sizeof(notes)];
	char build_id[SHIRUDO_KERNEL_BUILD_ID_STRING_MAX];

	if (shirudo_kernel_build_id_from_notes(notes, sizeof(notes), build_id) ||
	    strcmp(build_id, "01234567")) {
		fprintf(stderr, "failed to parse GNU build-id note: %s\n", build_id);
		return 1;
	}
	if (shirudo_kernel_build_id_from_notes(notes, 0, build_id) != -ENOENT) {
		fprintf(stderr, "empty notes should return -ENOENT\n");
		return 1;
	}
	memcpy(malformed, notes, sizeof(notes));
	put_u32(malformed, UINT32_MAX);
	if (shirudo_kernel_build_id_from_notes(malformed, sizeof(malformed),
					       build_id) != -EINVAL) {
		fprintf(stderr, "malformed notes should return -EINVAL\n");
		return 1;
	}
	return 0;
}
