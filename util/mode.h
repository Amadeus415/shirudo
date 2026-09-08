/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_MODE_H
#define SHIRUDO_MODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum shirudo_mode {
	SHIRUDO_MODE_UNTRUSTED_ROOT = 0,
	SHIRUDO_MODE_TRUSTED_ROOT = 1,
};

struct shirudo_mode_state {
	enum shirudo_mode mode;
	uint8_t cert_sha256[32];
};

/* Parse a committed mode buffer without accessing the filesystem. */
int shirudo_mode_parse(const char *buf, size_t len,
			       struct shirudo_mode_state *state);

/* Read the committed mode. Returns -ENOENT when init has not committed one. */
int shirudo_mode_read(struct shirudo_mode_state *state);

/* Commit the mode once, or verify an existing identical commitment. */
int shirudo_mode_commit(enum shirudo_mode mode,
			const uint8_t cert_sha256[32]);

const char *shirudo_mode_file_name(enum shirudo_mode mode);
const char *shirudo_mode_status_name(enum shirudo_mode mode);
const char *shirudo_mode_authorization(enum shirudo_mode mode,
					bool native_kernel_signing);

#endif /* SHIRUDO_MODE_H */
