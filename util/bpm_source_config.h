/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 */

#ifndef SHIRUDO_BPM_SOURCE_CONFIG_H
#define SHIRUDO_BPM_SOURCE_CONFIG_H

#include <stddef.h>

/* Parse one line from a target-local BPM repository source file. */
int shirudo_bpm_parse_source_line(char *line,
				  char *endpoint, size_t endpoint_sz,
				  char *key_file, size_t key_file_sz);

#endif /* SHIRUDO_BPM_SOURCE_CONFIG_H */
