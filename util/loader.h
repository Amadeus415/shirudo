/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Access to the BPF objects embedded into shirudo via .incbin.
 */

#ifndef SHIRUDO_LOADER_H
#define SHIRUDO_LOADER_H

#include <stddef.h>

struct shirudo_embedded_bpf {
	const char	*name;
	const void	*data;
	size_t		size;
};

const struct shirudo_embedded_bpf *shirudo_bpf2_blob(void);
const struct shirudo_embedded_bpf *shirudo_bpf2_trusted_root_blob(void);
const struct shirudo_embedded_bpf *shirudo_seal_blob(void);
const struct shirudo_embedded_bpf *shirudo_unload_blob(void);

#endif /* SHIRUDO_LOADER_H */
