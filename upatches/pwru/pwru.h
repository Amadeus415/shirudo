/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What pwru.bpf.c and shirudo pwru agree on: the filter stub the
 * builder replaces, the functions the upatch probes and its records.
 */

#ifndef SHIRUDO_PWRU_H
#define SHIRUDO_PWRU_H

/*
 * The filter stub is r0 = <magic>; exit, the last two instructions of
 * every probe once libbpf has appended it as the probe's one
 * subprogram. Without a filter it stays, and its non-zero return lets
 * every packet through.
 */
#define PWRU_STUB_MAGIC		0x75727770	/* "pwru" le */

/* The sections of the probes, the programs that end in the stub. */
#define PWRU_FENTRY_PREFIX	"fentry/"
#define PWRU_TP_PREFIX		"tp_btf/"

#define PWRU_FUNC_NAME_LEN	32
#define PWRU_COMM_LEN		16

enum pwru_func_id {
#define PWRU_FUNC(func, ...)	PWRU_FUNC_##func,
#define PWRU_TP(func, ...)	PWRU_FUNC_##func,
#include "pwru_funcs.h"
#undef PWRU_TP
#undef PWRU_FUNC
	PWRU_NR_FUNCS
};

/*
 * The serialized record, RECORD bytes at a fixed offset each; the
 * decoder reads the same offsets.
 */
#define PWRU_RECORD		160
#define PWRU_SERIAL_MAGIC	0x55525750u	/* "PWRU" le */
#define PWRU_SERIAL_VERSION	1

#endif /* SHIRUDO_PWRU_H */
