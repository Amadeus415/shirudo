/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Where init runs: the initrd, with the root file system at /sysroot.
 */

#ifndef SHIRUDO_UTIL_INITRD_H
#define SHIRUDO_UTIL_INITRD_H

#include <stdbool.h>

/*
 * The initrd marks itself with /etc/initrd-release; tests point
 * SHIRUDO_INITRD_RELEASE elsewhere.
 */
bool shirudo_in_initrd(void);

/* The root file system's mount point while the initrd runs. */
const char *shirudo_sysroot(void);

/*
 * The certificate init enrols: the initrd's own, measured copy while
 * the initrd runs, the one in the state tree otherwise.
 */
const char *shirudo_cert_path(void);

#endif /* SHIRUDO_UTIL_INITRD_H */
