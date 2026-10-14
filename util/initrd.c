// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Where init runs: the initrd, with the root file system at /sysroot.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "initrd.h"
#include "paths.h"

bool shirudo_in_initrd(void)
{
	const char *env = getenv("SHIRUDO_INITRD_RELEASE");

	return access(env && *env ? env : "/etc/initrd-release", F_OK) == 0;
}

const char *shirudo_sysroot(void)
{
	const char *env = getenv("SHIRUDO_SYSROOT");

	return env && *env ? env : "/sysroot";
}

const char *shirudo_keys_dir(void)
{
	return shirudo_in_initrd() ? SHIRUDO_INITRD_KEYS_DIR :
				     SHIRUDO_KEYS_DIR;
}

const char *shirudo_cert_path(void)
{
	return shirudo_in_initrd() ? SHIRUDO_INITRD_CERT_PATH :
				     SHIRUDO_CERT_PATH;
}
