/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Subcommand entry points dispatched from shirudo.c.
 */

#ifndef SHIRUDO_BUILTIN_H
#define SHIRUDO_BUILTIN_H

#include <stdbool.h>

/* Operator-side. */
int cmd_genkey(int argc, const char **argv);
int cmd_build(int argc, const char **argv);

/*
 * The shirudo-build helper (operator package only): whether it can be
 * reached, and the single exec site that hands an argument vector to
 * it (argv[0] is replaced; returns only on failure).
 */
bool shirudo_build_available(void);
int shirudo_build_exec(const char *label, char **argv);

/* Target-side. */
int cmd_init(int argc, const char **argv);
int cmd_upatch(int argc, const char **argv);
int cmd_bpm(int argc, const char **argv);

/*
 * Target-side shared op: load + attach + pin one signed LOAD upatch.
 * Used by `shirudo upatch load` and by `shirudo init` boot-restore so
 * both share the identical signature-verified path. 0 on success.
 */
int shirudo_upatch_apply(const char *path);
int shirudo_upatch_install(const char *path);
int shirudo_upatch_remove(const char *path);

/*
 * Target-side: detach, unpin and unarchive the upatch of that name
 * without a directive, because the key that signed it was revoked.
 * reason goes into the eventlog record. 1 when it was loaded and the
 * unload was measured, 0 when only the archive went, -errno otherwise.
 */
int shirudo_upatch_purge(const char *name, const char *reason);

/* Internal lifecycle result: the signed payload was valid, but its kprobe
 * target is unavailable because the backing module is not loaded. */
#define SHIRUDO_UPATCH_INSTALL_TARGET_MISSING 2

/* Either-side. */
int cmd_status(int argc, const char **argv);
int cmd_attest(int argc, const char **argv);
int cmd_version(int argc, const char **argv);
int cmd_keys(int argc, const char **argv);
int cmd_config(int argc, const char **argv);

#endif /* SHIRUDO_BUILTIN_H */
