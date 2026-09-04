/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Subcommand entry points dispatched from shirudo.c.
 */

#ifndef SHIRUDO_BUILTIN_H
#define SHIRUDO_BUILTIN_H

/* Operator-side. */
int cmd_genkey(int argc, const char **argv);
int cmd_build(int argc, const char **argv);

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

/* Either-side. */
int cmd_status(int argc, const char **argv);
int cmd_version(int argc, const char **argv);
int cmd_keys(int argc, const char **argv);
int cmd_config(int argc, const char **argv);

#endif /* SHIRUDO_BUILTIN_H */
