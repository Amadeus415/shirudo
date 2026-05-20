/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Inode labelling for the bpf/seal.c filesystem-sealing LSM.
 */

#ifndef SHIRUDO_SEAL_H
#define SHIRUDO_SEAL_H

/*
 * Set security.bpf.shirudo = SHIRUDO_VERSION_ID on one path. Idempotent
 * (create-or-replace). Call after creating any regular-fs file under
 * /var/lib/shirudo/ so the seal LSM protects it. Returns 0 or -errno.
 */
int shirudo_seal_label(const char *path);

/*
 * Label the running binary's inode and walk /var/lib/shirudo/ labelling
 * every inode on that filesystem (the bpffs mount is skipped -- bpf2
 * guards it). Best-effort per entry. Call BEFORE the seal LSM attaches,
 * so the bulk setxattr is not gated. Returns 0 or -errno on a fatal
 * (stat/walk) failure.
 */
int shirudo_seal_label_tree(void);

#endif /* SHIRUDO_SEAL_H */
