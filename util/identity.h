/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The identity init froze into the kernel, read back from its bpffs pin.
 */

#ifndef SHIRUDO_UTIL_IDENTITY_H
#define SHIRUDO_UTIL_IDENTITY_H

#include <stdint.h>

/* The keyring kinds the kernel names in a verdict (enum bpf_sig_keyring). */
#define SHIRUDO_SIG_KEYRING_USER	4
#define SHIRUDO_SIG_KEYRING_BPF		5

/*
 * Must match struct shirudo_sb_id in bpf/bpf2.c byte for byte. exe is
 * the binary that keeps running the target; alt_exe, when set, the
 * initrd's copy that ran init and is gone after the switch to the root.
 */
struct shirudo_identity {
	uint32_t	sb_dev;
	uint32_t	exe_dev;
	uint64_t	exe_ino;
	int32_t		keyring_serial;
	uint32_t	keyring_type;
	uint32_t	alt_exe_dev;
	uint32_t	pad;
	uint64_t	alt_exe_ino;
};

/*
 * The identity map init populated, froze and pinned this boot. -ENOENT
 * when init has not run, another -errno when the pin cannot be read.
 */
int shirudo_identity_read(struct shirudo_identity *out);

#endif /* SHIRUDO_UTIL_IDENTITY_H */
