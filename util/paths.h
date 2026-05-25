/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Canonical filesystem paths shirudo owns at runtime.
 */

#ifndef SHIRUDO_PATHS_H
#define SHIRUDO_PATHS_H

#include <stddef.h>

/* Target-side. */
#define SHIRUDO_VAR_LIB			"/var/lib/shirudo"
#define SHIRUDO_KEYS_DIR		SHIRUDO_VAR_LIB "/keys"
#define SHIRUDO_KEYS_DIR_ENV		"SHIRUDO_KEYS_DIR"
#define SHIRUDO_CERT_FILE		"cert.der"
#define SHIRUDO_CERT_PATH		SHIRUDO_KEYS_DIR "/" SHIRUDO_CERT_FILE
#define SHIRUDO_UPATCHES_DIR		SHIRUDO_VAR_LIB "/upatches"
#define SHIRUDO_INCOMING_DIR		SHIRUDO_VAR_LIB "/incoming"
#define SHIRUDO_EVENTLOG_PATH		SHIRUDO_VAR_LIB "/eventlog"
#define SHIRUDO_KEYRING_SERIAL_PATH	SHIRUDO_VAR_LIB "/keyring.serial"
#define SHIRUDO_BPFFS_DIR		SHIRUDO_VAR_LIB "/bpffs"
#define SHIRUDO_LSM_LINK_PIN		SHIRUDO_BPFFS_DIR "/lsm_link"
#define SHIRUDO_INODE_UNLINK_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_inode_unlink_link"
#define SHIRUDO_INODE_SETXATTR_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_inode_setxattr_link"
#define SHIRUDO_INODE_RMXATTR_LINK_PIN	SHIRUDO_BPFFS_DIR "/bpf2_inode_removexattr_link"
#define SHIRUDO_SEAL_FILE_OPEN_PIN	SHIRUDO_BPFFS_DIR "/seal_file_open_link"
#define SHIRUDO_SEAL_UNLINK_PIN		SHIRUDO_BPFFS_DIR "/seal_inode_unlink_link"
#define SHIRUDO_SEAL_RENAME_PIN		SHIRUDO_BPFFS_DIR "/seal_inode_rename_link"
#define SHIRUDO_SEAL_SETXATTR_PIN	SHIRUDO_BPFFS_DIR "/seal_inode_setxattr_link"
#define SHIRUDO_SEAL_RMXATTR_PIN	SHIRUDO_BPFFS_DIR "/seal_inode_removexattr_link"
#define SHIRUDO_BPFFS_UPATCHES_DIR	SHIRUDO_BPFFS_DIR "/upatches"

/* Operator-side. */
#define SHIRUDO_SIGNING_KEY_FILE	"signing_key.pem"
#define SHIRUDO_SIGNING_KEY_PATH	SHIRUDO_KEYS_DIR "/" SHIRUDO_SIGNING_KEY_FILE

/* Inode-xattr label (PLAN.md "Target hardening in two layers", layer 2). */
#define SHIRUDO_XATTR_NAME		"security.bpf.shirudo"

/*
 * Per-upatch payload_sha256 recorded on the pin directory in bpffs.
 * Written at load, read at unload for the payload_mismatch check; made
 * unforgeable by the bpf2 inode_setxattr guard. Needs the bpffs-xattr
 * kernel patch (TODO.kernel item 7).
 */
#define SHIRUDO_XATTR_PAYLOAD		"security.bpf.shirudo.payload"

/* Named kernel keyring (PLAN.md "Keyring model"). */
#define SHIRUDO_KEYRING_NAME		"shirudo"

/*
 * TPM2 NV-extend index for the measurement chain (owner-defined
 * range). Override at build time if it collides with site policy.
 * See PLAN.md "Why an NV-extend index, not a PCR".
 */
#ifndef SHIRUDO_NV_INDEX
#define SHIRUDO_NV_INDEX		0x01818E00u
#endif

/* Site config. */
#define SHIRUDO_CONF_PATH		"/etc/shirudo/shirudo.conf"

int shirudo_key_path(char *out, size_t out_sz,
		     const char *keys_dir, const char *file);
int shirudo_key_paths(const char *keys_dir,
		      char *pkey_path, size_t pkey_sz,
		      char *cert_path, size_t cert_sz);
const char *shirudo_keys_dir_resolve(const char *keys_dir_arg);

#endif /* SHIRUDO_PATHS_H */
