/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Raw add_key(2)/keyctl(2) wrappers; no libkeyutils.
 */

#ifndef SHIRUDO_KEYRING_H
#define SHIRUDO_KEYRING_H

#include <stddef.h>
#include <stdint.h>

typedef int32_t key_serial_t;

typedef void (*shirudo_keyring_cb)(key_serial_t serial,
				   const char *type,
				   const char *description,
				   void *ud);

/*
 * Look up a named keyring under the user keyring (@u). Returns the
 * serial, -ENOKEY if absent, or another -errno on failure.
 */
key_serial_t shirudo_keyring_find(const char *name);

/*
 * As above, but adds the keyring to @u if absent.
 */
key_serial_t shirudo_keyring_open_or_create(const char *name);

/*
 * Unlink a keyring from @u so init can replace an incomplete stale keyring.
 */
int shirudo_keyring_unlink_from_user(key_serial_t keyring);

/*
 * Add an X.509 cert (DER bytes) as an "asymmetric" key.
 */
key_serial_t shirudo_keyring_add_cert(key_serial_t keyring,
				      const void *cert, size_t cert_len);

/*
 * Freeze a keyring for the rest of the boot: drop write/link/setattr
 * (keeping view/read/search) so no key can be added or unlinked and the
 * permissions cannot be relaxed again -- dropping SETATTR makes it a
 * one-way change. The kernel can still find the cert at BPF_PROG_LOAD.
 * Returns 0 or -errno.
 */
int shirudo_keyring_seal(key_serial_t keyring);

/*
 * Pin a keyring's serial to disk so a later load can detect a
 * same-named keyring being swapped under it (the resolved-by-name
 * serial would no longer match the pin). Per-boot; init rewrites it
 * each boot. The file lives under the sealed tree. Returns 0 / -errno.
 */
int shirudo_keyring_pin_serial(key_serial_t serial);

/*
 * Read the pinned serial back. Returns the serial (>= 1), -ENOENT if no
 * pin exists, or another -errno (including -EINVAL for a corrupt pin).
 */
key_serial_t shirudo_keyring_read_pinned_serial(void);

/*
 * Iterate every key linked into <keyring>. Returns 0 / -errno.
 */
int shirudo_keyring_list(key_serial_t keyring,
			 shirudo_keyring_cb cb, void *ud);

/*
 * The kernel's bpf keyring, the trust anchor a signed loader names with
 * KEY_SPEC_BPF_KEYRING. Sealed empty at boot unless the kernel was
 * booted with bpf.keyring_unsealed=1, in which case it takes keys until
 * userspace seals it; from then on the kernel refuses every
 * caller-supplied keyring for signature verification.
 */
#ifndef KEY_SPEC_BPF_KEYRING
#define KEY_SPEC_BPF_KEYRING	(-9)
#endif

/* Its serial, or -errno on a kernel without one. */
key_serial_t shirudo_keyring_bpf_serial(void);
/* Enrol a DER certificate; -EPERM once the keyring is sealed. */
key_serial_t shirudo_keyring_bpf_add_cert(const unsigned char *cert,
					  size_t cert_len);
/* Seal it for the rest of the boot: no key can be linked afterwards. */
int shirudo_keyring_bpf_seal(void);

#endif /* SHIRUDO_KEYRING_H */
