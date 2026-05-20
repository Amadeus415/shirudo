/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libtss2 wrappers for the TPM2 NV-extend chain.
 */

#ifndef SHIRUDO_TPM_H
#define SHIRUDO_TPM_H

#include <stdint.h>
#include <stddef.h>

#define SHIRUDO_TPM_NV_DIGEST_LEN	32

struct shirudo_tpm;

int shirudo_tpm_open(struct shirudo_tpm **out);
void shirudo_tpm_close(struct shirudo_tpm *t);

/*
 * NV-extend index ops. The index carries TPMA_NV_AUTHWRITE/AUTHREAD,
 * so every read/extend authorises with the derived auth value
 * (SHA256("shirudo-nv-auth\0" || cert_sha256)) -- the caller passes
 * it in. nv_define is idempotent: it returns 0 if the index already
 * exists without re-defining (which would reset the chain).
 *
 * The index lives in the TCG owner range, so DefineSpace is authorised
 * by the owner (storage) hierarchy. owner_auth/owner_auth_len supply
 * that hierarchy's auth for TPMs whose owner auth is set; pass NULL/0
 * (the default) for the empty-owner-auth case (fresh TPM, swtpm, most
 * VMs). Returns 0, -EACCES if the owner hierarchy rejects the auth, or
 * another -errno.
 */
int shirudo_tpm_nv_define(struct shirudo_tpm *t, uint32_t index,
			  const uint8_t auth[SHIRUDO_TPM_NV_DIGEST_LEN],
			  const void *owner_auth, size_t owner_auth_len);
int shirudo_tpm_nv_read(struct shirudo_tpm *t, uint32_t index,
			const uint8_t auth[SHIRUDO_TPM_NV_DIGEST_LEN],
			uint8_t out[SHIRUDO_TPM_NV_DIGEST_LEN]);
int shirudo_tpm_nv_extend(struct shirudo_tpm *t, uint32_t index,
			  const uint8_t auth[SHIRUDO_TPM_NV_DIGEST_LEN],
			  const uint8_t event[SHIRUDO_TPM_NV_DIGEST_LEN]);

#endif /* SHIRUDO_TPM_H */
