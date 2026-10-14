// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libtss2 wrappers for the TPM2 NV-extend measurement chain.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include "config.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "tpm.h"

struct shirudo_tpm {
	TSS2_TCTI_CONTEXT	*tcti;
	ESYS_CONTEXT		*esys;
};

int shirudo_tpm_open(struct shirudo_tpm **out)
{
	struct shirudo_config cfg = {};
	struct shirudo_tpm *t;
	const char *tcti;
	TSS2_RC rc;

	t = xcalloc(1, sizeof(*t));
	if (!t)
		return -ENOMEM;

	/*
	 * Quiet libtss2's own stderr logging (it screams ERROR on the
	 * expected "index not yet defined" probe during first-init).
	 * shirudo logs its own diagnostics via pr_*; an operator who
	 * sets TSS2_LOG keeps their setting (overwrite = 0).
	 */
	setenv("TSS2_LOG", "all+none", 0);

	/*
	 * Default to the kernel resource manager. Precedence:
	 *   1. SHIRUDO_TPM_TCTI env var (highest)
	 *   2. tpm.tcti in /etc/shirudo/shirudo.conf
	 *   3. compiled-in default `device:/dev/tpmrm0`
	 * Override is for VMs/CI whose /dev/tpmrm0 is
	 * owner-provisioned and for tests against swtpm. Redirecting
	 * the TCTI on a target cannot defeat the operator-side
	 * guarantee: the operator verifies the chain value against a
	 * locally-computed expectation, so a fake TPM produces values
	 * the check rejects.
	 */
	tcti = getenv("SHIRUDO_TPM_TCTI");
	if ((!tcti || !*tcti) && shirudo_config_load(&cfg) == 0 &&
	    cfg.tpm_tcti[0])
		tcti = cfg.tpm_tcti;
	if (!tcti || !*tcti)
		tcti = "device:/dev/tpmrm0";

	rc = Tss2_TctiLdr_Initialize(tcti, &t->tcti);
	if (rc != TSS2_RC_SUCCESS)
		pr_err("tpm: TctiLdr_Initialize(%s): rc=0x%08x", tcti,
		       (unsigned)rc);
	explicit_bzero(&cfg, sizeof(cfg));	/* scrub tpm_owner_auth */
	if (rc != TSS2_RC_SUCCESS) {
		xfree(t, sizeof(*t));
		return -EIO;
	}
	rc = Esys_Initialize(&t->esys, t->tcti, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: Esys_Initialize: rc=0x%08x", (unsigned)rc);
		Tss2_TctiLdr_Finalize(&t->tcti);
		xfree(t, sizeof(*t));
		return -EIO;
	}
	*out = t;
	return 0;
}

void shirudo_tpm_close(struct shirudo_tpm *t)
{
	if (!t)
		return;
	if (t->esys)
		Esys_Finalize(&t->esys);
	if (t->tcti)
		Tss2_TctiLdr_Finalize(&t->tcti);
	xfree(t, sizeof(*t));
}

/* Auth-failure base code, masking off the session/handle/parameter number. */
static bool rc_is_auth_failure(TSS2_RC rc)
{
	TSS2_RC base = (rc & TPM2_RC_FMT1) ? (rc & 0x0BFu) : (rc & 0x1FFu);

	return base == TPM2_RC_BAD_AUTH || base == TPM2_RC_AUTH_FAIL ||
	       base == TPM2_RC_NV_AUTHORIZATION;
}

int shirudo_tpm_nv_define(struct shirudo_tpm *t, uint32_t index,
			  const uint8_t auth[SHIRUDO_TPM_NV_DIGEST_LEN],
			  const void *owner_auth, size_t owner_auth_len)
{
	TPM2B_AUTH nv_auth = { .size = SHIRUDO_TPM_NV_DIGEST_LEN };
	TPM2B_AUTH owner = {};
	TPM2B_NV_PUBLIC pub = {};
	ESYS_TR nv = ESYS_TR_NONE;
	TSS2_RC rc;

	/*
	 * Idempotent: if the index already exists, do not re-define --
	 * TPM2_NV_DefineSpace on a live index resets the chain to zero
	 * and would destroy every operator's cached expectation.
	 */
	rc = Esys_TR_FromTPMPublic(t->esys, index, ESYS_TR_NONE,
				   ESYS_TR_NONE, ESYS_TR_NONE, &nv);
	if (rc == TSS2_RC_SUCCESS)
		return 0;

	/*
	 * The index is in the owner range, so DefineSpace is authorised by
	 * the owner (storage) hierarchy. When that hierarchy's auth is set,
	 * the caller supplies it; an empty value uses the empty-password
	 * session (fresh TPM / swtpm / most VMs).
	 */
	if (owner_auth_len > sizeof(owner.buffer))
		return -EINVAL;
	if (owner_auth_len) {
		memcpy(owner.buffer, owner_auth, owner_auth_len);
		owner.size = (uint16_t)owner_auth_len;
		rc = Esys_TR_SetAuth(t->esys, ESYS_TR_RH_OWNER, &owner);
		if (rc != TSS2_RC_SUCCESS) {
			pr_err("tpm: TR_SetAuth(owner): rc=0x%08x", (unsigned)rc);
			explicit_bzero(owner.buffer, sizeof(owner.buffer));
			return -EIO;
		}
	}

	memcpy(nv_auth.buffer, auth, SHIRUDO_TPM_NV_DIGEST_LEN);

	pub.nvPublic.nvIndex = index;
	pub.nvPublic.nameAlg = TPM2_ALG_SHA256;
	pub.nvPublic.attributes =
		TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD | TPMA_NV_NO_DA |
		(((TPMA_NV)TPM2_NT_EXTEND << TPMA_NV_TPM2_NT_SHIFT) &
		 TPMA_NV_TPM2_NT_MASK);
	pub.nvPublic.dataSize = SHIRUDO_TPM_NV_DIGEST_LEN;

	rc = Esys_NV_DefineSpace(t->esys, ESYS_TR_RH_OWNER,
				 ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
				 &nv_auth, &pub, &nv);

	/* Owner auth is not needed again; clear it from the ctx and our copy. */
	if (owner_auth_len) {
		TPM2B_AUTH empty = {};

		Esys_TR_SetAuth(t->esys, ESYS_TR_RH_OWNER, &empty);
	}
	explicit_bzero(owner.buffer, sizeof(owner.buffer));

	/*
	 * Raced with another definer (or the existence probe above missed
	 * a just-created index): NV_DEFINED means it is there, which is all
	 * we need -- treat as success and reuse.
	 */
	if ((rc & 0xFFFFu) == TPM2_RC_NV_DEFINED)
		return 0;
	if (rc != TSS2_RC_SUCCESS) {
		if (rc_is_auth_failure(rc)) {
			pr_err("tpm: NV_DefineSpace(0x%08x): owner-hierarchy "
			       "authorization failed (rc=0x%08x). This TPM has "
			       "owner auth set; supply it via tpm.owner_auth in "
			       "%s (or SHIRUDO_TPM_OWNER_AUTH), or clear the TPM "
			       "owner auth.", index, (unsigned)rc,
			       SHIRUDO_CONF_PATH);
			return -EACCES;
		}
		pr_err("tpm: NV_DefineSpace(0x%08x): rc=0x%08x", index,
		       (unsigned)rc);
		return -EIO;
	}
	return 0;
}

static int nv_handle_with_auth(struct shirudo_tpm *t, uint32_t index,
			       const uint8_t auth[SHIRUDO_TPM_NV_DIGEST_LEN],
			       ESYS_TR *out)
{
	TPM2B_AUTH nv_auth = { .size = SHIRUDO_TPM_NV_DIGEST_LEN };
	ESYS_TR nv = ESYS_TR_NONE;
	TSS2_RC rc;

	rc = Esys_TR_FromTPMPublic(t->esys, index, ESYS_TR_NONE,
				   ESYS_TR_NONE, ESYS_TR_NONE, &nv);
	if (rc != TSS2_RC_SUCCESS)
		/*
		 * Quiet: an undefined index is the expected "no chain
		 * yet" case for the status/extend-probe readers, which
		 * map this to a clean degraded result.
		 */
		return -EIO;
	memcpy(nv_auth.buffer, auth, SHIRUDO_TPM_NV_DIGEST_LEN);
	rc = Esys_TR_SetAuth(t->esys, nv, &nv_auth);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: TR_SetAuth: rc=0x%08x", (unsigned)rc);
		return -EIO;
	}
	*out = nv;
	return 0;
}

int shirudo_tpm_nv_read(struct shirudo_tpm *t, uint32_t index,
			const uint8_t auth[SHIRUDO_TPM_NV_DIGEST_LEN],
			uint8_t out[SHIRUDO_TPM_NV_DIGEST_LEN])
{
	TPM2B_MAX_NV_BUFFER *data = NULL;
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	err = nv_handle_with_auth(t, index, auth, &nv);
	if (err)
		return err;

	rc = Esys_NV_Read(t->esys, nv, nv, ESYS_TR_PASSWORD,
			  ESYS_TR_NONE, ESYS_TR_NONE,
			  SHIRUDO_TPM_NV_DIGEST_LEN, 0, &data);
	if (rc != TSS2_RC_SUCCESS)
		return -EIO;	/* quiet: caller maps to degraded */
	if (data->size != SHIRUDO_TPM_NV_DIGEST_LEN) {
		pr_err("tpm: NV_Read returned %u bytes, expected %u",
		       data->size, SHIRUDO_TPM_NV_DIGEST_LEN);
		Esys_Free(data);
		return -EIO;
	}
	memcpy(out, data->buffer, SHIRUDO_TPM_NV_DIGEST_LEN);
	Esys_Free(data);
	return 0;
}

int shirudo_tpm_nv_extend(struct shirudo_tpm *t, uint32_t index,
			  const uint8_t auth[SHIRUDO_TPM_NV_DIGEST_LEN],
			  const uint8_t event[SHIRUDO_TPM_NV_DIGEST_LEN])
{
	TPM2B_MAX_NV_BUFFER data = { .size = SHIRUDO_TPM_NV_DIGEST_LEN };
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	err = nv_handle_with_auth(t, index, auth, &nv);
	if (err)
		return err;

	memcpy(data.buffer, event, SHIRUDO_TPM_NV_DIGEST_LEN);
	rc = Esys_NV_Extend(t->esys, nv, nv, ESYS_TR_PASSWORD,
			    ESYS_TR_NONE, ESYS_TR_NONE, &data);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_Extend(0x%08x): rc=0x%08x", index, (unsigned)rc);
		return -EIO;
	}
	return 0;
}
