// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libtss2 wrappers for the measurement register and attestation.
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

#define EK_CERT_NV_RSA		0x01C00002u
#define EK_CERT_NV_ECC		0x01C0000Au
#define NV_READ_CHUNK		512u

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
	 * owner-provisioned and for tests against a software TPM.
	 * Redirecting the TCTI on a target cannot defeat the
	 * operator-side guarantee: the evidence is signed by the key
	 * the operator pinned, so a substitute TPM fails verification.
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

/* Compare a TPM return code with a base code, masking handle numbers. */
static bool rc_is(TSS2_RC rc, TSS2_RC code)
{
	if ((rc & 0xFFFF0000u) != 0)
		return false;	/* not a TPM-layer code */
	if (rc & TPM2_RC_FMT1)
		return (rc & 0x0BFu) == (code & 0x0BFu);
	return (rc & 0xFFFu) == code;
}

static bool rc_is_auth_failure(TSS2_RC rc)
{
	return rc_is(rc, TPM2_RC_BAD_AUTH) || rc_is(rc, TPM2_RC_AUTH_FAIL) ||
	       rc_is(rc, TPM2_RC_NV_AUTHORIZATION) ||
	       rc_is(rc, TPM2_RC_POLICY_FAIL);
}

static void pcr_selection(uint32_t mask, TPML_PCR_SELECTION *sel)
{
	memset(sel, 0, sizeof(*sel));
	sel->count = 1;
	sel->pcrSelections[0].hash = TPM2_ALG_SHA256;
	sel->pcrSelections[0].sizeofSelect = SHIRUDO_TPM_PCR_SELECT_LEN;
	sel->pcrSelections[0].pcrSelect[0] = (uint8_t)mask;
	sel->pcrSelections[0].pcrSelect[1] = (uint8_t)(mask >> 8);
	sel->pcrSelections[0].pcrSelect[2] = (uint8_t)(mask >> 16);
}

int shirudo_tpm_pcr_read(struct shirudo_tpm *t, unsigned int pcr,
			 uint8_t out[32])
{
	TPML_PCR_SELECTION sel;
	TPML_DIGEST *values = NULL;
	UINT32 counter;
	TSS2_RC rc;

	if (pcr >= 24)
		return -EINVAL;
	pcr_selection(1u << pcr, &sel);
	rc = Esys_PCR_Read(t->esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			   &sel, &counter, NULL, &values);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: PCR_Read(%u): rc=0x%08x", pcr, (unsigned)rc);
		return -EIO;
	}
	if (values->count != 1 || values->digests[0].size != 32) {
		pr_err("tpm: PCR %u has no SHA-256 bank", pcr);
		Esys_Free(values);
		return -ENOENT;
	}
	memcpy(out, values->digests[0].buffer, 32);
	Esys_Free(values);
	return 0;
}

int shirudo_tpm_pcr_extend(struct shirudo_tpm *t, unsigned int pcr,
			   const uint8_t digest[32])
{
	TPML_DIGEST_VALUES dv = { .count = 1 };
	TSS2_RC rc;

	if (pcr >= 24)
		return -EINVAL;
	dv.digests[0].hashAlg = TPM2_ALG_SHA256;
	memcpy(dv.digests[0].digest.sha256, digest, 32);
	rc = Esys_PCR_Extend(t->esys, ESYS_TR_PCR0 + pcr, ESYS_TR_PASSWORD,
			     ESYS_TR_NONE, ESYS_TR_NONE, &dv);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: PCR_Extend(%u): rc=0x%08x", pcr, (unsigned)rc);
		return -EIO;
	}
	return 0;
}

int shirudo_tpm_reset_count(struct shirudo_tpm *t, uint32_t *out)
{
	TPMS_TIME_INFO *info = NULL;
	TSS2_RC rc;

	rc = Esys_ReadClock(t->esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			    &info);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: ReadClock: rc=0x%08x", (unsigned)rc);
		return -EIO;
	}
	*out = info->clockInfo.resetCount;
	Esys_Free(info);
	return 0;
}

static int nv_handle(struct shirudo_tpm *t, uint32_t index, ESYS_TR *out)
{
	TSS2_RC rc;

	rc = Esys_TR_FromTPMPublic(t->esys, index, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, out);
	if (rc_is(rc, TPM2_RC_HANDLE))
		return -ENOENT;		/* quiet: undefined is normal */
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: TR_FromTPMPublic(0x%08x): rc=0x%08x", index,
		       (unsigned)rc);
		return -EIO;
	}
	return 0;
}

int shirudo_tpm_nv_info(struct shirudo_tpm *t, uint32_t index,
			struct shirudo_tpm_nv_info *info)
{
	TPM2B_NV_PUBLIC *pub = NULL;
	TPM2B_NAME *name = NULL;
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	memset(info, 0, sizeof(*info));
	err = nv_handle(t, index, &nv);
	if (err == -ENOENT)
		return 0;
	if (err)
		return err;
	rc = Esys_NV_ReadPublic(t->esys, nv, ESYS_TR_NONE, ESYS_TR_NONE,
				ESYS_TR_NONE, &pub, &name);
	Esys_TR_Close(t->esys, &nv);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_ReadPublic(0x%08x): rc=0x%08x", index,
		       (unsigned)rc);
		return -EIO;
	}
	info->defined = true;
	info->written = (pub->nvPublic.attributes & TPMA_NV_WRITTEN) != 0;
	info->attrs = pub->nvPublic.attributes;
	info->data_size = pub->nvPublic.dataSize;
	if (pub->nvPublic.authPolicy.size == 32)
		memcpy(info->policy, pub->nvPublic.authPolicy.buffer, 32);
	if (name->size <= sizeof(info->name)) {
		memcpy(info->name, name->name, name->size);
		info->name_len = name->size;
	}
	Esys_Free(pub);
	Esys_Free(name);
	return 0;
}

/* Owner-hierarchy auth for DefineSpace/UndefineSpace; cleared after use. */
static int owner_auth_set(struct shirudo_tpm *t, const void *auth, size_t len)
{
	TPM2B_AUTH owner = {};
	TSS2_RC rc;

	if (len > sizeof(owner.buffer))
		return -EINVAL;
	if (len) {
		memcpy(owner.buffer, auth, len);
		owner.size = (uint16_t)len;
	}
	rc = Esys_TR_SetAuth(t->esys, ESYS_TR_RH_OWNER, &owner);
	explicit_bzero(owner.buffer, sizeof(owner.buffer));
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: TR_SetAuth(owner): rc=0x%08x", (unsigned)rc);
		return -EIO;
	}
	return 0;
}

static void owner_auth_clear(struct shirudo_tpm *t)
{
	TPM2B_AUTH empty = {};

	Esys_TR_SetAuth(t->esys, ESYS_TR_RH_OWNER, &empty);
}

static int owner_auth_error(const char *op, uint32_t index, TSS2_RC rc)
{
	if (rc_is_auth_failure(rc)) {
		pr_err("tpm: %s(0x%08x): owner-hierarchy authorization "
		       "failed (rc=0x%08x). This TPM has owner auth set; "
		       "supply it via tpm.owner_auth in %s (or "
		       "SHIRUDO_TPM_OWNER_AUTH), or clear the TPM owner "
		       "auth.", op, index, (unsigned)rc, SHIRUDO_CONF_PATH);
		return -EACCES;
	}
	pr_err("tpm: %s(0x%08x): rc=0x%08x", op, index, (unsigned)rc);
	return -EIO;
}

int shirudo_tpm_nv_define(struct shirudo_tpm *t, uint32_t index,
			  const uint8_t policy[32],
			  const void *owner_auth, size_t owner_auth_len)
{
	TPM2B_NV_PUBLIC pub = {};
	TPM2B_AUTH nv_auth = {};
	ESYS_TR nv = ESYS_TR_NONE;
	TSS2_RC rc;
	int err;

	err = owner_auth_set(t, owner_auth, owner_auth_len);
	if (err)
		return err;
	pub.nvPublic.nvIndex = index;
	pub.nvPublic.nameAlg = TPM2_ALG_SHA256;
	pub.nvPublic.attributes = SHIRUDO_TPM_REGISTER_ATTRS;
	pub.nvPublic.authPolicy.size = 32;
	memcpy(pub.nvPublic.authPolicy.buffer, policy, 32);
	pub.nvPublic.dataSize = SHIRUDO_TPM_NV_DIGEST_LEN;
	rc = Esys_NV_DefineSpace(t->esys, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
				 ESYS_TR_NONE, ESYS_TR_NONE, &nv_auth, &pub,
				 &nv);
	owner_auth_clear(t);
	if (rc != TSS2_RC_SUCCESS)
		return owner_auth_error("NV_DefineSpace", index, rc);
	Esys_TR_Close(t->esys, &nv);
	return 0;
}

int shirudo_tpm_nv_undefine(struct shirudo_tpm *t, uint32_t index,
			    const void *owner_auth, size_t owner_auth_len)
{
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	err = owner_auth_set(t, owner_auth, owner_auth_len);
	if (err)
		return err;
	rc = Esys_NV_UndefineSpace(t->esys, ESYS_TR_RH_OWNER, nv,
				   ESYS_TR_PASSWORD, ESYS_TR_NONE,
				   ESYS_TR_NONE);
	owner_auth_clear(t);
	if (rc != TSS2_RC_SUCCESS)
		return owner_auth_error("NV_UndefineSpace", index, rc);
	return 0;
}

int shirudo_tpm_nv_read(struct shirudo_tpm *t, uint32_t index, uint8_t out[32])
{
	TPM2B_MAX_NV_BUFFER *data = NULL;
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	rc = Esys_NV_Read(t->esys, nv, nv, ESYS_TR_PASSWORD, ESYS_TR_NONE,
			  ESYS_TR_NONE, SHIRUDO_TPM_NV_DIGEST_LEN, 0, &data);
	Esys_TR_Close(t->esys, &nv);
	if (rc_is(rc, TPM2_RC_NV_UNINITIALIZED))
		return -ENODATA;	/* quiet: nothing written this boot */
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_Read(0x%08x): rc=0x%08x", index, (unsigned)rc);
		return -EIO;
	}
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

static int policy_session_start(struct shirudo_tpm *t, ESYS_TR *session)
{
	TPMT_SYM_DEF sym = { .algorithm = TPM2_ALG_NULL };
	TSS2_RC rc;

	rc = Esys_StartAuthSession(t->esys, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				   NULL, TPM2_SE_POLICY, &sym, TPM2_ALG_SHA256,
				   session);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: StartAuthSession: rc=0x%08x", (unsigned)rc);
		return -EIO;
	}
	return 0;
}

static void session_flush(struct shirudo_tpm *t, ESYS_TR session)
{
	if (session != ESYS_TR_NONE)
		Esys_FlushContext(t->esys, session);
}

/*
 * Walk one branch of the register's write policy in a real session and
 * close it with PolicyOR. The session digest is then compared with the
 * policy computed in software, so a formula drift fails loudly here
 * instead of as an unexplained TPM2_RC_POLICY_FAIL.
 */
static int policy_session_register(struct shirudo_tpm *t, bool init,
				   uint32_t pcr_mask,
				   const uint8_t branch_written[32],
				   const uint8_t branch_init[32],
				   ESYS_TR *session)
{
	TPML_DIGEST branches = { .count = 2 };
	TPM2B_DIGEST *digest = NULL;
	uint8_t expected[32];
	TSS2_RC rc;
	int err;

	err = policy_session_start(t, session);
	if (err)
		return err;
	rc = Esys_PolicyNvWritten(t->esys, *session, ESYS_TR_NONE, ESYS_TR_NONE,
				  ESYS_TR_NONE, init ? TPM2_NO : TPM2_YES);
	if (rc == TSS2_RC_SUCCESS && init) {
		TPM2B_DIGEST live = { .size = 0 };
		TPML_PCR_SELECTION sel;

		pcr_selection(pcr_mask, &sel);
		rc = Esys_PolicyPCR(t->esys, *session, ESYS_TR_NONE,
				    ESYS_TR_NONE, ESYS_TR_NONE, &live, &sel);
	}
	if (rc == TSS2_RC_SUCCESS) {
		branches.digests[0].size = 32;
		memcpy(branches.digests[0].buffer, branch_written, 32);
		branches.digests[1].size = 32;
		memcpy(branches.digests[1].buffer, branch_init, 32);
		rc = Esys_PolicyOR(t->esys, *session, ESYS_TR_NONE,
				   ESYS_TR_NONE, ESYS_TR_NONE, &branches);
	}
	if (rc != TSS2_RC_SUCCESS) {
		if (rc_is(rc, TPM2_RC_VALUE) && init)
			pr_err("tpm: the anchoring PCR moved; the register "
			       "can only be initialised in the boot window");
		else
			pr_err("tpm: register policy assertion: rc=0x%08x",
			       (unsigned)rc);
		session_flush(t, *session);
		*session = ESYS_TR_NONE;
		return -EACCES;
	}
	rc = Esys_PolicyGetDigest(t->esys, *session, ESYS_TR_NONE,
				  ESYS_TR_NONE, ESYS_TR_NONE, &digest);
	shirudo_tpm_policy_or(branch_written, branch_init, expected);
	if (rc != TSS2_RC_SUCCESS || digest->size != 32 ||
	    memcmp(digest->buffer, expected, 32) != 0) {
		pr_err("tpm: register policy digest does not match the "
		       "computed policy (rc=0x%08x)", (unsigned)rc);
		Esys_Free(digest);
		session_flush(t, *session);
		*session = ESYS_TR_NONE;
		return -EPROTO;
	}
	Esys_Free(digest);
	return 0;
}

static int nv_extend_session(struct shirudo_tpm *t, uint32_t index,
			     ESYS_TR session, const uint8_t event[32])
{
	TPM2B_MAX_NV_BUFFER data = { .size = SHIRUDO_TPM_NV_DIGEST_LEN };
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	memcpy(data.buffer, event, SHIRUDO_TPM_NV_DIGEST_LEN);
	rc = Esys_NV_Extend(t->esys, nv, nv, session, ESYS_TR_NONE,
			    ESYS_TR_NONE, &data);
	Esys_TR_Close(t->esys, &nv);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_Extend(0x%08x): rc=0x%08x", index,
		       (unsigned)rc);
		return rc_is_auth_failure(rc) ? -EACCES : -EIO;
	}
	return 0;
}

int shirudo_tpm_nv_extend_first(struct shirudo_tpm *t, uint32_t index,
				uint32_t pcr_mask,
				const uint8_t branch_written[32],
				const uint8_t branch_init[32],
				const uint8_t event[32])
{
	ESYS_TR session = ESYS_TR_NONE;
	int err;

	err = policy_session_register(t, true, pcr_mask, branch_written,
				      branch_init, &session);
	if (err)
		return err;
	err = nv_extend_session(t, index, session, event);
	session_flush(t, session);
	return err;
}

int shirudo_tpm_nv_extend(struct shirudo_tpm *t, uint32_t index,
			  const uint8_t branch_written[32],
			  const uint8_t branch_init[32],
			  const uint8_t event[32])
{
	ESYS_TR session = ESYS_TR_NONE;
	int err;

	err = policy_session_register(t, false, 0, branch_written,
				      branch_init, &session);
	if (err)
		return err;
	err = nv_extend_session(t, index, session, event);
	session_flush(t, session);
	return err;
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static size_t put2b(uint8_t *p, const uint8_t *data, uint16_t len)
{
	put16(p, len);
	memcpy(p + 2, data, len);
	return 2u + len;
}

/* The marshalled form of a public area libtss2 handed back. */
static int public_from_tss(const TPMT_PUBLIC *p, uint8_t *out, size_t cap,
			   size_t *len)
{
	struct shirudo_tpm_public pub = {};

	if (p->nameAlg != TPM2_ALG_SHA256 || p->authPolicy.size > 32)
		return -EINVAL;
	pub.type = p->type;
	pub.attrs = p->objectAttributes;
	pub.policy_len = p->authPolicy.size;
	memcpy(pub.policy, p->authPolicy.buffer, pub.policy_len);
	if (p->type == TPM2_ALG_ECC) {
		const TPMS_ECC_PARMS *ecc = &p->parameters.eccDetail;

		pub.sym_alg = ecc->symmetric.algorithm;
		if (pub.sym_alg != TPM2_ALG_NULL) {
			pub.sym_bits = ecc->symmetric.keyBits.aes;
			pub.sym_mode = ecc->symmetric.mode.aes;
		}
		pub.scheme = ecc->scheme.scheme;
		if (pub.scheme != TPM2_ALG_NULL)
			pub.scheme_hash = ecc->scheme.details.anySig.hashAlg;
		pub.curve = ecc->curveID;
		if (ecc->kdf.scheme != TPM2_ALG_NULL ||
		    p->unique.ecc.x.size != 32 || p->unique.ecc.y.size != 32)
			return -EINVAL;
		memcpy(pub.x, p->unique.ecc.x.buffer, 32);
		memcpy(pub.y, p->unique.ecc.y.buffer, 32);
	} else if (p->type == TPM2_ALG_RSA) {
		const TPMS_RSA_PARMS *rsa = &p->parameters.rsaDetail;

		pub.sym_alg = rsa->symmetric.algorithm;
		if (pub.sym_alg != TPM2_ALG_NULL) {
			pub.sym_bits = rsa->symmetric.keyBits.aes;
			pub.sym_mode = rsa->symmetric.mode.aes;
		}
		pub.scheme = rsa->scheme.scheme;
		if (pub.scheme != TPM2_ALG_NULL)
			pub.scheme_hash = rsa->scheme.details.anySig.hashAlg;
		pub.rsa_bits = rsa->keyBits;
		pub.rsa_exponent = rsa->exponent;
		if (p->unique.rsa.size > sizeof(pub.n))
			return -EINVAL;
		pub.n_len = p->unique.rsa.size;
		memcpy(pub.n, p->unique.rsa.buffer, pub.n_len);
	} else {
		return -EPROTONOSUPPORT;
	}
	return shirudo_tpm_public_marshal(&pub, out, cap, len);
}

static int marshal_signature(const TPMT_SIGNATURE *sig, uint8_t *out,
			     size_t cap, size_t *len)
{
	const TPMS_SIGNATURE_ECDSA *e = &sig->signature.ecdsa;
	size_t off = 0;

	if (sig->sigAlg != TPM2_ALG_ECDSA || e->signatureR.size > 64 ||
	    e->signatureS.size > 64 || cap < 8u + 128u)
		return -EINVAL;
	put16(out + off, sig->sigAlg);
	off += 2;
	put16(out + off, e->hash);
	off += 2;
	off += put2b(out + off, e->signatureR.buffer, e->signatureR.size);
	off += put2b(out + off, e->signatureS.buffer, e->signatureS.size);
	*len = off;
	return 0;
}

/*
 * Create a primary under the endorsement hierarchy and take its
 * marshalled public area and its name, the latter checked against the
 * area so that what the evidence carries is what the TPM named.
 */
static int endorsement_primary(struct shirudo_tpm *t,
			       const TPM2B_PUBLIC *in_pub, const char *what,
			       struct shirudo_tpm_key *key)
{
	TPM2B_SENSITIVE_CREATE sensitive = {};
	TPML_PCR_SELECTION creation_pcr = {};
	TPM2B_PUBLIC *out_pub = NULL;
	TPM2B_NAME *name = NULL;
	TPM2B_DATA outside = {};
	uint8_t computed[SHIRUDO_TPM_NAME_LEN];
	ESYS_TR handle;
	TSS2_RC rc;
	int err;

	memset(key, 0, sizeof(*key));
	rc = Esys_CreatePrimary(t->esys, ESYS_TR_RH_ENDORSEMENT,
				ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
				&sensitive, in_pub, &outside, &creation_pcr,
				&handle, &out_pub, NULL, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		if (rc_is_auth_failure(rc))
			pr_err("tpm: CreatePrimary(%s): the endorsement "
			       "hierarchy has an auth value (rc=0x%08x)", what,
			       (unsigned)rc);
		else
			pr_err("tpm: CreatePrimary(%s): rc=0x%08x", what,
			       (unsigned)rc);
		return -EIO;
	}
	key->handle = handle;
	err = public_from_tss(&out_pub->publicArea, key->public,
			      sizeof(key->public), &key->public_len);
	Esys_Free(out_pub);
	if (!err)
		err = shirudo_tpm_object_name(key->public, key->public_len,
					      computed);
	if (!err) {
		rc = Esys_TR_GetName(t->esys, handle, &name);
		if (rc != TSS2_RC_SUCCESS || name->size != sizeof(computed) ||
		    memcmp(name->name, computed, sizeof(computed)) != 0) {
			pr_err("tpm: %s name does not match its marshalled "
			       "public area", what);
			err = -EPROTO;
		} else {
			memcpy(key->name, name->name, name->size);
			key->name_len = name->size;
		}
		Esys_Free(name);
	}
	if (err)
		shirudo_tpm_key_flush(t, key);
	return err;
}

int shirudo_tpm_ak_create(struct shirudo_tpm *t, struct shirudo_tpm_key *ak)
{
	TPM2B_PUBLIC in_pub = {};

	in_pub.publicArea.type = TPM2_ALG_ECC;
	in_pub.publicArea.nameAlg = TPM2_ALG_SHA256;
	in_pub.publicArea.objectAttributes =
		TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT;
	in_pub.publicArea.parameters.eccDetail.symmetric.algorithm =
		TPM2_ALG_NULL;
	in_pub.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
	in_pub.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
		TPM2_ALG_SHA256;
	in_pub.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
	in_pub.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
	return endorsement_primary(t, &in_pub, "attestation key", ak);
}

int shirudo_tpm_ek_create(struct shirudo_tpm *t, bool rsa,
			  struct shirudo_tpm_key *ek)
{
	TPM2B_PUBLIC in_pub = {};
	TPMT_PUBLIC *pub = &in_pub.publicArea;

	pub->type = rsa ? TPM2_ALG_RSA : TPM2_ALG_ECC;
	pub->nameAlg = TPM2_ALG_SHA256;
	pub->objectAttributes = SHIRUDO_TPM_EK_ATTRS;
	pub->authPolicy.size = 32;
	memcpy(pub->authPolicy.buffer, shirudo_tpm_ek_policy, 32);
	if (rsa) {
		TPMS_RSA_PARMS *p = &pub->parameters.rsaDetail;

		p->symmetric.algorithm = TPM2_ALG_AES;
		p->symmetric.keyBits.aes = 128;
		p->symmetric.mode.aes = TPM2_ALG_CFB;
		p->scheme.scheme = TPM2_ALG_NULL;
		p->keyBits = 2048;
		p->exponent = 0;
		pub->unique.rsa.size = 256;
	} else {
		TPMS_ECC_PARMS *p = &pub->parameters.eccDetail;

		p->symmetric.algorithm = TPM2_ALG_AES;
		p->symmetric.keyBits.aes = 128;
		p->symmetric.mode.aes = TPM2_ALG_CFB;
		p->scheme.scheme = TPM2_ALG_NULL;
		p->curveID = TPM2_ECC_NIST_P256;
		p->kdf.scheme = TPM2_ALG_NULL;
		pub->unique.ecc.x.size = 32;
		pub->unique.ecc.y.size = 32;
	}
	return endorsement_primary(t, &in_pub, "endorsement key", ek);
}

void shirudo_tpm_key_flush(struct shirudo_tpm *t, struct shirudo_tpm_key *key)
{
	if (key->handle != ESYS_TR_NONE && key->handle != 0)
		Esys_FlushContext(t->esys, key->handle);
	explicit_bzero(key, sizeof(*key));
	key->handle = ESYS_TR_NONE;
}

static int attestation_copy(const TPM2B_ATTEST *attest,
			    const TPMT_SIGNATURE *sig,
			    struct shirudo_tpm_attestation *out)
{
	if (attest->size > sizeof(out->attest))
		return -E2BIG;
	memcpy(out->attest, attest->attestationData, attest->size);
	out->attest_len = attest->size;
	return marshal_signature(sig, out->signature, sizeof(out->signature),
				 &out->signature_len);
}

int shirudo_tpm_quote(struct shirudo_tpm *t, const struct shirudo_tpm_key *ak,
		      const uint8_t *nonce, size_t nonce_len, uint32_t pcr_mask,
		      struct shirudo_tpm_attestation *out)
{
	TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL };
	TPMT_SIGNATURE *sig = NULL;
	TPM2B_ATTEST *quoted = NULL;
	TPML_PCR_SELECTION sel;
	TPM2B_DATA qual = {};
	TSS2_RC rc;
	int err;

	if (nonce_len > sizeof(qual.buffer))
		return -EINVAL;
	memcpy(qual.buffer, nonce, nonce_len);
	qual.size = (uint16_t)nonce_len;
	pcr_selection(pcr_mask, &sel);
	rc = Esys_Quote(t->esys, ak->handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
			ESYS_TR_NONE, &qual, &scheme, &sel, &quoted, &sig);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: Quote: rc=0x%08x", (unsigned)rc);
		return -EIO;
	}
	err = attestation_copy(quoted, sig, out);
	Esys_Free(quoted);
	Esys_Free(sig);
	return err;
}

int shirudo_tpm_nv_certify(struct shirudo_tpm *t,
			   const struct shirudo_tpm_key *ak, uint32_t index,
			   const uint8_t *nonce, size_t nonce_len,
			   struct shirudo_tpm_attestation *out)
{
	TPMT_SIG_SCHEME scheme = { .scheme = TPM2_ALG_NULL };
	TPMT_SIGNATURE *sig = NULL;
	TPM2B_ATTEST *info = NULL;
	TPM2B_DATA qual = {};
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	if (nonce_len > sizeof(qual.buffer))
		return -EINVAL;
	memcpy(qual.buffer, nonce, nonce_len);
	qual.size = (uint16_t)nonce_len;
	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	rc = Esys_NV_Certify(t->esys, ak->handle, nv, nv, ESYS_TR_PASSWORD,
			     ESYS_TR_PASSWORD, ESYS_TR_NONE, &qual, &scheme,
			     SHIRUDO_TPM_NV_DIGEST_LEN, 0, &info, &sig);
	Esys_TR_Close(t->esys, &nv);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: NV_Certify(0x%08x): rc=0x%08x", index,
		       (unsigned)rc);
		return rc_is(rc, TPM2_RC_NV_UNINITIALIZED) ? -ENODATA : -EIO;
	}
	err = attestation_copy(info, sig, out);
	Esys_Free(info);
	Esys_Free(sig);
	return err;
}

int shirudo_tpm_activate_credential(struct shirudo_tpm *t,
				    const struct shirudo_tpm_key *ak,
				    const struct shirudo_tpm_key *ek,
				    const uint8_t *blob, size_t blob_len,
				    const uint8_t *secret, size_t secret_len,
				    uint8_t *out, size_t cap, size_t *out_len)
{
	TPM2B_ENCRYPTED_SECRET sec = {};
	TPM2B_DIGEST *cert_info = NULL;
	ESYS_TR session = ESYS_TR_NONE;
	TPM2B_ID_OBJECT id = {};
	TSS2_RC rc;
	int err;

	if (blob_len > sizeof(id.credential) || secret_len > sizeof(sec.secret))
		return -EINVAL;
	id.size = (uint16_t)blob_len;
	memcpy(id.credential, blob, blob_len);
	sec.size = (uint16_t)secret_len;
	memcpy(sec.secret, secret, secret_len);
	err = policy_session_start(t, &session);
	if (err)
		return err;
	/* The endorsement key's policy: the hierarchy's own authorisation. */
	rc = Esys_PolicySecret(t->esys, ESYS_TR_RH_ENDORSEMENT, session,
			       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			       NULL, NULL, NULL, 0, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: PolicySecret(endorsement): rc=0x%08x",
		       (unsigned)rc);
		session_flush(t, session);
		return -EACCES;
	}
	rc = Esys_ActivateCredential(t->esys, ak->handle, ek->handle,
				     ESYS_TR_PASSWORD, session, ESYS_TR_NONE,
				     &id, &sec, &cert_info);
	session_flush(t, session);
	if (rc != TSS2_RC_SUCCESS) {
		pr_err("tpm: ActivateCredential: rc=0x%08x", (unsigned)rc);
		return (rc & 0xFFFF0000u) == 0 ? -EKEYREJECTED : -EIO;
	}
	if (cert_info->size > cap) {
		Esys_Free(cert_info);
		return -E2BIG;
	}
	memcpy(out, cert_info->buffer, cert_info->size);
	*out_len = cert_info->size;
	Esys_Free(cert_info);
	return 0;
}

static int nv_read_all(struct shirudo_tpm *t, uint32_t index, uint8_t *out,
		       size_t cap, size_t *len)
{
	TPM2B_NV_PUBLIC *pub = NULL;
	size_t off = 0, total;
	ESYS_TR nv;
	TSS2_RC rc;
	int err;

	err = nv_handle(t, index, &nv);
	if (err)
		return err;
	rc = Esys_NV_ReadPublic(t->esys, nv, ESYS_TR_NONE, ESYS_TR_NONE,
				ESYS_TR_NONE, &pub, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		Esys_TR_Close(t->esys, &nv);
		return -EIO;
	}
	total = pub->nvPublic.dataSize;
	Esys_Free(pub);
	if (total > cap) {
		Esys_TR_Close(t->esys, &nv);
		return -E2BIG;
	}
	while (off < total) {
		TPM2B_MAX_NV_BUFFER *data = NULL;
		size_t want = total - off;

		if (want > NV_READ_CHUNK)
			want = NV_READ_CHUNK;
		rc = Esys_NV_Read(t->esys, nv, nv, ESYS_TR_PASSWORD,
				  ESYS_TR_NONE, ESYS_TR_NONE, (UINT16)want,
				  (UINT16)off, &data);
		if (rc != TSS2_RC_SUCCESS) {
			Esys_TR_Close(t->esys, &nv);
			return -EIO;
		}
		if (data->size == 0 || data->size > want) {
			Esys_Free(data);
			Esys_TR_Close(t->esys, &nv);
			return -EIO;
		}
		memcpy(out + off, data->buffer, data->size);
		off += data->size;
		Esys_Free(data);
	}
	Esys_TR_Close(t->esys, &nv);
	*len = total;
	return 0;
}

int shirudo_tpm_ek_certificate(struct shirudo_tpm *t, uint8_t *out,
			       size_t cap, size_t *len, bool *rsa)
{
	int err;

	*rsa = false;
	err = nv_read_all(t, EK_CERT_NV_ECC, out, cap, len);
	if (err == -ENOENT) {
		err = nv_read_all(t, EK_CERT_NV_RSA, out, cap, len);
		*rsa = err == 0;
	}
	return err;
}
