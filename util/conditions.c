// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared local security conditions block + status verdict.
 */

#include <stdio.h>
#include <string.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "conditions.h"

/*
 * A tampered verdict gets no remedy: the node is not to be talked back
 * into service, only preserved and investigated.
 */
#define HINT_INCIDENT	"shirudo considers this node tampered: do not retry or work around it, keep the eventlog and journal as evidence and handle it as an incident"
#define HINT_LSM_OFF	"enforcement is off: if init did not complete this boot, `journalctl -b -u shirudo-initrd.service -u shirudo.service` names the failed step; if it did, handle the node as an incident"
#define HINT_NO_INIT	"on a target, shirudo init has not run this boot: `shirudo init --check-only` lists what is missing and the shirudo-initrd.service journal says why"
#define HINT_NO_TPM	"no TPM answered: check that /dev/tpmrm0 exists (tpm_tis or tpm_crb loaded) or that tpm.tcti names a reachable TPM; shirudo requires a TPM 2.0"
#define HINT_UNBOUND	"shirudo init did not set up the TPM register this boot: the shirudo-initrd.service and shirudo.service journals name the step that failed; fix it and run `shirudo init` again"

size_t conditions(const struct shirudo_conditions_input *in,
		  struct shirudo_condition *c, size_t cap)
{
	size_t n = 0;

	if (n < cap) {
		c[n].type = "LsmAttached";
		c[n].status = in->lsm_attached ? "OK" : "ALERT";
		c[n].hint = in->lsm_attached ? NULL : HINT_LSM_OFF;
		strscpy(c[n].detail, in->lsm_attached ?
			"the shirudo LSM is attached and pinned" :
			"the shirudo LSM is not attached, enforcement is OFF",
			sizeof(c[n].detail));
		n++;
	}
	if (n < cap) {
		c[n].type = "KeyringSealed";
		c[n].hint = NULL;
		if (!in->keyring_present && in->ksp_seen) {
			c[n].status = "ALERT";
			c[n].hint = HINT_INCIDENT;
			if (strsprintf(c[n].detail, sizeof(c[n].detail),
				       "the .bpf keyring init recorded (serial %lld) is gone (removed?)",
				       (__s64)in->keyring_serial_pinned) < 0)
				strscpy(c[n].detail, "?", sizeof(c[n].detail));
		} else if (!in->keyring_present) {
			c[n].status = "WARN";
			c[n].hint = HINT_NO_INIT;
			strscpy(c[n].detail,
				"no .bpf keyring recorded (init not run?)",
				sizeof(c[n].detail));
		} else if (in->ksm_seen && !in->keyring_serial_matches) {
			c[n].status = "ALERT";
			c[n].hint = HINT_INCIDENT;
			if (strsprintf(c[n].detail, sizeof(c[n].detail),
				       "the live .bpf keyring (serial %lld) is not the one init recorded (serial %lld) (swapped?)",
				       (__s64)in->keyring_serial,
				       (__s64)in->keyring_serial_pinned) < 0)
				strscpy(c[n].detail, "?", sizeof(c[n].detail));
		} else {
			c[n].status = "OK";
			if (strsprintf(c[n].detail, sizeof(c[n].detail),
				       ".bpf keyring serial %lld, %s",
				       (__s64)in->keyring_serial,
				       in->ksp_seen ? "the one init recorded" :
				       "not recorded by init") < 0)
				strscpy(c[n].detail, "?", sizeof(c[n].detail));
		}
		n++;
	}
	if (n < cap) {
		c[n].type = "ChainIntact";
		c[n].hint = NULL;
		if (!in->chain_seen) {
			c[n].status = "WARN";
			c[n].hint = in->tpm_reachable ? HINT_UNBOUND : HINT_NO_TPM;
			strscpy(c[n].detail, in->tpm_reachable ?
				"no TPM register set up this boot (init incomplete)" :
				"no TPM answered, nothing to compare",
				sizeof(c[n].detail));
		} else if (in->cm_seen && in->chain_matches) {
			c[n].status = "OK";
			strscpy(c[n].detail,
				"the TPM register matches the eventlog",
				sizeof(c[n].detail));
		} else if (in->cm_seen) {
			c[n].status = "ALERT";
			c[n].hint = HINT_INCIDENT;
			if (!in->chain_mismatch)
				strscpy(c[n].detail,
					"the TPM register does not match the eventlog (tamper?)",
					sizeof(c[n].detail));
			else if (strsprintf(c[n].detail, sizeof(c[n].detail),
					    "%s (tamper?)",
					    in->chain_mismatch) < 0)
				strscpy(c[n].detail, "?", sizeof(c[n].detail));
		} else {
			c[n].status = "WARN";
			strscpy(c[n].detail,
				"TPM register present, not compared with the eventlog",
				sizeof(c[n].detail));
		}
		n++;
	}
	if (n < cap) {
		c[n].type = "TpmMeasured";
		c[n].status = in->chain_seen ? "OK" : "WARN";
		c[n].hint = in->chain_seen ? NULL :
			    in->tpm_reachable ? HINT_UNBOUND : HINT_NO_TPM;
		if (in->chain_seen) {
			if (strsprintf(c[n].detail, sizeof(c[n].detail),
				       "NV index %s is set up and readable",
				       in->nv_index ? in->nv_index : "?") < 0)
				strscpy(c[n].detail, "?", sizeof(c[n].detail));
		} else if (in->tpm_reachable) {
			if (strsprintf(c[n].detail, sizeof(c[n].detail),
				       "NV index %s is not set up this boot",
				       in->nv_index ? in->nv_index : "?") < 0)
				strscpy(c[n].detail, "?", sizeof(c[n].detail));
		} else {
			strscpy(c[n].detail, "no TPM answered",
				sizeof(c[n].detail));
		}
		n++;
	}
	return n;
}

static bool hint_shown(const struct shirudo_condition *c, size_t i,
		       const char *shown)
{
	size_t j;

	if (shown && !strcmp(c[i].hint, shown))
		return true;
	for (j = 0; j < i; j++) {
		if (c[j].hint && !strcmp(c[j].hint, c[i].hint))
			return true;
	}
	return false;
}

void conditions_print(const struct shirudo_condition *c, size_t n,
		      bool hints, const char *shown)
{
	size_t i;

	printf("Conditions:\n");
	printf("  %-16s %-7s %s\n", "TYPE", "STATUS", "DETAIL");
	for (i = 0; i < n; i++) {
		printf("  %-16s %-7s %s\n", c[i].type, c[i].status,
		       c[i].detail);
		if (hints && c[i].hint && !hint_shown(c, i, shown))
			printf("  %-16s %-7s hint: %s\n", "", "", c[i].hint);
	}
}

const char *status_verdict(const struct shirudo_conditions_input *in)
{
	if (!in->reachable)
		return "unreachable";
	if (!in->parsed)
		return "unparseable";
	if ((in->cm_seen && !in->chain_matches) ||
	    (in->ksm_seen && !in->keyring_serial_matches) ||
	    (in->ksp_seen && !in->keyring_present))
		return "tampered";
	if (!in->lsm_attached)
		return "lsm-off";
	if (!in->keyring_present)
		return "init-pending";
	if (!in->chain_seen)
		return "degraded";
	return "ok";
}

void status_reason(const struct shirudo_conditions_input *in,
		   char *buf, size_t cap)
{
	const char *v = status_verdict(in);

	buf[0] = '\0';
	if (strcmp(v, "unreachable") == 0) {
		if (in->unreach)
			strscpy(buf, in->unreach, cap);
	} else if (strcmp(v, "unparseable") == 0) {
		strscpy(buf, "status JSON unparseable", cap);
	} else if (strcmp(v, "tampered") == 0) {
		if (in->cm_seen && !in->chain_matches)
			strscpy(buf, in->chain_mismatch ? in->chain_mismatch :
				"the TPM register does not match the eventlog",
				cap);
		else if (!in->keyring_present)
			strscpy(buf, "the .bpf keyring init recorded is gone",
				cap);
		else
			strscpy(buf, "the .bpf keyring was swapped", cap);
	} else if (strcmp(v, "lsm-off") == 0) {
		strscpy(buf, "the shirudo LSM is not attached, enforcement is OFF",
			cap);
	} else if (strcmp(v, "init-pending") == 0) {
		strscpy(buf, "`shirudo init` has not run this boot", cap);
	} else if (strcmp(v, "degraded") == 0) {
		strscpy(buf, in->tpm_reachable ?
			"no TPM register set up this boot" : "no TPM answered",
			cap);
	}
}

const char *status_hint(const struct shirudo_conditions_input *in)
{
	const char *v = status_verdict(in);

	if (strcmp(v, "tampered") == 0)
		return HINT_INCIDENT;
	if (strcmp(v, "lsm-off") == 0)
		return HINT_LSM_OFF;
	if (strcmp(v, "init-pending") == 0)
		return HINT_NO_INIT;
	if (strcmp(v, "degraded") == 0)
		return in->tpm_reachable ? HINT_UNBOUND : HINT_NO_TPM;
	return NULL;
}
