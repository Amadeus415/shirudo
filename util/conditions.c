// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared local security conditions block + status verdict.
 */

#include <stdio.h>
#include <string.h>

#include "conditions.h"

size_t shirudo_conditions(const struct shirudo_conditions_input *in,
			  struct shirudo_condition *c, size_t cap)
{
	size_t n = 0;

	if (n < cap) {
		c[n].type = "LsmAttached";
		c[n].status = in->lsm_attached ? "OK" : "ALERT";
		snprintf(c[n].detail, sizeof(c[n].detail), "%s",
			 in->lsm_attached ?
				"lsm/bpf link present and pinned" :
				"lsm/bpf absent -- enforcement OFF");
		n++;
	}
	if (n < cap) {
		c[n].type = "KeyringSealed";
		if (!in->keyring_present) {
			c[n].status = "WARN";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "shirudo keyring absent (not init'd?)");
		} else if (in->ksm_seen && !in->keyring_serial_matches) {
			c[n].status = "ALERT";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "pin serial=%lld != live serial=%lld (swapped?)",
				 (long long)in->keyring_serial_pinned,
				 (long long)in->keyring_serial);
		} else {
			c[n].status = "OK";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "serial=%lld, %s",
				 (long long)in->keyring_serial,
				 in->ksp_seen ? "pin matches"
					      : "no pin recorded");
		}
		n++;
	}
	if (n < cap) {
		c[n].type = "ChainIntact";
		if (!in->chain_seen) {
			c[n].status = "WARN";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "no TPM chain (degraded / --no-tpm)");
		} else if (in->cm_seen && in->chain_matches) {
			c[n].status = "OK";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "live NV chain == eventlog replay");
		} else if (in->cm_seen) {
			c[n].status = "ALERT";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "live NV chain != eventlog replay (tamper?)");
		} else {
			c[n].status = "WARN";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "chain present, replay not evaluated");
		}
		n++;
	}
	if (n < cap) {
		c[n].type = "TpmMeasured";
		c[n].status = in->chain_seen ? "OK" : "WARN";
		if (in->chain_seen)
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "NV index %s readable",
				 in->nv_index ? in->nv_index : "?");
		else
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "not measured");
		n++;
	}
	return n;
}

void shirudo_conditions_print(const struct shirudo_condition *c, size_t n)
{
	size_t i;

	printf("Conditions:\n");
	printf("  %-16s %-7s %s\n", "TYPE", "STATUS", "DETAIL");
	for (i = 0; i < n; i++)
		printf("  %-16s %-7s %s\n", c[i].type, c[i].status,
		       c[i].detail);
}

const char *shirudo_status_verdict(const struct shirudo_conditions_input *in)
{
	if (!in->reachable)
		return "unreachable";
	if (!in->parsed)
		return "unparseable";
	if ((in->cm_seen && !in->chain_matches) ||
	    (in->ksm_seen && !in->keyring_serial_matches))
		return "tampered";
	if (!in->lsm_attached)
		return "lsm-off";
	if (!in->keyring_present)
		return "init-pending";
	if (!in->chain_seen)
		return "degraded";
	return "ok";
}

void shirudo_status_reason(const struct shirudo_conditions_input *in,
			   char *buf, size_t cap)
{
	const char *v = shirudo_status_verdict(in);

	buf[0] = '\0';
	if (strcmp(v, "unreachable") == 0) {
		if (in->unreach)
			snprintf(buf, cap, "%s", in->unreach);
	} else if (strcmp(v, "unparseable") == 0) {
		snprintf(buf, cap, "status JSON unparseable");
	} else if (strcmp(v, "tampered") == 0) {
		if (in->cm_seen && !in->chain_matches)
			snprintf(buf, cap, "live NV chain != eventlog replay");
		else
			snprintf(buf, cap, "keyring serial swap detected");
	} else if (strcmp(v, "lsm-off") == 0) {
		snprintf(buf, cap, "LSM not attached -- enforcement OFF");
	} else if (strcmp(v, "init-pending") == 0) {
		snprintf(buf, cap, "target hasn't been `shirudo init`'d");
	} else if (strcmp(v, "degraded") == 0) {
		snprintf(buf, cap, "no TPM chain (unmeasured)");
	}
}
