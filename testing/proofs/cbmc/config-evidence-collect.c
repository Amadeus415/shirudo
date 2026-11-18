// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * config_evidence_collect() and collect_event() of util/config_attest.c on
 * every journal of LEN records and every active selection, the journal's
 * reader a stub that hands them over and SHA-256 any result: a history is
 * exported only as this TPM boot's records, in order and ending at the
 * selection, and a refusal returns nothing and leaves nothing allocated.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/config_measure.c"
/* The C converts a __s64 and cuts a __u64 to bytes on purpose. */
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#include "../../../util/chain.c"
#pragma CPROVER check pop
#include "../../../util/config_attest.c"

static const struct config_update_record *journal, *selection;
static int check_result, read_result;
static __u8 last_digest[32];
static bool hash_failed;

static int any_result(void)
{
	int ret;

	return ret;
}

int sha256_buffer(const void *data, size_t len, __u8 out[32])
{
	int ret = any_result();

	__CPROVER_assert(__CPROVER_r_ok(data, len), "hashes only its input");
	__CPROVER_assert(__CPROVER_w_ok(out, 32), "a digest's room");
	__CPROVER_havoc_slice(out, 32);
	memcpy(last_digest, out, 32);
	if (ret)
		hash_failed = true;
	return ret;
}

int config_update_check(struct config_update *update,
			struct config_update_record *out)
{
	if (!check_result)
		*out = *selection;
	return check_result;
}

int config_update_events(struct config_update *update,
			 shirudo_config_cb consume, void *ctx)
{
	size_t i;
	int ret;

	for (i = 0; i < LEN; i++) {
		ret = consume(&journal[i], ctx);
		if (ret)
			return ret;
	}
	return read_result;
}

static bool same(const __u8 *a, const __u8 *b)
{
	size_t i;

	for (i = 0; i < 32; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

static bool blank(const struct config_evidence *view)
{
	size_t i;

	for (i = 0; i < 32; i++)
		if (view->initial_pcr[i] || view->value[i])
			return false;
	return !view->events && !view->n_events && !view->capacity &&
	       !view->reset_count && !view->restart_count && !view->pcr &&
	       !view->present;
}

static bool this_boot(const struct config_update_record *record)
{
	return record->reset_count == selection->reset_count &&
	       record->restart_count == selection->restart_count;
}

/* On the selection's PCR, from its initial value, a sequence in a __s64. */
static bool agrees(const struct config_update_record *record)
{
	return record->pcr == selection->pcr &&
	       record->sequence <= INT64_MAX &&
	       same(record->initial_pcr, selection->initial_pcr);
}

/*
 * Whether this boot's records are one boot event, then updates in sequence,
 * that end at the selection; *n counts them.
 */
static bool history(size_t *n)
{
	const struct config_update_record *last = NULL;
	size_t i;

	*n = 0;
	for (i = 0; i < LEN; i++) {
		if (!this_boot(&journal[i]))
			continue;
		if (!agrees(&journal[i]) || !journal[i].sequence ||
		    journal[i].kind != (last ? CONFIG_EVENT_UPDATE :
					       CONFIG_EVENT_BOOT) ||
		    (last && journal[i].sequence - last->sequence != 1))
			return false;
		last = &journal[i];
		(*n)++;
	}
	return last && last->sequence == selection->sequence &&
	       same(last->target.root_hash, selection->target.root_hash);
}

static void check_exported(const struct config_evidence *view, size_t n)
{
	size_t i, at = 0;

	__CPROVER_assert(view->present && view->pcr == selection->pcr &&
			 view->reset_count == selection->reset_count &&
			 view->restart_count == selection->restart_count &&
			 same(view->initial_pcr, selection->initial_pcr),
			 "the selection's PCR, TPM boot and initial value");
	__CPROVER_assert(view->n_events == n && n <= view->capacity,
			 "this boot's records and no other, inside their room");
	for (i = 0; i < LEN; i++) {
		if (!this_boot(&journal[i]))
			continue;
		__CPROVER_assert(view->events[at].sequence ==
				 journal[i].sequence &&
				 view->events[at].kind == journal[i].kind &&
				 same(view->events[at].root_hash,
				      journal[i].target.root_hash),
				 "each as the journal has it, in its order");
		at++;
	}
	__CPROVER_assert(same(view->value, last_digest),
			 "the value after the last event");
}

void harness(void)
{
	struct config_update update, *given = NULL;
	struct config_evidence view;
	bool attested, whole;
	size_t n;
	int ret;

	journal = any_bytes(LEN * sizeof(*journal));
	selection = any_bytes(sizeof(*selection));
	check_result = any_result();
	read_result = any_result();
	if (attested)
		given = &update;
	ret = config_evidence_collect(given, &view);
	if (!given) {
		__CPROVER_assert(!ret && blank(&view),
				 "no config state exports no history");
		return;
	}
	whole = history(&n);
	__CPROVER_assert(!ret == (!check_result && !read_result && whole &&
				  !hash_failed),
			 "exports exactly a checked selection with its history whole");
	if (ret)
		__CPROVER_assert(blank(&view), "a refusal returns nothing");
	else
		check_exported(&view, n);
	config_evidence_clear(&view);
}
