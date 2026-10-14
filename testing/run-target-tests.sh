#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Run the complete target-side VM suite. All build/sign work is performed by
# the host bundle builder; target tests consume only prebuilt fixtures.

set -eu

cd "$(dirname "$0")"

# t1106 deliberately destroys the keyring trust anchor and must run last.
fail=0
: "${SHIRUDO_TEST_SUITE_FAILURES_FILE:=}"
for t in \
	t1200-target-fixtures.sh \
	t1118-bpm-tree.sh \
	t1119-bpm-tree-sequential.sh \
	t1120-bpm-tree-delete.sh \
	t1101-seal.sh \
	t1102-eventlog-full.sh \
	t1103-version-gate.sh \
	t1104-payload-mismatch.sh \
	t1105-siggate.sh \
	t1107-load-unload.sh \
	t1108-tpm-chain.sh \
	t1110-lsm-deny.sh \
	t1111-upatch-get.sh \
	t1112-prog-load-keyring-gate.sh \
	t1113-mount-lockdown.sh \
	t1114-uprobe-multi.sh \
	t1115-map-export-all.sh \
	t1116-otel-backend.sh \
	t1117-otel-serialized-metric.sh \
	t1121-bpf-keyring.sh \
	t1106-keyring-swap.sh
do
	if sh "$t"; then
		:
	else
		fail=$((fail + 1))
		if [ -n "$SHIRUDO_TEST_SUITE_FAILURES_FILE" ]; then
			printf '%s\n' "$t" >>"$SHIRUDO_TEST_SUITE_FAILURES_FILE" 2>/dev/null || :
		fi
	fi
done

exit "$fail"
