#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Run the target-side VM suite. Build/sign tests remain in run-tests.sh and
# execute on the operator host; this list consumes only prebuilt fixtures.

set -eu

cd "$(dirname "$0")"

fail=0
: "${SHIRUDO_TEST_SUITE_FAILURES_FILE:=}"
for t in \
	t1102-eventlog-full.sh \
	t1103-version-gate.sh \
	t1200-target-fixtures.sh \
	t1109-rollout-libssh.sh \
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
