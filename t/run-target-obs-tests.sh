#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu

cd "$(dirname "$0")"

fail=0
: "${SHIRUDO_TEST_SUITE_FAILURES_FILE:=}"
if sh t1210-linux-observability.sh; then
	:
else
	fail=$((fail + 1))
	if [ -n "$SHIRUDO_TEST_SUITE_FAILURES_FILE" ]; then
		printf '%s\n' t1210-linux-observability.sh \
			>>"$SHIRUDO_TEST_SUITE_FAILURES_FILE" 2>/dev/null || :
	fi
fi

exit "$fail"
