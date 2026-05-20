# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t/test-lib.sh -- minimal TAP-style test harness, whiteroom of the
# subset shirudo uses. Sourced by each tNNNN-*.sh test.
#
# Public API (stable):
#   test_expect_success "<title>" "<body>"
#   test_skip_all "<reason>"
#   test_done

set -eu

: "${TAP_COUNT:=0}"
: "${TAP_FAILED:=0}"

# Skip the whole script (TAP "1..0 # SKIP"). For tests whose
# prerequisites (root, kernel feature, opt-in env) are absent: a clean
# pass for the runner, never a failure.
test_skip_all() {
	printf '1..0 # SKIP %s\n' "$*"
	exit 0
}

test_expect_success() {
	local title="$1" body="$2"
	TAP_COUNT=$((TAP_COUNT + 1))
	if (eval "$body") >/dev/null 2>&1; then
		printf 'ok %d - %s\n' "$TAP_COUNT" "$title"
	else
		printf 'not ok %d - %s\n' "$TAP_COUNT" "$title"
		TAP_FAILED=$((TAP_FAILED + 1))
	fi
}

test_done() {
	printf '1..%d\n' "$TAP_COUNT"
	if [ "$TAP_FAILED" -gt 0 ]; then
		exit 1
	fi
	exit 0
}
