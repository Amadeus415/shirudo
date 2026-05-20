# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t/integration-lib.sh -- shared setup for the t11xx integration tests.
#
# These exercise the LIVE kernel (BPF LSM, kernel keyring, bpffs) and
# the installed binary, so they run ONLY when explicitly opted in via
# SHIRUDO_INTEGRATION=1, and as root, against a host where `shirudo
# init` has already attached the LSM. shirudo is single-tenant with
# hardcoded paths, so there is no isolation: intended for a dedicated
# throwaway host (the CI vTPM runner) or a developer who has read what
# the test does. The t11xx tests here are all NON-destructive -- they
# assert refusal/denial paths and leave kernel/keyring state untouched.
#
# Sourced after a leading `cd "$(dirname "$0")"` in each test.

. ./test-lib.sh

# Binary under test (the one that init'd the host) and the operator-side
# builder. Overridable for out-of-tree layouts.
: "${SHIRUDO_BIN:=/usr/local/bin/shirudo}"
: "${SHIRUDO_BUILD_BIN:=../tools/shirudo-build/shirudo-build}"

# Skip the whole script unless every precondition holds.
integration_guard() {
	[ "${SHIRUDO_INTEGRATION:-}" = "1" ] ||
		test_skip_all "set SHIRUDO_INTEGRATION=1 to run (destructive-capable, live host)"
	[ "$(id -u)" = "0" ] ||
		test_skip_all "must run as root"
	[ -x "$SHIRUDO_BIN" ] ||
		test_skip_all "shirudo binary not executable: $SHIRUDO_BIN"
	[ -e /var/lib/shirudo/bpffs/lsm_link ] ||
		test_skip_all "LSM not attached; run \`shirudo init\` first"
}

# Echo the name of an arbitrary currently-loaded upatch, or "" if none.
first_loaded_upatch() {
	for d in /var/lib/shirudo/bpffs/upatches/*/; do
		[ -e "$d/link" ] || continue
		basename "$d"
		return 0
	done
	return 0
}

# Extract a top-level JSON field from a --report=- document on stdin.
report_field() {
	python3 -c '
import sys, json
raw = sys.stdin.read()
i = raw.find("{")
d = json.loads(raw[i:]) if i >= 0 else {}
print(d.get(sys.argv[1], ""))
' "$1"
}

# Extract targets[0].<field> from a rollout aggregate report on stdin.
report_target_field() {
	python3 -c '
import sys, json
raw = sys.stdin.read()
i = raw.find("{")
d = json.loads(raw[i:]) if i >= 0 else {}
t = (d.get("targets") or [{}])[0]
print(t.get(sys.argv[1], ""))
' "$1"
}
