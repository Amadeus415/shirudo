#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1108 -- TPM measurement chain: on a host with a live NV chain, the
# eventlog replayed from zero must reproduce the live NV value (that is
# exactly the chain_matches_eventlog verdict `status` computes). Needs a
# usable TPM; on --no-tpm, degraded, or owner-auth-blocked hosts there
# is no chain and the test skips (it runs on the CI vTPM runner).

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

tpm_chain() {
	"$SHIRUDO_BIN" status --json --include-tpm 2>/dev/null | python3 -c '
import sys, json
d = json.load(sys.stdin)
t = d.get("tpm") or {}
print(t.get(sys.argv[1], "") if t.get(sys.argv[1], None) is not None else "")
' "$1"
}

[ -n "$(tpm_chain chain)" ] ||
	test_skip_all "no live TPM chain (degraded / --no-tpm / no usable TPM)"

test_expect_success 'eventlog replay reproduces the live NV chain value' '
	[ "$(tpm_chain chain_matches_eventlog)" = "True" ]
'

test_done
