#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1109 -- rollout/nodes over libssh against a loopback target: nodes
# reaches it and reports it attached; nodes show renders a per-node
# describe and a structured --json; rollout --dry-run pre-flights and
# reports ok-dryrun (the version gate passes when operator == target);
# a bogus --expect-version-id is refused. All --dry-run, so no SFTP
# upload and no remote load -- non-mutating. Uses a temp remote registry.

cd "$(dirname "$0")"
. ./integration-lib.sh
integration_guard

ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
	root@127.0.0.1 true >/dev/null 2>&1 ||
	test_skip_all "no key-auth ssh to root@127.0.0.1"
ARCH=$(ls /var/lib/shirudo/upatches/*.upatch 2>/dev/null | head -1)
[ -n "$ARCH" ] || test_skip_all "no .upatch to dry-run"

XDG=$(mktemp -d)
export XDG_CONFIG_HOME="$XDG"
trap 'rm -rf "$XDG"' EXIT
"$SHIRUDO_BIN" remote add lo root@127.0.0.1 >/dev/null 2>&1 ||
	test_skip_all "remote add failed"

test_expect_success 'nodes reaches the loopback target over libssh' '
	"$SHIRUDO_BIN" nodes --filter=lo 2>/dev/null |
		grep -E "^lo[[:space:]]" | grep -q yes
'

test_expect_success 'nodes show renders a describe for the loopback target' '
	out=$("$SHIRUDO_BIN" nodes show lo 2>/dev/null) &&
	echo "$out" | grep -q "^Name:" &&
	echo "$out" | grep -q "Reachable:" &&
	echo "$out" | grep -q "Conditions:" &&
	echo "$out" | grep -q "System Info:"
'

test_expect_success 'nodes show --json is structured and reachable' '
	"$SHIRUDO_BIN" nodes show --json lo 2>/dev/null |
		grep -q "\"reachable\":true"
'

test_expect_success 'rollout --dry-run pre-flights over libssh (ok-dryrun)' '
	r=$("$SHIRUDO_BIN" rollout "$ARCH" lo --dry-run --report=- 2>/dev/null |
	    report_target_field result) &&
	[ "$r" = "ok-dryrun" ]
'

test_expect_success 'rollout --dry-run with a bogus version-id is refused' '
	r=$("$SHIRUDO_BIN" rollout "$ARCH" lo --dry-run \
	      --expect-version-id=deadbeefdeadbeef --report=- 2>/dev/null |
	    report_target_field result) &&
	[ "$r" = "failed" ]
'

test_done
