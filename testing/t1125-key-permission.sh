#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1125 -- the trust anchor in the kernel's keyrings is root's to look
# at and nobody's but shirudo's to change: keyctl cannot unlink, clear,
# revoke, invalidate or re-permission the sealed keyring init froze or
# the certificate keys it holds, while viewing and listing them and
# loading against them keep working.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

command -v keyctl >/dev/null 2>&1 || test_skip_all "no keyctl"
RING=$("$SHIRUDO_BIN" status --json 2>/dev/null | report_field keyring_serial)
case "$RING" in
	''|None|0|-*) test_skip_all "no anchor keyring frozen this boot" ;;
esac
KEYS=$(keyctl rlist "$RING" 2>/dev/null)
[ -n "$KEYS" ] || test_skip_all "cannot list the anchor keyring $RING"
KEY=$(set -- $KEYS; echo "$1")
N_BEFORE=$(set -- $KEYS; echo $#)
keys_now() { set -- $(keyctl rlist "$RING" 2>/dev/null); echo $#; }
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

test_expect_success 'the anchor keyring and its keys are visible' '
	keyctl describe "$RING" >/dev/null &&
	keyctl describe "$KEY" >/dev/null &&
	keyctl rlist "$RING" | grep -q "$KEY" &&
	grep -q "^0*$(printf %08x "$KEY") " /proc/keys
'

test_expect_success 'root cannot unlink a key from the anchor keyring' '
	! keyctl unlink "$KEY" "$RING" 2>"$W/err" &&
	grep -qi "permission denied" "$W/err" &&
	[ "$(keys_now)" = "$N_BEFORE" ]
'

test_expect_success 'root cannot clear the anchor keyring' '
	! keyctl clear "$RING" 2>/dev/null &&
	[ "$(keys_now)" = "$N_BEFORE" ]
'

test_expect_success 'root cannot revoke or invalidate a key' '
	! keyctl revoke "$KEY" 2>/dev/null &&
	! keyctl invalidate "$KEY" 2>/dev/null &&
	! keyctl invalidate "$RING" 2>/dev/null &&
	keyctl describe "$KEY" >/dev/null &&
	[ "$(keys_now)" = "$N_BEFORE" ]
'

test_expect_success 'root cannot change the permissions or the timeout' '
	! keyctl setperm "$KEY" 0x3f3f3f3f 2>/dev/null &&
	! keyctl setperm "$RING" 0x3f3f3f3f 2>/dev/null &&
	! keyctl timeout "$KEY" 1 2>/dev/null &&
	! keyctl chown "$KEY" 1 2>/dev/null &&
	sleep 2 &&
	keyctl describe "$KEY" >/dev/null
'

test_expect_success 'root cannot link a key into the anchor keyring' '
	k=$(keyctl add user shirudo-test-t1125 x @s) &&
	! keyctl link "$k" "$RING" 2>/dev/null &&
	keyctl unlink "$k" @s &&
	[ "$(keys_now)" = "$N_BEFORE" ]
'

test_expect_success 'status still finds the anchor it froze' '
	m=$("$SHIRUDO_BIN" status --json 2>/dev/null | report_field keyring_serial_matches) &&
	[ "$m" = "True" ]
'

test_done
