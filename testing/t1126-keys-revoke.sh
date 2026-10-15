#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1126 -- revoking the second enrolled key on a live target: its key
# leaves the bpf keyring, the upatch it signed is unloaded and purged
# with a measured record, the revocation itself is measured, a load it
# signed is refused from then on, and the set on disk is without it.
# Runs after t1123 and t1124, which need the key enrolled.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

[ "$(keyring_mode)" = bpf ] ||
	test_skip_all "certificate staged in the user keyring; revocation needs the bpf keyring"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
OWN="$FIXTURES/shirudo-test-own-keyring.upatch"
OWN_CERT="$FIXTURES/own.der"
OWN_PIN=/run/shirudo/bpffs/upatches/shirudo-test-own-keyring/link
ARCHIVE=/var/lib/shirudo/upatches/shirudo-test-own-keyring.upatch
[ -s "$OWN" ] && [ -s "$OWN_CERT" ] || test_skip_all "missing own-keyring fixtures"
OWN_FP=$("$SHIRUDO_BIN" bpm key fingerprint "$OWN_CERT" 2>/dev/null)
PRIMARY_FP=$("$SHIRUDO_BIN" bpm key fingerprint /var/lib/shirudo/keys/cert.der 2>/dev/null)
[ -e "/var/lib/shirudo/keys/trusted/$OWN_FP.der" ] ||
	test_skip_all "the own-keyring certificate is not a trusted member"
RING=$("$SHIRUDO_BIN" status --json 2>/dev/null | report_field keyring_serial)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

status_field() {
	"$SHIRUDO_BIN" status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
v = d[\"$1\"]
print(len(v) if isinstance(v, list) else v)
"
}
# grep -c exits 1 for a count of zero, which the first revocation is.
events_of_type() {
	grep -c "\"type\":\"$1\"" /var/lib/shirudo/eventlog || :
}

test_expect_success 'the upatch signed by the second key is loaded' '
	if ! [ -e "$OWN_PIN" ]; then
		"$SHIRUDO_BIN" upatch load "$OWN" --no-precheck >/dev/null 2>&1
	fi &&
	[ -e "$OWN_PIN" ] && [ -s "$ARCHIVE" ]
'

test_expect_success 'the primary cannot go without an heir' '
	! "$SHIRUDO_BIN" keys revoke "$PRIMARY_FP" >/dev/null 2>&1 &&
	[ "$(status_field certs_enrolled)" = 2 ]
'

revoke_debug() {
	echo "--- keys revoke exit $1" >&2
	cat "$W/out" "$W/err" >&2
	grep -E "keyring +\.bpf" /proc/keys >&2
}

test_expect_success 'revoking the second key unlinks it and purges what it signed' '
	before_rev=$(events_of_type key_revoke) &&
	before_unl=$(events_of_type upatch_unload) &&
	{ "$SHIRUDO_BIN" keys revoke "$OWN_FP" >"$W/out" 2>"$W/err"; rc=$?; revoke_debug "$rc"; [ "$rc" = 0 ]; } &&
	grep -q "^revoked $OWN_FP" "$W/out" &&
	grep -q "^purged 1 upatch it signed, 1 of them loaded" "$W/out" &&
	! [ -e "$OWN_PIN" ] && ! [ -e "$ARCHIVE" ] &&
	[ "$(events_of_type key_revoke)" = $((before_rev + 1)) ] &&
	[ "$(events_of_type upatch_unload)" = $((before_unl + 1)) ] &&
	grep "\"type\":\"upatch_unload\"" /var/lib/shirudo/eventlog | tail -1 |
		grep -q "\"reason\":\"key_revoke\""
'

test_expect_success 'the bpf keyring holds one key and the set on disk is without it' '
	grep -qE "keyring +\.bpf: 1" /proc/keys &&
	[ "$(status_field certs_enrolled)" = 1 ] &&
	[ "$(status_field certs_revoked)" -ge 1 ] &&
	! [ -e "/var/lib/shirudo/keys/trusted/$OWN_FP.der" ] &&
	! [ -e "/var/lib/shirudo/keys/trusted/$OWN_FP.vouch" ] &&
	[ -s "/var/lib/shirudo/keys/revoked/$OWN_FP.der" ] &&
	"$SHIRUDO_BIN" status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert all(c[\"fingerprint\"] != \"$OWN_FP\" for c in d[\"certs\"]), d
"
'

test_expect_success 'a load signed by the revoked key is refused' '
	! "$SHIRUDO_BIN" upatch load "$OWN" --no-precheck >/dev/null 2>&1 &&
	! [ -e "$OWN_PIN" ]
'

test_expect_success 'the eventlog with the revocation replays to the register' '
	"$SHIRUDO_BIN" status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d[\"tpm\"][\"chain_matches_eventlog\"] is True, d[\"tpm\"]
" &&
	grep "\"type\":\"key_revoke\"" /var/lib/shirudo/eventlog | tail -1 |
		grep -q "\"fingerprint\":\"$OWN_FP\""
'

test_expect_success 'revoking it again is a no-op and adding it back is refused' '
	"$SHIRUDO_BIN" keys revoke "$OWN_FP" >/dev/null 2>&1 &&
	! "$SHIRUDO_BIN" keys add "$OWN_CERT" --vouch "$FIXTURES/own.vouch" >/dev/null 2>&1
'

test_expect_success 'the last key cannot go without --force' '
	! "$SHIRUDO_BIN" keys revoke "$PRIMARY_FP" >/dev/null 2>&1 &&
	grep -qE "keyring +\.bpf: 1" /proc/keys
'

test_done
