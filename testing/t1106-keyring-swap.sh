#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1106 -- same-named keyring substitution: a root attacker who
# displaces the sealed "shirudo" keyring in @u with a fake same-named
# one is caught by the serial pin. `status` reports MISMATCH and a load
# is refused with category tampered (before any BPF_PROG_LOAD). The
# fake keyring is removed and a fresh sealed one re-created on EXIT.
#
# Caveat: the substitution displaces (unlinks) the original keyring from
# @u, and the seal blocks re-linking it, so its serial cannot be
# recovered. The lsm/bpf_prog_load gate binds the serial frozen into the
# bpf2 identity map at the original init, so shirudo-signed loads stay
# refused until the next boot re-inits from scratch. The host remains
# fail-closed (enforcing) in the meantime -- the correct posture once the
# trust anchor has been destroyed -- so this test should be run on a host
# that will be rebooted, or last.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

# With the certificate enrolled in the kernel's bpf keyring there is no
# user keyring to substitute; t1121 covers that trust anchor.
[ "$("$SHIRUDO_BIN" status --json 2>/dev/null |
	python3 -c "import json, sys; print(json.load(sys.stdin).get(\"keyring_mode\", \"\"))")" != bpf ] ||
	test_skip_all "certificate is enrolled in the bpf keyring"

command -v keyctl >/dev/null 2>&1 || test_skip_all "no keyctl"
ARCH=$(ls /var/lib/shirudo/upatches/*.upatch 2>/dev/null | head -1)
[ -n "$ARCH" ] || test_skip_all "no persisted .upatch to attempt loading"
keyctl search @u keyring shirudo >/dev/null 2>&1 || test_skip_all "no shirudo keyring"

restore() {
	# Drop whatever "shirudo" keyring is in @u now (fake or stale), then
	# let init recreate a fresh sealed one with the cert and re-pin it.
	k=$(keyctl search @u keyring shirudo 2>/dev/null) &&
		keyctl unlink "$k" @u >/dev/null 2>&1
	"$SHIRUDO_BIN" init >/dev/null 2>&1 || true
}
trap restore EXIT

# Displace the real keyring with a fake same-named one in @u.
keyctl newring shirudo @u >/dev/null 2>&1 || test_skip_all "keyctl newring failed"

test_expect_success 'after swap, status reports keyring_serial_matches=false' '
	m=$("$SHIRUDO_BIN" status --json 2>/dev/null | report_field keyring_serial_matches) &&
	[ "$m" = "False" ]
'

test_expect_success 'after swap, a load is refused with category tampered' '
	cat=$("$SHIRUDO_BIN" upatch load "$ARCH" --no-precheck --report=- \
	      2>/dev/null | report_field category) &&
	[ "$cat" = "tampered" ]
'

test_done
