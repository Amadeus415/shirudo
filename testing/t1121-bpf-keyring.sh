#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1121 -- the certificates live in the kernel's bpf keyring: init
# enrolled the trusted set and sealed the keyring, status says so, a
# re-run of init leaves it alone, and nothing can be linked into it any
# more.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

[ "$(keyring_mode)" = bpf ] ||
	test_skip_all "certificate staged in the user keyring (kernel booted without bpf.keyring_unsealed=1)"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
# A certificate the keyring does not hold: the third one until t1124
# adds it to the set on disk, which the keyring learns of at a reboot.
FOREIGN_CERT="$FIXTURES/third.der"
[ -s "$FOREIGN_CERT" ] || FOREIGN_CERT="$FIXTURES/own.der"
LIFECYCLE="$FIXTURES/shirudo-test-lifecycle.upatch"
LIFECYCLE_UNLOAD="$FIXTURES/shirudo-test-lifecycle.unload.upatch"
LIFECYCLE_PIN=/run/shirudo/bpffs/upatches/shirudo-test-lifecycle/link
[ -s "$FOREIGN_CERT" ] || test_skip_all "missing certificate fixtures"
[ -s "$LIFECYCLE" ] && [ -s "$LIFECYCLE_UNLOAD" ] ||
	test_skip_all "missing lifecycle fixtures"
keys_in_ring() {
	sed -nE "s/^.*keyring +\.bpf: ([0-9]+).*$/\1/p" /proc/keys
}
N_ENROLLED=$(keys_in_ring)

test_expect_success 'the bpf keyring holds the trusted set and the pin names it' '
	[ -n "$N_ENROLLED" ] && [ "$N_ENROLLED" -ge 1 ] &&
	"$SHIRUDO_BIN" status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d[\"keyring_mode\"] == \"bpf\", d
assert d[\"keyring_present\"] is True, d
assert d[\"keyring_serial\"] == d[\"keyring_serial_pinned\"], d
assert d[\"certs_enrolled\"] == len(d[\"certs\"]) == $N_ENROLLED, d
"
'

test_expect_success 'a re-run of init keeps the enrolled keyring' '
	"$SHIRUDO_BIN" init &&
	[ "$(keyring_mode)" = bpf ] &&
	[ "$(keys_in_ring)" = "$N_ENROLLED" ]
'

test_expect_success 'a load and an unload pass the pre-flight check' '
	"$SHIRUDO_BIN" upatch load "$LIFECYCLE" >/dev/null 2>&1 &&
	test -e "$LIFECYCLE_PIN" &&
	"$SHIRUDO_BIN" upatch unload "$LIFECYCLE_UNLOAD" >/dev/null 2>&1 &&
	test ! -e "$LIFECYCLE_PIN"
'

test_expect_success 'the sealed bpf keyring refuses another key' '
	python3 - "$FOREIGN_CERT" <<"PY"
import ctypes, errno, os, platform, sys
nr = {"x86_64": 248, "aarch64": 217, "riscv64": 217}[platform.machine()]
libc = ctypes.CDLL(None, use_errno=True)
cert = open(sys.argv[1], "rb").read()
ret = libc.syscall(nr, b"asymmetric", None, cert, len(cert), -9)
err = ctypes.get_errno()
# EPERM from the sealed keyring; EACCES when the certificate is already
# a member and the add would update its key, which the LSM denies.
assert ret == -1 and err in (errno.EPERM, errno.EACCES), (ret, os.strerror(err))
PY
	[ "$(keys_in_ring)" = "$N_ENROLLED" ]
'

test_done
