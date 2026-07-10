#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1112 -- the lsm/bpf_prog_load admission gate binds the load to the
# sealed "shirudo" keyring's serial. A signed loader whose signature is
# perfectly valid -- but verified against a keyring the caller controls
# rather than the shirudo keyring -- is denied in-kernel with EACCES by
# the admission hook, AFTER the kernel recorded BPF_SIG_VERIFIED. This is
# the bypass the load-time scheme closes: before the hook existed, any
# CAP_BPF caller could sign a SYSCALL loader against their own keyring and
# load it. Distinct from t1105 (cert absent -> ENOKEY): here the signature
# passes and the hook is what refuses.
#
# Non-destructive: mints a throwaway key/cert, adds the cert only to this
# process's own session keyring, and never touches shirudo's keyring or
# any pinned state.

cd "$(dirname "$0")"
. ./integration-lib.sh
integration_guard

command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
[ -x "$SHIRUDO_BUILD_BIN" ] || test_skip_all "shirudo-build not found"
H=helper/test-signed-load
[ -x "$H" ] || test_skip_all "test-signed-load helper not built"
[ -e ../bpf/vmlinux.h ] || test_skip_all "no bpf/vmlinux.h (build the tree)"

case "$SHIRUDO_BUILD_BIN" in
/*) SHB="$SHIRUDO_BUILD_BIN" ;;
*)  SHB="$(pwd)/$SHIRUDO_BUILD_BIN" ;;
esac

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/own.pem" \
	-outform DER -out "$WORK/own.der" -days 1 -sha256 \
	-subj "/CN=caller-controlled" >/dev/null 2>&1 ||
	test_skip_all "openssl keygen failed"

cat > "$WORK/foo.bpf.c" <<'EOF'
// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_nanosleep")
int smoke(void *ctx)
{
	return 0;
}
EOF

# A valid loader, signed with the caller's own key. The cert IS added to
# the caller's session keyring by the helper, so the kernel's PKCS#7
# check passes -- only the keyring-serial gate can reject it.
( cd .. && "$SHB" "$WORK/foo.bpf.c" -o "$WORK/own.upatch" \
	--vmlinux bpf/vmlinux.h \
	--key "$WORK/own.pem" --cert "$WORK/own.der" ) \
	>/dev/null 2>&1 || test_skip_all "build failed"

# EACCES (13) is the admission-hook denial. A signature failure would be
# ENOKEY (126) or EKEYREJECTED (129) instead; assert it is neither, so a
# regression that stopped enforcing the keyring bind cannot pass by
# accidentally failing the signature.
test_expect_success 'valid signature, non-shirudo keyring -> denied by lsm/bpf_prog_load (EACCES)' '
	out=$(./$H "$WORK/own.upatch" "$WORK/own.der") &&
	echo "own-keyring load: $out" &&
	[ "$out" = "errno=13" ]
'

test_done
