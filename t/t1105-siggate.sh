#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1105 -- the signature gate (the trust boundary): a .upatch signed by
# a cert that is NOT in the target's sealed "shirudo" keyring is rejected
# at BPF_PROG_LOAD. Mints a throwaway foreign key/cert (never genkey,
# which would clobber the operator key), builds a foreign-signed upatch,
# and confirms the load fails. Non-destructive (the load is refused).

cd "$(dirname "$0")"
. ./integration-lib.sh
integration_guard

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
[ -x "$SHIRUDO_BUILD_BIN" ] || test_skip_all "shirudo-build not found"
[ -e ../bpf/vmlinux.h ] || test_skip_all "no bpf/vmlinux.h (build the tree)"
[ -e ../bpf/include/bpf/bpf_helpers.h ] || test_skip_all "no in-tree bpf headers"

# Absolute path to the builder so the cd-to-repo-root build still finds it.
case "$SHIRUDO_BUILD_BIN" in
/*) SHB="$SHIRUDO_BUILD_BIN" ;;
*)  SHB="$(pwd)/$SHIRUDO_BUILD_BIN" ;;
esac

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/foreign.pem" \
	-outform DER -out "$WORK/foreign.der" -days 1 -sha256 \
	-subj "/CN=foreign-attacker" >/dev/null 2>&1 ||
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

# Build from the repo root so shirudo-build locates ./bpf/include.
( cd .. && "$SHB" "$WORK/foo.bpf.c" -o "$WORK/foreign.upatch" \
	--vmlinux bpf/vmlinux.h \
	--key "$WORK/foreign.pem" --cert "$WORK/foreign.der" ) \
	>/dev/null 2>&1 || test_skip_all "foreign build failed"

test_expect_success 'foreign-signed upatch is rejected (cert not in keyring)' '
	$SHIRUDO_BIN upatch load "$WORK/foreign.upatch" --no-precheck \
	    --report=- >"$WORK/out" 2>/dev/null || true
	res=$(report_field result <"$WORK/out") &&
	cat=$(report_field category <"$WORK/out") &&
	[ "$res" = "failed" ] &&
	{ [ "$cat" = "keyring_missing" ] || [ "$cat" = "signature_rejected" ]; }
'

test_done
