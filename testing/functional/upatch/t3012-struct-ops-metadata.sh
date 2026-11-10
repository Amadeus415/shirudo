#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3012 -- struct_ops programs carry no attach site of their own, a
# struct_ops map must be in .struct_ops.link, and every struct_ops
# program must be in a struct_ops map.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHB=../tools/shirudo-build/shirudo-build
CHECK=helper/test-upatch-prog-metadata
FIXTURE=fixtures/struct-ops-tcp.bpf.c

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -x "$CHECK" ] || test_skip_all "metadata helper not built"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h (build the tree)"
[ -e ../vendor/libbpf/bpf/bpf_helpers.h ] || test_skip_all "no vendored bpf headers"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# shirudo signs with ML-DSA-87 only (needs OpenSSL >= 3.5 to mint it).
openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t3012" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

build() {
	( cd .. && "$B" "$1" -o "$WORK/$2.upatch" \
		--vmlinux vendor/linux/vmlinux.h --name "$2" \
		--extra-cflags "-I$(pwd)/vendor/libbpf" \
		--key "$WORK/k.pem" --cert "$WORK/c.der" )
}

sed 's/"\.struct_ops\.link"/".struct_ops"/' "$FIXTURE" >"$WORK/no-link.bpf.c"
cat "$FIXTURE" - >"$WORK/stray.bpf.c" <<'EOF'

SEC("struct_ops/shirudo_test_cc_stray")
void BPF_PROG(shirudo_test_cc_stray, struct sock *sk)
{
}
EOF

build "$(pwd)/$FIXTURE" struct-ops >/dev/null 2>&1 ||
	test_skip_all "struct_ops build failed"

test_expect_success 'struct_ops programs are recorded as struct_ops programs' '
	"$CHECK" "$WORK/struct-ops.upatch" struct-ops
'

test_expect_success 'a struct_ops map outside .struct_ops.link is refused' '
	! build "$WORK/no-link.bpf.c" no-link 2>"$WORK/no-link.err" &&
	grep -q "must be in SEC(\".struct_ops.link\")" "$WORK/no-link.err" &&
	[ ! -e "$WORK/no-link.upatch" ]
'

test_expect_success 'a struct_ops program no map refers to is refused' '
	! build "$WORK/stray.bpf.c" stray 2>"$WORK/stray.err" &&
	grep -q "referenced anywhere" "$WORK/stray.err" &&
	[ ! -e "$WORK/stray.upatch" ]
'

test_done
