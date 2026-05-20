#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0005 -- `shirudo upatch info` reads and dumps the embedded C source
# from the .upatch FILE, offline (no kernel, no root). Builds a tiny -g
# fentry program from a .bpf.c, signs it with a throwaway key, and checks
# both the human and --json output carry the *full* source -- including a
# pure-comment marker line that BTF line_info could never carry, proving
# the dump is the embedded source, not instruction-tagged line_info.
# Needs clang + shirudo-build (skips otherwise).

cd "$(dirname "$0")"
. ./test-lib.sh

S=../shirudo
SHB=../tools/shirudo-build/shirudo-build

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -e ../bpf/vmlinux.h ] || test_skip_all "no bpf/vmlinux.h (build the tree)"
[ -e ../bpf/include/bpf/bpf_helpers.h ] || test_skip_all "no in-tree bpf headers"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -sha256 -subj "/CN=t0005" \
	>/dev/null 2>&1 || test_skip_all "openssl keygen failed"

cat > "$WORK/t.bpf.c" <<'EOF'
// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

/* T0005-COMMENT-ONLY-MARKER: never appears in BTF line_info */
SEC("fentry/do_nanosleep")
int BPF_PROG(t0005_marker_fn)
{
	return 0;
}
EOF

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac
( cd .. && "$B" "$WORK/t.bpf.c" -o "$WORK/u.upatch" --vmlinux bpf/vmlinux.h \
	--name t0005 --key "$WORK/k.pem" --cert "$WORK/c.der" ) >/dev/null 2>&1 ||
	test_skip_all "build failed (clang/headers?)"

test_expect_success 'upatch info dumps the function from the embedded source (human)' '
	"$S" upatch info "$WORK/u.upatch" 2>/dev/null | grep -q "t0005_marker_fn"
'

test_expect_success 'upatch info dumps the comment-only marker (full source, human)' '
	"$S" upatch info "$WORK/u.upatch" 2>/dev/null | grep -q "T0005-COMMENT-ONLY-MARKER"
'

test_expect_success 'upatch info --json carries has_source + the full source' '
	"$S" upatch info "$WORK/u.upatch" --json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d[\"has_source\"] is True, d.get(\"has_source\")
assert \"t0005_marker_fn\" in d[\"source\"], \"missing function in source\"
assert \"T0005-COMMENT-ONLY-MARKER\" in d[\"source\"], \"missing comment marker\"
assert d[\"source_file\"].endswith(\"t.bpf.c\"), d.get(\"source_file\")
"
'

test_done
