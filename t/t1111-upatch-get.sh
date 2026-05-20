#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1111 -- `shirudo upatch get <name>` dumps the BPF line info (source)
# of a LOADED upatch read from the kernel (the BTF the signed gen_loader
# installed). Builds + loads a marker fentry upatch, asserts `get` shows
# the marker source, then unloads + cleans up on EXIT.

cd "$(dirname "$0")"
. ./integration-lib.sh
integration_guard

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
[ -x "$SHIRUDO_BUILD_BIN" ] || test_skip_all "shirudo-build not found"
[ -e ../bpf/vmlinux.h ] || test_skip_all "no bpf/vmlinux.h (build the tree)"
[ -e ../bpf/include/bpf/bpf_helpers.h ] || test_skip_all "no in-tree bpf headers"

case "$SHIRUDO_BUILD_BIN" in
/*) SHB="$SHIRUDO_BUILD_BIN" ;;
*)  SHB="$(pwd)/$SHIRUDO_BUILD_BIN" ;;
esac

NAME="shirudo-itget-$$"
PIN="/var/lib/shirudo/bpffs/upatches/$NAME/link"
PAYLOAD=""
WORK=$(mktemp -d)

restore() {
	if [ -e "$PIN" ] && [ -n "$PAYLOAD" ]; then
		"$SHB" --unload "$NAME" --payload-sha256 "$PAYLOAD" \
			-o "$WORK/r.upatch" >/dev/null 2>&1 &&
			"$SHIRUDO_BIN" upatch unload "$WORK/r.upatch" \
				--no-precheck >/dev/null 2>&1
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	rm -rf "$WORK"
}
trap restore EXIT

cat > "$WORK/t.bpf.c" <<'EOF'
// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_nanosleep")
int BPF_PROG(t1111_marker_fn)
{
	return 0;
}
EOF

( cd .. && "$SHB" "$WORK/t.bpf.c" -o "$WORK/load.upatch" \
	--vmlinux bpf/vmlinux.h --name "$NAME" ) >/dev/null 2>&1 ||
	test_skip_all "build failed"
PAYLOAD=$("$SHIRUDO_BIN" upatch info "$WORK/load.upatch" --json 2>/dev/null |
	  report_field payload_sha256)
[ -n "$PAYLOAD" ] || test_skip_all "could not read built payload"
"$SHIRUDO_BIN" upatch load "$WORK/load.upatch" --no-precheck >/dev/null 2>&1 ||
	test_skip_all "load failed"

test_expect_success 'upatch get dumps the loaded source line from the kernel' '
	"$SHIRUDO_BIN" upatch get "$NAME" 2>/dev/null | grep -q "t1111_marker_fn"
'

test_done
