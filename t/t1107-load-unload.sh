#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1107 -- the load/unload happy path on a freshly-built test upatch
# (a no-op fentry program, separate name from any real mitigation):
# load attaches+pins and records the payload xattr; a correctly-bound
# UNLOAD directive detaches and removes the pin. The test upatch is
# force-unloaded and its archive removed on EXIT, restoring the host.

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

NAME="shirudo-it-$$"
PIN="/var/lib/shirudo/bpffs/upatches/$NAME/link"
PINDIR="/var/lib/shirudo/bpffs/upatches/$NAME"
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
int BPF_PROG(probe)
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

test_expect_success 'load attaches, pins, and shows the upatch loaded' '
	"$SHIRUDO_BIN" upatch load "$WORK/load.upatch" --no-precheck \
		>/dev/null 2>&1 &&
	[ -e "$PIN" ] &&
	"$SHIRUDO_BIN" upatch list 2>/dev/null | grep -q "$NAME"
'

test_expect_success 'the pin dir carries the payload_sha256 xattr from load' '
	x=$(python3 -c "import os,sys;print(os.getxattr(sys.argv[1],\"security.bpf.shirudo.payload\").hex())" "$PINDIR" 2>/dev/null) &&
	[ "$x" = "$PAYLOAD" ]
'

test_expect_success 'a correctly-bound UNLOAD directive detaches + removes the pin' '
	"$SHB" --unload "$NAME" --payload-sha256 "$PAYLOAD" \
		-o "$WORK/unload.upatch" >/dev/null 2>&1 &&
	"$SHIRUDO_BIN" upatch unload "$WORK/unload.upatch" --no-precheck \
		>/dev/null 2>&1 &&
	[ ! -e "$PIN" ]
'

test_done
