#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1114 -- live uprobe.multi load attaches one upatch program to two
# unrelated user-space functions selected by a standard '*' glob.

cd "$(dirname "$0")"
. ./integration-lib.sh
integration_guard

command -v cc >/dev/null 2>&1 || test_skip_all "no C compiler"
command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -x "$SHIRUDO_BUILD_BIN" ] || test_skip_all "shirudo-build not found"
[ -e ../bpf/vmlinux.h ] || test_skip_all "no bpf/vmlinux.h (build the tree)"
[ -e ../bpf/include/bpf/bpf_helpers.h ] || test_skip_all "no in-tree bpf headers"

case "$SHIRUDO_BUILD_BIN" in
/*) SHB="$SHIRUDO_BUILD_BIN" ;;
*)  SHB="$(pwd)/$SHIRUDO_BUILD_BIN" ;;
esac

NAME="shirudo-ituprobe-$$"
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

cat > "$WORK/target.c" <<'EOF'
static volatile int sink;
__attribute__((noinline, used)) int fooFunc(int value) { return value + 1; }
__attribute__((noinline, used)) int barFunc(int value) { return value + 2; }
__attribute__((noinline, used)) int notTarget(int value) { return value + 3; }
int main(void) { sink = fooFunc(1) + barFunc(2) + notTarget(3); return 0; }
EOF
cc -O0 -g -Wl,--build-id=sha1 -o "$WORK/target" "$WORK/target.c" ||
	test_skip_all "could not build target ELF"

cat > "$WORK/t.bpf.c" <<EOF
// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe.multi/$WORK/target:*Func")
int probe(struct pt_regs *ctx)
{
	__u32 key = 0;
	__u64 *value = bpf_map_lookup_elem(&hits, &key);

	if (value)
		__sync_fetch_and_add(value, 1);
	return 0;
}
EOF

( cd .. && "$SHB" "$WORK/t.bpf.c" -o "$WORK/load.upatch" \
	--vmlinux bpf/vmlinux.h --name "$NAME" ) >/dev/null 2>&1 ||
	test_skip_all "uprobe.multi build failed"
PAYLOAD=$("$SHIRUDO_BIN" upatch info "$WORK/load.upatch" --json 2>/dev/null |
	  report_field payload_sha256)
[ -n "$PAYLOAD" ] || test_skip_all "could not read built payload"

cp "$WORK/target" "$WORK/target.original"
cp /bin/true "$WORK/target"
test_expect_success 'a changed target build ID is rejected before BPF load' '
	cat=$("$SHIRUDO_BIN" upatch load "$WORK/load.upatch" --no-precheck \
		--report=- 2>/dev/null | report_field category) &&
	[ "$cat" = "binary_mismatch" ] &&
	[ ! -e "$PIN" ]
'
mv "$WORK/target.original" "$WORK/target"

"$SHIRUDO_BIN" upatch load "$WORK/load.upatch" --no-precheck >/dev/null 2>&1 ||
	test_skip_all "kernel does not support this uprobe.multi load"

cat > "$WORK/check-location.py" <<'EOF'
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
want = "uprobe.multi/" + sys.argv[2] + " (2 funcs)"
assert doc["upatch"]["location"] == want
EOF

cat > "$WORK/check-hits.py" <<'EOF'
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
hits = next(m for m in doc["upatch"]["maps"] if m["name"] == "hits")
assert int(hits["entries"][0]["value"], 0) == 2
EOF

test_expect_success 'status reports the target path and two functions' '
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/before.json" &&
	python3 "$WORK/check-location.py" "$WORK/before.json" "$WORK/target"
'

test_expect_success 'fooFunc and barFunc both execute the same upatch program' '
	"$WORK/target" &&
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/after.json" &&
	python3 "$WORK/check-hits.py" "$WORK/after.json"
'

test_done
