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
mkdir -p "$WORK/decoders"

cat > "$WORK/decoders/t0005.lua" <<'EOF'
function decode(input)
	if input.data.serialized_bytes == 997 then
		return string.rep("x", 64 * 1024 * 1024)
	end
	if input.data.serialized_bytes == 998 then
		return string.char(255)
	end
	if input.data.serialized_bytes == 999 then
		while true do end
	end
	return {
		schema = 1,
		records = {{ name = "bash", count = 5, ratio = 1.5,
			enabled = true, ids = {"7", "9"} }},
	}
end
EOF

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -sha256 -subj "/CN=t0005" \
	>/dev/null 2>&1 || test_skip_all "openssl keygen failed"

cat > "$WORK/t.bpf.c" <<'EOF'
// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "shirudo_decoder.h"

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} t0005_map SEC(".maps");

const struct shirudo_decoder_manifest t0005_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_SERIAL_V2,
	.upatch = "t0005",
	.map = "t0005_map",
	.source = "decoders/t0005.lua",
	.entrypoint = "decode",
};

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

test_expect_success 'upatch info --json reports signed decoder metadata' '
	"$S" upatch info "$WORK/u.upatch" --json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
decoders = d.get(\"decoders\")
assert isinstance(decoders, list), decoders
assert len(decoders) == 1, decoders
dec = decoders[0]
assert dec[\"language\"] == \"lua\", dec
assert dec[\"input_format\"] == \"shirudo.serialized-pages.v2\", dec
assert dec[\"upatch\"] == \"t0005\", dec
assert dec[\"map\"] == \"t0005_map\", dec
assert dec[\"source_file\"] == \"decoders/t0005.lua\", dec
assert dec[\"entrypoint\"] == \"decode\", dec
assert dec[\"source_len\"] > 0, dec
"
'

test_expect_success 'signed Lua decoder returns JSON' '
	./helper/test-upatch-decode json "$WORK/u.upatch" |
	python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d == {\"schema\": 1, \"records\": [{\"name\": \"bash\",
    \"count\": 5, \"ratio\": 1.5, \"enabled\": True,
    \"ids\": [\"7\", \"9\"]}]}, d
"
'

test_expect_success 'signed Lua decoder maps tables to OTLP AnyValue' '
	./helper/test-upatch-decode otel "$WORK/u.upatch" |
	python3 -c "
import json, sys
d = json.load(sys.stdin)
values = d[\"kvlistValue\"][\"values\"]
fields = {item[\"key\"]: item[\"value\"] for item in values}
assert fields[\"schema\"] == {\"intValue\": \"1\"}, fields
record = fields[\"records\"][\"arrayValue\"][\"values\"][0]
record = {item[\"key\"]: item[\"value\"]
          for item in record[\"kvlistValue\"][\"values\"]}
assert record[\"name\"] == {\"stringValue\": \"bash\"}, record
assert record[\"count\"] == {\"intValue\": \"5\"}, record
assert record[\"ratio\"] == {\"doubleValue\": 1.5}, record
assert record[\"enabled\"] == {\"boolValue\": True}, record
assert record[\"ids\"] == {\"arrayValue\": {\"values\": [
    {\"stringValue\": \"7\"}, {\"stringValue\": \"9\"}]}}, record
"
'

test_expect_success 'Lua decoder enforces instruction and memory limits' '
	if ./helper/test-upatch-decode loop "$WORK/u.upatch"; then false; fi &&
	if ./helper/test-upatch-decode memory "$WORK/u.upatch"; then false; fi
'

test_expect_success 'Lua decoder rejects invalid UTF-8 output' '
	if ./helper/test-upatch-decode utf8 "$WORK/u.upatch"; then false; fi
'

test_done
