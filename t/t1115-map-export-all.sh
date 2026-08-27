#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./integration-lib.sh
integration_guard

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
[ -x "$SHIRUDO_BUILD_BIN" ] || test_skip_all "shirudo-build not found"
[ -e ../bpf/vmlinux.h ] || test_skip_all "no bpf/vmlinux.h"

case "$SHIRUDO_BUILD_BIN" in
/*) SHB="$SHIRUDO_BUILD_BIN" ;;
*)  SHB="$(pwd)/$SHIRUDO_BUILD_BIN" ;;
esac

NAME="shirudo-map-export-it-$$"
PIN="/var/lib/shirudo/bpffs/upatches/$NAME/link"
PAYLOAD=""
SERVER=""
WORK=$(mktemp -d)
CONFIG=/etc/shirudo/shirudo.conf
CONFIG_BACKUP=$WORK/shirudo.conf.backup
CONFIG_EXISTED=0

if [ -e "$CONFIG" ]; then
	cp "$CONFIG" "$CONFIG_BACKUP"
	CONFIG_EXISTED=1
fi

restore() {
	if [ -n "$SERVER" ]; then
		kill "$SERVER" >/dev/null 2>&1 || true
		wait "$SERVER" 2>/dev/null || true
	fi
	if [ -e "$PIN" ] && [ -n "$PAYLOAD" ]; then
		"$SHB" --unload "$NAME" --payload-sha256 "$PAYLOAD" \
			-o "$WORK/unload.upatch" >/dev/null 2>&1 &&
			"$SHIRUDO_BIN" upatch unload "$WORK/unload.upatch" \
				--no-precheck >/dev/null 2>&1
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	if [ "$CONFIG_EXISTED" -eq 1 ]; then
		cp "$CONFIG_BACKUP" "$CONFIG"
	else
		rm -f "$CONFIG"
	fi
	rm -rf "$WORK"
}
trap restore EXIT

mkdir -p "$WORK/decoders"

cat > "$WORK/decoders/first.lua" <<'EOF'
function decode(input)
	return {
		upatch = input.upatch,
		map = input.map,
		schema = 1,
		data = { records = {{ name = "first", count = 1 }} },
	}
end
EOF

cat > "$WORK/decoders/second.lua" <<'EOF'
function decode(input)
	return {{
		name = "shirudo.map_export.second",
		unit = "1",
		gauge = { dataPoints = {{ asInt = "1" }} },
	}}
end
EOF

cat > "$WORK/maps.bpf.c" <<EOF
// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "shirudo_decoder.h"

char _license[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} first SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} second SEC(".maps");

const struct shirudo_decoder_manifest first_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_LOG,
	.upatch = "$NAME",
	.map = "first",
	.source = "decoders/first.lua",
	.entrypoint = "decode",
};

const struct shirudo_decoder_manifest second_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_METRIC,
	.upatch = "$NAME",
	.map = "second",
	.source = "decoders/second.lua",
	.entrypoint = "decode",
};

SEC("fentry/do_nanosleep")
int BPF_PROG(probe)
{
	return 0;
}
EOF

( cd .. && "$SHB" "$WORK/maps.bpf.c" -o "$WORK/load.upatch" \
	--vmlinux bpf/vmlinux.h --name "$NAME" ) >/dev/null 2>&1 ||
	test_skip_all "build failed"
PAYLOAD=$("$SHIRUDO_BIN" upatch info "$WORK/load.upatch" --json 2>/dev/null |
	report_field payload_sha256)
[ -n "$PAYLOAD" ] || test_skip_all "could not read built payload"

test_expect_success '--all exports one detailed JSON record per loaded map' '
	"$SHIRUDO_BIN" upatch load "$WORK/load.upatch" --no-precheck \
		>/dev/null 2>&1 &&
	"$SHIRUDO_BIN" upatch map --all --json="$WORK/maps.ndjson" &&
	python3 - "$WORK/maps.ndjson" "$NAME" <<'PY'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
log = next(record for record in records
           if isinstance(record, dict) and record.get("map") == "first")
metric = next(record for record in records if isinstance(record, list))
assert log.get("upatch") == sys.argv[2], log
assert log.get("schema") == 1, log
assert isinstance(log.get("data"), dict), log
assert metric[0]["name"] == "shirudo.map_export.second", metric
PY
'

test_expect_success '--all auto exports mixed metric and log maps' '
	cat >"$WORK/otel-multi.py" <<'PY'
import http.server
import json
import pathlib
import sys

port_file, meta_file = sys.argv[1:3]
request_goal = int(sys.argv[3])
attempts = 0
tenant_ids = []


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        global attempts, tenant_ids
        attempts += 1
        tenant_ids.append(self.headers.get("X-Tenant-ID", ""))
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        pathlib.Path(meta_file).write_text(json.dumps({
            "attempts": attempts,
            "tenant_ids": tenant_ids,
        }))
        response = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)
        self.server.done = attempts >= request_goal

    def log_message(self, *args):
        pass


server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.done = False
server.timeout = 5
pathlib.Path(port_file).write_text(str(server.server_port))
while not server.done:
    server.handle_request()
PY
	rm -f "$WORK/otel.port" "$WORK/otel.meta";
	python3 "$WORK/otel-multi.py" "$WORK/otel.port" \
		"$WORK/otel.meta" 4 &
	SERVER=$!;
	i=0;
	while test ! -s "$WORK/otel.port" && test $i -lt 50
	do
		i=$((i + 1))
		sleep .02
	done &&
	test -s "$WORK/otel.port" &&
	port=$(cat "$WORK/otel.port") &&
	mkdir -p "$(dirname "$CONFIG")" &&
	printf "%s\n" "map_export.tenant_id = tenant-config-0000" \
		>"$CONFIG" &&
	command_rc=0 &&
	"$SHIRUDO_BIN" upatch map --all --otel \
		--otel-endpoint="http://127.0.0.1:$port/base" || command_rc=$?;
	if test "$command_rc" -eq 0
	then
		"$SHIRUDO_BIN" upatch map --all --otel \
			--tenant-id=tenant-uuid-1234 \
			--otel-endpoint="http://127.0.0.1:$port/base" || command_rc=$?
	fi;
	kill "$SERVER" >/dev/null 2>&1 || true
	wait "$SERVER" 2>/dev/null || true
	SERVER=""
	test "$command_rc" -eq 0 &&
	python3 - "$WORK/otel.meta" <<'PY'
import json
import sys

meta = json.load(open(sys.argv[1], encoding="utf-8"))
assert meta["attempts"] == 4, meta
assert meta["tenant_ids"] == (
    ["tenant-config-0000"] * 2 + ["tenant-uuid-1234"] * 2
), meta
PY
'

test_done
