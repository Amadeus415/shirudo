#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1116 -- live systemd map-export service and timer coverage. This is
# intentionally opt-in: it loads a temporary upatch and controls the target
# map-export units on the VM.

cd "$(dirname "$0")"
. ./integration-lib.sh
integration_guard

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v systemctl >/dev/null 2>&1 || test_skip_all "no systemctl"
[ -x "$SHIRUDO_BUILD_BIN" ] || test_skip_all "shirudo-build not found"
[ -e ../bpf/vmlinux.h ] || test_skip_all "no bpf/vmlinux.h"

CONFIG=/etc/shirudo/shirudo.conf
[ -r "$CONFIG" ] || test_skip_all "VM map-export configuration is absent"
grep -Eq '^map_export\.otel_endpoint[[:space:]]*=' "$CONFIG" ||
	test_skip_all "VM map-export endpoint is not configured"
systemctl cat shirudo-map-export.service >/dev/null 2>&1 ||
	test_skip_all "map-export service is not installed"
systemctl cat shirudo-map-export.timer >/dev/null 2>&1 ||
	test_skip_all "map-export timer is not installed"

case "$SHIRUDO_BUILD_BIN" in
/*) SHB="$SHIRUDO_BUILD_BIN" ;;
*)  SHB="$(pwd)/$SHIRUDO_BUILD_BIN" ;;
esac

NAME="shirudo-otel-backend-it-$$"
PIN="/var/lib/shirudo/bpffs/upatches/$NAME/link"
PAYLOAD=""
SERVER=""
WORK=$(mktemp -d)
CONFIG_BACKUP=$WORK/shirudo.conf.backup
CONFIG_EXISTED=1
TIMER_WAS_ACTIVE=0

if systemctl is-active --quiet shirudo-map-export.timer; then
	TIMER_WAS_ACTIVE=1
fi

restore() {
	systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
	systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true
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
	cp "$CONFIG_BACKUP" "$CONFIG"
	if [ "$TIMER_WAS_ACTIVE" -eq 1 ]; then
		systemctl start shirudo-map-export.timer >/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
}
trap restore EXIT

systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true

mkdir -p "$WORK/decoders"
cat > "$WORK/decoders/log.lua" <<'EOF'
function decode(input)
	return {
		schema = 1,
		records = {{ name = "backend", count = 1 }},
	}
end
EOF

cat > "$WORK/decoders/metric.lua" <<'EOF'
function decode(input)
	return {{
		name = "shirudo.otel.backend",
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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} backend_log SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} backend_metric SEC(".maps");

const struct shirudo_decoder_manifest log_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_LOG,
	.upatch = "$NAME",
	.map = "backend_log",
	.source = "decoders/log.lua",
	.entrypoint = "decode",
};

const struct shirudo_decoder_manifest metric_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_METRIC,
	.upatch = "$NAME",
	.map = "backend_metric",
	.source = "decoders/metric.lua",
	.entrypoint = "decode",
};

SEC("fentry/do_nanosleep")
int BPF_PROG(probe)
{
	return 0;
}
EOF

(
	cd .. &&
	"$SHB" "$WORK/maps.bpf.c" -o "$WORK/load.upatch" \
		--vmlinux bpf/vmlinux.h --name "$NAME"
) >/dev/null 2>&1 || test_skip_all "build failed"
PAYLOAD=$(
	"$SHIRUDO_BIN" upatch info "$WORK/load.upatch" --json 2>/dev/null |
		report_field payload_sha256
)
[ -n "$PAYLOAD" ] || test_skip_all "could not read built payload"

test_expect_success 'map-export service delivers both decoder-backed maps' '
	python3 "$WORK/otel.port" "$WORK/otel.meta" "$WORK/otel.ready" <<'"'"'PY'"'"' &
import http.server
import json
import pathlib
import sys

port_file = pathlib.Path(sys.argv[1])
meta = pathlib.Path(sys.argv[2])
ready = pathlib.Path(sys.argv[3])
requests = []

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        requests.append(self.path)
        meta.write_text(json.dumps({"requests": requests}))
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.timeout = 1
port_file.write_text(str(server.server_port))
ready.write_text("ready")
while len(requests) < 4:
    server.handle_request()
PY
	SERVER=$!;
	trap '\''if test -n "${SERVER:-}"; then kill "$SERVER" >/dev/null 2>&1 || true; wait "$SERVER" 2>/dev/null || true; fi'\'' EXIT;
	i=0;
	while { test ! -s "$WORK/otel.ready" || test ! -s "$WORK/otel.port"; } && test "$i" -lt 100
	do
		i=$((i + 1));
		sleep .1;
	done;
	test -s "$WORK/otel.ready" &&
	port=$(cat "$WORK/otel.port") &&
	printf "%s\n" \
		"map_export.otel_endpoint = http://127.0.0.1:$port" \
		"map_export.otel_insecure = true" \
		"map_export.otel_retries = 0" >"$CONFIG" &&
	"$SHIRUDO_BIN" upatch load "$WORK/load.upatch" --no-precheck \
		>/dev/null 2>&1 &&
	systemctl start shirudo-map-export.service &&
	systemctl start shirudo-map-export.timer &&
	i=0;
	while test ! -s "$WORK/otel.meta" && test "$i" -lt 100
	do
		i=$((i + 1));
		sleep .1;
	done;
	i=0;
	while test "$i" -lt 100
	do
		count=$(python3 - "$WORK/otel.meta" <<'"'"'PY'"'"'
import json
import sys
try:
    print(len(json.load(open(sys.argv[1], encoding="utf-8"))["requests"]))
except (FileNotFoundError, KeyError, json.JSONDecodeError):
    print(0)
PY
);
		test "$count" -ge 4 && break;
		i=$((i + 1));
		sleep .1;
	done;
	kill "$SERVER" >/dev/null 2>&1 || true;
	wait "$SERVER" 2>/dev/null || true;
	SERVER="";
	test "$count" -eq 4 &&
	systemctl show shirudo-map-export.service -p ExecMainStatus --value |
		grep -qx 0 &&
	python3 - "$WORK/otel.meta" <<'"'"'PY'"'"'
import json
import sys

requests = json.load(open(sys.argv[1], encoding="utf-8"))["requests"]
assert len(requests) == 4, requests
assert all(path.endswith("/v1/logs") or path.endswith("/v1/metrics")
           for path in requests), requests
assert sum(path.endswith("/v1/logs") for path in requests) == 2, requests
assert sum(path.endswith("/v1/metrics") for path in requests) == 2, requests
PY
'

test_done
