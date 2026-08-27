#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1117 -- live serializer-to-OTLP metric coverage. The serializer seeds
# deterministic counters, writes fixed-width records to shirudo_ser, and
# the signed Lua decoder turns those records into cumulative OTLP sums.

cd "$(dirname "$0")"
. ./integration-lib.sh
integration_guard

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v systemctl >/dev/null 2>&1 || test_skip_all "no systemctl"
[ -x "$SHIRUDO_BUILD_BIN" ] || test_skip_all "shirudo-build not found"
[ -e ../bpf/vmlinux.h ] || test_skip_all "no bpf/vmlinux.h"

CONFIG=/etc/shirudo/shirudo.conf
[ -r "$CONFIG" ] || test_skip_all "VM map-export configuration is absent"
grep -Eq '^map_export\.otel_endpoint[[:space:]]*=' "$CONFIG" ||
	test_skip_all "VM map-export endpoint is not configured"
systemctl cat shirudo-map-export.service >/dev/null 2>&1 ||
	test_skip_all "map-export service is not installed"

case "$SHIRUDO_BUILD_BIN" in
/*) SHB="$SHIRUDO_BUILD_BIN" ;;
*)  SHB="$(pwd)/$SHIRUDO_BUILD_BIN" ;;
esac

NAME="shirudo-serialized-metric-it-$$"
PINDIR="/var/lib/shirudo/bpffs/upatches/$NAME"
SERIALIZER_PIN="$PINDIR/serializers/counters"
PAYLOAD=""
SERVER=""
WORK=$(mktemp -d)
CONFIG_BACKUP=$WORK/shirudo.conf.backup
TIMER_WAS_ACTIVE=0

if systemctl is-active --quiet shirudo-map-export.timer; then
	TIMER_WAS_ACTIVE=1
fi
cp "$CONFIG" "$CONFIG_BACKUP"

restore() {
	systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
	systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true
	if [ -n "$SERVER" ]; then
		kill "$SERVER" >/dev/null 2>&1 || true
		wait "$SERVER" 2>/dev/null || true
	fi
	if [ -e "$SERIALIZER_PIN" ] && [ -n "$PAYLOAD" ]; then
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
cat > "$WORK/decoders/counters.lua" <<'EOF'
function decode(input)
	if not input.data.serialized or input.data.serialized_bytes ~= 48 then
		error("unexpected serialized counter payload")
	end

	local records = shirudo.fixed_records(input.data.pages, 24)
	if not records[1] or not records[2] or
	   records[1]:u32(0) ~= 0 or records[2]:u32(0) ~= 1 then
		error("unexpected counter records")
	end

	local packets = tonumber(records[1]:u64(8)) +
		tonumber(records[2]:u64(8))
	local bytes = tonumber(records[1]:u64(16)) +
		tonumber(records[2]:u64(16))
	local start = "1699999990000000000"
	local now = "1700000000000000000"

	return {
		{
			name = "shirudo.serialized.packets",
			unit = "1",
			sum = {
				aggregationTemporality = 2,
				isMonotonic = true,
				dataPoints = {{
					startTimeUnixNano = start,
					timeUnixNano = now,
					asInt = tostring(packets),
				}},
			},
		},
		{
			name = "shirudo.serialized.bytes",
			unit = "By",
			sum = {
				aggregationTemporality = 2,
				isMonotonic = true,
				dataPoints = {{
					startTimeUnixNano = start,
					timeUnixNano = now,
					asInt = tostring(bytes),
				}},
			},
		},
	}
end
EOF

cat > "$WORK/counters.bpf.c" <<EOF
// SPDX-License-Identifier: Dual BSD/GPL
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "shirudo_decoder.h"
#include "shirudo_serializer.h"

#define EINVAL 22

char _license[] SEC("license") = "Dual BSD/GPL";

struct counter_value {
	__u64 packets;
	__u64 bytes;
};

struct counter_record {
	__u32 key;
	__u32 reserved;
	__u64 packets;
	__u64 bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct counter_value);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shirudo_serial_chunk);
} shirudo_ser SEC(".maps");

const struct shirudo_decoder_manifest counters_decoder SEC(".rodata") = {
	.magic = SHIRUDO_DECODER_MANIFEST_MAGIC,
	.version = SHIRUDO_UPATCH_DECODER_VERSION,
	.language = SHIRUDO_UPATCH_DECODER_LANG_LUA,
	.api_version = 1,
	.input_format = SHIRUDO_UPATCH_DECODER_INPUT_MAP_V1,
	.export_signal = SHIRUDO_UPATCH_DECODER_EXPORT_METRIC,
	.upatch = "$NAME",
	.map = "counters",
	.source = "decoders/counters.lua",
	.entrypoint = "decode",
};

SEC("syscall")
int shirudo_serialize__counters(struct shirudo_serialize_ctx *ctx)
{
	struct shirudo_serial_chunk *chunk;
	struct counter_value *value;
	struct counter_record record = {};
	__u32 key, output_key = 0;

	if (!ctx || ctx->magic != SHIRUDO_SERIAL_MAGIC ||
	    ctx->version != SHIRUDO_SERIAL_VERSION ||
	    ctx->max_chunks < 1 ||
	    ctx->chunk_payload_size != SHIRUDO_SERIAL_CHUNK_PAYLOAD ||
	    ctx->page_index != 0 || ctx->cursor != 0 ||
	    ctx->invocation_id == 0)
		return -EINVAL;

	chunk = bpf_map_lookup_elem(&shirudo_ser, &output_key);
	if (!chunk)
		return -EINVAL;

	key = 0;
	value = bpf_map_lookup_elem(&counters, &key);
	if (!value)
		return -EINVAL;
	value->packets = 7;
	value->bytes = 100;
	record.key = key;
	record.packets = value->packets;
	record.bytes = value->bytes;
	__builtin_memcpy(&chunk->data[0], &record, sizeof(record));

	key = 1;
	value = bpf_map_lookup_elem(&counters, &key);
	if (!value)
		return -EINVAL;
	value->packets = 3;
	value->bytes = 50;
	record.key = key;
	record.packets = value->packets;
	record.bytes = value->bytes;
	__builtin_memcpy(&chunk->data[sizeof(record)], &record,
			 sizeof(record));

	chunk->magic = SHIRUDO_SERIAL_MAGIC;
	chunk->version = SHIRUDO_SERIAL_VERSION;
	chunk->flags = SHIRUDO_SERIAL_F_DONE;
	chunk->status = 0;
	chunk->chunk_index = 0;
	chunk->total_chunks = 1;
	chunk->bytes_total = 2 * sizeof(record);
	chunk->bytes_in_chunk = 2 * sizeof(record);
	chunk->page_index = ctx->page_index;
	chunk->reserved = 0;
	chunk->cursor = ctx->cursor;
	chunk->next_cursor = 2;
	chunk->invocation_id = ctx->invocation_id;
	return 0;
}
EOF

(
	cd .. &&
	"$SHB" "$WORK/counters.bpf.c" -o "$WORK/load.upatch" \
		--vmlinux bpf/vmlinux.h --name "$NAME"
) >/dev/null 2>&1 || test_skip_all "build failed"
PAYLOAD=$(
	"$SHIRUDO_BIN" upatch info "$WORK/load.upatch" --json 2>/dev/null |
		report_field payload_sha256
)
[ -n "$PAYLOAD" ] || test_skip_all "could not read built payload"

test_expect_success 'serialized counters become cumulative OTLP metrics' '
	rm -f "$WORK/otel.port" "$WORK/otel.body" "$WORK/otel.meta";
	python3 helper/otel-mock.py success \
		"$WORK/otel.port" "$WORK/otel.body" "$WORK/otel.meta" &
	SERVER=$!;
	i=0;
	while test ! -s "$WORK/otel.port" && test "$i" -lt 100
	do
		i=$((i + 1));
		sleep .1;
	done;
	test -s "$WORK/otel.port" &&
	port=$(cat "$WORK/otel.port") &&
	printf "%s\n" \
		"map_export.otel_endpoint = http://127.0.0.1:$port" \
		"map_export.otel_insecure = true" \
		"map_export.otel_retries = 0" >"$CONFIG" &&
	"$SHIRUDO_BIN" upatch load "$WORK/load.upatch" --no-precheck \
		>/dev/null 2>&1 &&
	test -e "$SERIALIZER_PIN" &&
	systemctl start shirudo-map-export.service &&
	wait "$SERVER";
	SERVER="";
	systemctl show shirudo-map-export.service -p ExecMainStatus --value |
		grep -qx 0 &&
	python3 - "$WORK/otel.meta" "$WORK/otel.body" <<'"'"'PY'"'"'
import json
import sys

meta = json.load(open(sys.argv[1], encoding="utf-8"))
doc = json.load(open(sys.argv[2], encoding="utf-8"))
assert meta["path"] == "/v1/metrics", meta
metrics = doc["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
assert len(metrics) == 2, metrics
by_name = {metric["name"]: metric for metric in metrics}
assert set(by_name) == {
	"shirudo.serialized.packets",
	"shirudo.serialized.bytes",
}, by_name
assert by_name["shirudo.serialized.packets"]["unit"] == "1"
assert by_name["shirudo.serialized.bytes"]["unit"] == "By"
for metric in metrics:
	series = metric["sum"]
	assert series["aggregationTemporality"] == 2, series
	assert series["isMonotonic"] is True, series
	point = series["dataPoints"][0]
	assert point["startTimeUnixNano"] == "1699999990000000000", point
	assert point["timeUnixNano"] == "1700000000000000000", point
assert by_name["shirudo.serialized.packets"]["sum"]["dataPoints"][0]["asInt"] == "10"
assert by_name["shirudo.serialized.bytes"]["sum"]["dataPoints"][0]["asInt"] == "150"
PY
'

test_done
