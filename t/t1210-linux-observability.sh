#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=linux-observability
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/var/lib/shirudo/bpffs/upatches/$NAME/link_0"
WORK=$(mktemp -d)

cleanup()
{
	if [ -e "$PIN" ] || [ -e "/var/lib/shirudo/bpffs/upatches/$NAME/link" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	rm -rf "$WORK"
}
trap cleanup EXIT

[ -s "$LOAD" ] || test_skip_all "missing Linux observability fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing Linux observability unload fixture"

export_maps()
{
	output="$1"
	for map in exec_arena tcp_arena udp_arena dns_arena ipv4_shields; do
		"$SHIRUDO_BIN" upatch map "$NAME" "$map" \
			--json="$output" >/dev/null
	done
}

load_observability()
{
	if "$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck --report=- \
		>"$WORK/load.log" 2>&1; then
		return 0
	fi
	cat "$WORK/load.log" >&2
	if [ -d /mnt/shirudo-out ]; then
		cp "$WORK/load.log" /mnt/shirudo-out/observability-load.log
	fi
	return 1
}

cat >"$WORK/check.py" <<'PY'
import json
import sys

documents = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
records = [document for document in documents
           if isinstance(document, dict) and "map" in document]
metrics = [document for document in documents if isinstance(document, list)]
expected = {"exec_arena", "tcp_arena", "udp_arena", "dns_arena"}
assert {record["map"] for record in records} == expected, documents
assert len(metrics) == 1, documents
assert metrics[0][0]["name"] == "enforcement.ipv4_shields_metric", metrics
for record in records:
    assert record["schema"] == 1, record
    assert record["upatch"] == "linux-observability", record
    assert isinstance(record["records"], list), record
PY

cat >"$WORK/check_initial.py" <<'PY'
import json
import sys

documents = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
records = {record["map"]: record for record in documents
           if isinstance(record, dict)}
assert all(records[name]["records"] for name in records), records
exec_ids = {(r["executable"]["dev"], r["executable"]["ino"])
            for r in records["exec_arena"]["records"]}
for name in ("tcp_arena", "udp_arena", "dns_arena"):
    assert any((r["executable"]["dev"], r["executable"]["ino"]) in exec_ids
               for r in records[name]["records"]), (name, records)
assert any(r["address"] == "127.0.0.1" for r in records["tcp_arena"]["records"])
assert any(r["address"] == "127.0.0.1" for r in records["udp_arena"]["records"])
assert any(n["name"] == "example.com"
           for r in records["dns_arena"]["records"] for n in r["names"])
long_name = ".".join(["a"] * 127)
assert any(n["name"] == long_name
           for r in records["dns_arena"]["records"] for n in r["names"])
assert any(r["address"] == "203.0.113.75" and
           any(n["name"] == "many.example" for n in r["names"])
           for r in records["dns_arena"]["records"])
PY

cat >"$WORK/check_metric.py" <<'PY'
import json
import sys

documents = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
metrics = [document for document in documents if isinstance(document, list)]
assert len(metrics) == 1, documents
metric = metrics[0][0]
assert metric["name"] == "enforcement.ipv4_shields_metric", metric
points = metric["sum"]["dataPoints"]
values = {point["attributes"][0]["value"]["stringValue"]: int(point["asInt"])
          for point in points}
assert values == {"allowed": 2, "denied": 3}, values
PY

cat >"$WORK/check_empty.py" <<'PY'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
for record in records:
    if isinstance(record, dict) and record["map"] != "exec_arena":
        assert not record["records"], record
PY

cat >"$WORK/check_exec_only.py" <<'PY'
import json
import sys

documents = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
records = {record["map"]: record for record in documents
           if isinstance(record, dict)}
assert records["exec_arena"]["records"], records
for name in ("tcp_arena", "udp_arena", "dns_arena"):
    assert not records[name]["records"], (name, records)
PY

test_expect_success 'combined observability upatch loads with five serializers' '
	load_observability &&
	[ -e "/var/lib/shirudo/bpffs/upatches/$NAME/serializers/exec_arena" ] &&
	[ -e "/var/lib/shirudo/bpffs/upatches/$NAME/serializers/tcp_arena" ] &&
	[ -e "/var/lib/shirudo/bpffs/upatches/$NAME/serializers/udp_arena" ] &&
	[ -e "/var/lib/shirudo/bpffs/upatches/$NAME/serializers/dns_arena" ] &&
	[ -e "/var/lib/shirudo/bpffs/upatches/$NAME/serializers/ipv4_shields" ]
'

test_expect_success 'IPv4 shields enforce TCP and UDP and export counters' '
	python3 linux_obs_events.py ipv4-firewall >"$WORK/firewall-events.log" 2>&1 &&
	export_maps "$WORK/firewall.ndjson" >"$WORK/firewall-export.log" 2>&1 &&
	python3 "$WORK/check_metric.py" "$WORK/firewall.ndjson" >"$WORK/firewall-check.log" 2>&1 || {
		cp -a "$WORK" /mnt/shirudo-out/t1210-firewall-work 2>/dev/null || true
		false
	}
'

test_expect_success 'exec, TCP, UDP, and DNS produce structured batches' '
	python3 linux_obs_events.py all &&
	python3 linux_obs_events.py dns-long &&
	python3 linux_obs_events.py dns-many &&
	export_maps "$WORK/initial.ndjson" &&
	python3 "$WORK/check.py" "$WORK/initial.ndjson" &&
	python3 "$WORK/check_initial.py" "$WORK/initial.ndjson"
'

test_expect_success 'serializer clears pending entries after export' '
	export_maps "$WORK/empty.ndjson" &&
	python3 "$WORK/check.py" "$WORK/empty.ndjson" &&
	python3 "$WORK/check_empty.py" "$WORK/empty.ndjson"
'

test_expect_success 'only the touched exec map is exported' '
	python3 linux_obs_events.py exec &&
	export_maps "$WORK/exec-only.ndjson" &&
	python3 "$WORK/check_exec_only.py" "$WORK/exec-only.ndjson"
'

test_done
