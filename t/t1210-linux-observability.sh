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
	for map in exec_arena tcp_arena udp_arena dns_arena; do
		"$SHIRUDO_BIN" upatch map "$NAME" "$map" \
			--json="$output" >/dev/null
	done
}

cat >"$WORK/check.py" <<'PY'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
expected = {"exec_arena", "tcp_arena", "udp_arena", "dns_arena"}
assert {record["map"] for record in records} == expected, records
for record in records:
    assert record["schema"] == 1, record
    assert record["upatch"] == "linux-observability", record
    assert isinstance(record["records"], list), record
PY

cat >"$WORK/check_initial.py" <<'PY'
import json
import sys

records = {r["map"]: r for r in
           (json.loads(line) for line in open(sys.argv[1], encoding="utf-8"))}
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
PY

cat >"$WORK/check_empty.py" <<'PY'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
for record in records:
    if record["map"] != "exec_arena":
        assert not record["records"], record
PY

cat >"$WORK/check_exec_only.py" <<'PY'
import json
import sys

records = {r["map"]: r for r in
           (json.loads(line) for line in open(sys.argv[1], encoding="utf-8"))}
assert records["exec_arena"]["records"], records
for name in ("tcp_arena", "udp_arena", "dns_arena"):
    assert not records[name]["records"], (name, records)
PY

test_expect_success 'combined observability upatch loads with four serializers' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck \
		>/dev/null 2>&1 &&
	[ -e "/var/lib/shirudo/bpffs/upatches/$NAME/serializers/exec_arena" ] &&
	[ -e "/var/lib/shirudo/bpffs/upatches/$NAME/serializers/tcp_arena" ] &&
	[ -e "/var/lib/shirudo/bpffs/upatches/$NAME/serializers/udp_arena" ] &&
	[ -e "/var/lib/shirudo/bpffs/upatches/$NAME/serializers/dns_arena" ]
'

test_expect_success 'exec, TCP, UDP, and DNS produce structured batches' '
	python3 linux_obs_events.py all &&
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
