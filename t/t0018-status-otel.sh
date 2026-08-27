#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

S=../shirudo

test_expect_success 'status --otel sends a structured keepalive log' '
	work=$(mktemp -d)
	python3 helper/otel-mock.py success "$work/port" "$work/body" \
		"$work/meta" &
	server=$!
	trap "kill $server 2>/dev/null || true; wait $server 2>/dev/null || true; rm -rf $work" EXIT
	i=0
	while test ! -s "$work/port" && test "$i" -lt 100; do
		sleep .02
		i=$((i + 1))
	done
	port=$(cat "$work/port") &&
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
		"$S" status --otel --include-tpm >"$work/stdout" 2>"$work/stderr" &&
	wait "$server" &&
	test ! -s "$work/stdout" &&
	python3 - "$work/body" "$work/meta" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1]))
meta = json.load(open(sys.argv[2]))
record = doc["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
values = {
    item["key"]: item["value"]
    for item in record["body"]["kvlistValue"]["values"]
}
assert meta["path"] == "/v1/logs"
assert record["eventName"] == "shirudo.keepalive"
assert {"schema", "status", "conditions", "tpm"} <= values.keys()
assert values["tpm"]["kvlistValue"]
status = values["status"]["stringValue"]
severity = {
    "ok": (9, "INFO"),
    "degraded": (13, "WARN"),
    "init-pending": (13, "WARN"),
    "lsm-off": (17, "ERROR"),
    "tampered": (17, "ERROR"),
}[status]
assert (record["severityNumber"], record["severityText"]) == severity
attrs = {item["key"]: item["value"] for item in record["attributes"]}
assert "shirudo.status" in attrs
assert "shirudo.version_id" in attrs
PY
'

test_expect_success 'status --json --otel keeps JSON output available' '
	work=$(mktemp -d)
	python3 helper/otel-mock.py success "$work/port" "$work/body" \
		"$work/meta" &
	server=$!
	trap "kill $server 2>/dev/null || true; wait $server 2>/dev/null || true; rm -rf $work" EXIT
	i=0
	while test ! -s "$work/port" && test "$i" -lt 100; do
		sleep .02
		i=$((i + 1))
	done
	port=$(cat "$work/port") &&
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
		"$S" status --json --otel --include-tpm >"$work/stdout" 2>"$work/stderr" &&
	wait "$server" &&
	python3 - "$work/stdout" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1]))
assert doc["schema"] == 1
assert "status" in doc
assert "tpm" in doc
PY
'

test_done
