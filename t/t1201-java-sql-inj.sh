#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1201 -- Java upatch lifecycle and end-to-end JDBC SQL injection blocking.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
LOAD="$FIXTURES/java-sql-inj.upatch"
UNLOAD="$FIXTURES/java-sql-inj.unload.upatch"
METRICS_LOAD="$FIXTURES/javaagent-metrics.upatch"
METRICS_UNLOAD="$FIXTURES/javaagent-metrics.unload.upatch"
ENV_FILE=/etc/environment.d/shirudo.conf
AGENT=/var/lib/shirudo/javaagent.jar
WORK=$(mktemp -d)

[ -s "$LOAD" ] || test_skip_all "missing Java SQL injection load fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing Java SQL injection unload fixture"
[ -s "$METRICS_LOAD" ] || test_skip_all "missing Java-agent metrics load fixture"
[ -s "$METRICS_UNLOAD" ] || test_skip_all "missing Java-agent metrics unload fixture"
command -v java >/dev/null 2>&1 || test_skip_all "no Java runtime"
command -v sql_inj_vuln >/dev/null 2>&1 || test_skip_all "SQL injection trigger is not installed"

cleanup()
{
	if [ -e "$AGENT" ] || [ -e "$ENV_FILE" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	if [ -e /var/lib/shirudo/bpffs/upatches/javaagent_metrics/test ]; then
		"$SHIRUDO_BIN" upatch unload "$METRICS_UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

test_expect_success 'Java demo starts without an installed agent' '
	test ! -e "$AGENT" && test ! -e "$ENV_FILE"
'

test_expect_success 'Java upatch loads and writes the agent environment' '
	"$SHIRUDO_BIN" upatch load "$METRICS_LOAD" --no-precheck >/dev/null 2>&1 &&
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	test -s "$AGENT" &&
	test -s "$ENV_FILE" &&
	grep -Fq "JAVA_TOOL_OPTIONS=\"-javaagent:/var/lib/shirudo/javaagent.jar=jar_id=" "$ENV_FILE" &&
	grep -Fq ",telemetry_upatch=javaagent_metrics\"" "$ENV_FILE"
'

test_expect_success 'RASP blocks the default SQL injection payload' '
	out=$(sql_inj_vuln 2>&1) &&
	echo "$out" | grep -Fq "[RASP ALERT] SQL Injection Attempt Detected" &&
	echo "$out" | grep -Fq "[App] !!! BLOCK ACTION TRIGGERED !!!" &&
	! echo "$out" | grep -Fq "Query completed successfully"
'

test_expect_success 'SQL injection hook increments the Java-agent OTLP metric' '
	out=$(sql_inj_vuln 2>&1) &&
	echo "$out" | grep -Fq "BLOCK ACTION TRIGGERED" &&
	"$SHIRUDO_BIN" upatch map javaagent_metrics javaagent_arena \
		--json="$WORK/javaagent.ndjson" >/dev/null 2>&1 &&
	python3 - "$WORK/javaagent.ndjson" <<"PY"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    metric = json.loads(stream.readline())
assert metric[0]["name"] == "shirudo.javaagent.sql_injection_attempts", metric
point = metric[0]["sum"]["dataPoints"][0]
assert point["asInt"] == "2", point
assert point["startTimeUnixNano"].isdigit(), point
assert point["timeUnixNano"].isdigit(), point
attrs = {item["key"]: item["value"] for item in point["attributes"]}
assert attrs["javaagent.jar_id"]["stringValue"] != "0", attrs
assert attrs["javaagent.hook_id"]["stringValue"] == "1", attrs
assert attrs["process.executable.ino"]["stringValue"] != "0", attrs
assert isinstance(attrs["process.executable.dev"]["stringValue"], str), attrs
assert attrs["process.executable.dev"]["stringValue"] != "0", attrs
PY
'

test_expect_success 'Java-agent metric is delivered through OTLP metrics' '
	out=$(sql_inj_vuln 2>&1) &&
	echo "$out" | grep -Fq "BLOCK ACTION TRIGGERED" &&
	{
		python3 helper/otel-mock.py success "$WORK/otel.port" "$WORK/otel.body" \
			"$WORK/otel.meta" &
		SERVER=$!;
		i=0; while test ! -s "$WORK/otel.port" && test "$i" -lt 100; do
			sleep .1; i=$((i + 1));
		done;
		test -s "$WORK/otel.port" &&
		port=$(cat "$WORK/otel.port") &&
		"$SHIRUDO_BIN" upatch map javaagent_metrics javaagent_arena --otel \
			--otel-endpoint="http://127.0.0.1:$port/base" &&
		wait "$SERVER"; SERVER="";
		python3 - "$WORK/otel.body" "$WORK/otel.meta" <<"PY"
import json
import sys

body = json.load(open(sys.argv[1], encoding="utf-8"))
meta = json.load(open(sys.argv[2], encoding="utf-8"))
assert meta["path"] == "/base/v1/metrics", meta
metric = body["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]
assert metric["name"] == "shirudo.javaagent.sql_injection_attempts", metric
point = metric["sum"]["dataPoints"][0]
assert point["asInt"] == "3", point
assert point["startTimeUnixNano"].isdigit(), point
assert point["timeUnixNano"].isdigit(), point
attrs = {item["key"]: item["value"] for item in point["attributes"]}
assert attrs["javaagent.hook_id"]["stringValue"] == "1", attrs
assert attrs["process.executable.ino"]["stringValue"] != "0", attrs
assert isinstance(attrs["process.executable.dev"]["stringValue"], str), attrs
assert attrs["process.executable.dev"]["stringValue"] != "0", attrs
PY
	}
'

test_expect_success 'RASP leaves a benign JDBC query executable' '
	out=$(sql_inj_vuln admin 2>&1) &&
	echo "$out" | grep -Fq "Query completed successfully! Result rows:" &&
	echo "$out" | grep -Fq -- "-> Found User: admin" &&
	! echo "$out" | grep -Fq "RASP ALERT"
'

test_expect_success 'Java unload clears the agent and environment' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	test ! -e "$AGENT" &&
	test ! -e "$ENV_FILE" &&
	"$SHIRUDO_BIN" upatch unload "$METRICS_UNLOAD" --no-precheck >/dev/null 2>&1
'

test_expect_success 'trigger remains runnable after Java unload' '
	out=$(sql_inj_vuln admin 2>&1) &&
	echo "$out" | grep -Fq "Query completed successfully! Result rows:" &&
	! echo "$out" | grep -Fq "RASP ALERT"
'

test_done
