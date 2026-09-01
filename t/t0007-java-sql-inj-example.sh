#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0007 -- build and run the Java SQL injection shield example locally.

cd "$(dirname "$0")"
. ./test-lib.sh

command -v mvn >/dev/null 2>&1 || test_skip_all "no Maven"
command -v java >/dev/null 2>&1 || test_skip_all "no Java runtime"
command -v go >/dev/null 2>&1 || test_skip_all "no Go toolchain"
[ -x ../shirudo ] || test_skip_all "shirudo not built"
[ -x ../tools/shirudo-build/shirudo-build ] || test_skip_all "shirudo-build not built"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

test_expect_success 'build Java SQL injection example artifacts' '
	JAVA_SQL_INJ_OUTPUT_DIR="$WORK/output" \
	SHIRUDO_BIN="$(pwd)/../shirudo" \
		../shields/java_sql_inj/build.sh >"$WORK/build.log" 2>&1
'

test_expect_success 'Java load artifact has no BPF loader or signature' '
	../shirudo upatch info "$WORK/output/java-sql-inj.upatch" --json |
	python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d[\"payload_type\"] == \"java\", d
assert d[\"loader_insns_len\"] == 0, d
assert d[\"signature_len\"] == 0, d
assert d[\"data_len\"] > 0, d
"
'

test_expect_success 'BPM package includes Java artifacts and trigger' '
	tar -tzf "$WORK/output/java-sql-injection-0.1.0.bee" |
		grep -q "java-sql-injection-0.1.0/bin/sql_inj_vuln" &&
	tar -tzf "$WORK/output/java-sql-injection-0.1.0.bee" |
		grep -q "java-sql-injection-0.1.0/upatches/java-sql-inj.upatch" &&
	tar -tzf "$WORK/output/java-sql-injection-0.1.0.bee" |
		grep -q "java-sql-injection-0.1.0/upatches/javaagent-metrics.upatch"
'

test_expect_success 'companion BPF upatch carries an OTLP metric decoder' '
	../shirudo upatch info "$WORK/output/javaagent-metrics.upatch" --json |
	python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d[\"name\"] == \"javaagent_metrics\", d
assert d[\"payload_type\"] == \"bpf\", d
assert len(d[\"decoders\"]) == 1, d
assert d[\"decoders\"][0][\"export_signal\"] == \"metric\", d
"
'

test_expect_success 'agent blocks SQL injection in the real H2 application' '
	out=$(java -javaagent:"$WORK/output/agent.jar" \
		-jar "$WORK/output/vulnerable-app.jar" 2>&1) &&
	echo "$out" | grep -Fq "[RASP ALERT] SQL Injection Attempt Detected" &&
	echo "$out" | grep -Fq "[App] !!! BLOCK ACTION TRIGGERED !!!"
'

test_expect_success 'agent permits a benign H2 query' '
	out=$(java -javaagent:"$WORK/output/agent.jar" \
		-jar "$WORK/output/vulnerable-app.jar" admin 2>&1) &&
	echo "$out" | grep -Fq "Query completed successfully! Result rows:" &&
	echo "$out" | grep -Fq -- "-> Found User: admin" &&
	! echo "$out" | grep -Fq "RASP ALERT"
'

test_done
