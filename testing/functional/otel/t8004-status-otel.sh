#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

S=../shirudo
H=helper/test-otel-map

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
		"$S" status --otel >"$work/stdout" 2>"$work/stderr" &&
	wait "$server" &&
	test ! -s "$work/stdout" &&
	python3 - "$work/body" "$work/meta" <<"PY"
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
    "reboot-pending": (13, "WARN"),
    "lsm-off": (17, "ERROR"),
    "tampered": (17, "ERROR"),
}[status]
assert (record["severityNumber"], record["severityText"]) == severity
attrs = {item["key"]: item["value"] for item in record["attributes"]}
assert "shirudo.status" in attrs
assert "shirudo.version_id" in attrs
PY
'

test_expect_success 'keepalive status severities and structured body are deterministic' '
	work=$(mktemp -d) || return 1
	for status in ok degraded init-pending reboot-pending lsm-off tampered
	do
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
		"$H" send-status "http://127.0.0.1:$port" "$status" &&
		wait "$server" &&
		python3 - "$status" "$work/body" <<'\''PY'\'' || return 1
import json, socket, sys
status = sys.argv[1]
rl = json.load(open(sys.argv[2]))["resourceLogs"][0]
resource = {item["key"]: item["value"] for item in rl["resource"]["attributes"]}
assert resource == {"service.name": {"stringValue": "shirudo"},
                    "service.version": {"stringValue": "test-1"},
                    "host.name": {"stringValue": socket.gethostname()}}, resource
assert rl["scopeLogs"][0]["scope"] == {"name": "shirudo.keepalive",
                                       "version": "test-1"}
record = rl["scopeLogs"][0]["logRecords"][0]
expected = {"ok": (9, "INFO"), "degraded": (13, "WARN"),
            "init-pending": (13, "WARN"), "reboot-pending": (13, "WARN"),
            "lsm-off": (17, "ERROR"),
            "tampered": (17, "ERROR")}[status]
assert (record["severityNumber"], record["severityText"]) == expected
assert record["eventName"] == "shirudo.keepalive"
body = {item["key"]: item["value"] for item in record["body"]["kvlistValue"]["values"]}
assert body["status"]["stringValue"] == status
assert body["schema"]["intValue"] == "1"
attrs = {item["key"]: item["value"] for item in record["attributes"]}
assert attrs == {"shirudo.status": {"stringValue": status},
                 "shirudo.version_id": {"stringValue": "test-version"},
                 "shirudo.tamper_attempts": {"intValue": "2"}}, attrs
PY
		rm -f "$work/port" "$work/body" "$work/meta" || return 1
	done
'

test_expect_success 'a status body many times larger as AnyValues is sent whole' '
	work=$(mktemp -d) || return 1
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
	"$H" send-wide-status "http://127.0.0.1:$port" 100000 &&
	wait "$server" &&
	python3 - "$work/body" <<'\''PY'\'' &&
import json, sys
rl = json.load(open(sys.argv[1]))["resourceLogs"][0]
record = rl["scopeLogs"][0]["logRecords"][0]
body = {item["key"]: item["value"] for item in record["body"]["kvlistValue"]["values"]}
values = body["conditions"]["arrayValue"]["values"]
assert len(values) == 100000 and values[-1] == {"intValue": "1"}, len(values)
PY
	rm -rf "$work"
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
		"$S" status --json --otel >"$work/stdout" 2>"$work/stderr" &&
	wait "$server" &&
	python3 - "$work/stdout" <<"PY"
import json
import sys

doc = json.load(open(sys.argv[1]))
assert doc["schema"] == 1
assert "status" in doc
assert "tpm" in doc
assert "tamper_attempts" in doc
PY
'

test_expect_success 'status --otel without an endpoint does not send' '
	work=$(mktemp -d)
	env -u OTEL_EXPORTER_OTLP_LOGS_ENDPOINT \
		-u OTEL_EXPORTER_OTLP_ENDPOINT \
		"$S" status --json --otel >"$work/stdout" 2>"$work/stderr" &&
	python3 - "$work/stdout" <<"PY"
import json
import sys

doc = json.load(open(sys.argv[1]))
assert doc["schema"] == 1
assert "status" in doc
PY
	rm -rf "$work"
'

test_expect_success 'status --json --include-system includes kernel config' '
	work=$(mktemp -d) &&
	"$S" status --json --include-system >"$work/status.json" 2>"$work/stderr" &&
	cat >"$work/check.py" <<"PY" &&
import json
import os
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
system = doc["system"]
assert isinstance(system["kernel_build_id"], str)
assert all(c in "0123456789abcdef" for c in system["kernel_build_id"])
config = system["kernel_config"]
assert isinstance(config, dict)
assert all(key.startswith("CONFIG_") for key in config)
assert list(config) == sorted(config)

path = "/boot/config-" + system["kernel_release"]
if os.path.isfile(path):
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\r\n")
        if line.startswith("# CONFIG_") and line.endswith(" is not set"):
            key = line[2:].split(" is not set", 1)[0]
            assert config[key] == "n"
            continue
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            if len(value) >= 2 and value[0] == value[-1] == "\"":
                value = value[1:-1]
            assert config[key] == value
            break
    else:
        raise AssertionError("kernel config has no CONFIG_ entries")
PY
	python3 -I "$work/check.py" "$work/status.json" &&
	rm -rf "$work"
'

test_expect_success 'status --include-system prints kernel config' '
	work=$(mktemp -d) &&
	"$S" status --include-system >"$work/status" 2>"$work/stderr" &&
	grep -Eq "^  Kernel build ID: +([0-9a-f]+)?$" "$work/status" &&
	"$S" status --json --include-system 2>/dev/null |
		python3 -c "import json, sys; sys.exit(0 if \"kernel_config\" in json.load(sys.stdin)[\"system\"] else 1)" &&
	rm -rf "$work"
'

test_expect_success 'a keepalive record carries its body as a string and one quote attribute' '
	work=$(mktemp -d) || return 1
	quote="attest=/1RDR4AY;sig=ABgACwAg;ak=ACMACwAE" &&
	printf "%s\303\251%s" \
		"{\"schema\":\"shirudo.keepalive/1\",\"image_id\":\"a\\\\b \\u00e9 " \
		"\",\"tamper\":[0,1],\"mask\":null}" >"$work/input" || return 1
	for verdict in ok degraded init-pending reboot-pending lsm-off tampered
	do
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
		"$H" send-keepalive "http://127.0.0.1:$port" "$verdict" \
			"$work/input" "$quote" &&
		wait "$server" &&
		python3 - "$verdict" "$work/body" "$work/meta" "$work/input" \
			"$quote" <<'\''PY'\'' || return 1
import json, socket, sys
verdict, quote = sys.argv[1], sys.argv[5]
sent = open(sys.argv[4], "rb").read()
assert b"\\u00e9 \xc3\xa9" in sent and b"a\\\\b" in sent, sent
assert json.load(open(sys.argv[3]))["path"] == "/v1/logs"
rl = json.load(open(sys.argv[2]))["resourceLogs"][0]
resource = {item["key"]: item["value"] for item in rl["resource"]["attributes"]}
assert resource == {"service.name": {"stringValue": "shirudo"},
                    "service.version": {"stringValue": "test-1"},
                    "host.name": {"stringValue": socket.gethostname()}}, resource
assert rl["scopeLogs"][0]["scope"] == {"name": "shirudo.keepalive",
                                       "version": "test-1"}
record = rl["scopeLogs"][0]["logRecords"][0]
expected = {"ok": (9, "INFO"), "degraded": (13, "WARN"),
            "init-pending": (13, "WARN"), "reboot-pending": (13, "WARN"),
            "lsm-off": (17, "ERROR"),
            "tampered": (17, "ERROR")}[verdict]
assert (record["severityNumber"], record["severityText"]) == expected
assert record["eventName"] == "shirudo.keepalive"
assert record["timeUnixNano"].isdigit()
assert list(record["body"]) == ["stringValue"], record["body"]
assert record["body"]["stringValue"].encode() == sent, record["body"]
assert record["attributes"] == [
    {"key": "shirudo.quote", "value": {"stringValue": quote}}
], record["attributes"]
PY
		rm -f "$work/port" "$work/body" "$work/meta" || return 1
	done
	rm -rf "$work"
'

test_expect_success 'a keepalive body JSON cannot carry unchanged is not sent' '
	work=$(mktemp -d) || return 1
	printf "{\"image_id\":\"\\377\"}" >"$work/latin1" &&
	printf "{\"image_id\":\"\\000\"}" >"$work/nul" || return 1
	for input in latin1 nul
	do
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
		! "$H" send-keepalive "http://127.0.0.1:$port" ok \
			"$work/$input" quote &&
		test ! -e "$work/body" || return 1
		kill "$server" && { wait "$server" || true; } &&
		rm -f "$work/port" || return 1
	done
	rm -rf "$work"
'

test_done
