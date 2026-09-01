#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0006 -- Java .jar upatches are packaged and inspected without the BPF
# signing/keyring path. This is deliberately an offline operator test.

cd "$(dirname "$0")"
. ./test-lib.sh

S=../shirudo
SHB=../tools/shirudo-build/shirudo-build

command -v jar >/dev/null 2>&1 || test_skip_all "no jar command"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

printf 'Manifest-Version: 1.0\nPremain-Class: example.Agent\n\n' >"$WORK/MANIFEST.MF"
mkdir "$WORK/classes"
printf 'not a class file\n' >"$WORK/classes/Agent.class"
jar --create --file "$WORK/agent.jar" --manifest "$WORK/MANIFEST.MF" \
	-C "$WORK/classes" Agent.class >/dev/null 2>&1 ||
	test_skip_all "jar could not create a test archive"

"$SHB" "$WORK/agent.jar" -o "$WORK/agent.upatch" >/dev/null 2>&1 ||
	test_skip_all "Java upatch build failed"

test_expect_success 'Java load upatch has raw jar payload and no BPF signature' '
	"$S" upatch info "$WORK/agent.upatch" --json 2>/dev/null |
	python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d[\"type\"] == \"load\", d
assert d[\"payload_type\"] == \"java\", d
assert d[\"loader_insns_len\"] == 0, d
assert d[\"signature_len\"] == 0, d
assert d[\"data_len\"] > 0, d
assert d[\"has_source\"] is False, d
"
'

test_expect_success 'Java load metadata names its optional telemetry companion' '
	"$SHB" "$WORK/agent.jar" --telemetry-upatch javaagent_metrics \
		-o "$WORK/agent-with-telemetry.upatch" >/dev/null 2>&1 &&
	"$S" upatch info "$WORK/agent-with-telemetry.upatch" --json |
	python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d[\"payload_type\"] == \"java\", d
assert d[\"telemetry_upatch\"] == \"javaagent_metrics\", d
"
'

test_expect_success 'Java unload upatch carries the expected payload hash' '
	payload=$("$S" upatch info "$WORK/agent.upatch" --json |
		python3 -c "import json, sys; print(json.load(sys.stdin)[\"payload_sha256\"])" ) &&
	"$SHB" --type java --unload agent --payload-sha256 "$payload" \
		-o "$WORK/agent.unload.upatch" >/dev/null 2>&1 &&
	"$S" upatch info "$WORK/agent.unload.upatch" --json 2>/dev/null |
	python3 -c "
import json, sys
d = json.load(sys.stdin)
assert d[\"type\"] == \"unload\", d
assert d[\"payload_type\"] == \"java\", d
assert d[\"metadata_len\"] == 32, d
assert d[\"data_len\"] == 0, d
"
'

test_done
