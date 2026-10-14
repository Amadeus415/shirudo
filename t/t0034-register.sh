#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0034 -- the measurement register against a software TPM: binding,
# the anchor, extends, the recreate and replay attacks, a reset, and
# the evidence a verifier accepts or refuses. Needs the libtpms-backed
# helper/tpmsim-cmd; skipped where libtpms is not installed.

cd "$(dirname "$0")"
. ./test-lib.sh

R=helper/test-register
SIM=$(pwd)/helper/tpmsim-cmd
S=../shirudo
[ -x "$SIM" ] || test_skip_all "helper/tpmsim-cmd not built (libtpms-dev missing)"
[ -x "$R" ] || test_skip_all "helper/test-register not built"
[ -x "$S" ] || test_skip_all "shirudo not built"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir -p "$WORK/keys"
head -c 700 /dev/urandom >"$WORK/keys/cert.der"
export SHIRUDO_TPM_TCTI="cmd:$SIM $WORK/tpm"
export SHIRUDO_EVENTLOG_PATH="$WORK/eventlog"
export SHIRUDO_KEYS_DIR="$WORK/keys"

py() { python3 -c "$1"; }
sha() { py "import hashlib; print(hashlib.sha256(bytes.fromhex(\"$1\")).hexdigest())"; }
field() { sed -n "s/^$1=//p"; }
Z=0000000000000000000000000000000000000000000000000000000000000000
PAYLOAD=$(py "print(\"ab\"*32)")

test_expect_success 'init binds the register to PCR 15 and anchors its name' '
	init=$(py "import hashlib; c = hashlib.sha256(open(\"$WORK/keys/cert.der\", \"rb\").read()).digest(); print(hashlib.sha256(b\"shirudo-init\\0\" + c + hashlib.sha256(b\"\").digest() + bytes(32)).hexdigest())") &&
	out=$(./$R init "$init") &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "reused=0" &&
	echo "$out" | grep -qx "pcr_before=$Z" &&
	name=$(echo "$out" | field name) &&
	[ "$(echo "$out" | field anchor)" = "nvpcr-init:shirudo:0x1818e00:$name" ] &&
	anchor_digest=$(py "import hashlib; print(hashlib.sha256(b\"nvpcr-init:shirudo:0x1818e00:$name\").hexdigest())") &&
	[ "$(./$R pcr 15)" = "$(sha "$Z$anchor_digest")" ] &&
	[ "$(echo "$out" | field value)" = "$(sha "$Z$init")" ] &&
	echo "$init" >"$WORK/init" && echo "$name" >"$WORK/name"
'

test_expect_success 'status reports the register bound, logged and anchored' '
	./$R status | grep -qx "tpm=1 defined=1 written=1 logged=1 anchored=1" &&
	$S status --json --include-tpm >"$WORK/status.json" &&
	python3 - "$WORK/status.json" <<"PY"
import json, sys
t = json.load(open(sys.argv[1]))["tpm"]
assert t["register_bound"] and t["register_anchored"], t
assert t["chain_matches_eventlog"] is True, t
assert t["pcr"] == 15, t
PY
'

test_expect_success 'a re-run of init reuses the register and adds no event' '
	out=$(./$R init "$(cat "$WORK/init")") &&
	echo "$out" | grep -qx "reused=1" &&
	[ "$(wc -l <"$WORK/eventlog")" = 1 ]
'

test_expect_success 'a load extends through the written branch and replays' '
	before=$(./$R read | field value) &&
	event=$(py "import hashlib; print(hashlib.sha256(b\"shirudo-upatch\\0\" + bytes.fromhex(\"$PAYLOAD\") + b\"foo\").hexdigest())") &&
	out=$(./$R load foo "$PAYLOAD") &&
	echo "$out" | grep -qx "rc=0" &&
	[ "$(echo "$out" | field value)" = "$(sha "$before$event")" ] &&
	./$R status | grep -qx "tpm=1 defined=1 written=1 logged=1 anchored=1"
'

test_expect_success 'the init branch cannot be satisfied after the anchor' '
	./$R first-write "$PAYLOAD" | grep -qx "rc=-13"
'

test_expect_success 'a recreated index is unwritable and no longer anchored' '
	out=$(./$R recreate) &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "written=0" &&
	[ "$(echo "$out" | field name)" != "$(cat "$WORK/name")" ] &&
	./$R extend-raw "$PAYLOAD" | grep -qx "rc=-19" &&
	./$R first-write "$PAYLOAD" | grep -qx "rc=-13" &&
	./$R status | grep -qx "tpm=1 defined=1 written=0 logged=1 anchored=0"
'

test_expect_success 'a TPM reset clears the register; init binds it again' '
	rm -f "$WORK/tpm/volatile" &&
	./$R read | grep -qx "rc=-19" &&
	out=$(./$R init "$(cat "$WORK/init")") &&
	echo "$out" | grep -qx "rc=0" &&
	echo "$out" | grep -qx "reused=0" &&
	[ "$(echo "$out" | field name)" = "$(cat "$WORK/name")" ] &&
	[ "$(echo "$out" | field value)" = "$(sha "$Z$(cat "$WORK/init")")" ] &&
	./$R status | grep -qx "tpm=1 defined=1 written=1 logged=1 anchored=1"
'

test_done
